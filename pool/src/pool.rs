// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction pool implementation.
//! Used for both the txpool and stempool layers in the pool.

use crate::types::{BlockChain, PoolAdapter, PoolConfig, PoolEntry, PoolError, TxSource};
use chrono::prelude::*;
use grin_chain::Chain;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::id::{self, ShortIdentifiable};
use grin_core::core::{
	transaction, Block, BlockHeader, BlockSums, Committed, Inputs, OutputIdentifier, Transaction,
	TxKernel, Weighting,
};
use grin_core::libtx::secp_ser::static_secp_instance;
use grin_p2p::{PeerInfo, Peers};
use grin_util::{OneTime, RwLock};
use log::debug;
use rand::{
	seq::{IteratorRandom, SliceRandom},
	thread_rng, Rng,
};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::thread;

pub trait DandelionAdapter {
	fn select_dandelion_peer(&self) -> Option<PeerInfo>;
	fn select_dandelionpp_peer(&self) -> Option<PeerInfo>;
	fn select_output_peer(&self, input_peer: &PeerInfo, is_stem: bool) -> Option<PeerInfo>;
	fn is_stem(&self) -> bool;
	fn is_expired(&self) -> bool;
	fn next_epoch(&self);
}

pub struct DandelionTxPool(pub Arc<ServerTxPool>);

impl DandelionTxPool {
	pub fn inner(&self) -> Arc<ServerTxPool> {
		Arc::clone(&self.0)
	}
}

pub struct PoolToChainAdapter {
	chain: OneTime<Weak<Chain>>,
}

impl PoolToChainAdapter {
	pub fn new() -> PoolToChainAdapter {
		PoolToChainAdapter {
			chain: OneTime::new(),
		}
	}

	pub fn set_chain(&self, chain_ref: Arc<Chain>) {
		self.chain.init(Arc::downgrade(&chain_ref));
	}

	fn chain(&self) -> Arc<Chain> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade the weak ref to our chain.")
	}
}

impl BlockChain for PoolToChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.chain()
			.head_header()
			.map_err(|_| PoolError::Other("failed to get head_header".to_string()))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, PoolError> {
		self.chain()
			.get_block_header(hash)
			.map_err(|_| PoolError::Other("failed to get block_header".to_string()))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, PoolError> {
		self.chain()
			.get_block_sums(hash)
			.map_err(|_| PoolError::Other("failed to get block_sums".to_string()))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain()
			.validate_tx(tx)
			.map_err(|_| PoolError::Other("failed to validate tx".to_string()))
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
		self.chain()
			.validate_inputs(inputs)
			.map_err(|_| PoolError::Other("failed to validate inputs".to_string()))
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), PoolError> {
		self.chain()
			.verify_coinbase_maturity(inputs)
			.map_err(|_| PoolError::ImmatureCoinbase)
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain()
			.verify_tx_lock_height(tx)
			.map_err(|_| PoolError::ImmatureTransaction)
	}
}

pub struct PoolToNetAdapter {
	tx_pool: OneTime<Weak<DandelionTxPool>>,
	peers: Option<Arc<Peers>>,
}

pub type PoolToNetAdapterAlt = PoolToNetAdapter;

impl PoolToNetAdapter {
	pub fn new() -> PoolToNetAdapter {
		PoolToNetAdapter {
			tx_pool: OneTime::new(),
			peers: None,
		}
	}

	pub fn set_tx_pool(&self, tx_pool_ref: DandelionTxPool) {
		let weak_ref: Weak<DandelionTxPool> = Arc::downgrade(&Arc::new(tx_pool_ref));
		self.tx_pool.init(weak_ref);
	}

	pub fn init(&mut self, peers: Arc<Peers>) {
		self.peers = Some(peers);
	}

	pub fn dummy() -> PoolToNetAdapter {
		PoolToNetAdapter {
			tx_pool: OneTime::new(),
			peers: None,
		}
	}

	fn tx_pool(&self) -> Arc<ServerTxPool> {
		self.tx_pool
			.borrow()
			.upgrade()
			.expect("Failed to upgrade the weak ref to our tx_pool.")
	}
}

impl PoolAdapter for PoolToNetAdapter {
	fn tx_accepted(&self, _entry: &PoolEntry) {
		// Placeholder for transaction acceptance logic
	}

	fn stem_tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		Ok(())
	}
}

impl DandelionAdapter for PoolToNetAdapter {
	fn select_dandelion_peer(&self) -> Option<PeerInfo> {
		self.peers.as_ref().and_then(|p| {
			p.iter()
				.connected()
				.choose_random()
				.map(|peer| peer.info.clone())
		})
	}

	fn select_dandelionpp_peer(&self) -> Option<PeerInfo> {
		self.select_dandelion_peer()
	}

	fn select_output_peer(&self, input_peer: &PeerInfo, is_stem: bool) -> Option<PeerInfo> {
		if is_stem {
			self.select_dandelion_peer()
		} else {
			self.peers.as_ref().and_then(|p| {
				let filtered_peers: Vec<_> = p
					.iter()
					.connected()
					.into_iter()
					.filter(|p| p.info.addr != input_peer.addr)
					.collect();
				filtered_peers
					.into_iter()
					.choose(&mut thread_rng())
					.map(|peer| peer.info.clone())
			})
		}
	}

	fn is_stem(&self) -> bool {
		let mut rng = thread_rng();
		rng.gen_bool(0.9) // 90% chance of stem phase
	}

	fn is_expired(&self) -> bool {
		// TODO: Implement proper epoch expiration logic if needed
		false
	}

	fn next_epoch(&self) {
		// No-op for now
	}
}

impl<T: DandelionAdapter> DandelionAdapter for Arc<T> {
	fn select_dandelion_peer(&self) -> Option<PeerInfo> {
		(**self).select_dandelion_peer()
	}

	fn select_dandelionpp_peer(&self) -> Option<PeerInfo> {
		(**self).select_dandelionpp_peer()
	}

	fn select_output_peer(&self, input_peer: &PeerInfo, is_stem: bool) -> Option<PeerInfo> {
		(**self).select_output_peer(input_peer, is_stem)
	}

	fn is_stem(&self) -> bool {
		(**self).is_stem()
	}

	fn is_expired(&self) -> bool {
		(**self).is_expired()
	}

	fn next_epoch(&self) {
		(**self).next_epoch()
	}
}

pub struct TransactionPool<A: PoolAdapter, B: BlockChain> {
	pub config: PoolConfig,
	pub txpool: Pool<B>,
	pub stempool: Pool<B>,
	pub adapter: Arc<A>,
	pub blockchain: Arc<B>,
}

impl<A: PoolAdapter, B: BlockChain> TransactionPool<A, B> {
	pub fn new(config: PoolConfig, adapter: Arc<A>, blockchain: Arc<B>) -> Self {
		TransactionPool {
			config,
			txpool: Pool::new(blockchain.clone(), "txpool".to_string()),
			stempool: Pool::new(blockchain.clone(), "stempool".to_string()),
			adapter,
			blockchain,
		}
	}

	pub fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.blockchain.chain_head()
	}

	pub fn add_to_pool(
		&mut self,
		src: TxSource,
		tx: Transaction,
		stem: bool,
		header: &BlockHeader,
	) -> Result<(), PoolError> {
		let entry = PoolEntry {
			src,
			tx,
			tx_at: Utc::now(),
		};
		let extra_tx = if stem {
			Some(
				self.txpool
					.all_transactions_aggregate(None)?
					.unwrap_or(Transaction::empty()),
			)
		} else {
			None
		};
		self.apply_tx_to_block_sums(&entry.tx, header)?;
		let pool = if stem {
			&mut self.stempool
		} else {
			&mut self.txpool
		};
		pool.add_to_pool(entry.clone(), extra_tx, header, self.config.min_fee_rate)?;
		self.adapter.tx_accepted(&entry);
		Ok(())
	}

	pub fn all_transactions_aggregate(
		&self,
		extra_tx: Option<Transaction>,
	) -> Result<Option<Transaction>, PoolError> {
		self.txpool.all_transactions_aggregate(extra_tx)
	}

	pub fn validate_raw_txs(
		&self,
		txs: &[Transaction],
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		weighting: Weighting,
	) -> Result<Vec<Transaction>, PoolError> {
		let mut valid_txs = vec![];
		for tx in txs {
			let mut candidate_txs = vec![];
			if let Some(extra_tx) = extra_tx.clone() {
				candidate_txs.push(extra_tx);
			}
			candidate_txs.extend(valid_txs.clone());
			candidate_txs.push(tx.clone());
			let agg_tx = transaction::aggregate(&candidate_txs)?;
			self.apply_tx_to_block_sums(&agg_tx, header)?;
			if self
				.txpool
				.validate_raw_tx(&agg_tx, header, weighting, self.config.min_fee_rate)
				.is_ok()
			{
				valid_txs.push(tx.clone());
			}
		}
		Ok(valid_txs)
	}

	fn apply_tx_to_block_sums(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
	) -> Result<BlockSums, PoolError> {
		let overage = tx.overage();
		let offset = {
			let secp = static_secp_instance();
			let secp = secp.lock();
			header.total_kernel_offset().add(&tx.offset, &secp)
		}?;
		let block_sums = self.blockchain.get_block_sums(&header.hash())?;
		let (utxo_sum, kernel_sum) =
			(block_sums, tx as &dyn Committed).verify_kernel_sums(overage, offset)?;
		Ok(BlockSums {
			utxo_sum,
			kernel_sum,
		})
	}

	pub fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		_peer_info: &PeerInfo,
	) -> Option<Transaction> {
		if let Some(tx) = self.txpool.retrieve_tx_by_kernel_hash(kernel_hash) {
			return Some(tx);
		}
		self.stempool.retrieve_tx_by_kernel_hash(kernel_hash)
	}

	pub fn prepare_mineable_transactions(&self) -> Result<Vec<Transaction>, PoolError> {
		self.txpool.prepare_mineable_transactions(
			self.config.mineable_max_weight,
			self.config.min_fee_rate,
		)
	}
}

pub struct Pool<B>
where
	B: BlockChain,
{
	pub entries: Vec<PoolEntry>,
	pub blockchain: Arc<B>,
	pub name: String,
}

impl<B: BlockChain> Clone for Pool<B> {
	fn clone(&self) -> Self {
		Pool {
			entries: self.entries.clone(),
			blockchain: Arc::clone(&self.blockchain),
			name: self.name.clone(),
		}
	}
}

impl<B: BlockChain> Pool<B> {
	pub fn new(chain: Arc<B>, name: String) -> Self {
		Pool {
			entries: vec![],
			blockchain: chain,
			name,
		}
	}

	pub fn contains_tx(&self, tx: &Transaction) -> bool {
		self.entries.iter().any(|x| x.tx.kernels() == tx.kernels())
	}

	pub fn retrieve_tx_by_kernel_hash(&self, hash: Hash) -> Option<Transaction> {
		for x in &self.entries {
			for k in x.tx.kernels() {
				if k.hash() == hash {
					return Some(x.tx.clone());
				}
			}
		}
		None
	}

	pub fn retrieve_transactions(
		&self,
		hash: Hash,
		nonce: u64,
		kern_ids: &[id::ShortId],
	) -> (Vec<Transaction>, Vec<id::ShortId>) {
		let mut txs = vec![];
		let mut found_ids = vec![];
		'outer: for x in &self.entries {
			for k in x.tx.kernels() {
				let short_id = k.short_id(&hash, nonce);
				if kern_ids.contains(&short_id) {
					txs.push(x.tx.clone());
					found_ids.push(short_id);
				}
				if found_ids.len() == kern_ids.len() {
					break 'outer;
				}
			}
		}
		txs.dedup();
		(
			txs,
			kern_ids
				.iter()
				.filter(|id| !found_ids.contains(id))
				.cloned()
				.collect(),
		)
	}

	pub fn prepare_mineable_transactions(
		&self,
		max_weight: u64,
		min_fee_rate: u64,
	) -> Result<Vec<Transaction>, PoolError> {
		let weighting = Weighting::AsLimitedTransaction(max_weight);
		let txs = self.bucket_transactions(weighting);
		let header = self.blockchain.chain_head()?;
		let valid_txs = self.validate_raw_txs(&txs, None, &header, weighting, min_fee_rate)?;
		Ok(valid_txs)
	}

	pub fn all_transactions(&self) -> Vec<Transaction> {
		self.entries.iter().map(|x| x.tx.clone()).collect()
	}

	pub fn all_transactions_aggregate(
		&self,
		extra_tx: Option<Transaction>,
	) -> Result<Option<Transaction>, PoolError> {
		let mut txs = self.all_transactions();
		if txs.is_empty() {
			return Ok(extra_tx);
		}
		txs.extend(extra_tx);
		let tx = transaction::aggregate(&txs)?;
		tx.validate(Weighting::NoLimit)?;
		Ok(Some(tx))
	}

	pub fn add_to_pool(
		&mut self,
		entry: PoolEntry,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		min_fee_rate: u64,
	) -> Result<(), PoolError> {
		let mut txs = self.all_transactions();
		if txs.contains(&entry.tx) {
			return Err(PoolError::DuplicateTx);
		}
		txs.extend(extra_tx);
		let agg_tx = if txs.is_empty() {
			entry.tx.clone()
		} else {
			txs.push(entry.tx.clone());
			transaction::aggregate(&txs)?
		};
		self.validate_raw_tx(&agg_tx, header, Weighting::NoLimit, min_fee_rate)?;
		self.log_pool_add(&entry, header);
		self.entries.push(entry);
		Ok(())
	}

	fn log_pool_add(&self, entry: &PoolEntry, header: &BlockHeader) {
		debug!(
			"add_to_pool [{}]: {} ({:?}) [in/out/kern: {}/{}/{}] pool: {} (at block {})",
			self.name,
			entry.tx.hash(),
			entry.src,
			entry.tx.inputs().len(),
			entry.tx.outputs().len(),
			entry.tx.kernels().len(),
			self.size(),
			header.hash(),
		);
	}

	fn validate_raw_tx(
		&self,
		tx: &Transaction,
		_header: &BlockHeader,
		weighting: Weighting,
		min_fee_rate: u64,
	) -> Result<(), PoolError> {
		if tx.fee_rate() < min_fee_rate {
			return Err(PoolError::LowFeeTransaction(min_fee_rate));
		}
		tx.validate(weighting)?;
		self.blockchain.validate_tx(tx)?;
		Ok(())
	}

	pub fn validate_raw_txs(
		&self,
		txs: &[Transaction],
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		weighting: Weighting,
		min_fee_rate: u64,
	) -> Result<Vec<Transaction>, PoolError> {
		let mut valid_txs = vec![];
		for tx in txs {
			let mut candidate_txs = vec![];
			if let Some(extra_tx) = extra_tx.clone() {
				candidate_txs.push(extra_tx);
			}
			candidate_txs.extend(valid_txs.clone());
			candidate_txs.push(tx.clone());
			let agg_tx = transaction::aggregate(&candidate_txs)?;
			if self
				.validate_raw_tx(&agg_tx, header, weighting, min_fee_rate)
				.is_ok()
			{
				valid_txs.push(tx.clone());
			}
		}
		Ok(valid_txs)
	}

	pub fn locate_spends(
		&self,
		tx: &Transaction,
		extra_tx: Option<Transaction>,
	) -> Result<(Vec<OutputIdentifier>, Vec<OutputIdentifier>), PoolError> {
		let mut inputs: Vec<_> = tx.inputs().into();
		let agg_tx = self
			.all_transactions_aggregate(extra_tx)?
			.unwrap_or(Transaction::empty());
		let mut outputs: Vec<OutputIdentifier> = agg_tx
			.outputs()
			.iter()
			.map(|out| out.identifier())
			.collect();
		let (spent_utxo, _, _, spent_pool) =
			transaction::cut_through(&mut inputs[..], &mut outputs[..])?;
		let spent_utxo = self.blockchain.validate_inputs(&spent_utxo.into())?;
		Ok((spent_pool.to_vec(), spent_utxo))
	}

	pub fn reconcile(
		&mut self,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		min_fee_rate: u64,
	) -> Result<(), PoolError> {
		let existing_entries = self.entries.clone();
		self.entries.clear();
		for x in existing_entries {
			let _ = self.add_to_pool(x, extra_tx.clone(), header, min_fee_rate);
		}
		Ok(())
	}

	pub fn evict_transaction(&mut self) {
		if let Some(evictable_transaction) = self.bucket_transactions(Weighting::NoLimit).last() {
			self.entries.retain(|x| x.tx != *evictable_transaction);
		}
	}

	fn bucket_transactions(&self, weighting: Weighting) -> Vec<Transaction> {
		let mut tx_buckets: Vec<Bucket> = Vec::new();
		let mut output_commits = HashMap::new();
		let mut rejected = HashSet::new();
		for entry in &self.entries {
			let mut insert_pos = None;
			let mut is_rejected = false;
			let tx_inputs: Vec<_> = entry.tx.inputs().into();
			for input in tx_inputs {
				if rejected.contains(&input.commitment()) {
					is_rejected = true;
					continue;
				} else if let Some(pos) = output_commits.get(&input.commitment()) {
					if insert_pos.is_some() {
						is_rejected = true;
						continue;
					} else {
						insert_pos = Some(*pos);
					}
				}
			}
			if is_rejected {
				for out in entry.tx.outputs() {
					rejected.insert(out.commitment());
				}
				continue;
			}
			match insert_pos {
				None => {
					insert_pos = Some(tx_buckets.len());
					tx_buckets.push(Bucket::new(entry.tx.clone(), tx_buckets.len()));
				}
				Some(pos) => {
					let bucket = &tx_buckets[pos];
					if let Ok(new_bucket) = bucket.aggregate_with_tx(entry.tx.clone(), weighting) {
						if new_bucket.fee_rate >= bucket.fee_rate {
							tx_buckets[pos] = new_bucket;
						} else {
							tx_buckets.push(Bucket::new(entry.tx.clone(), tx_buckets.len()));
						}
					} else {
						is_rejected = true;
					}
				}
			}
			if is_rejected {
				for out in entry.tx.outputs() {
					rejected.insert(out.commitment());
				}
			} else if let Some(insert_pos) = insert_pos {
				for out in entry.tx.outputs() {
					output_commits.insert(out.commitment(), insert_pos);
				}
			}
		}
		tx_buckets.sort_unstable_by_key(|x| (Reverse(x.fee_rate), x.age_idx));
		tx_buckets.into_iter().flat_map(|x| x.raw_txs).collect()
	}

	pub fn find_matching_transactions(&self, kernels: &[TxKernel]) -> Vec<Transaction> {
		let kernel_set = kernels.iter().collect::<HashSet<_>>();
		let mut found_txs = vec![];
		for entry in &self.entries {
			let entry_kernel_set = entry.tx.kernels().iter().collect::<HashSet<_>>();
			if entry_kernel_set.is_subset(&kernel_set) {
				found_txs.push(entry.tx.clone());
			}
		}
		found_txs
	}

	pub fn reconcile_block(&mut self, block: &Block) {
		let block_inputs: Vec<_> = block.inputs().into();
		self.entries.retain(|x| {
			let tx_inputs: Vec<_> = x.tx.inputs().into();
			!x.tx.kernels().iter().any(|y| block.kernels().contains(y))
				&& !tx_inputs.iter().any(|y| block_inputs.contains(y))
		});
	}

	pub fn size(&self) -> usize {
		self.entries.len()
	}

	pub fn kernel_count(&self) -> usize {
		self.entries.iter().map(|x| x.tx.kernels().len()).sum()
	}

	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}
}

struct Bucket {
	raw_txs: Vec<Transaction>,
	fee_rate: u64,
	age_idx: usize,
}

impl Bucket {
	fn new(tx: Transaction, age_idx: usize) -> Bucket {
		Bucket {
			fee_rate: tx.fee_rate(),
			raw_txs: vec![tx],
			age_idx,
		}
	}

	fn aggregate_with_tx(
		&self,
		new_tx: Transaction,
		weighting: Weighting,
	) -> Result<Bucket, PoolError> {
		let mut raw_txs = self.raw_txs.clone();
		raw_txs.push(new_tx);
		let agg_tx = transaction::aggregate(&raw_txs)?;
		agg_tx.validate(weighting)?;
		Ok(Bucket {
			fee_rate: agg_tx.fee_rate(),
			raw_txs: raw_txs,
			age_idx: self.age_idx,
		})
	}
}

pub type ServerTxPool = TransactionPool<PoolToNetAdapterAlt, PoolToChainAdapter>;
