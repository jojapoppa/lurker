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

use bincode;
use chrono::prelude::{DateTime, Utc};
use grin_chain::txhashset::BitmapChunk;
use grin_core::consensus::Difficulty;
use grin_core::core::pmmr::segment::{Segment, SegmentIdentifier};
use grin_core::core::transaction::TxKernel;
use grin_p2p::types::{NetAdapter, PeerAddr, PeerInfo, ReasonForBan, TxHashSetRead};
use grin_p2p::{ChainAdapter, Peers};
use grin_pool::{DandelionAdapter, PoolToChainAdapter, PoolToNetAdapterAlt, ServerTxPool};
use grin_util::secp::pedersen::RangeProof;
use log::{error, trace, warn};
use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::thread;

use crate::chain;
use crate::chain::{Options, SyncState};
use crate::common::hooks::NetEvents;
use crate::common::types::ServerConfig;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::{
	Block, BlockHeader, BlockSums, CompactBlock, Inputs, OutputIdentifier, Transaction,
};
use crate::pool::{
	BlockChain, Pool, PoolAdapter, PoolEntry, PoolError, PoolToNetMessages, TxSource,
};
use crate::util::{OneTime, RwLock, StopState};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use yggdrasilctl::Endpoint;

// Newtype to wrap ServerTxPool with an extra Arc
#[derive(Clone)]
pub struct DandelionTxPool(pub Arc<ServerTxPool>);

impl DandelionTxPool {
	pub fn inner(&self) -> ServerTxPool {
		Arc::clone(&self.0)
	}
}

#[derive(Clone)]
pub struct ChainToPoolAndNetAdapter {
	chain: OneTime<Weak<chain::Chain>>,
	pool: OneTime<Weak<DandelionTxPool>>,
	peers: Option<Arc<Peers>>,
}

impl ChainToPoolAndNetAdapter {
	/// Create a new combined adapter
	pub fn new(chain: Arc<chain::Chain>, tx_pool: DandelionTxPool) -> ChainToPoolAndNetAdapter {
		let chain_to_pool_and_net = ChainToPoolAndNetAdapter {
			chain: OneTime::new(),
			pool: OneTime::new(),
			peers: None,
		};
		chain_to_pool_and_net.chain.init(Arc::downgrade(&chain));
		let downgraded: Weak<DandelionTxPool> = Arc::downgrade(&Arc::new(tx_pool));
		chain_to_pool_and_net.pool.init(downgraded);
		chain_to_pool_and_net
	}

	pub fn init(&self, peers: Arc<Peers>) {
		self.peers = Some(peers);
	}
}

impl BlockChain for ChainToPoolAndNetAdapter {
	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.head_header()
			.map_err(|_| PoolError::Other("failed to get head_header".to_string()))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_block_header(hash)
			.map_err(|_| PoolError::Other("failed to get block_header".to_string()))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_block_sums(hash)
			.map_err(|_| PoolError::Other("failed to get block_sums".to_string()))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.validate_tx(tx)
			.map_err(|_| PoolError::Other("failed to validate tx".to_string()))
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.validate_inputs(inputs)
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|_| PoolError::Other("failed to validate inputs".to_string()))
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.verify_coinbase_maturity(inputs)
			.map_err(|_| PoolError::ImmatureCoinbase)
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.verify_tx_lock_height(tx)
			.map_err(|_| PoolError::ImmatureTransaction)
	}
}

impl grin_p2p::BlockChain for ChainToPoolAndNetAdapter {
	fn chain_head(&self) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.head_header()
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block(&self, hash: &Hash) -> Result<Block, grin_p2p::Error> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_block(hash)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_block_header(hash)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_header_by_height(height)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block_id_by_height(&self, height: u64) -> Result<Hash, grin_p2p::Error> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade chain ref")
			.get_header_by_height(height)
			.map(|h| h.hash())
			.map_err(|e| grin_p2p::Error::Chain(e))
	}
}

impl PoolToNetMessages for ChainToPoolAndNetAdapter {
	fn tx_received(&self, peer: &PeerInfo, tx: Transaction, header: &BlockHeader) {
		let tx_pool = self
			.pool
			.borrow()
			.upgrade()
			.expect("Failed to upgrade pool ref")
			.inner();
		let peer = peer.clone();
		let header = header.clone();
		thread::spawn(move || {
			// Acquire the transaction pool lock
			let mut lock = tx_pool.write();
			let entry = PoolEntry {
				src: TxSource::Peer(peer.addr.0),
				tx,
				tx_at: Utc::now(),
			};
			let res = lock.add_to_pool(entry.src, entry.tx, false, &header);
			if let Err(e) = res {
				warn!("Tx rejected from {:?}", peer);
			}
		});
	}
}

impl DandelionAdapter for ChainToPoolAndNetAdapter {
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

pub struct NetToChainAdapter {
	chain: Arc<chain::Chain>,
	sync_state: Arc<SyncState>,
	tx_pool: ServerTxPool,
	config: ServerConfig,
	net_hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	peers: Option<Arc<Peers>>,
}

impl NetToChainAdapter {
	/// Create a new network adapter
	pub fn new(
		sync_state: Arc<SyncState>,
		chain: Arc<chain::Chain>,
		tx_pool: ServerTxPool,
		config: ServerConfig,
		net_hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	) -> NetToChainAdapter {
		NetToChainAdapter {
			chain,
			sync_state,
			tx_pool,
			config,
			net_hooks,
			peers: None,
		}
	}

	pub fn init(&mut self, peers: Arc<Peers>) {
		self.peers = Some(peers);
	}
}

impl grin_p2p::BlockChain for NetToChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.head_header()
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block(&self, hash: &Hash) -> Result<Block, grin_p2p::Error> {
		self.chain
			.get_block(hash)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.get_block_header(hash)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain
			.get_header_by_height(height)
			.map_err(|e| grin_p2p::Error::Chain(e))
	}

	fn get_block_id_by_height(&self, height: u64) -> Result<Hash, grin_p2p::Error> {
		self.chain
			.get_header_by_height(height)
			.map(|h| h.hash())
			.map_err(|e| grin_p2p::Error::Chain(e))
	}
}

impl PoolToNetMessages for NetToChainAdapter {
	fn tx_received(&self, peer: &PeerInfo, tx: Transaction, header: &BlockHeader) {
		let tx_pool = self.tx_pool.clone();
		let peer = peer.clone();
		let header = header.clone();
		thread::spawn(move || {
			let mut lock = tx_pool.write();
			let entry = PoolEntry {
				src: TxSource::Peer(peer.addr.0),
				tx,
				tx_at: Utc::now(),
			};
			let res = lock.add_to_pool(entry.src, entry.tx, false, &header);
			if let Err(e) = res {
				warn!("Tx rejected from {:?}", peer);
			}
		});
	}
}

impl ChainAdapter for NetToChainAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
		self.chain.head().map(|tip| tip.total_difficulty)
	}

	fn total_height(&self) -> Result<u64, chain::Error> {
		self.chain.head().map(|tip| tip.height)
	}

	fn transaction_received(&self, tx: Transaction, stem: bool) -> Result<bool, chain::Error> {
		let mut lock = self.tx_pool.write();
		let header = self.chain.head_header()?;
		let entry = PoolEntry {
			src: TxSource::Broadcast,
			tx,
			tx_at: Utc::now(),
		};
		lock.add_to_pool(entry.src, entry.tx, stem, &header)
			.map_err(|e| chain::Error::Other(format!("failed to add transaction to pool: {}", e)))
			.map(|_| true)
	}

	fn get_transaction(&self, kernel_hash: Hash) -> Option<Transaction> {
		self.tx_pool.read().get_transaction(&kernel_hash)
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		Ok(self
			.tx_pool
			.read()
			.tx_kernel_received(&kernel_hash, peer_info)
			.is_some())
	}

	fn block_received(
		&self,
		b: Block,
		peer_info: &PeerInfo,
		opts: Options,
	) -> Result<bool, chain::Error> {
		self.chain
			.process_block(b, opts)
			.map(|opt_tip| opt_tip.is_some())
			.map_err(|e| chain::Error::Other(format!("block processing failed: {}", e)))
	}

	fn compact_block_received(
		&self,
		cb: CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.chain
			.process_compact_block(cb, peer_info)
			.map_err(|e| chain::Error::Other(format!("compact block processing failed: {}", e)))
	}

	fn header_received(&self, bh: BlockHeader, peer_info: &PeerInfo) -> Result<bool, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.header_received(bh, peer_info)
		} else {
			Err(chain::Error::Other(
				"No peers available for header_received".to_string(),
			))
		}
	}

	fn headers_received(
		&self,
		headers: &[BlockHeader],
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.chain
			.process_block_headers(headers, peer_info)
			.map_err(|e| chain::Error::Other(format!("headers processing failed: {}", e)))
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<BlockHeader>, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.locate_headers(locator)
		} else {
			Err(chain::Error::Other(
				"No peers available for locate_headers".to_string(),
			))
		}
	}

	fn get_block(&self, h: Hash, _peer_info: &PeerInfo) -> Option<Block> {
		self.chain.get_block(&h).ok()
	}

	fn txhashset_read(&self, h: Hash) -> Option<TxHashSetRead> {
		self.chain.txhashset_read(h).ok()
	}

	fn txhashset_archive_header(&self) -> Result<BlockHeader, chain::Error> {
		self.chain.txhashset_archive_header()
	}

	fn txhashset_receive_ready(&self) -> bool {
		self.chain.txhashset_receive_ready()
	}

	fn txhashset_download_update(
		&self,
		start_time: DateTime<Utc>,
		downloaded_size: u64,
		total_size: u64,
	) -> bool {
		self.chain
			.txhashset_download_update(start_time, downloaded_size, total_size)
	}

	fn txhashset_write(
		&self,
		h: Hash,
		txhashset_data: File,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.chain.txhashset_write(h, txhashset_data, peer_info)
	}

	fn get_tmp_dir(&self) -> PathBuf {
		self.chain.get_tmp_dir()
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> PathBuf {
		self.chain.get_tmpfile_pathname(tmpfile_name)
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.get_kernel_segment(hash, id)
		} else {
			Err(chain::Error::Other(
				"No peers available for kernel segment".to_string(),
			))
		}
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<(Segment<BitmapChunk>, Hash), chain::Error> {
		if let Some(peers) = &self.peers {
			peers.get_bitmap_segment(hash, id)
		} else {
			Err(chain::Error::Other(
				"No peers available for bitmap segment".to_string(),
			))
		}
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<(Segment<OutputIdentifier>, Hash), chain::Error> {
		if let Some(peers) = &self.peers {
			peers.get_output_segment(hash, id)
		} else {
			Err(chain::Error::Other(
				"No peers available for output segment".to_string(),
			))
		}
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.get_rangeproof_segment(hash, id)
		} else {
			Err(chain::Error::Other(
				"No peers available for rangeproof segment".to_string(),
			))
		}
	}

	fn receive_bitmap_segment(
		&self,
		block_hash: Hash,
		output_root: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<bool, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.receive_bitmap_segment(block_hash, output_root, segment)
		} else {
			Err(chain::Error::Other(
				"No peers available for bitmap segment".to_string(),
			))
		}
	}

	fn receive_output_segment(
		&self,
		block_hash: Hash,
		bitmap_root: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<bool, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.receive_output_segment(block_hash, bitmap_root, segment)
		} else {
			Err(chain::Error::Other(
				"No peers available for output segment".to_string(),
			))
		}
	}

	fn receive_rangeproof_segment(
		&self,
		block_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<bool, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.receive_rangeproof_segment(block_hash, segment)
		} else {
			Err(chain::Error::Other(
				"No peers available for rangeproof segment".to_string(),
			))
		}
	}

	fn receive_kernel_segment(
		&self,
		block_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<bool, chain::Error> {
		if let Some(peers) = &self.peers {
			peers.receive_kernel_segment(block_hash, segment)
		} else {
			Err(chain::Error::Other(
				"No peers available for kernel segment".to_string(),
			))
		}
	}
}

impl NetAdapter for NetToChainAdapter {
	fn find_peer_addrs(&self, capab: grin_p2p::Capabilities) -> Vec<PeerAddr> {
		if let Some(peers) = &self.peers {
			peers.find_peer_addrs(capab)
		} else {
			vec![]
		}
	}

	fn peer_addrs_received(&self, addrs: Vec<PeerAddr>) {
		if let Some(peers) = &self.peers {
			peers.peer_addrs_received(addrs);
		}
	}

	fn peer_difficulty(&self, addr: PeerAddr, diff: Difficulty, height: u64) {
		if let Some(peers) = &self.peers {
			peers.peer_difficulty(addr, diff, height);
		}
	}

	fn is_banned(&self, addr: PeerAddr) -> bool {
		if let Some(peers) = &self.peers {
			peers.is_banned(addr)
		} else {
			false
		}
	}
}
