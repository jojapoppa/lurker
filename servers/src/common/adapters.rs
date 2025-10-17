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

//! Adapters to interface between pool, chain, and p2p layers.

use crate::chain::types::NoopAdapter;
use crate::core::consensus::Difficulty;
use crate::core::core::hash::Hash;
use crate::core::core::{
	Block, BlockHeader, CompactBlock, OutputIdentifier, Segment, SegmentIdentifier, Transaction,
	TxKernel,
};
use crate::p2p::{self, PeerInfo, Peers};
use crate::pool::types::DandelionConfig;
use crate::pool::{BlockChain, PoolAdapter, PoolEntry, PoolError};
use grin_pool::{DandelionAdapter, PoolToChainAdapter, PoolToNetAdapterAlt, ServerTxPool};

use crate::util::secp::pedersen::{Commitment, RangeProof};
use chrono::prelude::{DateTime, Utc};
use grin_chain::txhashset::BitmapChunk;
use grin_util::RwLock;
use rand::seq::IteratorRandom;
use std::fs::File;
use std::sync::Arc;
use std::thread;

// Adapter for chain-related operations
pub struct ChainToPoolAndNetAdapter {
	pool: Arc<RwLock<ServerTxPool>>,
	chain: Arc<crate::chain::Chain>,
}

impl ChainToPoolAndNetAdapter {
	pub fn new(pool: Arc<RwLock<ServerTxPool>>, chain: Arc<crate::chain::Chain>) -> Self {
		ChainToPoolAndNetAdapter { pool, chain }
	}
}

impl p2p::ChainAdapter for ChainToPoolAndNetAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, grin_chain::Error> {
		self.chain.head().map(|h| h.total_difficulty)
	}

	fn total_height(&self) -> Result<u64, grin_chain::Error> {
		self.chain.head().map(|h| h.height)
	}

	fn block_received(
		&self,
		block: Block,
		peer_info: &PeerInfo,
		opts: grin_chain::Options,
	) -> Result<bool, grin_chain::Error> {
		let mut pool = self.pool.write();
		if let Err(e) = pool.reconcile_block(&block) {
			warn!("Pool failed to reconcile block: {:?}", e);
			return Ok(false);
		}
		// Additional logic for block acceptance
		Ok(true)
	}

	//fn check_txhashset(&self, header: &BlockHeader) -> bool {
	//    // Placeholder for txhashset validation
	//    true
	//}

	fn get_transaction(&self, kernel_hash: Hash) -> Option<Transaction> {
		let pool = self.pool.read();
		pool.retrieve_tx_by_kernel_hash(kernel_hash)
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, grin_chain::Error> {
		let pool = self.pool.read();
		Ok((*pool).retrieve_tx_by_kernel_hash(kernel_hash).is_some())
	}

	fn transaction_received(&self, tx: Transaction, stem: bool) -> Result<bool, grin_chain::Error> {
		let header = match self.chain.head_header() {
			Ok(header) => header,
			Err(e) => {
				warn!("Failed to get chain head: {:?}", e);
				return Ok(false);
			}
		};

		let mut pool = self.pool.write();
		let source = crate::pool::TxSource::Broadcast;
		pool.add_to_pool(source, tx, stem, &header)
			.map_err(|e| grin_chain::Error::Other(e.to_string()))
	}

	fn compact_block_received(
		&self,
		cb: CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, grin_chain::Error> {
		let header = match self.chain.head_header() {
			Ok(header) => header,
			Err(e) => {
				warn!("Failed to get chain head: {:?}", e);
				return Ok(false);
			}
		};

		let (txs, missing) = {
			let pool = self.pool.read();
			pool.retrieve_transactions(cb.hash(), cb.nonce, &cb.kern_ids)
		};

		// Placeholder for compact block handling
		true
	}

	fn header_received(
		&self,
		bh: BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for header handling
		Ok(true)
	}

	fn headers_received(
		&self,
		bh: &[BlockHeader],
		peer_info: &PeerInfo,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for headers handling
		Ok(true)
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<BlockHeader>, grin_chain::Error> {
		// Placeholder for header location
		Ok(vec![])
	}

	fn get_block(&self, h: Hash, peer_info: &PeerInfo) -> Option<Block> {
		// Placeholder for block retrieval
		None
	}

	fn txhashset_read(&self, h: Hash) -> Option<p2p::types::TxHashSetRead> {
		// Placeholder for txhashset read
		None
	}

	fn txhashset_archive_header(&self) -> Result<BlockHeader, grin_chain::Error> {
		// Placeholder for txhashset archive header
		Err(p2p::Error::Internal)
	}

	fn txhashset_receive_ready(&self) -> bool {
		// Placeholder for txhashset readiness
		false
	}

	fn txhashset_download_update(
		&self,
		start_time: DateTime<Utc>,
		downloaded_size: u64,
		total_size: u64,
	) -> bool {
		// Placeholder for txhashset download update
		false
	}

	fn txhashset_write(
		&self,
		h: Hash,
		txhashset_data: File,
		peer_info: &PeerInfo,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for txhashset write
		Ok(false)
	}

	fn get_tmp_dir(&self) -> std::path::PathBuf {
		// Placeholder for tmp dir
		std::path::PathBuf::new()
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> std::path::PathBuf {
		// Placeholder for tmp file path
		std::path::PathBuf::from(tmpfile_name)
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: crate::core::core::SegmentIdentifier,
	) -> Result<Segment<TxKernel>, grin_chain::Error> {
		// Placeholder for kernel segment
		Err(p2p::Error::Internal)
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: crate::core::core::SegmentIdentifier,
	) -> Result<(Segment<BitmapChunk>, grin_core::core::hash::Hash), grin_chain::Error> {
		// Placeholder for bitmap segment
		Err(p2p::Error::Internal)
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: crate::core::core::SegmentIdentifier,
	) -> Result<(Segment<OutputIdentifier>, grin_core::core::hash::Hash), grin_chain::Error> {
		// Placeholder for output segment
		Err(p2p::Error::Internal)
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<grin_util::secp::pedersen::RangeProof>, grin_chain::Error> {
		// Placeholder for rangeproof segment reception
		Ok(false)
	}

	fn receive_bitmap_segment(
		&self,
		block_hash: Hash,
		output_root: Hash,
		segment: crate::core::core::Segment<crate::chain::txhashset::BitmapChunk>,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for bitmap segment reception
		Ok(false)
	}

	fn receive_output_segment(
		&self,
		block_hash: Hash,
		bitmap_root: Hash,
		segment: crate::core::core::Segment<OutputIdentifier>,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for output segment reception
		Ok(false)
	}

	fn receive_rangeproof_segment(
		&self,
		block_hash: Hash,
		segment: crate::core::core::Segment<RangeProof>,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for rangeproof segment reception
		Ok(false)
	}

	fn receive_kernel_segment(
		&self,
		block_hash: Hash,
		segment: crate::core::core::Segment<TxKernel>,
	) -> Result<bool, grin_chain::Error> {
		// Placeholder for kernel segment reception
		Ok(false)
	}
}

//impl p2p::ChainValidationAdapter for ChainToPoolAndNetAdapter {
//    fn reset_validation(&self) {
//        // Placeholder for validation reset
//    }
//
//    fn check_block_validation(&self, block: &Block, peer: &PeerInfo) -> bool {
//        // Placeholder for block validation
//        true
//    }
//}

// Adapter for network-related operations
pub struct NetToChainAdapter {
	chain: Arc<crate::chain::Chain>,
	peers: Arc<p2p::Peers>,
}

impl NetToChainAdapter {
	pub fn new(chain: Arc<crate::chain::Chain>, peers: Arc<p2p::Peers>) -> Self {
		NetToChainAdapter { chain, peers }
	}
}

impl PoolAdapter for NetToChainAdapter {
	fn tx_accepted(&self, _entry: &PoolEntry) {
		// Placeholder for tx accepted
	}

	fn stem_tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		// Placeholder for stem tx accepted
		Ok(())
	}
}

impl DandelionAdapter for NetToChainAdapter {
	fn select_dandelion_peer(&self) -> Option<PeerInfo> {
		self.peers
			.iter()
			.connected()
			.choose_random()
			.map(|p| p.info.clone())
	}

	fn select_dandelionpp_peer(&self) -> Option<PeerInfo> {
		self.select_dandelion_peer()
	}

	fn select_output_peer(&self, input_peer: &PeerInfo, is_stem: bool) -> Option<PeerInfo> {
		if is_stem {
			self.select_dandelion_peer()
		} else {
			self.peers
				.iter()
				.connected()
				.into_iter()
				.filter(|p| p.info.addr != input_peer.addr)
				.choose(&mut rand::thread_rng())
				.map(|p| p.info.clone())
		}
	}

	fn is_stem(&self) -> bool {
		rand::thread_rng().gen_bool(0.9)
	}

	fn is_expired(&self) -> bool {
		false
	}

	fn next_epoch(&self) {
		// No-op
	}
}
