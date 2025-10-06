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
use crate::core::core::hash::Hash;
use crate::core::core::{Block, BlockHeader, Transaction};
use crate::p2p::{self, PeerInfo, Peers};
use crate::pool::{BlockChain, PoolAdapter, PoolEntry, PoolError};
use grin_pool::{DandelionAdapter, PoolToChainAdapter, PoolToNetAdapterAlt, ServerTxPool};
use grin_util::RwLock;
use rand::seq::IteratorRandom;
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
	fn block_accepted(&self, block: &Block, status: p2p::BlockStatus, opts: p2p::Options) {
		let mut pool = self.pool.write();
		if let Err(e) = pool.reconcile_block(block) {
			warn!("Pool failed to reconcile block: {:?}", e);
		}
		// Additional logic for block acceptance
	}

	fn check_txhashset(&self, header: &BlockHeader) -> bool {
		// Placeholder for txhashset validation
		true
	}

	fn get_transaction(&self, kernel_hash: Hash) -> Option<Transaction> {
		let pool = self.pool.read();
		pool.retrieve_tx_by_kernel_hash(kernel_hash)
	}

	fn tx_kernel_received(&self, kernel_hash: Hash, peer_info: &PeerInfo) -> bool {
		let pool = self.pool.read();
		pool.tx_kernel_received(&kernel_hash, peer_info).is_some()
	}

	fn transaction_received(&self, tx: Transaction, stem: bool) -> bool {
		let header = match self.chain.head_header() {
			Ok(header) => header,
			Err(e) => {
				warn!("Failed to get chain head: {:?}", e);
				return false;
			}
		};

		let mut pool = self.pool.write();
		let source = crate::pool::TxSource::Peer(peer_info.addr.0);
		pool.add_to_pool(source, tx, stem, &header).is_ok()
	}

	fn compact_block_received(&self, cb: p2p::types::CompactBlock, peer_info: &PeerInfo) -> bool {
		let header = match self.chain.head_header() {
			Ok(header) => header,
			Err(e) => {
				warn!("Failed to get chain head: {:?}", e);
				return false;
			}
		};

		let (txs, missing) = {
			let pool = self.pool.read();
			pool.retrieve_transactions(cb.hash(), cb.nonce, &cb.kern_ids)
		};

		// Placeholder for compact block handling
		true
	}
}

impl p2p::ChainValidationAdapter for ChainToPoolAndNetAdapter {
	fn reset_validation(&self) {
		// Placeholder for validation reset
	}

	fn check_block_validation(&self, block: &Block, peer: &PeerInfo) -> bool {
		// Placeholder for block validation
		true
	}
}

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
