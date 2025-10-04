// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use grin_p2p::types::{PeerInfo, ReasonForBan};
use log::{error, warn};
use std::sync::{Arc, RwLock, Weak};
use std::thread;

use crate::chain;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::{Block, BlockHeader, BlockSums, Inputs, OutputIdentifier, Transaction};
use crate::pool::{
	BlockChain, Pool, PoolAdapter, PoolEntry, PoolError, PoolToNetMessages, TxSource,
};
use crate::util::{OneTime, StopState};
use crate::ServerTxPool;

/// Implements the view of the chain required by the TransactionPool to
/// operate. Mostly needed to break any direct lifecycle or implementation
/// dependency between the pool and the chain.
#[derive(Clone)]
pub struct PoolToChainAdapter {
	chain: OneTime<Weak<chain::Chain>>,
}

impl PoolToChainAdapter {
	/// Create a new pool adapter
	pub fn new() -> PoolToChainAdapter {
		PoolToChainAdapter {
			chain: OneTime::new(),
		}
	}

	/// Set the pool adapter's chain. Should only be called once.
	pub fn set_chain(&self, chain_ref: Arc<chain::Chain>) {
		self.chain.init(Arc::downgrade(&chain_ref));
	}

	fn chain(&self) -> Arc<chain::Chain> {
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
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|_| PoolError::Other("failed to validate inputs".to_string()))
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

/// Adapter between the network and the transaction pool.
#[derive(Clone)]
pub struct PoolToNetAdapter {
	tx_pool: OneTime<Weak<RwLock<ServerTxPool>>>,
}

impl PoolToNetAdapter {
	/// Create a new network adapter
	pub fn new() -> PoolToNetAdapter {
		PoolToNetAdapter {
			tx_pool: OneTime::new(),
		}
	}

	/// Set the pool adapter's tx_pool. Should only be called once.
	pub fn set_tx_pool(&self, tx_pool_ref: Arc<RwLock<ServerTxPool>>) {
		self.tx_pool.init(Arc::downgrade(&tx_pool_ref));
	}

	fn tx_pool(&self) -> Arc<RwLock<ServerTxPool>> {
		self.tx_pool
			.borrow()
			.upgrade()
			.expect("Failed to upgrade the weak ref to our tx_pool.")
	}
}

impl PoolToNetMessages for PoolToNetAdapter {
	fn tx_received(&self, peer: &PeerInfo, tx: Transaction, header: &BlockHeader) {
		let tx_pool = self.tx_pool();
		let peer = peer.clone();
		let header = header.clone();
		thread::spawn(move || match tx_pool.write() {
			Ok(arc_guard) => match arc_guard.write() {
				Ok(mut tx_pool_lock) => {
					let res =
						tx_pool_lock.add_to_pool(TxSource::Peer(peer.addr), tx, true, &header);
					if let Err(e) = res {
						warn!("Tx rejected from {}: {:?}", peer, e);
					}
				}
				Err(e) => {
					warn!("Failed to acquire inner tx_pool lock: {:?}", e);
				}
			},
			Err(e) => {
				warn!("Failed to acquire outer tx_pool lock: {:?}", e);
			}
		});
	}
}

impl PoolAdapter for PoolToNetAdapter {
	fn tx_accepted(&self, entry: &PoolEntry) {
		// Broadcast the accepted tx to peers (fluff phase).
		// In full impl, send to connected peers via P2P (e.g., Yggdrasil overlay).
		warn!("tx_accepted: Broadcasting accepted tx {}", entry.tx.hash());
	}

	fn stem_tx_accepted(&self, entry: &PoolEntry) -> Result<(), PoolError> {
		// Relay the stem tx to the selected Dandelion peer.
		// In full impl, select Dandelion peer and send via P2P (e.g., Yggdrasil).
		warn!("stem_tx_accepted: Relaying stem tx {}", entry.tx.hash());
		Ok(())
	}
}

/// Adapter from the chain to the network.
#[derive(Clone)]
pub struct NetToChainAdapter {
	chain: Arc<chain::Chain>,
}

impl NetToChainAdapter {
	/// Create a new network adapter
	pub fn new(chain: Arc<chain::Chain>) -> NetToChainAdapter {
		NetToChainAdapter { chain }
	}
}

impl grin_p2p::BlockChain for NetToChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.head_header().map_err(|e| {
			error!("NetToChainAdapter: failed to get head header, {}", e);
			grin_p2p::Error::Other(format!("failed to get head header, {}", e))
		})
	}

	fn get_block(&self, hash: &Hash) -> Result<Block, grin_p2p::Error> {
		self.chain.get_block(hash).map_err(|e| {
			error!("NetToChainAdapter: failed to get block {}, {}", hash, e);
			grin_p2p::Error::Other(format!("failed to get block {}, {}", hash, e))
		})
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.get_block_header(hash).map_err(|e| {
			error!("NetToChainAdapter: failed to get header {}, {}", hash, e);
			grin_p2p::Error::Other(format!("failed to get header {}, {}", hash, e))
		})
	}

	fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.get_header_by_height(height).map_err(|e| {
			error!(
				"NetToChainAdapter: failed to get header at height {}, {}",
				height, e
			);
			grin_p2p::Error::Other(format!("failed to get header at height {}, {}", height, e))
		})
	}

	fn get_block_id_by_height(&self, height: u64) -> Result<Hash, grin_p2p::Error> {
		self.chain
			.get_header_by_height(height)
			.map(|h| h.hash())
			.map_err(|e| {
				error!(
					"NetToChainAdapter: failed to get block hash at height {}, {}",
					height, e
				);
				grin_p2p::Error::Other(format!(
					"failed to get block hash at height {}, {}",
					height, e
				))
			})
	}
}

/// Combined adapter from the chain to the pool and network.
#[derive(Clone)]
pub struct ChainToPoolAndNetAdapter {
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<ServerTxPool>>,
}

impl ChainToPoolAndNetAdapter {
	/// Create a new combined adapter
	pub fn new(
		chain: Arc<chain::Chain>,
		tx_pool: Arc<RwLock<ServerTxPool>>,
	) -> ChainToPoolAndNetAdapter {
		ChainToPoolAndNetAdapter { chain, tx_pool }
	}
}

impl BlockChain for ChainToPoolAndNetAdapter {
	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.chain
			.head_header()
			.map_err(|_| PoolError::Other("failed to get head_header".to_string()))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, PoolError> {
		self.chain
			.get_block_header(hash)
			.map_err(|_| PoolError::Other("failed to get block_header".to_string()))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, PoolError> {
		self.chain
			.get_block_sums(hash)
			.map_err(|_| PoolError::Other("failed to get block_sums".to_string()))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain
			.validate_tx(tx)
			.map_err(|_| PoolError::Other("failed to validate tx".to_string()))
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
		self.chain
			.validate_inputs(inputs)
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|_| PoolError::Other("failed to validate inputs".to_string()))
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), PoolError> {
		self.chain
			.verify_coinbase_maturity(inputs)
			.map_err(|_| PoolError::ImmatureCoinbase)
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain
			.verify_tx_lock_height(tx)
			.map_err(|_| PoolError::ImmatureTransaction)
	}
}

impl grin_p2p::BlockChain for ChainToPoolAndNetAdapter {
	fn chain_head(&self) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.head_header().map_err(|e| {
			error!("ChainToPoolAndNetAdapter: failed to get head header, {}", e);
			grin_p2p::Error::Other(format!("failed to get head header, {}", e))
		})
	}

	fn get_block(&self, hash: &Hash) -> Result<Block, grin_p2p::Error> {
		self.chain.get_block(hash).map_err(|e| {
			error!(
				"ChainToPoolAndNetAdapter: failed to get block {}, {}",
				hash, e
			);
			grin_p2p::Error::Other(format!("failed to get block {}, {}", hash, e))
		})
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.get_block_header(hash).map_err(|e| {
			error!(
				"ChainToPoolAndNetAdapter: failed to get header {}, {}",
				hash, e
			);
			grin_p2p::Error::Other(format!("failed to get header {}, {}", hash, e))
		})
	}

	fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, grin_p2p::Error> {
		self.chain.get_header_by_height(height).map_err(|e| {
			error!(
				"ChainToPoolAndNetAdapter: failed to get header at height {}, {}",
				height, e
			);
			grin_p2p::Error::Other(format!("failed to get header at height {}, {}", height, e))
		})
	}

	fn get_block_id_by_height(&self, height: u64) -> Result<Hash, grin_p2p::Error> {
		self.chain
			.get_header_by_height(height)
			.map(|h| h.hash())
			.map_err(|e| {
				error!(
					"ChainToPoolAndNetAdapter: failed to get block hash at height {}, {}",
					height, e
				);
				grin_p2p::Error::Other(format!(
					"failed to get block hash at height {}, {}",
					height, e
				))
			})
	}
}

impl PoolToNetMessages for ChainToPoolAndNetAdapter {
	fn tx_received(&self, peer: &PeerInfo, tx: Transaction, header: &BlockHeader) {
		let tx_pool = self.tx_pool.clone();
		let peer = peer.clone();
		let header = header.clone();
		thread::spawn(move || match tx_pool.write() {
			Ok(arc_guard) => match arc_guard.write() {
				Ok(mut tx_pool_lock) => {
					let res =
						tx_pool_lock.add_to_pool(TxSource::Peer(peer.addr), tx, true, &header);
					if let Err(e) = res {
						warn!("Tx rejected from {}: {:?}", peer, e);
					}
				}
				Err(e) => {
					warn!("Failed to acquire inner tx_pool lock: {:?}", e);
				}
			},
			Err(e) => {
				warn!("Failed to acquire outer tx_pool lock: {:?}", e);
			}
		});
	}
}

/// Dandelion relay adapter trait.
pub trait DandelionAdapter {
	/// Selects a peer randomly from the peers that support dandelion.
	fn select_dandelion_peer(&self) -> Option<PeerInfo>;

	/// Selects a peer randomly from the peers that support dandelion++.
	fn select_dandelionpp_peer(&self) -> Option<PeerInfo>;

	/// Selects a peer to send the transaction to the next hop.
	fn select_output_peer(&self, input_peer: &PeerInfo, is_stem: bool) -> Option<PeerInfo>;

	/// Whether we are currently in stem phase.
	fn is_stem(&self) -> bool;

	/// Whether the current epoch has expired.
	fn is_expired(&self) -> bool;

	/// Advance to the next epoch.
	fn next_epoch(&self);
}

/// Blanket impl to allow using Arc<dyn DandelionAdapter>.
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
