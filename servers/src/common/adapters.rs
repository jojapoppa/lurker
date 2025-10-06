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
use chrono::Utc;
use grin_p2p::types::{PeerInfo, ReasonForBan};
use grin_p2p::Peers;
use log::{error, trace, warn};
use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};
use std::sync::{Arc, Weak};
use std::thread;

use crate::chain;
use crate::chain::SyncState;
use crate::common::hooks::NetEvents;
use crate::common::types::ServerConfig;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::{Block, BlockHeader, BlockSums, Inputs, OutputIdentifier, Transaction};
use crate::pool;
use crate::pool::{
	BlockChain, Pool, PoolAdapter, PoolEntry, PoolError, PoolToNetMessages, TxSource,
};
use crate::util::{OneTime, RwLock, StopState};
use crate::ServerTxPool;

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

/// To break the self-reference, we use PoolToNetAdapterAlt in the generic for TransactionPool.
#[derive(Clone)]
pub struct PoolToNetAdapter {
	tx_pool: OneTime<Weak<DandelionTxPool>>,
	peers: Option<Arc<Peers>>,
}

/// Type alias to break the cycle
type PoolToNetAdapterAlt = PoolToNetAdapter;

impl PoolToNetAdapter {
	/// Create a new network adapter
	pub fn new() -> PoolToNetAdapter {
		PoolToNetAdapter {
			tx_pool: OneTime::new(),
			peers: None,
		}
	}

	/// Set the pool adapter's tx_pool. Should only be called once.
	pub fn set_tx_pool(&self, tx_pool_ref: DandelionTxPool) {
		let weak_ref: Weak<DandelionTxPool> = Arc::downgrade(&Arc::new(tx_pool_ref));
		self.tx_pool.init(weak_ref);
	}

	/// Initialize with peers
	pub fn init(&self, peers: Arc<Peers>) {
		self.peers = Some(peers);
	}

	/// Placeholder dummy adapter
	pub fn dummy() -> PoolToNetAdapter {
		PoolToNetAdapter {
			tx_pool: OneTime::new(),
			peers: None,
		}
	}

	fn tx_pool(&self) -> ServerTxPool {
		self.tx_pool
			.borrow()
			.upgrade()
			.expect("Failed to upgrade the weak ref to our tx_pool.")
			.inner()
	}
}

impl PoolToNetMessages for PoolToNetAdapter {
	fn tx_received(&self, peer: &PeerInfo, tx: Transaction, header: &BlockHeader) {
		let tx_pool = self.tx_pool();
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

impl PoolAdapter for PoolToNetAdapter {
	fn tx_accepted(&self, entry: &PoolEntry) {
		let tx = entry.tx.clone();
		let peers = self.peers.as_ref().map(|p| p.iter().connected());
		let rt = Runtime::new().expect("Failed to create Tokio runtime");
		rt.block_on(async {
			let socket_path = "/run/yggdrasil.sock";
			match UnixStream::connect(socket_path).await {
				Ok(socket) => {
					let mut endpoint = Endpoint::attach(socket).await;
					let tx_bytes = match bincode::serialize(&tx) {
						Ok(bytes) => bytes,
						Err(e) => {
							warn!("Failed to serialize tx {}: {:?}", tx.hash(), e);
							return;
						}
					};
					if let Some(peers_iter) = peers {
						let count = peers_iter.count();
						for peer in peers_iter {
							let addr = peer.info.addr.0.to_string();
							if let Err(e) = endpoint.add_peer(format!("tcp://{}", addr), None).await
							{
								warn!("Failed to add Yggdrasil peer {}: {:?}", addr, e);
								continue;
							}
							let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
								Ok(socket) => socket,
								Err(e) => {
									warn!("Failed to bind UDP socket for peer {}: {:?}", addr, e);
									continue;
								}
							};
							if let Err(e) = socket.connect(peer.info.addr.0).await {
								warn!("Failed to connect to Yggdrasil peer {}: {:?}", addr, e);
								continue;
							}
							if let Err(e) = socket.send(&tx_bytes).await {
								warn!("Failed to send tx {} to peer {}: {:?}", tx.hash(), addr, e);
								continue;
							}
						}
						warn!("Broadcasting tx {} to {} Yggdrasil peers", tx.hash(), count);
					}
				}
				Err(e) => {
					warn!("Failed to connect to Yggdrasil socket: {:?}", e);
				}
			}
		});
	}

	fn stem_tx_accepted(&self, entry: &PoolEntry) -> Result<(), PoolError> {
		let tx = entry.tx.clone();
		let peers = self.peers.as_ref().map(|p| p.iter().connected());
		let rt = Runtime::new().map_err(|e| PoolError::Other(e.to_string()))?;
		rt.block_on(async {
			let socket_path = "/run/yggdrasil.sock";
			match UnixStream::connect(socket_path).await {
				Ok(socket) => {
					let mut endpoint = Endpoint::attach(socket).await;
					let dandelion_peer = peers
						.and_then(|p| p.choose_random())
						.ok_or_else(|| PoolError::Other("No peers available".to_string()))?;
					let socket_addr = dandelion_peer.info.addr.0;
					let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
						.await
						.map_err(|e| PoolError::Other(e.to_string()))?;
					socket
						.connect(socket_addr)
						.await
						.map_err(|e| PoolError::Other(e.to_string()))?;
					let tx_bytes =
						bincode::serialize(&tx).map_err(|e| PoolError::Other(e.to_string()))?;
					socket
						.send(&tx_bytes)
						.await
						.map_err(|e| PoolError::Other(e.to_string()))?;
					warn!(
						"Relayed stem tx {} to Yggdrasil peer {}",
						tx.hash(),
						socket_addr
					);
					Ok(())
				}
				Err(e) => {
					warn!("Failed to connect to Yggdrasil socket: {:?}", e);
					Err(PoolError::Other(e.to_string()))
				}
			}
		})
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
				p.iter()
					.connected()
					.filter(|p| p.info.addr != input_peer.addr)
					.choose_random()
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
				p.iter()
					.connected()
					.filter(|p| p.info.addr != input_peer.addr)
					.choose_random()
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

// Adapter from the chain to the network.
#[derive(Clone)]
pub struct NetToChainAdapter {
	chain: Arc<chain::Chain>,
	sync_state: Arc<SyncState>,
	tx_pool: Arc<RwLock<ServerTxPool>>,
	config: ServerConfig,
	net_hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	peers: Option<Arc<Peers>>,
}

impl NetToChainAdapter {
	/// Create a new network adapter
	pub fn new(
		sync_state: Arc<SyncState>,
		chain: Arc<chain::Chain>,
		tx_pool: Arc<RwLock<ServerTxPool>>,
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

/// Dandelion relay adapter trait.
pub trait DandelionAdapter: Send + Sync {
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
