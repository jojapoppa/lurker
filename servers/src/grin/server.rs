use crate::api;
use crate::api::TLSConfig;
use crate::chain::{SyncState, SyncStatus};
use crate::common::hooks::init_net_hooks;
use crate::common::types::Error;
use crate::common::{adapters, stats};
use crate::core::core::hash::Hashed;
use crate::core::core::{Block, Transaction};
use crate::core::genesis;
use crate::core::global;
use crate::core::pow;
use crate::core::ser::ProtocolVersion;
use crate::grin::dandelion_monitor;
use crate::grin::seed;
use crate::grin::sync;
use crate::p2p::Capabilities;
use crate::util::file::get_first_line;
use crate::util::StopState;
use grin_util::RwLock;
use std::sync::Arc;
use std::{fs::File, io, thread};
use tokio::sync::oneshot;

pub type ServerTxPool =
	Arc<RwLock<pool::TransactionPool<adapters::PoolToChainAdapter, adapters::PoolToNetAdapter>>>;

pub struct Server {
	pub config: types::ServerConfig,
	pub p2p: Arc<p2p::Server>,
	pub chain: Arc<chain::Chain>,
	pub tx_pool: ServerTxPool,
	pub sync_state: Arc<SyncState>,
	pub state_info: stats::ServerStateInfo,
	pub stop_state: Arc<StopState>,
	pub lock_file: File,
	pub connect_thread: Option<thread::JoinHandle<()>>,
	pub sync_thread: thread::JoinHandle<()>,
	pub dandelion_thread: thread::JoinHandle<()>,
}

impl Server {
	fn one_grin_at_a_time(config: &types::ServerConfig) -> Result<File, Error> {
		Ok(File::create(&config.db_root.join("grin.lock"))?)
	}

	pub fn new(
		config: types::ServerConfig,
		stop_state: Option<Arc<StopState>>,
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<Server, Error> {
		// Obtain our lock_file or fail immediately with an error.
		let lock_file = Server::one_grin_at_a_time(&config)?;

		// Defaults to None (optional) in config file.
		// This translates to false here.
		let archive_mode = config.archive_mode.unwrap_or(false);

		let stop_state = stop_state.unwrap_or_else(|| Arc::new(StopState::new()));

		let pool_adapter = Arc::new(adapters::PoolToChainAdapter::new());
		let pool_net_adapter = Arc::new(adapters::PoolToNetAdapter::new());
		let tx_pool = Arc::new(RwLock::new(pool::TransactionPool::new(
			config.pool_config.clone(),
			pool_adapter.clone(),
			pool_net_adapter.clone(),
		)));
		pool_net_adapter.set_tx_pool(adapters::DandelionTxPool(Arc::new(tx_pool.clone())));

		let sync_state = Arc::new(SyncState::new());

		let genesis = match config.chain_type {
			global::ChainTypes::AutomatedTesting => pow::mine_genesis_block().unwrap(),
			global::ChainTypes::UserTesting => pow::mine_genesis_block().unwrap(),
			global::ChainTypes::Testnet => genesis::genesis_test(),
			global::ChainTypes::Mainnet => genesis::genesis_main(),
		};

		info!("Starting server, genesis block: {}", genesis.hash());

		let shared_chain = Arc::new(chain::Chain::init(
			config.db_root.clone(),
			pool_adapter.clone(),
			genesis.clone(),
			pow::verify_size,
			archive_mode,
		)?);

		pool_adapter.set_chain(shared_chain.clone());

		let chain_adapter = Arc::new(adapters::ChainToPoolAndNetAdapter::new(
			shared_chain.clone(),
			adapters::DandelionTxPool(Arc::new(tx_pool.clone())),
		));

		let net_adapter = Arc::new(adapters::NetToChainAdapter::new(
			sync_state.clone(),
			shared_chain.clone(),
			tx_pool.clone(),
			config.clone(),
			init_net_hooks(&config),
		));

		let capabilities = if archive_mode {
			Capabilities::default() | Capabilities::BLOCK_HIST
		} else {
			Capabilities::default()
		};
		debug!("Capabilities: {:?}", capabilities);

		let p2p_server = Arc::new(p2p::Server::new(
			&config.db_root,
			capabilities,
			config.p2p_config.clone(),
			net_adapter.clone(),
			genesis.hash(),
			stop_state.clone(),
		)?);

		chain_adapter.init(p2p_server.peers.clone());
		pool_net_adapter.init(p2p_server.peers.clone());
		net_adapter.init(p2p_server.peers.clone());

		let mut connect_thread = None;

		if config.p2p_config.seeding_type != p2p::Seeding::Programmatic {
			let seed_list = match config.p2p_config.seeding_type {
				p2p::Seeding::None => {
					warn!("No seed configured, will stay solo until connected to");
					seed::predefined_seeds(vec![])
				}
				p2p::Seeding::List => match &config.p2p_config.seeds {
					Some(seeds) => seed::predefined_seeds(seeds.peers.clone()),
					None => {
						return Err(Error::Configuration(
							"Seeds must be configured for seeding type List".to_owned(),
						));
					}
				},
				p2p::Seeding::DNSSeed => seed::default_dns_seeds(),
				_ => unreachable!(),
			};

			connect_thread = Some(seed::connect_and_monitor(
				p2p_server.clone(),
				seed_list,
				config.p2p_config.clone(),
				stop_state.clone(),
			)?);
		}

		let skip_sync_wait = config.skip_sync_wait.unwrap_or(false);
		sync_state.update(SyncStatus::AwaitingPeers(!skip_sync_wait));

		let sync_thread = sync::run_sync(
			sync_state.clone(),
			p2p_server.peers.clone(),
			shared_chain.clone(),
			stop_state.clone(),
		)?;

		let p2p_inner = p2p_server.clone();
		thread::Builder::new()
			.name("p2p-server".to_string())
			.spawn(move || {
				if let Err(e) = p2p_inner.listen() {
					error!("P2P server failed with error: {:?}", e);
				}
			})?;

		info!("Starting rest apis at: {}", &config.api_http_addr);
		let api_secret = get_first_line(config.api_secret_path.clone());
		let foreign_api_secret = get_first_line(config.foreign_api_secret_path.clone());
		let tls_conf = match config.tls_certificate_file.clone() {
			None => None,
			Some(file) => {
				let key = config.tls_certificate_key.clone().ok_or_else(|| {
					Error::ArgumentError("Private key for certificate is not set".to_string())
				})?;
				Some(TLSConfig::new(file, key))
			}
		};

		api::node_apis(
			&config.api_http_addr,
			shared_chain.clone(),
			tx_pool.clone(),
			p2p_server.peers.clone(),
			sync_state.clone(),
			api_secret,
			foreign_api_secret,
			tls_conf,
			api_chan,
			stop_state.clone(),
		)?;

		info!("Starting dandelion monitor: {}", &config.api_http_addr);
		let dandelion_thread = dandelion_monitor::monitor_transactions(
			config.dandelion_config.clone(),
			adapters::DandelionTxPool(Arc::new(tx_pool.clone())),
			pool_net_adapter,
			stop_state.clone(),
		)?;

		warn!("Grin server started.");
		Ok(Server {
			config,
			p2p: p2p_server,
			chain: shared_chain,
			tx_pool,
			sync_state,
			state_info: stats::ServerStateInfo {
				..Default::default()
			},
			stop_state,
			lock_file,
			connect_thread,
			sync_thread,
			dandelion_thread,
		})
	}
}
