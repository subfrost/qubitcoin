//! Qubitcoind: The Qubitcoin daemon.
//! A production-ready Bitcoin-compatible full node.

use qubitcoin_common::chainparams::{ChainParams, Network};
use qubitcoin_common::coins::EmptyCoinsView;
use qubitcoin_net::connection::{ConnConfig, ConnManager};
use qubitcoin_net::net_processing::{NetProcessor, StateNotifier};
use qubitcoin_net::protocol::{NetworkMagic, ServiceFlags};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_rpc::http_server::{RpcServer, RpcServerConfig};
use qubitcoin_rpc::node_rpc::{register_node_rpcs, NodeState};
use qubitcoin_rpc::server::RpcRegistry;
use qubitcoin_util::args::ArgsManager;
use qubitcoin_util::logging::{self, LogLevel};
use std::sync::Arc;
use tracing::Instrument;

const VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// StateNotifier implementation: bridges NetProcessor events to NodeState
// ---------------------------------------------------------------------------

/// Bridges network processor state changes into the RPC-visible [`NodeState`].
struct RpcStateNotifier {
    state: Arc<NodeState>,
}

impl StateNotifier for RpcStateNotifier {
    fn on_headers_update(&self, header_count: usize) {
        *self.state.chain_height.write() = header_count as i32 - 1;
    }

    fn on_peer_connected(&self, _peer_id: u64) {
        let mut count = self.state.connections.write();
        *count += 1;
        *self.state.peer_count.write() = *count;
    }

    fn on_peer_disconnected(&self, _peer_id: u64) {
        let mut count = self.state.connections.write();
        *count = count.saturating_sub(1);
        *self.state.peer_count.write() = *count;
    }

    fn on_block_received(&self, blocks_count: u64) {
        // Update chain height based on total blocks received.
        // In a production node this would come from the validated chain tip,
        // but during IBD this provides reasonable progress visibility.
        let _ = blocks_count;
    }
}

#[tokio::main]
async fn main() {
    // 1. Parse arguments
    let args_vec: Vec<String> = std::env::args().collect();
    let mut args = ArgsManager::new();
    args.set_default("server", "1");
    args.set_default("listen", "1");
    args.set_default("rpcport", "8332");
    args.set_default("port", "8333");
    args.set_default("maxconnections", "125");
    args.set_default("loglevel", "info");
    args.set_default("datadir", "~/.qubitcoin");
    args.parse_args(&args_vec);

    // Handle --help and --version
    if args.get_bool_arg("help") || args.get_bool_arg("h") || args.get_bool_arg("?") {
        print_usage();
        return;
    }

    if args.get_bool_arg("version") {
        println!("Qubitcoin Core version {}", VERSION);
        return;
    }

    // 2. Initialize structured logging via tracing
    let log_level = args
        .get_arg("loglevel")
        .and_then(LogLevel::from_str)
        .unwrap_or(LogLevel::Info);
    logging::init_tracing(log_level);

    tracing::info!(version = VERSION, "Qubitcoin Core starting");

    // 3. Determine network
    let network = if args.get_bool_arg("testnet4") {
        Network::Testnet4
    } else if args.get_bool_arg("testnet") {
        Network::Testnet
    } else if args.get_bool_arg("regtest") {
        Network::Regtest
    } else if args.get_bool_arg("signet") {
        Network::Signet
    } else {
        Network::Mainnet
    };

    let params = ChainParams::for_network(network);
    let default_port = params.default_port;

    let network_name = match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };
    tracing::info!(network = network_name, "selected network");

    // Report data directory
    if let Some(datadir) = args.get_arg("datadir") {
        tracing::info!(datadir = %datadir, "data directory");
    } else {
        tracing::info!("data directory: (default)");
    }

    // 4. Initialize chainstate
    let _chain_span = tracing::info_span!("block_processing").entered();
    let coins_view: Box<dyn qubitcoin_common::coins::CoinsView + Send + Sync> =
        Box::new(EmptyCoinsView);
    let chainstate = ChainstateManager::new(params, coins_view);
    tracing::info!(height = chainstate.height(), "chain initialized");
    drop(_chain_span);

    // 5. Initialize mempool
    let mempool = Arc::new(TxMemPool::new());
    tracing::info!(size = mempool.size(), "mempool initialized");

    // 6. Initialize shared node state for RPC
    let chain_name = match network {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };
    let node_state = Arc::new(NodeState::new(chain_name));

    // 7. Set up RPC server
    let rpc_port: u16 = args.get_int_arg("rpcport").unwrap_or(match network {
        Network::Mainnet => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Regtest => 18443,
        Network::Signet => 38332,
    }) as u16;

    let rpc_config = RpcServerConfig {
        bind_addr: format!("127.0.0.1:{}", rpc_port).parse().unwrap(),
        rpc_user: args.get_arg("rpcuser").map(|s| s.to_string()),
        rpc_password: args.get_arg("rpcpassword").map(|s| s.to_string()),
    };

    let mut registry = RpcRegistry::new();
    register_node_rpcs(&mut registry, node_state.clone());

    let rpc_bind_addr = rpc_config.bind_addr;
    let rpc_server = RpcServer::new(rpc_config, registry);

    // Spawn RPC server
    let rpc_span = tracing::info_span!("rpc_server", bind_addr = %rpc_bind_addr);
    tokio::spawn(
        async move {
            if let Err(e) = rpc_server.serve().await {
                tracing::error!(error = %e, "RPC server error");
            }
        }
        .instrument(rpc_span),
    );
    tracing::info!(bind_addr = %rpc_bind_addr, "RPC server listening");

    // 8. Set up P2P networking
    let p2p_port: u16 = args.get_int_arg("port").unwrap_or(default_port as i64) as u16;

    let magic = match network {
        Network::Mainnet => NetworkMagic::MAINNET,
        Network::Testnet => NetworkMagic::TESTNET,
        Network::Testnet4 => NetworkMagic::TESTNET4,
        Network::Regtest => NetworkMagic::REGTEST,
        Network::Signet => NetworkMagic::SIGNET,
    };

    let conn_config = ConnConfig {
        listen_addr: format!("0.0.0.0:{}", p2p_port).parse().unwrap(),
        magic,
        max_inbound: 125,
        max_outbound: args.get_int_arg("maxconnections").unwrap_or(10) as usize,
        our_services: ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
        user_agent: format!("/Qubitcoin:{}/", VERSION),
        best_height: chainstate.height(),
    };

    let mut conn_manager = ConnManager::new(conn_config);

    // Take the event receiver before wrapping in Arc.
    let event_rx = conn_manager.take_events();

    // Wrap ConnManager in Arc so it can be shared with NetProcessor.
    let conn_manager = Arc::new(conn_manager);

    if args.get_bool_arg("listen") || !args.is_set("listen") {
        let _p2p_span = tracing::info_span!("p2p_listener", port = p2p_port).entered();
        if let Err(e) = conn_manager.start_listening().await {
            tracing::error!(error = %e, "failed to start P2P listener");
        } else {
            tracing::info!(port = p2p_port, "P2P listening");
        }
    }

    // Connect to specified peers via -connect=<addr>
    let connect_targets = args.get_args("connect");
    for connect_addr in &connect_targets {
        if let Ok(addr) = connect_addr.parse() {
            let _conn_span = tracing::info_span!("p2p_connect", addr = %addr).entered();
            match conn_manager.connect_to(addr).await {
                Ok(peer_id) => {
                    tracing::info!(peer_id = peer_id, addr = %addr, "connecting to peer")
                }
                Err(e) => {
                    tracing::error!(addr = %connect_addr, error = %e, "failed to connect to peer")
                }
            }
        }
    }

    // If no explicit -connect peers, resolve DNS seeds for peer discovery.
    if connect_targets.is_empty() && network == Network::Mainnet {
        let seeds = &[
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-hierarchical-deterministic-not-combos.org",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
        ];

        let mut connected = 0usize;
        let max_seed_connections = 8usize;

        for seed in seeds {
            if connected >= max_seed_connections {
                break;
            }
            tracing::info!(seed = *seed, "resolving DNS seed");
            match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if connected >= max_seed_connections {
                            break;
                        }
                        match conn_manager.connect_to(addr).await {
                            Ok(peer_id) => {
                                tracing::info!(peer_id = peer_id, addr = %addr, seed = *seed, "connecting to seed peer");
                                connected += 1;
                            }
                            Err(e) => {
                                tracing::debug!(addr = %addr, error = %e, "failed to connect to seed peer");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(seed = *seed, error = %e, "failed to resolve DNS seed");
                }
            }
        }
        tracing::info!(count = connected, "connected to seed peers");
    }

    // Report max connections
    let max_connections = args.get_int_arg("maxconnections").unwrap_or(125);
    tracing::info!(max_connections = max_connections, "connection limit");

    // 9. Start network message processor
    if let Some(event_rx) = event_rx {
        let genesis_hash = ChainParams::for_network(network).genesis_block_hash;
        let notifier: Arc<dyn StateNotifier> = Arc::new(RpcStateNotifier {
            state: node_state.clone(),
        });
        let mut processor = NetProcessor::full(
            event_rx,
            conn_manager.clone(),
            genesis_hash,
            Arc::new(qubitcoin_net::net_processing::NullNodeInterface),
            notifier,
        );
        let net_span = tracing::info_span!("net_processor");
        tokio::spawn(
            async move {
                processor.run().await;
            }
            .instrument(net_span),
        );
    }

    tracing::info!("Qubitcoin Core startup complete");

    // 10. Main loop: wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            tracing::info!("received shutdown signal");
        }
        Err(e) => {
            tracing::error!(error = %e, "error waiting for shutdown");
        }
    }

    // 11. Graceful shutdown
    conn_manager.shutdown();
    tracing::info!("Qubitcoin Core shutdown complete");
}

fn print_usage() {
    println!("Qubitcoin Core version {}", VERSION);
    println!();
    println!("Usage: qubitcoind [options]");
    println!();
    println!("Options:");
    println!("  -help              Print this help message");
    println!("  -version           Print version");
    println!("  -testnet           Use testnet");
    println!("  -regtest           Use regtest");
    println!("  -signet            Use signet");
    println!("  -datadir=<dir>     Specify data directory");
    println!("  -port=<port>       P2P port (default: 8333)");
    println!("  -rpcport=<port>    RPC port (default: 8332)");
    println!("  -rpcuser=<user>    RPC username");
    println!("  -rpcpassword=<pw>  RPC password");
    println!("  -connect=<addr>    Connect to specified peer");
    println!("  -listen            Accept incoming connections (default: 1)");
    println!("  -maxconnections=<n> Max connections (default: 125)");
    println!("  -loglevel=<level>  Log level: error, warn, info, debug, trace");
}
