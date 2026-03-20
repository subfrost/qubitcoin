//! Qubitcoind: The Qubitcoin daemon.
//! A production-ready Bitcoin-compatible full node.

use qubitcoin_common::chainparams::{ChainParams, Network};
use qubitcoin_common::coins::{CoinsView, CoinsViewDB, FlushableCoinsView};
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_net::connection::{ConnConfig, ConnManager};
use qubitcoin_net::net_processing::{NetProcessor, NodeInterface, StateNotifier};
use qubitcoin_net::protocol::{NetworkMagic, ServiceFlags};
use qubitcoin_node::block_index_db::BlockIndexDB;
use qubitcoin_node::tx_index_db::TxIndexDB;
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::{self, TxMemPool};
use qubitcoin_primitives::{BlockHash, Txid, Uint256};
use qubitcoin_rpc::http_server::{RpcServer, RpcServerConfig};
use qubitcoin_rpc::node_rpc::{register_node_rpcs, NodeState};
use qubitcoin_rpc::server::RpcRegistry;
use qubitcoin_serialize::{deserialize, serialize};
use qubitcoin_node::block_storage::{BlockFileManager as NodeBlockFileManager, DiskBlockPos};
use qubitcoin_storage::traits::{Database, DbBatch};
use qubitcoin_storage::RocksDatabase;
use qubitcoin_util::args::ArgsManager;
use qubitcoin_util::logging::{self, LogLevel};
use qubitcoin_indexer::{IndexerManager, IndexerMode};
use qubitcoin_wallet::wallet::{DescriptorType, Wallet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Instrument;

/// Current qubitcoind version string, displayed at startup and in RPC responses.
const VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// ArcCoinsView: wraps Arc<CoinsViewDB> as a CoinsView trait object
// ---------------------------------------------------------------------------

/// Thin wrapper so a single `Arc<CoinsViewDB>` can serve as both the
/// `CoinsView` base for the cache *and* the `FlushableCoinsView` target.
struct ArcCoinsView<D: qubitcoin_storage::Database + Send + Sync + 'static> {
    inner: Arc<CoinsViewDB<D>>,
}

impl<D: qubitcoin_storage::Database + Send + Sync + 'static> qubitcoin_common::coins::CoinsView
    for ArcCoinsView<D>
{
    fn get_coin(
        &self,
        outpoint: &qubitcoin_consensus::OutPoint,
    ) -> Option<qubitcoin_common::coins::Coin> {
        qubitcoin_common::coins::CoinsView::get_coin(self.inner.as_ref(), outpoint)
    }

    fn get_best_block(&self) -> BlockHash {
        qubitcoin_common::coins::CoinsView::get_best_block(self.inner.as_ref())
    }

    fn estimate_size(&self) -> u64 {
        qubitcoin_common::coins::CoinsView::estimate_size(self.inner.as_ref())
    }
}

// ---------------------------------------------------------------------------
// StateNotifier implementation: bridges NetProcessor events to NodeState
// ---------------------------------------------------------------------------

/// Bridges network processor state changes into the RPC-visible [`NodeState`].
struct RpcStateNotifier {
    state: Arc<NodeState>,
}

impl StateNotifier for RpcStateNotifier {
    fn on_headers_update(&self, header_count: usize) {
        *self.state.headers_count.write() = header_count as i32 - 1;
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

    fn on_block_received(&self, _blocks_count: u64) {}
}

// ---------------------------------------------------------------------------
// LiveNodeInterface: bridges P2P network to chainstate + storage
// ---------------------------------------------------------------------------

/// Production implementation of [`NodeInterface`] that bridges the P2P
/// network layer to the real chainstate manager, mempool, and block storage.
struct LiveNodeInterface {
    chainstate: Arc<parking_lot::Mutex<ChainstateManager>>,
    mempool: Arc<TxMemPool>,
    block_files: Arc<NodeBlockFileManager>,
    coins_db: Arc<CoinsViewDB<RocksDatabase>>,
    block_index_db: Arc<BlockIndexDB<RocksDatabase>>,
    tx_index_db: Arc<TxIndexDB<RocksDatabase>>,
    node_state: Arc<NodeState>,
    /// Network magic bytes for block serialization.
    magic_bytes: [u8; 4],
    /// Counter for periodic UTXO flushes during IBD.
    blocks_since_flush: parking_lot::Mutex<u64>,
    /// Maximum UTXO cache size in bytes (from -dbcache).
    dbcache_limit: u64,
    /// Tracks IBD progress for logging blocks/sec and ETA.
    ibd_tracker: parking_lot::Mutex<IbdTracker>,
    /// Pending TX index entries accumulated between flushes.
    pending_tx_index: parking_lot::Mutex<Vec<(Txid, i32, u32, u32)>>,
    /// Optional in-process WASM secondary indexer manager.
    indexer_manager: Option<Arc<IndexerManager>>,
}

/// Tracks IBD (Initial Block Download) progress for logging.
struct IbdTracker {
    last_log_time: std::time::Instant,
    last_log_height: i32,
}

impl NodeInterface for LiveNodeInterface {
    fn process_block(&self, data: &[u8]) -> Result<bool, String> {
        // Deserialize the block.
        let block: Block = deserialize(data).map_err(|e| format!("block deserialize: {}", e))?;
        let block_hash = block.header.block_hash();

        // Write block data to flat files using the typed BlockFileManager.
        let pos = self
            .block_files
            .write_block(&block, self.magic_bytes)
            .map_err(|e| format!("block file write: {}", e))?;

        // Process through chainstate.
        let (accepted, block_undo) = {
            let mut cs = self.chainstate.lock();

            // Update the block index entry with file position before processing.
            if let Some(arena_idx) = cs.lookup_block_index(&block_hash) {
                let idx = cs.block_index_mut().get_mut(arena_idx);
                idx.file = pos.file;
                idx.data_pos = pos.pos;
                cs.mark_dirty(arena_idx);
            }

            cs.process_new_block(&block).map_err(|e| format!("{:?}", e))?
        };

        // Write undo data to disk and update block index with undo position.
        if let Some(undo) = block_undo {
            let undo_pos = self
                .block_files
                .write_undo(pos.file, &undo)
                .map_err(|e| format!("undo file write: {}", e))?;
            let mut cs = self.chainstate.lock();
            cs.set_undo_pos(&block_hash, undo_pos.pos);
        }

        if accepted {
            // Accumulate TX index entries for batched flush (avoids per-block RocksDB writes).
            {
                let mut pending = self.pending_tx_index.lock();
                for (i, tx) in block.vtx.iter().enumerate() {
                    pending.push((tx.txid().clone(), pos.file, pos.pos, i as u32));
                }
            }

            let mut flush_count = self.blocks_since_flush.lock();
            *flush_count += 1;

            // Update RPC state.
            let mut cs = self.chainstate.lock();
            let height = cs.height();
            let tip_hash = cs
                .tip()
                .map(|t| cs.block_index().get(t).block_hash.to_hex())
                .unwrap_or_default();
            *self.node_state.chain_height.write() = height;
            *self.node_state.best_block_hash.write() = tip_hash;

            // Log progress during IBD with blocks/sec and sync percentage.
            if height % 1000 == 0 {
                let cache_mb = cs.coins_tip().dynamic_memory_usage() / (1024 * 1024);
                let mut tracker = self.ibd_tracker.lock();
                let elapsed = tracker.last_log_time.elapsed();
                let blocks_delta = height - tracker.last_log_height;
                let blocks_per_sec = if elapsed.as_secs_f64() > 0.0 {
                    blocks_delta as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                // Estimate sync progress based on known mainnet height (~870,000 as of 2025).
                let estimated_tip = 870_000i32;
                let progress_pct = (height as f64 / estimated_tip as f64 * 100.0).min(100.0);

                tracing::info!(
                    height = height,
                    blocks_per_sec = format!("{:.1}", blocks_per_sec),
                    progress = format!("{:.2}%", progress_pct),
                    cache_mb = cache_mb,
                    "IBD progress"
                );

                tracker.last_log_time = std::time::Instant::now();
                tracker.last_log_height = height;
            }

            // Notify secondary indexers of the new block.
            if let Some(ref im) = self.indexer_manager {
                im.on_block_connected(height as u32, data);
            }

            // Memory-bounded flush: trigger when block count threshold OR cache
            // size exceeds the -dbcache limit (default 1024 MiB).
            let cache_bytes = cs.coins_tip().dynamic_memory_usage();
            let need_flush = *flush_count >= 2_000 || cache_bytes > self.dbcache_limit;

            if need_flush {
                let cache_mb = cache_bytes / (1024 * 1024);
                tracing::info!(height = height, cache_mb = cache_mb, "flushing UTXO cache and block index");
                cs.flush_coins(self.coins_db.as_ref());

                // Persist block index.
                let dirty = cs.dirty_block_indices();
                let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
                self.block_index_db.write_block_indices(&refs);
                cs.clear_dirty();

                // Flush accumulated TX index entries.
                {
                    let mut pending = self.pending_tx_index.lock();
                    if !pending.is_empty() {
                        self.tx_index_db.write_tx_positions(&pending);
                        pending.clear();
                    }
                }

                *flush_count = 0;
            }
        }

        Ok(accepted)
    }

    fn accept_block_header(&self, header_data: &[u8]) -> Result<bool, String> {
        let header: BlockHeader =
            deserialize(header_data).map_err(|e| format!("header deserialize: {}", e))?;
        let mut cs = self.chainstate.lock();
        match cs.accept_block_header(&header) {
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    fn accept_block_headers_batch(
        &self,
        headers: &[&[u8]],
    ) -> Vec<Result<bool, String>> {
        // Deserialize all headers first (no lock needed).
        let parsed: Vec<Result<BlockHeader, String>> = headers
            .iter()
            .map(|h| deserialize(*h).map_err(|e| format!("header deserialize: {}", e)))
            .collect();

        // Single lock acquisition for the entire batch.
        let mut cs = self.chainstate.lock();
        parsed
            .into_iter()
            .map(|res| match res {
                Ok(header) => match cs.accept_block_header(&header) {
                    Ok(_) => Ok(true),
                    Err(e) => Err(format!("{:?}", e)),
                },
                Err(e) => Err(e),
            })
            .collect()
    }

    fn process_transaction(&self, data: &[u8]) -> Result<bool, String> {
        let tx: qubitcoin_consensus::Transaction =
            deserialize(data).map_err(|e| format!("tx deserialize: {}", e))?;
        let txid = tx.txid().clone();

        // Basic validation: compute vsize and fee.
        let vsize = tx.get_virtual_size() as u32;

        // Accept to mempool with zero fee (fee validation is done inside).
        let tx_ref = std::sync::Arc::new(tx);
        let height = self.chainstate.lock().height();
        let result = mempool::accept_to_mempool(
            &self.mempool,
            &tx_ref,
            qubitcoin_primitives::Amount::from_sat(0),
            vsize,
            height,
        );

        match result {
            mempool::MempoolAcceptResult::Accepted { .. } => {
                tracing::debug!(txid = %txid.to_hex(), "transaction accepted to mempool");
                Ok(true)
            }
            mempool::MempoolAcceptResult::Rejected { reason } => {
                tracing::debug!(txid = %txid.to_hex(), reason = %reason, "transaction rejected");
                Err(reason)
            }
        }
    }

    fn has_transaction(&self, txid: &Uint256) -> bool {
        let txid_bytes = txid.data();
        let txid = qubitcoin_primitives::Txid::from_bytes(*txid_bytes);
        self.mempool.exists(&txid)
    }

    fn get_block(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let cs = self.chainstate.lock();
        let arena_idx = cs.lookup_block_index(hash)?;
        let entry = cs.block_index().get(arena_idx);

        if entry.file < 0 {
            return None;
        }

        let disk_pos = DiskBlockPos { file: entry.file, pos: entry.data_pos };
        let block = self.block_files.read_block(&disk_pos).ok()?;
        serialize(&block).ok()
    }

    fn get_transaction(&self, txid: &Uint256) -> Option<Vec<u8>> {
        let txid_bytes = txid.data();
        let txid = qubitcoin_primitives::Txid::from_bytes(*txid_bytes);
        let tx = self.mempool.get(&txid)?;
        serialize(&*tx).ok()
    }

    fn chain_height(&self) -> i32 {
        // Read from the lock-free NodeState instead of locking the chainstate
        // mutex.  The chainstate mutex is held for seconds during connect_block,
        // and chain_height is called from handle_headers on the event loop —
        // locking here would block the entire event loop.
        *self.node_state.chain_height.read()
    }

    fn add_address(&self, _addr: SocketAddr) {
        // TODO: address manager
    }

    fn get_addresses(&self, _max: usize) -> Vec<SocketAddr> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Data directory helpers
// ---------------------------------------------------------------------------

/// Resolve the data directory path, expanding `~` to the home directory.
fn resolve_datadir(raw: &str, network: Network) -> PathBuf {
    let base = if raw.starts_with("~/") || raw == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(&raw[2..])
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::from(raw)
    };

    // Append network subdirectory (mainnet uses the root).
    match network {
        Network::Mainnet => base,
        Network::Testnet => base.join("testnet3"),
        Network::Testnet4 => base.join("testnet4"),
        Network::Regtest => base.join("regtest"),
        Network::Signet => base.join("signet"),
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

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
    args.set_default("dbcache", "1024");
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

    // 4. Resolve and create data directory
    let datadir_raw = args
        .get_arg("datadir")
        .unwrap_or("~/.qubitcoin")
        .to_string();
    let datadir = resolve_datadir(&datadir_raw, network);
    let blocks_dir = datadir.join("blocks");
    let chainstate_dir = datadir.join("chainstate");
    let block_index_dir = datadir.join("blocks").join("index");

    let txindex_dir = datadir.join("indexes").join("txindex");

    std::fs::create_dir_all(&blocks_dir).expect("failed to create blocks directory");
    std::fs::create_dir_all(&chainstate_dir).expect("failed to create chainstate directory");
    std::fs::create_dir_all(&block_index_dir).expect("failed to create block index directory");
    std::fs::create_dir_all(&txindex_dir).expect("failed to create txindex directory");

    tracing::info!(datadir = %datadir.display(), "data directory initialized");

    // 5. Open databases
    let dbcache_mb = args.get_int_arg("dbcache").unwrap_or(1024) as usize;
    let chainstate_db = RocksDatabase::open(&chainstate_dir, dbcache_mb)
        .expect("failed to open chainstate database");
    let block_index_rocks = RocksDatabase::open(&block_index_dir, 8)
        .expect("failed to open block index database");

    let txindex_rocks = RocksDatabase::open(&txindex_dir, 8)
        .expect("failed to open txindex database");

    let coins_db = Arc::new(CoinsViewDB::new(chainstate_db, true));
    let block_index_db = Arc::new(BlockIndexDB::new_unobfuscated(block_index_rocks));
    let tx_index_db = Arc::new(TxIndexDB::new_unobfuscated(txindex_rocks));

    tracing::info!("databases opened");

    // 6. Initialize chainstate with persistent UTXO backing.
    //    Use ArcCoinsView so the same RocksDB instance serves as both the
    //    cache base view and the flush target (avoids RocksDB lock conflict).
    let coins_view: Box<dyn qubitcoin_common::coins::CoinsView + Send + Sync> =
        Box::new(ArcCoinsView { inner: coins_db.clone() });
    let mut chainstate = ChainstateManager::new(params.clone(), coins_view);

    // Load block index from disk.
    let records = block_index_db.load_all();
    if !records.is_empty() {
        tracing::info!(count = records.len(), "loading block index from disk");
        chainstate
            .load_block_index(&records)
            .expect("failed to load block index");
        tracing::info!(height = chainstate.height(), "block index loaded");
    }

    // Set up block file manager for flat-file block storage (typed, with undo support).
    let magic_bytes: [u8; 4] = match network {
        Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
        Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
        Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
        Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
    };
    let block_files = Arc::new(NodeBlockFileManager::new(&datadir));

    // Genesis persistence: if UTXO DB has no best block, load genesis and flush.
    let utxo_best = CoinsView::get_best_block(coins_db.as_ref());
    if utxo_best.is_null() {
        tracing::info!("no existing chain state, loading genesis block");
        let genesis = params.create_genesis_block();
        chainstate
            .load_genesis_block(&genesis)
            .expect("failed to load genesis block");
        chainstate.flush_coins(coins_db.as_ref());

        // Persist genesis block index.
        let dirty = chainstate.dirty_block_indices();
        let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
        block_index_db.write_block_indices(&refs);

        tracing::info!("genesis block loaded and persisted");
    } else {
        // Crash recovery: compare UTXO best_block with block index tip.
        // If they mismatch (e.g. after SIGKILL during IBD), disconnect
        // blocks from the index tip back to the UTXO best block, then
        // reset the active chain to match the persisted UTXO state.
        let index_tip_hash = chainstate
            .tip()
            .map(|t| chainstate.block_index().get(t).block_hash)
            .unwrap_or(BlockHash::ZERO);

        if utxo_best != index_tip_hash {
            tracing::warn!(
                utxo_best = %utxo_best.to_hex(),
                index_tip = %index_tip_hash.to_hex(),
                "UTXO best block does not match index tip, rewinding to UTXO state"
            );

            if let Some(utxo_idx) = chainstate.lookup_block_index(&utxo_best) {
                let utxo_height = chainstate.block_index().get(utxo_idx).height;
                let index_tip_height = chainstate.height();
                tracing::info!(
                    from = index_tip_height,
                    to = utxo_height,
                    "disconnecting blocks for crash recovery"
                );

                // Disconnect blocks from index tip down to UTXO best block.
                for h in (utxo_height + 1..=index_tip_height).rev() {
                    let idx_at_h = match chainstate.active_chain().get_block_index(h) {
                        Some(idx) => idx,
                        None => continue,
                    };
                    let entry = chainstate.block_index().get(idx_at_h);
                    let disk_pos = DiskBlockPos { file: entry.file, pos: entry.data_pos };
                    let undo_disk_pos = DiskBlockPos { file: entry.file, pos: entry.undo_pos };

                    let blk = match block_files.read_block(&disk_pos) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(height = h, error = %e, "failed to read block for disconnect, skipping");
                            continue;
                        }
                    };
                    let undo = match block_files.read_undo(&undo_disk_pos) {
                        Ok(u) => u,
                        Err(e) => {
                            tracing::warn!(height = h, error = %e, "failed to read undo for disconnect, skipping");
                            continue;
                        }
                    };

                    qubitcoin_node::validation::disconnect_block(
                        &blk,
                        h,
                        chainstate.coins_tip(),
                        &undo,
                    );
                    tracing::debug!(height = h, "disconnected block");
                }

                // Reset active chain to UTXO state.
                chainstate.reset_active_chain_to(utxo_idx);

                // Flush UTXO cache to persist clean state.
                chainstate.flush_coins(coins_db.as_ref());

                tracing::info!(height = utxo_height, "crash recovery complete");
            } else {
                tracing::error!("UTXO best block not found in block index, starting fresh");
                // Fall through -- the node will re-sync from network peers.
            }
        }

        tracing::info!(height = chainstate.height(), "chain state restored from disk");
    }

    // Set the assumed-valid block from chain params for IBD optimization.
    // Height 900,000 matches the assume-valid hash configured in chainparams.
    if !params.assumed_valid_block.is_null() {
        chainstate.set_assume_valid(params.assumed_valid_block, 900_000);
    }

    // Wire the disk-backed block reader so chainstate can read blocks/undo
    // from flat files during chain reorganization.
    {
        let bf = block_files.clone();
        chainstate.set_block_reader(std::sync::Arc::new(move |file, data_pos, undo_pos| {
            let block = bf.read_block(&DiskBlockPos { file, pos: data_pos }).ok()?;
            let undo = bf.read_undo(&DiskBlockPos { file, pos: undo_pos }).ok()?;
            Some((block, undo))
        }));
    }

    // Wrap chainstate in Arc<Mutex> for thread-safe sharing.
    let chainstate = Arc::new(parking_lot::Mutex::new(chainstate));

    tracing::info!(height = chainstate.lock().height(), "chain initialized");

    // 7. Initialize mempool
    let mempool = Arc::new(TxMemPool::new());
    tracing::info!(size = mempool.size(), "mempool initialized");

    // 7b. Initialize wallet — load from disk if available, else create new.
    let wallet_dir = datadir.join("wallet");
    std::fs::create_dir_all(&wallet_dir).expect("failed to create wallet directory");
    let wallet_db = RocksDatabase::open_default(&wallet_dir)
        .expect("failed to open wallet database");
    let wallet = {
        let stored = wallet_db.read(b"wallet_data").unwrap_or(None);
        if let Some(data) = stored {
            match Wallet::load_from_bytes(&data) {
                Ok(w) => {
                    tracing::info!(name = w.name(), "wallet loaded from disk");
                    w
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load wallet, creating new");
                    Wallet::new("default", DescriptorType::Wpkh)
                }
            }
        } else {
            tracing::info!("no existing wallet, creating new");
            Wallet::new("default", DescriptorType::Wpkh)
        }
    };
    let wallet = Arc::new(parking_lot::Mutex::new(wallet));
    let wallet_db = Arc::new(wallet_db);
    tracing::info!("wallet initialized");

    // 7c. Initialize secondary indexers (if any -loadindexer args provided).
    let indexer_manager: Option<Arc<IndexerManager>> = {
        let indexer_args = args.get_args("loadindexer");
        if indexer_args.is_empty() {
            None
        } else {
            let mode = if args.get_bool_arg("synchronous-secondary") {
                IndexerMode::Synchronous
            } else {
                IndexerMode::Async
            };
            let configs = qubitcoin_indexer::config::parse_load_indexer_args(&indexer_args);
            match IndexerManager::new(configs, &datadir, mode) {
                Ok(mgr) => {
                    let mgr = Arc::new(mgr);

                    // Catch up indexers that are behind the chain tip.
                    let chain_h = chainstate.lock().height() as u32;
                    if chain_h > 0 {
                        let bf = block_files.clone();
                        let cs_catchup = chainstate.clone();
                        mgr.catch_up(chain_h, |h| {
                            let cs = cs_catchup.lock();
                            let idx = cs.active_chain().get_block_index(h as i32)?;
                            let entry = cs.block_index().get(idx);
                            if entry.file < 0 {
                                return None;
                            }
                            let pos = DiskBlockPos { file: entry.file, pos: entry.data_pos };
                            let block = bf.read_block(&pos).ok()?;
                            serialize(&block).ok()
                        });
                    }

                    // Roll back any indexers that are ahead of the chain tip.
                    for label in mgr.labels() {
                        if let Some(ih) = mgr.indexer_height(label) {
                            if ih > chain_h {
                                tracing::warn!(
                                    indexer = %label,
                                    indexer_height = ih,
                                    chain_height = chain_h,
                                    "indexer ahead of chain, rolling back"
                                );
                                mgr.on_reorg(chain_h);
                            }
                        }
                    }

                    tracing::info!(
                        count = mgr.labels().len(),
                        mode = ?mode,
                        "secondary indexers initialized"
                    );
                    Some(mgr)
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to initialize secondary indexers");
                    None
                }
            }
        }
    };

    // 8. Initialize shared node state for RPC
    let chain_name = match network {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };
    let node_state = Arc::new(NodeState::new(chain_name));

    // Update RPC state with restored chain height.
    {
        let cs = chainstate.lock();
        let h = cs.height();
        *node_state.chain_height.write() = h;
        *node_state.headers_count.write() = h;
        if let Some(tip) = cs.tip() {
            *node_state.best_block_hash.write() =
                cs.block_index().get(tip).block_hash.to_hex();
        }
    }

    // 9. Set up RPC server
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

    // Register additional RPCs that access live chainstate.
    register_live_rpcs(
        &mut registry,
        chainstate.clone(),
        mempool.clone(),
        block_files.clone(),
        coins_db.clone(),
        tx_index_db.clone(),
    );

    // Register wallet RPCs.
    register_wallet_rpcs(
        &mut registry,
        wallet.clone(),
        chainstate.clone(),
        mempool.clone(),
        wallet_db.clone(),
    );

    // Register secondary indexer RPCs (if indexers are loaded).
    if let Some(ref im) = indexer_manager {
        use qubitcoin_rpc::server::{RpcRequest, RpcResponse, RPC_MISC_ERROR};
        qubitcoin_indexer::rpc::register_indexer_rpcs(
            &mut |name: &str, handler: Box<dyn Fn(&serde_json::Value) -> serde_json::Value + Send + Sync>| {
                registry.register(name, move |req: &RpcRequest| {
                    let params = req.params.clone().unwrap_or(serde_json::Value::Array(vec![]));
                    let result = handler(&params);
                    if let Some(err) = result.get("error") {
                        RpcResponse::error(
                            req.id.clone(),
                            RPC_MISC_ERROR,
                            err.as_str().unwrap_or("unknown error").to_string(),
                        )
                    } else {
                        RpcResponse::success(req.id.clone(), result)
                    }
                });
            },
            im.clone(),
        );
        tracing::info!("secondary indexer RPCs registered");

        // metashrew_view/metashrew_height aliases are registered via register_indexer_rpcs above
    }

    // Register real generatetoaddress for regtest mining.
    if network == Network::Regtest {
        use qubitcoin_rpc::server::{RpcRequest, RpcResponse, RPC_INVALID_PARAMS, RPC_MISC_ERROR};
        use qubitcoin_consensus::merkle::block_merkle_root;
        use qubitcoin_consensus::check::get_block_subsidy;
        use qubitcoin_consensus::transaction::{Transaction, TxIn, TxOut, OutPoint, Witness, TransactionRef, SEQUENCE_FINAL};
        use qubitcoin_primitives::ArithUint256;
        use qubitcoin_primitives::arith_uint256::uint256_to_arith;

        let cs_gen = chainstate.clone();
        let bf_gen = block_files.clone();
        let cdb_gen = coins_db.clone();
        let ns_gen = node_state.clone();
        let im_gen = indexer_manager.clone();
        let mp_gen = mempool.clone();
        let params_gen = params.clone();
        let magic_gen = magic_bytes;

        registry.register("generatetoaddress", move |req: &RpcRequest| {
            let params_arr = match req.params.as_ref().and_then(|p| p.as_array()) {
                Some(a) => a.clone(),
                None => return RpcResponse::error(req.id.clone(), RPC_INVALID_PARAMS, "expected array params".into()),
            };
            let nblocks = params_arr.get(0).and_then(|v| v.as_u64()).unwrap_or(0);
            let address_str = match params_arr.get(1).and_then(|v| v.as_str()) {
                Some(a) => a.to_string(),
                None => return RpcResponse::error(req.id.clone(), RPC_INVALID_PARAMS, "missing address".into()),
            };

            // Build coinbase output script from address (P2WPKH/P2TR bech32).
            let coinbase_script = {
                if let Ok((_, version, program)) = bech32::segwit::decode(&address_str) {
                    let ver_op: u8 = match version.to_u8() { 0 => 0x00, n => 0x50 + n };
                    let mut raw = Vec::with_capacity(2 + program.len());
                    raw.push(ver_op);
                    raw.push(program.len() as u8);
                    raw.extend_from_slice(&program);
                    qubitcoin_script::Script::from(raw)
                } else {
                    // Fallback: OP_TRUE (anyone-can-spend) for regtest.
                    qubitcoin_script::Script::from(vec![0x51u8])
                }
            };

            let mut hashes = Vec::new();
            let wall_clock = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            let mut last_time = {
                let cs = cs_gen.lock();
                let tip_time = if let Some(tip) = cs.tip() {
                    cs.block_index().get(tip).time
                } else {
                    0
                };
                // Use whichever is later: wall clock or tip time
                std::cmp::max(wall_clock, tip_time)
            };
            for _ in 0..nblocks {
                let mut cs = cs_gen.lock();
                let height = cs.height() + 1;
                let subsidy = get_block_subsidy(height, &params_gen.consensus);

                // Collect mempool transactions.
                let mempool_txids = mp_gen.get_txids();
                let mut user_txs: Vec<TransactionRef> = Vec::new();
                let mut has_witness = false;
                for txid in &mempool_txids {
                    if let Some(tx) = mp_gen.get(txid) {
                        // Check if any tx has witness data
                        for input in &tx.vin {
                            if !input.witness.is_empty() {
                                has_witness = true;
                            }
                        }
                        user_txs.push(tx);
                    }
                }

                // Create coinbase with optional witness commitment (BIP141).
                let mut sig_script = qubitcoin_script::Script::new();
                sig_script.push_int(height as i64);
                if sig_script.len() < 2 { sig_script.push_int(0); }

                let mut coinbase_outputs = vec![TxOut::new(subsidy, coinbase_script.clone())];
                let mut coinbase_witness = Witness::new();

                if has_witness {
                    // Compute witness commitment for BIP141.
                    // witness_root = merkle_root of all wtxids (coinbase wtxid = 0x00..00)
                    use qubitcoin_crypto::hash::hash256;
                    let mut witness_hashes: Vec<Uint256> = Vec::new();
                    witness_hashes.push(Uint256::default()); // coinbase wtxid = 0
                    for tx in &user_txs {
                        witness_hashes.push(tx.wtxid().into_uint256());
                    }
                    // Simple merkle root of witness hashes
                    let mut level = witness_hashes;
                    while level.len() > 1 {
                        let mut next = Vec::new();
                        for i in (0..level.len()).step_by(2) {
                            let left = &level[i];
                            let right = if i + 1 < level.len() { &level[i + 1] } else { &level[i] };
                            let mut combined = [0u8; 64];
                            combined[..32].copy_from_slice(left.as_bytes());
                            combined[32..].copy_from_slice(right.as_bytes());
                            let hash = hash256(&combined);
                            next.push(Uint256::from_bytes(hash));
                        }
                        level = next;
                    }
                    let witness_root = if level.is_empty() { Uint256::default() } else { level[0] };

                    // witness_commitment = SHA256d(witness_root || witness_nonce)
                    // witness_nonce = 0x00..00 (32 bytes)
                    let witness_nonce = [0u8; 32];
                    let mut commitment_preimage = [0u8; 64];
                    commitment_preimage[..32].copy_from_slice(witness_root.as_bytes());
                    commitment_preimage[32..].copy_from_slice(&witness_nonce);
                    let witness_commitment = hash256(&commitment_preimage);

                    // Add OP_RETURN output with witness commitment
                    // Format: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commitment>
                    let mut commitment_script = Vec::with_capacity(38);
                    commitment_script.push(0x6a); // OP_RETURN
                    commitment_script.push(0x24); // OP_PUSHBYTES_36
                    commitment_script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // witness magic
                    commitment_script.extend_from_slice(&witness_commitment);
                    coinbase_outputs.push(TxOut::new(
                        qubitcoin_primitives::Amount::from_sat(0),
                        qubitcoin_script::Script::from(commitment_script),
                    ));

                    // Coinbase witness: single 32-byte zero nonce
                    coinbase_witness.stack.push(witness_nonce.to_vec());
                }

                let coinbase_tx = Transaction::new(
                    2,
                    vec![TxIn { prevout: OutPoint::null(), script_sig: sig_script, sequence: SEQUENCE_FINAL, witness: coinbase_witness }],
                    coinbase_outputs,
                    0,
                );
                let coinbase_ref: TransactionRef = Arc::new(coinbase_tx);
                let mut all_txs = vec![coinbase_ref];
                all_txs.extend(user_txs);

                // Compute merkle root.
                let mut mutated = false;
                let merkle_root = block_merkle_root(&all_txs, &mut mutated);

                // Build header.
                let prev_hash = match cs.tip() {
                    Some(t) => cs.block_index().get(t).block_hash,
                    None => {
                        // Genesis block hash for regtest
                        BlockHash::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206").unwrap()
                    }
                };
                last_time += 1;
                let time = last_time;
                let bits = {
                    let arith = uint256_to_arith(&params_gen.consensus.pow_limit);
                    arith.get_compact(false)
                };

                let mut header = BlockHeader { version: 4, prev_blockhash: prev_hash, merkle_root, time, bits, nonce: 0 };

                // Solve PoW (trivial on regtest).
                let mut target = ArithUint256::zero();
                target.set_compact(header.bits);
                loop {
                    let hash = header.block_hash();
                    let hash_arith = uint256_to_arith(&hash.into_uint256());
                    if hash_arith <= target { break; }
                    header.nonce = header.nonce.wrapping_add(1);
                }

                let block = Block { header: header.clone(), vtx: all_txs };
                let block_hash = block.header.block_hash();

                // Serialize and process through chainstate.
                let block_bytes = match serialize(&block) {
                    Ok(b) => b,
                    Err(e) => return RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, format!("serialize: {}", e)),
                };

                // Write to block files.
                let pos = match bf_gen.write_block(&block, magic_gen) {
                    Ok(p) => p,
                    Err(e) => return RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, format!("write: {}", e)),
                };

                // Update block index with file position.
                if let Some(arena_idx) = cs.lookup_block_index(&block_hash) {
                    let idx = cs.block_index_mut().get_mut(arena_idx);
                    idx.file = pos.file;
                    idx.data_pos = pos.pos;
                    cs.mark_dirty(arena_idx);
                }

                // Process through chainstate (validates + connects).
                tracing::info!(height = height, time = time, prev_hash = %prev_hash.to_hex(), "mining block");
                match cs.process_new_block(&block) {
                    Ok((true, undo)) => {
                        // Write undo data.
                        if let Some(undo_data) = undo {
                            if let Ok(undo_pos) = bf_gen.write_undo(pos.file, &undo_data) {
                                cs.set_undo_pos(&block_hash, undo_pos.pos);
                            }
                        }
                        // Flush coins.
                        cs.flush_coins(cdb_gen.as_ref());
                        // Update RPC state.
                        *ns_gen.chain_height.write() = height;
                        *ns_gen.best_block_hash.write() = block_hash.to_hex();
                        // Remove included txs from mempool.
                        if !mempool_txids.is_empty() {
                            mp_gen.remove_for_block(&mempool_txids);
                        }
                    }
                    Ok((false, _)) => {
                        return RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, "block not accepted".into());
                    }
                    Err(e) => {
                        tracing::error!(height = height, time = time, error = %format!("{:?}", e), "mining failed");
                        return RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, format!("process: {:?}", e));
                    }
                }
                drop(cs);

                // Notify secondary indexers.
                if let Some(ref im) = im_gen {
                    im.on_block_connected(height as u32, &block_bytes);
                }

                hashes.push(block_hash.to_hex());
            }

            RpcResponse::success(req.id.clone(), serde_json::json!(hashes))
        });
        tracing::info!("real generatetoaddress registered for regtest");
    }

    tracing::info!(
        method_count = registry.method_count(),
        has_metashrew_height = registry.has_method("metashrew_height"),
        has_metashrew_view = registry.has_method("metashrew_view"),
        has_generatetoaddress = registry.has_method("generatetoaddress"),
        "RPC registry final state"
    );
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

    // 10. Set up P2P networking
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
        best_height: chainstate.lock().height(),
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

    // 11. Create LiveNodeInterface and start network processor BEFORE
    //     connecting to peers, so handshake events are processed immediately.
    let initial_height = chainstate.lock().height();
    let node_interface: Arc<dyn NodeInterface> = Arc::new(LiveNodeInterface {
        chainstate: chainstate.clone(),
        mempool: mempool.clone(),
        block_files: block_files.clone(),
        coins_db: coins_db.clone(),
        block_index_db: block_index_db.clone(),
        tx_index_db: tx_index_db.clone(),
        node_state: node_state.clone(),
        magic_bytes,
        blocks_since_flush: parking_lot::Mutex::new(0),
        dbcache_limit: (dbcache_mb as u64) * 1024 * 1024,
        pending_tx_index: parking_lot::Mutex::new(Vec::new()),
        ibd_tracker: parking_lot::Mutex::new(IbdTracker {
            last_log_time: std::time::Instant::now(),
            last_log_height: initial_height,
        }),
        indexer_manager: indexer_manager.clone(),
    });

    if let Some(event_rx) = event_rx {
        let genesis_hash = ChainParams::for_network(network).genesis_block_hash;
        let notifier: Arc<dyn StateNotifier> = Arc::new(RpcStateNotifier {
            state: node_state.clone(),
        });
        let mut processor = NetProcessor::full(
            event_rx,
            conn_manager.clone(),
            genesis_hash,
            node_interface,
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

    // Report max connections
    let max_connections = args.get_int_arg("maxconnections").unwrap_or(125);
    tracing::info!(max_connections = max_connections, "connection limit");

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
        let max_seed_connections = 16usize;

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

    tracing::info!("Qubitcoin Core startup complete");

    // 12. Main loop: wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            tracing::info!("received shutdown signal");
        }
        Err(e) => {
            tracing::error!(error = %e, "error waiting for shutdown");
        }
    }

    // 13. Graceful shutdown: flush all state to disk
    tracing::info!("flushing state to disk...");
    {
        let cs = chainstate.lock();

        // Flush UTXO cache.
        cs.flush_coins(coins_db.as_ref());

        // Persist all block index entries.
        let dirty = cs.dirty_block_indices();
        let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
        block_index_db.write_block_indices(&refs);

        tracing::info!(height = cs.height(), "state flushed to disk");
    }

    // Save wallet to disk.
    {
        let w = wallet.lock();
        match w.save_to_bytes() {
            Ok(data) => {
                let mut batch = wallet_db.new_batch();
                batch.put(b"wallet_data", &data);
                if let Err(e) = wallet_db.write_batch(batch, true) {
                    tracing::error!(error = %e, "failed to write wallet to disk");
                } else {
                    tracing::info!("wallet saved to disk");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize wallet");
            }
        }
    }

    conn_manager.shutdown();
    tracing::info!("Qubitcoin Core shutdown complete");
}

// ---------------------------------------------------------------------------
// Additional RPC methods that access live chainstate
// ---------------------------------------------------------------------------

fn register_live_rpcs(
    registry: &mut RpcRegistry,
    chainstate: Arc<parking_lot::Mutex<ChainstateManager>>,
    mempool: Arc<TxMemPool>,
    block_files: Arc<NodeBlockFileManager>,
    coins_db: Arc<CoinsViewDB<RocksDatabase>>,
    tx_index_db: Arc<TxIndexDB<RocksDatabase>>,
) {
    use qubitcoin_rpc::server::{RpcRequest, RpcResponse, RPC_INVALID_PARAMS, RPC_MISC_ERROR};

    // -- getblock -----------------------------------------------------------
    let cs = chainstate.clone();
    let bf = block_files.clone();
    registry.register("getblock", move |req: &RpcRequest| {
        let hash_str = match req
            .params
            .as_ref()
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
        {
            Some(h) => h,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing block hash parameter".into(),
                )
            }
        };

        let verbosity = req
            .params
            .as_ref()
            .and_then(|p| p.get(1))
            .and_then(|v| v.as_i64())
            .unwrap_or(1);

        let block_hash = match BlockHash::from_hex(hash_str) {
            Some(h) => h,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Invalid block hash".into(),
                )
            }
        };

        let cs = cs.lock();
        let arena_idx = match cs.lookup_block_index(&block_hash) {
            Some(idx) => idx,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    "Block not found".into(),
                )
            }
        };

        let entry = cs.block_index().get(arena_idx);

        if entry.file < 0 {
            return RpcResponse::error(
                req.id.clone(),
                RPC_MISC_ERROR,
                "Block data not available".into(),
            );
        }

        let disk_pos = DiskBlockPos { file: entry.file, pos: entry.data_pos };
        let block = match bf.read_block(&disk_pos) {
            Ok(b) => b,
            Err(e) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    format!("Failed to read block: {}", e),
                )
            }
        };

        if verbosity == 0 {
            // Return hex-encoded raw block.
            match serialize(&block) {
                Ok(block_data) => {
                    let hex: String = block_data.iter().map(|b| format!("{:02x}", b)).collect();
                    RpcResponse::success(req.id.clone(), serde_json::json!(hex))
                }
                Err(e) => {
                    RpcResponse::error(
                        req.id.clone(),
                        RPC_MISC_ERROR,
                        format!("Failed to serialize block: {}", e),
                    )
                }
            }
        } else {
            // Return JSON with txids.
            let txids: Vec<String> = block
                .vtx
                .iter()
                .map(|tx| tx.txid().to_hex())
                .collect();
            RpcResponse::success(
                req.id.clone(),
                serde_json::json!({
                    "hash": block_hash.to_hex(),
                    "height": entry.height,
                    "version": entry.version,
                    "time": entry.time,
                    "nonce": entry.nonce,
                    "bits": format!("{:08x}", entry.bits),
                    "nTx": block.vtx.len(),
                    "tx": txids,
                }),
            )
        }
    });

    // -- gettxout -----------------------------------------------------------
    let cs = chainstate.clone();
    registry.register("gettxout", move |req: &RpcRequest| {
        let params = match req.params.as_ref() {
            Some(p) => p,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing parameters".into(),
                )
            }
        };

        let txid_str = match params.get(0).and_then(|v| v.as_str()) {
            Some(t) => t,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing txid parameter".into(),
                )
            }
        };
        let vout = match params.get(1).and_then(|v| v.as_u64()) {
            Some(n) => n as u32,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing vout parameter".into(),
                )
            }
        };

        let txid = match qubitcoin_primitives::Txid::from_hex(txid_str) {
            Some(t) => t,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Invalid txid".into(),
                )
            }
        };

        let outpoint = qubitcoin_consensus::OutPoint::new(txid, vout);
        let cs = cs.lock();
        match cs.coins_tip().fetch_coin(&outpoint) {
            Some(coin) => RpcResponse::success(
                req.id.clone(),
                serde_json::json!({
                    "bestblock": cs.tip()
                        .map(|t| cs.block_index().get(t).block_hash.to_hex())
                        .unwrap_or_default(),
                    "confirmations": cs.height() - coin.height as i32 + 1,
                    "value": coin.tx_out.value.to_sat() as f64 / 100_000_000.0,
                    "coinbase": coin.coinbase,
                }),
            ),
            None => RpcResponse::success(req.id.clone(), serde_json::Value::Null),
        }
    });

    // -- sendrawtransaction -------------------------------------------------
    let mp = mempool.clone();
    let cs2 = chainstate.clone();
    registry.register("sendrawtransaction", move |req: &RpcRequest| {
        let hex_str = match req
            .params
            .as_ref()
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
        {
            Some(h) => h,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing hex transaction parameter".into(),
                )
            }
        };

        // Decode hex string.
        let raw_bytes: Result<Vec<u8>, _> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect();

        let raw_bytes = match raw_bytes {
            Ok(b) => b,
            Err(_) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Invalid hex encoding".into(),
                )
            }
        };

        let tx: qubitcoin_consensus::Transaction = match deserialize(&raw_bytes) {
            Ok(t) => t,
            Err(e) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    format!("TX decode failed: {}", e),
                )
            }
        };

        let txid = tx.txid().clone();
        let vsize = tx.get_virtual_size() as u32;
        let tx_ref = std::sync::Arc::new(tx.clone());

        // Compute the fee: sum(input values) - sum(output values)
        // Check both confirmed UTXO set AND mempool for unconfirmed outputs
        // (needed for commit/reveal flows where reveal spends the commit output).
        let cs_guard = cs2.lock();
        let height = cs_guard.height();
        let mut total_in: i64 = 0;
        for input in &tx.vin {
            if input.prevout.is_null() { continue; } // coinbase
            if let Some(coin) = cs_guard.coins_tip().get_coin(&input.prevout) {
                total_in += coin.tx_out.value.to_sat();
            } else if let Some(parent_tx) = mp.get(&input.prevout.hash) {
                // Check mempool for unconfirmed parent output
                if let Some(output) = parent_tx.vout.get(input.prevout.n as usize) {
                    total_in += output.value.to_sat();
                }
            }
        }
        drop(cs_guard);
        let total_out: i64 = tx.vout.iter().map(|o| o.value.to_sat()).sum();
        let fee = qubitcoin_primitives::Amount::from_sat(std::cmp::max(0, total_in - total_out));

        match mempool::accept_to_mempool(
            &mp,
            &tx_ref,
            fee,
            vsize,
            height,
        ) {
            mempool::MempoolAcceptResult::Accepted { .. } => {
                RpcResponse::success(req.id.clone(), serde_json::json!(txid.to_hex()))
            }
            mempool::MempoolAcceptResult::Rejected { reason } => {
                RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, reason)
            }
        }
    });

    // -- getrawtransaction --------------------------------------------------
    let mp2 = mempool.clone();
    let cs3 = chainstate.clone();
    let bf2 = block_files.clone();
    let txi = tx_index_db.clone();
    registry.register("getrawtransaction", move |req: &RpcRequest| {
        let txid_str = match req
            .params
            .as_ref()
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
        {
            Some(t) => t,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing txid parameter".into(),
                )
            }
        };

        let verbose = req
            .params
            .as_ref()
            .and_then(|p| p.get(1))
            .map(|v| {
                // Accept both boolean true and integer 1.
                v.as_bool().unwrap_or(false) || v.as_i64().unwrap_or(0) == 1
            })
            .unwrap_or(false);

        let txid = match qubitcoin_primitives::Txid::from_hex(txid_str) {
            Some(t) => t,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Invalid txid".into(),
                )
            }
        };

        // Check mempool first.
        if let Some(tx) = mp2.get(&txid) {
            if verbose {
                let raw = match serialize(&*tx) {
                    Ok(r) => r,
                    Err(e) => {
                        return RpcResponse::error(
                            req.id.clone(),
                            RPC_MISC_ERROR,
                            format!("Failed to serialize tx: {}", e),
                        )
                    }
                };
                let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
                let vin: Vec<serde_json::Value> = tx.vin.iter().map(|inp| {
                    serde_json::json!({
                        "txid": inp.prevout.hash.to_hex(),
                        "vout": inp.prevout.n,
                        "sequence": inp.sequence,
                    })
                }).collect();
                let vout: Vec<serde_json::Value> = tx.vout.iter().enumerate().map(|(n, out)| {
                    let spk_hex: String = out.script_pubkey.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                    serde_json::json!({
                        "value": out.value.to_sat() as f64 / 100_000_000.0,
                        "n": n,
                        "scriptPubKey": { "hex": spk_hex },
                    })
                }).collect();
                return RpcResponse::success(req.id.clone(), serde_json::json!({
                    "txid": tx.txid().to_hex(),
                    "hash": tx.wtxid().to_hex(),
                    "version": tx.version,
                    "size": tx.get_total_size(),
                    "vsize": tx.get_virtual_size(),
                    "weight": tx.get_weight(),
                    "locktime": tx.lock_time,
                    "vin": vin,
                    "vout": vout,
                    "hex": hex,
                }));
            }
            if let Ok(raw) = serialize(&*tx) {
                let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
                return RpcResponse::success(req.id.clone(), serde_json::json!(hex));
            }
        }

        // Look up in txindex.
        let (file, data_pos, tx_idx) = match txi.read_tx_pos(&txid) {
            Some(pos) => pos,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    "Transaction not found".into(),
                )
            }
        };

        // Read the full block from disk.
        let disk_pos = DiskBlockPos { file, pos: data_pos };
        let block = match bf2.read_block(&disk_pos) {
            Ok(b) => b,
            Err(e) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    format!("Failed to read block: {}", e),
                )
            }
        };

        // Extract the transaction.
        let tx = match block.vtx.get(tx_idx as usize) {
            Some(t) => t,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    "Transaction index out of range in block".into(),
                )
            }
        };

        // Verify txid matches.
        if *tx.txid() != txid {
            return RpcResponse::error(
                req.id.clone(),
                RPC_MISC_ERROR,
                "Transaction index mismatch".into(),
            );
        }

        let raw = match serialize(&**tx) {
            Ok(r) => r,
            Err(e) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    format!("Failed to serialize tx: {}", e),
                )
            }
        };
        let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();

        if verbose {
            // Get block metadata from chainstate.
            let block_hash = block.header.block_hash();
            let cs = cs3.lock();
            let (confirmations, blocktime) = match cs.lookup_block_index(&block_hash) {
                Some(idx) => {
                    let entry = cs.block_index().get(idx);
                    let confs = cs.height() - entry.height + 1;
                    (confs, entry.time)
                }
                None => (0i32, 0u32),
            };

            let vin: Vec<serde_json::Value> = tx.vin.iter().map(|inp| {
                serde_json::json!({
                    "txid": inp.prevout.hash.to_hex(),
                    "vout": inp.prevout.n,
                    "sequence": inp.sequence,
                })
            }).collect();
            let vout: Vec<serde_json::Value> = tx.vout.iter().enumerate().map(|(n, out)| {
                let spk_hex: String = out.script_pubkey.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                serde_json::json!({
                    "value": out.value.to_sat() as f64 / 100_000_000.0,
                    "n": n,
                    "scriptPubKey": { "hex": spk_hex },
                })
            }).collect();

            RpcResponse::success(req.id.clone(), serde_json::json!({
                "txid": tx.txid().to_hex(),
                "hash": tx.wtxid().to_hex(),
                "version": tx.version,
                "size": tx.get_total_size(),
                "vsize": tx.get_virtual_size(),
                "weight": tx.get_weight(),
                "locktime": tx.lock_time,
                "vin": vin,
                "vout": vout,
                "hex": hex,
                "blockhash": block_hash.to_hex(),
                "confirmations": confirmations,
                "blocktime": blocktime,
                "time": blocktime,
            }))
        } else {
            RpcResponse::success(req.id.clone(), serde_json::json!(hex))
        }
    });
}

// ---------------------------------------------------------------------------
// Wallet RPC methods
// ---------------------------------------------------------------------------

fn register_wallet_rpcs(
    registry: &mut RpcRegistry,
    wallet: Arc<parking_lot::Mutex<Wallet>>,
    chainstate: Arc<parking_lot::Mutex<ChainstateManager>>,
    mempool: Arc<TxMemPool>,
    wallet_db: Arc<RocksDatabase>,
) {
    use qubitcoin_rpc::server::{RpcRequest, RpcResponse, RPC_INVALID_PARAMS, RPC_MISC_ERROR};

    // -- getnewaddress ------------------------------------------------------
    let w = wallet.clone();
    registry.register("getnewaddress", move |req: &RpcRequest| {
        let mut w = w.lock();
        let addr = w.get_new_address();
        RpcResponse::success(req.id.clone(), serde_json::json!(addr.address))
    });

    // -- getbalance ---------------------------------------------------------
    let w = wallet.clone();
    registry.register("getbalance", move |req: &RpcRequest| {
        let w = w.lock();
        let balance = w.get_balance();
        let btc = balance.to_sat() as f64 / 100_000_000.0;
        RpcResponse::success(req.id.clone(), serde_json::json!(btc))
    });

    // -- listunspent --------------------------------------------------------
    let w = wallet.clone();
    registry.register("listunspent", move |req: &RpcRequest| {
        let w = w.lock();
        let utxos: Vec<serde_json::Value> = w
            .list_unspent()
            .iter()
            .map(|utxo| {
                serde_json::json!({
                    "txid": utxo.outpoint.hash.to_hex(),
                    "vout": utxo.outpoint.n,
                    "amount": utxo.tx_out.value.to_sat() as f64 / 100_000_000.0,
                    "confirmations": utxo.height.map(|h| h).unwrap_or(0),
                    "spendable": true,
                })
            })
            .collect();
        RpcResponse::success(req.id.clone(), serde_json::json!(utxos))
    });

    // -- sendtoaddress (simplified) -----------------------------------------
    // Accepts: sendtoaddress <address_hex_spk> <amount_btc>
    // Creates a transaction spending wallet UTXOs to the target, signs it,
    // and submits to mempool. Returns the txid.
    let w = wallet.clone();
    let cs = chainstate.clone();
    let mp = mempool.clone();
    let wdb = wallet_db.clone();
    registry.register("sendtoaddress", move |req: &RpcRequest| {
        let params = match req.params.as_ref() {
            Some(p) => p,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing parameters".into(),
                )
            }
        };

        let dest_hex = match params.get(0).and_then(|v| v.as_str()) {
            Some(a) => a,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing address parameter".into(),
                )
            }
        };

        let amount_btc = match params.get(1).and_then(|v| v.as_f64()) {
            Some(a) => a,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Missing amount parameter".into(),
                )
            }
        };

        let amount_sat = (amount_btc * 100_000_000.0) as i64;
        if amount_sat <= 0 {
            return RpcResponse::error(
                req.id.clone(),
                RPC_INVALID_PARAMS,
                "Invalid amount".into(),
            );
        }
        let send_amount = qubitcoin_primitives::Amount::from_sat(amount_sat);

        // Decode destination scriptPubKey from hex.
        let dest_spk_bytes: Result<Vec<u8>, _> = (0..dest_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&dest_hex[i..i + 2], 16))
            .collect();
        let dest_spk = match dest_spk_bytes {
            Ok(b) => qubitcoin_script::Script::from_bytes(b),
            Err(_) => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_INVALID_PARAMS,
                    "Invalid address hex".into(),
                )
            }
        };

        let mut w = w.lock();

        // Estimate fee rate from mempool (or use minimum relay fee).
        let fee_rate = mp.estimate_fee_rate();
        let fee_rate_per_vb = fee_rate.sats_per_kvb() / 1000;
        // Use at least 1 sat/vB.
        let fee_rate_per_vb = fee_rate_per_vb.max(1);

        // Select UTXOs using proper coin selection with fee estimation.
        let utxos: Vec<_> = w.list_unspent().into_iter().cloned().collect();
        let selection = match qubitcoin_wallet::coin_selection::select_coins(
            &utxos,
            send_amount,
            fee_rate_per_vb,
        ) {
            Some(s) => s,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    RPC_MISC_ERROR,
                    "Insufficient funds".into(),
                );
            }
        };

        // Build transaction.
        let mut inputs = Vec::new();
        let mut spent_outputs = Vec::new();
        for utxo in &selection.selected {
            inputs.push(qubitcoin_consensus::TxIn::new(
                utxo.outpoint.clone(),
                qubitcoin_script::Script::new(),
                0xFFFFFFFF,
            ));
            spent_outputs.push(utxo.tx_out.clone());
        }

        let mut outputs = vec![qubitcoin_consensus::TxOut::new(send_amount, dest_spk)];

        // Change output (only if change is above dust threshold).
        if selection.change.to_sat() > 546 {
            let change_addr = w.get_change_address();
            outputs.push(qubitcoin_consensus::TxOut::new(selection.change, change_addr.script_pubkey));
        }

        let mut tx = qubitcoin_consensus::Transaction::new(2, inputs, outputs, 0);

        // Sign.
        let signed = w.sign_transaction(&mut tx, &spent_outputs);
        if signed != selection.selected.len() {
            return RpcResponse::error(
                req.id.clone(),
                RPC_MISC_ERROR,
                format!("Only signed {} of {} inputs", signed, selection.selected.len()),
            );
        }

        let txid = tx.txid().clone();
        let vsize = tx.get_virtual_size() as u32;
        let tx_ref = std::sync::Arc::new(tx);

        // Submit to mempool.
        let height = cs.lock().height();
        match mempool::accept_to_mempool(
            &mp,
            &tx_ref,
            qubitcoin_primitives::Amount::from_sat(0),
            vsize,
            height,
        ) {
            mempool::MempoolAcceptResult::Accepted { .. } => {
                // Track in wallet.
                w.add_transaction(tx_ref, None);
                // Auto-save wallet to disk.
                if let Ok(data) = w.save_to_bytes() {
                    let mut batch = wdb.new_batch();
                    batch.put(b"wallet_data", &data);
                    let _ = wdb.write_batch(batch, true);
                }
                RpcResponse::success(req.id.clone(), serde_json::json!(txid.to_hex()))
            }
            mempool::MempoolAcceptResult::Rejected { reason } => {
                RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, reason)
            }
        }
    });
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
    println!("  -testnet4          Use testnet4");
    println!("  -regtest           Use regtest");
    println!("  -signet            Use signet");
    println!("  -datadir=<dir>     Specify data directory (default: ~/.qubitcoin)");
    println!("  -port=<port>       P2P port (default: 8333)");
    println!("  -rpcport=<port>    RPC port (default: 8332)");
    println!("  -rpcuser=<user>    RPC username");
    println!("  -rpcpassword=<pw>  RPC password");
    println!("  -connect=<addr>    Connect to specified peer");
    println!("  -listen            Accept incoming connections (default: 1)");
    println!("  -maxconnections=<n> Max connections (default: 125)");
    println!("  -loglevel=<level>  Log level: error, warn, info, debug, trace");
    println!("  -dbcache=<n>       UTXO cache size in MB (default: 1024)");
}
