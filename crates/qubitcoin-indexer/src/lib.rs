//! In-process WASM secondary indexer runtime for Qubitcoin.
//!
//! Embeds metashrew-compatible WASM indexers that run in-process alongside
//! the chain tip, providing atomic reorg handling and zero-config indexing.

pub mod config;
pub mod rollback;
pub mod rpc;
pub mod runtime;
pub mod smt;
pub mod state;
pub mod storage;

use config::IndexerConfig;
use runtime::WasmIndexerRuntime;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use storage::IndexerStorage;

/// Indexer execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexerMode {
    /// Indexers run synchronously — the chain tip does not advance until all
    /// indexers have processed the block.
    Synchronous,
    /// Indexers run asynchronously via a channel. The chain tip may be ahead.
    Async,
}

/// A single loaded indexer instance.
pub struct IndexerInstance {
    /// Human-readable label.
    pub label: String,
    /// Compiled WASM runtime.
    pub runtime: parking_lot::Mutex<WasmIndexerRuntime>,
    /// Dedicated RocksDB storage.
    pub storage: Arc<IndexerStorage>,
    /// SHA-256 hash of the WASM binary.
    pub wasm_hash: [u8; 32],
    /// Current tip height (atomically updated).
    pub tip_height: AtomicU32,
    /// Whether SMT state roots are computed.
    pub smt_enabled: bool,
}

/// Manages all loaded indexer instances.
pub struct IndexerManager {
    indexers: HashMap<String, Arc<IndexerInstance>>,
    mode: IndexerMode,
}

impl IndexerManager {
    /// Create a new IndexerManager by loading indexers from configs.
    ///
    /// Each indexer gets its own RocksDB at `{datadir}/indexers/{label}/db/`.
    pub fn new(
        configs: Vec<IndexerConfig>,
        datadir: &PathBuf,
        mode: IndexerMode,
    ) -> Result<Self, String> {
        let mut indexers = HashMap::new();

        for config in configs {
            tracing::info!(
                label = %config.label,
                wasm = %config.wasm_path.display(),
                "loading indexer module"
            );

            // Read WASM binary.
            let wasm_bytes = std::fs::read(&config.wasm_path).map_err(|e| {
                format!(
                    "failed to read WASM file '{}': {}",
                    config.wasm_path.display(),
                    e
                )
            })?;

            // Compute SHA-256 hash.
            let wasm_hash: [u8; 32] = Sha256::digest(&wasm_bytes).into();
            let hash_hex: String = wasm_hash.iter().map(|b| format!("{:02x}", b)).collect();

            // Open storage.
            let db_dir = datadir
                .join("indexers")
                .join(&config.label)
                .join("db");
            std::fs::create_dir_all(&db_dir).map_err(|e| {
                format!("failed to create indexer db dir: {}", e)
            })?;

            let storage = Arc::new(IndexerStorage::open(&db_dir)?);

            // Check WASM hash integrity.
            if let Some(stored_hash) = storage.get(state::WASM_HASH_KEY) {
                if stored_hash != wasm_hash {
                    tracing::warn!(
                        label = %config.label,
                        "WASM binary changed, stored state may be incompatible"
                    );
                }
            }
            storage.put(state::WASM_HASH_KEY, &wasm_hash)?;

            // Compile WASM module.
            let runtime = WasmIndexerRuntime::new(&wasm_bytes)?;

            let tip_height = storage.tip_height();

            tracing::info!(
                label = %config.label,
                hash = %hash_hex,
                tip_height = tip_height,
                smt = config.smt_enabled,
                "indexer module loaded"
            );

            let instance = Arc::new(IndexerInstance {
                label: config.label.clone(),
                runtime: parking_lot::Mutex::new(runtime),
                storage,
                wasm_hash,
                tip_height: AtomicU32::new(tip_height),
                smt_enabled: config.smt_enabled,
            });

            indexers.insert(config.label, instance);
        }

        Ok(IndexerManager { indexers, mode })
    }

    /// Get a reference to a loaded indexer by label.
    pub fn get_indexer(&self, label: &str) -> Option<&Arc<IndexerInstance>> {
        self.indexers.get(label)
    }

    /// Get all indexer labels.
    pub fn labels(&self) -> Vec<&str> {
        self.indexers.keys().map(|s| s.as_str()).collect()
    }

    /// True if no indexers are loaded.
    pub fn is_empty(&self) -> bool {
        self.indexers.is_empty()
    }

    /// Get the indexer mode.
    pub fn mode(&self) -> IndexerMode {
        self.mode
    }

    /// Notify all indexers that a new block has been connected.
    ///
    /// `block_data` is the raw serialized block.
    /// In synchronous mode, blocks until all indexers finish.
    pub fn on_block_connected(&self, height: u32, block_data: &[u8]) {
        if self.indexers.is_empty() {
            return;
        }

        // Build input: [height_le32 ++ block_data]
        let mut input = Vec::with_capacity(4 + block_data.len());
        input.extend_from_slice(&height.to_le_bytes());
        input.extend_from_slice(block_data);
        let input = Arc::new(input);

        match self.mode {
            IndexerMode::Synchronous => {
                // Run all indexers in parallel using rayon.
                let instances: Vec<&Arc<IndexerInstance>> = self.indexers.values().collect();
                rayon::scope(|s| {
                    for inst in &instances {
                        let inst = Arc::clone(inst);
                        let input = Arc::clone(&input);
                        s.spawn(move |_| {
                            run_indexer_block(&inst, height, &input);
                        });
                    }
                });
            }
            IndexerMode::Async => {
                // In async mode, still run synchronously for now (can add channel later).
                let instances: Vec<&Arc<IndexerInstance>> = self.indexers.values().collect();
                rayon::scope(|s| {
                    for inst in &instances {
                        let inst = Arc::clone(inst);
                        let input = Arc::clone(&input);
                        s.spawn(move |_| {
                            run_indexer_block(&inst, height, &input);
                        });
                    }
                });
            }
        }
    }

    /// Notify all indexers of a chain reorganization.
    ///
    /// Each indexer rolls back its state to `rollback_height`.
    pub fn on_reorg(&self, rollback_height: u32) {
        for (label, inst) in &self.indexers {
            let current = inst.tip_height.load(Ordering::Relaxed);
            if current > rollback_height {
                tracing::info!(
                    indexer = %label,
                    from = current,
                    to = rollback_height,
                    "rolling back indexer"
                );
                match rollback::rollback_to_height(&inst.storage, rollback_height) {
                    Ok(deleted) => {
                        inst.tip_height.store(rollback_height, Ordering::Relaxed);
                        tracing::info!(
                            indexer = %label,
                            deleted = deleted,
                            "indexer rollback complete"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            indexer = %label,
                            error = %e,
                            "indexer rollback failed"
                        );
                    }
                }
            }
        }
    }

    /// Call a view function on an indexer (async, with fuel-based yielding).
    pub async fn call_view_async(
        &self,
        label: &str,
        fn_name: &str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        let runtime = inst.runtime.lock();
        runtime
            .call_view_async(fn_name, input, inst.storage.clone(), label)
            .await
    }

    /// Call a view function on an indexer (sync, for non-async contexts).
    pub fn call_view(
        &self,
        label: &str,
        fn_name: &str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        let runtime = inst.runtime.lock();
        runtime.call_view(fn_name, input, inst.storage.clone(), label)
    }

    /// Get the current tip height for an indexer.
    pub fn indexer_height(&self, label: &str) -> Option<u32> {
        self.get_indexer(label)
            .map(|inst| inst.tip_height.load(Ordering::Relaxed))
    }

    /// Replay blocks for indexers that are behind the chain tip.
    ///
    /// `read_block` is a callback that reads a block at a given height,
    /// returning the raw serialized block data.
    pub fn catch_up<F>(&self, chain_height: u32, read_block: F)
    where
        F: Fn(u32) -> Option<Vec<u8>>,
    {
        for (label, inst) in &self.indexers {
            let indexer_height = inst.tip_height.load(Ordering::Relaxed);
            if indexer_height < chain_height {
                tracing::info!(
                    indexer = %label,
                    from = indexer_height + 1,
                    to = chain_height,
                    "replaying blocks for indexer catch-up"
                );
                for h in (indexer_height + 1)..=chain_height {
                    if let Some(block_data) = read_block(h) {
                        let mut input = Vec::with_capacity(4 + block_data.len());
                        input.extend_from_slice(&h.to_le_bytes());
                        input.extend_from_slice(&block_data);
                        run_indexer_block(inst, h, &input);
                    } else {
                        tracing::warn!(
                            indexer = %label,
                            height = h,
                            "block not available for catch-up, stopping"
                        );
                        break;
                    }
                }
            }
        }
    }
}

/// Build a minimal WASM binary for testing.
/// Calls __host_len and __flush (empty protobuf).
#[cfg(test)]
fn build_test_wasm() -> Vec<u8> {
    wat::parse_str(r#"
        (module
            (import "env" "__host_len" (func $host_len (result i32)))
            (import "env" "__load_input" (func $load_input (param i32)))
            (import "env" "__flush" (func $flush (param i32)))
            (import "env" "__log" (func $log (param i32)))
            (import "env" "__get" (func $get (param i32 i32)))
            (import "env" "__get_len" (func $get_len (param i32) (result i32)))
            (import "env" "abort" (func $abort (param i32 i32 i32 i32)))
            (memory (export "memory") 1)

            (func (export "_start")
                (drop (call $host_len))
                (i32.store (i32.const 96) (i32.const 0))
                (call $flush (i32.const 100))
            )
        )
    "#).expect("failed to parse test WAT")
}

/// Run a single indexer on a block, writing results to storage.
fn run_indexer_block(inst: &IndexerInstance, height: u32, input: &[u8]) {
    let runtime = inst.runtime.lock();
    match runtime.run_block(input.to_vec(), inst.storage.clone(), &inst.label) {
        Ok(pairs) => {
            // Write all key-value pairs using append-only model.
            for (key, value) in &pairs {
                if let Err(e) = inst.storage.append(key, value, height) {
                    tracing::error!(
                        indexer = %inst.label,
                        height = height,
                        error = %e,
                        "failed to append indexer state"
                    );
                    return;
                }
            }

            // Compute SMT root if enabled.
            if inst.smt_enabled && !pairs.is_empty() {
                let root = smt::compute_state_root(&pairs);
                let root_key = smt::smt_root_key(height);
                if let Err(e) = inst.storage.put(&root_key, &root) {
                    tracing::error!(
                        indexer = %inst.label,
                        height = height,
                        error = %e,
                        "failed to store SMT root"
                    );
                }
            }

            // Update tip height.
            if let Err(e) = inst.storage.set_tip_height(height) {
                tracing::error!(
                    indexer = %inst.label,
                    height = height,
                    error = %e,
                    "failed to update indexer tip height"
                );
                return;
            }
            inst.tip_height.store(height, Ordering::Relaxed);

            tracing::debug!(
                indexer = %inst.label,
                height = height,
                pairs = pairs.len(),
                "indexer processed block"
            );
        }
        Err(e) => {
            tracing::error!(
                indexer = %inst.label,
                height = height,
                error = %e,
                "indexer failed to process block"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn setup_indexer_manager(mode: IndexerMode) -> (IndexerManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let configs = vec![config::IndexerConfig {
            label: "test".to_string(),
            wasm_path,
            smt_enabled: false,
        }];

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(configs, &datadir, mode).unwrap();
        (mgr, dir)
    }

    #[test]
    fn test_indexer_manager_load() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        assert!(!mgr.is_empty());
        assert_eq!(mgr.labels().len(), 1);
        assert!(mgr.get_indexer("test").is_some());
        assert!(mgr.get_indexer("nonexistent").is_none());
    }

    #[test]
    fn test_indexer_manager_initial_height() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        assert_eq!(mgr.indexer_height("test"), Some(0));
    }

    #[test]
    fn test_on_block_connected_sync() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);

        // Feed a fake block.
        mgr.on_block_connected(1, b"fake_block");
        assert_eq!(mgr.indexer_height("test"), Some(1));

        mgr.on_block_connected(2, b"fake_block_2");
        assert_eq!(mgr.indexer_height("test"), Some(2));
    }

    #[test]
    fn test_on_block_connected_async() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Async);
        mgr.on_block_connected(1, b"fake_block");
        assert_eq!(mgr.indexer_height("test"), Some(1));
    }

    #[test]
    fn test_on_reorg() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);

        mgr.on_block_connected(1, b"block1");
        mgr.on_block_connected(2, b"block2");
        mgr.on_block_connected(3, b"block3");
        assert_eq!(mgr.indexer_height("test"), Some(3));

        // Reorg back to height 1.
        mgr.on_reorg(1);
        assert_eq!(mgr.indexer_height("test"), Some(1));
    }

    #[test]
    fn test_on_reorg_noop_when_below() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);

        mgr.on_block_connected(1, b"block1");

        // Reorg to height 5 — indexer is only at 1, should be a no-op.
        mgr.on_reorg(5);
        assert_eq!(mgr.indexer_height("test"), Some(1));
    }

    #[test]
    fn test_wasm_hash() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        let inst = mgr.get_indexer("test").unwrap();
        // Hash should be non-zero (valid SHA-256).
        assert_ne!(inst.wasm_hash, [0u8; 32]);
    }

    #[test]
    fn test_mode() {
        let (mgr_sync, _dir1) = setup_indexer_manager(IndexerMode::Synchronous);
        assert_eq!(mgr_sync.mode(), IndexerMode::Synchronous);

        let (mgr_async, _dir2) = setup_indexer_manager(IndexerMode::Async);
        assert_eq!(mgr_async.mode(), IndexerMode::Async);
    }

    #[test]
    fn test_empty_manager() {
        let dir = tempfile::tempdir().unwrap();
        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(vec![], &datadir, IndexerMode::Synchronous).unwrap();
        assert!(mgr.is_empty());
        assert_eq!(mgr.labels().len(), 0);
    }

    #[test]
    fn test_catch_up() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);

        // Simulate catch-up from height 1 to 3.
        mgr.catch_up(3, |h| Some(format!("block_{}", h).into_bytes()));
        assert_eq!(mgr.indexer_height("test"), Some(3));
    }

    #[test]
    fn test_catch_up_stops_on_missing_block() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);

        // Block 2 is missing, catch-up should stop at 1.
        mgr.catch_up(3, |h| {
            if h <= 1 {
                Some(format!("block_{}", h).into_bytes())
            } else {
                None
            }
        });
        assert_eq!(mgr.indexer_height("test"), Some(1));
    }

    #[test]
    fn test_multiple_indexers() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let configs = vec![
            config::IndexerConfig {
                label: "idx_a".to_string(),
                wasm_path: wasm_path.clone(),
                smt_enabled: false,
            },
            config::IndexerConfig {
                label: "idx_b".to_string(),
                wasm_path,
                smt_enabled: true,
            },
        ];

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(configs, &datadir, IndexerMode::Synchronous).unwrap();

        assert_eq!(mgr.labels().len(), 2);
        assert!(mgr.get_indexer("idx_a").is_some());
        assert!(mgr.get_indexer("idx_b").is_some());

        // Both process the same block in parallel.
        mgr.on_block_connected(1, b"block");
        assert_eq!(mgr.indexer_height("idx_a"), Some(1));
        assert_eq!(mgr.indexer_height("idx_b"), Some(1));
    }

    #[test]
    fn test_smt_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let configs = vec![config::IndexerConfig {
            label: "smt_test".to_string(),
            wasm_path,
            smt_enabled: true,
        }];

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(configs, &datadir, IndexerMode::Synchronous).unwrap();
        let inst = mgr.get_indexer("smt_test").unwrap();
        assert!(inst.smt_enabled);
    }

    #[test]
    fn test_call_view_not_found() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        let result = mgr.call_view("nonexistent", "fn", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_invalid_wasm_path() {
        let dir = tempfile::tempdir().unwrap();
        let configs = vec![config::IndexerConfig {
            label: "bad".to_string(),
            wasm_path: PathBuf::from("/nonexistent/path.wasm"),
            smt_enabled: false,
        }];
        let datadir = PathBuf::from(dir.path());
        let result = IndexerManager::new(configs, &datadir, IndexerMode::Synchronous);
        assert!(result.is_err());
    }
}
