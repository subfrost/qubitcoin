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
    /// Block height at which this indexer starts processing.
    pub start_height: u32,
    /// Indexer layer (secondary or tertiary).
    pub layer: config::IndexerLayer,
    /// Labels of indexers this one depends on (tertiary only).
    pub depends_on: Vec<String>,
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
                start_height: config.start_height,
                layer: config.layer,
                depends_on: config.depends_on.clone(),
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
    ///
    /// Indexers are processed in two phases:
    /// 1. Secondary indexers (no dependencies) run in parallel.
    /// 2. Tertiary indexers run after their dependencies have completed.
    ///
    /// An indexer is skipped if `height < start_height`.
    pub fn on_block_connected(&self, height: u32, block_data: &[u8]) {
        if self.indexers.is_empty() {
            return;
        }

        // Build input: [height_le32 ++ block_data]
        let mut input = Vec::with_capacity(4 + block_data.len());
        input.extend_from_slice(&height.to_le_bytes());
        input.extend_from_slice(block_data);
        let input = Arc::new(input);

        // Phase 1: Run secondary indexers (and tertiary with no deps) in parallel.
        let (phase1, phase2): (Vec<_>, Vec<_>) = self
            .indexers
            .values()
            .partition(|inst| inst.depends_on.is_empty());

        let run_phase = |instances: &[&Arc<IndexerInstance>]| {
            rayon::scope(|s| {
                for inst in instances {
                    if height < inst.start_height {
                        continue;
                    }
                    let inst = Arc::clone(inst);
                    let input = Arc::clone(&input);
                    s.spawn(move |_| {
                        run_indexer_block(&inst, height, &input);
                    });
                }
            });
        };

        run_phase(&phase1);

        // Phase 2: Run tertiary indexers whose dependencies have all reached
        // this height (i.e., phase 1 completed for them).
        if !phase2.is_empty() {
            let ready: Vec<&Arc<IndexerInstance>> = phase2
                .into_iter()
                .filter(|inst| {
                    if height < inst.start_height {
                        return false;
                    }
                    self.dependencies_satisfied(inst, height)
                })
                .collect();

            run_phase(&ready);
        }
    }

    /// Check if all dependencies for a tertiary indexer have reached the
    /// given height.
    fn dependencies_satisfied(&self, inst: &IndexerInstance, height: u32) -> bool {
        for dep_label in &inst.depends_on {
            match self.indexers.get(dep_label) {
                Some(dep) => {
                    if dep.tip_height.load(Ordering::Relaxed) < height {
                        return false;
                    }
                }
                None => {
                    tracing::warn!(
                        indexer = %inst.label,
                        dependency = %dep_label,
                        "dependency not found, skipping"
                    );
                    return false;
                }
            }
        }
        true
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
    ///
    /// Respects `start_height`: indexers won't replay blocks below their
    /// configured start height. Tertiary indexers replay after their
    /// dependencies have caught up.
    pub fn catch_up<F>(&self, chain_height: u32, read_block: F)
    where
        F: Fn(u32) -> Option<Vec<u8>>,
    {
        // Phase 1: catch up secondary indexers (no dependencies).
        for (label, inst) in &self.indexers {
            if !inst.depends_on.is_empty() {
                continue; // tertiary — handle in phase 2
            }
            self.catch_up_single(inst, label, chain_height, &read_block);
        }

        // Phase 2: catch up tertiary indexers (dependencies should now be current).
        for (label, inst) in &self.indexers {
            if inst.depends_on.is_empty() {
                continue; // already handled
            }
            if !self.dependencies_satisfied(inst, chain_height) {
                tracing::warn!(
                    indexer = %label,
                    "skipping tertiary catch-up: dependencies not satisfied"
                );
                continue;
            }
            self.catch_up_single(inst, label, chain_height, &read_block);
        }
    }

    fn catch_up_single<F>(
        &self,
        inst: &IndexerInstance,
        label: &str,
        chain_height: u32,
        read_block: &F,
    ) where
        F: Fn(u32) -> Option<Vec<u8>>,
    {
        let indexer_height = inst.tip_height.load(Ordering::Relaxed);
        let effective_start = std::cmp::max(indexer_height + 1, inst.start_height);
        if effective_start > chain_height {
            return;
        }
        tracing::info!(
            indexer = %label,
            from = effective_start,
            to = chain_height,
            "replaying blocks for indexer catch-up"
        );
        for h in effective_start..=chain_height {
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

    fn make_config(label: &str, wasm_path: PathBuf) -> config::IndexerConfig {
        config::IndexerConfig {
            label: label.to_string(),
            wasm_path,
            smt_enabled: false,
            start_height: 0,
            layer: config::IndexerLayer::Secondary,
            depends_on: vec![],
        }
    }

    fn setup_indexer_manager(mode: IndexerMode) -> (IndexerManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let configs = vec![make_config("test", wasm_path)];

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
            make_config("idx_a", wasm_path.clone()),
            {
                let mut c = make_config("idx_b", wasm_path);
                c.smt_enabled = true;
                c
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

        let configs = vec![{
            let mut c = make_config("smt_test", wasm_path);
            c.smt_enabled = true;
            c
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
        let configs = vec![make_config("bad", PathBuf::from("/nonexistent/path.wasm"))];
        let datadir = PathBuf::from(dir.path());
        let result = IndexerManager::new(configs, &datadir, IndexerMode::Synchronous);
        assert!(result.is_err());
    }

    #[test]
    fn test_start_height_skips_early_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let mut cfg = make_config("late_start", wasm_path);
        cfg.start_height = 5;

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(vec![cfg], &datadir, IndexerMode::Synchronous).unwrap();

        // Blocks 1-4 should be skipped.
        mgr.on_block_connected(1, b"block1");
        mgr.on_block_connected(2, b"block2");
        mgr.on_block_connected(3, b"block3");
        mgr.on_block_connected(4, b"block4");
        assert_eq!(mgr.indexer_height("late_start"), Some(0)); // still at 0

        // Block 5 should be processed.
        mgr.on_block_connected(5, b"block5");
        assert_eq!(mgr.indexer_height("late_start"), Some(5));

        // Block 6 onwards is normal.
        mgr.on_block_connected(6, b"block6");
        assert_eq!(mgr.indexer_height("late_start"), Some(6));
    }

    #[test]
    fn test_tertiary_depends_on_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let secondary = make_config("primary_idx", wasm_path.clone());
        let mut tertiary = make_config("derived_idx", wasm_path);
        tertiary.layer = config::IndexerLayer::Tertiary;
        tertiary.depends_on = vec!["primary_idx".to_string()];

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(
            vec![secondary, tertiary],
            &datadir,
            IndexerMode::Synchronous,
        )
        .unwrap();

        // Block 1: secondary processes first, then tertiary.
        mgr.on_block_connected(1, b"block1");
        assert_eq!(mgr.indexer_height("primary_idx"), Some(1));
        assert_eq!(mgr.indexer_height("derived_idx"), Some(1));

        // Block 2: same.
        mgr.on_block_connected(2, b"block2");
        assert_eq!(mgr.indexer_height("primary_idx"), Some(2));
        assert_eq!(mgr.indexer_height("derived_idx"), Some(2));
    }

    #[test]
    fn test_tertiary_with_start_height_and_dependency() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let secondary = make_config("base", wasm_path.clone());
        let mut tertiary = make_config("overlay", wasm_path);
        tertiary.layer = config::IndexerLayer::Tertiary;
        tertiary.depends_on = vec!["base".to_string()];
        tertiary.start_height = 3;

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(
            vec![secondary, tertiary],
            &datadir,
            IndexerMode::Synchronous,
        )
        .unwrap();

        // Blocks 1-2: secondary runs, tertiary skipped (start_height=3).
        mgr.on_block_connected(1, b"b1");
        mgr.on_block_connected(2, b"b2");
        assert_eq!(mgr.indexer_height("base"), Some(2));
        assert_eq!(mgr.indexer_height("overlay"), Some(0));

        // Block 3: both run.
        mgr.on_block_connected(3, b"b3");
        assert_eq!(mgr.indexer_height("base"), Some(3));
        assert_eq!(mgr.indexer_height("overlay"), Some(3));
    }

    #[test]
    fn test_catch_up_respects_start_height() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let mut cfg = make_config("late", wasm_path);
        cfg.start_height = 3;

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(vec![cfg], &datadir, IndexerMode::Synchronous).unwrap();

        // Catch up to height 5 — should only process blocks 3, 4, 5.
        mgr.catch_up(5, |h| Some(format!("block_{}", h).into_bytes()));
        assert_eq!(mgr.indexer_height("late"), Some(5));
    }

    #[test]
    fn test_missing_dependency_skips_tertiary() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        // Tertiary depends on "missing_dep" which doesn't exist.
        let mut tertiary = make_config("orphan", wasm_path);
        tertiary.layer = config::IndexerLayer::Tertiary;
        tertiary.depends_on = vec!["missing_dep".to_string()];

        let datadir = PathBuf::from(dir.path());
        let mgr = IndexerManager::new(vec![tertiary], &datadir, IndexerMode::Synchronous).unwrap();

        // Block should be skipped because dependency doesn't exist.
        mgr.on_block_connected(1, b"block1");
        assert_eq!(mgr.indexer_height("orphan"), Some(0));
    }
}
