//! In-process WASM secondary indexer runtime for Qubitcoin.
//!
//! Embeds metashrew-compatible WASM indexers that run in-process alongside
//! the chain tip, providing atomic reorg handling and zero-config indexing.
//!
//! The loaded indexers form a DAG rooted at the raw block (see [`dag`] and
//! `docs/INDEXER-DAG.md`): indexers read other indexers through `secondary`
//! edges and may take their input block from a [`transform`] node. The same
//! DAG can be run in fork mode over a hypothetical block ([`simulation`]),
//! and users can register their own nodes ([`usernodes`]).

pub mod adapters;
pub mod config;
pub mod dag;
pub mod dag_rpc;
pub mod rollback;
pub mod rpc;
pub mod runtime;
pub mod simulation;
pub mod smt;
pub mod state;
pub mod storage;
pub mod store;
pub mod transform;

use config::{IndexerConfig, TransformConfig};
use dag::{DagAccess, DagBackend};
use metashrew_runtime::MetashrewRuntime;
use qubitcoin_indexer_fork::{ExecLimits, ForkRuntime};
use rockshrew_runtime::RocksDBRuntimeAdapter;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use transform::TransformNode;

pub use adapters::{QubitcoinNodeAdapter, QubitcoinStorageAdapter};

/// A block queued for async indexer processing.
struct IndexerBlock {
    height: u32,
    data: Arc<Vec<u8>>, // [height_le32 ++ block_data]
}

/// Work for an indexer's worker thread, processed strictly in order.
enum IndexerMsg {
    Block(IndexerBlock),
    /// Roll the indexer back to this height.
    Reorg(u32),
}

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
///
/// Indexers without `secondary` edges run on the real metashrew/rockshrew
/// runtime (`runtime = Some`), for exact storage-format compatibility with
/// production alkanes.wasm and other modules. Indexers that read other
/// indexers through `__secondary_get` (which `MetashrewRuntime` does not
/// link) run on the fork runtime and commit through the same metashrew
/// store code (`runtime = None`). Both keep their KV in the same layout.
pub struct IndexerInstance {
    /// Human-readable label.
    pub label: String,
    /// MetashrewRuntime backed by RocksDB (None for fork-runner indexers).
    pub runtime: Option<Arc<tokio::sync::RwLock<MetashrewRuntime<RocksDBRuntimeAdapter>>>>,
    /// Direct RocksDB handle for admin/raw reads (secondarykvget, etc.).
    pub db: Arc<rocksdb::DB>,
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
    /// `secondary` edges: indexers whose KV this one reads.
    pub depends_on: Vec<String>,
    /// `transform` edge: the transform node producing this indexer's input.
    pub input: Option<String>,
    /// Whether this indexer is paused (skipped by on_block_connected).
    pub paused: AtomicBool,
    /// Path to the RocksDB directory (for rsyncd exposure / admin).
    pub db_path: PathBuf,
    /// Channel sender for async block processing. When set, blocks are
    /// queued to a dedicated worker thread instead of processed inline.
    block_sender: Option<mpsc::SyncSender<IndexerMsg>>,
    /// The WASM binary (fork mode compiles it on first use).
    pub wasm_bytes: Arc<Vec<u8>>,
    fork: OnceLock<Result<Arc<ForkRuntime>, String>>,
    /// Last block-processing error, if the last block failed.
    pub last_error: parking_lot::Mutex<Option<String>>,
}

impl IndexerInstance {
    /// The fork-mode runtime for this indexer's wasm (compiled once).
    pub fn fork_runtime(&self) -> Result<Arc<ForkRuntime>, String> {
        self.fork
            .get_or_init(|| ForkRuntime::new(&self.wasm_bytes).map(Arc::new))
            .clone()
    }

    /// `"metashrew"` or `"fork"`.
    pub fn runner(&self) -> &'static str {
        if self.runtime.is_some() {
            "metashrew"
        } else {
            "fork"
        }
    }

    /// True once any block has been committed to this indexer's store.
    pub fn has_state(&self) -> bool {
        store::stored_tip(&self.db).is_some()
    }
}

/// Info returned by `pause()`.
pub struct PauseInfo {
    pub label: String,
    pub db_path: PathBuf,
    pub tip_height: u32,
}

/// Info returned by `status()`.
pub struct IndexerStatusInfo {
    pub label: String,
    pub height: u32,
    pub paused: bool,
    pub wasm_hash: String,
    pub layer: config::IndexerLayer,
    pub db_path: PathBuf,
    pub smt_enabled: bool,
    pub start_height: u32,
    pub depends_on: Vec<String>,
    pub input: Option<String>,
    pub runner: &'static str,
    pub last_error: Option<String>,
}

/// The standard DAG, shared by worker threads, the simulation engine and
/// user nodes.
pub struct DagShared {
    pub indexers: parking_lot::RwLock<HashMap<String, Arc<IndexerInstance>>>,
    pub transforms: parking_lot::RwLock<HashMap<String, Arc<TransformNode>>>,
    /// Topological order of all standard nodes (indexers and transforms).
    pub order: parking_lot::RwLock<Vec<String>>,
    /// Recent transform outputs keyed by (transform, height, header hash).
    transform_cache: parking_lot::Mutex<VecDeque<((String, u32, [u8; 32]), Arc<Vec<u8>>)>>,
}

const TRANSFORM_CACHE_ENTRIES: usize = 16;

impl DagShared {
    fn new() -> Self {
        DagShared {
            indexers: parking_lot::RwLock::new(HashMap::new()),
            transforms: parking_lot::RwLock::new(HashMap::new()),
            order: parking_lot::RwLock::new(Vec::new()),
            transform_cache: parking_lot::Mutex::new(VecDeque::new()),
        }
    }

    pub fn indexer(&self, name: &str) -> Option<Arc<IndexerInstance>> {
        self.indexers.read().get(name).cloned()
    }

    pub fn transform(&self, name: &str) -> Option<Arc<TransformNode>> {
        self.transforms.read().get(name).cloned()
    }

    /// The DAG as name → upstream names (indexers and transforms).
    pub fn graph(&self) -> BTreeMap<String, Vec<String>> {
        let mut g = BTreeMap::new();
        for (n, i) in self.indexers.read().iter() {
            let mut ups = i.depends_on.clone();
            if let Some(t) = &i.input {
                ups.push(t.clone());
            }
            g.insert(n.clone(), ups);
        }
        for (n, t) in self.transforms.read().iter() {
            g.insert(n.clone(), t.upstreams());
        }
        g
    }

    /// Recompute the topological order (errors on cycles / unknown nodes).
    fn reorder(&self) -> Result<(), String> {
        let order = dag::topo_order(&self.graph())?;
        *self.order.write() = order;
        Ok(())
    }

    /// Indexers `inst` must wait for before processing a height: its
    /// `secondary` upstreams plus its input transform's upstreams.
    pub fn wait_set(&self, inst: &IndexerInstance) -> Vec<String> {
        let mut v = inst.depends_on.clone();
        if let Some(t) = inst.input.as_ref().and_then(|t| self.transform(t)) {
            v.extend(t.upstreams());
        }
        v
    }

    /// True once every indexer in `deps` has processed `height` (an indexer
    /// whose start height is above `height` never will, and counts as ready).
    pub fn deps_ready(&self, deps: &[String], height: u32) -> bool {
        deps.iter().all(|d| match self.indexer(d) {
            Some(dep) => {
                height < dep.start_height
                    || (dep.tip_height.load(Ordering::Acquire) >= height && dep.has_state())
            }
            None => false,
        })
    }

    /// Output of transform `name` for the raw block at `height`, computed
    /// against the persistent upstream state at `height` (cached).
    pub async fn transform_output(&self, self_arc: &Arc<DagShared>, name: &str, height: u32, raw_block: &[u8]) -> Result<Arc<Vec<u8>>, String> {
        let key_hash: [u8; 32] = Sha256::digest(&raw_block[..raw_block.len().min(80)]).into();
        let key = (name.to_string(), height, key_hash);
        if let Some((_, v)) = self.transform_cache.lock().iter().find(|(k, _)| *k == key) {
            return Ok(v.clone());
        }
        let t = self.transform(name).ok_or_else(|| format!("unknown transform '{}'", name))?;
        let access = DagAccess {
            node: name.to_string(),
            allowed: t.upstreams(),
            backend: Arc::new(PersistentBackend { shared: self_arc.clone(), height }),
        };
        let out = t
            .apply(height, raw_block, access, ExecLimits::default())
            .await
            .map_err(|e| format!("transform '{}' at {}: {}", name, height, e))?;
        let out = Arc::new(out.value);
        let mut c = self.transform_cache.lock();
        c.push_back((key, out.clone()));
        while c.len() > TRANSFORM_CACHE_ENTRIES {
            c.pop_front();
        }
        Ok(out)
    }

    fn clear_transform_cache(&self) {
        self.transform_cache.lock().clear();
    }
}

/// Upstream reads against the persistent stores, as of a height.
pub struct PersistentBackend {
    pub shared: Arc<DagShared>,
    pub height: u32,
}

#[async_trait::async_trait]
impl DagBackend for PersistentBackend {
    fn kv_get(&self, node: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let inst = self.shared.indexer(node).ok_or_else(|| format!("unknown indexer '{}'", node))?;
        store::read_at_height(&inst.db, key, self.height)
    }

    async fn view(&self, node: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        let inst = self.shared.indexer(node).ok_or_else(|| format!("unknown indexer '{}'", node))?;
        persistent_view(&self.shared, &inst, view_fn, input, self.height).await
    }
}

/// Call a view of a persistent indexer as of `height`.
pub async fn persistent_view(
    shared: &Arc<DagShared>,
    inst: &Arc<IndexerInstance>,
    view_fn: &str,
    input: Vec<u8>,
    height: u32,
) -> Result<Vec<u8>, String> {
    match &inst.runtime {
        Some(rt) => {
            let runtime = rt.read().await;
            runtime
                .view(view_fn.to_string(), &input, height)
                .await
                .map_err(|e| format!("view '{}' failed: {}", view_fn, e))
        }
        None => {
            let fork = inst.fork_runtime()?;
            let mut full = Vec::with_capacity(4 + input.len());
            full.extend_from_slice(&height.to_le_bytes());
            full.extend_from_slice(&input);
            let access = DagAccess {
                node: inst.label.clone(),
                allowed: inst.depends_on.clone(),
                backend: Arc::new(PersistentBackend { shared: shared.clone(), height }),
            };
            fork.call_export_ctx(
                view_fn,
                full,
                store::fork_storage(store::LayeredReader::at_height(inst.db.clone(), height), height),
                &inst.label,
                access.host(),
                ExecLimits::default(),
            )
            .await
            .map(|o| o.value)
            .map_err(|e| format!("view '{}' failed: {}", view_fn, e))
        }
    }
}

/// Manages all loaded indexer instances.
pub struct IndexerManager {
    indexers: HashMap<String, Arc<IndexerInstance>>,
    mode: IndexerMode,
    datadir: PathBuf,
    shared: Arc<DagShared>,
}

/// Open (or create) an indexer's store and runtime.
fn open_instance(config: &IndexerConfig, datadir: &Path) -> Result<IndexerInstance, String> {
    tracing::info!(
        label = %config.label,
        wasm = %config.wasm_path.display(),
        "loading indexer module"
    );
    let wasm_bytes = std::fs::read(&config.wasm_path).map_err(|e| {
        format!("failed to read WASM file '{}': {}", config.wasm_path.display(), e)
    })?;
    let wasm_hash: [u8; 32] = Sha256::digest(&wasm_bytes).into();

    let db_dir = datadir.join("indexers").join(&config.label).join("db");
    std::fs::create_dir_all(&db_dir).map_err(|e| format!("failed to create indexer db dir: {}", e))?;
    let db_opts = RocksDBRuntimeAdapter::get_optimized_options();
    let db = Arc::new(
        rocksdb::DB::open(&db_opts, &db_dir)
            .map_err(|e| format!("failed to open RocksDB at {:?}: {}", db_dir, e))?,
    );

    // Secondary edges need `__secondary_get`, which only the fork runner links.
    let runtime = if config.depends_on.is_empty() && !config.fork_runner {
        let adapter = RocksDBRuntimeAdapter::new(db.clone());
        // Spawn on a dedicated thread to avoid "cannot block inside async" panic.
        let rt = std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio for metashrew init");
                rt.block_on(MetashrewRuntime::new(&wasm_bytes, adapter))
            })
            .join()
            .expect("metashrew init thread panicked")
        })
        .map_err(|e| format!("metashrew runtime init: {}", e))?;
        Some(Arc::new(tokio::sync::RwLock::new(rt)))
    } else {
        // Validate the module up front.
        ForkRuntime::new(&wasm_bytes).map_err(|e| format!("indexer '{}': {}", config.label, e))?;
        None
    };

    let tip_height = store::stored_tip(&db).unwrap_or(0);
    Ok(IndexerInstance {
        label: config.label.clone(),
        runtime,
        db,
        wasm_hash,
        tip_height: AtomicU32::new(tip_height),
        smt_enabled: config.smt_enabled,
        start_height: config.start_height,
        layer: config.layer,
        depends_on: config.depends_on.clone(),
        input: config.input.clone(),
        paused: AtomicBool::new(false),
        db_path: db_dir,
        block_sender: None,
        wasm_bytes: Arc::new(wasm_bytes),
        fork: OnceLock::new(),
        last_error: parking_lot::Mutex::new(None),
    })
}

/// Process the hardcoded genesis block on a fresh metashrew-runner indexer
/// without edges (MetashrewRuntime needs block 0 to initialize its state).
fn process_genesis(inst: &IndexerInstance) {
    let Some(runtime) = inst.runtime.clone() else { return };
    let genesis_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";
    let genesis_bytes = hex::decode(genesis_hex).expect("genesis hex");
    tracing::info!(label = %inst.label, "processing genesis block (height 0)");
    let r = std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio for genesis");
            rt.block_on(async {
                {
                    let guard = runtime.read().await;
                    let mut ctx = guard.context.write().expect("metashrew context lock poisoned");
                    ctx.block = genesis_bytes;
                    ctx.height = 0;
                }
                runtime.read().await.run().await
            })
        })
        .join()
        .expect("genesis thread panicked")
    });
    match r {
        Ok(()) => tracing::info!(label = %inst.label, "genesis block processed"),
        Err(e) => tracing::warn!(label = %inst.label, error = %e, "genesis block processing failed (non-fatal)"),
    }
}

impl IndexerManager {
    /// Create a new IndexerManager by loading indexers from configs.
    ///
    /// Each indexer gets its own RocksDB at `{datadir}/indexers/{label}/db/`.
    /// Transform nodes named by an indexer's `input` in the
    /// `upstream/view/MAGIC` shorthand are created automatically.
    pub fn new(configs: Vec<IndexerConfig>, datadir: &PathBuf, mode: IndexerMode) -> Result<Self, String> {
        Self::with_transforms(configs, vec![], datadir, mode)
    }

    /// Like [`IndexerManager::new`], with explicit transform nodes.
    pub fn with_transforms(
        configs: Vec<IndexerConfig>,
        transforms: Vec<TransformConfig>,
        datadir: &PathBuf,
        mode: IndexerMode,
    ) -> Result<Self, String> {
        let shared = Arc::new(DagShared::new());

        // Transforms: explicit, then shorthand ones implied by `input`.
        let mut tcfgs: BTreeMap<String, TransformConfig> = BTreeMap::new();
        for t in transforms {
            tcfgs.insert(t.name.clone(), t);
        }
        for c in &configs {
            if let Some(i) = &c.input {
                if !tcfgs.contains_key(i) {
                    let t = TransformConfig::from_shorthand(i).ok_or_else(|| {
                        format!("indexer '{}': unknown transform '{}' (and not upstream/view/MAGIC)", c.label, i)
                    })?;
                    tcfgs.insert(i.clone(), t);
                }
            }
        }
        for (name, t) in &tcfgs {
            let node = TransformNode::from_config(t)?;
            shared.transforms.write().insert(name.clone(), Arc::new(node));
        }

        // Validate the graph before opening any store.
        {
            let mut g: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for c in &configs {
                let mut ups = c.depends_on.clone();
                if let Some(i) = &c.input {
                    ups.push(i.clone());
                }
                g.insert(c.label.clone(), ups);
            }
            for (n, t) in shared.transforms.read().iter() {
                for u in t.upstreams() {
                    if !configs.iter().any(|c| c.label == u) {
                        return Err(format!("transform '{}' reads '{}', which is not a loaded indexer", n, u));
                    }
                }
                g.insert(n.clone(), t.upstreams());
            }
            dag::topo_order(&g)?;
        }

        let mut indexers = HashMap::new();
        let mut receivers = Vec::new();
        for config in configs {
            let mut inst = open_instance(&config, datadir)?;
            let edges = !inst.depends_on.is_empty() || inst.input.is_some();
            if !edges && !inst.has_state() && inst.tip_height.load(Ordering::Relaxed) == 0 {
                process_genesis(&inst);
            }
            if mode == IndexerMode::Async {
                let (tx, rx) = mpsc::sync_channel::<IndexerMsg>(64);
                inst.block_sender = Some(tx);
                receivers.push((config.label.clone(), rx));
            }
            tracing::info!(
                label = %inst.label,
                hash = %hex::encode(inst.wasm_hash),
                tip_height = inst.tip_height.load(Ordering::Relaxed),
                runner = inst.runner(),
                smt = inst.smt_enabled,
                "indexer module loaded"
            );
            let inst = Arc::new(inst);
            shared.indexers.write().insert(config.label.clone(), inst.clone());
            indexers.insert(config.label, inst);
        }
        shared.reorder()?;

        // Worker threads (async mode): one per indexer, strictly in order.
        for (label, rx) in receivers {
            let inst = indexers.get(&label).unwrap().clone();
            let sh = shared.clone();
            std::thread::Builder::new()
                .name(format!("indexer-{}", label))
                .spawn(move || {
                    tracing::info!(indexer = %label, "indexer worker thread started");
                    while let Ok(msg) = rx.recv() {
                        match msg {
                            IndexerMsg::Block(block) => {
                                if inst.paused.load(Ordering::Relaxed) || block.height < inst.start_height {
                                    continue;
                                }
                                let deps = sh.wait_set(&inst);
                                let mut waited = 0u64;
                                while !sh.deps_ready(&deps, block.height) {
                                    if inst.paused.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(2));
                                    waited += 2;
                                    if waited % 60_000 == 0 {
                                        tracing::warn!(indexer = %label, height = block.height, deps = ?deps, "still waiting for upstream indexers");
                                    }
                                }
                                if inst.paused.load(Ordering::Relaxed) {
                                    continue;
                                }
                                run_indexer_block(&sh, &inst, block.height, &block.data);
                            }
                            IndexerMsg::Reorg(h) => rollback_instance(&sh, &inst, h),
                        }
                    }
                    tracing::info!(indexer = %label, "indexer worker thread exiting");
                })
                .map_err(|e| format!("failed to spawn indexer worker: {}", e))?;
        }

        Ok(IndexerManager { indexers, mode, datadir: datadir.clone(), shared })
    }

    /// The shared DAG (for the simulation engine and user nodes).
    pub fn shared(&self) -> Arc<DagShared> {
        self.shared.clone()
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
    /// In **Async mode** (recommended): queues the block to per-indexer
    /// worker threads and returns immediately. Each worker waits until the
    /// indexers it depends on (`secondary` edges and its input transform's
    /// upstreams) have processed the height.
    ///
    /// In **Synchronous mode**: runs every indexer in topological order and
    /// returns when all are done.
    pub fn on_block_connected(&self, height: u32, block_data: &[u8]) {
        if self.indexers.is_empty() {
            return;
        }
        let mut input = Vec::with_capacity(4 + block_data.len());
        input.extend_from_slice(&height.to_le_bytes());
        input.extend_from_slice(block_data);
        let input = Arc::new(input);

        let order = self.shared.order.read().clone();
        for label in &order {
            let Some(inst) = self.indexers.get(label) else { continue }; // transforms
            if height < inst.start_height || inst.paused.load(Ordering::Relaxed) {
                continue;
            }
            match &inst.block_sender {
                Some(sender) => {
                    let msg = IndexerMsg::Block(IndexerBlock { height, data: Arc::clone(&input) });
                    if sender.send(msg).is_err() {
                        tracing::error!(indexer = %inst.label, "indexer worker thread disconnected");
                    }
                }
                None => {
                    // Synchronous (or hot-loaded): inline, in topological order.
                    if self.shared.deps_ready(&self.shared.wait_set(inst), height) {
                        run_indexer_block(&self.shared, inst, height, &input);
                    } else {
                        tracing::warn!(indexer = %inst.label, height, "upstream indexers not at height, skipping");
                    }
                }
            }
        }
    }

    /// Notify all indexers of a chain reorganization: every indexer above
    /// `rollback_height` is rolled back to it (in order with its queued
    /// blocks in async mode).
    pub fn on_reorg(&self, rollback_height: u32) {
        self.shared.clear_transform_cache();
        for inst in self.indexers.values() {
            match &inst.block_sender {
                Some(sender) => {
                    let _ = sender.send(IndexerMsg::Reorg(rollback_height));
                }
                None => rollback_instance(&self.shared, inst, rollback_height),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Admin lifecycle methods
    // -----------------------------------------------------------------------

    /// Pause an indexer. While paused, `on_block_connected` skips it.
    /// Returns the DB path and tip height for admin operations (rsync, etc.).
    pub fn pause(&self, label: &str) -> Result<PauseInfo, String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        inst.paused.store(true, Ordering::Relaxed);
        inst.db.flush().ok(); // flush WAL for consistent state
        Ok(PauseInfo {
            label: label.to_string(),
            db_path: inst.db_path.clone(),
            tip_height: inst.tip_height.load(Ordering::Relaxed),
        })
    }

    /// Resume a paused indexer.
    pub fn resume(&self, label: &str) -> Result<(), String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        inst.paused.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Roll back a paused indexer to a specific height (immediate rollback).
    pub fn rollback_indexer(&self, label: &str, height: u32) -> Result<u32, String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        if !inst.paused.load(Ordering::Relaxed) {
            return Err("indexer must be paused before rollback".to_string());
        }
        let from = inst.tip_height.load(Ordering::Relaxed);
        store::rollback(&inst.db, height, from)?;
        inst.tip_height.store(height.min(from), Ordering::Relaxed);
        Ok(from.saturating_sub(height))
    }

    /// Hot-load a new WASM indexer module at runtime (processed inline).
    pub fn load(&mut self, label: &str, wasm_path: &Path, cfg: IndexerConfig) -> Result<String, String> {
        let mut cfg = cfg;
        cfg.label = label.to_string();
        cfg.wasm_path = wasm_path.to_path_buf();
        if let Some(i) = &cfg.input {
            if self.shared.transform(i).is_none() {
                let t = TransformConfig::from_shorthand(i).ok_or_else(|| format!("unknown transform '{}'", i))?;
                self.shared.transforms.write().insert(i.clone(), Arc::new(TransformNode::from_config(&t)?));
            }
        }
        let inst = Arc::new(open_instance(&cfg, &self.datadir)?);
        let hash_hex = hex::encode(inst.wasm_hash);
        self.shared.indexers.write().insert(label.to_string(), inst.clone());
        if let Err(e) = self.shared.reorder() {
            self.shared.indexers.write().remove(label);
            return Err(e);
        }
        self.indexers.insert(label.to_string(), inst);
        tracing::info!(label = label, hash = %hash_hex, "indexer hot-loaded");
        Ok(hash_hex)
    }

    /// Unload an indexer.
    pub fn unload(&mut self, label: &str) -> Result<(), String> {
        if self.indexers.remove(label).is_none() {
            return Err(format!("indexer '{}' not found", label));
        }
        self.shared.indexers.write().remove(label);
        let _ = self.shared.reorder();
        tracing::info!(label = label, "indexer unloaded");
        Ok(())
    }

    /// Get status info for all loaded indexers.
    pub fn status(&self) -> Vec<IndexerStatusInfo> {
        self.indexers
            .values()
            .map(|inst| IndexerStatusInfo {
                label: inst.label.clone(),
                height: inst.tip_height.load(Ordering::Relaxed),
                paused: inst.paused.load(Ordering::Relaxed),
                wasm_hash: hex::encode(inst.wasm_hash),
                layer: inst.layer,
                db_path: inst.db_path.clone(),
                smt_enabled: inst.smt_enabled,
                start_height: inst.start_height,
                depends_on: inst.depends_on.clone(),
                input: inst.input.clone(),
                runner: inst.runner(),
                last_error: inst.last_error.lock().clone(),
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // View methods
    // -----------------------------------------------------------------------

    /// Call a view function on an indexer at its tip (async).
    ///
    /// Each call creates a fresh wasmtime Store; no lock contention with
    /// block processing beyond the runtime's read lock.
    pub async fn call_view_async(&self, label: &str, fn_name: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?;
        let height = inst.tip_height.load(Ordering::Relaxed);
        persistent_view(&self.shared, inst, fn_name, input, height).await
    }

    /// Call a view function on an indexer (sync wrapper around async).
    pub fn call_view(&self, label: &str, fn_name: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        let shared = self.shared.clone();
        let inst = self
            .get_indexer(label)
            .ok_or_else(|| format!("indexer '{}' not found", label))?
            .clone();
        let fn_name = fn_name.to_string();
        std::thread::scope(|s| {
            s.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime: {}", e))?;
                let height = inst.tip_height.load(Ordering::Relaxed);
                rt.block_on(persistent_view(&shared, &inst, &fn_name, input, height))
            })
            .join()
            .map_err(|_| "view thread panicked".to_string())?
        })
    }

    /// Get the current tip height for an indexer.
    pub fn indexer_height(&self, label: &str) -> Option<u32> {
        self.get_indexer(label)
            .map(|inst| inst.tip_height.load(Ordering::Relaxed))
    }

    /// Replay blocks for indexers that are behind the chain tip.
    ///
    /// Each block is read once and handed to every indexer that needs it, in
    /// topological order. In **Async mode** blocks are queued to the
    /// workers; in **Synchronous mode** they are processed inline.
    pub fn catch_up<F>(&self, chain_height: u32, read_block: F)
    where
        F: Fn(u32) -> Option<Vec<u8>>,
    {
        let next: HashMap<String, u32> = self
            .indexers
            .iter()
            .map(|(l, inst)| {
                let h = if inst.has_state() || inst.tip_height.load(Ordering::Relaxed) > 0 {
                    inst.tip_height.load(Ordering::Relaxed) + 1
                } else {
                    inst.start_height
                };
                (l.clone(), h.max(inst.start_height))
            })
            .collect();
        let Some(from) = next.values().copied().min() else { return };
        if from > chain_height {
            return;
        }
        tracing::info!(from, to = chain_height, "replaying blocks for indexer catch-up");
        let order = self.shared.order.read().clone();
        for h in from..=chain_height {
            let Some(block_data) = read_block(h) else {
                tracing::warn!(height = h, "block not available for catch-up, stopping");
                break;
            };
            let mut input = Vec::with_capacity(4 + block_data.len());
            input.extend_from_slice(&h.to_le_bytes());
            input.extend_from_slice(&block_data);
            let input = Arc::new(input);
            for label in &order {
                let Some(inst) = self.indexers.get(label) else { continue };
                if h < next[label] || inst.paused.load(Ordering::Relaxed) {
                    continue;
                }
                match &inst.block_sender {
                    Some(sender) => {
                        let _ = sender.send(IndexerMsg::Block(IndexerBlock { height: h, data: input.clone() }));
                    }
                    None => run_indexer_block(&self.shared, inst, h, &input),
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

/// Roll one indexer back to `height` (no-op if it is not above it).
fn rollback_instance(shared: &Arc<DagShared>, inst: &IndexerInstance, height: u32) {
    let from = inst.tip_height.load(Ordering::Relaxed);
    if from <= height {
        return;
    }
    shared.clear_transform_cache();
    match store::rollback(&inst.db, height, from) {
        Ok(()) => {
            inst.tip_height.store(height, Ordering::Release);
            tracing::info!(indexer = %inst.label, from, to = height, "indexer rolled back");
        }
        Err(e) => {
            tracing::error!(indexer = %inst.label, from, to = height, error = %e, "indexer rollback failed");
            *inst.last_error.lock() = Some(e);
        }
    }
}

/// Run a single indexer on a block (`input` = `height_le32 ++ raw block`).
///
/// The input block is the raw block, or the output of the indexer's input
/// transform. Metashrew-runner indexers run through `MetashrewRuntime`;
/// fork-runner indexers run in fork mode over their store at `height - 1`
/// with `__secondary_get` reading their upstreams at `height`, and commit
/// through metashrew's store code.
fn run_indexer_block(shared: &Arc<DagShared>, inst: &Arc<IndexerInstance>, height: u32, input: &[u8]) {
    let raw = if input.len() > 4 { &input[4..] } else { &input[..0] };
    let result: Result<(), String> = std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio for indexer block");
            rt.block_on(async {
                let block: Arc<Vec<u8>> = match &inst.input {
                    None => Arc::new(raw.to_vec()),
                    Some(t) => shared.transform_output(shared, t, height, raw).await?,
                };
                match &inst.runtime {
                    Some(runtime_ref) => {
                        {
                            let ctx = runtime_ref.write().await;
                            let mut inner = ctx.context.write().expect("metashrew context lock poisoned");
                            inner.height = height;
                            inner.block = (*block).clone();
                        }
                        let guard = runtime_ref.read().await;
                        guard.run().await.map_err(|e| format!("{}", e))
                    }
                    None => {
                        let fork = inst.fork_runtime()?;
                        let mut full = Vec::with_capacity(4 + block.len());
                        full.extend_from_slice(&height.to_le_bytes());
                        full.extend_from_slice(&block);
                        let reader = store::LayeredReader::at_height(inst.db.clone(), height.saturating_sub(1));
                        let access = DagAccess {
                            node: inst.label.clone(),
                            allowed: inst.depends_on.clone(),
                            backend: Arc::new(PersistentBackend { shared: shared.clone(), height }),
                        };
                        let out = fork
                            .run_block_ctx(full, store::fork_storage(reader, height), &inst.label, access.host(), ExecLimits::default())
                            .await
                            .map_err(|e| e.to_string())?;
                        store::commit_block(&inst.db, height, &out.value)
                    }
                }
            })
        })
        .join()
        .unwrap_or_else(|_| Err("indexer thread panicked".into()))
    });

    match result {
        Ok(()) => {
            inst.tip_height.store(height, Ordering::Release);
            *inst.last_error.lock() = None;
            tracing::debug!(indexer = %inst.label, height = height, "indexer processed block");
        }
        Err(e) => {
            tracing::error!(indexer = %inst.label, height = height, error = %e, "indexer failed to process block");
            *inst.last_error.lock() = Some(format!("height {}: {}", height, e));
        }
    }
}

// Tests temporarily disabled during metashrew migration.
// TODO: Rewrite tests to use MetashrewRuntime instead of WasmIndexerRuntime.
#[cfg(test)]
#[cfg(feature = "__disabled_tests")]
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
            input: None,
            fork_runner: false,
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
        // In async mode, the block is queued to a worker thread.
        // Wait for the worker to process it.
        for _ in 0..100 {
            if mgr.indexer_height("test") == Some(1) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
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

    // -- Lifecycle tests: pause, resume, rollback, load, unload, status ----

    #[test]
    fn test_pause_sets_flag_and_returns_info() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.on_block_connected(1, b"block1");

        let info = mgr.pause("test").unwrap();
        assert_eq!(info.label, "test");
        assert_eq!(info.tip_height, 1);
        assert!(!info.db_path.as_os_str().is_empty());

        // Verify the paused flag is set.
        let inst = mgr.get_indexer("test").unwrap();
        assert!(inst.paused.load(Ordering::Relaxed));
    }

    #[test]
    fn test_pause_nonexistent_returns_error() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        assert!(mgr.pause("nonexistent").is_err());
    }

    #[test]
    fn test_resume_clears_flag() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.pause("test").unwrap();
        mgr.resume("test").unwrap();

        let inst = mgr.get_indexer("test").unwrap();
        assert!(!inst.paused.load(Ordering::Relaxed));
    }

    #[test]
    fn test_paused_indexer_skips_blocks() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.on_block_connected(1, b"block1");
        assert_eq!(mgr.indexer_height("test"), Some(1));

        mgr.pause("test").unwrap();
        mgr.on_block_connected(2, b"block2");
        // Should still be at height 1 (paused, block 2 skipped).
        assert_eq!(mgr.indexer_height("test"), Some(1));

        mgr.resume("test").unwrap();
        mgr.on_block_connected(3, b"block3");
        // Should advance to 3 after resume.
        assert_eq!(mgr.indexer_height("test"), Some(3));
    }

    #[test]
    fn test_rollback_indexer_requires_paused() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.on_block_connected(1, b"b1");
        mgr.on_block_connected(2, b"b2");

        // Should fail when not paused.
        assert!(mgr.rollback_indexer("test", 1).is_err());

        // Should succeed when paused.
        mgr.pause("test").unwrap();
        let _deleted = mgr.rollback_indexer("test", 0).unwrap();
        // deleted may be 0 since test WASM produces no state, but height resets.
        assert_eq!(mgr.indexer_height("test"), Some(0));
    }

    #[test]
    fn test_load_new_indexer() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let datadir = PathBuf::from(dir.path());
        let mut mgr = IndexerManager::new(vec![], &datadir, IndexerMode::Synchronous).unwrap();
        assert!(mgr.is_empty());

        let cfg = make_config("dynamic", wasm_path.clone());
        let hash = mgr.load("dynamic", &wasm_path, cfg).unwrap();
        assert!(!hash.is_empty());
        assert!(!mgr.is_empty());
        assert!(mgr.get_indexer("dynamic").is_some());

        // Loaded indexer should process blocks.
        mgr.on_block_connected(1, b"block1");
        assert_eq!(mgr.indexer_height("dynamic"), Some(1));
    }

    #[test]
    fn test_unload_removes_indexer() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, build_test_wasm()).unwrap();

        let datadir = PathBuf::from(dir.path());
        let mut mgr =
            IndexerManager::new(vec![make_config("removeme", wasm_path)], &datadir, IndexerMode::Synchronous)
                .unwrap();
        assert!(mgr.get_indexer("removeme").is_some());

        mgr.unload("removeme").unwrap();
        assert!(mgr.get_indexer("removeme").is_none());
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_unload_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let datadir = PathBuf::from(dir.path());
        let mut mgr = IndexerManager::new(vec![], &datadir, IndexerMode::Synchronous).unwrap();
        assert!(mgr.unload("ghost").is_err());
    }

    #[test]
    fn test_status_returns_all_indexers() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.on_block_connected(1, b"b1");

        let statuses = mgr.status();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].label, "test");
        assert_eq!(statuses[0].height, 1);
        assert!(!statuses[0].paused);
        assert!(!statuses[0].wasm_hash.is_empty());
    }

    #[test]
    fn test_status_reflects_paused() {
        let (mgr, _dir) = setup_indexer_manager(IndexerMode::Synchronous);
        mgr.pause("test").unwrap();
        let statuses = mgr.status();
        assert!(statuses[0].paused);
    }
}
