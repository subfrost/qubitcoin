//! User-registered DAG nodes ("searcher programs").
//!
//! An owner (an opaque string the caller supplies; authentication is the
//! caller's job, so the RPCs are admin-tier) registers a metashrew-ABI wasm
//! indexer with declared upstreams (standard indexers). The node then
//! indexes forward from its start height on the owner's behalf, backfilling
//! from the block files if the start height is in the past:
//!
//! * **Isolation.** Each node has its own store under
//!   `<datadir>/dag/users/<owner-hash>/<name>/db`; its `__flush` can only
//!   ever land there. It may read only its declared upstreams, through
//!   `__secondary_get` / upstream views at the same height.
//! * **Caps.** Every block runs under a fuel cap (the node's, bounded by the
//!   owner's quota), a memory cap and a deadline. A failing node is marked
//!   `errored` and stops; nothing else waits on it. `resumedagnode` retries.
//! * **Scheduling.** Standard indexers run first on block connect; user
//!   nodes are then processed by a bounded worker pool, in bounded batches,
//!   and may lag (status shows the lag).
//! * **Reorgs** roll user nodes back like the standard ones.
//! * **Metering, no pricing.** Every processed block and every view call is
//!   recorded in a usage ledger (fuel, KV bytes written, store size, view
//!   calls), readable per owner over a height range. Per-owner quotas (max
//!   nodes, fuel per block, store bytes) are enforced; the defaults allow
//!   zero user nodes, so the feature is off unless the operator enables it.
//!
//! User nodes can also be named in `simulateblock` as `@owner/name`.
//!
//! Two program kinds exist: `wasm` (a metashrew-ABI indexer run by the fork
//! runner) and `bpf` (a userspace eBPF program, see [`crate::bpf`]). Both go
//! through the same scheduling, metering, quotas, pause-on-error, reorg
//! rollback and simulation paths; only the executor differs.

use crate::bpf::BpfProgram;
use crate::dag::DagAccess;
use crate::simulation::{SimExec, SimNodeProvider, SimNodeSpec};
use crate::{store, DagShared, PersistentBackend};
use qubitcoin_indexer_fork::{ExecLimits, ForkRuntime};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Per-owner limits. `max_nodes = 0` disables user nodes for that owner.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    pub max_nodes: u32,
    pub fuel_per_block: u64,
    pub storage_bytes: u64,
}

impl Default for Quota {
    fn default() -> Self {
        Quota { max_nodes: 0, fuel_per_block: 1_000_000_000, storage_bytes: 1 << 30 }
    }
}

/// Engine settings.
#[derive(Clone, Debug)]
pub struct UserDagConfig {
    /// Worker threads for user nodes.
    pub workers: usize,
    /// Blocks a worker processes for one node before moving on.
    pub batch: u32,
    /// Quota for owners without an override.
    pub default_quota: Quota,
    /// Memory cap per wasm instance.
    pub max_memory_bytes: usize,
    /// Deadline per block (and per view call).
    pub deadline: Duration,
}

impl Default for UserDagConfig {
    fn default() -> Self {
        UserDagConfig {
            workers: 2,
            batch: 16,
            default_quota: Quota::default(),
            max_memory_bytes: 512 << 20,
            deadline: Duration::from_secs(10),
        }
    }
}

/// What the owner registered (persisted).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserNodeSpec {
    pub owner: String,
    pub name: String,
    /// `"wasm"` (a metashrew-ABI indexer) or `"bpf"` (SBPF v3 bytecode).
    pub kind: String,
    pub sha256: String,
    pub upstreams: Vec<String>,
    pub start_height: u32,
    /// Fuel cap per block (bounded by the owner's quota).
    pub fuel_per_block: Option<u64>,
}

impl UserNodeSpec {
    pub fn id(&self) -> String {
        node_id(&self.owner, &self.name)
    }
}

pub fn node_id(owner: &str, name: &str) -> String {
    format!("@{}/{}", owner, name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Errored(String),
}

struct Status {
    state: NodeState,
    blocks: u64,
    last_fuel: u64,
    /// `log` lines of the last processed block (BPF nodes).
    last_logs: Vec<String>,
}

/// The executor of a user node.
#[derive(Clone)]
pub enum NodeProgram {
    Wasm(Arc<ForkRuntime>),
    Bpf(Arc<BpfProgram>),
}

impl NodeProgram {
    fn load(kind: &str, program: &[u8]) -> Result<Self, String> {
        match kind {
            "wasm" => Ok(NodeProgram::Wasm(Arc::new(ForkRuntime::new(program).map_err(|e| format!("compile: {}", e))?))),
            "bpf" => Ok(NodeProgram::Bpf(Arc::new(BpfProgram::new(program)?))),
            k => Err(format!("unknown kind '{}' (expected 'wasm' or 'bpf')", k)),
        }
    }
}

/// File extension of a stored program of `kind`.
fn program_ext(kind: &str) -> &'static str {
    if kind == "bpf" {
        "bpf"
    } else {
        "wasm"
    }
}

/// A live user node.
pub struct UserNode {
    pub spec: UserNodeSpec,
    program: NodeProgram,
    pub db: Arc<rocksdb::DB>,
    db_dir: PathBuf,
    /// Next height to process.
    next: AtomicU32,
    status: parking_lot::Mutex<Status>,
    /// Held while processing or rolling back.
    work: parking_lot::Mutex<()>,
    removed: AtomicBool,
}

impl UserNode {
    /// Last processed height, if any.
    pub fn height(&self) -> Option<u32> {
        if store::stored_tip(&self.db).is_some() {
            Some(self.next.load(Ordering::Acquire).saturating_sub(1))
        } else {
            None
        }
    }

    fn limits(&self, quota: &Quota, cfg: &UserDagConfig) -> ExecLimits {
        let fuel = self.spec.fuel_per_block.unwrap_or(quota.fuel_per_block).min(quota.fuel_per_block);
        ExecLimits { fuel: Some(fuel), max_memory_bytes: Some(cfg.max_memory_bytes), deadline: Some(cfg.deadline) }
    }
}

/// One ledger row: what a node consumed at one height.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    pub fuel: u64,
    pub kv_writes: u64,
    pub kv_bytes_written: u64,
    pub storage_bytes: u64,
    pub view_calls: u64,
    pub blocks: u64,
    pub errors: u64,
}

impl Usage {
    fn add(&mut self, o: &Usage) {
        self.fuel += o.fuel;
        self.kv_writes += o.kv_writes;
        self.kv_bytes_written += o.kv_bytes_written;
        self.storage_bytes = self.storage_bytes.max(o.storage_bytes);
        self.view_calls += o.view_calls;
        self.blocks += o.blocks;
        self.errors += o.errors;
    }
}

/// Reads a block's raw bytes by height (from the node's block files).
pub type BlockSource = Arc<dyn Fn(u32) -> Option<Vec<u8>> + Send + Sync>;

/// The registry, scheduler and ledger for user nodes.
pub struct UserDag {
    shared: Arc<DagShared>,
    dir: PathBuf,
    pub config: UserDagConfig,
    nodes: parking_lot::RwLock<BTreeMap<String, Arc<UserNode>>>,
    quotas: parking_lot::RwLock<HashMap<String, Quota>>,
    ledger: Arc<rocksdb::DB>,
    ledger_lock: parking_lot::Mutex<()>,
    blocks: BlockSource,
    chain_tip: AtomicU32,
    queue: parking_lot::Mutex<(VecDeque<String>, HashSet<String>)>,
    wake: parking_lot::Condvar,
    stop: AtomicBool,
}

fn ledger_key(owner: &str, height: u32, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(owner.len() + name.len() + 6);
    k.extend_from_slice(owner.as_bytes());
    k.push(0);
    k.extend_from_slice(&height.to_be_bytes());
    k.push(0);
    k.extend_from_slice(name.as_bytes());
    k
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

impl UserDag {
    /// Open (or create) the user-node registry under `datadir/dag` and
    /// start `config.workers` worker threads. `blocks` reads raw blocks by
    /// height; `chain_tip` is the current height.
    pub fn open(
        shared: Arc<DagShared>,
        datadir: &std::path::Path,
        config: UserDagConfig,
        blocks: BlockSource,
        chain_tip: u32,
    ) -> Result<Arc<Self>, String> {
        let dir = datadir.join("dag");
        std::fs::create_dir_all(dir.join("programs")).map_err(|e| format!("dag dir: {}", e))?;
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let ledger = Arc::new(rocksdb::DB::open(&opts, dir.join("ledger")).map_err(|e| format!("ledger: {}", e))?);
        let me = Arc::new(UserDag {
            shared,
            dir,
            config,
            nodes: parking_lot::RwLock::new(BTreeMap::new()),
            quotas: parking_lot::RwLock::new(HashMap::new()),
            ledger,
            ledger_lock: parking_lot::Mutex::new(()),
            blocks,
            chain_tip: AtomicU32::new(chain_tip),
            queue: parking_lot::Mutex::new((VecDeque::new(), HashSet::new())),
            wake: parking_lot::Condvar::new(),
            stop: AtomicBool::new(false),
        });
        me.load_registry()?;
        for i in 0..me.config.workers.max(1) {
            let w = Arc::downgrade(&me);
            std::thread::Builder::new()
                .name(format!("dag-user-{}", i))
                .spawn(move || worker_loop(w))
                .map_err(|e| format!("spawn dag worker: {}", e))?;
        }
        me.enqueue_all();
        Ok(me)
    }

    /// Stop the workers (they exit at their next wake-up).
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn registry_path(&self) -> PathBuf {
        self.dir.join("registry.json")
    }

    fn save_registry(&self) -> Result<(), String> {
        let specs: Vec<UserNodeSpec> = self.nodes.read().values().map(|n| n.spec.clone()).collect();
        let quotas: BTreeMap<String, Quota> = self.quotas.read().iter().map(|(k, v)| (k.clone(), *v)).collect();
        let v = json!({ "nodes": specs, "quotas": quotas });
        let tmp = self.dir.join("registry.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&v).unwrap()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.registry_path()).map_err(|e| e.to_string())
    }

    fn load_registry(&self) -> Result<(), String> {
        let Ok(bytes) = std::fs::read(self.registry_path()) else { return Ok(()) };
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("registry.json: {}", e))?;
        if let Some(q) = v.get("quotas") {
            let q: HashMap<String, Quota> = serde_json::from_value(q.clone()).map_err(|e| e.to_string())?;
            *self.quotas.write() = q;
        }
        let specs: Vec<UserNodeSpec> =
            serde_json::from_value(v.get("nodes").cloned().unwrap_or(json!([]))).map_err(|e| e.to_string())?;
        for spec in specs {
            let prog = std::fs::read(self.dir.join("programs").join(format!("{}.{}", spec.sha256, program_ext(&spec.kind))))
                .map_err(|e| format!("program for {}: {}", spec.id(), e))?;
            match self.instantiate(spec.clone(), &prog) {
                Ok(n) => {
                    self.nodes.write().insert(spec.id(), n);
                }
                Err(e) => tracing::error!(node = %spec.id(), error = %e, "failed to reload user node"),
            }
        }
        Ok(())
    }

    /// The quota that applies to `owner`.
    pub fn quota(&self, owner: &str) -> Quota {
        self.quotas.read().get(owner).copied().unwrap_or(self.config.default_quota)
    }

    /// Override `owner`'s quota (persisted).
    pub fn set_quota(&self, owner: &str, q: Quota) -> Result<(), String> {
        self.quotas.write().insert(owner.to_string(), q);
        self.save_registry()
    }

    fn instantiate(&self, spec: UserNodeSpec, program: &[u8]) -> Result<Arc<UserNode>, String> {
        let program = NodeProgram::load(&spec.kind, program)?;
        let owner_dir = hex::encode(&Sha256::digest(spec.owner.as_bytes())[..8]);
        let db_dir = self.dir.join("users").join(owner_dir).join(&spec.name).join("db");
        std::fs::create_dir_all(&db_dir).map_err(|e| e.to_string())?;
        let db = Arc::new(
            rocksdb::DB::open(&rockshrew_runtime::RocksDBRuntimeAdapter::get_optimized_options(), &db_dir)
                .map_err(|e| format!("open store: {}", e))?,
        );
        let next = match store::stored_tip(&db) {
            Some(t) => t + 1,
            None => spec.start_height,
        };
        Ok(Arc::new(UserNode {
            spec,
            program,
            db,
            db_dir,
            next: AtomicU32::new(next),
            status: parking_lot::Mutex::new(Status { state: NodeState::Running, blocks: 0, last_fuel: 0, last_logs: Vec::new() }),
            work: parking_lot::Mutex::new(()),
            removed: AtomicBool::new(false),
        }))
    }

    /// Register a node. `program` is the wasm; `sha256` (hex) must match.
    pub fn register(&self, spec: UserNodeSpec, program: &[u8]) -> Result<Value, String> {
        if !valid_ident(&spec.owner) || !valid_ident(&spec.name) {
            return Err("owner and name must be 1-64 chars of [A-Za-z0-9-_.]".into());
        }
        match spec.kind.as_str() {
            "wasm" | "bpf" => {}
            k => return Err(format!("unknown kind '{}' (expected 'wasm' or 'bpf')", k)),
        }
        let have = hex::encode(Sha256::digest(program));
        if have != spec.sha256.trim_start_matches("0x").to_lowercase() {
            return Err(format!("sha256 mismatch (have {})", have));
        }
        for u in &spec.upstreams {
            if self.shared.indexer(u).is_none() {
                return Err(format!("unknown upstream '{}' (user nodes may read standard indexers)", u));
            }
        }
        let id = spec.id();
        let quota = self.quota(&spec.owner);
        {
            let nodes = self.nodes.read();
            if nodes.contains_key(&id) {
                return Err(format!("'{}' is already registered", id));
            }
            let owned = nodes.values().filter(|n| n.spec.owner == spec.owner).count() as u32;
            if owned >= quota.max_nodes {
                return Err(format!(
                    "quota: owner '{}' may register {} node(s) (has {})",
                    spec.owner, quota.max_nodes, owned
                ));
            }
        }
        let mut spec = spec;
        spec.sha256 = have.clone();
        // Compile / verify before anything is stored.
        NodeProgram::load(&spec.kind, program)?;
        std::fs::write(self.dir.join("programs").join(format!("{}.{}", have, program_ext(&spec.kind))), program)
            .map_err(|e| e.to_string())?;
        let node = self.instantiate(spec, program)?;
        self.nodes.write().insert(id.clone(), node.clone());
        self.save_registry()?;
        self.enqueue(&id);
        Ok(self.status_of(&node))
    }

    /// Remove a node and delete its store.
    pub fn unregister(&self, owner: &str, name: &str) -> Result<bool, String> {
        let id = node_id(owner, name);
        let Some(node) = self.nodes.write().remove(&id) else { return Ok(false) };
        node.removed.store(true, Ordering::Release);
        self.save_registry()?;
        let _g = node.work.lock();
        let dir = node.db_dir.clone();
        drop(_g);
        drop(node);
        // The store is closed once the last Arc (e.g. a running view) is gone.
        let _ = std::fs::remove_dir_all(&dir);
        Ok(true)
    }

    /// Clear an error and resume indexing.
    pub fn resume(&self, owner: &str, name: &str) -> Result<(), String> {
        let id = node_id(owner, name);
        let node = self.nodes.read().get(&id).cloned().ok_or_else(|| format!("unknown node '{}'", id))?;
        node.status.lock().state = NodeState::Running;
        self.enqueue(&id);
        Ok(())
    }

    pub fn node(&self, owner: &str, name: &str) -> Option<Arc<UserNode>> {
        self.nodes.read().get(&node_id(owner, name)).cloned()
    }

    fn status_of(&self, n: &UserNode) -> Value {
        let s = n.status.lock();
        let tip = self.chain_tip.load(Ordering::Acquire);
        let height = n.height();
        let lag = match height {
            Some(h) => tip.saturating_sub(h),
            None => tip.saturating_sub(n.spec.start_height.saturating_sub(1)),
        };
        let (state, error) = match &s.state {
            NodeState::Running => ("running", Value::Null),
            NodeState::Errored(e) => ("errored", json!(e)),
        };
        json!({
            "owner": n.spec.owner,
            "name": n.spec.name,
            "id": n.spec.id(),
            "kind": n.spec.kind,
            "sha256": n.spec.sha256,
            "upstreams": n.spec.upstreams,
            "start_height": n.spec.start_height,
            "height": height,
            "chain_height": tip,
            "lag": lag,
            "state": state,
            "error": error,
            "blocks_processed": s.blocks,
            "last_block_fuel": s.last_fuel,
            "logs": s.last_logs,
            "storage_bytes": store::approx_size(&n.db),
        })
    }

    /// `listdagnodes`.
    pub fn list(&self, owner: Option<&str>) -> Value {
        let nodes: Vec<Arc<UserNode>> = self.nodes.read().values().cloned().collect();
        Value::Array(
            nodes
                .iter()
                .filter(|n| owner.map(|o| o == n.spec.owner).unwrap_or(true))
                .map(|n| self.status_of(n))
                .collect(),
        )
    }

    /// `getdagnodestatus`.
    pub fn status(&self, owner: &str, name: &str) -> Result<Value, String> {
        let n = self.node(owner, name).ok_or_else(|| format!("unknown node '{}'", node_id(owner, name)))?;
        let mut v = self.status_of(&n);
        v["quota"] = serde_json::to_value(self.quota(owner)).unwrap();
        Ok(v)
    }

    /// The new chain height; queues every running node.
    pub fn notify_block(&self, height: u32) {
        self.chain_tip.store(height, Ordering::Release);
        self.enqueue_all();
    }

    /// Roll every node above `height` back to it (waits for in-flight work).
    pub fn on_reorg(&self, height: u32) {
        self.chain_tip.store(height, Ordering::Release);
        let nodes: Vec<Arc<UserNode>> = self.nodes.read().values().cloned().collect();
        for n in nodes {
            let _g = n.work.lock();
            let next = n.next.load(Ordering::Acquire);
            if next > height + 1 {
                match store::rollback(&n.db, height, next - 1) {
                    Ok(()) => n.next.store((height + 1).max(n.spec.start_height), Ordering::Release),
                    Err(e) => n.status.lock().state = NodeState::Errored(format!("rollback: {}", e)),
                }
            }
        }
    }

    fn enqueue(&self, id: &str) {
        let mut q = self.queue.lock();
        if q.1.insert(id.to_string()) {
            q.0.push_back(id.to_string());
        }
        self.wake.notify_one();
    }

    fn enqueue_all(&self) {
        let ids: Vec<String> = self.nodes.read().keys().cloned().collect();
        for id in ids {
            self.enqueue(&id);
        }
    }

    fn record(&self, owner: &str, height: u32, name: &str, u: &Usage) {
        let _g = self.ledger_lock.lock();
        let k = ledger_key(owner, height, name);
        let mut cur: Usage = self
            .ledger
            .get(&k)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        cur.add(u);
        let _ = self.ledger.put(&k, serde_json::to_vec(&cur).unwrap());
    }

    /// `getdagusage(owner, from, to)`: totals, per node, and per height
    /// (at most 1000 rows).
    pub fn usage(&self, owner: &str, from: u32, to: u32) -> Value {
        let mut prefix = owner.as_bytes().to_vec();
        prefix.push(0);
        let start = ledger_key(owner, from, "");
        let mut total = Usage::default();
        let mut per_node: BTreeMap<String, Usage> = BTreeMap::new();
        let mut rows = Vec::new();
        let it = self.ledger.iterator(rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward));
        for item in it {
            let Ok((k, v)) = item else { break };
            if !k.starts_with(&prefix) || k.len() < prefix.len() + 5 {
                break;
            }
            let h = u32::from_be_bytes(k[prefix.len()..prefix.len() + 4].try_into().unwrap());
            if h > to {
                break;
            }
            let name = String::from_utf8_lossy(&k[prefix.len() + 5..]).to_string();
            let Ok(u) = serde_json::from_slice::<Usage>(&v) else { continue };
            total.add(&u);
            per_node.entry(name.clone()).or_default().add(&u);
            if rows.len() < 1000 {
                rows.push(json!({ "height": h, "name": name, "usage": u }));
            }
        }
        json!({
            "owner": owner,
            "from": from,
            "to": to,
            "total": total,
            "nodes": per_node,
            "rows": rows,
            "quota": self.quota(owner),
        })
    }

    /// `dagview`: call `view_fn(input)` on a user node as of `height`
    /// (default: its last processed height).
    pub fn view(&self, owner: &str, name: &str, view_fn: &str, input: Vec<u8>, height: Option<u32>) -> Result<Vec<u8>, String> {
        let n = self.node(owner, name).ok_or_else(|| format!("unknown node '{}'", node_id(owner, name)))?;
        let at = n.height().ok_or("node has not indexed any block yet")?;
        let h = match height {
            Some(h) if h > at => return Err(format!("node has only reached height {}", at)),
            Some(h) => h,
            None => at,
        };
        let mut full = Vec::with_capacity(4 + input.len());
        full.extend_from_slice(&h.to_le_bytes());
        full.extend_from_slice(&input);
        let access = DagAccess {
            node: n.spec.id(),
            allowed: n.spec.upstreams.clone(),
            backend: Arc::new(PersistentBackend { shared: self.shared.clone(), height: h }),
        };
        let limits = n.limits(&self.quota(owner), &self.config);
        let db = n.db.clone();
        let label = n.spec.id();
        let vf = view_fn.to_string();
        let r = match &n.program {
            NodeProgram::Wasm(fork) => {
                let fork = fork.clone();
                crate::simulation::run_blocking(async move {
                    fork.call_export_ctx(
                        &vf,
                        full,
                        store::fork_storage(store::LayeredReader::at_height(db, h), h),
                        &label,
                        access.host(),
                        limits,
                    )
                    .await
                })
            }
            NodeProgram::Bpf(p) => p.view(&vf, &input, h, store::LayeredReader::at_height(db, h), access, limits),
        };
        let tip = self.chain_tip.load(Ordering::Acquire);
        let fuel = match &r {
            Ok(o) => o.fuel_used,
            Err(e) => e.fuel_used,
        };
        self.record(owner, tip, name, &Usage { view_calls: 1, fuel, ..Default::default() });
        r.map(|o| o.value).map_err(|e| format!("view '{}' failed: {}", view_fn, e))
    }

    /// Process up to `batch` heights of one node. Returns true if more work
    /// is ready right now.
    fn process(&self, n: &Arc<UserNode>) -> bool {
        let Some(_g) = n.work.try_lock() else { return false };
        for _ in 0..self.config.batch.max(1) {
            if n.removed.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire) {
                return false;
            }
            if n.status.lock().state != NodeState::Running {
                return false;
            }
            let h = n.next.load(Ordering::Acquire);
            if h > self.chain_tip.load(Ordering::Acquire) {
                return false;
            }
            if !self.shared.deps_ready(&n.spec.upstreams, h) {
                return false;
            }
            let Some(raw) = (self.blocks)(h) else { return false };
            let quota = self.quota(&n.spec.owner);
            let limits = n.limits(&quota, &self.config);
            let access = DagAccess {
                node: n.spec.id(),
                allowed: n.spec.upstreams.clone(),
                backend: Arc::new(PersistentBackend { shared: self.shared.clone(), height: h }),
            };
            let reader = store::LayeredReader::at_height(n.db.clone(), h.saturating_sub(1));
            let label = n.spec.id();
            let mut logs = Vec::new();
            let r = match &n.program {
                NodeProgram::Wasm(fork) => {
                    let fork = fork.clone();
                    let mut full = Vec::with_capacity(4 + raw.len());
                    full.extend_from_slice(&h.to_le_bytes());
                    full.extend_from_slice(&raw);
                    crate::simulation::run_blocking(async move {
                        fork.run_block_ctx(full, store::fork_storage(reader, h), &label, access.host(), limits).await
                    })
                }
                NodeProgram::Bpf(p) => p.run_block(h, &raw, reader, access, limits).map(|o| {
                    logs = o.value.logs;
                    qubitcoin_indexer_fork::ExecOutcome { value: o.value.pairs, fuel_used: o.fuel_used }
                }),
            };
            n.status.lock().last_logs = logs;
            let mut u = Usage { blocks: 1, ..Default::default() };
            let outcome: Result<(), String> = match r {
                Ok(o) => {
                    u.fuel = o.fuel_used;
                    u.kv_writes = o.value.len() as u64;
                    u.kv_bytes_written = o.value.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
                    match store::commit_block(&n.db, h, &o.value) {
                        Ok(()) => {
                            n.db.flush().ok();
                            u.storage_bytes = store::approx_size(&n.db);
                            if u.storage_bytes > quota.storage_bytes {
                                Err(format!("storage quota exceeded ({} > {} bytes)", u.storage_bytes, quota.storage_bytes))
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => {
                    u.fuel = e.fuel_used;
                    Err(format!("height {}: {}", h, e))
                }
            };
            let committed = outcome.is_ok() || u.storage_bytes > 0;
            if committed {
                n.next.store(h + 1, Ordering::Release);
            }
            match outcome {
                Ok(()) => {
                    let mut s = n.status.lock();
                    s.blocks += 1;
                    s.last_fuel = u.fuel;
                }
                Err(e) => {
                    u.errors = 1;
                    tracing::warn!(node = %n.spec.id(), error = %e, "user DAG node errored; paused");
                    let mut s = n.status.lock();
                    s.state = NodeState::Errored(e);
                    s.last_fuel = u.fuel;
                }
            }
            self.record(&n.spec.owner, h, &n.spec.name, &u);
        }
        n.next.load(Ordering::Acquire) <= self.chain_tip.load(Ordering::Acquire)
    }
}

fn worker_loop(dag: std::sync::Weak<UserDag>) {
    loop {
        let Some(d) = dag.upgrade() else { return };
        if d.stop.load(Ordering::Acquire) {
            return;
        }
        let id = {
            let mut q = d.queue.lock();
            if q.0.is_empty() {
                d.wake.wait_for(&mut q, Duration::from_millis(200));
            }
            match q.0.pop_front() {
                Some(id) => {
                    q.1.remove(&id);
                    Some(id)
                }
                None => None,
            }
        };
        let Some(id) = id else { continue };
        let node = d.nodes.read().get(&id).cloned();
        if let Some(n) = node {
            if d.process(&n) {
                d.enqueue(&id);
            } else if n.status.lock().state == NodeState::Running
                && n.next.load(Ordering::Acquire) <= d.chain_tip.load(Ordering::Acquire)
            {
                // Waiting on upstreams or a busy lock: retry shortly.
                let d2 = Arc::downgrade(&d);
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    if let Some(d) = d2.upgrade() {
                        d.enqueue(&id);
                    }
                });
            }
        }
    }
}

impl SimNodeProvider for UserDag {
    fn sim_node(&self, name: &str) -> Option<Result<SimNodeSpec, String>> {
        let rest = name.strip_prefix('@')?;
        let (owner, n) = rest.split_once('/')?;
        let node = self.node(owner, n)?;
        let exec = match &node.program {
            NodeProgram::Wasm(fork) => SimExec::Wasm {
                fork: fork.clone(),
                base: Some(node.db.clone()),
                base_tip: node.height(),
                start_height: node.spec.start_height,
            },
            NodeProgram::Bpf(p) => SimExec::Bpf {
                program: p.clone(),
                base: Some(node.db.clone()),
                base_tip: node.height(),
                start_height: node.spec.start_height,
            },
        };
        Some(Ok(SimNodeSpec { name: name.to_string(), upstreams: node.spec.upstreams.clone(), input: None, exec }))
    }
}
