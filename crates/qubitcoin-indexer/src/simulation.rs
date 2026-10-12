//! Pending-block simulation over the indexer DAG.
//!
//! [`SimulationEngine::simulate`] builds a block at `tip + 1` (header fields
//! filled, no proof of work; it is never submitted) from an ordered list of
//! raw transactions and an optional coinbase, and runs it through the DAG in
//! topological order. Every node runs in **fork mode**: its writes go to an
//! in-memory [`Layer`]; its reads go to that layer, then to the parent
//! overlays' layers, then to the node's confirmed store **as of the tip
//! height** (read-only, height-bounded, so concurrent indexing of the next
//! block never leaks in). `__secondary_get` and upstream views read the
//! *simulated* state of the upstream. Transform nodes are applied to the
//! simulated block against their upstreams' simulated state, and their output
//! feeds the downstream indexers.
//!
//! Overlays are content-addressed: the id is a hash of the tip, the parent
//! overlay, the coinbase, the ordered transaction hashes and the node set,
//! so an identical request returns the same overlay. A child overlay
//! (`parent`) holds only its own writes and shares the parent's layers
//! (copy-on-write), so a template prefix is simulated once and bundles are
//! layered on top. Results of views on an overlay are cached. Everything is
//! dropped when the tip changes.
//!
//! Nothing here writes to an indexer store or the chainstate: stores are only
//! read through [`store::read_at_height`].

use crate::dag::{self, DagAccess, DagBackend};
use crate::store::{self, Layer, LayeredReader};
use crate::transform::TransformNode;
use crate::DagShared;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::merkle::{block_merkle_root, block_witness_merkle_root};
use qubitcoin_consensus::transaction::{OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL};
use qubitcoin_indexer_fork::{ExecLimits, ForkRuntime};
use qubitcoin_primitives::{Amount, BlockHash};
use qubitcoin_script::Script;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Caps and cache bounds.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Maximum number of cached overlays.
    pub max_overlays: usize,
    /// Byte budget for overlay layers (keys + values written).
    pub max_overlay_bytes: usize,
    /// Byte budget for cached view results.
    pub max_view_cache_bytes: usize,
    /// Fuel cap per node per simulation (and per view call).
    pub fuel_per_node: u64,
    /// Linear memory cap per wasm instance.
    pub max_memory_bytes: usize,
    /// Wall-clock deadline per node per simulation (and per view call).
    pub deadline: Duration,
    /// Largest overlay a single simulation may produce.
    pub max_bytes_per_overlay: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            max_overlays: 64,
            max_overlay_bytes: 512 << 20,
            max_view_cache_bytes: 64 << 20,
            fuel_per_node: 20_000_000_000,
            max_memory_bytes: 4 << 30,
            deadline: Duration::from_secs(30),
            max_bytes_per_overlay: 256 << 20,
        }
    }
}

impl SimConfig {
    fn limits(&self) -> ExecLimits {
        ExecLimits {
            fuel: Some(self.fuel_per_node),
            max_memory_bytes: Some(self.max_memory_bytes),
            deadline: Some(self.deadline),
        }
    }
}

/// The chain tip a simulation builds on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimTip {
    /// Tip block hash (internal byte order).
    pub hash: [u8; 32],
    /// Tip height; the simulated block is at `height + 1`.
    pub height: u32,
    /// Header fields for the simulated block.
    pub version: i32,
    pub time: u32,
    pub bits: u32,
}

/// Source of the current tip (the node's chainstate, or a test stub).
pub trait SimChain: Send + Sync {
    fn tip(&self) -> Option<SimTip>;
}

impl<F: Fn() -> Option<SimTip> + Send + Sync> SimChain for F {
    fn tip(&self) -> Option<SimTip> {
        self()
    }
}

/// Build the serialized block a simulation runs: header (no PoW), coinbase
/// (the given one, or BIP34 height + `OP_TRUE` paying 0), then `txs`. A BIP141
/// witness commitment is added when any transaction carries a witness and
/// the coinbase has none.
pub fn assemble_block(tip: &SimTip, coinbase: Option<&[u8]>, txs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let height = tip.height + 1;
    let cb: Transaction = match coinbase {
        Some(raw) => qubitcoin_serialize::deserialize(raw).map_err(|e| format!("coinbase decode: {}", e))?,
        None => default_coinbase(height, b""),
    };
    let mut vtx: Vec<TransactionRef> = Vec::with_capacity(txs.len() + 1);
    vtx.push(Arc::new(cb));
    for (i, raw) in txs.iter().enumerate() {
        let tx: Transaction = qubitcoin_serialize::deserialize(raw).map_err(|e| format!("tx {} decode: {}", i, e))?;
        vtx.push(Arc::new(tx));
    }
    let has_commitment = vtx[0].vout.iter().any(|o| {
        let s = o.script_pubkey.as_bytes();
        s.len() >= 38 && s[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
    });
    if !has_commitment && vtx.iter().skip(1).any(|t| t.has_witness()) {
        let mut mutated = false;
        let root = block_witness_merkle_root(&vtx, &mut mutated);
        let mut pre = [0u8; 64];
        pre[..32].copy_from_slice(root.as_bytes());
        let commit = qubitcoin_crypto::hash::hash256(&pre);
        let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        spk.extend_from_slice(&commit);
        let c = vtx[0].clone();
        let mut vout = c.vout.clone();
        vout.push(TxOut::new(Amount::ZERO, Script::from_bytes(spk)));
        let mut vin = c.vin.clone();
        if vin[0].witness.stack.is_empty() {
            vin[0].witness = Witness { stack: vec![vec![0u8; 32]] };
        }
        vtx[0] = Arc::new(Transaction::new(c.version, vin, vout, c.lock_time));
    }
    let mut mutated = false;
    let merkle_root = block_merkle_root(&vtx, &mut mutated);
    let header = BlockHeader {
        version: tip.version,
        prev_blockhash: BlockHash::from_bytes(tip.hash),
        merkle_root,
        time: tip.time,
        bits: tip.bits,
        nonce: 0,
    };
    qubitcoin_serialize::serialize(&Block { header, vtx }).map_err(|e| format!("block encode: {}", e))
}

/// A coinbase at `height` (BIP34 push + `tag`) with one zero-value `OP_TRUE`
/// output. Used when a request carries no coinbase, and (tagged) as the
/// neutral coinbase of a stacked layer.
pub fn default_coinbase(height: u32, tag: &[u8]) -> Transaction {
    let mut script_sig = Script::new();
    script_sig.push_int(height as i64);
    script_sig.push_int(0);
    if !tag.is_empty() {
        script_sig.push_data(tag);
    }
    Transaction::new(
        2,
        vec![TxIn { prevout: OutPoint::null(), script_sig, sequence: SEQUENCE_FINAL, witness: Witness::new() }],
        vec![TxOut::new(Amount::ZERO, Script::from_bytes(vec![0x51]))],
        0,
    )
}

/// How a node is executed in a simulation.
pub enum SimExec {
    /// A metashrew-ABI wasm indexer. `base` is its confirmed store, read at
    /// `base_tip`, which must equal the chain tip (None = empty base: a
    /// simulation-only node).
    Wasm {
        fork: Arc<ForkRuntime>,
        base: Option<Arc<rocksdb::DB>>,
        base_tip: Option<u32>,
        start_height: u32,
    },
    Transform(Arc<TransformNode>),
    /// A user BPF program (same base-state rules as `Wasm`).
    Bpf {
        program: Arc<crate::bpf::BpfProgram>,
        base: Option<Arc<rocksdb::DB>>,
        base_tip: Option<u32>,
        start_height: u32,
    },
}

/// One node as the simulation sees it.
pub struct SimNodeSpec {
    pub name: String,
    /// Nodes it may read (`__secondary_get`, upstream views).
    pub upstreams: Vec<String>,
    /// Transform whose output is its input block.
    pub input: Option<String>,
    pub exec: SimExec,
}

impl SimNodeSpec {
    fn graph_upstreams(&self) -> Vec<String> {
        let mut v = self.upstreams.clone();
        if let Some(i) = &self.input {
            v.push(i.clone());
        }
        if let SimExec::Transform(t) = &self.exec {
            v = t.upstreams();
        }
        v
    }
    fn kind(&self) -> &'static str {
        match self.exec {
            SimExec::Wasm { .. } | SimExec::Bpf { .. } => "indexer",
            SimExec::Transform(_) => "transform",
        }
    }
}

/// Supplies nodes that are not standard indexers (user nodes).
pub trait SimNodeProvider: Send + Sync {
    /// The spec for `name`, if this provider owns it.
    fn sim_node(&self, name: &str) -> Option<Result<SimNodeSpec, String>>;
}

/// A finished simulation.
pub struct Overlay {
    pub id: String,
    pub tip: SimTip,
    pub height: u32,
    pub block: Arc<Vec<u8>>,
    pub parent: Option<Arc<Overlay>>,
    specs: Arc<HashMap<String, Arc<SimNodeSpec>>>,
    /// Nodes simulated here (topological order).
    pub nodes: Vec<String>,
    layers: HashMap<String, Arc<Layer>>,
    outputs: HashMap<String, Arc<Vec<u8>>>,
    pub result: Value,
    /// Bytes this overlay adds (its own layers and transform outputs).
    pub own_bytes: usize,
}

impl Overlay {
    /// Layers of `node`, newest first, through the parent chain.
    fn chain(&self, node: &str) -> Vec<Arc<Layer>> {
        let mut v = Vec::new();
        let mut cur = Some(self);
        while let Some(o) = cur {
            if let Some(l) = o.layers.get(node) {
                v.push(l.clone());
            }
            cur = o.parent.as_deref();
        }
        v
    }
}

/// Reads for one simulation (in progress or finished).
struct OverlayBackend {
    specs: Arc<HashMap<String, Arc<SimNodeSpec>>>,
    /// Layers produced so far in this overlay.
    current: Arc<parking_lot::RwLock<HashMap<String, Arc<Layer>>>>,
    parent: Option<Arc<Overlay>>,
    /// Simulated height (tip + 1).
    height: u32,
    tip_height: u32,
    limits: ExecLimits,
}

impl OverlayBackend {
    fn reader(&self, node: &str) -> Result<LayeredReader, String> {
        let spec = self.specs.get(node).ok_or_else(|| format!("node '{}' is not part of this overlay", node))?;
        let mut layers = Vec::new();
        if let Some(l) = self.current.read().get(node) {
            layers.push(l.clone());
        }
        if let Some(p) = &self.parent {
            layers.extend(p.chain(node));
        }
        let db = match &spec.exec {
            SimExec::Wasm { base, .. } | SimExec::Bpf { base, .. } => base.clone(),
            SimExec::Transform(_) => return Err(format!("'{}' is a transform and has no KV", node)),
        };
        Ok(LayeredReader { layers, db, base_height: self.tip_height })
    }

    fn access(self: &Arc<Self>, node: &str) -> DagAccess {
        let allowed = self.specs.get(node).map(|s| s.upstreams.clone()).unwrap_or_default();
        DagAccess { node: node.to_string(), allowed, backend: self.clone() }
    }

    async fn call_view(self: &Arc<Self>, node: &str, view_fn: &str, input: Vec<u8>) -> Result<(Vec<u8>, u64), String> {
        let spec = self.specs.get(node).ok_or_else(|| format!("node '{}' is not part of this overlay", node))?.clone();
        match &spec.exec {
            SimExec::Wasm { fork, .. } => {
                let reader = self.reader(node)?;
                let mut full = Vec::with_capacity(4 + input.len());
                full.extend_from_slice(&self.height.to_le_bytes());
                full.extend_from_slice(&input);
                fork.call_export_ctx(
                    view_fn,
                    full,
                    store::fork_storage(reader, self.height),
                    node,
                    self.access(node).host(),
                    self.limits,
                )
                .await
                .map(|o| (o.value, o.fuel_used))
                .map_err(|e| format!("view '{}' failed: {}", view_fn, e))
            }
            SimExec::Bpf { program, .. } => {
                let reader = self.reader(node)?;
                program
                    .view(view_fn, &input, self.height, reader, self.access(node), self.limits)
                    .map(|o| (o.value, o.fuel_used))
                    .map_err(|e| format!("view '{}' failed: {}", view_fn, e))
            }
            SimExec::Transform(_) => Err(format!("'{}' is a transform; it has no views", node)),
        }
    }
}

#[async_trait::async_trait]
impl DagBackend for OverlayBackend {
    fn kv_get(&self, node: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.reader(node)?.get(key)
    }

    async fn view(&self, node: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        // `DagBackend` takes &self; rebuild an Arc'd twin sharing the state.
        let me = Arc::new(OverlayBackend {
            specs: self.specs.clone(),
            current: self.current.clone(),
            parent: self.parent.clone(),
            height: self.height,
            tip_height: self.tip_height,
            limits: self.limits,
        });
        me.call_view(node, view_fn, input).await.map(|(v, _)| v)
    }
}

/// Request for [`SimulationEngine::simulate`].
#[derive(Clone, Debug, Default)]
pub struct SimRequest {
    pub txs: Vec<Vec<u8>>,
    pub coinbase: Option<Vec<u8>>,
    /// Nodes to simulate (their upstreams are added). None = every standard
    /// indexer (or the parent's set).
    pub indexers: Option<Vec<String>>,
    pub parent: Option<String>,
}

struct CacheState {
    tip: Option<[u8; 32]>,
    overlays: HashMap<String, (Arc<Overlay>, u64)>,
    overlay_bytes: usize,
    views: HashMap<(String, String, String, Vec<u8>), (Arc<Vec<u8>>, u64)>,
    view_bytes: usize,
}

/// Counters, for tests and `getsimulationinfo`.
#[derive(Default)]
pub struct SimStats {
    pub simulations: AtomicU64,
    pub overlay_hits: AtomicU64,
    pub view_calls: AtomicU64,
    pub view_hits: AtomicU64,
    pub invalidations: AtomicU64,
}

/// The simulation engine (one per node).
pub struct SimulationEngine {
    shared: Arc<DagShared>,
    chain: Arc<dyn SimChain>,
    pub config: SimConfig,
    providers: parking_lot::RwLock<Vec<Arc<dyn SimNodeProvider>>>,
    sim_only: parking_lot::RwLock<HashMap<String, Arc<SimNodeSpec>>>,
    cache: parking_lot::Mutex<CacheState>,
    tick: AtomicU64,
    pub stats: SimStats,
}

/// Run a future to completion on a private current-thread runtime in a
/// scoped thread (callable from sync code and from inside tokio).
pub(crate) fn run_blocking<T: Send>(fut: impl std::future::Future<Output = T> + Send) -> T {
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(fut)
        })
        .join()
        .expect("simulation thread panicked")
    })
}

fn display_hash(h: &[u8; 32]) -> String {
    let mut r = *h;
    r.reverse();
    hex::encode(r)
}

impl SimulationEngine {
    pub fn new(shared: Arc<DagShared>, chain: Arc<dyn SimChain>, config: SimConfig) -> Self {
        SimulationEngine {
            shared,
            chain,
            config,
            providers: parking_lot::RwLock::new(Vec::new()),
            sim_only: parking_lot::RwLock::new(HashMap::new()),
            cache: parking_lot::Mutex::new(CacheState {
                tip: None,
                overlays: HashMap::new(),
                overlay_bytes: 0,
                views: HashMap::new(),
                view_bytes: 0,
            }),
            tick: AtomicU64::new(0),
            stats: SimStats::default(),
        }
    }

    /// Register a provider of extra nodes (user nodes).
    pub fn add_provider(&self, p: Arc<dyn SimNodeProvider>) {
        self.providers.write().push(p);
    }

    /// Drop every overlay and cached view (tip change or reorg).
    pub fn invalidate(&self) {
        let mut c = self.cache.lock();
        c.overlays.clear();
        c.views.clear();
        c.overlay_bytes = 0;
        c.view_bytes = 0;
        c.tip = None;
        self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
    }

    /// Hook for the node's tip events.
    pub fn on_tip_changed(&self, new_tip: [u8; 32]) {
        let stale = self.cache.lock().tip.map(|t| t != new_tip).unwrap_or(false);
        if stale {
            self.invalidate();
        }
    }

    fn current_tip(&self) -> Result<SimTip, String> {
        let tip = self.chain.tip().ok_or("no chain tip")?;
        let stale = { self.cache.lock().tip.map(|t| t != tip.hash).unwrap_or(false) };
        if stale {
            self.invalidate();
        }
        self.cache.lock().tip = Some(tip.hash);
        Ok(tip)
    }

    /// Number of cached overlays and their bytes.
    pub fn cache_usage(&self) -> (usize, usize, usize, usize) {
        let c = self.cache.lock();
        (c.overlays.len(), c.overlay_bytes, c.views.len(), c.view_bytes)
    }

    /// Register a simulation-only tertiary (never touches a persistent store).
    pub fn load_simulation_indexer(&self, name: &str, wasm: &[u8], sha256_hex: &str, deps: Vec<String>) -> Result<String, String> {
        if name.is_empty() || name.contains('/') || name.starts_with('@') {
            return Err("invalid name".into());
        }
        if self.shared.indexer(name).is_some() || self.shared.transform(name).is_some() {
            return Err(format!("'{}' is already a standard node", name));
        }
        let have = hex::encode(Sha256::digest(wasm));
        if have != sha256_hex.trim_start_matches("0x").to_lowercase() {
            return Err(format!("sha256 mismatch (have {})", have));
        }
        for d in &deps {
            if self.shared.indexer(d).is_none() && !self.sim_only.read().contains_key(d) {
                return Err(format!("unknown dependency '{}'", d));
            }
        }
        let fork = ForkRuntime::new(wasm).map_err(|e| format!("compile: {}", e))?;
        let spec = SimNodeSpec {
            name: name.to_string(),
            upstreams: deps,
            input: None,
            exec: SimExec::Wasm { fork: Arc::new(fork), base: None, base_tip: None, start_height: 0 },
        };
        self.sim_only.write().insert(name.to_string(), Arc::new(spec));
        Ok(have)
    }

    pub fn unload_simulation_indexer(&self, name: &str) -> bool {
        self.sim_only.write().remove(name).is_some()
    }

    /// Spec of a node by name: standard indexer/transform, sim-only, provider.
    fn spec(&self, name: &str) -> Result<Arc<SimNodeSpec>, String> {
        if let Some(inst) = self.shared.indexer(name) {
            return Ok(Arc::new(SimNodeSpec {
                name: name.to_string(),
                upstreams: inst.depends_on.clone(),
                input: inst.input.clone(),
                exec: SimExec::Wasm {
                    fork: inst.fork_runtime()?,
                    base: Some(inst.db.clone()),
                    base_tip: if inst.has_state() {
                        Some(inst.tip_height.load(Ordering::Acquire))
                    } else {
                        None
                    },
                    start_height: inst.start_height,
                },
            }));
        }
        if let Some(t) = self.shared.transform(name) {
            return Ok(Arc::new(SimNodeSpec {
                name: name.to_string(),
                upstreams: t.upstreams(),
                input: None,
                exec: SimExec::Transform(t),
            }));
        }
        if let Some(s) = self.sim_only.read().get(name) {
            return Ok(s.clone());
        }
        for p in self.providers.read().iter() {
            if let Some(r) = p.sim_node(name) {
                return r.map(Arc::new);
            }
        }
        Err(format!("unknown node '{}'", name))
    }

    /// Specs for `names` plus all their upstreams; topological order.
    fn resolve(&self, names: &[String]) -> Result<(Arc<HashMap<String, Arc<SimNodeSpec>>>, Vec<String>), String> {
        let mut specs: HashMap<String, Arc<SimNodeSpec>> = HashMap::new();
        let mut stack: Vec<String> = names.to_vec();
        while let Some(n) = stack.pop() {
            if specs.contains_key(&n) {
                continue;
            }
            let s = self.spec(&n)?;
            stack.extend(s.graph_upstreams());
            specs.insert(n, s);
        }
        let graph: BTreeMap<String, Vec<String>> =
            specs.iter().map(|(n, s)| (n.clone(), s.graph_upstreams())).collect();
        let order = dag::topo_order(&graph)?;
        Ok((Arc::new(specs), order))
    }

    fn overlay_id(tip: &SimTip, parent: Option<&str>, coinbase: Option<&[u8]>, txs: &[Vec<u8>], nodes: &[String]) -> String {
        let mut h = Sha256::new();
        h.update(b"qubitcoin-sim-overlay-v1");
        h.update(tip.hash);
        h.update(parent.unwrap_or("").as_bytes());
        h.update([0u8]);
        match coinbase {
            Some(c) => {
                h.update([1u8]);
                h.update(Sha256::digest(c));
            }
            None => h.update([0u8]),
        }
        h.update((txs.len() as u64).to_le_bytes());
        for t in txs {
            h.update(Sha256::digest(t));
        }
        let mut sorted = nodes.to_vec();
        sorted.sort();
        for n in sorted {
            h.update(n.as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    }

    /// Look up a live overlay.
    pub fn overlay(&self, id: &str) -> Option<Arc<Overlay>> {
        let t = self.tick.fetch_add(1, Ordering::Relaxed);
        let mut c = self.cache.lock();
        let e = c.overlays.get_mut(id)?;
        e.1 = t;
        Some(e.0.clone())
    }

    /// Simulate a block. Returns the `simulateblock` result object.
    pub fn simulate(&self, req: SimRequest) -> Result<Value, String> {
        self.stats.simulations.fetch_add(1, Ordering::Relaxed);
        let tip = self.current_tip()?;
        let height = tip.height + 1;
        let parent = match &req.parent {
            Some(pid) => {
                let p = self.overlay(pid).ok_or_else(|| format!("unknown or expired overlay '{}'", pid))?;
                if p.tip.hash != tip.hash {
                    return Err("parent overlay is from an older tip".into());
                }
                Some(p)
            }
            None => None,
        };
        let requested: Vec<String> = match (&req.indexers, &parent) {
            (Some(v), Some(p)) => {
                for n in v {
                    if !p.nodes.contains(n) {
                        return Err(format!("'{}' was not simulated in the parent overlay", n));
                    }
                }
                v.clone()
            }
            (Some(v), None) => v.clone(),
            (None, Some(p)) => p.nodes.clone(),
            (None, None) => {
                let mut v: Vec<String> = self.shared.indexers.read().keys().cloned().collect();
                v.sort();
                v
            }
        };
        if requested.is_empty() {
            return Err("no indexers to simulate".into());
        }
        let (specs, order) = self.resolve(&requested)?;
        if let Some(p) = &parent {
            if let Some(n) = order.iter().find(|n| !p.nodes.contains(n)) {
                return Err(format!("'{}' was not simulated in the parent overlay", n));
            }
        }

        // A stacked layer reuses the parent's state and carries only the new
        // transactions, behind a zero-value coinbase tagged as a layer.
        let coinbase_bytes: Option<Vec<u8>> = match (&req.coinbase, &parent) {
            (Some(c), _) => Some(c.clone()),
            (None, Some(_)) => Some(
                qubitcoin_serialize::serialize(&default_coinbase(height, b"qubitcoin-sim-layer"))
                    .map_err(|e| e.to_string())?,
            ),
            (None, None) => None,
        };
        let id = Self::overlay_id(&tip, req.parent.as_deref(), req.coinbase.as_deref(), &req.txs, &order);
        if let Some(o) = self.overlay(&id) {
            self.stats.overlay_hits.fetch_add(1, Ordering::Relaxed);
            let mut r = o.result.clone();
            r["cached"] = json!(true);
            return Ok(r);
        }
        let block = Arc::new(assemble_block(&tip, coinbase_bytes.as_deref(), &req.txs)?);
        let block_hash: [u8; 32] = qubitcoin_crypto::hash::hash256(&block[..80]);

        let backend = Arc::new(OverlayBackend {
            specs: specs.clone(),
            current: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            parent: parent.clone(),
            height,
            tip_height: tip.height,
            limits: self.config.limits(),
        });
        let mut outputs: HashMap<String, Arc<Vec<u8>>> = HashMap::new();
        let mut per = serde_json::Map::new();
        let mut failed: BTreeSet<String> = BTreeSet::new();
        let mut own_bytes = 0usize;

        for name in &order {
            let spec = specs[name].clone();
            let mut entry = serde_json::Map::new();
            entry.insert("kind".into(), json!(spec.kind()));
            if let Some(up) = spec.graph_upstreams().iter().find(|u| failed.contains(*u)) {
                failed.insert(name.clone());
                entry.insert("ok".into(), json!(false));
                entry.insert("error".into(), json!(format!("upstream '{}' failed", up)));
                entry.insert("fuel_used".into(), json!(0));
                per.insert(name.clone(), Value::Object(entry));
                continue;
            }
            let r = self.run_node(&backend, &spec, &tip, &block, parent.as_deref(), &outputs);
            match r {
                Ok(NodeOut::Layer(layer, fuel)) => {
                    own_bytes += layer.bytes;
                    entry.insert("ok".into(), json!(true));
                    entry.insert("fuel_used".into(), json!(fuel));
                    entry.insert("kv_writes".into(), json!(layer.kv.len()));
                    backend.current.write().insert(name.clone(), Arc::new(layer));
                }
                Ok(NodeOut::Block(out, fuel)) => {
                    own_bytes += out.len();
                    entry.insert("ok".into(), json!(true));
                    entry.insert("fuel_used".into(), json!(fuel));
                    entry.insert("output_bytes".into(), json!(out.len()));
                    outputs.insert(name.clone(), Arc::new(out));
                }
                Err((kind, msg, fuel)) => {
                    failed.insert(name.clone());
                    entry.insert("ok".into(), json!(false));
                    entry.insert("error".into(), json!(msg));
                    entry.insert("error_kind".into(), json!(kind));
                    entry.insert("fuel_used".into(), json!(fuel));
                }
            }
            if own_bytes > self.config.max_bytes_per_overlay {
                return Err(format!(
                    "overlay exceeds the per-overlay memory cap ({} > {} bytes)",
                    own_bytes, self.config.max_bytes_per_overlay
                ));
            }
            per.insert(name.clone(), Value::Object(entry));
        }

        let result = json!({
            "overlay_id": id,
            "height": height,
            "tip": display_hash(&tip.hash),
            "block_hash": display_hash(&block_hash),
            "parent": req.parent,
            "cached": false,
            "overlay_bytes": own_bytes,
            "per_indexer": Value::Object(per),
        });
        let layers = std::mem::take(&mut *backend.current.write());
        let overlay = Arc::new(Overlay {
            id: id.clone(),
            tip,
            height,
            block,
            parent,
            specs,
            nodes: order,
            layers,
            outputs,
            result: result.clone(),
            own_bytes,
        });
        self.insert_overlay(overlay)?;
        Ok(result)
    }

    fn insert_overlay(&self, o: Arc<Overlay>) -> Result<(), String> {
        let t = self.tick.fetch_add(1, Ordering::Relaxed);
        if self.chain.tip().map(|t| t.hash) != Some(o.tip.hash) {
            // The tip moved while we were simulating; the result is stale.
            self.invalidate();
            return Err("chain tip changed during simulation; retry".into());
        }
        let mut c = self.cache.lock();
        if c.tip != Some(o.tip.hash) {
            return Err("chain tip changed during simulation; retry".into());
        }
        if let Some(old) = c.overlays.insert(o.id.clone(), (o.clone(), t)) {
            c.overlay_bytes -= old.0.own_bytes;
        }
        c.overlay_bytes += o.own_bytes;
        while c.overlays.len() > self.config.max_overlays.max(1)
            || (c.overlay_bytes > self.config.max_overlay_bytes && c.overlays.len() > 1)
        {
            let victim = c
                .overlays
                .iter()
                .filter(|(k, _)| **k != o.id)
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone());
            match victim {
                Some(v) => {
                    let (ov, _) = c.overlays.remove(&v).unwrap();
                    c.overlay_bytes -= ov.own_bytes;
                    Self::drop_views_locked(&mut c, &v);
                }
                None => break,
            }
        }
        Ok(())
    }

    fn drop_views_locked(c: &mut CacheState, overlay_id: &str) {
        let keys: Vec<_> = c.views.keys().filter(|k| k.0 == overlay_id).cloned().collect();
        for k in keys {
            if let Some((v, _)) = c.views.remove(&k) {
                c.view_bytes -= v.len() + k.3.len();
            }
        }
    }

    fn run_node(
        &self,
        backend: &Arc<OverlayBackend>,
        spec: &Arc<SimNodeSpec>,
        tip: &SimTip,
        block: &Arc<Vec<u8>>,
        _parent: Option<&Overlay>,
        outputs: &HashMap<String, Arc<Vec<u8>>>,
    ) -> Result<NodeOut, (&'static str, String, u64)> {
        let height = tip.height + 1;
        let input_block: Arc<Vec<u8>> = match &spec.input {
            None => block.clone(),
            Some(t) => outputs
                .get(t)
                .cloned()
                .ok_or(("host", format!("transform '{}' produced no output", t), 0))?,
        };
        match &spec.exec {
            SimExec::Transform(t) => {
                let access = backend.access(&spec.name);
                let limits = self.config.limits();
                let r = run_blocking(t.apply(height, &input_block, access, limits));
                r.map(|o| NodeOut::Block(o.value, o.fuel_used))
                    .map_err(|e| (e.kind.as_str(), e.message, e.fuel_used))
            }
            SimExec::Bpf { program, base, base_tip, start_height } => {
                check_base(base.is_some(), *base_tip, *start_height, tip.height)?;
                let reader = backend.reader(&spec.name).map_err(|e| ("host", e, 0))?;
                let access = backend.access(&spec.name);
                program
                    .run_block(height, &input_block, reader, access, self.config.limits())
                    .map(|o| NodeOut::Layer(Layer::from_pairs(o.value.pairs), o.fuel_used))
                    .map_err(|e| (e.kind.as_str(), e.message, e.fuel_used))
            }
            SimExec::Wasm { fork, base, base_tip, start_height } => {
                check_base(base.is_some(), *base_tip, *start_height, tip.height)?;
                let reader = backend.reader(&spec.name).map_err(|e| ("host", e, 0))?;
                let mut full = Vec::with_capacity(4 + input_block.len());
                full.extend_from_slice(&height.to_le_bytes());
                full.extend_from_slice(&input_block);
                let access = backend.access(&spec.name);
                let limits = self.config.limits();
                let fork = fork.clone();
                let name = spec.name.clone();
                let r = run_blocking(async move {
                    fork.run_block_ctx(full, store::fork_storage(reader, height), &name, access.host(), limits).await
                });
                r.map(|o| NodeOut::Layer(Layer::from_pairs(o.value), o.fuel_used))
                    .map_err(|e| (e.kind.as_str(), e.message, e.fuel_used))
            }
        }
    }

    /// `simulatedview`: call `view_fn(input)` on `node` against an overlay.
    /// For a transform node, `view_fn = "output"` returns its output block.
    pub fn view(&self, overlay_id: &str, node: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        self.stats.view_calls.fetch_add(1, Ordering::Relaxed);
        self.current_tip()?;
        let o = self.overlay(overlay_id).ok_or_else(|| format!("unknown or expired overlay '{}'", overlay_id))?;
        if !o.nodes.iter().any(|n| n == node) {
            return Err(format!("'{}' was not simulated in this overlay", node));
        }
        let key = (overlay_id.to_string(), node.to_string(), view_fn.to_string(), input.clone());
        {
            let t = self.tick.fetch_add(1, Ordering::Relaxed);
            let mut c = self.cache.lock();
            if let Some(e) = c.views.get_mut(&key) {
                e.1 = t;
                self.stats.view_hits.fetch_add(1, Ordering::Relaxed);
                return Ok((*e.0).clone());
            }
        }
        let out = if let Some(SimExec::Transform(_)) = o.specs.get(node).map(|s| &s.exec) {
            if view_fn != "output" {
                return Err("a transform only has the 'output' view".into());
            }
            o.outputs.get(node).map(|v| (**v).clone()).ok_or("transform failed in this overlay")?
        } else {
            if o.result["per_indexer"][node]["ok"] != json!(true) {
                return Err(format!("'{}' failed in this overlay", node));
            }
            let backend = Arc::new(OverlayBackend {
                specs: o.specs.clone(),
                current: Arc::new(parking_lot::RwLock::new(o.layers.clone())),
                parent: o.parent.clone(),
                height: o.height,
                tip_height: o.tip.height,
                limits: self.config.limits(),
            });
            let node_s = node.to_string();
            let vf = view_fn.to_string();
            run_blocking(async move { backend.call_view(&node_s, &vf, input).await })?.0
        };
        let t = self.tick.fetch_add(1, Ordering::Relaxed);
        let mut c = self.cache.lock();
        if c.overlays.contains_key(overlay_id) {
            let sz = out.len() + key.3.len();
            if sz <= self.config.max_view_cache_bytes {
                c.view_bytes += sz;
                if let Some((old, _)) = c.views.insert(key.clone(), (Arc::new(out.clone()), t)) {
                    c.view_bytes -= old.len() + key.3.len();
                }
                while c.view_bytes > self.config.max_view_cache_bytes {
                    let victim = c.views.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone());
                    match victim {
                        Some(v) => {
                            let (val, _) = c.views.remove(&v).unwrap();
                            c.view_bytes -= val.len() + v.3.len();
                        }
                        None => break,
                    }
                }
            }
        }
        Ok(out)
    }

    /// `releaseoverlay`. Children keep their own reference to the parent.
    pub fn release(&self, overlay_id: &str) -> bool {
        let mut c = self.cache.lock();
        match c.overlays.remove(overlay_id) {
            Some((o, _)) => {
                c.overlay_bytes -= o.own_bytes;
                Self::drop_views_locked(&mut c, overlay_id);
                true
            }
            None => false,
        }
    }
}

/// A persistent node's confirmed state must be at the tip to be simulated.
fn check_base(has_base: bool, base_tip: Option<u32>, start_height: u32, tip: u32) -> Result<(), (&'static str, String, u64)> {
    if has_base && tip + 1 > start_height {
        match base_tip {
            Some(h) if h == tip => {}
            Some(h) => return Err(("lagging", format!("indexer at height {} but the tip is {}", h, tip), 0)),
            None if tip >= start_height => {
                return Err(("lagging", format!("indexer has no state yet; the tip is {}", tip), 0))
            }
            None => {}
        }
    }
    Ok(())
}

enum NodeOut {
    Layer(Layer, u64),
    Block(Vec<u8>, u64),
}
