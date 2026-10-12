//! Indexer DAG: persistent indexing over secondary and transform edges, and
//! pending-block simulation over the DAG.
//!
//! Fixtures are tiny hand-written wasm modules (WAT), so the tests need no
//! wasm toolchain:
//!
//! * `sec`  — secondary: `/txs` += tx count of the input block, `/len` = input
//!   block length. Views `txs`, `len`.
//! * `ter`  — tertiary: `/dbl` = 2 × `sec./txs` (read with `__secondary_get`).
//!   View `dbl`.
//! * `burn` — `_start` loops forever (fuel / deadline caps).
//! * `tf`   — wasm transform: output = block ++ `sec.txs()` (via
//!   `__upstream_view`).
//!
//! Run with `-- --test-threads=1` if memory is tight. The test that runs
//! stock `MetashrewRuntime` nodes (4 GiB up-front commit each) is gated
//! behind `QUBITCOIN_TEST_METASHREW=1`.

use qubitcoin_consensus::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness, SEQUENCE_FINAL};
use qubitcoin_indexer::config::{IndexerConfig, TransformConfig, TransformKindConfig};
use qubitcoin_indexer::simulation::{assemble_block, SimConfig, SimRequest, SimTip, SimulationEngine};
use qubitcoin_indexer::{store, transform, IndexerManager, IndexerMode};
use qubitcoin_primitives::{Amount, Txid};
use qubitcoin_script::Script;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SEC_WAT: &str = r#"
(module
  (import "env" "__host_len" (func $host_len (result i32)))
  (import "env" "__load_input" (func $load_input (param i32)))
  (import "env" "__flush" (func $flush (param i32)))
  (import "env" "__get" (func $get (param i32 i32)))
  (import "env" "__get_len" (func $get_len (param i32) (result i32)))
  (memory (export "memory") 64)
  (data (i32.const 0xFC) "\04\00\00\00/txs")
  (data (i32.const 0x10C) "\04\00\00\00/len")
  (data (i32.const 0x3FC) "\18\00\00\00\0a\04/txs\0a\04\00\00\00\00\0a\04/len\0a\04\00\00\00\00")
  (func $read_u32 (param $key i32) (result i32)
    (if (result i32) (i32.eq (call $get_len (local.get $key)) (i32.const 4))
      (then (call $get (local.get $key) (i32.const 0x200)) (i32.load (i32.const 0x200)))
      (else (i32.const 0))))
  (func (export "_start")
    (local $n i32)
    (local.set $n (call $host_len))
    (call $load_input (i32.const 0x10000))
    (i32.store (i32.const 0x408)
      (i32.add (call $read_u32 (i32.const 0x100)) (i32.load8_u (i32.const 0x10054))))
    (i32.store (i32.const 0x414) (i32.sub (local.get $n) (i32.const 4)))
    (call $flush (i32.const 0x400)))
  (func $view (param $key i32) (result i32)
    (i32.store (i32.const 0x2FC) (call $get_len (local.get $key)))
    (call $get (local.get $key) (i32.const 0x300))
    (i32.const 0x300))
  (func (export "txs") (result i32) (call $view (i32.const 0x100)))
  (func (export "len") (result i32) (call $view (i32.const 0x110)))
)
"#;

const TER_WAT: &str = r#"
(module
  (import "env" "__flush" (func $flush (param i32)))
  (import "env" "__get" (func $get (param i32 i32)))
  (import "env" "__get_len" (func $get_len (param i32) (result i32)))
  (import "env" "__secondary_get_len" (func $sgl (param i32 i32) (result i32)))
  (import "env" "__secondary_get" (func $sg (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0xFC) "\04\00\00\00/txs")
  (data (i32.const 0x10C) "\04\00\00\00/dbl")
  (data (i32.const 0x11C) "\03\00\00\00sec")
  (data (i32.const 0x3FC) "\0c\00\00\00\0a\04/dbl\0a\04\00\00\00\00")
  (func (export "_start")
    (local $v i32)
    (if (i32.eq (call $sgl (i32.const 0x120) (i32.const 0x100)) (i32.const 4))
      (then (call $sg (i32.const 0x120) (i32.const 0x100) (i32.const 0x200))
            (local.set $v (i32.load (i32.const 0x200)))))
    (i32.store (i32.const 0x408) (i32.mul (local.get $v) (i32.const 2)))
    (call $flush (i32.const 0x400)))
  (func (export "dbl") (result i32)
    (i32.store (i32.const 0x2FC) (call $get_len (i32.const 0x110)))
    (call $get (i32.const 0x110) (i32.const 0x300))
    (i32.const 0x300))
)
"#;

const BURN_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (loop $l (br $l))))
"#;

const TF_WAT: &str = r#"
(module
  (import "env" "__host_len" (func $host_len (result i32)))
  (import "env" "__load_input" (func $load_input (param i32)))
  (import "env" "__upstream_view" (func $uv (param i32 i32 i32) (result i32)))
  (import "env" "__upstream_view_read" (func $uvr (param i32)))
  (memory (export "memory") 64)
  (data (i32.const 0x11C) "\03\00\00\00sec")
  (data (i32.const 0x13C) "\03\00\00\00txs")
  (data (i32.const 0x14C) "\00\00\00\00")
  (func (export "transform") (result i32)
    (local $n i32) (local $l i32)
    (local.set $n (call $host_len))
    (call $load_input (i32.const 0x10000))
    (local.set $l (call $uv (i32.const 0x120) (i32.const 0x140) (i32.const 0x150)))
    (call $uvr (i32.add (i32.const 0x10000) (local.get $n)))
    (i32.store (i32.const 0x10000) (i32.add (i32.sub (local.get $n) (i32.const 4)) (local.get $l)))
    (i32.const 0x10004))
)
"#;

fn wasm(dir: &Path, name: &str, wat_src: &str) -> PathBuf {
    let p = dir.join(format!("{}.wasm", name));
    std::fs::write(&p, wat::parse_str(wat_src).unwrap()).unwrap();
    p
}

fn fork_cfg(label: &str, path: PathBuf) -> IndexerConfig {
    let mut c = IndexerConfig::new(label, path);
    c.fork_runner = true;
    c
}

fn mk_tx(seed: u32) -> Vec<u8> {
    let mut prev = [0u8; 32];
    prev[..4].copy_from_slice(&seed.to_le_bytes());
    let tx = Transaction::new(
        2,
        vec![TxIn {
            prevout: OutPoint::new(Txid::from_bytes(prev), 0),
            script_sig: Script::new(),
            sequence: SEQUENCE_FINAL,
            witness: Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(1000), Script::from_bytes(vec![0x51]))],
        0,
    );
    qubitcoin_serialize::serialize(&tx).unwrap()
}

fn txs(n: u32, seed: u32) -> Vec<Vec<u8>> {
    (0..n).map(|i| mk_tx(seed * 1000 + i)).collect()
}

fn le32(v: &[u8]) -> u32 {
    assert_eq!(v.len(), 4, "expected a u32, got {:?}", v);
    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
}

/// A chain of test blocks fed to the manager, plus the tip the
/// simulation engine sees.
struct Chain {
    tip: Arc<parking_lot::Mutex<SimTip>>,
    blocks: Vec<Vec<u8>>,
}

impl Chain {
    fn new() -> Self {
        Chain {
            tip: Arc::new(parking_lot::Mutex::new(SimTip {
                hash: [7u8; 32],
                height: 0,
                version: 0x2000_0000,
                time: 1_700_000_000,
                bits: 0x207f_ffff,
            })),
            blocks: vec![],
        }
    }

    /// Build the next block with `n` txs, index it, advance the tip.
    fn connect(&mut self, mgr: &IndexerManager, n: u32) -> Vec<u8> {
        let t = *self.tip.lock();
        let b = assemble_block(&t, None, &txs(n, t.height + 1)).unwrap();
        mgr.on_block_connected(t.height + 1, &b);
        let mut tip = self.tip.lock();
        tip.hash = qubitcoin_crypto::hash::hash256(&b[..80]);
        tip.height += 1;
        tip.time += 1;
        self.blocks.push(b.clone());
        b
    }

    fn engine(&self, mgr: &IndexerManager, cfg: SimConfig) -> SimulationEngine {
        let tip = self.tip.clone();
        SimulationEngine::new(mgr.shared(), Arc::new(move || Some(*tip.lock())), cfg)
    }
}

fn dump_all(mgr: &IndexerManager) -> Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)> {
    let mut v: Vec<_> = mgr
        .shared()
        .indexers
        .read()
        .iter()
        .map(|(n, i)| {
            i.db.flush().ok();
            (n.clone(), store::dump(&i.db))
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn sec_ter(dir: &Path) -> IndexerManager {
    let mut ter = fork_cfg("ter", wasm(dir, "ter", TER_WAT));
    ter.depends_on = vec!["sec".into()];
    IndexerManager::new(
        vec![fork_cfg("sec", wasm(dir, "sec", SEC_WAT)), ter],
        &dir.to_path_buf(),
        IndexerMode::Synchronous,
    )
    .unwrap()
}

fn sim_u32(e: &SimulationEngine, id: &str, node: &str, f: &str) -> u32 {
    le32(&e.view(id, node, f, vec![]).unwrap())
}

#[test]
fn persistent_tertiary_reads_secondary_through_secondary_get() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    for n in [2, 0, 4] {
        chain.connect(&mgr, n);
    }
    // 3 blocks: (1+2) + (1+0) + (1+4) txs including coinbases.
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 9);
    assert_eq!(le32(&mgr.call_view("ter", "dbl", vec![]).unwrap()), 18);
    assert_eq!(mgr.indexer_height("ter"), Some(3));
    let st = mgr.status();
    assert!(st.iter().all(|s| s.runner == "fork" && s.last_error.is_none()));
}

#[test]
fn simulated_block_changes_overlay_not_tip_and_never_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    for n in [2, 0, 4] {
        chain.connect(&mgr, n);
    }
    let e = chain.engine(&mgr, SimConfig::default());
    let before = dump_all(&mgr);

    let r = e.simulate(SimRequest { txs: txs(4, 99), ..Default::default() }).unwrap();
    assert_eq!(r["height"], 4);
    assert_eq!(r["per_indexer"]["sec"]["ok"], true, "{}", r);
    assert_eq!(r["per_indexer"]["ter"]["ok"], true, "{}", r);
    assert!(r["per_indexer"]["sec"]["fuel_used"].as_u64().unwrap() > 0);
    let id = r["overlay_id"].as_str().unwrap().to_string();

    // Overlay: 9 + 5 (coinbase + 4); the tertiary sees the simulated secondary.
    assert_eq!(sim_u32(&e, &id, "sec", "txs"), 14);
    assert_eq!(sim_u32(&e, &id, "ter", "dbl"), 28);
    // Tip unchanged.
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 9);
    assert_eq!(le32(&mgr.call_view("ter", "dbl", vec![]).unwrap()), 18);

    assert!(e.release(&id));
    assert!(e.view(&id, "sec", "txs", vec![]).is_err());
    // Persistent stores are byte-for-byte untouched.
    assert_eq!(before, dump_all(&mgr));
}

#[test]
fn stacked_overlays_share_the_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    for n in [2, 0, 4] {
        chain.connect(&mgr, n);
    }
    let e = chain.engine(&mgr, SimConfig::default());
    let p = e.simulate(SimRequest { txs: txs(2, 50), ..Default::default() }).unwrap();
    let pid = p["overlay_id"].as_str().unwrap().to_string();
    assert_eq!(sim_u32(&e, &pid, "sec", "txs"), 12);

    let c = e
        .simulate(SimRequest { txs: txs(1, 51), parent: Some(pid.clone()), ..Default::default() })
        .unwrap();
    let cid = c["overlay_id"].as_str().unwrap().to_string();
    assert_ne!(cid, pid);
    // Layer = neutral coinbase + 1 tx on top of the prefix's state.
    assert_eq!(sim_u32(&e, &cid, "sec", "txs"), 14);
    assert_eq!(sim_u32(&e, &cid, "ter", "dbl"), 28);
    // Parent unchanged; the child only stored its own writes.
    assert_eq!(sim_u32(&e, &pid, "sec", "txs"), 12);
    assert_eq!(sim_u32(&e, &pid, "ter", "dbl"), 24);
    assert!(c["overlay_bytes"].as_u64().unwrap() <= p["overlay_bytes"].as_u64().unwrap());
    // A sibling bundle on the same prefix is independent.
    let s = e
        .simulate(SimRequest { txs: txs(3, 52), parent: Some(pid.clone()), ..Default::default() })
        .unwrap();
    assert_eq!(sim_u32(&e, s["overlay_id"].as_str().unwrap(), "sec", "txs"), 16);
    assert_eq!(sim_u32(&e, &cid, "sec", "txs"), 14);
}

#[test]
fn identical_requests_hit_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let e = chain.engine(&mgr, SimConfig::default());
    let a = e.simulate(SimRequest { txs: txs(3, 9), ..Default::default() }).unwrap();
    let b = e.simulate(SimRequest { txs: txs(3, 9), ..Default::default() }).unwrap();
    assert_eq!(a["overlay_id"], b["overlay_id"]);
    assert_eq!(a["cached"], false);
    assert_eq!(b["cached"], true);
    assert_eq!(e.stats.overlay_hits.load(Ordering::Relaxed), 1);
    // Different tx order => different overlay.
    let mut rev = txs(3, 9);
    rev.reverse();
    let c = e.simulate(SimRequest { txs: rev, ..Default::default() }).unwrap();
    assert_ne!(a["overlay_id"], c["overlay_id"]);

    let id = a["overlay_id"].as_str().unwrap();
    assert_eq!(sim_u32(&e, id, "ter", "dbl"), 2 * (2 + 4));
    assert_eq!(sim_u32(&e, id, "ter", "dbl"), 12);
    assert_eq!(e.stats.view_hits.load(Ordering::Relaxed), 1);

    // Bounded: max_overlays = 2 evicts the least recently used.
    let e2 = chain.engine(&mgr, SimConfig { max_overlays: 2, ..SimConfig::default() });
    let ids: Vec<String> = (0..3)
        .map(|i| e2.simulate(SimRequest { txs: txs(1, 100 + i), ..Default::default() }).unwrap()["overlay_id"]
            .as_str()
            .unwrap()
            .to_string())
        .collect();
    assert_eq!(e2.cache_usage().0, 2);
    assert!(e2.overlay(&ids[0]).is_none());
    assert!(e2.overlay(&ids[2]).is_some());
}

#[test]
fn new_tip_invalidates_everything() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let e = chain.engine(&mgr, SimConfig::default());
    let r = e.simulate(SimRequest { txs: txs(2, 1), ..Default::default() }).unwrap();
    let id = r["overlay_id"].as_str().unwrap().to_string();
    assert!(e.view(&id, "sec", "txs", vec![]).is_ok());

    chain.connect(&mgr, 0);
    // Even without the explicit hook, the next call notices the new tip.
    assert!(e.view(&id, "sec", "txs", vec![]).unwrap_err().contains("expired"));
    assert!(e.stats.invalidations.load(Ordering::Relaxed) >= 1);
    // The hook is idempotent; a fresh simulation builds on the new tip.
    e.on_tip_changed(chain.tip.lock().hash);
    let r2 = e.simulate(SimRequest { txs: txs(2, 1), ..Default::default() }).unwrap();
    assert_eq!(r2["height"], 3);
    assert_ne!(r2["overlay_id"], r["overlay_id"]);
    assert_eq!(sim_u32(&e, r2["overlay_id"].as_str().unwrap(), "sec", "txs"), 2 + 1 + 3);
}

#[test]
fn fuel_exhaustion_and_deadline_fail_only_that_node() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let burn = wat::parse_str(BURN_WAT).unwrap();
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&burn));

    let e = chain.engine(&mgr, SimConfig { fuel_per_node: 5_000_000, ..SimConfig::default() });
    assert!(e.load_simulation_indexer("burn", &burn, "00", vec![]).unwrap_err().contains("sha256"));
    e.load_simulation_indexer("burn", &burn, &sha, vec![]).unwrap();
    let r = e
        .simulate(SimRequest {
            txs: txs(1, 3),
            indexers: Some(vec!["sec".into(), "ter".into(), "burn".into()]),
            ..Default::default()
        })
        .unwrap();
    let p = &r["per_indexer"];
    assert_eq!(p["burn"]["ok"], false);
    assert_eq!(p["burn"]["error_kind"], "out_of_fuel", "{}", r);
    assert_eq!(p["burn"]["fuel_used"], 5_000_000);
    assert_eq!(p["sec"]["ok"], true);
    assert_eq!(p["ter"]["ok"], true);
    let id = r["overlay_id"].as_str().unwrap();
    assert_eq!(sim_u32(&e, id, "ter", "dbl"), 2 * (2 + 2));
    assert!(e.view(id, "burn", "x", vec![]).unwrap_err().contains("failed"));

    // Wall-clock deadline.
    let e = chain.engine(
        &mgr,
        SimConfig { fuel_per_node: u64::MAX / 2, deadline: Duration::from_millis(300), ..SimConfig::default() },
    );
    e.load_simulation_indexer("burn", &burn, &sha, vec![]).unwrap();
    let t0 = Instant::now();
    let r = e
        .simulate(SimRequest { txs: vec![], indexers: Some(vec!["burn".into(), "sec".into()]), ..Default::default() })
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(10));
    assert_eq!(r["per_indexer"]["burn"]["error_kind"], "deadline", "{}", r);
    assert_eq!(r["per_indexer"]["sec"]["ok"], true);
}

#[test]
fn undeclared_upstream_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let e = chain.engine(&mgr, SimConfig::default());
    let ter = wat::parse_str(TER_WAT).unwrap();
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&ter));
    // Same program as `ter`, but registered without declaring `sec`.
    e.load_simulation_indexer("sneaky", &ter, &sha, vec![]).unwrap();
    let r = e
        .simulate(SimRequest { txs: vec![], indexers: Some(vec!["sneaky".into()]), ..Default::default() })
        .unwrap();
    assert_eq!(r["per_indexer"]["sneaky"]["ok"], false);
    assert_eq!(r["per_indexer"]["sneaky"]["error_kind"], "host");
    assert!(r["per_indexer"]["sneaky"]["error"].as_str().unwrap().contains("access denied"), "{}", r);
    // Declared: works, and reads the simulated secondary (empty base for itself).
    e.load_simulation_indexer("honest", &ter, &sha, vec!["sec".into()]).unwrap();
    let r = e
        .simulate(SimRequest { txs: txs(2, 4), indexers: Some(vec!["honest".into()]), ..Default::default() })
        .unwrap();
    assert_eq!(sim_u32(&e, r["overlay_id"].as_str().unwrap(), "honest", "dbl"), 2 * (2 + 3));
}

fn transform_mgr(dir: &Path) -> IndexerManager {
    let sec = wasm(dir, "sec", SEC_WAT);
    let tf = wasm(dir, "tf", TF_WAT);
    let mut emb = fork_cfg("emb", sec.clone());
    emb.input = Some("sec/txs/ASP0".into());
    let mut w = fork_cfg("w", sec.clone());
    w.input = Some("wt".into());
    IndexerManager::with_transforms(
        vec![fork_cfg("sec", sec), emb, w],
        vec![TransformConfig {
            name: "wt".into(),
            kind: TransformKindConfig::Wasm { path: tf, sha256: None, upstreams: vec!["sec".into()] },
            fuel: Some(10_000_000),
        }],
        &dir.to_path_buf(),
        IndexerMode::Synchronous,
    )
    .unwrap()
}

#[test]
fn transform_edges_persistent_and_simulated() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = transform_mgr(dir.path());
    let mut chain = Chain::new();
    let mut last = vec![];
    for n in [1, 3] {
        last = chain.connect(&mgr, n);
    }
    // sec.txs at height 2 = (1+1) + (1+3) = 6.
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 6);
    // Built-in: block + one 19-byte coinbase output carrying "ASP0" ++ le32(6).
    let want = transform::embed_in_coinbase(&last, b"ASP0", &6u32.to_le_bytes()).unwrap();
    assert_eq!(want.len(), last.len() + 19);
    assert_eq!(le32(&mgr.call_view("emb", "len", vec![]).unwrap()) as usize, want.len());
    // The derived block keeps the raw tx count (and header, hence hash).
    assert_eq!(le32(&mgr.call_view("emb", "txs", vec![]).unwrap()), 6);
    assert_eq!(want[..80], last[..80]);
    // Wasm transform: block ++ sec.txs().
    assert_eq!(le32(&mgr.call_view("w", "len", vec![]).unwrap()) as usize, last.len() + 4);

    // Same edges in simulation: alkanes-style upstream runs first, the
    // transform reads its *simulated* view, downstreams reprocess the output.
    let e = chain.engine(&mgr, SimConfig::default());
    let before = dump_all(&mgr);
    let r = e.simulate(SimRequest { txs: txs(2, 77), ..Default::default() }).unwrap();
    for n in ["sec", "emb", "w", "wt", "sec/txs/ASP0"] {
        assert_eq!(r["per_indexer"][n]["ok"], true, "{}: {}", n, r);
    }
    assert_eq!(r["per_indexer"]["wt"]["kind"], "transform");
    let id = r["overlay_id"].as_str().unwrap();
    let sim_block = e.view(id, "wt", "output", vec![]).unwrap();
    let raw_len = sim_block.len() - 4;
    assert_eq!(le32(&sim_block[raw_len..]), 9, "wasm transform saw the simulated sec.txs");
    let emb_out = e.view(id, "sec/txs/ASP0", "output", vec![]).unwrap();
    let raw_sim = &sim_block[..raw_len];
    assert_eq!(emb_out, transform::embed_in_coinbase(raw_sim, b"ASP0", &9u32.to_le_bytes()).unwrap());
    assert_eq!(sim_u32(&e, id, "emb", "len") as usize, emb_out.len());
    assert_eq!(sim_u32(&e, id, "w", "len") as usize, raw_len + 4);
    assert_eq!(sim_u32(&e, id, "emb", "txs"), 9);
    assert_eq!(before, dump_all(&mgr));

    // Simulating only `emb` pulls in its transform and the transform's upstream.
    let r = e
        .simulate(SimRequest { txs: txs(2, 77), indexers: Some(vec!["emb".into()]), ..Default::default() })
        .unwrap();
    let mut names: Vec<_> = r["per_indexer"].as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(names, vec!["emb", "sec", "sec/txs/ASP0"]);
}

#[test]
fn reorg_rolls_back_every_indexer() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = transform_mgr(dir.path());
    let mut chain = Chain::new();
    for n in [1, 3, 5] {
        chain.connect(&mgr, n);
    }
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 2 + 4 + 6);
    mgr.on_reorg(1);
    for l in ["sec", "emb", "w"] {
        assert_eq!(mgr.indexer_height(l), Some(1), "{}", l);
    }
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 2);
    // Reconnect a different block 2.
    {
        let mut t = chain.tip.lock();
        t.height = 1;
        t.hash = qubitcoin_crypto::hash::hash256(&chain.blocks[0][..80]);
    }
    chain.connect(&mgr, 0);
    assert_eq!(le32(&mgr.call_view("sec", "txs", vec![]).unwrap()), 3);
    assert_eq!(le32(&mgr.call_view("emb", "txs", vec![]).unwrap()), 3);
    let st = mgr.status();
    assert!(st.iter().all(|s| s.last_error.is_none()), "{:?}", st.iter().map(|s| &s.last_error).collect::<Vec<_>>());
}

#[test]
fn async_mode_orders_dependents_after_upstreams() {
    let dir = tempfile::tempdir().unwrap();
    let sec = wasm(dir.path(), "sec", SEC_WAT);
    let mut ter = fork_cfg("ter", wasm(dir.path(), "ter", TER_WAT));
    ter.depends_on = vec!["sec".into()];
    let mut emb = fork_cfg("emb", sec.clone());
    emb.input = Some("sec/txs/ASP0".into());
    let mgr = IndexerManager::new(vec![fork_cfg("sec", sec), ter, emb], &dir.path().to_path_buf(), IndexerMode::Async)
        .unwrap();
    let mut chain = Chain::new();
    for n in [1, 2, 3, 4, 5] {
        chain.connect(&mgr, n);
    }
    let t0 = Instant::now();
    while mgr.indexer_height("ter") != Some(5) || mgr.indexer_height("emb") != Some(5) {
        assert!(t0.elapsed() < Duration::from_secs(30), "async indexers did not catch up");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(le32(&mgr.call_view("ter", "dbl", vec![]).unwrap()), 2 * (2 + 3 + 4 + 5 + 6));
    assert_eq!(le32(&mgr.call_view("emb", "txs", vec![]).unwrap()), 2 + 3 + 4 + 5 + 6);
}

#[test]
fn simulations_do_not_block_block_connect() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = Arc::new(sec_ter(dir.path()));
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let burn = wat::parse_str(BURN_WAT).unwrap();
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&burn));
    let e = Arc::new(chain.engine(
        &mgr,
        SimConfig { fuel_per_node: u64::MAX / 2, deadline: Duration::from_secs(3), ..SimConfig::default() },
    ));
    e.load_simulation_indexer("burn", &burn, &sha, vec![]).unwrap();
    let e2 = e.clone();
    let h = std::thread::spawn(move || {
        e2.simulate(SimRequest { txs: vec![], indexers: Some(vec!["burn".into()]), ..Default::default() })
    });
    std::thread::sleep(Duration::from_millis(200));
    let t0 = Instant::now();
    chain.connect(&mgr, 2);
    chain.connect(&mgr, 2);
    assert!(t0.elapsed() < Duration::from_secs(2), "block connect waited on a simulation: {:?}", t0.elapsed());
    assert_eq!(mgr.indexer_height("ter"), Some(3));
    // The simulation was built on the old tip: it reports that, not a stale overlay.
    let r = h.join().unwrap();
    assert!(r.is_err() || r.as_ref().unwrap()["per_indexer"]["burn"]["error_kind"] == "deadline");
}

#[test]
fn rpc_shapes() {
    use qubitcoin_indexer::dag_rpc::register_simulation_rpcs;
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let e = Arc::new(chain.engine(&mgr, SimConfig::default()));
    let mut rpcs = std::collections::HashMap::new();
    register_simulation_rpcs(&mut |n: &str, h| { rpcs.insert(n.to_string(), h); }, e);
    let tx_hex: Vec<String> = txs(2, 5).iter().map(hex::encode).collect();
    let r = rpcs["simulateblock"](&json!([tx_hex, {"indexers": ["ter"]}]));
    assert!(r.get("error").is_none(), "{}", r);
    let id = r["overlay_id"].as_str().unwrap();
    assert_eq!(r["per_indexer"]["ter"]["ok"], true);
    let v = rpcs["simulatedview"](&json!([id, "ter", "dbl", "0x"]));
    assert_eq!(v, json!(format!("0x{}", hex::encode((2u32 * (2 + 3)).to_le_bytes()))));
    let c = rpcs["simulateblock"](&json!([[], {"parent": id}]));
    assert_eq!(c["parent"], json!(id));
    assert!(rpcs["simulateblock"](&json!(["zz"])).get("error").is_some());
    assert_eq!(rpcs["releaseoverlay"](&json!([id])), json!({"released": true}));
    assert_eq!(rpcs["releaseoverlay"](&json!([id])), json!({"released": false}));
    let info = rpcs["getsimulationinfo"](&json!([]));
    assert_eq!(info["stats"]["simulations"], 2);
}

/// The built-in transform reproduces alspo's `embed_traces` (rust-bitcoin
/// `Builder::push_slice` + consensus encoding) byte for byte, including
/// segwit blocks and every push-opcode size class.
#[test]
fn embed_matches_rust_bitcoin_embed_traces() {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::script::{Builder, PushBytesBuf};
    let tip = SimTip { hash: [1; 32], height: 10, version: 0x2000_0000, time: 1, bits: 0x207fffff };
    // A segwit spend so the block carries witness data and a commitment.
    let sw = Transaction::new(
        2,
        vec![TxIn {
            prevout: OutPoint::new(Txid::from_bytes([9; 32]), 1),
            script_sig: Script::new(),
            sequence: SEQUENCE_FINAL,
            witness: Witness { stack: vec![vec![0xaa; 72], vec![0x02; 33]] },
        }],
        vec![TxOut::new(Amount::from_sat(5), Script::from_bytes(vec![0x00, 0x14].into_iter().chain([3u8; 20]).collect()))],
        0,
    );
    let mut list = txs(3, 1);
    list.push(qubitcoin_serialize::serialize(&sw).unwrap());
    let block = assemble_block(&tip, None, &list).unwrap();
    for n in [0usize, 0x47, 0x48, 0xfb, 0xfc, 0xfffb, 0xfffc, 100_000] {
        let payload: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let mine = transform::embed_in_coinbase(&block, b"ASP0", &payload).unwrap();

        let mut b: bitcoin::Block = deserialize(&block).unwrap();
        let mut data = b"ASP0".to_vec();
        data.extend_from_slice(&payload);
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(PushBytesBuf::try_from(data).unwrap())
            .into_script();
        b.txdata[0].output.push(bitcoin::TxOut { value: bitcoin::Amount::from_sat(0), script_pubkey: script });
        assert_eq!(mine, serialize(&b), "payload {}", n);
        assert_eq!(b.block_hash().to_string(), {
            let mut h = qubitcoin_crypto::hash::hash256(&block[..80]);
            h.reverse();
            hex::encode(h)
        });
    }
}

/// Against alspo's real fixtures (block 900000 + its traceblock, and the
/// deployed `/v4/{key}/traces` facade's output for that height). Set
/// `ALSPO_FIXTURES=/path/to/alspo-rs/fixtures`.
#[test]
fn embed_matches_alspo_live_facade_fixture() {
    let Ok(dir) = std::env::var("ALSPO_FIXTURES") else {
        eprintln!("skip: ALSPO_FIXTURES not set");
        return;
    };
    let rd = |n: &str| hex::decode(std::fs::read_to_string(Path::new(&dir).join(n)).unwrap().trim()).unwrap();
    let block = rd("block_900000.hex");
    let traceblock = rd("traceblock_900000.hex");
    let live = rd("live_synthetic_900000.hex");
    let mine = transform::embed_in_coinbase(&block, b"ASP0", &traceblock).unwrap();
    assert_eq!(mine.len(), live.len());
    assert!(mine == live, "built-in transform differs from the live facade output");
    // And the wasm-test fixture (the facade's `getblock` bytes for 900000).
    let syn = std::fs::read(Path::new(&dir).join("wasm/synthetic_900000.bin")).unwrap();
    assert!(syn == mine, "built-in transform differs from fixtures/wasm/synthetic_900000.bin");
}

/// Stock `MetashrewRuntime` nodes on both ends of a transform edge (the
/// alspo deployment shape: alkanes → traceblock transform → module).
/// `QUBITCOIN_TEST_METASHREW=1` (commits 4 GiB per runtime).
#[test]
fn metashrew_runner_transform_edge() {
    if std::env::var("QUBITCOIN_TEST_METASHREW").is_err() {
        eprintln!("skip: QUBITCOIN_TEST_METASHREW not set");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let sec = wasm(dir.path(), "sec", SEC_WAT);
    let mut emb = IndexerConfig::new("emb", sec.clone());
    emb.input = Some("sec/txs/ASP0".into());
    let mgr = IndexerManager::new(vec![IndexerConfig::new("sec", sec), emb], &dir.path().to_path_buf(), IndexerMode::Synchronous)
        .unwrap();
    assert!(mgr.status().iter().all(|s| s.runner == "metashrew"));
    let mut chain = Chain::new();
    let mut last = vec![];
    for n in [1, 3] {
        last = chain.connect(&mgr, n);
    }
    // sec also indexed the built-in genesis (1 tx) at height 0.
    let s = le32(&mgr.call_view("sec", "txs", vec![]).unwrap());
    assert_eq!(s, 1 + 2 + 4);
    let want = transform::embed_in_coinbase(&last, b"ASP0", &s.to_le_bytes()).unwrap();
    assert_eq!(le32(&mgr.call_view("emb", "len", vec![]).unwrap()) as usize, want.len());
    assert_eq!(le32(&mgr.call_view("emb", "txs", vec![]).unwrap()), 2 + 4);
    // Simulation over metashrew-runner nodes (fork mode on their stores).
    let e = chain.engine(&mgr, SimConfig::default());
    let before = dump_all(&mgr);
    let r = e.simulate(SimRequest { txs: txs(2, 8), ..Default::default() }).unwrap();
    let id = r["overlay_id"].as_str().unwrap();
    assert_eq!(sim_u32(&e, id, "sec", "txs"), s + 3, "{}", r);
    assert_eq!(sim_u32(&e, id, "emb", "txs"), 2 + 4 + 3);
    assert_eq!(before, dump_all(&mgr));
}

/// The real alkanes indexer: persistent blocks, then a simulated block, the
/// `traceblock` view on the overlay, and the built-in
/// `alkanes/traceblock/ASP0` transform feeding a downstream module.
/// `QUBITCOIN_ALKANES_WASM=/path/to/alkanes.wasm`.
#[test]
fn real_alkanes_wasm_simulation() {
    let Ok(path) = std::env::var("QUBITCOIN_ALKANES_WASM") else {
        eprintln!("skip: QUBITCOIN_ALKANES_WASM not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let sec = wasm(dir.path(), "sec", SEC_WAT);
    let mut down = fork_cfg("essentials", sec);
    down.input = Some("alkanes/traceblock/ASP0".into());
    let mgr = IndexerManager::new(
        vec![fork_cfg("alkanes", PathBuf::from(path)), down],
        &dir.path().to_path_buf(),
        IndexerMode::Synchronous,
    )
    .unwrap();
    let mut chain = Chain::new();
    for n in [0, 1, 2] {
        chain.connect(&mgr, n);
    }
    let st = mgr.status();
    for s in &st {
        assert!(s.last_error.is_none(), "{}: {:?}", s.label, s.last_error);
    }
    assert_eq!(mgr.indexer_height("alkanes"), Some(3));
    let tip_tb = mgr.call_view("alkanes", "traceblock", vec![]).unwrap();

    let e = chain.engine(&mgr, SimConfig::default());
    let before = dump_all(&mgr);
    let t0 = Instant::now();
    let r = e.simulate(SimRequest { txs: txs(3, 31), ..Default::default() }).unwrap();
    eprintln!("alkanes simulation: {:?} {}", t0.elapsed(), r);
    for n in ["alkanes", "alkanes/traceblock/ASP0", "essentials"] {
        assert_eq!(r["per_indexer"][n]["ok"], true, "{}: {}", n, r);
    }
    let id = r["overlay_id"].as_str().unwrap();
    let tb = e.view(id, "alkanes", "traceblock", vec![]).unwrap();
    let out = e.view(id, "alkanes/traceblock/ASP0", "output", vec![]).unwrap();
    let raw = e.overlay(id).unwrap().block.clone();
    assert_eq!(out, transform::embed_in_coinbase(&raw, b"ASP0", &tb).unwrap());
    assert_eq!(sim_u32(&e, id, "essentials", "len") as usize, out.len());
    assert_eq!(mgr.call_view("alkanes", "traceblock", vec![]).unwrap(), tip_tb);
    assert_eq!(before, dump_all(&mgr));
}

// ---------------------------------------------------------------------------
// User-registered DAG nodes
// ---------------------------------------------------------------------------

use qubitcoin_indexer::usernodes::{Quota, UserDag, UserDagConfig, UserNodeSpec};

fn sha_hex(b: &[u8]) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b))
}

fn spec(owner: &str, name: &str, prog: &[u8], ups: &[&str], start: u32) -> UserNodeSpec {
    UserNodeSpec {
        owner: owner.into(),
        name: name.into(),
        kind: "wasm".into(),
        sha256: sha_hex(prog),
        upstreams: ups.iter().map(|s| s.to_string()).collect(),
        start_height: start,
        fuel_per_block: None,
    }
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(30), "timed out waiting for {}", what);
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn open_dag(dir: &Path, mgr: &IndexerManager, blocks: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>, tip: u32) -> Arc<UserDag> {
    let src = blocks.clone();
    UserDag::open(
        mgr.shared(),
        dir,
        UserDagConfig::default(),
        Arc::new(move |h: u32| src.lock().get(h.checked_sub(1)? as usize).cloned()),
        tip,
    )
    .unwrap()
}

#[test]
fn user_nodes_index_isolate_meter_and_roll_back() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    for n in [2, 0, 4] {
        chain.connect(&mgr, n);
    }
    let blocks = Arc::new(parking_lot::Mutex::new(chain.blocks.clone()));
    let dag = open_dag(dir.path(), &mgr, blocks.clone(), 3);
    let ter = wat::parse_str(TER_WAT).unwrap();
    let sec = wat::parse_str(SEC_WAT).unwrap();
    let burn = wat::parse_str(BURN_WAT).unwrap();

    // Off by default: zero user nodes allowed.
    assert!(dag.register(spec("alice", "u1", &ter, &["sec"], 1), &ter).unwrap_err().contains("quota"));
    dag.set_quota("alice", Quota { max_nodes: 3, fuel_per_block: 50_000_000, storage_bytes: 1 << 30 }).unwrap();
    assert!(dag.register(spec("alice", "u1", &ter, &["sec"], 1), b"x").unwrap_err().contains("sha256"));
    assert!(dag.register(spec("alice", "u1", &ter, &["nope"], 1), &ter).unwrap_err().contains("unknown upstream"));
    // A wasm module is not BPF bytecode: the verifier refuses it.
    let mut b = spec("alice", "b1", &ter, &[], 1);
    b.kind = "bpf".into();
    assert!(dag.register(b, &ter).unwrap_err().contains("verifier"));

    // A tertiary-shaped user node, backfilled from height 1.
    let before_std = dump_all(&mgr);
    dag.register(spec("alice", "u1", &ter, &["sec"], 1), &ter).unwrap();
    // Same keys as the standard `sec` (/txs, /len): they land in its own store only.
    dag.register(spec("alice", "copy", &sec, &[], 2), &sec).unwrap();
    // Reads `sec` without declaring it: errors and pauses, without stalling others.
    dag.register(spec("alice", "bad", &ter, &[], 1), &ter).unwrap();
    assert!(dag.register(spec("alice", "four", &sec, &[], 1), &sec).unwrap_err().contains("quota"));

    wait_until("u1 and copy to reach 3", || {
        dag.node("alice", "u1").unwrap().height() == Some(3) && dag.node("alice", "copy").unwrap().height() == Some(3)
    });
    assert_eq!(le32(&dag.view("alice", "u1", "dbl", vec![], None).unwrap()), 18);
    assert_eq!(le32(&dag.view("alice", "u1", "dbl", vec![], Some(1)).unwrap()), 6);
    assert_eq!(le32(&dag.view("alice", "copy", "txs", vec![], None).unwrap()), 1 + 5);
    assert!(dag.view("alice", "u1", "dbl", vec![], Some(9)).is_err());
    assert_eq!(before_std, dump_all(&mgr), "user nodes wrote into a standard store");

    wait_until("bad to error", || dag.status("alice", "bad").unwrap()["state"] == "errored");
    let st = dag.status("alice", "bad").unwrap();
    assert!(st["error"].as_str().unwrap().contains("access denied"), "{}", st);
    assert_eq!(st["height"], serde_json::Value::Null);
    assert_eq!(st["lag"], 3);

    // Fuel cap: a looping program errors with out_of_fuel; quota on storage.
    dag.set_quota("bob", Quota { max_nodes: 1, fuel_per_block: 1_000_000, storage_bytes: 1 << 30 }).unwrap();
    dag.register(spec("bob", "burn", &burn, &[], 3), &burn).unwrap();
    dag.set_quota("carol", Quota { max_nodes: 1, fuel_per_block: 50_000_000, storage_bytes: 1 }).unwrap();
    dag.register(spec("carol", "big", &sec, &[], 1), &sec).unwrap();
    wait_until("burn/big to error", || {
        dag.status("bob", "burn").unwrap()["state"] == "errored" && dag.status("carol", "big").unwrap()["state"] == "errored"
    });
    assert!(dag.status("bob", "burn").unwrap()["error"].as_str().unwrap().contains("out_of_fuel"));
    assert!(dag.status("carol", "big").unwrap()["error"].as_str().unwrap().contains("storage quota"));

    // A new block: standard first, then user nodes; errored nodes stay put.
    let b4 = chain.connect(&mgr, 1);
    blocks.lock().push(b4);
    dag.notify_block(4);
    wait_until("u1 at 4", || dag.node("alice", "u1").unwrap().height() == Some(4));
    assert_eq!(le32(&dag.view("alice", "u1", "dbl", vec![], None).unwrap()), 2 * (9 + 2));
    assert_eq!(dag.status("alice", "bad").unwrap()["state"], "errored");
    assert_eq!(dag.list(Some("alice")).as_array().unwrap().len(), 3);
    assert_eq!(dag.list(None).as_array().unwrap().len(), 5);

    // Usage ledger.
    let u = dag.usage("alice", 0, 100);
    let u1 = &u["nodes"]["u1"];
    assert_eq!(u1["blocks"], 4, "{}", u);
    assert!(u1["fuel"].as_u64().unwrap() > 0);
    assert_eq!(u1["kv_writes"], 4);
    assert_eq!(u1["kv_bytes_written"], 4 * 8);
    assert_eq!(u1["view_calls"], 3, "{}", u); // the out-of-range view is refused before it runs
    assert!(u1["storage_bytes"].as_u64().unwrap() > 0);
    assert_eq!(u["nodes"]["bad"]["errors"], 1);
    let only3 = dag.usage("alice", 3, 3);
    assert!(only3["rows"].as_array().unwrap().iter().all(|r| r["height"] == 3 || r["height"] == 4 && r["usage"]["blocks"] == 0));
    assert_eq!(dag.usage("bob", 0, 100)["nodes"]["burn"]["fuel"], 1_000_000);

    // Simulation sees user nodes as @owner/name.
    let e = chain.engine(&mgr, SimConfig::default());
    e.add_provider(dag.clone());
    let r = e
        .simulate(SimRequest { txs: txs(2, 60), indexers: Some(vec!["@alice/u1".into()]), ..Default::default() })
        .unwrap();
    assert_eq!(r["per_indexer"]["@alice/u1"]["ok"], true, "{}", r);
    assert_eq!(sim_u32(&e, r["overlay_id"].as_str().unwrap(), "@alice/u1", "dbl"), 2 * (11 + 3));

    // Reorg to 2, then a different block 3.
    mgr.on_reorg(2);
    dag.on_reorg(2);
    assert_eq!(dag.node("alice", "u1").unwrap().height(), Some(2));
    assert_eq!(le32(&dag.view("alice", "u1", "dbl", vec![], None).unwrap()), 2 * 4);
    {
        let mut t = chain.tip.lock();
        t.height = 2;
        t.hash = qubitcoin_crypto::hash::hash256(&chain.blocks[1][..80]);
    }
    let alt3 = chain.connect(&mgr, 6);
    {
        let mut bl = blocks.lock();
        bl.truncate(2);
        bl.push(alt3);
    }
    dag.notify_block(3);
    wait_until("u1 back at 3", || dag.node("alice", "u1").unwrap().height() == Some(3));
    assert_eq!(le32(&dag.view("alice", "u1", "dbl", vec![], None).unwrap()), 2 * (4 + 7));
    assert_eq!(le32(&mgr.call_view("ter", "dbl", vec![]).unwrap()), 2 * (4 + 7));

    // Resume clears the error (it errors again: still undeclared).
    dag.resume("alice", "bad").unwrap();
    assert!(dag.unregister("alice", "copy").unwrap());
    assert!(!dag.unregister("alice", "copy").unwrap());

    // Registrations survive a restart.
    dag.shutdown();
    drop(e);
    drop(dag);
    std::thread::sleep(Duration::from_millis(300));
    let dag = open_dag(dir.path(), &mgr, blocks.clone(), 3);
    assert_eq!(dag.list(Some("alice")).as_array().unwrap().len(), 2);
    assert_eq!(dag.node("alice", "u1").unwrap().height(), Some(3));
    assert_eq!(dag.quota("carol").storage_bytes, 1);
}

#[test]
fn user_dag_rpc_shapes() {
    use qubitcoin_indexer::dag_rpc::register_user_dag_rpcs;
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mgr = sec_ter(dir.path());
    let mut chain = Chain::new();
    chain.connect(&mgr, 1);
    let blocks = Arc::new(parking_lot::Mutex::new(chain.blocks.clone()));
    let dag = open_dag(dir.path(), &mgr, blocks, 1);
    let mut rpcs = std::collections::HashMap::new();
    register_user_dag_rpcs(&mut |n: &str, h| { rpcs.insert(n.to_string(), h); }, dag.clone());
    let ter = wat::parse_str(TER_WAT).unwrap();
    let q = rpcs["setdagquota"](&json!(["o", {"max_nodes": 1}]));
    assert_eq!(q["quota"]["max_nodes"], 1);
    let r = rpcs["registerdagnode"](&json!(["o", "n", "wasm", format!("0x{}", hex::encode(&ter)), sha_hex(&ter), ["sec"], 1, {"fuel_per_block": 1000000}]));
    assert_eq!(r["id"], "@o/n", "{}", r);
    wait_until("n at 1", || dag.node("o", "n").unwrap().height() == Some(1));
    let s = rpcs["getdagnodestatus"](&json!(["o", "n"]));
    assert_eq!(s["state"], "running");
    assert_eq!(s["lag"], 0);
    assert_eq!(rpcs["dagview"](&json!(["o", "n", "dbl", "0x"])), json!(format!("0x{}", hex::encode(4u32.to_le_bytes()))));
    assert_eq!(rpcs["listdagnodes"](&json!(["o"])).as_array().unwrap().len(), 1);
    assert_eq!(rpcs["getdagusage"](&json!(["o", 0, 10]))["nodes"]["n"]["blocks"], 1);
    assert_eq!(rpcs["unregisterdagnode"](&json!(["o", "n"])), json!({"unregistered": true}));
    assert!(rpcs["resumedagnode"](&json!(["o", "n"])).get("error").is_some());
}

// ---------------------------------------------------------------------------
// BPF user nodes
// ---------------------------------------------------------------------------
//
// Programs are assembled in-test (solana-sbpf assembler, SBPF v3). The heap
// region starts at 0x3_0000_0000.
//
// * `COUNT_ASM` — block: `/txs` += tx count of the input block (u64), emits
//   the block's tx count, logs "/txs". View `txs`: emits `/txs`; any other
//   view exits with r0 = 2.
// * `DBL_ASM` — block: `/dbl` = `secondary_get(up0, "/txs")` +
//   `upstream_view(up0, "txs")` (= 2 × the upstream's `/txs`). Any view
//   emits `/dbl`.
// * `SPIN_ASM` — loops forever (instruction cap).
// * `RESERVED_ASM` — writes a host-reserved key (0xff prefix).

const COUNT_ASM: &str = "
    lddw r6, 0x300000000
    jne r1, 0, view
    mov64 r1, r6
    mov64 r2, 128
    mov64 r3, 0
    syscall get_input
    ldxb r7, [r6+84]
    stw [r6+256], 0x7378742f
    mov64 r1, r6
    add64 r1, 256
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 264
    mov64 r4, 8
    syscall kv_get
    ldxdw r8, [r6+264]
    jeq r0, 8, have
    mov64 r8, 0
have:
    add64 r8, r7
    stxdw [r6+264], r8
    mov64 r1, r6
    add64 r1, 256
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 264
    mov64 r4, 8
    syscall kv_set
    stxdw [r6+272], r7
    mov64 r1, r6
    add64 r1, 272
    mov64 r2, 8
    syscall emit
    mov64 r1, r6
    add64 r1, 256
    mov64 r2, 4
    syscall log
    mov64 r0, 0
    exit
view:
    mov64 r1, r6
    mov64 r2, 64
    mov64 r3, 0
    syscall get_input
    ldxw r7, [r6+4]
    jne r7, 3, bad
    ldxw r7, [r6+8]
    jne r7, 0x737874, bad
    stw [r6+256], 0x7378742f
    mov64 r1, r6
    add64 r1, 256
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 264
    mov64 r4, 8
    syscall kv_get
    mov64 r1, r6
    add64 r1, 264
    mov64 r2, 8
    syscall emit
    mov64 r0, 0
    exit
bad:
    mov64 r0, 2
    exit
";

const DBL_ASM: &str = "
    lddw r6, 0x300000000
    stw [r6+280], 0x6c62642f
    jne r1, 0, view
    stw [r6+256], 0x7378742f
    mov64 r1, 0
    mov64 r2, r6
    add64 r2, 256
    mov64 r3, 4
    mov64 r4, r6
    add64 r4, 264
    mov64 r5, 8
    syscall secondary_get
    ldxw r7, [r6+264]
    jeq r0, 4, got
    mov64 r7, 0
got:
    stw [r6+288], 0x737874
    stxdw [r6+320], r6
    stdw [r6+328], 0
    mov64 r8, r6
    add64 r8, 352
    stxdw [r6+336], r8
    stdw [r6+344], 8
    mov64 r1, 0
    mov64 r2, r6
    add64 r2, 288
    mov64 r3, 3
    mov64 r4, r6
    add64 r4, 320
    syscall upstream_view
    ldxw r8, [r6+352]
    add64 r7, r8
    stxdw [r6+272], r7
    mov64 r1, r6
    add64 r1, 280
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 272
    mov64 r4, 8
    syscall kv_set
    mov64 r0, 0
    exit
view:
    mov64 r1, r6
    add64 r1, 280
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 272
    mov64 r4, 8
    syscall kv_get
    mov64 r1, r6
    add64 r1, 272
    mov64 r2, 8
    syscall emit
    mov64 r0, 0
    exit
";

const SPIN_ASM: &str = "
spin:
    add64 r0, 1
    ja spin
";

const RESERVED_ASM: &str = "
    lddw r6, 0x300000000
    stb [r6+0], 0xff
    mov64 r1, r6
    mov64 r2, 1
    mov64 r3, r6
    mov64 r4, 1
    syscall kv_set
    mov64 r0, 0
    exit
";

use qubitcoin_indexer::bpf;

fn bpf_spec(owner: &str, name: &str, prog: &[u8], ups: &[&str], start: u32) -> UserNodeSpec {
    let mut s = spec(owner, name, prog, ups, start);
    s.kind = "bpf".into();
    s
}

fn le64(v: &[u8]) -> u64 {
    assert_eq!(v.len(), 8, "expected a u64, got {:?}", v);
    u64::from_le_bytes(v.try_into().unwrap())
}

fn quota(max_nodes: u32, fuel: u64) -> Quota {
    Quota { max_nodes, fuel_per_block: fuel, storage_bytes: 1 << 30 }
}

/// sec/ter manager with blocks of [2, 0, 4] txs (tx counts 3, 1, 5) and a
/// user DAG at tip 3.
fn bpf_fixture(dir: &Path) -> (IndexerManager, Chain, Arc<parking_lot::Mutex<Vec<Vec<u8>>>>, Arc<UserDag>) {
    let mgr = sec_ter(dir);
    let mut chain = Chain::new();
    for n in [2, 0, 4] {
        chain.connect(&mgr, n);
    }
    let blocks = Arc::new(parking_lot::Mutex::new(chain.blocks.clone()));
    let dag = open_dag(dir, &mgr, blocks.clone(), 3);
    (mgr, chain, blocks, dag)
}

#[test]
fn bpf_nodes_count_read_upstreams_and_isolate() {
    let dir = tempfile::tempdir().unwrap();
    let (mgr, _chain, _blocks, dag) = bpf_fixture(dir.path());
    let count = bpf::assemble(COUNT_ASM).unwrap();
    let dbl = bpf::assemble(DBL_ASM).unwrap();
    let reserved = bpf::assemble(RESERVED_ASM).unwrap();
    dag.set_quota("alice", quota(3, 10_000_000)).unwrap();
    dag.set_quota("bob", quota(2, 10_000_000)).unwrap();
    let before_std = dump_all(&mgr);

    dag.register(bpf_spec("alice", "cnt", &count, &[], 1), &count).unwrap();
    dag.register(bpf_spec("alice", "dbl", &dbl, &["sec"], 1), &dbl).unwrap();
    // Reads upstream #0 without declaring any: denied, pauses only itself.
    dag.register(bpf_spec("alice", "nodecl", &dbl, &[], 1), &dbl).unwrap();
    // The same program and keys under another owner, from height 2.
    dag.register(bpf_spec("bob", "cnt", &count, &[], 2), &count).unwrap();
    dag.register(bpf_spec("bob", "evil", &reserved, &[], 1), &reserved).unwrap();

    wait_until("bpf nodes at 3", || {
        ["alice/cnt", "alice/dbl", "bob/cnt"].iter().all(|id| {
            let (o, n) = id.split_once('/').unwrap();
            dag.node(o, n).unwrap().height() == Some(3)
        })
    });
    // Counting txs per block (3 + 1 + 5), as of any height.
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 9);
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], Some(1)).unwrap()), 3);
    assert_eq!(le64(&dag.view("alice", "cnt", bpf::EMITTED_VIEW, vec![], None).unwrap()), 5);
    assert_eq!(le64(&dag.view("alice", "cnt", bpf::EMITTED_VIEW, vec![], Some(2)).unwrap()), 1);
    let e = dag.view("alice", "cnt", "nope", vec![], None).unwrap_err();
    assert!(e.contains("r0 = 2"), "{}", e);
    let st = dag.status("alice", "cnt").unwrap();
    assert_eq!(st["kind"], "bpf");
    assert_eq!(st["state"], "running");
    assert_eq!(st["logs"], serde_json::json!(["/txs"]));

    // Upstream secondary key + upstream view: 2 × sec./txs, at each height.
    assert_eq!(le64(&dag.view("alice", "dbl", "dbl", vec![], None).unwrap()), 18);
    assert_eq!(le64(&dag.view("alice", "dbl", "dbl", vec![], Some(2)).unwrap()), 8);
    assert_eq!(le32(&mgr.call_view("ter", "dbl", vec![]).unwrap()), 18);

    // Isolation: undeclared upstream denied; reserved keys refused; bob's
    // counter (same keys) is its own; no standard store was touched.
    wait_until("nodecl and evil to error", || {
        dag.status("alice", "nodecl").unwrap()["state"] == "errored" && dag.status("bob", "evil").unwrap()["state"] == "errored"
    });
    let st = dag.status("alice", "nodecl").unwrap();
    assert!(st["error"].as_str().unwrap().contains("access denied"), "{}", st);
    assert_eq!(st["height"], serde_json::Value::Null);
    assert!(dag.status("bob", "evil").unwrap()["error"].as_str().unwrap().contains("reserved"));
    assert_eq!(le64(&dag.view("bob", "cnt", "txs", vec![], None).unwrap()), 1 + 5);
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 9);
    assert_ne!(dag.node("alice", "cnt").unwrap().db.path(), dag.node("bob", "cnt").unwrap().db.path());
    assert_eq!(before_std, dump_all(&mgr), "a BPF node wrote into a standard store");

    // Verifier: a bad program is refused and nothing is stored.
    let bad = bpf::assemble("ja +7\nexit").unwrap();
    dag.set_quota("dave", quota(1, 10_000_000)).unwrap();
    let e = dag.register(bpf_spec("dave", "bad", &bad, &[], 1), &bad).unwrap_err();
    assert!(e.contains("verifier") && e.contains("jump out of code"), "{}", e);
    let unknown = bpf::assemble("syscall open_socket\nmov64 r0, 0\nexit").unwrap();
    let e = dag.register(bpf_spec("dave", "bad", &unknown, &[], 1), &unknown).unwrap_err();
    assert!(e.contains("verifier") && e.contains("syscall"), "{}", e);
    assert!(dag.node("dave", "bad").is_none());
    assert!(!dir.path().join("dag/programs").join(format!("{}.bpf", sha_hex(&bad))).exists());

    // Metering: instructions are fuel; 2 writes per block (/txs + emit).
    let u = dag.usage("alice", 0, 100);
    let cnt = &u["nodes"]["cnt"];
    assert_eq!(cnt["blocks"], 3, "{}", u);
    assert_eq!(cnt["kv_writes"], 6, "{}", u);
    assert!(cnt["fuel"].as_u64().unwrap() > 0);
    assert_eq!(u["nodes"]["nodecl"]["errors"], 1);

    // Registrations (and the stored .bpf program) survive a restart.
    dag.shutdown();
    drop(dag);
    std::thread::sleep(Duration::from_millis(300));
    let dag = open_dag(dir.path(), &mgr, _blocks.clone(), 3);
    assert_eq!(dag.list(Some("alice")).as_array().unwrap().len(), 3);
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 9);
}

#[test]
fn bpf_instruction_cap_pauses_only_that_node() {
    let dir = tempfile::tempdir().unwrap();
    let (mgr, mut chain, blocks, dag) = bpf_fixture(dir.path());
    let count = bpf::assemble(COUNT_ASM).unwrap();
    let spin = bpf::assemble(SPIN_ASM).unwrap();
    dag.set_quota("carol", quota(2, 100_000)).unwrap();
    dag.register(bpf_spec("carol", "spin", &spin, &[], 2), &spin).unwrap();
    dag.register(bpf_spec("carol", "cnt", &count, &[], 1), &count).unwrap();
    wait_until("spin to error and cnt at 3", || {
        dag.status("carol", "spin").unwrap()["state"] == "errored" && dag.node("carol", "cnt").unwrap().height() == Some(3)
    });
    let st = dag.status("carol", "spin").unwrap();
    assert!(st["error"].as_str().unwrap().contains("out_of_fuel"), "{}", st);
    assert_eq!(st["height"], serde_json::Value::Null);
    assert_eq!(dag.usage("carol", 0, 100)["nodes"]["spin"]["fuel"], 100_000);

    // A new block: the counter advances, the spinner stays paused.
    let b4 = chain.connect(&mgr, 1);
    blocks.lock().push(b4);
    dag.notify_block(4);
    wait_until("cnt at 4", || dag.node("carol", "cnt").unwrap().height() == Some(4));
    assert_eq!(le64(&dag.view("carol", "cnt", "txs", vec![], None).unwrap()), 9 + 2);
    assert_eq!(dag.status("carol", "spin").unwrap()["state"], "errored");
    // A view is capped the same way (the node's fuel cap).
    let spin_view = dag.view("carol", "spin", "x", vec![], None);
    assert!(spin_view.is_err());

    // Resume retries, and it runs out again.
    dag.resume("carol", "spin").unwrap();
    wait_until("spin to error again", || {
        let u = dag.usage("carol", 0, 100);
        u["nodes"]["spin"]["errors"] == 2
    });
    assert_eq!(dag.status("carol", "spin").unwrap()["state"], "errored");
}

#[test]
fn bpf_reorg_rollback_and_simulation() {
    let dir = tempfile::tempdir().unwrap();
    let (mgr, mut chain, blocks, dag) = bpf_fixture(dir.path());
    let count = bpf::assemble(COUNT_ASM).unwrap();
    let dbl = bpf::assemble(DBL_ASM).unwrap();
    dag.set_quota("alice", quota(2, 10_000_000)).unwrap();
    dag.register(bpf_spec("alice", "cnt", &count, &[], 1), &count).unwrap();
    dag.register(bpf_spec("alice", "dbl", &dbl, &["sec"], 1), &dbl).unwrap();
    wait_until("both at 3", || {
        dag.node("alice", "cnt").unwrap().height() == Some(3) && dag.node("alice", "dbl").unwrap().height() == Some(3)
    });

    // Simulation overlay: a block with 2 txs (3 with the coinbase) on top of
    // the tip. The BPF nodes read their own and their upstream's simulated
    // state, and their stores are untouched.
    let before = (store::dump(&dag.node("alice", "cnt").unwrap().db), store::dump(&dag.node("alice", "dbl").unwrap().db));
    let e = chain.engine(&mgr, SimConfig::default());
    e.add_provider(dag.clone());
    let r = e
        .simulate(SimRequest {
            txs: txs(2, 70),
            indexers: Some(vec!["@alice/cnt".into(), "@alice/dbl".into()]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r["per_indexer"]["@alice/cnt"]["ok"], true, "{}", r);
    assert_eq!(r["per_indexer"]["@alice/dbl"]["ok"], true, "{}", r);
    assert_eq!(r["per_indexer"]["sec"]["ok"], true, "{}", r);
    assert!(r["per_indexer"]["@alice/cnt"]["fuel_used"].as_u64().unwrap() > 0);
    let id = r["overlay_id"].as_str().unwrap();
    assert_eq!(le64(&e.view(id, "@alice/cnt", "txs", vec![]).unwrap()), 9 + 3);
    assert_eq!(le64(&e.view(id, "@alice/cnt", bpf::EMITTED_VIEW, vec![]).unwrap()), 3);
    assert_eq!(le64(&e.view(id, "@alice/dbl", "dbl", vec![]).unwrap()), 2 * (9 + 3));
    // A stacked layer on the overlay.
    let r2 = e
        .simulate(SimRequest { txs: txs(1, 71), parent: Some(id.to_string()), ..Default::default() })
        .unwrap();
    let id2 = r2["overlay_id"].as_str().unwrap();
    assert_eq!(le64(&e.view(id2, "@alice/cnt", "txs", vec![]).unwrap()), 9 + 3 + 2);
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 9);
    let after = (store::dump(&dag.node("alice", "cnt").unwrap().db), store::dump(&dag.node("alice", "dbl").unwrap().db));
    assert_eq!(before, after, "simulation wrote into a BPF node's store");

    // Reorg to 2, then a different block 3 with 6 txs (7 with the coinbase).
    mgr.on_reorg(2);
    dag.on_reorg(2);
    assert_eq!(dag.node("alice", "cnt").unwrap().height(), Some(2));
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 4);
    assert_eq!(le64(&dag.view("alice", "dbl", "dbl", vec![], None).unwrap()), 8);
    assert!(dag.view("alice", "cnt", bpf::EMITTED_VIEW, vec![], Some(3)).is_err());
    {
        let mut t = chain.tip.lock();
        t.height = 2;
        t.hash = qubitcoin_crypto::hash::hash256(&chain.blocks[1][..80]);
    }
    let alt3 = chain.connect(&mgr, 6);
    {
        let mut bl = blocks.lock();
        bl.truncate(2);
        bl.push(alt3);
    }
    dag.notify_block(3);
    wait_until("both back at 3", || {
        dag.node("alice", "cnt").unwrap().height() == Some(3) && dag.node("alice", "dbl").unwrap().height() == Some(3)
    });
    assert_eq!(le64(&dag.view("alice", "cnt", "txs", vec![], None).unwrap()), 4 + 7);
    assert_eq!(le64(&dag.view("alice", "cnt", bpf::EMITTED_VIEW, vec![], None).unwrap()), 7);
    assert_eq!(le64(&dag.view("alice", "dbl", "dbl", vec![], None).unwrap()), 2 * (4 + 7));
}

#[test]
fn bpf_registerdagnode_rpc() {
    use qubitcoin_indexer::dag_rpc::register_user_dag_rpcs;
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let (_mgr, _chain, _blocks, dag) = bpf_fixture(dir.path());
    let mut rpcs = std::collections::HashMap::new();
    register_user_dag_rpcs(&mut |n: &str, h| { rpcs.insert(n.to_string(), h); }, dag.clone());
    let count = bpf::assemble(COUNT_ASM).unwrap();
    rpcs["setdagquota"](&json!(["o", {"max_nodes": 1}]));
    let r = rpcs["registerdagnode"](&json!(["o", "c", "bpf", format!("0x{}", hex::encode(&count)), sha_hex(&count), [], 1]));
    assert_eq!(r["kind"], "bpf", "{}", r);
    wait_until("c at 3", || dag.node("o", "c").unwrap().height() == Some(3));
    assert_eq!(rpcs["dagview"](&json!(["o", "c", "txs", "0x"])), json!(format!("0x{}", hex::encode(9u64.to_le_bytes()))));
    assert_eq!(rpcs["dagview"](&json!(["o", "c", "__emitted", "0x", 1])), json!(format!("0x{}", hex::encode(3u64.to_le_bytes()))));
}
