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
