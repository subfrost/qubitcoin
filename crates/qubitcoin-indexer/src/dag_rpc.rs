//! JSON-RPC methods for DAG simulation. All are admin-tier: the node
//! registers them with `register_admin`, like the mining RPCs.
//!
//! * `simulateblock(txs_hex[], {indexers?, parent?, coinbase_hex?})`
//! * `simulatedview(overlay_id, indexer, view_fn, input_hex)`
//! * `releaseoverlay(overlay_id)`
//! * `loadsimulationindexer(name, wasm_hex | path, sha256, deps[])`
//! * `unloadsimulationindexer(name)`
//! * `getsimulationinfo()`
//!
//! See `docs/INDEXER-DAG.md` for the shapes.

use crate::simulation::{SimRequest, SimulationEngine};
use crate::usernodes::{Quota, UserDag, UserNodeSpec};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

type Handler = Box<dyn Fn(&Value) -> Value + Send + Sync>;

fn err(m: impl Into<String>) -> Value {
    json!({ "error": m.into() })
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("bad hex: {}", e))
}

/// Help text for each method (shown by `help <method>`).
pub const HELP: &[(&str, &str)] = &[
    ("simulateblock", "simulateblock [\"txhex\",...] ( {\"indexers\":[\"name\",...],\"parent\":\"overlay_id\",\"coinbase_hex\":\"hex\"} )\n\nBuild a block at tip+1 (no proof of work, never submitted) from the ordered\nraw transactions and an optional coinbase, and run it through every loaded\nindexer (or the named ones and their upstreams) in topological order of the\nindexer DAG, in fork mode over the confirmed state. With \"parent\", the\ntransactions are layered on an existing overlay (copy-on-write). Nothing is\nwritten to any indexer database or the chainstate.\n\nResult: {\"overlay_id\",\"height\",\"tip\",\"block_hash\",\"parent\",\"cached\",\"overlay_bytes\",\n\"per_indexer\":{name:{\"ok\",\"kind\",\"fuel_used\",\"error\"?,\"error_kind\"?,\"kv_writes\"?|\"output_bytes\"?}}}"),
    ("simulatedview", "simulatedview \"overlay_id\" \"indexer\" \"view_fn\" \"input_hex\"\n\nCall a view function against a simulation overlay. Same result as\nsecondaryview (\"0x...\"). For a transform node, view_fn \"output\" returns the\ntransformed block."),
    ("releaseoverlay", "releaseoverlay \"overlay_id\"\n\nDrop a simulation overlay and its cached views. Result: {\"released\":bool}"),
    ("loadsimulationindexer", "loadsimulationindexer \"name\" \"wasm_hex|path\" \"sha256\" [\"dep\",...]\n\nRegister a tertiary indexer that exists only in simulation (empty base\nstate, reads its deps' simulated state). Never touches a persistent store.\nThe sha256 must match the wasm. Result: {\"name\",\"sha256\"}"),
    ("unloadsimulationindexer", "unloadsimulationindexer \"name\"\n\nRemove a simulation-only indexer. Result: {\"unloaded\":bool}"),
    ("getsimulationinfo", "getsimulationinfo\n\nOverlay cache usage, caps and counters."),
    ("registerdagnode", "registerdagnode \"owner\" \"name\" \"kind\" \"program_hex|path\" \"sha256\" [\"upstream\",...] start_height ( {\"fuel_per_block\":n} )\n\nRegister a user program as a DAG node that indexes from start_height on the\nowner's behalf (backfilling past heights). kind: \"wasm\" (metashrew ABI).\nIt gets its own namespaced store and may read only the declared upstreams\n(standard indexers). Subject to the owner's quota. Result: node status."),
    ("unregisterdagnode", "unregisterdagnode \"owner\" \"name\"\n\nRemove a user node and delete its store. Result: {\"unregistered\":bool}"),
    ("listdagnodes", "listdagnodes ( \"owner\" )\n\nStatus of every user node (optionally one owner's)."),
    ("getdagnodestatus", "getdagnodestatus \"owner\" \"name\"\n\nHeight, chain height, lag, state (running|errored), error, blocks processed,\nlast block fuel, storage bytes, quota."),
    ("dagview", "dagview \"owner\" \"name\" \"view_fn\" \"input_hex\" ( height )\n\nCall a view of a user node as of height (default: its last processed\nheight). Result: \"0x...\". Counted in the usage ledger."),
    ("getdagusage", "getdagusage \"owner\" from_height to_height\n\nUsage ledger: {\"total\",\"nodes\":{name:usage},\"rows\":[{height,name,usage}],\"quota\"} where\nusage = {fuel, kv_writes, kv_bytes_written, storage_bytes, view_calls, blocks, errors}."),
    ("setdagquota", "setdagquota \"owner\" {\"max_nodes\":n,\"fuel_per_block\":n,\"storage_bytes\":n}\n\nOverride an owner's quota (unset fields keep the current value)."),
    ("resumedagnode", "resumedagnode \"owner\" \"name\"\n\nClear an errored node's error and resume indexing."),
];

/// Register the user-node RPCs through `register(name, handler)`.
pub fn register_user_dag_rpcs<F>(register: &mut F, dag: Arc<UserDag>)
where
    F: FnMut(&str, Handler),
{
    fn s(p: &Value, i: usize) -> Option<&str> {
        p.get(i).and_then(|v| v.as_str())
    }
    {
        let d = dag.clone();
        register(
            "registerdagnode",
            Box::new(move |p: &Value| {
                let (Some(owner), Some(name), Some(kind), Some(prog), Some(sha)) = (s(p, 0), s(p, 1), s(p, 2), s(p, 3), s(p, 4)) else {
                    return err("usage: registerdagnode owner name kind program_hex|path sha256 [upstreams] start_height {limits}");
                };
                let program = if prog.starts_with("0x") {
                    decode_hex(prog)
                } else if std::path::Path::new(prog).is_file() {
                    std::fs::read(prog).map_err(|e| format!("read {}: {}", prog, e))
                } else {
                    decode_hex(prog)
                };
                let program = match program {
                    Ok(b) => b,
                    Err(m) => return err(m),
                };
                let upstreams: Vec<String> = p
                    .get(5)
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let start_height = p.get(6).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let fuel_per_block = p.get(7).and_then(|v| v.get("fuel_per_block")).and_then(|v| v.as_u64());
                let spec = UserNodeSpec {
                    owner: owner.into(),
                    name: name.into(),
                    kind: kind.into(),
                    sha256: sha.into(),
                    upstreams,
                    start_height,
                    fuel_per_block,
                };
                d.register(spec, &program).unwrap_or_else(err)
            }),
        );
    }
    {
        let d = dag.clone();
        register(
            "unregisterdagnode",
            Box::new(move |p: &Value| match (s(p, 0), s(p, 1)) {
                (Some(o), Some(n)) => match d.unregister(o, n) {
                    Ok(b) => json!({ "unregistered": b }),
                    Err(m) => err(m),
                },
                _ => err("usage: unregisterdagnode owner name"),
            }),
        );
    }
    {
        let d = dag.clone();
        register("listdagnodes", Box::new(move |p: &Value| d.list(s(p, 0))));
    }
    {
        let d = dag.clone();
        register(
            "getdagnodestatus",
            Box::new(move |p: &Value| match (s(p, 0), s(p, 1)) {
                (Some(o), Some(n)) => d.status(o, n).unwrap_or_else(err),
                _ => err("usage: getdagnodestatus owner name"),
            }),
        );
    }
    {
        let d = dag.clone();
        register(
            "dagview",
            Box::new(move |p: &Value| {
                let (Some(o), Some(n), Some(f)) = (s(p, 0), s(p, 1), s(p, 2)) else {
                    return err("usage: dagview owner name view_fn input_hex [height]");
                };
                let input = match decode_hex(s(p, 3).unwrap_or("")) {
                    Ok(b) => b,
                    Err(m) => return err(m),
                };
                let h = p.get(4).and_then(|v| v.as_u64()).map(|h| h as u32);
                match d.view(o, n, f, input, h) {
                    Ok(out) => json!(format!("0x{}", hex::encode(out))),
                    Err(m) => err(m),
                }
            }),
        );
    }
    {
        let d = dag.clone();
        register(
            "getdagusage",
            Box::new(move |p: &Value| {
                let Some(o) = s(p, 0) else { return err("usage: getdagusage owner from to") };
                let from = p.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let to = p.get(2).and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(u32::MAX);
                d.usage(o, from, to)
            }),
        );
    }
    {
        let d = dag.clone();
        register(
            "setdagquota",
            Box::new(move |p: &Value| {
                let Some(o) = s(p, 0) else { return err("usage: setdagquota owner {..}") };
                let cur = d.quota(o);
                let q = p.get(1).cloned().unwrap_or(Value::Null);
                let get = |k: &str, dflt: u64| q.get(k).and_then(|v| v.as_u64()).unwrap_or(dflt);
                let nq = Quota {
                    max_nodes: get("max_nodes", cur.max_nodes as u64) as u32,
                    fuel_per_block: get("fuel_per_block", cur.fuel_per_block),
                    storage_bytes: get("storage_bytes", cur.storage_bytes),
                };
                match d.set_quota(o, nq) {
                    Ok(()) => json!({ "owner": o, "quota": nq }),
                    Err(m) => err(m),
                }
            }),
        );
    }
    {
        let d = dag;
        register(
            "resumedagnode",
            Box::new(move |p: &Value| match (s(p, 0), s(p, 1)) {
                (Some(o), Some(n)) => match d.resume(o, n) {
                    Ok(()) => json!({ "resumed": true }),
                    Err(m) => err(m),
                },
                _ => err("usage: resumedagnode owner name"),
            }),
        );
    }
}

/// Register the simulation RPCs through `register(name, handler)`.
pub fn register_simulation_rpcs<F>(register: &mut F, engine: Arc<SimulationEngine>)
where
    F: FnMut(&str, Handler),
{
    {
        let e = engine.clone();
        register(
            "simulateblock",
            Box::new(move |p: &Value| {
                let txs = match p.get(0).and_then(|v| v.as_array()) {
                    Some(a) => a,
                    None => return err("txs_hex must be an array of hex strings"),
                };
                let mut raw = Vec::with_capacity(txs.len());
                for t in txs {
                    match t.as_str().map(decode_hex) {
                        Some(Ok(b)) => raw.push(b),
                        Some(Err(m)) => return err(m),
                        None => return err("txs_hex must be an array of hex strings"),
                    }
                }
                let opts = p.get(1).cloned().unwrap_or(Value::Null);
                let indexers = match opts.get("indexers") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(a)) => Some(a.iter().filter_map(|v| v.as_str().map(String::from)).collect()),
                    Some(_) => return err("indexers must be an array of names"),
                };
                let coinbase = match opts.get("coinbase_hex").and_then(|v| v.as_str()) {
                    Some(h) => match decode_hex(h) {
                        Ok(b) => Some(b),
                        Err(m) => return err(m),
                    },
                    None => None,
                };
                let parent = opts.get("parent").and_then(|v| v.as_str()).map(String::from);
                match e.simulate(SimRequest { txs: raw, coinbase, indexers, parent }) {
                    Ok(v) => v,
                    Err(m) => err(m),
                }
            }),
        );
    }
    {
        let e = engine.clone();
        register(
            "simulatedview",
            Box::new(move |p: &Value| {
                let s = |i: usize| p.get(i).and_then(|v| v.as_str());
                let (Some(id), Some(node), Some(f)) = (s(0), s(1), s(2)) else {
                    return err("usage: simulatedview overlay_id indexer view_fn input_hex");
                };
                let input = match decode_hex(s(3).unwrap_or("")) {
                    Ok(b) => b,
                    Err(m) => return err(m),
                };
                match e.view(id, node, f, input) {
                    Ok(out) => json!(format!("0x{}", hex::encode(out))),
                    Err(m) => err(m),
                }
            }),
        );
    }
    {
        let e = engine.clone();
        register(
            "releaseoverlay",
            Box::new(move |p: &Value| match p.get(0).and_then(|v| v.as_str()) {
                Some(id) => json!({ "released": e.release(id) }),
                None => err("missing overlay_id"),
            }),
        );
    }
    {
        let e = engine.clone();
        register(
            "loadsimulationindexer",
            Box::new(move |p: &Value| {
                let s = |i: usize| p.get(i).and_then(|v| v.as_str());
                let (Some(name), Some(prog), Some(sha)) = (s(0), s(1), s(2)) else {
                    return err("usage: loadsimulationindexer name wasm_hex|path sha256 [deps]");
                };
                let bytes = if prog.starts_with("0x") {
                    decode_hex(prog)
                } else if std::path::Path::new(prog).is_file() {
                    std::fs::read(prog).map_err(|e| format!("read {}: {}", prog, e))
                } else {
                    decode_hex(prog)
                };
                let bytes = match bytes {
                    Ok(b) => b,
                    Err(m) => return err(m),
                };
                let deps: Vec<String> = p
                    .get(3)
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                match e.load_simulation_indexer(name, &bytes, sha, deps) {
                    Ok(h) => json!({ "name": name, "sha256": h }),
                    Err(m) => err(m),
                }
            }),
        );
    }
    {
        let e = engine.clone();
        register(
            "unloadsimulationindexer",
            Box::new(move |p: &Value| match p.get(0).and_then(|v| v.as_str()) {
                Some(n) => json!({ "unloaded": e.unload_simulation_indexer(n) }),
                None => err("missing name"),
            }),
        );
    }
    {
        let e = engine;
        register(
            "getsimulationinfo",
            Box::new(move |_p: &Value| {
                let (n, b, vn, vb) = e.cache_usage();
                let c = &e.config;
                json!({
                    "overlays": n,
                    "overlay_bytes": b,
                    "cached_views": vn,
                    "view_cache_bytes": vb,
                    "limits": {
                        "max_overlays": c.max_overlays,
                        "max_overlay_bytes": c.max_overlay_bytes,
                        "max_view_cache_bytes": c.max_view_cache_bytes,
                        "fuel_per_node": c.fuel_per_node,
                        "max_memory_bytes": c.max_memory_bytes,
                        "deadline_ms": c.deadline.as_millis() as u64,
                        "max_bytes_per_overlay": c.max_bytes_per_overlay,
                    },
                    "stats": {
                        "simulations": e.stats.simulations.load(Ordering::Relaxed),
                        "overlay_hits": e.stats.overlay_hits.load(Ordering::Relaxed),
                        "view_calls": e.stats.view_calls.load(Ordering::Relaxed),
                        "view_hits": e.stats.view_hits.load(Ordering::Relaxed),
                        "invalidations": e.stats.invalidations.load(Ordering::Relaxed),
                    },
                })
            }),
        );
    }
}
