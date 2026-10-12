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
];

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
