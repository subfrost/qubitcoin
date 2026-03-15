//! RPC method registration for secondary indexers.
//!
//! Registers 4 RPC methods:
//! - `secondaryview`   — call a view function on an indexer
//! - `secondaryheight` — get an indexer's current tip height
//! - `secondaryhash`   — get the SHA-256 of an indexer's WASM binary
//! - `secondaryroot`   — get the SMT state root (if enabled)

use crate::IndexerManager;
use std::sync::Arc;

/// Register all secondary indexer RPC methods on the provided registry.
///
/// The registry type is kept generic via a closure-based approach so this
/// crate doesn't depend on `qubitcoin-rpc`.
pub fn register_indexer_rpcs<F>(register: &mut F, manager: Arc<IndexerManager>)
where
    F: FnMut(&str, Box<dyn Fn(&serde_json::Value) -> serde_json::Value + Send + Sync>),
{
    // secondaryheight ["label"]
    {
        let mgr = manager.clone();
        register(
            "secondaryheight",
            Box::new(move |params: &serde_json::Value| {
                let label = match params.get(0).and_then(|v| v.as_str()) {
                    Some(l) => l,
                    None => {
                        return serde_json::json!({
                            "error": "missing label parameter"
                        })
                    }
                };
                match mgr.get_indexer(label) {
                    Some(inst) => {
                        serde_json::json!(inst.tip_height.load(std::sync::atomic::Ordering::Relaxed))
                    }
                    None => serde_json::json!({
                        "error": format!("indexer '{}' not found", label)
                    }),
                }
            }),
        );
    }

    // secondaryhash ["label"]
    {
        let mgr = manager.clone();
        register(
            "secondaryhash",
            Box::new(move |params: &serde_json::Value| {
                let label = match params.get(0).and_then(|v| v.as_str()) {
                    Some(l) => l,
                    None => {
                        return serde_json::json!({
                            "error": "missing label parameter"
                        })
                    }
                };
                match mgr.get_indexer(label) {
                    Some(inst) => {
                        let hex: String =
                            inst.wasm_hash.iter().map(|b| format!("{:02x}", b)).collect();
                        serde_json::json!(hex)
                    }
                    None => serde_json::json!({
                        "error": format!("indexer '{}' not found", label)
                    }),
                }
            }),
        );
    }

    // secondaryroot ["label"]
    {
        let mgr = manager.clone();
        register(
            "secondaryroot",
            Box::new(move |params: &serde_json::Value| {
                let label = match params.get(0).and_then(|v| v.as_str()) {
                    Some(l) => l,
                    None => {
                        return serde_json::json!({
                            "error": "missing label parameter"
                        })
                    }
                };
                match mgr.get_indexer(label) {
                    Some(inst) => {
                        if !inst.smt_enabled {
                            return serde_json::json!({
                                "error": "SMT not enabled for this indexer"
                            });
                        }
                        let height =
                            inst.tip_height.load(std::sync::atomic::Ordering::Relaxed);
                        let root_key = crate::smt::smt_root_key(height);
                        match inst.storage.get(&root_key) {
                            Some(root) => {
                                let hex: String =
                                    root.iter().map(|b| format!("{:02x}", b)).collect();
                                serde_json::json!(format!("0x{}", hex))
                            }
                            None => serde_json::json!(
                                "0x0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                        }
                    }
                    None => serde_json::json!({
                        "error": format!("indexer '{}' not found", label)
                    }),
                }
            }),
        );
    }

    // secondaryview ["label", "view_fn", "input_hex", "latest"|height]
    {
        let mgr = manager.clone();
        register(
            "secondaryview",
            Box::new(move |params: &serde_json::Value| {
                let label = match params.get(0).and_then(|v| v.as_str()) {
                    Some(l) => l,
                    None => {
                        return serde_json::json!({
                            "error": "missing label parameter"
                        })
                    }
                };
                let view_fn = match params.get(1).and_then(|v| v.as_str()) {
                    Some(f) => f,
                    None => {
                        return serde_json::json!({
                            "error": "missing view_fn parameter"
                        })
                    }
                };
                let input_hex = params
                    .get(2)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Decode hex input.
                let input_bytes = match hex_decode(input_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return serde_json::json!({
                            "error": format!("invalid hex input: {}", e)
                        })
                    }
                };

                // Use async view with fuel-based cooperative yielding.
                // Since RPC handlers are sync, use tokio::task::block_in_place
                // to call the async view without blocking the runtime.
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        mgr.call_view_async(label, view_fn, input_bytes),
                    )
                });
                match result {
                    Ok(result) => {
                        let hex: String =
                            result.iter().map(|b| format!("{:02x}", b)).collect();
                        serde_json::json!(format!("0x{}", hex))
                    }
                    Err(e) => serde_json::json!({
                        "error": e
                    }),
                }
            }),
        );
    }
}

/// Simple hex decoder.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("{}", e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, IndexerManager, IndexerMode};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn setup_manager() -> (Arc<IndexerManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, crate::build_test_wasm()).unwrap();

        let configs = vec![config::IndexerConfig {
            label: "testrpc".to_string(),
            wasm_path,
            smt_enabled: false,
        }];

        let datadir = PathBuf::from(dir.path());
        let mgr = Arc::new(
            IndexerManager::new(configs, &datadir, IndexerMode::Synchronous).unwrap(),
        );
        (mgr, dir)
    }

    fn collect_rpcs(
        mgr: Arc<IndexerManager>,
    ) -> HashMap<String, Box<dyn Fn(&serde_json::Value) -> serde_json::Value + Send + Sync>>
    {
        let mut rpcs: HashMap<
            String,
            Box<dyn Fn(&serde_json::Value) -> serde_json::Value + Send + Sync>,
        > = HashMap::new();
        register_indexer_rpcs(
            &mut |name: &str,
                  handler: Box<
                dyn Fn(&serde_json::Value) -> serde_json::Value + Send + Sync,
            >| {
                rpcs.insert(name.to_string(), handler);
            },
            mgr,
        );
        rpcs
    }

    #[test]
    fn test_rpcs_registered() {
        let (mgr, _dir) = setup_manager();
        let rpcs = collect_rpcs(mgr);
        assert!(rpcs.contains_key("secondaryheight"));
        assert!(rpcs.contains_key("secondaryhash"));
        assert!(rpcs.contains_key("secondaryroot"));
        assert!(rpcs.contains_key("secondaryview"));
    }

    #[test]
    fn test_secondaryheight() {
        let (mgr, _dir) = setup_manager();
        mgr.on_block_connected(42, b"block");
        let rpcs = collect_rpcs(mgr);

        let handler = rpcs.get("secondaryheight").unwrap();
        let result = handler(&serde_json::json!(["testrpc"]));
        assert_eq!(result, serde_json::json!(42));
    }

    #[test]
    fn test_secondaryheight_not_found() {
        let (mgr, _dir) = setup_manager();
        let rpcs = collect_rpcs(mgr);

        let handler = rpcs.get("secondaryheight").unwrap();
        let result = handler(&serde_json::json!(["nonexistent"]));
        assert!(result.get("error").is_some());
    }

    #[test]
    fn test_secondaryheight_missing_param() {
        let (mgr, _dir) = setup_manager();
        let rpcs = collect_rpcs(mgr);

        let handler = rpcs.get("secondaryheight").unwrap();
        let result = handler(&serde_json::json!([]));
        assert!(result.get("error").is_some());
    }

    #[test]
    fn test_secondaryhash() {
        let (mgr, _dir) = setup_manager();
        let rpcs = collect_rpcs(mgr);

        let handler = rpcs.get("secondaryhash").unwrap();
        let result = handler(&serde_json::json!(["testrpc"]));
        // Should be a 64-char hex string.
        let hash = result.as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_secondaryroot_not_enabled() {
        let (mgr, _dir) = setup_manager();
        let rpcs = collect_rpcs(mgr);

        let handler = rpcs.get("secondaryroot").unwrap();
        let result = handler(&serde_json::json!(["testrpc"]));
        assert!(result.get("error").is_some());
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("not enabled")
        );
    }

    #[test]
    fn test_hex_decode_basic() {
        assert_eq!(hex_decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_decode_0x_prefix() {
        assert_eq!(hex_decode("0xab").unwrap(), vec![0xab]);
    }

    #[test]
    fn test_hex_decode_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("0x").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }
}
