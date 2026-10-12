//! Configuration parsing for indexer modules.
//!
//! Supports:
//! - `-loadindexer=label:path` command-line arguments
//! - `indexer.toml` manifest files

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Indexer layer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexerLayer {
    /// Secondary indexer: processes raw blocks, no dependencies on other indexers.
    Secondary,
    /// Tertiary indexer: depends on secondary (or other tertiary) indexers.
    Tertiary,
}

/// Configuration for a single indexer module.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// Human-readable label (e.g. "alkanes", "brc20").
    pub label: String,
    /// Path to the `.wasm` binary.
    pub wasm_path: PathBuf,
    /// Whether to compute SMT state roots.
    pub smt_enabled: bool,
    /// Block height at which this indexer begins processing.
    /// Blocks below this height are skipped. Default: 0 (process all blocks).
    pub start_height: u32,
    /// Indexer layer (secondary or tertiary).
    pub layer: IndexerLayer,
    /// `secondary` edges: labels of indexers whose KV this one reads through
    /// `__secondary_get` (at the same height). A node waits for all of them.
    pub depends_on: Vec<String>,
    /// `transform` edge: name of the transform node whose output block is
    /// this indexer's input block. `None` = the raw block (the DAG root).
    pub input: Option<String>,
    /// Run on the fork runner even without `secondary` edges (avoids
    /// `MetashrewRuntime`'s up-front 4 GiB memory commit). `runner=fork`.
    pub fork_runner: bool,
}

impl IndexerConfig {
    /// A secondary indexer reading raw blocks, with no edges.
    pub fn new(label: &str, wasm_path: PathBuf) -> Self {
        IndexerConfig {
            label: label.to_string(),
            wasm_path,
            smt_enabled: false,
            start_height: 0,
            layer: IndexerLayer::Secondary,
            depends_on: vec![],
            input: None,
            fork_runner: false,
        }
    }
}

/// What a transform node computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformKindConfig {
    /// Built-in `embed-view-in-coinbase{magic, upstream, view}`: append one
    /// coinbase output `OP_RETURN <push(magic ++ upstream.view(view_input))>`
    /// to the raw block. Byte-identical to alspo's `embed_traces` /
    /// `/v4/{apikey}/traces` facade for `alkanes/traceblock/ASP0`.
    EmbedViewInCoinbase {
        upstream: String,
        view: String,
        magic: Vec<u8>,
        view_input: Vec<u8>,
    },
    /// A sandboxed wasm exporting `transform() -> ArrayBuffer` (see docs).
    Wasm {
        path: PathBuf,
        /// Expected sha256 (hex) of the wasm; verified at load when set.
        sha256: Option<String>,
        /// Nodes the program may read (`__secondary_get`, `__upstream_view`).
        upstreams: Vec<String>,
    },
}

/// Configuration for a transform node (`-loadtransform`, or implied by an
/// indexer's `transform=upstream/view/MAGIC` shorthand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformConfig {
    pub name: String,
    pub kind: TransformKindConfig,
    /// Fuel cap per block for wasm transforms (None = engine default).
    pub fuel: Option<u64>,
}

impl TransformConfig {
    /// Nodes this transform reads.
    pub fn upstreams(&self) -> Vec<String> {
        match &self.kind {
            TransformKindConfig::EmbedViewInCoinbase { upstream, .. } => vec![upstream.clone()],
            TransformKindConfig::Wasm { upstreams, .. } => upstreams.clone(),
        }
    }

    /// Parse the `upstream/view/MAGIC` shorthand into a built-in transform
    /// named after the shorthand itself.
    pub fn from_shorthand(spec: &str) -> Option<Self> {
        let parts: Vec<&str> = spec.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        Some(TransformConfig {
            name: spec.to_string(),
            kind: TransformKindConfig::EmbedViewInCoinbase {
                upstream: parts[0].to_string(),
                view: parts[1].to_string(),
                magic: parts[2].as_bytes().to_vec(),
                view_input: vec![],
            },
            fuel: None,
        })
    }
}

/// Manifest file format (`indexer.toml`).
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexerManifest {
    pub label: String,
    pub sha256: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub installed_at: String,
    #[serde(default)]
    pub smt: bool,
    /// Block height at which this indexer begins processing (default: 0).
    #[serde(default)]
    pub start_height: u32,
    /// Indexer layer: "secondary" (default) or "tertiary".
    #[serde(default = "default_layer_str")]
    pub layer: String,
    /// Labels of indexers this one depends on (`secondary` edges).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// `transform` edge: a transform node name or `upstream/view/MAGIC`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
}

fn default_layer_str() -> String {
    "secondary".to_string()
}

/// Parse `-loadindexer=label:path[:opt]...` arguments.
///
/// `path` is a `.wasm` file or a directory holding `program.wasm` (and
/// optionally an `indexer.toml` manifest, whose fields win). Each extra
/// colon-separated `opt` is one of:
///
/// * `N` (a number) or `start=N` — start height (the original syntax);
/// * `deps=a,b` — `secondary` edges (read `a`, `b` via `__secondary_get`);
/// * `transform=T` (alias `input=T`) — `transform` edge: the input block is
///   the output of transform node `T`, or of the built-in
///   `embed-view-in-coinbase` when `T` is the shorthand `upstream/view/MAGIC`
///   (e.g. `transform=alkanes/traceblock/ASP0`);
/// * anything else (`a,b`) — `secondary` edges (the `-loadtertiary` form).
pub fn parse_load_indexer_args(args: &[&str]) -> Vec<IndexerConfig> {
    parse_indexer_args_with_layer(args, IndexerLayer::Secondary)
}

/// Parse `-loadtertiary=label:path:dep1,dep2` arguments.
pub fn parse_load_tertiary_args(args: &[&str]) -> Vec<IndexerConfig> {
    parse_indexer_args_with_layer(args, IndexerLayer::Tertiary)
}

fn parse_indexer_args_with_layer(args: &[&str], default_layer: IndexerLayer) -> Vec<IndexerConfig> {
    let mut configs = Vec::new();

    for arg in args {
        let parts: Vec<&str> = arg.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let label = parts[0];
        let path = PathBuf::from(parts[1]);

        let mut cli_deps: Vec<String> = vec![];
        let mut cli_start_height: u32 = 0;
        let mut cli_input: Option<String> = None;
        let mut cli_fork = false;
        for opt in &parts[2..] {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            if let Ok(h) = opt.parse::<u32>() {
                cli_start_height = h;
            } else if let Some(v) = opt.strip_prefix("start=") {
                cli_start_height = v.trim().parse().unwrap_or(0);
            } else if opt == "runner=fork" {
                cli_fork = true;
            } else if let Some(v) = opt.strip_prefix("deps=") {
                cli_deps.extend(split_list(v));
            } else if let Some(v) = opt.strip_prefix("transform=").or_else(|| opt.strip_prefix("input=")) {
                cli_input = Some(v.trim().to_string());
            } else {
                cli_deps.extend(split_list(opt));
            }
        }
        let layer_for = |deps: &Vec<String>, input: &Option<String>| {
            if default_layer == IndexerLayer::Tertiary || !deps.is_empty() || input.is_some() {
                IndexerLayer::Tertiary
            } else {
                IndexerLayer::Secondary
            }
        };

        if path.is_dir() {
            let manifest_path = path.join("indexer.toml");
            let wasm_path = path.join("program.wasm");
            if manifest_path.exists() {
                match load_manifest(&manifest_path) {
                    Ok(manifest) => {
                        let layer = parse_layer_str(&manifest.layer, default_layer);
                        let depends_on = if manifest.depends_on.is_empty() {
                            cli_deps.clone()
                        } else {
                            manifest.depends_on
                        };
                        let input = manifest.transform.or(cli_input.clone());
                        configs.push(IndexerConfig {
                            label: manifest.label,
                            wasm_path,
                            smt_enabled: manifest.smt,
                            start_height: manifest.start_height,
                            layer,
                            depends_on,
                            input,
                            fork_runner: cli_fork,
                        });
                    }
                    Err(e) => {
                        tracing::error!(
                            label = label,
                            path = %manifest_path.display(),
                            error = %e,
                            "failed to load indexer manifest"
                        );
                    }
                }
            } else {
                configs.push(IndexerConfig {
                    label: label.to_string(),
                    wasm_path,
                    smt_enabled: false,
                    start_height: cli_start_height,
                    layer: layer_for(&cli_deps, &cli_input),
                    depends_on: cli_deps.clone(),
                    input: cli_input.clone(),
                    fork_runner: cli_fork,
                });
            }
        } else {
            configs.push(IndexerConfig {
                label: label.to_string(),
                wasm_path: path,
                smt_enabled: false,
                start_height: cli_start_height,
                layer: layer_for(&cli_deps, &cli_input),
                depends_on: cli_deps.clone(),
                input: cli_input.clone(),
                fork_runner: cli_fork,
            });
        }
    }

    configs
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse `-loadtransform=name:SPEC[:opt]...` arguments, where `SPEC` is
///
/// * `builtin` / `embed-view-in-coinbase` with opts `upstream=U`, `view=V`,
///   `magic=M` (ASCII; `magic=0x..` for hex), optional `viewinput=0x..`; or
/// * a path to a transform `.wasm` with opts `sha256=HEX`, `deps=a,b`
///   (the upstreams it may read) and `fuel=N`.
pub fn parse_load_transform_args(args: &[&str]) -> Result<Vec<TransformConfig>, String> {
    let mut out = Vec::new();
    for arg in args {
        let parts: Vec<&str> = arg.split(':').collect();
        if parts.len() < 2 {
            return Err(format!("-loadtransform={}: expected name:spec[:opts]", arg));
        }
        let name = parts[0].to_string();
        let mut kv: HashMap<&str, &str> = HashMap::new();
        let mut spec = parts[1];
        let mut rest = &parts[2..];
        if spec == "builtin" && !rest.is_empty() && !rest[0].contains('=') {
            spec = rest[0];
            rest = &rest[1..];
        }
        for opt in rest {
            if let Some((k, v)) = opt.split_once('=') {
                kv.insert(k.trim(), v.trim());
            }
        }
        let fuel = kv.get("fuel").and_then(|v| v.parse().ok());
        let kind = match spec {
            "builtin" | "embed-view-in-coinbase" => {
                let get = |k: &str| {
                    kv.get(k)
                        .map(|s| s.to_string())
                        .ok_or_else(|| format!("-loadtransform={}: missing {}=", name, k))
                };
                let magic_s = get("magic")?;
                let magic = match magic_s.strip_prefix("0x") {
                    Some(h) => hex::decode(h).map_err(|e| format!("magic: {}", e))?,
                    None => magic_s.into_bytes(),
                };
                let view_input = match kv.get("viewinput") {
                    Some(h) => hex::decode(h.trim_start_matches("0x")).map_err(|e| format!("viewinput: {}", e))?,
                    None => vec![],
                };
                TransformKindConfig::EmbedViewInCoinbase {
                    upstream: get("upstream")?,
                    view: get("view")?,
                    magic,
                    view_input,
                }
            }
            path => TransformKindConfig::Wasm {
                path: PathBuf::from(path),
                sha256: kv.get("sha256").map(|s| s.to_lowercase()),
                upstreams: kv.get("deps").map(|v| split_list(v)).unwrap_or_default(),
            },
        };
        out.push(TransformConfig { name, kind, fuel });
    }
    Ok(out)
}

fn parse_layer_str(s: &str, default: IndexerLayer) -> IndexerLayer {
    match s.to_lowercase().as_str() {
        "tertiary" => IndexerLayer::Tertiary,
        "secondary" => IndexerLayer::Secondary,
        _ => default,
    }
}

/// Load an `indexer.toml` manifest.
fn load_manifest(path: &Path) -> Result<IndexerManifest, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read manifest: {}", e))?;
    toml::from_str(&content).map_err(|e| format!("parse manifest: {}", e))
}

/// Write an `indexer.toml` manifest.
pub fn write_manifest(path: &Path, manifest: &IndexerManifest) -> Result<(), String> {
    let content =
        toml::to_string_pretty(manifest).map_err(|e| format!("serialize manifest: {}", e))?;
    std::fs::write(path, content).map_err(|e| format!("write manifest: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest(label: &str) -> IndexerManifest {
        IndexerManifest {
            label: label.to_string(),
            sha256: "abc123".to_string(),
            source_url: "".to_string(),
            installed_at: "".to_string(),
            smt: false,
            start_height: 0,
            layer: "secondary".to_string(),
            depends_on: vec![],
            transform: None,
        }
    }

    #[test]
    fn test_parse_direct_wasm_path() {
        let args = vec!["test:/path/to/module.wasm"];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "test");
        assert_eq!(configs[0].wasm_path, PathBuf::from("/path/to/module.wasm"));
        assert!(!configs[0].smt_enabled);
        assert_eq!(configs[0].start_height, 0);
        assert_eq!(configs[0].layer, IndexerLayer::Secondary);
        assert!(configs[0].depends_on.is_empty());
    }

    #[test]
    fn test_parse_multiple_indexers() {
        let args = vec![
            "alkanes:/opt/alkanes.wasm",
            "brc20:/opt/brc20.wasm",
        ];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].label, "alkanes");
        assert_eq!(configs[1].label, "brc20");
    }

    #[test]
    fn test_parse_empty_args() {
        let args: Vec<&str> = vec![];
        let configs = parse_load_indexer_args(&args);
        assert!(configs.is_empty());
    }

    #[test]
    fn test_parse_invalid_format_no_colon() {
        let args = vec!["nocolon"];
        let configs = parse_load_indexer_args(&args);
        assert!(configs.is_empty());
    }

    #[test]
    fn test_parse_directory_without_manifest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("program.wasm"), b"fake wasm").unwrap();

        let arg = format!("test:{}", dir.path().display());
        let args = vec![arg.as_str()];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "test");
        assert_eq!(configs[0].wasm_path, dir.path().join("program.wasm"));
    }

    #[test]
    fn test_parse_directory_with_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = make_manifest("custom_label");
        manifest.smt = true;
        manifest.start_height = 100;
        manifest.layer = "tertiary".to_string();
        manifest.depends_on = vec!["alkanes".to_string()];
        write_manifest(&dir.path().join("indexer.toml"), &manifest).unwrap();
        std::fs::write(dir.path().join("program.wasm"), b"fake wasm").unwrap();

        let arg = format!("ignored:{}", dir.path().display());
        let args = vec![arg.as_str()];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "custom_label");
        assert!(configs[0].smt_enabled);
        assert_eq!(configs[0].start_height, 100);
        assert_eq!(configs[0].layer, IndexerLayer::Tertiary);
        assert_eq!(configs[0].depends_on, vec!["alkanes"]);
    }

    #[test]
    fn test_parse_tertiary_with_deps() {
        let args = vec!["overlay:/path/to/overlay.wasm:alkanes,brc20"];
        let configs = parse_load_tertiary_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "overlay");
        assert_eq!(configs[0].layer, IndexerLayer::Tertiary);
        assert_eq!(configs[0].depends_on, vec!["alkanes", "brc20"]);
    }

    #[test]
    fn test_parse_tertiary_single_dep() {
        let args = vec!["derived:/path/to/derived.wasm:base"];
        let configs = parse_load_tertiary_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].depends_on, vec!["base"]);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = make_manifest("test");
        manifest.sha256 = "deadbeef".to_string();
        manifest.source_url = "https://example.com/test.wasm".to_string();
        manifest.installed_at = "2025-01-01".to_string();
        manifest.start_height = 50;
        manifest.depends_on = vec!["foo".to_string(), "bar".to_string()];

        let path = dir.path().join("indexer.toml");
        write_manifest(&path, &manifest).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: IndexerManifest = toml::from_str(&content).unwrap();
        assert_eq!(loaded.label, "test");
        assert_eq!(loaded.sha256, "deadbeef");
        assert_eq!(loaded.start_height, 50);
        assert_eq!(loaded.depends_on, vec!["foo", "bar"]);
    }

    #[test]
    fn test_manifest_defaults() {
        // Minimal TOML — new fields should default correctly.
        let toml_str = r#"
            label = "minimal"
            sha256 = "abc"
        "#;
        let loaded: IndexerManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(loaded.label, "minimal");
        assert_eq!(loaded.start_height, 0);
        assert_eq!(loaded.layer, "secondary");
        assert!(loaded.depends_on.is_empty());
        assert!(!loaded.smt);
    }

    #[test]
    fn test_parse_direct_path_start_height_and_edges() {
        let configs = parse_load_indexer_args(&[
            "a:/x/a.wasm:100",
            "t:/x/t.wasm:deps=a,b:start=5",
            "e:/x/e.wasm:transform=alkanes/traceblock/ASP0",
            "old:/x/old.wasm:a,b",
        ]);
        assert_eq!(configs[0].start_height, 100);
        assert_eq!(configs[0].layer, IndexerLayer::Secondary);
        assert_eq!(configs[1].depends_on, vec!["a", "b"]);
        assert_eq!(configs[1].start_height, 5);
        assert_eq!(configs[1].layer, IndexerLayer::Tertiary);
        assert_eq!(configs[2].input.as_deref(), Some("alkanes/traceblock/ASP0"));
        assert!(configs[2].depends_on.is_empty());
        assert_eq!(configs[3].depends_on, vec!["a", "b"]);
    }

    #[test]
    fn test_parse_transforms() {
        let t = parse_load_transform_args(&[
            "traces:builtin:embed-view-in-coinbase:upstream=alkanes:view=traceblock:magic=ASP0",
            "mine:/x/t.wasm:sha256=AB:deps=alkanes,esplora:fuel=7",
        ])
        .unwrap();
        assert_eq!(t[0], TransformConfig::from_shorthand("alkanes/traceblock/ASP0").map(|mut c| {
            c.name = "traces".into();
            c
        }).unwrap());
        assert_eq!(t[1].upstreams(), vec!["alkanes", "esplora"]);
        assert_eq!(t[1].fuel, Some(7));
        match &t[1].kind {
            TransformKindConfig::Wasm { sha256, .. } => assert_eq!(sha256.as_deref(), Some("ab")),
            _ => panic!(),
        }
        assert!(TransformConfig::from_shorthand("a/b").is_none());
    }
}
