//! Configuration parsing for indexer modules.
//!
//! Supports:
//! - `-loadindexer=label:path` command-line arguments
//! - `indexer.toml` manifest files

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration for a single indexer module.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// Human-readable label (e.g. "alkanes", "brc20").
    pub label: String,
    /// Path to the `.wasm` binary.
    pub wasm_path: PathBuf,
    /// Whether to compute SMT state roots.
    pub smt_enabled: bool,
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
}

/// Parse `-loadindexer=label:path` arguments.
///
/// Returns a list of indexer configs. Each argument has the format
/// `label:path` where `path` points to a `.wasm` file, or `label:dir`
/// where `dir` contains an `indexer.toml` manifest.
pub fn parse_load_indexer_args(args: &[&str]) -> Vec<IndexerConfig> {
    let mut configs = Vec::new();

    for arg in args {
        if let Some((label, path_str)) = arg.split_once(':') {
            let path = PathBuf::from(path_str);

            if path.is_dir() {
                // Look for indexer.toml manifest.
                let manifest_path = path.join("indexer.toml");
                if manifest_path.exists() {
                    match load_manifest(&manifest_path) {
                        Ok(manifest) => {
                            let wasm_path = path.join("program.wasm");
                            configs.push(IndexerConfig {
                                label: manifest.label,
                                wasm_path,
                                smt_enabled: manifest.smt,
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
                    // Directory without manifest — look for program.wasm.
                    let wasm_path = path.join("program.wasm");
                    configs.push(IndexerConfig {
                        label: label.to_string(),
                        wasm_path,
                        smt_enabled: false,
                    });
                }
            } else {
                // Direct path to .wasm file.
                configs.push(IndexerConfig {
                    label: label.to_string(),
                    wasm_path: path,
                    smt_enabled: false,
                });
            }
        }
    }

    configs
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

    #[test]
    fn test_parse_direct_wasm_path() {
        let args = vec!["test:/path/to/module.wasm"];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "test");
        assert_eq!(configs[0].wasm_path, PathBuf::from("/path/to/module.wasm"));
        assert!(!configs[0].smt_enabled);
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
        // No colon means split_once returns None, so it's skipped.
        assert!(configs.is_empty());
    }

    #[test]
    fn test_parse_directory_without_manifest() {
        let dir = tempfile::tempdir().unwrap();
        // Create a program.wasm file.
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
        let manifest = IndexerManifest {
            label: "custom_label".to_string(),
            sha256: "abc123".to_string(),
            source_url: "".to_string(),
            installed_at: "".to_string(),
            smt: true,
        };
        write_manifest(&dir.path().join("indexer.toml"), &manifest).unwrap();
        std::fs::write(dir.path().join("program.wasm"), b"fake wasm").unwrap();

        let arg = format!("ignored:{}", dir.path().display());
        let args = vec![arg.as_str()];
        let configs = parse_load_indexer_args(&args);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].label, "custom_label");
        assert!(configs[0].smt_enabled);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = IndexerManifest {
            label: "test".to_string(),
            sha256: "deadbeef".to_string(),
            source_url: "https://example.com/test.wasm".to_string(),
            installed_at: "2025-01-01".to_string(),
            smt: false,
        };
        let path = dir.path().join("indexer.toml");
        write_manifest(&path, &manifest).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: IndexerManifest = toml::from_str(&content).unwrap();
        assert_eq!(loaded.label, "test");
        assert_eq!(loaded.sha256, "deadbeef");
        assert_eq!(loaded.source_url, "https://example.com/test.wasm");
        assert!(!loaded.smt);
    }
}
