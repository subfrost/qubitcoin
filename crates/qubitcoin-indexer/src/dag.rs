//! The indexer DAG: node identities, upstream access, topological order.
//!
//! The DAG is rooted at the raw block. Every other node is an **indexer**
//! (stateful: KV + views, metashrew ABI) or a **transform** (a function of the
//! raw block plus its upstreams' state at that height, producing a derived
//! block that downstream indexers reprocess). Edges are:
//!
//! * `secondary` — the downstream reads the upstream's KV (`__secondary_get`)
//!   or views at the same height;
//! * `transform` — the downstream's input block is the transform's output.
//!
//! [`DagAccess`] is what a running node is handed to reach its upstreams. It
//! enforces the declared-upstream allowlist and delegates to a
//! [`DagBackend`], which decides where state comes from (persistent stores at
//! a height, or a simulation overlay).

use async_trait::async_trait;
use qubitcoin_indexer_fork::{HostContext, SecondaryReader, UpstreamViewCaller};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Where a node's upstream reads go.
#[async_trait]
pub trait DagBackend: Send + Sync {
    /// Raw KV read of `node` at the backend's height.
    fn kv_get(&self, node: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    /// Call `view_fn(input)` on `node` at the backend's height.
    async fn view(&self, node: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String>;
}

/// A node's handle on its upstreams: only `allowed` may be read.
#[derive(Clone)]
pub struct DagAccess {
    pub node: String,
    pub allowed: Vec<String>,
    pub backend: Arc<dyn DagBackend>,
}

impl DagAccess {
    fn check(&self, upstream: &str) -> Result<(), String> {
        if self.allowed.iter().any(|a| a == upstream) {
            Ok(())
        } else {
            Err(format!(
                "access denied: '{}' is not a declared upstream of '{}'",
                upstream, self.node
            ))
        }
    }

    /// Host context for the wasm runtime (both ABIs routed through `self`).
    pub fn host(self) -> HostContext {
        let a = Arc::new(self);
        HostContext {
            secondary: Some(a.clone() as Arc<dyn SecondaryReader>),
            views: Some(a as Arc<dyn UpstreamViewCaller>),
        }
    }

    pub fn kv_get(&self, upstream: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.check(upstream)?;
        self.backend.kv_get(upstream, key)
    }

    pub async fn view(&self, upstream: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        self.check(upstream)?;
        self.backend.view(upstream, view_fn, input).await
    }
}

impl SecondaryReader for DagAccess {
    fn secondary_get(&self, indexer: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.kv_get(indexer, key)
    }
}

#[async_trait]
impl UpstreamViewCaller for DagAccess {
    async fn upstream_view(&self, indexer: &str, view_fn: &str, input: Vec<u8>) -> Result<Vec<u8>, String> {
        self.view(indexer, view_fn, input).await
    }
}

/// Topologically order `nodes` (name → upstream names). Deterministic
/// (lexicographic among ready nodes). Errors on an unknown upstream or a cycle.
pub fn topo_order(nodes: &BTreeMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    let mut indeg: BTreeMap<&str, usize> = BTreeMap::new();
    let mut downstream: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (n, ups) in nodes {
        indeg.entry(n.as_str()).or_insert(0);
        for u in ups {
            if !nodes.contains_key(u) {
                return Err(format!("node '{}' depends on unknown node '{}'", n, u));
            }
            if u == n {
                return Err(format!("node '{}' depends on itself", n));
            }
            *indeg.entry(n.as_str()).or_insert(0) += 1;
            downstream.entry(u.as_str()).or_default().push(n.as_str());
        }
    }
    let mut ready: BTreeSet<&str> = indeg.iter().filter(|(_, d)| **d == 0).map(|(n, _)| *n).collect();
    let mut out = Vec::with_capacity(nodes.len());
    while let Some(n) = ready.iter().next().copied() {
        ready.remove(n);
        out.push(n.to_string());
        if let Some(ds) = downstream.get(n) {
            for d in ds {
                let e = indeg.get_mut(d).unwrap();
                *e -= 1;
                if *e == 0 {
                    ready.insert(d);
                }
            }
        }
    }
    if out.len() != nodes.len() {
        let stuck: Vec<&str> = indeg.iter().filter(|(_, d)| **d > 0).map(|(n, _)| *n).collect();
        return Err(format!("dependency cycle among {:?}", stuck));
    }
    Ok(out)
}

/// `nodes` plus every transitive upstream of them.
pub fn with_ancestors(graph: &BTreeMap<String, Vec<String>>, nodes: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<String> = nodes.to_vec();
    while let Some(n) = stack.pop() {
        if out.insert(n.clone()) {
            if let Some(ups) = graph.get(&n) {
                stack.extend(ups.iter().cloned());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(edges: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        edges
            .iter()
            .map(|(n, u)| (n.to_string(), u.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn orders_upstreams_first() {
        let o = topo_order(&g(&[
            ("essentials", &["traces"]),
            ("traces", &["alkanes"]),
            ("alkanes", &[]),
            ("tert", &["alkanes", "esplora"]),
            ("esplora", &[]),
        ]))
        .unwrap();
        let pos = |n: &str| o.iter().position(|x| x == n).unwrap();
        assert!(pos("alkanes") < pos("traces"));
        assert!(pos("traces") < pos("essentials"));
        assert!(pos("esplora") < pos("tert"));
    }

    #[test]
    fn rejects_cycles_and_unknowns() {
        assert!(topo_order(&g(&[("a", &["b"]), ("b", &["a"])])).unwrap_err().contains("cycle"));
        assert!(topo_order(&g(&[("a", &["zz"])])).unwrap_err().contains("unknown"));
    }

    #[test]
    fn ancestors_closure() {
        let gr = g(&[("c", &["b"]), ("b", &["a"]), ("a", &[]), ("x", &[])]);
        let s = with_ancestors(&gr, &["c".to_string()]);
        assert_eq!(s.into_iter().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }
}
