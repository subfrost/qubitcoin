//! Metashrew-format store helpers and copy-on-write read layers.
//!
//! Every persistent DAG node (standard indexers run by `MetashrewRuntime`,
//! fork-runner indexers, user programs) keeps its KV in one RocksDB using the
//! metashrew append-only layout (`key/length`, `key/<n>` = `height:hex`). The
//! helpers here read a key **as of a height**, commit a block's flushed pairs,
//! and roll a store back, all through metashrew's own code so the format stays
//! byte-identical with rockshrew.
//!
//! [`LayeredReader`] is the read path of fork mode: a stack of immutable
//! in-memory [`Layer`]s (simulation overlays, newest first) over a store read
//! at a fixed height. It never writes.

use metashrew_runtime::smt::{BatchedSMTHelper, SMTHelper};
use metashrew_runtime::TIP_HEIGHT_KEY;
use rockshrew_runtime::RocksDBRuntimeAdapter;
use std::collections::HashMap;
use std::sync::Arc;

/// Value of `key` as of `height` (the latest update at or below it).
pub fn read_at_height(db: &Arc<rocksdb::DB>, key: &[u8], height: u32) -> Result<Option<Vec<u8>>, String> {
    let helper = SMTHelper::new(RocksDBRuntimeAdapter::new(db.clone()));
    helper
        .get_at_height(key, height)
        .map_err(|e| format!("store read: {}", e))
}

/// Stored tip height (metashrew `TIP_HEIGHT_KEY`), if any block was committed.
pub fn stored_tip(db: &rocksdb::DB) -> Option<u32> {
    match db.get(TIP_HEIGHT_KEY.as_bytes()) {
        Ok(Some(v)) if v.len() >= 4 => Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]])),
        _ => None,
    }
}

/// Commit one block's flushed pairs at `height` (one atomic write; also
/// advances the stored tip), exactly as metashrew's `__flush` does.
pub fn commit_block(db: &Arc<rocksdb::DB>, height: u32, pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), String> {
    let mut helper = BatchedSMTHelper::new(RocksDBRuntimeAdapter::new(db.clone()));
    helper
        .calculate_and_store_state_root_batched(height, pairs, &[])
        .map(|_| ())
        .map_err(|e| format!("store commit at {}: {}", height, e))
}

/// Roll a store back so that it reflects height `to` (updates above it are
/// removed). Uses metashrew's manifest rollback, falling back to the full
/// scan, then rewrites the stored tip.
pub fn rollback(db: &Arc<rocksdb::DB>, to: u32, from: u32) -> Result<(), String> {
    use metashrew_runtime::rollback::{rollback_smt_data, rollback_with_manifests};
    if to >= from {
        return Ok(());
    }
    let mut adapter = rockshrew_runtime::storage_adapter::RocksDBStorageAdapter::new(db.clone());
    let fast = rollback_with_manifests(&mut adapter, to, from).map_err(|e| format!("rollback: {}", e))?;
    if !fast {
        rollback_smt_data(&mut adapter, to, from).map_err(|e| format!("rollback: {}", e))?;
    }
    db.put(TIP_HEIGHT_KEY.as_bytes(), to.to_le_bytes())
        .map_err(|e| format!("rollback tip: {}", e))
}

/// Approximate on-disk size of a store (live SST data + memtables).
pub fn approx_size(db: &rocksdb::DB) -> u64 {
    let p = |name: &str| db.property_int_value(name).ok().flatten().unwrap_or(0);
    p("rocksdb.estimate-live-data-size") + p("rocksdb.cur-size-all-mem-tables")
}

/// Every raw key/value in a store (tests: prove a store is untouched).
pub fn dump(db: &rocksdb::DB) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.iterator(rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

/// One immutable layer of simulated writes for one node.
#[derive(Debug, Default)]
pub struct Layer {
    pub kv: HashMap<Vec<u8>, Vec<u8>>,
    /// Sum of key + value bytes, for the overlay memory budget.
    pub bytes: usize,
}

impl Layer {
    pub fn from_pairs(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let mut kv = HashMap::with_capacity(pairs.len());
        let mut bytes = 0;
        for (k, v) in pairs {
            let kl = k.len();
            bytes += kl + v.len();
            if let Some(old) = kv.insert(k, v) {
                // Later write of the same key wins; count the key once.
                bytes -= kl + old.len();
            }
        }
        Layer { kv, bytes }
    }
}

/// Read path for fork mode: layers (newest first), then an optional store
/// read at `base_height`. `db = None` means an empty base (a node that only
/// exists in simulation).
#[derive(Clone)]
pub struct LayeredReader {
    pub layers: Vec<Arc<Layer>>,
    pub db: Option<Arc<rocksdb::DB>>,
    pub base_height: u32,
}

impl LayeredReader {
    pub fn at_height(db: Arc<rocksdb::DB>, height: u32) -> Self {
        LayeredReader { layers: Vec::new(), db: Some(db), base_height: height }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        for l in &self.layers {
            if let Some(v) = l.kv.get(key) {
                return Ok(Some(v.clone()));
            }
        }
        match &self.db {
            Some(db) => read_at_height(db, key, self.base_height),
            None => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl qubitcoin_indexer_fork::ForkUpstream for LayeredReader {
    async fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.get(key)
    }
    async fn tip_height(&self) -> Result<u32, String> {
        Ok(self.base_height)
    }
}

/// Fork-mode storage over `reader`, projected at `height`.
pub fn fork_storage(reader: LayeredReader, height: u32) -> qubitcoin_indexer_fork::MemStorage {
    qubitcoin_indexer_fork::MemStorage::new(Arc::new(reader), height)
}
