//! Metashrew-sync trait implementations for qubitcoin.
//!
//! These adapters connect the metashrew sync framework to qubitcoin's
//! chainstate, allowing the indexer to receive blocks directly from
//! the consensus engine rather than over RPC.

use async_trait::async_trait;
use metashrew_sync::{
    BitcoinNodeAdapter, BlockInfo, ChainTip, StorageAdapter, StorageStats, SyncError, SyncResult,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// BitcoinNodeAdapter — receives blocks from qubitcoind's connect_block path
// ---------------------------------------------------------------------------

/// Adapts qubitcoin's chainstate into metashrew-sync's BitcoinNodeAdapter.
///
/// Instead of querying blocks over RPC, blocks are pushed via
/// `push_block()` from `on_block_connected()`. The sync loop reads
/// them from the channel.
pub struct QubitcoinNodeAdapter {
    /// Current chain tip height (updated by qubitcoind).
    tip_height: Arc<AtomicU32>,
    /// Block channel: (height, block_data, block_hash).
    block_tx: tokio::sync::mpsc::Sender<(u32, Vec<u8>, Vec<u8>)>,
    block_rx: Arc<RwLock<tokio::sync::mpsc::Receiver<(u32, Vec<u8>, Vec<u8>)>>>,
    /// Block hash lookup (populated by push_block).
    block_hashes: Arc<RwLock<std::collections::HashMap<u32, Vec<u8>>>>,
}

impl QubitcoinNodeAdapter {
    pub fn new(channel_size: usize) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(channel_size);
        Self {
            tip_height: Arc::new(AtomicU32::new(0)),
            block_tx: tx,
            block_rx: Arc::new(RwLock::new(rx)),
            block_hashes: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Called by qubitcoind when a new block is connected.
    pub fn push_block(&self, height: u32, block_data: Vec<u8>, block_hash: Vec<u8>) {
        self.tip_height.store(height, Ordering::SeqCst);
        {
            // Store hash for lookup
            let mut hashes = self.block_hashes.blocking_write();
            hashes.insert(height, block_hash.clone());
            // Keep only recent hashes to bound memory
            if height > 100 {
                hashes.remove(&(height - 100));
            }
        }
        // Non-blocking send; if channel is full, log and drop (backpressure).
        if let Err(e) = self.block_tx.try_send((height, block_data, block_hash)) {
            tracing::warn!(height, "block channel full, applying backpressure: {}", e);
            // Block until space is available
            let tx = self.block_tx.clone();
            let _ = tx.blocking_send(e.into_inner());
        }
    }

    /// Get the sender for use by the qubitcoind main loop.
    pub fn sender(&self) -> tokio::sync::mpsc::Sender<(u32, Vec<u8>, Vec<u8>)> {
        self.block_tx.clone()
    }
}

#[async_trait]
impl BitcoinNodeAdapter for QubitcoinNodeAdapter {
    async fn get_tip_height(&self) -> SyncResult<u32> {
        Ok(self.tip_height.load(Ordering::SeqCst))
    }

    async fn get_block_hash(&self, height: u32) -> SyncResult<Vec<u8>> {
        let hashes = self.block_hashes.read().await;
        hashes
            .get(&height)
            .cloned()
            .ok_or_else(|| SyncError::BitcoinNode(format!("block hash not found for height {}", height)))
    }

    async fn get_block_data(&self, height: u32) -> SyncResult<Vec<u8>> {
        // In push mode, blocks arrive via the channel. This method is called
        // by MetashrewSync when it needs to fetch a specific block (e.g., during
        // reorg detection). For now, return an error — the sync loop uses
        // get_next_block_data() which reads from our channel.
        Err(SyncError::BitcoinNode(format!(
            "direct block fetch not supported for height {} (push mode)",
            height
        )))
    }

    async fn get_block_info(&self, height: u32) -> SyncResult<BlockInfo> {
        let hash = self.get_block_hash(height).await?;
        // Block data not available via random access in push mode
        Err(SyncError::BitcoinNode(format!(
            "random access block info not supported (push mode), height {}",
            height
        )))
    }

    async fn get_chain_tip(&self) -> SyncResult<ChainTip> {
        let height = self.tip_height.load(Ordering::SeqCst);
        let hash = self
            .get_block_hash(height)
            .await
            .unwrap_or_else(|_| vec![0u8; 32]);
        Ok(ChainTip { height, hash })
    }

    async fn is_connected(&self) -> bool {
        true // Always connected — we ARE the node
    }
}

// ---------------------------------------------------------------------------
// StorageAdapter — wraps RocksDB for metashrew-sync's storage needs
// ---------------------------------------------------------------------------

/// RocksDB-backed storage adapter for metashrew-sync.
///
/// Uses the same RocksDB instance as the MetashrewRuntime. Stores
/// block hashes and state roots in a simple key format compatible
/// with metashrew's conventions.
pub struct QubitcoinStorageAdapter {
    db: Arc<rocksdb::DB>,
}

impl QubitcoinStorageAdapter {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    fn height_key() -> Vec<u8> {
        metashrew_runtime::TIP_HEIGHT_KEY.as_bytes().to_vec()
    }

    fn block_hash_key(height: u32) -> Vec<u8> {
        format!("/__INTERNAL/height-to-hash/{}", height).into_bytes()
    }

    fn state_root_key(height: u32) -> Vec<u8> {
        format!("smt:root:{}", height).into_bytes()
    }
}

#[async_trait]
impl StorageAdapter for QubitcoinStorageAdapter {
    async fn get_indexed_height(&self) -> SyncResult<u32> {
        match self.db.get(Self::height_key()) {
            Ok(Some(v)) if v.len() >= 4 => {
                Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            }
            Ok(_) => Ok(0),
            Err(e) => Err(SyncError::Storage(format!("get height: {}", e))),
        }
    }

    async fn set_indexed_height(&mut self, height: u32) -> SyncResult<()> {
        self.db
            .put(Self::height_key(), height.to_le_bytes())
            .map_err(|e| SyncError::Storage(format!("set height: {}", e)))
    }

    async fn store_block_hash(&mut self, height: u32, hash: &[u8]) -> SyncResult<()> {
        self.db
            .put(Self::block_hash_key(height), hash)
            .map_err(|e| SyncError::Storage(format!("store hash: {}", e)))
    }

    async fn get_block_hash(&self, height: u32) -> SyncResult<Option<Vec<u8>>> {
        self.db
            .get(Self::block_hash_key(height))
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|e| SyncError::Storage(format!("get hash: {}", e)))
    }

    async fn store_state_root(&mut self, height: u32, root: &[u8]) -> SyncResult<()> {
        self.db
            .put(Self::state_root_key(height), root)
            .map_err(|e| SyncError::Storage(format!("store root: {}", e)))
    }

    async fn get_state_root(&self, height: u32) -> SyncResult<Option<Vec<u8>>> {
        self.db
            .get(Self::state_root_key(height))
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|e| SyncError::Storage(format!("get root: {}", e)))
    }

    async fn rollback_to_height(&mut self, _height: u32) -> SyncResult<()> {
        // TODO: Implement rollback using metashrew's manifest-based approach
        tracing::warn!("rollback_to_height not yet implemented");
        Ok(())
    }

    async fn is_available(&self) -> bool {
        self.db.get(b"__test_availability__").is_ok()
    }

    async fn get_stats(&self) -> SyncResult<StorageStats> {
        let height = self.get_indexed_height().await?;
        Ok(StorageStats {
            total_entries: 0,
            indexed_height: height,
            storage_size_bytes: None,
        })
    }

    async fn get_db_handle(&self) -> SyncResult<Arc<rocksdb::DB>> {
        Ok(self.db.clone())
    }
}
