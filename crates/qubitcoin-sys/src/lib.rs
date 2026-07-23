//! Native embedding library for Qubitcoin.
//!
//! This crate provides `NativeNode`, the native counterpart to
//! `qubitcoin-web-sys`'s `QubitcoinDevnet`. While the web-sys crate targets
//! `wasm32` with in-memory storage and `js-sys` bindings, this crate uses
//! RocksDB storage, real file I/O, and the full wasmtime indexer runtime.
//!
//! # Modes
//!
//! - **Regtest (in-memory)**: wraps [`TestChain`] for instant devnet testing,
//!   identical semantics to `QubitcoinDevnet` but callable from native Rust,
//!   C FFI, or Node.js (via napi-rs in the future).
//!
//! - **Production (RocksDB)**: wraps `ChainstateManager` with RocksDB-backed
//!   UTXO storage and the wasmtime secondary indexer runtime. (Stubbed for now.)

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qubitcoin_common::coins::CoinsView;
use qubitcoin_common::keys::Key;
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::transaction::{OutPoint, TransactionRef};
use qubitcoin_indexer::config::{IndexerConfig, IndexerLayer};
use qubitcoin_indexer::{IndexerManager, IndexerMode};
use qubitcoin_node::test_framework::TestChain;
use qubitcoin_primitives::{Amount, BlockHash};
use qubitcoin_script::Script;
use qubitcoin_serialize::{deserialize, serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`NativeNode`] operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("deserialization error: {0}")]
    Deserialize(String),

    #[error("insufficient funds or UTXO not found")]
    InsufficientFunds,

    #[error("mining error: {0}")]
    Mining(String),

    #[error("block processing error: {0}")]
    BlockProcessing(String),

    #[error("indexer error: {0}")]
    Indexer(String),

    #[error("not supported in this mode: {0}")]
    UnsupportedMode(String),

    #[error("count must be > 0")]
    InvalidCount,

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

// ---------------------------------------------------------------------------
// NativeNode
// ---------------------------------------------------------------------------

/// Inner representation — regtest (in-memory) or production (RocksDB).
enum Inner {
    /// Regtest mode: in-memory chain backed by `TestChain`.
    Regtest {
        chain: TestChain,
        indexer_manager: Option<IndexerManager>,
        datadir: Option<tempfile::TempDir>,
    },
    /// Production mode: ChainstateManager + RocksDB + indexer runtime.
    /// Stubbed for now.
    #[allow(dead_code)]
    Production {
        datadir: PathBuf,
    },
}

/// A native Qubitcoin node embedding.
///
/// This is the native equivalent of `QubitcoinDevnet` from `qubitcoin-web-sys`.
/// It supports two modes:
///
/// - **Regtest**: fully in-memory chain for testing (same semantics as the
///   WASM devnet). Created via [`NativeNode::new_regtest`].
/// - **Production**: RocksDB-backed chain with real storage. Created via
///   [`NativeNode::open`]. (Currently stubbed with `todo!()`.)
pub struct NativeNode {
    inner: Inner,
}

impl NativeNode {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new regtest (in-memory) node from a 32-byte secret key.
    ///
    /// The key is used as the coinbase recipient for all mined blocks.
    /// The chain starts at height 0 with a genesis block already mined.
    ///
    /// This is the native equivalent of `QubitcoinDevnet::new()`.
    pub fn new_regtest(secret_key: &[u8; 32]) -> Result<Self, Error> {
        let key = Key::new(secret_key, true)
            .map_err(|e| Error::InvalidSecretKey(format!("{e}")))?;
        let chain = TestChain::new_with_key(key);
        Ok(NativeNode {
            inner: Inner::Regtest {
                chain,
                indexer_manager: None,
                datadir: None,
            },
        })
    }

    /// Create a new regtest node with a random coinbase key.
    pub fn new_regtest_random() -> Self {
        let chain = TestChain::new();
        NativeNode {
            inner: Inner::Regtest {
                chain,
                indexer_manager: None,
                datadir: None,
            },
        }
    }

    /// Open a production node backed by RocksDB at `datadir`.
    ///
    /// **Not yet implemented** -- will use `ChainstateManager` + RocksDB.
    pub fn open(_datadir: &Path, _network: &str) -> Result<Self, Error> {
        todo!("production mode with ChainstateManager + RocksDB is not yet implemented")
    }

    // -----------------------------------------------------------------------
    // Chain state
    // -----------------------------------------------------------------------

    /// Current chain height (0 = genesis only).
    pub fn height(&self) -> i32 {
        match &self.inner {
            Inner::Regtest { chain, .. } => chain.height(),
            Inner::Production { .. } => {
                todo!("production mode height")
            }
        }
    }

    /// Tip block hash as a `BlockHash`.
    pub fn tip_hash(&self) -> BlockHash {
        match &self.inner {
            Inner::Regtest { chain, .. } => *chain.tip_hash(),
            Inner::Production { .. } => {
                todo!("production mode tip_hash")
            }
        }
    }

    /// Tip block hash as a hex string.
    pub fn tip_hash_hex(&self) -> String {
        self.tip_hash().to_hex()
    }

    /// Number of UTXOs in the cache (regtest only).
    pub fn utxo_count(&self) -> usize {
        match &self.inner {
            Inner::Regtest { chain, .. } => chain.coins().cache_size(),
            Inner::Production { .. } => {
                todo!("production mode utxo_count")
            }
        }
    }

    /// Coinbase public key (33-byte compressed), regtest only.
    pub fn coinbase_pubkey(&self) -> Vec<u8> {
        match &self.inner {
            Inner::Regtest { chain, .. } => chain.coinbase_pubkey().serialize(),
            Inner::Production { .. } => {
                todo!("production mode coinbase_pubkey")
            }
        }
    }

    /// Number of mature (spendable) coinbase outputs.
    pub fn mature_coinbase_count(&self) -> usize {
        match &self.inner {
            Inner::Regtest { chain, .. } => chain.mature_coinbase_count(),
            Inner::Production { .. } => {
                todo!("production mode mature_coinbase_count")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mining (regtest only)
    // -----------------------------------------------------------------------

    /// Mine a single empty block. Returns the block in Bitcoin wire format.
    pub fn mine_block(&mut self) -> Result<Vec<u8>, Error> {
        match &mut self.inner {
            Inner::Regtest {
                chain,
                indexer_manager,
                ..
            } => {
                let block = chain.mine_block(vec![]);
                let bytes = Self::serialize_block(&block)?;

                // Notify indexers if loaded.
                if let Some(mgr) = indexer_manager {
                    mgr.on_block_connected(chain.height() as u32, &bytes);
                }

                Ok(bytes)
            }
            Inner::Production { .. } => {
                Err(Error::UnsupportedMode("mine_block not available in production mode".into()))
            }
        }
    }

    /// Mine a block containing the given transactions (each in wire format).
    pub fn mine_block_with_txs(&mut self, raw_txs: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        match &mut self.inner {
            Inner::Regtest {
                chain,
                indexer_manager,
                ..
            } => {
                let mut txs: Vec<TransactionRef> = Vec::with_capacity(raw_txs.len());
                for raw in raw_txs {
                    let tx = deserialize(raw)
                        .map_err(|e| Error::Deserialize(format!("{e}")))?;
                    txs.push(Arc::new(tx));
                }
                let block = chain.mine_block(txs);
                let bytes = Self::serialize_block(&block)?;

                if let Some(mgr) = indexer_manager {
                    mgr.on_block_connected(chain.height() as u32, &bytes);
                }

                Ok(bytes)
            }
            Inner::Production { .. } => {
                Err(Error::UnsupportedMode("mine_block_with_txs not available in production mode".into()))
            }
        }
    }

    /// Mine `count` empty blocks. Returns the final block in wire format.
    pub fn mine_blocks(&mut self, count: u32) -> Result<Vec<u8>, Error> {
        if count == 0 {
            return Err(Error::InvalidCount);
        }
        let mut last_bytes = Vec::new();
        for _ in 0..count {
            last_bytes = self.mine_block()?;
        }
        Ok(last_bytes)
    }

    // -----------------------------------------------------------------------
    // Block queries
    // -----------------------------------------------------------------------

    /// Get a block by height in Bitcoin wire format, or `None` if not found.
    pub fn get_block(&self, height: i32) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let block = chain.block_at(height)?;
                Self::serialize_block(block).ok()
            }
            Inner::Production { .. } => {
                todo!("production mode get_block")
            }
        }
    }

    /// Get the block hash at a given height as hex, or `None`.
    pub fn get_block_hash(&self, height: i32) -> Option<String> {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let block = chain.block_at(height)?;
                Some(block.block_hash().to_hex())
            }
            Inner::Production { .. } => {
                todo!("production mode get_block_hash")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Transaction helpers
    // -----------------------------------------------------------------------

    /// Create a simple transaction spending a single UTXO.
    ///
    /// * `txid` -- 32-byte txid of the UTXO to spend.
    /// * `vout` -- output index within that transaction.
    /// * `value_sat` -- amount in satoshis to send to `dest_script`.
    /// * `dest_script` -- the locking script for the recipient output.
    ///
    /// Returns the serialized transaction. Change (minus 1000-sat fee) goes
    /// back to the coinbase address.
    pub fn create_transaction(
        &self,
        txid: &[u8; 32],
        vout: u32,
        value_sat: i64,
        dest_script: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let outpoint = OutPoint::new((*txid).into(), vout);
                let amount = Amount::from_sat(value_sat);
                let script = Script::from_bytes(dest_script.to_vec());

                let tx = chain
                    .create_transaction(&outpoint, amount, &script)
                    .ok_or(Error::InsufficientFunds)?;

                serialize(&*tx).map_err(|e| Error::Serialize(format!("{e}")))
            }
            Inner::Production { .. } => {
                todo!("production mode create_transaction")
            }
        }
    }

    /// Find the first spendable (mature, unspent) coinbase output.
    ///
    /// Returns `(txid, vout, value_in_satoshis)` or `None`.
    pub fn get_spendable_output(&self) -> Option<([u8; 32], u32, i64)> {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let (outpoint, value) = chain.get_spendable_output()?;
                let mut txid_bytes = [0u8; 32];
                txid_bytes.copy_from_slice(outpoint.hash.as_bytes());
                Some((txid_bytes, outpoint.n, value.to_sat()))
            }
            Inner::Production { .. } => {
                todo!("production mode get_spendable_output")
            }
        }
    }

    // -----------------------------------------------------------------------
    // UTXO queries
    // -----------------------------------------------------------------------

    /// Check whether a UTXO exists.
    pub fn has_utxo(&self, txid: &[u8; 32], vout: u32) -> bool {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let outpoint = OutPoint::new((*txid).into(), vout);
                chain.coins().have_coin(&outpoint)
            }
            Inner::Production { .. } => {
                todo!("production mode has_utxo")
            }
        }
    }

    /// Get a UTXO's value in satoshis, or `None` if it doesn't exist.
    pub fn get_utxo_value(&self, txid: &[u8; 32], vout: u32) -> Option<i64> {
        match &self.inner {
            Inner::Regtest { chain, .. } => {
                let outpoint = OutPoint::new((*txid).into(), vout);
                let coin = chain.coins().get_coin(&outpoint)?;
                Some(coin.tx_out.value.to_sat())
            }
            Inner::Production { .. } => {
                todo!("production mode get_utxo_value")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Key / address helpers (static)
    // -----------------------------------------------------------------------

    /// Build a P2PKH script from a 20-byte pubkey hash.
    pub fn build_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let script = qubitcoin_script::build_p2pkh(pubkey_hash);
        script.as_bytes().to_vec()
    }

    /// Derive the compressed public key (33 bytes) from a 32-byte secret key.
    pub fn pubkey_from_secret(secret_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let key = Key::new(secret_key, true)
            .map_err(|e| Error::InvalidSecretKey(format!("{e}")))?;
        Ok(key.get_pubkey().serialize())
    }

    /// Compute Hash160 (RIPEMD160(SHA256(data))).
    pub fn hash160(data: &[u8]) -> Vec<u8> {
        qubitcoin_crypto::hash::hash160(data).to_vec()
    }

    // -----------------------------------------------------------------------
    // Block processing (production mode)
    // -----------------------------------------------------------------------

    /// Process an externally-received block (production mode only).
    ///
    /// Returns `true` if the block extended the best chain.
    pub fn process_block(&mut self, _data: &[u8]) -> Result<bool, Error> {
        match &mut self.inner {
            Inner::Regtest { .. } => {
                Err(Error::UnsupportedMode(
                    "process_block is only available in production mode; use mine_block for regtest".into(),
                ))
            }
            Inner::Production { .. } => {
                todo!("production mode process_block with ChainstateManager")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Indexer management
    // -----------------------------------------------------------------------

    /// Load a WASM secondary indexer from a file path.
    ///
    /// The indexer will be fed blocks as they are mined (regtest) or
    /// processed (production).
    pub fn load_indexer(&mut self, label: &str, wasm_path: &Path) -> Result<(), Error> {
        match &mut self.inner {
            Inner::Regtest {
                indexer_manager,
                datadir,
                chain,
            } => {
                // Ensure we have a temp directory for indexer storage.
                let dir = datadir.get_or_insert_with(|| {
                    tempfile::tempdir().expect("failed to create temp dir for indexer storage")
                });

                let config = IndexerConfig {
                    label: label.to_string(),
                    wasm_path: wasm_path.to_path_buf(),
                    smt_enabled: false,
                    start_height: 0,
                    layer: IndexerLayer::Secondary,
                    depends_on: Vec::new(),
                };

                let mgr = IndexerManager::new(
                    vec![config],
                    &dir.path().to_path_buf(),
                    IndexerMode::Synchronous,
                )
                .map_err(|e| Error::Indexer(e))?;

                // Replay existing blocks to bring the indexer up to date.
                let chain_height = chain.height();
                if chain_height >= 0 {
                    mgr.catch_up(chain_height as u32, |h| {
                        let block = chain.block_at(h as i32)?;
                        serialize(block).ok()
                    });
                }

                *indexer_manager = Some(mgr);
                Ok(())
            }
            Inner::Production { .. } => {
                todo!("production mode load_indexer")
            }
        }
    }

    /// Get the current tip height for a loaded indexer, or `None`.
    pub fn indexer_height(&self, label: &str) -> Option<u32> {
        match &self.inner {
            Inner::Regtest {
                indexer_manager, ..
            } => indexer_manager.as_ref()?.indexer_height(label),
            Inner::Production { .. } => {
                todo!("production mode indexer_height")
            }
        }
    }

    /// Call a named view function on a loaded indexer.
    ///
    /// Returns the raw result bytes.
    pub fn call_indexer_view(
        &self,
        label: &str,
        fn_name: &str,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match &self.inner {
            Inner::Regtest {
                indexer_manager, ..
            } => {
                let mgr = indexer_manager
                    .as_ref()
                    .ok_or_else(|| Error::Indexer("no indexers loaded".into()))?;
                mgr.call_view(label, fn_name, input.to_vec())
                    .map_err(|e| Error::Indexer(e))
            }
            Inner::Production { .. } => {
                todo!("production mode call_indexer_view")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn serialize_block(block: &Block) -> Result<Vec<u8>, Error> {
        serialize(block).map_err(|e| Error::Serialize(format!("{e}")))
    }
}

// ---------------------------------------------------------------------------
// Public re-exports for convenience
// ---------------------------------------------------------------------------

/// Re-export of the library version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 1; // minimal valid secret key
        key
    }

    #[test]
    fn test_new_regtest() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        assert_eq!(node.height(), 0);
        assert_ne!(node.tip_hash(), BlockHash::ZERO);
    }

    #[test]
    fn test_new_regtest_random() {
        let node = NativeNode::new_regtest_random();
        assert_eq!(node.height(), 0);
    }

    #[test]
    fn test_mine_block() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let block_bytes = node.mine_block().unwrap();
        assert_eq!(node.height(), 1);
        assert!(!block_bytes.is_empty());
    }

    #[test]
    fn test_mine_blocks() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let last_block = node.mine_blocks(10).unwrap();
        assert_eq!(node.height(), 10);
        assert!(!last_block.is_empty());
    }

    #[test]
    fn test_mine_blocks_zero() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let result = node.mine_blocks(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_block() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let genesis = node.get_block(0);
        assert!(genesis.is_some());
        assert!(node.get_block(1).is_none());
        assert!(node.get_block(-1).is_none());
    }

    #[test]
    fn test_get_block_hash() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let hash = node.get_block_hash(0);
        assert!(hash.is_some());
        assert!(!hash.unwrap().is_empty());
        assert!(node.get_block_hash(999).is_none());
    }

    #[test]
    fn test_tip_hash_hex() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let hex = node.tip_hash_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_utxo_count() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        // Genesis has one coinbase output.
        assert!(node.utxo_count() > 0);
    }

    #[test]
    fn test_coinbase_pubkey() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let pubkey = node.coinbase_pubkey();
        assert_eq!(pubkey.len(), 33); // compressed pubkey
    }

    #[test]
    fn test_mature_coinbase_and_spend() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();

        // No mature coinbases at genesis.
        assert_eq!(node.mature_coinbase_count(), 0);
        assert!(node.get_spendable_output().is_none());

        // Mine 100 blocks to mature the genesis coinbase.
        node.mine_blocks(100).unwrap();
        assert_eq!(node.mature_coinbase_count(), 1);

        let (txid, vout, value_sat) = node.get_spendable_output().unwrap();
        assert!(value_sat > 0);

        // Verify UTXO exists.
        assert!(node.has_utxo(&txid, vout));
        assert_eq!(node.get_utxo_value(&txid, vout), Some(value_sat));

        // Create a transaction.
        let dest_script = vec![0x51]; // OP_1
        let send_amount = 1_000_000i64; // 0.01 BTC
        let tx_bytes = node
            .create_transaction(&txid, vout, send_amount, &dest_script)
            .unwrap();
        assert!(!tx_bytes.is_empty());

        // Mine it.
        node.mine_block_with_txs(&[tx_bytes]).unwrap();

        // Original UTXO should be spent.
        assert!(!node.has_utxo(&txid, vout));
    }

    #[test]
    fn test_create_transaction_insufficient_funds() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        node.mine_blocks(100).unwrap();

        let (txid, vout, _) = node.get_spendable_output().unwrap();
        let result = node.create_transaction(&txid, vout, 100_000_000_000, &[0x51]);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_utxo_nonexistent() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        assert!(!node.has_utxo(&[0u8; 32], 0));
    }

    #[test]
    fn test_get_utxo_value_nonexistent() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        assert_eq!(node.get_utxo_value(&[0u8; 32], 0), None);
    }

    #[test]
    fn test_static_helpers() {
        let secret = test_secret_key();
        let pubkey = NativeNode::pubkey_from_secret(&secret).unwrap();
        assert_eq!(pubkey.len(), 33);

        let hash = NativeNode::hash160(&pubkey);
        assert_eq!(hash.len(), 20);

        let script = NativeNode::build_p2pkh_script(&hash.try_into().unwrap());
        assert!(!script.is_empty());
    }

    #[test]
    fn test_process_block_regtest_error() {
        let mut node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        let result = node.process_block(b"fake");
        assert!(result.is_err());
    }

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
    }

    #[test]
    fn test_indexer_no_manager() {
        let node = NativeNode::new_regtest(&test_secret_key()).unwrap();
        assert_eq!(node.indexer_height("test"), None);
        assert!(node.call_indexer_view("test", "fn", &[]).is_err());
    }
}
