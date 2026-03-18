//! WASM bindings for the secondary indexer runtime.
//!
//! Allows JS to load metashrew-compatible WASM indexer modules, feed them
//! blocks, and call view functions — all running in the browser.

use qubitcoin_indexer_core::rollback::rollback_to_height;
use qubitcoin_indexer_core::smt::compute_state_root;
use qubitcoin_indexer_core::traits::{IndexerStorageReader, IndexerStorageWriter};
use qubitcoin_indexer_web::storage::WebIndexerStorage;
use qubitcoin_indexer_web::runtime::WebIndexerRuntime;
use wasm_bindgen::prelude::*;

/// A secondary indexer instance running in the browser.
///
/// Wraps a compiled WASM indexer module and its in-memory storage.
#[wasm_bindgen]
pub struct SecondaryIndexer {
    runtime: WebIndexerRuntime,
    storage: WebIndexerStorage,
}

#[wasm_bindgen]
impl SecondaryIndexer {
    /// Load and compile a WASM indexer module from bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(wasm_bytes: &[u8]) -> Result<SecondaryIndexer, JsValue> {
        let runtime = WebIndexerRuntime::new(wasm_bytes)?;
        let storage = WebIndexerStorage::new();
        Ok(SecondaryIndexer { runtime, storage })
    }

    /// Feed a block to the indexer for processing.
    ///
    /// `block_data` is the raw block bytes (Bitcoin wire format).
    /// The indexer's `_start()` is invoked and resulting state changes are
    /// flushed to the in-memory store.
    #[wasm_bindgen(js_name = "processBlock")]
    pub fn process_block(&mut self, block_data: &[u8]) -> Result<(), JsValue> {
        let h = self.storage.tip_height();
        let pairs = self.runtime.run_block(h, block_data.to_vec(), &self.storage)?;

        // Apply key-value pairs to storage.
        for (key, value) in &pairs {
            self.storage.put(key, value)
                .map_err(|e| JsValue::from_str(&e))?;
        }

        // Bump tip height.
        self.storage.set_tip_height(h + 1)
            .map_err(|e| JsValue::from_str(&e))?;
        Ok(())
    }

    /// Call a named view function on the indexer.
    ///
    /// `height` is the block height context for the view call.
    /// Returns the raw result bytes.
    #[wasm_bindgen(js_name = "callView")]
    pub fn call_view(&self, fn_name: &str, height: u32, input: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.runtime.call_view(fn_name, height, input.to_vec(), &self.storage)
    }

    /// Current indexer tip height.
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> u32 {
        self.storage.tip_height()
    }

    /// Compute the sparse Merkle tree state root at the current height.
    #[wasm_bindgen(js_name = "stateRoot")]
    pub fn state_root(&self) -> Vec<u8> {
        let pairs = self.storage.keys_with_lengths();
        let mut kv: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (key, _len) in &pairs {
            if let Some(val) = self.storage.get_latest(key) {
                kv.push((key.clone(), val));
            }
        }
        compute_state_root(&kv).to_vec()
    }

    /// Roll back the indexer state to a previous height.
    ///
    /// Deletes all entries recorded above `target_height`.
    #[wasm_bindgen(js_name = "rollbackTo")]
    pub fn rollback_to(&mut self, target_height: u32) -> Result<u32, JsValue> {
        let keys = self.storage.keys_with_lengths();
        let deleted = rollback_to_height(&self.storage, target_height, &keys)
            .map_err(|e| JsValue::from_str(&e))?;
        Ok(deleted)
    }
}
