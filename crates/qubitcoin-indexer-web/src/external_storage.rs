//! External storage backend that delegates to JS host via wasm_bindgen.
//!
//! Moves indexer state OUT of WASM linear memory into the host environment.
//! The JS side provides the actual storage implementation (Map, IndexedDB, etc.).

use qubitcoin_indexer_core::state;
use qubitcoin_indexer_core::traits::{IndexerStorage, IndexerStorageReader, IndexerStorageWriter};
use wasm_bindgen::prelude::*;

// ─── JS imports ──────────────────────────────────────────────────────────────
// These are provided by the host environment before WASM instantiation.
// The JS adapter must set `globalThis.__qubitcoin_storage` with these methods.

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageGet")]
    fn js_storage_get(store_id: u32, key: &[u8]) -> JsValue;

    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storagePut")]
    fn js_storage_put(store_id: u32, key: &[u8], value: &[u8]);

    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageDeleteBatch")]
    fn js_storage_delete_batch(store_id: u32, keys: &[u8]);

    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageCreate")]
    fn js_storage_create() -> u32;

    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageExport")]
    fn js_storage_export(store_id: u32) -> Vec<u8>;

    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageImport")]
    fn js_storage_import(store_id: u32, data: &[u8]) -> u32;

    /// Get all logical keys that have length sentinels (for rollback/stateRoot).
    /// Returns packed binary: [count_u32, (key_len_u32, key_bytes, length_u32)*]
    #[wasm_bindgen(js_namespace = ["globalThis", "__qubitcoin_storage"], js_name = "storageKeysWithLengths")]
    fn js_storage_keys_with_lengths(store_id: u32) -> Vec<u8>;
}

// ─── ExternalStorage ─────────────────────────────────────────────────────────

/// Storage backend that delegates all operations to the JS host environment.
///
/// Data lives on the JS heap (Node.js Map, IndexedDB, etc.) — NOT in WASM
/// linear memory. This prevents OOM when indexing many blocks/contracts.
pub struct ExternalStorage {
    store_id: u32,
}

impl ExternalStorage {
    /// Create a new external store. The JS adapter allocates the backing store
    /// and returns an opaque ID.
    pub fn new() -> Self {
        ExternalStorage {
            store_id: js_storage_create(),
        }
    }

    /// Construct from a known store ID (e.g. after import).
    pub fn from_id(store_id: u32) -> Self {
        ExternalStorage { store_id }
    }

    pub fn store_id(&self) -> u32 {
        self.store_id
    }

    fn get_u32(&self, key: &[u8]) -> Option<u32> {
        let data = self.get(key)?;
        if data.len() >= 4 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }

    /// Get all logical keys and their append-list lengths.
    pub fn keys_with_lengths(&self) -> Vec<(Vec<u8>, u32)> {
        let packed = js_storage_keys_with_lengths(self.store_id);
        let mut result = Vec::new();
        if packed.len() < 4 {
            return result;
        }
        let count = u32::from_le_bytes(packed[0..4].try_into().unwrap()) as usize;
        let mut pos = 4;
        for _ in 0..count {
            if pos + 4 > packed.len() {
                break;
            }
            let key_len = u32::from_le_bytes(packed[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + key_len + 4 > packed.len() {
                break;
            }
            let key = packed[pos..pos + key_len].to_vec();
            pos += key_len;
            let length = u32::from_le_bytes(packed[pos..pos + 4].try_into().unwrap());
            pos += 4;
            result.push((key, length));
        }
        result
    }

    /// Export all data as a flat binary blob (same format as WebIndexerStorage).
    pub fn export_bytes(&self) -> Vec<u8> {
        js_storage_export(self.store_id)
    }

    /// Import data from a flat binary blob, replacing all existing data.
    pub fn import_bytes(&self, data: &[u8]) -> Result<usize, String> {
        let count = js_storage_import(self.store_id, data) as usize;
        Ok(count)
    }
}

impl Default for ExternalStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Trait impls ─────────────────────────────────────────────────────────────

impl IndexerStorageReader for ExternalStorage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let result = js_storage_get(self.store_id, key);
        if result.is_null() || result.is_undefined() {
            None
        } else {
            // wasm_bindgen returns a Uint8Array → Vec<u8>
            let arr = js_sys::Uint8Array::new(&result);
            Some(arr.to_vec())
        }
    }

    fn get_latest(&self, key: &[u8]) -> Option<Vec<u8>> {
        let len_key = state::length_key(key);
        let len = self.get_u32(&len_key)?;
        if len == 0 {
            return None;
        }
        let idx_key = state::index_key(key, len - 1);
        self.get(&idx_key)
    }

    fn get_length(&self, key: &[u8]) -> u32 {
        let len_key = state::length_key(key);
        self.get_u32(&len_key).unwrap_or(0)
    }

    fn tip_height(&self) -> u32 {
        self.get_u32(state::HEIGHT_KEY).unwrap_or(0)
    }
}

impl IndexerStorageWriter for ExternalStorage {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        js_storage_put(self.store_id, key, value);
        Ok(())
    }

    fn append(&self, key: &[u8], value: &[u8], height: u32) -> Result<(), String> {
        let len_key = state::length_key(key);
        let current_len = self.get_u32(&len_key).unwrap_or(0);

        let idx_key = state::index_key(key, current_len);
        let h_key = state::entry_height_key(key, current_len);

        self.put(&len_key, &(current_len + 1).to_le_bytes())?;
        self.put(&idx_key, value)?;
        self.put(&h_key, &height.to_le_bytes())?;
        Ok(())
    }

    fn set_tip_height(&self, height: u32) -> Result<(), String> {
        self.put(state::HEIGHT_KEY, &height.to_le_bytes())
    }

    fn delete_batch(&self, keys: &[Vec<u8>]) -> Result<(), String> {
        // Pack keys as: [count_u32, (key_len_u32, key_bytes)*]
        let mut packed = Vec::new();
        packed.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for k in keys {
            packed.extend_from_slice(&(k.len() as u32).to_le_bytes());
            packed.extend_from_slice(k);
        }
        js_storage_delete_batch(self.store_id, &packed);
        Ok(())
    }
}

impl IndexerStorage for ExternalStorage {
    fn export_bytes(&self) -> Vec<u8> {
        self.export_bytes()
    }

    fn import_bytes(&self, data: &[u8]) -> Result<usize, String> {
        self.import_bytes(data)
    }

    fn keys_with_lengths(&self) -> Vec<(Vec<u8>, u32)> {
        self.keys_with_lengths()
    }
}
