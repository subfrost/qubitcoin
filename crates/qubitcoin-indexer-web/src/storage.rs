//! In-memory key-value storage for web indexer instances.
//!
//! Mirrors the append-only model of the native `IndexerStorage` but
//! uses a `HashMap<Vec<u8>, Vec<u8>>` instead of RocksDB.

use qubitcoin_indexer_core::state;
use qubitcoin_indexer_core::traits::{IndexerStorageReader, IndexerStorageWriter};
use std::cell::UnsafeCell;
use std::collections::HashMap;

/// In-memory storage backend for a single web indexer.
///
/// Uses `UnsafeCell` for interior mutability — safe because WASM is
/// single-threaded and `IndexerStorageWriter` takes `&self`.
pub struct WebIndexerStorage {
    kv: UnsafeCell<HashMap<Vec<u8>, Vec<u8>>>,
}

impl WebIndexerStorage {
    /// Create a new empty storage.
    pub fn new() -> Self {
        WebIndexerStorage {
            kv: UnsafeCell::new(HashMap::new()),
        }
    }

    /// Shared borrow of the inner map.
    fn map(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        // SAFETY: single-threaded WASM — no concurrent access.
        unsafe { &*self.kv.get() }
    }

    /// Mutable borrow of the inner map.
    fn map_mut(&self) -> &mut HashMap<Vec<u8>, Vec<u8>> {
        // SAFETY: single-threaded WASM — no concurrent access.
        unsafe { &mut *self.kv.get() }
    }

    /// Get a raw u32 from a key.
    fn get_u32(&self, key: &[u8]) -> Option<u32> {
        let data = self.get(key)?;
        if data.len() >= 4 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }

    /// Get all logical keys and their lengths (for rollback).
    pub fn keys_with_lengths(&self) -> Vec<(Vec<u8>, u32)> {
        let sentinel = u32::MAX.to_le_bytes();
        let mut result = Vec::new();
        for (key, value) in self.map() {
            if key.len() >= 4 && key.ends_with(&sentinel) {
                if value.len() >= 4 {
                    let len = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                    let base_key = key[..key.len() - 4].to_vec();
                    result.push((base_key, len));
                }
            }
        }
        result
    }
}

impl Default for WebIndexerStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexerStorageReader for WebIndexerStorage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map().get(key).cloned()
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

impl IndexerStorageWriter for WebIndexerStorage {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.map_mut().insert(key.to_vec(), value.to_vec());
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
        let map = self.map_mut();
        for k in keys {
            map.remove(k);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_get() {
        let storage = WebIndexerStorage::new();
        storage.put(b"key1", b"value1").unwrap();
        assert_eq!(storage.get(b"key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_append_and_get_latest() {
        let storage = WebIndexerStorage::new();
        storage.append(b"log", b"first", 100).unwrap();
        assert_eq!(storage.get_latest(b"log"), Some(b"first".to_vec()));
        assert_eq!(storage.get_length(b"log"), 1);

        storage.append(b"log", b"second", 101).unwrap();
        assert_eq!(storage.get_latest(b"log"), Some(b"second".to_vec()));
        assert_eq!(storage.get_length(b"log"), 2);
    }

    #[test]
    fn test_tip_height() {
        let storage = WebIndexerStorage::new();
        assert_eq!(storage.tip_height(), 0);
        storage.set_tip_height(500).unwrap();
        assert_eq!(storage.tip_height(), 500);
    }

    #[test]
    fn test_keys_with_lengths() {
        let storage = WebIndexerStorage::new();
        storage.append(b"alpha", b"val1", 10).unwrap();
        storage.append(b"beta", b"val2", 20).unwrap();

        let kwl = storage.keys_with_lengths();
        assert_eq!(kwl.len(), 2);
    }
}
