//! In-memory key-value storage for web indexer instances.
//!
//! Mirrors the append-only model of the native `IndexerStorage` but
//! uses a `HashMap<Vec<u8>, Vec<u8>>` instead of RocksDB.

use qubitcoin_indexer_core::state;
use qubitcoin_indexer_core::traits::{IndexerStorage, IndexerStorageReader, IndexerStorageWriter};
use std::cell::RefCell;
use std::collections::BTreeMap as HashMap;

/// In-memory storage backend for a single web indexer.
///
/// Uses `RefCell` for interior mutability with runtime borrow checking.
/// This catches aliased mutable borrows that could corrupt the HashMap.
pub struct WebIndexerStorage {
    kv: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    insert_count: RefCell<usize>,
}

impl WebIndexerStorage {
    /// Create a new empty storage.
    pub fn new() -> Self {
        WebIndexerStorage {
            kv: RefCell::new(HashMap::new()),
            insert_count: RefCell::new(0),
        }
    }

    pub fn total_inserts(&self) -> usize {
        *self.insert_count.borrow()
    }

    /// Shared borrow of the inner map.
    pub fn map(&self) -> std::cell::Ref<'_, HashMap<Vec<u8>, Vec<u8>>> {
        self.kv.borrow()
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
        let map = self.kv.borrow();
        for (key, value) in map.iter() {
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

    /// Export all key-value pairs as a flat binary blob.
    /// Format: u32 entry_count, then for each: u32 key_len, key_bytes, u32 value_len, value_bytes
    pub fn export_bytes(&self) -> Vec<u8> {
        let map = self.kv.borrow();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (k, v) in map.iter() {
            buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        buf
    }

    /// Import key-value pairs from a flat binary blob, replacing all existing data.
    pub fn import_bytes(&self, data: &[u8]) -> Result<usize, String> {
        let mut map = self.kv.borrow_mut();
        map.clear();
        *self.insert_count.borrow_mut() = 0;

        if data.len() < 4 { return Ok(0); }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let mut pos = 4;

        for _ in 0..count {
            if pos + 4 > data.len() { return Err("truncated key length".into()); }
            let key_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + key_len > data.len() { return Err("truncated key data".into()); }
            let key = data[pos..pos+key_len].to_vec();
            pos += key_len;

            if pos + 4 > data.len() { return Err("truncated value length".into()); }
            let val_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + val_len > data.len() { return Err("truncated value data".into()); }
            let value = data[pos..pos+val_len].to_vec();
            pos += val_len;

            map.insert(key, value);
        }

        *self.insert_count.borrow_mut() = count;
        Ok(count)
    }
}

impl Default for WebIndexerStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexerStorageReader for WebIndexerStorage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.borrow().get(key).cloned()
    }

    fn get_latest(&self, key: &[u8]) -> Option<Vec<u8>> {
        let len_key = state::length_key(key);
        let len_result = self.get_u32(&len_key);

        // If normal lookup fails for a rune proto key, try brute-force search
        if len_result.is_none() && key.starts_with(b"/runes/proto/") && key.len() > 60 {
            // Brute force: search ALL keys for the length_key
            let map = self.kv.borrow();
            let found = map.get(&len_key);
            if found.is_some() {
                panic!("get_latest BUG: brute-force found the key but get() didn't! len_key_len={}", len_key.len());
            }
            // Also check if any key in the map is a prefix-match
            let matches: Vec<_> = map.keys()
                .filter(|k| k.starts_with(key) && k.ends_with(&[0xff, 0xff, 0xff, 0xff]))
                .take(3)
                .collect();
            if !matches.is_empty() {
                panic!(
                    "get_latest BUG: found {} prefix-matching sentinel keys but exact match failed! key_len={} match_len={}",
                    matches.len(), len_key.len(), matches[0].len()
                );
            }
        }

        let len = len_result?;
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
        self.kv.borrow_mut().insert(key.to_vec(), value.to_vec());
        *self.insert_count.borrow_mut() += 1;
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

        // Verify the length key is readable after put
        let verify = self.get_u32(&len_key);
        if verify != Some(current_len + 1) {
            panic!(
                "append: length key not readable after put! expected={} got={:?} key_len={} len_key_len={}",
                current_len + 1, verify, key.len(), len_key.len()
            );
        }

        Ok(())
    }

    fn set_tip_height(&self, height: u32) -> Result<(), String> {
        self.put(state::HEIGHT_KEY, &height.to_le_bytes())
    }

    fn delete_batch(&self, keys: &[Vec<u8>]) -> Result<(), String> {
        let mut map = self.kv.borrow_mut();
        for k in keys {
            map.remove(k);
        }
        Ok(())
    }
}

impl IndexerStorage for WebIndexerStorage {
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
    fn test_protorune_balance_sheet_pattern() {
        let storage = WebIndexerStorage::new();

        let outpoint = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x00\x00\x00\x00";
        let base_key = b"/runes/byoutpoint/";

        let mut full_key = Vec::new();
        full_key.extend_from_slice(base_key);
        full_key.extend_from_slice(outpoint);

        let value = b"some_balance_data";
        storage.append(&full_key, value, 100).unwrap();

        let result = storage.get_latest(&full_key);
        assert_eq!(result, Some(value.to_vec()));

        let mut length_key = full_key.clone();
        length_key.extend_from_slice(b"/length");
        storage.append(&length_key, &1u32.to_le_bytes(), 100).unwrap();
        assert_eq!(storage.get_latest(&length_key), Some(1u32.to_le_bytes().to_vec()));

        let mut index_key = full_key.clone();
        index_key.extend_from_slice(b"/0");
        storage.append(&index_key, b"entry_0_data", 100).unwrap();
        assert_eq!(storage.get_latest(&index_key), Some(b"entry_0_data".to_vec()));
    }

    #[test]
    fn test_multiple_block_append_get_latest() {
        let storage = WebIndexerStorage::new();
        let key = b"/test/key";

        storage.append(key, b"first", 0).unwrap();
        assert_eq!(storage.get_latest(key), Some(b"first".to_vec()));

        storage.append(key, b"second", 1).unwrap();
        assert_eq!(storage.get_latest(key), Some(b"second".to_vec()));
        assert_eq!(storage.get_length(key), 2);
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
