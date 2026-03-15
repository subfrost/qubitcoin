//! RocksDB storage for a single indexer instance.
//!
//! Implements the append-only key-value model where each logical key
//! accumulates values over time, enabling rollback by height.

use crate::state;
use std::path::Path;

/// Storage backend for a single indexer, wrapping a dedicated RocksDB instance.
pub struct IndexerStorage {
    db: rocksdb::DB,
}

impl IndexerStorage {
    /// Open (or create) a RocksDB database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(16 * 1024 * 1024);
        opts.set_max_write_buffer_number(2);
        opts.set_level_compaction_dynamic_level_bytes(true);

        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_block_cache(&rocksdb::Cache::new_lru_cache(32 * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&block_opts);

        opts.increase_parallelism(2);
        opts.set_max_background_jobs(2);

        let db = rocksdb::DB::open(&opts, path).map_err(|e| format!("indexer db open: {}", e))?;
        Ok(IndexerStorage { db })
    }

    /// Raw get.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }

    /// Raw put (single key).
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.db
            .put(key, value)
            .map_err(|e| format!("indexer db put: {}", e))
    }

    /// Write a batch of key-value pairs atomically.
    pub fn write_batch(&self, pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), String> {
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in pairs {
            batch.put(k, v);
        }
        self.db
            .write(batch)
            .map_err(|e| format!("indexer db batch: {}", e))
    }

    /// Append a value to the append-only list for `key` at `height`.
    ///
    /// Updates length, stores value at the next index, and records the height.
    pub fn append(&self, key: &[u8], value: &[u8], height: u32) -> Result<(), String> {
        let len_key = state::length_key(key);
        let current_len = self.get_u32(&len_key).unwrap_or(0);

        let idx_key = state::index_key(key, current_len);
        let h_key = state::entry_height_key(key, current_len);

        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&len_key, &(current_len + 1).to_le_bytes());
        batch.put(&idx_key, value);
        batch.put(&h_key, &height.to_le_bytes());
        self.db
            .write(batch)
            .map_err(|e| format!("indexer db append: {}", e))
    }

    /// Get the latest value for a logical key (last entry in the append list).
    pub fn get_latest(&self, key: &[u8]) -> Option<Vec<u8>> {
        let len_key = state::length_key(key);
        let len = self.get_u32(&len_key)?;
        if len == 0 {
            return None;
        }
        let idx_key = state::index_key(key, len - 1);
        self.get(&idx_key)
    }

    /// Get the value at a specific index.
    pub fn get_at_index(&self, key: &[u8], index: u32) -> Option<Vec<u8>> {
        let idx_key = state::index_key(key, index);
        self.get(&idx_key)
    }

    /// Get the length of the append list for a key.
    pub fn get_length(&self, key: &[u8]) -> u32 {
        let len_key = state::length_key(key);
        self.get_u32(&len_key).unwrap_or(0)
    }

    /// Read a u32 from a key.
    pub fn get_u32(&self, key: &[u8]) -> Option<u32> {
        let data = self.get(key)?;
        if data.len() >= 4 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }

    /// Get the stored indexer tip height.
    pub fn tip_height(&self) -> u32 {
        self.get_u32(state::HEIGHT_KEY).unwrap_or(0)
    }

    /// Set the indexer tip height.
    pub fn set_tip_height(&self, height: u32) -> Result<(), String> {
        self.put(state::HEIGHT_KEY, &height.to_le_bytes())
    }

    /// Delete a range of keys using a WriteBatch.
    pub fn delete_batch(&self, keys: &[Vec<u8>]) -> Result<(), String> {
        let mut batch = rocksdb::WriteBatch::default();
        for k in keys {
            batch.delete(k);
        }
        self.db
            .write(batch)
            .map_err(|e| format!("indexer db delete batch: {}", e))
    }

    /// Create a raw RocksDB iterator.
    pub fn raw_iterator(&self) -> rocksdb::DBIterator<'_> {
        self.db.iterator(rocksdb::IteratorMode::Start)
    }

    /// Prefix iterator for scanning keys.
    pub fn prefix_iterator(&self, prefix: &[u8]) -> rocksdb::DBIterator<'_> {
        self.db.prefix_iterator(prefix)
    }

    /// Flush WAL to ensure durability.
    pub fn flush(&self) -> Result<(), String> {
        self.db
            .flush()
            .map_err(|e| format!("indexer db flush: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_storage() -> (IndexerStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = IndexerStorage::open(dir.path()).unwrap();
        (storage, dir)
    }

    #[test]
    fn test_put_get() {
        let (storage, _dir) = temp_storage();
        storage.put(b"key1", b"value1").unwrap();
        assert_eq!(storage.get(b"key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_get_missing() {
        let (storage, _dir) = temp_storage();
        assert_eq!(storage.get(b"nonexistent"), None);
    }

    #[test]
    fn test_write_batch() {
        let (storage, _dir) = temp_storage();
        let pairs = vec![
            (b"k1".to_vec(), b"v1".to_vec()),
            (b"k2".to_vec(), b"v2".to_vec()),
            (b"k3".to_vec(), b"v3".to_vec()),
        ];
        storage.write_batch(&pairs).unwrap();
        assert_eq!(storage.get(b"k1"), Some(b"v1".to_vec()));
        assert_eq!(storage.get(b"k2"), Some(b"v2".to_vec()));
        assert_eq!(storage.get(b"k3"), Some(b"v3".to_vec()));
    }

    #[test]
    fn test_append_and_get_latest() {
        let (storage, _dir) = temp_storage();
        storage.append(b"log", b"first", 100).unwrap();
        assert_eq!(storage.get_latest(b"log"), Some(b"first".to_vec()));
        assert_eq!(storage.get_length(b"log"), 1);

        storage.append(b"log", b"second", 101).unwrap();
        assert_eq!(storage.get_latest(b"log"), Some(b"second".to_vec()));
        assert_eq!(storage.get_length(b"log"), 2);

        // Can still read first entry by index.
        assert_eq!(storage.get_at_index(b"log", 0), Some(b"first".to_vec()));
        assert_eq!(storage.get_at_index(b"log", 1), Some(b"second".to_vec()));
    }

    #[test]
    fn test_get_latest_empty() {
        let (storage, _dir) = temp_storage();
        assert_eq!(storage.get_latest(b"empty"), None);
        assert_eq!(storage.get_length(b"empty"), 0);
    }

    #[test]
    fn test_tip_height() {
        let (storage, _dir) = temp_storage();
        assert_eq!(storage.tip_height(), 0);
        storage.set_tip_height(500).unwrap();
        assert_eq!(storage.tip_height(), 500);
        storage.set_tip_height(1000).unwrap();
        assert_eq!(storage.tip_height(), 1000);
    }

    #[test]
    fn test_get_u32() {
        let (storage, _dir) = temp_storage();
        storage.put(b"num", &42u32.to_le_bytes()).unwrap();
        assert_eq!(storage.get_u32(b"num"), Some(42));
    }

    #[test]
    fn test_get_u32_missing() {
        let (storage, _dir) = temp_storage();
        assert_eq!(storage.get_u32(b"missing"), None);
    }

    #[test]
    fn test_delete_batch() {
        let (storage, _dir) = temp_storage();
        storage.put(b"a", b"1").unwrap();
        storage.put(b"b", b"2").unwrap();
        storage.put(b"c", b"3").unwrap();

        storage
            .delete_batch(&[b"a".to_vec(), b"c".to_vec()])
            .unwrap();

        assert_eq!(storage.get(b"a"), None);
        assert_eq!(storage.get(b"b"), Some(b"2".to_vec()));
        assert_eq!(storage.get(b"c"), None);
    }

    #[test]
    fn test_multiple_keys_append() {
        let (storage, _dir) = temp_storage();
        storage.append(b"key_a", b"val_a1", 1).unwrap();
        storage.append(b"key_b", b"val_b1", 1).unwrap();
        storage.append(b"key_a", b"val_a2", 2).unwrap();

        assert_eq!(storage.get_length(b"key_a"), 2);
        assert_eq!(storage.get_length(b"key_b"), 1);
        assert_eq!(storage.get_latest(b"key_a"), Some(b"val_a2".to_vec()));
        assert_eq!(storage.get_latest(b"key_b"), Some(b"val_b1".to_vec()));
    }
}
