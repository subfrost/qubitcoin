//! RocksDB database backend.
//! Maps to: src/dbwrapper.cpp (LevelDB -> RocksDB)

use crate::traits::{Database, DbBatch, DbIterator};
use std::path::Path;

/// Error type for RocksDB operations.
#[derive(Debug, thiserror::Error)]
pub enum RocksError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),
}

/// RocksDB-backed key-value database for production use.
pub struct RocksDatabase {
    db: rocksdb::DB,
}

impl RocksDatabase {
    /// Open a RocksDB database at the given path.
    pub fn open<P: AsRef<Path>>(path: P, cache_size_mb: usize) -> Result<Self, RocksError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(64);
        opts.set_write_buffer_size(cache_size_mb * 1024 * 1024);
        opts.set_compression_type(rocksdb::DBCompressionType::None);

        let db = rocksdb::DB::open(&opts, path)?;
        Ok(RocksDatabase { db })
    }

    /// Open with default options.
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self, RocksError> {
        Self::open(path, 4) // 4 MB default write buffer
    }
}

impl Database for RocksDatabase {
    type Batch = RocksBatch;
    type Iterator<'a> = RocksIterator<'a>;
    type Error = RocksError;

    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.db.get(key)?)
    }

    fn exists(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.db.get(key)?.is_some())
    }

    fn write_batch(&self, batch: Self::Batch, sync: bool) -> Result<(), Self::Error> {
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(sync);
        self.db.write_opt(batch.inner, &write_opts)?;
        Ok(())
    }

    fn new_batch(&self) -> Self::Batch {
        RocksBatch {
            inner: rocksdb::WriteBatch::default(),
        }
    }

    fn new_iterator(&self) -> Self::Iterator<'_> {
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        RocksIterator {
            inner: iter,
            current: None,
        }
    }

    fn compact(&self) -> Result<(), Self::Error> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }

    fn estimated_size(&self) -> Result<u64, Self::Error> {
        let prop = self
            .db
            .property_value("rocksdb.estimate-live-data-size")
            .unwrap_or(None)
            .unwrap_or_default();
        Ok(prop.parse::<u64>().unwrap_or(0))
    }
}

/// Write batch for RocksDB.
pub struct RocksBatch {
    inner: rocksdb::WriteBatch,
}

impl DbBatch for RocksBatch {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.inner.put(key, value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.inner.delete(key);
    }

    fn clear(&mut self) {
        self.inner.clear();
    }
}

/// Iterator over RocksDB entries.
pub struct RocksIterator<'a> {
    inner: rocksdb::DBIterator<'a>,
    current: Option<(Box<[u8]>, Box<[u8]>)>,
}

impl<'a> DbIterator for RocksIterator<'a> {
    fn seek(&mut self, key: &[u8]) {
        self.inner.set_mode(rocksdb::IteratorMode::From(
            key,
            rocksdb::Direction::Forward,
        ));
        self.advance();
    }

    fn seek_to_first(&mut self) {
        self.inner.set_mode(rocksdb::IteratorMode::Start);
        self.advance();
    }

    fn valid(&self) -> bool {
        self.current.is_some()
    }

    fn next(&mut self) {
        self.advance();
    }

    fn key(&self) -> &[u8] {
        &self.current.as_ref().unwrap().0
    }

    fn value(&self) -> &[u8] {
        &self.current.as_ref().unwrap().1
    }
}

impl<'a> RocksIterator<'a> {
    fn advance(&mut self) {
        self.current = self.inner.next().map(|result| {
            let (k, v) = result.unwrap();
            (k, v)
        });
    }
}
