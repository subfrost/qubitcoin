//! qubitcoin-storage: Database abstraction for Qubitcoin.
//!
//! Maps to: src/dbwrapper.h
//!
//! Provides:
//! - `Database`, `DbBatch`, `DbIterator` traits
//! - `MemoryDb` (BTreeMap-backed, for testing)
//! - `RocksDatabase` (production, behind `rocksdb-backend` feature)
//! - `DbWrapper<D>` with typed serialization + XOR obfuscation

pub mod block_file;
pub mod memory;
#[cfg(feature = "rocksdb-backend")]
pub mod rocks;
pub mod traits;
pub mod wrapper;

pub use block_file::{
    BlockFileManager, BlockFilePos, MAINNET_MAGIC, MAX_BLOCKFILE_SIZE, STORAGE_HEADER_BYTES,
};
pub use memory::{MemoryBatch, MemoryDb, MemoryIterator};
#[cfg(feature = "rocksdb-backend")]
pub use rocks::RocksDatabase;
pub use traits::{Database, DbBatch, DbIterator};
pub use wrapper::DbWrapper;
