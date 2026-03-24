//! SecondaryPointer — a KeyValuePointer backed by secondary indexer storage.
//!
//! Lets tertiary indexers read from secondary indexer KV stores using
//! the same KeyValuePointer API that secondary indexers use to write.
//!
//! ```rust,no_run
//! use qubitcoin_tertiary_support::SecondaryPointer;
//! use qubitcoin_support::KeyValuePointer;
//!
//! // Read pool balance the same way alkanes-rs writes it:
//! let ptr = SecondaryPointer::for_indexer("alkanes")
//!     .keyword("/alkanes/")
//!     .select(&token_id_bytes)
//!     .keyword("/balances/")
//!     .select(&pool_id_bytes);
//! let balance: u128 = ptr.get_value::<u128>();
//! ```

use std::sync::Arc;
use qubitcoin_support::{KeyValuePointer, ByteView};
use crate::secondary_get;

/// A read-only pointer into a named secondary indexer's storage.
///
/// Implements `KeyValuePointer` — `get()` reads via `__secondary_get`,
/// `set()` is a no-op (secondary storage is read-only from tertiary).
#[derive(Clone, Debug)]
pub struct SecondaryPointer {
    /// The secondary indexer name (e.g., "alkanes", "esplora").
    indexer: Arc<String>,
    /// The raw key bytes.
    key: Arc<Vec<u8>>,
}

impl SecondaryPointer {
    /// Create a root pointer for a named secondary indexer.
    ///
    /// Equivalent to `IndexPointer::from(b"")` but reads from
    /// the named secondary indexer instead of own storage.
    pub fn for_indexer(name: &str) -> Self {
        SecondaryPointer {
            indexer: Arc::new(name.to_string()),
            key: Arc::new(Vec::new()),
        }
    }
}

impl KeyValuePointer for SecondaryPointer {
    fn wrap(word: &Vec<u8>) -> Self {
        // Default indexer name — callers should use for_indexer() instead.
        SecondaryPointer {
            indexer: Arc::new(String::new()),
            key: Arc::new(word.clone()),
        }
    }

    fn unwrap(&self) -> Arc<Vec<u8>> {
        self.key.clone()
    }

    fn get(&self) -> Arc<Vec<u8>> {
        match secondary_get(&self.indexer, &self.key) {
            Some(v) => Arc::new(v),
            None => Arc::new(Vec::new()),
        }
    }

    fn set(&mut self, _v: Arc<Vec<u8>>) {
        // No-op: secondary storage is read-only from tertiary indexers.
    }

    fn inherits(&mut self, from: &Self) {
        // Inherit the indexer name from parent pointer.
        self.indexer = from.indexer.clone();
    }
}
