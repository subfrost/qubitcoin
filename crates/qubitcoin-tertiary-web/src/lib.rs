//! Browser-compatible tertiary indexer runtime for Qubitcoin.
//!
//! Extends the secondary indexer runtime with `__secondary_get` host functions
//! that allow tertiary WASM modules to read from named secondary indexer stores
//! (e.g., "alkanes", "esplora") during block processing and view calls.

pub mod runtime;

pub use runtime::TertiaryRuntime;
