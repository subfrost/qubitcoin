//! Browser-compatible WASM indexer runtime for Qubitcoin.
//!
//! Uses the browser's native `WebAssembly` API (via `js-sys`) to run
//! metashrew-compatible indexer modules. Storage is backed by an in-memory
//! `HashMap`, matching the approach used by `metashrew-test`.

pub mod runtime;
pub mod storage;

pub use runtime::WebIndexerRuntime;
pub use storage::WebIndexerStorage;
