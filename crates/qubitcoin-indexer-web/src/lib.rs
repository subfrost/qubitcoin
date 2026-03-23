//! Browser-compatible WASM indexer runtime for Qubitcoin.
//!
//! Uses the browser's native `WebAssembly` API (via `js-sys`) to run
//! metashrew-compatible indexer modules. Storage can be either:
//! - In-memory `BTreeMap` (WebIndexerStorage) — simple, all in WASM memory
//! - External JS-hosted storage (ExternalStorage) — data on JS heap, avoids OOM

pub mod external_storage;
pub mod runtime;
pub mod storage;

pub use external_storage::ExternalStorage;
pub use runtime::WebIndexerRuntime;
pub use storage::WebIndexerStorage;
