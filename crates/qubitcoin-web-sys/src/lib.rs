//! WASM bindings for Qubitcoin.
//!
//! This crate provides `wasm-bindgen` exports that expose Qubitcoin's chain
//! validation, block processing, and secondary indexer runtime to JavaScript.
//! It targets both browser (`wasm32-unknown-unknown`) and Node.js via `wasm-pack`.

mod backends;
mod chain;
mod devnet_server;
mod indexer;
mod types;

use wasm_bindgen::prelude::*;

/// Initialize the WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    // Future: set up panic hook, logging, etc.
}

/// Returns the library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
