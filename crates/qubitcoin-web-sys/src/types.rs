//! Serialization helpers for crossing the WASM boundary.
//!
//! All complex types (blocks, transactions, etc.) cross the JS boundary as
//! raw Bitcoin-serialized `Uint8Array` blobs.  This keeps the binding layer
//! thin and avoids duplicating every struct field in JS.

use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::transaction::Transaction;
use qubitcoin_serialize::{deserialize, serialize};
use wasm_bindgen::prelude::*;

/// Serialize a block to its Bitcoin wire-format bytes.
pub fn block_to_bytes(block: &Block) -> Result<Vec<u8>, JsValue> {
    serialize(block).map_err(|e| JsValue::from_str(&format!("serialize block: {e}")))
}

/// Deserialize a block from Bitcoin wire-format bytes.
pub fn block_from_bytes(data: &[u8]) -> Result<Block, JsValue> {
    deserialize(data).map_err(|e| JsValue::from_str(&format!("deserialize block: {e}")))
}

/// Serialize a transaction to its Bitcoin wire-format bytes.
pub fn tx_to_bytes(tx: &Transaction) -> Result<Vec<u8>, JsValue> {
    serialize(tx).map_err(|e| JsValue::from_str(&format!("serialize tx: {e}")))
}

/// Deserialize a transaction from Bitcoin wire-format bytes.
pub fn tx_from_bytes(data: &[u8]) -> Result<Transaction, JsValue> {
    deserialize(data).map_err(|e| JsValue::from_str(&format!("deserialize tx: {e}")))
}
