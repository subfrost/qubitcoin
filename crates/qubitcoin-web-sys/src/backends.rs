//! In-process backend implementations for the devnet.
//!
//! These implement the `alkanes-rpc-core` backend traits against the
//! in-memory [`TestChain`] and [`SecondaryIndexer`] state, so the full
//! RPC dispatch + protobuf codec runs entirely in WASM without network.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use alkanes_rpc_core::backend::*;
use alkanes_rpc_core::types::*;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Value, json};

use qubitcoin_consensus::transaction::TransactionRef;
use qubitcoin_indexer_web::runtime::WebIndexerRuntime;
use qubitcoin_indexer_web::storage::WebIndexerStorage;
use qubitcoin_indexer_core::traits::{IndexerStorageReader, IndexerStorageWriter};
use qubitcoin_node::test_framework::TestChain;
use qubitcoin_serialize::serialize;

use qubitcoin_primitives::Amount;

use crate::types;

/// Shared devnet state accessible by all backends via Rc<RefCell<...>>.
pub struct DevnetState {
    pub chain: TestChain,
    pub alkanes_runtime: WebIndexerRuntime,
    pub alkanes_storage: WebIndexerStorage,
    pub esplora_runtime: Option<WebIndexerRuntime>,
    pub esplora_storage: Option<WebIndexerStorage>,
}

impl DevnetState {
    /// Mine `count` empty blocks and auto-index each through all indexers.
    pub fn mine_and_index(&mut self, count: u32) -> Result<Vec<Vec<u8>>> {
        let mut block_bytes_vec = Vec::new();
        for _ in 0..count {
            let block = self.chain.mine_block(vec![]);
            let block_bytes = types::block_to_bytes(&block)
                .map_err(|e| anyhow::anyhow!("block serialize: {:?}", e))?;
            self.index_block(&block_bytes)?;
            block_bytes_vec.push(block_bytes);
        }
        Ok(block_bytes_vec)
    }

    /// Mine a block with transactions and auto-index.
    pub fn mine_with_txs_and_index(&mut self, txs: Vec<TransactionRef>) -> Result<Vec<u8>> {
        let block = self.chain.mine_block(txs);
        let block_bytes = types::block_to_bytes(&block)
            .map_err(|e| anyhow::anyhow!("block serialize: {:?}", e))?;
        self.index_block(&block_bytes)?;
        Ok(block_bytes)
    }

    /// Feed a block through all loaded indexers.
    fn index_block(&mut self, block_bytes: &[u8]) -> Result<()> {
        // Index through alkanes
        let pairs = self.alkanes_runtime.run_block(block_bytes.to_vec(), &self.alkanes_storage)
            .map_err(|e| anyhow::anyhow!("alkanes index: {:?}", e))?;
        for (key, value) in &pairs {
            self.alkanes_storage.put(key, value)
                .map_err(|e| anyhow::anyhow!("alkanes storage put: {}", e))?;
        }
        let h = self.alkanes_storage.tip_height();
        self.alkanes_storage.set_tip_height(h + 1)
            .map_err(|e| anyhow::anyhow!("alkanes set height: {}", e))?;

        // Index through esplora (if loaded)
        if let (Some(ref runtime), Some(ref mut storage)) =
            (&self.esplora_runtime, &mut self.esplora_storage)
        {
            let pairs = runtime.run_block(block_bytes.to_vec(), storage)
                .map_err(|e| anyhow::anyhow!("esplora index: {:?}", e))?;
            for (key, value) in &pairs {
                storage.put(key, value)
                    .map_err(|e| anyhow::anyhow!("esplora storage put: {}", e))?;
            }
            let h = storage.tip_height();
            storage.set_tip_height(h + 1)
                .map_err(|e| anyhow::anyhow!("esplora set height: {}", e))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DevnetBitcoinBackend
// ---------------------------------------------------------------------------

pub struct DevnetBitcoinBackend {
    pub state: Rc<RefCell<DevnetState>>,
}

#[async_trait(?Send)]
impl BitcoinBackend for DevnetBitcoinBackend {
    async fn call(&self, method: &str, params: Vec<Value>, id: Value) -> Result<JsonRpcResponse> {
        match method {
            "getblockcount" => {
                let state = self.state.borrow();
                Ok(JsonRpcResponse::success(json!(state.chain.height()), id))
            }
            "getbestblockhash" => {
                let state = self.state.borrow();
                Ok(JsonRpcResponse::success(
                    json!(state.chain.tip_hash().to_hex()),
                    id,
                ))
            }
            "getblockhash" => {
                let height = params.get(0)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                let state = self.state.borrow();
                match state.chain.block_at(height) {
                    Some(block) => Ok(JsonRpcResponse::success(
                        json!(block.block_hash().to_hex()),
                        id,
                    )),
                    None => Ok(JsonRpcResponse::error(
                        INTERNAL_ERROR,
                        format!("Block not found at height {}", height),
                        id,
                    )),
                }
            }
            "getblock" => {
                let hash_hex = params.get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let verbosity = params.get(1)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);
                let state = self.state.borrow();

                // Find block by hash (scan all heights)
                let mut found_block = None;
                for h in 0..=state.chain.height() {
                    if let Some(block) = state.chain.block_at(h) {
                        if block.block_hash().to_hex() == hash_hex {
                            found_block = Some(block.clone());
                            break;
                        }
                    }
                }

                match found_block {
                    Some(block) => {
                        if verbosity == 0 {
                            // Return raw hex
                            let buf = serialize(&block)
                                .map_err(|e| anyhow::anyhow!("serialize block: {}", e))?;
                            Ok(JsonRpcResponse::success(json!(hex::encode(&buf)), id))
                        } else {
                            // Return basic block info
                            Ok(JsonRpcResponse::success(json!({
                                "hash": block.block_hash().to_hex(),
                                "height": state.chain.height(), // approximate
                                "tx": block.vtx.iter().map(|tx| {
                                    tx.txid().to_hex()
                                }).collect::<Vec<_>>(),
                                "nTx": block.vtx.len(),
                            }), id))
                        }
                    }
                    None => Ok(JsonRpcResponse::error(
                        INTERNAL_ERROR,
                        format!("Block not found: {}", hash_hex),
                        id,
                    )),
                }
            }
            "generatetoaddress" => {
                let count = params.get(0)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as u32;
                // Address param is ignored — we always mine to the devnet key
                let mut state = self.state.borrow_mut();
                let block_bytes_vec = state.mine_and_index(count)?;
                // Return array of block hashes
                let hashes: Vec<Value> = block_bytes_vec.iter().map(|_bytes| {
                    // The chain already advanced, get recent hashes
                    json!("mined")
                }).collect();
                // Actually return the hashes properly
                drop(state);
                let state = self.state.borrow();
                let height = state.chain.height();
                let mut hashes = Vec::new();
                for h in (height - count as i32 + 1)..=height {
                    if let Some(block) = state.chain.block_at(h) {
                        hashes.push(json!(block.block_hash().to_hex()));
                    }
                }
                Ok(JsonRpcResponse::success(json!(hashes), id))
            }
            "sendrawtransaction" => {
                let hex_tx = params.get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tx_bytes = hex::decode(hex_tx)
                    .map_err(|e| anyhow::anyhow!("invalid tx hex: {}", e))?;
                let tx = types::tx_from_bytes(&tx_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid tx: {:?}", e))?;
                let txid = tx.txid().to_hex();
                // Mine a block containing this transaction
                let mut state = self.state.borrow_mut();
                state.mine_with_txs_and_index(vec![Arc::new(tx)])?;
                Ok(JsonRpcResponse::success(json!(txid), id))
            }
            "getrawtransaction" => {
                let txid_hex = params.get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let verbose = params.get(1)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let state = self.state.borrow();
                // Scan blocks for matching txid
                for block in (0..=state.chain.height()).filter_map(|h| state.chain.block_at(h)) {
                    for tx in &block.vtx {
                        if tx.txid().to_hex() == txid_hex {
                            if verbose == 0 {
                                // Return raw hex
                                if let Ok(bytes) = serialize(tx.as_ref()) {
                                    return Ok(JsonRpcResponse::success(json!(hex::encode(&bytes)), id));
                                }
                            } else {
                                // Return basic tx info (verbose)
                                if let Ok(bytes) = serialize(tx.as_ref()) {
                                    return Ok(JsonRpcResponse::success(json!({
                                        "hex": hex::encode(&bytes),
                                        "txid": txid_hex,
                                        "size": bytes.len(),
                                    }), id));
                                }
                            }
                        }
                    }
                }
                Ok(JsonRpcResponse::error(
                    INTERNAL_ERROR,
                    format!("Transaction not found: {}", txid_hex),
                    id,
                ))
            }
            _ => Ok(JsonRpcResponse::error(
                METHOD_NOT_FOUND,
                format!("Bitcoin method not supported in devnet: {}", method),
                id,
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// DevnetMetashrewBackend
// ---------------------------------------------------------------------------

pub struct DevnetMetashrewBackend {
    pub state: Rc<RefCell<DevnetState>>,
}

#[async_trait(?Send)]
impl MetashrewBackend for DevnetMetashrewBackend {
    async fn forward(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        // metashrew_view(method, hex_input, block_tag) or metashrew_height
        let method_parts: Vec<&str> = request.method.split('_').collect();
        let method_name = if method_parts.len() > 1 {
            method_parts[1..].join("_")
        } else {
            String::new()
        };

        match method_name.as_str() {
            "height" => {
                let state = self.state.borrow();
                let height = state.alkanes_storage.tip_height();
                Ok(JsonRpcResponse::success(
                    json!(height.to_string()),
                    request.id.clone(),
                ))
            }
            "view" => {
                // params: [method_name, hex_input, block_tag]
                let view_method = request.params.get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let hex_input = request.params.get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let input_hex = hex_input.strip_prefix("0x").unwrap_or(hex_input);
                let input_bytes = hex::decode(input_hex)
                    .map_err(|e| anyhow::anyhow!("invalid hex input: {}", e))?;

                let state = self.state.borrow();
                let result = state.alkanes_runtime.call_view(
                    view_method,
                    input_bytes,
                    &state.alkanes_storage,
                ).map_err(|e| anyhow::anyhow!("view call failed: {:?}", e))?;

                Ok(JsonRpcResponse::success(
                    json!(format!("0x{}", hex::encode(&result))),
                    request.id.clone(),
                ))
            }
            _ => Ok(JsonRpcResponse::error(
                METHOD_NOT_FOUND,
                format!("Metashrew method not supported: {}", method_name),
                request.id.clone(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// DevnetEsploraBackend
// ---------------------------------------------------------------------------

pub struct DevnetEsploraBackend {
    pub state: Rc<RefCell<DevnetState>>,
}

impl DevnetEsploraBackend {
    /// Scan the chain for unspent outputs matching the coinbase script.
    ///
    /// This is the devnet fallback when no esplora indexer is loaded.
    /// Since all mining rewards go to the devnet key, this covers the
    /// primary use case for integration tests.
    fn coinbase_utxos_as_esplora(&self, state: &DevnetState) -> Value {
        let script = state.chain.coinbase_script();
        let utxos = state.chain.utxos_for_script(script);

        let result: Vec<Value> = utxos.iter().map(|(outpoint, value, height)| {
            json!({
                "txid": outpoint.hash.to_hex(),
                "vout": outpoint.n,
                "value": value.to_sat(),
                "status": {
                    "confirmed": true,
                    "block_height": height
                }
            })
        }).collect();

        json!(result)
    }
}

#[async_trait(?Send)]
impl EsploraBackend for DevnetEsploraBackend {
    async fn fetch(&self, path: &str) -> Result<Value> {
        let state = self.state.borrow();

        // Route esplora REST paths
        if path.starts_with("/address/") && path.ends_with("/utxo") {
            // Try esplora indexer first
            if let (Some(ref runtime), Some(ref storage)) =
                (&state.esplora_runtime, &state.esplora_storage)
            {
                let addr = path.strip_prefix("/address/")
                    .and_then(|s| s.strip_suffix("/utxo"))
                    .unwrap_or("");
                if let Ok(result) = runtime.call_view("address_utxo", addr.as_bytes().to_vec(), storage) {
                    if let Ok(json_str) = String::from_utf8(result) {
                        if let Ok(parsed) = serde_json::from_str::<Value>(&json_str) {
                            return Ok(parsed);
                        }
                    }
                }
            }
            // Fallback: return coinbase UTXOs (devnet mines to its own key)
            return Ok(self.coinbase_utxos_as_esplora(&state));
        }

        if path == "/fee-estimates" {
            return Ok(json!({
                "1": 1.0,
                "2": 1.0,
                "3": 1.0,
                "6": 1.0,
                "25": 1.0,
                "144": 1.0,
                "504": 1.0,
                "1008": 1.0
            }));
        }

        // /tx/{txid}/hex — return raw transaction hex
        if path.starts_with("/tx/") && path.ends_with("/hex") {
            let txid_hex = path.strip_prefix("/tx/")
                .and_then(|s| s.strip_suffix("/hex"))
                .unwrap_or("");

            // Scan blocks for matching txid
            for block in (0..=state.chain.height()).filter_map(|h| state.chain.block_at(h)) {
                for tx in &block.vtx {
                    if tx.txid().to_hex() == txid_hex {
                        if let Ok(bytes) = serialize(tx.as_ref()) {
                            return Ok(json!(hex::encode(&bytes)));
                        }
                    }
                }
            }
            return Ok(Value::Null);
        }

        // /tx/{txid} — return transaction info
        if path.starts_with("/tx/") && !path.contains('/') {
            // Not implemented yet — return null
            return Ok(Value::Null);
        }

        // Generic esplora path — try indexer
        if let (Some(ref runtime), Some(ref storage)) =
            (&state.esplora_runtime, &state.esplora_storage)
        {
            if let Ok(result) = runtime.call_view("rest", path.as_bytes().to_vec(), storage) {
                if let Ok(json_str) = String::from_utf8(result) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&json_str) {
                        return Ok(parsed);
                    }
                }
            }
        }

        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// DevnetOrdBackend
// ---------------------------------------------------------------------------

/// Minimal ord backend for devnet that returns the chain height and
/// empty inscription/output data. This is sufficient to unblock
/// `sandshrew_balances` which calls `ord_blockheight` and `ord_outputs`.
pub struct DevnetOrdBackend {
    pub state: Rc<RefCell<DevnetState>>,
}

#[async_trait(?Send)]
impl OrdBackend for DevnetOrdBackend {
    async fn fetch(&self, path: &str) -> Result<Value> {
        let state = self.state.borrow();

        // /blockheight → current chain height
        if path == "/blockheight" {
            return Ok(json!(state.chain.height()));
        }

        // /blockcount → current chain height
        if path == "/blockcount" {
            return Ok(json!(state.chain.height()));
        }

        // /outputs/{address} → empty array (no inscriptions in devnet)
        if path.starts_with("/outputs") {
            return Ok(json!([]));
        }

        // /blockheight → chain height
        if path.starts_with("/blockhash") {
            return Ok(json!(state.chain.tip_hash().to_hex()));
        }

        // /inscription/* → null
        if path.starts_with("/inscription") {
            return Ok(Value::Null);
        }

        // /rune/* → null
        if path.starts_with("/rune") {
            return Ok(Value::Null);
        }

        Ok(Value::Null)
    }

    async fn fetch_content(&self, _inscription_id: &str) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}
