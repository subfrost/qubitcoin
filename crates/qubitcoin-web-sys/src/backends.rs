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
use qubitcoin_indexer_web::ExternalStorage;
use qubitcoin_indexer_core::traits::{IndexerStorage, IndexerStorageReader, IndexerStorageWriter};
use qubitcoin_tertiary_web::TertiaryRuntime;
use qubitcoin_node::test_framework::TestChain;
use qubitcoin_serialize::serialize;

use std::collections::HashMap;

use qubitcoin_primitives::Amount;

use crate::types;

/// Decode a bech32/bech32m segwit address to its witness program scriptPubKey.
///
/// Returns `Some(script_bytes)` for valid segwit addresses (bc1/tb1/bcrt1).
/// The scriptPubKey format is: `[witness_version_opcode] [push_len] [witness_program]`
///
/// Uses low-level bech32 decoding to support ALL HRPs including `bcrt` (regtest).
/// `bech32::segwit::decode()` only recognizes `bc` and `tb` — not `bcrt`.
fn address_to_script(address: &str) -> Option<Vec<u8>> {
    // First try the standard segwit decode (handles bc1 and tb1)
    if let Ok((_, witness_version, program)) = bech32::segwit::decode(address) {
        let version_opcode = match witness_version.to_u8() {
            0 => 0x00u8,
            n => 0x50 + n,
        };
        let mut script = Vec::with_capacity(2 + program.len());
        script.push(version_opcode);
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        return Some(script);
    }

    // Fallback: manual decode for non-standard HRPs (e.g. bcrt for regtest).
    // Split on '1' to find the data part, then decode the 5-bit groups.
    let sep_pos = address.rfind('1')?;
    let data_part = &address[sep_pos + 1..];
    if data_part.len() < 7 { return None; } // minimum: version + 2-byte program + 6 checksum

    // Decode base32 characters (bech32 alphabet)
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values: Vec<u8> = Vec::new();
    for ch in data_part.chars() {
        let idx = charset.find(ch)? as u8;
        values.push(idx);
    }

    // Strip 6 checksum characters
    if values.len() < 7 { return None; }
    values.truncate(values.len() - 6);

    // First value is the witness version
    let witness_version = values[0];
    if witness_version > 16 { return None; }

    // Remaining values are 5-bit groups → convert to 8-bit bytes
    let five_bit = &values[1..];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    for &v in five_bit {
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Discard incomplete trailing bits (must be zero-padded)

    if result.len() < 2 || result.len() > 40 { return None; }

    // Build scriptPubKey
    let version_opcode = match witness_version {
        0 => 0x00u8,
        n => 0x50 + n,
    };
    let mut script = Vec::with_capacity(2 + result.len());
    script.push(version_opcode);
    script.push(result.len() as u8);
    script.extend_from_slice(&result);
    Some(script)
}

/// A named tertiary indexer instance with its own runtime and storage.
pub struct TertiaryIndexerInstance {
    pub label: String,
    pub runtime: TertiaryRuntime,
    pub storage: Box<dyn IndexerStorage>,
}

/// Shared devnet state accessible by all backends via Rc<RefCell<...>>.
pub struct DevnetState {
    pub chain: TestChain,
    pub alkanes_runtime: WebIndexerRuntime,
    pub alkanes_storage: Box<dyn IndexerStorage>,
    pub esplora_runtime: Option<WebIndexerRuntime>,
    pub esplora_storage: Option<Box<dyn IndexerStorage>>,
    /// Additional named secondary indexers (beyond alkanes + esplora).
    /// Each gets its own storage and is indexed on every block.
    pub additional_secondaries: Vec<SecondaryIndexerInstance>,
    /// Tertiary indexers that run after secondary indexers.
    pub tertiary_indexers: Vec<TertiaryIndexerInstance>,
    /// Whether to use external (JS-hosted) storage for new stores.
    pub use_external_storage: bool,
}

/// A named secondary indexer instance with its own runtime and storage.
pub struct SecondaryIndexerInstance {
    pub label: String,
    pub runtime: WebIndexerRuntime,
    pub storage: Box<dyn IndexerStorage>,
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

    /// Mine a block with extra coinbase outputs.
    ///
    /// `raw_outputs`: pairs of (value_u64_le, script_hex) encoded as:
    ///   [8-byte LE value][2-byte LE script_len][script_bytes] repeated
    pub fn mine_with_coinbase_outputs_raw_and_index(
        &mut self,
        raw_outputs: &[u8],
    ) -> Result<Vec<u8>> {
        use qubitcoin_consensus::transaction::TxOut;
        use qubitcoin_script::Script;
        use qubitcoin_primitives::Amount;

        let mut outputs = Vec::new();
        let mut pos = 0;
        while pos + 10 <= raw_outputs.len() {
            // 8-byte LE value
            let value = i64::from_le_bytes(raw_outputs[pos..pos+8].try_into()
                .map_err(|_| anyhow::anyhow!("invalid value at {}", pos))?);
            pos += 8;
            // 2-byte LE script length
            let script_len = u16::from_le_bytes(raw_outputs[pos..pos+2].try_into()
                .map_err(|_| anyhow::anyhow!("invalid script_len at {}", pos))?) as usize;
            pos += 2;
            // script bytes
            if pos + script_len > raw_outputs.len() {
                return Err(anyhow::anyhow!("script overflows at {}", pos));
            }
            let script = Script::from_bytes(raw_outputs[pos..pos+script_len].to_vec());
            pos += script_len;

            outputs.push(TxOut::new(Amount::from_sat(value), script));
        }

        let block = self.chain.mine_block_with_coinbase_outputs(vec![], outputs);
        let block_bytes = types::block_to_bytes(&block)
            .map_err(|e| anyhow::anyhow!("block serialize: {:?}", e))?;
        self.index_block(&block_bytes)?;
        Ok(block_bytes)
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
        // Current tip height (before this block)
        let alkanes_height = self.alkanes_storage.tip_height();

        let pairs = self.alkanes_runtime.run_block(
            alkanes_height, block_bytes.to_vec(), self.alkanes_storage.as_ref(),
        ).map_err(|e| anyhow::anyhow!("alkanes index: {:?}", e))?;

        for (key, value) in &pairs {
            self.alkanes_storage.put(key, value)
                .map_err(|e| anyhow::anyhow!("alkanes storage put: {}", e))?;
        }

        self.alkanes_storage.set_tip_height(alkanes_height + 1)
            .map_err(|e| anyhow::anyhow!("alkanes set height: {}", e))?;

        // Index through esplora (if loaded)
        if let (Some(ref runtime), Some(ref mut storage)) =
            (&self.esplora_runtime, &mut self.esplora_storage)
        {
            let esplora_height = storage.tip_height();
            let pairs = runtime.run_block(esplora_height, block_bytes.to_vec(), storage.as_ref())
                .map_err(|e| anyhow::anyhow!("esplora index: {:?}", e))?;
            for (key, value) in &pairs {
                storage.append(key, value, esplora_height)
                    .map_err(|e| anyhow::anyhow!("esplora storage append: {}", e))?;
            }
            storage.set_tip_height(esplora_height + 1)
                .map_err(|e| anyhow::anyhow!("esplora set height: {}", e))?;
        }

        // Index through additional secondary indexers
        for secondary in &mut self.additional_secondaries {
            let s_height = secondary.storage.tip_height();
            let pairs = secondary.runtime.run_block(
                s_height, block_bytes.to_vec(), secondary.storage.as_ref(),
            ).map_err(|e| anyhow::anyhow!("secondary '{}' index: {:?}", secondary.label, e))?;
            for (key, value) in &pairs {
                secondary.storage.put(key, value)
                    .map_err(|e| anyhow::anyhow!("secondary '{}' put: {}", secondary.label, e))?;
            }
            secondary.storage.set_tip_height(s_height + 1)
                .map_err(|e| anyhow::anyhow!("secondary '{}' set height: {}", secondary.label, e))?;
        }

        // Index through tertiary indexers (run after all secondary indexers)
        if !self.tertiary_indexers.is_empty() {
            let secondary_storages = self.build_secondary_storage_map();
            for tertiary in &mut self.tertiary_indexers {
                let t_height = tertiary.storage.tip_height();
                let pairs = tertiary.runtime.run_block(
                    t_height, block_bytes.to_vec(),
                    tertiary.storage.as_ref(), &secondary_storages,
                ).map_err(|e| anyhow::anyhow!("tertiary '{}' index: {:?}", tertiary.label, e))?;
                for (key, value) in &pairs {
                    tertiary.storage.put(key, value)
                        .map_err(|e| anyhow::anyhow!("tertiary '{}' put: {}", tertiary.label, e))?;
                }
                tertiary.storage.set_tip_height(t_height + 1)
                    .map_err(|e| anyhow::anyhow!("tertiary '{}' set height: {}", tertiary.label, e))?;
            }
        }

        Ok(())
    }

    /// Create a new storage instance based on the configured backend.
    pub fn create_storage(&self) -> Box<dyn IndexerStorage> {
        if self.use_external_storage {
            Box::new(ExternalStorage::new())
        } else {
            Box::new(WebIndexerStorage::new())
        }
    }

    /// Build a map of secondary indexer name → storage pointer for tertiary access.
    fn build_secondary_storage_map(&self) -> HashMap<String, *const dyn IndexerStorageReader> {
        let mut map: HashMap<String, *const dyn IndexerStorageReader> = HashMap::new();
        map.insert("alkanes".to_string(), self.alkanes_storage.as_ref() as *const dyn IndexerStorageReader);
        if let Some(ref storage) = self.esplora_storage {
            map.insert("esplora".to_string(), storage.as_ref() as *const dyn IndexerStorageReader);
        }
        for secondary in &self.additional_secondaries {
            map.insert(secondary.label.clone(), secondary.storage.as_ref() as *const dyn IndexerStorageReader);
        }
        map
    }

    /// Call a view function on a named tertiary indexer.
    ///
    /// Returns `None` if no tertiary indexer with that label exists.
    pub fn call_tertiary_view(
        &self,
        label: &str,
        fn_name: &str,
        height: u32,
        payload: Vec<u8>,
    ) -> Option<Result<Vec<u8>, anyhow::Error>> {
        let tertiary = self.tertiary_indexers.iter().find(|t| t.label == label)?;
        let secondary_storages = self.build_secondary_storage_map();
        Some(
            tertiary.runtime.call_view(
                fn_name, height, payload,
                tertiary.storage.as_ref(), &secondary_storages,
            ).map_err(|e| anyhow::anyhow!("tertiary '{}' view '{}': {:?}", label, fn_name, e))
        )
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
                let addr_str = params.get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let mut state = self.state.borrow_mut();
                // If an address is provided, mine with an extra coinbase output to that address
                let block_bytes_vec = if !addr_str.is_empty() {
                    if let Some(script) = address_to_script(addr_str) {
                        let mut all_bytes = Vec::new();
                        for _ in 0..count {
                            // Build raw output: 8-byte LE value + 2-byte LE script_len + script
                            let value: i64 = 5_000_000_000; // 50 BTC coinbase reward
                            let mut raw = Vec::new();
                            raw.extend_from_slice(&value.to_le_bytes());
                            raw.extend_from_slice(&(script.len() as u16).to_le_bytes());
                            raw.extend_from_slice(&script);
                            let block_bytes = state.mine_with_coinbase_outputs_raw_and_index(&raw)?;
                            all_bytes.push(block_bytes);
                        }
                        all_bytes
                    } else {
                        state.mine_and_index(count)?
                    }
                } else {
                    state.mine_and_index(count)?
                };
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
                let block_tag = request.params.get(2)
                    .and_then(|v| v.as_str())
                    .unwrap_or("latest");

                let input_hex = hex_input.strip_prefix("0x").unwrap_or(hex_input);
                let input_bytes = hex::decode(input_hex)
                    .map_err(|e| anyhow::anyhow!("invalid hex input: {}", e))?;

                let state = self.state.borrow();

                // Resolve block_tag to height
                let height = if block_tag == "latest" {
                    state.alkanes_storage.tip_height().saturating_sub(1)
                } else {
                    block_tag.parse::<u32>().unwrap_or(0)
                };

                // Check if view_method targets a specific indexer (e.g., "charms/indexerheight")
                if let Some((indexer_label, fn_name)) = view_method.split_once('/') {
                    // Route to named indexer
                    // Try additional secondaries
                    for secondary in &state.additional_secondaries {
                        if secondary.label == indexer_label {
                            match secondary.runtime.call_view(
                                fn_name, height, input_bytes.clone(), secondary.storage.as_ref(),
                            ) {
                                Ok(data) => {
                                    return Ok(JsonRpcResponse::success(
                                        json!(format!("0x{}", hex::encode(&data))),
                                        request.id.clone(),
                                    ));
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    // Try tertiary indexers
                    for tertiary in &state.tertiary_indexers {
                        if tertiary.label == indexer_label {
                            if let Some(Ok(data)) = state.call_tertiary_view(
                                indexer_label, fn_name, height, input_bytes.clone(),
                            ) {
                                return Ok(JsonRpcResponse::success(
                                    json!(format!("0x{}", hex::encode(&data))),
                                    request.id.clone(),
                                ));
                            }
                        }
                    }
                    return Err(anyhow::anyhow!(
                        "dispatch error: view '{}/{}' not found in any indexer",
                        indexer_label, fn_name,
                    ));
                }

                // No prefix — try alkanes (primary secondary) first
                let result = state.alkanes_runtime.call_view(
                    view_method,
                    height,
                    input_bytes.clone(),
                    state.alkanes_storage.as_ref(),
                );

                match result {
                    Ok(data) => {
                        return Ok(JsonRpcResponse::success(
                            json!(format!("0x{}", hex::encode(&data))),
                            request.id.clone(),
                        ));
                    }
                    Err(_) => {
                        // Try additional secondary indexers
                        for secondary in &state.additional_secondaries {
                            match secondary.runtime.call_view(
                                view_method, height, input_bytes.clone(),
                                secondary.storage.as_ref(),
                            ) {
                                Ok(data) => {
                                    return Ok(JsonRpcResponse::success(
                                        json!(format!("0x{}", hex::encode(&data))),
                                        request.id.clone(),
                                    ));
                                }
                                Err(_) => continue,
                            }
                        }

                        // Try tertiary indexers
                        for tertiary in &state.tertiary_indexers {
                            if let Some(Ok(data)) = state.call_tertiary_view(
                                &tertiary.label, view_method, height, input_bytes.clone(),
                            ) {
                                return Ok(JsonRpcResponse::success(
                                    json!(format!("0x{}", hex::encode(&data))),
                                    request.id.clone(),
                                ));
                            }
                        }
                        // No indexer handled it
                        return Err(anyhow::anyhow!(
                            "view '{}' not found in alkanes or any secondary/tertiary indexer",
                            view_method,
                        ));
                    }
                }
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
    /// Scan the chain for unspent outputs matching a given address.
    ///
    /// Tries the esplora indexer's `utxosbyscripthash` view function first.
    /// Falls back to scanning the chain's UTXO set by scriptPubKey.
    fn utxos_for_address(&self, state: &DevnetState, address: &str) -> Value {
        let script = match address_to_script(address) {
            Some(s) => s,
            None => return json!([]),
        };

        // Try esplora indexer with scripthash
        if let (Some(ref runtime), Some(ref storage)) =
            (&state.esplora_runtime, &state.esplora_storage)
        {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&script);
            let script_hash: [u8; 32] = hasher.finalize().into();
            // esplorashrew expects reversed (display order) hex for script hashes
            let reversed: Vec<u8> = script_hash.iter().rev().cloned().collect();
            let sh_hex = hex::encode(reversed);

            let esplora_height = storage.tip_height().saturating_sub(1);
            if let Ok(result) = runtime.call_view(
                "utxosbyscripthash",
                esplora_height,
                sh_hex.as_bytes().to_vec(),
                storage.as_ref(),
            ) {
                if let Ok(json_str) = String::from_utf8(result) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&json_str) {
                        // Only return if the array is non-empty.
                        // An empty array means esplorashrew didn't find anything,
                        // so we fall through to the block-scan fallback.
                        if let Some(arr) = parsed.as_array() {
                            if !arr.is_empty() {
                                return parsed;
                            }
                        }
                    }
                }
            }
        }

        // Fallback: full block scan with spend tracking.
        //
        // We bypass coins.have_coin() because the CoinsViewCache uses
        // parking_lot::RwLock which may have issues in WASM contexts.
        // Instead, we build a set of spent outpoints from all tx inputs,
        // then return outputs matching the script that aren't in the spent set.
        use std::collections::HashSet;

        let target_script = script;
        let chain_height = state.chain.height();

        // First pass: collect all spent outpoints
        let mut spent: HashSet<(String, u32)> = HashSet::new();
        for h in 0..=chain_height {
            if let Some(block) = state.chain.block_at(h) {
                for (tx_idx, tx) in block.vtx.iter().enumerate() {
                    if tx_idx == 0 { continue; } // skip coinbase inputs
                    for input in &tx.vin {
                        spent.insert((input.prevout.hash.to_hex(), input.prevout.n));
                    }
                }
            }
        }

        // Second pass: collect unspent outputs matching the target script
        let maturity = 100i32;
        let mut result: Vec<Value> = Vec::new();
        for h in 0..=chain_height {
            if let Some(block) = state.chain.block_at(h) {
                for (tx_idx, tx) in block.vtx.iter().enumerate() {
                    for (vout, txout) in tx.vout.iter().enumerate() {
                        if txout.script_pubkey.as_bytes() != target_script {
                            continue;
                        }
                        let txid_hex = tx.txid().to_hex();
                        if spent.contains(&(txid_hex.clone(), vout as u32)) {
                            continue;
                        }
                        // Coinbase maturity check
                        if tx_idx == 0 {
                            let depth = chain_height - h;
                            if depth < maturity {
                                continue;
                            }
                        }
                        result.push(json!({
                            "txid": txid_hex,
                            "vout": vout,
                            "value": txout.value.to_sat(),
                            "status": {
                                "confirmed": true,
                                "block_height": h
                            }
                        }));
                    }
                }
            }
        }
        json!(result)
    }
}

#[async_trait(?Send)]
impl EsploraBackend for DevnetEsploraBackend {
    async fn fetch(&self, path: &str) -> Result<Value> {
        let state = self.state.borrow();

        // Route esplora REST paths
        if path.starts_with("/address/") && path.ends_with("/utxo") {
            let addr = path.strip_prefix("/address/")
                .and_then(|s| s.strip_suffix("/utxo"))
                .unwrap_or("");
            return Ok(self.utxos_for_address(&state, addr));
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
            let esplora_height = storage.tip_height().saturating_sub(1);
            if let Ok(result) = runtime.call_view("rest", esplora_height, path.as_bytes().to_vec(), storage.as_ref()) {
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
