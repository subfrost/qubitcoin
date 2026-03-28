//! DevnetServer — in-process JSON-RPC server for testing.
//!
//! Wraps the chain, indexers, and alkanes-rpc-core dispatcher into a single
//! WASM export that processes JSON-RPC requests entirely in-memory.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use alkanes_rpc_core::types::{JsonRpcRequest, JsonRpcResponse};
use alkanes_rpc_core::RpcDispatcher;
use wasm_bindgen::prelude::*;

use qubitcoin_common::keys::Key;
use qubitcoin_indexer_core::traits::{IndexerStorage, IndexerStorageReader};
use qubitcoin_indexer_web::runtime::WebIndexerRuntime;
use qubitcoin_indexer_web::storage::WebIndexerStorage;
use qubitcoin_indexer_web::ExternalStorage;
use qubitcoin_tertiary_web::TertiaryRuntime;
use qubitcoin_node::test_framework::TestChain;

use crate::backends::*;

/// Poll a future that is expected to complete immediately (no real I/O).
///
/// All devnet backends are synchronous in-memory operations, so every future
/// produced by the dispatcher resolves on the first poll.
fn poll_immediately<T>(fut: Pin<Box<dyn Future<Output = T> + '_>>) -> T {
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |p| RawWaker::new(p, &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = fut;
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("devnet dispatch returned Pending — all operations should be synchronous"),
    }
}

/// In-process JSON-RPC server for devnet testing.
///
/// Handles the full alkanes RPC protocol (btc_*, alkanes_*, metashrew_*,
/// esplora_*, sandshrew_multicall, etc.) against an in-memory chain and
/// secondary indexers. No network, no disk.
#[wasm_bindgen]
pub struct DevnetServer {
    state: Rc<RefCell<DevnetState>>,
}

#[wasm_bindgen]
impl DevnetServer {
    /// Create a new devnet server.
    ///
    /// * `secret_key` — 32-byte key for the coinbase recipient.
    /// * `alkanes_wasm` — compiled alkanes indexer WASM module bytes.
    /// * `esplora_wasm` — (optional) compiled esplora indexer WASM bytes.
    ///   Pass `undefined` or empty `Uint8Array` to skip.
    /// Create a new devnet server.
    ///
    /// * `secret_key` — 32-byte key for the coinbase recipient.
    /// * `alkanes_wasm` — compiled alkanes indexer WASM module bytes.
    /// * `esplora_wasm` — (optional) compiled esplora indexer WASM bytes.
    /// * `use_external_storage` — if true, use JS-hosted storage (IndexedDB/Map)
    ///   instead of WASM-internal BTreeMap. Prevents OOM with many contracts.
    #[wasm_bindgen(constructor)]
    pub fn new(
        secret_key: &[u8],
        alkanes_wasm: &[u8],
        esplora_wasm: Option<js_sys::Uint8Array>,
        use_external_storage: Option<bool>,
    ) -> Result<DevnetServer, JsValue> {
        let external = use_external_storage.unwrap_or(false);

        if secret_key.len() != 32 {
            return Err(JsValue::from_str("secret_key must be exactly 32 bytes"));
        }

        let key = Key::new(secret_key, true)
            .map_err(|e| JsValue::from_str(&format!("invalid secret key: {e}")))?;

        let alkanes_runtime = WebIndexerRuntime::new(alkanes_wasm)?;
        let alkanes_storage: Box<dyn IndexerStorage> = if external {
            Box::new(ExternalStorage::new())
        } else {
            Box::new(WebIndexerStorage::new())
        };

        let (esplora_runtime, esplora_storage) = match esplora_wasm {
            Some(ref arr) if arr.length() > 0 => {
                let bytes = arr.to_vec();
                let runtime = WebIndexerRuntime::new(&bytes)?;
                let storage: Box<dyn IndexerStorage> = if external {
                    Box::new(ExternalStorage::new())
                } else {
                    Box::new(WebIndexerStorage::new())
                };
                (Some(runtime), Some(storage))
            }
            _ => (None, None),
        };

        let state = Rc::new(RefCell::new(DevnetState {
            chain: TestChain::new_with_key_wpkh(key),
            alkanes_runtime,
            alkanes_storage,
            esplora_runtime,
            esplora_storage,
            additional_secondaries: Vec::new(),
            tertiary_indexers: Vec::new(),
            use_external_storage: external,
        }));

        Ok(DevnetServer { state })
    }

    /// Add a tertiary indexer WASM module.
    ///
    /// * `label` — unique name for this tertiary indexer (e.g., "quspo", "qusprey").
    /// * `wasm_bytes` — compiled tertiary indexer WASM module bytes.
    ///
    /// Tertiary indexers run after all secondary indexers and can read their state.
    #[wasm_bindgen(js_name = "addTertiary")]
    pub fn add_tertiary(&self, label: &str, wasm_bytes: &[u8]) -> Result<(), JsValue> {
        self.add_tertiary_with_config(label, wasm_bytes, &[])
    }

    /// Add a tertiary indexer WASM module with runtime configuration.
    ///
    /// Config is passed to the WASM via `__host_config_len()` / `__load_config()`.
    #[wasm_bindgen(js_name = "addTertiaryWithConfig")]
    pub fn add_tertiary_with_config(
        &self,
        label: &str,
        wasm_bytes: &[u8],
        config: &[u8],
    ) -> Result<(), JsValue> {
        let runtime = TertiaryRuntime::new(wasm_bytes)?;
        let mut state = self.state.borrow_mut();
        let storage = state.create_storage();
        state.tertiary_indexers.push(
            crate::backends::TertiaryIndexerInstance {
                label: label.to_string(),
                runtime,
                storage,
                config: config.to_vec(),
            },
        );
        Ok(())
    }

    /// Add an additional secondary indexer WASM module.
    ///
    /// * `label` — unique name for this secondary indexer (e.g., "charms", "brc20").
    /// * `wasm_bytes` — compiled secondary indexer WASM module bytes.
    ///
    /// Additional secondaries run after alkanes/esplora but before tertiary indexers.
    /// Their storage is accessible to tertiary indexers via `__secondary_get(label, key)`.
    #[wasm_bindgen(js_name = "addSecondary")]
    pub fn add_secondary(&self, label: &str, wasm_bytes: &[u8]) -> Result<(), JsValue> {
        let runtime = WebIndexerRuntime::new(wasm_bytes)?;
        let mut state = self.state.borrow_mut();
        let storage = state.create_storage();
        state.additional_secondaries.push(
            crate::backends::SecondaryIndexerInstance {
                label: label.to_string(),
                runtime,
                storage,
            },
        );
        web_sys::console::log_1(
            &format!("[devnet] Added secondary '{}' (total: {})", label, state.additional_secondaries.len()).into()
        );
        Ok(())
    }

    /// Process a JSON-RPC request string and return the JSON-RPC response string.
    ///
    /// All methods — including lua_evalsaved, sandshrew_balances, alkanes_*,
    /// esplora_*, etc. — flow through the alkanes-rpc-core RpcDispatcher.
    /// Lua scripts are handled by the dispatcher's built-in shims that map
    /// known script hashes to their Rust equivalents.
    #[wasm_bindgen(js_name = "handleRpc")]
    pub fn handle_rpc(&self, request_json: &str) -> Result<String, JsValue> {
        let request: JsonRpcRequest = serde_json::from_str(request_json)
            .map_err(|e| JsValue::from_str(&format!("invalid JSON-RPC request: {}", e)))?;

        let dispatcher = RpcDispatcher::new(
            DevnetBitcoinBackend { state: self.state.clone() },
            DevnetMetashrewBackend { state: self.state.clone() },
            DevnetEsploraBackend { state: self.state.clone() },
            DevnetOrdBackend { state: self.state.clone() },
        );

        let response = poll_immediately(dispatcher.dispatch(&request))
            .map_err(|e| JsValue::from_str(&format!("dispatch error: {}", e)))?;

        serde_json::to_string(&response)
            .map_err(|e| JsValue::from_str(&format!("serialize error: {}", e)))
    }

    /// Mine `count` empty blocks and auto-index through all indexers.
    #[wasm_bindgen(js_name = "mineBlocks")]
    pub fn mine_blocks(&self, count: u32) -> Result<(), JsValue> {
        let mut state = self.state.borrow_mut();
        state.mine_and_index(count)
            .map_err(|e| JsValue::from_str(&format!("mine error: {}", e)))?;
        Ok(())
    }

    /// Mine a block with extra outputs in the coinbase transaction.
    ///
    /// `extra_outputs_hex`: hex-encoded concatenated Bitcoin TxOut entries.
    /// Each TxOut is serialized as: [8-byte LE value] + [varint script_len] + [script bytes]
    ///
    /// This is metaprotocol-agnostic — the caller constructs the raw outputs.
    #[wasm_bindgen(js_name = "mineBlockWithCoinbaseOutputs")]
    pub fn mine_block_with_coinbase_outputs(&self, extra_outputs_hex: &str) -> Result<(), JsValue> {
        let hex_str = extra_outputs_hex.strip_prefix("0x").unwrap_or(extra_outputs_hex);
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("invalid hex: {}", e)))?;

        let mut state = self.state.borrow_mut();
        state.mine_with_coinbase_outputs_raw_and_index(&bytes)
            .map_err(|e| JsValue::from_str(&format!("mine error: {}", e)))?;
        Ok(())
    }

    /// Current chain height.
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> i32 {
        self.state.borrow().chain.height()
    }

    /// Current alkanes indexer height.
    #[wasm_bindgen(getter, js_name = "indexerHeight")]
    pub fn indexer_height(&self) -> u32 {
        self.state.borrow().alkanes_storage.tip_height()
    }

    /// Tip block hash as hex.
    #[wasm_bindgen(getter, js_name = "tipHashHex")]
    pub fn tip_hash_hex(&self) -> String {
        self.state.borrow().chain.tip_hash().to_hex()
    }

    /// Export all indexer state as a single binary blob for persistence.
    ///
    /// Format:
    /// - [4-byte magic "DNET"]
    /// - [u32 version = 1]
    /// - [u32 chain_height]
    /// - [u32 num_blocks] then for each block: [u32 block_len] [block_bytes]
    /// - [u32 alkanes_blob_len] [alkanes_storage_blob]
    /// - [u32 esplora_blob_len] [esplora_storage_blob] (0 if no esplora)
    /// - [u32 num_tertiary] [for each: u32 label_len, label_utf8, u32 blob_len, blob]
    #[wasm_bindgen(js_name = "exportState")]
    pub fn export_state(&self) -> Result<Vec<u8>, JsValue> {
        let state = self.state.borrow();
        let mut buf = Vec::new();

        // Magic + version
        buf.extend_from_slice(b"DNET");
        buf.extend_from_slice(&1u32.to_le_bytes());

        // Chain height
        let chain_height = state.chain.height();
        buf.extend_from_slice(&(chain_height as u32).to_le_bytes());

        // Serialize all blocks so the chain can be fully reconstructed on import.
        // For devnet the chain is small (typically 100-200 blocks), so this is
        // reasonable. Each block is stored as [u32 len][block_bytes].
        let num_blocks = if chain_height >= 0 { (chain_height + 1) as u32 } else { 0 };
        buf.extend_from_slice(&num_blocks.to_le_bytes());
        for h in 0..num_blocks as i32 {
            if let Some(block) = state.chain.block_at(h) {
                let block_bytes = crate::types::block_to_bytes(block)
                    .map_err(|e| JsValue::from_str(&format!("export block {}: {:?}", h, e)))?;
                buf.extend_from_slice(&(block_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(&block_bytes);
            } else {
                return Err(JsValue::from_str(&format!("missing block at height {}", h)));
            }
        }

        // Alkanes storage blob
        let alkanes_blob = state.alkanes_storage.export_bytes();
        buf.extend_from_slice(&(alkanes_blob.len() as u32).to_le_bytes());
        buf.extend_from_slice(&alkanes_blob);

        // Esplora storage blob (0-length if not present)
        match &state.esplora_storage {
            Some(storage) => {
                let esplora_blob = storage.export_bytes();
                buf.extend_from_slice(&(esplora_blob.len() as u32).to_le_bytes());
                buf.extend_from_slice(&esplora_blob);
            }
            None => {
                buf.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        // Tertiary indexers
        let num_tertiary = state.tertiary_indexers.len() as u32;
        buf.extend_from_slice(&num_tertiary.to_le_bytes());
        for tertiary in &state.tertiary_indexers {
            let label_bytes = tertiary.label.as_bytes();
            buf.extend_from_slice(&(label_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(label_bytes);
            let blob = tertiary.storage.export_bytes();
            buf.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            buf.extend_from_slice(&blob);
        }

        Ok(buf)
    }

    /// Import state from a previously exported blob, restoring all indexer
    /// storage and replaying blocks into the chain.
    #[wasm_bindgen(js_name = "importState")]
    pub fn import_state(&self, data: &[u8]) -> Result<(), JsValue> {
        let parse_err = |msg: &str| JsValue::from_str(&format!("importState: {}", msg));

        if data.len() < 16 {
            return Err(parse_err("blob too small"));
        }

        // Verify magic
        if &data[0..4] != b"DNET" {
            return Err(parse_err("invalid magic (expected DNET)"));
        }

        // Verify version
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != 1 {
            return Err(parse_err(&format!("unsupported version: {}", version)));
        }

        let chain_height = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let mut pos = 12;

        // Read blocks
        if pos + 4 > data.len() { return Err(parse_err("truncated num_blocks")); }
        let num_blocks = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
        pos += 4;

        // Skip over block data (we reconstruct the chain by mining empty blocks)
        for i in 0..num_blocks {
            if pos + 4 > data.len() { return Err(parse_err(&format!("truncated block {} length", i))); }
            let block_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + block_len > data.len() { return Err(parse_err(&format!("truncated block {} data", i))); }
            pos += block_len;
        }

        // Alkanes storage blob
        if pos + 4 > data.len() { return Err(parse_err("truncated alkanes blob length")); }
        let alkanes_blob_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + alkanes_blob_len > data.len() { return Err(parse_err("truncated alkanes blob")); }
        let alkanes_blob = &data[pos..pos+alkanes_blob_len];
        pos += alkanes_blob_len;

        // Esplora storage blob
        if pos + 4 > data.len() { return Err(parse_err("truncated esplora blob length")); }
        let esplora_blob_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;
        let esplora_blob = if esplora_blob_len > 0 {
            if pos + esplora_blob_len > data.len() { return Err(parse_err("truncated esplora blob")); }
            let blob = &data[pos..pos+esplora_blob_len];
            pos += esplora_blob_len;
            Some(blob)
        } else {
            None
        };

        // Tertiary indexers
        if pos + 4 > data.len() { return Err(parse_err("truncated num_tertiary")); }
        let num_tertiary = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;

        let mut tertiary_data: Vec<(String, Vec<u8>)> = Vec::with_capacity(num_tertiary);
        for i in 0..num_tertiary {
            if pos + 4 > data.len() { return Err(parse_err(&format!("truncated tertiary {} label length", i))); }
            let label_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + label_len > data.len() { return Err(parse_err(&format!("truncated tertiary {} label", i))); }
            let label = String::from_utf8(data[pos..pos+label_len].to_vec())
                .map_err(|_| parse_err(&format!("invalid utf8 in tertiary {} label", i)))?;
            pos += label_len;

            if pos + 4 > data.len() { return Err(parse_err(&format!("truncated tertiary {} blob length", i))); }
            let blob_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + blob_len > data.len() { return Err(parse_err(&format!("truncated tertiary {} blob", i))); }
            tertiary_data.push((label, data[pos..pos+blob_len].to_vec()));
            pos += blob_len;
        }

        // All parsing succeeded — now apply the state.
        let mut state = self.state.borrow_mut();

        // Advance the chain to the exported height by mining empty blocks.
        // We don't replay the original blocks (which may have had transactions)
        // because the indexer state is authoritative — it comes from the imported
        // blobs. The chain is needed for:
        // 1. Correct height() / tip_hash() responses
        // 2. Coinbase UTXO set (same key → same outputs)
        // 3. Future mine_block() calls that need prev_blockhash
        //
        // Transaction UTXOs from the original chain won't exist, but the esplora
        // indexer has the correct UTXO data in its imported storage.
        let current_height = state.chain.height();
        let target_height = chain_height as i32;
        if target_height > current_height {
            let blocks_to_mine = (target_height - current_height) as u32;
            for _ in 0..blocks_to_mine {
                state.chain.mine_block(vec![]);
            }
        }

        // Import indexer storage
        state.alkanes_storage.import_bytes(alkanes_blob)
            .map_err(|e| parse_err(&format!("alkanes import: {}", e)))?;

        if let (Some(ref esplora_storage), Some(esplora_blob)) = (&state.esplora_storage, esplora_blob) {
            esplora_storage.import_bytes(esplora_blob)
                .map_err(|e| parse_err(&format!("esplora import: {}", e)))?;
        }

        // Import tertiary indexer storage (match by label)
        for (label, blob) in &tertiary_data {
            if let Some(tertiary) = state.tertiary_indexers.iter().find(|t| &t.label == label) {
                tertiary.storage.import_bytes(blob)
                    .map_err(|e| parse_err(&format!("tertiary '{}' import: {}", label, e)))?;
            }
            // If no matching tertiary indexer exists, silently skip — it may
            // have been added after the snapshot was taken.
        }

        Ok(())
    }
}
