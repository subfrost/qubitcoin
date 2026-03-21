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
use qubitcoin_indexer_core::traits::IndexerStorageReader;
use qubitcoin_indexer_web::runtime::WebIndexerRuntime;
use qubitcoin_indexer_web::storage::WebIndexerStorage;
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
    #[wasm_bindgen(constructor)]
    pub fn new(
        secret_key: &[u8],
        alkanes_wasm: &[u8],
        esplora_wasm: Option<js_sys::Uint8Array>,
    ) -> Result<DevnetServer, JsValue> {
        if secret_key.len() != 32 {
            return Err(JsValue::from_str("secret_key must be exactly 32 bytes"));
        }

        let key = Key::new(secret_key, true)
            .map_err(|e| JsValue::from_str(&format!("invalid secret key: {e}")))?;

        let alkanes_runtime = WebIndexerRuntime::new(alkanes_wasm)?;
        let alkanes_storage = WebIndexerStorage::new();

        let (esplora_runtime, esplora_storage) = match esplora_wasm {
            Some(ref arr) if arr.length() > 0 => {
                let bytes = arr.to_vec();
                let runtime = WebIndexerRuntime::new(&bytes)?;
                let storage = WebIndexerStorage::new();
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
            tertiary_indexers: Vec::new(),
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
        let runtime = TertiaryRuntime::new(wasm_bytes)?;
        let storage = WebIndexerStorage::new();
        self.state.borrow_mut().tertiary_indexers.push(
            crate::backends::TertiaryIndexerInstance {
                label: label.to_string(),
                runtime,
                storage,
            },
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
}
