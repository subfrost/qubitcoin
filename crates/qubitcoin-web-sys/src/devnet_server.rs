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
        }));

        Ok(DevnetServer { state })
    }

    /// Process a JSON-RPC request string and return the JSON-RPC response string.
    #[wasm_bindgen(js_name = "handleRpc")]
    pub fn handle_rpc(&self, request_json: &str) -> Result<String, JsValue> {
        let request: JsonRpcRequest = serde_json::from_str(request_json)
            .map_err(|e| JsValue::from_str(&format!("invalid JSON-RPC request: {}", e)))?;

        // Pre-dispatch: intercept lua_evalscript/lua_evalsaved and handle
        // natively. The SDK uses Lua scripts for getEnrichedBalances and
        // spendable UTXO discovery which we don't support in WASM.
        let request = self.intercept_lua_calls(request);

        // Handle precomputed responses from Lua interception
        if request.method == "__devnet_precomputed" {
            let result = request.params.into_iter().next()
                .unwrap_or(serde_json::Value::Null);
            let response = JsonRpcResponse::success(result, request.id);
            return serde_json::to_string(&response)
                .map_err(|e| JsValue::from_str(&format!("serialize error: {}", e)));
        }

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

    /// Intercept Lua RPC calls and handle them natively.
    ///
    /// The SDK uses `lua_evalscript`/`lua_evalsaved` for UTXO discovery
    /// and balance queries. Since we don't have Lua in WASM, we detect
    /// the script patterns and execute equivalent logic natively.
    fn intercept_lua_calls(&self, request: JsonRpcRequest) -> JsonRpcRequest {
        use serde_json::json;
        let method = &request.method;

        if method == "lua_evalsaved" || method == "lua_evalscript"
            || method == "sandshrew_evalsaved" || method == "sandshrew_evalscript"
        {
            let is_evalsaved = method.contains("evalsaved");

            // For evalsaved, params[0] is the script hash, params[1+] are args
            // For evalscript, params[0] is the script text, params[1+] are args
            let addr = if is_evalsaved {
                request.params.get(1).and_then(|v| v.as_str())
            } else {
                request.params.get(1).and_then(|v| v.as_str())
            };

            if let Some(addr) = addr {
                // Check what kind of script this is
                let script_text = request.params.get(0).and_then(|v| v.as_str()).unwrap_or("");
                let is_spendables_script = script_text.contains("is_coinbase") || is_evalsaved;
                let is_balance_script = script_text.contains("ord_blockheight");

                if is_spendables_script || is_balance_script || is_evalsaved {
                    // Execute the script logic natively using chain state
                    let state = self.state.borrow();
                    let height = state.chain.height();
                    let script = state.chain.coinbase_script();
                    let utxos = state.chain.utxos_for_script(script);

                    if is_balance_script {
                        // Return sandshrew_balances-compatible format
                        let spendable: Vec<serde_json::Value> = utxos.iter().map(|(op, val, h)| {
                            json!({
                                "outpoint": format!("{}:{}", op.hash.to_hex(), op.n),
                                "value": val.to_sat(),
                                "height": h
                            })
                        }).collect();

                        let indexer_height = state.alkanes_storage.tip_height();

                        let result = json!({
                            "calls": 0,
                            "returns": {
                                "spendable": spendable,
                                "assets": [],
                                "pending": [],
                                "ordHeight": height,
                                "metashrewHeight": indexer_height
                            },
                            "runtime": 0
                        });

                        // Return as a pre-computed response by wrapping in a special method
                        // that the dispatcher will handle as a pass-through
                        return JsonRpcRequest {
                            jsonrpc: "2.0".to_string(),
                            method: "__devnet_precomputed".to_string(),
                            params: vec![result],
                            id: request.id,
                        };
                    } else {
                        // Spendables script — return UTXOs in the Lua format
                        let mut spendable = Vec::new();
                        let mut immature = Vec::new();

                        for (op, val, h) in &utxos {
                            let confirmations = height - h;
                            let entry = json!({
                                "txid": op.hash.to_hex(),
                                "vout": op.n,
                                "value": val.to_sat(),
                                "outpoint": format!("{}:{}", op.hash.to_hex(), op.n),
                                "height": h,
                                "confirmations": confirmations,
                                "is_coinbase": true
                            });

                            if confirmations >= 100 {
                                spendable.push(entry);
                            } else {
                                let mut entry = entry;
                                entry.as_object_mut().unwrap().insert(
                                    "maturity_blocks_remaining".to_string(),
                                    json!(100 - confirmations),
                                );
                                immature.push(entry);
                            }
                        }

                        let result = json!({
                            "calls": 0,
                            "returns": {
                                "spendable": spendable,
                                "immature": immature,
                                "currentHeight": height,
                                "address": addr
                            },
                            "runtime": 0
                        });

                        return JsonRpcRequest {
                            jsonrpc: "2.0".to_string(),
                            method: "__devnet_precomputed".to_string(),
                            params: vec![result],
                            id: request.id,
                        };
                    }
                }
            }
        }

        request
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
