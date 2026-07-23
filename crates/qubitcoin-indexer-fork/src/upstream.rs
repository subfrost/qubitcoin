//! Read-through upstream KV source.
//!
//! When the WASM calls `__get`/`__get_len` and the in-memory storage
//! doesn't have a key, the host functions consult a [`ForkUpstream`]
//! to fetch the value from a confirmed-state indexer (typically
//! `metashrew_view "getstorageat"` JSON-RPC against
//! `https://mainnet.subfrost.io/v4/subfrost`).
//!
//! The trait is async because the canonical upstream is over HTTP;
//! for tests and tight loops, [`testing::StubUpstream`] is a sync
//! HashMap-backed impl.

use async_trait::async_trait;

/// An async key-value source. Implementors typically wrap a JSON-RPC
/// client that exposes the indexer's confirmed key-value store.
///
/// `fetch` distinguishes:
///   * `Ok(Some(v))` — upstream knows the key and returned `v`.
///   * `Ok(None)`    — upstream confirms the key is genuinely absent.
///   * `Err(e)`      — transient or permanent failure (network, parse,
///                     auth). Callers may surface this to WASM as an
///                     "absent" key (matches the empty-projection
///                     semantics for novel outpoints) or propagate.
#[async_trait]
pub trait ForkUpstream: Send + Sync {
    /// Fetch the value associated with `key`, if any.
    async fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;

    /// Upstream's current confirmed tip height. Used to derive the
    /// projected tip (`tip + 1`) when constructing fork-mode storage.
    async fn tip_height(&self) -> Result<u32, String> {
        Ok(0)
    }
}

// -- HTTP impl ---------------------------------------------------------------
//
// Calls metashrew_view "getstorageat" via JSON-RPC. The payload format
// is the standard JSON-RPC 2.0 envelope; the result is the hex-encoded
// value bytes (or null for missing).

#[cfg(feature = "http-upstream")]
pub use http::HttpForkUpstream;

#[cfg(feature = "http-upstream")]
mod http {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// HTTP-backed upstream that calls `metashrew_view "getstorageat"`.
    ///
    /// Default URL: `https://mainnet.subfrost.io/v4/subfrost`. Override
    /// via [`HttpForkUpstream::with_url`].
    pub struct HttpForkUpstream {
        client: reqwest::Client,
        url: String,
    }

    impl HttpForkUpstream {
        pub fn new() -> Result<Self, String> {
            Self::with_url("https://mainnet.subfrost.io/v4/subfrost".into())
        }

        pub fn with_url(url: String) -> Result<Self, String> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| format!("HttpForkUpstream client: {}", e))?;
            Ok(Self { client, url })
        }

        pub fn url(&self) -> &str {
            &self.url
        }
    }

    #[derive(Serialize)]
    struct JsonRpcReq<'a> {
        jsonrpc: &'a str,
        id: u32,
        method: &'a str,
        params: Vec<serde_json::Value>,
    }

    #[derive(Deserialize)]
    struct JsonRpcResp {
        #[serde(default)]
        result: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<serde_json::Value>,
    }

    // -- alkanes-side getstorageat protobuf shape ----------------------
    //
    // The remote `metashrew_view "getstorageat"` is the alkanes
    // view-function in `alkanes-rs/src/view.rs:402`, NOT a generic
    // raw-kv getter. It expects a prost-encoded `AlkaneStorageRequest`:
    //
    //   message AlkaneStorageRequest { AlkaneId id = 1; bytes path = 2; }
    //   message AlkaneId { Uint128 block = 1; Uint128 tx = 2; }
    //   message Uint128 { uint64 lo = 1; uint64 hi = 2; }
    //
    // Inside the view fn, `req.id.clone().unwrap()` panics whenever the
    // input doesn't decode to `Some(id)`. Sending the raw IndexPointer
    // key as the payload (as this fork did pre-fix) decodes to the
    // default — id None, path [] — and triggers that unwrap. The bug
    // shows up in the indexer's logs as
    //   `unwrap_failed → getstorageat`
    // and the trace stack ending at `alkanes.wasm!getstorageat`.
    //
    // We hand-inline the four message types here rather than depend on
    // `alkanes-support` so this fork stays generic. The WASM ALWAYS
    // composes storage keys as `/alkanes/{id_bytes}/storage/{path}`
    // where `id_bytes` is 32 bytes (block_le16 + tx_le16) — see
    // `AlkaneId: Into<Vec<u8>>` in alkanes-support. Keys that don't
    // match this shape get `Ok(None)` (treated as absent), matching
    // the pre-fix behaviour for genuine misses.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct AlkanesViewUint128 {
        #[prost(uint64, tag = "1")]
        lo: u64,
        #[prost(uint64, tag = "2")]
        hi: u64,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct AlkanesViewAlkaneId {
        #[prost(message, optional, tag = "1")]
        block: Option<AlkanesViewUint128>,
        #[prost(message, optional, tag = "2")]
        tx:    Option<AlkanesViewUint128>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct AlkanesViewStorageRequest {
        #[prost(message, optional, tag = "1")]
        id:   Option<AlkanesViewAlkaneId>,
        #[prost(bytes = "vec", tag = "2")]
        path: Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct AlkanesViewStorageResponse {
        #[prost(bytes = "vec", tag = "1")]
        value: Vec<u8>,
    }

    const ALKANES_KEY_PREFIX:    &[u8] = b"/alkanes/";
    const ALKANES_STORAGE_INNER: &[u8] = b"/storage/";

    /// Try to parse `key` as the IndexPointer-composed shape
    /// `b"/alkanes/" ++ <32-byte id> ++ b"/storage/" ++ <path>`. Returns
    /// `(block, tx, path_bytes)` on a match.
    fn parse_alkane_storage_key(key: &[u8]) -> Option<(u128, u128, Vec<u8>)> {
        if !key.starts_with(ALKANES_KEY_PREFIX) {
            return None;
        }
        let after_prefix = &key[ALKANES_KEY_PREFIX.len()..];
        if after_prefix.len() < 32 {
            return None;
        }
        let id_bytes = &after_prefix[..32];
        let rest     = &after_prefix[32..];
        if !rest.starts_with(ALKANES_STORAGE_INNER) {
            return None;
        }
        let path = rest[ALKANES_STORAGE_INNER.len()..].to_vec();
        let mut block_buf = [0u8; 16];
        block_buf.copy_from_slice(&id_bytes[..16]);
        let mut tx_buf = [0u8; 16];
        tx_buf.copy_from_slice(&id_bytes[16..]);
        let block = u128::from_le_bytes(block_buf);
        let tx    = u128::from_le_bytes(tx_buf);
        Some((block, tx, path))
    }

    fn split_u128_lo_hi(v: u128) -> (u64, u64) {
        ((v as u64), ((v >> 64) as u64))
    }

    #[async_trait]
    impl ForkUpstream for HttpForkUpstream {
        async fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            // Decode the IndexPointer key. If it doesn't match the
            // alkanes shape we treat it as absent — the view function
            // we proxy through has no notion of generic raw-kv keys.
            let (block, tx, path) = match parse_alkane_storage_key(key) {
                Some(p) => p,
                None    => return Ok(None),
            };
            let (block_lo, block_hi) = split_u128_lo_hi(block);
            let (tx_lo,    tx_hi)    = split_u128_lo_hi(tx);
            let request = AlkanesViewStorageRequest {
                id: Some(AlkanesViewAlkaneId {
                    block: Some(AlkanesViewUint128 { lo: block_lo, hi: block_hi }),
                    tx:    Some(AlkanesViewUint128 { lo: tx_lo,    hi: tx_hi    }),
                }),
                path,
            };
            use prost::Message;
            let hex_input = format!("0x{}", hex::encode(request.encode_to_vec()));
            let req = JsonRpcReq {
                jsonrpc: "2.0",
                id: 0,
                method: "metashrew_view",
                params: vec![
                    serde_json::Value::String("getstorageat".into()),
                    serde_json::Value::String(hex_input),
                    serde_json::Value::String("latest".into()),
                ],
            };
            let resp: JsonRpcResp = self
                .client
                .post(&self.url)
                .json(&req)
                .send()
                .await
                .map_err(|e| format!("upstream send: {}", e))?
                .json()
                .await
                .map_err(|e| format!("upstream parse: {}", e))?;

            if let Some(err) = resp.error {
                return Err(format!("upstream rpc error: {}", err));
            }
            // `getstorageat` returns the prost-encoded
            // `AlkaneStorageResponse { bytes value = 1 }` as hex. An
            // empty response or a default-encoded one both correspond
            // to "key absent" — we surface that as `Ok(None)` so the
            // WASM's __get_len call returns 0 and the trace continues.
            let hex_str = match resp.result {
                None | Some(serde_json::Value::Null) => return Ok(None),
                Some(serde_json::Value::String(s))   => s,
                Some(other) => return Err(format!("upstream unexpected result: {}", other)),
            };
            let trimmed = hex_str.trim_start_matches("0x");
            if trimmed.is_empty() {
                return Ok(None);
            }
            let bytes = hex::decode(trimmed)
                .map_err(|e| format!("upstream decode hex: {}", e))?;
            if bytes.is_empty() {
                return Ok(None);
            }
            let decoded = AlkanesViewStorageResponse::decode(&*bytes)
                .map_err(|e| format!("upstream decode response: {}", e))?;
            if decoded.value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(decoded.value))
            }
        }

        async fn tip_height(&self) -> Result<u32, String> {
            let req = JsonRpcReq {
                jsonrpc: "2.0",
                id: 0,
                method: "metashrew_height",
                params: vec![],
            };
            let resp: JsonRpcResp = self
                .client
                .post(&self.url)
                .json(&req)
                .send()
                .await
                .map_err(|e| format!("tip send: {}", e))?
                .json()
                .await
                .map_err(|e| format!("tip parse: {}", e))?;

            if let Some(err) = resp.error {
                return Err(format!("tip rpc error: {}", err));
            }
            match resp.result {
                Some(serde_json::Value::Number(n)) => n
                    .as_u64()
                    .map(|x| x as u32)
                    .ok_or_else(|| "tip not u64".into()),
                Some(serde_json::Value::String(s)) => s
                    .trim_start_matches("0x")
                    .parse::<u32>()
                    .or_else(|_| {
                        u32::from_str_radix(s.trim_start_matches("0x"), 16)
                            .map_err(|e| format!("tip parse {}: {}", s, e))
                    })
                    .map_err(|e| format!("tip parse: {}", e)),
                _ => Err("tip missing".into()),
            }
        }
    }
}

// -- Test stubs --------------------------------------------------------------

pub mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// HashMap-backed upstream for tests. `Ok(Some(v))` for known keys,
    /// `Ok(None)` for absent keys. Records every fetch call for assertions.
    pub struct StubUpstream {
        kv: HashMap<Vec<u8>, Vec<u8>>,
        tip: u32,
        fetch_count: Arc<AtomicUsize>,
    }

    impl StubUpstream {
        pub fn new(kv: HashMap<Vec<u8>, Vec<u8>>) -> Self {
            Self {
                kv,
                tip: 0,
                fetch_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub fn with_tip(mut self, tip: u32) -> Self {
            self.tip = tip;
            self
        }

        pub fn fetch_counter(&self) -> Arc<AtomicUsize> {
            self.fetch_count.clone()
        }
    }

    #[async_trait]
    impl ForkUpstream for StubUpstream {
        async fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.kv.get(key).cloned())
        }

        async fn tip_height(&self) -> Result<u32, String> {
            Ok(self.tip)
        }
    }

    /// Upstream that always errors. Used to verify error paths.
    pub struct ErrorUpstream {
        pub message: String,
    }

    #[async_trait]
    impl ForkUpstream for ErrorUpstream {
        async fn fetch(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Err(self.message.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{ErrorUpstream, StubUpstream};
    use super::ForkUpstream;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn stub_returns_configured_value() {
        let mut kv = HashMap::new();
        kv.insert(b"hello".to_vec(), b"world".to_vec());
        let up = StubUpstream::new(kv);
        let r = rt();
        let v = r.block_on(up.fetch(b"hello")).unwrap();
        assert_eq!(v, Some(b"world".to_vec()));
    }

    #[test]
    fn stub_returns_none_for_missing_key() {
        let up = StubUpstream::new(HashMap::new());
        let r = rt();
        assert!(r.block_on(up.fetch(b"absent")).unwrap().is_none());
    }

    #[test]
    fn stub_records_fetch_count() {
        let up = StubUpstream::new(HashMap::new());
        let counter = up.fetch_counter();
        let r = rt();
        r.block_on(up.fetch(b"a")).unwrap();
        r.block_on(up.fetch(b"b")).unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stub_tip_is_configurable() {
        let up = StubUpstream::new(HashMap::new()).with_tip(99);
        let r = rt();
        assert_eq!(r.block_on(up.tip_height()).unwrap(), 99);
    }

    #[test]
    fn error_upstream_propagates_error() {
        let up = ErrorUpstream {
            message: "boom".into(),
        };
        let r = rt();
        let err = r.block_on(up.fetch(b"k")).unwrap_err();
        assert_eq!(err, "boom");
    }
}
