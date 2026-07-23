//! qubitcoin-jsonrpc: JSON-RPC reverse proxy
//!
//! Presents the qubitcoind RPC API surface (no auth) and translates:
//!   - secondaryview("alkanes", fn, hex)  → metashrew_view(fn, hex) on metashrew
//!   - secondaryview("esplora", fn, hex)  → esplora REST API
//!   - secondaryview("ord", fn, hex)      → ord REST API
//!   - secondaryview("brc20", fn, hex)    → metashrew_view on brc20 rockshrew
//!   - secondaryheight("alkanes")         → metashrew_height() on metashrew
//!   - secondaryheight("esplora")         → metashrew_height() on metashrew
//!   - Everything else                    → bitcoind (with Basic auth)
//!
//! Environment variables:
//!   LISTEN_ADDR       (default: 0.0.0.0:19443)
//!   BITCOIND_URL      (default: http://localhost:18443)
//!   BITCOIND_USER     (default: bitcoinrpc)
//!   BITCOIND_PASS     (default: bitcoinrpc)
//!   METASHREW_URL     (default: http://localhost:8080)
//!   ESPLORA_URL       (default: http://localhost:50010)
//!   ORD_URL           (default: http://localhost:8090)
//!   ESPO_URL          (default: http://localhost:5778)   — OPI/brc20-prog
//!   BRC20_URL         (default: http://localhost:8082)   — brc20 rockshrew

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
struct Config {
    bitcoind_url: String,
    bitcoind_auth: String, // "Basic <b64>"
    metashrew_url: String,
    esplora_url: String,
    ord_url: String,
    espo_url: String,
    brc20_url: String,
}

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    fn error(id: serde_json::Value, code: i64, msg: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(serde_json::json!({ "code": code, "message": msg })),
        }
    }
}

struct Proxy {
    config: Config,
    client: Client,
}

impl Proxy {
    fn new(config: Config) -> Self {
        Self { config, client: Client::new() }
    }

    /// Forward a JSON-RPC request to bitcoind (with auth).
    async fn forward_bitcoind(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let body = serde_json::json!({
            "jsonrpc": req.jsonrpc.as_deref().unwrap_or("1.0"),
            "id": req.id,
            "method": req.method,
            "params": req.params,
        });

        match self.client.post(&self.config.bitcoind_url)
            .header("Authorization", &self.config.bitcoind_auth)
            .header("Content-Type", "application/json")
            .json(&body)
            .send().await
        {
            Ok(resp) => self.parse_upstream(req.id.clone(), resp).await,
            Err(e) => JsonRpcResponse::error(req.id.clone(), -32603, format!("bitcoind: {e}")),
        }
    }

    /// Forward a JSON-RPC request to metashrew (no auth).
    async fn forward_metashrew(&self, id: serde_json::Value, method: &str, params: serde_json::Value) -> JsonRpcResponse {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        match self.client.post(&self.config.metashrew_url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send().await
        {
            Ok(resp) => self.parse_upstream(id, resp).await,
            Err(e) => JsonRpcResponse::error(id, -32603, format!("metashrew: {e}")),
        }
    }

    async fn parse_upstream(&self, id: serde_json::Value, resp: reqwest::Response) -> JsonRpcResponse {
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return JsonRpcResponse::error(id, -32603, format!("read body: {e}")),
        };
        let parsed: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return JsonRpcResponse::error(id, -32603, format!("parse: {e}")),
        };

        // Check for upstream error
        if let Some(err) = parsed.get("error") {
            if !err.is_null() {
                return JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: None,
                    error: Some(err.clone()),
                };
            }
        }

        if let Some(result) = parsed.get("result") {
            JsonRpcResponse::success(id, result.clone())
        } else {
            JsonRpcResponse::error(id, -32603, "no result field in upstream response".into())
        }
    }

    /// Forward a JSON-RPC request to a generic metashrew-compatible backend (no auth).
    async fn forward_rockshrew(&self, url: &str, id: serde_json::Value, method: &str, params: serde_json::Value) -> JsonRpcResponse {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        match self.client.post(url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send().await
        {
            Ok(resp) => self.parse_upstream(id, resp).await,
            Err(e) => JsonRpcResponse::error(id, -32603, format!("rockshrew({url}): {e}")),
        }
    }

    /// Route a request.
    async fn handle(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "secondaryview" => self.handle_secondaryview(req).await,
            "secondaryheight" => self.handle_secondaryheight(req).await,
            "tertiaryview" => self.handle_tertiaryview(req).await,
            "tertiaryheight" => self.handle_tertiaryheight(req).await,
            _ => self.forward_bitcoind(&req).await,
        }
    }

    /// secondaryview ["label", "view_fn", "input_hex"]
    /// → metashrew_view ["view_fn", "input_hex"]
    async fn handle_secondaryview(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let params = match req.params.as_array() {
            Some(a) => a,
            None => return JsonRpcResponse::error(req.id, -32602, "params must be an array".into()),
        };

        if params.len() < 3 {
            return JsonRpcResponse::error(req.id, -32602,
                format!("secondaryview requires [label, view_fn, input_hex], got {} params", params.len()));
        }

        let label = params[0].as_str().unwrap_or("");
        let view_fn = &params[1];
        let input_hex = &params[2];

        log::debug!("secondaryview label={label} fn={view_fn} input_len={}",
            input_hex.as_str().map(|s| s.len()).unwrap_or(0));

        match label {
            "alkanes" => {
                // Forward to metashrew_view on alkanes rockshrew
                let ms_params = serde_json::json!([view_fn, input_hex]);
                self.forward_metashrew(req.id, "metashrew_view", ms_params).await
            }
            "esplora" => {
                // Translate esplorashrew view functions to esplora REST API calls
                let fn_name = view_fn.as_str().unwrap_or("");
                let hex_input = input_hex.as_str().unwrap_or("");
                self.handle_esplora_view(req.id, fn_name, hex_input).await
            }
            "ord" => {
                // Forward to ord REST API
                let fn_name = view_fn.as_str().unwrap_or("");
                let hex_input = input_hex.as_str().unwrap_or("");
                self.handle_ord_view(req.id, fn_name, hex_input).await
            }
            "brc20" => {
                // Forward to brc20 rockshrew via metashrew_view
                let ms_params = serde_json::json!([view_fn, input_hex]);
                self.forward_rockshrew(&self.config.brc20_url, req.id, "metashrew_view", ms_params).await
            }
            other => {
                log::warn!("secondaryview: unknown label '{other}', forwarding to metashrew");
                let ms_params = serde_json::json!([view_fn, input_hex]);
                self.forward_metashrew(req.id, "metashrew_view", ms_params).await
            }
        }
    }

    /// Handle ord label view functions by translating to ord REST API.
    async fn handle_ord_view(&self, id: serde_json::Value, fn_name: &str, hex_input: &str) -> JsonRpcResponse {
        let clean_hex = hex_input.strip_prefix("0x").unwrap_or(hex_input);
        let input_text = if clean_hex.is_empty() {
            String::new()
        } else {
            match hex::decode(clean_hex) {
                Ok(b) => String::from_utf8_lossy(&b).to_string(),
                Err(e) => return JsonRpcResponse::error(id, -32602, format!("invalid hex: {e}")),
            }
        };

        let path = match fn_name {
            "inscription" => format!("/inscription/{}", input_text),
            "inscriptions" => format!("/inscriptions/{}", input_text),
            "content" => format!("/content/{}", input_text),
            "sat" => format!("/sat/{}", input_text),
            "output" => format!("/output/{}", input_text),
            "block" => format!("/block/{}", input_text),
            other => return JsonRpcResponse::error(id, -32601, format!("unknown ord view: {other}")),
        };

        let url = format!("{}{}", self.config.ord_url, path);
        log::info!("ord GET {url}");

        match self.client.get(&url).header("Accept", "application/json").send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    let hex_body = format!("0x{}", hex::encode(body.as_bytes()));
                    JsonRpcResponse::success(id, serde_json::Value::String(hex_body))
                }
                Err(e) => JsonRpcResponse::error(id, -32603, format!("ord read: {e}")),
            },
            Err(e) => JsonRpcResponse::error(id, -32603, format!("ord request: {e}")),
        }
    }

    /// tertiaryview ["label", "view_fn", "input_hex"]
    /// Routes to espo (OPI / brc20-prog) backend.
    async fn handle_tertiaryview(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let params = match req.params.as_array() {
            Some(a) => a,
            None => return JsonRpcResponse::error(req.id, -32602, "params must be an array".into()),
        };

        if params.len() < 3 {
            return JsonRpcResponse::error(req.id, -32602,
                format!("tertiaryview requires [label, view_fn, input_hex], got {} params", params.len()));
        }

        let label = params[0].as_str().unwrap_or("");
        let view_fn = &params[1];
        let input_hex = &params[2];

        log::info!("tertiaryview label={label} fn={view_fn}");

        match label {
            "espo" | "brc20-prog" | "opi" => {
                let ms_params = serde_json::json!([view_fn, input_hex]);
                self.forward_rockshrew(&self.config.espo_url, req.id, "metashrew_view", ms_params).await
            }
            other => {
                log::warn!("tertiaryview: unknown label '{other}', forwarding to espo");
                let ms_params = serde_json::json!([view_fn, input_hex]);
                self.forward_rockshrew(&self.config.espo_url, req.id, "metashrew_view", ms_params).await
            }
        }
    }

    /// tertiaryheight ["label"]
    async fn handle_tertiaryheight(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let label = req.params.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("espo");

        log::info!("tertiaryheight label={label}");

        self.forward_rockshrew(&self.config.espo_url, req.id, "metashrew_height", serde_json::json!([])).await
    }

    /// Handle esplora label view functions by translating to esplora REST API.
    ///
    /// esplorashrew input format: the input_hex is hex-encoded text (e.g. hex of "abcdef...").
    /// The secondaryview call hex-decodes it to get the text, then uses it as the API param.
    ///
    /// Response: the JSON body is hex-encoded and returned as the RPC result string.
    async fn handle_esplora_view(&self, id: serde_json::Value, fn_name: &str, hex_input: &str) -> JsonRpcResponse {
        // Strip 0x prefix if present, handle empty input for views like tipheight
        let clean_hex = hex_input.strip_prefix("0x").unwrap_or(hex_input);
        if clean_hex.is_empty() || fn_name == "tipheight" {
            // No input needed — just fetch the endpoint
            let path = match fn_name {
                "tipheight" => "/blocks/tip/height".to_string(),
                other => return JsonRpcResponse::error(id, -32601, format!("unknown esplora view: {other}")),
            };
            let url = format!("{}{}", self.config.esplora_url, path);
            log::info!("esplora GET {url}");
            return match self.client.get(&url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(body) => {
                        let hex_body = format!("0x{}", hex::encode(body.as_bytes()));
                        JsonRpcResponse::success(id, serde_json::Value::String(hex_body))
                    }
                    Err(e) => JsonRpcResponse::error(id, -32603, format!("esplora read: {e}")),
                },
                Err(e) => JsonRpcResponse::error(id, -32603, format!("esplora request: {e}")),
            };
        }

        // Decode the hex input to get the text parameter
        let input_bytes = match hex::decode(clean_hex) {
            Ok(b) => b,
            Err(e) => return JsonRpcResponse::error(id, -32602, format!("invalid hex input: {e}")),
        };
        let input_text = String::from_utf8_lossy(&input_bytes);

        // The signal programs follow Electrum convention and pre-reverse the
        // scripthash bytes (sha256(scriptPubKey) reversed). Modern esplora REST
        // expects forward byte order, so reverse them back.
        let input_str = input_text.to_string();
        let scripthash = if input_str.len() == 64 && input_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: Vec<u8> = (0..32).map(|i| {
                u8::from_str_radix(&input_str[i*2..i*2+2], 16).unwrap_or(0)
            }).collect();
            let reversed: Vec<u8> = bytes.into_iter().rev().collect();
            hex::encode(&reversed)
        } else {
            input_str
        };

        let path = match fn_name {
            "utxosbyscripthash" => format!("/scripthash/{}/utxo", scripthash),
            "txsbyscripthash" => format!("/scripthash/{}/txs", scripthash),
            "scripthashbalance" => format!("/scripthash/{}", scripthash),
            "tipheight" => "/blocks/tip/height".to_string(),
            other => {
                return JsonRpcResponse::error(id, -32601, format!("unknown esplora view: {other}"));
            }
        };

        let url = format!("{}{}", self.config.esplora_url, path);
        log::info!("esplora GET {url}");

        match self.client.get(&url).send().await {
            Ok(resp) => {
                match resp.text().await {
                    Ok(body) => {
                        // Return as "0x" + hex-encoded body (matching esplorashrew/secondaryview format)
                        let hex_body = format!("0x{}", hex::encode(body.as_bytes()));
                        JsonRpcResponse::success(id, serde_json::Value::String(hex_body))
                    }
                    Err(e) => JsonRpcResponse::error(id, -32603, format!("esplora read: {e}")),
                }
            }
            Err(e) => JsonRpcResponse::error(id, -32603, format!("esplora request: {e}")),
        }
    }

    /// secondaryheight ["label"]
    /// → metashrew_height []
    async fn handle_secondaryheight(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let label = req.params.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("alkanes");

        log::debug!("secondaryheight label={label}");

        self.forward_metashrew(req.id, "metashrew_height", serde_json::json!([])).await
    }
}

async fn handle_request(
    req: Request<Incoming>,
    proxy: Arc<Proxy>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Collect the body
    let body_bytes = req.into_body().collect().await?.to_bytes();

    let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = JsonRpcResponse::error(serde_json::Value::Null, -32700, format!("parse error: {e}"));
            let json = serde_json::to_vec(&resp).unwrap();
            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(json)))
                .unwrap());
        }
    };

    log::info!("{} params={}", rpc_req.method,
        serde_json::to_string(&rpc_req.params).unwrap_or_default().chars().take(200).collect::<String>());

    let resp = proxy.handle(rpc_req).await;
    let json = serde_json::to_vec(&resp).unwrap();

    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:19443".into())
        .parse()?;

    let bitcoind_url = env::var("BITCOIND_URL").unwrap_or_else(|_| "http://localhost:18443".into());
    let bitcoind_user = env::var("BITCOIND_USER").unwrap_or_else(|_| "bitcoinrpc".into());
    let bitcoind_pass = env::var("BITCOIND_PASS").unwrap_or_else(|_| "bitcoinrpc".into());
    let metashrew_url = env::var("METASHREW_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let esplora_url = env::var("ESPLORA_URL").unwrap_or_else(|_| "http://localhost:50010".into());
    let ord_url = env::var("ORD_URL").unwrap_or_else(|_| "http://localhost:8090".into());
    let espo_url = env::var("ESPO_URL").unwrap_or_else(|_| "http://localhost:5778".into());
    let brc20_url = env::var("BRC20_URL").unwrap_or_else(|_| "http://localhost:8082".into());

    let auth_b64 = base64::engine::general_purpose::STANDARD
        .encode(format!("{bitcoind_user}:{bitcoind_pass}"));

    let config = Config {
        bitcoind_url,
        bitcoind_auth: format!("Basic {auth_b64}"),
        metashrew_url,
        esplora_url,
        ord_url,
        espo_url,
        brc20_url,
    };

    log::info!("qubitcoin-jsonrpc starting on {listen_addr}");
    log::info!("  bitcoind  → {}", config.bitcoind_url);
    log::info!("  metashrew → {}", config.metashrew_url);
    log::info!("  esplora   → {}", config.esplora_url);
    log::info!("  ord       → {}", config.ord_url);
    log::info!("  espo      → {}", config.espo_url);
    log::info!("  brc20     → {}", config.brc20_url);

    let proxy = Arc::new(Proxy::new(config));
    let listener = TcpListener::bind(listen_addr).await?;

    log::info!("Listening on {listen_addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let proxy = proxy.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                handle_request(req, proxy)
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                log::error!("Connection error from {addr}: {e}");
            }
        });
    }
}
