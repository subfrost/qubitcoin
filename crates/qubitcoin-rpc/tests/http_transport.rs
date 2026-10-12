//! JSON-RPC over HTTP transport parity with Bitcoin Core (httprpc.cpp,
//! rpc/request.cpp): batches, 1.0 vs 2.0 reply shapes, HTTP status codes,
//! notifications.

use std::io::{Read, Write};
use std::net::TcpStream;

use serde_json::{json, Value};

use qubitcoin_rpc::http_server::{RpcServer, RpcServerConfig};
use qubitcoin_rpc::server::{RpcRegistry, RpcRequest, RpcResponse, RPC_MISC_ERROR};

fn start() -> u16 {
    let mut reg = RpcRegistry::new();
    reg.register("ping", |req: &RpcRequest| RpcResponse::success(req.id.clone(), json!("pong")));
    reg.register("nothing", |req: &RpcRequest| RpcResponse::success(req.id.clone(), Value::Null));
    reg.register("fail", |req: &RpcRequest| RpcResponse::error(req.id.clone(), RPC_MISC_ERROR, "boom".into()));
    // A free port picked by the OS (fixed ports collide on shared build hosts).
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let server = RpcServer::new(
        RpcServerConfig { bind_addr: format!("127.0.0.1:{}", port).parse().unwrap(), rpc_user: Some("u".into()), rpc_password: Some("p".into()) },
        reg,
    );
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let _ = server.serve().await;
        })
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    port
}

/// POST `body`; returns (HTTP status, parsed body or Null).
fn post(port: u16, body: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[test]
fn test_transport_parity() {
    let port = start();

    // JSON-RPC 1.0: both members, null result kept; errors map to HTTP codes.
    let (st, v) = post(port, r#"{"method":"nothing","params":[],"id":1}"#);
    assert_eq!(st, 200);
    assert_eq!(v, json!({"result": null, "error": null, "id": 1}));
    let (st, v) = post(port, r#"{"method":"nosuch","id":2}"#);
    assert_eq!(st, 404);
    assert_eq!(v["error"]["code"], json!(-32601));
    assert_eq!(v["result"], Value::Null);
    let (st, v) = post(port, r#"{"method":"fail","id":3}"#);
    assert_eq!(st, 500);
    assert_eq!(v["error"]["message"], json!("boom"));
    let (st, _) = post(port, r#"{"id":4}"#);
    assert_eq!(st, 400);
    let (st, v) = post(port, "{not json");
    assert_eq!(st, 500);
    assert_eq!(v["error"]["code"], json!(-32700));

    // JSON-RPC 2.0: always 200, exactly one of result/error.
    let (st, v) = post(port, r#"{"jsonrpc":"2.0","method":"nosuch","id":5}"#);
    assert_eq!(st, 200);
    assert!(v.get("result").is_none());
    assert_eq!(v["error"]["code"], json!(-32601));
    let (st, v) = post(port, r#"{"jsonrpc":"2.0","method":"nothing","id":6}"#);
    assert_eq!(st, 200);
    assert_eq!(v, json!({"jsonrpc": "2.0", "result": null, "id": 6}));
    // A 2.0 notification gets no body.
    let (st, _) = post(port, r#"{"jsonrpc":"2.0","method":"ping"}"#);
    assert_eq!(st, 204);

    // Batch: 200, one reply per non-notification, each in its own dialect.
    let (st, v) = post(
        port,
        r#"[{"method":"ping","id":"a"},{"jsonrpc":"2.0","method":"fail","id":"b"},{"jsonrpc":"2.0","method":"ping"},{"method":"nosuch","id":"c"},7]"#,
    );
    assert_eq!(st, 200);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 4);
    assert_eq!(arr[0], json!({"result": "pong", "error": null, "id": "a"}));
    assert_eq!(arr[1]["jsonrpc"], json!("2.0"));
    assert_eq!(arr[1]["error"]["message"], json!("boom"));
    assert_eq!(arr[2]["error"]["code"], json!(-32601));
    assert_eq!(arr[3]["error"]["code"], json!(-32600));
}
