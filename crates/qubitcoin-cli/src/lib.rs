// Copyright (c) 2024 The Qubitcoin developers
// Distributed under the MIT software license.

//! qubitcoin-cli: CLI client library for Qubitcoin.
//!
//! Provides utilities for building JSON-RPC requests, parsing responses,
//! and formatting results for terminal display.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for connecting to a Qubitcoin RPC server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// The URL of the JSON-RPC endpoint (e.g. `http://127.0.0.1:8332`).
    pub rpc_url: String,
    /// Optional username for HTTP basic authentication.
    pub rpc_user: Option<String>,
    /// Optional password for HTTP basic authentication.
    pub rpc_password: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        CliConfig {
            rpc_url: "http://127.0.0.1:8332".to_string(),
            rpc_user: None,
            rpc_password: None,
        }
    }
}

impl CliConfig {
    /// Create a new configuration with explicit values.
    pub fn new(rpc_url: String, rpc_user: Option<String>, rpc_password: Option<String>) -> Self {
        CliConfig {
            rpc_url,
            rpc_user,
            rpc_password,
        }
    }

    /// Return `true` if authentication credentials are configured.
    pub fn has_auth(&self) -> bool {
        self.rpc_user.is_some() && self.rpc_password.is_some()
    }
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

/// Build a JSON-RPC 2.0 request string.
///
/// # Arguments
///
/// * `method` - The RPC method name (e.g. `"getblockcount"`).
/// * `params` - Positional parameters as a `Vec<Value>`.
///
/// # Returns
///
/// A JSON string ready to send over HTTP.
pub fn build_request(method: &str, params: Vec<Value>) -> String {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    serde_json::to_string(&request).expect("failed to serialize RPC request")
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Parse a JSON-RPC response string.
///
/// On success, returns the `result` field. On error (either a JSON-RPC error
/// object or a malformed response), returns an `Err` with a human-readable
/// message.
pub fn parse_response(response: &str) -> Result<Value, String> {
    let parsed: Value =
        serde_json::from_str(response).map_err(|e| format!("Failed to parse response: {}", e))?;

    // Check for JSON-RPC error.
    if let Some(error) = parsed.get("error") {
        if !error.is_null() {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            return Err(format!("RPC error {}: {}", code, message));
        }
    }

    // Extract the result.
    match parsed.get("result") {
        Some(result) => Ok(result.clone()),
        None => Err("Response missing 'result' field".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Result formatting
// ---------------------------------------------------------------------------

/// Format a JSON value for human-readable terminal display.
///
/// - Strings are printed without surrounding quotes.
/// - Numbers, booleans, and null are printed as-is.
/// - Objects and arrays are pretty-printed with 2-space indentation.
pub fn format_result(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{:?}", value)),
    }
}

// ---------------------------------------------------------------------------
// CLI argument parsing (lightweight, no external dep)
// ---------------------------------------------------------------------------

/// Parsed command-line arguments.
#[derive(Debug)]
pub struct CliArgs {
    /// RPC configuration.
    pub config: CliConfig,
    /// The RPC method to call.
    pub method: Option<String>,
    /// Positional parameters for the RPC method.
    pub params: Vec<Value>,
    /// Whether `--help` was requested.
    pub help: bool,
}

/// Parse command-line arguments into a [`CliArgs`] struct.
///
/// Recognized flags:
/// - `-rpcconnect=HOST` or `--rpcconnect=HOST`
/// - `-rpcport=PORT`   or `--rpcport=PORT`
/// - `-rpcuser=USER`   or `--rpcuser=USER`
/// - `-rpcpassword=PW` or `--rpcpassword=PW`
/// - `--help` / `-h`
///
/// The first non-flag argument is the method name; all subsequent non-flag
/// arguments are parameters. Numeric strings are sent as numbers, `true`/
/// `false` as booleans, otherwise as strings.
pub fn parse_args(args: &[String]) -> CliArgs {
    let mut config = CliConfig::default();
    let mut method: Option<String> = None;
    let mut params: Vec<Value> = Vec::new();
    let mut help = false;

    let mut rpc_host = "127.0.0.1".to_string();
    let mut rpc_port: u16 = 8332;

    for arg in args {
        if arg == "--help" || arg == "-h" || arg == "-?" {
            help = true;
            continue;
        }

        // Handle -key=value or --key=value flags.
        let stripped = arg.trim_start_matches('-');
        if let Some((key, value)) = stripped.split_once('=') {
            match key {
                "rpcconnect" => rpc_host = value.to_string(),
                "rpcport" => {
                    if let Ok(p) = value.parse::<u16>() {
                        rpc_port = p;
                    }
                }
                "rpcuser" => config.rpc_user = Some(value.to_string()),
                "rpcpassword" => config.rpc_password = Some(value.to_string()),
                _ => {
                    // Unknown flag -- treat as positional if method is set.
                    if method.is_none() {
                        method = Some(arg.clone());
                    } else {
                        params.push(coerce_param(arg));
                    }
                }
            }
            continue;
        }

        // Positional argument.
        if method.is_none() {
            method = Some(arg.clone());
        } else {
            params.push(coerce_param(arg));
        }
    }

    config.rpc_url = format!("http://{}:{}", rpc_host, rpc_port);

    CliArgs {
        config,
        method,
        params,
        help,
    }
}

/// Attempt to coerce a string parameter into a more specific JSON type.
fn coerce_param(s: &str) -> Value {
    // Try boolean.
    if s == "true" {
        return Value::Bool(true);
    }
    if s == "false" {
        return Value::Bool(false);
    }
    // Try integer.
    if let Ok(n) = s.parse::<i64>() {
        return Value::Number(serde_json::Number::from(n));
    }
    // Try float (only if it contains a dot to avoid matching ints).
    if s.contains('.') {
        if let Ok(f) = s.parse::<f64>() {
            if let Some(n) = serde_json::Number::from_f64(f) {
                return Value::Number(n);
            }
        }
    }
    // Try JSON array/object.
    if (s.starts_with('[') && s.ends_with(']')) || (s.starts_with('{') && s.ends_with('}')) {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            return v;
        }
    }
    // Fall back to string.
    Value::String(s.to_string())
}

/// Return the usage/help string.
pub fn usage() -> &'static str {
    "\
Usage: qubitcoin-cli [options] <command> [params]

Options:
  -rpcconnect=<ip>    Connect to RPC server at <ip> (default: 127.0.0.1)
  -rpcport=<port>     Connect to RPC server on <port> (default: 8332)
  -rpcuser=<user>     Username for RPC authentication
  -rpcpassword=<pw>   Password for RPC authentication
  -h, --help          Show this help message

Commands:
  getblockchaininfo         Return blockchain state info
  getblockcount             Return the current block height
  getblockhash <height>     Return block hash at given height
  getblock <hash>           Return block data
  getbestblockhash          Return the tip block hash
  getdifficulty             Return current difficulty
  getmininginfo             Return mining info
  getnetworkinfo            Return network info
  getpeerinfo               Return connected peer info
  getconnectioncount        Return number of connections
  getmempoolinfo            Return mempool state info
  getrawmempool [verbose]   Return mempool transaction ids
  validateaddress <addr>    Validate an address
  help [command]            List commands or get help for one
  stop                      Stop the server

For more information, use: qubitcoin-cli help"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- CliConfig --

    #[test]
    fn test_cli_config_default() {
        let cfg = CliConfig::default();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:8332");
        assert!(cfg.rpc_user.is_none());
        assert!(cfg.rpc_password.is_none());
        assert!(!cfg.has_auth());
    }

    #[test]
    fn test_cli_config_with_auth() {
        let cfg = CliConfig::new(
            "http://localhost:18332".into(),
            Some("user".into()),
            Some("pass".into()),
        );
        assert!(cfg.has_auth());
        assert_eq!(cfg.rpc_url, "http://localhost:18332");
    }

    // -- build_request --

    #[test]
    fn test_build_request_no_params() {
        let req = build_request("getblockcount", vec![]);
        let parsed: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["method"], "getblockcount");
        assert_eq!(parsed["params"], json!([]));
        assert_eq!(parsed["id"], 1);
    }

    #[test]
    fn test_build_request_with_params() {
        let req = build_request("getblockhash", vec![json!(100)]);
        let parsed: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(parsed["method"], "getblockhash");
        assert_eq!(parsed["params"], json!([100]));
    }

    #[test]
    fn test_build_request_multiple_params() {
        let req = build_request("generatetoaddress", vec![json!(10), json!("qc1qaddr")]);
        let parsed: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(parsed["params"][0], 10);
        assert_eq!(parsed["params"][1], "qc1qaddr");
    }

    #[test]
    fn test_build_request_is_valid_json() {
        let req = build_request("help", vec![json!("getblock")]);
        assert!(serde_json::from_str::<Value>(&req).is_ok());
    }

    // -- parse_response --

    #[test]
    fn test_parse_response_success() {
        let raw = r#"{"jsonrpc":"2.0","result":42,"id":1}"#;
        let result = parse_response(raw).unwrap();
        assert_eq!(result, json!(42));
    }

    #[test]
    fn test_parse_response_success_object() {
        let raw = r#"{"jsonrpc":"2.0","result":{"blocks":100},"id":1}"#;
        let result = parse_response(raw).unwrap();
        assert_eq!(result["blocks"], 100);
    }

    #[test]
    fn test_parse_response_success_null_result() {
        let raw = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        let result = parse_response(raw).unwrap();
        assert_eq!(result, json!(null));
    }

    #[test]
    fn test_parse_response_error() {
        let raw =
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}"#;
        let result = parse_response(raw);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("-32601"));
        assert!(err.contains("Method not found"));
    }

    #[test]
    fn test_parse_response_null_error_field() {
        // error: null should be treated as success.
        let raw = r#"{"jsonrpc":"2.0","result":"ok","error":null,"id":1}"#;
        let result = parse_response(raw).unwrap();
        assert_eq!(result, json!("ok"));
    }

    #[test]
    fn test_parse_response_invalid_json() {
        let result = parse_response("not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_parse_response_missing_result() {
        let raw = r#"{"jsonrpc":"2.0","id":1}"#;
        let result = parse_response(raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'result'"));
    }

    // -- format_result --

    #[test]
    fn test_format_result_string() {
        assert_eq!(format_result(&json!("hello")), "hello");
    }

    #[test]
    fn test_format_result_number() {
        assert_eq!(format_result(&json!(42)), "42");
    }

    #[test]
    fn test_format_result_float() {
        assert_eq!(format_result(&json!(1.5)), "1.5");
    }

    #[test]
    fn test_format_result_bool() {
        assert_eq!(format_result(&json!(true)), "true");
        assert_eq!(format_result(&json!(false)), "false");
    }

    #[test]
    fn test_format_result_null() {
        assert_eq!(format_result(&json!(null)), "null");
    }

    #[test]
    fn test_format_result_object() {
        let val = json!({"key": "value"});
        let formatted = format_result(&val);
        assert!(formatted.contains("\"key\""));
        assert!(formatted.contains("\"value\""));
        // Should be pretty-printed (multi-line).
        assert!(formatted.contains('\n'));
    }

    #[test]
    fn test_format_result_array() {
        let val = json!([1, 2, 3]);
        let formatted = format_result(&val);
        assert!(formatted.contains('1'));
        assert!(formatted.contains('2'));
        assert!(formatted.contains('3'));
    }

    // -- parse_args --

    #[test]
    fn test_parse_args_simple_method() {
        let args: Vec<String> = vec!["getblockcount".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.method, Some("getblockcount".into()));
        assert!(parsed.params.is_empty());
        assert!(!parsed.help);
    }

    #[test]
    fn test_parse_args_method_with_params() {
        let args: Vec<String> = vec!["getblockhash".into(), "100".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.method, Some("getblockhash".into()));
        assert_eq!(parsed.params, vec![json!(100)]);
    }

    #[test]
    fn test_parse_args_bool_params() {
        let args: Vec<String> = vec!["getrawmempool".into(), "true".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.params, vec![json!(true)]);
    }

    #[test]
    fn test_parse_args_string_param() {
        let args: Vec<String> = vec!["getblock".into(), "abc123def".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.params, vec![json!("abc123def")]);
    }

    #[test]
    fn test_parse_args_help() {
        let args: Vec<String> = vec!["--help".into()];
        let parsed = parse_args(&args);
        assert!(parsed.help);
        assert!(parsed.method.is_none());
    }

    #[test]
    fn test_parse_args_rpc_flags() {
        let args: Vec<String> = vec![
            "-rpcconnect=192.168.1.1".into(),
            "-rpcport=18332".into(),
            "-rpcuser=alice".into(),
            "-rpcpassword=secret".into(),
            "getinfo".into(),
        ];
        let parsed = parse_args(&args);
        assert_eq!(parsed.config.rpc_url, "http://192.168.1.1:18332");
        assert_eq!(parsed.config.rpc_user, Some("alice".into()));
        assert_eq!(parsed.config.rpc_password, Some("secret".into()));
        assert_eq!(parsed.method, Some("getinfo".into()));
    }

    #[test]
    fn test_parse_args_no_args() {
        let args: Vec<String> = vec![];
        let parsed = parse_args(&args);
        assert!(parsed.method.is_none());
        assert!(parsed.params.is_empty());
        assert!(!parsed.help);
    }

    #[test]
    fn test_parse_args_default_url() {
        let args: Vec<String> = vec!["help".into()];
        let parsed = parse_args(&args);
        assert_eq!(parsed.config.rpc_url, "http://127.0.0.1:8332");
    }

    // -- coerce_param --

    #[test]
    fn test_coerce_param_integer() {
        assert_eq!(coerce_param("42"), json!(42));
        assert_eq!(coerce_param("-1"), json!(-1));
        assert_eq!(coerce_param("0"), json!(0));
    }

    #[test]
    fn test_coerce_param_float() {
        assert_eq!(coerce_param("1.5"), json!(1.5));
    }

    #[test]
    fn test_coerce_param_bool() {
        assert_eq!(coerce_param("true"), json!(true));
        assert_eq!(coerce_param("false"), json!(false));
    }

    #[test]
    fn test_coerce_param_json_array() {
        let result = coerce_param("[1,2,3]");
        assert_eq!(result, json!([1, 2, 3]));
    }

    #[test]
    fn test_coerce_param_string_fallback() {
        assert_eq!(coerce_param("hello"), json!("hello"));
        assert_eq!(coerce_param("abc123"), json!("abc123"));
    }

    // -- usage --

    #[test]
    fn test_usage_not_empty() {
        let u = usage();
        assert!(!u.is_empty());
        assert!(u.contains("qubitcoin-cli"));
        assert!(u.contains("rpcconnect"));
    }
}
