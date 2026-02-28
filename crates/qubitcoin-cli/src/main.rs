// Copyright (c) 2024 The Qubitcoin developers
// Distributed under the MIT software license.

//! qubitcoin-cli: command-line client for interacting with a Qubitcoin
//! JSON-RPC server.
//!
//! Usage:
//!     qubitcoin-cli [options] <command> [params...]
//!
//! Examples:
//!     qubitcoin-cli getblockcount
//!     qubitcoin-cli getblockhash 0
//!     qubitcoin-cli -rpcport=18332 getblockchaininfo

use qubitcoin_cli::{build_request, format_result, parse_args, parse_response, usage};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cli = parse_args(&args);

    // Handle --help.
    if cli.help || cli.method.is_none() {
        println!("{}", usage());
        if cli.help {
            std::process::exit(0);
        } else {
            // No method supplied.
            eprintln!("error: no command specified");
            std::process::exit(1);
        }
    }

    let method = cli.method.unwrap();
    let request_body = build_request(&method, cli.params);

    // Attempt to connect and send the request.
    match send_rpc_request(&cli.config.rpc_url, &request_body, &cli.config) {
        Ok(response_body) => match parse_response(&response_body) {
            Ok(result) => {
                println!("{}", format_result(&result));
            }
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!(
                "error: Could not connect to server at {}: {}",
                cli.config.rpc_url, e
            );
            eprintln!("Make sure qubitcoind is running and accepting RPC connections.");
            std::process::exit(1);
        }
    }
}

/// Send a JSON-RPC request over a raw TCP connection using minimal HTTP/1.1.
///
/// This avoids pulling in a full HTTP client dependency. For production use
/// this would be replaced with a proper HTTP client (e.g. reqwest).
fn send_rpc_request(
    url: &str,
    body: &str,
    config: &qubitcoin_cli::CliConfig,
) -> Result<String, String> {
    // Parse the URL to extract host and port.
    let url_stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host, port) = if let Some((h, p)) = url_stripped.split_once(':') {
        let port: u16 = p.parse().map_err(|_| "Invalid port".to_string())?;
        (h.to_string(), port)
    } else {
        (url_stripped.to_string(), 8332u16)
    };

    // Connect.
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

    // Build HTTP request.
    let mut http_request = format!(
        "POST / HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n",
        host,
        body.len()
    );

    // Add basic auth header if credentials are present.
    if config.has_auth() {
        let credentials = format!(
            "{}:{}",
            config.rpc_user.as_deref().unwrap_or(""),
            config.rpc_password.as_deref().unwrap_or("")
        );
        let encoded = base64_encode(credentials.as_bytes());
        http_request.push_str(&format!("Authorization: Basic {}\r\n", encoded));
    }

    http_request.push_str("Connection: close\r\n\r\n");
    http_request.push_str(body);

    // Send.
    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    // Read response.
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    // Extract the body from the HTTP response (after the blank line).
    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else if let Some(pos) = response.find("\n\n") {
        Ok(response[pos + 2..].to_string())
    } else {
        // No headers found; return the whole thing and let the JSON parser
        // sort it out.
        Ok(response)
    }
}

/// Minimal Base64 encoder (no external dependency).
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
