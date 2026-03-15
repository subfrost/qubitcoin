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
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    // Check for local commands (not RPC).
    if args.first().map(|s| s.as_str()) == Some("installindexer") {
        install_indexer_command(&args[1..]);
        return;
    }

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

/// Handle the `installindexer` local command.
///
/// Usage: qubitcoin-cli installindexer <label> <source> [--branch <branch>] [--token <pat>] [--smt]
///
/// Source can be:
///   - A local path to a .wasm file
///   - A git URL (https://github.com/...) — will clone, build to wasm32, and install
fn install_indexer_command(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: qubitcoin-cli installindexer <label> <source> [options]");
        eprintln!();
        eprintln!("  <label>              Human-readable name (e.g. 'alkanes')");
        eprintln!("  <source>             Path to .wasm file or git URL");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --branch <branch>    Git branch/tag to checkout (default: main)");
        eprintln!("  --token <pat>        GitHub PAT for private repos");
        eprintln!("  --package <name>     Build specific package in a workspace");
        eprintln!("  --smt                Enable sparse merkle tree state roots");
        std::process::exit(1);
    }

    let label = &args[0];
    let source = &args[1];
    let smt = args.iter().any(|a| a == "--smt");
    let branch = extract_flag_value(args, "--branch");
    let token = extract_flag_value(args, "--token");
    let package = extract_flag_value(args, "--package");

    // Determine install directory.
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let install_dir = PathBuf::from(&home)
        .join(".local")
        .join("qubitcoin")
        .join("indexers")
        .join(label);

    if let Err(e) = std::fs::create_dir_all(&install_dir) {
        eprintln!("error: failed to create directory {}: {}", install_dir.display(), e);
        std::process::exit(1);
    }

    let wasm_dest = install_dir.join("program.wasm");

    if is_git_url(source) {
        // Clone, build, and install from git.
        install_from_git(label, source, &branch, &token, &package, &wasm_dest, &install_dir);
    } else {
        // Copy local .wasm file.
        let source_path = PathBuf::from(source);
        if source_path.exists() {
            if let Err(e) = std::fs::copy(&source_path, &wasm_dest) {
                eprintln!("error: failed to copy WASM file: {}", e);
                std::process::exit(1);
            }
        } else {
            eprintln!("error: source file not found: {}", source);
            std::process::exit(1);
        }
    }

    // Compute SHA-256 of installed WASM.
    let wasm_bytes = std::fs::read(&wasm_dest).expect("failed to read installed WASM");
    let hash = sha256_hex(&wasm_bytes);

    // Write indexer.toml manifest.
    let mut manifest = format!(
        "label = \"{}\"\n\
         sha256 = \"{}\"\n\
         source_url = \"{}\"\n\
         installed_at = \"{}\"\n\
         smt = {}\n",
        label, hash, source, chrono_now(), smt,
    );
    if let Some(ref branch) = branch {
        manifest.push_str(&format!("branch = \"{}\"\n", branch));
    }
    if token.is_some() {
        manifest.push_str("private = true\n");
    }

    let manifest_path = install_dir.join("indexer.toml");
    if let Err(e) = std::fs::write(&manifest_path, &manifest) {
        eprintln!("error: failed to write manifest: {}", e);
        std::process::exit(1);
    }

    println!("Installed indexer '{}' to {}", label, install_dir.display());
    println!("SHA-256: {}", hash);
    println!();
    println!("Add to qubitcoind config or command line:");
    println!("  -loadindexer={}:{}", label, install_dir.display());
}

/// Check if a source string looks like a git URL.
fn is_git_url(source: &str) -> bool {
    source.starts_with("https://") || source.starts_with("git@") || source.starts_with("http://")
}

/// Extract the value following a flag (e.g. --branch main).
fn extract_flag_value(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
        // Also support --flag=value
        if let Some(rest) = arg.strip_prefix(&format!("{}=", flag)) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Clone a git repo, build the WASM, and copy it to the install dir.
fn install_from_git(
    label: &str,
    url: &str,
    branch: &Option<String>,
    token: &Option<String>,
    package: &Option<String>,
    wasm_dest: &PathBuf,
    install_dir: &PathBuf,
) {
    use std::process::Command;

    // Build the authenticated git URL if a token is provided.
    let clone_url = if let Some(ref tok) = token {
        // https://github.com/user/repo -> https://TOKEN@github.com/user/repo
        if let Some(rest) = url.strip_prefix("https://") {
            format!("https://{}@{}", tok, rest)
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    };

    // Clone to a temp directory.
    let build_dir = install_dir.join("_build");
    if build_dir.exists() {
        let _ = std::fs::remove_dir_all(&build_dir);
    }

    println!("Cloning {}...", url);

    let mut clone_cmd = Command::new("git");
    clone_cmd
        .arg("clone")
        .arg("--depth")
        .arg("1");
    if let Some(ref b) = branch {
        clone_cmd.arg("--branch").arg(b);
    }
    clone_cmd.arg(&clone_url).arg(&build_dir);

    let status = clone_cmd
        .status()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to run git clone: {}", e);
            std::process::exit(1);
        });

    if !status.success() {
        eprintln!("error: git clone failed");
        std::process::exit(1);
    }

    // Build the WASM.
    println!("Building WASM for {}...", label);

    let mut build_cmd = Command::new("cargo");
    build_cmd
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg("wasm32-unknown-unknown");
    if let Some(ref pkg) = package {
        build_cmd.arg("-p").arg(pkg);
    }
    let status = build_cmd
        .current_dir(&build_dir)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to run cargo build: {}", e);
            std::process::exit(1);
        });

    if !status.success() {
        eprintln!("error: cargo build failed for {}", label);
        std::process::exit(1);
    }

    // Find the built .wasm file.
    let wasm_dir = build_dir
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release");

    let wasm_file = find_wasm_file(&wasm_dir);
    match wasm_file {
        Some(wasm_path) => {
            println!("Found WASM: {}", wasm_path.display());
            if let Err(e) = std::fs::copy(&wasm_path, wasm_dest) {
                eprintln!("error: failed to copy WASM: {}", e);
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("error: no .wasm file found in {}", wasm_dir.display());
            std::process::exit(1);
        }
    }

    // Clean up build directory.
    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Find the first .wasm file in a directory.
fn find_wasm_file(dir: &PathBuf) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                // Skip deps/*.wasm — we want the main crate output.
                if !path.to_string_lossy().contains("deps") {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Simple SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize_hex()
}

/// Minimal timestamp string.
fn chrono_now() -> String {
    // Use seconds since epoch as a simple timestamp.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", dur.as_secs())
}

/// Minimal SHA-256 implementation (no external deps).
struct Sha256Hasher {
    data: Vec<u8>,
}

impl Sha256Hasher {
    fn new() -> Self {
        Sha256Hasher { data: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    fn finalize_hex(&self) -> String {
        // Use the system sha256sum command as a fallback to avoid
        // adding a crypto dependency to the CLI binary.
        use std::process::Command;
        let output = Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(&self.data)?;
                child.wait_with_output()
            });

        match output {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout);
                s.split_whitespace().next().unwrap_or("").to_string()
            }
            Err(_) => "unknown".to_string(),
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
