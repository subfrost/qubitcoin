//! qubitcoin-tx: Raw transaction utility.
//!
//! Maps to: `bitcoin-tx` command-line tool in Bitcoin Core.
//!
//! Usage:
//!   qubitcoin-tx -decode <hex>        Decode a raw transaction
//!   qubitcoin-tx -txid <hex>          Get the txid of a raw transaction
//!   qubitcoin-tx -vsize <hex>         Get the virtual size of a raw transaction
//!   qubitcoin-tx -create              Create a new raw transaction (interactive)

use qubitcoin_tx::tx_tool;
use qubitcoin_util::args::ArgsManager;

fn print_usage() {
    eprintln!("Qubitcoin Core qubitcoin-tx utility version 0.1.0");
    eprintln!();
    eprintln!("Usage: qubitcoin-tx [options] <hex-tx> [commands]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -decode=<hex>     Decode a raw transaction and print JSON");
    eprintln!("  -txid=<hex>       Get the txid of a raw transaction");
    eprintln!("  -vsize=<hex>      Get the virtual size of a raw transaction");
    eprintln!("  -create           Create a new empty raw transaction");
    eprintln!("  -json             Output in JSON format (default)");
    eprintln!("  -help             Print this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  qubitcoin-tx -decode=0200000001aa...00000000");
    eprintln!("  qubitcoin-tx -txid=0200000001aa...00000000");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut mgr = ArgsManager::new();
    mgr.parse_args(&args);

    if mgr.get_bool_arg("help") || mgr.get_bool_arg("h") || args.len() <= 1 {
        print_usage();
        std::process::exit(0);
    }

    // Handle -decode=<hex>
    if let Some(hex_str) = mgr.get_arg("decode") {
        match tx_tool::decode_raw_transaction(hex_str) {
            Ok(json) => {
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            Err(e) => {
                eprintln!("Error decoding transaction: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Handle -txid=<hex>
    if let Some(hex_str) = mgr.get_arg("txid") {
        match tx_tool::get_txid(hex_str) {
            Ok(txid) => {
                println!("{}", txid);
            }
            Err(e) => {
                eprintln!("Error computing txid: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Handle -vsize=<hex>
    if let Some(hex_str) = mgr.get_arg("vsize") {
        match tx_tool::get_virtual_size(hex_str) {
            Ok(vsize) => {
                println!("{}", vsize);
            }
            Err(e) => {
                eprintln!("Error computing virtual size: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Handle -create (create an empty transaction)
    if mgr.get_bool_arg("create") {
        match tx_tool::create_raw_transaction(&[], &[], 0, 2) {
            Ok(hex_str) => {
                println!("{}", hex_str);
            }
            Err(e) => {
                eprintln!("Error creating transaction: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // If we get here, try to decode the second argument as a raw tx hex
    if args.len() > 1 && !args[1].starts_with('-') {
        match tx_tool::decode_raw_transaction(&args[1]) {
            Ok(json) => {
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    eprintln!("Error: No valid command specified.");
    print_usage();
    std::process::exit(1);
}
