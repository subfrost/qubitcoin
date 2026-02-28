//! Fuzz target: P2P network message deserialization.
//!
//! Constructs a raw Bitcoin protocol message from fuzzer data and feeds it
//! through the message header parser and payload decoder. The goal is to find
//! panics in the parsing code. Malformed input should be handled gracefully.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_net::protocol::MessageHeader;

// Re-use the parse_message function from the connection module.
// It is pub, so we can call it directly.
use qubitcoin_net::connection::parse_message;

fuzz_target!(|data: &[u8]| {
    // --- Test 1: Parse a raw 24-byte message header ---
    if data.len() >= 24 {
        let hdr_bytes: [u8; 24] = data[..24].try_into().unwrap();
        let header = MessageHeader::deserialize(&hdr_bytes);

        // Extract command string (must not panic even with garbage bytes).
        let _cmd = header.command_str();

        // Verify checksum against the remaining payload bytes (must not panic).
        if data.len() > 24 {
            let _valid = header.verify_checksum(&data[24..]);
        }
    }

    // --- Test 2: Parse a message with a known command + arbitrary payload ---
    // Use all bytes as the payload and try several common commands.
    {
        let commands = [
            "version",
            "verack",
            "ping",
            "pong",
            "getaddr",
            "sendheaders",
            "wtxidrelay",
            "sendaddrv2",
            "filterclear",
            "mempool",
            "sendtxrcncl",
            "feefilter",
            "inv",
            "getdata",
            "notfound",
            "block",
            "tx",
            "headers",
            "sendcmpct",
            "getheaders",
            "getblocks",
            "getcfheaders",
            "getcfilters",
            "getcfcheckpt",
            "addr",
            "reject",
            "cmpctblock",
            "getblocktxn",
            "blocktxn",
            "filterload",
            "filteradd",
            "merkleblock",
            "addrv2",
            "cfheaders",
            "cfilter",
            "cfcheckpt",
        ];

        for cmd in &commands {
            // parse_message must not panic on any combination of command + payload.
            let _msg = parse_message(cmd, data);
        }
    }

    // --- Test 3: Use the first byte to select a command, rest as payload ---
    if !data.is_empty() {
        let commands = [
            "version",
            "verack",
            "ping",
            "pong",
            "inv",
            "getdata",
            "getheaders",
            "getblocks",
            "headers",
            "addr",
            "reject",
            "sendcmpct",
            "feefilter",
            "sendtxrcncl",
            "getcfheaders",
            "getcfilters",
            "getcfcheckpt",
        ];
        let idx = data[0] as usize % commands.len();
        let payload = &data[1..];
        let _msg = parse_message(commands[idx], payload);
    }
});
