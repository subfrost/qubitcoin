//! Fuzz target: Transaction deserialization.
//!
//! Feeds arbitrary bytes to the transaction deserializer. The goal is to find
//! inputs that cause panics or other unexpected behaviour in the parsing code.
//! Malformed input should always produce an `Err`, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_consensus::transaction::deserialize_transaction;
use qubitcoin_serialize::Encodable;

fuzz_target!(|data: &[u8]| {
    // Try deserialization with witness support (the most common path).
    let mut reader = data;
    if let Ok(tx) = deserialize_transaction(&mut reader, true) {
        // If deserialization succeeded, verify the roundtrip: re-serialise and
        // re-deserialise, then check that the two Transaction values agree on
        // their txid (which is derived from the non-witness serialisation).
        let mut buf = Vec::new();
        if tx.encode(&mut buf).is_ok() {
            let mut reader2 = &buf[..];
            if let Ok(tx2) = deserialize_transaction(&mut reader2, true) {
                assert_eq!(tx.txid(), tx2.txid(), "txid mismatch after roundtrip");
            }
        }
    }

    // Also try deserialization without witness support to exercise both paths.
    let mut reader_no_wit = data;
    let _ = deserialize_transaction(&mut reader_no_wit, false);
});
