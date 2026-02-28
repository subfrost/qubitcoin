//! Fuzz target: Block deserialization.
//!
//! Feeds arbitrary bytes to the block deserializer (header + transactions).
//! The goal is to find inputs that cause panics. Malformed input should
//! produce an `Err`, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_serialize::{Decodable, Encodable};

fuzz_target!(|data: &[u8]| {
    // Try full block deserialization.
    let mut reader = data;
    if let Ok(block) = Block::decode(&mut reader) {
        // Verify header roundtrip.
        let mut hdr_buf = Vec::new();
        if block.header.encode(&mut hdr_buf).is_ok() {
            let mut hdr_reader = &hdr_buf[..];
            if let Ok(hdr2) = BlockHeader::decode(&mut hdr_reader) {
                assert_eq!(block.header, hdr2, "header mismatch after roundtrip");
            }
        }

        // Verify full block roundtrip.
        let mut blk_buf = Vec::new();
        if block.encode(&mut blk_buf).is_ok() {
            let mut blk_reader = &blk_buf[..];
            if let Ok(block2) = Block::decode(&mut blk_reader) {
                assert_eq!(
                    block.header, block2.header,
                    "block header mismatch after roundtrip"
                );
                assert_eq!(
                    block.vtx.len(),
                    block2.vtx.len(),
                    "tx count mismatch after roundtrip"
                );
            }
        }
    }

    // Also try just the 80-byte header deserialization on arbitrary data.
    let mut hdr_reader = data;
    let _ = BlockHeader::decode(&mut hdr_reader);
});
