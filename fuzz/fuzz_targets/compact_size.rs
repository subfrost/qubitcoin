//! Fuzz target: CompactSize read/write roundtrip.
//!
//! Tests that:
//! 1. Reading CompactSize from arbitrary bytes does not panic.
//! 2. For any successfully-read value, writing it back and re-reading produces
//!    the same value (roundtrip property).
//! 3. Writing arbitrary u64 values does not panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_serialize::{read_compact_size, write_compact_size};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // --- Test 1: read from arbitrary bytes (with range check) ---
    {
        let mut cursor = Cursor::new(data);
        if let Ok(value) = read_compact_size(&mut cursor) {
            // Roundtrip: write the value back and re-read it.
            let mut buf = Vec::new();
            if write_compact_size(&mut buf, value).is_ok() {
                let mut cursor2 = Cursor::new(&buf);
                let value2 = read_compact_size(&mut cursor2)
                    .expect("re-read of a written compact size must succeed");
                assert_eq!(value, value2, "CompactSize roundtrip mismatch");
            }
        }
    }

    // --- Test 2: read from arbitrary bytes (without range check) ---
    {
        let mut cursor = Cursor::new(data);
        if let Ok(value) =
            qubitcoin_serialize::compact_size::read_compact_size_with_range(&mut cursor, false)
        {
            let mut buf = Vec::new();
            if write_compact_size(&mut buf, value).is_ok() {
                let mut cursor2 = Cursor::new(&buf);
                if let Ok(value2) =
                    qubitcoin_serialize::compact_size::read_compact_size_with_range(
                        &mut cursor2,
                        false,
                    )
                {
                    assert_eq!(value, value2, "CompactSize roundtrip mismatch (no range check)");
                }
            }
        }
    }

    // --- Test 3: treat the first 8 bytes as a u64, write and re-read ---
    if data.len() >= 8 {
        let value = u64::from_le_bytes(data[..8].try_into().unwrap());
        let mut buf = Vec::new();
        // write_compact_size always succeeds for valid u64 values.
        if write_compact_size(&mut buf, value).is_ok() {
            let mut cursor = Cursor::new(&buf);
            // Read back - may fail due to range check for very large values,
            // but must not panic.
            let _ = read_compact_size(&mut cursor);

            // Without range check it must roundtrip.
            let mut cursor2 = Cursor::new(&buf);
            if let Ok(value2) =
                qubitcoin_serialize::compact_size::read_compact_size_with_range(&mut cursor2, false)
            {
                assert_eq!(value, value2, "u64 CompactSize roundtrip mismatch");
            }
        }
    }
});
