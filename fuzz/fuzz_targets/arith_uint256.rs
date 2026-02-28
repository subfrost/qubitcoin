//! Fuzz target: ArithUint256 arithmetic operations.
//!
//! Constructs ArithUint256 values from arbitrary bytes and exercises
//! arithmetic, bitwise, shift, and compact-encoding operations.
//! The goal is to find panics (especially in division, shifting, and
//! compact roundtrips).

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_primitives::arith_uint256::{arith_to_uint256, uint256_to_arith, ArithUint256};

/// Construct an ArithUint256 from up to 32 bytes of fuzzer data.
/// If fewer than 32 bytes are available, the remaining limbs stay zero.
fn arith_from_bytes(data: &[u8]) -> ArithUint256 {
    let mut limbs = [0u32; 8];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let offset = i * 4;
        if offset + 4 <= data.len() {
            *limb = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        } else if offset < data.len() {
            let mut buf = [0u8; 4];
            let avail = data.len() - offset;
            buf[..avail].copy_from_slice(&data[offset..]);
            *limb = u32::from_le_bytes(buf);
        }
    }
    // ArithUint256 fields are private, so use from_u64 + shifts to build.
    // Instead, use the Uint256 -> ArithUint256 conversion path.
    let mut raw = [0u8; 32];
    let copy_len = data.len().min(32);
    raw[..copy_len].copy_from_slice(&data[..copy_len]);
    let u256 = qubitcoin_primitives::Uint256::from_bytes(raw);
    uint256_to_arith(&u256)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }

    // Split the input: first 32 bytes for `a`, remaining for `b` and control.
    let a = arith_from_bytes(&data[..32]);
    let b = arith_from_bytes(&data[1..]);
    let control = data[32]; // single byte to pick operations

    // --- Addition / Subtraction ---
    {
        let c = a + b;
        let d = c - b;
        // Due to wrapping semantics, a + b - b == a.
        assert_eq!(a, d, "add/sub roundtrip failed");
    }

    // --- Multiplication ---
    {
        let small = ArithUint256::from_u64(control as u64);
        let _product = a * small;
    }

    // --- Bitwise operations ---
    {
        let _xor = a ^ b;
        let _and = a & b;
        let _or = a | b;
        let _not = !a;
    }

    // --- Shift operations (shift amount from control byte) ---
    {
        let shift = (control as u32) % 256;
        let _left = a << shift;
        let _right = a >> shift;
    }

    // --- Negation ---
    {
        let neg_a = -a;
        let sum = a + neg_a;
        assert_eq!(
            sum,
            ArithUint256::from_u64(0),
            "a + (-a) should be zero"
        );
    }

    // --- Comparison ---
    {
        let _cmp = a.compare_to(&b);
        let _bits_a = a.bits();
        let _bits_b = b.bits();
    }

    // --- Division (skip if divisor is zero to avoid intended panic) ---
    {
        if b != ArithUint256::from_u64(0) {
            let _quotient = a / b;
        }
    }

    // --- Compact encoding roundtrip ---
    {
        let compact = a.get_compact(false);
        let mut target = ArithUint256::default();
        let (negative, overflow) = target.set_compact(compact);
        // For non-negative, non-overflow values the roundtrip should hold:
        // set_compact(get_compact(a)).get_compact() == get_compact(a)
        if !negative && !overflow {
            let compact2 = target.get_compact(false);
            assert_eq!(compact, compact2, "compact encoding roundtrip mismatch");
        }
    }

    // --- Uint256 <-> ArithUint256 conversion roundtrip ---
    {
        let u = arith_to_uint256(&a);
        let a2 = uint256_to_arith(&u);
        assert_eq!(a, a2, "Uint256 conversion roundtrip mismatch");
    }

    // --- Inc / Dec ---
    {
        let mut x = a;
        x.inc();
        x.dec();
        assert_eq!(a, x, "inc/dec roundtrip failed");
    }

    // --- to_f64 (must not panic) ---
    {
        let _f = a.to_f64();
    }
});
