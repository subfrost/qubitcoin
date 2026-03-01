//! Scoring and script classification for quantum-vulnerable outputs.
//!
//! Mirrors the scoring logic in the qday-analyzer WASM crate, but operates
//! on qubitcoin native types instead of rust-bitcoin types.

use qubitcoin_crypto::hash::hash160;
use qubitcoin_script::{Opcode, Script};

/// Vulnerability types for quantum-exposed Bitcoin outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VulnType {
    /// Public key directly in scriptPubKey.
    P2PK = 0,
    /// P2PKH where pubkey was revealed via prior spend.
    ExposedP2PKH = 1,
    /// Taproot (witness v1) exposes x-only public key.
    P2TR = 2,
}

/// Approximate year from block height.
fn height_to_approx_year(height: u32) -> u32 {
    2009 + (height / 52560)
}

/// Age component (max 400).
pub fn age_score(creation_height: u32) -> u16 {
    let year = height_to_approx_year(creation_height);
    match year {
        0..=2010 => 400,
        2011..=2012 => 300,
        2013..=2014 => 200,
        2015..=2017 => 100,
        2018..=2020 => 50,
        _ => 0,
    }
}

/// Dormancy component (max 300).
pub fn dormancy_score(creation_height: u32, current_height: u32) -> u16 {
    let blocks_dormant = current_height.saturating_sub(creation_height);
    let years_dormant = blocks_dormant / 52560;
    match years_dormant {
        10.. => 300,
        5..=9 => 200,
        2..=4 => 100,
        _ => 0,
    }
}

/// Inverse value component (max 200).
pub fn value_score(sats: u64) -> u16 {
    const BTC: u64 = 100_000_000;
    match sats {
        0..=999_999 => 200,
        1_000_000..=99_999_999 => 150,
        s if s < 50 * BTC => 100,
        s if s < 1000 * BTC => 50,
        _ => 0,
    }
}

/// Pattern component (max 100).
pub fn pattern_score(is_coinbase: bool, ever_spent_from_address: bool) -> u16 {
    if is_coinbase && !ever_spent_from_address {
        100
    } else if is_coinbase {
        50
    } else {
        0
    }
}

/// Composite safety score (0-1000).
pub fn compute_score(
    creation_height: u32,
    current_height: u32,
    value_sats: u64,
    is_coinbase: bool,
) -> u16 {
    age_score(creation_height)
        + dormancy_score(creation_height, current_height)
        + value_score(value_sats)
        + pattern_score(is_coinbase, false)
}

/// Check if a scriptPubKey is P2PK. Returns the public key bytes if so.
pub fn is_p2pk(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let len = bytes.len();

    // Compressed: 0x21 <33 bytes> OP_CHECKSIG(0xac)
    if len == 35 && bytes[0] == 0x21 && bytes[34] == Opcode::OpCheckSig as u8 {
        let pubkey = &bytes[1..34];
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) && pubkey.len() == 33 {
            return Some(pubkey.to_vec());
        }
    }

    // Uncompressed: 0x41 <65 bytes> OP_CHECKSIG(0xac)
    if len == 67 && bytes[0] == 0x41 && bytes[66] == Opcode::OpCheckSig as u8 {
        let pubkey = &bytes[1..66];
        if pubkey[0] == 0x04 && pubkey.len() == 65 {
            return Some(pubkey.to_vec());
        }
    }

    None
}

/// Check if a scriptPubKey is P2PKH. Returns the 20-byte pubkey hash.
pub fn is_p2pkh(script: &Script) -> Option<[u8; 20]> {
    let bytes = script.as_bytes();
    if bytes.len() == 25
        && bytes[0] == Opcode::OpDup as u8
        && bytes[1] == Opcode::OpHash160 as u8
        && bytes[2] == 0x14
        && bytes[23] == Opcode::OpEqualVerify as u8
        && bytes[24] == Opcode::OpCheckSig as u8
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[3..23]);
        Some(hash)
    } else {
        None
    }
}

/// Check if a scriptPubKey is P2TR. Returns the 32-byte x-only pubkey.
pub fn is_p2tr(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    // OP_1 (0x51) + push-32 (0x20) + 32 bytes
    if bytes.len() == 34 && bytes[0] == Opcode::Op1 as u8 && bytes[1] == 0x20 {
        Some(bytes[2..34].to_vec())
    } else {
        None
    }
}

/// Extract pubkey from a P2PKH scriptSig: <sig> <pubkey>.
pub fn extract_p2pkh_pubkey(script_sig: &Script) -> Option<Vec<u8>> {
    let bytes = script_sig.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    // First push: signature (variable length)
    let sig_len = bytes[0] as usize;
    if sig_len == 0 || 1 + sig_len >= bytes.len() {
        return None;
    }

    // Second push: pubkey
    let pk_start = 1 + sig_len;
    let pk_len = bytes[pk_start] as usize;
    if pk_start + 1 + pk_len > bytes.len() {
        return None;
    }

    let pubkey = &bytes[pk_start + 1..pk_start + 1 + pk_len];
    match pubkey.len() {
        33 if pubkey[0] == 0x02 || pubkey[0] == 0x03 => Some(pubkey.to_vec()),
        65 if pubkey[0] == 0x04 => Some(pubkey.to_vec()),
        _ => None,
    }
}

/// Compute HASH160(pubkey) using qubitcoin-crypto.
pub fn pubkey_hash160(data: &[u8]) -> [u8; 20] {
    hash160(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age_score() {
        assert_eq!(age_score(0), 400);        // Genesis (2009)
        assert_eq!(age_score(100_000), 400);  // ~2010 (2009 + 100000/52560 = 2010)
        assert_eq!(age_score(160_000), 300);  // ~2012 (2009 + 3 = 2012)
        assert_eq!(age_score(300_000), 200);  // ~2014 (2009 + 5 = 2014)
        assert_eq!(age_score(500_000), 50);   // ~2018 (2009 + 9 = 2018)
        assert_eq!(age_score(800_000), 0);    // ~2024 (2009 + 15 = 2024)
    }

    #[test]
    fn test_dormancy_score() {
        assert_eq!(dormancy_score(0, 800_000), 300);      // 15+ years
        assert_eq!(dormancy_score(500_000, 800_000), 200); // ~5 years (300k blocks / 52560 = 5)
        assert_eq!(dormancy_score(700_000, 800_000), 0);   // ~1 year (100k / 52560 = 1)
        assert_eq!(dormancy_score(690_000, 800_000), 100); // ~2 years (110k / 52560 = 2)
    }

    #[test]
    fn test_value_score() {
        assert_eq!(value_score(1_000), 200);          // dust
        assert_eq!(value_score(50_000_000), 150);     // 0.5 BTC
        assert_eq!(value_score(200_000_000), 100);    // 2 BTC
        assert_eq!(value_score(10_000_000_000), 50);  // 100 BTC
        assert_eq!(value_score(200_000_000_000), 0);  // 2000 BTC
    }

    #[test]
    fn test_composite_score() {
        // Early coinbase dust: max all categories
        let score = compute_score(100, 800_000, 1_000, true);
        assert_eq!(score, 400 + 300 + 200 + 100); // 1000
    }

    #[test]
    fn test_is_p2pk_compressed() {
        // Build compressed P2PK: 0x21 <33 bytes> 0xac
        let mut script_bytes = vec![0x21];
        let mut pubkey = vec![0x02]; // compressed prefix
        pubkey.extend_from_slice(&[0xaa; 32]);
        script_bytes.extend_from_slice(&pubkey);
        script_bytes.push(0xac); // OP_CHECKSIG
        let script = Script::from_bytes(script_bytes);
        let result = is_p2pk(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 33);
    }

    #[test]
    fn test_is_p2pk_uncompressed() {
        let mut script_bytes = vec![0x41];
        let mut pubkey = vec![0x04]; // uncompressed prefix
        pubkey.extend_from_slice(&[0xbb; 64]);
        script_bytes.extend_from_slice(&pubkey);
        script_bytes.push(0xac); // OP_CHECKSIG
        let script = Script::from_bytes(script_bytes);
        let result = is_p2pk(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 65);
    }

    #[test]
    fn test_is_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script_bytes = vec![0x76, 0xa9, 0x14];
        script_bytes.extend_from_slice(&[0xcc; 20]);
        script_bytes.extend_from_slice(&[0x88, 0xac]);
        let script = Script::from_bytes(script_bytes);
        let result = is_p2pkh(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), [0xcc; 20]);
    }

    #[test]
    fn test_is_p2tr() {
        // OP_1 <32 bytes>
        let mut script_bytes = vec![0x51, 0x20];
        script_bytes.extend_from_slice(&[0xdd; 32]);
        let script = Script::from_bytes(script_bytes);
        let result = is_p2tr(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 32);
    }
}
