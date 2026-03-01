use crate::types::VulnType;
use bitcoin::blockdata::opcodes::all as op;
use bitcoin::blockdata::script::Instruction;
use bitcoin::Script;

/// Median time-past approximation from block height.
/// Returns approximate year for scoring purposes.
fn height_to_approx_year(height: u32) -> u32 {
    // ~144 blocks/day, ~52560 blocks/year
    // Genesis: 2009-01-03
    2009 + (height / 52560)
}

/// Compute the age component of the safety score (max 400).
///
/// Pre-2011 outputs (Satoshi era) get maximum score since they're
/// almost certainly lost. Score decreases for more recent outputs.
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

/// Compute the dormancy component (max 300).
///
/// Measures how long the output has been unspent. Longer dormancy
/// suggests the owner has lost access to their keys.
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

/// Compute the inverse value component (max 200).
///
/// Smaller outputs are safer to freeze because they're less likely
/// to be actively managed. Dust outputs are almost certainly abandoned.
pub fn value_score(sats: u64) -> u16 {
    const BTC: u64 = 100_000_000;
    match sats {
        0..=999_999 => 200,                         // < 0.01 BTC
        1_000_000..=99_999_999 => 150,              // 0.01 - 1 BTC
        s if s < 50 * BTC => 100,                   // 1 - 50 BTC
        s if s < 1000 * BTC => 50,                  // 50 - 1000 BTC
        _ => 0,                                     // > 1000 BTC
    }
}

/// Compute the pattern component (max 100).
///
/// Coinbase outputs that have never been spent are likely from early
/// miners who lost their keys. Non-coinbase outputs get no bonus.
pub fn pattern_score(is_coinbase: bool, ever_spent_from_address: bool) -> u16 {
    if is_coinbase && !ever_spent_from_address {
        100
    } else if is_coinbase {
        50
    } else {
        0
    }
}

/// Compute the composite safety score (0-1000).
///
/// Higher score = safer to make unspendable (more likely lost/abandoned).
pub fn compute_score(
    creation_height: u32,
    current_height: u32,
    value_sats: u64,
    is_coinbase: bool,
) -> u16 {
    let age = age_score(creation_height);
    let dormancy = dormancy_score(creation_height, current_height);
    let value = value_score(value_sats);
    let pattern = pattern_score(is_coinbase, false);
    age + dormancy + value + pattern
}

/// Check if a scriptPubKey is P2PK (pay-to-public-key).
///
/// Matches patterns:
/// - `<33-byte compressed pubkey> OP_CHECKSIG`
/// - `<65-byte uncompressed pubkey> OP_CHECKSIG`
pub fn is_p2pk(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let len = bytes.len();

    // Compressed P2PK: 0x21 <33 bytes> OP_CHECKSIG(0xac)
    if len == 35 && bytes[0] == 0x21 && bytes[34] == op::OP_CHECKSIG.to_u8() {
        let pubkey = bytes[1..34].to_vec();
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) && pubkey.len() == 33 {
            return Some(pubkey);
        }
    }

    // Uncompressed P2PK: 0x41 <65 bytes> OP_CHECKSIG(0xac)
    if len == 67 && bytes[0] == 0x41 && bytes[66] == op::OP_CHECKSIG.to_u8() {
        let pubkey = bytes[1..66].to_vec();
        if pubkey[0] == 0x04 && pubkey.len() == 65 {
            return Some(pubkey);
        }
    }

    None
}

/// Check if a scriptPubKey is P2PKH (pay-to-public-key-hash).
///
/// Returns the 20-byte pubkey hash if it matches:
/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`
pub fn is_p2pkh(script: &Script) -> Option<[u8; 20]> {
    let bytes = script.as_bytes();
    if bytes.len() == 25
        && bytes[0] == op::OP_DUP.to_u8()
        && bytes[1] == op::OP_HASH160.to_u8()
        && bytes[2] == 0x14 // push 20 bytes
        && bytes[23] == op::OP_EQUALVERIFY.to_u8()
        && bytes[24] == op::OP_CHECKSIG.to_u8()
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[3..23]);
        Some(hash)
    } else {
        None
    }
}

/// Check if a scriptPubKey is P2TR (pay-to-taproot, witness v1).
///
/// Returns the 32-byte x-only public key if it matches:
/// `OP_1 <32 bytes>`
pub fn is_p2tr(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    // OP_1 (0x51) followed by push-32 (0x20) followed by 32 bytes
    if bytes.len() == 34 && bytes[0] == op::OP_PUSHNUM_1.to_u8() && bytes[1] == 0x20 {
        Some(bytes[2..34].to_vec())
    } else {
        None
    }
}

/// Extract the public key from a P2PKH scriptSig.
///
/// P2PKH scriptSigs have the pattern: `<sig> <pubkey>`
/// Returns the pubkey bytes (33 compressed or 65 uncompressed).
pub fn extract_p2pkh_pubkey(script_sig: &Script) -> Option<Vec<u8>> {
    let bytes = script_sig.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut instructions = script_sig.instructions();

    // Skip signature push
    let _sig = match instructions.next() {
        Some(Ok(Instruction::PushBytes(data))) => data,
        _ => return None,
    };

    // Get pubkey push
    let pubkey = match instructions.next() {
        Some(Ok(Instruction::PushBytes(data))) => data.as_bytes().to_vec(),
        _ => return None,
    };

    // Validate pubkey length
    match pubkey.len() {
        33 if pubkey[0] == 0x02 || pubkey[0] == 0x03 => Some(pubkey),
        65 if pubkey[0] == 0x04 => Some(pubkey),
        _ => None,
    }
}

/// Compute HASH160 (RIPEMD160(SHA256(data))) of a public key.
///
/// Used to check if a revealed pubkey corresponds to a P2PKH address.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use bitcoin::hashes::{hash160, Hash};
    let h = hash160::Hash::hash(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(h.as_ref());
    result
}
