//! Q-Day seize consensus constants and frozen set loading.
//!
//! This module holds the hardcoded Q-Day data: the frozen outpoint set
//! (computed offline by the metashrew analyzer) and the FROST P2MR address
//! that receives seized funds.

use crate::transaction::OutPoint;
use qubitcoin_crypto::hash::hash256;
use qubitcoin_primitives::Txid;
use qubitcoin_script::{build_p2mr, Script};
use std::collections::HashSet;

/// Serialized frozen outpoints data (generated offline by metashrew analyzer).
///
/// Format: count (u32 LE) followed by each outpoint (32-byte txid + 4-byte vout LE).
/// Placeholder: empty until the analyzer is run against the chain.
pub const FROZEN_OUTPOINTS_DATA: &[u8] = &[];

/// The 32-byte P2MR witness program (FROST group key merkle root).
///
/// This is the merkle root of the tapscript tree containing the FROST
/// group key check script. Seized funds are sent to this program.
/// Placeholder: zeros until FROST DKG is performed.
pub const SEIZE_P2MR_PROGRAM: [u8; 32] = [0u8; 32];

/// SHA256d commitment hash over the frozen set for validation.
///
/// Nodes verify that the embedded frozen set matches this hash.
/// Placeholder: zeros until the frozen set is computed.
pub const FROZEN_COMMITMENT_HASH: [u8; 32] = [0u8; 32];

/// A frozen outpoints set backed by a `HashSet<OutPoint>`.
#[derive(Debug, Clone)]
pub struct FrozenOutpoints {
    outpoints: HashSet<OutPoint>,
}

impl FrozenOutpoints {
    /// Create an empty frozen set.
    pub fn new() -> Self {
        FrozenOutpoints {
            outpoints: HashSet::new(),
        }
    }

    /// Create from a pre-computed set.
    pub fn from_set(outpoints: HashSet<OutPoint>) -> Self {
        FrozenOutpoints { outpoints }
    }

    /// Check if an outpoint is frozen.
    pub fn is_frozen(&self, outpoint: &OutPoint) -> bool {
        self.outpoints.contains(outpoint)
    }

    /// Number of frozen outpoints.
    pub fn len(&self) -> usize {
        self.outpoints.len()
    }

    /// Whether the frozen set is empty.
    pub fn is_empty(&self) -> bool {
        self.outpoints.is_empty()
    }

    /// Insert an outpoint into the frozen set.
    pub fn insert(&mut self, outpoint: OutPoint) -> bool {
        self.outpoints.insert(outpoint)
    }

    /// Get an iterator over all frozen outpoints, sorted deterministically.
    pub fn iter_sorted(&self) -> Vec<OutPoint> {
        let mut sorted: Vec<OutPoint> = self.outpoints.iter().cloned().collect();
        sorted.sort_by(|a, b| {
            let cmp = a.hash.as_bytes().cmp(b.hash.as_bytes());
            if cmp == std::cmp::Ordering::Equal {
                a.n.cmp(&b.n)
            } else {
                cmp
            }
        });
        sorted
    }

    /// Compute a deterministic commitment hash over the frozen set.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let sorted = self.iter_sorted();
        let mut buf = Vec::new();
        for op in &sorted {
            buf.extend_from_slice(op.hash.as_bytes());
            buf.extend_from_slice(&op.n.to_le_bytes());
        }
        hash256(&buf)
    }

    /// Deserialize a frozen set from bytes.
    ///
    /// Format: count (u32 LE) followed by each outpoint (32 + 4 bytes).
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Ok(FrozenOutpoints::new());
        }
        if data.len() < 4 {
            return Err("frozen set data too short");
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let expected_len = 4 + count * 36;
        if data.len() < expected_len {
            return Err("frozen set data truncated");
        }

        let mut set = HashSet::with_capacity(count);
        for i in 0..count {
            let offset = 4 + i * 36;
            let txid = Txid::from_bytes({
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data[offset..offset + 32]);
                arr
            });
            let vout = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());
            set.insert(OutPoint::new(txid, vout));
        }

        Ok(FrozenOutpoints { outpoints: set })
    }

    /// Serialize the frozen set to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sorted = self.iter_sorted();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for op in &sorted {
            buf.extend_from_slice(op.hash.as_bytes());
            buf.extend_from_slice(&op.n.to_le_bytes());
        }
        buf
    }
}

impl Default for FrozenOutpoints {
    fn default() -> Self {
        Self::new()
    }
}

/// Load the frozen set from the embedded consensus data.
///
/// Deserializes `FROZEN_OUTPOINTS_DATA` and validates against `FROZEN_COMMITMENT_HASH`.
/// Returns an empty set if the placeholder data is empty.
pub fn load_frozen_set() -> Result<FrozenOutpoints, &'static str> {
    if FROZEN_OUTPOINTS_DATA.is_empty() {
        return Ok(FrozenOutpoints::new());
    }

    let frozen = FrozenOutpoints::from_bytes(FROZEN_OUTPOINTS_DATA)?;

    // Validate commitment hash
    let computed_hash = frozen.commitment_hash();
    if computed_hash != FROZEN_COMMITMENT_HASH {
        return Err("frozen set commitment hash mismatch");
    }

    Ok(frozen)
}

/// Build the seize P2MR scriptPubKey from the consensus constant.
pub fn seize_script_pubkey() -> Script {
    build_p2mr(&SEIZE_P2MR_PROGRAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_outpoint(n: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&n.to_le_bytes());
        OutPoint::new(Txid::from_bytes(bytes), n)
    }

    #[test]
    fn test_empty_frozen_set() {
        let frozen = load_frozen_set().unwrap();
        assert!(frozen.is_empty());
    }

    #[test]
    fn test_frozen_set_roundtrip() {
        let mut fs = FrozenOutpoints::new();
        for i in 0..5 {
            fs.insert(make_outpoint(i));
        }

        let bytes = fs.to_bytes();
        let fs2 = FrozenOutpoints::from_bytes(&bytes).unwrap();
        assert_eq!(fs.len(), fs2.len());
        for op in &fs.iter_sorted() {
            assert!(fs2.is_frozen(op));
        }
    }

    #[test]
    fn test_commitment_deterministic() {
        let mut fs1 = FrozenOutpoints::new();
        let mut fs2 = FrozenOutpoints::new();

        fs1.insert(make_outpoint(1));
        fs1.insert(make_outpoint(2));
        fs2.insert(make_outpoint(2));
        fs2.insert(make_outpoint(1));

        assert_eq!(fs1.commitment_hash(), fs2.commitment_hash());
    }

    #[test]
    fn test_seize_script_is_p2mr() {
        let script = seize_script_pubkey();
        assert!(script.is_p2mr());
    }
}
