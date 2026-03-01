//! Frozen outpoints set for Q-Day consensus enforcement.
//!
//! The frozen set is computed deterministically at activation height and
//! then remains immutable. Any transaction spending a frozen outpoint is
//! rejected by consensus.

use qubitcoin_consensus::OutPoint;
use qubitcoin_crypto::hash::hash256;
use qubitcoin_primitives::Txid;
use std::collections::HashSet;

/// Set of outpoints that are frozen (unspendable) due to quantum vulnerability.
///
/// Backed by a `HashSet<OutPoint>` for O(1) membership testing. The set is
/// computed once at activation height and never modified afterward.
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

    /// Get an iterator over all frozen outpoints.
    pub fn iter(&self) -> impl Iterator<Item = &OutPoint> {
        self.outpoints.iter()
    }

    /// Compute a deterministic commitment hash over the frozen set.
    ///
    /// Sorts outpoints lexicographically by (txid, vout), serializes them,
    /// and computes SHA256d over the result. This hash can be embedded in
    /// a block header or used for cross-node verification.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut sorted: Vec<&OutPoint> = self.outpoints.iter().collect();
        sorted.sort_by(|a, b| {
            let cmp = a.hash.as_bytes().cmp(b.hash.as_bytes());
            if cmp == std::cmp::Ordering::Equal {
                a.n.cmp(&b.n)
            } else {
                cmp
            }
        });

        let mut buf = Vec::new();
        for op in sorted {
            // Write txid bytes (32) + vout (4 LE)
            buf.extend_from_slice(op.hash.as_bytes());
            buf.extend_from_slice(&op.n.to_le_bytes());
        }

        hash256(&buf)
    }

    /// Serialize the frozen set to bytes.
    ///
    /// Format: count (u32 LE) followed by each outpoint (32 + 4 bytes).
    /// Outpoints are sorted for determinism.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sorted: Vec<&OutPoint> = self.outpoints.iter().collect();
        sorted.sort_by(|a, b| {
            let cmp = a.hash.as_bytes().cmp(b.hash.as_bytes());
            if cmp == std::cmp::Ordering::Equal {
                a.n.cmp(&b.n)
            } else {
                cmp
            }
        });

        let mut buf = Vec::new();
        buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for op in sorted {
            buf.extend_from_slice(op.hash.as_bytes());
            buf.extend_from_slice(&op.n.to_le_bytes());
        }
        buf
    }

    /// Deserialize a frozen set from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
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
}

impl Default for FrozenOutpoints {
    fn default() -> Self {
        Self::new()
    }
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
    fn test_frozen_set_basic() {
        let mut fs = FrozenOutpoints::new();
        let op1 = make_outpoint(1);
        let op2 = make_outpoint(2);

        assert!(!fs.is_frozen(&op1));
        fs.insert(op1.clone());
        assert!(fs.is_frozen(&op1));
        assert!(!fs.is_frozen(&op2));
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut fs = FrozenOutpoints::new();
        for i in 0..10 {
            fs.insert(make_outpoint(i));
        }

        let bytes = fs.to_bytes();
        let fs2 = FrozenOutpoints::from_bytes(&bytes).unwrap();

        assert_eq!(fs.len(), fs2.len());
        for op in fs.iter() {
            assert!(fs2.is_frozen(op));
        }
    }

    #[test]
    fn test_commitment_deterministic() {
        let mut fs1 = FrozenOutpoints::new();
        let mut fs2 = FrozenOutpoints::new();

        // Insert in different order
        fs1.insert(make_outpoint(1));
        fs1.insert(make_outpoint(2));
        fs1.insert(make_outpoint(3));

        fs2.insert(make_outpoint(3));
        fs2.insert(make_outpoint(1));
        fs2.insert(make_outpoint(2));

        assert_eq!(fs1.commitment_hash(), fs2.commitment_hash());
    }

    #[test]
    fn test_empty_set() {
        let fs = FrozenOutpoints::new();
        assert!(fs.is_empty());
        assert_eq!(fs.len(), 0);

        let bytes = fs.to_bytes();
        let fs2 = FrozenOutpoints::from_bytes(&bytes).unwrap();
        assert!(fs2.is_empty());
    }
}
