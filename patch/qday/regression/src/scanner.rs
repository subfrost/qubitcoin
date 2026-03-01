//! UTXO scanning for frozen set computation.
//!
//! At activation height, the node iterates the entire UTXO set, scores
//! each output for quantum vulnerability, and builds the frozen set.

use crate::error::QdayError;
use crate::frozen_set::FrozenOutpoints;
use crate::scoring::{compute_score, is_p2pk, is_p2tr, is_p2pkh, VulnType};
use qubitcoin_consensus::OutPoint;
use qubitcoin_script::Script;

/// A UTXO entry returned by the UTXO iterator.
pub struct UtxoEntry {
    /// The outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// The scriptPubKey of this output.
    pub script_pubkey: Script,
    /// Value in satoshis.
    pub value: u64,
    /// Block height where this output was created.
    pub height: u32,
    /// Whether this output is from a coinbase transaction.
    pub is_coinbase: bool,
}

/// Trait for iterating over the UTXO set.
///
/// Implementors should provide sequential access to all UTXOs in the
/// coins database. This is used at activation height to compute the
/// frozen set.
pub trait UtxoIterator {
    /// Advance to the next UTXO entry.
    ///
    /// Returns `None` when iteration is complete, or an error string
    /// if the database read fails.
    fn next_utxo(&mut self) -> Result<Option<UtxoEntry>, String>;
}

/// Set of pubkey hashes that have been exposed by prior spends.
///
/// In production, this would be populated by scanning the spend history
/// or maintained as an index. For the frozen set computation, it can be
/// provided externally.
pub type ExposedKeySet = std::collections::HashSet<[u8; 20]>;

/// Compute the frozen outpoints set by scanning the UTXO set.
///
/// This function is called exactly once at the activation height.
/// It iterates every UTXO, checks for quantum vulnerability, computes
/// the safety score, and includes outputs above the threshold.
///
/// # Arguments
///
/// * `utxo_iter` - Iterator over all UTXOs in the coins database
/// * `exposed_keys` - Set of pubkey hashes revealed by prior spends
/// * `current_height` - The activation height
/// * `score_threshold` - Minimum score for an output to be frozen
pub fn compute_frozen_set(
    utxo_iter: &mut dyn UtxoIterator,
    exposed_keys: &ExposedKeySet,
    current_height: u32,
    score_threshold: u16,
) -> Result<FrozenOutpoints, QdayError> {
    let mut frozen = FrozenOutpoints::new();

    loop {
        let entry = utxo_iter
            .next_utxo()
            .map_err(|e| QdayError::UtxoIteration(e))?;

        let entry = match entry {
            Some(e) => e,
            None => break,
        };

        // Check vulnerability type
        let vuln_type = if is_p2pk(&entry.script_pubkey).is_some() {
            Some(VulnType::P2PK)
        } else if is_p2tr(&entry.script_pubkey).is_some() {
            Some(VulnType::P2TR)
        } else if let Some(pkh) = is_p2pkh(&entry.script_pubkey) {
            if exposed_keys.contains(&pkh) {
                Some(VulnType::ExposedP2PKH)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(_vtype) = vuln_type {
            let score = compute_score(
                entry.height,
                current_height,
                entry.value,
                entry.is_coinbase,
            );

            if score >= score_threshold {
                frozen.insert(entry.outpoint);
            }
        }
    }

    Ok(frozen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qubitcoin_primitives::Txid;

    struct MockUtxoIter {
        entries: Vec<UtxoEntry>,
        index: usize,
    }

    impl UtxoIterator for MockUtxoIter {
        fn next_utxo(&mut self) -> Result<Option<UtxoEntry>, String> {
            if self.index >= self.entries.len() {
                return Ok(None);
            }
            let entry = UtxoEntry {
                outpoint: self.entries[self.index].outpoint.clone(),
                script_pubkey: self.entries[self.index].script_pubkey.clone(),
                value: self.entries[self.index].value,
                height: self.entries[self.index].height,
                is_coinbase: self.entries[self.index].is_coinbase,
            };
            self.index += 1;
            Ok(Some(entry))
        }
    }

    fn make_p2pk_script() -> Script {
        // Compressed P2PK: 0x21 <33 bytes> 0xac
        let mut bytes = vec![0x21];
        let mut pubkey = vec![0x02];
        pubkey.extend_from_slice(&[0xaa; 32]);
        bytes.extend_from_slice(&pubkey);
        bytes.push(0xac);
        Script::from_bytes(bytes)
    }

    fn make_p2pkh_script(hash: &[u8; 20]) -> Script {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(hash);
        bytes.extend_from_slice(&[0x88, 0xac]);
        Script::from_bytes(bytes)
    }

    #[test]
    fn test_compute_frozen_set_p2pk() {
        let op = OutPoint::new(Txid::from_bytes([1u8; 32]), 0);
        let entries = vec![UtxoEntry {
            outpoint: op.clone(),
            script_pubkey: make_p2pk_script(),
            value: 5000,            // dust - high value score
            height: 100,            // very early - high age score
            is_coinbase: true,      // coinbase pattern bonus
        }];

        let mut iter = MockUtxoIter {
            entries,
            index: 0,
        };
        let exposed = ExposedKeySet::new();
        let frozen = compute_frozen_set(&mut iter, &exposed, 800_000, 500).unwrap();

        assert!(frozen.is_frozen(&op));
    }

    #[test]
    fn test_below_threshold_not_frozen() {
        let op = OutPoint::new(Txid::from_bytes([2u8; 32]), 0);
        let entries = vec![UtxoEntry {
            outpoint: op.clone(),
            script_pubkey: make_p2pk_script(),
            value: 200_000_000_000, // 2000 BTC - low value score
            height: 800_000,        // recent - low age
            is_coinbase: false,
        }];

        let mut iter = MockUtxoIter {
            entries,
            index: 0,
        };
        let exposed = ExposedKeySet::new();
        let frozen = compute_frozen_set(&mut iter, &exposed, 800_001, 500).unwrap();

        assert!(!frozen.is_frozen(&op));
    }

    #[test]
    fn test_exposed_p2pkh_included() {
        let hash = [0xcc; 20];
        let op = OutPoint::new(Txid::from_bytes([3u8; 32]), 0);
        let entries = vec![UtxoEntry {
            outpoint: op.clone(),
            script_pubkey: make_p2pkh_script(&hash),
            value: 1000,
            height: 50,
            is_coinbase: true,
        }];

        let mut iter = MockUtxoIter {
            entries,
            index: 0,
        };
        let mut exposed = ExposedKeySet::new();
        exposed.insert(hash);

        let frozen = compute_frozen_set(&mut iter, &exposed, 800_000, 500).unwrap();
        assert!(frozen.is_frozen(&op));
    }

    #[test]
    fn test_unexposed_p2pkh_not_included() {
        let hash = [0xcc; 20];
        let op = OutPoint::new(Txid::from_bytes([4u8; 32]), 0);
        let entries = vec![UtxoEntry {
            outpoint: op.clone(),
            script_pubkey: make_p2pkh_script(&hash),
            value: 1000,
            height: 50,
            is_coinbase: true,
        }];

        let mut iter = MockUtxoIter {
            entries,
            index: 0,
        };
        let exposed = ExposedKeySet::new(); // Empty - key not exposed

        let frozen = compute_frozen_set(&mut iter, &exposed, 800_000, 500).unwrap();
        assert!(!frozen.is_frozen(&op));
    }
}
