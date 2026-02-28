//! Partially Signed Bitcoin Transaction (PSBT) -- simplified BIP 174.
//!
//! Maps to: `src/psbt.h` and `src/psbt.cpp` in Bitcoin Core.
//!
//! This is a minimal implementation sufficient for the wallet to build,
//! sign, and finalize transactions.  Full BIP-174 serialization is not
//! yet implemented.

use std::collections::HashMap;

use qubitcoin_consensus::transaction::{Transaction, TxIn, TxOut, Witness};
use qubitcoin_script::Script;

// ---------------------------------------------------------------------------
// PsbtInput
// ---------------------------------------------------------------------------

/// Per-input metadata carried alongside the unsigned transaction.
#[derive(Debug, Clone, Default)]
pub struct PsbtInput {
    /// The witness UTXO being spent (for segwit inputs).
    pub witness_utxo: Option<TxOut>,
    /// Partial signatures: compressed-pubkey bytes -> DER-encoded signature.
    pub partial_sigs: HashMap<Vec<u8>, Vec<u8>>,
    /// The finalized scriptSig (set after finalization).
    pub final_script_sig: Option<Script>,
    /// The finalized witness (set after finalization).
    pub final_witness: Option<Witness>,
}

impl PsbtInput {
    /// Whether this input has been finalized (has a final scriptSig or witness).
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_witness.is_some()
    }
}

// ---------------------------------------------------------------------------
// PsbtOutput
// ---------------------------------------------------------------------------

/// Per-output metadata (minimal for now).
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    // Reserved for future fields (BIP-32 derivation paths, etc.).
}

// ---------------------------------------------------------------------------
// Psbt
// ---------------------------------------------------------------------------

/// A simplified Partially Signed Bitcoin Transaction (BIP 174).
///
/// Holds an unsigned transaction together with per-input and per-output
/// metadata that signers populate incrementally.
#[derive(Debug, Clone)]
pub struct Psbt {
    /// The unsigned base transaction.
    pub unsigned_tx: Transaction,
    /// Per-input signing / UTXO data.
    pub inputs: Vec<PsbtInput>,
    /// Per-output data.
    pub outputs: Vec<PsbtOutput>,
}

impl Psbt {
    /// Create a PSBT from an unsigned transaction.
    ///
    /// The transaction's scriptSigs and witnesses are expected to be empty.
    /// One `PsbtInput` / `PsbtOutput` entry is created for each input / output.
    pub fn from_unsigned_tx(tx: Transaction) -> Self {
        let num_inputs = tx.vin.len();
        let num_outputs = tx.vout.len();
        Psbt {
            unsigned_tx: tx,
            inputs: vec![PsbtInput::default(); num_inputs],
            outputs: vec![PsbtOutput::default(); num_outputs],
        }
    }

    /// Check whether *all* inputs have been finalized.
    pub fn is_finalized(&self) -> bool {
        !self.inputs.is_empty() && self.inputs.iter().all(|i| i.is_finalized())
    }

    /// Try to finalize every input.
    ///
    /// For each non-finalized input that has at least one partial signature
    /// and a `witness_utxo`, a simple P2WPKH finalization is attempted:
    ///
    /// * `final_script_sig` is set to an empty script (native segwit).
    /// * `final_witness` is set to `[signature, pubkey]`.
    ///
    /// Returns `true` if the PSBT is fully finalized after this call.
    pub fn finalize(&mut self) -> bool {
        for input in &mut self.inputs {
            if input.is_finalized() {
                continue;
            }

            // Simple P2WPKH finalization: requires exactly one partial sig.
            if input.partial_sigs.len() == 1 && input.witness_utxo.is_some() {
                let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();

                input.final_witness = Some(Witness {
                    stack: vec![sig.clone(), pubkey.clone()],
                });
                input.final_script_sig = Some(Script::new());
            }
        }

        self.is_finalized()
    }

    /// Extract the fully-signed transaction from a finalized PSBT.
    ///
    /// Returns `None` if the PSBT is not fully finalized.
    pub fn extract_tx(&self) -> Option<Transaction> {
        if !self.is_finalized() {
            return None;
        }

        let mut vin: Vec<TxIn> = Vec::with_capacity(self.unsigned_tx.vin.len());

        for (i, orig_input) in self.unsigned_tx.vin.iter().enumerate() {
            let psbt_in = &self.inputs[i];

            let script_sig = psbt_in.final_script_sig.clone().unwrap_or_else(Script::new);

            let witness = psbt_in.final_witness.clone().unwrap_or_else(Witness::new);

            let mut txin = TxIn::new(orig_input.prevout.clone(), script_sig, orig_input.sequence);
            txin.witness = witness;
            vin.push(txin);
        }

        let vout = self.unsigned_tx.vout.clone();
        Some(Transaction::new(
            self.unsigned_tx.version,
            vin,
            vout,
            self.unsigned_tx.lock_time,
        ))
    }

    /// Add a partial signature for the input at the given index.
    ///
    /// `pubkey` is the compressed public key bytes, `sig` the DER-encoded
    /// signature (with sighash byte appended).
    pub fn add_partial_sig(&mut self, input_index: usize, pubkey: Vec<u8>, sig: Vec<u8>) {
        if let Some(input) = self.inputs.get_mut(input_index) {
            input.partial_sigs.insert(pubkey, sig);
        }
    }

    /// Set the witness UTXO for the input at the given index.
    pub fn set_witness_utxo(&mut self, input_index: usize, utxo: TxOut) {
        if let Some(input) = self.inputs.get_mut(input_index) {
            input.witness_utxo = Some(utxo);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qubitcoin_consensus::transaction::{OutPoint, TxIn, TxOut, SEQUENCE_FINAL};
    use qubitcoin_primitives::{Amount, Txid};
    use qubitcoin_script::Script;

    /// Helper: build a minimal unsigned transaction with one input and one output.
    fn make_unsigned_tx() -> Transaction {
        let input = TxIn::new(
            OutPoint::new(Txid::from_bytes([0xaa; 32]), 0),
            Script::new(), // empty scriptSig (unsigned)
            SEQUENCE_FINAL,
        );
        let output = TxOut::new(
            Amount::from_sat(49_000),
            Script::from_bytes(vec![
                0x00, 0x14, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            ]),
        );
        Transaction::new(2, vec![input], vec![output], 0)
    }

    #[test]
    fn test_psbt_from_unsigned_tx() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx);

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert!(!psbt.is_finalized());
    }

    #[test]
    fn test_psbt_not_finalized_without_sigs() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx);

        // Attempting to finalize without any signatures should fail.
        assert!(!psbt.finalize());
        assert!(!psbt.is_finalized());
        assert!(psbt.extract_tx().is_none());
    }

    #[test]
    fn test_psbt_finalize_p2wpkh() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx);

        // Provide a mock witness UTXO and partial signature.
        let mock_utxo = TxOut::new(
            Amount::from_sat(50_000),
            Script::from_bytes(vec![
                0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            ]),
        );
        psbt.set_witness_utxo(0, mock_utxo);

        let mock_pubkey = vec![0x02; 33]; // mock compressed pubkey
        let mut mock_sig = vec![0x30, 0x44];
        mock_sig.extend_from_slice(&[0x00; 70]); // mock DER sig
        psbt.add_partial_sig(0, mock_pubkey.clone(), mock_sig.clone());

        // Finalize.
        assert!(psbt.finalize());
        assert!(psbt.is_finalized());

        // Extract the signed transaction.
        let signed_tx = psbt.extract_tx().unwrap();
        assert_eq!(signed_tx.vin.len(), 1);
        assert!(!signed_tx.vin[0].witness.is_null());
        assert_eq!(signed_tx.vin[0].witness.stack.len(), 2);
    }

    #[test]
    fn test_psbt_extract_preserves_outputs() {
        let tx = make_unsigned_tx();
        let original_vout = tx.vout.clone();
        let mut psbt = Psbt::from_unsigned_tx(tx);

        // Set up for finalization.
        psbt.set_witness_utxo(0, TxOut::new(Amount::from_sat(50_000), Script::new()));
        psbt.add_partial_sig(0, vec![0x03; 33], vec![0x30; 72]);
        psbt.finalize();

        let signed = psbt.extract_tx().unwrap();
        assert_eq!(signed.vout.len(), original_vout.len());
        assert_eq!(signed.vout[0].value, original_vout[0].value);
    }

    #[test]
    fn test_psbt_multi_input() {
        let input0 = TxIn::new(
            OutPoint::new(Txid::from_bytes([0xaa; 32]), 0),
            Script::new(),
            SEQUENCE_FINAL,
        );
        let input1 = TxIn::new(
            OutPoint::new(Txid::from_bytes([0xbb; 32]), 1),
            Script::new(),
            SEQUENCE_FINAL,
        );
        let output = TxOut::new(Amount::from_sat(90_000), Script::new());
        let tx = Transaction::new(2, vec![input0, input1], vec![output], 0);

        let mut psbt = Psbt::from_unsigned_tx(tx);
        assert_eq!(psbt.inputs.len(), 2);

        // Only finalize the first input.
        psbt.set_witness_utxo(0, TxOut::new(Amount::from_sat(50_000), Script::new()));
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72]);

        // Should not be fully finalized.
        assert!(!psbt.finalize());
        assert!(!psbt.is_finalized());

        // Now finalize the second input.
        psbt.set_witness_utxo(1, TxOut::new(Amount::from_sat(50_000), Script::new()));
        psbt.add_partial_sig(1, vec![0x03; 33], vec![0x30; 72]);

        assert!(psbt.finalize());
        assert!(psbt.is_finalized());
        assert!(psbt.extract_tx().is_some());
    }
}
