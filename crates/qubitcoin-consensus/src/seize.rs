//! Q-Day seize transaction construction and validation.
//!
//! At the seize activation height, frozen quantum-vulnerable UTXOs are
//! consensus-seized via special transactions that move funds to a
//! FROST-controlled P2MR address.

use crate::qday_seize::FrozenOutpoints;
use crate::transaction::{OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness};
use qubitcoin_primitives::Amount;
use qubitcoin_script::Script;

/// Maximum number of inputs per seize transaction.
///
/// Keeps individual seize transactions at a reasonable size.
const MAX_SEIZE_INPUTS_PER_TX: usize = 5000;

/// Seize transaction version number.
/// Version 3 distinguishes seize transactions from regular transactions.
pub const SEIZE_TX_VERSION: u32 = 3;

/// Represents a frozen UTXO with its value.
#[derive(Debug, Clone)]
pub struct FrozenUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
}

/// Create seize transactions that move frozen UTXOs to the FROST P2MR address.
///
/// `coin_value_lookup` is a closure that returns the value of a UTXO given
/// its outpoint, or `None` if the outpoint is not in the UTXO set.
///
/// Returns an ordered vector of seize transactions. Each transaction:
/// - Has version 3
/// - Inputs: frozen outpoints with empty scriptsig/witness
/// - Output: single P2MR output with sum of input values
/// - lock_time: 0
pub fn create_seize_transactions<F>(
    frozen: &FrozenOutpoints,
    coin_value_lookup: F,
    seize_script: &Script,
) -> Vec<Transaction>
where
    F: Fn(&OutPoint) -> Option<Amount>,
{
    // Collect all frozen UTXOs that exist in the UTXO set
    let frozen_utxos: Vec<FrozenUtxo> = frozen
        .iter_sorted()
        .into_iter()
        .filter_map(|outpoint| {
            coin_value_lookup(&outpoint).map(|value| FrozenUtxo { outpoint, value })
        })
        .collect();

    if frozen_utxos.is_empty() {
        return Vec::new();
    }

    // Batch into transactions
    let mut transactions = Vec::new();
    for chunk in frozen_utxos.chunks(MAX_SEIZE_INPUTS_PER_TX) {
        let vin: Vec<TxIn> = chunk
            .iter()
            .map(|fu| TxIn {
                prevout: fu.outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect();

        let total_value: Amount = chunk.iter().fold(Amount::ZERO, |sum, fu| sum + fu.value);

        let vout = vec![TxOut {
            value: total_value,
            script_pubkey: seize_script.clone(),
        }];

        let tx = Transaction::new(SEIZE_TX_VERSION, vin, vout, 0);
        transactions.push(tx);
    }

    transactions
}

/// Validate that a transaction is a valid seize transaction.
///
/// Checks:
/// - Transaction version == 3
/// - All inputs are frozen outpoints
/// - Single output to the seize script
/// - Values balance (sum of input values == output value)
pub fn validate_seize_transaction<F>(
    tx: &Transaction,
    frozen: &FrozenOutpoints,
    seize_script: &Script,
    coin_value_lookup: F,
) -> bool
where
    F: Fn(&OutPoint) -> Option<Amount>,
{
    // Check version
    if tx.version != SEIZE_TX_VERSION {
        return false;
    }

    // Check single output to seize script
    if tx.vout.len() != 1 || tx.vout[0].script_pubkey != *seize_script {
        return false;
    }

    // Check all inputs are frozen and compute expected total value
    let mut total_input_value = Amount::ZERO;
    for input in &tx.vin {
        if !frozen.is_frozen(&input.prevout) {
            return false;
        }
        match coin_value_lookup(&input.prevout) {
            Some(value) => total_input_value = total_input_value + value,
            None => return false,
        }
    }

    // Check values balance
    if tx.vout[0].value != total_input_value {
        return false;
    }

    // Check lock_time is 0
    if tx.lock_time != 0 {
        return false;
    }

    true
}

/// Validate that a block at the seize height contains the expected seize transactions.
///
/// The seize transactions must appear immediately after the coinbase transaction,
/// in the exact order produced by `create_seize_transactions`.
///
/// Accepts `&[TransactionRef]` (i.e. `&[Arc<Transaction>]`) to match the block's
/// `vtx` field type directly.
pub fn validate_seize_block(
    block_txs: &[TransactionRef],
    expected_seize_txs: &[Transaction],
) -> Result<(), &'static str> {
    if expected_seize_txs.is_empty() {
        return Ok(());
    }

    // Block must have at least coinbase + seize transactions
    let min_txs = 1 + expected_seize_txs.len();
    if block_txs.len() < min_txs {
        return Err("block missing required seize transactions");
    }

    // Seize transactions must appear right after coinbase
    for (i, expected_tx) in expected_seize_txs.iter().enumerate() {
        let block_tx = &block_txs[1 + i]; // skip coinbase at index 0

        // Compare txids
        if block_tx.txid() != expected_tx.txid() {
            return Err("seize transaction mismatch in block");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qubitcoin_primitives::Txid;
    use std::sync::Arc;

    fn make_outpoint(n: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&n.to_le_bytes());
        OutPoint::new(Txid::from_bytes(bytes), n)
    }

    fn make_seize_script() -> Script {
        qubitcoin_script::build_p2mr(&[0xaa; 32])
    }

    #[test]
    fn test_create_seize_transactions() {
        let mut frozen = FrozenOutpoints::new();
        for i in 0..3 {
            frozen.insert(make_outpoint(i));
        }

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(10_000)) };

        let txs = create_seize_transactions(&frozen, lookup, &seize_script);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].vin.len(), 3);
        assert_eq!(txs[0].vout.len(), 1);
        assert_eq!(txs[0].vout[0].value, Amount::from_sat(30_000));
        assert_eq!(txs[0].version, SEIZE_TX_VERSION);
    }

    #[test]
    fn test_create_seize_transactions_batching() {
        let mut frozen = FrozenOutpoints::new();
        // Create more than MAX_SEIZE_INPUTS_PER_TX outpoints
        for i in 0..5002 {
            frozen.insert(make_outpoint(i));
        }

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(1_000)) };

        let txs = create_seize_transactions(&frozen, lookup, &seize_script);
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].vin.len(), 5000);
        assert_eq!(txs[1].vin.len(), 2);
    }

    #[test]
    fn test_validate_seize_transaction() {
        let mut frozen = FrozenOutpoints::new();
        for i in 0..3 {
            frozen.insert(make_outpoint(i));
        }

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(10_000)) };

        let txs = create_seize_transactions(&frozen, &lookup, &seize_script);
        assert!(validate_seize_transaction(
            &txs[0],
            &frozen,
            &seize_script,
            &lookup
        ));
    }

    #[test]
    fn test_validate_seize_transaction_wrong_version() {
        let mut frozen = FrozenOutpoints::new();
        frozen.insert(make_outpoint(0));

        let seize_script = make_seize_script();

        // Create a tx with wrong version
        let tx = Transaction::new(
            2, // wrong version
            vec![TxIn {
                prevout: make_outpoint(0),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            }],
            vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: seize_script.clone(),
            }],
            0,
        );

        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(10_000)) };
        assert!(!validate_seize_transaction(&tx, &frozen, &seize_script, lookup));
    }

    #[test]
    fn test_value_conservation() {
        let mut frozen = FrozenOutpoints::new();
        for i in 0..5 {
            frozen.insert(make_outpoint(i));
        }

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> {
            Some(Amount::from_sat((op.n as i64 + 1) * 10_000))
        };

        let txs = create_seize_transactions(&frozen, &lookup, &seize_script);
        let total_in: i64 = (1..=5).map(|i| i * 10_000i64).sum();
        let total_out: i64 = txs.iter().map(|tx| tx.vout[0].value.to_sat()).sum();
        assert_eq!(total_in, total_out);
    }

    #[test]
    fn test_validate_seize_block() {
        let mut frozen = FrozenOutpoints::new();
        frozen.insert(make_outpoint(0));

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(10_000)) };

        let seize_txs = create_seize_transactions(&frozen, &lookup, &seize_script);

        // Build a mock block with coinbase + seize tx
        let coinbase = Transaction::new(
            2,
            vec![TxIn::new(OutPoint::null(), Script::new(), 0xffffffff)],
            vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: Script::new(),
            }],
            0,
        );

        let mut block_txs: Vec<TransactionRef> = vec![Arc::new(coinbase)];
        for tx in &seize_txs {
            block_txs.push(Arc::new(tx.clone()));
        }

        assert!(validate_seize_block(&block_txs, &seize_txs).is_ok());
    }

    #[test]
    fn test_validate_seize_block_missing() {
        let mut frozen = FrozenOutpoints::new();
        frozen.insert(make_outpoint(0));

        let seize_script = make_seize_script();
        let lookup = |op: &OutPoint| -> Option<Amount> { Some(Amount::from_sat(10_000)) };

        let seize_txs = create_seize_transactions(&frozen, &lookup, &seize_script);

        // Block with only coinbase (missing seize tx)
        let coinbase = Transaction::new(
            2,
            vec![TxIn::new(OutPoint::null(), Script::new(), 0xffffffff)],
            vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: Script::new(),
            }],
            0,
        );

        let block_txs: Vec<TransactionRef> = vec![Arc::new(coinbase)];
        assert!(validate_seize_block(&block_txs, &seize_txs).is_err());
    }
}
