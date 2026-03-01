//! Consensus-level enforcement of frozen outpoints.
//!
//! Provides `check_qday_frozen()` which is called during `connect_block()`
//! for each transaction after `check_tx_inputs()`.

use crate::error::QdayError;
use crate::policy::QdayPolicy;
use qubitcoin_consensus::{Transaction, TxValidationResult, ValidationState};

/// Check if a transaction spends any frozen outpoints.
///
/// Returns `Ok(())` if the transaction is valid, or `Err(QdayError)` if it
/// attempts to spend a frozen quantum-vulnerable outpoint.
///
/// This function should be called in `connect_block()` for each non-coinbase
/// transaction, AFTER `check_tx_inputs()` succeeds.
pub fn check_qday_frozen(
    tx: &Transaction,
    policy: &QdayPolicy,
    height: i32,
) -> Result<(), QdayError> {
    if !policy.is_active(height) {
        return Ok(());
    }

    if tx.is_coinbase() {
        return Ok(());
    }

    for input in tx.vin.iter() {
        let outpoint = &input.prevout;
        if policy.frozen_outpoints.is_frozen(outpoint) {
            return Err(QdayError::FrozenOutpointSpent {
                txid: format!("{}", outpoint.hash),
                vout: outpoint.n,
                score: policy.score_threshold,
            });
        }
    }

    Ok(())
}

/// Apply Q-Day check and set validation state on failure.
///
/// Convenience wrapper that translates `QdayError` into a `TxValidationResult`
/// for integration with the existing validation pipeline.
pub fn check_qday_frozen_with_state(
    tx: &Transaction,
    policy: &QdayPolicy,
    height: i32,
    state: &mut ValidationState<TxValidationResult>,
) -> bool {
    match check_qday_frozen(tx, policy, height) {
        Ok(()) => true,
        Err(e) => {
            state.invalid(
                TxValidationResult::Consensus,
                "qday-frozen",
                &e.to_string(),
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frozen_set::FrozenOutpoints;
    use qubitcoin_consensus::{OutPoint, TxIn, TxOut, Witness};
    use qubitcoin_primitives::{Amount, Txid};
    use qubitcoin_script::Script;

    fn make_outpoint(n: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&n.to_le_bytes());
        OutPoint::new(Txid::from_bytes(bytes), n)
    }

    fn make_tx(inputs: Vec<OutPoint>) -> Transaction {
        let vin: Vec<TxIn> = inputs
            .into_iter()
            .map(|op| TxIn {
                prevout: op,
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect();

        Transaction::new(
            2, // version
            vin,
            vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::new(),
            }],
            0, // locktime
        )
    }

    #[test]
    fn test_inactive_policy_allows_all() {
        let policy = QdayPolicy::disabled();
        let tx = make_tx(vec![make_outpoint(1)]);
        assert!(check_qday_frozen(&tx, &policy, 900_000).is_ok());
    }

    #[test]
    fn test_frozen_outpoint_rejected() {
        let op = make_outpoint(42);
        let mut frozen = FrozenOutpoints::new();
        frozen.insert(op.clone());

        let mut policy = QdayPolicy::new(850_000, 500);
        policy.frozen_outpoints = frozen;

        let tx = make_tx(vec![op]);
        let result = check_qday_frozen(&tx, &policy, 850_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            QdayError::FrozenOutpointSpent { vout, .. } => assert_eq!(vout, 42),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_non_frozen_outpoint_allowed() {
        let frozen_op = make_outpoint(42);
        let spending_op = make_outpoint(99);

        let mut frozen = FrozenOutpoints::new();
        frozen.insert(frozen_op);

        let mut policy = QdayPolicy::new(850_000, 500);
        policy.frozen_outpoints = frozen;

        let tx = make_tx(vec![spending_op]);
        assert!(check_qday_frozen(&tx, &policy, 850_000).is_ok());
    }

    #[test]
    fn test_below_activation_height() {
        let op = make_outpoint(42);
        let mut frozen = FrozenOutpoints::new();
        frozen.insert(op.clone());

        let mut policy = QdayPolicy::new(850_000, 500);
        policy.frozen_outpoints = frozen;

        let tx = make_tx(vec![op]);
        // Below activation height - should pass
        assert!(check_qday_frozen(&tx, &policy, 849_999).is_ok());
    }
}
