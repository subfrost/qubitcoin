//! Coin selection algorithms for the Qubitcoin wallet.
//!
//! Maps to: `src/wallet/coinselection.h` and `src/wallet/coinselection.cpp`
//! in Bitcoin Core.
//!
//! Provides two strategies:
//! - **Largest-first**: a straightforward greedy algorithm that picks the
//!   largest UTXOs until the target (plus estimated fee) is met.
//! - **Branch-and-bound (BnB)**: a simplified greedy variant that attempts to
//!   minimize the change output (and thus avoids creating dust).

use crate::wallet::WalletUtxo;
use qubitcoin_primitives::Amount;

// ---------------------------------------------------------------------------
// CoinSelectionResult
// ---------------------------------------------------------------------------

/// The result of a successful coin selection.
#[derive(Debug)]
pub struct CoinSelectionResult {
    /// The UTXOs selected for spending.
    pub selected: Vec<WalletUtxo>,
    /// Sum of the values of the selected UTXOs.
    pub total_value: Amount,
    /// Estimated fee for the transaction.
    pub fee: Amount,
    /// Amount that will go to a change output (`total_value - target - fee`).
    pub change: Amount,
}

// ---------------------------------------------------------------------------
// Fee estimation helpers
// ---------------------------------------------------------------------------

/// Rough estimate of the virtual size of a transaction.
///
/// Assumes P2WPKH inputs (~68 vbytes each) and two outputs (~31 vbytes each)
/// plus a fixed overhead of 11 vbytes (version, locktime, segwit marker).
fn estimate_vsize(num_inputs: usize, num_outputs: usize) -> usize {
    // Base overhead: 4 (version) + 1 (marker) + 1 (flag) + 1 (vin count)
    //             + 1 (vout count) + 4 (locktime) = ~11 vbytes (after witness discount)
    let overhead: usize = 11;
    // P2WPKH input: ~68 vbytes (outpoint 36 + scriptSig 1 + sequence 4 + witness ~27)
    let per_input: usize = 68;
    // Standard output: ~31 vbytes (value 8 + scriptPubKey ~23)
    let per_output: usize = 31;
    overhead + num_inputs * per_input + num_outputs * per_output
}

/// Compute the estimated fee given a number of inputs, outputs, and fee rate.
fn estimate_fee(num_inputs: usize, num_outputs: usize, fee_rate_per_vb: i64) -> Amount {
    let vsize = estimate_vsize(num_inputs, num_outputs) as i64;
    Amount::from_sat(vsize * fee_rate_per_vb)
}

// ---------------------------------------------------------------------------
// Largest-first selection
// ---------------------------------------------------------------------------

/// Select coins using a *largest-first* greedy strategy.
///
/// UTXOs are sorted by value in descending order and picked one-by-one until
/// the accumulated value covers `target + estimated_fee`.  If there is not
/// enough value, `None` is returned.
///
/// The resulting transaction is assumed to have one payment output and
/// potentially one change output (two outputs total).
pub fn select_coins(
    utxos: &[WalletUtxo],
    target: Amount,
    fee_rate_per_vb: i64,
) -> Option<CoinSelectionResult> {
    if utxos.is_empty() || target.to_sat() <= 0 {
        return None;
    }

    // Sort descending by value.
    let mut sorted: Vec<&WalletUtxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.tx_out.value.to_sat().cmp(&a.tx_out.value.to_sat()));

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = Amount::ZERO;

    for utxo in sorted {
        selected.push(utxo.clone());
        total = total + utxo.tx_out.value;

        // Assume 2 outputs (payment + change) once we have at least one input.
        let fee = estimate_fee(selected.len(), 2, fee_rate_per_vb);
        let needed = target + fee;

        if total.to_sat() >= needed.to_sat() {
            let change = total - needed;
            return Some(CoinSelectionResult {
                selected,
                total_value: total,
                fee,
                change,
            });
        }
    }

    // Could not satisfy the target.
    None
}

// ---------------------------------------------------------------------------
// Branch-and-bound (simplified greedy) selection
// ---------------------------------------------------------------------------

/// Select coins using a simplified *branch-and-bound* strategy.
///
/// This is a greedy algorithm that tries to find a combination whose total
/// value is close to `target + fee`, minimising the change output. If the
/// best combination produces change smaller than `cost_of_change` it is
/// considered *exact* and no change output is created (the excess is added
/// to the fee instead).
///
/// The algorithm proceeds in two passes:
/// 1. Try to find a single UTXO that covers the target exactly (within the
///    `cost_of_change` tolerance).
/// 2. Fall back to accumulating the smallest UTXOs first (ascending order) to
///    minimise overshoot.
///
/// Returns `None` when funds are insufficient.
pub fn select_coins_bnb(
    utxos: &[WalletUtxo],
    target: Amount,
    fee_rate_per_vb: i64,
    cost_of_change: Amount,
) -> Option<CoinSelectionResult> {
    if utxos.is_empty() || target.to_sat() <= 0 {
        return None;
    }

    // Pre-sort ascending by value.
    let mut sorted_asc: Vec<&WalletUtxo> = utxos.iter().collect();
    sorted_asc.sort_by(|a, b| a.tx_out.value.to_sat().cmp(&b.tx_out.value.to_sat()));

    // --- Pass 1: look for a single UTXO close to the target ----------------
    // We want total >= target + fee  AND  total - (target + fee) <= cost_of_change
    let fee_one_input_one_output = estimate_fee(1, 1, fee_rate_per_vb);
    let needed_exact = target + fee_one_input_one_output;

    for utxo in sorted_asc.iter().rev() {
        let val = utxo.tx_out.value;
        if val.to_sat() >= needed_exact.to_sat() {
            let excess = val - needed_exact;
            if excess.to_sat() <= cost_of_change.to_sat() {
                // Treat the excess as extra fee (no change output).
                let total_fee = fee_one_input_one_output + excess;
                return Some(CoinSelectionResult {
                    selected: vec![(*utxo).clone()],
                    total_value: val,
                    fee: total_fee,
                    change: Amount::ZERO,
                });
            }
        }
    }

    // --- Pass 2: accumulate smallest-first ---------------------------------
    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = Amount::ZERO;

    for utxo in &sorted_asc {
        selected.push((*utxo).clone());
        total = total + utxo.tx_out.value;

        let num_outputs = 2; // payment + change
        let fee = estimate_fee(selected.len(), num_outputs, fee_rate_per_vb);
        let needed = target + fee;

        if total.to_sat() >= needed.to_sat() {
            let change = total - needed;

            // If change is below cost_of_change, donate it to fees.
            if change.to_sat() <= cost_of_change.to_sat() {
                let total_fee = fee + change;
                return Some(CoinSelectionResult {
                    selected,
                    total_value: total,
                    fee: total_fee,
                    change: Amount::ZERO,
                });
            }

            return Some(CoinSelectionResult {
                selected,
                total_value: total,
                fee,
                change,
            });
        }
    }

    // Insufficient funds.
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::WalletUtxo;
    use qubitcoin_consensus::transaction::{OutPoint, TxOut};
    use qubitcoin_primitives::{Amount, Txid};
    use qubitcoin_script::Script;

    /// Helper: build a mock UTXO with the given value (in satoshis).
    fn mock_utxo(value: i64, index: u32) -> WalletUtxo {
        WalletUtxo {
            outpoint: OutPoint::new(Txid::from_bytes([index as u8; 32]), index),
            tx_out: TxOut::new(Amount::from_sat(value), Script::new()),
            height: Some(1),
            is_change: false,
        }
    }

    // -- select_coins (largest-first) tests ---------------------------------

    #[test]
    fn test_select_coins_basic() {
        let utxos = vec![
            mock_utxo(10_000, 0),
            mock_utxo(20_000, 1),
            mock_utxo(50_000, 2),
        ];

        let result = select_coins(&utxos, Amount::from_sat(15_000), 1).unwrap();
        // Should pick the 50_000 UTXO first (largest).
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_value, Amount::from_sat(50_000));
        assert!(result.fee.to_sat() > 0);
        assert!(result.change.to_sat() > 0);
        // total = fee + target + change
        assert_eq!(
            result.total_value,
            Amount::from_sat(15_000) + result.fee + result.change
        );
    }

    #[test]
    fn test_select_coins_multiple_inputs() {
        let utxos = vec![
            mock_utxo(5_000, 0),
            mock_utxo(6_000, 1),
            mock_utxo(7_000, 2),
        ];
        // Target is higher than the largest single UTXO.
        let result = select_coins(&utxos, Amount::from_sat(10_000), 1).unwrap();
        assert!(result.selected.len() >= 2);
        assert!(result.total_value.to_sat() >= 10_000 + result.fee.to_sat());
    }

    #[test]
    fn test_select_coins_insufficient_funds() {
        let utxos = vec![mock_utxo(1_000, 0)];
        let result = select_coins(&utxos, Amount::from_sat(100_000), 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_coins_empty_utxos() {
        let result = select_coins(&[], Amount::from_sat(1_000), 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_coins_fee_rate_impact() {
        let utxos = vec![mock_utxo(100_000, 0)];
        let low = select_coins(&utxos, Amount::from_sat(50_000), 1).unwrap();
        let high = select_coins(&utxos, Amount::from_sat(50_000), 10).unwrap();
        assert!(high.fee.to_sat() > low.fee.to_sat());
        assert!(high.change.to_sat() < low.change.to_sat());
    }

    // -- select_coins_bnb tests ---------------------------------------------

    #[test]
    fn test_bnb_exact_match() {
        // A single UTXO whose value is close enough to target + 1-in/1-out fee.
        let fee_1_1 = estimate_fee(1, 1, 1);
        let target = Amount::from_sat(10_000);
        let exact_value = target.to_sat() + fee_1_1.to_sat() + 50; // small excess
        let utxos = vec![mock_utxo(exact_value, 0)];

        let result = select_coins_bnb(
            &utxos,
            target,
            1,
            Amount::from_sat(500), // cost_of_change
        )
        .unwrap();

        // Should select the single UTXO with no change output.
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.change, Amount::ZERO);
    }

    #[test]
    fn test_bnb_smallest_first_fallback() {
        let utxos = vec![
            mock_utxo(3_000, 0),
            mock_utxo(4_000, 1),
            mock_utxo(5_000, 2),
            mock_utxo(100_000, 3),
        ];

        let result =
            select_coins_bnb(&utxos, Amount::from_sat(10_000), 1, Amount::from_sat(200)).unwrap();

        // The algorithm should accumulate smallest first rather than picking the
        // 100_000 UTXO (which has too much excess for exact match pass).
        assert!(result.total_value.to_sat() >= 10_000 + result.fee.to_sat());
    }

    #[test]
    fn test_bnb_insufficient_funds() {
        let utxos = vec![mock_utxo(500, 0), mock_utxo(500, 1)];
        let result = select_coins_bnb(&utxos, Amount::from_sat(100_000), 1, Amount::from_sat(500));
        assert!(result.is_none());
    }

    #[test]
    fn test_bnb_empty_utxos() {
        let result = select_coins_bnb(&[], Amount::from_sat(1_000), 1, Amount::from_sat(500));
        assert!(result.is_none());
    }
}
