//! Ephemeral dust policy.
//!
//! Port of Bitcoin Core's `policy/ephemeral_policy.cpp` (v29): a
//! transaction may carry one dust output (for example a zero-value
//! Pay-to-Anchor) only if it pays no fee itself, so there is never an
//! incentive to mine it alone, and the dust must be spent by a child in the
//! same package.

use std::collections::{HashMap, HashSet};

use qubitcoin_consensus::transaction::{OutPoint, Transaction, TransactionRef};
use qubitcoin_primitives::{Amount, Txid};

use crate::mempool::{is_dust, FeeRate, TxMemPool};

/// Maximum number of dust outputs a standard transaction may have
/// (Core's `MAX_DUST_OUTPUTS_PER_TX`).
pub const MAX_DUST_OUTPUTS_PER_TX: usize = 1;

/// Number of outputs of `tx` that are dust at `dust_relay_fee`.
pub fn dust_output_count(tx: &Transaction, dust_relay_fee: FeeRate) -> usize {
    tx.vout.iter().filter(|o| is_dust(o, dust_relay_fee)).count()
}

/// Port of Core's `HasDust()`.
pub fn has_dust(tx: &Transaction, dust_relay_fee: FeeRate) -> bool {
    dust_output_count(tx, dust_relay_fee) > 0
}

/// Port of Core's `PreCheckEphemeralTx()`: a transaction with dust must be
/// zero-fee (both base and modified fee). Returns the debug message on
/// failure; the reject reason is `"dust"`.
pub fn pre_check_ephemeral_tx(
    tx: &Transaction,
    dust_relay_fee: FeeRate,
    base_fee: Amount,
    mod_fee: i64,
) -> Result<(), String> {
    if (base_fee.to_sat() != 0 || mod_fee != 0) && has_dust(tx, dust_relay_fee) {
        return Err("tx with dust output must be 0-fee".to_string());
    }
    Ok(())
}

/// Port of Core's `CheckEphemeralSpends()`: every dust output of a parent
/// (in the package or in the mempool) must be spent by each child that
/// spends that parent. On failure returns the offending child's index in
/// `package` and the debug message (reject reason
/// `"missing-ephemeral-spends"`).
pub fn check_ephemeral_spends(
    package: &[TransactionRef],
    dust_relay_fee: FeeRate,
    pool: &TxMemPool,
) -> Result<(), (usize, String)> {
    let by_txid: HashMap<Txid, &TransactionRef> = package.iter().map(|t| (*t.txid(), t)).collect();
    for (i, tx) in package.iter().enumerate() {
        let mut processed: HashSet<Txid> = HashSet::new();
        let mut unspent_dust: HashSet<OutPoint> = HashSet::new();
        for input in &tx.vin {
            let parent_txid = input.prevout.hash;
            if !processed.insert(parent_txid) {
                continue;
            }
            let parent = match by_txid.get(&parent_txid) {
                Some(p) => Some((*p).clone()),
                None => pool.get(&parent_txid),
            };
            if let Some(parent) = parent {
                for (n, out) in parent.vout.iter().enumerate() {
                    if is_dust(out, dust_relay_fee) {
                        unspent_dust.insert(OutPoint::new(parent_txid, n as u32));
                    }
                }
            }
        }
        if unspent_dust.is_empty() {
            continue;
        }
        for input in &tx.vin {
            unspent_dust.remove(&input.prevout);
        }
        if !unspent_dust.is_empty() {
            return Err((
                i,
                format!(
                    "tx {} (wtxid={}) did not spend parent's ephemeral dust",
                    tx.txid().to_hex(),
                    tx.wtxid().to_hex()
                ),
            ));
        }
    }
    Ok(())
}
