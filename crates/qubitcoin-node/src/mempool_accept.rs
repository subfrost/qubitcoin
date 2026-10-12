//! Mempool acceptance with full input resolution, for single transactions
//! and packages.
//!
//! Port of the `MemPoolAccept` class in Bitcoin Core's `validation.cpp`
//! (`PreChecks`, `ReplacementChecks`, `PolicyScriptChecks`,
//! `AcceptSingleTransaction`, `AcceptMultipleTransactions` /
//! `AcceptPackage`, `IsWellFormedPackage` from `policy/packages.cpp`, and the
//! standardness subset of `IsStandardTx` from `policy/policy.cpp`), with the
//! TRUC ([`crate::truc_policy`]) and ephemeral-dust
//! ([`crate::ephemeral_policy`]) rules.
//!
//! Inputs are resolved against the confirmed UTXO set, the mempool, and (for
//! packages) earlier package members. Every accepting entry point in the
//! node (P2P `tx`, `sendrawtransaction`, `testmempoolaccept`,
//! `submitpackage`) goes through here.

use std::collections::{HashMap, HashSet};

use qubitcoin_common::coins::CoinsView;
use qubitcoin_consensus::check::{check_transaction, get_transaction_sigop_cost, COINBASE_MATURITY};
use qubitcoin_consensus::transaction::{
    serialize_transaction, OutPoint, Transaction, TransactionRef, TxOut, SEQUENCE_FINAL,
};
use qubitcoin_consensus::validation_state::TxValidationState;
use qubitcoin_primitives::{Amount, Txid};

use crate::chainstate::ChainstateManager;
use crate::ephemeral_policy::{
    check_ephemeral_spends, dust_output_count, has_dust, pre_check_ephemeral_tx,
    MAX_DUST_OUTPUTS_PER_TX,
};
use crate::mempool::{
    verify_mempool_tx_scripts, FeeRate, MempoolEntry, TxMemPool, DEFAULT_ANCESTOR_LIMIT,
    DUST_RELAY_TX_FEE,
};
use crate::truc_policy::{package_truc_checks, single_truc_checks, TrucAncestor, TRUC_VERSION};

/// Largest transaction version considered standard (Core v28 `TX_MAX_STANDARD_VERSION`).
pub const TX_MAX_STANDARD_VERSION: u32 = 3;
/// Maximum standard transaction weight (`MAX_STANDARD_TX_WEIGHT`).
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
/// Minimum non-witness size of a standard transaction (`MIN_STANDARD_TX_NONWITNESS_SIZE`).
pub const MIN_STANDARD_TX_NONWITNESS_SIZE: usize = 65;
/// Maximum standard scriptSig size (`MAX_STANDARD_SCRIPTSIG_SIZE`).
pub const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1650;
/// Maximum sigop cost of a standard transaction (`MAX_STANDARD_TX_SIGOPS_COST`).
pub const MAX_STANDARD_TX_SIGOPS_COST: i64 = 16_000;
/// Sigop-to-vsize exchange rate (`DEFAULT_BYTES_PER_SIGOP`).
pub const DEFAULT_BYTES_PER_SIGOP: u64 = 20;
/// Maximum number of transactions in a package (`MAX_PACKAGE_COUNT`).
pub const MAX_PACKAGE_COUNT: usize = 25;
/// Maximum total weight of a package (`MAX_PACKAGE_WEIGHT`).
pub const MAX_PACKAGE_WEIGHT: usize = 404_000;

/// Sigop counting flags (P2SH | WITNESS).
const SIGOP_FLAGS: u32 = 0x1 | 0x800;

/// Why a transaction was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRejection {
    /// Core's reject reason (e.g. `"TRUC-violation"`, `"dust"`).
    pub reason: String,
    /// Core's debug message (may be empty).
    pub details: String,
    /// `TX_MISSING_INPUTS`: some input could not be found.
    pub missing_inputs: bool,
}

impl TxRejection {
    fn new(reason: &str, details: impl Into<String>) -> Self {
        TxRejection {
            reason: reason.to_string(),
            details: details.into(),
            missing_inputs: false,
        }
    }

    /// Core's `ValidationState::ToString()`: `reason` or `reason, details`.
    pub fn to_state_string(&self) -> String {
        if self.details.is_empty() {
            self.reason.clone()
        } else {
            format!("{}, {}", self.reason, self.details)
        }
    }
}

/// A transaction that passed (or, outside test mode, entered) the mempool.
#[derive(Debug, Clone)]
pub struct TxAccepted {
    /// Transaction id.
    pub txid: Txid,
    /// Witness transaction id (hex).
    pub wtxid: String,
    /// Sigop-adjusted virtual size.
    pub vsize: u64,
    /// Base fee.
    pub fee: Amount,
    /// Feerate used for acceptance (Core's `m_effective_feerate`).
    pub effective_feerate: FeeRate,
    /// Wtxids whose fees made up `effective_feerate`.
    pub effective_includes: Vec<String>,
    /// Transactions evicted by replacement.
    pub replaced: Vec<Txid>,
    /// The transaction was already in the mempool (Core's `MEMPOOL_ENTRY`).
    pub already_in_mempool: bool,
}

/// Per-transaction state carried from the checks to the commit.
struct Workspace {
    entry: MempoolEntry,
    conflicts: Vec<Txid>,
    vsize: u64,
    fee: Amount,
}

/// Sigop-adjusted virtual size (Core's `GetVirtualTransactionSize`).
pub fn virtual_size(tx: &Transaction, sigop_cost: i64) -> u64 {
    let weight = tx.get_weight() as u64;
    let w = weight.max(sigop_cost.max(0) as u64 * DEFAULT_BYTES_PER_SIGOP);
    (w + 3) / 4
}

/// `IsFinalTx` (consensus/tx_verify.cpp).
fn is_final_tx(tx: &Transaction, height: i32, block_time: i64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let lt = tx.lock_time as i64;
    let cutoff = if lt < 500_000_000 { height as i64 } else { block_time };
    lt < cutoff || tx.vin.iter().all(|i| i.sequence == SEQUENCE_FINAL)
}

/// The standardness subset of Core's `IsStandardTx()` that this node
/// enforces: version, weight, minimum size, scriptSig size/push-only, and
/// the dust-output count.
pub fn is_standard_tx(tx: &Transaction) -> Result<(), TxRejection> {
    if tx.version < 1 || tx.version > TX_MAX_STANDARD_VERSION {
        return Err(TxRejection::new("version", ""));
    }
    if tx.get_weight() > MAX_STANDARD_TX_WEIGHT {
        return Err(TxRejection::new("tx-size", ""));
    }
    if serialize_transaction(tx, false).len() < MIN_STANDARD_TX_NONWITNESS_SIZE {
        return Err(TxRejection::new("tx-size-small", ""));
    }
    for input in &tx.vin {
        if input.script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(TxRejection::new("scriptsig-size", ""));
        }
        if !input.script_sig.is_push_only() {
            return Err(TxRejection::new("scriptsig-not-pushonly", ""));
        }
    }
    if dust_output_count(tx, DUST_RELAY_TX_FEE) > MAX_DUST_OUTPUTS_PER_TX {
        return Err(TxRejection::new("dust", ""));
    }
    Ok(())
}

/// Port of Core's `IsWellFormedPackage()` (policy/packages.cpp).
pub fn is_well_formed_package(txs: &[TransactionRef]) -> Result<(), TxRejection> {
    if txs.len() > MAX_PACKAGE_COUNT {
        return Err(TxRejection::new("package-too-many-transactions", ""));
    }
    let weight: usize = txs.iter().map(|t| t.get_weight()).sum();
    if txs.len() > 1 && weight > MAX_PACKAGE_WEIGHT {
        return Err(TxRejection::new("package-too-large", ""));
    }
    let mut seen: HashSet<Txid> = HashSet::new();
    for t in txs {
        if !seen.insert(*t.txid()) {
            return Err(TxRejection::new("package-contains-duplicates", ""));
        }
    }
    // Topologically sorted: no tx spends a later package member.
    let mut later: HashSet<Txid> = txs.iter().map(|t| *t.txid()).collect();
    for t in txs {
        later.remove(t.txid());
        if t.vin.iter().any(|i| later.contains(&i.prevout.hash)) {
            return Err(TxRejection::new("package-not-sorted", ""));
        }
    }
    let mut spent: HashSet<OutPoint> = HashSet::new();
    for t in txs {
        for i in &t.vin {
            if !spent.insert(i.prevout.clone()) {
                return Err(TxRejection::new("conflict-in-package", ""));
            }
        }
    }
    Ok(())
}

/// Port of Core's `IsChildWithParentsTree()`: the last transaction is the
/// child, every other one is its direct parent, and parents do not depend on
/// each other.
pub fn is_child_with_parents_tree(txs: &[TransactionRef]) -> bool {
    let child = match txs.last() {
        Some(c) => c,
        None => return false,
    };
    let parents: HashSet<Txid> = txs[..txs.len() - 1].iter().map(|t| *t.txid()).collect();
    let child_inputs: HashSet<Txid> = child.vin.iter().map(|i| i.prevout.hash).collect();
    if !parents.iter().all(|p| child_inputs.contains(p)) {
        return false;
    }
    txs[..txs.len() - 1]
        .iter()
        .all(|p| p.vin.iter().all(|i| !parents.contains(&i.prevout.hash)))
}

/// Mempool acceptance against a chainstate and a pool. Callers hold the
/// chainstate lock for the duration (inputs and the tip must not move).
pub struct MemPoolAccept<'a> {
    cs: &'a ChainstateManager,
    pool: &'a TxMemPool,
}

impl<'a> MemPoolAccept<'a> {
    /// New acceptor.
    pub fn new(cs: &'a ChainstateManager, pool: &'a TxMemPool) -> Self {
        MemPoolAccept { cs, pool }
    }

    fn truc_ancestor(&self, txid: &Txid) -> Option<TrucAncestor> {
        let e = self.pool.get_entry(txid)?;
        let children = self
            .pool
            .children_of(txid)
            .into_iter()
            .map(|c| {
                let count = self
                    .pool
                    .get(&c)
                    .map(|t| self.pool.ancestors_of_inputs(&t).len() + 1)
                    .unwrap_or(1);
                (c, count)
            })
            .collect::<Vec<_>>();
        // Descendant count including self.
        let mut desc = HashSet::new();
        let mut stack: Vec<Txid> = children.iter().map(|(c, _)| *c).collect();
        while let Some(t) = stack.pop() {
            if desc.insert(t) {
                stack.extend(self.pool.children_of(&t));
            }
        }
        Some(TrucAncestor {
            txid: *txid,
            wtxid: e.tx().wtxid().to_hex(),
            version: e.tx().version,
            descendant_count: desc.len() + 1,
            children,
        })
    }

    /// Port of Core's `PreChecks` + `ReplacementChecks` +
    /// `PolicyScriptChecks` for one transaction. `package` holds the other
    /// members (already-checked ones' outputs are spendable) when called for
    /// a package.
    fn checks(
        &self,
        tx: &TransactionRef,
        package: Option<(&[TransactionRef], &HashMap<Txid, TransactionRef>)>,
    ) -> Result<Workspace, TxRejection> {
        let txid = *tx.txid();
        let mut state = TxValidationState::new();
        if !check_transaction(tx, &mut state) {
            return Err(TxRejection::new(state.get_reject_reason(), state.get_debug_message()));
        }
        if tx.is_coinbase() {
            return Err(TxRejection::new("coinbase", ""));
        }
        is_standard_tx(tx)?;

        let tip = self.cs.tip().ok_or_else(|| TxRejection::new("no-tip", ""))?;
        let next_height = self.cs.height() + 1;
        let mtp = self.cs.median_time_past(tip);
        if !is_final_tx(tx, next_height, mtp) {
            return Err(TxRejection::new("non-final", "non-final transaction"));
        }

        if self.pool.exists(&txid) {
            let same = self
                .pool
                .get(&txid)
                .map(|m| m.wtxid() == tx.wtxid())
                .unwrap_or(false);
            return Err(TxRejection::new(
                if same { "txn-already-in-mempool" } else { "txn-same-nonwitness-data-in-mempool" },
                "",
            ));
        }

        // Resolve inputs: package members, then mempool, then UTXO set.
        let coins = self.cs.coins_tip();
        let mut spent_outputs: Vec<TxOut> = Vec::with_capacity(tx.vin.len());
        let mut prev_heights: Vec<i32> = Vec::with_capacity(tx.vin.len());
        let mut value_in: i64 = 0;
        let mut spends_coinbase = false;
        for input in &tx.vin {
            let from_pkg = package
                .and_then(|(_, view)| view.get(&input.prevout.hash))
                .and_then(|p| p.vout.get(input.prevout.n as usize).cloned());
            let out = match from_pkg {
                Some(o) => {
                    prev_heights.push(next_height);
                    o
                }
                None => match self.pool.get(&input.prevout.hash) {
                    Some(p) => match p.vout.get(input.prevout.n as usize) {
                        Some(o) => {
                            prev_heights.push(next_height);
                            o.clone()
                        }
                        None => {
                            return Err(TxRejection {
                                missing_inputs: true,
                                ..TxRejection::new("bad-txns-inputs-missingorspent", "")
                            })
                        }
                    },
                    None => match coins.get_coin(&input.prevout) {
                        Some(coin) => {
                            if coin.coinbase {
                                spends_coinbase = true;
                                if next_height - (coin.height as i32) < COINBASE_MATURITY {
                                    return Err(TxRejection::new(
                                        "bad-txns-premature-spend-of-coinbase",
                                        format!(
                                            "tried to spend coinbase at depth {}",
                                            next_height - coin.height as i32
                                        ),
                                    ));
                                }
                            }
                            prev_heights.push(coin.height as i32);
                            coin.tx_out.clone()
                        }
                        None => {
                            return Err(TxRejection {
                                missing_inputs: true,
                                ..TxRejection::new("bad-txns-inputs-missingorspent", "")
                            })
                        }
                    },
                },
            };
            value_in += out.value.to_sat();
            spent_outputs.push(out);
        }
        let value_out: i64 = tx.vout.iter().map(|o| o.value.to_sat()).sum();
        if value_in < value_out {
            return Err(TxRejection::new(
                "bad-txns-in-belowout",
                format!("value in ({}) < value out ({})", value_in, value_out),
            ));
        }
        let fee = Amount::from_sat(value_in - value_out);

        // BIP68 (CheckSequenceLocksAtTip).
        if !sequence_locks_at_tip(self.cs, tx, &mut prev_heights) {
            return Err(TxRejection::new("non-BIP68-final", ""));
        }
        let mod_fee = fee.to_sat() + self.pool.get_fee_delta(&txid);

        let spk_of: HashMap<OutPoint, qubitcoin_script::Script> = tx
            .vin
            .iter()
            .zip(spent_outputs.iter())
            .map(|(i, o)| (i.prevout.clone(), o.script_pubkey.clone()))
            .collect();
        let sigops = get_transaction_sigop_cost(tx, SIGOP_FLAGS, |op| spk_of.get(op).cloned());
        if sigops > MAX_STANDARD_TX_SIGOPS_COST {
            return Err(TxRejection::new("bad-txns-too-many-sigops", format!("{}", sigops)));
        }
        let vsize = virtual_size(tx, sigops);

        // Ephemeral dust: a dusty tx must pay nothing itself. Standing in
        // for Core's minimum relay fee (which a 0-fee tx always fails on its
        // own), a dusty tx is only accepted inside a package whose child
        // spends the dust.
        if let Err(msg) = pre_check_ephemeral_tx(tx, DUST_RELAY_TX_FEE, fee, mod_fee) {
            return Err(TxRejection::new("dust", msg));
        }
        if package.is_none() && has_dust(tx, DUST_RELAY_TX_FEE) {
            return Err(TxRejection::new(
                "dust",
                "tx with dust output must be submitted in a package with a child spending it",
            ));
        }

        let min_fee = self.pool.min_relay_fee().get_fee(vsize as usize).to_sat();
        if mod_fee < min_fee {
            return Err(TxRejection::new(
                "min relay fee not met",
                format!("{} < {}", mod_fee, min_fee),
            ));
        }

        // P2A spends must have an empty witness (Core's IsWitnessStandard).
        for (i, out) in spent_outputs.iter().enumerate() {
            if out.script_pubkey.is_pay_to_anchor() && !tx.vin[i].witness.stack.is_empty() {
                return Err(TxRejection::new("bad-witness-nonstandard", ""));
            }
        }

        // In-mempool ancestors and in-package parents.
        let mempool_ancestor_ids = self.pool.ancestors_of_inputs(tx);
        let mempool_ancestors: Vec<TrucAncestor> = mempool_ancestor_ids
            .iter()
            .filter_map(|t| self.truc_ancestor(t))
            .collect();
        let in_package_ancestors = match package {
            Some((members, _)) => {
                let by: HashMap<Txid, &TransactionRef> = members.iter().map(|t| (*t.txid(), t)).collect();
                let mut seen = HashSet::new();
                let mut stack: Vec<Txid> = tx.vin.iter().map(|i| i.prevout.hash).collect();
                while let Some(t) = stack.pop() {
                    if let Some(p) = by.get(&t) {
                        if seen.insert(t) {
                            stack.extend(p.vin.iter().map(|i| i.prevout.hash));
                        }
                    }
                }
                seen.len()
            }
            None => 0,
        };
        if (mempool_ancestor_ids.len() + in_package_ancestors + 1) as u64 > DEFAULT_ANCESTOR_LIMIT {
            return Err(TxRejection::new(
                "too-long-mempool-chain",
                format!("too many unconfirmed ancestors [limit: {}]", DEFAULT_ANCESTOR_LIMIT),
            ));
        }

        // Direct conflicts (for TRUC's "child will be replaced" logic).
        let direct_conflicts: HashSet<Txid> = tx
            .vin
            .iter()
            .filter_map(|i| self.pool.get_spender(&i.prevout))
            .collect();

        // TRUC rules.
        let mut sibling: Option<Txid> = None;
        match package {
            None => {
                if let Some((msg, sib)) = single_truc_checks(tx, &mempool_ancestors, &direct_conflicts, vsize) {
                    match sib {
                        // Sibling eviction: treat the sibling as a conflict
                        // and let the replacement rules decide.
                        Some(s) => sibling = Some(s),
                        None => return Err(TxRejection::new("TRUC-violation", msg)),
                    }
                }
            }
            Some((members, _)) => {
                if let Some((msg, _)) = single_truc_checks(tx, &mempool_ancestors, &direct_conflicts, vsize) {
                    // No sibling eviction in package mode.
                    return Err(TxRejection::new("TRUC-violation", msg));
                }
                if let Some(msg) = package_truc_checks(tx, vsize, members, &mempool_ancestors) {
                    return Err(TxRejection::new("TRUC-violation", msg));
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entry = MempoolEntry::new(
            tx.clone(),
            fee,
            vsize as u32,
            now,
            self.cs.height(),
            spends_coinbase,
            sigops.max(0) as u32,
        );

        // Descendant limits on in-mempool parents (TRUC already bounded v3).
        if tx.version != TRUC_VERSION {
            if let Err(e) = self.pool.check_descendant_limits(&entry) {
                return Err(TxRejection::new("too-long-mempool-chain", e));
            }
        }

        // Replacement (BIP125 + full-RBF), including a TRUC sibling.
        let extra: Vec<Txid> = sibling.into_iter().collect();
        let conflicts = match self.pool.check_rbf_with_extra(&entry, &extra) {
            Ok(c) => c,
            Err(e) => {
                let reason = e.split(':').next().unwrap_or("").trim().to_string();
                let reason = if sibling.is_some() && reason.starts_with("insufficient fee") {
                    "insufficient fee (including sibling eviction)".to_string()
                } else if reason.is_empty() {
                    "replacement-rejected".to_string()
                } else {
                    reason
                };
                return Err(TxRejection::new(&reason, e));
            }
        };

        if let Err(e) = verify_mempool_tx_scripts(tx, &spent_outputs) {
            let (reason, details) = match e.split_once(" (") {
                Some((r, d)) => (r.to_string(), d.trim_end_matches(')').to_string()),
                None => (e.clone(), String::new()),
            };
            return Err(TxRejection::new(&reason, details));
        }

        if !self.pool.has_room(vsize as u32) {
            return Err(TxRejection::new("mempool full", ""));
        }

        Ok(Workspace {
            entry,
            conflicts,
            vsize,
            fee,
        })
    }

    fn accepted(&self, tx: &TransactionRef, ws: &Workspace) -> TxAccepted {
        let rate = if ws.vsize > 0 {
            FeeRate::new(ws.fee.to_sat() * 1000 / ws.vsize as i64)
        } else {
            FeeRate::ZERO
        };
        TxAccepted {
            txid: *tx.txid(),
            wtxid: tx.wtxid().to_hex(),
            vsize: ws.vsize,
            fee: ws.fee,
            effective_feerate: rate,
            effective_includes: vec![tx.wtxid().to_hex()],
            replaced: ws.conflicts.clone(),
            already_in_mempool: false,
        }
    }

    fn commit(&self, ws: Workspace) {
        if ws.conflicts.is_empty() {
            self.pool.add_unchecked(ws.entry);
        } else {
            self.pool.replace(ws.entry, &ws.conflicts);
        }
    }

    /// Port of Core's `AcceptSingleTransaction` (`test_accept` = dry run).
    pub fn accept_single(&self, tx: &TransactionRef, test_accept: bool) -> Result<TxAccepted, TxRejection> {
        // CheckEphemeralSpends: a child of an in-mempool dusty parent must
        // spend the dust.
        if let Err((_, msg)) = check_ephemeral_spends(std::slice::from_ref(tx), DUST_RELAY_TX_FEE, self.pool) {
            return Err(TxRejection::new("missing-ephemeral-spends", msg));
        }
        let ws = self.checks(tx, None)?;
        let result = self.accepted(tx, &ws);
        if !test_accept {
            self.commit(ws);
        }
        Ok(result)
    }

    /// Validate (and unless `test_accept`, submit) a package.
    ///
    /// Port of Core's `AcceptMultipleTransactions` (test mode) and
    /// `AcceptPackage` (submit). Members are checked in order against the
    /// mempool plus the members before them; members already in the mempool
    /// are reported as such. Members that pass are committed in order unless
    /// one of their in-package ancestors failed, or the package's ephemeral
    /// dust would be left unspent. Returns the package-level error (if any)
    /// and one result per member.
    pub fn accept_package(
        &self,
        txs: &[TransactionRef],
        test_accept: bool,
    ) -> (Option<TxRejection>, Vec<Result<TxAccepted, TxRejection>>) {
        if let Err(e) = is_well_formed_package(txs) {
            return (Some(e), Vec::new());
        }
        let mut view: HashMap<Txid, TransactionRef> = HashMap::new();
        let mut results: Vec<Result<TxAccepted, TxRejection>> = Vec::with_capacity(txs.len());
        let mut workspaces: Vec<Option<Workspace>> = Vec::with_capacity(txs.len());
        let mut failed: HashSet<Txid> = HashSet::new();
        for tx in txs {
            if let Some(m) = self.pool.get(tx.txid()) {
                if m.wtxid() == tx.wtxid() {
                    if test_accept {
                        // Package testmempoolaccept doesn't allow members
                        // already in the mempool.
                        results.push(Err(TxRejection::new("txn-already-in-mempool", "")));
                        workspaces.push(None);
                        failed.insert(*tx.txid());
                        continue;
                    }
                    let e = self.pool.get_entry(tx.txid()).expect("present");
                    results.push(Ok(TxAccepted {
                        txid: *tx.txid(),
                        wtxid: tx.wtxid().to_hex(),
                        vsize: e.vsize() as u64,
                        fee: e.fee(),
                        effective_feerate: e.fee_rate(),
                        effective_includes: vec![tx.wtxid().to_hex()],
                        replaced: Vec::new(),
                        already_in_mempool: true,
                    }));
                    workspaces.push(None);
                    continue;
                }
            }
            if tx.vin.iter().any(|i| failed.contains(&i.prevout.hash)) {
                results.push(Err(TxRejection {
                    missing_inputs: true,
                    ..TxRejection::new("bad-txns-inputs-missingorspent", "")
                }));
                workspaces.push(None);
                failed.insert(*tx.txid());
                continue;
            }
            match self.checks(tx, Some((txs, &view))) {
                Ok(ws) => {
                    results.push(Ok(self.accepted(tx, &ws)));
                    workspaces.push(Some(ws));
                    view.insert(*tx.txid(), tx.clone());
                }
                Err(e) => {
                    results.push(Err(e));
                    workspaces.push(None);
                    failed.insert(*tx.txid());
                }
            }
        }

        // CheckEphemeralSpends over the members that passed.
        let passing: Vec<TransactionRef> = txs
            .iter()
            .zip(results.iter())
            .filter(|(_, r)| r.is_ok())
            .map(|(t, _)| t.clone())
            .collect();
        if let Err((child_idx, msg)) = check_ephemeral_spends(&passing, DUST_RELAY_TX_FEE, self.pool) {
            let child_txid = *passing[child_idx].txid();
            for (i, tx) in txs.iter().enumerate() {
                if *tx.txid() == child_txid {
                    results[i] = Err(TxRejection::new("missing-ephemeral-spends", msg.clone()));
                    workspaces[i] = None;
                    failed.insert(child_txid);
                }
            }
        }
        // A dusty member whose dust no passing member spends must not enter
        // the mempool alone; members depending on a failure fail too.
        loop {
            let mut changed = false;
            for (i, tx) in txs.iter().enumerate() {
                if results[i].is_err() || workspaces[i].is_none() {
                    continue;
                }
                let depends_on_failed = tx.vin.iter().any(|inp| failed.contains(&inp.prevout.hash));
                let dust_unspent = has_dust(tx, DUST_RELAY_TX_FEE)
                    && tx.vout.iter().enumerate().any(|(n, o)| {
                        crate::mempool::is_dust(o, DUST_RELAY_TX_FEE)
                            && !txs.iter().enumerate().any(|(j, c)| {
                                results[j].is_ok()
                                    && c.vin.iter().any(|ci| ci.prevout == OutPoint::new(*tx.txid(), n as u32))
                            })
                    });
                if depends_on_failed || dust_unspent {
                    results[i] = Err(TxRejection::new("package-not-validated", ""));
                    workspaces[i] = None;
                    failed.insert(*tx.txid());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let package_error = if results.iter().any(|r| r.is_err()) {
            Some(TxRejection::new("transaction failed", ""))
        } else {
            None
        };
        if !test_accept {
            for ws in workspaces.into_iter().flatten() {
                self.commit(ws);
            }
        }
        (package_error, results)
    }
}

/// Whether a mempool transaction is still valid on top of the current tip:
/// every input exists (mempool or UTXO set), spent coinbases are mature,
/// and the transaction is final for the next block. The per-transaction
/// test of Core's `CTxMemPool::removeForReorg` (txmempool.cpp).
fn still_valid_at_tip(cs: &ChainstateManager, pool: &TxMemPool, tx: &Transaction) -> bool {
    let tip = match cs.tip() {
        Some(t) => t,
        None => return false,
    };
    let next_height = cs.height() + 1;
    if !is_final_tx(tx, next_height, cs.median_time_past(tip)) {
        return false;
    }
    for input in &tx.vin {
        if let Some(p) = pool.get(&input.prevout.hash) {
            if p.vout.len() <= input.prevout.n as usize {
                return false;
            }
            continue;
        }
        match cs.coins_tip().get_coin(&input.prevout) {
            Some(c) => {
                if c.coinbase && next_height - (c.height as i32) < COINBASE_MATURITY {
                    return false;
                }
            }
            None => return false,
        }
    }
    sequence_locks_ok(cs, pool, tx)
}

/// Bring the mempool in line with a chain update.
///
/// Port of the mempool half of Core's `ActivateBestChainStep` /
/// `ConnectTip` (`removeForBlock`) and `MaybeUpdateMempoolForReorg`:
/// transactions of newly connected blocks (and their conflicts) leave the
/// pool; after a reorganisation, transactions of disconnected blocks that
/// are not in the new branch are re-submitted (oldest block first, in block
/// order), and then everything that is no longer valid on the new tip
/// (missing inputs, immature coinbase spends, non-final, unmet sequence
/// locks) is removed with reason `REORG` (`removeForReorg`).
pub fn update_mempool_for_chain_update(
    cs: &ChainstateManager,
    pool: &TxMemPool,
    update: &crate::chainstate::ChainUpdate,
) {
    for c in &update.connected {
        pool.remove_for_block_txs(&c.block.vtx);
    }
    if update.disconnected.is_empty() {
        return;
    }
    let in_new_chain: HashSet<Txid> = update
        .connected
        .iter()
        .flat_map(|c| c.block.vtx.iter().map(|t| *t.txid()))
        .collect();
    let acc = MemPoolAccept::new(cs, pool);
    for (_, block) in update.disconnected.iter().rev() {
        for tx in block.vtx.iter().skip(1) {
            if in_new_chain.contains(tx.txid()) || pool.exists(tx.txid()) {
                continue;
            }
            if let Err(e) = acc.accept_single(tx, false) {
                tracing::debug!(txid = %tx.txid().to_hex(), reason = %e.reason, "reorg: tx not re-added");
            }
        }
    }
    // removeForReorg.
    let mut stale = Vec::new();
    for e in pool.entries_snapshot() {
        if !still_valid_at_tip(cs, pool, e.tx()) {
            stale.push(e.txid());
        }
    }
    for t in stale {
        pool.remove_recursive_with_reason(&t, crate::mempool::MemPoolRemovalReason::Reorg);
    }
}

/// BIP68 relative lock-times for the next block, with unconfirmed inputs
/// (mempool or `view`) counted at the next block's height.
///
/// Port of Core's `CheckSequenceLocksAtTip()` (validation.cpp).
fn sequence_locks_at_tip(
    cs: &ChainstateManager,
    tx: &Transaction,
    prev_heights: &mut [i32],
) -> bool {
    use crate::validation::{check_sequence_locks, LOCKTIME_VERIFY_SEQUENCE};
    let tip = match cs.tip() {
        Some(t) => t,
        None => return false,
    };
    let next_height = cs.height() + 1;
    if next_height < cs.consensus().csv_height {
        return true;
    }
    let tip_mtp = cs.median_time_past(tip);
    let chain = cs.active_chain();
    let mtp_at = |h: i32| -> i64 {
        match chain.get_block_index(h) {
            Some(i) => cs.median_time_past(i),
            None => tip_mtp,
        }
    };
    check_sequence_locks(tx, LOCKTIME_VERIFY_SEQUENCE, prev_heights, next_height, tip_mtp, mtp_at)
}

fn sequence_locks_ok(cs: &ChainstateManager, pool: &TxMemPool, tx: &Transaction) -> bool {
    let next_height = cs.height() + 1;
    let mut heights: Vec<i32> = Vec::with_capacity(tx.vin.len());
    for input in &tx.vin {
        if pool.exists(&input.prevout.hash) {
            heights.push(next_height);
        } else {
            match cs.coins_tip().get_coin(&input.prevout) {
                Some(c) => heights.push(c.height as i32),
                None => return false,
            }
        }
    }
    sequence_locks_at_tip(cs, tx, &mut heights)
}
