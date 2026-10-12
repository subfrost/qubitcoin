//! Mempool acceptance with full input resolution, for single transactions
//! and packages.
//!
//! Port of the `MemPoolAccept` class in Bitcoin Core's `validation.cpp`
//! (`PreChecks`, `ReplacementChecks`, `PackageRBFChecks`,
//! `PolicyScriptChecks`, `AcceptSingleTransaction`,
//! `AcceptMultipleTransactions`, `AcceptSubPackage`, `AcceptPackage`),
//! `CTxMemPool::CalculateMemPoolAncestors` / `CheckPackageLimits`
//! (txmempool.cpp) incl. the CPFP carve-out, `IsWellFormedPackage` from
//! `policy/packages.cpp`, and `IsStandardTx` from `policy/policy.cpp`, with
//! the TRUC ([`crate::truc_policy`]) and ephemeral-dust
//! ([`crate::ephemeral_policy`]) rules.
//!
//! Inputs are resolved against the confirmed UTXO set, the mempool, and (for
//! packages) earlier package members. Every accepting entry point in the
//! node (P2P `tx`, `sendrawtransaction`, `testmempoolaccept`,
//! `submitpackage`, reorg re-adds) goes through here.

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
    verify_mempool_tx_scripts, FeeRate, MempoolEntry, MempoolPolicy, TxMemPool,
    DEFAULT_ANCESTOR_LIMIT, DEFAULT_ANCESTOR_SIZE_LIMIT, DEFAULT_DESCENDANT_LIMIT,
    DEFAULT_DESCENDANT_SIZE_LIMIT, DUST_RELAY_TX_FEE, MAX_BIP125_REPLACEMENT_CANDIDATES,
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
/// CPFP carve-out size allowance (`EXTRA_DESCENDANT_TX_SIZE_LIMIT`).
pub const EXTRA_DESCENDANT_TX_SIZE_LIMIT: u64 = 10_000;

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
    /// `TX_RECONSIDERABLE`: the result may change in a package (fee too
    /// low on its own, or an ephemeral-dust parent needing its child).
    pub reconsiderable: bool,
}

impl TxRejection {
    /// A plain (non-reconsiderable) rejection.
    pub fn new(reason: &str, details: impl Into<String>) -> Self {
        TxRejection {
            reason: reason.to_string(),
            details: details.into(),
            missing_inputs: false,
            reconsiderable: false,
        }
    }

    fn reconsiderable(reason: &str, details: impl Into<String>) -> Self {
        TxRejection {
            reconsiderable: true,
            ..Self::new(reason, details)
        }
    }

    fn missing() -> Self {
        TxRejection {
            missing_inputs: true,
            ..Self::new("bad-txns-inputs-missingorspent", "")
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
    /// Feerate used for acceptance (Core's `m_effective_feerate`): the
    /// package feerate when it was accepted through package CPFP.
    pub effective_feerate: FeeRate,
    /// Wtxids whose fees made up `effective_feerate`.
    pub effective_includes: Vec<String>,
    /// Transactions evicted by replacement.
    pub replaced: Vec<Txid>,
    /// The transaction was already in the mempool (Core's `MEMPOOL_ENTRY`).
    pub already_in_mempool: bool,
}

/// How a transaction is being validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// On its own (`AcceptSingleTransaction`).
    Single,
    /// With earlier package members as inputs, each judged on its own
    /// feerate (`AcceptMultipleTransactions`, test accept).
    PackageTest,
    /// As part of a subpackage judged on its combined feerate; fee and
    /// replacement rules are applied to the whole subpackage.
    PackageEval,
}

/// Per-transaction state carried from the checks to the commit.
struct Workspace {
    tx: TransactionRef,
    entry: MempoolEntry,
    /// Everything evicted (direct conflicts and their descendants).
    conflicts: Vec<Txid>,
    /// Direct conflicts only.
    direct_conflicts: Vec<Txid>,
    vsize: u64,
    fee: Amount,
    mod_fee: i64,
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

/// Port of Core's `IsStandardTx()`: version, weight, minimum size,
/// scriptSig size/push-only, output templates and data carriers
/// ([`crate::policy`]), and the dust-output count.
pub fn is_standard_tx(tx: &Transaction, policy: &MempoolPolicy) -> Result<(), TxRejection> {
    if tx.version < 1 || tx.version > TX_MAX_STANDARD_VERSION {
        return Err(TxRejection::new("version", ""));
    }
    if tx.get_weight() > MAX_STANDARD_TX_WEIGHT {
        return Err(TxRejection::new("tx-size", ""));
    }
    for input in &tx.vin {
        if input.script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(TxRejection::new("scriptsig-size", ""));
        }
        if !input.script_sig.is_push_only() {
            return Err(TxRejection::new("scriptsig-not-pushonly", ""));
        }
    }
    if let Err(reason) = crate::policy::check_standard_outputs(tx, policy) {
        return Err(TxRejection::new(reason, ""));
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

/// Ancestor/descendant limits (Core's `CTxMemPool::Limits`).
#[derive(Debug, Clone, Copy)]
struct Limits {
    ancestor_count: u64,
    ancestor_size: u64,
    descendant_count: u64,
    descendant_size: u64,
}

const DEFAULT_LIMITS: Limits = Limits {
    ancestor_count: DEFAULT_ANCESTOR_LIMIT,
    ancestor_size: DEFAULT_ANCESTOR_SIZE_LIMIT,
    descendant_count: DEFAULT_DESCENDANT_LIMIT,
    descendant_size: DEFAULT_DESCENDANT_SIZE_LIMIT,
};

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

    fn vsize_of(&self, txid: &Txid) -> u64 {
        self.pool.get_entry(txid).map(|e| e.vsize() as u64).unwrap_or(0)
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
        Some(TrucAncestor {
            txid: *txid,
            wtxid: e.tx().wtxid().to_hex(),
            version: e.tx().version,
            descendant_count: self.pool.descendants_of(txid).len() + 1,
            children,
        })
    }

    /// Port of Core's `CalculateMemPoolAncestors` limit checks: ancestor
    /// count/size of the new tx (counting `extra_ancestors` in-package
    /// ancestors of `extra_size` vbytes), and for every in-mempool ancestor
    /// its descendant count/size after adding the tx.
    fn check_limits(
        &self,
        mempool_ancestors: &[Txid],
        vsize: u64,
        extra_ancestors: u64,
        extra_size: u64,
        limits: Limits,
    ) -> Result<(), String> {
        let anc_count = mempool_ancestors.len() as u64 + extra_ancestors + 1;
        if anc_count > limits.ancestor_count {
            return Err(format!("too many unconfirmed ancestors [limit: {}]", limits.ancestor_count));
        }
        let anc_size: u64 = mempool_ancestors.iter().map(|a| self.vsize_of(a)).sum::<u64>() + extra_size + vsize;
        if anc_size > limits.ancestor_size {
            return Err(format!("exceeds ancestor size limit [limit: {}]", limits.ancestor_size));
        }
        for a in mempool_ancestors {
            let desc = self.pool.descendants_of(a);
            let count = desc.len() as u64 + 1;
            let size: u64 = desc.iter().map(|d| self.vsize_of(d)).sum::<u64>() + self.vsize_of(a);
            if count + 1 > limits.descendant_count {
                return Err(format!("too many descendants for tx {} [limit: {}]", a.to_hex(), limits.descendant_count));
            }
            if size + vsize > limits.descendant_size {
                return Err(format!(
                    "exceeds descendant size limit for tx {} [limit: {}]",
                    a.to_hex(),
                    limits.descendant_size
                ));
            }
        }
        Ok(())
    }

    /// Port of Core's `PreChecks` + `ReplacementChecks` +
    /// `PolicyScriptChecks` for one transaction. `package` holds the other
    /// members (already-checked ones' outputs are spendable) when called for
    /// a package.
    fn checks(
        &self,
        tx: &TransactionRef,
        mode: Mode,
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
        is_standard_tx(tx, self.pool.policy())?;
        if serialize_transaction(tx, false).len() < MIN_STANDARD_TX_NONWITNESS_SIZE {
            return Err(TxRejection::new("tx-size-small", ""));
        }

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
                .map(|p| p.vout.get(input.prevout.n as usize).cloned());
            let out = match from_pkg {
                Some(Some(o)) => {
                    prev_heights.push(next_height);
                    o
                }
                Some(None) => return Err(TxRejection::missing()),
                None => match self.pool.get(&input.prevout.hash) {
                    Some(p) => match p.vout.get(input.prevout.n as usize) {
                        Some(o) => {
                            prev_heights.push(next_height);
                            o.clone()
                        }
                        None => return Err(TxRejection::missing()),
                    },
                    None => match coins.get_coin(&input.prevout) {
                        Some(coin) => {
                            if coin.coinbase {
                                spends_coinbase = true;
                                if next_height - (coin.height as i32) < COINBASE_MATURITY {
                                    return Err(TxRejection::new(
                                        "bad-txns-premature-spend-of-coinbase",
                                        format!("tried to spend coinbase at depth {}", next_height - coin.height as i32),
                                    ));
                                }
                            }
                            prev_heights.push(coin.height as i32);
                            coin.tx_out.clone()
                        }
                        None => return Err(TxRejection::missing()),
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
        if mode == Mode::Single && has_dust(tx, DUST_RELAY_TX_FEE) {
            return Err(TxRejection::reconsiderable(
                "dust",
                "tx with dust output must be submitted in a package with a child spending it",
            ));
        }

        // Minimum relay feerate (package evaluation checks the package
        // feerate instead).
        if mode != Mode::PackageEval {
            let min_fee = self.pool.min_relay_fee().get_fee(vsize as usize).to_sat();
            if mod_fee < min_fee {
                return Err(TxRejection::reconsiderable(
                    "min relay fee not met",
                    format!("{} < {}", mod_fee, min_fee),
                ));
            }
        }

        // P2A spends must have an empty witness (Core's IsWitnessStandard).
        for (i, out) in spent_outputs.iter().enumerate() {
            if out.script_pubkey.is_pay_to_anchor() && !tx.vin[i].witness.stack.is_empty() {
                return Err(TxRejection::new("bad-witness-nonstandard", ""));
            }
        }

        // In-mempool ancestors and in-package ancestors.
        let mempool_ancestor_ids = self.pool.ancestors_of_inputs(tx);
        let mempool_ancestors: Vec<TrucAncestor> = mempool_ancestor_ids
            .iter()
            .filter_map(|t| self.truc_ancestor(t))
            .collect();
        let (pkg_anc_count, pkg_anc_size) = match package {
            Some((members, _)) => {
                let by: HashMap<Txid, &TransactionRef> = members.iter().map(|t| (*t.txid(), t)).collect();
                let mut seen = HashSet::new();
                let mut stack: Vec<Txid> = tx.vin.iter().map(|i| i.prevout.hash).collect();
                let mut size = 0u64;
                while let Some(t) = stack.pop() {
                    if let Some(p) = by.get(&t) {
                        if seen.insert(t) {
                            size += p.get_virtual_size() as u64;
                            stack.extend(p.vin.iter().map(|i| i.prevout.hash));
                        }
                    }
                }
                (seen.len() as u64, size)
            }
            None => (0, 0),
        };

        // Direct conflicts.
        let direct_conflicts: Vec<Txid> = {
            let mut v: Vec<Txid> = Vec::new();
            for i in &tx.vin {
                if let Some(c) = self.pool.get_spender(&i.prevout) {
                    if !v.contains(&c) {
                        v.push(c);
                    }
                }
            }
            v
        };
        let direct_set: HashSet<Txid> = direct_conflicts.iter().copied().collect();

        // TRUC rules.
        let mut sibling: Option<Txid> = None;
        match package {
            None => {
                if let Some((msg, sib)) = single_truc_checks(tx, &mempool_ancestors, &direct_set, vsize) {
                    match sib {
                        // Sibling eviction: treat the sibling as a conflict
                        // and let the replacement rules decide.
                        Some(s) => sibling = Some(s),
                        None => return Err(TxRejection::new("TRUC-violation", msg)),
                    }
                }
            }
            Some((members, _)) => {
                if let Some((msg, _)) = single_truc_checks(tx, &mempool_ancestors, &direct_set, vsize) {
                    // No sibling eviction in package mode.
                    return Err(TxRejection::new("TRUC-violation", msg));
                }
                if let Some(msg) = package_truc_checks(tx, vsize, members, &mempool_ancestors) {
                    return Err(TxRejection::new("TRUC-violation", msg));
                }
            }
        }

        // Ancestor/descendant limits. A single replaced conflict frees one
        // descendant slot (Core's maybe_rbf_limits).
        let mut limits = DEFAULT_LIMITS;
        if direct_conflicts.len() == 1 {
            limits.descendant_count += 1;
            limits.descendant_size += self.vsize_of(&direct_conflicts[0])
                + self
                    .pool
                    .descendants_of(&direct_conflicts[0])
                    .iter()
                    .map(|d| self.vsize_of(d))
                    .sum::<u64>();
        }
        if tx.version != TRUC_VERSION {
            if let Err(msg) = self.check_limits(&mempool_ancestor_ids, vsize, pkg_anc_count, pkg_anc_size, limits) {
                // CPFP carve-out: a small tx with a single in-mempool
                // ancestor may exceed its parent's descendant limit by one.
                let carve_out = vsize <= EXTRA_DESCENDANT_TX_SIZE_LIMIT
                    && pkg_anc_count == 0
                    && self
                        .check_limits(
                            &mempool_ancestor_ids,
                            vsize,
                            0,
                            0,
                            Limits {
                                ancestor_count: 2,
                                ancestor_size: limits.ancestor_size,
                                descendant_count: limits.descendant_count + 1,
                                descendant_size: limits.descendant_size + EXTRA_DESCENDANT_TX_SIZE_LIMIT,
                            },
                        )
                        .is_ok();
                if !carve_out {
                    return Err(TxRejection::new("too-long-mempool-chain", msg));
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

        // Replacement (BIP125 + full-RBF), including a TRUC sibling. In
        // package evaluation the fee rules are applied to the subpackage
        // as a whole (package RBF), so only the conflict set is collected.
        let conflicts = if mode == Mode::PackageEval {
            let mut all: Vec<Txid> = Vec::new();
            for c in &direct_conflicts {
                for t in std::iter::once(*c).chain(self.pool.descendants_of(c)) {
                    if !all.contains(&t) {
                        all.push(t);
                    }
                }
            }
            if tx.vin.iter().any(|i| all.contains(&i.prevout.hash)) {
                return Err(TxRejection::new("bad-txns-spends-conflicting-tx", ""));
            }
            all
        } else {
            let extra: Vec<Txid> = sibling.into_iter().collect();
            match self.pool.check_rbf_with_extra(&entry, &extra) {
                Ok(c) => c,
                Err(e) => {
                    let reason = e.split(':').next().unwrap_or("").trim().to_string();
                    let is_fee = reason.starts_with("insufficient fee");
                    let reason = if sibling.is_some() && is_fee {
                        "insufficient fee (including sibling eviction)".to_string()
                    } else if reason.is_empty() {
                        "replacement-rejected".to_string()
                    } else {
                        reason
                    };
                    return Err(if is_fee {
                        TxRejection::reconsiderable(&reason, e)
                    } else {
                        TxRejection::new(&reason, e)
                    });
                }
            }
        };
        let mut direct_conflicts = direct_conflicts;
        if let Some(s) = sibling {
            direct_conflicts.push(s);
        }

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
            tx: tx.clone(),
            entry,
            conflicts,
            direct_conflicts,
            vsize,
            fee,
            mod_fee,
        })
    }

    fn accepted(&self, ws: &Workspace) -> TxAccepted {
        let rate = if ws.vsize > 0 {
            FeeRate::new(ws.mod_fee * 1000 / ws.vsize as i64)
        } else {
            FeeRate::ZERO
        };
        TxAccepted {
            txid: *ws.tx.txid(),
            wtxid: ws.tx.wtxid().to_hex(),
            vsize: ws.vsize,
            fee: ws.fee,
            effective_feerate: rate,
            effective_includes: vec![ws.tx.wtxid().to_hex()],
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

    fn mempool_entry_result(&self, tx: &TransactionRef) -> TxAccepted {
        let e = self.pool.get_entry(tx.txid()).expect("present");
        TxAccepted {
            txid: *tx.txid(),
            wtxid: tx.wtxid().to_hex(),
            vsize: e.vsize() as u64,
            fee: e.fee(),
            effective_feerate: e.fee_rate(),
            effective_includes: vec![tx.wtxid().to_hex()],
            replaced: Vec::new(),
            already_in_mempool: true,
        }
    }

    /// Port of Core's `AcceptSingleTransaction` (`test_accept` = dry run).
    pub fn accept_single(&self, tx: &TransactionRef, test_accept: bool) -> Result<TxAccepted, TxRejection> {
        // CheckEphemeralSpends: a child of an in-mempool dusty parent must
        // spend the dust.
        if let Err((_, msg)) = check_ephemeral_spends(std::slice::from_ref(tx), DUST_RELAY_TX_FEE, self.pool) {
            return Err(TxRejection::new("missing-ephemeral-spends", msg));
        }
        let ws = self.checks(tx, Mode::Single, None)?;
        let result = self.accepted(&ws);
        if !test_accept {
            self.commit(ws);
        }
        Ok(result)
    }

    /// Validate (and unless `test_accept`, submit) a package.
    ///
    /// Test mode is Core's `AcceptMultipleTransactions` with
    /// `test_accept`: every member is checked against the mempool plus the
    /// members before it, on its own feerate, and nothing is committed.
    ///
    /// Submit mode is Core's `AcceptPackage`: each member is first tried on
    /// its own (and committed if it passes); members that fail only on
    /// feerate (or are missing a parent that did) are then evaluated
    /// together as one subpackage on their combined feerate, with package
    /// RBF for a 1-parent-1-child subpackage, and committed all-or-nothing.
    /// A non-reconsiderable failure stops package evaluation.
    ///
    /// Returns the package-level error (if any) and one result per member
    /// (empty when the package is malformed).
    pub fn accept_package(
        &self,
        txs: &[TransactionRef],
        test_accept: bool,
    ) -> (Option<TxRejection>, Vec<Result<TxAccepted, TxRejection>>) {
        if let Err(e) = is_well_formed_package(txs) {
            return (Some(e), Vec::new());
        }
        if test_accept {
            self.package_test(txs)
        } else {
            self.package_submit(txs)
        }
    }

    fn package_test(&self, txs: &[TransactionRef]) -> (Option<TxRejection>, Vec<Result<TxAccepted, TxRejection>>) {
        let mut view: HashMap<Txid, TransactionRef> = HashMap::new();
        let mut results: Vec<Result<TxAccepted, TxRejection>> = Vec::with_capacity(txs.len());
        let mut failed: HashSet<Txid> = HashSet::new();
        for tx in txs {
            if let Some(m) = self.pool.get(tx.txid()) {
                if m.wtxid() == tx.wtxid() {
                    // Package testmempoolaccept doesn't allow members
                    // already in the mempool.
                    results.push(Err(TxRejection::new("txn-already-in-mempool", "")));
                    failed.insert(*tx.txid());
                    continue;
                }
            }
            if tx.vin.iter().any(|i| failed.contains(&i.prevout.hash)) {
                results.push(Err(TxRejection::missing()));
                failed.insert(*tx.txid());
                continue;
            }
            match self.checks(tx, Mode::PackageTest, Some((txs, &view))) {
                Ok(ws) => {
                    results.push(Ok(self.accepted(&ws)));
                    view.insert(*tx.txid(), tx.clone());
                }
                Err(e) => {
                    results.push(Err(e));
                    failed.insert(*tx.txid());
                }
            }
        }
        let passing: Vec<TransactionRef> = txs
            .iter()
            .zip(results.iter())
            .filter(|(_, r)| r.is_ok())
            .map(|(t, _)| t.clone())
            .collect();
        if let Err((child_idx, msg)) = check_ephemeral_spends(&passing, DUST_RELAY_TX_FEE, self.pool) {
            let child_txid = *passing[child_idx].txid();
            if let Some(i) = txs.iter().position(|t| *t.txid() == child_txid) {
                results[i] = Err(TxRejection::new("missing-ephemeral-spends", msg));
            }
        }
        let err = if results.iter().any(|r| r.is_err()) {
            Some(TxRejection::new("transaction failed", ""))
        } else {
            None
        };
        (err, results)
    }

    fn package_submit(&self, txs: &[TransactionRef]) -> (Option<TxRejection>, Vec<Result<TxAccepted, TxRejection>>) {
        let mut results: Vec<Option<Result<TxAccepted, TxRejection>>> = vec![None; txs.len()];
        let mut to_eval: Vec<usize> = Vec::new();
        let mut quit_early = false;
        let eval_set = |to_eval: &Vec<usize>| -> HashSet<Txid> { to_eval.iter().map(|&i| *txs[i].txid()).collect() };

        for (i, tx) in txs.iter().enumerate() {
            if let Some(m) = self.pool.get(tx.txid()) {
                if m.wtxid() == tx.wtxid() {
                    results[i] = Some(Ok(self.mempool_entry_result(tx)));
                    continue;
                }
            }
            // A member whose parent is waiting for package evaluation
            // cannot be judged on its own.
            let waiting = eval_set(&to_eval);
            if tx.vin.iter().any(|inp| waiting.contains(&inp.prevout.hash)) {
                to_eval.push(i);
                continue;
            }
            match self.accept_single(tx, false) {
                Ok(r) => results[i] = Some(Ok(r)),
                Err(e) if e.reconsiderable || e.missing_inputs => {
                    results[i] = Some(Err(e));
                    to_eval.push(i);
                }
                Err(e) => {
                    results[i] = Some(Err(e));
                    quit_early = true;
                }
            }
        }

        if quit_early || to_eval.is_empty() {
            // Evaluation never ran for the waiting members.
            for &i in &to_eval {
                if results[i].is_none() {
                    results[i] = Some(Err(TxRejection::new("package-not-validated", "")));
                }
            }
            let results: Vec<_> = results.into_iter().map(|r| r.expect("filled")).collect();
            let err = if results.iter().any(|r| r.is_err()) {
                Some(TxRejection::new("transaction failed", ""))
            } else {
                None
            };
            return (err, results);
        }

        // AcceptSubPackage(txns_package_eval): joint checks on the package
        // feerate.
        let sub: Vec<TransactionRef> = to_eval.iter().map(|&i| txs[i].clone()).collect();
        let mut view: HashMap<Txid, TransactionRef> = HashMap::new();
        let mut workspaces: Vec<Workspace> = Vec::new();
        let mut sub_error: Option<(usize, TxRejection)> = None;
        for (k, tx) in sub.iter().enumerate() {
            match self.checks(tx, Mode::PackageEval, Some((&sub, &view))) {
                Ok(ws) => {
                    view.insert(*tx.txid(), tx.clone());
                    workspaces.push(ws);
                }
                Err(e) => {
                    sub_error = Some((k, e));
                    break;
                }
            }
        }
        if sub_error.is_none() {
            if let Err((child_idx, msg)) = check_ephemeral_spends(&sub, DUST_RELAY_TX_FEE, self.pool) {
                sub_error = Some((child_idx, TxRejection::new("missing-ephemeral-spends", msg)));
            }
        }
        let total_vsize: u64 = workspaces.iter().map(|w| w.vsize).sum();
        let total_mod_fee: i64 = workspaces.iter().map(|w| w.mod_fee).sum();
        if sub_error.is_none() {
            // CheckFeeRate on the package feerate.
            let min_fee = self.pool.min_relay_fee().get_fee(total_vsize as usize).to_sat();
            if total_mod_fee < min_fee {
                sub_error = Some((
                    sub.len() - 1,
                    TxRejection::new("min relay fee not met", format!("{} < {}", total_mod_fee, min_fee)),
                ));
            }
        }
        if sub_error.is_none() {
            if let Err(e) = self.package_limits(&sub, &workspaces) {
                sub_error = Some((sub.len() - 1, e));
            }
        }
        if sub_error.is_none() {
            if let Err(e) = self.package_rbf_checks(&workspaces, total_vsize, total_mod_fee) {
                sub_error = Some((sub.len() - 1, e));
            }
        }

        match sub_error {
            Some((k, e)) => {
                for (pos, &i) in to_eval.iter().enumerate() {
                    results[i] = Some(Err(if pos == k { e.clone() } else { TxRejection::new("package-not-validated", "") }));
                }
            }
            None => {
                let rate = if total_vsize > 0 {
                    FeeRate::new(total_mod_fee * 1000 / total_vsize as i64)
                } else {
                    FeeRate::ZERO
                };
                let includes: Vec<String> = sub.iter().map(|t| t.wtxid().to_hex()).collect();
                // Evict everything the subpackage replaces once, then add.
                let mut evict: Vec<Txid> = Vec::new();
                for w in &workspaces {
                    for c in &w.conflicts {
                        if !evict.contains(c) {
                            evict.push(*c);
                        }
                    }
                }
                for c in &evict {
                    self.pool
                        .remove_recursive_with_reason(c, crate::mempool::MemPoolRemovalReason::Replaced);
                }
                for (pos, ws) in workspaces.into_iter().enumerate() {
                    let mut acc = self.accepted(&ws);
                    acc.effective_feerate = rate;
                    acc.effective_includes = includes.clone();
                    acc.replaced = if pos == 0 { evict.clone() } else { Vec::new() };
                    self.pool.add_unchecked(ws.entry);
                    results[to_eval[pos]] = Some(Ok(acc));
                }
            }
        }
        let results: Vec<_> = results.into_iter().map(|r| r.expect("filled")).collect();
        let err = if results.iter().any(|r| r.is_err()) {
            Some(TxRejection::new("transaction failed", ""))
        } else {
            None
        };
        (err, results)
    }

    /// Port of Core's `CheckPackageLimits` (txmempool.cpp): the subpackage
    /// counted as descending from every in-mempool ancestor of its members.
    fn package_limits(&self, sub: &[TransactionRef], ws: &[Workspace]) -> Result<(), TxRejection> {
        let mut ancestors: HashSet<Txid> = HashSet::new();
        for t in sub {
            ancestors.extend(self.pool.ancestors_of_inputs(t));
        }
        let pkg_count = sub.len() as u64;
        let pkg_size: u64 = ws.iter().map(|w| w.vsize).sum();
        let anc_size: u64 = ancestors.iter().map(|a| self.vsize_of(a)).sum();
        if ancestors.len() as u64 + pkg_count > DEFAULT_ANCESTOR_LIMIT
            || anc_size + pkg_size > DEFAULT_ANCESTOR_SIZE_LIMIT
        {
            return Err(TxRejection::new("package-mempool-limits", "exceeds ancestor limits"));
        }
        for a in &ancestors {
            let desc = self.pool.descendants_of(a);
            let size: u64 = desc.iter().map(|d| self.vsize_of(d)).sum::<u64>() + self.vsize_of(a);
            if desc.len() as u64 + 1 + pkg_count > DEFAULT_DESCENDANT_LIMIT
                || size + pkg_size > DEFAULT_DESCENDANT_SIZE_LIMIT
            {
                return Err(TxRejection::new(
                    "package-mempool-limits",
                    format!("exceeds descendant limits for tx {}", a.to_hex()),
                ));
            }
        }
        Ok(())
    }

    /// Port of Core v28's `PackageRBFChecks`: replacements by a subpackage
    /// are only allowed for a 1-parent-1-child subpackage whose conflicts
    /// each sit in a cluster of at most two transactions; the subpackage
    /// must pay more than everything it evicts, pay for its own relay at the
    /// incremental feerate, and have a higher feerate than every replaced
    /// cluster (Core's feerate-diagram check reduces to this for clusters
    /// of size <= 2 replaced by one package chunk).
    fn package_rbf_checks(&self, ws: &[Workspace], total_vsize: u64, total_mod_fee: i64) -> Result<(), TxRejection> {
        let mut evict: Vec<Txid> = Vec::new();
        let mut direct: Vec<Txid> = Vec::new();
        for w in ws {
            for c in &w.conflicts {
                if !evict.contains(c) {
                    evict.push(*c);
                }
            }
            for c in &w.direct_conflicts {
                if !direct.contains(c) {
                    direct.push(*c);
                }
            }
        }
        if evict.is_empty() {
            return Ok(());
        }
        let fail = |d: &str| TxRejection::new("package RBF failed", d.to_string());
        if ws.len() != 2 {
            return Err(fail("package must be 1-parent-1-child"));
        }
        if evict.len() > MAX_BIP125_REPLACEMENT_CANDIDATES {
            return Err(fail("too many potential replacements"));
        }
        // Cluster size limit: each conflict's cluster (ancestors +
        // descendants + itself) is at most 2.
        for c in &direct {
            let tx = match self.pool.get(c) {
                Some(t) => t,
                None => continue,
            };
            let cluster = 1 + self.pool.ancestors_of_inputs(&tx).len() + self.pool.descendants_of(c).len();
            if cluster > 2 {
                return Err(fail(&format!("{} has both ancestor and descendant, exceeding cluster limit of 2", c.to_hex())));
            }
        }
        let evicted_fees: i64 = evict
            .iter()
            .filter_map(|t| self.pool.get_entry(t))
            .map(|e| e.fee().to_sat() + self.pool.get_fee_delta(&e.txid()))
            .sum();
        if total_mod_fee <= evicted_fees {
            return Err(TxRejection::new(
                "package RBF failed",
                format!("insufficient fee, rejecting replacement; new fees {} <= old fees {}", total_mod_fee, evicted_fees),
            ));
        }
        let relay = self.pool.incremental_relay_fee().get_fee(total_vsize as usize).to_sat();
        if total_mod_fee - evicted_fees < relay {
            return Err(TxRejection::new(
                "package RBF failed",
                format!("insufficient anti-DoS fees, {} < {}", total_mod_fee - evicted_fees, relay),
            ));
        }
        // Feerate improvement over every replaced cluster.
        let pkg_rate = (total_mod_fee as i128) * 1000 / (total_vsize.max(1) as i128);
        for c in &direct {
            let tx = match self.pool.get(c) {
                Some(t) => t,
                None => continue,
            };
            let mut cluster: Vec<Txid> = vec![*c];
            cluster.extend(self.pool.ancestors_of_inputs(&tx));
            cluster.extend(self.pool.descendants_of(c));
            let (f, s) = cluster.iter().filter_map(|t| self.pool.get_entry(t)).fold((0i64, 0u64), |(f, s), e| {
                (f + e.fee().to_sat() + self.pool.get_fee_delta(&e.txid()), s + e.vsize() as u64)
            });
            let rate = (f as i128) * 1000 / (s.max(1) as i128);
            if pkg_rate <= rate {
                return Err(fail("insufficient feerate: does not improve feerate diagram"));
            }
        }
        Ok(())
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
