//! TRUC (Topologically Restricted Until Confirmation, "v3") policy.
//!
//! Port of Bitcoin Core's `policy/truc_policy.cpp` / `truc_policy.h`
//! (v28): version-3 transactions may have at most one unconfirmed ancestor
//! and one unconfirmed descendant, are size-limited (10 kvB, 1 kvB for a
//! child), and cannot be mixed with non-v3 transactions in an unconfirmed
//! chain. A v3 child that would exceed the parent's descendant limit may
//! evict its sibling under RBF rules ("sibling eviction").

use std::collections::HashSet;

use qubitcoin_consensus::transaction::{Transaction, TransactionRef};
use qubitcoin_primitives::Txid;

/// Version number of TRUC transactions (`TRUC_VERSION`).
pub const TRUC_VERSION: u32 = 3;
/// Ancestor count limit, including the transaction itself.
pub const TRUC_ANCESTOR_LIMIT: usize = 2;
/// Descendant count limit, including the transaction itself.
pub const TRUC_DESCENDANT_LIMIT: usize = 2;
/// Maximum sigop-adjusted virtual size of any TRUC transaction.
pub const TRUC_MAX_VSIZE: u64 = 10_000;
/// Maximum sigop-adjusted virtual size of a TRUC transaction with an
/// unconfirmed parent.
pub const TRUC_CHILD_MAX_VSIZE: u64 = 1_000;

/// What the TRUC checks need to know about an in-mempool ancestor.
#[derive(Debug, Clone)]
pub struct TrucAncestor {
    /// Ancestor txid.
    pub txid: Txid,
    /// Ancestor wtxid (hex), for error strings.
    pub wtxid: String,
    /// Ancestor `nVersion`.
    pub version: u32,
    /// Descendant count including itself (Core's `GetCountWithDescendants`).
    pub descendant_count: usize,
    /// Direct in-mempool children: `(txid, ancestor count including self)`.
    pub children: Vec<(Txid, usize)>,
}

fn ids(tx: &Transaction) -> (String, String) {
    (tx.txid().to_hex(), tx.wtxid().to_hex())
}

/// Port of Core's `SingleTRUCChecks()`. On violation returns the debug
/// string and, when sibling eviction may be considered, the sibling to
/// evict.
pub fn single_truc_checks(
    tx: &Transaction,
    mempool_ancestors: &[TrucAncestor],
    direct_conflicts: &HashSet<Txid>,
    vsize: u64,
) -> Option<(String, Option<Txid>)> {
    let (txid, wtxid) = ids(tx);
    // Check TRUC and non-TRUC inheritance.
    for a in mempool_ancestors {
        if tx.version != TRUC_VERSION && a.version == TRUC_VERSION {
            return Some((
                format!(
                    "non-version=3 tx {} (wtxid={}) cannot spend from version=3 tx {} (wtxid={})",
                    txid,
                    wtxid,
                    a.txid.to_hex(),
                    a.wtxid
                ),
                None,
            ));
        } else if tx.version == TRUC_VERSION && a.version != TRUC_VERSION {
            return Some((
                format!(
                    "version=3 tx {} (wtxid={}) cannot spend from non-version=3 tx {} (wtxid={})",
                    txid,
                    wtxid,
                    a.txid.to_hex(),
                    a.wtxid
                ),
                None,
            ));
        }
    }

    // The rest of the rules only apply to transactions with version=3.
    if tx.version != TRUC_VERSION {
        return None;
    }

    if vsize > TRUC_MAX_VSIZE {
        return Some((
            format!(
                "version=3 tx {} (wtxid={}) is too big: {} > {} virtual bytes",
                txid, wtxid, vsize, TRUC_MAX_VSIZE
            ),
            None,
        ));
    }

    if mempool_ancestors.len() + 1 > TRUC_ANCESTOR_LIMIT {
        return Some((
            format!("tx {} (wtxid={}) would have too many ancestors", txid, wtxid),
            None,
        ));
    }

    if let Some(parent) = mempool_ancestors.first() {
        if vsize > TRUC_CHILD_MAX_VSIZE {
            return Some((
                format!(
                    "version=3 child tx {} (wtxid={}) is too big: {} > {} virtual bytes",
                    txid, wtxid, vsize, TRUC_CHILD_MAX_VSIZE
                ),
                None,
            ));
        }
        // Don't double-count a child that is going to be replaced.
        let child_will_be_replaced = parent
            .children
            .iter()
            .any(|(c, _)| direct_conflicts.contains(c));
        if parent.descendant_count + 1 > TRUC_DESCENDANT_LIMIT && !child_will_be_replaced {
            // Sibling eviction is only considered when the parent has
            // exactly one child, which itself has no other ancestors.
            let consider_sibling_eviction = parent.descendant_count == 2
                && parent.children.len() == 1
                && parent.children[0].1 == 2;
            return Some((
                format!("tx {} (wtxid={}) would exceed descendant count limit", txid, wtxid),
                if consider_sibling_eviction { Some(parent.children[0].0) } else { None },
            ));
        }
    }
    None
}

/// Port of Core's `PackageTRUCChecks()`: the TRUC rules for `tx` given the
/// other members of its package and its in-mempool ancestors.
pub fn package_truc_checks(
    tx: &TransactionRef,
    vsize: u64,
    package: &[TransactionRef],
    mempool_ancestors: &[TrucAncestor],
) -> Option<String> {
    let (txid, wtxid) = ids(tx);
    let in_package_parents: Vec<&TransactionRef> = package
        .iter()
        .filter(|p| !std::ptr::eq(p.as_ref(), tx.as_ref()))
        .filter(|p| tx.vin.iter().any(|i| i.prevout.hash == *p.txid()))
        .collect();

    if tx.version == TRUC_VERSION {
        if vsize > TRUC_MAX_VSIZE {
            return Some(format!(
                "version=3 tx {} (wtxid={}) is too big: {} > {} virtual bytes",
                txid, wtxid, vsize, TRUC_MAX_VSIZE
            ));
        }
        if mempool_ancestors.len() + in_package_parents.len() + 1 > TRUC_ANCESTOR_LIMIT {
            return Some(format!("tx {} (wtxid={}) would have too many ancestors", txid, wtxid));
        }
        let has_parent = mempool_ancestors.len() + in_package_parents.len() > 0;
        if has_parent {
            if vsize > TRUC_CHILD_MAX_VSIZE {
                return Some(format!(
                    "version=3 child tx {} (wtxid={}) is too big: {} > {} virtual bytes",
                    txid, wtxid, vsize, TRUC_CHILD_MAX_VSIZE
                ));
            }
            // Exactly one parent exists, in the mempool or the package.
            let (parent_txid, parent_wtxid, parent_version, parent_has_mempool_descendant) =
                match mempool_ancestors.first() {
                    Some(a) => (a.txid, a.wtxid.clone(), a.version, a.descendant_count > 1),
                    None => {
                        let p = in_package_parents[0];
                        (*p.txid(), p.wtxid().to_hex(), p.version, false)
                    }
                };
            if parent_version != TRUC_VERSION {
                return Some(format!(
                    "version=3 tx {} (wtxid={}) cannot spend from non-version=3 tx {} (wtxid={})",
                    txid,
                    wtxid,
                    parent_txid.to_hex(),
                    parent_wtxid
                ));
            }
            for other in package {
                if std::ptr::eq(other.as_ref(), tx.as_ref()) {
                    continue;
                }
                for input in &other.vin {
                    if input.prevout.hash == parent_txid {
                        return Some(format!(
                            "tx {} (wtxid={}) would exceed descendant count limit",
                            txid, wtxid
                        ));
                    }
                    if input.prevout.hash == *tx.txid() {
                        return Some(format!(
                            "tx {} (wtxid={}) would have too many ancestors",
                            txid, wtxid
                        ));
                    }
                }
            }
            if parent_has_mempool_descendant {
                return Some(format!(
                    "tx {} (wtxid={}) would exceed descendant count limit",
                    txid, wtxid
                ));
            }
        }
    } else {
        // Non-TRUC transactions cannot have TRUC parents.
        for a in mempool_ancestors {
            if a.version == TRUC_VERSION {
                return Some(format!(
                    "non-version=3 tx {} (wtxid={}) cannot spend from version=3 tx {} (wtxid={})",
                    txid,
                    wtxid,
                    a.txid.to_hex(),
                    a.wtxid
                ));
            }
        }
        for p in in_package_parents {
            if p.version == TRUC_VERSION {
                return Some(format!(
                    "non-version=3 tx {} (wtxid={}) cannot spend from version=3 tx {} (wtxid={})",
                    txid,
                    wtxid,
                    p.txid().to_hex(),
                    p.wtxid().to_hex()
                ));
            }
        }
    }
    None
}
