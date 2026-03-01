//! Q-Day Regression: Consensus rule change to freeze quantum-vulnerable UTXOs.
//!
//! This crate implements the Q-Day freeze mechanism for Qubitcoin. At a
//! configured activation height, the node scans the UTXO set, scores each
//! output for quantum vulnerability and abandonment likelihood, and freezes
//! (makes unspendable) outputs above a safety threshold.
//!
//! # Integration
//!
//! The check is applied in `connect_block()` after `check_tx_inputs()`:
//!
//! ```ignore
//! use qday_regression::{QdayPolicy, check_qday_frozen};
//!
//! // In connect_block(), for each non-coinbase tx:
//! if policy.is_active(height) {
//!     check_qday_frozen(&tx, &policy, height)?;
//! }
//! ```
//!
//! # Design Principles
//!
//! - **Deterministic**: Frozen set computed identically on every node
//! - **Conservative**: Higher threshold = fewer frozen outputs = safer
//! - **Isolated**: Separate crate keeps quantum logic out of base consensus
//! - **No false positives**: HashSet membership, not probabilistic

pub mod consensus;
pub mod error;
pub mod frozen_set;
pub mod policy;
pub mod scanner;
pub mod scoring;

pub use consensus::{check_qday_frozen, check_qday_frozen_with_state};
pub use error::QdayError;
pub use frozen_set::FrozenOutpoints;
pub use policy::QdayPolicy;
pub use scanner::{compute_frozen_set, ExposedKeySet, UtxoEntry, UtxoIterator};
pub use scoring::{
    age_score, compute_score, dormancy_score, extract_p2pkh_pubkey, is_p2pk, is_p2pkh, is_p2tr,
    pattern_score, pubkey_hash160, value_score, VulnType,
};
