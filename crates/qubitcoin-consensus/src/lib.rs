//! qubitcoin-consensus: Embeddable consensus library for Qubitcoin.
//!
//! Zero I/O, no_std-optional. Pure functions for consensus validation.
//!
//! Maps to: bitcoin_consensus static lib + consensus/ directory
//!
//! Provides:
//! - Transaction types: OutPoint, TxIn, TxOut, Transaction, Block, BlockHeader
//! - Consensus validation: check_transaction, merkle root, PoW, subsidy
//! - ConsensusParams for network configurations
//! - ValidationState for error reporting

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod block;
pub mod check;
pub mod merkle;
pub mod params;
pub mod sighash;
pub mod sign;
pub mod transaction;
pub mod validation_state;

pub use block::{Block, BlockHeader};
pub use check::{
    check_proof_of_work, check_transaction, get_block_subsidy, get_legacy_sigop_count,
    get_p2sh_sigop_count, get_transaction_sigop_cost, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT,
    WITNESS_SCALE_FACTOR,
};
pub use merkle::{block_merkle_root, block_witness_merkle_root};
pub use params::ConsensusParams;
pub use sighash::{
    remove_codeseparators, signature_hash, taproot_signature_hash, witness_v0_signature_hash,
    PrecomputedTransactionData, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE,
};
pub use sign::TransactionSignatureChecker;
pub use transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, MAX_SEQUENCE_NONFINAL,
    SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_GRANULARITY,
    SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG,
};
pub use validation_state::{BlockValidationResult, TxValidationResult, ValidationState};

#[cfg(feature = "rust-bitcoin-compat")]
pub mod compat;
