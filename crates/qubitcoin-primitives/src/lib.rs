//! qubitcoin-primitives: Primitive types for Qubitcoin.
//!
//! Maps to: src/uint256.h, src/arith_uint256.h, src/consensus/amount.h
//!
//! Provides:
//! - `Uint256`, `Uint160`: Fixed-size opaque byte blobs (for hashes)
//! - `ArithUint256`: 256-bit integer with full arithmetic (for difficulty)
//! - `Amount`: Satoshi amount type
//! - `Txid`, `Wtxid`, `BlockHash`: Typed hash wrappers

pub mod amount;
pub mod arith_uint256;
pub mod hash_types;
pub mod uint256;

// Convenient re-exports
pub use amount::{money_range, Amount, COIN, MAX_MONEY};
pub use arith_uint256::{arith_to_uint256, uint256_to_arith, ArithUint256};
pub use hash_types::{BlockHash, Txid, Wtxid};
pub use uint256::{Uint160, Uint256};
