//! qubitcoin-crypto: Cryptographic primitives for Qubitcoin.
//!
//! Wraps secp256k1 and bitcoin_hashes to provide:
//! - SHA256d (double SHA256)
//! - RIPEMD160, Hash160, SHA256
//! - SipHash-2-4
//! - secp256k1 ECDSA and Schnorr operations
//!
//! Maps to: src/crypto/ in Bitcoin Core

pub mod hash;
pub mod muhash;
pub mod siphash;

// Re-export secp256k1 for downstream crates
pub use bitcoin_hashes;
pub use secp256k1;
