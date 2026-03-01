//! FROST threshold Schnorr keygen and P2MR address computation for Qubitcoin.
//!
//! This crate provides:
//! - **Dealer keygen**: Generate FROST 170/255 (or any t/n) threshold key shares
//! - **P2MR address**: Compute a BIP-360 P2MR witness program from a FROST group key
//! - **Keystore**: Serialize and persist key shares as JSON files

pub mod address;
pub mod keygen;
pub mod keystore;

pub use address::{build_p2mr_frost_script, frost_group_key_to_p2mr_program};
pub use keygen::{generate_frost_keys, group_verifying_key};
pub use keystore::{save_all_shares, FrostKeystore};
