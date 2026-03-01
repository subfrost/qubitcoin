//! qubitcoin-wallet: Wallet implementation for Qubitcoin.
//!
//! Maps to: `src/wallet/` in Bitcoin Core.
//!
//! Provides:
//! - [`wallet`]: Core descriptor wallet -- key management, address generation,
//!   transaction tracking, and UTXO accounting.
//! - [`coin_selection`]: Coin selection algorithms (largest-first, branch-and-bound).
//! - [`psbt`]: Simplified Partially Signed Bitcoin Transaction (BIP 174).

/// Coin selection algorithms (largest-first and branch-and-bound).
pub mod coin_selection;
/// Simplified Partially Signed Bitcoin Transaction (BIP 174) implementation.
pub mod psbt;
/// Core descriptor wallet: `Wallet`, `WalletKey`, `AddressInfo`, `DerivationPath`, `DescriptorType`.
pub mod wallet;
