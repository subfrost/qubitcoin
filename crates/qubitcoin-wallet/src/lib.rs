//! qubitcoin-wallet: Wallet implementation for Qubitcoin.
//!
//! Maps to: `src/wallet/` in Bitcoin Core.
//!
//! Provides:
//! - [`wallet`]: Core descriptor wallet -- key management, address generation,
//!   transaction tracking, and UTXO accounting.
//! - [`coin_selection`]: Coin selection algorithms (largest-first, branch-and-bound).
//! - [`psbt`]: Simplified Partially Signed Bitcoin Transaction (BIP 174).

pub mod coin_selection;
pub mod psbt;
pub mod wallet;
