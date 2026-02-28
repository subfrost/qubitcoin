//! qubitcoin-util: Utility functions for Qubitcoin.
//!
//! Maps to: various utility files in Bitcoin Core (logging, time, args).
//!
//! Provides:
//! - [`logging`]: Logging initialization and log categories matching Bitcoin Core's `-debug=` categories.
//! - [`time`]: Time utilities including a mockable clock for testing.
//! - [`args`]: Command-line argument parser matching Bitcoin Core's `-key=value` style.

pub mod args;
pub mod logging;
pub mod metrics;
pub mod time;
