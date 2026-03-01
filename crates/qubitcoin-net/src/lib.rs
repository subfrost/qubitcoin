//! qubitcoin-net: P2P networking for Qubitcoin.
//!
//! Maps to: src/net.cpp, src/net.h, src/net_processing.cpp, src/protocol.h,
//!          src/addrman.h, src/banman.h
//!
//! This crate provides the data structures and types for Bitcoin's P2P
//! networking protocol:
//!
//! - [`protocol`]: Message types, headers, service flags, inventory vectors
//! - [`peer`]: Per-connection state and the PeerManager registry
//! - [`connection`]: TCP connection management (listen, connect, handshake)
//! - [`net_processing`]: High-level message processing (inv, getdata, blocks)
//! - [`addr_manager`]: Address book for peer discovery (new/tried tables)
//! - [`ban_manager`]: Ban list for misbehaving peers

/// Address management for peer discovery (new/tried tables).
/// Equivalent to `CAddrMan` in Bitcoin Core.
pub mod addr_manager;

/// Ban list for misbehaving peers with expiry support.
/// Equivalent to `BanMan` in Bitcoin Core.
pub mod ban_manager;

/// TCP connection management: `ConnManager`, listen, connect, handshake, message I/O.
/// Equivalent to `CConnman` in Bitcoin Core.
pub mod connection;

/// High-level message processing: `NetProcessor` handles inv, getdata, blocks, headers, tx relay.
/// Equivalent to `PeerManagerImpl` in Bitcoin Core's `net_processing.cpp`.
pub mod net_processing;

/// Per-connection state and the thread-safe peer registry.
/// Equivalent to `CNode` and peer tracking in Bitcoin Core.
pub mod peer;

/// P2P protocol types: message headers, service flags, inventory vectors, messages.
/// Equivalent to `protocol.h` in Bitcoin Core.
pub mod protocol;

/// Connection-level rate limiting, bandwidth caps, and slow-peer detection.
pub mod rate_limiter;
