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

pub mod addr_manager;
pub mod ban_manager;
pub mod connection;
pub mod net_processing;
pub mod peer;
pub mod protocol;
pub mod rate_limiter;
