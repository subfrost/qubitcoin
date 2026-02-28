//! Address management for peer discovery.
//!
//! Maps to: src/addrman.h / src/addrman.cpp (CAddrMan)
//!
//! Provides:
//! - `AddrInfo`: Metadata about a known network address
//! - `AddrManager`: Thread-safe address book with new/tried tables
//!
//! The address manager tracks addresses that peers have told us about (new)
//! and addresses that we have successfully connected to (tried). When the
//! node needs a new outbound peer it calls `select()` which returns an
//! address to try connecting to.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use parking_lot::RwLock;

use crate::protocol::{NetAddress, ServiceFlags};

// ---------------------------------------------------------------------------
// AddrInfo
// ---------------------------------------------------------------------------

/// Metadata about a known network address.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    /// The network address (ip, port, services).
    pub addr: NetAddress,
    /// Who told us about this address.
    pub source: SocketAddr,
    /// Last time we successfully connected to this address.
    pub last_success: Option<Instant>,
    /// Last time we attempted to connect to this address.
    pub last_try: Option<Instant>,
    /// Number of connection attempts made.
    pub attempts: u32,
    /// Services advertised by this address.
    pub services: ServiceFlags,
}

// ---------------------------------------------------------------------------
// AddrManager
// ---------------------------------------------------------------------------

/// Manages known network addresses for peer discovery.
///
/// Addresses are tracked in two tables:
/// - **new**: addresses we have learned about from peers but have not connected to.
/// - **tried**: addresses we have successfully connected to in the past.
///
/// This mirrors the new/tried table design in Bitcoin Core's CAddrMan.
pub struct AddrManager {
    /// All known addresses indexed by their socket address.
    addrs: RwLock<HashMap<SocketAddr, AddrInfo>>,
    /// Addresses available for connection attempts (not yet successfully connected).
    new_addrs: RwLock<Vec<SocketAddr>>,
    /// Addresses that we have successfully connected to.
    tried_addrs: RwLock<Vec<SocketAddr>>,
}

impl AddrManager {
    /// Create an empty address manager.
    pub fn new() -> Self {
        AddrManager {
            addrs: RwLock::new(HashMap::new()),
            new_addrs: RwLock::new(Vec::new()),
            tried_addrs: RwLock::new(Vec::new()),
        }
    }

    /// Add a network address learned from `source`.
    ///
    /// If the address is already known, this is a no-op (we do not overwrite
    /// existing metadata). New addresses are placed in the "new" table.
    pub fn add(&self, addr: NetAddress, source: SocketAddr) {
        let sock_addr = addr.socket_addr();
        let services = addr.services;

        let mut all = self.addrs.write();
        if all.contains_key(&sock_addr) {
            return;
        }

        let info = AddrInfo {
            addr,
            source,
            last_success: None,
            last_try: None,
            attempts: 0,
            services,
        };

        all.insert(sock_addr, info);
        drop(all);

        self.new_addrs.write().push(sock_addr);
    }

    /// Mark an address as successfully connected (move to the tried table).
    pub fn mark_good(&self, addr: &SocketAddr) {
        let mut all = self.addrs.write();
        if let Some(info) = all.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempts = 0;
        }
        drop(all);

        // Move from new to tried if present.
        let mut new = self.new_addrs.write();
        if let Some(pos) = new.iter().position(|a| a == addr) {
            new.swap_remove(pos);
            drop(new);
            let mut tried = self.tried_addrs.write();
            if !tried.contains(addr) {
                tried.push(*addr);
            }
        }
    }

    /// Mark that a connection attempt was made to the given address.
    pub fn mark_attempt(&self, addr: &SocketAddr) {
        let mut all = self.addrs.write();
        if let Some(info) = all.get_mut(addr) {
            info.last_try = Some(Instant::now());
            info.attempts += 1;
        }
    }

    /// Select an address to try connecting to.
    ///
    /// Prefers tried addresses over new addresses. Returns `None` if no
    /// addresses are available.
    pub fn select(&self) -> Option<SocketAddr> {
        // Prefer tried addresses first (they have proven to work).
        {
            let tried = self.tried_addrs.read();
            if !tried.is_empty() {
                // Simple selection: pick the first tried address.
                // A production implementation would use randomized selection
                // to avoid always hitting the same peer.
                return Some(tried[0]);
            }
        }

        // Fall back to new addresses.
        {
            let new = self.new_addrs.read();
            if !new.is_empty() {
                return Some(new[0]);
            }
        }

        None
    }

    /// Total number of known addresses across all tables.
    pub fn size(&self) -> usize {
        self.addrs.read().len()
    }

    /// Return the number of "new" addresses (not yet successfully connected).
    pub fn new_count(&self) -> usize {
        self.new_addrs.read().len()
    }

    /// Return the number of "tried" addresses (successfully connected before).
    pub fn tried_count(&self) -> usize {
        self.tried_addrs.read().len()
    }

    /// Get a set of addresses suitable for sharing with peers (addr message).
    ///
    /// Returns up to 1000 addresses, prioritizing tried addresses.
    pub fn get_addr(&self) -> Vec<NetAddress> {
        let all = self.addrs.read();
        let tried = self.tried_addrs.read();
        let new = self.new_addrs.read();

        let mut result = Vec::new();
        let max = 1000;

        // Add tried addresses first.
        for sock in tried.iter() {
            if result.len() >= max {
                break;
            }
            if let Some(info) = all.get(sock) {
                result.push(info.addr.clone());
            }
        }

        // Fill with new addresses.
        for sock in new.iter() {
            if result.len() >= max {
                break;
            }
            if let Some(info) = all.get(sock) {
                result.push(info.addr.clone());
            }
        }

        result
    }

    /// Get the `AddrInfo` for a specific address, if known.
    pub fn get_info(&self, addr: &SocketAddr) -> Option<AddrInfo> {
        self.addrs.read().get(addr).cloned()
    }

    /// Remove an address from all tables.
    pub fn remove(&self, addr: &SocketAddr) {
        self.addrs.write().remove(addr);
        self.new_addrs.write().retain(|a| a != addr);
        self.tried_addrs.write().retain(|a| a != addr);
    }
}

impl Default for AddrManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(ip_last: u8, port: u16) -> NetAddress {
        NetAddress::new(
            ServiceFlags::NODE_NETWORK,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip_last)),
            port,
        )
    }

    fn source_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333)
    }

    #[test]
    fn test_addr_manager_new() {
        let am = AddrManager::new();
        assert_eq!(am.size(), 0);
        assert_eq!(am.new_count(), 0);
        assert_eq!(am.tried_count(), 0);
        assert!(am.select().is_none());
    }

    #[test]
    fn test_addr_manager_add() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        am.add(addr, source_addr());

        assert_eq!(am.size(), 1);
        assert_eq!(am.new_count(), 1);
        assert_eq!(am.tried_count(), 0);
    }

    #[test]
    fn test_addr_manager_add_duplicate() {
        let am = AddrManager::new();
        let addr1 = make_addr(1, 8333);
        let addr2 = make_addr(1, 8333); // same ip:port

        am.add(addr1, source_addr());
        am.add(addr2, source_addr());

        // Should not duplicate.
        assert_eq!(am.size(), 1);
        assert_eq!(am.new_count(), 1);
    }

    #[test]
    fn test_addr_manager_add_different() {
        let am = AddrManager::new();
        am.add(make_addr(1, 8333), source_addr());
        am.add(make_addr(2, 8333), source_addr());
        am.add(make_addr(3, 8334), source_addr());

        assert_eq!(am.size(), 3);
        assert_eq!(am.new_count(), 3);
    }

    #[test]
    fn test_addr_manager_select_new() {
        let am = AddrManager::new();
        am.add(make_addr(1, 8333), source_addr());

        let selected = am.select();
        assert!(selected.is_some());
        let selected = selected.unwrap();
        assert_eq!(selected.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(selected.port(), 8333);
    }

    #[test]
    fn test_addr_manager_mark_good() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());

        assert_eq!(am.new_count(), 1);
        assert_eq!(am.tried_count(), 0);

        am.mark_good(&sock);

        assert_eq!(am.new_count(), 0);
        assert_eq!(am.tried_count(), 1);
        assert_eq!(am.size(), 1); // total unchanged

        // Check that last_success was set and attempts reset.
        let info = am.get_info(&sock).unwrap();
        assert!(info.last_success.is_some());
        assert_eq!(info.attempts, 0);
    }

    #[test]
    fn test_addr_manager_mark_good_idempotent() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());
        am.mark_good(&sock);
        am.mark_good(&sock); // second call should be no-op on tables

        assert_eq!(am.tried_count(), 1);
        assert_eq!(am.new_count(), 0);
    }

    #[test]
    fn test_addr_manager_mark_attempt() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());

        am.mark_attempt(&sock);
        let info = am.get_info(&sock).unwrap();
        assert_eq!(info.attempts, 1);
        assert!(info.last_try.is_some());

        am.mark_attempt(&sock);
        let info = am.get_info(&sock).unwrap();
        assert_eq!(info.attempts, 2);
    }

    #[test]
    fn test_addr_manager_mark_attempt_unknown() {
        let am = AddrManager::new();
        let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8333);
        // Should not panic.
        am.mark_attempt(&unknown);
    }

    #[test]
    fn test_addr_manager_select_prefers_tried() {
        let am = AddrManager::new();
        let new_addr = make_addr(1, 8333);
        let tried_addr = make_addr(2, 8333);
        let tried_sock = tried_addr.socket_addr();

        am.add(new_addr, source_addr());
        am.add(tried_addr, source_addr());
        am.mark_good(&tried_sock);

        // select() should prefer the tried address.
        let selected = am.select().unwrap();
        assert_eq!(selected, tried_sock);
    }

    #[test]
    fn test_addr_manager_get_addr() {
        let am = AddrManager::new();
        for i in 1..=5 {
            am.add(make_addr(i, 8333), source_addr());
        }

        let addrs = am.get_addr();
        assert_eq!(addrs.len(), 5);
    }

    #[test]
    fn test_addr_manager_get_addr_prioritizes_tried() {
        let am = AddrManager::new();
        let tried_addr = make_addr(1, 8333);
        let tried_sock = tried_addr.socket_addr();
        am.add(tried_addr, source_addr());
        am.add(make_addr(2, 8333), source_addr());
        am.mark_good(&tried_sock);

        let addrs = am.get_addr();
        assert_eq!(addrs.len(), 2);
        // First address should be the tried one.
        assert_eq!(addrs[0].socket_addr(), tried_sock);
    }

    #[test]
    fn test_addr_manager_remove() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());
        assert_eq!(am.size(), 1);

        am.remove(&sock);
        assert_eq!(am.size(), 0);
        assert_eq!(am.new_count(), 0);
        assert!(am.get_info(&sock).is_none());
    }

    #[test]
    fn test_addr_manager_remove_tried() {
        let am = AddrManager::new();
        let addr = make_addr(1, 8333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());
        am.mark_good(&sock);

        assert_eq!(am.tried_count(), 1);
        am.remove(&sock);
        assert_eq!(am.size(), 0);
        assert_eq!(am.tried_count(), 0);
    }

    #[test]
    fn test_addr_manager_get_info() {
        let am = AddrManager::new();
        let addr = make_addr(42, 18333);
        let sock = addr.socket_addr();
        am.add(addr, source_addr());

        let info = am.get_info(&sock).unwrap();
        assert_eq!(info.addr.port, 18333);
        assert!(info.services.contains(ServiceFlags::NODE_NETWORK));
        assert_eq!(info.source, source_addr());
        assert_eq!(info.attempts, 0);
        assert!(info.last_success.is_none());
        assert!(info.last_try.is_none());
    }

    #[test]
    fn test_addr_manager_default() {
        let am = AddrManager::default();
        assert_eq!(am.size(), 0);
    }
}
