//! Peer state management.
//!
//! Maps to: parts of src/net.h (CNode) and src/net_processing.cpp (Peer)
//!
//! Provides:
//! - `PeerState`: Connection state machine
//! - `Peer`: Per-connection state
//! - `PeerManager`: Thread-safe registry of all connected peers

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

use crate::protocol::ServiceFlags;

// ---------------------------------------------------------------------------
// PeerState
// ---------------------------------------------------------------------------

/// State machine for a peer connection.
///
/// State transitions:
///   Connecting -> Connected -> Handshaking -> Ready -> Disconnecting -> Disconnected
///
/// Any state may transition directly to Disconnecting/Disconnected on error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// TCP connection in progress.
    Connecting,
    /// TCP connection established, waiting to begin handshake.
    Connected,
    /// Version/verack handshake in progress.
    Handshaking,
    /// Handshake complete, peer is fully operational.
    Ready,
    /// Disconnect initiated (graceful shutdown in progress).
    Disconnecting,
    /// Connection is closed.
    Disconnected,
}

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

/// Connection type classification (maps to Bitcoin Core's ConnectionType).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Inbound connection from a peer.
    Inbound,
    /// Outbound full-relay connection (blocks, txns, addrs).
    OutboundFullRelay,
    /// Manual connection via -connect or addnode RPC.
    Manual,
    /// Feeler connection for address validation (short-lived).
    Feeler,
    /// Block-relay-only connection (no tx relay, no addr relay).
    BlockRelay,
    /// Address fetch connection (get addrs then disconnect).
    AddrFetch,
}

/// Represents a connected peer and its associated state.
///
/// Maps to CNode in Bitcoin Core.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Unique identifier assigned by PeerManager.
    pub id: u64,
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Current connection state.
    pub state: PeerState,
    /// Negotiated protocol version (set after version handshake).
    pub version: u32,
    /// Services advertised by this peer.
    pub services: ServiceFlags,
    /// User agent string (e.g., "/Satoshi:25.0.0/").
    pub user_agent: String,
    /// Best block height advertised by this peer.
    pub start_height: i32,
    /// When this connection was established.
    pub connected_at: Instant,
    /// When we last received data from this peer.
    pub last_recv: Instant,
    /// When we last sent data to this peer.
    pub last_send: Instant,
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// Whether this peer wants transaction relay (BIP 37).
    pub relay: bool,
    /// Total bytes sent to this peer.
    pub bytes_sent: u64,
    /// Total bytes received from this peer.
    pub bytes_recv: u64,
    /// Nonce of outstanding ping (None if no ping in flight).
    pub ping_nonce: Option<u64>,
    /// Minimum fee rate filter in sat/kvB (BIP 133).
    pub min_fee_filter: i64,
    /// Connection type (inbound, outbound-full, block-relay, etc.).
    pub conn_type: ConnectionType,
    /// Whether this peer supports wtxid-based relay (BIP 339).
    pub wtxid_relay: bool,
    /// Whether this peer supports addrv2 messages (BIP 155).
    pub wants_addrv2: bool,
    /// Whether we prefer headers announcements from this peer (BIP 130).
    pub prefer_headers: bool,
    /// Whether we prefer compact block announcements from this peer (BIP 152).
    pub prefer_cmpctblock: bool,
    /// Compact blocks version supported by this peer.
    pub cmpctblock_version: u64,
    /// Whether the peer's version handshake has been fully processed.
    pub version_received: bool,
    /// Whether we have received verack from this peer.
    pub verack_received: bool,
    /// Whether this peer has been marked as misbehaving (discouraged).
    pub discouraged: bool,
}

impl Peer {
    /// Create a new peer in Connecting state.
    pub fn new(id: u64, addr: SocketAddr, inbound: bool) -> Self {
        let now = Instant::now();
        let conn_type = if inbound {
            ConnectionType::Inbound
        } else {
            ConnectionType::OutboundFullRelay
        };
        Peer {
            id,
            addr,
            state: PeerState::Connecting,
            version: 0,
            services: ServiceFlags::NODE_NONE,
            user_agent: String::new(),
            start_height: 0,
            connected_at: now,
            last_recv: now,
            last_send: now,
            inbound,
            relay: true,
            bytes_sent: 0,
            bytes_recv: 0,
            ping_nonce: None,
            min_fee_filter: 0,
            conn_type,
            wtxid_relay: false,
            wants_addrv2: false,
            prefer_headers: false,
            prefer_cmpctblock: false,
            cmpctblock_version: 0,
            version_received: false,
            verack_received: false,
            discouraged: false,
        }
    }

    /// Returns true if the peer has completed the version handshake.
    pub fn is_ready(&self) -> bool {
        self.state == PeerState::Ready
    }

    /// Update the timestamp for the last received data.
    pub fn update_last_recv(&mut self) {
        self.last_recv = Instant::now();
    }

    /// Update the timestamp for the last sent data.
    pub fn update_last_send(&mut self) {
        self.last_send = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// PeerManager
// ---------------------------------------------------------------------------

/// Thread-safe manager for all connected peers.
///
/// Provides atomic peer ID generation and RwLock-protected access
/// to the peer table. Tracks inbound/outbound connection limits.
pub struct PeerManager {
    /// Map from peer ID to peer state.
    peers: RwLock<HashMap<u64, Peer>>,
    /// Next peer ID to assign.
    next_id: AtomicU64,
    /// Maximum number of inbound connections.
    max_inbound: usize,
    /// Maximum number of outbound connections.
    max_outbound: usize,
}

impl PeerManager {
    /// Create a new PeerManager with the given connection limits.
    pub fn new(max_inbound: usize, max_outbound: usize) -> Self {
        PeerManager {
            peers: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_inbound,
            max_outbound,
        }
    }

    /// Register a new peer and return its assigned ID.
    ///
    /// The peer is created in `Connecting` state.
    pub fn add_peer(&self, addr: SocketAddr, inbound: bool) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let peer = Peer::new(id, addr, inbound);
        self.peers.write().insert(id, peer);
        id
    }

    /// Remove a peer by ID. No-op if the peer does not exist.
    pub fn remove_peer(&self, id: u64) {
        self.peers.write().remove(&id);
    }

    /// Get a clone of a peer's state. Returns None if the peer does not exist.
    pub fn get_peer(&self, id: u64) -> Option<Peer> {
        self.peers.read().get(&id).cloned()
    }

    /// Total number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Number of inbound peers.
    pub fn inbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| p.inbound).count()
    }

    /// Number of outbound peers.
    pub fn outbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| !p.inbound).count()
    }

    /// Get all peer IDs.
    pub fn get_peer_ids(&self) -> Vec<u64> {
        self.peers.read().keys().copied().collect()
    }

    /// Update a peer's state in-place with the given closure.
    ///
    /// No-op if the peer does not exist.
    pub fn update_peer<F: FnOnce(&mut Peer)>(&self, id: u64, f: F) {
        if let Some(peer) = self.peers.write().get_mut(&id) {
            f(peer);
        }
    }

    /// Get the maximum inbound connection limit.
    pub fn max_inbound(&self) -> usize {
        self.max_inbound
    }

    /// Get the maximum outbound connection limit.
    pub fn max_outbound(&self) -> usize {
        self.max_outbound
    }

    /// Check whether we can accept another inbound connection.
    pub fn can_accept_inbound(&self) -> bool {
        self.inbound_count() < self.max_inbound
    }

    /// Check whether we can initiate another outbound connection.
    pub fn can_connect_outbound(&self) -> bool {
        self.outbound_count() < self.max_outbound
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_peer_new() {
        let peer = Peer::new(1, test_addr(8333), false);
        assert_eq!(peer.id, 1);
        assert_eq!(peer.state, PeerState::Connecting);
        assert!(!peer.inbound);
        assert_eq!(peer.version, 0);
        assert_eq!(peer.services, ServiceFlags::NODE_NONE);
        assert_eq!(peer.user_agent, "");
        assert_eq!(peer.start_height, 0);
        assert!(peer.relay);
        assert_eq!(peer.bytes_sent, 0);
        assert_eq!(peer.bytes_recv, 0);
        assert!(peer.ping_nonce.is_none());
        assert_eq!(peer.min_fee_filter, 0);
        assert_eq!(peer.conn_type, ConnectionType::OutboundFullRelay);
        assert!(!peer.wtxid_relay);
        assert!(!peer.wants_addrv2);
        assert!(!peer.prefer_headers);
        assert!(!peer.prefer_cmpctblock);
        assert_eq!(peer.cmpctblock_version, 0);
        assert!(!peer.version_received);
        assert!(!peer.verack_received);
        assert!(!peer.discouraged);
    }

    #[test]
    fn test_peer_new_inbound() {
        let peer = Peer::new(2, test_addr(8333), true);
        assert!(peer.inbound);
        assert_eq!(peer.conn_type, ConnectionType::Inbound);
    }

    #[test]
    fn test_connection_type_values() {
        assert_ne!(ConnectionType::Inbound, ConnectionType::OutboundFullRelay);
        assert_ne!(ConnectionType::Manual, ConnectionType::Feeler);
        assert_ne!(ConnectionType::BlockRelay, ConnectionType::AddrFetch);
        // Clone + Copy
        let ct = ConnectionType::Manual;
        let ct2 = ct;
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_peer_is_ready() {
        let mut peer = Peer::new(1, test_addr(8333), false);
        assert!(!peer.is_ready());
        peer.state = PeerState::Ready;
        assert!(peer.is_ready());
    }

    #[test]
    fn test_peer_state_transitions() {
        let mut peer = Peer::new(1, test_addr(8333), true);
        assert_eq!(peer.state, PeerState::Connecting);

        peer.state = PeerState::Connected;
        assert_eq!(peer.state, PeerState::Connected);

        peer.state = PeerState::Handshaking;
        assert_eq!(peer.state, PeerState::Handshaking);

        peer.state = PeerState::Ready;
        assert!(peer.is_ready());

        peer.state = PeerState::Disconnecting;
        assert!(!peer.is_ready());

        peer.state = PeerState::Disconnected;
        assert_eq!(peer.state, PeerState::Disconnected);
    }

    #[test]
    fn test_peer_update_timestamps() {
        let mut peer = Peer::new(1, test_addr(8333), false);
        let initial_recv = peer.last_recv;
        let initial_send = peer.last_send;

        // Give a tiny bit of time to pass.
        std::thread::sleep(std::time::Duration::from_millis(1));

        peer.update_last_recv();
        assert!(peer.last_recv >= initial_recv);

        peer.update_last_send();
        assert!(peer.last_send >= initial_send);
    }

    #[test]
    fn test_peer_manager_new() {
        let pm = PeerManager::new(125, 10);
        assert_eq!(pm.max_inbound(), 125);
        assert_eq!(pm.max_outbound(), 10);
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_peer_manager_add_and_get() {
        let pm = PeerManager::new(125, 10);
        let id = pm.add_peer(test_addr(8333), false);
        assert!(id > 0);

        let peer = pm.get_peer(id).expect("peer should exist");
        assert_eq!(peer.id, id);
        assert_eq!(peer.addr, test_addr(8333));
        assert!(!peer.inbound);
    }

    #[test]
    fn test_peer_manager_unique_ids() {
        let pm = PeerManager::new(125, 10);
        let id1 = pm.add_peer(test_addr(8333), false);
        let id2 = pm.add_peer(test_addr(8334), false);
        let id3 = pm.add_peer(test_addr(8335), true);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_peer_manager_remove() {
        let pm = PeerManager::new(125, 10);
        let id = pm.add_peer(test_addr(8333), false);
        assert_eq!(pm.peer_count(), 1);

        pm.remove_peer(id);
        assert_eq!(pm.peer_count(), 0);
        assert!(pm.get_peer(id).is_none());
    }

    #[test]
    fn test_peer_manager_remove_nonexistent() {
        let pm = PeerManager::new(125, 10);
        // Should not panic.
        pm.remove_peer(999);
    }

    #[test]
    fn test_peer_manager_counts() {
        let pm = PeerManager::new(125, 10);
        pm.add_peer(test_addr(8333), true); // inbound
        pm.add_peer(test_addr(8334), false); // outbound
        pm.add_peer(test_addr(8335), true); // inbound
        pm.add_peer(test_addr(8336), false); // outbound
        pm.add_peer(test_addr(8337), true); // inbound

        assert_eq!(pm.peer_count(), 5);
        assert_eq!(pm.inbound_count(), 3);
        assert_eq!(pm.outbound_count(), 2);
    }

    #[test]
    fn test_peer_manager_get_peer_ids() {
        let pm = PeerManager::new(125, 10);
        let id1 = pm.add_peer(test_addr(8333), false);
        let id2 = pm.add_peer(test_addr(8334), true);
        let id3 = pm.add_peer(test_addr(8335), false);

        let mut ids = pm.get_peer_ids();
        ids.sort();
        let mut expected = vec![id1, id2, id3];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn test_peer_manager_update_peer() {
        let pm = PeerManager::new(125, 10);
        let id = pm.add_peer(test_addr(8333), false);

        pm.update_peer(id, |peer| {
            peer.state = PeerState::Ready;
            peer.version = 70016;
            peer.services = ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS;
            peer.user_agent = "/Satoshi:25.0.0/".to_string();
            peer.start_height = 800_000;
        });

        let peer = pm.get_peer(id).unwrap();
        assert!(peer.is_ready());
        assert_eq!(peer.version, 70016);
        assert!(peer.services.contains(ServiceFlags::NODE_WITNESS));
        assert_eq!(peer.user_agent, "/Satoshi:25.0.0/");
        assert_eq!(peer.start_height, 800_000);
    }

    #[test]
    fn test_peer_manager_update_nonexistent() {
        let pm = PeerManager::new(125, 10);
        // Should not panic.
        pm.update_peer(999, |peer| {
            peer.state = PeerState::Ready;
        });
    }

    #[test]
    fn test_peer_manager_can_accept_inbound() {
        let pm = PeerManager::new(2, 10);
        assert!(pm.can_accept_inbound());

        pm.add_peer(test_addr(8333), true);
        assert!(pm.can_accept_inbound());

        pm.add_peer(test_addr(8334), true);
        assert!(!pm.can_accept_inbound());
    }

    #[test]
    fn test_peer_manager_can_connect_outbound() {
        let pm = PeerManager::new(125, 2);
        assert!(pm.can_connect_outbound());

        pm.add_peer(test_addr(8333), false);
        assert!(pm.can_connect_outbound());

        pm.add_peer(test_addr(8334), false);
        assert!(!pm.can_connect_outbound());
    }

    #[test]
    fn test_peer_manager_mixed_add_remove() {
        let pm = PeerManager::new(125, 10);
        let id1 = pm.add_peer(test_addr(8333), true);
        let id2 = pm.add_peer(test_addr(8334), false);
        let id3 = pm.add_peer(test_addr(8335), true);

        assert_eq!(pm.peer_count(), 3);
        assert_eq!(pm.inbound_count(), 2);
        assert_eq!(pm.outbound_count(), 1);

        pm.remove_peer(id1);
        assert_eq!(pm.peer_count(), 2);
        assert_eq!(pm.inbound_count(), 1);
        assert_eq!(pm.outbound_count(), 1);

        pm.remove_peer(id2);
        assert_eq!(pm.peer_count(), 1);
        assert_eq!(pm.inbound_count(), 1);
        assert_eq!(pm.outbound_count(), 0);

        // id3 should still exist.
        assert!(pm.get_peer(id3).is_some());
    }

    #[test]
    fn test_peer_manager_get_nonexistent() {
        let pm = PeerManager::new(125, 10);
        assert!(pm.get_peer(42).is_none());
    }

    #[test]
    fn test_peer_clone() {
        let peer = Peer::new(1, test_addr(8333), false);
        let cloned = peer.clone();
        assert_eq!(cloned.id, peer.id);
        assert_eq!(cloned.addr, peer.addr);
        assert_eq!(cloned.state, peer.state);
    }
}
