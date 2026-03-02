//! TCP connection management for the Bitcoin P2P network.
//!
//! Maps to: parts of src/net.cpp (CConnman)
//!
//! Handles message framing, serialization over the wire, and connection
//! lifecycle (listen, connect, handshake, message loop, shutdown).
//!
//! The main entry point is `ConnManager`, which owns a TCP listener task
//! and spawns per-peer tasks that read/write Bitcoin protocol messages.

use crate::peer::{PeerManager, PeerState};
use crate::protocol::{
    InvType, InvVect, MessageHeader, NetAddress, NetMessage, NetworkMagic, ServiceFlags,
    VersionMessage, MAX_PAYLOAD_SIZE, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION,
    WTXID_RELAY_VERSION,
};
use qubitcoin_primitives::BlockHash;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

// ---------------------------------------------------------------------------
// ConnectionEvent
// ---------------------------------------------------------------------------

/// Events produced by the connection layer and consumed by higher-level code
/// (e.g. [`NetProcessor`](crate::net_processing::NetProcessor)).
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// A new inbound connection has been accepted.
    NewInbound {
        /// Unique identifier assigned to this peer.
        peer_id: u64,
        /// Remote socket address of the connecting peer.
        addr: SocketAddr,
    },
    /// An outbound connection has been established.
    NewOutbound {
        /// Unique identifier assigned to this peer.
        peer_id: u64,
        /// Remote socket address we connected to.
        addr: SocketAddr,
    },
    /// A fully parsed message was received from a peer.
    MessageReceived {
        /// Identifier of the peer that sent the message.
        peer_id: u64,
        /// The deserialized P2P protocol message.
        message: NetMessage,
    },
    /// A peer has disconnected (or been disconnected).
    Disconnected {
        /// Identifier of the disconnected peer.
        peer_id: u64,
        /// Human-readable reason for the disconnection.
        reason: String,
    },
    /// The version/verack handshake completed successfully.
    HandshakeComplete {
        /// Identifier of the peer whose handshake completed.
        peer_id: u64,
    },
}

// ---------------------------------------------------------------------------
// ConnConfig
// ---------------------------------------------------------------------------

/// Configuration for the connection manager.
#[derive(Debug, Clone)]
pub struct ConnConfig {
    /// Address to bind the TCP listener to.
    pub listen_addr: SocketAddr,
    /// Network magic bytes (mainnet, testnet, etc.).
    pub magic: NetworkMagic,
    /// Maximum number of inbound connections to accept.
    pub max_inbound: usize,
    /// Maximum number of outbound connections to maintain.
    pub max_outbound: usize,
    /// Services we advertise in our version message.
    pub our_services: ServiceFlags,
    /// User-agent string sent in version messages.
    pub user_agent: String,
    /// Our best known block height, sent in version messages.
    pub best_height: i32,
}

impl Default for ConnConfig {
    fn default() -> Self {
        ConnConfig {
            listen_addr: "0.0.0.0:8333".parse().unwrap(),
            magic: NetworkMagic::MAINNET,
            max_inbound: 125,
            max_outbound: 10,
            our_services: ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
            user_agent: "/Qubitcoin:0.1.0/".to_string(),
            best_height: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnManager
// ---------------------------------------------------------------------------

/// The connection manager: owns all TCP I/O and produces [`ConnectionEvent`]s.
///
/// Usage:
/// ```ignore
/// let mut cm = ConnManager::new(ConnConfig::default());
/// let events = cm.take_events().unwrap();
/// cm.start_listening().await?;
/// cm.connect_to("1.2.3.4:8333".parse()?).await?;
/// ```
pub struct ConnManager {
    config: ConnConfig,
    peer_manager: Arc<PeerManager>,
    event_tx: mpsc::UnboundedSender<ConnectionEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<ConnectionEvent>>,
    shutdown_tx: broadcast::Sender<()>,
    /// Per-peer send channels for outbound messages.
    peer_senders: Arc<parking_lot::RwLock<HashMap<u64, mpsc::UnboundedSender<(String, Vec<u8>)>>>>,
    /// Our local nonce, used for self-connection detection.
    local_nonce: u64,
}

impl ConnManager {
    /// Create a new connection manager with the given configuration.
    pub fn new(config: ConnConfig) -> Self {
        let peer_manager = Arc::new(PeerManager::new(config.max_inbound, config.max_outbound));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _) = broadcast::channel(1);
        let local_nonce = rand::random::<u64>();

        ConnManager {
            config,
            peer_manager,
            event_tx,
            event_rx: Some(event_rx),
            shutdown_tx,
            peer_senders: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            local_nonce,
        }
    }

    /// Take the event receiver (can only be called once).
    ///
    /// The caller should drain this channel to process connection events.
    /// Returns `None` if already taken.
    pub fn take_events(&mut self) -> Option<mpsc::UnboundedReceiver<ConnectionEvent>> {
        self.event_rx.take()
    }

    /// Get a reference to the shared peer manager.
    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &ConnConfig {
        &self.config
    }

    /// Start listening for inbound connections.
    ///
    /// Spawns a background task that accepts TCP connections and spawns
    /// per-peer handler tasks. Returns immediately after binding.
    pub async fn start_listening(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let peer_manager = self.peer_manager.clone();
        let event_tx = self.event_tx.clone();
        let magic = self.config.magic;
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let peer_senders = self.peer_senders.clone();
        let local_nonce = self.local_nonce;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                if !peer_manager.can_accept_inbound() {
                                    // At capacity -- drop the connection.
                                    drop(stream);
                                    continue;
                                }
                                let peer_id = peer_manager.add_peer(addr, true);
                                let _ = event_tx.send(ConnectionEvent::NewInbound {
                                    peer_id,
                                    addr,
                                });

                                let pm = peer_manager.clone();
                                let etx = event_tx.clone();
                                let cfg = config.clone();
                                let mut srx = shutdown_rx.resubscribe();
                                let ps = peer_senders.clone();

                                tokio::spawn(async move {
                                    handle_connection(
                                        stream, peer_id, true, magic, pm, etx, cfg, &mut srx, ps, local_nonce,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "accept error");
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Initiate an outbound connection to `addr`.
    ///
    /// Returns the peer ID on success. The handshake happens asynchronously
    /// in a spawned task; watch the event channel for `HandshakeComplete`.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<u64, Box<dyn std::error::Error>> {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| format!("connect timeout to {}", addr))??;
        let peer_id = self.peer_manager.add_peer(addr, false);
        let _ = self
            .event_tx
            .send(ConnectionEvent::NewOutbound { peer_id, addr });

        let pm = self.peer_manager.clone();
        let etx = self.event_tx.clone();
        let magic = self.config.magic;
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let ps = self.peer_senders.clone();
        let local_nonce = self.local_nonce;

        tokio::spawn(async move {
            handle_connection(
                stream,
                peer_id,
                false,
                magic,
                pm,
                etx,
                config,
                &mut shutdown_rx,
                ps,
                local_nonce,
            )
            .await;
        });

        Ok(peer_id)
    }

    /// Send a message to a specific peer by peer_id.
    ///
    /// Returns `true` if the message was queued successfully, `false` if the
    /// peer is not connected or the channel is closed.
    pub fn send_to_peer(&self, peer_id: u64, command: &str, payload: Vec<u8>) -> bool {
        let senders = self.peer_senders.read();
        if let Some(sender) = senders.get(&peer_id) {
            sender.send((command.to_string(), payload)).is_ok()
        } else {
            false
        }
    }

    /// Disconnect a specific peer by dropping its send channel.
    ///
    /// When the sender is dropped the per-peer writer task exits, which
    /// in turn closes the TCP connection.
    pub fn disconnect_peer(&self, peer_id: u64) {
        self.peer_senders.write().remove(&peer_id);
    }

    /// Shutdown all connections.
    ///
    /// Sends a shutdown signal to the listener task and all per-peer tasks.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Main per-peer loop: performs the version handshake, then reads messages
/// until the connection closes or shutdown is signalled.
///
/// Uses split read/write halves: a dedicated writer task drains the outbound
/// channel while the reader loop processes inbound messages.  This prevents
/// the previous `select!` race where a steady stream of inbound data could
/// starve outbound sends (e.g. `getheaders` never being written because
/// Bitcoin Core's post-handshake messages kept the read branch winning).
async fn handle_connection(
    stream: TcpStream,
    peer_id: u64,
    inbound: bool,
    magic: NetworkMagic,
    peer_manager: Arc<PeerManager>,
    event_tx: mpsc::UnboundedSender<ConnectionEvent>,
    config: ConnConfig,
    shutdown_rx: &mut broadcast::Receiver<()>,
    peer_senders: Arc<parking_lot::RwLock<HashMap<u64, mpsc::UnboundedSender<(String, Vec<u8>)>>>>,
    local_nonce: u64,
) {
    peer_manager.update_peer(peer_id, |p| p.state = PeerState::Connected);

    // Split the TCP stream so reads and writes happen independently.
    let (reader, writer) = tokio::io::split(stream);

    // The "write_tx" channel is used by BOTH:
    //   1. The inline handshake logic (version, verack, pong) in the read loop
    //   2. External callers via ConnManager::send_to_peer -> outbound_tx
    //
    // The writer task drains write_tx and serialises messages onto the wire.
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();

    // Register the channel so ConnManager::send_to_peer reaches us.
    {
        let mut senders = peer_senders.write();
        senders.insert(peer_id, write_tx.clone());
    }

    // ── Writer task ────────────────────────────────────────────────
    let writer_magic = magic;
    let writer_handle = tokio::spawn(async move {
        let mut writer = writer;
        while let Some((command, payload)) = write_rx.recv().await {
            let header = MessageHeader::new(writer_magic, &command, &payload);
            if let Err(e) = AsyncWriteExt::write_all(&mut writer, &header.serialize()).await {
                tracing::debug!(peer_id = peer_id, error = %e, "writer: header send error");
                return;
            }
            if let Err(e) = AsyncWriteExt::write_all(&mut writer, &payload).await {
                tracing::debug!(peer_id = peer_id, error = %e, "writer: payload send error");
                return;
            }
            if let Err(e) = AsyncWriteExt::flush(&mut writer).await {
                tracing::debug!(peer_id = peer_id, error = %e, "writer: flush error");
                return;
            }
        }
        // Channel closed – connection is shutting down.
    });

    // ── Helper closure to queue an outbound message ────────────────
    let enqueue =
        |cmd: &str, payload: Vec<u8>| -> bool { write_tx.send((cmd.to_string(), payload)).is_ok() };

    // ── Outbound connections send version first ────────────────────
    if !inbound {
        let addr = peer_manager
            .get_peer(peer_id)
            .map(|p| p.addr)
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let version_msg = build_version_message_with_nonce(&config, addr, local_nonce);
        if !enqueue("version", serialize_version(&version_msg)) {
            peer_senders.write().remove(&peer_id);
            cleanup_peer(
                peer_id,
                &peer_manager,
                &event_tx,
                "channel closed early".to_string(),
            );
            writer_handle.abort();
            return;
        }
    }

    peer_manager.update_peer(peer_id, |p| p.state = PeerState::Handshaking);

    // ── Read loop ──────────────────────────────────────────────────
    let mut reader = reader;
    loop {
        let mut header_buf = [0u8; 24];

        tokio::select! {
            result = AsyncReadExt::read_exact(&mut reader, &mut header_buf) => {
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        peer_senders.write().remove(&peer_id);
                        cleanup_peer(
                            peer_id,
                            &peer_manager,
                            &event_tx,
                            format!("read error: {}", e),
                        );
                        drop(write_tx);
                        writer_handle.abort();
                        return;
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                peer_senders.write().remove(&peer_id);
                cleanup_peer(peer_id, &peer_manager, &event_tx, "shutdown".to_string());
                drop(write_tx);
                writer_handle.abort();
                return;
            }
        }

        let header = MessageHeader::deserialize(&header_buf);

        // Verify magic bytes.
        if header.magic != magic {
            tracing::debug!(
                peer_id = peer_id,
                expected = ?magic.0,
                got = ?header.magic.0,
                "bad magic"
            );
            peer_senders.write().remove(&peer_id);
            cleanup_peer(peer_id, &peer_manager, &event_tx, "bad magic".to_string());
            drop(write_tx);
            writer_handle.abort();
            return;
        }

        // Enforce MAX_PAYLOAD_SIZE (4 MB, matching Bitcoin Core).
        if header.payload_size > MAX_PAYLOAD_SIZE {
            peer_senders.write().remove(&peer_id);
            cleanup_peer(
                peer_id,
                &peer_manager,
                &event_tx,
                "payload too large".to_string(),
            );
            drop(write_tx);
            writer_handle.abort();
            return;
        }

        // Read the payload.
        let mut payload = vec![0u8; header.payload_size as usize];
        if !payload.is_empty() {
            match AsyncReadExt::read_exact(&mut reader, &mut payload).await {
                Ok(_) => {}
                Err(e) => {
                    peer_senders.write().remove(&peer_id);
                    cleanup_peer(
                        peer_id,
                        &peer_manager,
                        &event_tx,
                        format!("payload read error: {}", e),
                    );
                    drop(write_tx);
                    writer_handle.abort();
                    return;
                }
            }
        }

        // Verify checksum.
        if !header.verify_checksum(&payload) {
            peer_senders.write().remove(&peer_id);
            cleanup_peer(
                peer_id,
                &peer_manager,
                &event_tx,
                "bad checksum".to_string(),
            );
            drop(write_tx);
            writer_handle.abort();
            return;
        }

        // Parse the message.
        let command = header.command_str().to_string();
        tracing::trace!(peer_id = peer_id, command = %command, size = payload.len(), "recv");
        let message = parse_message(&command, &payload);

        // Update peer statistics.
        peer_manager.update_peer(peer_id, |p| {
            p.bytes_recv += 24 + payload.len() as u64;
            p.update_last_recv();
        });

        // Handle handshake messages inline – responses go through the writer.
        match &message {
            NetMessage::Version(ver) => {
                // Check minimum protocol version.
                if ver.version < MIN_PEER_PROTO_VERSION {
                    tracing::info!(
                        peer_id = peer_id,
                        version = ver.version,
                        min = MIN_PEER_PROTO_VERSION,
                        "peer version too old, disconnecting"
                    );
                    peer_senders.write().remove(&peer_id);
                    cleanup_peer(
                        peer_id,
                        &peer_manager,
                        &event_tx,
                        "obsolete version".to_string(),
                    );
                    drop(write_tx);
                    writer_handle.abort();
                    return;
                }

                // Detect self-connection via nonce.
                if ver.nonce == local_nonce && ver.nonce != 0 {
                    tracing::info!(peer_id = peer_id, "detected self-connection, disconnecting");
                    peer_senders.write().remove(&peer_id);
                    cleanup_peer(
                        peer_id,
                        &peer_manager,
                        &event_tx,
                        "self-connection".to_string(),
                    );
                    drop(write_tx);
                    writer_handle.abort();
                    return;
                }

                peer_manager.update_peer(peer_id, |p| {
                    p.version = ver.version;
                    p.services = ver.services;
                    p.user_agent = ver.user_agent.clone();
                    p.start_height = ver.start_height;
                    p.relay = ver.relay;
                });

                // Inbound: reply with our own version first.
                if inbound {
                    let addr = peer_manager
                        .get_peer(peer_id)
                        .map(|p| p.addr)
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    let version_msg = build_version_message_with_nonce(&config, addr, local_nonce);
                    enqueue("version", serialize_version(&version_msg));
                }

                // Send feature negotiation messages BEFORE verack (BIP 339, BIP 155).
                // These MUST be sent between VERSION and VERACK.
                // Use greatest-common-version (min of our version and peer's version)
                // for feature negotiation, matching Bitcoin Core.
                let common_version = std::cmp::min(PROTOCOL_VERSION, ver.version);
                if common_version >= WTXID_RELAY_VERSION {
                    // BIP 339: Announce wtxid-based transaction relay.
                    enqueue("wtxidrelay", vec![]);
                }
                // BIP 155: Announce support for addrv2 messages.
                enqueue("sendaddrv2", vec![]);

                // Now send verack to complete the handshake.
                enqueue("verack", vec![]);
            }
            NetMessage::Verack => {
                peer_manager.update_peer(peer_id, |p| p.state = PeerState::Ready);
                let _ = event_tx.send(ConnectionEvent::HandshakeComplete { peer_id });
            }
            NetMessage::Ping(nonce) => {
                enqueue("pong", nonce.to_le_bytes().to_vec());
            }
            _ => {}
        }

        // Forward every message to the event channel.
        let _ = event_tx.send(ConnectionEvent::MessageReceived { peer_id, message });
    }
}

/// Transition a peer to Disconnected, remove it from the manager, and emit
/// a disconnect event.
fn cleanup_peer(
    peer_id: u64,
    pm: &PeerManager,
    tx: &mpsc::UnboundedSender<ConnectionEvent>,
    reason: String,
) {
    pm.update_peer(peer_id, |p| p.state = PeerState::Disconnected);
    pm.remove_peer(peer_id);
    let _ = tx.send(ConnectionEvent::Disconnected { peer_id, reason });
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a [`VersionMessage`] into its wire-format byte representation.
///
/// Layout (86 + user_agent.len() bytes):
///   version:      4 bytes  (i32 LE)
///   services:     8 bytes  (u64 LE)
///   timestamp:    8 bytes  (i64 LE)
///   addr_recv:   26 bytes  (services 8 + ipv6 16 + port 2 BE)
///   addr_from:   26 bytes  (services 8 + ipv6 16 + port 2 BE)
///   nonce:        8 bytes  (u64 LE)
///   user_agent:   varint len + bytes
///   start_height: 4 bytes  (i32 LE)
///   relay:        1 byte   (bool)
pub fn serialize_version(msg: &VersionMessage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(86 + msg.user_agent.len());

    // version
    buf.extend_from_slice(&(msg.version as i32).to_le_bytes());
    // services
    buf.extend_from_slice(&msg.services.bits().to_le_bytes());
    // timestamp
    buf.extend_from_slice(&msg.timestamp.to_le_bytes());
    // addr_recv (no timestamp prefix in version message)
    serialize_net_address_into(&msg.addr_recv, &mut buf);
    // addr_from
    serialize_net_address_into(&msg.addr_from, &mut buf);
    // nonce
    buf.extend_from_slice(&msg.nonce.to_le_bytes());
    // user_agent (varint length + bytes)
    write_varint(msg.user_agent.len() as u64, &mut buf);
    buf.extend_from_slice(msg.user_agent.as_bytes());
    // start_height
    buf.extend_from_slice(&msg.start_height.to_le_bytes());
    // relay
    buf.push(if msg.relay { 1 } else { 0 });

    buf
}

/// Deserialize a [`VersionMessage`] from its wire-format bytes.
///
/// Returns `None` if the payload is too short or malformed.
pub fn deserialize_version(data: &[u8]) -> Option<VersionMessage> {
    if data.len() < 46 {
        // Minimum: 4+8+8+26 = 46 bytes before user_agent.
        return None;
    }

    let version = i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u32;
    let services_bits = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let services = ServiceFlags::from_bits_truncate(services_bits);
    let timestamp = i64::from_le_bytes(data[12..20].try_into().ok()?);
    let addr_recv = deserialize_net_address(&data[20..46])?;

    // addr_from starts at 46
    if data.len() < 72 {
        return None;
    }
    let addr_from = deserialize_net_address(&data[46..72])?;

    // nonce at 72
    if data.len() < 80 {
        return None;
    }
    let nonce = u64::from_le_bytes(data[72..80].try_into().ok()?);

    // user_agent at 80
    let (ua_len, varint_size) = read_varint(&data[80..])?;
    let ua_start = 80 + varint_size;
    let ua_end = ua_start + ua_len as usize;
    if data.len() < ua_end {
        return None;
    }
    let user_agent = String::from_utf8_lossy(&data[ua_start..ua_end]).to_string();

    // start_height
    let sh_start = ua_end;
    if data.len() < sh_start + 4 {
        return None;
    }
    let start_height = i32::from_le_bytes(data[sh_start..sh_start + 4].try_into().ok()?);

    // relay (optional -- defaults to true if absent)
    let relay = if data.len() > sh_start + 4 {
        data[sh_start + 4] != 0
    } else {
        true
    };

    Some(VersionMessage {
        version,
        services,
        timestamp,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}

/// Serialize a [`NetAddress`] (26 bytes: 8 services + 16 ipv6 + 2 port).
fn serialize_net_address_into(addr: &NetAddress, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&addr.services.bits().to_le_bytes());
    // IPv4-mapped IPv6 address
    match addr.ip {
        std::net::IpAddr::V4(v4) => {
            buf.extend_from_slice(&[0u8; 10]);
            buf.extend_from_slice(&[0xff, 0xff]);
            buf.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            buf.extend_from_slice(&v6.octets());
        }
    }
    // Port is big-endian on the wire.
    buf.extend_from_slice(&addr.port.to_be_bytes());
}

/// Deserialize a [`NetAddress`] from 26 bytes.
fn deserialize_net_address(data: &[u8]) -> Option<NetAddress> {
    if data.len() < 26 {
        return None;
    }
    let services =
        ServiceFlags::from_bits_truncate(u64::from_le_bytes(data[0..8].try_into().ok()?));
    let ip_bytes: [u8; 16] = data[8..24].try_into().ok()?;
    let ip = if ip_bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        // IPv4-mapped
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[12],
            ip_bytes[13],
            ip_bytes[14],
            ip_bytes[15],
        ))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes))
    };
    let port = u16::from_be_bytes([data[24], data[25]]);

    Some(NetAddress::new(services, ip, port))
}

/// Write a Bitcoin-style variable-length integer.
pub fn write_varint(val: u64, buf: &mut Vec<u8>) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a Bitcoin-style variable-length integer.
/// Returns `(value, bytes_consumed)`.
pub fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0xff => {
            if data.len() < 9 {
                return None;
            }
            let val = u64::from_le_bytes(data[1..9].try_into().ok()?);
            Some((val, 9))
        }
        0xfe => {
            if data.len() < 5 {
                return None;
            }
            let val = u32::from_le_bytes(data[1..5].try_into().ok()?) as u64;
            Some((val, 5))
        }
        0xfd => {
            if data.len() < 3 {
                return None;
            }
            let val = u16::from_le_bytes(data[1..3].try_into().ok()?) as u64;
            Some((val, 3))
        }
        v => Some((v as u64, 1)),
    }
}

/// Parse a raw payload into a [`NetMessage`] based on the command string.
pub fn parse_message(command: &str, payload: &[u8]) -> NetMessage {
    match command {
        "version" => {
            if let Some(ver) = deserialize_version(payload) {
                NetMessage::Version(ver)
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "verack" => NetMessage::Verack,
        "ping" => {
            if payload.len() >= 8 {
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap());
                NetMessage::Ping(nonce)
            } else {
                NetMessage::Ping(0)
            }
        }
        "pong" => {
            if payload.len() >= 8 {
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap());
                NetMessage::Pong(nonce)
            } else {
                NetMessage::Pong(0)
            }
        }
        "getaddr" => NetMessage::GetAddr,
        "sendheaders" => NetMessage::SendHeaders,
        "wtxidrelay" => NetMessage::WtxidRelay,
        "sendaddrv2" => NetMessage::SendAddrV2,
        "filterclear" => NetMessage::FilterClear,
        "mempool" => NetMessage::MemPool,
        "sendtxrcncl" => {
            if payload.len() >= 12 {
                let version = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let salt = u64::from_le_bytes(payload[4..12].try_into().unwrap());
                NetMessage::SendTxRcncl { version, salt }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "feefilter" => {
            if payload.len() >= 8 {
                let fee = i64::from_le_bytes(payload[..8].try_into().unwrap());
                NetMessage::FeeFilter(fee)
            } else {
                NetMessage::FeeFilter(0)
            }
        }
        "inv" => NetMessage::Inv(parse_inv_list(payload)),
        "getdata" => NetMessage::GetData(parse_inv_list(payload)),
        "notfound" => NetMessage::NotFound(parse_inv_list(payload)),
        "block" => NetMessage::Block(payload.to_vec()),
        "tx" => NetMessage::Tx(payload.to_vec()),
        "headers" => {
            let headers = parse_headers_payload(payload);
            NetMessage::Headers(headers)
        }
        "sendcmpct" => {
            if payload.len() >= 9 {
                let announce = payload[0] != 0;
                let version = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                NetMessage::SendCmpct { announce, version }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "cmpctblock" => NetMessage::CmpctBlock(payload.to_vec()),
        "getblocktxn" => NetMessage::GetBlockTxn(payload.to_vec()),
        "blocktxn" => NetMessage::BlockTxn(payload.to_vec()),
        "filterload" => NetMessage::FilterLoad(payload.to_vec()),
        "filteradd" => NetMessage::FilterAdd(payload.to_vec()),
        "merkleblock" => NetMessage::MerkleBlock(payload.to_vec()),
        "addrv2" => NetMessage::AddrV2(payload.to_vec()),
        "cfheaders" => NetMessage::CFHeaders(payload.to_vec()),
        "cfilter" => NetMessage::CFilter(payload.to_vec()),
        "cfcheckpt" => NetMessage::CFCheckpt(payload.to_vec()),
        "getheaders" | "getblocks" => {
            // Parse getblocks/getheaders: version(4) + varint count + hashes(32 each) + hash_stop(32)
            if payload.len() < 4 {
                return NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                };
            }
            let version = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            let (count, offset) = match read_varint(&payload[4..]) {
                Some(v) => v,
                None => {
                    return NetMessage::Unknown {
                        command: command.to_string(),
                        payload: payload.to_vec(),
                    };
                }
            };
            let mut pos = 4 + offset;
            let mut locators = Vec::new();
            for _ in 0..count {
                if pos + 32 > payload.len() {
                    break;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[pos..pos + 32]);
                locators.push(BlockHash::from_bytes(h));
                pos += 32;
            }
            let hash_stop = if pos + 32 <= payload.len() {
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[pos..pos + 32]);
                BlockHash::from_bytes(h)
            } else {
                BlockHash::ZERO
            };
            if command == "getheaders" {
                NetMessage::GetHeaders {
                    version,
                    locators,
                    hash_stop,
                }
            } else {
                NetMessage::GetBlocks {
                    version,
                    locators,
                    hash_stop,
                }
            }
        }
        "getcfheaders" => {
            if payload.len() >= 37 {
                let filter_type = payload[0];
                let start_height = u32::from_le_bytes(payload[1..5].try_into().unwrap());
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[5..37]);
                NetMessage::GetCFHeaders {
                    filter_type,
                    start_height,
                    stop_hash: BlockHash::from_bytes(h),
                }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "getcfilters" => {
            if payload.len() >= 37 {
                let filter_type = payload[0];
                let start_height = u32::from_le_bytes(payload[1..5].try_into().unwrap());
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[5..37]);
                NetMessage::GetCFilters {
                    filter_type,
                    start_height,
                    stop_hash: BlockHash::from_bytes(h),
                }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "getcfcheckpt" => {
            if payload.len() >= 33 {
                let filter_type = payload[0];
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[1..33]);
                NetMessage::GetCFCheckpt {
                    filter_type,
                    stop_hash: BlockHash::from_bytes(h),
                }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        "addr" => {
            // Parse addr: varint count + (timestamp(4) + net_address(26)) each
            let mut addrs = Vec::new();
            let (count, offset) = match read_varint(payload) {
                Some(v) => v,
                None => return NetMessage::Addr(addrs),
            };
            let mut pos = offset;
            for _ in 0..count {
                if pos + 30 > payload.len() {
                    break;
                }
                let timestamp = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
                if let Some(addr) = deserialize_net_address(&payload[pos + 4..pos + 30]) {
                    addrs.push((timestamp, addr));
                }
                pos += 30;
            }
            NetMessage::Addr(addrs)
        }
        "reject" => {
            // Parse reject: varint message_len + message + code(1) + varint reason_len + reason
            if let Some((msg_len, offset)) = read_varint(payload) {
                let msg_start = offset;
                let msg_end = msg_start + msg_len as usize;
                if msg_end < payload.len() {
                    let message = String::from_utf8_lossy(&payload[msg_start..msg_end]).to_string();
                    let code = payload[msg_end];
                    let reason = if msg_end + 1 < payload.len() {
                        if let Some((reason_len, r_offset)) = read_varint(&payload[msg_end + 1..]) {
                            let r_start = msg_end + 1 + r_offset;
                            let r_end = (r_start + reason_len as usize).min(payload.len());
                            String::from_utf8_lossy(&payload[r_start..r_end]).to_string()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    NetMessage::Reject {
                        message,
                        code,
                        reason,
                    }
                } else {
                    NetMessage::Unknown {
                        command: command.to_string(),
                        payload: payload.to_vec(),
                    }
                }
            } else {
                NetMessage::Unknown {
                    command: command.to_string(),
                    payload: payload.to_vec(),
                }
            }
        }
        _ => NetMessage::Unknown {
            command: command.to_string(),
            payload: payload.to_vec(),
        },
    }
}

/// Parse an inv / getdata / notfound payload into a vector of [`InvVect`].
fn parse_inv_list(data: &[u8]) -> Vec<InvVect> {
    let mut result = Vec::new();
    let (count, offset) = match read_varint(data) {
        Some(v) => v,
        None => return result,
    };
    let mut pos = offset;
    for _ in 0..count {
        if pos + 36 > data.len() {
            break;
        }
        let type_val = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let inv_type = InvType::from_u32(type_val).unwrap_or(InvType::Error);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[pos + 4..pos + 36]);
        let hash = qubitcoin_primitives::Uint256::from_bytes(hash_bytes);
        result.push(InvVect::new(inv_type, hash));
        pos += 36;
    }
    result
}

/// Parse a headers payload: varint count followed by 81-byte header entries.
fn parse_headers_payload(data: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let (count, offset) = match read_varint(data) {
        Some(v) => v,
        None => return result,
    };
    let mut pos = offset;
    for _ in 0..count {
        // Each header is 80 bytes + 1 byte varint txn_count (always 0).
        if pos + 81 > data.len() {
            break;
        }
        result.push(data[pos..pos + 80].to_vec());
        pos += 81;
    }
    result
}

/// Serialize a [`NetMessage`] into its wire-format payload bytes.
pub fn serialize_message(msg: &NetMessage) -> Vec<u8> {
    match msg {
        NetMessage::Version(ver) => serialize_version(ver),
        NetMessage::Verack => Vec::new(),
        NetMessage::Ping(nonce) => nonce.to_le_bytes().to_vec(),
        NetMessage::Pong(nonce) => nonce.to_le_bytes().to_vec(),
        NetMessage::GetAddr => Vec::new(),
        NetMessage::SendHeaders => Vec::new(),
        NetMessage::WtxidRelay => Vec::new(),
        NetMessage::SendAddrV2 => Vec::new(),
        NetMessage::FilterClear => Vec::new(),
        NetMessage::MemPool => Vec::new(),
        NetMessage::SendTxRcncl { version, salt } => {
            let mut buf = Vec::with_capacity(12);
            buf.extend_from_slice(&version.to_le_bytes());
            buf.extend_from_slice(&salt.to_le_bytes());
            buf
        }
        NetMessage::FeeFilter(fee) => fee.to_le_bytes().to_vec(),
        NetMessage::Inv(inv) => serialize_inv_list(inv),
        NetMessage::GetData(inv) => serialize_inv_list(inv),
        NetMessage::NotFound(inv) => serialize_inv_list(inv),
        NetMessage::Block(data) => data.clone(),
        NetMessage::Tx(data) => data.clone(),
        NetMessage::Headers(headers) => serialize_headers(headers),
        NetMessage::SendCmpct { announce, version } => {
            let mut buf = Vec::with_capacity(9);
            buf.push(if *announce { 1 } else { 0 });
            buf.extend_from_slice(&version.to_le_bytes());
            buf
        }
        NetMessage::CmpctBlock(data) => data.clone(),
        NetMessage::GetBlockTxn(data) => data.clone(),
        NetMessage::BlockTxn(data) => data.clone(),
        NetMessage::FilterLoad(data) => data.clone(),
        NetMessage::FilterAdd(data) => data.clone(),
        NetMessage::MerkleBlock(data) => data.clone(),
        NetMessage::AddrV2(data) => data.clone(),
        NetMessage::CFHeaders(data) => data.clone(),
        NetMessage::CFilter(data) => data.clone(),
        NetMessage::CFCheckpt(data) => data.clone(),
        NetMessage::GetHeaders {
            version,
            locators,
            hash_stop,
        }
        | NetMessage::GetBlocks {
            version,
            locators,
            hash_stop,
        } => {
            let mut buf = Vec::new();
            // version (4 bytes LE)
            buf.extend_from_slice(&(*version as u32).to_le_bytes());
            // hash count (varint)
            write_varint(locators.len() as u64, &mut buf);
            // locator hashes (32 bytes each)
            for hash in locators {
                buf.extend_from_slice(hash.as_bytes());
            }
            // hash_stop (32 bytes)
            buf.extend_from_slice(hash_stop.as_bytes());
            buf
        }
        NetMessage::Reject {
            message,
            code,
            reason,
        } => {
            let mut buf = Vec::new();
            write_varint(message.len() as u64, &mut buf);
            buf.extend_from_slice(message.as_bytes());
            buf.push(*code);
            write_varint(reason.len() as u64, &mut buf);
            buf.extend_from_slice(reason.as_bytes());
            buf
        }
        NetMessage::Addr(addrs) => serialize_addr_list(addrs),
        NetMessage::GetCFHeaders {
            filter_type,
            start_height,
            stop_hash,
        } => {
            let mut buf = Vec::with_capacity(37);
            buf.push(*filter_type);
            buf.extend_from_slice(&start_height.to_le_bytes());
            buf.extend_from_slice(stop_hash.as_bytes());
            buf
        }
        NetMessage::GetCFilters {
            filter_type,
            start_height,
            stop_hash,
        } => {
            let mut buf = Vec::with_capacity(37);
            buf.push(*filter_type);
            buf.extend_from_slice(&start_height.to_le_bytes());
            buf.extend_from_slice(stop_hash.as_bytes());
            buf
        }
        NetMessage::GetCFCheckpt {
            filter_type,
            stop_hash,
        } => {
            let mut buf = Vec::with_capacity(33);
            buf.push(*filter_type);
            buf.extend_from_slice(stop_hash.as_bytes());
            buf
        }
        NetMessage::Unknown { payload, .. } => payload.clone(),
    }
}

/// Serialize a list of [`InvVect`] into wire format.
fn serialize_inv_list(inv: &[InvVect]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + inv.len() * 36);
    write_varint(inv.len() as u64, &mut buf);
    for item in inv {
        buf.extend_from_slice(&item.inv_type.to_u32().to_le_bytes());
        buf.extend_from_slice(item.hash.data());
    }
    buf
}

/// Serialize an addr list into wire format.
fn serialize_addr_list(addrs: &[(u32, NetAddress)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + addrs.len() * 30);
    write_varint(addrs.len() as u64, &mut buf);
    for (timestamp, addr) in addrs {
        buf.extend_from_slice(&timestamp.to_le_bytes());
        serialize_net_address_into(addr, &mut buf);
    }
    buf
}

/// Serialize block headers into wire format.
fn serialize_headers(headers: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + headers.len() * 81);
    write_varint(headers.len() as u64, &mut buf);
    for hdr in headers {
        buf.extend_from_slice(hdr);
        // txn_count = 0
        buf.push(0);
    }
    buf
}

/// Build a [`VersionMessage`] to send to a remote peer.
///
/// If `nonce` is provided, it is used directly (for self-connection detection).
/// Otherwise a random nonce is generated.
pub fn build_version_message(config: &ConnConfig, remote_addr: SocketAddr) -> VersionMessage {
    build_version_message_with_nonce(config, remote_addr, rand::random::<u64>())
}

/// Build a [`VersionMessage`] with a specific nonce.
pub fn build_version_message_with_nonce(
    config: &ConnConfig,
    remote_addr: SocketAddr,
    nonce: u64,
) -> VersionMessage {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    VersionMessage {
        version: PROTOCOL_VERSION,
        services: config.our_services,
        timestamp,
        addr_recv: NetAddress::new(
            ServiceFlags::NODE_NONE,
            remote_addr.ip(),
            remote_addr.port(),
        ),
        addr_from: NetAddress::new(
            config.our_services,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            config.listen_addr.port(),
        ),
        nonce,
        user_agent: config.user_agent.clone(),
        start_height: config.best_height,
        relay: true,
    }
}

/// Send a raw message (header + payload) over a TCP stream.
pub async fn send_raw_message(
    stream: &mut TcpStream,
    magic: NetworkMagic,
    command: &str,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let header = MessageHeader::new(magic, command, payload);
    stream.write_all(&header.serialize()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // -- ConnConfig tests ---------------------------------------------------

    #[test]
    fn test_conn_config_default() {
        let cfg = ConnConfig::default();
        assert_eq!(
            cfg.listen_addr,
            "0.0.0.0:8333".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.magic, NetworkMagic::MAINNET);
        assert_eq!(cfg.max_inbound, 125);
        assert_eq!(cfg.max_outbound, 10);
        assert!(cfg.our_services.contains(ServiceFlags::NODE_NETWORK));
        assert!(cfg.our_services.contains(ServiceFlags::NODE_WITNESS));
        assert_eq!(cfg.user_agent, "/Qubitcoin:0.1.0/");
        assert_eq!(cfg.best_height, 0);
    }

    #[test]
    fn test_conn_config_custom() {
        let cfg = ConnConfig {
            listen_addr: "127.0.0.1:18333".parse().unwrap(),
            magic: NetworkMagic::TESTNET,
            max_inbound: 50,
            max_outbound: 5,
            our_services: ServiceFlags::NODE_NETWORK,
            user_agent: "/Test:0.0.1/".to_string(),
            best_height: 42,
        };
        assert_eq!(cfg.magic, NetworkMagic::TESTNET);
        assert_eq!(cfg.max_inbound, 50);
        assert_eq!(cfg.best_height, 42);
    }

    // -- ConnManager tests --------------------------------------------------

    #[test]
    fn test_conn_manager_creation() {
        let mut cm = ConnManager::new(ConnConfig::default());
        assert_eq!(cm.peer_manager().peer_count(), 0);
        assert!(cm.take_events().is_some());
        // Second call returns None.
        assert!(cm.take_events().is_none());
    }

    #[test]
    fn test_conn_manager_config_accessible() {
        let cm = ConnManager::new(ConnConfig::default());
        assert_eq!(cm.config().magic, NetworkMagic::MAINNET);
        assert_eq!(cm.config().max_inbound, 125);
    }

    #[test]
    fn test_conn_manager_shutdown_does_not_panic() {
        let cm = ConnManager::new(ConnConfig::default());
        // Shutdown with no active connections should be a no-op.
        cm.shutdown();
    }

    // -- ConnectionEvent tests ----------------------------------------------

    #[test]
    fn test_connection_event_new_inbound() {
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let event = ConnectionEvent::NewInbound { peer_id: 1, addr };
        match event {
            ConnectionEvent::NewInbound { peer_id, addr: a } => {
                assert_eq!(peer_id, 1);
                assert_eq!(a, addr);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_connection_event_new_outbound() {
        let addr: SocketAddr = "5.6.7.8:8333".parse().unwrap();
        let event = ConnectionEvent::NewOutbound { peer_id: 2, addr };
        match event {
            ConnectionEvent::NewOutbound { peer_id, addr: a } => {
                assert_eq!(peer_id, 2);
                assert_eq!(a, addr);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_connection_event_disconnected() {
        let event = ConnectionEvent::Disconnected {
            peer_id: 3,
            reason: "timeout".to_string(),
        };
        match event {
            ConnectionEvent::Disconnected { peer_id, reason } => {
                assert_eq!(peer_id, 3);
                assert_eq!(reason, "timeout");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_connection_event_handshake_complete() {
        let event = ConnectionEvent::HandshakeComplete { peer_id: 4 };
        match event {
            ConnectionEvent::HandshakeComplete { peer_id } => {
                assert_eq!(peer_id, 4);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_connection_event_clone() {
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let event = ConnectionEvent::NewInbound { peer_id: 1, addr };
        let cloned = event.clone();
        match cloned {
            ConnectionEvent::NewInbound { peer_id, .. } => assert_eq!(peer_id, 1),
            _ => panic!("wrong variant"),
        }
    }

    // -- Varint tests -------------------------------------------------------

    #[test]
    fn test_varint_single_byte() {
        let mut buf = Vec::new();
        write_varint(0, &mut buf);
        assert_eq!(buf, vec![0]);

        buf.clear();
        write_varint(252, &mut buf);
        assert_eq!(buf, vec![252]);
    }

    #[test]
    fn test_varint_two_bytes() {
        let mut buf = Vec::new();
        write_varint(253, &mut buf);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[0], 0xfd);

        let (val, size) = read_varint(&buf).unwrap();
        assert_eq!(val, 253);
        assert_eq!(size, 3);
    }

    #[test]
    fn test_varint_four_bytes() {
        let mut buf = Vec::new();
        write_varint(70000, &mut buf);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 0xfe);

        let (val, size) = read_varint(&buf).unwrap();
        assert_eq!(val, 70000);
        assert_eq!(size, 5);
    }

    #[test]
    fn test_varint_eight_bytes() {
        let mut buf = Vec::new();
        let big = 0x1_0000_0000u64;
        write_varint(big, &mut buf);
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0xff);

        let (val, size) = read_varint(&buf).unwrap();
        assert_eq!(val, big);
        assert_eq!(size, 9);
    }

    #[test]
    fn test_varint_roundtrip() {
        for val in [0, 1, 252, 253, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000] {
            let mut buf = Vec::new();
            write_varint(val, &mut buf);
            let (decoded, _) = read_varint(&buf).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_read_varint_empty() {
        assert!(read_varint(&[]).is_none());
    }

    #[test]
    fn test_read_varint_truncated() {
        assert!(read_varint(&[0xfd, 0x01]).is_none()); // needs 3 bytes
        assert!(read_varint(&[0xfe, 0x01, 0x02]).is_none()); // needs 5
        assert!(read_varint(&[0xff, 0x01]).is_none()); // needs 9
    }

    // -- Version serialization tests ----------------------------------------

    fn make_test_version() -> VersionMessage {
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
            timestamp: 1700000000,
            addr_recv: NetAddress::new(
                ServiceFlags::NODE_NETWORK,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                8333,
            ),
            addr_from: NetAddress::new(
                ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                8333,
            ),
            nonce: 0xdeadbeef,
            user_agent: "/QubitCoin:0.1.0/".to_string(),
            start_height: 800_000,
            relay: true,
        }
    }

    #[test]
    fn test_serialize_version_roundtrip() {
        let original = make_test_version();
        let bytes = serialize_version(&original);
        let restored = deserialize_version(&bytes).expect("deserialize should succeed");

        assert_eq!(restored.version, original.version);
        assert_eq!(restored.services, original.services);
        assert_eq!(restored.timestamp, original.timestamp);
        assert_eq!(restored.nonce, original.nonce);
        assert_eq!(restored.user_agent, original.user_agent);
        assert_eq!(restored.start_height, original.start_height);
        assert_eq!(restored.relay, original.relay);
        assert_eq!(restored.addr_recv.port, original.addr_recv.port);
        assert_eq!(restored.addr_from.port, original.addr_from.port);
    }

    #[test]
    fn test_serialize_version_minimum_size() {
        let ver = make_test_version();
        let bytes = serialize_version(&ver);
        // 4 + 8 + 8 + 26 + 26 + 8 + varint(17) + 17 + 4 + 1 = 103
        assert!(
            bytes.len() >= 86,
            "version payload too short: {}",
            bytes.len()
        );
    }

    #[test]
    fn test_serialize_version_fields() {
        let ver = make_test_version();
        let bytes = serialize_version(&ver);

        // First 4 bytes: version as i32 LE
        let version = i32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u32;
        assert_eq!(version, PROTOCOL_VERSION);

        // Next 8 bytes: services
        let svc = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        assert_eq!(
            svc,
            (ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS).bits()
        );

        // Next 8 bytes: timestamp
        let ts = i64::from_le_bytes(bytes[12..20].try_into().unwrap());
        assert_eq!(ts, 1700000000);
    }

    #[test]
    fn test_deserialize_version_too_short() {
        assert!(deserialize_version(&[0u8; 10]).is_none());
        assert!(deserialize_version(&[0u8; 45]).is_none());
    }

    #[test]
    fn test_version_relay_false() {
        let mut ver = make_test_version();
        ver.relay = false;
        let bytes = serialize_version(&ver);
        let restored = deserialize_version(&bytes).unwrap();
        assert!(!restored.relay);
    }

    #[test]
    fn test_version_empty_user_agent() {
        let mut ver = make_test_version();
        ver.user_agent = String::new();
        let bytes = serialize_version(&ver);
        let restored = deserialize_version(&bytes).unwrap();
        assert_eq!(restored.user_agent, "");
    }

    #[test]
    fn test_version_ipv6_address() {
        let mut ver = make_test_version();
        ver.addr_recv = NetAddress::new(
            ServiceFlags::NODE_NETWORK,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8333,
        );
        let bytes = serialize_version(&ver);
        let restored = deserialize_version(&bytes).unwrap();
        assert_eq!(restored.addr_recv.port, 8333);
        match restored.addr_recv.ip {
            IpAddr::V6(v6) => assert_eq!(v6, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            _ => panic!("expected IPv6"),
        }
    }

    // -- NetAddress serialization tests -------------------------------------

    #[test]
    fn test_net_address_serialize_ipv4() {
        let addr = NetAddress::new(
            ServiceFlags::NODE_NETWORK,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8333,
        );
        let mut buf = Vec::new();
        serialize_net_address_into(&addr, &mut buf);
        assert_eq!(buf.len(), 26);

        let restored = deserialize_net_address(&buf).unwrap();
        assert_eq!(restored.port, 8333);
        assert_eq!(restored.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(restored.services, ServiceFlags::NODE_NETWORK);
    }

    #[test]
    fn test_net_address_serialize_ipv6() {
        let addr = NetAddress::new(
            ServiceFlags::NODE_WITNESS,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            18333,
        );
        let mut buf = Vec::new();
        serialize_net_address_into(&addr, &mut buf);
        assert_eq!(buf.len(), 26);

        let restored = deserialize_net_address(&buf).unwrap();
        assert_eq!(restored.port, 18333);
        assert_eq!(restored.ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_deserialize_net_address_too_short() {
        assert!(deserialize_net_address(&[0u8; 25]).is_none());
    }

    // -- Message parsing tests ----------------------------------------------

    #[test]
    fn test_parse_message_verack() {
        let msg = parse_message("verack", &[]);
        assert!(matches!(msg, NetMessage::Verack));
    }

    #[test]
    fn test_parse_message_ping() {
        let nonce: u64 = 0x1234567890abcdef;
        let msg = parse_message("ping", &nonce.to_le_bytes());
        match msg {
            NetMessage::Ping(n) => assert_eq!(n, nonce),
            _ => panic!("expected Ping"),
        }
    }

    #[test]
    fn test_parse_message_pong() {
        let nonce: u64 = 42;
        let msg = parse_message("pong", &nonce.to_le_bytes());
        match msg {
            NetMessage::Pong(n) => assert_eq!(n, 42),
            _ => panic!("expected Pong"),
        }
    }

    #[test]
    fn test_parse_message_ping_short_payload() {
        let msg = parse_message("ping", &[1, 2, 3]);
        match msg {
            NetMessage::Ping(n) => assert_eq!(n, 0),
            _ => panic!("expected Ping"),
        }
    }

    #[test]
    fn test_parse_message_getaddr() {
        let msg = parse_message("getaddr", &[]);
        assert!(matches!(msg, NetMessage::GetAddr));
    }

    #[test]
    fn test_parse_message_sendheaders() {
        let msg = parse_message("sendheaders", &[]);
        assert!(matches!(msg, NetMessage::SendHeaders));
    }

    #[test]
    fn test_parse_message_feefilter() {
        let fee: i64 = 1000;
        let msg = parse_message("feefilter", &fee.to_le_bytes());
        match msg {
            NetMessage::FeeFilter(f) => assert_eq!(f, 1000),
            _ => panic!("expected FeeFilter"),
        }
    }

    #[test]
    fn test_parse_message_unknown() {
        let msg = parse_message("customcmd", &[1, 2, 3]);
        match msg {
            NetMessage::Unknown { command, payload } => {
                assert_eq!(command, "customcmd");
                assert_eq!(payload, vec![1, 2, 3]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_parse_message_version() {
        let ver = make_test_version();
        let payload = serialize_version(&ver);
        let msg = parse_message("version", &payload);
        match msg {
            NetMessage::Version(v) => {
                assert_eq!(v.version, PROTOCOL_VERSION);
                assert_eq!(v.user_agent, "/QubitCoin:0.1.0/");
            }
            _ => panic!("expected Version"),
        }
    }

    #[test]
    fn test_parse_message_version_invalid() {
        let msg = parse_message("version", &[0u8; 10]);
        assert!(matches!(msg, NetMessage::Unknown { .. }));
    }

    #[test]
    fn test_parse_message_sendcmpct() {
        let mut payload = Vec::new();
        payload.push(1); // announce = true
        payload.extend_from_slice(&2u64.to_le_bytes()); // version = 2
        let msg = parse_message("sendcmpct", &payload);
        match msg {
            NetMessage::SendCmpct { announce, version } => {
                assert!(announce);
                assert_eq!(version, 2);
            }
            _ => panic!("expected SendCmpct"),
        }
    }

    #[test]
    fn test_parse_message_block() {
        let data = vec![0xab; 100];
        let msg = parse_message("block", &data);
        match msg {
            NetMessage::Block(d) => assert_eq!(d.len(), 100),
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn test_parse_message_tx() {
        let data = vec![0xcd; 50];
        let msg = parse_message("tx", &data);
        match msg {
            NetMessage::Tx(d) => assert_eq!(d.len(), 50),
            _ => panic!("expected Tx"),
        }
    }

    // -- Inv serialization roundtrip ----------------------------------------

    #[test]
    fn test_inv_serialize_roundtrip() {
        let inv = vec![
            InvVect::new(
                InvType::Tx,
                qubitcoin_primitives::Uint256::from_bytes([0x11; 32]),
            ),
            InvVect::new(
                InvType::Block,
                qubitcoin_primitives::Uint256::from_bytes([0x22; 32]),
            ),
        ];
        let payload = serialize_inv_list(&inv);
        let parsed = parse_inv_list(&payload);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].inv_type, InvType::Tx);
        assert_eq!(parsed[1].inv_type, InvType::Block);
        assert_eq!(parsed[0].hash, inv[0].hash);
        assert_eq!(parsed[1].hash, inv[1].hash);
    }

    #[test]
    fn test_inv_empty_list() {
        let inv: Vec<InvVect> = vec![];
        let payload = serialize_inv_list(&inv);
        let parsed = parse_inv_list(&payload);
        assert!(parsed.is_empty());
    }

    // -- Headers serialization roundtrip ------------------------------------

    #[test]
    fn test_headers_serialize_roundtrip() {
        let headers = vec![vec![0xaa; 80], vec![0xbb; 80]];
        let payload = serialize_headers(&headers);
        let parsed = parse_headers_payload(&payload);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], vec![0xaa; 80]);
        assert_eq!(parsed[1], vec![0xbb; 80]);
    }

    // -- serialize_message tests --------------------------------------------

    #[test]
    fn test_serialize_message_verack() {
        let payload = serialize_message(&NetMessage::Verack);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_serialize_message_ping() {
        let payload = serialize_message(&NetMessage::Ping(42));
        assert_eq!(payload.len(), 8);
        let nonce = u64::from_le_bytes(payload.try_into().unwrap());
        assert_eq!(nonce, 42);
    }

    #[test]
    fn test_serialize_message_feefilter() {
        let payload = serialize_message(&NetMessage::FeeFilter(1000));
        let fee = i64::from_le_bytes(payload.try_into().unwrap());
        assert_eq!(fee, 1000);
    }

    // -- build_version_message tests ----------------------------------------

    #[test]
    fn test_build_version_message() {
        let config = ConnConfig::default();
        let remote: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let ver = build_version_message(&config, remote);

        assert_eq!(ver.version, PROTOCOL_VERSION);
        assert_eq!(ver.services, config.our_services);
        assert_eq!(ver.user_agent, config.user_agent);
        assert_eq!(ver.start_height, config.best_height);
        assert!(ver.relay);
        assert_eq!(ver.addr_recv.port, 8333);
        assert_eq!(ver.addr_recv.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        // Timestamp should be recent (within 60 seconds of now).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((ver.timestamp - now).abs() < 60);
    }

    #[test]
    fn test_build_version_message_custom_config() {
        let config = ConnConfig {
            listen_addr: "0.0.0.0:18333".parse().unwrap(),
            magic: NetworkMagic::TESTNET,
            max_inbound: 50,
            max_outbound: 5,
            our_services: ServiceFlags::NODE_NETWORK,
            user_agent: "/Test:1.0/".to_string(),
            best_height: 100_000,
        };
        let remote: SocketAddr = "192.168.1.1:18333".parse().unwrap();
        let ver = build_version_message(&config, remote);

        assert_eq!(ver.services, ServiceFlags::NODE_NETWORK);
        assert_eq!(ver.user_agent, "/Test:1.0/");
        assert_eq!(ver.start_height, 100_000);
        assert_eq!(ver.addr_from.port, 18333);
    }

    #[test]
    fn test_build_version_message_serializes_correctly() {
        let config = ConnConfig::default();
        let remote: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let ver = build_version_message(&config, remote);
        let bytes = serialize_version(&ver);
        let restored = deserialize_version(&bytes).unwrap();
        assert_eq!(restored.version, ver.version);
        assert_eq!(restored.services, ver.services);
        assert_eq!(restored.user_agent, ver.user_agent);
        assert_eq!(restored.start_height, ver.start_height);
    }

    // -- send_raw_message tests (with tokio) --------------------------------

    #[tokio::test]
    async fn test_send_raw_message_verack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let send_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            send_raw_message(&mut stream, NetworkMagic::REGTEST, "verack", &[])
                .await
                .unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 24];
        stream.read_exact(&mut buf).await.unwrap();

        let header = MessageHeader::deserialize(&buf);
        assert_eq!(header.magic, NetworkMagic::REGTEST);
        assert_eq!(header.command_str(), "verack");
        assert_eq!(header.payload_size, 0);
        assert!(header.verify_checksum(&[]));

        send_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_raw_message_with_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let nonce: u64 = 0xdeadbeef;

        let send_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            send_raw_message(
                &mut stream,
                NetworkMagic::MAINNET,
                "ping",
                &nonce.to_le_bytes(),
            )
            .await
            .unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header_buf = [0u8; 24];
        stream.read_exact(&mut header_buf).await.unwrap();
        let header = MessageHeader::deserialize(&header_buf);

        assert_eq!(header.command_str(), "ping");
        assert_eq!(header.payload_size, 8);

        let mut payload = [0u8; 8];
        stream.read_exact(&mut payload).await.unwrap();
        let received_nonce = u64::from_le_bytes(payload);
        assert_eq!(received_nonce, 0xdeadbeef);
        assert!(header.verify_checksum(&payload));

        send_handle.await.unwrap();
    }

    // -- Full handshake integration test ------------------------------------

    #[tokio::test]
    async fn test_conn_manager_listen_and_connect() {
        // Use port 0 to let the OS assign a free port.
        let config = ConnConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            magic: NetworkMagic::REGTEST,
            max_inbound: 10,
            max_outbound: 10,
            our_services: ServiceFlags::NODE_NETWORK,
            user_agent: "/Test:0.1/".to_string(),
            best_height: 1,
        };

        // We need a real listener to get the actual port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        drop(listener);

        let server_config = ConnConfig {
            listen_addr: listen_addr,
            ..config.clone()
        };

        let mut server = ConnManager::new(server_config.clone());
        let mut server_events = server.take_events().unwrap();

        server.start_listening().await.unwrap();

        // Give the listener a moment to bind.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Connect a raw client.
        let _client_stream = TcpStream::connect(listen_addr).await.unwrap();

        // Server should emit NewInbound.
        let event = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_events.recv())
            .await
            .expect("timeout waiting for event")
            .expect("channel closed");

        match event {
            ConnectionEvent::NewInbound { peer_id, addr } => {
                assert!(peer_id > 0);
                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            other => panic!("expected NewInbound, got {:?}", other),
        }

        server.shutdown();
    }

    #[tokio::test]
    async fn test_version_handshake_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let magic = NetworkMagic::REGTEST;

        // Spawn a "server" that reads a version message and replies with verack.
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read header.
            let mut hdr_buf = [0u8; 24];
            stream.read_exact(&mut hdr_buf).await.unwrap();
            let hdr = MessageHeader::deserialize(&hdr_buf);
            assert_eq!(hdr.command_str(), "version");
            assert_eq!(hdr.magic, magic);

            // Read payload.
            let mut payload = vec![0u8; hdr.payload_size as usize];
            stream.read_exact(&mut payload).await.unwrap();
            assert!(hdr.verify_checksum(&payload));

            // Parse version.
            let ver = deserialize_version(&payload).unwrap();
            assert_eq!(ver.version, PROTOCOL_VERSION);
            assert_eq!(ver.user_agent, "/Qubitcoin:0.1.0/");

            // Send verack.
            send_raw_message(&mut stream, magic, "verack", &[])
                .await
                .unwrap();
        });

        // Client: send version, receive verack.
        let mut client = TcpStream::connect(addr).await.unwrap();
        let config = ConnConfig {
            magic,
            ..ConnConfig::default()
        };
        let ver = build_version_message(&config, addr);
        send_raw_message(&mut client, magic, "version", &serialize_version(&ver))
            .await
            .unwrap();

        // Read verack.
        let mut hdr_buf = [0u8; 24];
        client.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = MessageHeader::deserialize(&hdr_buf);
        assert_eq!(hdr.command_str(), "verack");
        assert_eq!(hdr.payload_size, 0);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_ping_pong_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let magic = NetworkMagic::REGTEST;
        let nonce: u64 = 0x42424242;

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Send ping.
            send_raw_message(&mut stream, magic, "ping", &nonce.to_le_bytes())
                .await
                .unwrap();

            // Read pong.
            let mut hdr_buf = [0u8; 24];
            stream.read_exact(&mut hdr_buf).await.unwrap();
            let hdr = MessageHeader::deserialize(&hdr_buf);
            assert_eq!(hdr.command_str(), "pong");

            let mut payload = [0u8; 8];
            stream.read_exact(&mut payload).await.unwrap();
            let pong_nonce = u64::from_le_bytes(payload);
            assert_eq!(pong_nonce, nonce);
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Read ping.
        let mut hdr_buf = [0u8; 24];
        client.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = MessageHeader::deserialize(&hdr_buf);
        assert_eq!(hdr.command_str(), "ping");

        let mut payload = [0u8; 8];
        client.read_exact(&mut payload).await.unwrap();
        let received_nonce = u64::from_le_bytes(payload);

        // Send pong.
        send_raw_message(&mut client, magic, "pong", &received_nonce.to_le_bytes())
            .await
            .unwrap();

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_cleanup_peer() {
        let pm = Arc::new(PeerManager::new(10, 10));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let peer_addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let peer_id = pm.add_peer(peer_addr, false);

        cleanup_peer(peer_id, &pm, &tx, "test disconnect".to_string());

        assert!(pm.get_peer(peer_id).is_none());

        let event = rx.recv().await.unwrap();
        match event {
            ConnectionEvent::Disconnected {
                peer_id: id,
                reason,
            } => {
                assert_eq!(id, peer_id);
                assert_eq!(reason, "test disconnect");
            }
            _ => panic!("expected Disconnected"),
        }
    }

    // -- New message parsing tests ------------------------------------------

    #[test]
    fn test_parse_message_wtxidrelay() {
        let msg = parse_message("wtxidrelay", &[]);
        assert!(matches!(msg, NetMessage::WtxidRelay));
        assert_eq!(msg.command(), "wtxidrelay");
    }

    #[test]
    fn test_parse_message_sendaddrv2() {
        let msg = parse_message("sendaddrv2", &[]);
        assert!(matches!(msg, NetMessage::SendAddrV2));
        assert_eq!(msg.command(), "sendaddrv2");
    }

    #[test]
    fn test_parse_message_filterclear() {
        let msg = parse_message("filterclear", &[]);
        assert!(matches!(msg, NetMessage::FilterClear));
    }

    #[test]
    fn test_parse_message_mempool() {
        let msg = parse_message("mempool", &[]);
        assert!(matches!(msg, NetMessage::MemPool));
    }

    #[test]
    fn test_parse_message_sendtxrcncl() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0xdeadbeefcafe1234u64.to_le_bytes());
        let msg = parse_message("sendtxrcncl", &payload);
        match msg {
            NetMessage::SendTxRcncl { version, salt } => {
                assert_eq!(version, 1);
                assert_eq!(salt, 0xdeadbeefcafe1234);
            }
            _ => panic!("expected SendTxRcncl"),
        }
    }

    #[test]
    fn test_parse_message_sendtxrcncl_too_short() {
        let msg = parse_message("sendtxrcncl", &[1, 2, 3]);
        assert!(matches!(msg, NetMessage::Unknown { .. }));
    }

    #[test]
    fn test_parse_message_cmpctblock() {
        let data = vec![0xaa; 100];
        let msg = parse_message("cmpctblock", &data);
        match msg {
            NetMessage::CmpctBlock(d) => assert_eq!(d.len(), 100),
            _ => panic!("expected CmpctBlock"),
        }
    }

    #[test]
    fn test_parse_message_getblocktxn() {
        let data = vec![0xbb; 40];
        let msg = parse_message("getblocktxn", &data);
        match msg {
            NetMessage::GetBlockTxn(d) => assert_eq!(d.len(), 40),
            _ => panic!("expected GetBlockTxn"),
        }
    }

    #[test]
    fn test_parse_message_blocktxn() {
        let data = vec![0xcc; 60];
        let msg = parse_message("blocktxn", &data);
        match msg {
            NetMessage::BlockTxn(d) => assert_eq!(d.len(), 60),
            _ => panic!("expected BlockTxn"),
        }
    }

    #[test]
    fn test_parse_message_filterload() {
        let data = vec![0xdd; 36];
        let msg = parse_message("filterload", &data);
        match msg {
            NetMessage::FilterLoad(d) => assert_eq!(d.len(), 36),
            _ => panic!("expected FilterLoad"),
        }
    }

    #[test]
    fn test_parse_message_filteradd() {
        let data = vec![0xee; 32];
        let msg = parse_message("filteradd", &data);
        match msg {
            NetMessage::FilterAdd(d) => assert_eq!(d.len(), 32),
            _ => panic!("expected FilterAdd"),
        }
    }

    #[test]
    fn test_parse_message_merkleblock() {
        let data = vec![0xff; 80];
        let msg = parse_message("merkleblock", &data);
        match msg {
            NetMessage::MerkleBlock(d) => assert_eq!(d.len(), 80),
            _ => panic!("expected MerkleBlock"),
        }
    }

    #[test]
    fn test_parse_message_addrv2() {
        let data = vec![1, 2, 3, 4, 5];
        let msg = parse_message("addrv2", &data);
        match msg {
            NetMessage::AddrV2(d) => assert_eq!(d, vec![1, 2, 3, 4, 5]),
            _ => panic!("expected AddrV2"),
        }
    }

    #[test]
    fn test_parse_message_reject() {
        // Build a reject payload: varint(2) + "tx" + code(0x10) + varint(6) + "reason"
        let mut payload = Vec::new();
        write_varint(2, &mut payload);
        payload.extend_from_slice(b"tx");
        payload.push(0x10);
        write_varint(6, &mut payload);
        payload.extend_from_slice(b"reason");
        let msg = parse_message("reject", &payload);
        match msg {
            NetMessage::Reject {
                message,
                code,
                reason,
            } => {
                assert_eq!(message, "tx");
                assert_eq!(code, 0x10);
                assert_eq!(reason, "reason");
            }
            _ => panic!("expected Reject, got {:?}", msg),
        }
    }

    #[test]
    fn test_parse_message_getcfheaders() {
        let mut payload = Vec::new();
        payload.push(0x00); // filter_type
        payload.extend_from_slice(&100u32.to_le_bytes()); // start_height
        payload.extend_from_slice(&[0xab; 32]); // stop_hash
        let msg = parse_message("getcfheaders", &payload);
        match msg {
            NetMessage::GetCFHeaders {
                filter_type,
                start_height,
                stop_hash,
            } => {
                assert_eq!(filter_type, 0);
                assert_eq!(start_height, 100);
                assert_eq!(stop_hash.as_bytes(), &[0xab; 32]);
            }
            _ => panic!("expected GetCFHeaders"),
        }
    }

    #[test]
    fn test_parse_message_getcfilters() {
        let mut payload = Vec::new();
        payload.push(0x01); // filter_type
        payload.extend_from_slice(&200u32.to_le_bytes());
        payload.extend_from_slice(&[0xcd; 32]);
        let msg = parse_message("getcfilters", &payload);
        match msg {
            NetMessage::GetCFilters {
                filter_type,
                start_height,
                stop_hash,
            } => {
                assert_eq!(filter_type, 1);
                assert_eq!(start_height, 200);
                assert_eq!(stop_hash.as_bytes(), &[0xcd; 32]);
            }
            _ => panic!("expected GetCFilters"),
        }
    }

    #[test]
    fn test_parse_message_getcfcheckpt() {
        let mut payload = Vec::new();
        payload.push(0x00);
        payload.extend_from_slice(&[0xef; 32]);
        let msg = parse_message("getcfcheckpt", &payload);
        match msg {
            NetMessage::GetCFCheckpt {
                filter_type,
                stop_hash,
            } => {
                assert_eq!(filter_type, 0);
                assert_eq!(stop_hash.as_bytes(), &[0xef; 32]);
            }
            _ => panic!("expected GetCFCheckpt"),
        }
    }

    // -- Addr serialization roundtrip --

    #[test]
    fn test_addr_serialize_roundtrip() {
        let addrs = vec![
            (
                1700000000u32,
                NetAddress::new(
                    ServiceFlags::NODE_NETWORK,
                    IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                    8333,
                ),
            ),
            (
                1700000001u32,
                NetAddress::new(
                    ServiceFlags::NODE_WITNESS,
                    IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                    18333,
                ),
            ),
        ];
        let msg = NetMessage::Addr(addrs.clone());
        let payload = serialize_message(&msg);
        let parsed = parse_message("addr", &payload);
        match parsed {
            NetMessage::Addr(parsed_addrs) => {
                assert_eq!(parsed_addrs.len(), 2);
                assert_eq!(parsed_addrs[0].0, 1700000000);
                assert_eq!(parsed_addrs[0].1.port, 8333);
                assert_eq!(parsed_addrs[1].0, 1700000001);
                assert_eq!(parsed_addrs[1].1.port, 18333);
            }
            _ => panic!("expected Addr"),
        }
    }

    // -- serialize_message roundtrip tests for new types --

    #[test]
    fn test_serialize_message_wtxidrelay() {
        let payload = serialize_message(&NetMessage::WtxidRelay);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_serialize_message_sendaddrv2() {
        let payload = serialize_message(&NetMessage::SendAddrV2);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_serialize_message_sendtxrcncl() {
        let msg = NetMessage::SendTxRcncl {
            version: 1,
            salt: 42,
        };
        let payload = serialize_message(&msg);
        assert_eq!(payload.len(), 12);
        let parsed = parse_message("sendtxrcncl", &payload);
        match parsed {
            NetMessage::SendTxRcncl { version, salt } => {
                assert_eq!(version, 1);
                assert_eq!(salt, 42);
            }
            _ => panic!("expected SendTxRcncl"),
        }
    }

    #[test]
    fn test_serialize_message_getcfheaders() {
        let msg = NetMessage::GetCFHeaders {
            filter_type: 0,
            start_height: 100,
            stop_hash: BlockHash::from_bytes([0xab; 32]),
        };
        let payload = serialize_message(&msg);
        assert_eq!(payload.len(), 37);
        let parsed = parse_message("getcfheaders", &payload);
        match parsed {
            NetMessage::GetCFHeaders {
                filter_type,
                start_height,
                stop_hash,
            } => {
                assert_eq!(filter_type, 0);
                assert_eq!(start_height, 100);
                assert_eq!(stop_hash.as_bytes(), &[0xab; 32]);
            }
            _ => panic!("expected GetCFHeaders"),
        }
    }

    #[test]
    fn test_serialize_message_getcfcheckpt() {
        let msg = NetMessage::GetCFCheckpt {
            filter_type: 0,
            stop_hash: BlockHash::from_bytes([0xcd; 32]),
        };
        let payload = serialize_message(&msg);
        assert_eq!(payload.len(), 33);
    }

    #[test]
    fn test_build_version_message_with_nonce() {
        let config = ConnConfig::default();
        let remote: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let ver = build_version_message_with_nonce(&config, remote, 12345);
        assert_eq!(ver.nonce, 12345);
        assert_eq!(ver.version, PROTOCOL_VERSION);
    }
}
