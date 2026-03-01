//! Network message processing: handles inv, getdata, block, tx, headers messages.
//!
//! Maps to: src/net_processing.cpp (PeerManagerImpl)
//!
//! The `NetProcessor` consumes `ConnectionEvent`s from the connection layer
//! and dispatches appropriate responses. It is the bridge between the raw P2P
//! transport (connection.rs) and the higher-level node logic (validation,
//! mempool, chain state).
//!
//! During Initial Block Download (IBD), NetProcessor sends `getheaders`
//! requests to connected peers and accumulates the header chain.
//!
//! Key protocol behaviors implemented:
//! - Headers-first sync (getheaders → headers → getheaders → ...)
//! - Block download via inv → getdata → block pipeline
//! - Inventory relay (inv announcements)
//! - Address relay (addr/addrv2/getaddr)
//! - Misbehavior tracking (single Misbehaving() = immediate discourage)
//! - Compact block negotiation (sendcmpct)
//! - Feature negotiation (wtxidrelay, sendaddrv2, sendheaders, feefilter)
//! - Timeouts: inactivity, headers download, block stalling

use crate::connection::ConnectionEvent;
use crate::connection::{serialize_message, ConnManager};
use crate::protocol::{
    InvType, InvVect, NetMessage, BLOCK_DOWNLOAD_TIMEOUT_BASE, BLOCK_STALLING_TIMEOUT,
    MAX_ADDR_TO_SEND, MAX_BLOCKS_IN_TRANSIT_PER_PEER, MAX_HEADERS_RESULTS, MAX_INV_SIZE,
    PROTOCOL_VERSION,
};
use qubitcoin_primitives::{BlockHash, Uint256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// NodeInterface trait
// ---------------------------------------------------------------------------

/// Interface between the network layer and the node validation/storage layer.
///
/// This trait decouples the P2P protocol processing (`NetProcessor`) from the
/// concrete block validation (`ChainstateManager`), mempool, and storage
/// implementations. The daemon binary implements this trait to bridge the two.
///
/// Maps to the combination of `ChainstateManager`, `CTxMemPool`, and
/// `CConnman` interfaces that Bitcoin Core's `PeerManagerImpl` accesses.
pub trait NodeInterface: Send + Sync {
    /// Process a received block (deserialize, validate, add to chain).
    /// Returns Ok(accepted) on success, Err(reason) on failure.
    fn process_block(&self, data: &[u8]) -> Result<bool, String>;

    /// Process a received transaction (deserialize, validate, add to mempool).
    /// Returns Ok(accepted) on success, Err(reason) on failure.
    fn process_transaction(&self, data: &[u8]) -> Result<bool, String>;

    /// Check if we already have a transaction (in mempool or recent rejects).
    fn has_transaction(&self, txid: &Uint256) -> bool;

    /// Get a serialized block by hash. Returns None if we don't have it.
    fn get_block(&self, hash: &BlockHash) -> Option<Vec<u8>>;

    /// Get a serialized transaction by txid. Returns None if not in mempool.
    fn get_transaction(&self, txid: &Uint256) -> Option<Vec<u8>>;

    /// Get the current chain tip height.
    fn chain_height(&self) -> i32;

    /// Add an address to our address book for future peer discovery.
    fn add_address(&self, addr: SocketAddr);

    /// Get addresses from our address book to send to a peer.
    fn get_addresses(&self, max: usize) -> Vec<SocketAddr>;
}

/// Callback interface for state change notifications.
///
/// The daemon implements this to update RPC-visible state when the network
/// processor receives headers, blocks, or changes peer state.
pub trait StateNotifier: Send + Sync {
    /// Called when header count changes (during IBD headers-first sync).
    fn on_headers_update(&self, _header_count: usize) {}
    /// Called when a peer connects (handshake complete).
    fn on_peer_connected(&self, _peer_id: u64) {}
    /// Called when a peer disconnects.
    fn on_peer_disconnected(&self, _peer_id: u64) {}
    /// Called when block count changes.
    fn on_block_received(&self, _blocks_count: u64) {}
}

/// No-op state notifier.
pub struct NullNotifier;
impl StateNotifier for NullNotifier {}

/// No-op implementation for testing or when no node is connected.
pub struct NullNodeInterface;

impl NodeInterface for NullNodeInterface {
    fn process_block(&self, _data: &[u8]) -> Result<bool, String> {
        Ok(false)
    }
    fn process_transaction(&self, _data: &[u8]) -> Result<bool, String> {
        Ok(false)
    }
    fn has_transaction(&self, _txid: &Uint256) -> bool {
        false
    }
    fn get_block(&self, _hash: &BlockHash) -> Option<Vec<u8>> {
        None
    }
    fn get_transaction(&self, _txid: &Uint256) -> Option<Vec<u8>> {
        None
    }
    fn chain_height(&self) -> i32 {
        0
    }
    fn add_address(&self, _addr: SocketAddr) {}
    fn get_addresses(&self, _max: usize) -> Vec<SocketAddr> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Per-peer sync state
// ---------------------------------------------------------------------------

/// Per-peer synchronization state.
///
/// Maps to the `Peer` struct in Bitcoin Core's net_processing.cpp.
struct PeerSyncState {
    /// Whether this peer has completed the version/verack handshake.
    handshake_complete: bool,
    /// Whether we have sent a `getheaders` request to this peer.
    headers_requested: bool,
    /// Number of headers we have received from this peer.
    headers_received: u64,
    /// Block hashes currently in-flight from this peer, with request timestamp.
    blocks_in_flight: Vec<(BlockHash, Instant)>,
    /// When we last received data from this peer.
    last_activity: Instant,
    /// When we last sent a ping to this peer.
    last_ping: Option<Instant>,
    /// Whether we're waiting for a pong from this peer.
    ping_outstanding: bool,
    /// Whether this peer supports wtxid relay (BIP 339).
    wtxid_relay: bool,
    /// Whether this peer supports addrv2 (BIP 155).
    wants_addrv2: bool,
    /// Whether this peer prefers headers announcements (BIP 130).
    prefer_headers: bool,
    /// Whether this peer prefers compact block announcements (BIP 152).
    prefer_cmpctblock: bool,
    /// Compact block version negotiated with this peer.
    cmpctblock_version: u64,
    /// Minimum fee filter from this peer (BIP 133), in sat/kvB.
    min_fee_filter: i64,
    /// When header sync started (for timeout).
    headers_sync_start: Option<Instant>,
    /// Number of unconnecting headers received from this peer.
    unconnecting_headers: u64,
    /// Inventory we've already seen from this peer.
    known_inv: HashSet<BlockHash>,
    /// Whether this peer has been discouraged (misbehavior detected).
    discouraged: bool,
    /// Reason for discouragement, if any.
    discourage_reason: Option<String>,
}

impl PeerSyncState {
    fn new() -> Self {
        PeerSyncState {
            handshake_complete: false,
            headers_requested: false,
            headers_received: 0,
            blocks_in_flight: Vec::<(BlockHash, Instant)>::new(),
            last_activity: Instant::now(),
            last_ping: None,
            ping_outstanding: false,
            wtxid_relay: false,
            wants_addrv2: false,
            prefer_headers: false,
            prefer_cmpctblock: false,
            cmpctblock_version: 0,
            min_fee_filter: 0,
            headers_sync_start: None,
            unconnecting_headers: 0,
            known_inv: HashSet::new(),
            discouraged: false,
            discourage_reason: None,
        }
    }

    fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// NetProcessor
// ---------------------------------------------------------------------------

/// Processes network messages and dispatches appropriate responses.
///
/// Consumes events from the connection manager's event channel and handles
/// protocol-level message processing: inventory announcements, data requests,
/// block/tx relay, headers sync, etc.
///
/// During IBD the processor sends `getheaders` to newly-connected peers and
/// follows the header chain until it is fully synchronized.
pub struct NetProcessor {
    /// Channel to receive connection events.
    event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    /// Connection manager for sending messages to peers.
    conn_manager: Arc<ConnManager>,
    /// Node interface for block/tx validation and storage.
    node: Arc<dyn NodeInterface>,
    /// Genesis block hash – always included as the last locator entry.
    genesis_hash: BlockHash,
    /// Known header hashes (simplified header chain) — deduplicated.
    header_chain: Vec<BlockHash>,
    /// Fast lookup for headers already in `header_chain`.
    header_set: HashSet<BlockHash>,
    /// Headers we still need to download blocks for.
    blocks_to_download: VecDeque<BlockHash>,
    /// Blocks we have already downloaded (hash set for dedup).
    blocks_downloaded: HashSet<BlockHash>,
    /// Buffer for blocks received out of chain order during IBD.
    /// Key: block hash, Value: (peer_id, raw block data).
    pending_blocks: HashMap<BlockHash, (u64, Vec<u8>)>,
    /// Index into `header_chain` for the next block to process in order.
    next_process_idx: usize,
    /// When `next_process_idx` last advanced (for head-of-line stall detection).
    last_drain_time: Instant,
    /// Per-peer state.
    peer_states: HashMap<u64, PeerSyncState>,
    /// Total blocks received.
    blocks_received: u64,
    /// Total headers received.
    total_headers: u64,
    /// Total transactions received.
    txns_received: u64,
    /// Inventory we have already seen (block hashes).
    seen_inv: HashSet<BlockHash>,
    /// Whether we are in Initial Block Download mode.
    is_ibd: bool,
    /// When we started IBD.
    ibd_start: Instant,
    /// State change notifier (for updating RPC-visible state).
    notifier: Arc<dyn StateNotifier>,
}

impl NetProcessor {
    /// Create a new processor that will drain events from `event_rx` and
    /// use `conn_manager` to send messages back to peers.
    ///
    /// `genesis_hash` is always included as the last entry in block locators
    /// so that peers know we share the same chain.
    pub fn new(
        event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
        conn_manager: Arc<ConnManager>,
        genesis_hash: BlockHash,
    ) -> Self {
        Self::with_node(
            event_rx,
            conn_manager,
            genesis_hash,
            Arc::new(NullNodeInterface),
        )
    }

    /// Create a new processor with a node interface for block/tx validation.
    pub fn with_node(
        event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
        conn_manager: Arc<ConnManager>,
        genesis_hash: BlockHash,
        node: Arc<dyn NodeInterface>,
    ) -> Self {
        Self::full(
            event_rx,
            conn_manager,
            genesis_hash,
            node,
            Arc::new(NullNotifier),
        )
    }

    /// Create a processor with both a node interface and a state notifier.
    pub fn full(
        event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
        conn_manager: Arc<ConnManager>,
        genesis_hash: BlockHash,
        node: Arc<dyn NodeInterface>,
        notifier: Arc<dyn StateNotifier>,
    ) -> Self {
        NetProcessor {
            event_rx,
            conn_manager,
            node,
            genesis_hash,
            header_chain: Vec::new(),
            header_set: HashSet::new(),
            blocks_to_download: VecDeque::new(),
            blocks_downloaded: HashSet::new(),
            pending_blocks: HashMap::new(),
            next_process_idx: 0,
            last_drain_time: Instant::now(),
            peer_states: HashMap::new(),
            blocks_received: 0,
            total_headers: 0,
            txns_received: 0,
            seen_inv: HashSet::new(),
            is_ibd: true,
            ibd_start: Instant::now(),
            notifier,
        }
    }

    /// Run the message processing loop.
    ///
    /// This method runs until the event channel is closed (i.e. the connection
    /// manager is dropped or shut down).
    pub async fn run(&mut self) {
        let mut stall_interval = tokio::time::interval(std::time::Duration::from_millis(500));
        // Don't queue up stall checks if processing falls behind.
        stall_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    let event = match event {
                        Some(e) => e,
                        None => break, // channel closed
                    };
                    match event {
                        ConnectionEvent::HandshakeComplete { peer_id } => {
                            tracing::info!(peer_id = peer_id, "handshake complete, requesting headers");
                            let mut state = PeerSyncState::new();
                            state.handshake_complete = true;
                            state.headers_sync_start = Some(Instant::now());
                            self.peer_states.insert(peer_id, state);
                            self.notifier.on_peer_connected(peer_id);

                            // Send getheaders from our current tip (or genesis).
                            self.send_getheaders(peer_id);
                            // Also tell peer we prefer header announcements (BIP 130).
                            self.conn_manager
                                .send_to_peer(peer_id, "sendheaders", vec![]);
                            // Send compact block negotiation (BIP 152).
                            self.send_sendcmpct(peer_id);
                        }
                        ConnectionEvent::MessageReceived { peer_id, message } => {
                            // Update activity timestamp.
                            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                                state.mark_activity();
                            }
                            self.handle_message(peer_id, message).await;
                        }
                        ConnectionEvent::Disconnected { peer_id, reason } => {
                            tracing::info!(peer_id = peer_id, reason = %reason, "peer disconnected");
                            // Re-queue in-flight blocks from disconnected peer
                            // to the FRONT so the head-of-line block is first.
                            let mut requeued = 0usize;
                            if let Some(state) = self.peer_states.get(&peer_id) {
                                // Push in reverse so earliest blocks end up at front.
                                for (hash, _) in state.blocks_in_flight.iter().rev() {
                                    self.blocks_to_download.push_front(*hash);
                                    requeued += 1;
                                }
                            }
                            self.peer_states.remove(&peer_id);
                            self.notifier.on_peer_disconnected(peer_id);

                            // Redistribute re-queued blocks to remaining peers.
                            if requeued > 0 {
                                let peer_ids: Vec<u64> = self
                                    .peer_states
                                    .iter()
                                    .filter(|(_, s)| s.handshake_complete && !s.discouraged)
                                    .map(|(&pid, _)| pid)
                                    .collect();
                                for pid in peer_ids {
                                    self.request_blocks(pid);
                                }
                            }
                        }
                        ConnectionEvent::NewInbound { peer_id, addr } => {
                            tracing::debug!(peer_id = peer_id, addr = %addr, "new inbound peer");
                        }
                        ConnectionEvent::NewOutbound { peer_id, addr } => {
                            tracing::debug!(peer_id = peer_id, addr = %addr, "new outbound peer");
                        }
                    }
                }
                _ = stall_interval.tick() => {
                    self.check_stalled_peers();
                }
            }
        }
    }

    /// Build and send a `getheaders` message to a peer.
    ///
    /// Uses exponential-backoff locator hashes from the current header chain,
    /// similar to Bitcoin Core's `CBlockLocator`.  The genesis hash is always
    /// included as the last entry so the remote peer can identify our chain.
    fn send_getheaders(&mut self, peer_id: u64) {
        // Build locator using exponential backoff, like Bitcoin Core.
        // Always includes the genesis hash so the peer knows our chain.
        let locators: Vec<BlockHash> = if self.header_chain.is_empty() {
            // We only know genesis – use it as the sole locator.
            vec![self.genesis_hash]
        } else {
            let mut locs = vec![];
            let mut step = 1usize;
            let mut idx = self.header_chain.len() - 1;
            loop {
                locs.push(self.header_chain[idx]);
                if idx == 0 {
                    break;
                }
                if idx < step {
                    // Jump to genesis
                    if self.header_chain[0] != *locs.last().unwrap() {
                        locs.push(self.header_chain[0]);
                    }
                    break;
                }
                idx -= step;
                // Start exponential backoff after 10 entries (matches Bitcoin Core)
                if locs.len() > 10 {
                    step *= 2;
                }
            }
            // Always include genesis as the last entry.
            let genesis = self.genesis_hash;
            if *locs.last().unwrap() != genesis {
                locs.push(genesis);
            }
            locs
        };

        // Serialize getheaders.
        let msg = NetMessage::GetHeaders {
            version: PROTOCOL_VERSION,
            locators,
            hash_stop: BlockHash::ZERO,
        };
        let payload = serialize_message(&msg);
        self.conn_manager
            .send_to_peer(peer_id, "getheaders", payload);

        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.headers_requested = true;
        }

        tracing::info!(
            peer_id = peer_id,
            header_chain_len = self.header_chain.len(),
            "sent getheaders"
        );
    }

    /// Send compact block negotiation (BIP 152).
    ///
    /// We send sendcmpct with version 2 (segwit-aware) to indicate we support
    /// compact blocks. We don't request high-bandwidth mode initially (announce=false).
    fn send_sendcmpct(&self, peer_id: u64) {
        let msg = NetMessage::SendCmpct {
            announce: false,
            version: 2,
        };
        let payload = serialize_message(&msg);
        self.conn_manager
            .send_to_peer(peer_id, "sendcmpct", payload);
    }

    /// Request blocks from a peer via getdata.
    ///
    /// Pulls hashes from `blocks_to_download` up to MAX_BLOCKS_IN_TRANSIT_PER_PEER
    /// and sends a getdata message.
    fn request_blocks(&mut self, peer_id: u64) {
        let state = match self.peer_states.get_mut(&peer_id) {
            Some(s) => s,
            None => return,
        };

        // Don't request if we already have too many in-flight.
        if state.blocks_in_flight.len() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER {
            return;
        }

        let available = MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.blocks_in_flight.len();
        let mut inv_list = Vec::new();

        for _ in 0..available {
            if let Some(hash) = self.blocks_to_download.pop_front() {
                if !self.blocks_downloaded.contains(&hash) {
                    state.blocks_in_flight.push((hash, Instant::now()));
                    inv_list.push(InvVect::new(
                        InvType::WitnessBlock,
                        qubitcoin_primitives::Uint256::from_bytes(*hash.data()),
                    ));
                }
            } else {
                break;
            }
        }

        if !inv_list.is_empty() {
            let count = inv_list.len();
            let msg = NetMessage::GetData(inv_list);
            let payload = serialize_message(&msg);
            self.conn_manager.send_to_peer(peer_id, "getdata", payload);
            tracing::debug!(peer_id = peer_id, count = count, "requesting blocks");
        }
    }

    /// Start block download by distributing blocks across all connected peers.
    fn start_block_download(&mut self) {
        let peer_ids: Vec<u64> = self
            .peer_states
            .iter()
            .filter(|(_, state)| state.handshake_complete && !state.discouraged)
            .map(|(&pid, _)| pid)
            .collect();
        tracing::info!(
            peers = peer_ids.len(),
            blocks_queued = self.blocks_to_download.len(),
            "starting block download from all peers"
        );
        for pid in peer_ids {
            self.request_blocks(pid);
        }
    }

    /// Mark a peer as misbehaving and disconnect them.
    ///
    /// In Bitcoin Core v30+, a single call to Misbehaving() immediately
    /// discourages the peer (no score accumulation). We follow the same
    /// approach.
    fn misbehaving(&mut self, peer_id: u64, reason: &str) {
        tracing::warn!(
            peer_id = peer_id,
            reason = reason,
            "peer misbehaving, discouraging"
        );
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.discouraged = true;
            state.discourage_reason = Some(reason.to_string());
        }
        // Disconnect the misbehaving peer.
        self.conn_manager.disconnect_peer(peer_id);
    }

    /// Check for stalled peers and head-of-line blocking.
    ///
    /// Two checks:
    /// 1. Peers whose oldest in-flight block exceeds `BLOCK_DOWNLOAD_TIMEOUT_BASE`
    ///    are disconnected and their blocks re-queued.
    /// 2. If the next block needed for chain-order processing has been in-flight
    ///    for longer than `BLOCK_STALLING_TIMEOUT`, re-request it from a faster
    ///    peer to break head-of-line blocking.
    fn check_stalled_peers(&mut self) {
        // --- 1. Hard timeout: disconnect completely stalled peers ---
        let timeout = std::time::Duration::from_secs(BLOCK_DOWNLOAD_TIMEOUT_BASE);
        let stalled: Vec<u64> = self
            .peer_states
            .iter()
            .filter_map(|(&pid, state)| {
                if let Some((_, oldest_time)) = state.blocks_in_flight.first() {
                    if oldest_time.elapsed() > timeout {
                        return Some(pid);
                    }
                }
                None
            })
            .collect();

        for peer_id in stalled {
            tracing::warn!(
                peer_id = peer_id,
                "peer stalled, re-queuing blocks and disconnecting"
            );
            // Re-queue all in-flight blocks from this peer.
            if let Some(state) = self.peer_states.get(&peer_id) {
                for (hash, _) in &state.blocks_in_flight {
                    self.blocks_to_download.push_back(*hash);
                }
            }
            // Mark discouraged and disconnect.
            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.discouraged = true;
                state.discourage_reason = Some("block download stall".to_string());
                state.blocks_in_flight.clear();
            }
            self.conn_manager.disconnect_peer(peer_id);
        }

        // --- 2. Head-of-line stall: re-request from a faster peer ---
        self.check_head_of_line_stall();

        // --- 3. Kick idle peers to download more blocks ---
        self.kick_idle_peers();
    }

    /// Detect head-of-line blocking and re-request the stalled block.
    ///
    /// If the next block needed for ordered processing has been in-flight on a
    /// peer for longer than `BLOCK_STALLING_TIMEOUT`, steal it from the slow
    /// peer and request it from a different peer with available capacity.
    fn check_head_of_line_stall(&mut self) {
        if self.next_process_idx >= self.header_chain.len() {
            return;
        }

        let head_hash = self.header_chain[self.next_process_idx];

        // Already in the buffer — drain_processable will handle it.
        if self.pending_blocks.contains_key(&head_hash) {
            // Try to drain now (might have been buffered since last drain).
            self.drain_processable();
            return;
        }

        // Block was downloaded but data is not buffered — the data was lost
        // (e.g. the block went through the non-IBD path and failed).  Remove
        // it from `blocks_downloaded` so it will be re-requested below.
        if self.blocks_downloaded.contains(&head_hash)
            && !self.pending_blocks.contains_key(&head_hash)
        {
            self.blocks_downloaded.remove(&head_hash);
            self.blocks_to_download.push_front(head_hash);
            tracing::info!(
                height = self.next_process_idx + 1,
                "re-queuing lost head-of-line block for download"
            );
        }

        let stall_timeout = std::time::Duration::from_secs(BLOCK_STALLING_TIMEOUT);

        // Find which peer has the head-of-line block in-flight.
        let mut slow_peer: Option<u64> = None;
        let mut in_any_flight = false;
        let mut stall_secs = 0u64;
        for (&pid, state) in &self.peer_states {
            if let Some((_, req_time)) = state.blocks_in_flight.iter().find(|(h, _)| *h == head_hash)
            {
                in_any_flight = true;
                let elapsed = req_time.elapsed();
                if elapsed > stall_timeout {
                    slow_peer = Some(pid);
                    stall_secs = elapsed.as_secs();
                }
                break;
            }
        }

        // If the block is not in ANY peer's in-flight list, it may have been
        // lost when a peer disconnected.  Re-queue it and request immediately.
        if !in_any_flight {
            self.blocks_to_download.push_front(head_hash);
            let peer_ids: Vec<u64> = self
                .peer_states
                .iter()
                .filter(|(_, s)| {
                    s.handshake_complete
                        && !s.discouraged
                        && s.blocks_in_flight.len() < MAX_BLOCKS_IN_TRANSIT_PER_PEER
                })
                .map(|(&pid, _)| pid)
                .collect();
            if !peer_ids.is_empty() {
                tracing::info!(
                    height = self.next_process_idx + 1,
                    peers = peer_ids.len(),
                    "head-of-line block not in-flight, re-requesting"
                );
                for pid in peer_ids {
                    self.request_blocks(pid);
                }
            }
            return;
        }

        let slow_pid = match slow_peer {
            Some(pid) => pid,
            None => return, // In-flight but not yet stalled.
        };

        // Find a different peer with capacity.  Allow one extra in-flight
        // block (over the normal limit) during stall recovery so that we
        // can always find a candidate even when all peers are at capacity.
        let fast_peer = self
            .peer_states
            .iter()
            .filter(|(&pid, state)| {
                pid != slow_pid
                    && state.handshake_complete
                    && !state.discouraged
                    && state.blocks_in_flight.len() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER
            })
            .min_by_key(|(_, state)| state.blocks_in_flight.len())
            .map(|(&pid, _)| pid);

        // Remove stalled block from slow peer first so we free a slot.
        if let Some(state) = self.peer_states.get_mut(&slow_pid) {
            state.blocks_in_flight.retain(|(h, _)| *h != head_hash);
        }

        if let Some(fast_pid) = fast_peer {
            tracing::info!(
                height = self.next_process_idx + 1,
                slow_peer = slow_pid,
                fast_peer = fast_pid,
                stall_secs = stall_secs,
                "re-requesting stalled head-of-line block"
            );

            // Assign to the faster peer.
            if let Some(state) = self.peer_states.get_mut(&fast_pid) {
                state.blocks_in_flight.push((head_hash, Instant::now()));
            }
            let inv = vec![InvVect::new(
                InvType::WitnessBlock,
                qubitcoin_primitives::Uint256::from_bytes(*head_hash.data()),
            )];
            let msg = NetMessage::GetData(inv);
            let payload = serialize_message(&msg);
            self.conn_manager.send_to_peer(fast_pid, "getdata", payload);

            // Fill the slow peer's freed slot with the next block from queue.
            self.request_blocks(slow_pid);
        } else {
            // All peers at capacity — re-queue the block and request from
            // the slow peer (which now has a freed slot).
            tracing::info!(
                height = self.next_process_idx + 1,
                slow_peer = slow_pid,
                stall_secs = stall_secs,
                "re-requesting stalled head-of-line block (no fast peer available)"
            );
            self.blocks_to_download.push_front(head_hash);
            self.request_blocks(slow_pid);
        }
    }

    /// Kick peers that have capacity but no in-flight blocks.
    ///
    /// After header sync, only one peer initially calls `request_blocks`.
    /// This ensures ALL connected peers participate in block download.
    fn kick_idle_peers(&mut self) {
        if self.blocks_to_download.is_empty() {
            return;
        }
        let idle_peers: Vec<u64> = self
            .peer_states
            .iter()
            .filter(|(_, state)| {
                state.handshake_complete
                    && !state.discouraged
                    && state.blocks_in_flight.is_empty()
            })
            .map(|(&pid, _)| pid)
            .collect();
        for pid in idle_peers {
            self.request_blocks(pid);
        }
    }

    /// Handle a single message from a peer.
    async fn handle_message(&mut self, peer_id: u64, message: NetMessage) {
        match message {
            NetMessage::Headers(ref headers) => {
                self.handle_headers(peer_id, headers);
            }
            NetMessage::Block(ref data) => {
                self.handle_block(peer_id, data);
            }
            NetMessage::Inv(ref inv) => {
                self.handle_inv(peer_id, inv);
            }
            NetMessage::GetData(ref inv) => {
                self.handle_getdata(peer_id, inv);
            }
            NetMessage::Tx(ref data) => {
                self.handle_tx(peer_id, data);
            }
            NetMessage::SendHeaders => {
                tracing::debug!(peer_id = peer_id, "peer prefers headers announcements");
                if let Some(state) = self.peer_states.get_mut(&peer_id) {
                    state.prefer_headers = true;
                }
            }
            NetMessage::SendCmpct { announce, version } => {
                tracing::debug!(
                    peer_id = peer_id,
                    announce = announce,
                    version = version,
                    "compact blocks negotiation"
                );
                if let Some(state) = self.peer_states.get_mut(&peer_id) {
                    if version == 1 || version == 2 {
                        state.prefer_cmpctblock = announce;
                        state.cmpctblock_version = version;
                    }
                }
            }
            NetMessage::FeeFilter(fee) => {
                tracing::debug!(peer_id = peer_id, fee = fee, "fee filter");
                if fee >= 0 {
                    if let Some(state) = self.peer_states.get_mut(&peer_id) {
                        state.min_fee_filter = fee;
                    }
                } else {
                    self.misbehaving(peer_id, "negative feefilter");
                }
            }
            NetMessage::WtxidRelay => {
                tracing::debug!(peer_id = peer_id, "peer supports wtxid relay");
                if let Some(state) = self.peer_states.get_mut(&peer_id) {
                    state.wtxid_relay = true;
                }
            }
            NetMessage::SendAddrV2 => {
                tracing::debug!(peer_id = peer_id, "peer supports addrv2");
                if let Some(state) = self.peer_states.get_mut(&peer_id) {
                    state.wants_addrv2 = true;
                }
            }
            NetMessage::SendTxRcncl { version, salt } => {
                tracing::debug!(
                    peer_id = peer_id,
                    version = version,
                    salt = salt,
                    "peer supports tx reconciliation"
                );
                // BIP 330: transaction reconciliation - acknowledged but not
                // fully implemented yet.
            }
            NetMessage::GetHeaders { ref locators, .. } => {
                self.handle_getheaders(peer_id, locators);
            }
            NetMessage::GetBlocks { .. } => {
                tracing::debug!(peer_id = peer_id, "received getblocks");
                // getblocks is a legacy protocol; we prefer getheaders.
                // We don't serve blocks via getblocks during IBD.
            }
            NetMessage::Addr(ref addrs) => {
                self.handle_addr(peer_id, addrs);
            }
            NetMessage::AddrV2(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received addrv2");
                // AddrV2 requires BIP 155 parsing - accepted but not fully parsed yet.
            }
            NetMessage::GetAddr => {
                self.handle_getaddr(peer_id);
            }
            NetMessage::NotFound(ref inv) => {
                tracing::debug!(peer_id = peer_id, count = inv.len(), "received notfound");
                // Remove in-flight blocks that were not found.
                if let Some(state) = self.peer_states.get_mut(&peer_id) {
                    for item in inv {
                        if item.inv_type == InvType::Block || item.inv_type == InvType::WitnessBlock
                        {
                            let hash = BlockHash::from_bytes(*item.hash.data());
                            state.blocks_in_flight.retain(|(h, _)| h != &hash);
                        }
                    }
                }
            }
            NetMessage::Reject {
                ref message,
                code,
                ref reason,
            } => {
                tracing::debug!(
                    peer_id = peer_id,
                    message = %message,
                    code = code,
                    reason = %reason,
                    "received reject"
                );
                // Reject messages are deprecated (BIP 61) but we still log them.
            }
            NetMessage::CmpctBlock(ref data) => {
                tracing::debug!(
                    peer_id = peer_id,
                    bytes = data.len(),
                    "received compact block"
                );
                // Compact block processing - accept and log for now.
                // Full BIP 152 reconstruction requires maintaining a tx mempool index.
            }
            NetMessage::GetBlockTxn(ref data) => {
                tracing::debug!(
                    peer_id = peer_id,
                    bytes = data.len(),
                    "received getblocktxn"
                );
                // We don't serve compact block transactions yet.
            }
            NetMessage::BlockTxn(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received blocktxn");
                // Compact block transaction response - accept and log.
            }
            NetMessage::FilterLoad(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received filterload");
                // BIP 37 bloom filter - accepted but not acted upon.
                // We don't support serving filtered blocks.
            }
            NetMessage::FilterAdd(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received filteradd");
            }
            NetMessage::FilterClear => {
                tracing::debug!(peer_id = peer_id, "received filterclear");
            }
            NetMessage::MerkleBlock(ref data) => {
                tracing::debug!(
                    peer_id = peer_id,
                    bytes = data.len(),
                    "received merkleblock"
                );
            }
            NetMessage::MemPool => {
                tracing::debug!(peer_id = peer_id, "received mempool request");
                // We don't serve mempool contents yet.
            }
            NetMessage::CFHeaders(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received cfheaders");
            }
            NetMessage::CFilter(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received cfilter");
            }
            NetMessage::CFCheckpt(ref data) => {
                tracing::debug!(peer_id = peer_id, bytes = data.len(), "received cfcheckpt");
            }
            NetMessage::GetCFHeaders { .. }
            | NetMessage::GetCFilters { .. }
            | NetMessage::GetCFCheckpt { .. } => {
                tracing::debug!(peer_id = peer_id, "received compact filter request");
                // We don't serve compact filters yet.
            }
            // Version/Verack/Ping/Pong are handled at the connection layer.
            NetMessage::Version(_)
            | NetMessage::Verack
            | NetMessage::Ping(_)
            | NetMessage::Pong(_) => {}
            NetMessage::Unknown {
                ref command,
                ref payload,
            } => {
                tracing::debug!(
                    peer_id = peer_id,
                    command = %command,
                    bytes = payload.len(),
                    "received unknown message"
                );
            }
        }
    }

    /// Handle received headers.
    fn handle_headers(&mut self, peer_id: u64, headers: &[Vec<u8>]) {
        let count = headers.len();
        tracing::info!(
            peer_id = peer_id,
            count = count,
            total = self.total_headers,
            "received headers"
        );

        if count == 0 {
            tracing::info!(
                "headers sync complete, {} total headers",
                self.total_headers
            );
            // If headers sync is done, start requesting blocks from all peers.
            if !self.blocks_to_download.is_empty() {
                self.start_block_download();
            }
            return;
        }

        // Enforce maximum headers per message.
        if count > MAX_HEADERS_RESULTS {
            self.misbehaving(peer_id, "too many headers");
            return;
        }

        // Parse and store header hashes, deduplicating across peers.
        let mut new_count = 0usize;
        for header_data in headers {
            if header_data.len() >= 80 {
                // The block hash is SHA256d of the 80-byte header.
                let hash_bytes = qubitcoin_crypto::hash::hash256(header_data);
                let hash = BlockHash::from_bytes(hash_bytes);
                // Only add if we haven't seen this header before.
                if self.header_set.insert(hash) {
                    self.header_chain.push(hash);
                    // Queue block for download.
                    if !self.blocks_downloaded.contains(&hash) {
                        self.blocks_to_download.push_back(hash);
                    }
                    self.total_headers += 1;
                    new_count += 1;
                }
            }
        }

        if new_count < count {
            tracing::debug!(
                peer_id = peer_id,
                new = new_count,
                duplicates = count - new_count,
                "deduplicated headers"
            );
        }

        // Update per-peer count.
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.headers_received += count as u64;
        }

        // Notify state change.
        self.notifier.on_headers_update(self.header_chain.len());

        // Log progress every 2000 headers.
        if self.total_headers % 2000 == 0 || new_count < count {
            tracing::info!(
                headers = self.total_headers,
                unique = self.header_chain.len(),
                "header sync progress"
            );
        }

        // If we got a full batch, there are likely more -- request next batch.
        if count >= MAX_HEADERS_RESULTS {
            self.send_getheaders(peer_id);
        } else {
            tracing::info!(
                total_headers = self.total_headers,
                blocks_queued = self.blocks_to_download.len(),
                "header download complete"
            );
            // IBD header phase complete. Start block download from all peers.
            self.start_block_download();
        }
    }

    /// Handle a received block.
    ///
    /// During IBD, blocks may arrive out of chain order (from multiple peers).
    /// We buffer them in `pending_blocks` and process in `header_chain` order
    /// via `drain_processable()`.
    fn handle_block(&mut self, peer_id: u64, data: &[u8]) {
        self.blocks_received += 1;

        // Extract block hash from the 80-byte header.
        let block_hash = if data.len() >= 80 {
            let hash_bytes = qubitcoin_crypto::hash::hash256(&data[..80]);
            Some(BlockHash::from_bytes(hash_bytes))
        } else {
            None
        };

        tracing::debug!(
            peer_id = peer_id,
            bytes = data.len(),
            blocks = self.blocks_received,
            "received block"
        );

        // Mark block as downloaded and remove from in-flight.
        if let Some(hash) = block_hash {
            self.blocks_downloaded.insert(hash);
            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.blocks_in_flight.retain(|(h, _)| h != &hash);
            }

            // Request more blocks if we have room.
            self.request_blocks(peer_id);
        }

        // Notify state change.
        self.notifier.on_block_received(self.blocks_received);

        // Decide whether to buffer (IBD) or process immediately (post-IBD).
        let is_ibd_block = block_hash
            .map(|h| self.header_set.contains(&h))
            .unwrap_or(false);

        if is_ibd_block {
            let hash = block_hash.unwrap();
            // Buffer the block for ordered processing.
            self.pending_blocks.insert(hash, (peer_id, data.to_vec()));
            // Drain all processable blocks in chain order.
            self.drain_processable();
        } else {
            // Non-IBD block (inv/getdata announcement): process immediately.
            let in_ibd = self.next_process_idx < self.header_chain.len();
            match self.node.process_block(data) {
                Ok(true) => {
                    tracing::info!(blocks = self.blocks_received, "block accepted");
                }
                Ok(false) => {
                    tracing::debug!(
                        peer_id = peer_id,
                        "block not accepted (already have or invalid)"
                    );
                }
                Err(reason) => {
                    if in_ibd {
                        // During IBD, unsolicited blocks (e.g. inv-announced
                        // tip blocks) will fail because their ancestors aren't
                        // in block_index yet.  Don't punish the peer for this.
                        tracing::debug!(
                            peer_id = peer_id,
                            reason = %reason,
                            "ignoring unsolicited block during IBD"
                        );
                    } else {
                        tracing::warn!(peer_id = peer_id, reason = %reason, "block rejected");
                        self.misbehaving(peer_id, &format!("invalid block: {}", reason));
                    }
                }
            }
        }
    }

    /// Process buffered blocks in `header_chain` order.
    ///
    /// During IBD, blocks arrive from multiple peers out of order. This method
    /// walks `header_chain` from `next_process_idx` and processes every block
    /// whose data is already in `pending_blocks`, stopping at the first gap.
    fn drain_processable(&mut self) {
        let start_idx = self.next_process_idx;
        while self.next_process_idx < self.header_chain.len() {
            let hash = self.header_chain[self.next_process_idx];
            if let Some((peer_id, data)) = self.pending_blocks.remove(&hash) {
                match self.node.process_block(&data) {
                    Ok(true) => {
                        let height = self.next_process_idx + 1;
                        // Log every 1000 blocks or first 100 blocks for progress.
                        if height <= 100 || height % 1000 == 0 {
                            tracing::info!(
                                height = height,
                                pending = self.pending_blocks.len(),
                                "block accepted"
                            );
                        }
                    }
                    Ok(false) => {
                        tracing::debug!("block not accepted (already have or invalid)");
                    }
                    Err(reason) => {
                        tracing::error!(
                            peer_id = peer_id,
                            height = self.next_process_idx + 1,
                            hash = %hash,
                            reason = %reason,
                            "block rejected during ordered processing, skipping"
                        );
                        // Advance past the failed block to avoid a permanent
                        // stall.  The header was already inserted into the
                        // block_index by accept_block_header (inside
                        // process_new_block) even if the body failed, so
                        // subsequent blocks can still reference it as a parent.
                    }
                }
                self.next_process_idx += 1;
                self.last_drain_time = Instant::now();
            } else {
                // Next block in chain order hasn't arrived yet.
                break;
            }
        }
        let processed = self.next_process_idx - start_idx;
        let height = self.next_process_idx;
        if processed > 0 && (height <= 100 || height % 1000 == 0 || processed >= 10) {
            tracing::info!(
                height = height,
                batch = processed,
                pending = self.pending_blocks.len(),
                queued = self.blocks_to_download.len(),
                "drain batch complete"
            );
        }
    }

    /// Handle an inv announcement.
    fn handle_inv(&mut self, peer_id: u64, inv: &[InvVect]) {
        if inv.len() > MAX_INV_SIZE {
            self.misbehaving(peer_id, "inv message too large");
            return;
        }

        tracing::debug!(peer_id = peer_id, count = inv.len(), "received inv");

        let mut blocks_to_request = Vec::new();

        for item in inv {
            let hash = BlockHash::from_bytes(*item.hash.data());

            match item.inv_type {
                InvType::Block | InvType::WitnessBlock => {
                    if !self.seen_inv.contains(&hash) && !self.blocks_downloaded.contains(&hash) {
                        self.seen_inv.insert(hash);
                        blocks_to_request.push(InvVect::new(InvType::WitnessBlock, item.hash));
                    }
                }
                InvType::Tx | InvType::WitnessTx => {
                    // Track seen transactions.
                    if let Some(state) = self.peer_states.get_mut(&peer_id) {
                        state.known_inv.insert(hash);
                    }
                    // During IBD, ignore tx announcements.
                    if !self.is_ibd && !self.node.has_transaction(&item.hash) {
                        // Request the transaction we don't have.
                        let getdata = vec![InvVect::new(InvType::WitnessTx, item.hash)];
                        let msg = NetMessage::GetData(getdata);
                        let payload = serialize_message(&msg);
                        self.conn_manager.send_to_peer(peer_id, "getdata", payload);
                    }
                }
                _ => {}
            }
        }

        // Request announced blocks we don't have.
        if !blocks_to_request.is_empty() {
            let count = blocks_to_request.len();
            let msg = NetMessage::GetData(blocks_to_request);
            let payload = serialize_message(&msg);
            self.conn_manager.send_to_peer(peer_id, "getdata", payload);
            tracing::debug!(
                peer_id = peer_id,
                count = count,
                "requesting announced blocks"
            );
        }
    }

    /// Handle a getdata request from a peer.
    fn handle_getdata(&mut self, peer_id: u64, inv: &[InvVect]) {
        if inv.len() > MAX_INV_SIZE {
            self.misbehaving(peer_id, "getdata message too large");
            return;
        }
        tracing::debug!(peer_id = peer_id, count = inv.len(), "peer requests items");

        for item in inv {
            let hash = BlockHash::from_bytes(*item.hash.data());
            match item.inv_type {
                InvType::Block | InvType::WitnessBlock => {
                    if let Some(block_data) = self.node.get_block(&hash) {
                        self.conn_manager.send_to_peer(peer_id, "block", block_data);
                    } else {
                        tracing::trace!(peer_id = peer_id, "requested block not found");
                    }
                }
                InvType::Tx | InvType::WitnessTx => {
                    if let Some(tx_data) = self.node.get_transaction(&item.hash) {
                        self.conn_manager.send_to_peer(peer_id, "tx", tx_data);
                    } else {
                        tracing::trace!(peer_id = peer_id, "requested tx not found");
                    }
                }
                _ => {}
            }
        }
    }

    /// Handle a received transaction.
    fn handle_tx(&mut self, peer_id: u64, data: &[u8]) {
        self.txns_received += 1;
        tracing::debug!(
            peer_id = peer_id,
            bytes = data.len(),
            total_txns = self.txns_received,
            "received tx"
        );
        // Validate transaction and add to mempool via the node interface.
        match self.node.process_transaction(data) {
            Ok(true) => {
                tracing::debug!(
                    peer_id = peer_id,
                    total_txns = self.txns_received,
                    "tx accepted to mempool"
                );
            }
            Ok(false) => {
                tracing::trace!(peer_id = peer_id, "tx not accepted (duplicate or policy)");
            }
            Err(reason) => {
                tracing::debug!(peer_id = peer_id, reason = %reason, "tx rejected");
            }
        }
    }

    /// Handle a getheaders request from a peer.
    fn handle_getheaders(&self, peer_id: u64, locators: &[BlockHash]) {
        tracing::debug!(
            peer_id = peer_id,
            locators = locators.len(),
            "peer sent getheaders"
        );

        // Find the fork point in our header chain.
        let start_idx = if locators.is_empty() {
            0
        } else {
            let mut found_idx = None;
            for locator in locators {
                if let Some(idx) = self.header_chain.iter().position(|h| h == locator) {
                    found_idx = Some(idx + 1); // Start after the found locator.
                    break;
                }
            }
            found_idx.unwrap_or(0)
        };

        // Send up to MAX_HEADERS_RESULTS headers starting from the fork point.
        let _end_idx = (start_idx + MAX_HEADERS_RESULTS).min(self.header_chain.len());
        if start_idx >= self.header_chain.len() {
            // Nothing to send.
            self.conn_manager.send_to_peer(
                peer_id,
                "headers",
                serialize_message(&NetMessage::Headers(vec![])),
            );
            return;
        }

        // We only have hashes, not full 80-byte headers.
        // Serving headers requires the block index to store raw headers.
        // For now, log that we can't serve them.
        tracing::debug!(
            peer_id = peer_id,
            "cannot serve headers (raw headers not stored)"
        );
    }

    /// Handle received addresses.
    fn handle_addr(&self, peer_id: u64, addrs: &[(u32, crate::protocol::NetAddress)]) {
        if addrs.len() > MAX_ADDR_TO_SEND {
            tracing::debug!(
                peer_id = peer_id,
                count = addrs.len(),
                max = MAX_ADDR_TO_SEND,
                "addr message too large, ignoring excess"
            );
        }
        tracing::debug!(peer_id = peer_id, count = addrs.len(), "received addresses");

        // Add addresses to our address book via the node interface.
        let limit = addrs.len().min(MAX_ADDR_TO_SEND);
        for (_timestamp, net_addr) in &addrs[..limit] {
            let socket_addr = SocketAddr::new(net_addr.ip, net_addr.port);
            self.node.add_address(socket_addr);
        }
    }

    /// Handle a getaddr request from a peer.
    fn handle_getaddr(&self, peer_id: u64) {
        tracing::debug!(peer_id = peer_id, "peer requests addresses");

        // Get addresses from our address book via the node interface.
        let our_addrs = self.node.get_addresses(MAX_ADDR_TO_SEND);
        let addr_entries: Vec<_> = our_addrs
            .into_iter()
            .map(|sa| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                (
                    now,
                    crate::protocol::NetAddress::new(
                        crate::protocol::ServiceFlags::NODE_NETWORK,
                        sa.ip(),
                        sa.port(),
                    ),
                )
            })
            .collect();

        let msg = NetMessage::Addr(addr_entries);
        let payload = serialize_message(&msg);
        self.conn_manager.send_to_peer(peer_id, "addr", payload);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{ConnConfig, ConnManager};
    use std::net::SocketAddr;

    /// Helper to create a ConnManager wrapped in Arc for testing.
    fn make_test_conn_manager() -> Arc<ConnManager> {
        Arc::new(ConnManager::new(ConnConfig::default()))
    }

    fn make_test_processor(rx: mpsc::UnboundedReceiver<ConnectionEvent>) -> NetProcessor {
        let cm = make_test_conn_manager();
        NetProcessor::new(rx, cm, BlockHash::ZERO)
    }

    #[tokio::test]
    async fn test_net_processor_creation() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let processor = make_test_processor(rx);
        assert!(processor.is_ibd);
        assert_eq!(processor.total_headers, 0);
        assert_eq!(processor.blocks_received, 0);
        assert_eq!(processor.txns_received, 0);
    }

    #[tokio::test]
    async fn test_net_processor_processes_handshake() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        // Drop sender so the loop terminates.
        drop(tx);

        // run() should process the event and return when the channel closes.
        processor.run().await;

        // After handshake the peer should be tracked.
        assert!(processor.peer_states.contains_key(&1));
        assert!(processor.peer_states[&1].handshake_complete);
    }

    #[tokio::test]
    async fn test_net_processor_handles_disconnect() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::Disconnected {
            peer_id: 1,
            reason: "test".to_string(),
        })
        .unwrap();
        drop(tx);

        processor.run().await;

        // Peer should be removed after disconnect.
        assert!(!processor.peer_states.contains_key(&1));
    }

    #[tokio::test]
    async fn test_net_processor_handles_messages() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();

        tx.send(ConnectionEvent::NewInbound { peer_id: 1, addr })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Verack,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Ping(42),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendHeaders,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::FeeFilter(1000),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Inv(vec![]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::GetData(vec![]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Headers(vec![]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Block(vec![0; 80]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Tx(vec![0; 50]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::GetAddr,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Unknown {
                command: "foo".to_string(),
                payload: vec![],
            },
        })
        .unwrap();
        // Test new message types
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::WtxidRelay,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendAddrV2,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendTxRcncl {
                version: 1,
                salt: 42,
            },
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::CmpctBlock(vec![0; 100]),
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::FilterClear,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::MemPool,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::AddrV2(vec![1, 2, 3]),
        })
        .unwrap();
        drop(tx);

        processor.run().await;
    }

    #[tokio::test]
    async fn test_net_processor_empty_channel() {
        let (tx, rx) = mpsc::unbounded_channel::<ConnectionEvent>();
        let mut processor = make_test_processor(rx);
        drop(tx);
        // Should return immediately since channel is closed.
        processor.run().await;
    }

    #[tokio::test]
    async fn test_net_processor_headers_sync() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        // Simulate handshake.
        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Simulate receiving 3 headers (each 80 bytes).
        let headers: Vec<Vec<u8>> = (0..3).map(|i| vec![i as u8; 80]).collect();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Headers(headers),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        // We should have accumulated 3 headers.
        assert_eq!(processor.total_headers, 3);
        assert_eq!(processor.header_chain.len(), 3);
        // 3 blocks were queued and then moved to in-flight via request_blocks.
        let state = &processor.peer_states[&1];
        assert_eq!(state.blocks_in_flight.len(), 3);
    }

    #[tokio::test]
    async fn test_net_processor_feature_negotiation() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Send feature negotiation messages.
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::WtxidRelay,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendAddrV2,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendHeaders,
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendCmpct {
                announce: true,
                version: 2,
            },
        })
        .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::FeeFilter(1000),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        let state = &processor.peer_states[&1];
        assert!(state.wtxid_relay);
        assert!(state.wants_addrv2);
        assert!(state.prefer_headers);
        assert!(state.prefer_cmpctblock);
        assert_eq!(state.cmpctblock_version, 2);
        assert_eq!(state.min_fee_filter, 1000);
    }

    #[tokio::test]
    async fn test_net_processor_inv_handling() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Send inv with a block.
        let block_hash = qubitcoin_primitives::Uint256::from_bytes([0x42; 32]);
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Inv(vec![InvVect::new(InvType::Block, block_hash)]),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        // Block hash should be in seen_inv.
        let hash = BlockHash::from_bytes([0x42; 32]);
        assert!(processor.seen_inv.contains(&hash));
    }

    #[tokio::test]
    async fn test_net_processor_block_received() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        // Send a block.
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Block(vec![0xab; 285]),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        assert_eq!(processor.blocks_received, 1);
    }

    #[tokio::test]
    async fn test_net_processor_tx_received() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Tx(vec![0; 100]),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        assert_eq!(processor.txns_received, 1);
    }

    #[tokio::test]
    async fn test_net_processor_misbehaving_negative_feefilter() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::FeeFilter(-1),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        assert!(processor.peer_states[&1].discouraged);
    }

    #[tokio::test]
    async fn test_net_processor_misbehaving_oversized_inv() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Send an inv that exceeds MAX_INV_SIZE.
        let oversized_inv: Vec<InvVect> = (0..MAX_INV_SIZE + 1)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                InvVect::new(
                    InvType::Tx,
                    qubitcoin_primitives::Uint256::from_bytes(bytes),
                )
            })
            .collect();

        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Inv(oversized_inv),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        assert!(processor.peer_states[&1].discouraged);
    }

    #[tokio::test]
    async fn test_net_processor_notfound_clears_inflight() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Manually add a block to in-flight.
        let block_hash = BlockHash::from_bytes([0x42; 32]);
        if let Some(state) = processor.peer_states.get_mut(&1) {
            state.blocks_in_flight.push((block_hash, Instant::now()));
        }

        // Send notfound for that block.
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::NotFound(vec![InvVect::new(
                InvType::Block,
                qubitcoin_primitives::Uint256::from_bytes([0x42; 32]),
            )]),
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        assert!(processor.peer_states[&1].blocks_in_flight.is_empty());
    }

    #[tokio::test]
    async fn test_peer_sync_state_creation() {
        let state = PeerSyncState::new();
        assert!(!state.handshake_complete);
        assert!(!state.headers_requested);
        assert_eq!(state.headers_received, 0);
        assert!(state.blocks_in_flight.is_empty());
        assert!(!state.wtxid_relay);
        assert!(!state.wants_addrv2);
        assert!(!state.prefer_headers);
        assert!(!state.prefer_cmpctblock);
        assert_eq!(state.cmpctblock_version, 0);
        assert_eq!(state.min_fee_filter, 0);
        assert!(!state.discouraged);
    }

    #[tokio::test]
    async fn test_peer_sync_state_activity() {
        let mut state = PeerSyncState::new();
        let before = state.last_activity;
        std::thread::sleep(std::time::Duration::from_millis(1));
        state.mark_activity();
        assert!(state.last_activity > before);
    }

    #[tokio::test]
    async fn test_net_processor_sendcmpct_negotiation() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_test_processor(rx);

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();

        // Reject invalid version.
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::SendCmpct {
                announce: true,
                version: 99,
            },
        })
        .unwrap();

        drop(tx);
        processor.run().await;

        // Invalid version should not enable compact blocks.
        let state = &processor.peer_states[&1];
        assert!(!state.prefer_cmpctblock);
        assert_eq!(state.cmpctblock_version, 0);
    }

    // --- NodeInterface tests ---

    /// Mock NodeInterface that tracks calls for testing.
    struct MockNode {
        blocks_processed: std::sync::Mutex<Vec<Vec<u8>>>,
        txns_processed: std::sync::Mutex<Vec<Vec<u8>>>,
        addrs_added: std::sync::Mutex<Vec<SocketAddr>>,
        accept_blocks: bool,
        accept_txns: bool,
    }

    impl MockNode {
        fn new(accept_blocks: bool, accept_txns: bool) -> Self {
            MockNode {
                blocks_processed: std::sync::Mutex::new(Vec::new()),
                txns_processed: std::sync::Mutex::new(Vec::new()),
                addrs_added: std::sync::Mutex::new(Vec::new()),
                accept_blocks,
                accept_txns,
            }
        }
    }

    impl NodeInterface for MockNode {
        fn process_block(&self, data: &[u8]) -> Result<bool, String> {
            self.blocks_processed.lock().unwrap().push(data.to_vec());
            if self.accept_blocks {
                Ok(true)
            } else {
                Err("test rejection".to_string())
            }
        }

        fn process_transaction(&self, data: &[u8]) -> Result<bool, String> {
            self.txns_processed.lock().unwrap().push(data.to_vec());
            if self.accept_txns {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn has_transaction(&self, _txid: &Uint256) -> bool {
            false
        }

        fn get_block(&self, _hash: &BlockHash) -> Option<Vec<u8>> {
            Some(vec![0xBB; 80]) // dummy block
        }

        fn get_transaction(&self, _txid: &Uint256) -> Option<Vec<u8>> {
            Some(vec![0xCC; 50])
        }

        fn chain_height(&self) -> i32 {
            100
        }

        fn add_address(&self, addr: SocketAddr) {
            self.addrs_added.lock().unwrap().push(addr);
        }

        fn get_addresses(&self, max: usize) -> Vec<SocketAddr> {
            let mut addrs = vec![
                "1.2.3.4:8333".parse().unwrap(),
                "5.6.7.8:8333".parse().unwrap(),
            ];
            addrs.truncate(max);
            addrs
        }
    }

    fn make_mock_processor(
        rx: mpsc::UnboundedReceiver<ConnectionEvent>,
        node: Arc<dyn NodeInterface>,
    ) -> NetProcessor {
        let cm = make_test_conn_manager();
        NetProcessor::with_node(rx, cm, BlockHash::ZERO, node)
    }

    #[tokio::test]
    async fn test_node_interface_block_processing() {
        let node = Arc::new(MockNode::new(true, true));
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_mock_processor(rx, node.clone());

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Block(vec![0xAA; 100]),
        })
        .unwrap();
        drop(tx);

        processor.run().await;

        let blocks = node.blocks_processed.lock().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 100);
    }

    #[tokio::test]
    async fn test_node_interface_tx_processing() {
        let node = Arc::new(MockNode::new(true, true));
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_mock_processor(rx, node.clone());

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Tx(vec![0xDD; 50]),
        })
        .unwrap();
        drop(tx);

        processor.run().await;

        let txns = node.txns_processed.lock().unwrap();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].len(), 50);
    }

    #[tokio::test]
    async fn test_node_interface_block_rejection_misbehaves() {
        let node = Arc::new(MockNode::new(false, true));
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_mock_processor(rx, node.clone());

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Block(vec![0xAA; 100]),
        })
        .unwrap();
        drop(tx);

        processor.run().await;

        // Peer should be discouraged after sending an invalid block.
        let state = &processor.peer_states[&1];
        assert!(state.discouraged);
    }

    #[tokio::test]
    async fn test_node_interface_addr_processing() {
        use crate::protocol::{NetAddress, ServiceFlags};

        let node = Arc::new(MockNode::new(true, true));
        let (tx, rx) = mpsc::unbounded_channel();
        let mut processor = make_mock_processor(rx, node.clone());

        let addr_list = vec![
            (
                1000,
                NetAddress::new(
                    ServiceFlags::NODE_NETWORK,
                    "10.0.0.1".parse().unwrap(),
                    8333,
                ),
            ),
            (
                1001,
                NetAddress::new(
                    ServiceFlags::NODE_NETWORK,
                    "10.0.0.2".parse().unwrap(),
                    8333,
                ),
            ),
        ];

        tx.send(ConnectionEvent::HandshakeComplete { peer_id: 1 })
            .unwrap();
        tx.send(ConnectionEvent::MessageReceived {
            peer_id: 1,
            message: NetMessage::Addr(addr_list),
        })
        .unwrap();
        drop(tx);

        processor.run().await;

        let addrs = node.addrs_added.lock().unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].ip().to_string(), "10.0.0.1");
        assert_eq!(addrs[1].ip().to_string(), "10.0.0.2");
    }

    #[tokio::test]
    async fn test_null_node_interface() {
        let null_node = NullNodeInterface;
        assert_eq!(null_node.process_block(&[]).unwrap(), false);
        assert_eq!(null_node.process_transaction(&[]).unwrap(), false);
        assert!(!null_node.has_transaction(&Uint256::ZERO));
        assert!(null_node.get_block(&BlockHash::ZERO).is_none());
        assert!(null_node.get_transaction(&Uint256::ZERO).is_none());
        assert_eq!(null_node.chain_height(), 0);
        assert!(null_node.get_addresses(10).is_empty());
    }

    #[tokio::test]
    async fn test_with_node_constructor() {
        let node = Arc::new(NullNodeInterface);
        let (_tx, rx) = mpsc::unbounded_channel();
        let cm = make_test_conn_manager();
        let processor = NetProcessor::with_node(rx, cm, BlockHash::ZERO, node);
        assert!(processor.is_ibd);
    }
}
