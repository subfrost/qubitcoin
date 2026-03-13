//! Bitcoin protocol message types.
//!
//! Maps to: src/protocol.h, src/protocol.cpp
//!
//! Provides:
//! - `NetworkMagic`: Network identification magic bytes
//! - `MessageHeader`: 24-byte message header with checksum
//! - `ServiceFlags`: Bitflags for advertised node services
//! - `NetAddress`: Network address with services
//! - `InvType`, `InvVect`: Inventory vector types
//! - `NetMessage`: All P2P protocol messages
//! - `VersionMessage`: Version handshake message

use qubitcoin_crypto::hash::hash256;
use qubitcoin_primitives::{BlockHash, Uint256};

/// Current protocol version.
pub const PROTOCOL_VERSION: u32 = 70016;

/// Minimum peer protocol version we will connect to.
/// Peers older than this are disconnected.
pub const MIN_PEER_PROTO_VERSION: u32 = 31800;

/// Maximum payload size (4 MB, matching Bitcoin Core's MAX_SIZE for messages).
pub const MAX_PAYLOAD_SIZE: u32 = 4_000_000;

/// Maximum number of inventory items in a single inv/getdata message.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum number of headers in a single headers message.
pub const MAX_HEADERS_RESULTS: usize = 2000;

/// Maximum number of blocks we request from a single peer at once.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 32;

/// Maximum number of addresses in a single addr/addrv2 message.
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Maximum number of unconnecting headers before triggering DoS.
pub const MAX_UNCONNECTING_HEADERS: usize = 10;

/// Inactivity timeout (20 minutes, matching Bitcoin Core's TIMEOUT_INTERVAL).
pub const TIMEOUT_INTERVAL: u64 = 20 * 60;

/// Time between pings (2 minutes).
pub const PING_INTERVAL: u64 = 2 * 60;

/// Headers download timeout base in seconds.
pub const HEADERS_DOWNLOAD_TIMEOUT_BASE: u64 = 15 * 60;

/// Block stalling timeout in seconds.
/// After this, the head-of-line block is reassigned to a faster peer.
pub const BLOCK_STALLING_TIMEOUT: u64 = 8;

/// Block download timeout base in seconds.
/// Bitcoin Core uses pow_target_spacing (600s) * 1 = 600s.
pub const BLOCK_DOWNLOAD_TIMEOUT_BASE: u64 = 600;

/// BIP 152 compact blocks version 1 (pre-segwit).
pub const CMPCT_BLOCK_VERSION_1: u64 = 1;

/// BIP 152 compact blocks version 2 (segwit).
pub const CMPCT_BLOCK_VERSION_2: u64 = 2;

/// Protocol version at which `sendheaders` feature was introduced (BIP 130).
pub const SENDHEADERS_VERSION: u32 = 70012;

/// Protocol version at which `feefilter` feature was introduced (BIP 133).
pub const FEEFILTER_VERSION: u32 = 70013;

/// Protocol version at which compact blocks were introduced (BIP 152).
pub const SHORT_IDS_BLOCKS_VERSION: u32 = 70014;

/// Protocol version at which `wtxidrelay` was introduced (BIP 339).
pub const WTXID_RELAY_VERSION: u32 = 70016;

// ---------------------------------------------------------------------------
// NetworkMagic
// ---------------------------------------------------------------------------

/// Network magic bytes identifying which network a message belongs to.
///
/// These are the first 4 bytes of every P2P message and are used to detect
/// the start of a message in the TCP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkMagic(
    /// The 4-byte magic value.
    pub [u8; 4],
);

impl NetworkMagic {
    /// Mainnet magic: 0xf9beb4d9
    pub const MAINNET: Self = NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9]);
    /// Testnet3 magic: 0x0b110907
    pub const TESTNET: Self = NetworkMagic([0x0b, 0x11, 0x09, 0x07]);
    /// Regtest magic: 0xfabfb5da
    pub const REGTEST: Self = NetworkMagic([0xfa, 0xbf, 0xb5, 0xda]);
    /// Testnet4 magic: 0x1c163f28
    pub const TESTNET4: Self = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]);
    /// Signet magic: 0x0a03cf40
    pub const SIGNET: Self = NetworkMagic([0x0a, 0x03, 0xcf, 0x40]);
}

// ---------------------------------------------------------------------------
// MessageHeader
// ---------------------------------------------------------------------------

/// Message header (24 bytes total).
///
/// Layout:
/// - magic: 4 bytes - network identification
/// - command: 12 bytes - null-padded ASCII command string
/// - payload_size: 4 bytes - little-endian payload length
/// - checksum: 4 bytes - first 4 bytes of SHA256d(payload)
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Network magic bytes identifying the network (mainnet, testnet, etc.).
    pub magic: NetworkMagic,
    /// Null-padded 12-byte ASCII command string (e.g., `"version\0\0\0\0\0"`).
    pub command: [u8; 12],
    /// Length of the message payload in bytes (little-endian on the wire).
    pub payload_size: u32,
    /// First 4 bytes of SHA256d(payload), used for integrity verification.
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Create a new message header, computing the checksum from the payload.
    pub fn new(magic: NetworkMagic, command: &str, payload: &[u8]) -> Self {
        let mut cmd_bytes = [0u8; 12];
        let cmd_len = command.len().min(12);
        cmd_bytes[..cmd_len].copy_from_slice(&command.as_bytes()[..cmd_len]);

        let hash = hash256(payload);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash[..4]);

        MessageHeader {
            magic,
            command: cmd_bytes,
            payload_size: payload.len() as u32,
            checksum,
        }
    }

    /// Extract the command string, stripping trailing null bytes.
    pub fn command_str(&self) -> &str {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(12);
        // Safety: command bytes should be valid ASCII. If they are not, fall back
        // to returning up to the first invalid byte.
        std::str::from_utf8(&self.command[..end]).unwrap_or("")
    }

    /// Verify the checksum against the given payload.
    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        let hash = hash256(payload);
        self.checksum == hash[..4]
    }

    /// Serialize the header to a 24-byte array.
    pub fn serialize(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&self.magic.0);
        buf[4..16].copy_from_slice(&self.command);
        buf[16..20].copy_from_slice(&self.payload_size.to_le_bytes());
        buf[20..24].copy_from_slice(&self.checksum);
        buf
    }

    /// Deserialize a header from a 24-byte array.
    pub fn deserialize(data: &[u8; 24]) -> Self {
        let mut magic_bytes = [0u8; 4];
        magic_bytes.copy_from_slice(&data[0..4]);

        let mut command = [0u8; 12];
        command.copy_from_slice(&data[4..16]);

        let payload_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&data[20..24]);

        MessageHeader {
            magic: NetworkMagic(magic_bytes),
            command,
            payload_size,
            checksum,
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceFlags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Service flags advertised in `version` messages.
    ///
    /// These indicate what services a node offers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ServiceFlags: u64 {
        /// No services.
        const NODE_NONE = 0;
        /// Full node - can serve full blocks.
        const NODE_NETWORK = 1 << 0;
        /// BIP 111 - supports bloom filtering.
        const NODE_BLOOM = 1 << 2;
        /// BIP 144 - supports segregated witness.
        const NODE_WITNESS = 1 << 3;
        /// BIP 157/158 - supports compact block filters.
        const NODE_COMPACT_FILTERS = 1 << 6;
        /// BIP 159 - limited node (only last 288 blocks).
        const NODE_NETWORK_LIMITED = 1 << 10;
        /// BIP 324 - supports v2 P2P transport.
        const NODE_P2P_V2 = 1 << 11;
    }
}

impl Default for ServiceFlags {
    fn default() -> Self {
        ServiceFlags::NODE_NONE
    }
}

// ---------------------------------------------------------------------------
// NetAddress
// ---------------------------------------------------------------------------

/// Network address with associated service flags.
///
/// Maps to CAddress / CService in Bitcoin Core.
#[derive(Debug, Clone)]
pub struct NetAddress {
    /// Bitfield of services advertised by this address.
    pub services: ServiceFlags,
    /// IP address (IPv4 or IPv6).
    pub ip: std::net::IpAddr,
    /// TCP port number.
    pub port: u16,
}

impl NetAddress {
    /// Create a new network address.
    pub fn new(services: ServiceFlags, ip: std::net::IpAddr, port: u16) -> Self {
        NetAddress { services, ip, port }
    }

    /// Return the socket address (ip:port).
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip, self.port)
    }
}

// ---------------------------------------------------------------------------
// InvType / InvVect
// ---------------------------------------------------------------------------

/// Inventory vector type, indicating what kind of data object is referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InvType {
    /// Error or unrecognized inventory type.
    Error = 0,
    /// Transaction identified by txid.
    Tx = 1,
    /// Block identified by block hash.
    Block = 2,
    /// Filtered block (BIP 37 bloom filter match).
    FilteredBlock = 3,
    /// Compact block (BIP 152).
    CompactBlock = 4,
    /// BIP 339: witness transaction identified by wtxid.
    WTx = 5,
    /// Witness-serialized transaction (`MSG_TX | MSG_WITNESS_FLAG`).
    WitnessTx = 0x40000001,
    /// Witness-serialized block (`MSG_BLOCK | MSG_WITNESS_FLAG`).
    WitnessBlock = 0x40000002,
    /// Witness-serialized filtered block (`MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG`).
    WitnessFilteredBlock = 0x40000003,
}

impl InvType {
    /// Convert from a raw u32 value.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(InvType::Error),
            1 => Some(InvType::Tx),
            2 => Some(InvType::Block),
            3 => Some(InvType::FilteredBlock),
            4 => Some(InvType::CompactBlock),
            5 => Some(InvType::WTx),
            0x40000001 => Some(InvType::WitnessTx),
            0x40000002 => Some(InvType::WitnessBlock),
            0x40000003 => Some(InvType::WitnessFilteredBlock),
            _ => None,
        }
    }

    /// Convert to raw u32 value.
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    /// Returns the witness-stripped type for a witness inventory type.
    pub fn without_witness(self) -> Self {
        match self {
            InvType::WitnessTx => InvType::Tx,
            InvType::WitnessBlock => InvType::Block,
            InvType::WitnessFilteredBlock => InvType::FilteredBlock,
            other => other,
        }
    }

    /// Returns the witness version of this inventory type.
    pub fn with_witness(self) -> Self {
        match self {
            InvType::Tx => InvType::WitnessTx,
            InvType::Block => InvType::WitnessBlock,
            InvType::FilteredBlock => InvType::WitnessFilteredBlock,
            other => other,
        }
    }

    /// Returns true if this is a witness-serialized type.
    pub fn is_witness(self) -> bool {
        matches!(
            self,
            InvType::WitnessTx | InvType::WitnessBlock | InvType::WitnessFilteredBlock
        )
    }
}

/// Inventory vector: a type and a hash identifying a data object on the network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InvVect {
    /// The type of data object this inventory entry refers to.
    pub inv_type: InvType,
    /// The 256-bit hash identifying the data object (block hash or txid).
    pub hash: Uint256,
}

impl InvVect {
    /// Create a new inventory vector.
    pub fn new(inv_type: InvType, hash: Uint256) -> Self {
        InvVect { inv_type, hash }
    }
}

// ---------------------------------------------------------------------------
// VersionMessage
// ---------------------------------------------------------------------------

/// Version handshake message (the first message sent by both peers).
///
/// Maps to CAddress + version message fields in Bitcoin Core's protocol.
#[derive(Debug, Clone)]
pub struct VersionMessage {
    /// Protocol version being used.
    pub version: u32,
    /// Services offered by the sending node.
    pub services: ServiceFlags,
    /// Unix timestamp at the time of sending.
    pub timestamp: i64,
    /// Address of the receiving node (as seen by sender).
    pub addr_recv: NetAddress,
    /// Address of the sending node.
    pub addr_from: NetAddress,
    /// Random nonce to detect self-connections.
    pub nonce: u64,
    /// User agent string (e.g., "/Satoshi:25.0.0/").
    pub user_agent: String,
    /// Best block height known to the sending node.
    pub start_height: i32,
    /// Whether the sender wants to receive relay messages (BIP 37).
    pub relay: bool,
}

// ---------------------------------------------------------------------------
// NetMessage
// ---------------------------------------------------------------------------

/// All P2P protocol messages.
///
/// This enum covers the full set of Bitcoin protocol messages.
/// Raw payloads are used for Block, Tx, and Headers to avoid
/// deserializing them at the protocol layer.
#[derive(Debug, Clone)]
pub enum NetMessage {
    /// Version handshake message.
    Version(VersionMessage),
    /// Version acknowledgement.
    Verack,
    /// Ping with nonce for latency measurement.
    Ping(u64),
    /// Pong response with the same nonce.
    Pong(u64),
    /// Request peer addresses.
    GetAddr,
    /// Advertise known addresses (legacy v1). Each entry is (timestamp, address).
    Addr(Vec<(u32, NetAddress)>),
    /// Advertise known addresses (BIP 155 v2). Raw payload for now.
    AddrV2(Vec<u8>),
    /// Advertise inventory (blocks/txns we have).
    Inv(Vec<InvVect>),
    /// Request data objects by inventory.
    GetData(Vec<InvVect>),
    /// Request block hashes in a range (locator-based).
    GetBlocks {
        /// Protocol version of the sender.
        version: u32,
        /// Block locator hashes (exponential backoff from chain tip).
        locators: Vec<BlockHash>,
        /// Hash to stop at, or zero for "as many as possible".
        hash_stop: BlockHash,
    },
    /// Request block headers in a range (headers-first sync).
    GetHeaders {
        /// Protocol version of the sender.
        version: u32,
        /// Block locator hashes (exponential backoff from chain tip).
        locators: Vec<BlockHash>,
        /// Hash to stop at, or zero for "as many as possible".
        hash_stop: BlockHash,
    },
    /// A full serialized block.
    Block(Vec<u8>),
    /// A serialized transaction.
    Tx(Vec<u8>),
    /// A list of serialized block headers.
    Headers(Vec<Vec<u8>>),
    /// Response indicating requested items were not found.
    NotFound(Vec<InvVect>),
    /// Reject message (deprecated but still encountered on the network).
    Reject {
        /// The command string of the rejected message (e.g., `"tx"`).
        message: String,
        /// Rejection code (e.g., 0x10 for invalid, 0x12 for insufficient fee).
        code: u8,
        /// Human-readable reason for rejection.
        reason: String,
    },
    /// Request peer to send headers instead of inv for new blocks (BIP 130).
    SendHeaders,
    /// Request compact block relay (BIP 152).
    SendCmpct {
        /// Whether to use high-bandwidth mode (unsolicited compact blocks).
        announce: bool,
        /// Compact block protocol version (1 = pre-segwit, 2 = segwit).
        version: u64,
    },
    /// Minimum fee rate filter in sat/kvB (BIP 133).
    FeeFilter(i64),
    /// Announce wtxid-based relay support (BIP 339).
    /// Sent between VERSION and VERACK during handshake.
    WtxidRelay,
    /// Announce addrv2 support (BIP 155).
    /// Sent between VERSION and VERACK during handshake.
    SendAddrV2,
    /// Transaction reconciliation initiation (BIP 330).
    SendTxRcncl {
        /// Reconciliation protocol version.
        version: u32,
        /// Random salt for reconciliation sketch computation.
        salt: u64,
    },
    /// Compact block (BIP 152).
    CmpctBlock(Vec<u8>),
    /// Request block transactions for compact block (BIP 152).
    GetBlockTxn(Vec<u8>),
    /// Block transactions response for compact block (BIP 152).
    BlockTxn(Vec<u8>),
    /// Bloom filter load (BIP 37).
    FilterLoad(Vec<u8>),
    /// Add data to bloom filter (BIP 37).
    FilterAdd(Vec<u8>),
    /// Clear bloom filter (BIP 37).
    FilterClear,
    /// Merkle block with partial merkle tree (BIP 37).
    MerkleBlock(Vec<u8>),
    /// Request memory pool contents.
    MemPool,
    /// Request compact filter headers (BIP 157).
    GetCFHeaders {
        /// Filter type (0 = basic).
        filter_type: u8,
        /// Start block height.
        start_height: u32,
        /// Hash of the last block in the requested range.
        stop_hash: BlockHash,
    },
    /// Compact filter headers response (BIP 157).
    CFHeaders(Vec<u8>),
    /// Request compact filters (BIP 157).
    GetCFilters {
        /// Filter type (0 = basic).
        filter_type: u8,
        /// Start block height.
        start_height: u32,
        /// Hash of the last block in the requested range.
        stop_hash: BlockHash,
    },
    /// Compact filter response (BIP 157).
    CFilter(Vec<u8>),
    /// Request compact filter checkpoints (BIP 157).
    GetCFCheckpt {
        /// Filter type (0 = basic).
        filter_type: u8,
        /// Hash of the last block in the requested range.
        stop_hash: BlockHash,
    },
    /// Compact filter checkpoints response (BIP 157).
    CFCheckpt(Vec<u8>),
    /// Unknown/unrecognized message type.
    Unknown {
        /// The command string from the message header.
        command: String,
        /// The raw payload bytes.
        payload: Vec<u8>,
    },
}

impl NetMessage {
    /// Return the protocol command string for this message.
    pub fn command(&self) -> &str {
        match self {
            NetMessage::Version(_) => "version",
            NetMessage::Verack => "verack",
            NetMessage::Ping(_) => "ping",
            NetMessage::Pong(_) => "pong",
            NetMessage::GetAddr => "getaddr",
            NetMessage::Addr(_) => "addr",
            NetMessage::AddrV2(_) => "addrv2",
            NetMessage::Inv(_) => "inv",
            NetMessage::GetData(_) => "getdata",
            NetMessage::GetBlocks { .. } => "getblocks",
            NetMessage::GetHeaders { .. } => "getheaders",
            NetMessage::Block(_) => "block",
            NetMessage::Tx(_) => "tx",
            NetMessage::Headers(_) => "headers",
            NetMessage::NotFound(_) => "notfound",
            NetMessage::Reject { .. } => "reject",
            NetMessage::SendHeaders => "sendheaders",
            NetMessage::SendCmpct { .. } => "sendcmpct",
            NetMessage::FeeFilter(_) => "feefilter",
            NetMessage::WtxidRelay => "wtxidrelay",
            NetMessage::SendAddrV2 => "sendaddrv2",
            NetMessage::SendTxRcncl { .. } => "sendtxrcncl",
            NetMessage::CmpctBlock(_) => "cmpctblock",
            NetMessage::GetBlockTxn(_) => "getblocktxn",
            NetMessage::BlockTxn(_) => "blocktxn",
            NetMessage::FilterLoad(_) => "filterload",
            NetMessage::FilterAdd(_) => "filteradd",
            NetMessage::FilterClear => "filterclear",
            NetMessage::MerkleBlock(_) => "merkleblock",
            NetMessage::MemPool => "mempool",
            NetMessage::GetCFHeaders { .. } => "getcfheaders",
            NetMessage::CFHeaders(_) => "cfheaders",
            NetMessage::GetCFilters { .. } => "getcfilters",
            NetMessage::CFilter(_) => "cfilter",
            NetMessage::GetCFCheckpt { .. } => "getcfcheckpt",
            NetMessage::CFCheckpt(_) => "cfcheckpt",
            NetMessage::Unknown { command, .. } => command,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_magic_values() {
        assert_eq!(NetworkMagic::MAINNET.0, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(NetworkMagic::TESTNET.0, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(NetworkMagic::REGTEST.0, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(NetworkMagic::SIGNET.0, [0x0a, 0x03, 0xcf, 0x40]);
    }

    #[test]
    fn test_network_magic_equality() {
        assert_eq!(NetworkMagic::MAINNET, NetworkMagic::MAINNET);
        assert_ne!(NetworkMagic::MAINNET, NetworkMagic::TESTNET);
    }

    #[test]
    fn test_message_header_new_and_command_str() {
        let payload = b"hello world";
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "version", payload);
        assert_eq!(hdr.command_str(), "version");
        assert_eq!(hdr.magic, NetworkMagic::MAINNET);
        assert_eq!(hdr.payload_size, payload.len() as u32);
    }

    #[test]
    fn test_message_header_command_str_full_length() {
        // A 12-char command fills the entire field (no null terminator).
        let payload = b"";
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "123456789012", payload);
        assert_eq!(hdr.command_str(), "123456789012");
    }

    #[test]
    fn test_message_header_command_str_short() {
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "tx", b"");
        assert_eq!(hdr.command_str(), "tx");
        // The rest of the command field should be null-padded.
        assert_eq!(hdr.command[2..], [0u8; 10]);
    }

    #[test]
    fn test_message_header_checksum_verification() {
        let payload = b"test payload data";
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "inv", payload);
        assert!(hdr.verify_checksum(payload));
        // Wrong payload should fail verification.
        assert!(!hdr.verify_checksum(b"wrong payload"));
    }

    #[test]
    fn test_message_header_empty_payload_checksum() {
        let payload = b"";
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "verack", payload);
        assert!(hdr.verify_checksum(payload));
        assert_eq!(hdr.payload_size, 0);
    }

    #[test]
    fn test_message_header_serialize_deserialize_roundtrip() {
        let payload = b"some data here";
        let original = MessageHeader::new(NetworkMagic::MAINNET, "getdata", payload);
        let serialized = original.serialize();
        assert_eq!(serialized.len(), 24);

        let deserialized = MessageHeader::deserialize(&serialized);
        assert_eq!(deserialized.magic, original.magic);
        assert_eq!(deserialized.command, original.command);
        assert_eq!(deserialized.payload_size, original.payload_size);
        assert_eq!(deserialized.checksum, original.checksum);
        assert_eq!(deserialized.command_str(), "getdata");
    }

    #[test]
    fn test_message_header_serialize_layout() {
        let hdr = MessageHeader::new(NetworkMagic::MAINNET, "ping", b"");
        let bytes = hdr.serialize();

        // First 4 bytes: magic
        assert_eq!(&bytes[0..4], &[0xf9, 0xbe, 0xb4, 0xd9]);
        // Bytes 4-16: command "ping" + null padding
        assert_eq!(&bytes[4..8], b"ping");
        assert_eq!(&bytes[8..16], &[0u8; 8]);
        // Bytes 16-20: payload size (0, little-endian)
        assert_eq!(&bytes[16..20], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_service_flags() {
        let flags = ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS;
        assert!(flags.contains(ServiceFlags::NODE_NETWORK));
        assert!(flags.contains(ServiceFlags::NODE_WITNESS));
        assert!(!flags.contains(ServiceFlags::NODE_BLOOM));
        assert_eq!(flags.bits(), 0b1001); // bits 0 and 3
    }

    #[test]
    fn test_service_flags_default() {
        let flags = ServiceFlags::default();
        assert_eq!(flags, ServiceFlags::NODE_NONE);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_service_flags_all_values() {
        assert_eq!(ServiceFlags::NODE_NETWORK.bits(), 1);
        assert_eq!(ServiceFlags::NODE_BLOOM.bits(), 4);
        assert_eq!(ServiceFlags::NODE_WITNESS.bits(), 8);
        assert_eq!(ServiceFlags::NODE_COMPACT_FILTERS.bits(), 64);
        assert_eq!(ServiceFlags::NODE_NETWORK_LIMITED.bits(), 1024);
        assert_eq!(ServiceFlags::NODE_P2P_V2.bits(), 2048);
    }

    #[test]
    fn test_net_address() {
        let addr = NetAddress::new(
            ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            8333,
        );
        assert_eq!(addr.port, 8333);
        assert!(addr.services.contains(ServiceFlags::NODE_NETWORK));
        let sock = addr.socket_addr();
        assert_eq!(sock.port(), 8333);
        assert_eq!(
            sock.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn test_inv_type_from_u32() {
        assert_eq!(InvType::from_u32(0), Some(InvType::Error));
        assert_eq!(InvType::from_u32(1), Some(InvType::Tx));
        assert_eq!(InvType::from_u32(2), Some(InvType::Block));
        assert_eq!(InvType::from_u32(3), Some(InvType::FilteredBlock));
        assert_eq!(InvType::from_u32(4), Some(InvType::CompactBlock));
        assert_eq!(InvType::from_u32(0x40000001), Some(InvType::WitnessTx));
        assert_eq!(InvType::from_u32(0x40000002), Some(InvType::WitnessBlock));
        assert_eq!(
            InvType::from_u32(0x40000003),
            Some(InvType::WitnessFilteredBlock)
        );
        assert_eq!(InvType::from_u32(999), None);
    }

    #[test]
    fn test_inv_type_to_u32_roundtrip() {
        let types = [
            InvType::Error,
            InvType::Tx,
            InvType::Block,
            InvType::FilteredBlock,
            InvType::CompactBlock,
            InvType::WitnessTx,
            InvType::WitnessBlock,
            InvType::WitnessFilteredBlock,
        ];
        for t in &types {
            assert_eq!(InvType::from_u32(t.to_u32()), Some(*t));
        }
    }

    #[test]
    fn test_inv_type_witness_conversion() {
        assert_eq!(InvType::Tx.with_witness(), InvType::WitnessTx);
        assert_eq!(InvType::Block.with_witness(), InvType::WitnessBlock);
        assert_eq!(
            InvType::FilteredBlock.with_witness(),
            InvType::WitnessFilteredBlock
        );
        assert_eq!(InvType::WitnessTx.without_witness(), InvType::Tx);
        assert_eq!(InvType::WitnessBlock.without_witness(), InvType::Block);
        assert_eq!(
            InvType::WitnessFilteredBlock.without_witness(),
            InvType::FilteredBlock
        );
        assert!(InvType::WitnessTx.is_witness());
        assert!(!InvType::Tx.is_witness());
    }

    #[test]
    fn test_inv_vect() {
        let hash = Uint256::from_bytes([0xab; 32]);
        let inv = InvVect::new(InvType::Tx, hash);
        assert_eq!(inv.inv_type, InvType::Tx);
        assert_eq!(inv.hash, Uint256::from_bytes([0xab; 32]));
    }

    #[test]
    fn test_inv_vect_equality() {
        let hash1 = Uint256::from_bytes([1u8; 32]);
        let hash2 = Uint256::from_bytes([2u8; 32]);
        let inv1 = InvVect::new(InvType::Block, hash1);
        let inv2 = InvVect::new(InvType::Block, hash1);
        let inv3 = InvVect::new(InvType::Block, hash2);
        let inv4 = InvVect::new(InvType::Tx, hash1);
        assert_eq!(inv1, inv2);
        assert_ne!(inv1, inv3);
        assert_ne!(inv1, inv4);
    }

    #[test]
    fn test_net_message_command() {
        assert_eq!(NetMessage::Verack.command(), "verack");
        assert_eq!(NetMessage::Ping(42).command(), "ping");
        assert_eq!(NetMessage::Pong(42).command(), "pong");
        assert_eq!(NetMessage::GetAddr.command(), "getaddr");
        assert_eq!(NetMessage::SendHeaders.command(), "sendheaders");
        assert_eq!(NetMessage::FeeFilter(1000).command(), "feefilter");
        assert_eq!(NetMessage::WtxidRelay.command(), "wtxidrelay");
        assert_eq!(NetMessage::SendAddrV2.command(), "sendaddrv2");
        assert_eq!(
            NetMessage::SendTxRcncl {
                version: 1,
                salt: 0
            }
            .command(),
            "sendtxrcncl"
        );
        assert_eq!(NetMessage::FilterClear.command(), "filterclear");
        assert_eq!(NetMessage::MemPool.command(), "mempool");
        assert_eq!(NetMessage::CmpctBlock(vec![]).command(), "cmpctblock");
        assert_eq!(NetMessage::GetBlockTxn(vec![]).command(), "getblocktxn");
        assert_eq!(NetMessage::BlockTxn(vec![]).command(), "blocktxn");
        assert_eq!(NetMessage::FilterLoad(vec![]).command(), "filterload");
        assert_eq!(NetMessage::FilterAdd(vec![]).command(), "filteradd");
        assert_eq!(NetMessage::MerkleBlock(vec![]).command(), "merkleblock");
        assert_eq!(NetMessage::AddrV2(vec![]).command(), "addrv2");
        assert_eq!(NetMessage::CFHeaders(vec![]).command(), "cfheaders");
        assert_eq!(NetMessage::CFilter(vec![]).command(), "cfilter");
        assert_eq!(NetMessage::CFCheckpt(vec![]).command(), "cfcheckpt");
        assert_eq!(
            NetMessage::Unknown {
                command: "custom".to_string(),
                payload: vec![]
            }
            .command(),
            "custom"
        );
    }

    #[test]
    fn test_version_message() {
        let ver = VersionMessage {
            version: PROTOCOL_VERSION,
            services: ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
            timestamp: 1700000000,
            addr_recv: NetAddress::new(
                ServiceFlags::NODE_NETWORK,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                8333,
            ),
            addr_from: NetAddress::new(
                ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                8333,
            ),
            nonce: 0xdeadbeef,
            user_agent: "/QubitCoin:0.1.0/".to_string(),
            start_height: 800_000,
            relay: true,
        };
        assert_eq!(ver.version, 70016);
        assert!(ver.services.contains(ServiceFlags::NODE_WITNESS));
        assert_eq!(ver.user_agent, "/QubitCoin:0.1.0/");
        assert!(ver.relay);
    }

    #[test]
    fn test_message_header_different_networks() {
        let payload = b"test";
        let hdr_main = MessageHeader::new(NetworkMagic::MAINNET, "ping", payload);
        let hdr_test = MessageHeader::new(NetworkMagic::TESTNET, "ping", payload);
        let hdr_reg = MessageHeader::new(NetworkMagic::REGTEST, "ping", payload);

        // Same checksum since same payload, but different magic.
        assert_eq!(hdr_main.checksum, hdr_test.checksum);
        assert_eq!(hdr_main.checksum, hdr_reg.checksum);
        assert_ne!(hdr_main.magic, hdr_test.magic);
        assert_ne!(hdr_main.magic, hdr_reg.magic);
    }

    #[test]
    fn test_message_header_deserialize_verifies() {
        let payload = b"important data";
        let original = MessageHeader::new(NetworkMagic::TESTNET, "block", payload);
        let serialized = original.serialize();
        let restored = MessageHeader::deserialize(&serialized);

        // The restored header should verify against the original payload.
        assert!(restored.verify_checksum(payload));
    }

    #[test]
    fn test_net_message_getblocks() {
        let msg = NetMessage::GetBlocks {
            version: PROTOCOL_VERSION,
            locators: vec![BlockHash::ZERO],
            hash_stop: BlockHash::ZERO,
        };
        assert_eq!(msg.command(), "getblocks");
    }

    #[test]
    fn test_net_message_getheaders() {
        let msg = NetMessage::GetHeaders {
            version: PROTOCOL_VERSION,
            locators: vec![],
            hash_stop: BlockHash::ZERO,
        };
        assert_eq!(msg.command(), "getheaders");
    }

    #[test]
    fn test_net_message_sendcmpct() {
        let msg = NetMessage::SendCmpct {
            announce: true,
            version: 2,
        };
        assert_eq!(msg.command(), "sendcmpct");
    }

    #[test]
    fn test_net_address_ipv6() {
        let addr = NetAddress::new(
            ServiceFlags::NODE_NETWORK,
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            18333,
        );
        assert_eq!(addr.port, 18333);
        assert_eq!(addr.socket_addr().port(), 18333);
    }
}
