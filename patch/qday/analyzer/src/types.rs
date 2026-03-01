/// Vulnerability types for quantum-exposed Bitcoin outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VulnType {
    /// Public key directly in scriptPubKey (OP_CHECKSIG without hash).
    /// Includes Satoshi-era coins and early mining outputs.
    P2PK = 0,
    /// P2PKH where the public key has been revealed by a prior spend
    /// from the same address, exposing it to quantum attack.
    ExposedP2PKH = 1,
    /// Taproot outputs expose the x-only public key directly in the
    /// witness program, making them quantum-vulnerable by design.
    P2TR = 2,
}

impl VulnType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(VulnType::P2PK),
            1 => Some(VulnType::ExposedP2PKH),
            2 => Some(VulnType::P2TR),
            _ => None,
        }
    }
}

/// A quantum-vulnerable unspent transaction output.
#[derive(Debug, Clone)]
pub struct VulnerableOutpoint {
    /// Transaction ID (32 bytes, internal byte order).
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Type of quantum vulnerability.
    pub vuln_type: VulnType,
    /// Block height where this output was created.
    pub height: u32,
    /// Composite safety score (0-1000). Higher = safer to freeze.
    pub score: u16,
    /// The exposed public key bytes (compressed or uncompressed for P2PK,
    /// compressed for ExposedP2PKH, x-only 32 bytes for P2TR).
    pub pubkey: Vec<u8>,
}

/// Serialize an outpoint (txid + vout) to 36 bytes.
pub fn outpoint_key(txid: &[u8; 32], vout: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(txid);
    key.extend_from_slice(&vout.to_le_bytes());
    key
}

/// Deserialize a 36-byte outpoint key back to (txid, vout).
pub fn parse_outpoint_key(data: &[u8]) -> Option<([u8; 32], u32)> {
    if data.len() < 36 {
        return None;
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&data[..32]);
    let vout = u32::from_le_bytes(data[32..36].try_into().ok()?);
    Some((txid, vout))
}
