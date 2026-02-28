//! Bitcoin Script type.
//! Maps to: src/script/script.h (CScript, CScriptBase)
//!
//! A Script is a byte vector representing a sequence of opcodes and data pushes.
//! This is the fundamental type for Bitcoin's scripting language.

use crate::opcode::Opcode;
use crate::script_num::ScriptNum;
use std::io::{Read, Write};

/// Maximum size of a single script element (520 bytes).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of non-push operations per script.
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of public keys per OP_CHECKMULTISIG.
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum number of public keys per OP_CHECKSIGADD (BIP342).
pub const MAX_PUBKEYS_PER_MULTI_A: usize = 999;

/// Maximum script size in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum combined stack + altstack size.
pub const MAX_STACK_SIZE: usize = 1000;

/// Threshold for interpreting nLockTime as block height vs. timestamp.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Maximum nLockTime value.
pub const LOCKTIME_MAX: u32 = 0xFFFFFFFF;

/// Tapscript annex tag.
pub const ANNEX_TAG: u8 = 0x50;

/// BIP342 validation weight per sigop passed.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

/// BIP342 validation weight offset.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Bitcoin Script.
///
/// Wraps a byte vector. Provides methods for building scripts from opcodes
/// and for iterating over opcodes in an existing script.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Script {
    data: Vec<u8>,
}

impl Script {
    /// Create an empty script.
    pub fn new() -> Self {
        Script { data: Vec::new() }
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Script { data: bytes }
    }

    /// Create from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Script {
            data: bytes.to_vec(),
        }
    }

    /// Get the raw script bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the script is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Take ownership of the byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    // --- Script building methods ---

    /// Push an opcode.
    pub fn push_opcode(&mut self, opcode: Opcode) -> &mut Self {
        self.data.push(opcode as u8);
        self
    }

    /// Push an integer value using the most compact encoding.
    /// Uses OP_0 for 0, OP_1NEGATE for -1, OP_1..OP_16 for 1..16,
    /// and minimal byte push for other values.
    pub fn push_int(&mut self, n: i64) -> &mut Self {
        if n == -1 || (1..=16).contains(&n) {
            // OP_1NEGATE = 0x4f, OP_1 = 0x51..OP_16 = 0x60
            self.data
                .push((n as u8).wrapping_add(Opcode::Op1 as u8 - 1));
        } else if n == 0 {
            self.data.push(Opcode::Op0 as u8);
        } else {
            let bytes = ScriptNum::encode_i64(n);
            self.push_data(&bytes);
        }
        self
    }

    /// Push raw data with appropriate length prefix.
    /// Uses the smallest possible push opcode.
    pub fn push_data(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len();
        if len == 0 {
            // Empty push - use OP_0
            self.data.push(Opcode::Op0 as u8);
        } else if len <= 0x4b {
            // Direct push: byte value IS the length
            self.data.push(len as u8);
            self.data.extend_from_slice(data);
        } else if len <= 0xff {
            self.data.push(Opcode::OpPushData1 as u8);
            self.data.push(len as u8);
            self.data.extend_from_slice(data);
        } else if len <= 0xffff {
            self.data.push(Opcode::OpPushData2 as u8);
            self.data.extend_from_slice(&(len as u16).to_le_bytes());
            self.data.extend_from_slice(data);
        } else {
            self.data.push(Opcode::OpPushData4 as u8);
            self.data.extend_from_slice(&(len as u32).to_le_bytes());
            self.data.extend_from_slice(data);
        }
        self
    }

    // --- Script analysis methods ---

    /// Parse the next opcode and optional data at the given position.
    /// Returns (opcode_byte, data, new_position) or None if at end/error.
    pub fn get_op(&self, pos: usize) -> Option<(u8, Vec<u8>, usize)> {
        if pos >= self.data.len() {
            return None;
        }

        let opcode = self.data[pos];
        let mut pc = pos + 1;

        if opcode <= 0x4b {
            // Direct push of opcode bytes
            let n = opcode as usize;
            if pc + n > self.data.len() {
                return None;
            }
            let data = self.data[pc..pc + n].to_vec();
            pc += n;
            Some((opcode, data, pc))
        } else if opcode == Opcode::OpPushData1 as u8 {
            if pc >= self.data.len() {
                return None;
            }
            let n = self.data[pc] as usize;
            pc += 1;
            if pc + n > self.data.len() {
                return None;
            }
            let data = self.data[pc..pc + n].to_vec();
            pc += n;
            Some((opcode, data, pc))
        } else if opcode == Opcode::OpPushData2 as u8 {
            if pc + 2 > self.data.len() {
                return None;
            }
            let n = u16::from_le_bytes([self.data[pc], self.data[pc + 1]]) as usize;
            pc += 2;
            if pc + n > self.data.len() {
                return None;
            }
            let data = self.data[pc..pc + n].to_vec();
            pc += n;
            Some((opcode, data, pc))
        } else if opcode == Opcode::OpPushData4 as u8 {
            if pc + 4 > self.data.len() {
                return None;
            }
            let n = u32::from_le_bytes([
                self.data[pc],
                self.data[pc + 1],
                self.data[pc + 2],
                self.data[pc + 3],
            ]) as usize;
            pc += 4;
            if pc + n > self.data.len() {
                return None;
            }
            let data = self.data[pc..pc + n].to_vec();
            pc += n;
            Some((opcode, data, pc))
        } else {
            Some((opcode, vec![], pc))
        }
    }

    /// Iterate over all opcodes in the script.
    pub fn iter_ops(&self) -> ScriptOpsIter<'_> {
        ScriptOpsIter {
            script: self,
            pos: 0,
        }
    }

    /// Check if the script is a pay-to-script-hash (P2SH) script.
    /// Format: OP_HASH160 <20 bytes> OP_EQUAL
    pub fn is_p2sh(&self) -> bool {
        self.data.len() == 23
            && self.data[0] == Opcode::OpHash160 as u8
            && self.data[1] == 0x14 // push 20 bytes
            && self.data[22] == Opcode::OpEqual as u8
    }

    /// Check if the script is a pay-to-public-key-hash (P2PKH) script.
    /// Format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    pub fn is_p2pkh(&self) -> bool {
        self.data.len() == 25
            && self.data[0] == Opcode::OpDup as u8
            && self.data[1] == Opcode::OpHash160 as u8
            && self.data[2] == 0x14
            && self.data[23] == Opcode::OpEqualVerify as u8
            && self.data[24] == Opcode::OpCheckSig as u8
    }

    /// Check if the script is a witness program (BIP141).
    /// Format: OP_0/OP_1..OP_16 <2..40 bytes>
    pub fn is_witness_program(&self) -> Option<(u8, &[u8])> {
        if self.data.len() < 4 || self.data.len() > 42 {
            return None;
        }

        let version_opcode = self.data[0];
        if version_opcode != Opcode::Op0 as u8
            && !(Opcode::Op1 as u8..=Opcode::Op16 as u8).contains(&version_opcode)
        {
            return None;
        }

        let program_len = self.data[1] as usize;
        if program_len + 2 != self.data.len() || !(2..=40).contains(&program_len) {
            return None;
        }

        let version = if version_opcode == 0 {
            0
        } else {
            version_opcode - (Opcode::Op1 as u8 - 1)
        };

        Some((version, &self.data[2..]))
    }

    /// Check if the script is pay-to-witness-public-key-hash (P2WPKH).
    /// Format: OP_0 <20 bytes>
    pub fn is_p2wpkh(&self) -> bool {
        self.data.len() == 22 && self.data[0] == Opcode::Op0 as u8 && self.data[1] == 0x14
    }

    /// Check if the script is pay-to-witness-script-hash (P2WSH).
    /// Format: OP_0 <32 bytes>
    pub fn is_p2wsh(&self) -> bool {
        self.data.len() == 34 && self.data[0] == Opcode::Op0 as u8 && self.data[1] == 0x20
    }

    /// Check if the script is a Taproot output (P2TR).
    /// Format: OP_1 <32 bytes>
    pub fn is_p2tr(&self) -> bool {
        self.data.len() == 34 && self.data[0] == Opcode::Op1 as u8 && self.data[1] == 0x20
    }

    /// Check if the script is provably unspendable (starts with OP_RETURN).
    pub fn is_unspendable(&self) -> bool {
        self.data.len() > 0 && self.data[0] == Opcode::OpReturn as u8
            || self.data.len() > MAX_SCRIPT_SIZE
    }

    /// Check if the script contains only push operations.
    pub fn is_push_only(&self) -> bool {
        let mut pos = 0;
        while let Some((opcode, _, new_pos)) = self.get_op(pos) {
            if opcode > Opcode::Op16 as u8 {
                return false;
            }
            pos = new_pos;
        }
        true
    }

    /// Count the number of signature operations in the script.
    /// Does NOT count operations inside P2SH scripts.
    pub fn get_sig_op_count(&self, accurate: bool) -> usize {
        let mut count = 0;
        let mut last_opcode = 0u8;
        let mut pos = 0;

        while let Some((opcode, _, new_pos)) = self.get_op(pos) {
            match Opcode::from_u8(opcode) {
                Some(Opcode::OpCheckSig) | Some(Opcode::OpCheckSigVerify) => {
                    count += 1;
                }
                Some(Opcode::OpCheckMultiSig) | Some(Opcode::OpCheckMultiSigVerify) => {
                    if accurate
                        && last_opcode >= Opcode::Op1 as u8
                        && last_opcode <= Opcode::Op16 as u8
                    {
                        count += (last_opcode - (Opcode::Op1 as u8 - 1)) as usize;
                    } else {
                        count += MAX_PUBKEYS_PER_MULTISIG;
                    }
                }
                _ => {}
            }
            last_opcode = opcode;
            pos = new_pos;
        }

        count
    }
}

// Serialization
impl qubitcoin_serialize::Encodable for Script {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize, qubitcoin_serialize::Error> {
        // Script is serialized as a CompactSize-prefixed byte vector
        let mut size = qubitcoin_serialize::write_compact_size(w, self.data.len() as u64)?;
        w.write_all(&self.data)?;
        size += self.data.len();
        Ok(size)
    }
}

impl qubitcoin_serialize::Decodable for Script {
    fn decode<R: Read>(r: &mut R) -> Result<Self, qubitcoin_serialize::Error> {
        let data = Vec::<u8>::decode(r)?;
        Ok(Script { data })
    }
}

impl std::fmt::Debug for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Script({})", hex::encode(&self.data))
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as opcodes
        let mut pos = 0;
        let mut first = true;
        while let Some((opcode, data, new_pos)) = self.get_op(pos) {
            if !first {
                write!(f, " ")?;
            }
            first = false;

            if !data.is_empty() {
                write!(f, "{}", hex::encode(&data))?;
            } else if let Some(op) = Opcode::from_u8(opcode) {
                write!(f, "{}", op.name())?;
            } else {
                write!(f, "0x{:02x}", opcode)?;
            }
            pos = new_pos;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for Script {
    fn from(data: Vec<u8>) -> Self {
        Script { data }
    }
}

/// Iterator over script operations.
pub struct ScriptOpsIter<'a> {
    script: &'a Script,
    pos: usize,
}

impl<'a> Iterator for ScriptOpsIter<'a> {
    /// (opcode_byte, push_data)
    type Item = (u8, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let (opcode, data, new_pos) = self.script.get_op(self.pos)?;
        self.pos = new_pos;
        Some((opcode, data))
    }
}

// --- Standard script builders ---

/// Build a P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn build_p2pkh(pubkey_hash: &[u8; 20]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::OpDup);
    s.push_opcode(Opcode::OpHash160);
    s.push_data(pubkey_hash);
    s.push_opcode(Opcode::OpEqualVerify);
    s.push_opcode(Opcode::OpCheckSig);
    s
}

/// Build a P2SH script: OP_HASH160 <hash> OP_EQUAL
pub fn build_p2sh(script_hash: &[u8; 20]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::OpHash160);
    s.push_data(script_hash);
    s.push_opcode(Opcode::OpEqual);
    s
}

/// Build a P2WPKH script: OP_0 <20-byte hash>
pub fn build_p2wpkh(pubkey_hash: &[u8; 20]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::Op0);
    s.push_data(pubkey_hash);
    s
}

/// Build a P2WSH script: OP_0 <32-byte hash>
pub fn build_p2wsh(script_hash: &[u8; 32]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::Op0);
    s.push_data(script_hash);
    s
}

/// Build a P2TR script: OP_1 <32-byte x-only pubkey>
pub fn build_p2tr(output_key: &[u8; 32]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::Op1);
    s.push_data(output_key);
    s
}

/// Build an OP_RETURN script with data.
pub fn build_op_return(data: &[u8]) -> Script {
    let mut s = Script::new();
    s.push_opcode(Opcode::OpReturn);
    if !data.is_empty() {
        s.push_data(data);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_detection() {
        let hash = [0u8; 20];
        let script = build_p2pkh(&hash);
        assert!(script.is_p2pkh());
        assert!(!script.is_p2sh());
        assert_eq!(script.len(), 25);
    }

    #[test]
    fn test_p2sh_detection() {
        let hash = [0u8; 20];
        let script = build_p2sh(&hash);
        assert!(script.is_p2sh());
        assert!(!script.is_p2pkh());
        assert_eq!(script.len(), 23);
    }

    #[test]
    fn test_p2wpkh_detection() {
        let hash = [0u8; 20];
        let script = build_p2wpkh(&hash);
        assert!(script.is_p2wpkh());
        let (version, program) = script.is_witness_program().unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 20);
    }

    #[test]
    fn test_p2wsh_detection() {
        let hash = [0u8; 32];
        let script = build_p2wsh(&hash);
        assert!(script.is_p2wsh());
        let (version, program) = script.is_witness_program().unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn test_p2tr_detection() {
        let key = [0u8; 32];
        let script = build_p2tr(&key);
        assert!(script.is_p2tr());
        let (version, program) = script.is_witness_program().unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn test_push_int() {
        let mut s = Script::new();
        s.push_int(0);
        assert_eq!(s.as_bytes(), &[Opcode::Op0 as u8]);

        let mut s = Script::new();
        s.push_int(1);
        assert_eq!(s.as_bytes(), &[Opcode::Op1 as u8]);

        let mut s = Script::new();
        s.push_int(16);
        assert_eq!(s.as_bytes(), &[Opcode::Op16 as u8]);

        let mut s = Script::new();
        s.push_int(-1);
        assert_eq!(s.as_bytes(), &[Opcode::Op1Negate as u8]);
    }

    #[test]
    fn test_push_data() {
        let mut s = Script::new();
        let data = vec![0x42; 10];
        s.push_data(&data);
        assert_eq!(s.as_bytes()[0], 10); // direct push length
        assert_eq!(&s.as_bytes()[1..], &data[..]);
    }

    #[test]
    fn test_op_return() {
        let script = build_op_return(b"hello");
        assert!(script.is_unspendable());
    }

    #[test]
    fn test_iter_ops() {
        let hash = [0u8; 20];
        let script = build_p2pkh(&hash);
        let ops: Vec<_> = script.iter_ops().collect();
        assert_eq!(ops.len(), 5);
        assert_eq!(ops[0].0, Opcode::OpDup as u8);
        assert_eq!(ops[1].0, Opcode::OpHash160 as u8);
        assert_eq!(ops[2].1.len(), 20); // push data
        assert_eq!(ops[3].0, Opcode::OpEqualVerify as u8);
        assert_eq!(ops[4].0, Opcode::OpCheckSig as u8);
    }

    #[test]
    fn test_is_push_only() {
        let mut s = Script::new();
        s.push_data(&[1, 2, 3]);
        s.push_int(5);
        assert!(s.is_push_only());

        let mut s2 = Script::new();
        s2.push_opcode(Opcode::OpDup);
        assert!(!s2.is_push_only());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let script = build_p2pkh(&[0xab; 20]);
        let encoded = qubitcoin_serialize::serialize(&script).unwrap();
        let decoded: Script = qubitcoin_serialize::deserialize(&encoded).unwrap();
        assert_eq!(script, decoded);
    }

    #[test]
    fn test_sig_op_count() {
        let mut s = Script::new();
        s.push_opcode(Opcode::OpCheckSig);
        assert_eq!(s.get_sig_op_count(true), 1);

        let mut s = Script::new();
        s.push_int(3); // OP_3
        s.push_opcode(Opcode::OpCheckMultiSig);
        assert_eq!(s.get_sig_op_count(true), 3);
    }
}
