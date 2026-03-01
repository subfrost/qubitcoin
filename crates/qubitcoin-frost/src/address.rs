//! P2MR address computation from FROST group key.
//!
//! Converts a FROST group verifying key into a P2MR (Pay-to-Merkle-Root)
//! witness program and script.

use frost_secp256k1_tr as frost;
use frost::keys::PublicKeyPackage;
use qubitcoin_script::{Opcode, Script};

use crate::keygen::group_verifying_key;

/// Compute the 32-byte P2MR witness program from a FROST public key package.
///
/// The FROST group key is used as the single leaf in a tapscript-style
/// merkle tree. The computed tapleaf hash becomes the merkle root, which
/// IS the P2MR witness program (no internal key tweak — key P2MR difference
/// from taproot).
pub fn frost_group_key_to_p2mr_program(pubkey_package: &PublicKeyPackage) -> [u8; 32] {
    let xonly = group_verifying_key(pubkey_package);

    // Build a script that checks the FROST group key:
    // <xonly_pubkey> OP_CHECKSIG
    let mut leaf_script = Script::new();
    leaf_script.push_data(&xonly);
    leaf_script.push_opcode(Opcode::OpCheckSig);

    // Compute tapleaf hash: tagged_hash("TapLeaf", [leaf_version, compact_size(script), script])
    // leaf_version = 0xc0 (tapscript)
    let leaf_version: u8 = 0xc0;
    let script_bytes = leaf_script.as_bytes();

    let mut data = Vec::new();
    data.push(leaf_version);
    // Write compact size of script length
    let mut compact_buf = Vec::new();
    qubitcoin_serialize::write_compact_size(&mut compact_buf, script_bytes.len() as u64).unwrap();
    data.extend_from_slice(&compact_buf);
    data.extend_from_slice(script_bytes);

    qubitcoin_crypto::hash::tagged_hash(b"TapLeaf", &data)
}

/// Build a P2MR scriptPubKey from a 32-byte witness program (merkle root).
pub fn build_p2mr_frost_script(program: &[u8; 32]) -> Script {
    qubitcoin_script::build_p2mr(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_frost_keys;

    #[test]
    fn test_p2mr_program_is_32_bytes() {
        let (_, pubkey_pkg) = generate_frost_keys(3, 2).unwrap();
        let program = frost_group_key_to_p2mr_program(&pubkey_pkg);
        assert_eq!(program.len(), 32);
        assert_ne!(program, [0u8; 32]);
    }

    #[test]
    fn test_p2mr_script_is_valid() {
        let (_, pubkey_pkg) = generate_frost_keys(3, 2).unwrap();
        let program = frost_group_key_to_p2mr_program(&pubkey_pkg);
        let script = build_p2mr_frost_script(&program);
        assert!(script.is_p2mr());
    }
}
