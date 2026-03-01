//! FROST dealer-based key generation.
//!
//! Generates threshold Schnorr key shares using the FROST trusted dealer
//! protocol. Adapted from subfrost-cli's `handle_frost_create`.

use frost_secp256k1_tr as frost;
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage, SecretShare};
use frost::Identifier;
use rand::rngs::OsRng;

/// Errors from FROST key generation.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("FROST keygen failed: {0}")]
    Frost(#[from] frost::Error),
}

/// Generate FROST threshold key shares using the trusted dealer protocol.
///
/// Returns a vector of `(Identifier, KeyPackage)` pairs (one per signer)
/// and the group `PublicKeyPackage`.
///
/// # Arguments
/// * `signers` - Total number of signers (e.g. 255)
/// * `threshold` - Minimum signers needed to produce a signature (e.g. 170)
pub fn generate_frost_keys(
    signers: u16,
    threshold: u16,
) -> Result<(Vec<(Identifier, KeyPackage)>, PublicKeyPackage), KeygenError> {
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        signers,
        threshold,
        IdentifierList::Default,
        &mut OsRng,
    )?;

    let key_packages: Vec<(Identifier, KeyPackage)> = shares
        .into_iter()
        .map(|(id, secret_share): (Identifier, SecretShare)| {
            let key_package = KeyPackage::try_from(secret_share)
                .expect("valid secret share must convert to key package");
            (id, key_package)
        })
        .collect();

    Ok((key_packages, pubkey_package))
}

/// Extract the 32-byte x-only group verifying key from a FROST public key package.
///
/// This is the raw bytes of the group's x-only public key, suitable for
/// use as a P2MR witness program or taproot-compatible key.
pub fn group_verifying_key(pkg: &PublicKeyPackage) -> [u8; 32] {
    let vk = pkg.verifying_key();
    let serialized = vk
        .serialize()
        .expect("group verifying key must serialize");
    // serialized is 33 bytes (compressed point); x-only is bytes [1..33]
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&serialized[1..33]);
    xonly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_3_of_5() {
        let (shares, pubkey_pkg) = generate_frost_keys(5, 3).unwrap();
        assert_eq!(shares.len(), 5);
        let xonly = group_verifying_key(&pubkey_pkg);
        assert_ne!(xonly, [0u8; 32]);
    }

    #[test]
    fn test_keygen_170_of_255() {
        let (shares, pubkey_pkg) = generate_frost_keys(255, 170).unwrap();
        assert_eq!(shares.len(), 255);
        let xonly = group_verifying_key(&pubkey_pkg);
        assert_eq!(xonly.len(), 32);
        assert_ne!(xonly, [0u8; 32]);
    }

    #[test]
    fn test_group_key_deterministic_per_run() {
        // Two calls produce different keys (randomized dealer)
        let (_, pkg1) = generate_frost_keys(3, 2).unwrap();
        let (_, pkg2) = generate_frost_keys(3, 2).unwrap();
        let k1 = group_verifying_key(&pkg1);
        let k2 = group_verifying_key(&pkg2);
        // Extremely unlikely to collide
        assert_ne!(k1, k2);
    }
}
