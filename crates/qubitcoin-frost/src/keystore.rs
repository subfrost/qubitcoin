//! FROST keystore: serialization and persistence of key shares.
//!
//! Simplified from subfrost-common's keystore. Stores FROST key packages
//! as JSON files for offline custody.

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use serde::{Deserialize, Serialize};

/// A serializable FROST keystore entry for a single signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostKeystore {
    /// Human-readable identifier for this signer (e.g. "signer-001").
    pub identifier: String,
    /// JSON-serialized `KeyPackage` for this signer.
    pub key_package_json: String,
    /// JSON-serialized `PublicKeyPackage` (same for all signers).
    pub public_key_package_json: String,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
}

impl FrostKeystore {
    /// Create a new keystore entry.
    pub fn new(
        identifier: String,
        key_package: &KeyPackage,
        public_key_package: &PublicKeyPackage,
    ) -> Self {
        let key_package_json =
            serde_json::to_string(key_package).expect("KeyPackage must serialize");
        let public_key_package_json =
            serde_json::to_string(public_key_package).expect("PublicKeyPackage must serialize");

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        FrostKeystore {
            identifier,
            key_package_json,
            public_key_package_json,
            created_at,
        }
    }

    /// Save this keystore entry to a JSON file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Load a keystore entry from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Save all signer key shares to individual JSON files in `output_dir`.
///
/// Creates files named `signer-001.json`, `signer-002.json`, etc.
pub fn save_all_shares(
    shares: &[(Identifier, KeyPackage)],
    pubkey_pkg: &PublicKeyPackage,
    output_dir: &std::path::Path,
) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(output_dir)?;

    for (i, (_id, key_pkg)) in shares.iter().enumerate() {
        let identifier = format!("signer-{:03}", i + 1);
        let keystore = FrostKeystore::new(identifier.clone(), key_pkg, pubkey_pkg);
        let filename = format!("{}.json", identifier);
        let filepath = output_dir.join(filename);
        keystore.save_to_file(&filepath)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_frost_keys;

    #[test]
    fn test_keystore_roundtrip() {
        let (shares, pubkey_pkg) = generate_frost_keys(3, 2).unwrap();
        let (id, key_pkg) = &shares[0];
        let ks = FrostKeystore::new("test-signer".to_string(), key_pkg, &pubkey_pkg);

        let json = serde_json::to_string_pretty(&ks).unwrap();
        let ks2: FrostKeystore = serde_json::from_str(&json).unwrap();

        assert_eq!(ks.identifier, ks2.identifier);
        assert_eq!(ks.key_package_json, ks2.key_package_json);
        assert_eq!(ks.public_key_package_json, ks2.public_key_package_json);
    }

    #[test]
    fn test_save_all_shares() {
        let (shares, pubkey_pkg) = generate_frost_keys(5, 3).unwrap();
        let dir = std::env::temp_dir().join("frost-test-shares");
        let _ = std::fs::remove_dir_all(&dir);

        save_all_shares(&shares, &pubkey_pkg, &dir).unwrap();

        for i in 1..=5 {
            let path = dir.join(format!("signer-{:03}.json", i));
            assert!(path.exists());
            let ks = FrostKeystore::from_file(&path).unwrap();
            assert_eq!(ks.identifier, format!("signer-{:03}", i));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
