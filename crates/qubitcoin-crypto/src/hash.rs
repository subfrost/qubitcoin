//! Cryptographic hash functions wrapping bitcoin_hashes.
//! Maps to: src/crypto/ (SHA256, RIPEMD160, etc.)

pub use bitcoin_hashes::hash160;
pub use bitcoin_hashes::ripemd160;
pub use bitcoin_hashes::sha1;
pub use bitcoin_hashes::sha256;
pub use bitcoin_hashes::sha256d;
pub use bitcoin_hashes::sha512;
pub use bitcoin_hashes::Hash;
pub use bitcoin_hashes::HashEngine;

/// Double-SHA256 hash: SHA256(SHA256(data))
/// This is the primary hash used in Bitcoin for block hashes, txids, etc.
#[inline]
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(data);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

/// HASH160: RIPEMD160(SHA256(data))
/// Used for Bitcoin addresses (P2PKH, P2SH).
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let hash = bitcoin_hashes::hash160::Hash::hash(data);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(bytes);
    result
}

/// Single SHA256 hash.
#[inline]
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let hash = sha256::Hash::hash(data);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

/// RIPEMD160 hash.
#[inline]
pub fn ripemd160_hash(data: &[u8]) -> [u8; 20] {
    let hash = ripemd160::Hash::hash(data);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(bytes);
    result
}

/// SHA-1 hash (used in OP_SHA1).
#[inline]
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let hash = sha1::Hash::hash(data);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(bytes);
    result
}

/// Tagged hash per BIP340: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256_hash(tag);
    let mut engine = sha256::HashEngine::default();
    bitcoin_hashes::HashEngine::input(&mut engine, &tag_hash);
    bitcoin_hashes::HashEngine::input(&mut engine, &tag_hash);
    bitcoin_hashes::HashEngine::input(&mut engine, msg);
    let hash = sha256::Hash::from_engine(engine);
    let bytes: &[u8] = hash.as_ref();
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_empty() {
        // SHA256d of empty input
        let result = hash256(b"");
        let expected =
            hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hash160_empty() {
        let result = hash160(b"");
        let expected = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256_hash(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }
}
