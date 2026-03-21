//! Memory layout utilities for WASM host-guest communication.
//!
//! Implements the AssemblyScript ArrayBuffer convention:
//! `[4-byte LE length][data bytes...]`

/// Convert data to ArrayBuffer layout with length prefix.
pub fn to_arraybuffer_layout<T: AsRef<[u8]>>(v: T) -> Vec<u8> {
    let data = v.as_ref();
    let mut buffer = Vec::with_capacity(data.len() + 4);
    buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buffer.extend_from_slice(data);
    buffer
}

/// Get a passback pointer (4 bytes past start) from a slice.
///
/// The slice must be in ArrayBuffer layout (length-prefixed).
/// Returns a pointer to the data portion (past the length prefix).
pub fn to_passback_ptr_from_slice(buf: &[u8]) -> i32 {
    buf.as_ptr() as i32 + 4
}
