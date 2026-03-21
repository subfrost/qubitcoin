//! Client-side support library for authoring tertiary indexer WASMs.
//!
//! Provides extern declarations for all host functions (standard metashrew ABI
//! plus `__secondary_get_len` and `__secondary_get`), and high-level wrappers.
//!
//! # Usage
//!
//! ```rust,no_run
//! use qubitcoin_tertiary_support::*;
//! use std::sync::Arc;
//!
//! initialize();
//! let input_data = input();
//! let height = u32::from_le_bytes(input_data[0..4].try_into().unwrap());
//!
//! // Read from a secondary indexer
//! let value = secondary_get("alkanes", b"/some/key");
//!
//! // Write to own storage
//! set(Arc::new(b"my_key".to_vec()), Arc::new(b"my_value".to_vec()));
//! flush();
//! ```

extern crate alloc;

use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;

pub mod compat;
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/metashrew.rs"));
}

use proto::KeyValueFlush;

// ---------------------------------------------------------------------------
// Host function externs (provided by TertiaryRuntime)
// ---------------------------------------------------------------------------

extern "C" {
    fn __host_len() -> i32;
    fn __load_input(ptr: u32);
    fn __get_len(key_ptr: u32) -> i32;
    fn __get(key_ptr: u32, value_ptr: u32);
    fn __flush(data_ptr: u32);
    fn __log(ptr: u32);

    // Tertiary-specific: read from named secondary indexer stores
    fn __secondary_get_len(name_ptr: i32, key_ptr: i32) -> i32;
    fn __secondary_get(name_ptr: i32, key_ptr: i32, value_ptr: i32);
}

// ---------------------------------------------------------------------------
// Global cache (same pattern as metashrew-core)
// ---------------------------------------------------------------------------

static mut CACHE: Option<HashMap<Arc<Vec<u8>>, Arc<Vec<u8>>>> = None;
static mut TO_FLUSH: Option<Vec<Arc<Vec<u8>>>> = None;

/// Initialize the cache and flush queue.
#[allow(static_mut_refs)]
pub fn initialize() {
    unsafe {
        if CACHE.is_none() {
            TO_FLUSH = Some(Vec::new());
            CACHE = Some(HashMap::new());
        }
    }
}

/// Get a value from own storage with caching.
#[allow(static_mut_refs)]
pub fn get(v: Arc<Vec<u8>>) -> Arc<Vec<u8>> {
    unsafe {
        initialize();
        if let Some(cached) = CACHE.as_ref().unwrap().get(&v) {
            return cached.clone();
        }
        let key_buf = compat::to_arraybuffer_layout(v.as_ref());
        let key_ptr = compat::to_passback_ptr_from_slice(&key_buf);
        let length = __get_len(key_ptr as u32);
        let mut buffer = vec![0u8; (length as usize) + 4];
        buffer[..4].copy_from_slice(&length.to_le_bytes());
        let val_ptr = buffer.as_mut_ptr() as u32 + 4;
        __get(key_ptr as u32, val_ptr);
        let value = Arc::new(buffer[4..].to_vec());
        CACHE.as_mut().unwrap().insert(v.clone(), value.clone());
        value
    }
}

/// Set a value in own storage (written on flush).
#[allow(static_mut_refs)]
pub fn set(k: Arc<Vec<u8>>, v: Arc<Vec<u8>>) {
    unsafe {
        initialize();
        CACHE.as_mut().unwrap().insert(k.clone(), v);
        TO_FLUSH.as_mut().unwrap().push(k);
    }
}

/// Flush all pending writes to own storage.
#[allow(static_mut_refs)]
pub fn flush() {
    unsafe {
        initialize();
        let mut to_encode = Vec::new();
        for item in TO_FLUSH.as_ref().unwrap() {
            to_encode.push((*item.clone()).clone());
            to_encode.push((*(CACHE.as_ref().unwrap().get(item).unwrap().clone())).clone());
        }
        TO_FLUSH = Some(Vec::new());
        let msg = KeyValueFlush { list: to_encode };
        let serialized = msg.encode_to_vec();
        let mut buf = compat::to_arraybuffer_layout(&serialized);
        let ptr = buf.as_mut_ptr() as u32 + 4;
        __flush(ptr);
    }
}

/// Load the input data (height_le32 + block_bytes).
pub fn input() -> Vec<u8> {
    initialize();
    unsafe {
        let length = __host_len();
        let mut buffer = vec![0u8; (length as usize) + 4];
        buffer[..4].copy_from_slice(&length.to_le_bytes());
        let ptr = buffer.as_mut_ptr() as u32 + 4;
        __load_input(ptr);
        buffer[4..].to_vec()
    }
}

/// Read a value from a named secondary indexer's storage.
///
/// Returns `None` if the indexer name is unknown or the key is not found.
///
/// # Arguments
/// * `indexer_name` — e.g., `"alkanes"` or `"esplora"`
/// * `key` — raw storage key bytes
pub fn secondary_get(indexer_name: &str, key: &[u8]) -> Option<Vec<u8>> {
    let name_buf = compat::to_arraybuffer_layout(indexer_name.as_bytes());
    let name_ptr = compat::to_passback_ptr_from_slice(&name_buf);
    let key_buf = compat::to_arraybuffer_layout(key);
    let key_ptr = compat::to_passback_ptr_from_slice(&key_buf);

    let len = unsafe { __secondary_get_len(name_ptr, key_ptr) };
    if len == 0 {
        return None;
    }

    let mut val_buffer = vec![0u8; (len as usize) + 4];
    val_buffer[..4].copy_from_slice(&len.to_le_bytes());
    let val_ptr = val_buffer.as_mut_ptr() as i32 + 4;
    unsafe { __secondary_get(name_ptr, key_ptr, val_ptr) };
    Some(val_buffer[4..].to_vec())
}

/// Log a message to the host console.
pub fn log(msg: &str) {
    let mut buf = compat::to_arraybuffer_layout(msg.as_bytes());
    let ptr = buf.as_mut_ptr() as u32 + 4;
    unsafe { __log(ptr) };
}

/// Export bytes with ArrayBuffer layout for view function return values.
///
/// Returns a pointer suitable for returning from a `#[no_mangle] pub extern "C" fn`.
pub fn export_bytes(bytes: Vec<u8>) -> u32 {
    let mut buffer = Vec::with_capacity(bytes.len() + 4);
    let len = bytes.len() as u32;
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(&bytes);
    let ptr = Box::leak(Box::new(buffer)).as_mut_ptr() as u32;
    ptr + 4
}
