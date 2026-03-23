//! Tertiary indexer runtime with secondary storage read access.
//!
//! Extends the standard metashrew ABI with two additional host functions:
//!
//! - `__secondary_get_len(name_ptr, key_ptr) -> i32`
//! - `__secondary_get(name_ptr, key_ptr, value_ptr)`
//!
//! These let the WASM module read from named secondary indexer stores
//! (e.g., "alkanes", "esplora") without owning or modifying them.

use qubitcoin_indexer_core::proto::KeyValueFlush;
use qubitcoin_indexer_core::traits::IndexerStorageReader;

use js_sys::{Function, Object, Reflect, Uint8Array, WebAssembly};
use prost::Message;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::closure::WasmClosure;

/// A compiled tertiary indexer runtime.
///
/// Like `WebIndexerRuntime`, but its host imports include `__secondary_get_len`
/// and `__secondary_get` so the WASM can read secondary indexer state.
pub struct TertiaryRuntime {
    /// The compiled WASM module.
    module: WebAssembly::Module,
}

impl TertiaryRuntime {
    /// Compile a WASM module from bytes.
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, JsValue> {
        let uint8 = Uint8Array::from(wasm_bytes);
        let module = WebAssembly::Module::new(&uint8.into())?;
        Ok(TertiaryRuntime { module })
    }

    /// Run `_start()` for block processing.
    ///
    /// Input format: `[height_le32 ++ block_data]` (same as secondary indexers).
    ///
    /// `own_storage` — this tertiary indexer's own KV store (read/write).
    /// `secondary_storages` — named secondary stores (read-only).
    pub fn run_block(
        &self,
        height: u32,
        block_data: Vec<u8>,
        own_storage: &dyn IndexerStorageReader,
        secondary_storages: &HashMap<String, *const dyn IndexerStorageReader>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JsValue> {
        let mut input_data = Vec::with_capacity(4 + block_data.len());
        input_data.extend_from_slice(&height.to_le_bytes());
        input_data.extend_from_slice(&block_data);

        let state = Rc::new(RefCell::new(TertiaryHostState {
            input_data,
            pending_flush: None,
            // SAFETY: own_storage outlives the TertiaryHostState — the caller (DevnetState)
            // owns the storage and this function blocks until execution completes.
            own_storage_ref: unsafe {
                std::mem::transmute::<*const dyn IndexerStorageReader, *const dyn IndexerStorageReader>(
                    own_storage as *const dyn IndexerStorageReader
                )
            },
            secondary_storages: secondary_storages.clone(),
            had_failure: false,
            completed: false,
            memory: None,
        }));

        let (import_object, _closures) = self.build_imports(&state)?;
        let instance = WebAssembly::Instance::new(&self.module, &import_object)?;

        {
            let exports = instance.exports();
            let memory: WebAssembly::Memory =
                Reflect::get(&exports, &"memory".into())?.dyn_into()?;
            state.borrow_mut().memory = Some(memory);

            let start_fn: Function = Reflect::get(&exports, &"_start".into())?.dyn_into()?;
            start_fn.call0(&JsValue::NULL)?;
        }

        // CRITICAL: Clear ALL JS references to allow GC.
        state.borrow_mut().memory = None;
        drop(instance);
        drop(_closures);
        drop(import_object);

        let state = state.borrow();
        if state.had_failure {
            return Err(JsValue::from_str("Tertiary WASM module aborted"));
        }
        if !state.completed {
            return Err(JsValue::from_str("Tertiary WASM module did not call __flush"));
        }

        Ok(state.pending_flush.clone().unwrap_or_default())
    }

    /// Call a view function on the tertiary indexer.
    ///
    /// `own_storage` — this tertiary indexer's own KV store (read-only during views).
    /// `secondary_storages` — named secondary stores (read-only).
    pub fn call_view(
        &self,
        fn_name: &str,
        height: u32,
        payload: Vec<u8>,
        own_storage: &dyn IndexerStorageReader,
        secondary_storages: &HashMap<String, *const dyn IndexerStorageReader>,
    ) -> Result<Vec<u8>, JsValue> {
        let mut input_data = Vec::with_capacity(4 + payload.len());
        input_data.extend_from_slice(&height.to_le_bytes());
        input_data.extend_from_slice(&payload);

        let state = Rc::new(RefCell::new(TertiaryHostState {
            input_data,
            pending_flush: None,
            // SAFETY: own_storage outlives the TertiaryHostState — the caller (DevnetState)
            // owns the storage and this function blocks until execution completes.
            own_storage_ref: unsafe {
                std::mem::transmute::<*const dyn IndexerStorageReader, *const dyn IndexerStorageReader>(
                    own_storage as *const dyn IndexerStorageReader
                )
            },
            secondary_storages: secondary_storages.clone(),
            had_failure: false,
            completed: false,
            memory: None,
        }));

        let (import_object, _closures) = self.build_imports(&state)?;
        let instance = WebAssembly::Instance::new(&self.module, &import_object)?;

        let result = {
            let exports = instance.exports();
            let memory: WebAssembly::Memory =
                Reflect::get(&exports, &"memory".into())?.dyn_into()?;
            state.borrow_mut().memory = Some(memory.clone());

            let view_fn: Function = Reflect::get(&exports, &fn_name.into())?.dyn_into()?;
            let result_ptr = view_fn.call0(&JsValue::NULL)?;
            let ptr = result_ptr.as_f64().ok_or("view fn did not return i32")? as i32;

            read_arraybuffer(&memory, ptr)
        };

        // CRITICAL: Clear ALL JS references to allow GC.
        state.borrow_mut().memory = None;
        drop(instance);
        drop(_closures);
        drop(import_object);

        result
    }

    /// Build the JS import object with host functions.
    ///
    /// Returns `(imports_object, closures)`. The caller MUST hold `closures`
    /// alive for the duration of the WASM execution. When `closures` is dropped,
    /// the JS closures are freed, allowing GC of the associated
    /// `WebAssembly::Instance` and its linear memory.
    ///
    /// JOURNAL: 2026-03-22 — Previously used `Closure::forget()` which leaked
    /// closures per call. Each leaked closure prevented GC of the
    /// `WebAssembly::Memory`, causing OOM after many blocks.
    fn build_imports(
        &self,
        state: &Rc<RefCell<TertiaryHostState>>,
    ) -> Result<(Object, TertiaryImportClosures), JsValue> {
        let env = Object::new();
        let mut closures: Vec<TertiaryClosureHandle> = Vec::new();

        // __host_len() -> i32
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move || -> i32 {
                s.borrow().input_data.len() as i32
            }) as Box<dyn Fn() -> i32>);
            Reflect::set(&env, &"__host_len".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __load_input(ptr: i32)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |ptr: i32| {
                let st = s.borrow();
                let memory = st.memory.as_ref().expect("memory not set");
                write_to_memory(memory, ptr as u32, &st.input_data);
            }) as Box<dyn Fn(i32)>);
            Reflect::set(&env, &"__load_input".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __get_len(key_ptr: i32) -> i32  (reads from OWN storage)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |key_ptr: i32| -> i32 {
                let st = s.borrow();
                let memory = match st.memory.as_ref() {
                    Some(m) => m,
                    None => return 0,
                };
                let key = match read_arraybuffer(memory, key_ptr) {
                    Ok(k) => k,
                    Err(_) => return 0,
                };
                let storage = unsafe { &*st.own_storage_ref };
                match storage.get(&key) {
                    Some(v) => v.len() as i32,
                    None => 0,
                }
            }) as Box<dyn Fn(i32) -> i32>);
            Reflect::set(&env, &"__get_len".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __get(key_ptr: i32, value_ptr: i32)  (reads from OWN storage)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |key_ptr: i32, value_ptr: i32| {
                let st = s.borrow();
                let memory = match st.memory.as_ref() {
                    Some(m) => m,
                    None => return,
                };
                let key = match read_arraybuffer(memory, key_ptr) {
                    Ok(k) => k,
                    Err(_) => return,
                };
                let storage = unsafe { &*st.own_storage_ref };
                if let Some(value) = storage.get(&key) {
                    write_to_memory(memory, value_ptr as u32, &value);
                }
            }) as Box<dyn Fn(i32, i32)>);
            Reflect::set(&env, &"__get".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __secondary_get_len(name_ptr: i32, key_ptr: i32) -> i32
        //
        // Read the length of a value from a named secondary indexer's storage.
        // `name_ptr` points to an ArrayBuffer containing the indexer name (e.g., "alkanes").
        // `key_ptr` points to an ArrayBuffer containing the storage key.
        // Returns the byte length of the value, or 0 if not found.
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |name_ptr: i32, key_ptr: i32| -> i32 {
                let st = s.borrow();
                let memory = match st.memory.as_ref() {
                    Some(m) => m,
                    None => return 0,
                };
                let name_bytes = match read_arraybuffer(memory, name_ptr) {
                    Ok(b) => b,
                    Err(_) => return 0,
                };
                let name_str = match std::str::from_utf8(&name_bytes) {
                    Ok(s) => s,
                    Err(_) => return 0,
                };
                let key = match read_arraybuffer(memory, key_ptr) {
                    Ok(k) => k,
                    Err(_) => return 0,
                };
                let storage_ptr = match st.secondary_storages.get(name_str) {
                    Some(p) => *p,
                    None => return 0,
                };
                let storage = unsafe { &*storage_ptr };
                match storage.get(&key) {
                    Some(v) => v.len() as i32,
                    None => 0,
                }
            }) as Box<dyn Fn(i32, i32) -> i32>);
            Reflect::set(&env, &"__secondary_get_len".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __secondary_get(name_ptr: i32, key_ptr: i32, value_ptr: i32)
        //
        // Read a value from a named secondary indexer's storage into WASM memory.
        // The caller must have previously called __secondary_get_len to know the size
        // and allocated `value_ptr` with enough space.
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |name_ptr: i32, key_ptr: i32, value_ptr: i32| {
                let st = s.borrow();
                let memory = match st.memory.as_ref() {
                    Some(m) => m,
                    None => return,
                };
                let name_bytes = match read_arraybuffer(memory, name_ptr) {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let name_str = match std::str::from_utf8(&name_bytes) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let key = match read_arraybuffer(memory, key_ptr) {
                    Ok(k) => k,
                    Err(_) => return,
                };
                let storage_ptr = match st.secondary_storages.get(name_str) {
                    Some(p) => *p,
                    None => return,
                };
                let storage = unsafe { &*storage_ptr };
                if let Some(value) = storage.get(&key) {
                    write_to_memory(memory, value_ptr as u32, &value);
                }
            }) as Box<dyn Fn(i32, i32, i32)>);
            Reflect::set(&env, &"__secondary_get".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __flush(data_ptr: i32)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |data_ptr: i32| {
                let mut st = s.borrow_mut();
                let memory = match st.memory.as_ref() {
                    Some(m) => m.clone(),
                    None => {
                        st.had_failure = true;
                        return;
                    }
                };
                let data = match read_arraybuffer(&memory, data_ptr) {
                    Ok(d) => d,
                    Err(_) => {
                        st.had_failure = true;
                        return;
                    }
                };
                let flush_msg = match KeyValueFlush::decode(data.as_slice()) {
                    Ok(m) => m,
                    Err(_) => {
                        st.had_failure = true;
                        return;
                    }
                };
                let mut pairs = Vec::new();
                let list = &flush_msg.list;
                let mut i = 0;
                while i + 1 < list.len() {
                    pairs.push((list[i].to_vec(), list[i + 1].to_vec()));
                    i += 2;
                }
                st.pending_flush = Some(pairs);
                st.completed = true;
            }) as Box<dyn Fn(i32)>);
            Reflect::set(&env, &"__flush".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // __log(ptr: i32)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |ptr: i32| {
                let st = s.borrow();
                let memory = match st.memory.as_ref() {
                    Some(m) => m,
                    None => return,
                };
                if let Ok(msg_bytes) = read_arraybuffer(memory, ptr) {
                    if let Ok(msg) = String::from_utf8(msg_bytes) {
                        web_sys::console::log_1(&format!("[tertiary] {}", msg).into());
                    }
                }
            }) as Box<dyn Fn(i32)>);
            Reflect::set(&env, &"__log".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        // abort(msg_ptr, file_ptr, line, col)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |_msg: i32, _file: i32, _line: i32, _col: i32| {
                s.borrow_mut().had_failure = true;
            }) as Box<dyn Fn(i32, i32, i32, i32)>);
            Reflect::set(&env, &"abort".into(), closure.as_ref())?;
            closures.push(TertiaryClosureHandle::from_closure(closure));
        }

        let imports = Object::new();
        Reflect::set(&imports, &"env".into(), &env)?;
        Ok((imports, TertiaryImportClosures { _closures: closures }))
    }
}

/// Host state shared between closures during tertiary WASM execution.
struct TertiaryHostState {
    input_data: Vec<u8>,
    pending_flush: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    /// Pointer to this tertiary indexer's own storage (read/write).
    own_storage_ref: *const dyn IndexerStorageReader,
    /// Named secondary indexer storages (read-only).
    secondary_storages: HashMap<String, *const dyn IndexerStorageReader>,
    had_failure: bool,
    completed: bool,
    memory: Option<WebAssembly::Memory>,
}

/// Holds closures created for WASM host imports.
///
/// CRITICAL: Without this, each `run_block` / `call_view` call leaks closures
/// via `Closure::forget()`. Those leaked closures prevent GC of the
/// `WebAssembly::Memory` they captured, causing OOM after many blocks.
/// By storing closures here and dropping them when execution completes,
/// the JS GC can reclaim both the closures and the `WebAssembly::Instance` +
/// `Memory` they reference.
struct TertiaryImportClosures {
    _closures: Vec<TertiaryClosureHandle>,
}

/// Type-erased closure handle that drops the closure when dropped.
/// Type-erased closure handle — see `ClosureHandle` in qubitcoin-indexer-web
/// for detailed documentation.
struct TertiaryClosureHandle {
    _ref: JsValue,
}

impl TertiaryClosureHandle {
    fn from_closure<T: ?Sized + WasmClosure>(closure: Closure<T>) -> Self {
        TertiaryClosureHandle { _ref: closure.into_js_value() }
    }
}

/// Write bytes into WASM linear memory at the given offset.
fn write_to_memory(memory: &WebAssembly::Memory, offset: u32, data: &[u8]) {
    let buffer = memory.buffer();
    let mem = Uint8Array::new(&buffer);
    let data_arr = Uint8Array::from(data);
    mem.set(&data_arr, offset);
}

/// Read an AssemblyScript ArrayBuffer from WASM memory.
///
/// Layout: 4-byte LE length at `(ptr - 4)`, then `length` bytes at `ptr`.
fn read_arraybuffer(memory: &WebAssembly::Memory, ptr: i32) -> Result<Vec<u8>, JsValue> {
    if ptr < 4 {
        return Err(JsValue::from_str("invalid arraybuffer pointer"));
    }

    let buffer = memory.buffer();
    let mem = Uint8Array::new(&buffer);
    let len_offset = (ptr - 4) as u32;
    let mut len_bytes = [0u8; 4];
    for i in 0..4 {
        len_bytes[i] = mem.get_index(len_offset + i as u32);
    }
    let len = u32::from_le_bytes(len_bytes);

    let data_offset = ptr as u32;
    let mut data = vec![0u8; len as usize];
    for i in 0..len {
        data[i as usize] = mem.get_index(data_offset + i);
    }

    Ok(data)
}
