//! Browser-native WebAssembly indexer runtime.
//!
//! Uses `js_sys::WebAssembly` to instantiate and run metashrew-compatible
//! WASM indexer modules in the browser or Node.js environment.

use crate::storage::WebIndexerStorage;
use js_sys::{Function, Object, Reflect, Uint8Array, WebAssembly};
use prost::Message;
use qubitcoin_indexer_core::proto::KeyValueFlush;
use qubitcoin_indexer_core::traits::IndexerStorageReader;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A compiled web indexer runtime.
pub struct WebIndexerRuntime {
    /// The compiled WASM module.
    module: WebAssembly::Module,
}

impl WebIndexerRuntime {
    /// Compile a WASM module from bytes.
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, JsValue> {
        let uint8 = Uint8Array::from(wasm_bytes);
        let module = WebAssembly::Module::new(&uint8.into())?;
        Ok(WebIndexerRuntime { module })
    }

    /// Run `_start()` for block processing.
    ///
    /// The `height` is prepended as a 4-byte little-endian prefix to `block_data`,
    /// matching the metashrew ABI that WASM indexers expect from `__load_input`.
    ///
    /// Returns the key-value pairs to flush to storage.
    pub fn run_block(
        &self,
        height: u32,
        block_data: Vec<u8>,
        storage: &WebIndexerStorage,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JsValue> {
        // Metashrew ABI: input = [height_le32 ++ block_data]
        let mut input_data = Vec::with_capacity(4 + block_data.len());
        input_data.extend_from_slice(&height.to_le_bytes());
        input_data.extend_from_slice(&block_data);

        let state = Rc::new(RefCell::new(HostState {
            input_data,
            pending_flush: None,
            storage_ref: storage as *const WebIndexerStorage,
            had_failure: false,
            completed: false,
            memory: None,
        }));

        let import_object = self.build_imports(&state)?;
        let instance = WebAssembly::Instance::new(&self.module, &import_object)?;

        // Extract memory and store it in HostState before calling _start.
        let exports = instance.exports();
        let memory: WebAssembly::Memory =
            Reflect::get(&exports, &"memory".into())?.dyn_into()?;
        state.borrow_mut().memory = Some(memory);

        let start_fn: Function = Reflect::get(&exports, &"_start".into())?.dyn_into()?;
        start_fn.call0(&JsValue::NULL)?;

        let state = state.borrow();
        if state.had_failure {
            return Err(JsValue::from_str("WASM module aborted"));
        }
        if !state.completed {
            return Err(JsValue::from_str("WASM module did not call __flush"));
        }

        Ok(state.pending_flush.clone().unwrap_or_default())
    }

    /// Call a view function.
    ///
    /// The `height` is prepended as a 4-byte little-endian prefix to `payload`,
    /// matching the metashrew ABI that WASM indexers expect from `__load_input`.
    pub fn call_view(
        &self,
        fn_name: &str,
        height: u32,
        payload: Vec<u8>,
        storage: &WebIndexerStorage,
    ) -> Result<Vec<u8>, JsValue> {
        // Metashrew ABI: input = [height_le32 ++ payload]
        let mut input_data = Vec::with_capacity(4 + payload.len());
        input_data.extend_from_slice(&height.to_le_bytes());
        input_data.extend_from_slice(&payload);

        let state = Rc::new(RefCell::new(HostState {
            input_data,
            pending_flush: None,
            storage_ref: storage as *const WebIndexerStorage,
            had_failure: false,
            completed: false,
            memory: None,
        }));

        let import_object = self.build_imports(&state)?;
        let instance = WebAssembly::Instance::new(&self.module, &import_object)?;

        // Extract memory and store it in HostState before calling the view fn.
        let exports = instance.exports();
        let memory: WebAssembly::Memory =
            Reflect::get(&exports, &"memory".into())?.dyn_into()?;
        state.borrow_mut().memory = Some(memory.clone());

        let view_fn: Function = Reflect::get(&exports, &fn_name.into())?.dyn_into()?;
        let result_ptr = view_fn.call0(&JsValue::NULL)?;
        let ptr = result_ptr.as_f64().ok_or("view fn did not return i32")? as i32;

        read_arraybuffer(&memory, ptr)
    }

    /// Build the JS import object with host functions.
    fn build_imports(
        &self,
        state: &Rc<RefCell<HostState>>,
    ) -> Result<Object, JsValue> {
        let env = Object::new();

        // __host_len() -> i32
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move || -> i32 {
                s.borrow().input_data.len() as i32
            }) as Box<dyn Fn() -> i32>);
            Reflect::set(&env, &"__host_len".into(), closure.as_ref())?;
            closure.forget();
        }

        // __load_input(ptr: i32)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |ptr: i32| {
                let st = s.borrow();
                let memory = st.memory.as_ref().expect("memory not set");
                let data = &st.input_data;
                write_to_memory(memory, ptr as u32, data);
            }) as Box<dyn Fn(i32)>);
            Reflect::set(&env, &"__load_input".into(), closure.as_ref())?;
            closure.forget();
        }

        // __get_len(key_ptr: i32) -> i32
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
                let storage = unsafe { &*st.storage_ref };
                let result = match storage.get(&key) {
                    Some(v) => v.len() as i32,
                    None => 0,
                };
                // Log ALL non-zero reads for protorune keys
                if result > 0 && key.starts_with(b"/runes/proto/") {
                    web_sys::console::log_1(&format!(
                        "[__get_len] HIT proto key_len={} val_len={}", key.len(), result
                    ).into());
                }
                result
            }) as Box<dyn Fn(i32) -> i32>);
            Reflect::set(&env, &"__get_len".into(), closure.as_ref())?;
            closure.forget();
        }

        // __get(key_ptr: i32, value_ptr: i32)
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
                let storage = unsafe { &*st.storage_ref };
                // Use raw get — matches raw put in index_block
                if let Some(value) = storage.get(&key) {
                    write_to_memory(memory, value_ptr as u32, &value);
                }
            }) as Box<dyn Fn(i32, i32)>);
            Reflect::set(&env, &"__get".into(), closure.as_ref())?;
            closure.forget();
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
            closure.forget();
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
                // Read and log the message via web_sys::console
                if let Ok(msg_bytes) = read_arraybuffer(memory, ptr) {
                    if let Ok(msg) = String::from_utf8(msg_bytes) {
                        web_sys::console::log_1(&msg.into());
                    }
                }
            }) as Box<dyn Fn(i32)>);
            Reflect::set(&env, &"__log".into(), closure.as_ref())?;
            closure.forget();
        }

        // abort(msg_ptr, file_ptr, line, col)
        {
            let s = state.clone();
            let closure = Closure::wrap(Box::new(move |_msg: i32, _file: i32, _line: i32, _col: i32| {
                s.borrow_mut().had_failure = true;
            }) as Box<dyn Fn(i32, i32, i32, i32)>);
            Reflect::set(&env, &"abort".into(), closure.as_ref())?;
            closure.forget();
        }

        let imports = Object::new();
        Reflect::set(&imports, &"env".into(), &env)?;
        Ok(imports)
    }
}

/// Host state shared between closures during WASM execution.
struct HostState {
    input_data: Vec<u8>,
    pending_flush: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    storage_ref: *const WebIndexerStorage,
    had_failure: bool,
    completed: bool,
    /// Set after instantiation, before calling _start or view fn.
    memory: Option<WebAssembly::Memory>,
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
    let len = u32::from_le_bytes(len_bytes) as u32;

    let data_offset = ptr as u32;
    let mut data = vec![0u8; len as usize];
    for i in 0..len {
        data[i as usize] = mem.get_index(data_offset + i);
    }

    Ok(data)
}
