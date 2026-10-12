//! The `bpf` program kind for user-registered DAG nodes.
//!
//! A BPF node is a userspace eBPF program run by `solana-sbpf`'s interpreter
//! (no JIT). It is the eBPF twin of the `wasm` kind: it indexes a block per
//! invocation, keeps its own namespaced KV store, may read only its declared
//! upstreams, and answers views. The ABI is documented in
//! `docs/INDEXER-DAG.md` ("BPF programs"); in short:
//!
//! * **Format.** The program is raw SBPF **v3** bytecode (8-byte
//!   instructions, the text section only, entry at instruction 0). v3 is
//!   classic eBPF plus static helper calls (`call` with `src = 0` and
//!   `imm = helper id`) and pc-relative internal calls. [`assemble`] turns
//!   solana-sbpf assembly into such bytecode.
//! * **Verification.** At registration the program is run through
//!   solana-sbpf's `RequisiteVerifier` (opcodes, registers, jump targets,
//!   `lddw` pairs, shifts, division by an immediate zero) and
//!   `LocalVerifier` (every helper call names a known helper), plus a size
//!   cap. A rejected program is never stored.
//! * **Entry.** One entrypoint. `r1` is the mode (0 = block, 1 = view) and
//!   `r2` the input length. `r0 = 0` on exit means success; anything else
//!   fails the invocation.
//! * **Caps.** An instruction meter (the node's fuel cap: one instruction =
//!   one unit of fuel, helpers charge extra) bounds every invocation, the
//!   stack is 16 frames of 4 KiB, the heap is a fixed zeroed region (1 MiB,
//!   or the node's memory cap if smaller), and pending KV writes, emitted
//!   bytes and log lines are bounded. The wall-clock deadline is checked at
//!   each helper call; the instruction cap is the hard bound.
//! * **Helpers** (numbered by solana-sbpf's static-syscall id, the
//!   murmur3-32 hash of the name; see [`HELPERS`]): `get_input`,
//!   `upstream_view`, `secondary_get`, `kv_get`, `kv_set`, `emit`, `log`.

use crate::dag::DagAccess;
use crate::store::LayeredReader;
use qubitcoin_indexer_fork::{ExecError, ExecErrorKind, ExecLimits, ExecOutcome};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    declare_builtin_function, ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult, StableResult},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunctionDefinition, BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::{LocalVerifier, RequisiteVerifier},
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// `r1` on entry: index the block returned by `get_input`.
pub const MODE_BLOCK: u64 = 0;
/// `r1` on entry: answer the view named in the input.
pub const MODE_VIEW: u64 = 1;

/// The SBPF version user programs are assembled and run as.
pub const SBPF_VERSION: SBPFVersion = SBPFVersion::V3;
/// Largest accepted program, in instructions.
pub const MAX_PROGRAM_INSNS: usize = 65_536;
/// Call depth (stack frames of `STACK_FRAME_BYTES`).
pub const MAX_CALL_DEPTH: usize = 16;
/// Heap region size (capped by the node's memory cap).
pub const HEAP_BYTES: usize = 1 << 20;
/// Fixed cost of one helper call, on top of the instruction itself.
pub const HELPER_COST: u64 = 100;
/// Extra cost per 8 bytes a helper moves.
pub const HELPER_COST_PER_WORD: u64 = 1;
/// Extra cost of an `upstream_view` (on top of the bytes moved).
pub const UPSTREAM_VIEW_COST: u64 = 10_000;
/// Pending KV write bytes (keys + values) one invocation may buffer.
pub const MAX_PENDING_WRITE_BYTES: usize = 64 << 20;
/// Bytes one invocation may `emit`.
pub const MAX_EMIT_BYTES: usize = 4 << 20;
/// `log` lines kept per invocation; later lines are dropped (and counted).
pub const MAX_LOG_LINES: usize = 32;
/// Longest `log` line kept (longer lines are truncated).
pub const MAX_LOG_LINE: usize = 256;
/// Returned by `kv_get` / `secondary_get` for an absent key.
pub const ABSENT: u64 = u64::MAX;
/// Keys starting with this byte belong to the host; `kv_set` refuses them.
pub const RESERVED_KEY_BYTE: u8 = 0xff;
/// The host-provided view returning what a block `emit`ted.
pub const EMITTED_VIEW: &str = "__emitted";

/// The helper names, in ABI order. A helper's call id is
/// [`helper_id`]`(name)`.
pub const HELPERS: [&str; 7] = ["get_input", "upstream_view", "secondary_get", "kv_get", "kv_set", "emit", "log"];

/// The `imm` a program uses to call helper `name` (`call` with `src = 0`).
pub fn helper_id(name: &str) -> u32 {
    ebpf::hash_symbol_name(name.as_bytes())
}

/// Own-store key holding what the block at `height` emitted.
pub fn emit_key(height: u32) -> Vec<u8> {
    let mut k = vec![RESERVED_KEY_BYTE];
    k.extend_from_slice(b"emit/");
    k.extend_from_slice(&height.to_be_bytes());
    k
}

/// Per-invocation state the helpers act on.
pub struct BpfCtx {
    remaining: u64,
    mapping: Option<MemoryMapping>,
    mode: u64,
    input: Vec<u8>,
    access: DagAccess,
    reader: LayeredReader,
    writes: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_bytes: usize,
    emitted: Vec<u8>,
    logs: Vec<String>,
    dropped_logs: u64,
    host_error: Option<(ExecErrorKind, String)>,
    deadline: Option<Instant>,
}

impl ContextObject for BpfCtx {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
    fn active_mapping_ptr(&mut self) -> std::ptr::NonNull<MemoryMapping> {
        std::ptr::NonNull::from(self.mapping.as_mut().expect("memory mapping set before the VM"))
    }
}

/// A helper failure; the details are in `BpfCtx::host_error`.
#[derive(Debug)]
struct HelperFault;

impl std::fmt::Display for HelperFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper failed")
    }
}
impl std::error::Error for HelperFault {}

type HelperResult = Result<u64, Box<dyn std::error::Error>>;

impl BpfCtx {
    fn fail(&mut self, kind: ExecErrorKind, msg: impl Into<String>) -> Box<dyn std::error::Error> {
        if self.host_error.is_none() {
            self.host_error = Some((kind, msg.into()));
        }
        Box::new(HelperFault)
    }

    /// Charge a helper call moving `bytes` bytes, and check the deadline.
    fn enter(&mut self, bytes: usize) -> Result<(), Box<dyn std::error::Error>> {
        self.consume(HELPER_COST + (bytes as u64).div_ceil(8) * HELPER_COST_PER_WORD);
        if let Some(d) = self.deadline {
            if Instant::now() >= d {
                return Err(self.fail(ExecErrorKind::Deadline, "deadline exceeded"));
            }
        }
        Ok(())
    }

    fn read(&mut self, addr: u64, len: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let m = self.mapping.as_ref().unwrap();
        match m.map(AccessType::Load, addr, len) {
            StableResult::Ok(hb) => {
                // SAFETY: the mapping only hands out buffers inside the
                // regions set up for this invocation, which outlive it.
                Ok(unsafe { &*hb.ptr() }.to_vec())
            }
            StableResult::Err(e) => Err(self.fail(ExecErrorKind::Failed, format!("helper read: {}", e))),
        }
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if data.is_empty() {
            return Ok(());
        }
        let m = self.mapping.as_ref().unwrap();
        match m.map(AccessType::Store, addr, data.len() as u64) {
            StableResult::Ok(hb) => {
                // SAFETY: as in `read`; `map` refused read-only regions for a store.
                unsafe { (&mut *hb.ptr_mut()).copy_from_slice(data) };
                Ok(())
            }
            StableResult::Err(e) => Err(self.fail(ExecErrorKind::Failed, format!("helper write: {}", e))),
        }
    }

    /// Copy `min(len(v), cap)` bytes of `v` to `out` and return `len(v)`.
    fn copy_out(&mut self, v: &[u8], out: u64, cap: u64) -> HelperResult {
        let n = v.len().min(cap as usize);
        self.write(out, &v[..n])?;
        Ok(v.len() as u64)
    }

    fn upstream(&mut self, idx: u64) -> Result<String, Box<dyn std::error::Error>> {
        match self.access.allowed.get(idx as usize) {
            Some(n) => Ok(n.clone()),
            None => {
                let msg = format!(
                    "access denied: upstream #{} is not declared by '{}' ({} declared)",
                    idx,
                    self.access.node,
                    self.access.allowed.len()
                );
                Err(self.fail(ExecErrorKind::Host, msg))
            }
        }
    }
}

declare_builtin_function!(
    /// `get_input(buf, len, offset) -> total`: copy input bytes
    /// `[offset, offset + len)` (clamped) to `buf`; returns the input length.
    GetInput,
    fn rust(ctx: &mut BpfCtx, buf: u64, len: u64, offset: u64, _d: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        let total = ctx.input.len();
        let start = (offset as usize).min(total);
        let n = (len as usize).min(total - start);
        ctx.enter(n)?;
        let chunk = ctx.input[start..start + n].to_vec();
        ctx.write(buf, &chunk)?;
        Ok(total as u64)
    }
);

declare_builtin_function!(
    /// `upstream_view(upstream_idx, view_ptr, view_len, args_ptr) -> len`,
    /// `args_ptr` → `[in_ptr, in_len, out_ptr, out_cap]` (4 × u64 LE).
    UpstreamView,
    fn rust(ctx: &mut BpfCtx, idx: u64, view_ptr: u64, view_len: u64, args_ptr: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        ctx.enter(0)?;
        ctx.consume(UPSTREAM_VIEW_COST);
        let name = ctx.upstream(idx)?;
        let view = ctx.read(view_ptr, view_len.min(256))?;
        let view = String::from_utf8(view).map_err(|_| ctx.fail(ExecErrorKind::Failed, "view name is not UTF-8"))?;
        let args = ctx.read(args_ptr, 32)?;
        let w = |i: usize| u64::from_le_bytes(args[i * 8..i * 8 + 8].try_into().unwrap());
        let (in_ptr, in_len, out_ptr, out_cap) = (w(0), w(1), w(2), w(3));
        let input = ctx.read(in_ptr, in_len)?;
        ctx.enter(input.len())?;
        let access = ctx.access.clone();
        let r = crate::simulation::run_blocking(async move { access.view(&name, &view, input).await });
        match r {
            Ok(v) => {
                ctx.enter(v.len().min(out_cap as usize))?;
                ctx.copy_out(&v, out_ptr, out_cap)
            }
            Err(e) => Err(ctx.fail(ExecErrorKind::Host, e)),
        }
    }
);

declare_builtin_function!(
    /// `secondary_get(upstream_idx, key_ptr, key_len, out_ptr, out_cap) -> len | ABSENT`.
    SecondaryGet,
    fn rust(ctx: &mut BpfCtx, idx: u64, key_ptr: u64, key_len: u64, out_ptr: u64, out_cap: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        ctx.enter(key_len as usize)?;
        let name = ctx.upstream(idx)?;
        let key = ctx.read(key_ptr, key_len)?;
        match ctx.access.kv_get(&name, &key) {
            Ok(Some(v)) => {
                ctx.enter(v.len().min(out_cap as usize))?;
                ctx.copy_out(&v, out_ptr, out_cap)
            }
            Ok(None) => Ok(ABSENT),
            Err(e) => Err(ctx.fail(ExecErrorKind::Host, e)),
        }
    }
);

declare_builtin_function!(
    /// `kv_get(key_ptr, key_len, out_ptr, out_cap) -> len | ABSENT` (own store).
    KvGet,
    fn rust(ctx: &mut BpfCtx, key_ptr: u64, key_len: u64, out_ptr: u64, out_cap: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        ctx.enter(key_len as usize)?;
        let key = ctx.read(key_ptr, key_len)?;
        let v = match ctx.writes.get(&key) {
            Some(v) => Some(v.clone()),
            None => ctx.reader.get(&key).map_err(|e| ctx.fail(ExecErrorKind::Host, e))?,
        };
        match v {
            Some(v) => {
                ctx.enter(v.len().min(out_cap as usize))?;
                ctx.copy_out(&v, out_ptr, out_cap)
            }
            None => Ok(ABSENT),
        }
    }
);

declare_builtin_function!(
    /// `kv_set(key_ptr, key_len, val_ptr, val_len) -> 0` (own store, block mode).
    KvSet,
    fn rust(ctx: &mut BpfCtx, key_ptr: u64, key_len: u64, val_ptr: u64, val_len: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        ctx.enter((key_len + val_len) as usize)?;
        if ctx.mode != MODE_BLOCK {
            return Err(ctx.fail(ExecErrorKind::Host, "kv_set is not allowed in a view"));
        }
        let key = ctx.read(key_ptr, key_len)?;
        if key.first() == Some(&RESERVED_KEY_BYTE) {
            return Err(ctx.fail(ExecErrorKind::Host, "kv_set: keys starting with 0xff are reserved"));
        }
        let val = ctx.read(val_ptr, val_len)?;
        ctx.pending_bytes += key.len() + val.len();
        if ctx.pending_bytes > MAX_PENDING_WRITE_BYTES {
            return Err(ctx.fail(
                ExecErrorKind::Memory,
                format!("pending writes exceed {} bytes", MAX_PENDING_WRITE_BYTES),
            ));
        }
        ctx.writes.insert(key, val);
        Ok(0)
    }
);

declare_builtin_function!(
    /// `emit(ptr, len) -> total`: append to the invocation's output.
    Emit,
    fn rust(ctx: &mut BpfCtx, ptr: u64, len: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        ctx.enter(len as usize)?;
        if ctx.emitted.len() + len as usize > MAX_EMIT_BYTES {
            return Err(ctx.fail(ExecErrorKind::Memory, format!("emit exceeds {} bytes", MAX_EMIT_BYTES)));
        }
        let b = ctx.read(ptr, len)?;
        ctx.emitted.extend_from_slice(&b);
        Ok(ctx.emitted.len() as u64)
    }
);

declare_builtin_function!(
    /// `log(ptr, len) -> 0 (kept) | 1 (dropped by the rate limit)`.
    Log,
    fn rust(ctx: &mut BpfCtx, ptr: u64, len: u64, _c: u64, _d: u64, _e: u64,) -> Result<u64, Box<dyn std::error::Error>> {
        let len = len.min(MAX_LOG_LINE as u64);
        ctx.enter(len as usize)?;
        if ctx.logs.len() >= MAX_LOG_LINES {
            ctx.dropped_logs += 1;
            return Ok(1);
        }
        let b = ctx.read(ptr, len)?;
        ctx.logs.push(String::from_utf8_lossy(&b).into_owned());
        Ok(0)
    }
);

fn loader() -> Arc<BuiltinProgram<BpfCtx>> {
    static LOADER: OnceLock<Arc<BuiltinProgram<BpfCtx>>> = OnceLock::new();
    LOADER
        .get_or_init(|| {
            let config = Config {
                max_call_depth: MAX_CALL_DEPTH,
                enable_instruction_meter: true,
                enable_address_translation: true,
                reject_broken_elfs: true,
                enabled_sbpf_versions: SBPF_VERSION..=SBPF_VERSION,
                ..Config::default()
            };
            let mut l = BuiltinProgram::new_loader(config);
            GetInput::register(&mut l, "get_input").unwrap();
            UpstreamView::register(&mut l, "upstream_view").unwrap();
            SecondaryGet::register(&mut l, "secondary_get").unwrap();
            KvGet::register(&mut l, "kv_get").unwrap();
            KvSet::register(&mut l, "kv_set").unwrap();
            Emit::register(&mut l, "emit").unwrap();
            Log::register(&mut l, "log").unwrap();
            Arc::new(l)
        })
        .clone()
}

/// Assemble solana-sbpf assembly (SBPF v3; helpers by name, e.g.
/// `syscall kv_get`) into program bytes for `registerdagnode … "bpf"`.
pub fn assemble(src: &str) -> Result<Vec<u8>, String> {
    let exe = solana_sbpf::assembler::assemble::<BpfCtx>(src, loader())?;
    Ok(exe.get_text_bytes().1.to_vec())
}

/// What one invocation produced.
#[derive(Debug, Default)]
pub struct BpfRun {
    /// Own-store writes (block mode), sorted by key; includes the
    /// [`emit_key`] entry when the block emitted anything.
    pub pairs: Vec<(Vec<u8>, Vec<u8>)>,
    /// Bytes passed to `emit`.
    pub emitted: Vec<u8>,
    /// Kept `log` lines.
    pub logs: Vec<String>,
    /// `log` calls dropped by the rate limit.
    pub dropped_logs: u64,
}

/// A verified BPF program.
#[derive(Debug)]
pub struct BpfProgram {
    bytes: Vec<u8>,
}

impl BpfProgram {
    /// Verify `bytes` (raw SBPF v3 bytecode).
    pub fn new(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() % ebpf::INSN_SIZE != 0 {
            return Err(format!("verifier: program length {} is not a non-zero multiple of 8", bytes.len()));
        }
        if bytes.len() / ebpf::INSN_SIZE > MAX_PROGRAM_INSNS {
            return Err(format!("verifier: program exceeds {} instructions", MAX_PROGRAM_INSNS));
        }
        if bytes.starts_with(b"\x7fELF") {
            return Err("verifier: ELF is not accepted; pass the raw SBPF v3 text section".into());
        }
        let exe = Self::executable(bytes)?;
        exe.verify::<RequisiteVerifier>().map_err(|e| format!("verifier: {}", e))?;
        exe.verify::<LocalVerifier>().map_err(|e| format!("verifier: {}", e))?;
        Ok(BpfProgram { bytes: bytes.to_vec() })
    }

    fn executable(bytes: &[u8]) -> Result<Executable<BpfCtx>, String> {
        Executable::from_text_bytes(bytes, loader(), SBPF_VERSION, FunctionRegistry::default())
            .map_err(|e| format!("verifier: {}", e))
    }

    /// Index one block: input `height_le32 ++ block`.
    pub fn run_block(
        &self,
        height: u32,
        block: &[u8],
        reader: LayeredReader,
        access: DagAccess,
        limits: ExecLimits,
    ) -> Result<ExecOutcome<BpfRun>, ExecError> {
        let mut input = Vec::with_capacity(4 + block.len());
        input.extend_from_slice(&height.to_le_bytes());
        input.extend_from_slice(block);
        let mut out = self.invoke(MODE_BLOCK, input, reader, access, limits)?;
        if !out.value.emitted.is_empty() {
            let k = emit_key(height);
            out.value.pairs.push((k, out.value.emitted.clone()));
        }
        Ok(out)
    }

    /// Answer `view_fn(input)` as of `height` (`reader` reads the store at
    /// that height). The result is what the program emitted. The host view
    /// [`EMITTED_VIEW`] returns what the block at `height` emitted.
    pub fn view(
        &self,
        view_fn: &str,
        input: &[u8],
        height: u32,
        reader: LayeredReader,
        access: DagAccess,
        limits: ExecLimits,
    ) -> Result<ExecOutcome<Vec<u8>>, ExecError> {
        if view_fn == EMITTED_VIEW {
            let v = reader.get(&emit_key(height)).map_err(|e| ExecError {
                kind: ExecErrorKind::Host,
                message: e,
                fuel_used: 0,
            })?;
            return Ok(ExecOutcome { value: v.unwrap_or_default(), fuel_used: 0 });
        }
        let mut full = Vec::with_capacity(8 + view_fn.len() + input.len());
        full.extend_from_slice(&height.to_le_bytes());
        full.extend_from_slice(&(view_fn.len() as u32).to_le_bytes());
        full.extend_from_slice(view_fn.as_bytes());
        full.extend_from_slice(input);
        let out = self.invoke(MODE_VIEW, full, reader, access, limits)?;
        Ok(ExecOutcome { value: out.value.emitted, fuel_used: out.fuel_used })
    }

    fn invoke(
        &self,
        mode: u64,
        input: Vec<u8>,
        reader: LayeredReader,
        access: DagAccess,
        limits: ExecLimits,
    ) -> Result<ExecOutcome<BpfRun>, ExecError> {
        let failed = |kind, message: String, fuel_used| ExecError { kind, message, fuel_used };
        let exe = Self::executable(&self.bytes).map_err(|e| failed(ExecErrorKind::Failed, e, 0))?;
        let cap = limits.fuel.unwrap_or(u64::MAX);
        let config = exe.get_config();
        let heap_len = limits.max_memory_bytes.map(|m| m.min(HEAP_BYTES)).unwrap_or(HEAP_BYTES);
        let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(heap_len);
        let stack_len = stack.len();
        let regions: Vec<MemoryRegion> = vec![
            exe.get_ro_region(),
            MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
            MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
        ];
        // SAFETY: `stack`, `heap` and `exe` (the read-only region) outlive
        // every use of the mapping, which is dropped with `ctx` below.
        let mapping = unsafe { MemoryMapping::new(regions, config, SBPF_VERSION) }
            .map_err(|e| failed(ExecErrorKind::Failed, format!("memory mapping: {}", e), 0))?;
        let input_len = input.len() as u64;
        let mut ctx = BpfCtx {
            remaining: cap,
            mapping: Some(mapping),
            mode,
            input,
            access,
            reader,
            writes: BTreeMap::new(),
            pending_bytes: 0,
            emitted: Vec::new(),
            logs: Vec::new(),
            dropped_logs: 0,
            host_error: None,
            deadline: limits.deadline.map(|d| Instant::now() + d),
        };
        let (count, result) = {
            let mut vm = EbpfVm::new(loader(), SBPF_VERSION, &mut ctx, stack_len);
            vm.registers[1] = mode;
            vm.registers[2] = input_len;
            let mut frames = vec![CallFrame::default(); config.max_call_depth];
            vm.execute_program(&exe, &mut ExecutionMode::Interpreted, &mut frames)
        };
        let fuel_used = count.min(cap);
        let r = match result {
            ProgramResult::Ok(0) => Ok(()),
            ProgramResult::Ok(code) => Err(failed(ExecErrorKind::Failed, format!("program exited with r0 = {}", code), fuel_used)),
            ProgramResult::Err(EbpfError::ExceededMaxInstructions) => Err(failed(
                ExecErrorKind::OutOfFuel,
                format!("instruction cap of {} exhausted", cap),
                cap,
            )),
            ProgramResult::Err(EbpfError::SyscallError(_)) => {
                let (kind, msg) = ctx.host_error.take().unwrap_or((ExecErrorKind::Failed, "helper failed".into()));
                Err(failed(kind, msg, fuel_used))
            }
            ProgramResult::Err(e) => Err(failed(ExecErrorKind::Failed, e.to_string(), fuel_used)),
        };
        // The mapping points into `stack` / `heap`; drop it before them.
        ctx.mapping = None;
        drop(stack);
        drop(heap);
        r?;
        if ctx.dropped_logs > 0 {
            tracing::debug!(node = %ctx.access.node, dropped = ctx.dropped_logs, "bpf log lines dropped by the rate limit");
        }
        for l in &ctx.logs {
            tracing::debug!(node = %ctx.access.node, "bpf log: {}", l);
        }
        Ok(ExecOutcome {
            value: BpfRun {
                pairs: std::mem::take(&mut ctx.writes).into_iter().collect(),
                emitted: ctx.emitted,
                logs: ctx.logs,
                dropped_logs: ctx.dropped_logs,
            },
            fuel_used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_ids_are_stable() {
        // These are part of the ABI (docs/INDEXER-DAG.md); never change them.
        let ids: Vec<u32> = HELPERS.iter().map(|n| helper_id(n)).collect();
        assert_eq!(
            ids,
            vec![0x79b36278, 0x6b5d9eb8, 0x7528dfa6, 0x1c9fb127, 0x8c33b6d3, 0x61390aef, 0x6bf5c3fe]
        );
    }

    #[test]
    fn verifier_rejects_malformed_programs() {
        assert!(BpfProgram::new(&[0x95, 0, 0, 0, 0, 0, 0]).unwrap_err().contains("multiple of 8"));
        assert!(BpfProgram::new(&[]).is_err());
        let unknown = assemble("syscall no_such_helper\nexit").unwrap();
        assert!(BpfProgram::new(&unknown).unwrap_err().contains("syscall"));
        let jump = assemble("ja +5\nexit").unwrap();
        assert!(BpfProgram::new(&jump).unwrap_err().contains("jump out of code"));
        let ok = assemble("mov64 r0, 0\nexit").unwrap();
        assert!(BpfProgram::new(&ok).is_ok());
    }
}
