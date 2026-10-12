# The indexer DAG and pending-block simulation

`qubitcoind` runs metashrew-ABI WASM indexers in process (`-loadindexer`).
The loaded indexers form a DAG, and the same DAG can be run over a
hypothetical next block without touching any persistent state. This page
covers the model, how to configure it, the simulation RPCs, and the
limitations we know about.

## Model

The DAG is rooted at the raw block of each connected block (or the
hypothetical block in a simulation). Every other node is one of two kinds:

* An **indexer** is stateful. It has its own KV store (metashrew append-only
  layout, one RocksDB per indexer under `<datadir>/indexers/<label>/db`) and
  `view` exports.
* A **transform** is stateless. It is a function of the root block plus the
  state of its declared upstreams at that height. It produces a derived block
  that downstream indexers reprocess as their `_start` input
  (`height_le32 ++ T(block)`).

Edges come in two kinds:

| edge | meaning | ABI |
| --- | --- | --- |
| `secondary` | The downstream reads the upstream's KV at the same height. | `__secondary_get_len(name, key) -> len`, `__secondary_get(name, key, out)` (the `qubitcoin-tertiary-support` ABI) |
| `transform` | The downstream's input block is the transform's output. | the downstream is a stock metashrew wasm |

Nodes are processed in topological order. Cycles and unknown nodes are
rejected at load. A node only reads upstreams it declares; any other read
fails that node with `access denied`.

The alspo deployment shape (`/v4/{apikey}/traces` + alspo modules) is
`root → alkanes → transform(traceblock → ASP0) → essentials, tokendata, …`,
and it runs in process with no HTTP facade:

```
-loadindexer=alkanes:/opt/alkanes.wasm
-loadindexer=essentials:/opt/alspo_mod_essentials.wasm:transform=alkanes/traceblock/ASP0
-loadindexer=tokendata:/opt/alspo_mod_tokendata.wasm:transform=alkanes/traceblock/ASP0
```

Both modules share one transform node, so the transform is computed once per
block (results are cached by `(transform, height, header hash)`).

## Configuration

```
-loadindexer=<label>:<path>[:opt]...
```

`path` is a `.wasm` file, or a directory holding `program.wasm` and an
optional `indexer.toml`. The options are:

| option | meaning |
| --- | --- |
| `N` or `start=N` | Start height (the original syntax, still accepted). |
| `deps=a,b` | `secondary` edges. A bare `a,b` also works, which is the old `-loadtertiary` form. |
| `transform=T` (alias `input=T`) | `transform` edge. `T` is a transform name, or the shorthand `upstream/view/MAGIC` for the built-in transform. |
| `runner=fork` | Run on the fork runner (see below) even without `secondary` edges. |

In `indexer.toml`, `depends_on = [...]` and `transform = "..."` set the same
two edges.

```
-loadtransform=<name>:builtin:embed-view-in-coinbase:upstream=U:view=V:magic=M[:viewinput=0x..]
-loadtransform=<name>:<path.wasm>[:sha256=HEX][:deps=a,b][:fuel=N]
```

For the built-in transform, `magic` is ASCII, or hex with a `0x` prefix.
For a wasm transform, `deps` lists the nodes the program may read, and
`sha256` is checked at load.

### Runners

* Indexers **without** `secondary` edges run on the real `MetashrewRuntime`
  (rockshrew), exactly as before. This covers stock alspo modules behind a
  transform edge.
* Indexers **with** `secondary` edges run on the **fork runner**
  (`qubitcoin-indexer-fork`), because `MetashrewRuntime` does not link
  `__secondary_get`. The fork runner reads the indexer's own store as of
  `height - 1`, reads upstreams as of `height`, and commits the flushed pairs
  through metashrew's own store code (`BatchedSMTHelper`). The on-disk format
  is therefore identical, and the views, rollback and `secondarykv*` RPCs
  work the same way.

### Ordering, async mode and reorgs

* **Synchronous** (`-synchronous-secondary`): every block runs through the
  DAG in topological order.
* **Async** (default): one worker per indexer, fed in order. A worker waits
  until every indexer it depends on has processed the height. That covers its
  `secondary` upstreams and its input transform's upstreams.
* **Reorg**: every indexer above the fork point is rolled back (metashrew's
  manifest rollback, with a full-scan fallback). In async mode the rollback is
  queued behind the blocks already in that indexer's channel. Before this
  change, rollback was a TODO and nothing was rolled back.

## Transforms

### Built-in `embed-view-in-coinbase{magic, upstream, view}`

The built-in calls `upstream.view(view_input)` at the block's height and
appends one coinbase output, `value 0, OP_RETURN <push(magic ++ result)>`,
using rust-bitcoin's `push_slice` opcode choice (direct push, then
`OP_PUSHDATA1/2/4`). The header is unchanged, so the block hash still
validates. With `alkanes/traceblock/ASP0`, the output is byte-identical to
alspo's `embed_traces` and to the deployed facade. Tests prove this against
rust-bitcoin for every push-size class, and against
`fixtures/live_synthetic_900000.hex` and
`fixtures/wasm/synthetic_900000.bin` from alspo-rs
(`ALSPO_FIXTURES=.../alspo-rs/fixtures`).

### Wasm transforms

A wasm transform exports `transform() -> i32`, which returns an ArrayBuffer
pointer (length in the 4 bytes before the pointer) to the output block. Its
input (`__host_len` / `__load_input`) is `height_le32 ++ raw block`. It can
read the **state** of its declared upstreams at that height, from the
persistent store or from the simulation overlay:

* `__secondary_get_len(name, key) -> i32` and `__secondary_get(name, key, out)`;
* `__upstream_view(name, view_fn, input) -> i32`, which returns the result
  length (or -1); then `__upstream_view_read(out)` copies the result.

All arguments are ArrayBuffer pointers. The program runs under the fuel,
memory and deadline caps, and gets no other host I/O.

## Simulation

All simulation RPCs are **admin tier** (`register_admin`, like the mining
RPCs).

### `simulateblock`

```
simulateblock ["txhex", ...] ( {"indexers": ["name", ...], "parent": "overlay_id", "coinbase_hex": "hex"} )
```

`simulateblock` builds a block at `tip + 1`: version `0x20000000`,
`prev = tip`, `time = max(MTP + 1, now)`, the next required `bits`, the
merkle root, and a BIP141 commitment when any transaction has a witness. No
proof of work is computed, and the block is never submitted. When no
coinbase is given, the block gets one with a BIP34 height and a zero-value
`OP_TRUE` output. The transactions are not validated.

The block runs through every loaded indexer, or through the named nodes plus
all their upstreams, in topological order and in fork mode:

* Writes go to an in-memory layer.
* Reads go to the layer, then to the parent overlays' layers, then to the
  indexer's confirmed store **as of the tip height**. The read is
  height-bounded, so block-connect indexing that runs concurrently never
  leaks in.
* `__secondary_get` and upstream views read the upstream's **simulated**
  state.
* Transforms are applied to the simulated block against their upstreams'
  simulated state, and their output feeds the downstream nodes.

Result:

```json
{
  "overlay_id": "91255abf…",
  "height": 4,
  "tip": "<tip hash>",
  "block_hash": "<simulated block hash>",
  "parent": null,
  "cached": false,
  "overlay_bytes": 2126,
  "per_indexer": {
    "alkanes":                 {"ok": true,  "kind": "indexer",   "fuel_used": 9345563, "kv_writes": 26},
    "alkanes/traceblock/ASP0": {"ok": true,  "kind": "transform", "fuel_used": 0, "output_bytes": 342},
    "essentials":              {"ok": true,  "kind": "indexer",   "fuel_used": 30, "kv_writes": 2},
    "burn":                    {"ok": false, "kind": "indexer",   "fuel_used": 5000000, "error": "out of fuel", "error_kind": "out_of_fuel"}
  }
}
```

`error_kind` is one of `out_of_fuel`, `deadline`, `memory`, `host` (a refused
or failed upstream read, e.g. `access denied`), `failed` (trap, abort or
missing `__flush`), or `lagging` (the indexer's confirmed state is not at the
tip yet). A failing node fails only itself and the nodes downstream of it
(`"upstream 'x' failed"`). Its siblings still succeed.

**Stacking (`parent`).** The new transactions are layered on an existing
overlay. The child holds only its own writes and shares the parent's layers
copy-on-write, so a template prefix is simulated once and each bundle runs
on top of it. The child's node set is the parent's (or a subset of it). A
child layer is run as a block with the same height and header fields,
holding a zero-value coinbase tagged `qubitcoin-sim-layer` (or
`coinbase_hex`) followed by the new transactions. This is incremental
application. State effects compose exactly, but per-block aggregates that an
indexer rebuilds from its own input block (for example a block's trace list,
or anything keyed by "the transactions in this block") cover only the
layer's transactions. To get exact whole-block semantics, simulate the full
list without `parent`.

### `simulatedview`

```
simulatedview "overlay_id" "indexer" "view_fn" "input_hex"   →  "0x…"
```

Same result as `secondaryview`, computed against the overlay. For a
transform node, `view_fn = "output"` returns the transformed block.

### `releaseoverlay`

`releaseoverlay "overlay_id"` returns `{"released": bool}`. A child keeps
its own reference to its parent.

### `loadsimulationindexer` / `unloadsimulationindexer`

```
loadsimulationindexer "name" "wasm_hex|path" "sha256" ["dep", ...]   →  {"name", "sha256"}
unloadsimulationindexer "name"                                        →  {"unloaded": bool}
```

These register a tertiary that exists **only in simulation** (a searcher
program). Its base state is empty, it reads its declared deps' simulated
state, and it never touches a persistent store. The sha256 must match the
wasm. Such a node runs only when named in `indexers`.

### `getsimulationinfo`

Returns cache usage, the configured caps, and counters (`simulations`,
`overlay_hits`, `view_calls`, `view_hits`, `invalidations`).

### Caching and bounds

* Overlay ids are `sha256("qubitcoin-sim-overlay-v1" ‖ tip ‖ parent id ‖
  coinbase hash ‖ ordered sha256 of each raw tx ‖ sorted node set)`. An
  identical request returns the same `overlay_id` with `"cached": true`. Raw
  tx hashes (wtxid-like) are used rather than txids, because witness data
  matters to alkanes envelopes.
* View results are cached per `(overlay_id, indexer, view_fn, input)`.
* The cache is an LRU with a maximum overlay count and byte budgets for the
  overlay layers and the cached views. A single overlay larger than its cap
  is refused.
* Everything is dropped on a tip change or reorg. The daemon calls the
  engine from its tip events (`ChainEvents::on_tip`, which fires on every tip
  change, including disconnects), and every call also re-checks the tip. A
  simulation that finishes after the tip moved returns an error instead of
  a stale overlay.

### Safety

| cap | flag | default |
| --- | --- | --- |
| fuel per node per simulation (and per view call) | `-simfuel` | 20 000 000 000 |
| wall-clock deadline per node | `-simdeadlinems` | 30 000 |
| wasm linear memory per instance | `-simmaxmemorymb` | 4096 |
| cached overlays | `-simmaxoverlays` | 64 |
| overlay layer bytes | `-simmaxoverlaymb` | 512 |
| view-cache bytes | `-simviewcachemb` | 64 |
| bytes one overlay may add | (fixed) | 256 MiB |

* Simulation never writes to an indexer store or the chainstate. Stores are
  opened read-only by the code path (`store::read_at_height`), and the
  engine has no handle on the chainstate beyond the tip. Tests compare every
  key of every indexer DB before and after (`dag_simulation.rs`). A daemon
  test also compares the UTXO set, tip, height, mempool and indexer DB around
  a simulation on a live regtest chain (`chain_events.rs`).
* Simulations use their own wasm instances and take no indexer lock, so
  block-connect indexing proceeds while a simulation runs. A test connects
  blocks while a simulation is spinning until its deadline.

## User-registered nodes (searcher programs)

An owner can register a program as a persistent DAG node. The owner is an
opaque string the caller supplies. Authentication is the caller's job, which
is why these RPCs are admin-tier. The node indexes forward from its start
height on the owner's behalf. A start height in the past is backfilled from
the block files.

* **Program kinds.** `wasm` is a metashrew-ABI indexer with `_start`,
  `__flush`, views, and `__secondary_get` / `__upstream_view` on its
  upstreams. `bpf` is a userspace eBPF program with the helper ABI below
  ([BPF programs](#bpf-programs)). Both kinds share everything else on this
  page: isolation, scheduling, caps, metering, reorgs and simulation.
* **Upstreams** are standard indexers. The node reads them at the same
  height, and any read of an undeclared node fails it with `access denied`.
* **Isolation.** Each node has its own store at
  `<datadir>/dag/users/<sha256(owner)[..8]>/<name>/db`, in the same metashrew
  layout. Its `__flush` can only land there, so it cannot write another
  node's KV.
* **Scheduling.** On block connect the standard indexers run first. Then the
  user nodes are queued to a bounded worker pool (`-dagworkers`, default 2),
  which processes each node in batches of up to 16 blocks. A node may lag;
  `lag` in its status shows by how much.
* **Failures.** Each block runs under the node's fuel cap (bounded by the
  owner's quota), a 512 MiB memory cap and a 10 s deadline. A trap, a refused
  read, an exhausted cap or an exceeded store quota marks the node `errored`
  and stops it. Nothing else waits on a user node. `resumedagnode` retries
  it.
* **Reorgs** roll user nodes back with the standard indexers, after waiting
  for in-flight work.
* **Persistence.** Registrations and quotas are kept in
  `<datadir>/dag/registry.json`, and programs in
  `<datadir>/dag/programs/<sha256>.wasm` (or `.bpf`). Nodes resume where they stopped
  after a restart.
* **Simulation.** A user node can be named in `simulateblock` as
  `@owner/name` (it must be caught up to the tip).

### BPF programs

A `bpf` node runs on [solana-sbpf](https://crates.io/crates/solana-sbpf)'s
interpreter (0.25, built without its JIT). The kind is the eBPF twin of
`wasm`: one invocation per block, its own namespaced store, reads only of
declared upstreams, and views.

**Format.** `program_hex|path` is raw **SBPF v3** bytecode: 8-byte
little-endian eBPF instructions (the text section only, no ELF), entry at
instruction 0, at most 65 536 instructions. SBPF v3 is classic eBPF
(`lddw`, `neg`, `le`/`be`, 32- and 64-bit ALU and jumps) with static helper
calls (`call` with `src = 0`, `imm = helper id`) and pc-relative internal
calls (`call` with `src = 1`). `qubitcoin_indexer::bpf::assemble` turns
solana-sbpf assembly into such bytecode (`syscall kv_get` names a helper).
The sha256 is of these bytes.

**Verification.** Registration runs solana-sbpf's `RequisiteVerifier`
(known opcodes, valid registers, no writes to `r10`, jump targets inside the
program and not into an `lddw`, valid shift amounts and endianness
operands, no division by an immediate zero) and `LocalVerifier` (every
helper call names a helper below, no unresolved internal call), plus the
length and size checks. A rejected program returns `verifier: …` and is
never stored or scheduled. The verifier does not prove termination; the
instruction cap does.

**Execution.** One entrypoint. On entry `r1` is the mode and `r2` the input
length:

| mode | `r1` | input (`get_input`) | result |
| --- | --- | --- | --- |
| block | 0 | `height_le32 ‖ block` (exactly the wasm `_start` input) | `kv_set` writes, committed atomically if the program exits with `r0 = 0` |
| view | 1 | `height_le32 ‖ name_len_le32 ‖ view_name ‖ view_input` | the bytes passed to `emit` |

So views are one `view` entry that dispatches on the view name in its
input. `dagview owner name view_fn input_hex` and `simulatedview` call it.
A non-zero `r0` fails the invocation (`program exited with r0 = N`), like a
trap in wasm.

**Memory.** The address space is the program (read-only, at 0), the stack
(16 frames of 4 KiB at `0x2_0000_0000`, `r10` = frame pointer) and a zeroed
heap at `0x3_0000_0000` of 1 MiB (or the node's memory cap if smaller).
Every access is bounds-checked by the VM. Pending writes are capped at
64 MiB per invocation, `emit` at 4 MiB.

**Caps and metering.** The instruction meter is the node's fuel cap (the
same `fuel_per_block` quota as wasm): one instruction is one unit of fuel,
and each helper call costs 100 plus 1 per 8 bytes it moves
(`upstream_view` adds 10 000). The total is what the ledger records as
`fuel`. An exhausted cap is `out_of_fuel`. The wall-clock deadline is
checked at every helper call.

**Helpers.** Arguments go in `r1`–`r5` and the result comes back in `r0`.
Each helper's id is the murmur3-32 hash of its name (solana-sbpf's
static-syscall encoding). The ids are fixed by a unit test.

| # | helper | id | arguments | returns |
| --- | --- | --- | --- | --- |
| 1 | `get_input` | `0x79b36278` | `buf, len, offset` | the input length. Copies input bytes `[offset, offset+len)` (clamped) to `buf`. `offset` lets a small heap stream a large block. |
| 2 | `upstream_view` | `0x6b5d9eb8` | `upstream_idx, view_ptr, view_len, args_ptr` | the full result length. `args_ptr` points at four LE u64s `in_ptr, in_len, out_ptr, out_cap` (eBPF passes only five registers, so arguments 4 to 7 of `upstream_view(upstream_idx, view_ptr, view_len, in_ptr, in_len, out_ptr, out_cap)` travel in memory). Copies `min(len, out_cap)` bytes to `out_ptr`. |
| 3 | `secondary_get` | `0x7528dfa6` | `upstream_idx, key_ptr, key_len, out_ptr, out_cap` | the value length, or `u64::MAX` if the key is absent. Copies `min(len, out_cap)` bytes. |
| 4 | `kv_get` | `0x1c9fb127` | `key_ptr, key_len, out_ptr, out_cap` | as `secondary_get`, on the node's own store (its own pending writes first) |
| 5 | `kv_set` | `0x8c33b6d3` | `key_ptr, key_len, val_ptr, val_len` | 0. Block mode only. Keys starting with `0xff` are reserved for the host. |
| 6 | `emit` | `0x61390aef` | `ptr, len` | the total emitted so far. In a view this is the result. In a block it is the block's output, stored in the node's store and readable with the host view `__emitted` (`dagview owner name "__emitted" "" height`). |
| 7 | `log` | `0x6bf5c3fe` | `ptr, len` | 0 if kept, 1 if dropped. At most 32 lines of 256 bytes per invocation. The last block's lines show as `logs` in `getdagnodestatus` and go to the daemon log at debug level. |

`upstream_idx` indexes the node's declared `upstreams` list (0 is the first).
Any other index, like any undeclared read in wasm, fails the node with
`access denied`. Upstream reads are as of the block being indexed (or the
view's height), and in a simulation they read the upstream's simulated
state. Reads of the node's own store go through the same height-bounded
store reader as wasm, so a node only ever sees its own namespace, and the
store has the same metashrew layout and reorg rollback as wasm nodes.

A tx counter, in solana-sbpf assembly (the test fixture `COUNT_ASM` in
`crates/qubitcoin-indexer/tests/dag_simulation.rs` adds a view, an emit and
a log):

```
    lddw r6, 0x300000000      ; heap
    mov64 r1, r6              ; get_input(heap, 128, 0)
    mov64 r2, 128
    mov64 r3, 0
    syscall get_input
    ldxb r7, [r6+84]          ; height(4) + header(80): tx count varint (< 0xfd)
    stw [r6+256], 0x7378742f  ; key "/txs"
    mov64 r1, r6              ; kv_get("/txs", heap+264, 8)
    add64 r1, 256
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 264
    mov64 r4, 8
    syscall kv_get            ; absent → u64::MAX; the heap is zeroed
    ldxdw r8, [r6+264]
    add64 r8, r7
    stxdw [r6+264], r8
    mov64 r1, r6              ; kv_set("/txs", heap+264, 8)
    add64 r1, 256
    mov64 r2, 4
    mov64 r3, r6
    add64 r3, 264
    mov64 r4, 8
    syscall kv_set
    mov64 r0, 0
    exit
```

### Metering and quotas (no pricing)

Every processed block and every `dagview` call is recorded in a usage ledger
(`<datadir>/dag/ledger`, keyed by owner, height and node). Each entry holds
`{fuel, kv_writes, kv_bytes_written, storage_bytes, view_calls, blocks,
errors}`. View calls are recorded at the chain height of the call.

Per-owner quotas are `{max_nodes, fuel_per_block, storage_bytes}`. The
defaults come from `-dagmaxusernodes` (default **0**, so user nodes are off
unless the operator enables them), `-dagfuelperblock` (default 1e9) and
`-dagmaxstoragemb` (default 1024). `setdagquota` overrides them per owner.
Quotas are enforced at registration (node count) and on every block (fuel
cap, store size after commit).

### RPCs

| method | params | result |
| --- | --- | --- |
| `registerdagnode` | `owner, name, kind ("wasm"\|"bpf"), program_hex\|path, sha256, [upstreams], start_height, {fuel_per_block?}` | node status |
| `unregisterdagnode` | `owner, name` | `{"unregistered": bool}` (the store is deleted) |
| `listdagnodes` | `[owner]` | `[status, ...]` |
| `getdagnodestatus` | `owner, name` | `{owner, name, id, kind, sha256, upstreams, start_height, height, chain_height, lag, state, error, blocks_processed, last_block_fuel, logs, storage_bytes, quota}` |
| `dagview` | `owner, name, view_fn, input_hex, [height]` | `"0x..."` |
| `getdagusage` | `owner, from, to` | `{owner, from, to, total, nodes: {name: usage}, rows: [{height, name, usage}] (≤1000), quota}` |
| `setdagquota` | `owner, {max_nodes?, fuel_per_block?, storage_bytes?}` | `{owner, quota}` |
| `resumedagnode` | `owner, name` | `{"resumed": true}` |

## Limitations

* BPF programs are raw SBPF v3 bytecode. ELF objects (from `clang -target
  bpf` or the Solana toolchain) are refused, so programs with a `.rodata`
  section must be linked down to text first, or build their constants with
  stores. Linux eBPF maps, tail calls, and Linux helper numbers do not
  exist here; only the seven helpers above do.
* A BPF block's deadline is checked only at helper calls. The instruction
  cap is the hard bound on a run, so a loop with no helper calls runs until
  the cap (about 1e9 instructions at the default quota) even after the
  deadline has passed.
* A BPF `emit` from a block is stored and viewable, but it does not feed
  other nodes. User transforms are not supported (see below).
* User nodes may read standard indexers only. They cannot read other user
  nodes, and user transforms are not supported. The store-size quota uses
  RocksDB's estimate (`estimate-live-data-size` plus memtables).
* Nodes in one simulation run sequentially in topological order. Independent
  branches are not parallelised.
* Stacked layers are incremental (see above).
* The simulated block is structurally valid but unvalidated: transactions
  are not checked against the UTXO set, and the default coinbase pays
  nothing.
* An indexer that lags the tip (async mode) reports `lagging` instead of
  being simulated on stale state.
* The fork runner does not compute SMT state roots (`secondaryroot`), the
  same as metashrew's batched path, which stores a placeholder.
* Hot-loaded indexers (`indexerload`) are processed inline, not on a worker.
