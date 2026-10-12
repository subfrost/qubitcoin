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

## Limitations

* **User-registered DAG nodes, BPF programs, metering and quotas** are not
  implemented yet (`registerdagnode` and the related RPCs). The only searcher
  program supported today is the simulation-only wasm tertiary from
  `loadsimulationindexer`.
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
