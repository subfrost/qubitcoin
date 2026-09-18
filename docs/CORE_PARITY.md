# Bitcoin Core parity report

Reference: `bitcoin/bitcoin` master at **`0e9018e8b6`** ("net, rpc: Asmap version
improvements/follow-ups"), `CLIENT_VERSION_MAJOR 32`, surveyed 2026-09-18.
Subject: this repository at `95e5878`.

Qubitcoin is a from-scratch Rust reimplementation of Core, not a fork of its
C++ tree, so "catching up" is not patch application — every gap below has to be
re-expressed in Rust against Qubitcoin's own types. Rough sizes: ~67k lines of
Rust under `crates/` against ~255k lines of non-test C++ under Core's `src/`.
Parity is therefore a programme, not a change; this document records where the
line currently sits and in what order the remaining work is worth doing.

## Method, and its limits

The survey is a **symbol and marker scan** of `crates/**/*.rs` for the names,
constants and error strings that each Core subsystem is built out of (e.g.
`enforce_BIP94`, `MAX_TIMEWARP`, `signet_challenge`, `ThresholdState`,
`cluster_linearize`, `TRUC`, `BIP324`), cross-checked by reading the Rust that
matched. That is good at finding whole subsystems that are absent — which is
what most of the gap turned out to be — and weak at finding a subsystem that is
present but subtly wrong. **Nothing here should be read as an audit of the code
that does exist.** Where a subsystem is listed as present, it means the
machinery is there and looked structurally faithful, not that it was verified
against Core's test vectors.

## Present and reasonably built out

Taproot / tapscript / schnorr / annex / `OP_SUCCESS`; BIP143 and BIP341
sighash; BIP30, BIP34, BIP68 sequence locks; CLTV and CSV; segwit witness
programs and the witness commitment; compact blocks (BIP152); addrman; banman;
RBF; the orphanage; PSBT; descriptors; muhash and coinstats; pruning; parallel
script checking; the undo/UTXO compressor; bech32m; testnet4 and signet
chainparams entries.

## Fixed in this pass

Three of the gaps were consensus-correctness bugs rather than missing features,
so they were implemented rather than merely filed.

### 1. BIP94 (timewarp mitigation + retarget base) — was entirely absent

Two rules, both live on testnet4 and both previously missing, which meant
Qubitcoin would fork off testnet4 at the first retarget:

* **The header rule.** At every difficulty adjustment boundary the block's
  timestamp must be at least `prev_block_time - MAX_TIMEWARP` (600s).
  Implemented in `contextual_check_block_header_with_arena` in
  `crates/qubitcoin-node/src/validation.rs`, rejecting with
  `"time-timewarp-attack"` / `BlockValidationResult::InvalidHeader`. Maps to
  `src/validation.cpp:4105-4113`.
* **The retarget base.** With BIP94 the new target is derived from the `nBits`
  of the *first* block of the previous period rather than the last, so the
  min-difficulty exception cannot leak into real difficulty (the testnet4
  "block storm" mitigation). `get_next_work_required` and
  `calculate_next_work_required` in `crates/qubitcoin-common/src/pow.rs` gained
  a `first_bits` parameter for this. Maps to `src/pow.cpp:67-76`.

`ConsensusParams::enforce_bip94` is true on testnet4 only, matching Core.
7 new tests.

### 2. BIP325 signet block solution validation — was entirely absent

Qubitcoin had signet chainparams but no signet *rule*: it accepted any
PoW-valid block on signet, which is a total consensus failure on that network.
New `crates/qubitcoin-consensus/src/signet.rs` is a port of Core's
`src/signet.cpp`: `SignetTxs::create` builds the `to_spend`/`to_sign` pair,
`check_signet_block_solution` verifies the solution out of the witness
commitment section, with the modified merkle root computed over the
commitment-stripped block. Wired into `check_block` as step 1b, guarded by
`params.signet_blocks`, rejecting `"bad-signet-blksig"` (matches
`validation.cpp:3939`). 11 tests, including verifying the real signet block at
height 1 (`test_data/signet_block_1.hex`).

`SIGNET_DEFAULT_CHALLENGE` is now in `params.rs`, and `Script` gained
`push_opcode_byte` so scripts can be rebuilt opcode-by-opcode without losing
unknown opcodes.

### 3. Stale chainparams — minimum chain work and assumevalid

All five networks were refreshed from Core master's
`src/kernel/chainparams.cpp`. testnet4 previously had **zero** for both, i.e.
no low-work protection at all. `genesis_hash` and `min_bip9_warning_height`
fields were added at the same time, since both were referenced by the work
below.

### 4. BIP9 versionbits — was entirely absent

New `crates/qubitcoin-common/src/versionbits.rs`, a port of Core's
`versionbits.{h,cpp}` and `versionbits_impl.h`: the
`DEFINED -> STARTED -> LOCKED_IN -> ACTIVE | FAILED` state machine with
per-period caching, `get_state_since_height_for`, signalling statistics,
`compute_block_version`, GBT status, and the unknown-activation warning
checker. `ConsensusParams` gained a `deployments` array and `DeploymentPos`,
carrying the `testdummy` deployment with each network's real period and
threshold. `qubitcoind`'s block generator now sets the block version from
`compute_block_version` instead of hardcoding 4. 18 tests.

This has no effect on current consensus — every historical fork is buried in
both Core and Qubitcoin, and `testdummy` is `NEVER_ACTIVE` everywhere but
regtest — but it is the machinery any future soft fork needs, and it is what
`getdeploymentinfo`/`getblocktemplate` report from.

## Backlog, in the order worth doing it

### Tier 1 — network participation is degraded without these

| Gap | Core reference | Why it matters |
| --- | --- | --- |
| **Fee estimation** | `src/policy/fees.cpp`, `fees_args.cpp` | `estimatesmartfee` cannot be implemented at all. Any wallet on top of this node is guessing. |
| **sigcache / script cache** | `src/script/sigcache.cpp`, `validation.cpp` | Without them every block re-verifies every signature from scratch. This is a large constant factor on IBD and block connect, not a correctness issue. |
| **Mempool persistence** | `src/node/mempool_persist.cpp` | Mempool is lost on restart; the node re-learns fee floors and loses unconfirmed wallet transactions. |
| **txrequest / txdownloadman** | `src/node/txdownloadman*.cpp`, `src/txrequest.cpp` | Transaction relay currently has no de-duplicated, peer-prioritised request scheduler. Wastes bandwidth and is a privacy/DoS surface. |
| **Timeoffsets** | `src/node/timeoffsets.cpp` | Core removed the old adjusted-time consensus hack and replaced it with a warning-only median offset. Without it there is no clock-skew warning. |

### Tier 2 — policy divergence from the network

| Gap | Core reference | Why it matters |
| --- | --- | --- |
| **TRUC / v3 transactions (BIP431)** | `src/policy/truc_policy.cpp` | Relay policy Core has enforced since v28. A TRUC-shaped package is relayed by the network but not by this node, and vice versa. |
| **Package relay and package validation** | `src/policy/packages.cpp`, `validation.cpp` | `submitpackage`, 1P1C relay, and package RBF. Increasingly how real fee-bumping works. |
| **Cluster mempool (`cluster_linearize`, `txgraph`)** | `src/cluster_linearize.h`, `src/txgraph.cpp` | The v30 mempool rework. Large, self-contained, and changes eviction and mining order. Expect this to keep moving upstream. |
| **Ephemeral dust** | `src/policy/ephemeral_policy.cpp` | Only a single marker present. Needed for TRUC-based fee-bumping patterns. |
| **Miniscript** | `src/script/miniscript.h` | Descriptor support exists, but without miniscript the descriptor language is a strict subset of Core's. |

### Tier 3 — features and interoperability

BIP324 v2 encrypted transport (`src/net.cpp`, `bip324.cpp`) — Core negotiates
it by default now, so absence is visible to peers.
asmap and netgroup bucketing (`src/addrman.cpp`, `util/asmap.cpp`) — eclipse
resistance; note the reference commit is itself an asmap change.
BIP157/158 compact block filters — 8 markers, effectively a stub.
Assumeutxo (`src/node/utxo_snapshot.cpp`) — 3 markers; snapshot loading absent.
Headers sync with presync/anti-DoS (`src/headerssync.cpp`) — 4 markers.
I2P (`src/i2p.cpp`) and Tor control (`src/torcontrol.cpp`) — one marker each.
MuSig2 (`src/musig.cpp`), silent payments / BIP352 (`src/common/bip352.cpp`),
private broadcast, mapport/UPnP, external signer.

## Working notes for whoever picks this up

* `ConsensusParams` is constructed at exactly five struct-literal sites, all in
  `crates/qubitcoin-consensus/src/params.rs`. Adding a field touches only those
  five; there is no `Default` to fall through.
* `BlockIndex` lives in an arena (`BlockMap` in
  `crates/qubitcoin-node/src/chainstate.rs`) and is addressed by `usize`, with
  `None` standing in for Core's `nullptr` parent-of-genesis. It is **not**
  `Clone`. Cached structures keyed on arena indices — the versionbits caches,
  for instance — are only valid while the arena stays index-stable.
* The layering is `primitives -> script -> consensus -> common -> node`.
  Anything needing `get_ancestor`/`compute_mtp` belongs in `common` or above,
  which is why `versionbits.rs` is in `common` while the deployment
  *parameters* are in `consensus`.
* Test technique for anything header-contextual: median time past is real, so
  give arena blocks plausible ascending timestamps in the past, or an earlier
  check (`time-too-old`, `MAX_FUTURE_BLOCK_TIME`) fires first and masks the
  rule under test.
