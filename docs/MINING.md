# Mining with qubitcoind

This page is for pool operators and anyone pointing pool software at
`qubitcoind`. That includes ckpool, public-pool, the DATUM gateway, and the
SRI/SV2 template provider via its bitcoind-RPC adapter. The mining interface
is a port of Bitcoin Core's `rpc/mining.cpp`, `node/miner.cpp`, `src/zmq/`
and the mempool half of `validation.cpp`. It aims to look like Core on the
wire. The differences we know about are listed at the end.

## RPC surface

Authentication follows Core: every method that changes state or can block
needs `rpcuser`/`rpcpassword`. With no credentials configured, admin methods
are refused (fail-closed). The read-only methods are public so that a reverse
proxy can expose them.

| Method | Tier | Notes |
| --- | --- | --- |
| `getblocktemplate` | admin | BIP22/23/9/145. Must be called with `{"rules": ["segwit"]}` (plus `"signet"` on signet). Returns `capabilities`, `version`, `rules`, `vbavailable`, `vbrequired`, `previousblockhash`, `transactions[{data,txid,hash,depends,fee,sigops,weight}]`, `coinbaseaux`, `coinbasevalue`, `longpollid`, `target`, `mintime`, `mutable`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`, `curtime`, `bits`, `height`, `default_witness_commitment`, and `signet_challenge` on signet. |
| ↳ long poll | | Pass the previous `longpollid`. The call returns when the tip changes, or when the mempool has changed by the first check (60 s), re-checking every 10 s, as Core does. |
| ↳ proposal (BIP23) | | `{"mode": "proposal", "data": "<block hex>"}` → `null` or a reject reason. PoW is not checked. |
| `submitblock` | admin | `null` when connected. `"duplicate"`, `"inconclusive"` (valid side-branch block with less work), or the reject reason (`"high-hash"`, `"bad-cb-amount"`, `"prev-blk-not-found"`, …). Side branches are stored, and the node reorganises onto them once their chain has the most work. |
| `submitheader` | admin | `null`, or `RPC_VERIFY_ERROR` with the reason. |
| `getblockheader` | public | Verbose JSON (Core fields plus `target`) or 80-byte hex. |
| `prioritisetransaction` | admin | `txid, 0, fee_delta`. The delta steers block assembly; the coinbase claims real fees only. Transactions with dust outputs are refused (Core v29). |
| `getprioritisedtransactions` | admin | |
| `getmininginfo` | public | Live values, including Core v29's `bits`, `target` and `next {height, bits, difficulty, target}`. |
| `getnetworkhashps`, `getdifficulty` | public | |
| `sendrawtransaction` | public | Core semantics: `maxfeerate` (default 0.10 BTC/kvB), `maxburnamount`, error codes -22/-25/-26/-27. A transaction already in the mempool is a success. |
| `testmempoolaccept` | public | Up to 25 transactions. Packages are judged on individual feerates, as Core does. |
| `submitpackage` | public | Child-with-parents packages. Members go in alone first; the rest are evaluated on the package feerate (CPFP). Package RBF for 1-parent-1-child. Returns `package_msg`, `tx-results` keyed by wtxid, and `replaced-transactions`. |
| `generatetoaddress` | public | Regtest only. Rejects invalid addresses (`-5 Error: Invalid address`). |

Transport follows Core's `httprpc.cpp`:
- JSON-RPC 1.0 replies always carry both `result` and `error`.
- 1.0 errors answer HTTP 400 (invalid request), 404 (method not found) or 500.
- JSON-RPC 2.0 replies are always HTTP 200.
- 2.0 notifications get HTTP 204.
- Batches (JSON arrays) are supported.

## Block assembly

`BlockAssembler` (`crates/qubitcoin-node/src/miner.rs`) selects transactions
by ancestor feerate, the way Core v28/v29 does:
- CPFP packages are chosen together, and `prioritisetransaction` deltas are
  applied.
- The weight limit is `-blockmaxweight` (default 3 996 000) and the sigop
  limit is 80 000.
- The coinbase carries the BIP34 height and the BIP141 witness commitment.
- Every template passes `TestBlockValidity` before it is served.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-blockmaxweight=<n>` | 3996000 | Maximum template weight. |
| `-blockmintxfee=<BTC/kvB>` | 0 | Minimum package feerate to mine. |
| `-minrelaytxfee=<BTC/kvB>` | 0 | Mempool relay floor (Core semantics; Core's default is higher). |
| `-maxmempool=<MB>` | 300 | |
| `-datacarrier=<0\|1>` | 1 | Accept `OP_RETURN` outputs. |
| `-datacarriersize=<n>` | 100000 | Total `OP_RETURN` scriptPubKey bytes per transaction (Core v30 semantics: any number of outputs). |
| `-permitbaremultisig=<0\|1>` | 1 | Accept bare multisig outputs (at most 3 keys). |
| `-blocknotify=<cmd>` | | Run `cmd` (via `sh -c`) on every new tip once out of initial sync; `%s` becomes the block hash. |
| `-zmqpub<topic>=<address>` | | See below. |

## ZMQ

Build with the default `zmq` feature (pure-Rust `zeromq` crate; TCP only).
Topics are `hashblock`, `rawblock`, `hashtx`, `rawtx` and `sequence`.
Several topics may share an address, and then they share one PUB socket.

The wire format matches Core: `[topic, body, 4-byte LE sequence]`, and hashes
are sent in display order. `sequence` bodies are `<hash><label>`, where the
label is:
- `C` for a connected block,
- `D` for a disconnected block,
- `A` for a mempool acceptance and `R` for a removal; both are followed by
  the 8-byte LE mempool sequence.

Events come in Core's order:
1. Disconnected blocks: `hashtx`/`rawtx` for each transaction, then `D`.
2. Connected blocks: `hashtx`/`rawtx` for each transaction, then `C`.
3. Mempool changes from the reorganisation: re-added transactions publish
   `A` and `hashtx`/`rawtx`; removals publish `R`.
4. `hashblock`/`rawblock` for the new tip only, and not during initial
   block download.

## Reorganisations

The chainstate follows Core's `AcceptBlock` / `ActivateBestChain`:
- Side-branch blocks are validated and stored, and never connected against
  the wrong UTXO set.
- The chain with the most work wins; on equal work, the block seen first
  wins.
- A reorganisation disconnects back to the fork using undo data from the rev
  files, then connects the new branch block by block. Each block is validated
  on a scratch UTXO view and committed only on success.
- A block that fails is marked invalid, along with its descendants, and the
  previous chain is restored.
- After a reorganisation, disconnected transactions return to the mempool.
  Anything no longer valid on the new tip is removed: missing inputs,
  immature coinbase spends, non-final transactions, unmet BIP68 locks.

## Smoke test

```
python3 test-harness/mining_smoke.py target/debug/qubitcoind
```

The script starts a throwaway regtest node with random RPC credentials. It
covers generatetoaddress, the GBT → build → proposal → submitblock cycle,
long polling, `-blocknotify`, prioritisation, `testmempoolaccept` /
`submitpackage`, a reorganisation through `submitblock` side branches, and
the transport behaviour. The ZMQ checks run if `pyzmq` is installed.

## Known differences from Core

- **Mining order** is Core v28/v29 ancestor-feerate selection. Core v31+
  orders by cluster linearization (cluster mempool), which this node does
  not implement.
- **Relay floor.** The default relay floor and `-blockmintxfee` are 0. Core's
  defaults are higher (configure with `-minrelaytxfee`). Because the floor is
  0, an ephemeral-dust parent is refused on its own by an explicit rule
  rather than by the fee floor. The outcome is the same: it is only accepted
  in a package with a child that spends the dust.
- **Package RBF** uses Core v28's cluster-size-2 rules. Core's feerate-diagram
  comparison is reduced to "higher package feerate than every replaced
  cluster", which is equivalent for those cluster sizes.
- **Package relay over P2P** (1P1C orphan resolution) is not implemented.
  Packages enter through `submitpackage` only.
- **Mempool size and eviction** use the existing descendant-feerate trimming.
  `-mempoolexpiry` and mempool persistence across restarts are not
  implemented.
- **ZMQ.** No `-zmqpub*hwm` options; the internal queue drops when full. No
  `ipc://` endpoints.
- **`hashblock` on reorganisation** is published for the new tip only, as
  Core does.
- **`getblocktemplate`** offers no `coinbasetxn`/`workid` (Core does not
  either), and no BIP9 deployments beyond `testdummy`, because all real
  forks are buried.
- **`submitheader`** does not run headers presync / minimum-chain-work
  anti-DoS.
- **JSON numbers.** Amounts in `testmempoolaccept` / `submitpackage` are
  JSON numbers (BTC). Core prints fixed 8-decimal values; the numbers
  compare equal, but the text formatting can differ (e.g. `1e-5`).
