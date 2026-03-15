# Qubitcoin Technical Specification

A 1:1 Rust port of Bitcoin Core. This document specifies the consensus rules, protocol parameters, and implementation details for audit and review purposes.

## 1. Network Parameters

### Supported Networks

| Parameter | Mainnet | Testnet3 | Testnet4 | Signet | Regtest |
|-----------|---------|----------|----------|--------|---------|
| P2P Port | 8333 | 18333 | 48333 | 38333 | 18444 |
| Magic Bytes | `f9beb4d9` | `0b110907` | `1c163f28` | `0a03cf40` | `fabfb5da` |
| Bech32 HRP | `bc` | `tb` | `tb` | `tb` | `bcrt` |
| P2PKH Prefix | `0x00` | `0x6f` | `0x6f` | `0x6f` | `0x6f` |
| P2SH Prefix | `0x05` | `0xc4` | `0xc4` | `0xc4` | `0xc4` |
| WIF Prefix | `0x80` | `0xef` | `0xef` | `0xef` | `0xef` |
| BIP44 Coin Type | 0 | 1 | 1 | 1 | 1 |

### Genesis Blocks

| Network | Genesis Hash |
|---------|-------------|
| Mainnet | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` |
| Testnet3 | `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943` |
| Testnet4 | `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` |
| Signet | `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` |
| Regtest | `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206` |

### DNS Seeds (Mainnet)

- `seed.bitcoin.sipa.be`
- `dnsseed.bluematt.me`
- `seed.bitcoin.jonasschnelli.ch`
- `seed.btc.petertodd.net`
- `seed.bitcoin.sprovoost.nl`
- `dnsseed.emzy.de`
- `seed.bitcoin.wiz.biz`
- `seed.mainnet.achownodes.xyz`

## 2. Consensus Rules

### Block Limits

| Parameter | Value |
|-----------|-------|
| Maximum Block Weight | 4,000,000 weight units |
| Maximum Block Serialized Size | 4,000,000 bytes |
| Maximum Block Sigops Cost | 80,000 |
| Witness Scale Factor | 4 |
| Coinbase Maturity | 100 blocks |
| Subsidy Halving Interval | 210,000 blocks |
| Initial Block Reward | 50 BTC |

### Proof-of-Work

| Parameter | Value |
|-----------|-------|
| Target Spacing | 600 seconds (10 minutes) |
| Target Timespan | 1,209,600 seconds (2 weeks) |
| Difficulty Adjustment Interval | 2,016 blocks |
| PoW Limit (Mainnet) | `00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| Minimum Chain Work | `0000000000000000000000000000000000000000dee8e2a309ad8a9820433c68` |

### Soft Fork Activation Heights (Mainnet)

| BIP | Name | Activation Height |
|-----|------|-------------------|
| 34 | Block height in coinbase | 227,931 |
| 66 | Strict DER signatures | 363,725 |
| 65 | OP_CHECKLOCKTIMEVERIFY | 388,381 |
| 68/112/113 | CSV (relative lock-time) | 419,328 |
| 141/143/147 | Segregated Witness | 481,824 |
| 341/342 | Taproot | 709,632 |

### Assume-Valid

Block 900,000: `000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a`

Blocks at or below this height skip script verification during IBD.

### Transaction Limits

| Parameter | Value |
|-----------|-------|
| Maximum Transaction Size | 4,000,000 bytes |
| Maximum Script Element Size | 520 bytes |
| Maximum Operations Per Script | 201 |
| Maximum Script Size | 10,000 bytes |
| Maximum Stack Size | 1,000 elements |
| Maximum Multisig Keys | 20 (legacy), 999 (Tapscript OP_CHECKSIGADD) |
| Locktime Threshold | 500,000,000 (below = height, above = Unix timestamp) |

## 3. Script Engine

### Output Types

| Type | BIP | Script Pattern | Size |
|------|-----|----------------|------|
| P2PKH | - | `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` | 25 bytes |
| P2SH | 16 | `OP_HASH160 <20> OP_EQUAL` | 23 bytes |
| P2WPKH | 141 | `OP_0 <20>` | 22 bytes |
| P2WSH | 141 | `OP_0 <32>` | 34 bytes |
| P2TR | 341 | `OP_1 <32>` | 34 bytes |
| OP_RETURN | - | `OP_RETURN <data>` | variable |

### Verification Flags

**Mandatory (consensus):** P2SH, DERSIG, NULLDUMMY, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, TAPROOT

**Standard (relay policy):** STRICTENC, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE

### Signature Algorithms

- **ECDSA** (secp256k1): Legacy and SegWit v0 inputs
- **Schnorr** (secp256k1): Taproot / SegWit v1 inputs (BIP340)
- **SIGHASH types:** ALL, NONE, SINGLE, ANYONECANPAY (combinable)
- **Lax DER parsing:** Custom `ecdsa_signature_parse_der_lax()` with S-normalization for consensus compatibility with pre-BIP66 transactions

## 4. P2P Protocol

### Protocol Version

| Parameter | Value |
|-----------|-------|
| Current Version | 70016 |
| Minimum Peer Version | 31800 |
| User Agent | `/Qubitcoin:0.1.0/` |

### Message Format

24-byte header: 4-byte network magic + 12-byte command (null-padded) + 4-byte payload length (little-endian) + 4-byte SHA256d checksum (first 4 bytes of double-SHA256 of payload).

### Message Types

**Handshake:** `version`, `verack`, `wtxidrelay`, `sendaddrv2`, `sendheaders`, `sendcmpct`

**Address:** `addr`, `addrv2`, `getaddr`

**Block relay:** `inv`, `getdata`, `getblocks`, `getheaders`, `headers`, `block`, `tx`, `notfound`

**Compact blocks (BIP152):** `sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`

**Bloom filter (BIP37):** `filterload`, `filteradd`, `filterclear`, `merkleblock`

**Other:** `ping`, `pong`, `feefilter`, `reject`, `mempool`

### Inventory Types

| Type | Value | Description |
|------|-------|-------------|
| MSG_TX | 1 | Transaction by txid |
| MSG_BLOCK | 2 | Block by hash |
| MSG_FILTERED_BLOCK | 3 | Bloom-filtered block |
| MSG_COMPACT_BLOCK | 4 | Compact block (BIP152) |
| MSG_WTX | 5 | Witness tx by wtxid (BIP339) |
| MSG_WITNESS_TX | 0x40000001 | Witness-serialized tx |
| MSG_WITNESS_BLOCK | 0x40000002 | Witness-serialized block |

### Service Flags

| Flag | Bit | Description |
|------|-----|-------------|
| NODE_NETWORK | 1 << 0 | Full chain history |
| NODE_BLOOM | 1 << 2 | BIP37 bloom filters |
| NODE_WITNESS | 1 << 3 | SegWit (BIP144) |
| NODE_COMPACT_FILTERS | 1 << 6 | BIP157/158 |
| NODE_NETWORK_LIMITED | 1 << 10 | Last 288 blocks (BIP159) |
| NODE_P2P_V2 | 1 << 11 | v2 transport (BIP324) |

### Protocol Limits

| Parameter | Value |
|-----------|-------|
| Max inventory items per message | 50,000 |
| Max headers per message | 2,000 |
| Max blocks in transit per peer | 32 |
| Max addresses per message | 1,000 |
| Ping interval | 120 seconds |
| Inactivity timeout | 1,200 seconds |
| Block stall timeout | 8 seconds |
| Head-of-line recovery | Direct-request from all peers |

## 5. Storage

### RocksDB Configuration

| Parameter | Value |
|-----------|-------|
| Compression | LZ4 |
| Write Buffer Size | 64 MB |
| Max Write Buffers | 3 |
| L0 Compaction Trigger | 4 SST files |
| Dynamic Level Sizing | Enabled |
| Bloom Filter | 10 bits/key (~1% FPR) |
| Block Cache | LRU, configurable (default 2048 MB) |
| Direct I/O | Enabled (reads + flush/compaction) |
| Compaction Readahead | 2 MB |
| Background Jobs | 8 threads |

### UTXO Cache

| Parameter | Value |
|-----------|-------|
| Default Cache Size (`-dbcache`) | 1024 MB |
| Warm Cache Retention | 512 MB unspent UTXOs retained after flush |
| Per-Entry Overhead | 140 bytes |
| Flush Interval | Every 2,000 blocks or when cache exceeds `-dbcache` |

### Flat-File Block Storage

Block data stored in `blk*.dat` files with 128 MB rotation, matching Bitcoin Core's format. Undo data in `rev*.dat` files. Block index maps block hashes to file positions.

## 6. Wallet

### Descriptor Types

| Type | BIP | Derivation Path | Address Format |
|------|-----|-----------------|----------------|
| P2PKH | 44 | `m/44'/coin'/0'/change/index` | `1...` |
| P2SH-P2WPKH | 49 | `m/49'/coin'/0'/change/index` | `3...` |
| P2WPKH | 84 | `m/84'/coin'/0'/change/index` | `bc1q...` |
| P2TR | 86 | `m/86'/coin'/0'/change/index` | `bc1p...` |

### Signing Support

- Legacy input signing (pre-SegWit sighash)
- SegWit v0 signing (BIP143)
- Taproot key-path signing (BIP341)
- PSBT support (BIP174)

## 7. Secondary Indexer Runtime

### Overview

Qubitcoind embeds a metashrew-compatible WASM runtime for running secondary indexer modules in-process. This eliminates the need for separate indexer processes (Electrs, metashrew, etc.), providing:

- Zero-config indexing that follows the chain tip automatically
- Atomic reorg handling via append-only KV storage with rollback
- Parallel execution of multiple indexers via rayon
- Single binary deployment

### WASM Runtime Configuration

Dual-engine design matching metashrew-runtime:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Wasmtime version | 18.0.4 | ABI compatibility with existing metashrew modules |
| NaN canonicalization | Enabled | Deterministic floating point |
| Relaxed SIMD determinism | Enabled | Consistent SIMD results |
| Static memory | 4GB address space | Full WASM32 range |
| Guard pages | 64KB | Memory safety |
| Copy-on-write | Disabled | Deterministic initialization |
| Fuel (async engine) | u64::MAX, yield every 10,000 | Cooperative yielding for views |
| Unknown imports | Trapped | wasm-bindgen glue compatibility |

### Host Functions (Metashrew ABI)

| Function | Signature | Description |
|----------|-----------|-------------|
| `__host_len` | `() -> i32` | Input data length |
| `__load_input` | `(ptr: i32)` | Copy `[height_le32 ++ block]` to WASM memory |
| `__get` | `(key_ptr: i32, value_ptr: i32)` | Read value from append-only store |
| `__get_len` | `(key_ptr: i32) -> i32` | Get value length |
| `__flush` | `(data_ptr: i32)` | Write KeyValueFlush protobuf to storage |
| `__log` | `(ptr: i32)` | Log message |
| `abort` | `(msg, file, line, col)` | Error handler |

Memory layout: AssemblyScript ArrayBuffer convention (4-byte LE length prefix at `ptr-4`, data at `ptr`).

### Storage Layout

Append-only key-value model (matching metashrew-runtime):

| Key Pattern | Value | Description |
|-------------|-------|-------------|
| `key ++ u32::MAX_le` | `u32 LE` | Entry count for logical key |
| `key ++ index_le32` | `bytes` | Value at index N |
| `key ++ "/__height__/" ++ index_le32` | `u32 LE` | Height at which entry was written |
| `__HEIGHT__` | `u32 LE` | Indexer tip height |

Each indexer gets an isolated RocksDB instance at `{datadir}/indexers/{label}/db/`.

### Indexer RPC Methods

| Method | Params | Returns |
|--------|--------|---------|
| `secondaryview` | `[label, view_fn, input_hex]` | `"0x..."` hex result |
| `secondaryheight` | `[label]` | Height (integer) |
| `secondaryhash` | `[label]` | SHA-256 hex of WASM binary |
| `secondaryroot` | `[label]` | `"0x..."` SMT state root (if enabled) |

### Verified Indexer Modules

| Module | Repository | Description |
|--------|-----------|-------------|
| esplorashrew | [kungfuflex/esplorashrew-rs](https://github.com/kungfuflex/esplorashrew-rs) | Esplora-compatible block/tx/address API |
| alkanes | [kungfuflex/alkanes-rs](https://github.com/kungfuflex/alkanes-rs) | Alkanes metaprotocol |
| brc20shrew | [subfrost/brc20shrew-rs](https://github.com/subfrost/brc20shrew-rs) | BRC-20 + inscriptions |
| opshrew | [opnet-protocol/opshrew](https://github.com/opnet-protocol/opshrew) | OP_NET smart contracts |

### CLI Package Manager

```bash
qubitcoin-cli installindexer <label> <source> [--branch <tag>] [--token <pat>] [--package <name>] [--smt]
```

Supports local `.wasm` files and git URLs. For git sources: clones, builds to `wasm32-unknown-unknown`, installs to `~/.local/qubitcoin/indexers/{label}/`. Writes `indexer.toml` manifest with SHA-256, source URL, and metadata.

## 8. RPC Interface

### Available Methods

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Chain state: height, headers, difficulty, IBD status |
| `getblockcount` | Current block height |
| `getbestblockhash` | Tip block hash |
| `getblockhash` | Block hash at height |
| `getdifficulty` | Current mining difficulty |
| `getmininginfo` | Network hashrate and difficulty |
| `getnetworkinfo` | Protocol version, connections, relay fees |
| `getpeerinfo` | Per-peer connection details |
| `getconnectioncount` | Connected peer count |
| `getnettotals` | Total bytes sent/received |
| `getmempoolinfo` | Mempool size and count |
| `getrawmempool` | Mempool transaction list |
| `getblock` | Block data by hash (raw hex or JSON) |
| `gettxout` | UTXO lookup by outpoint |
| `getrawtransaction` | Transaction by txid (hex or verbose JSON) |
| `sendrawtransaction` | Broadcast raw transaction |
| `secondaryview` | Call indexer view function |
| `secondaryheight` | Get indexer tip height |
| `secondaryhash` | Get indexer WASM hash |
| `secondaryroot` | Get indexer SMT state root |
| `getnewaddress` | Generate new wallet address |
| `getbalance` | Wallet balance |
| `listunspent` | Wallet UTXOs |
| `sendtoaddress` | Send funds |
| `help` | List available methods |
| `uptime` | Daemon uptime in seconds |
| `stop` | Graceful shutdown |

### Configuration

- Default RPC port: 8332 (mainnet), 18332 (testnet)
- JSON-RPC 2.0 protocol
- HTTP/1.1 transport
- Authentication via `-rpcuser` / `-rpcpassword`

## 9. Command-Line Options

```
-datadir=<dir>       Data directory (default: ~/.qubitcoin)
-port=<port>         P2P port (default: 8333)
-rpcport=<port>      RPC port (default: 8332)
-rpcuser=<user>      RPC username
-rpcpassword=<pw>    RPC password
-connect=<addr>      Connect to specific peer
-listen              Accept incoming connections (default: 1)
-maxconnections=<n>  Max connections (default: 125)
-loglevel=<level>    Log level: error, warn, info, debug, trace
-dbcache=<n>         UTXO cache size in MB (default: 1024)
-loadindexer=<l:p>   Load WASM indexer (label:path, repeatable)
--synchronous-secondary  Block tip until all indexers finish each block
-testnet             Use testnet3
-testnet4            Use testnet4
-regtest             Use regtest
-signet              Use signet
```

## 10. BIP Compliance

| BIP | Title | Status |
|-----|-------|--------|
| 16 | Pay-to-Script-Hash | Implemented |
| 30 | Duplicate transaction prevention | Implemented |
| 32 | Hierarchical Deterministic Wallets | Implemented |
| 34 | Block v2 (height in coinbase) | Implemented |
| 37 | Bloom filtering (message types) | Implemented |
| 65 | OP_CHECKLOCKTIMEVERIFY | Implemented |
| 66 | Strict DER signatures | Implemented |
| 68 | Relative lock-time (sequence numbers) | Implemented |
| 112 | OP_CHECKSEQUENCEVERIFY | Implemented |
| 113 | Median-Time-Past for lock-time | Implemented |
| 130 | sendheaders message | Implemented |
| 133 | feefilter message | Implemented |
| 141 | Segregated Witness (consensus) | Implemented |
| 143 | SegWit v0 signature hashing | Implemented |
| 144 | SegWit (network serialization) | Implemented |
| 147 | NULLDUMMY enforcement | Implemented |
| 152 | Compact block relay | Implemented |
| 155 | addrv2 message | Implemented |
| 174 | Partially Signed Bitcoin Transactions | Implemented |
| 339 | wtxid relay | Implemented |
| 340 | Schnorr signatures | Implemented |
| 341 | Taproot (SegWit v1) | Implemented |
| 342 | Tapscript validation | Implemented |

## 11. Crate Architecture

```
                           qubitcoind
                        /    |    |    \
              qubitcoin-net  |  qubitcoin-rpc  qubitcoin-wallet
                         \  |    /
                     qubitcoin-indexer
                             |
                        qubitcoin-node
                             |
                        qubitcoin-common
                       /       |       \
              qubitcoin-consensus  qubitcoin-storage  qubitcoin-util
                    |         |
              qubitcoin-script  qubitcoin-serialize
                    \        /
                 qubitcoin-primitives
                        |
                   qubitcoin-crypto
```

| Crate | Description |
|-------|-------------|
| `qubitcoin-crypto` | SHA256d, RIPEMD160, SipHash, secp256k1 |
| `qubitcoin-primitives` | Uint256, Amount, Txid, BlockHash |
| `qubitcoin-serialize` | Encodable/Decodable, CompactSize, DataStream |
| `qubitcoin-script` | Script interpreter, opcodes, verification |
| `qubitcoin-consensus` | Block, Transaction, merkle, sighash |
| `qubitcoin-common` | CoinsView, ChainParams, PoW, BlockIndex |
| `qubitcoin-storage` | Database traits, RocksDB backend |
| `qubitcoin-node` | Validation, ChainstateManager, mempool |
| `qubitcoin-net` | Tokio P2P networking, protocol messages |
| `qubitcoin-rpc` | JSON-RPC server, HTTP transport |
| `qubitcoin-indexer` | Metashrew WASM runtime, host ABI, storage, RPC |
| `qubitcoin-wallet` | Descriptor wallet, signing, PSBT |
| `qubitcoin-util` | Logging, args, metrics |
| `qubitcoin-tx` | Raw transaction tool |
| `qubitcoin-cli` | RPC client + indexer package manager |
| `qubitcoind` | Full node daemon |

## License

MIT
