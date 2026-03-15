# qubitcoin

A 1:1 Rust port of Bitcoin Core with full consensus compatibility. Qubitcoin uses custom types throughout (not rust-bitcoin) to maintain exact fidelity with the C++ reference implementation.

## Workspace Structure

| Crate | Description | Bitcoin Core Equivalent |
|-------|-------------|------------------------|
| `qubitcoin-crypto` | SHA256d, RIPEMD160, SipHash, secp256k1 wrappers | `src/crypto/` |
| `qubitcoin-primitives` | Uint256, ArithUint256, Amount, Txid, BlockHash | `src/uint256.h`, `src/arith_uint256.h`, `src/consensus/amount.h` |
| `qubitcoin-serialize` | Encodable/Decodable traits, CompactSize, VarInt, DataStream | `src/serialize.h`, `src/streams.h` |
| `qubitcoin-script` | Script type, opcodes, interpreter, verification flags | `src/script/` |
| `qubitcoin-consensus` | Block, Transaction, merkle, sighash, validation params | `bitcoin_consensus` static lib |
| `qubitcoin-common` | CoinsView, ChainParams, PoW, BlockIndex, keys | `bitcoin_common` static lib |
| `qubitcoin-storage` | Database traits, RocksDB backend, flat-file block storage | `src/dbwrapper.h` |
| `qubitcoin-node` | Validation, ChainstateManager, mempool, block index DB | `bitcoin_node` static lib |
| `qubitcoin-net` | Tokio-based P2P networking, protocol messages, peer management | `src/net.cpp`, `src/net_processing.cpp` |
| `qubitcoin-rpc` | JSON-RPC server with HTTP/1.1 transport | `src/rpc/` |
| `qubitcoin-wallet` | Descriptor wallet, coin selection, transaction signing | `src/wallet/` |
| `qubitcoin-util` | Logging, time, argument parsing, metrics | Utility files |
| `qubitcoin-tx` | Raw transaction creation and inspection tool | `src/bitcoin-tx.cpp` |
| `qubitcoin-indexer` | In-process WASM secondary indexer runtime (metashrew-compatible) | - |
| `qubitcoin-cli` | Command-line RPC client with indexer package manager | `src/bitcoin-cli.cpp` |
| `qubitcoind` | Full node daemon binary | `src/bitcoind.cpp` |

## Quick Start

**Build:**
```bash
cargo build --release
```

**Run the daemon:**
```bash
./target/release/qubitcoind
```

**CLI client:**
```bash
./target/release/qubitcoin-cli getblockchaininfo
```

**Run with secondary indexers:**
```bash
# Install indexer modules from git
./target/release/qubitcoin-cli installindexer esplora https://github.com/kungfuflex/esplorashrew-rs
./target/release/qubitcoin-cli installindexer alkanes https://github.com/kungfuflex/alkanes-rs --branch v2.1.6
./target/release/qubitcoin-cli installindexer brc20 https://github.com/subfrost/brc20shrew-rs --package shrew-brc20
./target/release/qubitcoin-cli installindexer opnet https://github.com/opnet-protocol/opshrew --token $PAT

# Run with all indexers
./target/release/qubitcoind \
  -loadindexer=esplora:~/.local/qubitcoin/indexers/esplora \
  -loadindexer=alkanes:~/.local/qubitcoin/indexers/alkanes \
  -loadindexer=brc20:~/.local/qubitcoin/indexers/brc20 \
  -loadindexer=opnet:~/.local/qubitcoin/indexers/opnet

# Query indexers via RPC
./target/release/qubitcoin-cli secondaryheight esplora
./target/release/qubitcoin-cli secondaryview esplora tipheight ""
```

**Run all tests:**
```bash
cargo test --workspace
```

**Run with logging:**
```bash
RUST_LOG=debug ./target/release/qubitcoind
```

## Architecture Overview

Crates are layered bottom-up by dependency:

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

Binary crates (`qubitcoin-cli`, `qubitcoin-tx`) have minimal internal dependencies.

## Key Design Decisions

- **Arena-based block index**: `BlockMap` stores all block metadata in an arena with O(1) hash lookup and O(log n) ancestor queries via skip-list pointers, matching Bitcoin Core's `CBlockIndex`
- **`parking_lot::RwLock`**: Used throughout for lower-latency reader-writer locks compared to `std::sync`
- **Trait-based DB abstraction**: `Database`, `DbBatch`, `DbIterator` traits with `MemoryDb` (testing) and `RocksDB` (production) backends
- **Parallel script verification**: Rayon work-stealing threadpool for block script checks, matching Bitcoin Core's `CCheckQueue`
- **Flat-file block storage**: `blk*.dat` and `rev*.dat` files with 128 MB rotation, matching Bitcoin Core's format byte-for-byte
- **Lax DER signature parsing**: Custom `ecdsa_signature_parse_der_lax()` with S-normalization, required for consensus compatibility with pre-BIP66 transactions
- **Assume-valid optimization**: Skip script verification for blocks below a trusted hash
- **Memory-bounded UTXO cache**: Automatic flush to RocksDB when exceeding `-dbcache` limit
- **Custom types**: Uint256, Amount, Script, Transaction, etc. are all custom implementations for 1:1 fidelity with Bitcoin Core, not wrappers around rust-bitcoin
- **In-process WASM indexers**: Metashrew-compatible secondary indexer runtime with dual wasmtime engines (sync for blocks, async with fuel-based yielding for views), parallel execution via rayon, append-only KV storage with rollback support

## Test Coverage

| Category | Count |
|----------|-------|
| Unit tests | 1,115+ |
| Script test vectors | 1,217 |
| Transaction test vectors | 214 |
| Indexer runtime tests | 71 |
| Fuzz targets | 6 (tx, block, script, compact_size, arith_uint256, net messages) |

All tests pass. Mainnet P2P sync verified: 938K+ headers and 73K+ blocks processed from real Bitcoin peers. All 4 known metaprotocol indexers (esplora, alkanes, brc20, opnet) verified running in-process with 0 errors.

## BIP Support

| BIP | Title |
|-----|-------|
| 16 | Pay-to-Script-Hash (P2SH) |
| 30 | Duplicate transaction prevention |
| 32 | Hierarchical Deterministic Wallets |
| 34 | Block v2 (height in coinbase) |
| 37 | Bloom filtering (message types) |
| 65 | OP_CHECKLOCKTIMEVERIFY |
| 66 | Strict DER signatures |
| 68 | Relative lock-time (sequence numbers) |
| 112 | OP_CHECKSEQUENCEVERIFY |
| 113 | Median-Time-Past for lock-time |
| 130 | sendheaders message |
| 133 | feefilter message |
| 141 | Segregated Witness (consensus) |
| 143 | Segwit v0 signature hashing |
| 144 | Segwit (network serialization) |
| 147 | NULLDUMMY enforcement |
| 152 | Compact block relay |
| 155 | addrv2 message |
| 174 | Partially Signed Bitcoin Transactions |
| 339 | wtxid relay |
| 340 | Schnorr signatures |
| 341 | Taproot (SegWit v1) |
| 342 | Tapscript validation |

## License

MIT
