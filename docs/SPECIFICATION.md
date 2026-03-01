# Qubitcoin Specification

Full specification of the Qubitcoin codebase, organized for audit. All file paths are relative to the workspace root (`/home/ubuntu/qubitcoin/`).

---

## 1. Crate-by-Crate Module Map

### 1.1 qubitcoin-crypto

**Path:** `crates/qubitcoin-crypto/`
**Maps to:** Bitcoin Core `src/crypto/`

| Module | Description |
|--------|-------------|
| `hash` | Double-SHA256, SHA256, RIPEMD160, HASH160, SHA1, BIP340 tagged hash |
| `muhash` | MuHash rolling hash accumulator |
| `siphash` | SipHash-2-4 for hash table randomization |

**Key functions:**
- `hash256(data) -> [u8; 32]` — Double SHA256
- `hash160(data) -> [u8; 20]` — RIPEMD160(SHA256(data))
- `sha256_hash(data) -> [u8; 32]` — Single SHA256
- `ripemd160_hash(data) -> [u8; 20]` — RIPEMD160
- `sha1_hash(data) -> [u8; 20]` — SHA-1
- `tagged_hash(tag, data) -> [u8; 32]` — BIP340 tagged hash

**Re-exports:** `bitcoin_hashes`, `secp256k1`

---

### 1.2 qubitcoin-primitives

**Path:** `crates/qubitcoin-primitives/`
**Maps to:** Bitcoin Core `src/uint256.h`, `src/arith_uint256.h`, `src/consensus/amount.h`

| Module | Description |
|--------|-------------|
| `amount` | Satoshi amount type with range validation |
| `arith_uint256` | 256-bit integer with full arithmetic operations |
| `hash_types` | Typed hash wrappers (Txid, Wtxid, BlockHash) |
| `uint256` | Fixed-size opaque byte containers (Uint256, Uint160) |

**Key types:**
- `Uint256` — 32-byte immutable hash container
- `Uint160` — 20-byte immutable hash container
- `ArithUint256` — 256-bit integer with Add, Sub, Mul, Div, Shl, Shr, BitAnd, BitOr
- `Amount` — Satoshi amount (i64 wrapper)
- `Txid`, `Wtxid`, `BlockHash` — Newtype hash wrappers

**Constants:**
- `COIN = 100_000_000` — satoshis per BTC
- `MAX_MONEY = 21_000_000 * COIN` — maximum supply (2,100,000,000,000,000 satoshis)

---

### 1.3 qubitcoin-serialize

**Path:** `crates/qubitcoin-serialize/`
**Maps to:** Bitcoin Core `src/serialize.h`, `src/streams.h`

| Module | Description |
|--------|-------------|
| `compact_size` | CompactSize variable-length encoding (1/3/5/9 bytes) |
| `data_stream` | In-memory buffer for serialization I/O |
| `encode` | Encodable/Decodable traits |
| `varint` | Variable-length integer encoding |

**Key types:**
- `Encodable` trait — serialize to `Write`
- `Decodable` trait — deserialize from `Read`
- `DataStream` — buffered I/O wrapper

**Key functions:**
- `read_compact_size()` / `write_compact_size()`
- `read_varint()` / `write_varint()`
- `serialize()` / `deserialize()`

**Constants:**
- `MAX_SIZE = 0x02000000` (32 MB)
- `MAX_VECTOR_ALLOCATE = 5_000_000`

---

### 1.4 qubitcoin-script

**Path:** `crates/qubitcoin-script/`
**Maps to:** Bitcoin Core `src/script/`

| Module | Description |
|--------|-------------|
| `interpreter` | Stack-based script execution engine |
| `opcode` | All Bitcoin opcodes (OP_0 through OP_NOP10, OP_CHECKSIGADD) |
| `script` | Script byte vector with builders |
| `script_error` | Script execution error codes |
| `script_num` | Consensus-critical numeric type (CScriptNum equivalent) |
| `verify_flags` | Script verification flags (P2SH, WITNESS, TAPROOT, etc.) |

**Key types:**
- `Script` — byte vector with `push_opcode()`, `push_int()`, `push_data()`, `get_op()`
- `Opcode` — enum of all Bitcoin opcodes
- `ScriptNum` — consensus-critical integer (default 4-byte, 5-byte for CLTV/CSV)
- `ScriptError` — all script validation error variants
- `ScriptVerifyFlags` — bitflags (P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLFAIL, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
- `BaseSignatureChecker`, `SignatureChecker` — traits for signature verification dispatch
- `SigVersion` — SIGVERSION_BASE, WITNESS_V0, TAPROOT, TAPSCRIPT

**Key functions:**
- `eval_script()` — execute script on stack (1,000+ line 1:1 port of Bitcoin Core)
- `verify_script()` — full script verification with P2SH, witness, and taproot support
- `cast_to_bool()` — consensus-critical boolean cast
- Script builders: `build_p2pkh()`, `build_p2wpkh()`, `build_p2wsh()`, `build_p2sh()`, `build_p2tr()`, `build_op_return()`

**Constants:**
- `MAX_SCRIPT_SIZE = 10_000`
- `MAX_SCRIPT_ELEMENT_SIZE = 520`
- `MAX_OPS_PER_SCRIPT = 201`
- `MAX_PUBKEYS_PER_MULTISIG = 20`
- `MAX_PUBKEYS_PER_MULTI_A = 999`
- `MAX_STACK_SIZE = 1_000`
- `LOCKTIME_THRESHOLD = 500_000_000`
- `LOCKTIME_MAX = 0xFFFFFFFF`
- `ANNEX_TAG = 0x50`
- `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50`
- `VALIDATION_WEIGHT_OFFSET = 50`
- `DEFAULT_MAX_NUM_SIZE = 4`

---

### 1.5 qubitcoin-consensus

**Path:** `crates/qubitcoin-consensus/`
**Maps to:** Bitcoin Core `bitcoin_consensus` static library

| Module | Description |
|--------|-------------|
| `block` | BlockHeader and Block types |
| `check` | Context-free validation (check_transaction, check_proof_of_work) |
| `merkle` | Merkle root computation with mutation detection |
| `params` | ConsensusParams for all networks |
| `sighash` | Signature hash algorithms (legacy, BIP143, BIP341) |
| `sign` | TransactionSignatureChecker, lock-time verification |
| `transaction` | OutPoint, TxIn, TxOut, Transaction, Witness |
| `validation_state` | ValidationState for structured error reporting |

**Key types:**
- `BlockHeader` — 80-byte header with `block_hash()` method
- `Block` — header + vtx (`Vec<TransactionRef>`)
- `Transaction` — version, vin, vout, lock_time, witness data
- `OutPoint` — (Txid, vout index)
- `TxIn` — prevout, script_sig, sequence
- `TxOut` — value (i64), script_pubkey
- `Witness` — stack of witness items
- `ConsensusParams` — per-network activation heights, PoW limits, timing
- `ValidationState` — result + reject reason for block/tx validation
- `PrecomputedTransactionData` — cached hash midstates for sighash

**Key functions:**
- `check_transaction()` — context-free transaction checks (no-empty, no-negative, size limits)
- `check_proof_of_work()` — verify block hash meets target
- `get_block_subsidy()` — mining reward for a given height
- `block_merkle_root()` — merkle root from txids
- `block_witness_merkle_root()` — witness merkle root from wtxids
- `signature_hash()` — legacy sighash (pre-segwit)
- `witness_v0_signature_hash()` — BIP143 segwit v0 sighash
- `taproot_signature_hash()` — BIP341 taproot sighash

**Constants:**
- `MAX_BLOCK_WEIGHT = 4_000_000`
- `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`
- `MAX_BLOCK_SIGOPS_COST = 80_000`
- `WITNESS_SCALE_FACTOR = 4`
- `COINBASE_MATURITY = 100`
- `SEQUENCE_FINAL = 0xFFFFFFFF`
- `MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE`
- `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31`
- `SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22`
- `SEQUENCE_LOCKTIME_MASK = 0x0000FFFF`
- `SEQUENCE_LOCKTIME_GRANULARITY = 9`
- `CURRENT_TX_VERSION = 2`
- Sighash types: `SIGHASH_ALL (1)`, `SIGHASH_NONE (2)`, `SIGHASH_SINGLE (3)`, `SIGHASH_ANYONECANPAY (0x80)`

---

### 1.6 qubitcoin-common

**Path:** `crates/qubitcoin-common/`
**Maps to:** Bitcoin Core `bitcoin_common` static library

| Module | Description |
|--------|-------------|
| `batch_flush` | Batch writing utilities for UTXO cache flush |
| `chain` | BlockIndex, Chain, BlockStatus with skip-list ancestors |
| `chainparams` | Network definitions (mainnet, testnet3, testnet4, regtest, signet) |
| `coins` | CoinsView trait hierarchy, UTXO cache, amount/script compression |
| `keys` | Key, PubKey, XOnlyPubKey types |
| `pow` | Proof-of-work: difficulty retargeting, next work required |

**Key types:**
- `BlockIndex` — arena-based block metadata (height, hash, work, status, skip pointer)
- `BlockStatus` — validation level flags + storage flags
- `Chain` — linear chain of block indices
- `ChainParams` — full network parameters
- `Network` — enum (Mainnet, Testnet3, Testnet4, Regtest, Signet)
- `Coin` — UTXO entry (output, height, coinbase flag)
- `CoinsView` trait — read-only UTXO interface
- `CoinsViewCache` — in-memory cache with DIRTY/FRESH tracking
- `CoinsViewDB<D>` — generic database-backed UTXO set
- `Key` — private key wrapper
- `PubKey` — compressed/uncompressed public key
- `XOnlyPubKey` — x-only public key for taproot

**Key functions:**
- `get_ancestor(height)` — O(log n) ancestor lookup via skip pointers
- `get_block_proof()` — calculate chain work from nBits
- `get_next_work_required()` — difficulty retargeting at 2016-block boundaries
- `calculate_next_work_required()` — compute new target from actual timespan
- `compress_amount()` / `decompress_amount()` — UTXO amount compression
- `compress_script()` / `decompress_script()` — P2PKH/P2SH/P2PK script compression

**Constants:**
- `MAX_FUTURE_BLOCK_TIME = 7_200` (2 hours)
- `TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME`
- `MEDIAN_TIME_SPAN = 11`

---

### 1.7 qubitcoin-storage

**Path:** `crates/qubitcoin-storage/`
**Maps to:** Bitcoin Core `src/dbwrapper.h`

| Module | Description |
|--------|-------------|
| `block_file` | Flat-file block storage (blk*.dat, rev*.dat) with BlockFileManager |
| `memory` | BTreeMap-backed in-memory database for testing |
| `rocks` | RocksDB backend (feature-gated on `rocksdb-backend`) |
| `traits` | Database, DbBatch, DbIterator trait definitions |
| `wrapper` | DbWrapper with typed serialization and XOR obfuscation |

**Key types:**
- `Database` trait — `read()`, `write_batch()`, `new_batch()`, `new_iterator()`, `compact()`
- `DbBatch` trait — `put()`, `delete()`, `clear()`
- `DbIterator` trait — `seek()`, `seek_to_first()`, `next()`, `key()`, `value()`
- `MemoryDb` / `MemoryBatch` / `MemoryIterator` — in-memory implementation
- `RocksDatabase` — RocksDB implementation
- `DbWrapper<D>` — typed serialization + XOR obfuscation layer
- `BlockFileManager` — manages blk*.dat and rev*.dat flat files
- `BlockFilePos` — (file_number, byte_offset)

**Constants:**
- `MAX_BLOCKFILE_SIZE = 0x8000000` (128 MB)
- `OBFUSCATION_KEY_KEY = b"\x0e\x00obfuscate_key"` — key for stored XOR key
- Obfuscation key length: 8 bytes

---

### 1.8 qubitcoin-node

**Path:** `crates/qubitcoin-node/`
**Maps to:** Bitcoin Core `bitcoin_node` static library

| Module | Description |
|--------|-------------|
| `block_index_db` | Persistent block index using RocksDB |
| `block_storage` | Block file management (blk*.dat / rev*.dat) |
| `chainstate` | BlockMap, Chainstate, ChainstateManager |
| `mempool` | TxMemPool, FeeRate, MempoolEntry |
| `mmap_storage` | Memory-mapped block file reading |
| `script_check` | Parallel script verification via Rayon + lax DER parser |
| `test_framework` | Testing utilities |
| `tx_index_db` | Transaction index database (txid -> file position) |
| `undo` | BlockUndo / TxUndo for chain reorganization |
| `validation` | Block and transaction validation logic |

**Key types:**
- `BlockMap` — arena-based block index (HashMap + arena allocator)
- `Chainstate` — active chain + UTXO cache
- `ChainstateManager` — block index + chainstate + assume-valid
- `TxMemPool` — transaction memory pool with fee tracking
- `FeeRate` — sat/kvB fee rate
- `MempoolEntry` — transaction in mempool with fee/size metadata
- `BlockIndexRecord` / `BlockIndexDB` — persistent block index in RocksDB
- `TxIndexDB` — txid -> (file, data_pos, tx_index) mapping
- `BlockUndo` / `TxUndo` — undo data for disconnecting blocks
- `TransactionSignatureChecker` — signature checker with tx context
- `SequenceLockPair` — BIP68 lock constraints

**Key functions:**
- `check_block_header()` — context-free header validation
- `check_block()` — context-free block validation (size, merkle, transactions)
- `contextual_check_block_header()` — header checks against chain (prev link, difficulty, MTP)
- `contextual_check_block()` — transaction-level context checks (locktime, BIP34/68/113)
- `connect_block()` — apply block to chainstate (UTXO update, script verification)
- `disconnect_block()` — reverse block effects using undo data
- `check_inputs()` — verify UTXO existence and amounts
- `get_block_script_flags()` — determine script flags for a given height
- `calculate_sequence_locks()` — BIP68 relative lock-time calculation
- `verify_ecdsa_signature()` — ECDSA verification with lax DER
- `ecdsa_signature_parse_der_lax()` — lenient DER parser matching Bitcoin Core

---

### 1.9 qubitcoin-net

**Path:** `crates/qubitcoin-net/`
**Maps to:** Bitcoin Core `src/net.cpp`, `src/net_processing.cpp`

| Module | Description |
|--------|-------------|
| `addr_manager` | Address book for peer discovery (new/tried tables) |
| `ban_manager` | Ban list for misbehaving peers |
| `connection` | TCP connection management (listen, connect, handshake) |
| `net_processing` | High-level message processing (inv, getdata, blocks, headers, txs) |
| `peer` | Per-connection state and PeerManager registry |
| `protocol` | Wire protocol: message types, headers, service flags, inventory |
| `rate_limiter` | Rate limiting for inbound messages |

**Key types:**
- `NetworkMagic` — 4-byte network identifier
- `MessageHeader` — 24-byte P2P message header (magic, command, length, checksum)
- `ServiceFlags` — bitflags (NODE_NETWORK, NODE_BLOOM, NODE_WITNESS, etc.)
- `NetMessage` — enum of all 36 P2P message types
- `InvType` / `InvVect` — inventory vector types
- `VersionMessage` — version handshake payload
- `PeerState` — Connecting, Connected, Handshaking, Ready, Disconnecting, Disconnected
- `ConnectionType` — Inbound, OutboundFullRelay, Manual, Feeler, BlockRelay, AddrFetch
- `Peer` — per-connection state tracking
- `PeerManager` — registry of all connected peers
- `NodeInterface` trait — abstracts block/tx processing for P2P layer
- `StateNotifier` trait — callbacks for chain state changes
- `NetProcessor` — main message processing engine

---

### 1.10 qubitcoin-rpc

**Path:** `crates/qubitcoin-rpc/`
**Maps to:** Bitcoin Core `src/rpc/`

| Module | Description |
|--------|-------------|
| `http_server` | HTTP/1.1 server with optional Basic Auth |
| `methods` | RPC method implementations |
| `node_rpc` | RPC handlers wired to shared NodeState |
| `server` | JSON-RPC 2.0 request/response types, handler registry |

**Key types:**
- `RpcRequest` / `RpcResponse` — JSON-RPC 2.0 messages
- `JsonRpcVersion` — V1Legacy, V2
- `RpcError` — error with code, message, optional data
- `RpcRegistry` — handler registration and dispatch
- `RpcServer` — HTTP server binding
- `NodeState` — shared mutable state (chain height, best hash, peers, mempool)
- `PeerInfo` / `MempoolEntry` — structured RPC response types

**Error codes:**
- `RPC_PARSE_ERROR = -32700`
- `RPC_INVALID_REQUEST = -32600`
- `RPC_METHOD_NOT_FOUND = -32601`
- `RPC_INVALID_PARAMS = -32602`
- `RPC_INTERNAL_ERROR = -32603`
- `RPC_MISC_ERROR = -1`
- `RPC_TYPE_ERROR = -3`
- `RPC_INVALID_ADDRESS_OR_KEY = -5`
- `RPC_VERIFY_ERROR = -25`
- `RPC_VERIFY_REJECTED = -26`

---

### 1.11 qubitcoin-wallet

**Path:** `crates/qubitcoin-wallet/`
**Maps to:** Bitcoin Core `src/wallet/`

| Module | Description |
|--------|-------------|
| `coin_selection` | Coin selection: largest-first greedy and branch-and-bound |
| `psbt` | Partially Signed Bitcoin Transaction (BIP 174) |
| `wallet` | Descriptor wallet: key management, signing, persistence |

**Key types:**
- `DerivationPath` — BIP32 HD path (Vec<u32> with HARDENED = 0x8000_0000)
- `DescriptorType` — Pkh, Wpkh, ShWpkh, Tr
- `WalletKey` — private key + public key + derivation metadata
- `AddressInfo` — generated address with key index and descriptor type
- `WalletTx` — tracked transaction
- `WalletUtxo` — unspent output with outpoint, value, height, is_change
- `Wallet` — core wallet struct

**Key functions:**
- `Wallet::generate_address()` — derive next address by descriptor type
- `Wallet::sign_transaction()` — sign inputs (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR)
- `Wallet::send_to_address()` — build, sign, and broadcast a transaction
- `Wallet::save_to_bytes()` / `Wallet::load_from_bytes()` — binary persistence
- `select_coins()` — largest-first greedy with fee estimation
- `select_coins_bnb()` — branch-and-bound for minimal change
- `estimate_fee()` — fee from virtual size and fee rate
- `DerivationPath::bip44()` / `bip84()` / `bip86()` — standard derivation paths

---

### 1.12 qubitcoin-util

**Path:** `crates/qubitcoin-util/`
**Maps to:** Bitcoin Core utility files

| Module | Description |
|--------|-------------|
| `args` | Command-line argument parser (Bitcoin Core `-key=value` style) |
| `logging` | Logging initialization with debug categories |
| `metrics` | Metrics and telemetry |
| `time` | Mockable clock for testing |

**Key types:**
- `ArgsManager` — parse and query `-key=value`, `-key`, `-nokey` style arguments
- `LogLevel` — Debug, Info, Warning, Error, Critical
- `Clock` trait — mockable time source

---

### 1.13 qubitcoin-tx

**Path:** `crates/qubitcoin-tx/`
**Maps to:** Bitcoin Core `src/bitcoin-tx.cpp`

| Module | Description |
|--------|-------------|
| `tx_tool` | Raw transaction creation, decoding, and inspection |

**Binary:** `qubitcoin-tx`

---

### 1.14 qubitcoin-cli

**Path:** `crates/qubitcoin-cli/`
**Maps to:** Bitcoin Core `src/bitcoin-cli.cpp`

**Key types and functions:**
- `CliConfig` — RPC connection configuration
- `CliArgs` — parsed CLI arguments
- `build_request()` — create JSON-RPC 2.0 request
- `parse_response()` — parse JSON-RPC response
- `format_result()` — pretty-print JSON
- `parse_args()` — CLI argument parser

**Recognized flags:** `-rpcconnect`, `-rpcport`, `-rpcuser`, `-rpcpassword`

**Binary:** `qubitcoin-cli`

---

### 1.15 qubitcoind

**Path:** `crates/qubitcoind/`
**Maps to:** Bitcoin Core `src/bitcoind.cpp`

**Binary:** `qubitcoind`

Integrates all crates into a production-ready full node daemon:
- `ArcCoinsView` — wraps `Arc<CoinsViewDB>` as `CoinsView` trait object
- `RpcStateNotifier` — bridges P2P events to RPC NodeState
- `LiveNodeInterface` — bridges P2P network to chainstate + block storage + UTXO DB
- Startup: chainstate init, mempool, block files, RocksDB, P2P connections, RPC server, wallet

---

## 2. Consensus Constants Reference

### Block Limits

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `MAX_BLOCK_WEIGHT` | 4,000,000 | Maximum block weight in weight units | `crates/qubitcoin-consensus/src/check.rs:13` |
| `MAX_BLOCK_SERIALIZED_SIZE` | 4,000,000 | Maximum serialized block size in bytes | `crates/qubitcoin-consensus/src/check.rs:16` |
| `MAX_BLOCK_SIGOPS_COST` | 80,000 | Maximum sigops cost per block | `crates/qubitcoin-consensus/src/check.rs:19` |
| `WITNESS_SCALE_FACTOR` | 4 | Weight ratio: non-witness vs witness bytes | `crates/qubitcoin-consensus/src/check.rs:25` |
| `COINBASE_MATURITY` | 100 | Blocks before coinbase output is spendable | `crates/qubitcoin-consensus/src/check.rs:22` |

### Transaction Rules

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `CURRENT_TX_VERSION` | 2 | Default transaction version | `crates/qubitcoin-consensus/src/transaction.rs:38` |
| `SEQUENCE_FINAL` | 0xFFFFFFFF | Marks input as final (no relative lock-time) | `crates/qubitcoin-consensus/src/transaction.rs:20` |
| `MAX_SEQUENCE_NONFINAL` | 0xFFFFFFFE | Maximum non-final sequence value | `crates/qubitcoin-consensus/src/transaction.rs:23` |
| `SEQUENCE_LOCKTIME_DISABLE_FLAG` | 1 << 31 | Disables relative lock-time (BIP68) | `crates/qubitcoin-consensus/src/transaction.rs:26` |
| `SEQUENCE_LOCKTIME_TYPE_FLAG` | 1 << 22 | Time-based vs height-based lock (BIP68) | `crates/qubitcoin-consensus/src/transaction.rs:29` |
| `SEQUENCE_LOCKTIME_MASK` | 0x0000FFFF | Relative lock-time value mask (BIP68) | `crates/qubitcoin-consensus/src/transaction.rs:32` |
| `SEQUENCE_LOCKTIME_GRANULARITY` | 9 | Time granularity: 512-second intervals (BIP68) | `crates/qubitcoin-consensus/src/transaction.rs:35` |

### Script Limits

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `MAX_SCRIPT_SIZE` | 10,000 | Maximum script size in bytes | `crates/qubitcoin-script/src/script.rs:24` |
| `MAX_SCRIPT_ELEMENT_SIZE` | 520 | Maximum push data size in bytes | `crates/qubitcoin-script/src/script.rs:12` |
| `MAX_OPS_PER_SCRIPT` | 201 | Maximum non-push opcodes per script | `crates/qubitcoin-script/src/script.rs:15` |
| `MAX_STACK_SIZE` | 1,000 | Maximum combined stack + altstack items | `crates/qubitcoin-script/src/script.rs:27` |
| `MAX_PUBKEYS_PER_MULTISIG` | 20 | Maximum keys in OP_CHECKMULTISIG | `crates/qubitcoin-script/src/script.rs:18` |
| `MAX_PUBKEYS_PER_MULTI_A` | 999 | Maximum keys in OP_CHECKSIGADD (tapscript) | `crates/qubitcoin-script/src/script.rs:21` |
| `DEFAULT_MAX_NUM_SIZE` | 4 | Default ScriptNum byte size | `crates/qubitcoin-script/src/script_num.rs:26` |
| `LOCKTIME_THRESHOLD` | 500,000,000 | Height/time boundary for nLockTime | `crates/qubitcoin-script/src/script.rs:30` |
| `LOCKTIME_MAX` | 0xFFFFFFFF | Maximum locktime value | `crates/qubitcoin-script/src/script.rs:33` |

### Taproot / Tapscript (BIP341/342)

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `ANNEX_TAG` | 0x50 | Taproot annex byte tag | `crates/qubitcoin-script/src/script.rs:36` |
| `VALIDATION_WEIGHT_PER_SIGOP_PASSED` | 50 | Tapscript sigops weight budget | `crates/qubitcoin-script/src/script.rs:39` |
| `VALIDATION_WEIGHT_OFFSET` | 50 | Tapscript base validation weight | `crates/qubitcoin-script/src/script.rs:42` |

### Money

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `COIN` | 100,000,000 | Satoshis per BTC | `crates/qubitcoin-primitives/src/amount.rs:10` |
| `MAX_MONEY` | 2,100,000,000,000,000 sat | Maximum supply (21M BTC) | `crates/qubitcoin-primitives/src/amount.rs:14` |
| `subsidy_halving_interval` | 210,000 (mainnet) | Blocks between subsidy halvings | `crates/qubitcoin-consensus/src/params.rs:99` |
| `subsidy_halving_interval` | 150 (regtest) | Accelerated halving for testing | `crates/qubitcoin-consensus/src/params.rs:167` |

### Time

| Constant | Value | Description | Source |
|----------|-------|-------------|--------|
| `MAX_FUTURE_BLOCK_TIME` | 7,200 (2 hours) | Maximum allowed future timestamp | `crates/qubitcoin-common/src/chain.rs:23` |
| `TIMESTAMP_WINDOW` | 7,200 | Alias for MAX_FUTURE_BLOCK_TIME | `crates/qubitcoin-common/src/chain.rs:28` |
| `MEDIAN_TIME_SPAN` | 11 | Blocks used for Median-Time-Past | `crates/qubitcoin-common/src/chain.rs:31` |

### Mainnet PoW Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| `pow_target_timespan` | 1,209,600 (14 days) | `crates/qubitcoin-consensus/src/params.rs:87` |
| `pow_target_spacing` | 600 (10 minutes) | `crates/qubitcoin-consensus/src/params.rs:88` |
| `pow_limit` | 00000000ffffffff...ff | `crates/qubitcoin-consensus/src/params.rs:83-85` |
| `rule_change_activation_threshold` | 1,916 (95% of 2016) | `crates/qubitcoin-consensus/src/params.rs:81` |
| `miner_confirmation_window` | 2,016 | `crates/qubitcoin-consensus/src/params.rs:82` |

### Mainnet Activation Heights

| Softfork | Height | Source |
|----------|--------|--------|
| BIP34 (block v2) | 227,931 | `crates/qubitcoin-consensus/src/params.rs:74` |
| BIP66 (strict DER) | 363,725 | `crates/qubitcoin-consensus/src/params.rs:76` |
| BIP65 (CLTV) | 388,381 | `crates/qubitcoin-consensus/src/params.rs:75` |
| CSV (BIP68/112/113) | 419,328 | `crates/qubitcoin-consensus/src/params.rs:77` |
| SegWit (BIP141) | 481,824 | `crates/qubitcoin-consensus/src/params.rs:78` |
| Taproot (BIP341) | 709,632 | `crates/qubitcoin-consensus/src/params.rs:79` |

---

## 3. BIP Implementation Matrix

| BIP | Title | Activation | Crate(s) | Key Function(s) | Tests |
|-----|-------|-----------|----------|------------------|-------|
| 16 | P2SH | Height 173,805 | script, node | `verify_script()` (P2SH path), `get_block_script_flags()` | Script vectors |
| 30 | Duplicate txid prevention | Always (exceptions: 91842, 91880) | node | `connect_block()` BIP30 checks | Unit tests |
| 32 | HD Wallets | N/A (wallet) | wallet | `DerivationPath::bip44/84/86()` | Wallet tests |
| 34 | Block v2 (height in coinbase) | Height 227,931 | node | `contextual_check_block()` coinbase height check | Validation tests |
| 37 | Bloom filtering | Protocol | net | FilterLoad/FilterAdd/FilterClear messages | — |
| 65 | OP_CHECKLOCKTIMEVERIFY | Height 388,381 | script, node | `eval_script()` OP_CLTV handler | Script vectors |
| 66 | Strict DER | Height 363,725 | script, node | `check_signature_encoding()` | Script vectors |
| 68 | Relative lock-time | CSV height | consensus, node | `calculate_sequence_locks()` | Validation tests |
| 112 | OP_CHECKSEQUENCEVERIFY | CSV height | script, node | `eval_script()` OP_CSV handler | Script vectors |
| 113 | Median-Time-Past | CSV height | node | `contextual_check_block()` MTP locktime | Validation tests |
| 130 | sendheaders | Protocol v70012 | net | SendHeaders message handler | Net tests |
| 133 | feefilter | Protocol v70013 | net | FeeFilter message handler | Net tests |
| 141 | Segregated Witness | Height 481,824 | consensus, node, script | Weight calculation, witness commitment | Script vectors, validation tests |
| 143 | Segwit v0 sighash | Height 481,824 | consensus | `witness_v0_signature_hash()` | Sighash tests, tx vectors |
| 144 | Segwit (network) | Height 481,824 | consensus, net | Witness serialization flag (0x0001) | Serialization tests |
| 147 | NULLDUMMY | Height 481,824 | script, node | ScriptVerifyFlags::NULLDUMMY | Script vectors |
| 152 | Compact block relay | Protocol v70014 | net | SendCmpct, CmpctBlock, GetBlockTxn, BlockTxn | Net tests |
| 155 | addrv2 | Protocol | net | AddrV2, SendAddrV2 messages | Net tests |
| 174 | PSBT | N/A (wallet) | wallet | `psbt` module | — |
| 339 | wtxid relay | Protocol v70016 | net | WtxidRelay message, Wtxid inventory | Net tests |
| 340 | Schnorr signatures | Height 709,632 | crypto, node | secp256k1 Schnorr verify | Signature tests |
| 341 | Taproot | Height 709,632 | consensus, script, node | `taproot_signature_hash()`, `verify_script()` taproot path | Script vectors, tx vectors |
| 342 | Tapscript | Height 709,632 | script | `eval_script()` tapscript execution, OP_SUCCESS pre-scan | Script vectors |

---

## 4. Consensus-Critical Code Paths (Audit Focus Areas)

### 4.1 Block Validation Pipeline

```
check_block_header()              crates/qubitcoin-node/src/validation.rs:361
  ├── check_proof_of_work()       crates/qubitcoin-consensus/src/check.rs:127
  └── verify nBits != 0
          │
contextual_check_block_header()   crates/qubitcoin-node/src/validation.rs:591
  ├── verify previous block exists
  ├── check height + 1
  ├── get_next_work_required()    crates/qubitcoin-common/src/pow.rs:37
  └── check timestamp > MTP
          │
check_block()                     crates/qubitcoin-node/src/validation.rs:394
  ├── check_block_header()
  ├── block_merkle_root()         crates/qubitcoin-consensus/src/merkle.rs:49
  ├── check size <= MAX_BLOCK_SERIALIZED_SIZE
  ├── check weight <= MAX_BLOCK_WEIGHT
  ├── first tx is coinbase
  ├── only one coinbase
  └── check_transaction() for each tx
          │
contextual_check_block()          crates/qubitcoin-node/src/validation.rs:746
  ├── BIP113: MTP-based locktime
  ├── BIP34: height in coinbase
  ├── BIP68: sequence locks
  ├── witness commitment check
  └── sigops cost <= MAX_BLOCK_SIGOPS_COST
          │
connect_block()                   crates/qubitcoin-node/src/validation.rs:1024
  ├── BIP30: check no duplicate unspent txids
  ├── check_inputs() — verify UTXOs exist
  ├── get_block_script_flags()
  ├── parallel script verification (Rayon)
  ├── update UTXO set (spend inputs, add outputs)
  ├── write undo data to rev*.dat
  └── update chain tip
```

### 4.2 Script Execution

```
verify_script()                   crates/qubitcoin-script/src/interpreter.rs:1638
  ├── eval_script(scriptSig)      crates/qubitcoin-script/src/interpreter.rs:584
  ├── eval_script(scriptPubKey)
  ├── if P2SH: eval_script(redeemScript)
  ├── if witness v0:
  │     ├── P2WPKH: synthesize P2PKH script, eval
  │     └── P2WSH: eval witness script
  ├── if witness v1 (taproot):
  │     ├── key-spend: verify Schnorr signature
  │     └── script-spend:
  │           ├── verify control block
  │           ├── OP_SUCCESS pre-scan
  │           └── eval tapscript
  └── CLEANSTACK check
```

### 4.3 Signature Verification

```
verify_ecdsa_signature()          crates/qubitcoin-node/src/script_check.rs:258
  ├── ecdsa_signature_parse_der_lax()   script_check.rs:303
  │     └── Lenient DER parser (handles negative R/S, missing leading zeros)
  ├── sig.normalize_s()           script_check.rs:290
  │     └── Enforce low-S (BIP62 rule 6)
  └── secp256k1::verify()         secp256k1 crate

Schnorr (taproot key-spend):
  └── secp256k1::verify_schnorr() via verify_script() taproot path
```

**Critical note:** The lax DER parser is required for consensus compatibility. Rust secp256k1's `from_der()` incorrectly zeroes R when encountering negative DER values. The custom parser at `script_check.rs:303` handles all legacy Bitcoin signatures correctly.

### 4.4 UTXO Management

```
CoinsView (trait)                 crates/qubitcoin-common/src/coins.rs
  │
CoinsViewDB<D>                    coins.rs (persistent layer)
  ├── RocksDB-backed UTXO storage
  ├── Amount compression          coins.rs:37  (10x exponent encoding)
  └── Script compression          coins.rs:98  (P2PKH/P2SH/P2PK templates)
  │
CoinsViewCache                    coins.rs (in-memory cache)
  ├── DIRTY/FRESH flags for write tracking
  ├── spend() — mark UTXO as spent
  ├── add_coin() — add new UTXO
  └── flush() — write dirty entries to backend
```

### 4.5 Proof-of-Work Verification

```
check_proof_of_work()             crates/qubitcoin-consensus/src/check.rs:127
  ├── decode nBits → target (ArithUint256)
  ├── verify target <= pow_limit
  └── verify block_hash <= target

get_next_work_required()          crates/qubitcoin-common/src/pow.rs:37
  ├── if not at retarget boundary: return prev nBits
  ├── if pow_no_retargeting: return prev nBits (regtest)
  └── calculate_next_work_required()
        ├── actual_timespan = block[height] - block[height - 2016]
        ├── clamp to [timespan/4, timespan*4]
        ├── new_target = old_target * actual_timespan / target_timespan
        └── cap at pow_limit
```

### 4.6 Transaction Validation

```
check_transaction()               crates/qubitcoin-consensus/src/check.rs
  ├── non-empty vin and vout
  ├── size within limits
  ├── no negative or overflow output values
  ├── sum of outputs <= MAX_MONEY
  ├── no duplicate inputs
  └── coinbase scriptSig size [2, 100]

check_inputs()                    crates/qubitcoin-node/src/validation.rs
  ├── verify each input references an existing UTXO
  ├── verify no double-spends within block
  ├── sum inputs >= sum outputs (fee >= 0)
  └── coinbase maturity check (100 blocks)
```

### 4.7 Merkle Root Computation

```
block_merkle_root()               crates/qubitcoin-consensus/src/merkle.rs:49
  └── compute_merkle_root(txids)
        ├── pair adjacent hashes, SHA256d each pair
        ├── if odd count: duplicate last element
        └── detect mutations (duplicate txids)

block_witness_merkle_root()       crates/qubitcoin-consensus/src/merkle.rs:57
  └── compute_merkle_root(wtxids)
        └── coinbase wtxid = 0x00...00 (32 zero bytes)
```

---

## 5. P2P Protocol Reference

### Message Types

| Command | Enum Variant | Payload | Direction |
|---------|-------------|---------|-----------|
| `version` | Version | protocol_version, services, timestamp, addrs, nonce, user_agent, start_height, relay | Both |
| `verack` | Verack | (empty) | Both |
| `ping` | Ping | nonce (u64) | Both |
| `pong` | Pong | nonce (u64) | Both |
| `getaddr` | GetAddr | (empty) | Out |
| `addr` | Addr | count, [timestamp, services, ip, port] | In |
| `addrv2` | AddrV2 | count, [timestamp, services, network_id, addr, port] | In |
| `inv` | Inv | count, [type, hash] | Both |
| `getdata` | GetData | count, [type, hash] | Out |
| `getblocks` | GetBlocks | version, count, [block_locator_hashes], hash_stop | Out |
| `getheaders` | GetHeaders | version, count, [block_locator_hashes], hash_stop | Out |
| `headers` | Headers | count, [block_header + tx_count=0] | In |
| `block` | Block | full serialized block | In |
| `tx` | Tx | full serialized transaction | Both |
| `notfound` | NotFound | count, [type, hash] | In |
| `sendheaders` | SendHeaders | (empty) | Both |
| `sendcmpct` | SendCmpct | announce (bool), version (u64) | Both |
| `feefilter` | FeeFilter | feerate (u64, sat/kvB) | Both |
| `wtxidrelay` | WtxidRelay | (empty) | Both |
| `sendaddrv2` | SendAddrV2 | (empty) | Both |
| `sendtxrcncl` | SendTxRcncl | (empty) | Both |
| `cmpctblock` | CmpctBlock | header, nonce, short_ids, prefilled_txs | In |
| `getblocktxn` | GetBlockTxn | block_hash, indexes | Out |
| `blocktxn` | BlockTxn | block_hash, transactions | In |
| `filterload` | FilterLoad | filter, hash_funcs, tweak, flags | Out |
| `filteradd` | FilterAdd | data | Out |
| `filterclear` | FilterClear | (empty) | Out |
| `merkleblock` | MerkleBlock | header, tx_count, hashes, flags | In |
| `mempool` | MemPool | (empty) | Out |
| `getcfheaders` | GetCFHeaders | filter_type, start_height, stop_hash | Out |
| `cfheaders` | CFHeaders | filter_type, stop_hash, prev_filter_header, filter_hashes | In |
| `getcfilters` | GetCFilters | filter_type, start_height, stop_hash | Out |
| `cfilter` | CFilter | filter_type, block_hash, filter_data | In |
| `getcfcheckpt` | GetCFCheckpt | filter_type, stop_hash | Out |
| `cfcheckpt` | CFCheckpt | filter_type, stop_hash, filter_headers | In |

### Protocol Versions

| Version | Feature | Constant |
|---------|---------|----------|
| 31800 | Minimum peer version | `MIN_PEER_PROTO_VERSION` |
| 70012 | sendheaders (BIP 130) | `SENDHEADERS_VERSION` |
| 70013 | feefilter (BIP 133) | `FEEFILTER_VERSION` |
| 70014 | Compact blocks (BIP 152) | `SHORT_IDS_BLOCKS_VERSION` |
| 70016 | wtxid relay (BIP 339) | `WTXID_RELAY_VERSION` / `PROTOCOL_VERSION` |

### Service Flags

| Flag | Bit | Value | Description |
|------|-----|-------|-------------|
| `NODE_NETWORK` | 0 | 0x0001 | Full block history |
| `NODE_BLOOM` | 2 | 0x0004 | BIP 111 bloom filtering |
| `NODE_WITNESS` | 3 | 0x0008 | BIP 144 segregated witness |
| `NODE_COMPACT_FILTERS` | 6 | 0x0040 | BIP 157/158 compact filters |
| `NODE_NETWORK_LIMITED` | 10 | 0x0400 | BIP 159 limited node (288 blocks) |
| `NODE_P2P_V2` | 11 | 0x0800 | BIP 324 v2 transport |

### Network Magic Bytes

| Network | Magic | Source |
|---------|-------|--------|
| Mainnet | `f9beb4d9` | `crates/qubitcoin-net/src/protocol.rs` |
| Testnet3 | `0b110907` | `crates/qubitcoin-net/src/protocol.rs` |
| Testnet4 | `1c163f28` | `crates/qubitcoin-net/src/protocol.rs` |
| Regtest | `fabfb5da` | `crates/qubitcoin-net/src/protocol.rs` |
| Signet | `0a03cf40` | `crates/qubitcoin-net/src/protocol.rs` |

### Connection Lifecycle

```
Outbound:                          Inbound:
  connect(ip:port)                   accept(socket)
  → send Version                     ← recv Version
  ← recv Version                     → send Version
  → send Verack                      ← recv Verack
  ← recv Verack                      → send Verack
  → send WtxidRelay (if v70016)      ← recv WtxidRelay
  → send SendAddrV2                  ← recv SendAddrV2
  → send SendHeaders                 ← recv SendHeaders
  → send SendCmpct                   ← recv SendCmpct
      ↓ READY                            ↓ READY
  → send GetHeaders (IBD)            ← respond with Headers
```

### IBD Pipeline

1. **Header sync**: Send `getheaders` with locator hashes, receive up to 2,000 headers per response. Repeat until caught up.
2. **Block download**: Request blocks via `getdata` with `MSG_WITNESS_BLOCK` type. Up to 16 blocks in-flight per peer (`MAX_BLOCKS_IN_TRANSIT_PER_PEER`).
3. **Ordered processing**: `pending_blocks` buffer + `header_set` dedup ensures blocks are processed in chain order despite multi-peer parallel download.
4. **Stall detection**: 500ms timer in `tokio::select!`, per-peer `BLOCK_DOWNLOAD_TIMEOUT_BASE` (600s). Stalled peers are disconnected and their blocks re-queued.

### P2P Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PAYLOAD_SIZE` | 4,000,000 | Maximum message payload (4 MB) |
| `MAX_INV_SIZE` | 50,000 | Maximum inventory items per message |
| `MAX_HEADERS_RESULTS` | 2,000 | Maximum headers per response |
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | 16 | Concurrent block requests per peer |
| `MAX_ADDR_TO_SEND` | 1,000 | Maximum addresses per message |
| `MAX_UNCONNECTING_HEADERS` | 10 | Unconnecting headers before DoS |
| `TIMEOUT_INTERVAL` | 1,200s | Inactivity disconnect (20 min) |
| `PING_INTERVAL` | 120s | Ping frequency (2 min) |
| `HEADERS_DOWNLOAD_TIMEOUT_BASE` | 900s | Headers sync timeout (15 min) |
| `BLOCK_STALLING_TIMEOUT` | 2s | Block stalling detection |
| `BLOCK_DOWNLOAD_TIMEOUT_BASE` | 600s | Per-peer block download timeout |

---

## 6. RPC Interface Reference

### Blockchain

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getblockchaininfo` | — | object | Chain name, height, best hash, difficulty, softfork status |
| `getblockcount` | — | int | Current block height |
| `getbestblockhash` | — | string | Hash of the tip block |
| `getblockhash` | `height: int` | string | Block hash at given height |
| `getblock` | `blockhash: string, verbosity?: int` | string\|object | Raw hex (0), JSON (1), or JSON with tx details (2) |
| `gettxout` | `txid: string, vout: int, mempool?: bool` | object | UTXO info or null if spent |
| `getrawtransaction` | `txid: string, verbose?: bool` | string\|object | Raw hex or decoded JSON (requires txindex) |
| `validateaddress` | `address: string` | object | Address validity check |

### Mining

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getdifficulty` | — | float | Current PoW difficulty |
| `getmininginfo` | — | object | Mining-related information |
| `getnetworkhashps` | `nblocks?: int, height?: int` | float | Estimated network hash rate |
| `generatetoaddress` | `nblocks: int, address: string, maxtries?: int` | array | Mine blocks to address (regtest) |

### Network

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getnetworkinfo` | — | object | Network and protocol info |
| `getpeerinfo` | — | array | Per-peer connection details |
| `getconnectioncount` | — | int | Number of connected peers |
| `getnettotals` | — | object | Total bytes sent/received |

### Mempool

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getmempoolinfo` | — | object | Mempool size, bytes, fee stats |
| `getrawmempool` | `verbose?: bool` | array\|object | List of mempool txids or detailed entries |
| `getmempoolentry` | `txid: string` | object | Single mempool entry details |
| `sendrawtransaction` | `hexstring: string, maxfeerate?: float` | string | Submit raw transaction, returns txid |

### Wallet

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getnewaddress` | — | string | Generate new receiving address |
| `getbalance` | — | float | Total confirmed wallet balance (BTC) |
| `listunspent` | — | array | List of unspent outputs |
| `sendtoaddress` | `address: string, amount: float` | string | Send BTC, returns txid |

### Utility

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `getinfo` | — | object | General node information |
| `help` | `command?: string` | string | List commands or command-specific help |
| `stop` | — | string | Shut down the node |
| `uptime` | — | int | Node uptime in seconds |

---

## 7. Storage Architecture

### Flat-File Block Storage

Block data is stored in sequentially numbered flat files matching Bitcoin Core's format:

- **Block files:** `blk00000.dat`, `blk00001.dat`, ... (128 MB max each)
- **Undo files:** `rev00000.dat`, `rev00001.dat`, ... (parallel to block files)
- **Record format:** `[magic(4)] [size(4)] [block_data(size)]`
- **Management:** `BlockFileManager` in `crates/qubitcoin-node/src/block_storage.rs`
- **Rotation:** automatic when file exceeds `MAX_BLOCKFILE_SIZE` (128 MB)

### RocksDB Databases

Three separate RocksDB instances:

| Database | Path | Key Format | Value Format | Purpose |
|----------|------|-----------|--------------|---------|
| UTXO (coins) | `chainstate/` | `[b'C' \| outpoint]` | compressed Coin | Unspent transaction outputs |
| Block Index | `blocks/index/` | `[b'b' \| block_hash(32)]` | 144-byte BlockIndexRecord | Block metadata |
| Tx Index | `indexes/txindex/` | `[b't' \| txid(32)]` | `[file(4) \| pos(4) \| idx(4)]` | Transaction location |

### DbWrapper XOR Obfuscation

All RocksDB values are XOR-obfuscated to prevent spurious pattern matches by antivirus software:

- **Key:** 8-byte random value, stored under `\x0e\x00obfuscate_key`
- **Operation:** `value[i] ^= key[i % 8]` on every read and write
- **Implementation:** `crates/qubitcoin-storage/src/wrapper.rs`

### Block Index Record

144-byte serialized record per block:

| Field | Type | Description |
|-------|------|-------------|
| version | i32 | Block version |
| height | i32 | Block height |
| status | u32 | Validation + storage flags |
| n_tx | u32 | Transaction count |
| file | i32 | Block file number |
| data_pos | u32 | Byte offset in blk*.dat |
| undo_pos | u32 | Byte offset in rev*.dat |
| block_hash | [u8; 32] | Block hash |
| prev_hash | [u8; 32] | Previous block hash |
| chain_work | [u8; 32] | Cumulative chain work |
| time | u32 | Block timestamp |
| bits | u32 | Encoded difficulty target |
| nonce | u32 | PoW nonce |

**File:** `crates/qubitcoin-node/src/block_index_db.rs`

---

## 8. Wallet Architecture

### HD Descriptor Wallet

The wallet supports BIP32 hierarchical deterministic key derivation with three standard derivation paths:

| BIP | Path | Address Type | Descriptor |
|-----|------|-------------|------------|
| 44 | `m/44'/0'/0'/change/index` | P2PKH (legacy) | `pkh()` |
| 84 | `m/84'/0'/0'/change/index` | P2WPKH (native segwit) | `wpkh()` |
| 86 | `m/86'/0'/0'/change/index` | P2TR (taproot) | `tr()` |

Additionally supports P2SH-P2WPKH (wrapped segwit) via `ShWpkh` descriptor type.

### Supported Address Types

| Type | scriptPubKey Pattern | Signing Method |
|------|---------------------|----------------|
| P2PKH | `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` | Legacy sighash, scriptSig: `<sig> <pubkey>` |
| P2WPKH | `OP_0 <20-byte-hash>` | BIP143 sighash, witness: `[<sig>, <pubkey>]` |
| P2SH-P2WPKH | `OP_HASH160 <script-hash> OP_EQUAL` | BIP143 sighash, scriptSig wraps witness program |
| P2TR | `OP_1 <32-byte-key>` | BIP341 Schnorr signature, witness: `[<sig>]` |

### Transaction Signing Pipeline

```
sign_transaction()                crates/qubitcoin-wallet/src/wallet.rs:537
  ├── for each input:
  │     ├── lookup WalletKey by scriptPubKey
  │     ├── match descriptor type:
  │     │     ├── P2PKH:     signature_hash() → ECDSA sign → scriptSig
  │     │     ├── P2WPKH:    witness_v0_signature_hash() → ECDSA sign → witness
  │     │     ├── P2SH-P2WPKH: witness_v0_signature_hash() → ECDSA sign → scriptSig + witness
  │     │     └── P2TR:      taproot_signature_hash() → Schnorr sign → witness
  │     └── append SIGHASH_ALL byte to signature
  └── return signed transaction
```

### Coin Selection

Two strategies implemented in `crates/qubitcoin-wallet/src/coin_selection.rs`:

1. **Largest-first greedy** (`select_coins`): Sort UTXOs descending by value, pick until target + fee is covered. Simple and predictable.
2. **Branch-and-bound** (`select_coins_bnb`): Two-pass algorithm minimizing change output. Pass 1 tries single UTXO near target. Pass 2 accumulates smallest-first. Donates dust change to fees.

Fee estimation: `overhead(11 vB) + inputs(68 vB each) + outputs(31 vB each) * fee_rate_per_vb`

### Persistence

Binary format serialized via `save_to_bytes()` / `load_from_bytes()`:
- Wallet name, key entries (privkey, pubkey, descriptor type, derivation path), addresses, change addresses, UTXOs
- Stored in RocksDB under wallet key
- Auto-saved on `sendtoaddress`

---

## 9. Test Coverage Matrix

| Crate | Unit Tests | Notable Categories | External Vectors |
|-------|------------|-------------------|------------------|
| qubitcoin-crypto | 18 | Hash functions, SipHash, MuHash | — |
| qubitcoin-primitives | 35 | ArithUint256 arithmetic, amount range, hash types | — |
| qubitcoin-serialize | 30 | CompactSize edge cases, VarInt roundtrip, DataStream | — |
| qubitcoin-script | 104 | Opcode encoding, ScriptNum, interpreter, verify_script | 1,217 script vectors (`script_tests.json`) |
| qubitcoin-consensus | 107 | Transaction validation, merkle, sighash, block checks | 214 tx vectors (`tx_valid.json`, `tx_invalid.json`) |
| qubitcoin-common | 132 | BlockIndex ancestors, CoinsView, PoW retarget, ChainParams | — |
| qubitcoin-storage | 21 | DbWrapper XOR, MemoryDb, BlockFileManager | — |
| qubitcoin-node | 188 | Validation pipeline, connect/disconnect, script_check, mempool | — |
| qubitcoin-net | 160 | Protocol serialization, message handling, peer management | — |
| qubitcoin-rpc | 100 | JSON-RPC parsing, method dispatch, response formatting | — |
| qubitcoin-wallet | 30 | Signing (P2PKH/P2WPKH/P2SH-P2WPKH/P2TR), coin selection, persistence | — |
| qubitcoin-util | 59 | ArgsManager parsing, time, logging | — |
| qubitcoin-tx | 13 | Transaction tool operations | — |
| qubitcoin-cli | 34 | CLI argument parsing, request building, response formatting | — |
| **Total** | **1,031+** | | **1,431 external vectors** |

### Fuzz Targets

6 cargo-fuzz targets in `fuzz/`:

| Target | Input | Goal |
|--------|-------|------|
| `fuzz_tx` | Raw bytes | Transaction deserialization |
| `fuzz_block` | Raw bytes | Block deserialization |
| `fuzz_script` | Raw bytes | Script execution |
| `fuzz_compact_size` | Raw bytes | CompactSize parsing |
| `fuzz_arith_uint256` | Raw bytes | 256-bit arithmetic operations |
| `fuzz_net_messages` | Raw bytes | P2P message deserialization |

### Benchmark Suite

Criterion benchmarks covering:
- Cryptographic hash functions (SHA256d, HASH160)
- Primitive operations (ArithUint256 arithmetic)
- Serialization (CompactSize, transaction encode/decode)
- Consensus (merkle root, check_transaction, check_proof_of_work)
