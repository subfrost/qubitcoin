// Copyright (c) 2024 The Qubitcoin developers
// Distributed under the MIT software license.

//! Mining RPCs.
//!
//! Port of Bitcoin Core's `src/rpc/mining.cpp` (`getblocktemplate` with
//! BIP22/BIP23/BIP9/BIP145, `submitblock`, `submitheader`,
//! `prioritisetransaction`, `getprioritisedtransactions`, `getmininginfo`,
//! `getnetworkhashps`, `generatetoaddress`) and `getblockheader` from
//! `src/rpc/blockchain.cpp`.
//!
//! The handlers work on a [`MiningContext`]: the shared chainstate and
//! mempool, plus a [`BlockSink`] supplied by the daemon that persists a block
//! and runs it through `ProcessNewBlock` (block files, undo data, flushes,
//! notifications live there), and a [`TipWatch`] used for long polling.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use serde_json::{json, Map, Value};

use qubitcoin_common::chain::BlockStatus;
use qubitcoin_common::versionbits::VersionBitsCache;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::check::{
    MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR,
};
use qubitcoin_consensus::validation_state::BlockValidationState;
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_node::miner::{
    get_difficulty, get_minimum_time, update_time, update_uncommitted_block_structures,
    BlockAssembler, BlockAssemblerOptions, BlockTemplate,
};
use qubitcoin_primitives::arith_uint256::{arith_to_uint256, uint256_to_arith};
use qubitcoin_primitives::{ArithUint256, BlockHash, Txid};
use qubitcoin_script::Script;
use qubitcoin_serialize::{deserialize, serialize};

use crate::server::{
    RpcRegistry, RpcRequest, RpcResponse, RPC_DESERIALIZATION_ERROR, RPC_INVALID_ADDRESS_OR_KEY,
    RPC_INVALID_PARAMETER, RPC_MISC_ERROR, RPC_TYPE_ERROR, RPC_VERIFY_ERROR,
};

/// Bitcoin Core's `RPC_CLIENT_NOT_CONNECTED`.
pub const RPC_CLIENT_NOT_CONNECTED: i32 = -9;
/// Bitcoin Core's `RPC_CLIENT_IN_INITIAL_DOWNLOAD`.
pub const RPC_CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10;

/// How long a long-poll waits before it first checks the mempool (Core: 1 min).
pub const LONGPOLL_FIRST_CHECK: Duration = Duration::from_secs(60);
/// Interval of the later mempool checks (Core: 10 s).
pub const LONGPOLL_RECHECK: Duration = Duration::from_secs(10);
/// A cached template is rebuilt for mempool changes only after this long
/// (Core: 5 s).
pub const TEMPLATE_REFRESH_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// What happened to a block handed to a [`BlockSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkOutcome {
    /// False if the block data was already known (Core's `new_block`).
    pub new_block: bool,
    /// The block is on the active chain after processing.
    pub in_active_chain: bool,
}

/// Persists and connects blocks on behalf of the mining RPCs.
pub trait BlockSink: Send + Sync {
    /// Store `block` and run it through `ProcessNewBlock` (which may
    /// reorganise onto it). `Err` when the block itself is invalid. Called
    /// without the chainstate lock held.
    fn process_new_block(&self, block: &Block) -> Result<SinkOutcome, BlockValidationState>;
}

/// A [`BlockSink`] that connects blocks to an in-memory chainstate only
/// (no block files). Used by tests and embedders without storage.
pub struct MemoryBlockSink {
    /// The chainstate blocks are connected to.
    pub chainstate: Arc<Mutex<ChainstateManager>>,
    /// Mempool to clean up after each connected block.
    pub mempool: Arc<TxMemPool>,
    /// Tip watch to notify.
    pub tip_watch: Arc<TipWatch>,
}

impl BlockSink for MemoryBlockSink {
    fn process_new_block(&self, block: &Block) -> Result<SinkOutcome, BlockValidationState> {
        let mut cs = self.chainstate.lock();
        let out = cs.process_block(block, None)?;
        qubitcoin_node::mempool_accept::update_mempool_for_chain_update(&cs, &self.mempool, &out.update);
        if out.update.tip_changed() {
            self.mempool.add_transactions_updated(1);
            let tip = cs.tip().expect("tip");
            self.tip_watch.notify(cs.block_index().get(tip).block_hash);
        }
        let e = cs.block_index().get(out.arena_idx);
        Ok(SinkOutcome {
            new_block: out.new_block,
            in_active_chain: cs.active_chain().get_block_index(e.height) == Some(out.arena_idx),
        })
    }
}

/// The current best block hash, with a condition variable for waiters.
///
/// Stands in for Core's `g_best_block` / `g_best_block_cv` (and the mining
/// interface's `waitTipChanged`). The daemon calls [`TipWatch::notify`]
/// whenever the tip moves, from any source (P2P, `submitblock`, generate).
pub struct TipWatch {
    tip: Mutex<BlockHash>,
    cv: Condvar,
}

impl TipWatch {
    /// Create a watch starting at `tip`.
    pub fn new(tip: BlockHash) -> Self {
        TipWatch {
            tip: Mutex::new(tip),
            cv: Condvar::new(),
        }
    }

    /// Record a new tip and wake every waiter.
    pub fn notify(&self, tip: BlockHash) {
        *self.tip.lock() = tip;
        self.cv.notify_all();
    }

    /// The last recorded tip.
    pub fn current(&self) -> BlockHash {
        *self.tip.lock()
    }

    /// Wait until the tip differs from `old` or `deadline` passes; returns
    /// the tip at that point.
    pub fn wait_tip_changed(&self, old: BlockHash, deadline: Instant) -> BlockHash {
        let mut tip = self.tip.lock();
        while *tip == old {
            if self.cv.wait_until(&mut tip, deadline).timed_out() {
                break;
            }
        }
        *tip
    }
}

/// A template kept between `getblocktemplate` calls (Core keeps the same
/// statics in `getblocktemplate`).
struct CachedTemplate {
    prev: BlockHash,
    txs_updated: u64,
    built_at: Instant,
    template: BlockTemplate,
}

/// Shared state for the mining RPCs.
pub struct MiningContext {
    /// The chainstate.
    pub chainstate: Arc<Mutex<ChainstateManager>>,
    /// The mempool.
    pub mempool: Arc<TxMemPool>,
    /// Persists and connects blocks.
    pub sink: Arc<dyn BlockSink>,
    /// Tip-change notifications (long polling).
    pub tip_watch: Arc<TipWatch>,
    /// Block assembly policy.
    pub assembler_options: BlockAssemblerOptions,
    /// Number of connected peers (GBT refuses to serve with none on mainnet).
    pub peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    /// Core's `IsTestChain()`: skips the connection and IBD checks.
    pub is_test_chain: bool,
    /// Chain name for `getmininginfo` (`main`, `test`, `regtest`, ...).
    pub chain_name: String,
    /// Register `generatetoaddress` (regtest).
    pub allow_generate: bool,
    /// Long-poll wait before the first mempool check ([`LONGPOLL_FIRST_CHECK`]).
    pub longpoll_first_check: Duration,
    /// Long-poll mempool re-check interval ([`LONGPOLL_RECHECK`]).
    pub longpoll_recheck: Duration,
    cache: Mutex<Option<CachedTemplate>>,
}

impl MiningContext {
    /// Build a context. See the field docs for the arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chainstate: Arc<Mutex<ChainstateManager>>,
        mempool: Arc<TxMemPool>,
        sink: Arc<dyn BlockSink>,
        tip_watch: Arc<TipWatch>,
        assembler_options: BlockAssemblerOptions,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
        is_test_chain: bool,
        chain_name: &str,
        allow_generate: bool,
    ) -> Self {
        MiningContext {
            chainstate,
            mempool,
            sink,
            tip_watch,
            assembler_options,
            peer_count,
            is_test_chain,
            chain_name: chain_name.to_string(),
            allow_generate,
            longpoll_first_check: LONGPOLL_FIRST_CHECK,
            longpoll_recheck: LONGPOLL_RECHECK,
            cache: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

fn param(req: &RpcRequest, i: usize) -> Option<&Value> {
    match req.params.as_ref()? {
        Value::Array(a) => a.get(i).filter(|v| !v.is_null()),
        _ => None,
    }
}

/// Core's `BIP22ValidationResult`: null when valid, else the reject reason
/// (or "rejected" when there is none).
fn bip22_result(state: &BlockValidationState) -> Value {
    let reason = state.get_reject_reason();
    if reason.is_empty() {
        json!("rejected")
    } else {
        json!(reason)
    }
}

/// Target for compact `bits`, as a 64-char hex string.
fn target_hex(bits: u32) -> String {
    let mut t = ArithUint256::zero();
    t.set_compact(bits);
    arith_to_uint256(&t).to_hex()
}

/// `gbt_rule_value` (rpc/mining.cpp): prefix `!` unless the rule is optional.
fn gbt_rule_value(name: &str, optional: bool) -> String {
    if optional {
        name.to_string()
    } else {
        format!("!{}", name)
    }
}

/// Decode a segwit address to its scriptPubKey; any other string pays to
/// `OP_TRUE` (the regtest behaviour `generatetoaddress` always had here).
fn coinbase_script_for(address: &str) -> Script {
    if let Ok((_, version, program)) = bech32::segwit::decode(address) {
        let ver_op: u8 = match version.to_u8() {
            0 => 0x00,
            n => 0x50 + n,
        };
        let mut raw = Vec::with_capacity(2 + program.len());
        raw.push(ver_op);
        raw.push(program.len() as u8);
        raw.extend_from_slice(&program);
        Script::from_bytes(raw)
    } else {
        Script::from_bytes(vec![0x51])
    }
}

/// Port of Core's `GetNetworkHashPS` (rpc/mining.cpp).
fn network_hash_ps(cs: &ChainstateManager, lookup: i64, height: i64) -> f64 {
    let chain = cs.active_chain();
    let arena = cs.block_index();
    let tip_h = cs.height();
    if tip_h < 0 {
        return 0.0;
    }
    let h = if height >= 0 && height < tip_h as i64 { height as i32 } else { tip_h };
    let pb_idx = match chain.get_block_index(h) {
        Some(i) => i,
        None => return 0.0,
    };
    let pb = arena.get(pb_idx);
    let mut lookup = lookup;
    if lookup <= 0 {
        let interval = cs.consensus().difficulty_adjustment_interval();
        lookup = pb.height as i64 % interval + 1;
    }
    if lookup > pb.height as i64 {
        lookup = pb.height as i64;
    }
    if lookup <= 0 {
        return 0.0;
    }
    let mut min_time = pb.get_block_time();
    let mut max_time = min_time;
    let mut p0 = pb;
    for _ in 0..lookup {
        match p0.prev {
            Some(p) => {
                p0 = arena.get(p);
                let t = p0.get_block_time();
                min_time = min_time.min(t);
                max_time = max_time.max(t);
            }
            None => break,
        }
    }
    if min_time == max_time {
        return 0.0;
    }
    let work = pb.chain_work - p0.chain_work;
    work.to_f64() / (max_time - min_time) as f64
}

// ---------------------------------------------------------------------------
// getblocktemplate
// ---------------------------------------------------------------------------

/// Build (or reuse) the template for the current tip. Core rebuilds when the
/// tip changes, or when the mempool changed and the cached one is older
/// than 5 s; otherwise it only refreshes the time.
fn current_template(ctx: &MiningContext, cs: &ChainstateManager) -> Result<(BlockTemplate, u64), String> {
    let tip = cs.tip().ok_or("no chain tip")?;
    let tip_hash = cs.block_index().get(tip).block_hash;
    let txs_updated = ctx.mempool.get_transactions_updated();
    let mut cache = ctx.cache.lock();
    let stale = match cache.as_ref() {
        None => true,
        Some(c) => {
            c.prev != tip_hash
                || (c.txs_updated != txs_updated
                    && c.built_at.elapsed().as_secs() > TEMPLATE_REFRESH_SECS)
        }
    };
    if stale {
        let tmpl = BlockAssembler::new(cs, Some(&ctx.mempool), ctx.assembler_options.clone())
            .create_new_block(&Script::from_bytes(vec![0x51]))
            .map_err(|e| e.to_string())?;
        *cache = Some(CachedTemplate {
            prev: tip_hash,
            txs_updated,
            built_at: Instant::now(),
            template: tmpl,
        });
    }
    let c = cache.as_mut().expect("template cached above");
    update_time(&mut c.template.block.header, cs, tip);
    c.template.block.header.nonce = 0;
    Ok((c.template.clone(), c.txs_updated))
}

fn getblocktemplate(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let oparam = match param(req, 0) {
        None => Map::new(),
        Some(Value::Object(o)) => o.clone(),
        Some(_) => {
            return RpcResponse::error(id, RPC_TYPE_ERROR, "template_request must be an object".into())
        }
    };

    let mode = match oparam.get("mode") {
        None | Some(Value::Null) => "template".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return RpcResponse::error(id, RPC_INVALID_PARAMETER, "Invalid mode".into()),
    };
    let lpval = oparam.get("longpollid").cloned().filter(|v| !v.is_null());

    // BIP23 proposal.
    if mode == "proposal" {
        let data = match oparam.get("data") {
            Some(Value::String(s)) => s.clone(),
            _ => {
                return RpcResponse::error(
                    id,
                    RPC_TYPE_ERROR,
                    "Missing data String key for proposal".into(),
                )
            }
        };
        let block: Block = match hex_decode(&data).and_then(|b| deserialize(&b).ok()) {
            Some(b) => b,
            None => {
                return RpcResponse::error(id, RPC_DESERIALIZATION_ERROR, "Block decode failed".into())
            }
        };
        let cs = ctx.chainstate.lock();
        let hash = block.header.block_hash();
        if let Some(idx) = cs.lookup_block_index(&hash) {
            let e = cs.block_index().get(idx);
            if e.is_valid(BlockStatus::VALID_SCRIPTS) {
                return RpcResponse::success(id, json!("duplicate"));
            }
            if e.status.has_failed() {
                return RpcResponse::success(id, json!("duplicate-invalid"));
            }
            return RpcResponse::success(id, json!("duplicate-inconclusive"));
        }
        let tip_hash = cs.tip().map(|t| cs.block_index().get(t).block_hash);
        if Some(block.header.prev_blockhash) != tip_hash {
            return RpcResponse::success(id, json!("inconclusive-not-best-prevblk"));
        }
        return match cs.test_block_validity(&block, false, true) {
            Ok(()) => RpcResponse::success(id, Value::Null),
            Err(state) => RpcResponse::success(id, bip22_result(&state)),
        };
    }

    let mut client_rules: HashSet<String> = HashSet::new();
    if let Some(rules) = oparam.get("rules") {
        match rules {
            Value::Array(a) => {
                for r in a {
                    if let Some(s) = r.as_str() {
                        client_rules.insert(s.to_string());
                    }
                }
            }
            Value::Null => {}
            _ => return RpcResponse::error(id, RPC_TYPE_ERROR, "rules must be an array".into()),
        }
    }

    if mode != "template" {
        return RpcResponse::error(id, RPC_INVALID_PARAMETER, "Invalid mode".into());
    }

    if !ctx.is_test_chain {
        if (ctx.peer_count)() == 0 {
            return RpcResponse::error(
                id,
                RPC_CLIENT_NOT_CONNECTED,
                "Qubitcoin is not connected!".into(),
            );
        }
        if ctx.chainstate.lock().is_initial_block_download() {
            return RpcResponse::error(
                id,
                RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                "Qubitcoin is in initial sync and waiting for blocks...".into(),
            );
        }
    }

    // Long polling: wait for the tip to change, or (after the first
    // minute, re-checked every 10 s) for the mempool to change.
    if let Some(lp) = lpval {
        let (watched, txs_updated_lp) = match lp.as_str() {
            Some(s) if s.len() >= 64 => {
                let h = BlockHash::from_hex(&s[..64]).unwrap_or(BlockHash::ZERO);
                let n = s[64..].parse::<u64>().unwrap_or(0);
                (h, n)
            }
            _ => {
                // Spec does not define a non-string longpollid; Core watches
                // the current tip and mempool state.
                let cache_txs = ctx.cache.lock().as_ref().map(|c| c.txs_updated);
                (
                    ctx.tip_watch.current(),
                    cache_txs.unwrap_or_else(|| ctx.mempool.get_transactions_updated()),
                )
            }
        };
        let mut check_at = Instant::now() + ctx.longpoll_first_check;
        loop {
            let tip = ctx.tip_watch.wait_tip_changed(watched, check_at);
            if tip != watched {
                break;
            }
            if ctx.mempool.get_transactions_updated() != txs_updated_lp {
                break;
            }
            check_at += ctx.longpoll_recheck;
        }
    }

    let cs = ctx.chainstate.lock();
    let consensus = cs.consensus().clone();

    if consensus.signet_blocks && !client_rules.contains("signet") {
        return RpcResponse::error(
            id,
            RPC_INVALID_PARAMETER,
            "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})".into(),
        );
    }
    if !client_rules.contains("segwit") {
        return RpcResponse::error(
            id,
            RPC_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})".into(),
        );
    }

    let (tmpl, txs_updated_last) = match current_template(ctx, &cs) {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(id, RPC_MISC_ERROR, e),
    };
    let tip = cs.tip().expect("template built on a tip");
    let prev = cs.block_index().get(tip);
    let height = prev.height + 1;
    let pre_segwit = height < consensus.segwit_height;
    let mut block = tmpl.block.clone();

    // transactions[]
    let mut transactions = Vec::with_capacity(block.vtx.len().saturating_sub(1));
    let mut index_of: std::collections::HashMap<Txid, usize> = std::collections::HashMap::new();
    for (i, tx) in block.vtx.iter().enumerate() {
        index_of.insert(*tx.txid(), i);
        if tx.is_coinbase() {
            continue;
        }
        let deps: Vec<usize> = tx
            .vin
            .iter()
            .filter_map(|inp| index_of.get(&inp.prevout.hash).copied())
            .collect();
        let mut sigops = tmpl.tx_sigops_cost[i];
        if pre_segwit {
            sigops /= WITNESS_SCALE_FACTOR as i64;
        }
        let data = serialize(&**tx).map(|b| hex_encode(&b)).unwrap_or_default();
        transactions.push(json!({
            "data": data,
            "txid": tx.txid().to_hex(),
            "hash": tx.wtxid().to_hex(),
            "depends": deps,
            "fee": tmpl.tx_fees[i].to_sat(),
            "sigops": sigops,
            "weight": tx.get_weight(),
        }));
    }

    // BIP9 rules / vbavailable, and version masking for rules the client
    // does not understand.
    let mut rules: Vec<String> = vec!["csv".to_string()];
    if !pre_segwit {
        rules.push("!segwit".to_string());
    }
    if consensus.signet_blocks {
        rules.push("!signet".to_string());
    }
    let mut vbavailable = Map::new();
    let gbt = VersionBitsCache::new().gbt_status(cs.block_index().as_slice(), tip, &consensus);
    for info in gbt.signalling.iter() {
        vbavailable.insert(gbt_rule_value(info.name, info.gbt_optional_rule), json!(info.bit));
        if !info.gbt_optional_rule && !client_rules.contains(info.name) {
            block.header.version &= !(info.mask as i32);
        }
    }
    for info in gbt.locked_in.iter() {
        block.header.version |= info.mask as i32;
        vbavailable.insert(gbt_rule_value(info.name, info.gbt_optional_rule), json!(info.bit));
        if !info.gbt_optional_rule && !client_rules.contains(info.name) {
            block.header.version &= !(info.mask as i32);
        }
    }
    for info in gbt.active.iter() {
        rules.push(gbt_rule_value(info.name, info.gbt_optional_rule));
        if !info.gbt_optional_rule && !client_rules.contains(info.name) {
            return RpcResponse::error(
                id,
                RPC_INVALID_PARAMETER,
                format!("Support for '{}' rule requires explicit client support", info.name),
            );
        }
    }

    let (sigop_limit, size_limit) = if pre_segwit {
        (
            MAX_BLOCK_SIGOPS_COST as i64 / WITNESS_SCALE_FACTOR as i64,
            MAX_BLOCK_SERIALIZED_SIZE as i64 / WITNESS_SCALE_FACTOR as i64,
        )
    } else {
        (MAX_BLOCK_SIGOPS_COST as i64, MAX_BLOCK_SERIALIZED_SIZE as i64)
    };

    let mut result = Map::new();
    result.insert("capabilities".into(), json!(["proposal"]));
    result.insert("version".into(), json!(block.header.version));
    result.insert("rules".into(), json!(rules));
    result.insert("vbavailable".into(), Value::Object(vbavailable));
    result.insert("vbrequired".into(), json!(0));
    result.insert("previousblockhash".into(), json!(block.header.prev_blockhash.to_hex()));
    result.insert("transactions".into(), Value::Array(transactions));
    result.insert("coinbaseaux".into(), json!({}));
    result.insert("coinbasevalue".into(), json!(block.vtx[0].vout[0].value.to_sat()));
    result.insert(
        "longpollid".into(),
        json!(format!("{}{}", prev.block_hash.to_hex(), txs_updated_last)),
    );
    result.insert("target".into(), json!(target_hex(block.header.bits)));
    result.insert("mintime".into(), json!(get_minimum_time(&cs, tip)));
    result.insert("mutable".into(), json!(["time", "transactions", "prevblock"]));
    result.insert("noncerange".into(), json!("00000000ffffffff"));
    result.insert("sigoplimit".into(), json!(sigop_limit));
    result.insert("sizelimit".into(), json!(size_limit));
    if !pre_segwit {
        result.insert("weightlimit".into(), json!(MAX_BLOCK_WEIGHT as i64));
    }
    result.insert("curtime".into(), json!(block.header.time as i64));
    result.insert("bits".into(), json!(format!("{:08x}", block.header.bits)));
    result.insert("height".into(), json!(height as i64));
    if consensus.signet_blocks {
        result.insert("signet_challenge".into(), json!(hex_encode(&consensus.signet_challenge)));
    }
    if !tmpl.coinbase_commitment.is_empty() {
        result.insert(
            "default_witness_commitment".into(),
            json!(hex_encode(&tmpl.coinbase_commitment)),
        );
    }
    RpcResponse::success(id, Value::Object(result))
}

// ---------------------------------------------------------------------------
// submitblock / submitheader
// ---------------------------------------------------------------------------

/// Core's `submitblock` result for `block`: `Ok(Value::Null)` when accepted
/// as the new tip, otherwise a BIP22 string. `Err` is an internal error
/// (Core's `state.IsError()`), reported as `RPC_VERIFY_ERROR`.
pub fn submit_block(ctx: &MiningContext, mut block: Block) -> Result<Value, String> {
    {
        let cs = ctx.chainstate.lock();
        let consensus = cs.consensus().clone();
        let prev_idx = cs.lookup_block_index(&block.header.prev_blockhash);
        if let Some(pi) = prev_idx {
            let h = cs.block_index().get(pi).height + 1;
            update_uncommitted_block_structures(&mut block, &consensus, h);
        }

        let hash = block.header.block_hash();
        if let Some(idx) = cs.lookup_block_index(&hash) {
            let e = cs.block_index().get(idx);
            // Known-invalid: AcceptBlockHeader's BLOCK_CACHED_INVALID
            // "duplicate"; already have the data: !new_block && accepted.
            if e.status.has_failed() || e.status.contains(BlockStatus::HAVE_DATA) {
                return Ok(json!("duplicate"));
            }
        }

        // CheckBlock (context free, with proof of work).
        let mut state = BlockValidationState::new();
        if !qubitcoin_node::validation::check_block(&block, &consensus, &mut state, true) {
            return Ok(bip22_result(&state));
        }
        let pi = match prev_idx {
            Some(p) => p,
            None => return Ok(json!("prev-blk-not-found")),
        };
        if cs.block_index().get(pi).status.has_failed() {
            return Ok(json!("bad-prevblk"));
        }
    }

    // ProcessNewBlock: stored wherever it attaches; reorganises onto it if
    // its chain now has the most work.
    Ok(match ctx.sink.process_new_block(&block) {
        // Core: `!new_block && accepted` -> "duplicate".
        Ok(o) if !o.new_block => json!("duplicate"),
        // Connected (BlockChecked fired with a valid state).
        Ok(o) if o.in_active_chain => Value::Null,
        // Valid but on a side branch with less work: BlockChecked never
        // fired for it.
        Ok(_) => json!("inconclusive"),
        Err(state) if state.is_error() => return Err(state.get_reject_reason().to_string()),
        Err(state) => bip22_result(&state),
    })
}

fn submitblock(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let hex = match param(req, 0).and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return RpcResponse::error(id, RPC_TYPE_ERROR, "hexdata must be a string".into()),
    };
    let block: Block = match hex_decode(hex).and_then(|b| deserialize(&b).ok()) {
        Some(b) => b,
        None => return RpcResponse::error(id, RPC_DESERIALIZATION_ERROR, "Block decode failed".into()),
    };
    if block.vtx.is_empty() || !block.vtx[0].is_coinbase() {
        return RpcResponse::error(
            id,
            RPC_DESERIALIZATION_ERROR,
            "Block does not start with a coinbase".into(),
        );
    }
    match submit_block(ctx, block) {
        Ok(v) => RpcResponse::success(id, v),
        Err(msg) => RpcResponse::error(id, RPC_VERIFY_ERROR, msg),
    }
}

fn submitheader(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let header: BlockHeader = match param(req, 0)
        .and_then(|v| v.as_str())
        .and_then(hex_decode)
        .filter(|b| b.len() == 80)
        .and_then(|b| deserialize(&b).ok())
    {
        Some(h) => h,
        None => {
            return RpcResponse::error(
                id,
                RPC_DESERIALIZATION_ERROR,
                "Block header decode failed".into(),
            )
        }
    };
    let mut cs = ctx.chainstate.lock();
    if cs.lookup_block_index(&header.prev_blockhash).is_none() {
        return RpcResponse::error(
            id,
            RPC_VERIFY_ERROR,
            format!("Must submit previous header ({}) first", header.prev_blockhash.to_hex()),
        );
    }
    if let Some(idx) = cs.lookup_block_index(&header.block_hash()) {
        if cs.block_index().get(idx).status.has_failed() {
            return RpcResponse::error(id, RPC_VERIFY_ERROR, "duplicate".into());
        }
    }
    match cs.accept_block_header(&header) {
        Ok(_) => RpcResponse::success(id, Value::Null),
        Err(state) => {
            let reason = state.get_reject_reason();
            RpcResponse::error(
                id,
                RPC_VERIFY_ERROR,
                if reason.is_empty() { "rejected".into() } else { reason.to_string() },
            )
        }
    }
}

// ---------------------------------------------------------------------------
// getblockheader
// ---------------------------------------------------------------------------

/// Core's `blockheaderToJSON` (rpc/blockchain.cpp).
pub fn block_header_to_json(cs: &ChainstateManager, idx: usize) -> Value {
    let e = cs.block_index().get(idx);
    let chain = cs.active_chain();
    let in_active = chain.get_block_index(e.height) == Some(idx);
    let confirmations = if in_active { cs.height() - e.height + 1 } else { -1 };
    let mut o = Map::new();
    o.insert("hash".into(), json!(e.block_hash.to_hex()));
    o.insert("confirmations".into(), json!(confirmations));
    o.insert("height".into(), json!(e.height));
    o.insert("version".into(), json!(e.version));
    o.insert("versionHex".into(), json!(format!("{:08x}", e.version as u32)));
    o.insert("merkleroot".into(), json!(e.merkle_root.to_hex()));
    o.insert("time".into(), json!(e.time as i64));
    o.insert("mediantime".into(), json!(cs.median_time_past(idx)));
    o.insert("nonce".into(), json!(e.nonce as u64));
    o.insert("bits".into(), json!(format!("{:08x}", e.bits)));
    o.insert("target".into(), json!(target_hex(e.bits)));
    o.insert("difficulty".into(), json!(get_difficulty(e.bits)));
    o.insert("chainwork".into(), json!(e.chain_work.to_hex()));
    o.insert("nTx".into(), json!(e.tx_count));
    if let Some(p) = e.prev {
        o.insert(
            "previousblockhash".into(),
            json!(cs.block_index().get(p).block_hash.to_hex()),
        );
    }
    if in_active {
        if let Some(n) = chain.get_block_index(e.height + 1) {
            o.insert("nextblockhash".into(), json!(cs.block_index().get(n).block_hash.to_hex()));
        }
    }
    Value::Object(o)
}

fn getblockheader(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let hash = match param(req, 0).and_then(|v| v.as_str()) {
        Some(h) if h.len() == 64 => match BlockHash::from_hex(h) {
            Some(b) => b,
            None => {
                return RpcResponse::error(
                    id,
                    RPC_INVALID_PARAMETER,
                    "blockhash must be hexadecimal string".into(),
                )
            }
        },
        _ => {
            return RpcResponse::error(
                id,
                RPC_INVALID_PARAMETER,
                "blockhash must be of length 64 (not 0, for '')".into(),
            )
        }
    };
    let verbose = param(req, 1)
        .map(|v| v.as_bool().unwrap_or_else(|| v.as_i64().map(|n| n != 0).unwrap_or(true)))
        .unwrap_or(true);
    let cs = ctx.chainstate.lock();
    let idx = match cs.lookup_block_index(&hash) {
        Some(i) => i,
        None => return RpcResponse::error(id, RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into()),
    };
    if !verbose {
        let header = cs.block_index().get(idx).get_block_header();
        return match serialize(&header) {
            Ok(b) => RpcResponse::success(id, json!(hex_encode(&b))),
            Err(e) => RpcResponse::error(id, RPC_MISC_ERROR, format!("serialize: {}", e)),
        };
    }
    RpcResponse::success(id, block_header_to_json(&cs, idx))
}

// ---------------------------------------------------------------------------
// prioritisetransaction / getprioritisedtransactions
// ---------------------------------------------------------------------------

fn prioritisetransaction(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let txid = match param(req, 0).and_then(|v| v.as_str()).and_then(Txid::from_hex) {
        Some(t) => t,
        None => {
            return RpcResponse::error(id, RPC_INVALID_PARAMETER, "txid must be hexadecimal string".into())
        }
    };
    if let Some(d) = param(req, 1) {
        if d.as_f64() != Some(0.0) {
            return RpcResponse::error(
                id,
                RPC_INVALID_PARAMETER,
                "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.".into(),
            );
        }
    }
    let delta = match param(req, 2).and_then(|v| v.as_i64()) {
        Some(d) => d,
        None => return RpcResponse::error(id, RPC_TYPE_ERROR, "fee_delta must be an integer".into()),
    };
    ctx.mempool.prioritise_transaction(&txid, delta);
    RpcResponse::success(id, json!(true))
}

fn getprioritisedtransactions(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let mut o = Map::new();
    for p in ctx.mempool.get_prioritised_transactions() {
        let mut e = Map::new();
        e.insert("fee_delta".into(), json!(p.delta));
        e.insert("in_mempool".into(), json!(p.in_mempool));
        if let Some(m) = p.modified_fee {
            e.insert("modified_fee".into(), json!(m.to_sat()));
        }
        o.insert(p.txid.to_hex(), Value::Object(e));
    }
    RpcResponse::success(req.id.clone(), Value::Object(o))
}

// ---------------------------------------------------------------------------
// getmininginfo / getnetworkhashps / getdifficulty
// ---------------------------------------------------------------------------

fn getmininginfo(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let cs = ctx.chainstate.lock();
    let bits = cs.tip().map(|t| cs.block_index().get(t).bits).unwrap_or(0);
    let mut o = Map::new();
    o.insert("blocks".into(), json!(cs.height()));
    if let Some(c) = ctx.cache.lock().as_ref() {
        o.insert("currentblockweight".into(), json!(c.template.block_weight));
        o.insert("currentblocktx".into(), json!(c.template.block.vtx.len() - 1));
    }
    o.insert("bits".into(), json!(format!("{:08x}", bits)));
    o.insert("difficulty".into(), json!(get_difficulty(bits)));
    o.insert("target".into(), json!(target_hex(bits)));
    o.insert("networkhashps".into(), json!(network_hash_ps(&cs, 120, -1)));
    o.insert("pooledtx".into(), json!(ctx.mempool.size()));
    o.insert("chain".into(), json!(ctx.chain_name));
    o.insert("warnings".into(), json!([]));
    RpcResponse::success(req.id.clone(), Value::Object(o))
}

fn getnetworkhashps(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let nblocks = param(req, 0).and_then(|v| v.as_i64()).unwrap_or(120);
    let height = param(req, 1).and_then(|v| v.as_i64()).unwrap_or(-1);
    let cs = ctx.chainstate.lock();
    RpcResponse::success(req.id.clone(), json!(network_hash_ps(&cs, nblocks, height)))
}

fn getdifficulty(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let cs = ctx.chainstate.lock();
    let bits = cs.tip().map(|t| cs.block_index().get(t).bits).unwrap_or(0x1d00ffff);
    RpcResponse::success(req.id.clone(), json!(get_difficulty(bits)))
}

// ---------------------------------------------------------------------------
// generatetoaddress
// ---------------------------------------------------------------------------

/// Mine `nblocks` blocks paying to `script`, returning their hashes.
///
/// Port of Core's `generateBlocks` / `GenerateBlock` (rpc/mining.cpp): each
/// block is assembled by `BlockAssembler::CreateNewBlock`, its nonce is
/// ground until it meets the target, and it goes through
/// `ProcessNewBlock`. Timestamps are kept strictly increasing so that
/// back-to-back regtest blocks never collide.
pub fn generate_blocks(ctx: &MiningContext, script: &Script, nblocks: u64) -> Result<Vec<String>, String> {
    let mut hashes = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut last_time = {
        let cs = ctx.chainstate.lock();
        let tip_time = cs.tip().map(|t| cs.block_index().get(t).time).unwrap_or(0);
        now.max(tip_time)
    };
    for _ in 0..nblocks {
        let mut block = {
            let cs = ctx.chainstate.lock();
            let tmpl = BlockAssembler::new(&cs, Some(&ctx.mempool), ctx.assembler_options.clone())
                .create_new_block(script)
                .map_err(|e| e.to_string())?;
            let mut block = tmpl.block;
            last_time += 1;
            block.header.time = last_time;
            if let Some(tip) = cs.tip() {
                block.header.bits = cs.next_work_required(tip, block.header.time);
            }
            block
        };
        let mut target = ArithUint256::zero();
        target.set_compact(block.header.bits);
        while uint256_to_arith(&block.header.block_hash().into_uint256()) > target {
            block.header.nonce = block.header.nonce.wrapping_add(1);
            if block.header.nonce == 0 {
                // Exhausted the nonce space: bump the time and continue.
                block.header.time += 1;
                last_time = block.header.time;
            }
        }
        let hash = block.header.block_hash();
        match ctx.sink.process_new_block(&block) {
            Ok(o) if o.in_active_chain => {}
            Ok(_) => return Err("ProcessNewBlock, block not accepted".into()),
            Err(state) => {
                return Err(format!("ProcessNewBlock, block not accepted: {}", state.get_reject_reason()))
            }
        }
        hashes.push(hash.to_hex());
    }
    Ok(hashes)
}

fn generatetoaddress(ctx: &MiningContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let nblocks = param(req, 0).and_then(|v| v.as_u64()).unwrap_or(0);
    let address = match param(req, 1).and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return RpcResponse::error(id, crate::server::RPC_INVALID_PARAMS, "missing address".into()),
    };
    match generate_blocks(ctx, &coinbase_script_for(address), nblocks) {
        Ok(h) => RpcResponse::success(id, json!(h)),
        Err(e) => RpcResponse::error(id, RPC_MISC_ERROR, e),
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register the mining RPCs. `getblocktemplate`, `submitblock` and
/// `submitheader` are admin-tier (they need credentials, as every Core RPC
/// does); the read-only ones are public.
pub fn register_mining_rpcs(registry: &mut RpcRegistry, ctx: Arc<MiningContext>) {
    let c = ctx.clone();
    registry.register_admin("getblocktemplate", move |req| getblocktemplate(&c, req));
    let c = ctx.clone();
    registry.register_admin("submitblock", move |req| submitblock(&c, req));
    let c = ctx.clone();
    registry.register_admin("submitheader", move |req| submitheader(&c, req));
    let c = ctx.clone();
    registry.register_admin("prioritisetransaction", move |req| prioritisetransaction(&c, req));
    let c = ctx.clone();
    registry.register_admin("getprioritisedtransactions", move |req| {
        getprioritisedtransactions(&c, req)
    });
    let c = ctx.clone();
    registry.register("getblockheader", move |req| getblockheader(&c, req));
    let c = ctx.clone();
    registry.register("getmininginfo", move |req| getmininginfo(&c, req));
    let c = ctx.clone();
    registry.register("getnetworkhashps", move |req| getnetworkhashps(&c, req));
    let c = ctx.clone();
    registry.register("getdifficulty", move |req| getdifficulty(&c, req));
    if ctx.allow_generate {
        let c = ctx.clone();
        registry.register("generatetoaddress", move |req| generatetoaddress(&c, req));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qubitcoin_common::chainparams::ChainParams;
    use qubitcoin_common::coins::EmptyCoinsView;

    fn regtest_ctx() -> Arc<MiningContext> {
        let params = ChainParams::regtest();
        let mut cs = ChainstateManager::new(params.clone(), Box::new(EmptyCoinsView));
        cs.load_genesis_block(&params.create_genesis_block()).unwrap();
        let tip = params.genesis_block_hash;
        let cs = Arc::new(Mutex::new(cs));
        let mempool = Arc::new(TxMemPool::new());
        let tip_watch = Arc::new(TipWatch::new(tip));
        let sink = Arc::new(MemoryBlockSink {
            chainstate: cs.clone(),
            mempool: mempool.clone(),
            tip_watch: tip_watch.clone(),
        });
        Arc::new(MiningContext::new(
            cs,
            mempool,
            sink,
            tip_watch,
            BlockAssemblerOptions::default(),
            Arc::new(|| 0),
            true,
            "regtest",
            true,
        ))
    }

    fn registry(ctx: &Arc<MiningContext>) -> RpcRegistry {
        let mut r = RpcRegistry::new();
        register_mining_rpcs(&mut r, ctx.clone());
        r
    }

    fn call(r: &RpcRegistry, method: &str, params: Value) -> RpcResponse {
        r.dispatch(&RpcRequest {
            jsonrpc: Some("2.0".into()),
            method: method.into(),
            params: Some(params),
            id: json!(1),
        })
    }

    fn ok(resp: RpcResponse) -> Value {
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        resp.result.expect("result")
    }

    fn err_code(resp: RpcResponse) -> i32 {
        resp.error.expect("expected an error").code
    }

    #[test]
    fn test_registers_mining_methods_with_tiers() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        use crate::server::AuthTier;
        for m in ["getblocktemplate", "submitblock", "submitheader", "prioritisetransaction", "getprioritisedtransactions"] {
            assert_eq!(r.auth_tier_for(m), Some(AuthTier::Admin), "{}", m);
        }
        for m in ["getblockheader", "getmininginfo", "getnetworkhashps", "getdifficulty", "generatetoaddress"] {
            assert_eq!(r.auth_tier_for(m), Some(AuthTier::Public), "{}", m);
        }
    }

    #[test]
    fn test_gbt_requires_segwit_rule() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        assert_eq!(err_code(call(&r, "getblocktemplate", json!([]))), RPC_INVALID_PARAMETER);
        assert_eq!(
            err_code(call(&r, "getblocktemplate", json!([{"rules": ["csv"]}]))),
            RPC_INVALID_PARAMETER
        );
        assert_eq!(
            err_code(call(&r, "getblocktemplate", json!([{"mode": "bogus", "rules": ["segwit"]}]))),
            RPC_INVALID_PARAMETER
        );
        assert_eq!(err_code(call(&r, "getblocktemplate", json!(["x"]))), RPC_TYPE_ERROR);
    }

    #[test]
    fn test_gbt_field_shape_matches_core() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        let t = ok(call(&r, "getblocktemplate", json!([{"rules": ["segwit"]}])));
        let mut keys: Vec<&str> = t.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort();
        // Bitcoin Core's documented getblocktemplate result on a non-signet,
        // post-segwit chain (rpc/mining.cpp).
        let mut expected = vec![
            "capabilities", "version", "rules", "vbavailable", "vbrequired",
            "previousblockhash", "transactions", "coinbaseaux", "coinbasevalue",
            "longpollid", "target", "mintime", "mutable", "noncerange", "sigoplimit",
            "sizelimit", "weightlimit", "curtime", "bits", "height",
            "default_witness_commitment",
        ];
        expected.sort();
        assert_eq!(keys, expected);
        assert_eq!(t["capabilities"], json!(["proposal"]));
        assert_eq!(t["rules"], json!(["csv", "!segwit"]));
        assert_eq!(t["vbrequired"], json!(0));
        assert_eq!(t["height"], json!(1));
        assert_eq!(t["bits"], json!("207fffff"));
        assert_eq!(
            t["target"],
            json!("7fffff0000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(t["noncerange"], json!("00000000ffffffff"));
        assert_eq!(t["mutable"], json!(["time", "transactions", "prevblock"]));
        assert_eq!(t["sigoplimit"], json!(80000));
        assert_eq!(t["sizelimit"], json!(4000000));
        assert_eq!(t["weightlimit"], json!(4000000));
        assert_eq!(t["coinbasevalue"], json!(50 * 100_000_000i64));
        assert_eq!(t["coinbaseaux"], json!({}));
        let lp = t["longpollid"].as_str().unwrap();
        assert_eq!(&lp[..64], t["previousblockhash"].as_str().unwrap());
        assert!(t["default_witness_commitment"].as_str().unwrap().starts_with("6a24aa21a9ed"));
        assert!(t["curtime"].as_i64().unwrap() >= t["mintime"].as_i64().unwrap());
    }

    #[test]
    fn test_gbt_mainnet_checks_connections() {
        let ctx = regtest_ctx();
        let mut c = MiningContext::new(
            ctx.chainstate.clone(),
            ctx.mempool.clone(),
            ctx.sink.clone(),
            ctx.tip_watch.clone(),
            BlockAssemblerOptions::default(),
            Arc::new(|| 0),
            false,
            "main",
            false,
        );
        c.allow_generate = false;
        let r = registry(&Arc::new(c));
        assert_eq!(
            err_code(call(&r, "getblocktemplate", json!([{"rules": ["segwit"]}]))),
            RPC_CLIENT_NOT_CONNECTED
        );
        assert!(!r.has_method("generatetoaddress"));
    }

    #[test]
    fn test_submitblock_errors() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        assert_eq!(err_code(call(&r, "submitblock", json!(["zz"]))), RPC_DESERIALIZATION_ERROR);
        assert_eq!(err_code(call(&r, "submitblock", json!([]))), RPC_TYPE_ERROR);
        // A header with no transactions.
        let mut empty = serialize(&ctx.chainstate.lock().block_index().get(0).get_block_header()).unwrap();
        empty.push(0);
        let resp = call(&r, "submitblock", json!([hex_encode(&empty)]));
        let e = resp.error.unwrap();
        assert_eq!(e.code, RPC_DESERIALIZATION_ERROR);
        assert_eq!(e.message, "Block does not start with a coinbase");
    }

    #[test]
    fn test_submitblock_duplicate_and_high_hash() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        ok(call(&r, "generatetoaddress", json!([1, "x"])));
        assert_eq!(ctx.chainstate.lock().height(), 1);

        // Assemble a fresh block, break its PoW, submit -> "high-hash".
        let mut b = {
            let cs = ctx.chainstate.lock();
            BlockAssembler::new(&cs, None, BlockAssemblerOptions::default())
                .create_new_block(&Script::from_bytes(vec![0x51]))
                .unwrap()
                .block
        };
        let mut target = ArithUint256::zero();
        target.set_compact(b.header.bits);
        while uint256_to_arith(&b.header.block_hash().into_uint256()) <= target {
            b.header.nonce += 1;
        }
        let hex = hex_encode(&serialize(&b).unwrap());
        assert_eq!(ok(call(&r, "submitblock", json!([hex]))), json!("high-hash"));

        // Solve properly -> null, then again -> "duplicate".
        while uint256_to_arith(&b.header.block_hash().into_uint256()) > target {
            b.header.nonce += 1;
        }
        let hex = hex_encode(&serialize(&b).unwrap());
        assert_eq!(ok(call(&r, "submitblock", json!([hex.clone()]))), Value::Null);
        assert_eq!(ctx.chainstate.lock().height(), 2);
        assert_eq!(ctx.tip_watch.current(), b.header.block_hash());
        assert_eq!(ok(call(&r, "submitblock", json!([hex]))), json!("duplicate"));
    }

    #[test]
    fn test_submitblock_prev_not_found() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        let mut b = {
            let cs = ctx.chainstate.lock();
            BlockAssembler::new(&cs, None, BlockAssemblerOptions::default())
                .create_new_block(&Script::from_bytes(vec![0x51]))
                .unwrap()
                .block
        };
        b.header.prev_blockhash = BlockHash::from_bytes([7u8; 32]);
        let mut target = ArithUint256::zero();
        target.set_compact(b.header.bits);
        while uint256_to_arith(&b.header.block_hash().into_uint256()) > target {
            b.header.nonce += 1;
        }
        let hex = hex_encode(&serialize(&b).unwrap());
        assert_eq!(ok(call(&r, "submitblock", json!([hex]))), json!("prev-blk-not-found"));
    }

    #[test]
    fn test_submitheader_and_getblockheader() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        let mut b = {
            let cs = ctx.chainstate.lock();
            BlockAssembler::new(&cs, None, BlockAssemblerOptions::default())
                .create_new_block(&Script::from_bytes(vec![0x51]))
                .unwrap()
                .block
        };
        let mut target = ArithUint256::zero();
        target.set_compact(b.header.bits);
        while uint256_to_arith(&b.header.block_hash().into_uint256()) > target {
            b.header.nonce += 1;
        }
        let hdr_hex = hex_encode(&serialize(&b.header).unwrap());
        assert_eq!(hdr_hex.len(), 160);

        // Unknown parent.
        let mut orphan = b.header.clone();
        orphan.prev_blockhash = BlockHash::from_bytes([9u8; 32]);
        let e = call(&r, "submitheader", json!([hex_encode(&serialize(&orphan).unwrap())]))
            .error
            .unwrap();
        assert_eq!(e.code, RPC_VERIFY_ERROR);
        assert!(e.message.starts_with("Must submit previous header"));
        assert_eq!(err_code(call(&r, "submitheader", json!(["00"]))), RPC_DESERIALIZATION_ERROR);

        assert_eq!(ok(call(&r, "submitheader", json!([hdr_hex.clone()]))), Value::Null);
        let hash = b.header.block_hash().to_hex();
        let h = ok(call(&r, "getblockheader", json!([hash.clone()])));
        assert_eq!(h["confirmations"], json!(-1), "header only, not on the active chain");
        assert_eq!(h["height"], json!(1));
        let mut keys: Vec<&str> = h.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort();
        let mut expected = vec![
            "hash", "confirmations", "height", "version", "versionHex", "merkleroot", "time",
            "mediantime", "nonce", "bits", "target", "difficulty", "chainwork", "nTx",
            "previousblockhash",
        ];
        expected.sort();
        assert_eq!(keys, expected);
        assert_eq!(ok(call(&r, "getblockheader", json!([hash.clone(), false]))), json!(hdr_hex));

        // Now the full block connects; the header gains confirmations and
        // the genesis header a nextblockhash.
        let blk_hex = hex_encode(&serialize(&b).unwrap());
        assert_eq!(ok(call(&r, "submitblock", json!([blk_hex]))), Value::Null);
        let h = ok(call(&r, "getblockheader", json!([hash.clone()])));
        assert_eq!(h["confirmations"], json!(1));
        let genesis = ChainParams::regtest().genesis_block_hash.to_hex();
        let g = ok(call(&r, "getblockheader", json!([genesis])));
        assert_eq!(g["nextblockhash"], json!(hash));
        assert_eq!(g["confirmations"], json!(2));

        assert_eq!(
            err_code(call(&r, "getblockheader", json!(["00".repeat(32)]))),
            RPC_INVALID_ADDRESS_OR_KEY
        );
        assert_eq!(err_code(call(&r, "getblockheader", json!(["abc"]))), RPC_INVALID_PARAMETER);
    }

    #[test]
    fn test_prioritisetransaction_rpcs() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        let txid = "11".repeat(32);
        assert_eq!(ok(call(&r, "prioritisetransaction", json!([txid.clone(), 0, 1234]))), json!(true));
        assert_eq!(ok(call(&r, "prioritisetransaction", json!([txid.clone(), null, 66]))), json!(true));
        assert_eq!(
            err_code(call(&r, "prioritisetransaction", json!([txid.clone(), 1, 5]))),
            RPC_INVALID_PARAMETER
        );
        assert_eq!(err_code(call(&r, "prioritisetransaction", json!([txid.clone()]))), RPC_TYPE_ERROR);
        let p = ok(call(&r, "getprioritisedtransactions", json!([])));
        assert_eq!(p[&txid], json!({"fee_delta": 1300, "in_mempool": false}));
        // Cancelling the delta removes the entry.
        ok(call(&r, "prioritisetransaction", json!([txid.clone(), 0, -1300])));
        assert_eq!(ok(call(&r, "getprioritisedtransactions", json!([]))), json!({}));
    }

    #[test]
    fn test_mininginfo_and_difficulty_are_live() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        ok(call(&r, "generatetoaddress", json!([3, "x"])));
        let m = ok(call(&r, "getmininginfo", json!([])));
        assert_eq!(m["blocks"], json!(3));
        assert_eq!(m["chain"], json!("regtest"));
        assert_eq!(m["bits"], json!("207fffff"));
        assert_eq!(m["pooledtx"], json!(0));
        let d = ok(call(&r, "getdifficulty", json!([]))).as_f64().unwrap();
        assert!(d > 0.0 && d < 1e-9);
        assert!(ok(call(&r, "getnetworkhashps", json!([]))).as_f64().unwrap() >= 0.0);
    }

    #[test]
    fn test_longpoll_returns_on_new_tip() {
        let ctx = regtest_ctx();
        let r = Arc::new(registry(&ctx));
        let t = ok(call(&r, "getblocktemplate", json!([{"rules": ["segwit"]}])));
        let lp = t["longpollid"].as_str().unwrap().to_string();
        let r2 = r.clone();
        let waiter = std::thread::spawn(move || {
            ok(call(&r2, "getblocktemplate", json!([{"rules": ["segwit"], "longpollid": lp}])))
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(!waiter.is_finished(), "long poll must block while nothing changes");
        let mined = ok(call(&r, "generatetoaddress", json!([1, "x"])));
        let t2 = waiter.join().unwrap();
        assert_eq!(t2["previousblockhash"], mined[0]);
        assert_eq!(t2["height"], json!(2));
    }

    #[test]
    fn test_longpoll_returns_on_mempool_change_after_timeout() {
        let base = regtest_ctx();
        let mut c = MiningContext::new(
            base.chainstate.clone(),
            base.mempool.clone(),
            base.sink.clone(),
            base.tip_watch.clone(),
            BlockAssemblerOptions::default(),
            Arc::new(|| 0),
            true,
            "regtest",
            true,
        );
        c.longpoll_first_check = Duration::from_millis(100);
        c.longpoll_recheck = Duration::from_millis(50);
        let ctx = Arc::new(c);
        let r = registry(&ctx);
        let t = ok(call(&r, "getblocktemplate", json!([{"rules": ["segwit"]}])));
        let lp = t["longpollid"].as_str().unwrap().to_string();
        // The mempool changes (here: a fee delta bumps nTransactionsUpdated).
        ctx.mempool.prioritise_transaction(&Txid::from_bytes([3; 32]), 1);
        let start = Instant::now();
        let t2 = ok(call(&r, "getblocktemplate", json!([{"rules": ["segwit"], "longpollid": lp}])));
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert_eq!(t2["previousblockhash"], t["previousblockhash"]);
    }

    #[test]
    fn test_proposal_mode() {
        let ctx = regtest_ctx();
        let r = registry(&ctx);
        let b = {
            let cs = ctx.chainstate.lock();
            BlockAssembler::new(&cs, None, BlockAssemblerOptions::default())
                .create_new_block(&Script::from_bytes(vec![0x51]))
                .unwrap()
                .block
        };
        let hex = hex_encode(&serialize(&b).unwrap());
        assert_eq!(
            ok(call(&r, "getblocktemplate", json!([{"mode": "proposal", "data": hex}]))),
            Value::Null,
            "unsolved template is a valid proposal (PoW is not checked)"
        );
        let mut bad = b.clone();
        bad.header.merkle_root = Default::default();
        let hex = hex_encode(&serialize(&bad).unwrap());
        assert_eq!(
            ok(call(&r, "getblocktemplate", json!([{"mode": "proposal", "data": hex}]))),
            json!("bad-txnmrklroot")
        );
        let mut stale = b.clone();
        stale.header.prev_blockhash = BlockHash::from_bytes([5; 32]);
        let hex = hex_encode(&serialize(&stale).unwrap());
        assert_eq!(
            ok(call(&r, "getblocktemplate", json!([{"mode": "proposal", "data": hex}]))),
            json!("inconclusive-not-best-prevblk")
        );
        assert_eq!(
            err_code(call(&r, "getblocktemplate", json!([{"mode": "proposal"}]))),
            RPC_TYPE_ERROR
        );
    }
}
