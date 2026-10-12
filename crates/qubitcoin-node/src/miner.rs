//! Block template assembly.
//!
//! Port of Bitcoin Core's `node/miner.cpp` / `node/miner.h`
//! (`BlockAssembler`, `UpdateTime`, `GetMinimumTime`,
//! `RegenerateCommitments`) plus `ChainstateManager::GenerateCoinbaseCommitment`
//! and `UpdateUncommittedBlockStructures` from `validation.cpp`.
//!
//! [`BlockAssembler::create_new_block`] selects mempool transactions by
//! ancestor feerate (Core's `addPackageTxs`, CPFP-aware), respecting the
//! block weight and sigop-cost limits, builds the coinbase (BIP34 height
//! push, subsidy plus fees) with the BIP141 witness commitment, and returns a
//! [`BlockTemplate`] carrying the per-transaction fees and sigop costs that
//! `getblocktemplate` reports.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;

use qubitcoin_common::versionbits::VersionBitsCache;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::check::{
    get_block_subsidy, get_legacy_sigop_count, get_transaction_sigop_cost, COINBASE_MATURITY,
    MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR,
};
use qubitcoin_consensus::merkle::{block_merkle_root, block_witness_merkle_root};
use qubitcoin_consensus::params::{ConsensusParams, MAX_TIMEWARP};
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_consensus::validation_state::BlockValidationState;
use qubitcoin_primitives::{Amount, Txid};
use qubitcoin_script::Script;

use crate::chainstate::ChainstateManager;
use crate::mempool::{FeeRate, TxMemPool, DEFAULT_MIN_RELAY_TX_FEE};

/// Default `-blockmaxweight`: the consensus maximum less 4000 WU reserved for
/// the coinbase. Port of Core's `DEFAULT_BLOCK_MAX_WEIGHT` (policy/policy.h).
pub const DEFAULT_BLOCK_MAX_WEIGHT: u64 = MAX_BLOCK_WEIGHT as u64 - 4000;

/// Default `-blockmintxfee`.
///
/// Core's `DEFAULT_BLOCK_MIN_TX_FEE` is 1000 sat/kvB, equal to its default
/// `-minrelaytxfee`. This node's relay floor ([`DEFAULT_MIN_RELAY_TX_FEE`])
/// is 0, so the mining floor follows it: a stricter mining floor would leave
/// zero-fee transactions that the mempool accepted stranded forever (and
/// change what `generatetoaddress` mines).
pub const DEFAULT_BLOCK_MIN_TX_FEE: FeeRate = DEFAULT_MIN_RELAY_TX_FEE;

/// Weight reserved for the coinbase when filling a block (Core's initial
/// `nBlockWeight = 4000` in `BlockAssembler::resetBlock`).
pub const COINBASE_RESERVED_WEIGHT: u64 = 4000;

/// Sigop cost reserved for the coinbase (Core's initial
/// `nBlockSigOpsCost = 400`).
pub const COINBASE_RESERVED_SIGOPS: i64 = 400;

/// Port of Core's `DEFAULT_BYTES_PER_SIGOP` (policy/policy.h): the sigop
/// cost to virtual-size exchange rate used by `GetVirtualTransactionSize`.
pub const DEFAULT_BYTES_PER_SIGOP: u64 = 20;

/// Give up filling the block after this many consecutive package failures
/// once it is nearly full. Port of `MAX_CONSECUTIVE_FAILURES` in
/// `BlockAssembler::addPackageTxs`.
const MAX_CONSECUTIVE_FAILURES: u32 = 1000;

/// Script verification flags that matter for sigop counting (P2SH and
/// WITNESS). Matches the `STANDARD_SCRIPT_VERIFY_FLAGS` subset Core passes to
/// `GetTransactionSigOpCost` when it builds mempool entries.
const SIGOP_COUNT_FLAGS: u32 = 0x1 | 0x800;

/// BIP141 witness commitment header (`OP_RETURN 0x24 0xaa21a9ed`).
pub const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Port of Core's `MINIMUM_WITNESS_COMMITMENT` (consensus/validation.h).
pub const MINIMUM_WITNESS_COMMITMENT: usize = 38;

/// Options for [`BlockAssembler`]. Port of `BlockAssembler::Options`.
#[derive(Debug, Clone)]
pub struct BlockAssemblerOptions {
    /// Maximum block weight to fill to (`-blockmaxweight`). Clamped to
    /// `[4000, MAX_BLOCK_WEIGHT - 4000]` as Core's `ClampOptions` does.
    pub block_max_weight: u64,
    /// Minimum package feerate for inclusion (`-blockmintxfee`).
    pub block_min_fee_rate: FeeRate,
    /// Run `TestBlockValidity` on the finished template (Core's
    /// `test_block_validity`, default true).
    pub test_block_validity: bool,
}

impl Default for BlockAssemblerOptions {
    fn default() -> Self {
        BlockAssemblerOptions {
            block_max_weight: DEFAULT_BLOCK_MAX_WEIGHT,
            block_min_fee_rate: DEFAULT_BLOCK_MIN_TX_FEE,
            test_block_validity: true,
        }
    }
}

impl BlockAssemblerOptions {
    /// Port of Core's `ClampOptions` (node/miner.cpp).
    fn clamped(&self) -> Self {
        let mut o = self.clone();
        o.block_max_weight = o
            .block_max_weight
            .clamp(COINBASE_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT as u64 - 4000);
        o
    }
}

/// A block template. Port of Core's `CBlockTemplate` (node/miner.h).
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// The candidate block. The header's nonce is 0; the merkle root is
    /// filled in for the coinbase as built.
    pub block: Block,
    /// Per-transaction fees, parallel to `block.vtx`. Entry 0 (the coinbase)
    /// is minus the total fees, as in Core's `vTxFees`.
    pub tx_fees: Vec<Amount>,
    /// Per-transaction sigop cost, parallel to `block.vtx` (`vTxSigOpsCost`).
    pub tx_sigops_cost: Vec<i64>,
    /// The witness commitment output script (`vchCoinbaseCommitment`), empty
    /// when segwit is not active.
    pub coinbase_commitment: Vec<u8>,
    /// Height of the block being built.
    pub height: i32,
    /// Sum of the (unmodified) fees of the included transactions.
    pub total_fees: Amount,
    /// Weight accounted for while filling (including the coinbase reserve).
    pub block_weight: u64,
    /// Sigop cost accounted for while filling (including the reserve).
    pub block_sigops_cost: i64,
}

/// Errors from [`BlockAssembler::create_new_block`].
#[derive(Debug, Clone)]
pub enum MinerError {
    /// The chain has no tip to build on.
    NoTip,
    /// `TestBlockValidity` rejected the assembled block.
    InvalidTemplate(BlockValidationState),
}

impl std::fmt::Display for MinerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinerError::NoTip => write!(f, "no chain tip"),
            MinerError::InvalidTemplate(state) => write!(
                f,
                "TestBlockValidity failed: {}",
                state.get_reject_reason()
            ),
        }
    }
}

impl std::error::Error for MinerError {}

/// Current wall-clock time in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Minimum timestamp for a block built on `prev_idx`.
///
/// Port of Core's `GetMinimumTime()` (node/miner.cpp): MTP + 1, and under
/// BIP94 the first block of a retarget period may not be more than
/// `MAX_TIMEWARP` seconds before its parent.
pub fn get_minimum_time(cs: &ChainstateManager, prev_idx: usize) -> i64 {
    let prev = cs.block_index().get(prev_idx);
    let mut min_time = cs.median_time_past(prev_idx) + 1;
    let params = cs.consensus();
    if params.enforce_bip94 {
        let interval = params.difficulty_adjustment_interval() as i32;
        if interval > 0 && (prev.height + 1) % interval == 0 {
            min_time = min_time.max(prev.get_block_time() - MAX_TIMEWARP);
        }
    }
    min_time
}

/// Bump `header.time` to `max(minimum time, now)` and, on networks with the
/// min-difficulty rule, recompute `nBits` for the new time. Returns the
/// number of seconds the time moved.
///
/// Port of Core's `UpdateTime()` (node/miner.cpp).
pub fn update_time(header: &mut BlockHeader, cs: &ChainstateManager, prev_idx: usize) -> i64 {
    let old_time = header.time as i64;
    let new_time = get_minimum_time(cs, prev_idx).max(now_secs());
    if old_time < new_time {
        header.time = new_time as u32;
    }
    if cs.consensus().pow_allow_min_difficulty_blocks {
        header.bits = cs.next_work_required(prev_idx, header.time);
    }
    new_time - old_time
}

/// Index of the coinbase output carrying the witness commitment, if any
/// (the last matching output wins).
///
/// Port of Core's `GetWitnessCommitmentIndex()` (consensus/validation.h).
pub fn get_witness_commitment_index(block: &Block) -> Option<usize> {
    let coinbase = block.vtx.first()?;
    coinbase.vout.iter().enumerate().rev().find_map(|(i, out)| {
        let spk = out.script_pubkey.as_bytes();
        if spk.len() >= MINIMUM_WITNESS_COMMITMENT && spk[..6] == WITNESS_COMMITMENT_HEADER {
            Some(i)
        } else {
            None
        }
    })
}

/// Whether segwit is active for a block at `height`.
fn segwit_active_at(params: &ConsensusParams, height: i32) -> bool {
    height >= params.segwit_height
}

/// Give a committed coinbase its 32-byte zero witness reserved value if it
/// has no witness yet. Returns true if the coinbase was changed.
///
/// Port of Core's `ChainstateManager::UpdateUncommittedBlockStructures()`.
pub fn update_uncommitted_block_structures(
    block: &mut Block,
    params: &ConsensusParams,
    height: i32,
) -> bool {
    if block.vtx.is_empty() || !segwit_active_at(params, height) {
        return false;
    }
    if get_witness_commitment_index(block).is_none() {
        return false;
    }
    let cb = &block.vtx[0];
    if cb.vin.is_empty() || !cb.vin[0].witness.stack.is_empty() {
        return false;
    }
    let mut vin = cb.vin.clone();
    vin[0].witness = Witness {
        stack: vec![vec![0u8; 32]],
    };
    let new_cb = Transaction::new(cb.version, vin, cb.vout.clone(), cb.lock_time);
    block.vtx[0] = Arc::new(new_cb);
    true
}

/// Add the BIP141 witness commitment output to the coinbase (unless one is
/// already present) and set the witness reserved value. Returns the
/// commitment output script, or an empty vector when segwit is inactive.
///
/// Port of Core's `ChainstateManager::GenerateCoinbaseCommitment()`.
pub fn generate_coinbase_commitment(
    block: &mut Block,
    params: &ConsensusParams,
    height: i32,
) -> Vec<u8> {
    if block.vtx.is_empty() || !segwit_active_at(params, height) {
        return Vec::new();
    }
    let commitment = match get_witness_commitment_index(block) {
        Some(pos) => block.vtx[0].vout[pos].script_pubkey.as_bytes().to_vec(),
        None => {
            let mut mutated = false;
            let witness_root = block_witness_merkle_root(&block.vtx, &mut mutated);
            // commitment = SHA256d(witness_root || witness_reserved_value),
            // with the reserved value all zeros.
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(witness_root.as_bytes());
            let hash = qubitcoin_crypto::hash::hash256(&preimage);
            let mut spk = Vec::with_capacity(MINIMUM_WITNESS_COMMITMENT);
            spk.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
            spk.extend_from_slice(&hash);

            let cb = &block.vtx[0];
            let mut vout = cb.vout.clone();
            vout.push(TxOut::new(Amount::ZERO, Script::from_bytes(spk.clone())));
            block.vtx[0] = Arc::new(Transaction::new(cb.version, cb.vin.clone(), vout, cb.lock_time));
            spk
        }
    };
    update_uncommitted_block_structures(block, params, height);
    commitment
}

/// Rebuild the witness commitment and merkle root after the coinbase or the
/// transaction list changed.
///
/// Port of Core's `RegenerateCommitments()` (node/miner.cpp).
pub fn regenerate_commitments(block: &mut Block, params: &ConsensusParams, height: i32) {
    if let Some(pos) = get_witness_commitment_index(block) {
        let cb = &block.vtx[0];
        let mut vout = cb.vout.clone();
        vout.remove(pos);
        block.vtx[0] = Arc::new(Transaction::new(cb.version, cb.vin.clone(), vout, cb.lock_time));
    }
    generate_coinbase_commitment(block, params, height);
    let mut mutated = false;
    block.header.merkle_root = block_merkle_root(&block.vtx, &mut mutated);
}

/// `IsFinalTx` (consensus/tx_verify.cpp).
fn is_final_tx(tx: &Transaction, block_height: i32, block_time: i64) -> bool {
    const LOCKTIME_THRESHOLD: i64 = 500_000_000;
    if tx.lock_time == 0 {
        return true;
    }
    let lock_time = tx.lock_time as i64;
    let cutoff = if lock_time < LOCKTIME_THRESHOLD {
        block_height as i64
    } else {
        block_time
    };
    if lock_time < cutoff {
        return true;
    }
    tx.vin.iter().all(|i| i.sequence == SEQUENCE_FINAL)
}

/// Sigop-adjusted virtual size. Port of Core's `GetVirtualTransactionSize(
/// weight, sigop_cost, bytes_per_sigop)` (policy/policy.cpp).
fn virtual_size(weight: u64, sigop_cost: i64) -> u64 {
    let w = weight.max(sigop_cost.max(0) as u64 * DEFAULT_BYTES_PER_SIGOP);
    (w + WITNESS_SCALE_FACTOR as u64 - 1) / WITNESS_SCALE_FACTOR as u64
}

/// Per-transaction data the package selection works on (the subset of
/// Core's `CTxMemPoolEntry` that `addPackageTxs` reads).
struct Candidate {
    tx: TransactionRef,
    txid: Txid,
    fee: Amount,
    modified_fee: i64,
    vsize: u64,
    weight: u64,
    sigops: i64,
    parents: Vec<usize>,
    children: Vec<usize>,
    /// Number of in-mempool ancestors including self (for `SortForBlock`).
    ancestor_count: usize,
}

/// Ancestor score of a candidate whose not-yet-included ancestor package
/// has `pkg_fee`/`pkg_size`. As Core's `CompareTxMemPoolEntryByAncestorFee`
/// it is the lower of the package feerate and the transaction's own.
#[derive(Clone, Copy)]
struct Score {
    fee: i64,
    size: u64,
}

impl Score {
    fn of(own_fee: i64, own_size: u64, pkg_fee: i64, pkg_size: u64) -> Score {
        // own/own_size > pkg/pkg_size  <=>  own*pkg_size > pkg*own_size
        if (own_fee as i128) * (pkg_size as i128) > (pkg_fee as i128) * (own_size as i128) {
            Score { fee: pkg_fee, size: pkg_size }
        } else {
            Score { fee: own_fee, size: own_size }
        }
    }

    fn cmp(&self, other: &Score) -> Ordering {
        let a = (self.fee as i128) * (other.size.max(1) as i128);
        let b = (other.fee as i128) * (self.size.max(1) as i128);
        a.cmp(&b)
    }
}

/// Heap item: highest score first, ties by smaller txid (Core's
/// `CompareIteratorByHash`).
struct HeapItem {
    score: Score,
    idx: usize,
    txid: Txid,
    generation: u32,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| other.txid.as_bytes().cmp(self.txid.as_bytes()))
    }
}

/// Builds block templates. Port of Core's `node::BlockAssembler`.
pub struct BlockAssembler<'a> {
    chainstate: &'a ChainstateManager,
    mempool: Option<&'a TxMemPool>,
    options: BlockAssemblerOptions,
}

impl<'a> BlockAssembler<'a> {
    /// Create an assembler over `chainstate` and (optionally) `mempool`.
    /// Without a mempool the template contains only the coinbase.
    pub fn new(
        chainstate: &'a ChainstateManager,
        mempool: Option<&'a TxMemPool>,
        options: BlockAssemblerOptions,
    ) -> Self {
        BlockAssembler {
            chainstate,
            mempool,
            options: options.clamped(),
        }
    }

    /// Build a new block template paying the subsidy plus fees to
    /// `script_pubkey`.
    ///
    /// Port of Core's `BlockAssembler::CreateNewBlock()`.
    pub fn create_new_block(&self, script_pubkey: &Script) -> Result<BlockTemplate, MinerError> {
        let cs = self.chainstate;
        let tip = cs.tip().ok_or(MinerError::NoTip)?;
        let prev = cs.block_index().get(tip);
        let height = prev.height + 1;
        let params = cs.consensus();

        let version = VersionBitsCache::new().compute_block_version(
            cs.block_index().as_slice(),
            Some(tip),
            params,
        );

        let header = BlockHeader {
            version,
            prev_blockhash: prev.block_hash,
            merkle_root: Default::default(),
            time: now_secs() as u32,
            bits: 0,
            nonce: 0,
        };
        // Core: pblock->nTime = now; then UpdateTime() below. Lock-time
        // finality is judged against the parent's MTP (BIP113).
        let lock_time_cutoff = cs.median_time_past(tip);

        let selected = match self.mempool {
            Some(pool) => self.add_package_txs(pool, height, lock_time_cutoff),
            None => Selection::default(),
        };

        // Coinbase: subsidy + fees, scriptSig = <height> OP_0.
        let subsidy = get_block_subsidy(height, params);
        let mut script_sig = Script::new();
        script_sig.push_int(height as i64);
        script_sig.push_int(0);
        let coinbase = Transaction::new(
            2,
            vec![TxIn {
                prevout: OutPoint::null(),
                script_sig,
                sequence: SEQUENCE_FINAL,
                witness: Witness::new(),
            }],
            vec![TxOut::new(subsidy + selected.fees, script_pubkey.clone())],
            0,
        );

        let mut vtx: Vec<TransactionRef> = Vec::with_capacity(selected.txs.len() + 1);
        vtx.push(Arc::new(coinbase));
        vtx.extend(selected.txs.iter().cloned());
        let mut block = Block { header, vtx };

        let commitment = generate_coinbase_commitment(&mut block, params, height);

        // Fill in header fields.
        update_time(&mut block.header, cs, tip);
        block.header.bits = cs.next_work_required(tip, block.header.time);
        block.header.nonce = 0;
        let mut mutated = false;
        block.header.merkle_root = block_merkle_root(&block.vtx, &mut mutated);

        let mut tx_fees = Vec::with_capacity(block.vtx.len());
        tx_fees.push(-selected.fees);
        tx_fees.extend(selected.tx_fees.iter().copied());
        let mut tx_sigops_cost = Vec::with_capacity(block.vtx.len());
        tx_sigops_cost.push(WITNESS_SCALE_FACTOR as i64 * get_legacy_sigop_count(&block.vtx[0]) as i64);
        tx_sigops_cost.extend(selected.tx_sigops.iter().copied());

        if self.options.test_block_validity {
            cs.test_block_validity(&block, false, false)
                .map_err(MinerError::InvalidTemplate)?;
        }

        tracing::debug!(
            height,
            txs = block.vtx.len() - 1,
            weight = selected.block_weight,
            sigops = selected.block_sigops,
            fees = selected.fees.to_sat(),
            "CreateNewBlock"
        );

        Ok(BlockTemplate {
            block,
            tx_fees,
            tx_sigops_cost,
            coinbase_commitment: commitment,
            height,
            total_fees: selected.fees,
            block_weight: selected.block_weight,
            block_sigops_cost: selected.block_sigops,
        })
    }

    /// Resolve the mempool into selection candidates.
    ///
    /// Core relies on the mempool being consistent with the tip. This
    /// node's mempool does not yet enforce every consensus rule at entry
    /// (coinbase maturity, missing inputs after a block arrives), so
    /// candidates whose inputs cannot be resolved, or that spend an
    /// immature coinbase, are dropped here together with their descendants
    /// rather than producing a template that fails `TestBlockValidity`.
    fn build_candidates(&self, pool: &TxMemPool, height: i32) -> Vec<Candidate> {
        let cs = self.chainstate;
        let coins = cs.coins_tip();
        let entries = pool.entries_snapshot();
        let index_of: HashMap<Txid, usize> =
            entries.iter().enumerate().map(|(i, e)| (e.txid(), i)).collect();

        // Resolve inputs and compute sigops; mark unresolvable entries.
        let n = entries.len();
        let mut ok = vec![true; n];
        let mut parents: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut sigops = vec![0i64; n];
        for (i, e) in entries.iter().enumerate() {
            let tx = e.tx();
            let mut spks: HashMap<OutPoint, Script> = HashMap::new();
            for input in &tx.vin {
                if let Some(&p) = index_of.get(&input.prevout.hash) {
                    match entries[p].tx().vout.get(input.prevout.n as usize) {
                        Some(out) => {
                            if !parents[i].contains(&p) {
                                parents[i].push(p);
                            }
                            spks.insert(input.prevout.clone(), out.script_pubkey.clone());
                        }
                        None => ok[i] = false,
                    }
                } else {
                    match qubitcoin_common::coins::CoinsView::get_coin(coins, &input.prevout) {
                        Some(coin) => {
                            if coin.coinbase && height - (coin.height as i32) < COINBASE_MATURITY {
                                ok[i] = false;
                            }
                            spks.insert(input.prevout.clone(), coin.tx_out.script_pubkey.clone());
                        }
                        None => ok[i] = false,
                    }
                }
            }
            sigops[i] = get_transaction_sigop_cost(tx, SIGOP_COUNT_FLAGS, |op| spks.get(op).cloned());
        }

        // Propagate "not ok" to descendants (a child of a dropped parent
        // cannot be mined either).
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ps) in parents.iter().enumerate() {
            for &p in ps {
                children[p].push(i);
            }
        }
        let mut stack: Vec<usize> = (0..n).filter(|&i| !ok[i]).collect();
        while let Some(i) = stack.pop() {
            for &c in &children[i] {
                if ok[c] {
                    ok[c] = false;
                    stack.push(c);
                }
            }
        }

        // Compact into candidates.
        let mut remap = vec![usize::MAX; n];
        let mut out = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            if !ok[i] {
                continue;
            }
            remap[i] = out.len();
            let weight = e.tx().get_weight() as u64;
            let txid = e.txid();
            out.push(Candidate {
                tx: e.tx().clone(),
                txid,
                fee: e.fee(),
                modified_fee: e.fee().to_sat() + pool.get_fee_delta(&txid),
                vsize: virtual_size(weight, sigops[i]),
                weight,
                sigops: sigops[i],
                parents: Vec::new(),
                children: Vec::new(),
                ancestor_count: 0,
            });
        }
        for (i, ps) in parents.iter().enumerate() {
            if remap[i] == usize::MAX {
                continue;
            }
            let ci = remap[i];
            for &p in ps {
                let cp = remap[p];
                debug_assert!(cp != usize::MAX);
                out[ci].parents.push(cp);
                out[cp].children.push(ci);
            }
        }
        for i in 0..out.len() {
            let count = ancestors_of(&out, i, |_| false).len();
            out[i].ancestor_count = count;
        }
        out
    }

    /// Select transactions by ancestor feerate.
    ///
    /// Port of Core's `BlockAssembler::addPackageTxs()`, with Core's
    /// `mapModifiedTx` (ancestor state reduced by already-included
    /// ancestors) represented by re-pushing a descendant into the heap with
    /// its updated score whenever one of its ancestors is included.
    fn add_package_txs(&self, pool: &TxMemPool, height: i32, lock_time_cutoff: i64) -> Selection {
        let cands = self.build_candidates(pool, height);
        let n = cands.len();
        let mut sel = Selection {
            block_weight: COINBASE_RESERVED_WEIGHT,
            block_sigops: COINBASE_RESERVED_SIGOPS,
            ..Default::default()
        };
        let mut in_block = vec![false; n];
        let mut failed = vec![false; n];
        let mut generation = vec![0u32; n];

        let pkg_state = |i: usize, in_block: &[bool]| -> (Vec<usize>, i64, u64, i64) {
            let anc = ancestors_of(&cands, i, |j| in_block[j]);
            let fee = anc.iter().map(|&j| cands[j].modified_fee).sum();
            let size = anc.iter().map(|&j| cands[j].vsize).sum();
            let sig = anc.iter().map(|&j| cands[j].sigops).sum();
            (anc, fee, size, sig)
        };

        let mut heap = BinaryHeap::with_capacity(n);
        for i in 0..n {
            let (_, fee, size, _) = pkg_state(i, &in_block);
            heap.push(HeapItem {
                score: Score::of(cands[i].modified_fee, cands[i].vsize, fee, size),
                idx: i,
                txid: cands[i].txid,
                generation: 0,
            });
        }

        let max_weight = self.options.block_max_weight;
        let mut consecutive_failed = 0u32;
        while let Some(item) = heap.pop() {
            let i = item.idx;
            if in_block[i] || failed[i] || item.generation != generation[i] {
                continue;
            }
            let (mut package, pkg_fee, pkg_size, pkg_sigops) = pkg_state(i, &in_block);

            // Everything else we might consider has a lower feerate.
            if pkg_fee < self.options.block_min_fee_rate.get_fee(pkg_size as usize).to_sat() {
                break;
            }

            // TestPackage: weight and sigop limits.
            let fits = sel.block_weight + WITNESS_SCALE_FACTOR as u64 * pkg_size < max_weight
                && sel.block_sigops + pkg_sigops < MAX_BLOCK_SIGOPS_COST as i64;
            // TestPackageTransactions: finality.
            let final_ok = fits
                && package
                    .iter()
                    .all(|&j| is_final_tx(&cands[j].tx, height, lock_time_cutoff));
            if !final_ok {
                failed[i] = true;
                consecutive_failed += 1;
                if consecutive_failed > MAX_CONSECUTIVE_FAILURES
                    && sel.block_weight > max_weight.saturating_sub(4000)
                {
                    // Give up if we're close to full and haven't succeeded in a while.
                    break;
                }
                continue;
            }
            consecutive_failed = 0;

            // SortForBlock: ancestor count, then txid.
            package.sort_by(|&a, &b| {
                cands[a]
                    .ancestor_count
                    .cmp(&cands[b].ancestor_count)
                    .then_with(|| cands[a].txid.as_bytes().cmp(cands[b].txid.as_bytes()))
            });
            for &j in &package {
                in_block[j] = true;
                let c = &cands[j];
                sel.txs.push(c.tx.clone());
                sel.tx_fees.push(c.fee);
                sel.tx_sigops.push(c.sigops);
                sel.block_weight += c.weight;
                sel.block_sigops += c.sigops;
                sel.fees += c.fee;
            }

            // UpdatePackagesForAdded: re-score every not-yet-included
            // descendant of the package.
            let mut seen: HashSet<usize> = HashSet::new();
            let mut stack: Vec<usize> = package.iter().flat_map(|&j| cands[j].children.clone()).collect();
            while let Some(d) = stack.pop() {
                if in_block[d] || !seen.insert(d) {
                    continue;
                }
                stack.extend(cands[d].children.iter().copied());
                if failed[d] {
                    continue;
                }
                generation[d] += 1;
                let (_, fee, size, _) = pkg_state(d, &in_block);
                heap.push(HeapItem {
                    score: Score::of(cands[d].modified_fee, cands[d].vsize, fee, size),
                    idx: d,
                    txid: cands[d].txid,
                    generation: generation[d],
                });
            }
        }
        sel
    }
}

/// Indices of `i` and its in-mempool ancestors, skipping those for which
/// `skip` returns true (already in the block).
fn ancestors_of(cands: &[Candidate], i: usize, skip: impl Fn(usize) -> bool) -> Vec<usize> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![i];
    while let Some(j) = stack.pop() {
        if skip(j) || !seen.insert(j) {
            continue;
        }
        out.push(j);
        stack.extend(cands[j].parents.iter().copied());
    }
    out
}

/// Output of package selection.
#[derive(Default)]
struct Selection {
    txs: Vec<TransactionRef>,
    tx_fees: Vec<Amount>,
    tx_sigops: Vec<i64>,
    fees: Amount,
    block_weight: u64,
    block_sigops: i64,
}

/// Difficulty for a compact target, relative to the minimum difficulty
/// (`0x1d00ffff`).
///
/// Port of Core's `GetDifficulty()` (rpc/blockchain.cpp).
pub fn get_difficulty(bits: u32) -> f64 {
    let mut shift = (bits >> 24) & 0xff;
    let mut diff = 0x0000ffff as f64 / (bits & 0x00ff_ffff).max(1) as f64;
    while shift < 29 {
        diff *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        diff /= 256.0;
        shift -= 1;
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_difficulty_genesis_bits() {
        assert!((get_difficulty(0x1d00ffff) - 1.0).abs() < 1e-12);
        // Regtest pow limit.
        assert!(get_difficulty(0x207fffff) < 1e-9);
    }

    #[test]
    fn test_virtual_size_sigop_adjusted() {
        assert_eq!(virtual_size(400, 0), 100);
        assert_eq!(virtual_size(401, 0), 101);
        // 100 sigops * 20 bytes = 2000 > 400 weight.
        assert_eq!(virtual_size(400, 100), 500);
    }

    #[test]
    fn test_is_final_tx() {
        let mk = |lock_time, seq| {
            Transaction::new(
                2,
                vec![TxIn::new(OutPoint::new(Txid::from_bytes([1; 32]), 0), Script::new(), seq)],
                vec![],
                lock_time,
            )
        };
        assert!(is_final_tx(&mk(0, 0), 10, 0));
        assert!(is_final_tx(&mk(9, 0), 10, 0));
        assert!(!is_final_tx(&mk(10, 0), 10, 0));
        assert!(is_final_tx(&mk(10, SEQUENCE_FINAL), 10, 0));
        assert!(!is_final_tx(&mk(600_000_000, 0), 10, 599_999_999));
        assert!(is_final_tx(&mk(600_000_000, 0), 10, 600_000_001));
    }

    #[test]
    fn test_score_prefers_lower_of_own_and_package() {
        // Parent pays 0, child pays 1000 over 100 vB: package rate 1000/200.
        let s = Score::of(1000, 100, 1000, 200);
        assert_eq!((s.fee, s.size), (1000, 200));
        // High-fee parent with a low-fee child: the child's own rate wins.
        let s = Score::of(10, 100, 5010, 200);
        assert_eq!((s.fee, s.size), (10, 100));
    }

    #[test]
    fn test_witness_commitment_roundtrip() {
        let params = ConsensusParams::regtest();
        let cb = Transaction::new(
            2,
            vec![TxIn::new(OutPoint::null(), Script::from_bytes(vec![0x51, 0x00]), SEQUENCE_FINAL)],
            vec![TxOut::new(Amount::from_sat(50), Script::from_bytes(vec![0x51]))],
            0,
        );
        let mut block = Block {
            header: BlockHeader::new(),
            vtx: vec![Arc::new(cb)],
        };
        let c = generate_coinbase_commitment(&mut block, &params, 1);
        assert_eq!(c.len(), MINIMUM_WITNESS_COMMITMENT);
        assert_eq!(c[..6], WITNESS_COMMITMENT_HEADER);
        assert_eq!(get_witness_commitment_index(&block), Some(1));
        assert_eq!(block.vtx[0].vin[0].witness.stack, vec![vec![0u8; 32]]);
        // Idempotent: a second call keeps the single commitment.
        let c2 = generate_coinbase_commitment(&mut block, &params, 1);
        assert_eq!(c, c2);
        assert_eq!(block.vtx[0].vout.len(), 2);
    }
}
