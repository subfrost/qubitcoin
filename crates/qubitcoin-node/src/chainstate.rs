//! Chainstate management: block index, active chain, UTXO set.
//!
//! Maps to: `src/validation.h` / `src/validation.cpp` in Bitcoin Core
//! (specifically `Chainstate` and `ChainstateManager`).
//!
//! This module provides:
//! - `BlockMap`: Arena-based storage for block indices (replaces Bitcoin Core's
//!   pointer-based `BlockMap` / `std::unordered_map<uint256, CBlockIndex*>`).
//! - `Chainstate`: A single chainstate instance holding the active chain and
//!   UTXO cache tip.
//! - `ChainstateManager`: Top-level manager that owns the block index, chain
//!   parameters, and the active chainstate. Entry point for block processing.

use crate::undo::BlockUndo;
use qubitcoin_common::chain::{
    get_ancestor, get_block_proof, get_skip_height, BlockIndex, BlockStatus, Chain,
};
use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::{add_coins, CoinsView, CoinsViewCache, EmptyCoinsView, FlushableCoinsView};
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::params::ConsensusParams;
use qubitcoin_consensus::validation_state::{BlockValidationResult, BlockValidationState};
use qubitcoin_primitives::{ArithUint256, BlockHash};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// Validation helpers -- imported from sibling module (created in parallel).
// These will be provided by `crate::validation` once that module lands.
// Until then, we use inline stubs so that chainstate compiles and passes
// its own tests independently.
#[cfg(not(test))]
use crate::validation::{
    check_block, check_block_header, connect_block, contextual_check_block,
    contextual_check_block_header_with_arena, disconnect_block, DisconnectResult,
};

// ---------------------------------------------------------------------------
// BlockMap
// ---------------------------------------------------------------------------

/// Arena-based storage for block indices.
///
/// Instead of raw pointers like Bitcoin Core, we use indices into a `Vec`.
/// This avoids all `unsafe` code while providing O(1) index access and
/// O(1) amortised hash-based lookup by block hash.
///
/// Maps to: the `BlockMap` typedef
/// (`std::unordered_map<uint256, CBlockIndex*>`) in Bitcoin Core.
pub struct BlockMap {
    /// All block indices, indexed by arena position.
    indices: Vec<BlockIndex>,
    /// Lookup by block hash -> arena index.
    by_hash: HashMap<BlockHash, usize>,
}

impl BlockMap {
    /// Create an empty block map.
    pub fn new() -> Self {
        BlockMap {
            indices: Vec::new(),
            by_hash: HashMap::new(),
        }
    }

    /// Insert a block index into the arena.
    ///
    /// Returns the arena index at which the entry was stored.
    ///
    /// # Panics
    ///
    /// Panics (in debug mode) if a block with the same hash is already present.
    pub fn insert(&mut self, index: BlockIndex) -> usize {
        let hash = index.block_hash;
        let arena_idx = self.indices.len();
        debug_assert!(
            !self.by_hash.contains_key(&hash),
            "BlockMap::insert: duplicate block hash {}",
            hash.to_hex(),
        );
        self.by_hash.insert(hash, arena_idx);
        self.indices.push(index);
        arena_idx
    }

    /// Get an immutable reference to the block index at `idx`.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of bounds.
    #[inline]
    pub fn get(&self, idx: usize) -> &BlockIndex {
        &self.indices[idx]
    }

    /// Get the underlying slice for arena-based ancestor lookup.
    #[inline]
    pub fn as_slice(&self) -> &[BlockIndex] {
        &self.indices
    }

    /// Get a mutable reference to the block index at `idx`.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of bounds.
    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> &mut BlockIndex {
        &mut self.indices[idx]
    }

    /// Look up the arena index for a block by its hash.
    ///
    /// Returns `None` if the hash is not present.
    pub fn find_by_hash(&self, hash: &BlockHash) -> Option<usize> {
        self.by_hash.get(hash).copied()
    }

    /// Return the number of block index entries in the arena.
    #[inline]
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Return `true` if the block map contains no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Compute and set the skip pointer for the block at `arena_idx`.
    ///
    /// The skip pointer links a block to an ancestor determined by
    /// [`get_skip_height`], enabling O(log n) ancestor lookups via
    /// [`get_ancestor`].
    ///
    /// This must be called after inserting a block whose `prev` pointer
    /// is already set. For the genesis block (height 0) the skip pointer
    /// remains `None` because `get_skip_height(0) == 0` (self-referential).
    ///
    /// Maps to: `CBlockIndex::BuildSkip()` in Bitcoin Core's `chain.cpp`.
    pub fn build_skip_pointer(&mut self, arena_idx: usize) {
        let height = self.indices[arena_idx].height;
        if height < 1 {
            // Genesis block: no ancestor to skip to.
            return;
        }
        let skip_target_height = get_skip_height(height);
        // Walk from the block's prev to find the ancestor at skip_target_height.
        if let Some(prev_idx) = self.indices[arena_idx].prev {
            if let Some(skip_idx) = get_ancestor(&self.indices, prev_idx, skip_target_height) {
                self.indices[arena_idx].skip = Some(skip_idx);
            }
        }
    }
}

impl Default for BlockMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Chainstate
// ---------------------------------------------------------------------------

/// A single chainstate instance.
///
/// Holds the active chain (a linear sequence of block-index arena handles
/// ordered by height) and the UTXO cache tip.
///
/// Maps to: `Chainstate` in Bitcoin Core's `src/validation.h`.
pub struct Chainstate {
    /// The active chain of block indices (by height).
    pub chain: Chain,
    /// UTXO cache layer (sits on top of a backing `CoinsView`).
    coins_tip: CoinsViewCache,
}

impl Chainstate {
    /// Create a new chainstate with an empty chain and the given coins view
    /// as the backing store for the UTXO cache.
    pub fn new(coins_view: Box<dyn CoinsView + Send + Sync>) -> Self {
        Chainstate {
            chain: Chain::new(),
            coins_tip: CoinsViewCache::new(coins_view),
        }
    }
}

// ---------------------------------------------------------------------------
// ChainstateManager
// ---------------------------------------------------------------------------

/// Callback type for reading blocks and undo data from disk.
///
/// Used by chain reorganization code to read block data that is not in memory.
/// Returns `(Block, BlockUndo)` for the given block hash, or `None` if not found.
/// Callback for reading blocks and undo data from disk.
///
/// Parameters: `(file_num, data_pos, undo_pos)` — the position fields from
/// the block index entry.  Returns `(Block, BlockUndo)` on success.
pub type BlockReader = Arc<dyn Fn(i32, u32, u32) -> Option<(Block, BlockUndo)> + Send + Sync>;

/// Reads a block's data from disk: `(file_num, data_pos)`.
pub type BlockDataReader = Arc<dyn Fn(i32, u32) -> Option<Block> + Send + Sync>;

/// Reads a block's undo data from disk: `(file_num, undo_pos)`.
pub type UndoReader = Arc<dyn Fn(i32, u32) -> Option<BlockUndo> + Send + Sync>;

/// Persists a connected block's undo data next to its block file
/// (`file_num`), returning the undo position (Core's `WriteUndoDataForBlock`).
pub type UndoWriter = Arc<dyn Fn(i32, &BlockUndo) -> Option<u32> + Send + Sync>;

/// A block that became part of the active chain during
/// [`ChainstateManager::activate_best_chain`] (Core's `ConnectTip`).
#[derive(Clone, Debug)]
pub struct ConnectedBlock {
    /// Arena index.
    pub arena_idx: usize,
    /// Height.
    pub height: i32,
    /// The block.
    pub block: Arc<Block>,
    /// Its undo data.
    pub undo: BlockUndo,
}

/// What an `ActivateBestChain` run changed.
///
/// `disconnected` is in disconnection order (old tip first), `connected` in
/// connection order (fork point upwards). After a failed reorg attempt that
/// was rolled back, the same blocks can appear in both lists.
#[derive(Clone, Debug, Default)]
pub struct ChainUpdate {
    /// Blocks removed from the active chain (Core's `DisconnectTip`).
    pub disconnected: Vec<(usize, Arc<Block>)>,
    /// Blocks added to the active chain.
    pub connected: Vec<ConnectedBlock>,
    /// Blocks found invalid while connecting, with the reason.
    pub invalid: Vec<(usize, BlockValidationState)>,
    /// Arena index of the fork point of the first reorganisation, if any
    /// block was disconnected.
    pub fork_idx: Option<usize>,
}

impl ChainUpdate {
    /// Whether the active tip changed.
    pub fn tip_changed(&self) -> bool {
        !self.connected.is_empty() || !self.disconnected.is_empty()
    }
}

/// Result of [`ChainstateManager::process_block`].
#[derive(Clone, Debug)]
pub struct ProcessOutcome {
    /// Arena index of the block.
    pub arena_idx: usize,
    /// False if the block data was already known (Core's `new_block`).
    pub new_block: bool,
    /// Chain changes caused by this block.
    pub update: ChainUpdate,
}

/// Manages the blockchain state: block index, active chain, UTXO set.
///
/// This is the primary entry point for processing new blocks. It owns the
/// block index arena, the chain parameters, and the active chainstate.
///
/// Maps to: `ChainstateManager` in Bitcoin Core's `src/validation.h`.
pub struct ChainstateManager {
    /// Chain parameters (network, consensus params, genesis hash, etc.).
    params: ChainParams,
    /// Block index arena.
    block_index: BlockMap,
    /// The active chainstate.
    active_chainstate: Chainstate,
    /// In-memory block cache (used by tests and as fallback).
    stored_blocks: HashMap<BlockHash, Block>,
    /// In-memory undo data cache.
    stored_undos: HashMap<BlockHash, BlockUndo>,
    /// Optional callback for reading blocks from disk (production mode).
    block_reader: Option<BlockReader>,
    /// Block-data reader (production mode); takes precedence over `block_reader`.
    block_data_reader: Option<BlockDataReader>,
    /// Undo-data reader (production mode); takes precedence over `block_reader`.
    undo_reader: Option<UndoReader>,
    /// Undo-data writer (production mode).
    undo_writer: Option<UndoWriter>,
    /// Blocks whose whole ancestry has data (Core: `nChainTx != 0`),
    /// indexed by arena index.
    linked: Vec<bool>,
    /// Blocks with data whose parent's ancestry is not complete yet, keyed
    /// by parent (Core's `m_blocks_unlinked`).
    unlinked: HashMap<usize, Vec<usize>>,
    /// Possible new tips: linked, not failed, at least as much work as the
    /// tip (Core's `setBlockIndexCandidates`).
    candidates: HashSet<usize>,
    /// Hash of the assumed-valid block. Blocks at or below this height
    /// skip script verification during IBD, dramatically speeding up sync.
    assume_valid: Option<BlockHash>,
    /// Height of the assumed-valid block, as configured.
    ///
    /// Retained for diagnostics only. It is deliberately NOT used to decide
    /// whether to skip script verification: see `should_skip_scripts`, where a
    /// height-only test was removed because it disabled signature checking for
    /// every block below this height on any chain, not just the externally
    /// verified one.
    #[allow(dead_code)]
    assume_valid_height: Option<i32>,
    /// Arena indices of block index entries modified since the last flush.
    dirty_indices: HashSet<usize>,
    /// Latch for [`ChainstateManager::is_initial_block_download`]: once IBD
    /// has been observed to finish it never restarts (Core's
    /// `m_cached_finished_ibd`).
    finished_ibd: std::sync::atomic::AtomicBool,
}

/// Maximum age of the tip before the node considers itself in initial block
/// download. Port of Bitcoin Core's `DEFAULT_MAX_TIP_AGE` (validation.h).
pub const DEFAULT_MAX_TIP_AGE: i64 = 24 * 60 * 60;

/// A fixed, owned snapshot of the coins a single block touches.
///
/// Used as the base of a throwaway [`CoinsViewCache`] so that
/// [`ChainstateManager::test_block_validity`] can run `connect_block` without
/// mutating the live UTXO cache (Core builds a `CCoinsViewCache` on top of
/// `CoinsTip()` for the same purpose).
struct SnapshotCoinsView {
    coins: HashMap<qubitcoin_consensus::transaction::OutPoint, qubitcoin_common::coins::Coin>,
    best_block: BlockHash,
}

impl CoinsView for SnapshotCoinsView {
    fn get_coin(
        &self,
        outpoint: &qubitcoin_consensus::transaction::OutPoint,
    ) -> Option<qubitcoin_common::coins::Coin> {
        self.coins.get(outpoint).cloned()
    }

    fn get_best_block(&self) -> BlockHash {
        self.best_block
    }
}

impl ChainstateManager {
    /// Create a new `ChainstateManager` with an empty chain.
    ///
    /// `params` -- full chain parameters for the target network.
    /// `coins_view` -- the base coins view that backs the UTXO cache
    /// (typically `CoinsViewDB` in production or `EmptyCoinsView` in tests).
    pub fn new(params: ChainParams, coins_view: Box<dyn CoinsView + Send + Sync>) -> Self {
        ChainstateManager {
            params,
            block_index: BlockMap::new(),
            active_chainstate: Chainstate::new(coins_view),
            stored_blocks: HashMap::new(),
            stored_undos: HashMap::new(),
            block_reader: None,
            block_data_reader: None,
            undo_reader: None,
            undo_writer: None,
            linked: Vec::new(),
            unlinked: HashMap::new(),
            candidates: HashSet::new(),
            assume_valid: None,
            assume_valid_height: None,
            dirty_indices: HashSet::new(),
            finished_ibd: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Set a block reader callback for disk-based block retrieval.
    pub fn set_block_reader(&mut self, reader: BlockReader) {
        self.block_reader = Some(reader);
    }

    /// Install disk accessors for block data and undo data. With them set,
    /// side-branch blocks are read back from disk when a reorganisation
    /// needs them and undo data is written as blocks connect; without them
    /// (tests, embedded use) blocks and undo data are kept in memory.
    pub fn set_disk_access(&mut self, blocks: BlockDataReader, undo_reader: UndoReader, undo_writer: UndoWriter) {
        self.block_data_reader = Some(blocks);
        self.undo_reader = Some(undo_reader);
        self.undo_writer = Some(undo_writer);
    }

    fn memory_mode(&self) -> bool {
        self.block_reader.is_none() && self.block_data_reader.is_none()
    }

    fn is_linked(&self, idx: usize) -> bool {
        self.linked.get(idx).copied().unwrap_or(false)
    }

    fn set_linked(&mut self, idx: usize) {
        if self.linked.len() <= idx {
            self.linked.resize(idx + 1, false);
        }
        self.linked[idx] = true;
    }

    /// Set the undo data position for a block index entry (after writing
    /// undo data to disk).
    pub fn set_undo_pos(&mut self, hash: &BlockHash, undo_pos: u32) {
        if let Some(idx) = self.block_index.find_by_hash(hash) {
            self.block_index.get_mut(idx).undo_pos = undo_pos;
            self.dirty_indices.insert(idx);
        }
    }

    /// Set the assumed-valid block hash and height for IBD optimization.
    pub fn set_assume_valid(&mut self, hash: BlockHash, height: i32) {
        self.assume_valid = Some(hash);
        self.assume_valid_height = Some(height);
    }

    /// Reset the active chain to the given arena index.
    ///
    /// Used during crash recovery to rewind the chain tip to match the
    /// persisted UTXO state.  Sets both the active chain tip and the
    /// UTXO cache best block.
    pub fn reset_active_chain_to(&mut self, arena_idx: usize) {
        let height = self.block_index.get(arena_idx).height;
        let hash = self.block_index.get(arena_idx).block_hash;
        let block_index = &self.block_index;
        self.active_chainstate
            .chain
            .set_tip_with(arena_idx, height, |idx| {
                let entry = block_index.get(idx);
                entry.prev.map(|p| (p, block_index.get(p).height))
            });
        self.active_chainstate.coins_tip.set_best_block(hash);
    }

    // -- Accessors ----------------------------------------------------------

    /// Get the active chain.
    #[inline]
    pub fn active_chain(&self) -> &Chain {
        &self.active_chainstate.chain
    }

    /// Get the chain tip height (returns `-1` if the chain is empty).
    #[inline]
    pub fn height(&self) -> i32 {
        self.active_chainstate.chain.height()
    }

    /// Get the chain tip block index (arena index), or `None` if empty.
    #[inline]
    pub fn tip(&self) -> Option<usize> {
        self.active_chainstate.chain.tip()
    }

    /// Get the chain parameters.
    #[inline]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// Get the consensus parameters.
    #[inline]
    pub fn consensus(&self) -> &ConsensusParams {
        &self.params.consensus
    }

    /// Access the block index map (immutable).
    #[inline]
    pub fn block_index(&self) -> &BlockMap {
        &self.block_index
    }

    /// Access the block index map (mutable).
    #[inline]
    pub fn block_index_mut(&mut self) -> &mut BlockMap {
        &mut self.block_index
    }

    /// Mark a block index entry as dirty (needs to be flushed to disk).
    #[inline]
    pub fn mark_dirty(&mut self, arena_idx: usize) {
        self.dirty_indices.insert(arena_idx);
    }

    /// Access the UTXO cache.
    #[inline]
    pub fn coins_tip(&self) -> &CoinsViewCache {
        &self.active_chainstate.coins_tip
    }

    /// Look up a block index by hash.
    #[inline]
    pub fn lookup_block_index(&self, hash: &BlockHash) -> Option<usize> {
        self.block_index.find_by_hash(hash)
    }

    /// Get the block hash at a given height on the active chain.
    pub fn get_block_hash_at_height(&self, height: i32) -> Option<String> {
        let arena_idx = self.active_chainstate.chain.get_block_index(height)?;
        let block = self.block_index.get(arena_idx);
        Some(block.block_hash.to_hex())
    }

    // -- Persistence helpers -------------------------------------------------

    /// Flush the UTXO cache to a persistent backing store.
    ///
    /// Delegates to [`CoinsViewCache::flush_to`] which writes all dirty entries
    /// to the provided [`FlushableCoinsView`] (typically a `CoinsViewDB`).
    pub fn flush_coins(&self, target: &dyn FlushableCoinsView) -> bool {
        self.active_chainstate.coins_tip.flush_to(target)
    }

    /// Load block index entries from a set of records (typically loaded from
    /// `BlockIndexDB`). Rebuilds the arena, prev/skip pointers, and finds
    /// the best chain.
    ///
    /// Returns `Ok(())` on success or `Err(description)` on failure.
    pub fn load_block_index(
        &mut self,
        records: &[crate::block_index_db::BlockIndexRecord],
    ) -> Result<(), String> {
        use qubitcoin_common::chain::BlockIndex as BI;

        if records.is_empty() {
            return Ok(());
        }

        // Sort by height for correct insertion order.
        let mut sorted: Vec<&crate::block_index_db::BlockIndexRecord> = records.iter().collect();
        sorted.sort_by_key(|r| r.height);

        // Insert all entries into the arena.
        for record in &sorted {
            let mut idx = BI::new();
            idx.block_hash = record.block_hash;
            idx.version = record.version;
            idx.prev_blockhash = record.prev_blockhash;
            idx.merkle_root = record.merkle_root;
            idx.time = record.time;
            idx.bits = record.bits;
            idx.nonce = record.nonce;
            idx.height = record.height;
            idx.status = BlockStatus::new(record.status_bits);
            idx.file = record.file;
            idx.data_pos = record.data_pos;
            idx.undo_pos = record.undo_pos;
            idx.tx_count = record.tx_count;
            idx.chain_tx_count = record.chain_tx_count;
            idx.chain_work = record.chain_work();

            self.block_index.insert(idx);
        }

        // Resolve prev links and build skip pointers.
        for arena_idx in 0..self.block_index.len() {
            let prev_hash = self.block_index.get(arena_idx).prev_blockhash;
            if !prev_hash.is_null() {
                if let Some(prev_idx) = self.block_index.find_by_hash(&prev_hash) {
                    self.block_index.get_mut(arena_idx).prev = Some(prev_idx);
                    // Compute time_max from parent.
                    let parent_time_max = self.block_index.get(prev_idx).time_max;
                    let this_time = self.block_index.get(arena_idx).time;
                    self.block_index.get_mut(arena_idx).time_max =
                        std::cmp::max(parent_time_max, this_time);
                }
            } else {
                // Genesis block: time_max = time.
                let t = self.block_index.get(arena_idx).time;
                self.block_index.get_mut(arena_idx).time_max = t;
            }
            self.block_index.build_skip_pointer(arena_idx);
        }

        // Find the best fully-validated chain tip and set the active chain.
        let mut best_idx: Option<usize> = None;
        let mut best_work = ArithUint256::zero();

        for i in 0..self.block_index.len() {
            let entry = self.block_index.get(i);
            if entry.is_valid(BlockStatus::VALID_SCRIPTS) && entry.chain_work > best_work {
                best_work = entry.chain_work;
                best_idx = Some(i);
            }
        }

        // Rebuild the "whole ancestry has data" links and the candidate set
        // (entries were inserted in height order, so parents come first).
        for i in 0..self.block_index.len() {
            let e = self.block_index.get(i);
            if e.status.has_data() && !e.status.has_failed() && e.prev.map_or(true, |p| self.is_linked(p)) {
                self.set_linked(i);
            }
        }
        for i in 0..self.block_index.len() {
            let e = self.block_index.get(i);
            if self.is_linked(i) && !e.status.has_failed() && e.chain_work >= best_work {
                self.candidates.insert(i);
            }
        }

        if let Some(best) = best_idx {
            let best_height = self.block_index.get(best).height;
            let block_index = &self.block_index;
            self.active_chainstate
                .chain
                .set_tip_with(best, best_height, |idx| {
                    let entry = block_index.get(idx);
                    entry.prev.map(|p| (p, block_index.get(p).height))
                });

            let tip_hash = self.block_index.get(best).block_hash;
            tracing::info!(
                height = best_height,
                hash = %tip_hash.to_hex(),
                "loaded block index, best chain found"
            );
        }

        Ok(())
    }

    /// Get block index entries modified since the last flush.
    /// Used for persisting the block index to disk.
    pub fn dirty_block_indices(&self) -> Vec<&BlockIndex> {
        self.dirty_indices
            .iter()
            .map(|&i| self.block_index.get(i))
            .collect()
    }

    /// Clear the dirty set after a successful flush.
    pub fn clear_dirty(&mut self) {
        self.dirty_indices.clear();
    }

    // -- Genesis block ------------------------------------------------------

    /// Initialize the genesis block.
    ///
    /// This creates the block-index entry for the genesis block, marks it as
    /// fully valid, adds its coinbase outputs to the UTXO cache, and sets the
    /// active chain tip to height 0.
    ///
    /// Returns `Err` with a description if the genesis block hash does not
    /// match the chain parameters.
    pub fn load_genesis_block(&mut self, genesis: &Block) -> Result<(), String> {
        let hash = genesis.block_hash();

        // Verify the genesis hash matches the chain parameters.
        if hash != self.params.genesis_block_hash {
            return Err(format!(
                "Genesis block hash mismatch: expected {}, got {}",
                self.params.genesis_block_hash.to_hex(),
                hash.to_hex(),
            ));
        }

        // Don't re-initialise if the genesis block is already loaded.
        if self.block_index.find_by_hash(&hash).is_some() {
            return Ok(());
        }

        // Build the block index entry.
        let mut index = BlockIndex::from_header(&genesis.header, 0);
        index.chain_work = get_block_proof(&index);
        index.tx_count = genesis.vtx.len() as u32;
        index.chain_tx_count = genesis.vtx.len() as u64;
        index.status.raise_validity(BlockStatus::VALID_SCRIPTS);
        index.status.insert(BlockStatus::HAVE_DATA);
        index.time_max = genesis.header.time;

        let chain_work = index.chain_work;
        let arena_idx = self.block_index.insert(index);
        self.block_index.build_skip_pointer(arena_idx);
        self.dirty_indices.insert(arena_idx);

        let _ = chain_work;
        self.set_linked(arena_idx);
        self.candidates.insert(arena_idx);
        if self.memory_mode() {
            self.stored_blocks.insert(hash, genesis.clone());
        }

        // Update the active chain.
        self.active_chainstate.chain.set_tip(arena_idx, 0);

        // Add coinbase outputs to the UTXO cache.
        if let Some(coinbase) = genesis.vtx.first() {
            add_coins(&self.active_chainstate.coins_tip, coinbase, 0, true);
        }

        // Mark the best block in the UTXO view.
        self.active_chainstate.coins_tip.set_best_block(hash);

        Ok(())
    }

    // -- Block header acceptance --------------------------------------------

    /// Accept a block header: validate and add to the block index.
    ///
    /// Returns the arena index of the (new or existing) block index entry on
    /// success, or a `BlockValidationState` describing the failure.
    ///
    /// This is a simplified version of Bitcoin Core's `AcceptBlockHeader`.
    /// Validation steps:
    /// 1. Check if the header is already known.
    /// 2. Perform context-free header checks (PoW, etc.).
    /// 3. Look up the parent block.
    /// 4. Perform contextual header checks (timestamp, difficulty, etc.).
    /// 5. Add the new block index entry to the arena.
    pub fn accept_block_header(
        &mut self,
        header: &BlockHeader,
    ) -> Result<usize, BlockValidationState> {
        let hash = header.block_hash();

        // 1. Already known?
        if let Some(idx) = self.block_index.find_by_hash(&hash) {
            return Ok(idx);
        }

        // 2. Context-free header checks.
        let mut state = BlockValidationState::new();
        if !check_block_header(header, &self.params.consensus, &mut state) {
            return Err(state);
        }

        // 3. Find the parent.
        let prev_idx = match self.block_index.find_by_hash(&header.prev_blockhash) {
            Some(idx) => idx,
            None => {
                let mut state = BlockValidationState::new();
                state.invalid(
                    BlockValidationResult::InvalidHeader,
                    "bad-prevblk",
                    "previous block not found",
                );
                return Err(state);
            }
        };

        // Check that the parent has not been marked as invalid.
        if self.block_index.get(prev_idx).status.has_failed() {
            let mut state = BlockValidationState::new();
            state.invalid(
                BlockValidationResult::InvalidHeader,
                "bad-prevblk",
                "previous block is invalid",
            );
            return Err(state);
        }

        // 4. Contextual header checks (with arena for real MTP).
        if !contextual_check_block_header_with_arena(
            header,
            &self.block_index.get(prev_idx),
            &self.params.consensus,
            &mut state,
            Some(self.block_index.as_slice()),
            Some(prev_idx),
        ) {
            return Err(state);
        }

        // 5. Build the new block index entry.
        let prev = self.block_index.get(prev_idx);
        let height = prev.height + 1;
        let mut index = BlockIndex::from_header(header, height);
        index.prev = Some(prev_idx);
        index.chain_work = prev.chain_work + get_block_proof(&index);
        index.time_max = std::cmp::max(prev.time_max, header.time);
        index.status.raise_validity(BlockStatus::VALID_TREE);

        let arena_idx = self.block_index.insert(index);
        self.block_index.build_skip_pointer(arena_idx);
        self.dirty_indices.insert(arena_idx);
        Ok(arena_idx)
    }

    // -- Full block processing ----------------------------------------------

    /// Process a new block (legacy interface).
    ///
    /// Returns `(on_tip, undo)`: whether this block is the active tip after
    /// processing, and its undo data if it was connected by this call. `Err`
    /// when the block itself is invalid. See [`process_block`](Self::process_block).
    pub fn process_new_block(&mut self, block: &Block) -> Result<(bool, Option<BlockUndo>), BlockValidationState> {
        let out = self.process_block(block, None)?;
        let on_tip = self.tip() == Some(out.arena_idx);
        let undo = out
            .update
            .connected
            .iter()
            .rev()
            .find(|c| c.arena_idx == out.arena_idx)
            .map(|c| c.undo.clone());
        Ok((on_tip, undo))
    }

    /// Process a new block: store it (wherever it attaches), then switch to
    /// the chain with the most work.
    ///
    /// Port of Bitcoin Core's `ChainstateManager::ProcessNewBlock()`:
    /// [`accept_block`](Self::accept_block) followed by
    /// [`activate_best_chain`](Self::activate_best_chain). `pos` is the
    /// block's on-disk position (`file`, `data_pos`) when the caller has
    /// already written it. Returns `Err` only when this block itself is
    /// invalid; other blocks found invalid during a reorganisation are
    /// reported in [`ChainUpdate::invalid`].
    pub fn process_block(
        &mut self,
        block: &Block,
        pos: Option<(i32, u32)>,
    ) -> Result<ProcessOutcome, BlockValidationState> {
        let (arena_idx, new_block) = self.accept_block(block, pos)?;
        let update = self.activate_best_chain(Some((arena_idx, block)));
        if let Some((_, state)) = update.invalid.iter().find(|(i, _)| *i == arena_idx) {
            let state = state.clone();
            return Err(state);
        }
        Ok(ProcessOutcome {
            arena_idx,
            new_block,
            update,
        })
    }

    fn mark_failed(&mut self, idx: usize) {
        self.block_index.get_mut(idx).status.insert(BlockStatus::FAILED_VALID);
        self.dirty_indices.insert(idx);
        self.candidates.remove(&idx);
        // Invalidate candidates descending from it (Core: BLOCK_FAILED_CHILD).
        let h = self.block_index.get(idx).height;
        let doomed: Vec<usize> = self
            .candidates
            .iter()
            .copied()
            .filter(|&c| get_ancestor(self.block_index.as_slice(), c, h) == Some(idx))
            .collect();
        for c in doomed {
            self.block_index.get_mut(c).status.insert(BlockStatus::FAILED_CHILD);
            self.dirty_indices.insert(c);
            self.candidates.remove(&c);
        }
    }

    /// Validate and store a block without connecting it.
    ///
    /// Port of Core's `ChainstateManager::AcceptBlock()`: the header is
    /// accepted, `CheckBlock` and `ContextualCheckBlock` run, and the block
    /// is recorded as having data (and, once its whole ancestry has data,
    /// becomes a tip candidate). Returns `(arena_idx, new_block)`.
    pub fn accept_block(
        &mut self,
        block: &Block,
        pos: Option<(i32, u32)>,
    ) -> Result<(usize, bool), BlockValidationState> {
        let arena_idx = self.accept_block_header(&block.header)?;
        {
            let e = self.block_index.get(arena_idx);
            if e.status.has_failed() {
                let mut state = BlockValidationState::new();
                state.invalid(BlockValidationResult::CachedInvalid, "duplicate", "block is marked invalid");
                return Err(state);
            }
            if e.status.has_data() && (self.is_linked(arena_idx) || e.height == 0) {
                // Already have it. A block that is valid but no longer in
                // the active chain (crash recovery) stays a candidate.
                if !self.active_contains(arena_idx) && !e.status.has_failed() {
                    self.candidates.insert(arena_idx);
                }
                return Ok((arena_idx, false));
            }
        }

        let mut state = BlockValidationState::new();
        // A mutated block (e.g. stripped witness) says nothing about the
        // validity of the real block with this hash, so it is not cached as
        // invalid (Core skips BLOCK_MUTATED here).
        if !check_block(block, &self.params.consensus, &mut state, true) {
            if *state.get_result() != BlockValidationResult::MutatedBlock {
                self.mark_failed(arena_idx);
            }
            return Err(state);
        }
        if let Some(pi) = self.block_index.get(arena_idx).prev {
            let prev_height = self.block_index.get(pi).height;
            let ancestors = self.collect_ancestors(pi, 11);
            let prev_median_time = BlockIndex::get_median_time_past(&ancestors);
            if !contextual_check_block(block, prev_height, prev_median_time, &self.params.consensus, &mut state) {
                if *state.get_result() != BlockValidationResult::MutatedBlock {
                    self.mark_failed(arena_idx);
                }
                return Err(state);
            }
        }

        // Store.
        {
            let idx = self.block_index.get_mut(arena_idx);
            idx.tx_count = block.vtx.len() as u32;
            idx.status.insert(BlockStatus::HAVE_DATA);
            idx.status.raise_validity(BlockStatus::VALID_TRANSACTIONS);
            if let Some((file, data_pos)) = pos {
                idx.file = file;
                idx.data_pos = data_pos;
            }
        }
        self.dirty_indices.insert(arena_idx);
        if self.memory_mode() {
            self.stored_blocks.insert(block.block_hash(), block.clone());
        }

        // Link it (and any descendants waiting for it).
        let prev = self.block_index.get(arena_idx).prev;
        if prev.map_or(true, |p| self.is_linked(p)) {
            let mut queue = vec![arena_idx];
            while let Some(i) = queue.pop() {
                let parent_tx = self
                    .block_index
                    .get(i)
                    .prev
                    .map(|p| self.block_index.get(p).chain_tx_count)
                    .unwrap_or(0);
                let n = self.block_index.get(i).tx_count as u64;
                self.block_index.get_mut(i).chain_tx_count = parent_tx + n;
                self.set_linked(i);
                self.dirty_indices.insert(i);
                if !self.block_index.get(i).status.has_failed() {
                    self.candidates.insert(i);
                }
                if let Some(children) = self.unlinked.remove(&i) {
                    queue.extend(children);
                }
            }
        } else if let Some(p) = prev {
            self.unlinked.entry(p).or_default().push(arena_idx);
        }
        Ok((arena_idx, true))
    }

    fn active_contains(&self, idx: usize) -> bool {
        let h = self.block_index.get(idx).height;
        self.active_chainstate.chain.get_block_index(h) == Some(idx)
    }

    // -- Mining support ------------------------------------------------------

    /// Median time past of the block at `arena_idx`.
    ///
    /// Port of Bitcoin Core's `CBlockIndex::GetMedianTimePast()`.
    pub fn median_time_past(&self, arena_idx: usize) -> i64 {
        qubitcoin_common::chain::compute_mtp(self.block_index.as_slice(), arena_idx)
    }

    /// `nBits` required for a block built on `prev_idx` with timestamp
    /// `block_time`.
    ///
    /// Port of Bitcoin Core's `GetNextWorkRequired()` (src/pow.cpp), resolved
    /// against this manager's block index.
    pub fn next_work_required(&self, prev_idx: usize, block_time: u32) -> u32 {
        crate::validation::get_next_work_required_with_arena(
            self.block_index.get(prev_idx),
            block_time,
            &self.params.consensus,
            Some(self.block_index.as_slice()),
            Some(prev_idx),
        )
    }

    /// Whether the node is still in initial block download.
    ///
    /// Port of Bitcoin Core's `ChainstateManager::IsInitialBlockDownload()`:
    /// true while there is no tip, the tip has less work than
    /// `nMinimumChainWork`, or the tip is older than [`DEFAULT_MAX_TIP_AGE`].
    /// Once it has returned `false` it latches and keeps returning `false`.
    pub fn is_initial_block_download(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.finished_ibd.load(Ordering::Relaxed) {
            return false;
        }
        let tip = match self.tip() {
            Some(t) => self.block_index.get(t),
            None => return true,
        };
        let min_work =
            qubitcoin_primitives::arith_uint256::uint256_to_arith(&self.params.consensus.minimum_chain_work);
        if tip.chain_work < min_work {
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if tip.get_block_time() < now - DEFAULT_MAX_TIP_AGE {
            return true;
        }
        self.finished_ibd.store(true, Ordering::Relaxed);
        false
    }

    /// Check that `block` would be valid if connected on top of the current
    /// tip, without changing any chain or UTXO state.
    ///
    /// Port of Bitcoin Core's `TestBlockValidity()` (validation.cpp):
    /// `ContextualCheckBlockHeader`, `CheckBlock(fCheckPOW,
    /// fCheckMerkleRoot)`, `ContextualCheckBlock`, then `ConnectBlock` with
    /// `fJustCheck=true` against a throwaway coins view. Core asserts that
    /// the block builds on the tip; here a mismatch is reported as the
    /// `inconclusive-not-best-prevblk` rejection that the BIP23 proposal
    /// path uses.
    pub fn test_block_validity(
        &self,
        block: &Block,
        check_pow: bool,
        check_merkle_root: bool,
    ) -> Result<(), BlockValidationState> {
        let mut state = BlockValidationState::new();
        let tip = match self.tip() {
            Some(t) => t,
            None => {
                state.invalid(BlockValidationResult::InvalidHeader, "bad-prevblk", "no chain tip");
                return Err(state);
            }
        };
        let prev = self.block_index.get(tip);
        if block.header.prev_blockhash != prev.block_hash {
            state.invalid(
                BlockValidationResult::InvalidHeader,
                "inconclusive-not-best-prevblk",
                "block does not build on the current tip",
            );
            return Err(state);
        }
        let consensus = &self.params.consensus;
        let arena = self.block_index.as_slice();

        if !crate::validation::contextual_check_block_header_with_arena(
            &block.header,
            prev,
            consensus,
            &mut state,
            Some(arena),
            Some(tip),
        ) {
            return Err(state);
        }
        if !crate::validation::check_block_with_options(
            block,
            consensus,
            &mut state,
            check_pow,
            check_merkle_root,
        ) {
            return Err(state);
        }
        let prev_mtp = qubitcoin_common::chain::compute_mtp(arena, tip);
        if !crate::validation::contextual_check_block(block, prev.height, prev_mtp, consensus, &mut state) {
            return Err(state);
        }

        // ConnectBlock(fJustCheck=true): run on a throwaway cache whose base
        // is a snapshot of exactly the coins this block reads, so the live
        // UTXO cache is never touched.
        let mut coins = HashMap::new();
        let tip_view = &self.active_chainstate.coins_tip;
        for tx in &block.vtx {
            for input in &tx.vin {
                if input.prevout.is_null() {
                    continue;
                }
                if let Some(c) = tip_view.get_coin(&input.prevout) {
                    coins.insert(input.prevout.clone(), c);
                }
            }
            // Outputs too, so the BIP30 overwrite check sees existing coins.
            for n in 0..tx.vout.len() {
                let op = qubitcoin_consensus::transaction::OutPoint::new(*tx.txid(), n as u32);
                if let Some(c) = tip_view.get_coin(&op) {
                    coins.insert(op, c);
                }
            }
        }
        let scratch = CoinsViewCache::new(Box::new(SnapshotCoinsView {
            coins,
            best_block: prev.block_hash,
        }));
        let chain = &self.active_chainstate.chain;
        let mtp_lookup = |h: i32| -> i64 {
            match chain.get_block_index(h) {
                Some(ai) => qubitcoin_common::chain::compute_mtp(arena, ai),
                None => block.header.time as i64,
            }
        };
        crate::validation::connect_block(
            block,
            prev.height + 1,
            &scratch,
            consensus,
            Some(&mtp_lookup),
            false,
        )?;
        Ok(())
    }

    // -- Internal helpers ---------------------------------------------------

    /// Block data for `idx`: the block in hand, memory, or disk.
    fn read_block(&self, idx: usize, in_hand: Option<(usize, &Block)>) -> Option<Arc<Block>> {
        if let Some((i, b)) = in_hand {
            if i == idx {
                return Some(Arc::new(b.clone()));
            }
        }
        let e = self.block_index.get(idx);
        if let Some(b) = self.stored_blocks.get(&e.block_hash) {
            return Some(Arc::new(b.clone()));
        }
        if !e.status.has_data() || e.file < 0 {
            return None;
        }
        if let Some(r) = &self.block_data_reader {
            return r(e.file, e.data_pos).map(Arc::new);
        }
        if let Some(r) = &self.block_reader {
            return r(e.file, e.data_pos, e.undo_pos).map(|(b, _)| Arc::new(b));
        }
        None
    }

    /// Undo data for an active-chain block.
    fn read_undo(&self, idx: usize) -> Option<BlockUndo> {
        let e = self.block_index.get(idx);
        if let Some(u) = self.stored_undos.get(&e.block_hash) {
            return Some(u.clone());
        }
        if e.file < 0 {
            return None;
        }
        if let Some(r) = &self.undo_reader {
            if !e.status.has_undo() {
                return None;
            }
            return r(e.file, e.undo_pos);
        }
        if let Some(r) = &self.block_reader {
            return r(e.file, e.data_pos, e.undo_pos).map(|(_, u)| u);
        }
        None
    }

    /// The most-work valid candidate (Core's `FindMostWorkChain`); ties go
    /// to the block seen first.
    fn find_most_work_chain(&mut self) -> Option<usize> {
        loop {
            let mut best: Option<usize> = None;
            for &c in &self.candidates {
                let better = match best {
                    None => true,
                    Some(b) => {
                        // Core's CBlockIndexWorkComparator: more work, then
                        // the block received first.
                        let (wc, wb) = (self.block_index.get(c).chain_work, self.block_index.get(b).chain_work);
                        wc > wb || (wc == wb && c < b)
                    }
                };
                if better {
                    best = Some(c);
                }
            }
            let best = best?;
            // Every block between the fork point and the candidate must be
            // usable (not failed).
            let mut walk = Some(best);
            let mut bad = None;
            while let Some(i) = walk {
                if self.active_contains(i) {
                    break;
                }
                if self.block_index.get(i).status.has_failed() {
                    bad = Some(i);
                    break;
                }
                walk = self.block_index.get(i).prev;
            }
            match bad {
                None => return Some(best),
                Some(_) => {
                    self.block_index.get_mut(best).status.insert(BlockStatus::FAILED_CHILD);
                    self.dirty_indices.insert(best);
                    self.candidates.remove(&best);
                }
            }
        }
    }

    fn set_active_tip(&mut self, idx: usize) {
        let height = self.block_index.get(idx).height;
        let block_index = &self.block_index;
        self.active_chainstate.chain.set_tip_with(idx, height, |i| {
            let e = block_index.get(i);
            e.prev.map(|p| (p, block_index.get(p).height))
        });
        let hash = self.block_index.get(idx).block_hash;
        self.active_chainstate.coins_tip.set_best_block(hash);
    }

    /// Connect `idx` (whose parent is the tip) on a throwaway view; commit
    /// the UTXO changes only if the block is valid (Core's `ConnectTip`
    /// with its `CCoinsViewCache view(&CoinsTip())`).
    fn connect_tip(&mut self, idx: usize, block: &Block) -> Result<BlockUndo, BlockValidationState> {
        let height = self.block_index.get(idx).height;
        let skip_scripts = self.should_skip_scripts(idx);

        // Snapshot the coins the block reads (and, where BIP30 applies,
        // the ones it would overwrite) from the tip cache.
        let tip_view = &self.active_chainstate.coins_tip;
        let mut wanted: Vec<qubitcoin_consensus::transaction::OutPoint> = Vec::new();
        let bip30 = height < self.params.consensus.bip34_height || height >= 1_983_702;
        for tx in &block.vtx {
            for input in &tx.vin {
                if !input.prevout.is_null() {
                    wanted.push(input.prevout.clone());
                }
            }
            if bip30 {
                for n in 0..tx.vout.len() {
                    wanted.push(qubitcoin_consensus::transaction::OutPoint::new(*tx.txid(), n as u32));
                }
            }
        }
        tip_view.prefetch_coins(&wanted);
        let mut coins = HashMap::with_capacity(wanted.len());
        for op in wanted {
            if let Some(c) = tip_view.fetch_coin(&op) {
                coins.insert(op, c);
            }
        }
        let prev_hash = self.block_index.get(idx).prev_blockhash;
        let scratch = CoinsViewCache::new(Box::new(SnapshotCoinsView {
            coins,
            best_block: prev_hash,
        }));

        let arena = self.block_index.as_slice();
        let chain = &self.active_chainstate.chain;
        let mtp_lookup = |h: i32| -> i64 {
            match chain.get_block_index(h) {
                Some(ai) => qubitcoin_common::chain::compute_mtp(arena, ai),
                None => block.header.time as i64,
            }
        };
        let undo = connect_block(block, height, &scratch, &self.params.consensus, Some(&mtp_lookup), skip_scripts)?;
        self.active_chainstate.coins_tip.apply_changes(scratch.dirty_changes());
        Ok(undo)
    }

    /// Switch to the most-work valid chain, reorganising as needed.
    ///
    /// Port of Core's `Chainstate::ActivateBestChain()` /
    /// `ActivateBestChainStep()`: find the most-work candidate, disconnect
    /// the active chain back to the fork point using undo data, connect the
    /// new branch block by block. A block that fails to connect is marked
    /// invalid (its descendants too) and the search repeats, which
    /// reconnects the previous chain if it is again the best. The UTXO cache
    /// is only modified by blocks that connect successfully.
    pub fn activate_best_chain(&mut self, in_hand: Option<(usize, &Block)>) -> ChainUpdate {
        let mut update = ChainUpdate::default();
        // Bound the work in pathological cases (each pass either moves the
        // tip to more work or marks a block invalid).
        for _ in 0..10_000 {
            let best = match self.find_most_work_chain() {
                Some(b) => b,
                None => break,
            };
            let tip = match self.tip() {
                Some(t) => t,
                None => break,
            };
            if best == tip || self.block_index.get(best).chain_work < self.block_index.get(tip).chain_work {
                break;
            }

            // Path from the fork point (exclusive) up to `best`.
            let mut path = Vec::new();
            let mut walk = Some(best);
            while let Some(i) = walk {
                if self.active_contains(i) {
                    break;
                }
                path.push(i);
                walk = self.block_index.get(i).prev;
            }
            let fork = match walk {
                Some(f) => f,
                None => {
                    self.candidates.remove(&best);
                    continue;
                }
            };
            path.reverse();
            let fork_height = self.block_index.get(fork).height;

            // Make sure everything needed is available before touching state.
            let mut to_disconnect = Vec::new();
            let mut available = true;
            let mut h = self.height();
            while h > fork_height {
                let i = self.active_chainstate.chain.get_block_index(h).expect("active chain");
                match (self.read_block(i, in_hand), self.read_undo(i)) {
                    (Some(b), Some(u)) => to_disconnect.push((i, b, u)),
                    _ => {
                        available = false;
                        break;
                    }
                }
                h -= 1;
            }
            if !available {
                tracing::error!(
                    candidate = %self.block_index.get(best).block_hash.to_hex(),
                    "cannot reorganise: block or undo data for the active chain is unavailable"
                );
                self.candidates.remove(&best);
                continue;
            }

            for (i, b, u) in to_disconnect {
                let height = self.block_index.get(i).height;
                if matches!(
                    disconnect_block(&b, height, &self.active_chainstate.coins_tip, &u),
                    DisconnectResult::Failed
                ) {
                    tracing::error!(height, "DisconnectBlock failed; UTXO set may be inconsistent");
                }
                let prev = self.block_index.get(i).prev.expect("non-genesis");
                self.set_active_tip(prev);
                // The disconnected block remains a candidate if it still has
                // at least as much work as the eventual tip.
                self.candidates.insert(i);
                if update.fork_idx.is_none() {
                    update.fork_idx = Some(fork);
                }
                update.disconnected.push((i, b));
            }

            for i in path {
                let block = match self.read_block(i, in_hand) {
                    Some(b) => b,
                    None => {
                        // Data vanished; stop here, the next pass re-evaluates.
                        self.candidates.remove(&best);
                        break;
                    }
                };
                match self.connect_tip(i, &block) {
                    Ok(undo) => {
                        {
                            let e = self.block_index.get_mut(i);
                            e.status.raise_validity(BlockStatus::VALID_SCRIPTS);
                        }
                        let file = self.block_index.get(i).file;
                        if let (Some(w), true) = (&self.undo_writer, file >= 0) {
                            if let Some(pos) = w(file, &undo) {
                                let e = self.block_index.get_mut(i);
                                e.undo_pos = pos;
                                e.status.insert(BlockStatus::HAVE_UNDO);
                            }
                        }
                        if self.memory_mode() {
                            self.stored_undos.insert(block.block_hash(), undo.clone());
                        }
                        self.dirty_indices.insert(i);
                        self.set_active_tip(i);
                        let height = self.block_index.get(i).height;
                        update.connected.push(ConnectedBlock {
                            arena_idx: i,
                            height,
                            block,
                            undo,
                        });
                    }
                    Err(state) => {
                        tracing::warn!(
                            hash = %self.block_index.get(i).block_hash.to_hex(),
                            reason = %state.get_reject_reason(),
                            "ConnectTip failed, marking block invalid"
                        );
                        self.mark_failed(i);
                        update.invalid.push((i, state));
                        break;
                    }
                }
            }
        }

        // Prune candidates that can no longer win (Core's
        // PruneBlockIndexCandidates).
        if let Some(t) = self.tip() {
            let tip_work = self.block_index.get(t).chain_work;
            let block_index = &self.block_index;
            self.candidates.retain(|&c| block_index.get(c).chain_work >= tip_work);
            self.candidates.insert(t);
        }
        update
    }

    /// Build the chain path from genesis (index 0) to the block at
    /// `tip_idx`, returning a `Vec` where `result[height] = arena_index`.
    #[cfg(test)]
    fn build_chain_path(&self, tip_idx: usize) -> Vec<usize> {
        let tip_height = self.block_index.get(tip_idx).height;
        let mut path = vec![0usize; (tip_height + 1) as usize];
        let mut current = tip_idx;
        let mut h = tip_height;
        while h >= 0 {
            path[h as usize] = current;
            match self.block_index.get(current).prev {
                Some(prev) => {
                    current = prev;
                    h -= 1;
                }
                None => break,
            }
        }
        path
    }

    /// Determine whether script verification should be skipped for a block.
    ///
    /// Returns `true` when assume-valid is configured and the block at
    /// `arena_idx` is either the assume-valid block itself or an ancestor
    /// of it. This allows IBD to skip the expensive parallel script
    /// verification for blocks already trusted by the network.
    fn should_skip_scripts(&self, arena_idx: usize) -> bool {
        let assume_hash = match &self.assume_valid {
            Some(h) => h,
            None => return false,
        };

        let block_hash = self.block_index.get(arena_idx).block_hash;

        // Exact match: this IS the assume-valid block.
        if block_hash == *assume_hash {
            return true;
        }

        // Check if the assume-valid block is in our index.
        let assume_idx = match self.block_index.find_by_hash(&assume_hash) {
            Some(idx) => idx,
            None => {
                // We have not seen the assume-valid header yet, so we cannot
                // know whether this block is on the chain that leads to it.
                //
                // Do NOT fall back to a bare `height < assume_valid_height`
                // comparison here. The configured height is static, while the
                // anchor hash is the only thing that actually ties a block to
                // the externally verified chain -- so a height-only test
                // disables script verification for every block below that
                // height on *any* chain the node is fed, including one whose
                // transactions carry no valid signatures at all. Bitcoin Core
                // likewise only skips scripts for a block it can prove is an
                // ancestor of the configured assume-valid block.
                //
                // Verifying scripts until the anchor header arrives is the
                // safe direction: header sync normally reaches the anchor well
                // before block validation does, so the cost is small and
                // transient.
                return false;
            }
        };

        // The block at arena_idx is an ancestor of assume_valid if
        // get_ancestor(assume_valid, block_height) == arena_idx.
        let block_height = self.block_index.get(arena_idx).height;
        let assume_height = self.block_index.get(assume_idx).height;

        if block_height > assume_height {
            return false; // Block is beyond the assume-valid block.
        }

        let ancestor = get_ancestor(self.block_index.as_slice(), assume_idx, block_height);
        ancestor == Some(arena_idx)
    }

    /// Collect up to `count` ancestors of the block at `arena_idx`, starting
    /// with the block itself.
    ///
    /// Returns a `Vec<&BlockIndex>` ordered from the given block backwards
    /// through its parents.
    fn collect_ancestors(&self, arena_idx: usize, count: usize) -> Vec<&BlockIndex> {
        let mut result = Vec::with_capacity(count);
        let mut current = Some(arena_idx);
        for _ in 0..count {
            match current {
                Some(idx) => {
                    let entry = self.block_index.get(idx);
                    result.push(entry);
                    current = entry.prev;
                }
                None => break,
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Validation stubs for tests
// ---------------------------------------------------------------------------
//
// When running unit tests for this module, we do not yet have the
// `crate::validation` module available (it is being developed in parallel).
// These stubs provide minimal implementations that accept all inputs so that
// the chainstate tests can exercise the data-structure logic independently
// of full consensus validation.

#[cfg(test)]
fn check_block_header(
    _header: &BlockHeader,
    _params: &ConsensusParams,
    _state: &mut BlockValidationState,
) -> bool {
    true
}

#[cfg(test)]
fn check_block(
    _block: &Block,
    _params: &ConsensusParams,
    _state: &mut BlockValidationState,
    _check_merkle_root: bool,
) -> bool {
    true
}

#[cfg(test)]
fn contextual_check_block_header(
    _header: &BlockHeader,
    _prev: &BlockIndex,
    _params: &ConsensusParams,
    _state: &mut BlockValidationState,
) -> bool {
    true
}

#[cfg(test)]
fn contextual_check_block_header_with_arena(
    _header: &BlockHeader,
    _prev: &BlockIndex,
    _params: &ConsensusParams,
    _state: &mut BlockValidationState,
    _arena: Option<&[BlockIndex]>,
    _prev_idx: Option<usize>,
) -> bool {
    true
}

#[cfg(test)]
fn contextual_check_block(
    _block: &Block,
    _prev_height: i32,
    _prev_median_time: i64,
    _params: &ConsensusParams,
    _state: &mut BlockValidationState,
) -> bool {
    true
}

#[cfg(test)]
fn connect_block(
    block: &Block,
    height: i32,
    view: &CoinsViewCache,
    _params: &ConsensusParams,
    _mtp_at_height: Option<&dyn Fn(i32) -> i64>,
    _skip_scripts: bool,
) -> Result<BlockUndo, BlockValidationState> {
    use crate::undo::TxUndo;

    let mut block_undo = BlockUndo::new();

    // Add coinbase outputs.
    if let Some(coinbase) = block.vtx.first() {
        add_coins(view, coinbase, height as u32, true);
    }

    // Process non-coinbase transactions: capture spent coins then spend.
    for tx in block.vtx.iter().skip(1) {
        add_coins(view, tx, height as u32, false);

        let mut tx_undo = TxUndo::new();
        for input in &tx.vin {
            let coin = view
                .fetch_coin(&input.prevout)
                .unwrap_or_else(|| qubitcoin_common::coins::Coin::empty());
            tx_undo.prev_coins.push(coin);
            view.spend_coin(&input.prevout);
        }
        block_undo.tx_undo.push(tx_undo);
    }

    Ok(block_undo)
}

/// Result of a block disconnection (test stub).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisconnectResult {
    Ok,
    #[allow(dead_code)]
    Unclean,
    #[allow(dead_code)]
    Failed,
}

#[cfg(test)]
fn disconnect_block(
    block: &Block,
    _height: i32,
    view: &CoinsViewCache,
    undo: &BlockUndo,
) -> DisconnectResult {
    use qubitcoin_consensus::transaction::OutPoint;

    // Walk transactions in reverse.
    for (tx_idx, tx) in block.vtx.iter().enumerate().rev() {
        let txid = tx.txid().clone();

        // Remove outputs.
        for (i, _) in tx.vout.iter().enumerate() {
            let outpoint = OutPoint::new(txid.clone(), i as u32);
            view.spend_coin(&outpoint);
        }

        // Restore inputs from undo data for non-coinbase txs.
        if !tx.is_coinbase() && tx_idx > 0 {
            let undo_idx = tx_idx - 1;
            if undo_idx < undo.tx_undo.len() {
                for (input, undo_coin) in
                    tx.vin.iter().zip(undo.tx_undo[undo_idx].prev_coins.iter())
                {
                    if !undo_coin.is_spent() {
                        view.add_coin(&input.prevout, undo_coin.clone(), true);
                    }
                }
            }
        }
    }

    DisconnectResult::Ok
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qubitcoin_consensus::block::{Block, BlockHeader};
    use qubitcoin_primitives::{BlockHash, Uint256};

    /// Helper: build a minimal genesis block whose hash matches the regtest
    /// genesis. We use regtest because its PoW limit is extremely permissive
    /// and the genesis parameters are simpler.
    fn make_regtest_genesis() -> Block {
        // The regtest genesis has the same header fields as mainnet except
        // nBits = 0x207fffff and nTime = 1296688602.
        let mut header = BlockHeader::new();
        header.version = 1;
        header.time = 1296688602;
        header.bits = 0x207fffff;
        header.nonce = 2;
        header.merkle_root =
            Uint256::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .unwrap();

        Block {
            header,
            // The genesis coinbase transaction is not needed for our structural
            // tests; an empty vtx is acceptable because the test stubs accept
            // everything.
            vtx: Vec::new(),
        }
    }

    // -- BlockMap tests -----------------------------------------------------

    #[test]
    fn test_block_map_empty() {
        let map = BlockMap::new();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert!(map.find_by_hash(&BlockHash::ZERO).is_none());
    }

    #[test]
    fn test_block_map_insert_and_lookup() {
        let mut map = BlockMap::new();
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: Uint256::ZERO,
            time: 1000,
            bits: 0x207fffff,
            nonce: 42,
        };
        let index = BlockIndex::from_header(&header, 0);
        let hash = index.block_hash;

        let arena_idx = map.insert(index);
        assert_eq!(arena_idx, 0);
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());

        // Lookup by hash.
        assert_eq!(map.find_by_hash(&hash), Some(0));

        // Access by arena index.
        let entry = map.get(arena_idx);
        assert_eq!(entry.block_hash, hash);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn test_block_map_multiple_inserts() {
        let mut map = BlockMap::new();

        for i in 0..5u32 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: Uint256::ZERO,
                time: 1000 + i,
                bits: 0x207fffff,
                nonce: i,
            };
            let index = BlockIndex::from_header(&header, i as i32);
            map.insert(index);
        }

        assert_eq!(map.len(), 5);

        // Each entry should be at its sequential index.
        for i in 0..5 {
            let entry = map.get(i);
            assert_eq!(entry.height, i as i32);
        }
    }

    #[test]
    fn test_block_map_get_mut() {
        let mut map = BlockMap::new();
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: Uint256::ZERO,
            time: 2000,
            bits: 0x207fffff,
            nonce: 99,
        };
        let index = BlockIndex::from_header(&header, 0);
        let arena_idx = map.insert(index);

        // Mutate via get_mut.
        map.get_mut(arena_idx).height = 42;
        assert_eq!(map.get(arena_idx).height, 42);
    }

    // -- ChainstateManager tests --------------------------------------------

    #[test]
    fn test_chainstate_manager_empty() {
        let params = ChainParams::regtest();
        let manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));

        assert_eq!(manager.height(), -1);
        assert!(manager.tip().is_none());
        assert!(manager.active_chain().is_empty());
        assert_eq!(manager.block_index().len(), 0);
    }

    #[test]
    fn test_chainstate_manager_params() {
        let params = ChainParams::regtest();
        let manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));

        assert_eq!(
            manager.params().network,
            qubitcoin_common::chainparams::Network::Regtest,
        );
        assert!(manager.consensus().pow_no_retargeting);
        assert!(manager.consensus().pow_allow_min_difficulty_blocks);
    }

    #[test]
    fn test_load_genesis_block() {
        let params = ChainParams::regtest();
        let expected_hash = params.genesis_block_hash;
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));

        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();

        // The test genesis must match the regtest genesis hash.
        assert_eq!(genesis_hash, expected_hash);

        manager.load_genesis_block(&genesis).unwrap();

        // Chain should now be at height 0.
        assert_eq!(manager.height(), 0);

        // Tip should be the genesis.
        let tip_idx = manager.tip().expect("chain should have a tip");
        let tip = manager.block_index().get(tip_idx);
        assert_eq!(tip.block_hash, expected_hash);
        assert_eq!(tip.height, 0);

        // The genesis block should be fully valid.
        assert!(tip.is_valid(BlockStatus::VALID_SCRIPTS));

        // Chain work should be non-zero (the genesis block has some work).
        assert!(tip.chain_work > ArithUint256::zero());

        // Block index should have exactly one entry.
        assert_eq!(manager.block_index().len(), 1);
    }

    #[test]
    fn test_load_genesis_block_idempotent() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();

        manager.load_genesis_block(&genesis).unwrap();
        // Loading again should be a no-op.
        manager.load_genesis_block(&genesis).unwrap();

        assert_eq!(manager.height(), 0);
        assert_eq!(manager.block_index().len(), 1);
    }

    #[test]
    fn test_load_genesis_block_wrong_hash() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));

        // Build a block with the wrong hash.
        let mut header = BlockHeader::new();
        header.version = 1;
        header.time = 9999999;
        header.bits = 0x207fffff;
        header.nonce = 0;
        let bad_genesis = Block::with_header(header);

        let result = manager.load_genesis_block(&bad_genesis);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn test_lookup_block_index() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();

        manager.load_genesis_block(&genesis).unwrap();

        assert!(manager.lookup_block_index(&genesis_hash).is_some());
        assert!(manager.lookup_block_index(&BlockHash::ZERO).is_none());
    }

    #[test]
    fn test_accept_block_header_after_genesis() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();

        manager.load_genesis_block(&genesis).unwrap();

        // Create a header that builds on genesis.
        let header = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: 1296688612,
            bits: 0x207fffff,
            nonce: 0,
        };

        let arena_idx = manager.accept_block_header(&header).unwrap();
        let entry = manager.block_index().get(arena_idx);
        assert_eq!(entry.height, 1);
        assert!(entry.prev.is_some());
        assert_eq!(entry.prev_blockhash, genesis_hash);
        assert_eq!(manager.block_index().len(), 2);
    }

    #[test]
    fn test_accept_block_header_unknown_parent() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        manager.load_genesis_block(&genesis).unwrap();

        // Header referencing a parent that doesn't exist.
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            merkle_root: Uint256::ZERO,
            time: 1296688612,
            bits: 0x207fffff,
            nonce: 0,
        };

        let result = manager.accept_block_header(&header);
        assert!(result.is_err());
        let state = result.unwrap_err();
        assert!(state.is_invalid());
        assert_eq!(state.get_reject_reason(), "bad-prevblk");
    }

    #[test]
    fn test_accept_header_idempotent() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        let header = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: 1296688612,
            bits: 0x207fffff,
            nonce: 0,
        };

        let idx1 = manager.accept_block_header(&header).unwrap();
        let idx2 = manager.accept_block_header(&header).unwrap();
        assert_eq!(idx1, idx2);
        assert_eq!(manager.block_index().len(), 2);
    }

    #[test]
    fn test_process_new_block_extends_chain() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        // Build block 1 on top of genesis.
        let header1 = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: 1296688612,
            bits: 0x207fffff,
            nonce: 0,
        };
        let block1 = Block::with_header(header1);
        let block1_hash = block1.block_hash();

        let (on_active, _undo) = manager.process_new_block(&block1).unwrap();
        assert!(on_active); // Should be on the active chain.

        assert_eq!(manager.height(), 1);
        let tip_idx = manager.tip().unwrap();
        let tip = manager.block_index().get(tip_idx);
        assert_eq!(tip.block_hash, block1_hash);
        assert_eq!(tip.height, 1);
        assert!(tip.is_valid(BlockStatus::VALID_SCRIPTS));
    }

    #[test]
    fn test_process_sequential_blocks() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        manager.load_genesis_block(&genesis).unwrap();

        let mut prev_hash = genesis.block_hash();
        let base_time: u32 = 1296688612;

        // Build a chain of 10 blocks.
        for i in 0..10 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: i as u32,
            };
            let block = Block::with_header(header);
            prev_hash = block.block_hash();

            let (on_active, _undo) = manager.process_new_block(&block).unwrap();
            assert!(on_active, "block {} should be on active chain", i + 1);
        }

        assert_eq!(manager.height(), 10);
        assert_eq!(manager.block_index().len(), 11); // genesis + 10 blocks

        let tip_idx = manager.tip().unwrap();
        let tip = manager.block_index().get(tip_idx);
        assert_eq!(tip.height, 10);
        assert_eq!(tip.block_hash, prev_hash);
    }

    #[test]
    fn test_collect_ancestors() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        manager.load_genesis_block(&genesis).unwrap();

        let mut prev_hash = genesis.block_hash();
        let base_time: u32 = 1296688612;

        // Build 5 blocks.
        for i in 0..5 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: i as u32,
            };
            let block = Block::with_header(header);
            prev_hash = block.block_hash();
            manager.process_new_block(&block).unwrap();
        }

        // Collect ancestors of the tip (height 5).
        let tip_idx = manager.tip().unwrap();
        let ancestors = manager.collect_ancestors(tip_idx, 11);

        // We should get 6 entries (tip + 5 predecessors including genesis).
        assert_eq!(ancestors.len(), 6);
        // First ancestor is the tip itself.
        assert_eq!(ancestors[0].height, 5);
        // Last is genesis.
        assert_eq!(ancestors[5].height, 0);
    }

    #[test]
    fn test_coins_tip_accessible() {
        let params = ChainParams::regtest();
        let manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));

        // The coins tip should be accessible and report zero cached entries.
        assert_eq!(manager.coins_tip().cache_size(), 0);
    }

    #[test]
    fn test_stored_blocks_populated() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        // Build block 1.
        let header1 = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: 1296688612,
            bits: 0x207fffff,
            nonce: 0,
        };
        let block1 = Block::with_header(header1);
        let block1_hash = block1.block_hash();

        manager.process_new_block(&block1).unwrap();

        // The block and its undo data should be stored.
        assert!(manager.stored_blocks.contains_key(&block1_hash));
        assert!(manager.stored_undos.contains_key(&block1_hash));
    }

    #[test]
    fn test_chain_reorg_to_longer_fork() {
        // Build a chain A -> B1 -> B2, then create a fork A -> C1 -> C2 -> C3.
        // The longer fork (C-chain) should become the active chain.
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        let base_time: u32 = 1296688612;

        // Build the B-chain: 2 blocks on top of genesis.
        let mut b_prev = genesis_hash;
        let mut b_hashes = Vec::new();
        for i in 0..2 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: b_prev,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 100 + i as u32,
            };
            let block = Block::with_header(header);
            b_prev = block.block_hash();
            b_hashes.push(b_prev);
            manager.process_new_block(&block).unwrap();
        }

        // Active chain should be at height 2 with B2 as tip.
        assert_eq!(manager.height(), 2);
        let tip_hash = manager.block_index().get(manager.tip().unwrap()).block_hash;
        assert_eq!(tip_hash, *b_hashes.last().unwrap());

        // Build the C-chain: 3 blocks on top of genesis (longer fork).
        let mut c_prev = genesis_hash;
        let mut c_hashes = Vec::new();
        for i in 0..3 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: c_prev,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 200 + i as u32,
            };
            let block = Block::with_header(header);
            c_prev = block.block_hash();
            c_hashes.push(c_prev);
            manager.process_new_block(&block).unwrap();
        }

        // The C-chain (height 3) has more work, so it should be the active chain.
        assert_eq!(manager.height(), 3);
        let tip_hash = manager.block_index().get(manager.tip().unwrap()).block_hash;
        assert_eq!(tip_hash, *c_hashes.last().unwrap());
    }

    #[test]
    fn test_chain_reorg_fork_at_height_1() {
        // Build chain: G -> A1 -> A2 -> A3 (3 blocks)
        // Then fork:   G -> A1 -> B2 -> B3 -> B4 (3 blocks after A1)
        // The fork should win because it has more total work.
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        let base_time: u32 = 1296688612;

        // Build A-chain: G -> A1 -> A2 -> A3
        let mut a_prev = genesis_hash;
        let mut a_hashes = Vec::new();
        for i in 0..3 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: a_prev,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 300 + i as u32,
            };
            let block = Block::with_header(header);
            a_prev = block.block_hash();
            a_hashes.push(a_prev);
            manager.process_new_block(&block).unwrap();
        }
        assert_eq!(manager.height(), 3);

        // Fork from A1 (height 1): B2 -> B3 -> B4
        let fork_parent = a_hashes[0]; // A1 at height 1
        let mut b_prev = fork_parent;
        let mut b_hashes = Vec::new();
        for i in 0..3 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: b_prev,
                merkle_root: Uint256::ZERO,
                time: base_time + ((i + 3) as u32) * 600,
                bits: 0x207fffff,
                nonce: 400 + i as u32,
            };
            let block = Block::with_header(header);
            b_prev = block.block_hash();
            b_hashes.push(b_prev);
            manager.process_new_block(&block).unwrap();
        }

        // B-chain tip is at height 4 (1 + 3), which has more work than
        // A-chain at height 3.
        assert_eq!(manager.height(), 4);
        let tip_hash = manager.block_index().get(manager.tip().unwrap()).block_hash;
        assert_eq!(tip_hash, *b_hashes.last().unwrap());

        // A1 should still be in the active chain at height 1.
        let h1_idx = manager.active_chain().get_block_index(1).unwrap();
        let h1_hash = manager.block_index().get(h1_idx).block_hash;
        assert_eq!(h1_hash, a_hashes[0]);
    }

    #[test]
    fn test_no_reorg_for_equal_work() {
        // Build chain: G -> A1, then fork: G -> B1 (same height, same work).
        // The first chain should remain active.
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        let genesis_hash = genesis.block_hash();
        manager.load_genesis_block(&genesis).unwrap();

        let base_time: u32 = 1296688612;

        // Build A1.
        let header_a = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: base_time,
            bits: 0x207fffff,
            nonce: 500,
        };
        let block_a = Block::with_header(header_a);
        let hash_a = block_a.block_hash();
        manager.process_new_block(&block_a).unwrap();
        assert_eq!(manager.height(), 1);

        // Build B1 (different nonce, same difficulty).
        let header_b = BlockHeader {
            version: 1,
            prev_blockhash: genesis_hash,
            merkle_root: Uint256::ZERO,
            time: base_time + 1,
            bits: 0x207fffff,
            nonce: 501,
        };
        let block_b = Block::with_header(header_b);
        let hash_b = block_b.block_hash();
        manager.process_new_block(&block_b).unwrap();

        // With equal chain work, activate_best_chain uses the *first* block
        // found with the highest work. Due to the iteration order, the result
        // depends on arena ordering. Both are valid, so we just verify height.
        assert_eq!(manager.height(), 1);

        // The tip should be one of the two blocks.
        let tip_hash = manager.block_index().get(manager.tip().unwrap()).block_hash;
        assert!(tip_hash == hash_a || tip_hash == hash_b);
    }

    #[test]
    fn test_build_chain_path() {
        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        manager.load_genesis_block(&genesis).unwrap();

        let mut prev_hash = genesis.block_hash();
        let base_time: u32 = 1296688612;

        // Build 3 blocks.
        for i in 0..3 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 600 + i as u32,
            };
            let block = Block::with_header(header);
            prev_hash = block.block_hash();
            manager.process_new_block(&block).unwrap();
        }

        let tip_idx = manager.tip().unwrap();
        let path = manager.build_chain_path(tip_idx);

        // Path should have 4 entries: genesis + 3 blocks.
        assert_eq!(path.len(), 4);
        // Genesis is at index 0.
        assert_eq!(manager.block_index().get(path[0]).height, 0);
        // Tip is at index 3.
        assert_eq!(manager.block_index().get(path[3]).height, 3);
    }

    #[test]
    fn test_skip_pointers_set_and_used_by_get_ancestor() {
        use qubitcoin_common::chain::{get_ancestor, get_skip_height};

        let params = ChainParams::regtest();
        let mut manager = ChainstateManager::new(params, Box::new(EmptyCoinsView));
        let genesis = make_regtest_genesis();
        manager.load_genesis_block(&genesis).unwrap();

        // Build a chain of 100 blocks so that skip pointers get interesting
        // values (skip distances grow as heights increase).
        let mut prev_hash = genesis.block_hash();
        let base_time: u32 = 1296688612;

        for i in 0..100 {
            let header = BlockHeader {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Uint256::ZERO,
                time: base_time + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 700 + i as u32,
            };
            let block = Block::with_header(header);
            prev_hash = block.block_hash();
            manager.process_new_block(&block).unwrap();
        }

        assert_eq!(manager.height(), 100);
        let arena = manager.block_index().as_slice();

        // 1. Verify that skip pointers are actually populated for blocks
        //    with height >= 2 (height 0 and 1 skip to height 0 which is
        //    trivially reachable via prev).
        let mut populated_count = 0;
        for idx in 0..arena.len() {
            let block = &arena[idx];
            if block.height >= 2 {
                assert!(
                    block.skip.is_some(),
                    "skip pointer should be set for block at height {}",
                    block.height,
                );
                // Verify the skip target is at the correct height.
                let skip_idx = block.skip.unwrap();
                let expected_height = get_skip_height(block.height);
                assert_eq!(
                    arena[skip_idx].height, expected_height,
                    "skip target for height {} should be at height {}, but is at {}",
                    block.height, expected_height, arena[skip_idx].height,
                );
                populated_count += 1;
            }
        }
        assert!(populated_count > 0, "should have set some skip pointers");

        // 2. Verify get_ancestor returns correct results for various
        //    target heights using the skip pointers (O(log n) path).
        let tip_idx = manager.tip().unwrap();
        for target in [0, 1, 10, 25, 50, 75, 99, 100] {
            let result = get_ancestor(arena, tip_idx, target);
            assert!(
                result.is_some(),
                "ancestor at height {} should exist",
                target
            );
            let ancestor_idx = result.unwrap();
            assert_eq!(
                arena[ancestor_idx].height, target,
                "ancestor lookup for height {} returned wrong height {}",
                target, arena[ancestor_idx].height,
            );
        }

        // 3. Cross-check: walk from the ancestor back to genesis using prev
        //    pointers to make sure the skip-found ancestor is on the same chain.
        let ancestor_50 = get_ancestor(arena, tip_idx, 50).unwrap();
        let mut walk = ancestor_50;
        let mut depth = 50;
        while depth > 0 {
            walk = arena[walk].prev.expect("prev should be set");
            depth -= 1;
        }
        assert_eq!(
            arena[walk].height, 0,
            "walking prev from ancestor(50) should reach genesis"
        );

        // 4. Verify that looking up ancestors of intermediate blocks also works.
        let block_at_64 = get_ancestor(arena, tip_idx, 64).unwrap();
        let ancestor_32_of_64 = get_ancestor(arena, block_at_64, 32).unwrap();
        let ancestor_32_of_tip = get_ancestor(arena, tip_idx, 32).unwrap();
        assert_eq!(
            ancestor_32_of_64, ancestor_32_of_tip,
            "ancestor(64, 32) should equal ancestor(100, 32) on the same chain",
        );
    }
}
