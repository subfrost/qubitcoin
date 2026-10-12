//! Block-connection plumbing shared by every way a block reaches the node
//! (P2P, `submitblock`, `generatetoaddress`).
//!
//! [`ChainEvents`] is the daemon's stand-in for the validation-interface
//! signals Bitcoin Core fires from `ActivateBestChain`
//! (`BlockConnected` / `UpdatedBlockTip`): it removes the block's
//! transactions and their conflicts from the mempool (`removeForBlock`),
//! wakes `getblocktemplate` long polls, and forwards to the external
//! notifiers (`-blocknotify`, ZMQ).
//!
//! [`DaemonBlockSink`] is the daemon's [`BlockSink`] for the mining RPCs:
//! it stores the block in the flat files, runs it through
//! `ProcessNewBlock`, persists undo data, the UTXO cache and the block index,
//! and then raises the events above.

use std::sync::Arc;

use qubitcoin_common::coins::CoinsViewDB;
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::validation_state::BlockValidationState;
use qubitcoin_indexer::IndexerManager;
use qubitcoin_node::block_index_db::BlockIndexDB;
use qubitcoin_node::block_storage::BlockFileManager;
use qubitcoin_node::tx_index_db::TxIndexDB;
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_primitives::BlockHash;
use qubitcoin_rpc::mining::{BlockSink, TipWatch};
use qubitcoin_rpc::node_rpc::NodeState;
use qubitcoin_serialize::serialize;
use qubitcoin_storage::RocksDatabase;

use crate::notify::Notifications;

/// Fan-out for "a block was connected and is the new tip".
pub struct ChainEvents {
    pub mempool: Arc<TxMemPool>,
    pub tip_watch: Arc<TipWatch>,
    pub node_state: Arc<NodeState>,
    pub notifications: Arc<Notifications>,
}

impl ChainEvents {
    /// Called with the chainstate lock held, right after `block` became the
    /// tip at `height`. Must not lock the chainstate.
    ///
    /// `initial_download` mirrors Core's `fInitialDownload` argument to
    /// `UpdatedBlockTip`: `-blocknotify` is suppressed while it is true.
    pub fn block_connected(&self, block: &Block, hash: BlockHash, height: i32, initial_download: bool) {
        self.mempool.remove_for_block_txs(&block.vtx);
        self.mempool.add_transactions_updated(1);
        *self.node_state.chain_height.write() = height;
        *self.node_state.best_block_hash.write() = hash.to_hex();
        *self.node_state.is_initial_block_download.write() = initial_download;
        *self.node_state.mempool_size.write() = self.mempool.size();
        self.notifications.block_connected(block, hash, initial_download);
        self.tip_watch.notify(hash);
    }
}

/// Persists and connects blocks produced or received by the mining RPCs.
pub struct DaemonBlockSink {
    pub chainstate: Arc<parking_lot::Mutex<ChainstateManager>>,
    pub block_files: Arc<BlockFileManager>,
    pub coins_db: Arc<CoinsViewDB<RocksDatabase>>,
    pub block_index_db: Arc<BlockIndexDB<RocksDatabase>>,
    pub tx_index_db: Arc<TxIndexDB<RocksDatabase>>,
    pub indexer_manager: Option<Arc<IndexerManager>>,
    pub magic_bytes: [u8; 4],
    pub events: Arc<ChainEvents>,
}

impl BlockSink for DaemonBlockSink {
    fn process_new_block(&self, block: &Block) -> Result<bool, BlockValidationState> {
        let block_hash = block.header.block_hash();
        let pos = self.block_files.write_block(block, self.magic_bytes).map_err(|e| {
            let mut s = BlockValidationState::new();
            s.error(&format!("block file write: {}", e));
            s
        })?;

        let mut cs = self.chainstate.lock();
        // ProcessNewBlock creates the index entry (via AcceptBlockHeader), so
        // the file position is recorded afterwards.
        let (on_tip, undo) = match cs.process_new_block(block) {
            Ok(r) => r,
            Err(state) => {
                tracing::warn!(
                    hash = %block_hash.to_hex(),
                    reason = %state.get_reject_reason(),
                    "block rejected"
                );
                // Persist the FAILED_VALID mark.
                let dirty = cs.dirty_block_indices();
                if !dirty.is_empty() {
                    let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
                    self.block_index_db.write_block_indices(&refs);
                }
                return Err(state);
            }
        };
        if let Some(arena_idx) = cs.lookup_block_index(&block_hash) {
            let idx = cs.block_index_mut().get_mut(arena_idx);
            if idx.file < 0 || undo.is_some() {
                idx.file = pos.file;
                idx.data_pos = pos.pos;
                cs.mark_dirty(arena_idx);
            }
        }
        if undo.is_some() {
            let entries: Vec<_> = block
                .vtx
                .iter()
                .enumerate()
                .map(|(i, tx)| (*tx.txid(), pos.file, pos.pos, i as u32))
                .collect();
            self.tx_index_db.write_tx_positions(&entries);
        }
        if let Some(undo_data) = undo {
            if let Ok(undo_pos) = self.block_files.write_undo(pos.file, &undo_data) {
                cs.set_undo_pos(&block_hash, undo_pos.pos);
            }
        }
        // Flush coins + block index for crash safety (one block per call).
        cs.flush_coins(self.coins_db.as_ref());
        let dirty = cs.dirty_block_indices();
        if !dirty.is_empty() {
            let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
            self.block_index_db.write_block_indices(&refs);
        }
        cs.clear_dirty();

        let height = cs.height();
        if on_tip {
            let ibd = cs.is_initial_block_download();
            tracing::info!(height, hash = %block_hash.to_hex(), txs = block.vtx.len(), "new block connected");
            self.events.block_connected(block, block_hash, height, ibd);
        }
        drop(cs);

        if on_tip {
            if let Some(ref im) = self.indexer_manager {
                match serialize(block) {
                    Ok(bytes) => im.on_block_connected(height as u32, &bytes),
                    Err(e) => tracing::error!(error = %e, "serialize block for indexers"),
                }
            }
        }
        Ok(on_tip)
    }
}
