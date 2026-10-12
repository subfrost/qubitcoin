//! Block processing shared by every way a block reaches the node (P2P,
//! `submitblock`, `generatetoaddress`), and the fan-out of the resulting
//! chain changes.
//!
//! [`BlockProcessor`] stores the block in the flat files, runs it through
//! `ProcessNewBlock` (which may reorganise the chain, reading side-branch
//! blocks and undo data back from disk), persists the UTXO cache, block
//! index and txindex, and feeds secondary indexers.
//!
//! [`ChainEvents`] is the daemon's stand-in for the validation-interface
//! signals Bitcoin Core fires from `ActivateBestChain`, in Core's order:
//! `BlockDisconnected` for each disconnected block, `BlockConnected` for each
//! connected one, the mempool update (`removeForBlock`,
//! `MaybeUpdateMempoolForReorg`, `removeForReorg`, whose acceptances and
//! removals reach ZMQ through the mempool listener), then `UpdatedBlockTip`
//! (`hashblock`/`rawblock`, `-blocknotify`, long-poll wake-up).

use std::sync::Arc;

use qubitcoin_common::coins::CoinsViewDB;
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::validation_state::BlockValidationState;
use qubitcoin_indexer::IndexerManager;
use qubitcoin_node::block_index_db::BlockIndexDB;
use qubitcoin_node::block_storage::BlockFileManager;
use qubitcoin_node::chainstate::{ChainUpdate, ChainstateManager};
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_node::mempool_accept::update_mempool_for_chain_update;
use qubitcoin_node::tx_index_db::TxIndexDB;
use qubitcoin_primitives::{BlockHash, Txid};
use qubitcoin_rpc::mining::{BlockSink, SinkOutcome, TipWatch};
use qubitcoin_rpc::node_rpc::NodeState;
use qubitcoin_serialize::serialize;
use qubitcoin_storage::RocksDatabase;

use crate::notify::Notifications;

/// Fan-out for chain changes.
pub struct ChainEvents {
    pub mempool: Arc<TxMemPool>,
    pub tip_watch: Arc<TipWatch>,
    pub node_state: Arc<NodeState>,
    pub notifications: Arc<Notifications>,
    /// Called with the new tip after every tip change (connect, disconnect,
    /// reorg); the indexer simulation engine drops its overlays here.
    pub on_tip: Option<Arc<dyn Fn(BlockHash) + Send + Sync>>,
}

impl ChainEvents {
    /// Handle the result of an `ActivateBestChain` run. Called with the
    /// chainstate lock held (`cs`); must not lock the chainstate again.
    pub fn chain_updated(&self, cs: &ChainstateManager, update: &ChainUpdate) {
        if !update.tip_changed() {
            return;
        }
        let ibd = cs.is_initial_block_download();
        for (_, b) in &update.disconnected {
            self.notifications.block_disconnected(b);
        }
        for c in &update.connected {
            self.notifications.block_connected(&c.block);
        }
        update_mempool_for_chain_update(cs, &self.mempool, update);
        self.mempool.add_transactions_updated(1);

        let tip = cs.tip().expect("tip exists after a chain update");
        let tip_hash = cs.block_index().get(tip).block_hash;
        *self.node_state.chain_height.write() = cs.height();
        *self.node_state.best_block_hash.write() = tip_hash.to_hex();
        *self.node_state.is_initial_block_download.write() = ibd;
        *self.node_state.mempool_size.write() = self.mempool.size();
        // UpdatedBlockTip: only when something was connected (Core skips
        // the notification when the new tip is the fork point).
        if let Some(last) = update.connected.last() {
            if last.arena_idx == tip {
                self.notifications.updated_block_tip(&last.block, tip_hash, ibd);
            }
        }
        self.tip_watch.notify(tip_hash);
        if let Some(f) = &self.on_tip {
            f(tip_hash);
        }
    }
}

/// The tip a pending-block simulation builds on: the active tip, with
/// header fields for a block at `tip + 1` (time = max(MTP + 1, now), the
/// next required bits). No proof of work is ever computed.
pub fn sim_tip(cs: &ChainstateManager) -> Option<qubitcoin_indexer::simulation::SimTip> {
    let tip = cs.tip()?;
    let e = cs.block_index().get(tip);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let time = (cs.median_time_past(tip) + 1).max(now) as u32;
    Some(qubitcoin_indexer::simulation::SimTip {
        hash: *e.block_hash.data(),
        height: e.height as u32,
        version: 0x2000_0000,
        time,
        bits: cs.next_work_required(tip, time),
    })
}

/// Stores, connects and persists blocks.
pub struct BlockProcessor {
    pub chainstate: Arc<parking_lot::Mutex<ChainstateManager>>,
    pub block_files: Arc<BlockFileManager>,
    pub coins_db: Arc<CoinsViewDB<RocksDatabase>>,
    pub block_index_db: Arc<BlockIndexDB<RocksDatabase>>,
    pub tx_index_db: Arc<TxIndexDB<RocksDatabase>>,
    pub indexer_manager: Option<Arc<IndexerManager>>,
    /// User-registered DAG nodes; run after the standard indexers.
    pub user_dag: Option<Arc<qubitcoin_indexer::usernodes::UserDag>>,
    pub magic_bytes: [u8; 4],
    pub events: Arc<ChainEvents>,
    /// Flush the UTXO cache once it exceeds this many bytes (`-dbcache`).
    pub dbcache_limit: u64,
    /// Blocks connected since the last flush.
    pub blocks_since_flush: parking_lot::Mutex<u64>,
    /// TX index entries waiting for the next flush.
    pub pending_tx_index: parking_lot::Mutex<Vec<(Txid, i32, u32, u32)>>,
}

impl BlockProcessor {
    /// Write the UTXO cache, dirty block index entries and pending txindex
    /// entries (used at shutdown).
    pub fn flush(&self) {
        let mut cs = self.chainstate.lock();
        self.persist(&mut cs);
    }

    fn persist(&self, cs: &mut ChainstateManager) {
        cs.flush_coins(self.coins_db.as_ref());
        let dirty = cs.dirty_block_indices();
        if !dirty.is_empty() {
            let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
            self.block_index_db.write_block_indices(&refs);
        }
        cs.clear_dirty();
        let mut pending = self.pending_tx_index.lock();
        if !pending.is_empty() {
            self.tx_index_db.write_tx_positions(&pending);
            pending.clear();
        }
        *self.blocks_since_flush.lock() = 0;
    }

    /// Store `block` and run `ProcessNewBlock`. With `flush_now`, the UTXO
    /// cache, block index and txindex are written before returning (used by
    /// the RPCs); otherwise they are written every 2000 blocks or when the
    /// UTXO cache exceeds `-dbcache` (block download).
    pub fn process(&self, block: &Block, flush_now: bool) -> Result<SinkOutcome, BlockValidationState> {
        let block_hash = block.header.block_hash();

        // Write the data unless we already have it.
        let have = {
            let cs = self.chainstate.lock();
            cs.lookup_block_index(&block_hash)
                .map(|i| cs.block_index().get(i).status.has_data())
                .unwrap_or(false)
        };
        let pos = if have {
            None
        } else {
            let p = self.block_files.write_block(block, self.magic_bytes).map_err(|e| {
                let mut s = BlockValidationState::new();
                s.error(&format!("block file write: {}", e));
                s
            })?;
            Some((p.file, p.pos))
        };

        let mut cs = self.chainstate.lock();
        let outcome = match cs.process_block(block, pos) {
            Ok(o) => o,
            Err(state) => {
                tracing::warn!(hash = %block_hash.to_hex(), reason = %state.get_reject_reason(), "block rejected");
                // Persist FAILED_VALID marks.
                let dirty = cs.dirty_block_indices();
                if !dirty.is_empty() {
                    let refs: Vec<&qubitcoin_common::chain::BlockIndex> = dirty.into_iter().collect();
                    self.block_index_db.write_block_indices(&refs);
                }
                cs.clear_dirty();
                return Err(state);
            }
        };
        let update = &outcome.update;
        for (i, state) in &update.invalid {
            tracing::warn!(
                hash = %cs.block_index().get(*i).block_hash.to_hex(),
                reason = %state.get_reject_reason(),
                "block found invalid during chain activation"
            );
        }
        if !update.disconnected.is_empty() {
            tracing::info!(
                disconnected = update.disconnected.len(),
                connected = update.connected.len(),
                new_tip = %cs.block_index().get(cs.tip().unwrap()).block_hash.to_hex(),
                "chain reorganisation"
            );
        }

        {
            let mut pending = self.pending_tx_index.lock();
            for c in &update.connected {
                let e = cs.block_index().get(c.arena_idx);
                for (i, tx) in c.block.vtx.iter().enumerate() {
                    pending.push((*tx.txid(), e.file, e.data_pos, i as u32));
                }
            }
        }
        self.events.chain_updated(&cs, update);

        let in_active_chain = {
            let e = cs.block_index().get(outcome.arena_idx);
            cs.active_chain().get_block_index(e.height) == Some(outcome.arena_idx)
        };
        let height = cs.height();
        if !update.connected.is_empty() && (height % 1000 == 0 || flush_now) {
            tracing::info!(height, hash = %cs.block_index().get(cs.tip().unwrap()).block_hash.to_hex(), "new best block");
        }

        let need_flush = {
            let mut n = self.blocks_since_flush.lock();
            *n += update.connected.len() as u64;
            flush_now || *n >= 2_000 || cs.coins_tip().dynamic_memory_usage() > self.dbcache_limit
        };
        if need_flush {
            self.persist(&mut cs);
        }
        // Fork point height for indexer rollback.
        let fork_height = update.fork_idx.map(|f| cs.block_index().get(f).height);
        drop(cs);

        if let Some(ref im) = self.indexer_manager {
            if let Some(h) = fork_height {
                im.on_reorg(h as u32);
                if let Some(ref d) = self.user_dag {
                    d.on_reorg(h as u32);
                }
            }
            for c in &update.connected {
                match serialize(&*c.block) {
                    Ok(bytes) => im.on_block_connected(c.height as u32, &bytes),
                    Err(e) => tracing::error!(error = %e, "serialize block for indexers"),
                }
            }
            // Standard indexers first; user nodes follow on their own pool.
            if let (Some(d), Some(last)) = (&self.user_dag, update.connected.last()) {
                d.notify_block(last.height as u32);
            }
        }
        Ok(SinkOutcome {
            new_block: outcome.new_block,
            in_active_chain,
        })
    }
}

/// The mining RPCs' sink: processes through the shared [`BlockProcessor`]
/// and flushes immediately.
pub struct DaemonBlockSink {
    pub processor: Arc<BlockProcessor>,
}

impl BlockSink for DaemonBlockSink {
    fn process_new_block(&self, block: &Block) -> Result<SinkOutcome, BlockValidationState> {
        self.processor.process(block, true)
    }
}

#[cfg(test)]
mod tests {
    //! Disk-backed reorganisation through the daemon's real storage stack
    //! (flat files, RocksDB UTXO/index/txindex), entering through the P2P
    //! `NodeInterface::process_block` and through `submitblock`.

    use super::*;
    use qubitcoin_common::chainparams::ChainParams;
    use qubitcoin_common::coins::Coin;
    use qubitcoin_consensus::block::BlockHeader;
    use qubitcoin_consensus::check::{check_proof_of_work, get_block_subsidy};
    use qubitcoin_consensus::merkle::block_merkle_root;
    use qubitcoin_consensus::transaction::{
        OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
    };
    use qubitcoin_net::net_processing::NodeInterface;
    use qubitcoin_node::block_storage::DiskBlockPos;
    use qubitcoin_node::mempool_accept::MemPoolAccept;
    use qubitcoin_node::miner::generate_coinbase_commitment;
    use qubitcoin_primitives::{Amount, BlockHash};
    use qubitcoin_script::Script;
    use std::path::PathBuf;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

    fn wsh_op_true() -> Script {
        let h = qubitcoin_crypto::hash::sha256_hash(&[0x51]);
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&h);
        Script::from_bytes(spk)
    }

    struct Node {
        dir: PathBuf,
        cs: Arc<parking_lot::Mutex<ChainstateManager>>,
        mempool: Arc<TxMemPool>,
        processor: Arc<BlockProcessor>,
        p2p: crate::LiveNodeInterface,
        coins_db: Arc<CoinsViewDB<RocksDatabase>>,
    }

    /// Open (or reopen) a regtest node in `dir`, as `main` does.
    fn open(dir: &PathBuf) -> Node {
        open_with(dir, None, None)
    }

    fn open_with(
        dir: &PathBuf,
        indexer_manager: Option<Arc<IndexerManager>>,
        on_tip: Option<Arc<dyn Fn(BlockHash) + Send + Sync>>,
    ) -> Node {
        std::fs::create_dir_all(dir.join("blocks/index")).unwrap();
        std::fs::create_dir_all(dir.join("chainstate")).unwrap();
        std::fs::create_dir_all(dir.join("txindex")).unwrap();
        let params = ChainParams::regtest();
        let coins_db = Arc::new(CoinsViewDB::new(RocksDatabase::open(dir.join("chainstate"), 8).unwrap(), true));
        let block_index_db = Arc::new(BlockIndexDB::new_unobfuscated(RocksDatabase::open(dir.join("blocks/index"), 8).unwrap()));
        let tx_index_db = Arc::new(TxIndexDB::new_unobfuscated(RocksDatabase::open(dir.join("txindex"), 8).unwrap()));
        let block_files = Arc::new(BlockFileManager::new(dir));
        let mut cs = ChainstateManager::new(params.clone(), Box::new(crate::ArcCoinsView { inner: coins_db.clone() }));
        let records = block_index_db.load_all();
        if records.is_empty() {
            let genesis = params.create_genesis_block();
            cs.load_genesis_block(&genesis).unwrap();
            cs.flush_coins(coins_db.as_ref());
            let pos = block_files.write_block(&genesis, MAGIC).unwrap();
            let gi = cs.lookup_block_index(&genesis.header.block_hash()).unwrap();
            let e = cs.block_index_mut().get_mut(gi);
            e.file = pos.file;
            e.data_pos = pos.pos;
            cs.mark_dirty(gi);
        } else {
            cs.load_block_index(&records).unwrap();
        }
        let (bf1, bf2, bf3) = (block_files.clone(), block_files.clone(), block_files.clone());
        cs.set_disk_access(
            Arc::new(move |file, pos| bf1.read_block(&DiskBlockPos { file, pos }).ok()),
            Arc::new(move |file, pos| bf2.read_undo(&DiskBlockPos { file, pos }).ok()),
            Arc::new(move |file, u: &qubitcoin_node::undo::BlockUndo| bf3.write_undo(file, u).ok().map(|p| p.pos)),
        );
        let cs = Arc::new(parking_lot::Mutex::new(cs));
        let mempool = Arc::new(TxMemPool::new());
        let node_state = Arc::new(NodeState::new("regtest"));
        let tip = { let c = cs.lock(); c.block_index().get(c.tip().unwrap()).block_hash };
        let events = Arc::new(ChainEvents {
            mempool: mempool.clone(),
            tip_watch: Arc::new(TipWatch::new(tip)),
            node_state: node_state.clone(),
            notifications: Arc::new(Notifications::default()),
            on_tip,
        });
        let processor = Arc::new(BlockProcessor {
            chainstate: cs.clone(),
            block_files: block_files.clone(),
            coins_db: coins_db.clone(),
            block_index_db,
            tx_index_db,
            indexer_manager,
            user_dag: None,
            magic_bytes: MAGIC,
            events,
            dbcache_limit: 1 << 30,
            blocks_since_flush: parking_lot::Mutex::new(0),
            pending_tx_index: parking_lot::Mutex::new(Vec::new()),
        });
        let p2p = crate::LiveNodeInterface {
            chainstate: cs.clone(),
            mempool: mempool.clone(),
            block_files,
            node_state,
            ibd_tracker: parking_lot::Mutex::new(crate::IbdTracker {
                last_log_time: std::time::Instant::now(),
                last_log_height: 0,
            }),
            processor: processor.clone(),
        };
        Node { dir: dir.clone(), cs, mempool, processor, p2p, coins_db }
    }

    fn tip(n: &Node) -> BlockHash {
        let c = n.cs.lock();
        c.block_index().get(c.tip().unwrap()).block_hash
    }

    fn block_on(n: &Node, parent: BlockHash, txs: Vec<TransactionRef>, fees: i64, tag: u8) -> Block {
        let c = n.cs.lock();
        let pidx = c.lookup_block_index(&parent).unwrap();
        let p = c.block_index().get(pidx);
        let height = p.height + 1;
        let mut sig = Script::new();
        sig.push_int(height as i64);
        sig.push_data(&[tag, 0x77]);
        let value = get_block_subsidy(height, c.consensus()).to_sat() + fees;
        let cb = Transaction::new(
            2,
            vec![TxIn { prevout: OutPoint::null(), script_sig: sig, sequence: SEQUENCE_FINAL, witness: Witness::new() }],
            vec![TxOut::new(Amount::from_sat(value), wsh_op_true())],
            0,
        );
        let mut vtx: Vec<TransactionRef> = vec![Arc::new(cb)];
        vtx.extend(txs);
        let mut b = Block {
            header: BlockHeader {
                version: 0x2000_0000,
                prev_blockhash: parent,
                merkle_root: Default::default(),
                time: (c.median_time_past(pidx) + 1).max(p.time as i64 + 1) as u32,
                bits: 0x207fffff,
                nonce: 0,
            },
            vtx,
        };
        generate_coinbase_commitment(&mut b, c.consensus(), height);
        let mut m = false;
        b.header.merkle_root = block_merkle_root(&b.vtx, &mut m);
        while !check_proof_of_work(&b.header.block_hash().into_uint256(), b.header.bits, c.consensus()) {
            b.header.nonce += 1;
        }
        b
    }

    fn p2p(n: &Node, b: &Block) -> bool {
        n.p2p.process_block(&serialize(b).unwrap()).unwrap()
    }

    /// Hash of the persisted UTXO set (after a flush).
    fn utxo_hash(n: &Node) -> [u8; 32] {
        n.processor.flush();
        let mut coins: Vec<(OutPoint, Coin)> = n.coins_db.iter_all_coins();
        coins.sort_by(|a, b| (a.0.hash.as_bytes(), a.0.n).cmp(&(b.0.hash.as_bytes(), b.0.n)));
        let mut buf = Vec::new();
        for (op, c) in coins {
            buf.extend_from_slice(&serialize(&op).unwrap());
            buf.extend_from_slice(&serialize(&c).unwrap());
        }
        qubitcoin_crypto::hash::sha256_hash(&buf)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qbtc-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn test_p2p_two_deep_reorg_on_disk_survives_restart() {
        let dir = temp_dir("reorg");
        let n = open(&dir);
        let mut pre = Vec::new();
        for _ in 0..101 {
            let b = block_on(&n, tip(&n), vec![], 0, 0);
            assert!(p2p(&n, &b));
            pre.push(b);
        }
        let fork = tip(&n);
        let c0 = OutPoint::new(*pre[0].vtx[0].txid(), 0);
        let v0 = pre[0].vtx[0].vout[0].value.to_sat();
        let t1 = Arc::new(Transaction::new(
            2,
            vec![TxIn { prevout: c0, script_sig: Script::new(), sequence: SEQUENCE_FINAL, witness: Witness { stack: vec![vec![0x51]] } }],
            vec![TxOut::new(Amount::from_sat(v0 - 1000), wsh_op_true())],
            0,
        ));
        {
            let c = n.cs.lock();
            MemPoolAccept::new(&c, &n.mempool).accept_single(&t1, false).unwrap();
        }
        let a1 = block_on(&n, fork, vec![t1.clone()], 1000, 0xa);
        assert!(p2p(&n, &a1));
        assert_eq!(n.mempool.size(), 0);
        let a2 = block_on(&n, a1.block_hash(), vec![], 0, 0xa);
        assert!(p2p(&n, &a2));

        // Side branch, delivered over "P2P"; B1/B2 stored, B3 reorganises.
        let b1 = block_on(&n, fork, vec![], 0, 0xb);
        assert!(!p2p(&n, &b1));
        let b2 = block_on(&n, b1.block_hash(), vec![], 0, 0xb);
        assert!(!p2p(&n, &b2));
        assert_eq!(tip(&n), a2.block_hash());
        let b3 = block_on(&n, b2.block_hash(), vec![], 0, 0xb);
        assert!(p2p(&n, &b3));
        assert_eq!(tip(&n), b3.block_hash());
        assert!(n.mempool.exists(t1.txid()), "disconnected tx returns to the mempool");

        // Expected UTXO set: an in-memory replay of genesis..fork + B.
        let expected_b = {
            let params = ChainParams::regtest();
            let mut mem = ChainstateManager::new(params.clone(), Box::new(qubitcoin_common::coins::EmptyCoinsView));
            mem.load_genesis_block(&params.create_genesis_block()).unwrap();
            for b in pre.iter().chain([&b1, &b2, &b3]) {
                assert!(mem.process_new_block(b).unwrap().0);
            }
            let mut coins = mem.coins_tip().iter_coins();
            coins.sort_by(|a, b| (a.0.hash.as_bytes(), a.0.n).cmp(&(b.0.hash.as_bytes(), b.0.n)));
            let mut buf = Vec::new();
            for (op, c) in coins {
                buf.extend_from_slice(&serialize(&op).unwrap());
                buf.extend_from_slice(&serialize(&c).unwrap());
            }
            qubitcoin_crypto::hash::sha256_hash(&buf)
        };
        assert_eq!(utxo_hash(&n), expected_b);

        // Restart from disk, then reorganise back to A: disconnecting B
        // needs the undo data written to rev files before the restart.
        drop(n);
        let n = open(&dir);
        assert_eq!(tip(&n), b3.block_hash());
        let a3 = block_on(&n, a2.block_hash(), vec![], 0, 0xa);
        assert!(!p2p(&n, &a3));
        let a4 = block_on(&n, a3.block_hash(), vec![], 0, 0xa);
        assert!(p2p(&n, &a4));
        assert_eq!(tip(&n), a4.block_hash());
        // t1 is confirmed in A1 again.
        let c = n.cs.lock();
        assert!(c.coins_tip().fetch_coin(&OutPoint::new(*t1.txid(), 0)).is_some());
        drop(c);
        let _ = std::fs::remove_dir_all(&n.dir);
    }

    #[test]
    fn test_submitblock_side_branch_then_reorg_on_disk() {
        use qubitcoin_rpc::mining::{submit_block, MiningContext};
        let dir = temp_dir("submit");
        let n = open(&dir);
        for _ in 0..3 {
            let b = block_on(&n, tip(&n), vec![], 0, 0);
            assert!(p2p(&n, &b));
        }
        let fork = tip(&n);
        let tip_watch = n.processor.events.tip_watch.clone();
        let ctx = MiningContext::new(
            n.cs.clone(),
            n.mempool.clone(),
            Arc::new(DaemonBlockSink { processor: n.processor.clone() }),
            tip_watch,
            Default::default(),
            Arc::new(|| 0),
            true,
            "regtest",
            false,
        );
        let a1 = block_on(&n, fork, vec![], 0, 0xa);
        assert_eq!(submit_block(&ctx, a1.clone()).unwrap(), serde_json::Value::Null);
        let b1 = block_on(&n, fork, vec![], 0, 0xb);
        assert_eq!(submit_block(&ctx, b1.clone()).unwrap(), serde_json::json!("inconclusive"));
        assert_eq!(submit_block(&ctx, b1.clone()).unwrap(), serde_json::json!("duplicate"));
        let b2 = block_on(&n, b1.block_hash(), vec![], 0, 0xb);
        assert_eq!(submit_block(&ctx, b2.clone()).unwrap(), serde_json::Value::Null, "heavier side branch reorganises");
        assert_eq!(tip(&n), b2.block_hash());
        // An invalid heavier extension of A is rejected and changes nothing.
        let a2 = block_on(&n, a1.block_hash(), vec![], 0, 0xa);
        assert_eq!(submit_block(&ctx, a2.clone()).unwrap(), serde_json::json!("inconclusive"));
        let mut bad = block_on(&n, a2.block_hash(), vec![], 0, 0xa);
        let cb = &bad.vtx[0];
        let mut vout = cb.vout.clone();
        vout[0].value = vout[0].value + Amount::from_sat(1);
        bad.vtx[0] = Arc::new(Transaction::new(cb.version, cb.vin.clone(), vout, cb.lock_time));
        qubitcoin_node::miner::regenerate_commitments(&mut bad, &ChainParams::regtest().consensus, 6);
        while !check_proof_of_work(&bad.header.block_hash().into_uint256(), bad.header.bits, &ChainParams::regtest().consensus) {
            bad.header.nonce += 1;
        }
        let before = utxo_hash(&n);
        assert_eq!(submit_block(&ctx, bad).unwrap(), serde_json::json!("bad-cb-amount"));
        assert_eq!(tip(&n), b2.block_hash(), "rolled back to B after the failed reorg");
        assert_eq!(utxo_hash(&n), before);
        let _ = std::fs::remove_dir_all(&n.dir);
    }

    /// Counts transactions: `/txs` += tx count of each block; view `txs`.
    const SEC_WAT: &str = r#"
(module
  (import "env" "__host_len" (func $host_len (result i32)))
  (import "env" "__load_input" (func $load_input (param i32)))
  (import "env" "__flush" (func $flush (param i32)))
  (import "env" "__get" (func $get (param i32 i32)))
  (import "env" "__get_len" (func $get_len (param i32) (result i32)))
  (memory (export "memory") 64)
  (data (i32.const 0xFC) "\04\00\00\00/txs")
  (data (i32.const 0x3FC) "\0c\00\00\00\0a\04/txs\0a\04\00\00\00\00")
  (func $read_u32 (param $key i32) (result i32)
    (if (result i32) (i32.eq (call $get_len (local.get $key)) (i32.const 4))
      (then (call $get (local.get $key) (i32.const 0x200)) (i32.load (i32.const 0x200)))
      (else (i32.const 0))))
  (func (export "_start")
    (drop (call $host_len))
    (call $load_input (i32.const 0x10000))
    (i32.store (i32.const 0x408)
      (i32.add (call $read_u32 (i32.const 0x100)) (i32.load8_u (i32.const 0x10054))))
    (call $flush (i32.const 0x400)))
  (func (export "txs") (result i32)
    (i32.store (i32.const 0x2FC) (call $get_len (i32.const 0x100)))
    (call $get (i32.const 0x100) (i32.const 0x300))
    (i32.const 0x300))
)
"#;

    #[test]
    fn test_simulateblock_over_live_chain_touches_nothing_and_expires_on_new_tip() {
        use qubitcoin_indexer::simulation::{SimConfig, SimRequest, SimulationEngine};
        use qubitcoin_indexer::{config::IndexerConfig, store, IndexerMode};
        let dir = temp_dir("sim");
        std::fs::create_dir_all(&dir).unwrap();
        let wasm = dir.join("sec.wasm");
        std::fs::write(&wasm, wat::parse_str(SEC_WAT).unwrap()).unwrap();
        let mut cfg = IndexerConfig::new("sec", wasm);
        cfg.fork_runner = true;
        let im = Arc::new(IndexerManager::new(vec![cfg], &dir.join("idx"), IndexerMode::Synchronous).unwrap());
        let slot: Arc<std::sync::OnceLock<Arc<SimulationEngine>>> = Arc::new(std::sync::OnceLock::new());
        let s2 = slot.clone();
        let hook: Arc<dyn Fn(BlockHash) + Send + Sync> = Arc::new(move |h: BlockHash| {
            if let Some(e) = s2.get() {
                e.on_tip_changed(*h.data());
            }
        });
        let n = open_with(&dir, Some(im.clone()), Some(hook));
        let mut blocks = vec![];
        for _ in 0..3 {
            let b = block_on(&n, tip(&n), vec![], 0, 0);
            assert!(p2p(&n, &b));
            blocks.push(b);
        }
        assert_eq!(im.indexer_height("sec"), Some(3));
        let cs2 = n.cs.clone();
        let engine = Arc::new(SimulationEngine::new(
            im.shared(),
            Arc::new(move || sim_tip(&cs2.lock())),
            SimConfig::default(),
        ));
        slot.set(engine.clone()).ok().unwrap();

        let utxo_before = utxo_hash(&n);
        let tip_before = tip(&n);
        let db = im.get_indexer("sec").unwrap().db.clone();
        let idx_before = store::dump(&db);
        let spend = Transaction::new(
            2,
            vec![TxIn {
                prevout: OutPoint::new(*blocks[0].vtx[0].txid(), 0),
                script_sig: Script::new(),
                sequence: SEQUENCE_FINAL,
                witness: Witness { stack: vec![vec![0x51]] },
            }],
            vec![TxOut::new(Amount::from_sat(1000), wsh_op_true())],
            0,
        );
        let r = engine
            .simulate(SimRequest { txs: vec![serialize(&spend).unwrap()], ..Default::default() })
            .unwrap();
        assert_eq!(r["height"], 4);
        assert_eq!(r["per_indexer"]["sec"]["ok"], true, "{}", r);
        let id = r["overlay_id"].as_str().unwrap().to_string();
        let v = engine.view(&id, "sec", "txs", vec![]).unwrap();
        assert_eq!(u32::from_le_bytes(v[..4].try_into().unwrap()), 3 + 2);
        // The simulated block is never submitted and nothing persistent moved.
        assert_eq!(tip(&n), tip_before);
        assert_eq!(n.cs.lock().height(), 3);
        assert_eq!(utxo_hash(&n), utxo_before);
        assert_eq!(store::dump(&db), idx_before);
        assert_eq!(n.mempool.size(), 0);

        // A new tip fires the hook and drops the overlay.
        let b = block_on(&n, tip(&n), vec![], 0, 0);
        assert!(p2p(&n, &b));
        assert!(engine.overlay(&id).is_none());
        assert_eq!(im.indexer_height("sec"), Some(4));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
