//! Chain reorganisation regression tests (real consensus validation).
//!
//! Covers the side-branch handling ported from Bitcoin Core's
//! `AcceptBlock` / `ActivateBestChain`: side-branch blocks are stored and
//! only connected once their chain has the most work; a reorganisation
//! disconnects back to the fork with undo data and connects the new branch;
//! an invalid block met while connecting is marked invalid and the previous
//! chain is restored. UTXO-set commitments are compared against a fresh
//! replay of the expected chain and against the pre-reorg state.

use std::sync::Arc;

use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::{CoinsView, EmptyCoinsView};
use qubitcoin_common::chain::BlockStatus;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::check::{check_proof_of_work, get_block_subsidy};
use qubitcoin_consensus::merkle::block_merkle_root;
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_node::mempool_accept::{update_mempool_for_chain_update, MemPoolAccept};
use qubitcoin_node::miner::generate_coinbase_commitment;
use qubitcoin_primitives::{Amount, BlockHash};
use qubitcoin_script::Script;
use qubitcoin_serialize::serialize;

fn wsh_op_true() -> Script {
    let h = qubitcoin_crypto::hash::sha256_hash(&[0x51]);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&h);
    Script::from_bytes(spk)
}

fn new_chain() -> ChainstateManager {
    let params = ChainParams::regtest();
    let mut cs = ChainstateManager::new(params.clone(), Box::new(EmptyCoinsView));
    cs.load_genesis_block(&params.create_genesis_block()).unwrap();
    cs
}

/// Build a solved block on `parent` with `txs`; `tag` makes coinbases of
/// competing branches differ; `overpay` adds satoshis to the coinbase.
fn block_on(cs: &ChainstateManager, parent: BlockHash, txs: Vec<TransactionRef>, fees: i64, tag: u8, overpay: i64) -> Block {
    let pidx = cs.lookup_block_index(&parent).expect("parent known");
    let pentry = cs.block_index().get(pidx);
    let height = pentry.height + 1;
    let mut sig = Script::new();
    sig.push_int(height as i64);
    sig.push_data(&[tag, 0xab]);
    let value = get_block_subsidy(height, cs.consensus()).to_sat() + fees + overpay;
    let cb = Transaction::new(
        2,
        vec![TxIn { prevout: OutPoint::null(), script_sig: sig, sequence: SEQUENCE_FINAL, witness: Witness::new() }],
        vec![TxOut::new(Amount::from_sat(value), wsh_op_true())],
        0,
    );
    let mut vtx: Vec<TransactionRef> = vec![Arc::new(cb)];
    vtx.extend(txs);
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: parent,
            merkle_root: Default::default(),
            time: (cs.median_time_past(pidx) + 1).max(pentry.time as i64 + 1) as u32,
            bits: 0x207fffff,
            nonce: 0,
        },
        vtx,
    };
    generate_coinbase_commitment(&mut block, cs.consensus(), height);
    let mut mutated = false;
    block.header.merkle_root = block_merkle_root(&block.vtx, &mut mutated);
    while !check_proof_of_work(&block.header.block_hash().into_uint256(), block.header.bits, cs.consensus()) {
        block.header.nonce += 1;
    }
    block
}

fn tip_hash(cs: &ChainstateManager) -> BlockHash {
    cs.block_index().get(cs.tip().unwrap()).block_hash
}

fn spend(prevout: OutPoint, value: i64, fee: i64) -> TransactionRef {
    Arc::new(Transaction::new(
        2,
        vec![TxIn { prevout, script_sig: Script::new(), sequence: SEQUENCE_FINAL, witness: Witness { stack: vec![vec![0x51]] } }],
        vec![TxOut::new(Amount::from_sat(value - fee), wsh_op_true())],
        0,
    ))
}

/// A commitment to the full UTXO set (the in-memory chain keeps every coin
/// in the tip cache): SHA256 over sorted (outpoint, coin) serializations.
fn utxo_hash(cs: &ChainstateManager) -> [u8; 32] {
    let mut coins = cs.coins_tip().iter_coins();
    coins.sort_by(|a, b| (a.0.hash.as_bytes(), a.0.n).cmp(&(b.0.hash.as_bytes(), b.0.n)));
    let mut buf = Vec::new();
    for (op, coin) in coins {
        buf.extend_from_slice(&serialize(&op).unwrap());
        buf.extend_from_slice(&serialize(&coin).unwrap());
    }
    qubitcoin_crypto::hash::sha256_hash(&buf)
}

/// Common prefix: genesis + 101 blocks so two coinbases are mature.
fn prefix() -> (ChainstateManager, Vec<Block>) {
    let mut cs = new_chain();
    let mut blocks = Vec::new();
    for _ in 0..101 {
        let b = block_on(&cs, tip_hash(&cs), vec![], 0, 0, 0);
        assert!(cs.process_new_block(&b).unwrap().0);
        blocks.push(b);
    }
    (cs, blocks)
}

fn replay(blocks: &[Block]) -> [u8; 32] {
    let mut cs = new_chain();
    for b in blocks {
        assert!(cs.process_new_block(b).unwrap().0, "replay block connects");
    }
    utxo_hash(&cs)
}

fn coin(b: &Block) -> (OutPoint, i64) {
    (OutPoint::new(*b.vtx[0].txid(), 0), b.vtx[0].vout[0].value.to_sat())
}

#[test]
fn test_two_deep_reorg_and_round_trip() {
    let (mut cs, pre) = prefix();
    let fork = tip_hash(&cs);
    let pool = TxMemPool::new();
    let (c0, v0) = coin(&pre[0]);
    let (c1, v1) = coin(&pre[1]);

    // Branch A: A1 carries t1 (from the mempool), A2 empty.
    let t1 = spend(c0.clone(), v0, 1_000);
    MemPoolAccept::new(&cs, &pool).accept_single(&t1, false).unwrap();
    let a1 = block_on(&cs, fork, vec![t1.clone()], 1_000, 0xa, 0);
    let out = cs.process_block(&a1, None).unwrap();
    update_mempool_for_chain_update(&cs, &pool, &out.update);
    assert_eq!(pool.size(), 0);
    let a2 = block_on(&cs, a1.block_hash(), vec![], 0, 0xa, 0);
    cs.process_block(&a2, None).unwrap();
    assert_eq!(tip_hash(&cs), a2.block_hash());
    let a_tip_hash = utxo_hash(&cs);

    // Branch B from the fork: B1 carries t2 (a different coin).
    let t2 = spend(c1.clone(), v1, 2_000);
    let b1 = block_on(&cs, fork, vec![t2.clone()], 2_000, 0xb, 0);
    let b2 = block_on_after(&cs, &b1, vec![], 0xb);
    let o = cs.process_block(&b1, None).unwrap();
    assert!(!o.update.tip_changed(), "less work: stored, not connected");
    let o = cs.process_block(&b2, None).unwrap();
    assert!(!o.update.tip_changed(), "equal work: first-seen tip stays");
    assert_eq!(tip_hash(&cs), a2.block_hash());
    assert_eq!(utxo_hash(&cs), a_tip_hash, "storing side blocks does not touch the UTXO set");

    // B3 makes B heavier: 2-deep reorg.
    let b3 = block_on_after_store(&cs, &b2, 0xb);
    let o = cs.process_block(&b3, None).unwrap();
    assert_eq!(tip_hash(&cs), b3.block_hash());
    let disc: Vec<BlockHash> = o.update.disconnected.iter().map(|(_, b)| b.block_hash()).collect();
    assert_eq!(disc, vec![a2.block_hash(), a1.block_hash()]);
    let conn: Vec<BlockHash> = o.update.connected.iter().map(|c| c.block.block_hash()).collect();
    assert_eq!(conn, vec![b1.block_hash(), b2.block_hash(), b3.block_hash()]);
    let mut expected_b = pre.clone();
    expected_b.extend([b1.clone(), b2.clone(), b3.clone()]);
    assert_eq!(utxo_hash(&cs), replay(&expected_b), "UTXO set equals a fresh replay of the B chain");

    // Mempool: t1 (in disconnected A1, not in B) comes back.
    update_mempool_for_chain_update(&cs, &pool, &o.update);
    assert!(pool.exists(t1.txid()));
    assert!(!pool.exists(t2.txid()));

    // Round trip: A3 (equal work, no reorg), A4 (reorg back).
    let a3 = block_on_after_store(&cs, &a2, 0xa);
    assert!(!cs.process_block(&a3, None).unwrap().update.tip_changed());
    let a4 = block_on_after_store(&cs, &a3, 0xa);
    let o = cs.process_block(&a4, None).unwrap();
    assert_eq!(tip_hash(&cs), a4.block_hash());
    assert_eq!(o.update.disconnected.len(), 3);
    assert_eq!(o.update.connected.len(), 4);
    let mut expected_a = pre.clone();
    expected_a.extend([a1.clone(), a2.clone(), a3.clone(), a4.clone()]);
    assert_eq!(utxo_hash(&cs), replay(&expected_a), "UTXO set equals a fresh replay of the A chain");
    // t1 is confirmed again; t2 is back in the pool.
    update_mempool_for_chain_update(&cs, &pool, &o.update);
    assert!(!pool.exists(t1.txid()));
    assert!(pool.exists(t2.txid()));
}

/// A block on `prev`, which need not be known to `cs` yet (only its
/// parent must be).
fn block_on_after(cs: &ChainstateManager, prev: &Block, txs: Vec<TransactionRef>, tag: u8) -> Block {
    let parent_idx = cs.lookup_block_index(&prev.header.prev_blockhash).expect("grandparent known");
    let height = cs.block_index().get(parent_idx).height + 2;
    let mut sig = Script::new();
    sig.push_int(height as i64);
    sig.push_data(&[tag, 0xcd]);
    let value = get_block_subsidy(height, cs.consensus()).to_sat();
    let cb = Transaction::new(
        2,
        vec![TxIn { prevout: OutPoint::null(), script_sig: sig, sequence: SEQUENCE_FINAL, witness: Witness::new() }],
        vec![TxOut::new(Amount::from_sat(value), wsh_op_true())],
        0,
    );
    let mut vtx: Vec<TransactionRef> = vec![Arc::new(cb)];
    vtx.extend(txs);
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: prev.block_hash(),
            merkle_root: Default::default(),
            time: prev.header.time + 1,
            bits: 0x207fffff,
            nonce: 0,
        },
        vtx,
    };
    generate_coinbase_commitment(&mut block, cs.consensus(), height);
    let mut mutated = false;
    block.header.merkle_root = block_merkle_root(&block.vtx, &mut mutated);
    while !check_proof_of_work(&block.header.block_hash().into_uint256(), block.header.bits, cs.consensus()) {
        block.header.nonce += 1;
    }
    block
}

/// A block on `prev`, which is already stored in `cs`.
fn block_on_after_store(cs: &ChainstateManager, prev: &Block, tag: u8) -> Block {
    block_on(cs, prev.block_hash(), vec![], 0, tag, 0)
}

#[test]
fn test_invalid_side_branch_tip_restores_chain() {
    let (mut cs, _pre) = prefix();
    let fork = tip_hash(&cs);
    let a1 = block_on(&cs, fork, vec![], 0, 0xa, 0);
    cs.process_block(&a1, None).unwrap();
    let a2 = block_on_after_store(&cs, &a1, 0xa);
    cs.process_block(&a2, None).unwrap();
    let before = utxo_hash(&cs);

    let b1 = block_on(&cs, fork, vec![], 0, 0xb, 0);
    cs.process_block(&b1, None).unwrap();
    let b2 = block_on_after_store(&cs, &b1, 0xb);
    cs.process_block(&b2, None).unwrap();
    // B3 pays its coinbase one satoshi too much: only ConnectBlock can tell.
    let b3 = block_on(&cs, b2.block_hash(), vec![], 0, 0xb, 1);
    let err = cs.process_block(&b3, None).unwrap_err();
    assert_eq!(err.get_reject_reason(), "bad-cb-amount");
    assert_eq!(tip_hash(&cs), a2.block_hash(), "equal-work first-seen chain restored");
    assert_eq!(utxo_hash(&cs), before, "UTXO set identical after the failed reorg round trip");
    let b3_idx = cs.lookup_block_index(&b3.block_hash()).unwrap();
    assert!(cs.block_index().get(b3_idx).status.has_failed());

    // Building on the invalid block is refused at the header.
    let b4 = block_on(&cs, b3.block_hash(), vec![], 0, 0xb, 0);
    assert!(cs.process_block(&b4, None).is_err());
    assert_eq!(utxo_hash(&cs), before);
}

#[test]
fn test_invalid_block_mid_branch_marks_descendants() {
    let (mut cs, pre) = prefix();
    let fork = tip_hash(&cs);
    let a1 = block_on(&cs, fork, vec![], 0, 0xa, 0);
    cs.process_block(&a1, None).unwrap();
    let a2 = block_on_after_store(&cs, &a1, 0xa);
    cs.process_block(&a2, None).unwrap();
    let before = utxo_hash(&cs);

    let b1 = block_on(&cs, fork, vec![], 0, 0xb, 0);
    cs.process_block(&b1, None).unwrap();
    // B2 spends a coin that does not exist.
    let ghost = spend(OutPoint::new(*pre[5].vtx[0].txid(), 7), 1_000_000, 0);
    let b2 = block_on(&cs, b1.block_hash(), vec![ghost], 0, 0xb, 0);
    // Context-free checks pass, it is stored (equal work, not connected).
    let o = cs.process_block(&b2, None).unwrap();
    assert!(!o.update.tip_changed());
    let b3 = block_on_after_store(&cs, &b2, 0xb);
    let o = cs.process_block(&b3, None).unwrap();
    assert_eq!(o.update.invalid.len(), 1);
    assert_eq!(o.update.invalid[0].1.get_reject_reason(), "bad-txns-inputs-missingorspent");
    assert_eq!(tip_hash(&cs), a2.block_hash());
    assert_eq!(utxo_hash(&cs), before);
    let b3_idx = cs.lookup_block_index(&b3.block_hash()).unwrap();
    assert!(cs.block_index().get(b3_idx).status.contains(BlockStatus::FAILED_CHILD));
    // A later heavier valid chain still wins.
    let a3 = block_on_after_store(&cs, &a2, 0xa);
    cs.process_block(&a3, None).unwrap();
    assert_eq!(tip_hash(&cs), a3.block_hash());
}

#[test]
fn test_out_of_order_side_branch_links_when_parent_arrives() {
    let (mut cs, _pre) = prefix();
    let fork = tip_hash(&cs);
    let a1 = block_on(&cs, fork, vec![], 0, 0xa, 0);
    cs.process_block(&a1, None).unwrap();

    let b1 = block_on(&cs, fork, vec![], 0, 0xb, 0);
    let b2 = block_on_after(&cs, &b1, vec![], 0xb);
    // Headers first (as P2P does), then B2's data before B1's.
    cs.accept_block_header(&b1.header).unwrap();
    cs.accept_block_header(&b2.header).unwrap();
    let o = cs.process_block(&b2, None).unwrap();
    assert!(!o.update.tip_changed(), "B2 cannot connect without B1's data");
    let o = cs.process_block(&b1, None).unwrap();
    assert_eq!(o.update.connected.len(), 2);
    assert_eq!(tip_hash(&cs), b2.block_hash());
    assert!(cs.coins_tip().get_coin(&OutPoint::new(*b2.vtx[0].txid(), 0)).is_some());
    assert!(cs.coins_tip().get_coin(&OutPoint::new(*a1.vtx[0].txid(), 0)).is_none());
}
