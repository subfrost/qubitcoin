//! Integration tests for `qubitcoin_node::miner::BlockAssembler` on regtest,
//! with real consensus validation (the chainstate's unit-test stubs are not
//! compiled into integration tests).
//!
//! Mirrors the intent of Bitcoin Core's `src/test/miner_tests.cpp`:
//! ancestor-feerate (CPFP) ordering, fee accounting in the coinbase,
//! prioritisetransaction deltas, the weight and min-fee limits, and
//! `TestBlockValidity`.

use std::sync::Arc;

use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::{CoinsView, EmptyCoinsView};
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::check::{check_proof_of_work, get_block_subsidy};
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::{accept_to_mempool, FeeRate, MempoolAcceptResult, TxMemPool};
use qubitcoin_node::miner::{
    get_witness_commitment_index, BlockAssembler, BlockAssemblerOptions, BlockTemplate,
    WITNESS_COMMITMENT_HEADER,
};
use qubitcoin_primitives::{Amount, Txid};
use qubitcoin_script::Script;

/// P2WSH(OP_TRUE): anyone can spend with the witness `[OP_TRUE]`.
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

fn solve(block: &mut Block, cs: &ChainstateManager) {
    while !check_proof_of_work(
        &block.header.block_hash().into_uint256(),
        block.header.bits,
        cs.consensus(),
    ) {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
}

fn template(cs: &ChainstateManager, pool: &TxMemPool, opts: BlockAssemblerOptions) -> BlockTemplate {
    BlockAssembler::new(cs, Some(pool), opts)
        .create_new_block(&wsh_op_true())
        .expect("create_new_block")
}

/// Mine one block from a template and connect it; returns the block.
fn mine(cs: &mut ChainstateManager, pool: &TxMemPool) -> Block {
    let mut block = template(cs, pool, BlockAssemblerOptions::default()).block;
    solve(&mut block, cs);
    let (on_tip, _) = cs.process_new_block(&block).expect("block connects");
    assert!(on_tip);
    pool.remove_for_block_txs(&block.vtx);
    block
}

/// Spend `prevout` (a P2WSH(OP_TRUE) output worth `value`) paying `fee`.
fn spend(prevout: OutPoint, value: i64, fee: i64) -> TransactionRef {
    Arc::new(Transaction::new(
        2,
        vec![TxIn {
            prevout,
            script_sig: Script::new(),
            sequence: SEQUENCE_FINAL,
            witness: Witness {
                stack: vec![vec![0x51]],
            },
        }],
        vec![TxOut::new(Amount::from_sat(value - fee), wsh_op_true())],
        0,
    ))
}

fn add(pool: &TxMemPool, cs: &ChainstateManager, tx: &TransactionRef, fee: i64) {
    match accept_to_mempool(
        pool,
        tx,
        Amount::from_sat(fee),
        tx.get_virtual_size() as u32,
        cs.height(),
    ) {
        MempoolAcceptResult::Accepted { .. } => {}
        MempoolAcceptResult::Rejected { reason } => panic!("mempool rejected: {}", reason),
    }
}

/// A chain with `n` mature coinbases; returns their (outpoint, value).
fn chain_with_mature_coins(n: usize) -> (ChainstateManager, TxMemPool, Vec<(OutPoint, i64)>) {
    let mut cs = new_chain();
    let pool = TxMemPool::new();
    let mut coinbases = Vec::new();
    for _ in 0..(100 + n) {
        let b = mine(&mut cs, &pool);
        coinbases.push((OutPoint::new(*b.vtx[0].txid(), 0), b.vtx[0].vout[0].value.to_sat()));
    }
    coinbases.truncate(n);
    (cs, pool, coinbases)
}

fn txids(block: &Block) -> Vec<Txid> {
    block.vtx.iter().skip(1).map(|t| *t.txid()).collect()
}

#[test]
fn test_empty_template_shape() {
    let cs = new_chain();
    let pool = TxMemPool::new();
    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(t.height, 1);
    assert_eq!(t.block.vtx.len(), 1);
    let cb = &t.block.vtx[0];
    // BIP34 height push then OP_0.
    assert_eq!(cb.vin[0].script_sig.as_bytes(), &[0x51, 0x00]);
    assert_eq!(cb.vout[0].value, get_block_subsidy(1, cs.consensus()));
    // Witness commitment is always added while segwit is active (Core's
    // GenerateCoinbaseCommitment), with the zero reserved value.
    assert_eq!(get_witness_commitment_index(&t.block), Some(1));
    assert_eq!(t.coinbase_commitment[..6], WITNESS_COMMITMENT_HEADER);
    assert_eq!(cb.vin[0].witness.stack, vec![vec![0u8; 32]]);
    assert_eq!(t.tx_fees, vec![Amount::ZERO]);
    assert_eq!(t.block.header.bits, 0x207fffff);
    assert_eq!(t.block.header.prev_blockhash, cs.params().genesis_block_hash);
}

#[test]
fn test_cpfp_package_ordering_and_fees() {
    let (mut cs, pool, coins) = chain_with_mature_coins(2);
    let (op_a, val_a) = coins[0].clone();
    let (op_b, val_b) = coins[1].clone();

    // Low-fee parent with a high-fee child (CPFP), and an unrelated tx in
    // between: package feerate of parent+child beats the unrelated tx.
    let parent = spend(op_a, val_a, 100);
    let child = spend(OutPoint::new(*parent.txid(), 0), val_a - 100, 50_000);
    let other = spend(op_b, val_b, 5_000);
    add(&pool, &cs, &parent, 100);
    add(&pool, &cs, &child, 50_000);
    add(&pool, &cs, &other, 5_000);

    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(txids(&t.block), vec![*parent.txid(), *child.txid(), *other.txid()]);
    assert_eq!(t.total_fees, Amount::from_sat(55_100));
    assert_eq!(
        t.tx_fees,
        vec![
            Amount::from_sat(-55_100),
            Amount::from_sat(100),
            Amount::from_sat(50_000),
            Amount::from_sat(5_000)
        ]
    );
    // OP_TRUE witness scripts carry no sigops.
    assert!(t.tx_sigops_cost.iter().all(|&s| s == 0));
    let height = cs.height() + 1;
    assert_eq!(
        t.block.vtx[0].vout[0].value,
        get_block_subsidy(height, cs.consensus()) + Amount::from_sat(55_100)
    );

    // Solve and connect: the tip advances and the mempool drains.
    let mut block = t.block.clone();
    solve(&mut block, &cs);
    let (on_tip, _) = cs.process_new_block(&block).expect("template block valid");
    assert!(on_tip);
    assert_eq!(cs.height(), height);
    pool.remove_for_block_txs(&block.vtx);
    assert_eq!(pool.size(), 0);
    // The child's output is now a confirmed coin.
    assert!(cs.coins_tip().get_coin(&OutPoint::new(*child.txid(), 0)).is_some());
}

#[test]
fn test_prioritisetransaction_reorders_but_coinbase_pays_real_fees() {
    let (cs, pool, coins) = chain_with_mature_coins(2);
    let a = spend(coins[0].0.clone(), coins[0].1, 1_000);
    let b = spend(coins[1].0.clone(), coins[1].1, 2_000);
    add(&pool, &cs, &a, 1_000);
    add(&pool, &cs, &b, 2_000);

    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(txids(&t.block), vec![*b.txid(), *a.txid()]);

    pool.prioritise_transaction(a.txid(), 10_000);
    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(txids(&t.block), vec![*a.txid(), *b.txid()]);
    // The delta changes selection only; the coinbase claims actual fees.
    assert_eq!(t.total_fees, Amount::from_sat(3_000));

    let pr = pool.get_prioritised_transactions();
    assert_eq!(pr.len(), 1);
    assert_eq!(pr[0].delta, 10_000);
    assert!(pr[0].in_mempool);
    assert_eq!(pr[0].modified_fee, Some(Amount::from_sat(11_000)));
}

#[test]
fn test_negative_delta_below_min_fee_excludes() {
    let (cs, pool, coins) = chain_with_mature_coins(1);
    let a = spend(coins[0].0.clone(), coins[0].1, 1_000);
    add(&pool, &cs, &a, 1_000);
    pool.prioritise_transaction(a.txid(), -1_000_000);
    let opts = BlockAssemblerOptions {
        block_min_fee_rate: FeeRate::new(1000),
        ..Default::default()
    };
    let t = template(&cs, &pool, opts);
    assert!(txids(&t.block).is_empty());
}

#[test]
fn test_block_min_fee_rate_and_max_weight() {
    let (cs, pool, coins) = chain_with_mature_coins(2);
    let cheap = spend(coins[0].0.clone(), coins[0].1, 50); // < 1 sat/vB
    let rich = spend(coins[1].0.clone(), coins[1].1, 10_000);
    add(&pool, &cs, &cheap, 50);
    add(&pool, &cs, &rich, 10_000);

    // Default floor (0, following the relay floor) mines both.
    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(t.block.vtx.len(), 3);

    let t = template(
        &cs,
        &pool,
        BlockAssemblerOptions {
            block_min_fee_rate: FeeRate::new(1000),
            ..Default::default()
        },
    );
    assert_eq!(txids(&t.block), vec![*rich.txid()]);

    // A weight limit at the coinbase reserve leaves room for nothing.
    let t = template(
        &cs,
        &pool,
        BlockAssemblerOptions {
            block_max_weight: 4000,
            ..Default::default()
        },
    );
    assert_eq!(t.block.vtx.len(), 1);
}

#[test]
fn test_immature_coinbase_spend_is_skipped() {
    let (mut cs, pool, coins) = chain_with_mature_coins(1);
    let mature = spend(coins[0].0.clone(), coins[0].1, 1_000);
    add(&pool, &cs, &mature, 1_000);

    // accept_to_mempool does not check coinbase maturity, so a spend of the
    // newest coinbase (and its child) gets in; the assembler must still
    // build a valid block by leaving them out.
    let fresh = mine(&mut cs, &TxMemPool::new());
    let value = fresh.vtx[0].vout[0].value.to_sat();
    let immature = spend(OutPoint::new(*fresh.vtx[0].txid(), 0), value, 1_000);
    let immature_child = spend(OutPoint::new(*immature.txid(), 0), value - 1_000, 1_000);
    add(&pool, &cs, &immature, 1_000);
    add(&pool, &cs, &immature_child, 1_000);

    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert_eq!(txids(&t.block), vec![*mature.txid()]);
}

#[test]
fn test_test_block_validity_rejects_without_mutating_utxo() {
    let (cs, pool, coins) = chain_with_mature_coins(1);
    let a = spend(coins[0].0.clone(), coins[0].1, 1_000);
    add(&pool, &cs, &a, 1_000);
    let t = template(&cs, &pool, BlockAssemblerOptions::default());
    assert!(cs.test_block_validity(&t.block, false, true).is_ok());
    // Validity checking must not spend the coin in the live cache.
    assert!(cs.coins_tip().get_coin(&coins[0].0).is_some());

    // Overpaying coinbase -> bad-cb-amount.
    let mut bad = t.block.clone();
    let cb = &bad.vtx[0];
    let mut vout = cb.vout.clone();
    vout[0].value = vout[0].value + Amount::from_sat(1);
    bad.vtx[0] = Arc::new(Transaction::new(cb.version, cb.vin.clone(), vout, cb.lock_time));
    qubitcoin_node::miner::regenerate_commitments(&mut bad, cs.consensus(), t.height);
    let err = cs.test_block_validity(&bad, false, true).unwrap_err();
    assert_eq!(err.get_reject_reason(), "bad-cb-amount");

    // Wrong parent -> inconclusive-not-best-prevblk.
    let mut stale = t.block.clone();
    stale.header.prev_blockhash = cs.params().genesis_block_hash;
    let err = cs.test_block_validity(&stale, false, false).unwrap_err();
    assert_eq!(err.get_reject_reason(), "inconclusive-not-best-prevblk");
}

#[test]
fn test_remove_for_block_evicts_conflicts() {
    let (cs, pool, coins) = chain_with_mature_coins(1);
    let a = spend(coins[0].0.clone(), coins[0].1, 1_000);
    let a_child = spend(OutPoint::new(*a.txid(), 0), coins[0].1 - 1_000, 1_000);
    add(&pool, &cs, &a, 1_000);
    add(&pool, &cs, &a_child, 1_000);
    // A conflicting spend of the same coin is confirmed elsewhere.
    let conflict = spend(coins[0].0.clone(), coins[0].1, 7_000);
    let before = pool.get_transactions_updated();
    pool.remove_for_block_txs(&[conflict]);
    assert_eq!(pool.size(), 0);
    assert!(pool.get_transactions_updated() > before);
}
