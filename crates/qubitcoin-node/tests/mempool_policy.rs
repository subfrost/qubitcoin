//! Mempool policy tests: `MemPoolAccept` single/package acceptance, TRUC
//! (v3) rules incl. sibling eviction, Pay-to-Anchor, and ephemeral dust.
//!
//! Modelled on Bitcoin Core's `test/functional/mempool_truc.py`,
//! `mempool_ephemeral_dust.py`, `mempool_accept.py` and
//! `src/test/txvalidation_tests.cpp`, run against real consensus
//! validation on regtest.

use std::sync::Arc;

use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::{CoinsView, EmptyCoinsView};
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::check::check_proof_of_work;
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_node::mempool_accept::{is_child_with_parents_tree, MemPoolAccept};
use qubitcoin_node::miner::{BlockAssembler, BlockAssemblerOptions};
use qubitcoin_primitives::{Amount, Txid};
use qubitcoin_script::{Script, PAY_TO_ANCHOR_SCRIPT};

fn wsh_op_true() -> Script {
    let h = qubitcoin_crypto::hash::sha256_hash(&[0x51]);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&h);
    Script::from_bytes(spk)
}

fn p2a() -> Script {
    Script::from_bytes(PAY_TO_ANCHOR_SCRIPT.to_vec())
}

fn solve(block: &mut Block, cs: &ChainstateManager) {
    while !check_proof_of_work(&block.header.block_hash().into_uint256(), block.header.bits, cs.consensus()) {
        block.header.nonce += 1;
    }
}

fn mine(cs: &mut ChainstateManager, pool: &TxMemPool) -> Block {
    let mut block = BlockAssembler::new(cs, Some(pool), BlockAssemblerOptions::default())
        .create_new_block(&wsh_op_true())
        .expect("template")
        .block;
    solve(&mut block, cs);
    assert!(cs.process_new_block(&block).expect("connect").0);
    pool.remove_for_block_txs(&block.vtx);
    block
}

/// (chain, pool, mature P2WSH(OP_TRUE) coinbase outpoints with values)
fn setup(n: usize) -> (ChainstateManager, TxMemPool, Vec<(OutPoint, i64)>) {
    let params = ChainParams::regtest();
    let mut cs = ChainstateManager::new(params.clone(), Box::new(EmptyCoinsView));
    cs.load_genesis_block(&params.create_genesis_block()).unwrap();
    let pool = TxMemPool::new();
    let mut coins = Vec::new();
    for _ in 0..(100 + n) {
        let b = mine(&mut cs, &pool);
        coins.push((OutPoint::new(*b.vtx[0].txid(), 0), b.vtx[0].vout[0].value.to_sat()));
    }
    coins.truncate(n);
    (cs, pool, coins)
}

/// Spend `inputs` (P2WSH(OP_TRUE) unless `anchor` marks a P2A input) into
/// `outputs`.
fn mk(version: u32, inputs: &[(OutPoint, bool)], outputs: Vec<(i64, Script)>) -> TransactionRef {
    let vin = inputs
        .iter()
        .map(|(op, anchor)| TxIn {
            prevout: op.clone(),
            script_sig: Script::new(),
            sequence: SEQUENCE_FINAL,
            witness: if *anchor { Witness::new() } else { Witness { stack: vec![vec![0x51]] } },
        })
        .collect();
    let vout = outputs.into_iter().map(|(v, s)| TxOut::new(Amount::from_sat(v), s)).collect();
    Arc::new(Transaction::new(version, vin, vout, 0))
}

fn out(tx: &TransactionRef, n: u32) -> OutPoint {
    OutPoint::new(*tx.txid(), n)
}

#[test]
fn test_single_accept_basic_rejections() {
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();

    // Missing inputs.
    let ghost = mk(2, &[(OutPoint::new(Txid::from_bytes([9; 32]), 0), false)], vec![(1000, wsh_op_true())]);
    let e = acc.accept_single(&ghost, false).unwrap_err();
    assert!(e.missing_inputs);
    assert_eq!(e.reason, "bad-txns-inputs-missingorspent");

    // Non-standard version.
    let e = acc.accept_single(&mk(4, &[(op.clone(), false)], vec![(v - 1000, wsh_op_true())]), false).unwrap_err();
    assert_eq!(e.reason, "version");

    // Too small (64-byte txs are non-standard; CVE-2017-12842).
    let tiny = mk(2, &[(op.clone(), false)], vec![(v - 1000, Script::from_bytes(vec![0x6a]))]);
    assert_eq!(acc.accept_single(&tiny, false).unwrap_err().reason, "tx-size-small");

    // Non-final.
    let mut nf = (*mk(2, &[(op.clone(), false)], vec![(v - 1000, wsh_op_true())])).clone();
    nf.vin[0].sequence = 0;
    let nf = Arc::new(Transaction::new(nf.version, nf.vin, nf.vout, 10_000));
    assert_eq!(acc.accept_single(&nf, false).unwrap_err().reason, "non-final");

    // Dust on its own.
    let dusty = mk(2, &[(op.clone(), false)], vec![(v - 1000, wsh_op_true()), (0, p2a())]);
    assert_eq!(acc.accept_single(&dusty, false).unwrap_err().reason, "dust");

    // test_accept is a dry run; a real accept then a duplicate.
    let good = mk(2, &[(op.clone(), false)], vec![(v - 1000, wsh_op_true())]);
    let r = acc.accept_single(&good, true).unwrap();
    assert_eq!(r.fee, Amount::from_sat(1000));
    assert_eq!(pool.size(), 0);
    acc.accept_single(&good, false).unwrap();
    assert_eq!(pool.size(), 1);
    assert_eq!(acc.accept_single(&good, false).unwrap_err().reason, "txn-already-in-mempool");
    // The entry carries real sigops/time now.
    assert!(pool.get_entry(good.txid()).unwrap().time() > 0);
}

#[test]
fn test_premature_coinbase_spend_rejected() {
    let (mut cs, pool, _) = setup(1);
    let fresh = mine(&mut cs, &pool);
    let acc = MemPoolAccept::new(&cs, &pool);
    let v = fresh.vtx[0].vout[0].value.to_sat();
    let tx = mk(2, &[(out(&fresh.vtx[0], 0), false)], vec![(v - 1000, wsh_op_true())]);
    assert_eq!(
        acc.accept_single(&tx, false).unwrap_err().reason,
        "bad-txns-premature-spend-of-coinbase"
    );
}

#[test]
fn test_truc_inheritance_and_topology() {
    let (cs, pool, coins) = setup(2);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();

    let parent = mk(3, &[(op, false)], vec![(v / 2, wsh_op_true()), (v / 2 - 1000, wsh_op_true())]);
    acc.accept_single(&parent, false).unwrap();

    // non-v3 child of a v3 parent.
    let c2 = mk(2, &[(out(&parent, 0), false)], vec![(v / 2 - 1000, wsh_op_true())]);
    let e = acc.accept_single(&c2, false).unwrap_err();
    assert_eq!(e.reason, "TRUC-violation");
    assert!(e.details.starts_with("non-version=3 tx"), "{}", e.details);

    // v3 child too big (> 1000 vB).
    let outs: Vec<(i64, Script)> = (0..30).map(|_| (10_000, wsh_op_true())).collect();
    let big = mk(3, &[(out(&parent, 0), false)], outs);
    let e = acc.accept_single(&big, false).unwrap_err();
    assert!(e.details.contains("child tx") && e.details.contains("is too big"), "{}", e.details);

    // v3 child OK; a v3 grandchild has too many ancestors.
    let child = mk(3, &[(out(&parent, 0), false)], vec![(v / 2 - 2000, wsh_op_true())]);
    acc.accept_single(&child, false).unwrap();
    let grandchild = mk(3, &[(out(&child, 0), false)], vec![(v / 2 - 3000, wsh_op_true())]);
    let e = acc.accept_single(&grandchild, false).unwrap_err();
    assert!(e.details.contains("too many ancestors"), "{}", e.details);

    // v3 spending a non-v3 unconfirmed parent.
    let (op2, v2) = coins[1].clone();
    let v2parent = mk(2, &[(op2, false)], vec![(v2 - 1000, wsh_op_true())]);
    acc.accept_single(&v2parent, false).unwrap();
    let v3kid = mk(3, &[(out(&v2parent, 0), false)], vec![(v2 - 2000, wsh_op_true())]);
    let e = acc.accept_single(&v3kid, false).unwrap_err();
    assert!(e.details.contains("cannot spend from non-version=3"), "{}", e.details);
}

#[test]
fn test_truc_sibling_eviction() {
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    let half = v / 2;
    let parent = mk(3, &[(op, false)], vec![(half, wsh_op_true()), (half - 1000, wsh_op_true())]);
    acc.accept_single(&parent, false).unwrap();
    let child1 = mk(3, &[(out(&parent, 0), false)], vec![(half - 1000, wsh_op_true())]);
    acc.accept_single(&child1, false).unwrap();

    // A second child of the same parent (different output) must out-pay
    // the sibling under RBF rules.
    let cheap = mk(3, &[(out(&parent, 1), false)], vec![(half - 1000 - 500, wsh_op_true())]);
    let e = acc.accept_single(&cheap, false).unwrap_err();
    assert_eq!(e.reason, "insufficient fee (including sibling eviction)", "{:?}", e);

    let rich = mk(3, &[(out(&parent, 1), false)], vec![(half - 1000 - 5_000, wsh_op_true())]);
    let r = acc.accept_single(&rich, false).unwrap();
    assert_eq!(r.replaced, vec![*child1.txid()]);
    assert!(!pool.exists(child1.txid()));
    assert!(pool.exists(rich.txid()));
}

#[test]
fn test_ephemeral_anchor_package() {
    let (mut cs, pool, coins) = setup(2);
    let (op, v) = coins[0].clone();

    // 0-fee parent with a 0-value P2A anchor; the child spends the anchor
    // and pays for both (CPFP).
    let parent = mk(3, &[(op, false)], vec![(v, wsh_op_true()), (0, p2a())]);
    let child = mk(3, &[(out(&parent, 1), true), (coins[1].0.clone(), false)], vec![(coins[1].1 - 5_000, wsh_op_true())]);
    let pkg = vec![parent.clone(), child.clone()];
    assert!(is_child_with_parents_tree(&pkg));

    {
        let acc = MemPoolAccept::new(&cs, &pool);
        // Parent alone: dust.
        assert_eq!(acc.accept_single(&parent, false).unwrap_err().reason, "dust");

        // A fee-paying dusty parent is never allowed.
        let paying = mk(3, &[(coins[0].0.clone(), false)], vec![(v - 100, wsh_op_true()), (0, p2a())]);
        let (err, res) = acc.accept_package(&[paying, child.clone()], true);
        assert!(err.is_some());
        let e = res[0].as_ref().unwrap_err();
        assert_eq!((e.reason.as_str(), e.details.as_str()), ("dust", "tx with dust output must be 0-fee"));

        // Child not spending the dust -> missing-ephemeral-spends; nothing enters.
        let lazy = mk(3, &[(out(&parent, 0), false)], vec![(v - 5_000, wsh_op_true())]);
        let (err, res) = acc.accept_package(&[parent.clone(), lazy], false);
        assert!(err.is_some());
        assert_eq!(res[1].as_ref().unwrap_err().reason, "missing-ephemeral-spends");
        assert_eq!(res[0].as_ref().unwrap_err().reason, "package-not-validated");
        assert_eq!(pool.size(), 0);

        // Test-accept then submit the good package.
        let (err, res) = acc.accept_package(&pkg, true);
        assert!(err.is_none(), "{:?} {:?}", err, res);
        assert_eq!(pool.size(), 0);
        let (err, res) = acc.accept_package(&pkg, false);
        assert!(err.is_none(), "{:?}", res);
        assert_eq!(pool.size(), 2);
        assert_eq!(res[1].as_ref().unwrap().fee, Amount::from_sat(5_000));
    }

    // Both get mined together; the anchor spend is valid at consensus.
    let b = mine(&mut cs, &pool);
    let ids: Vec<Txid> = b.vtx.iter().skip(1).map(|t| *t.txid()).collect();
    assert_eq!(ids, vec![*parent.txid(), *child.txid()]);
    assert!(cs.coins_tip().get_coin(&out(&child, 0)).is_some());
}

#[test]
fn test_p2a_spend_must_have_empty_witness() {
    let (cs, pool, coins) = setup(2);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    // A P2A output above the dust threshold (240 sat) is standard on its own.
    let parent = mk(2, &[(op, false)], vec![(v - 1_000, wsh_op_true()), (240, p2a())]);
    acc.accept_single(&parent, false).unwrap();
    let with_wit = mk(2, &[(out(&parent, 1), false), (coins[1].0.clone(), false)], vec![(coins[1].1, wsh_op_true())]);
    assert_eq!(acc.accept_single(&with_wit, true).unwrap_err().reason, "bad-witness-nonstandard");
    let ok = mk(2, &[(out(&parent, 1), true), (coins[1].0.clone(), false)], vec![(coins[1].1, wsh_op_true())]);
    acc.accept_single(&ok, false).unwrap();
}

#[test]
fn test_package_well_formedness() {
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    let a = mk(2, &[(op.clone(), false)], vec![(v - 1000, wsh_op_true())]);
    let b = mk(2, &[(out(&a, 0), false)], vec![(v - 2000, wsh_op_true())]);
    let (err, _) = acc.accept_package(&[b.clone(), a.clone()], true);
    assert_eq!(err.unwrap().reason, "package-not-sorted");
    let (err, _) = acc.accept_package(&[a.clone(), a.clone()], true);
    assert_eq!(err.unwrap().reason, "package-contains-duplicates");
    let a2 = mk(2, &[(op, false)], vec![(v - 3000, wsh_op_true())]);
    let (err, _) = acc.accept_package(&[a.clone(), a2], true);
    assert_eq!(err.unwrap().reason, "conflict-in-package");
    // Parents depending on each other: not child-with-parents.
    let c = mk(2, &[(out(&b, 0), false), (out(&a, 0), false)], vec![(1000, wsh_op_true())]);
    assert!(!is_child_with_parents_tree(&[a, b, c]));
}

fn setup_with_pool(n: usize, pool: TxMemPool) -> (ChainstateManager, TxMemPool, Vec<(OutPoint, i64)>) {
    let (cs, _p, coins) = setup(n);
    (cs, pool, coins)
}

/// Spend output `n` of `parent` (worth `value`) into `outs` P2WSH outputs.
fn chain_child(parent: &TransactionRef, n: u32, value: i64, fee: i64, outs: usize) -> TransactionRef {
    let each = (value - fee) / outs as i64;
    mk(2, &[(out(parent, n), false)], (0..outs).map(|_| (each, wsh_op_true())).collect())
}

#[test]
fn test_ancestor_count_limit() {
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, mut v) = coins[0].clone();
    let mut prev = mk(2, &[(op, false)], vec![(v - 1_000, wsh_op_true())]);
    v -= 1_000;
    acc.accept_single(&prev, false).unwrap();
    for _ in 0..24 {
        let next = chain_child(&prev, 0, v, 1_000, 1);
        v -= 1_000;
        acc.accept_single(&next, false).unwrap();
        prev = next;
    }
    assert_eq!(pool.size(), 25);
    let e = acc.accept_single(&chain_child(&prev, 0, v, 1_000, 1), false).unwrap_err();
    assert_eq!(e.reason, "too-long-mempool-chain");
    assert!(e.details.starts_with("too many unconfirmed ancestors"), "{}", e.details);
}

#[test]
fn test_descendant_limit_and_cpfp_carve_out() {
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    // Parent with three outputs; a 24-long chain hangs off output 0, so
    // the parent has 25 in-mempool descendants including itself.
    let third = (v - 1_000) / 3;
    let parent = mk(2, &[(op, false)], vec![(third, wsh_op_true()), (third, wsh_op_true()), (third, wsh_op_true())]);
    acc.accept_single(&parent, false).unwrap();
    let mut prev = parent.clone();
    let mut val = third;
    let mut idx = 0;
    for _ in 0..24 {
        let next = chain_child(&prev, idx, val, 1_000, 1);
        val -= 1_000;
        idx = 0;
        acc.accept_single(&next, false).unwrap();
        prev = next;
    }
    // One more child of the parent exceeds its descendant limit, but the
    // carve-out admits a small tx whose only ancestor is the parent...
    let carve = chain_child(&parent, 1, third, 1_000, 1);
    acc.accept_single(&carve, false).unwrap();
    // ...exactly once.
    let e = acc.accept_single(&chain_child(&parent, 2, third, 1_000, 1), false).unwrap_err();
    assert_eq!(e.reason, "too-long-mempool-chain");
    assert!(e.details.starts_with("too many descendants for tx"), "{}", e.details);
}

#[test]
fn test_package_feerate_cpfp_with_relay_floor() {
    use qubitcoin_node::mempool::{FeeRate, MempoolPolicy};
    let pool = TxMemPool::new_with_options(FeeRate::new(1_000), 300_000_000, MempoolPolicy::default());
    let (cs, pool, coins) = setup_with_pool(1, pool);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    let parent = mk(2, &[(op, false)], vec![(v, wsh_op_true())]); // 0 fee
    let child = mk(2, &[(out(&parent, 0), false)], vec![(v - 2_000, wsh_op_true())]);
    let e = acc.accept_single(&parent, true).unwrap_err();
    assert_eq!(e.reason, "min relay fee not met");
    assert!(e.reconsiderable);
    // Test accept judges members on their own feerate (Core).
    let (err, _) = acc.accept_package(&[parent.clone(), child.clone()], true);
    assert!(err.is_some());
    // Submission uses the package feerate.
    let (err, res) = acc.accept_package(&[parent.clone(), child.clone()], false);
    assert!(err.is_none(), "{:?}", res);
    let p = res[0].as_ref().unwrap();
    assert_eq!(p.effective_includes, vec![parent.wtxid().to_hex(), child.wtxid().to_hex()]);
    assert_eq!(p.effective_feerate, res[1].as_ref().unwrap().effective_feerate);
    assert_eq!(pool.size(), 2);
}

#[test]
fn test_package_rbf_one_parent_one_child() {
    let (cs, pool, coins) = setup(2);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    let original = mk(2, &[(op.clone(), false)], vec![(v - 5_000, wsh_op_true())]);
    acc.accept_single(&original, false).unwrap();

    // Replacement parent pays less than the original on its own...
    let new_parent = mk(2, &[(op.clone(), false)], vec![(v - 100, wsh_op_true())]);
    assert!(acc.accept_single(&new_parent, true).unwrap_err().reconsiderable);
    // ...a child that does not pay enough for both fails package RBF.
    let cheap_child = mk(2, &[(out(&new_parent, 0), false)], vec![(v - 100 - 1_000, wsh_op_true())]);
    let (err, res) = acc.accept_package(&[new_parent.clone(), cheap_child], false);
    assert!(err.is_some());
    assert_eq!(res[1].as_ref().unwrap_err().reason, "package RBF failed");
    assert!(pool.exists(original.txid()));

    // A child paying for the package replaces the original.
    let child = mk(2, &[(out(&new_parent, 0), false)], vec![(v - 100 - 20_000, wsh_op_true())]);
    let (err, res) = acc.accept_package(&[new_parent.clone(), child.clone()], false);
    assert!(err.is_none(), "{:?}", res);
    assert_eq!(res[0].as_ref().unwrap().replaced, vec![*original.txid()]);
    assert!(!pool.exists(original.txid()));
    assert!(pool.exists(new_parent.txid()) && pool.exists(child.txid()));
}

#[test]
fn test_output_standardness_and_datacarrier() {
    use qubitcoin_node::mempool::{FeeRate, MempoolPolicy};
    let (cs, pool, coins) = setup(1);
    let acc = MemPoolAccept::new(&cs, &pool);
    let (op, v) = coins[0].clone();
    let bare = mk(2, &[(op.clone(), false)], vec![(v - 1_000, Script::from_bytes(vec![0x51, 0x51, 0x93]))]);
    assert_eq!(acc.accept_single(&bare, true).unwrap_err().reason, "scriptpubkey");
    let mut data = vec![0x6a, 0x4c, 200];
    data.extend([7u8; 200]);
    let with_data = mk(2, &[(op.clone(), false)], vec![(v - 1_000, wsh_op_true()), (0, Script::from_bytes(data))]);
    acc.accept_single(&with_data, true).unwrap();
    let strict = TxMemPool::new_with_options(
        FeeRate::new(0),
        300_000_000,
        MempoolPolicy { max_datacarrier_bytes: Some(83), permit_bare_multisig: true },
    );
    let acc2 = MemPoolAccept::new(&cs, &strict);
    assert_eq!(acc2.accept_single(&with_data, true).unwrap_err().reason, "datacarrier");
}

#[test]
fn test_bip68_relative_lock() {
    let (mut cs, pool, coins) = setup(1);
    // Confirm a fresh coin at the next height, then spend it with a
    // 5-block relative lock.
    let (op, v) = coins[0].clone();
    let parent = mk(2, &[(op, false)], vec![(v - 1_000, wsh_op_true())]);
    MemPoolAccept::new(&cs, &pool).accept_single(&parent, false).unwrap();
    mine(&mut cs, &pool);
    let mut locked = (*mk(2, &[(out(&parent, 0), false)], vec![(v - 2_000, wsh_op_true())])).clone();
    locked.vin[0].sequence = 5;
    let locked = Arc::new(Transaction::new(2, locked.vin, locked.vout, 0));
    assert_eq!(
        MemPoolAccept::new(&cs, &pool).accept_single(&locked, true).unwrap_err().reason,
        "non-BIP68-final"
    );
    for _ in 0..4 {
        mine(&mut cs, &pool);
    }
    MemPoolAccept::new(&cs, &pool).accept_single(&locked, true).unwrap();
}
