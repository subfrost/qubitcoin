//! `sendrawtransaction`, `testmempoolaccept`, `submitpackage` against a
//! regtest chain, checked against Bitcoin Core's documented result shapes
//! and error codes (src/rpc/mempool.cpp).

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Value};

use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::EmptyCoinsView;
use qubitcoin_consensus::check::check_proof_of_work;
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::TxMemPool;
use qubitcoin_node::miner::{BlockAssembler, BlockAssemblerOptions};
use qubitcoin_primitives::Amount;
use qubitcoin_rpc::mempool_rpc::{register_mempool_rpcs, MempoolRpcContext};
use qubitcoin_rpc::server::{RpcRegistry, RpcRequest, RpcResponse};
use qubitcoin_script::{Script, PAY_TO_ANCHOR_SCRIPT};
use qubitcoin_serialize::serialize;

fn wsh_op_true() -> Script {
    let h = qubitcoin_crypto::hash::sha256_hash(&[0x51]);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&h);
    Script::from_bytes(spk)
}

struct Env {
    registry: RpcRegistry,
    pool: Arc<TxMemPool>,
    coins: Vec<(OutPoint, i64)>,
}

fn env(n: usize) -> Env {
    let params = ChainParams::regtest();
    let mut cs = ChainstateManager::new(params.clone(), Box::new(EmptyCoinsView));
    cs.load_genesis_block(&params.create_genesis_block()).unwrap();
    let mut coins = Vec::new();
    for _ in 0..(100 + n) {
        let mut b = BlockAssembler::new(&cs, None, BlockAssemblerOptions::default())
            .create_new_block(&wsh_op_true())
            .unwrap()
            .block;
        while !check_proof_of_work(&b.header.block_hash().into_uint256(), b.header.bits, cs.consensus()) {
            b.header.nonce += 1;
        }
        cs.process_new_block(&b).unwrap();
        coins.push((OutPoint::new(*b.vtx[0].txid(), 0), b.vtx[0].vout[0].value.to_sat()));
    }
    coins.truncate(n);
    let pool = Arc::new(TxMemPool::new());
    let mut registry = RpcRegistry::new();
    register_mempool_rpcs(
        &mut registry,
        Arc::new(MempoolRpcContext {
            chainstate: Arc::new(Mutex::new(cs)),
            mempool: pool.clone(),
        }),
    );
    Env { registry, pool, coins }
}

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

fn hex(tx: &TransactionRef) -> String {
    serialize(&**tx).unwrap().iter().map(|b| format!("{:02x}", b)).collect()
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
    resp.result.unwrap()
}

fn err(resp: RpcResponse) -> (i32, String) {
    let e = resp.error.expect("expected error");
    (e.code, e.message)
}

#[test]
fn test_sendrawtransaction_core_semantics() {
    let e = env(2);
    let (op, v) = e.coins[0].clone();
    let tx = mk(2, &[(op.clone(), false)], vec![(v - 1_000, wsh_op_true())]);

    assert_eq!(err(call(&e.registry, "sendrawtransaction", json!(["zz"]))).0, -22);
    let ghost = mk(2, &[(OutPoint::new(*tx.txid(), 7), false)], vec![(1_000, wsh_op_true())]);
    assert_eq!(
        err(call(&e.registry, "sendrawtransaction", json!([hex(&ghost)]))),
        (-25, "bad-txns-inputs-missingorspent".to_string())
    );
    let dusty = mk(2, &[(op.clone(), false)], vec![(v - 1_000, wsh_op_true()), (0, wsh_op_true())]);
    let (code, msg) = err(call(&e.registry, "sendrawtransaction", json!([hex(&dusty)])));
    assert_eq!(code, -26);
    assert!(msg.starts_with("dust"), "{}", msg);

    // 1 BTC fee on ~100 vB is far above 0.10 BTC/kvB.
    let greedy = mk(2, &[(op.clone(), false)], vec![(v - 100_000_000, wsh_op_true())]);
    let (code, msg) = err(call(&e.registry, "sendrawtransaction", json!([hex(&greedy)])));
    assert_eq!(code, -25);
    assert!(msg.starts_with("Fee exceeds maximum"), "{}", msg);

    assert_eq!(ok(call(&e.registry, "sendrawtransaction", json!([hex(&tx)]))), json!(tx.txid().to_hex()));
    // Re-sending a mempool tx succeeds (Core re-announces it).
    assert_eq!(ok(call(&e.registry, "sendrawtransaction", json!([hex(&tx)]))), json!(tx.txid().to_hex()));
    assert_eq!(e.pool.size(), 1);

    // maxfeerate 0 disables the check.
    let (op2, v2) = e.coins[1].clone();
    let greedy2 = mk(2, &[(op2, false)], vec![(v2 - 100_000_000, wsh_op_true())]);
    ok(call(&e.registry, "sendrawtransaction", json!([hex(&greedy2), 0])));

    // maxburnamount.
    let burn = mk(2, &[(OutPoint::new(*tx.txid(), 0), false)], vec![(5_000, Script::from_bytes(vec![0x6a]))]);
    assert_eq!(err(call(&e.registry, "sendrawtransaction", json!([hex(&burn)]))).0, -25);
}

#[test]
fn test_testmempoolaccept_single_and_package() {
    let e = env(1);
    let (op, v) = e.coins[0].clone();
    let parent = mk(2, &[(op, false)], vec![(v - 1_000, wsh_op_true())]);
    let child = mk(2, &[(OutPoint::new(*parent.txid(), 0), false)], vec![(v - 3_000, wsh_op_true())]);

    let r = ok(call(&e.registry, "testmempoolaccept", json!([[hex(&parent)]])));
    let o = &r[0];
    let mut keys: Vec<&str> = o.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(keys, vec!["allowed", "fees", "txid", "vsize", "wtxid"]);
    assert_eq!(o["allowed"], json!(true));
    assert_eq!(o["fees"]["base"], json!(0.00001));
    assert_eq!(o["fees"]["effective-includes"], json!([parent.wtxid().to_hex()]));
    assert_eq!(e.pool.size(), 0, "test accept must not change the mempool");

    // Child alone: missing inputs.
    let r = ok(call(&e.registry, "testmempoolaccept", json!([[hex(&child)]])));
    assert_eq!(r[0]["allowed"], json!(false));
    assert_eq!(r[0]["reject-reason"], json!("missing-inputs"));

    // As a package both pass.
    let r = ok(call(&e.registry, "testmempoolaccept", json!([[hex(&parent), hex(&child)]])));
    assert_eq!(r[0]["allowed"], json!(true));
    assert_eq!(r[1]["allowed"], json!(true));
    assert_eq!(r[1]["fees"]["base"], json!(0.00002));

    // Unsorted: package-error on every entry, no per-tx verdicts.
    let r = ok(call(&e.registry, "testmempoolaccept", json!([[hex(&child), hex(&parent)]])));
    for x in r.as_array().unwrap() {
        assert_eq!(x["package-error"], json!("package-not-sorted"));
        assert!(x.get("allowed").is_none());
    }

    // max-fee-exceeded.
    let r = ok(call(&e.registry, "testmempoolaccept", json!([[hex(&parent)], 0.00000001])));
    assert_eq!(r[0]["reject-reason"], json!("max-fee-exceeded"));

    assert_eq!(err(call(&e.registry, "testmempoolaccept", json!([[]]))).0, -8);
}

#[test]
fn test_submitpackage_ephemeral_anchor() {
    let e = env(2);
    let (op, v) = e.coins[0].clone();
    let anchor = Script::from_bytes(PAY_TO_ANCHOR_SCRIPT.to_vec());
    let parent = mk(3, &[(op, false)], vec![(v, wsh_op_true()), (0, anchor)]);
    let child = mk(
        3,
        &[(OutPoint::new(*parent.txid(), 1), true), (e.coins[1].0.clone(), false)],
        vec![(e.coins[1].1 - 4_000, wsh_op_true())],
    );

    // The parent cannot be sent alone.
    let (code, msg) = err(call(&e.registry, "sendrawtransaction", json!([hex(&parent)])));
    assert_eq!(code, -26);
    assert!(msg.starts_with("dust"));

    // Topology: a lone unrelated pair is not child-with-parents.
    let unrelated = mk(2, &[(e.coins[1].0.clone(), false)], vec![(e.coins[1].1 - 1_000, wsh_op_true())]);
    assert_eq!(err(call(&e.registry, "submitpackage", json!([[hex(&parent), hex(&unrelated)]]))).0, -25);

    let r = ok(call(&e.registry, "submitpackage", json!([[hex(&parent), hex(&child)]])));
    assert_eq!(r["package_msg"], json!("success"), "{}", r);
    let res = &r["tx-results"];
    let p = &res[parent.wtxid().to_hex()];
    assert_eq!(p["txid"], json!(parent.txid().to_hex()));
    assert_eq!(p["fees"]["base"], json!(0.0));
    let c = &res[child.wtxid().to_hex()];
    assert_eq!(c["fees"]["base"], json!(0.00004));
    assert!(c["vsize"].as_u64().unwrap() > 0);
    assert_eq!(r["replaced-transactions"], json!([]));
    assert_eq!(e.pool.size(), 2);

    // Re-submitting reports the mempool entries (no effective feerate).
    let r = ok(call(&e.registry, "submitpackage", json!([[hex(&parent), hex(&child)]])));
    assert_eq!(r["package_msg"], json!("success"));
    assert!(r["tx-results"][child.wtxid().to_hex()]["fees"].get("effective-feerate").is_none());
}

#[test]
fn test_submitpackage_failure_reports_per_tx() {
    let e = env(1);
    let (op, v) = e.coins[0].clone();
    let parent = mk(2, &[(op, false)], vec![(v - 1_000, wsh_op_true())]);
    // Child creates value out of thin air.
    let child = mk(2, &[(OutPoint::new(*parent.txid(), 0), false)], vec![(v, wsh_op_true())]);
    let r = ok(call(&e.registry, "submitpackage", json!([[hex(&parent), hex(&child)]])));
    assert_eq!(r["package_msg"], json!("transaction failed"));
    let c = &r["tx-results"][child.wtxid().to_hex()];
    assert!(c["error"].as_str().unwrap().starts_with("bad-txns-in-belowout"), "{}", c);
    // The parent was valid on its own and is accepted (Core accepts
    // package members that pass individually).
    assert!(r["tx-results"][parent.wtxid().to_hex()].get("error").is_none());
    assert_eq!(e.pool.size(), 1);
}
