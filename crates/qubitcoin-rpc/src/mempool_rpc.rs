// Copyright (c) 2024 The Qubitcoin developers
// Distributed under the MIT software license.

//! Transaction submission RPCs.
//!
//! Port of Bitcoin Core's `sendrawtransaction`, `testmempoolaccept` and
//! `submitpackage` (src/rpc/mempool.cpp) and `BroadcastTransaction`
//! (src/node/transaction.cpp), on top of
//! [`qubitcoin_node::mempool_accept::MemPoolAccept`].

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Map, Value};

use qubitcoin_common::coins::CoinsView;
use qubitcoin_consensus::transaction::{OutPoint, Transaction, TransactionRef};
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::{FeeRate, TxMemPool};
use qubitcoin_node::mempool_accept::{
    is_child_with_parents_tree, MemPoolAccept, TxAccepted, TxRejection, MAX_PACKAGE_COUNT,
};
use qubitcoin_serialize::deserialize;

use crate::server::{
    RpcRegistry, RpcRequest, RpcResponse, RPC_DESERIALIZATION_ERROR, RPC_INVALID_PARAMETER,
    RPC_TYPE_ERROR, RPC_VERIFY_ERROR, RPC_VERIFY_REJECTED,
};

/// Core's `RPC_TRANSACTION_ERROR` (alias of `RPC_VERIFY_ERROR`).
pub const RPC_TRANSACTION_ERROR: i32 = RPC_VERIFY_ERROR;
/// Core's `RPC_TRANSACTION_REJECTED` (alias of `RPC_VERIFY_REJECTED`).
pub const RPC_TRANSACTION_REJECTED: i32 = RPC_VERIFY_REJECTED;
/// Core's `RPC_VERIFY_ALREADY_IN_UTXO_SET`.
pub const RPC_VERIFY_ALREADY_IN_UTXO_SET: i32 = -27;

/// Default `maxfeerate`: 0.10 BTC/kvB (Core's `DEFAULT_MAX_RAW_TX_FEE_RATE`).
pub const DEFAULT_MAX_RAW_TX_FEE_RATE: FeeRate = FeeRate::new(10_000_000);

/// Shared state for the submission RPCs.
pub struct MempoolRpcContext {
    /// The chainstate (inputs are resolved under its lock).
    pub chainstate: Arc<Mutex<ChainstateManager>>,
    /// The mempool.
    pub mempool: Arc<TxMemPool>,
}

fn param(req: &RpcRequest, i: usize) -> Option<&Value> {
    match req.params.as_ref()? {
        Value::Array(a) => a.get(i).filter(|v| !v.is_null()),
        _ => None,
    }
}

fn btc(sat: i64) -> Value {
    json!(sat as f64 / 100_000_000.0)
}

fn decode_tx(hex: &str) -> Option<TransactionRef> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect();
    let tx: Transaction = deserialize(&bytes?).ok()?;
    if tx.vin.is_empty() {
        return None;
    }
    Some(Arc::new(tx))
}

/// Parse a BTC/kvB feerate parameter (Core's `ParseFeeRate`), defaulting to
/// [`DEFAULT_MAX_RAW_TX_FEE_RATE`].
fn max_fee_rate(req: &RpcRequest, i: usize) -> Result<FeeRate, String> {
    match param(req, i) {
        None => Ok(DEFAULT_MAX_RAW_TX_FEE_RATE),
        Some(v) => match v.as_f64() {
            Some(f) if f >= 0.0 => Ok(FeeRate::new((f * 100_000_000.0).round() as i64)),
            _ => Err("Fee rates larger than or equal to 1BTC/kvB are not accepted".into()),
        },
    }
}

/// Core's `maxburnamount` check: unspendable outputs above the limit.
fn check_burn(tx: &Transaction, max_burn_sat: i64) -> bool {
    tx.vout
        .iter()
        .all(|o| !(o.script_pubkey.is_unspendable() && o.value.to_sat() > max_burn_sat))
}

fn max_burn(req: &RpcRequest, i: usize) -> i64 {
    param(req, i)
        .and_then(|v| v.as_f64())
        .map(|f| (f * 100_000_000.0).round() as i64)
        .unwrap_or(0)
}

/// Core's `HandleATMPError` + `JSONRPCTransactionError`.
fn atmp_error(id: Value, e: &TxRejection) -> RpcResponse {
    if e.missing_inputs {
        RpcResponse::error(id, RPC_TRANSACTION_ERROR, "bad-txns-inputs-missingorspent".into())
    } else {
        RpcResponse::error(id, RPC_TRANSACTION_REJECTED, e.to_state_string())
    }
}

fn sendrawtransaction(ctx: &MempoolRpcContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let tx = match param(req, 0).and_then(|v| v.as_str()).and_then(decode_tx) {
        Some(t) => t,
        None => {
            return RpcResponse::error(
                id,
                RPC_DESERIALIZATION_ERROR,
                "TX decode failed. Make sure the tx has at least one input.".into(),
            )
        }
    };
    let max_rate = match max_fee_rate(req, 1) {
        Ok(r) => r,
        Err(e) => return RpcResponse::error(id, RPC_INVALID_PARAMETER, e),
    };
    if !check_burn(&tx, max_burn(req, 2)) {
        return RpcResponse::error(
            id,
            RPC_TRANSACTION_ERROR,
            "Unspendable output exceeds maximum configured by user (maxburnamount)".into(),
        );
    }
    let cs = ctx.chainstate.lock();
    // BroadcastTransaction: refuse if any output is already confirmed.
    for n in 0..tx.vout.len() {
        if cs.coins_tip().get_coin(&OutPoint::new(*tx.txid(), n as u32)).is_some() {
            return RpcResponse::error(
                id,
                RPC_VERIFY_ALREADY_IN_UTXO_SET,
                "Transaction outputs already in utxo set".into(),
            );
        }
    }
    // Already in the mempool: success (Core re-announces it).
    if ctx.mempool.exists(tx.txid()) {
        return RpcResponse::success(id, json!(tx.txid().to_hex()));
    }
    let acc = MemPoolAccept::new(&cs, &ctx.mempool);
    if max_rate.sats_per_kvb() > 0 {
        match acc.accept_single(&tx, true) {
            Err(e) => return atmp_error(id, &e),
            Ok(r) => {
                if r.fee > max_rate.get_fee(r.vsize as usize) {
                    return RpcResponse::error(
                        id,
                        RPC_TRANSACTION_ERROR,
                        "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".into(),
                    );
                }
            }
        }
    }
    match acc.accept_single(&tx, false) {
        Ok(_) => RpcResponse::success(id, json!(tx.txid().to_hex())),
        Err(e) => atmp_error(id, &e),
    }
}

fn fees_json(r: &TxAccepted, with_effective: bool) -> Value {
    let mut fees = Map::new();
    fees.insert("base".into(), btc(r.fee.to_sat()));
    if with_effective {
        fees.insert("effective-feerate".into(), btc(r.effective_feerate.sats_per_kvb()));
        fees.insert("effective-includes".into(), json!(r.effective_includes));
    }
    Value::Object(fees)
}

fn parse_tx_array(req: &RpcRequest, id: &Value) -> Result<Vec<TransactionRef>, RpcResponse> {
    let arr = match param(req, 0).and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return Err(RpcResponse::error(id.clone(), RPC_TYPE_ERROR, "Expected an array of raw transactions".into()))
        }
    };
    if arr.is_empty() || arr.len() > MAX_PACKAGE_COUNT {
        return Err(RpcResponse::error(
            id.clone(),
            RPC_INVALID_PARAMETER,
            format!("Array must contain between 1 and {} transactions.", MAX_PACKAGE_COUNT),
        ));
    }
    let mut txs = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v.as_str().unwrap_or("");
        match decode_tx(s) {
            Some(t) => txs.push(t),
            None => {
                return Err(RpcResponse::error(
                    id.clone(),
                    RPC_DESERIALIZATION_ERROR,
                    format!("TX decode failed: {} Make sure the tx has at least one input.", s),
                ))
            }
        }
    }
    Ok(txs)
}

fn testmempoolaccept(ctx: &MempoolRpcContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let txs = match parse_tx_array(req, &id) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let max_rate = match max_fee_rate(req, 1) {
        Ok(r) => r,
        Err(e) => return RpcResponse::error(id, RPC_INVALID_PARAMETER, e),
    };
    let cs = ctx.chainstate.lock();
    let acc = MemPoolAccept::new(&cs, &ctx.mempool);

    // (package-level error, per-tx results; None = validation unfinished)
    let (package_error, results): (Option<TxRejection>, Vec<Option<Result<TxAccepted, TxRejection>>>) =
        if txs.len() == 1 {
            (None, vec![Some(acc.accept_single(&txs[0], true))])
        } else {
            let (err, res) = acc.accept_package(&txs, true);
            if res.is_empty() {
                (err, vec![None; txs.len()])
            } else if let Some(first_fail) = res.iter().position(|r| r.is_err()) {
                // Core stops at the first failure: only it has a result.
                let mut v: Vec<Option<_>> = vec![None; txs.len()];
                v[first_fail] = Some(res[first_fail].clone());
                (None, v)
            } else {
                (None, res.into_iter().map(Some).collect())
            }
        };

    let mut out = Vec::with_capacity(txs.len());
    let mut exit_early = false;
    for (tx, r) in txs.iter().zip(results.into_iter()) {
        let mut o = Map::new();
        o.insert("txid".into(), json!(tx.txid().to_hex()));
        o.insert("wtxid".into(), json!(tx.wtxid().to_hex()));
        if let Some(pe) = &package_error {
            o.insert("package-error".into(), json!(pe.to_state_string()));
        }
        match r {
            None => {}
            Some(_) if exit_early => {}
            Some(Ok(a)) => {
                if max_rate.sats_per_kvb() > 0 && a.fee > max_rate.get_fee(a.vsize as usize) {
                    o.insert("allowed".into(), json!(false));
                    o.insert("reject-reason".into(), json!("max-fee-exceeded"));
                    exit_early = true;
                } else {
                    o.insert("allowed".into(), json!(true));
                    o.insert("vsize".into(), json!(a.vsize));
                    o.insert("fees".into(), fees_json(&a, true));
                }
            }
            Some(Err(e)) => {
                o.insert("allowed".into(), json!(false));
                if e.missing_inputs {
                    o.insert("reject-reason".into(), json!("missing-inputs"));
                } else {
                    o.insert("reject-reason".into(), json!(e.reason));
                    o.insert("reject-details".into(), json!(e.to_state_string()));
                }
            }
        }
        out.push(Value::Object(o));
    }
    RpcResponse::success(id, Value::Array(out))
}

fn submitpackage(ctx: &MempoolRpcContext, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let txs = match parse_tx_array(req, &id) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let max_rate = match max_fee_rate(req, 1) {
        Ok(r) => r,
        Err(e) => return RpcResponse::error(id, RPC_INVALID_PARAMETER, e),
    };
    let burn = max_burn(req, 2);
    if txs.iter().any(|t| !check_burn(t, burn)) {
        return RpcResponse::error(
            id,
            RPC_TRANSACTION_ERROR,
            "Unspendable output exceeds maximum configured by user (maxburnamount)".into(),
        );
    }
    if !is_child_with_parents_tree(&txs) {
        return RpcResponse::error(
            id,
            RPC_TRANSACTION_ERROR,
            "package topology disallowed. not child-with-parents or parents depend on each other."
                .into(),
        );
    }

    let cs = ctx.chainstate.lock();
    let acc = MemPoolAccept::new(&cs, &ctx.mempool);

    // maxfeerate is enforced on every member before anything is submitted
    // (Core passes it into package validation as max_sane_feerate).
    let (pre_err, pre) = acc.accept_package(&txs, true);
    let too_rich: Option<usize> = if max_rate.sats_per_kvb() > 0 {
        pre.iter().position(|r| match r {
            Ok(a) => !a.already_in_mempool && a.effective_feerate > max_rate,
            Err(_) => false,
        })
    } else {
        None
    };
    let (package_error, results) = if pre.is_empty() {
        (pre_err, Vec::new())
    } else if let Some(i) = too_rich {
        let mut res = pre;
        res[i] = Err(TxRejection {
            reason: "max feerate exceeded".into(),
            details: String::new(),
            missing_inputs: false,
        });
        (
            Some(TxRejection {
                reason: "transaction failed".into(),
                details: String::new(),
                missing_inputs: false,
            }),
            res,
        )
    } else {
        acc.accept_package(&txs, false)
    };

    let package_msg = match &package_error {
        None => "success".to_string(),
        Some(e) => e.to_state_string(),
    };
    let mut tx_results = Map::new();
    let mut replaced: Vec<String> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        let r = match results.get(i) {
            Some(r) => r,
            None => continue, // "unevaluated" entries are not reported (as Core).
        };
        let mut o = Map::new();
        o.insert("txid".into(), json!(tx.txid().to_hex()));
        match r {
            Ok(a) => {
                o.insert("vsize".into(), json!(a.vsize));
                o.insert("fees".into(), fees_json(a, !a.already_in_mempool));
                replaced.extend(a.replaced.iter().map(|t| t.to_hex()));
            }
            Err(e) if e.reason == "txn-same-nonwitness-data-in-mempool" => {
                if let Some(m) = ctx.mempool.get(tx.txid()) {
                    o.insert("other-wtxid".into(), json!(m.wtxid().to_hex()));
                }
            }
            Err(e) => {
                o.insert("error".into(), json!(e.to_state_string()));
            }
        }
        tx_results.insert(tx.wtxid().to_hex(), Value::Object(o));
    }
    replaced.sort();
    replaced.dedup();
    RpcResponse::success(
        id,
        json!({
            "package_msg": package_msg,
            "tx-results": Value::Object(tx_results),
            "replaced-transactions": replaced,
        }),
    )
}

/// Register `sendrawtransaction`, `testmempoolaccept` and `submitpackage`.
/// They stay public-tier like the `sendrawtransaction` this replaces.
pub fn register_mempool_rpcs(registry: &mut RpcRegistry, ctx: Arc<MempoolRpcContext>) {
    let c = ctx.clone();
    registry.register("sendrawtransaction", move |req| sendrawtransaction(&c, req));
    let c = ctx.clone();
    registry.register("testmempoolaccept", move |req| testmempoolaccept(&c, req));
    let c = ctx.clone();
    registry.register("submitpackage", move |req| submitpackage(&c, req));
}
