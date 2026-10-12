//! End-to-end regtest mining over the HTTP JSON-RPC server, the way a pool
//! (ckpool / public-pool / DATUM) drives a node:
//!
//! 1. `generatetoaddress` to mature coinbases,
//! 2. mempool transactions (a CPFP pair plus an unrelated spend),
//! 3. `getblocktemplate` over JSON-RPC 1.0,
//! 4. build the coinbase and block from the template fields alone
//!    (BIP34 height, extranonce, `coinbasevalue`, `default_witness_commitment`),
//! 5. grind the nonce, `submitblock`, and check the tip advanced and the
//!    coinbase paid subsidy + fees.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Value};

use qubitcoin_common::chainparams::ChainParams;
use qubitcoin_common::coins::EmptyCoinsView;
use qubitcoin_consensus::block::{Block, BlockHeader};
use qubitcoin_consensus::check::get_block_subsidy;
use qubitcoin_consensus::merkle::block_merkle_root;
use qubitcoin_consensus::transaction::{
    OutPoint, Transaction, TransactionRef, TxIn, TxOut, Witness, SEQUENCE_FINAL,
};
use qubitcoin_consensus::validation_state::BlockValidationState;
use qubitcoin_node::chainstate::ChainstateManager;
use qubitcoin_node::mempool::{accept_to_mempool, MempoolAcceptResult, TxMemPool};
use qubitcoin_node::miner::BlockAssemblerOptions;
use qubitcoin_primitives::arith_uint256::uint256_to_arith;
use qubitcoin_primitives::{Amount, ArithUint256, BlockHash};
use qubitcoin_rpc::http_server::{RpcServer, RpcServerConfig};
use qubitcoin_rpc::mining::{register_mining_rpcs, BlockSink, MemoryBlockSink, MiningContext, SinkOutcome, TipWatch};
use qubitcoin_rpc::server::RpcRegistry;
use qubitcoin_script::Script;
use qubitcoin_serialize::{deserialize, serialize};

/// Records every connected block (the in-memory chainstate does not keep
/// block bodies outside its own unit tests).
struct RecordingSink {
    inner: MemoryBlockSink,
    blocks: Mutex<Vec<Block>>,
}

impl BlockSink for RecordingSink {
    fn process_new_block(&self, block: &Block) -> Result<SinkOutcome, BlockValidationState> {
        let r = self.inner.process_new_block(block)?;
        if r.in_active_chain && r.new_block {
            self.blocks.lock().push(block.clone());
        }
        Ok(r)
    }
}

fn wsh_op_true() -> Vec<u8> {
    let h = qubitcoin_crypto::hash::sha256_hash(&[0x51]);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&h);
    spk
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// POST a JSON-RPC 1.0 request (no "jsonrpc" member, like ckpool) and
/// return the parsed reply object.
fn rpc(port: u16, method: &str, params: Value) -> Value {
    let body = json!({"method": method, "params": params, "id": 7}).to_string();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dTpw\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let json_start = resp.find("\r\n\r\n").unwrap() + 4;
    serde_json::from_str(&resp[json_start..]).unwrap()
}

fn spend(prevout: OutPoint, value: i64, fee: i64) -> TransactionRef {
    Arc::new(Transaction::new(
        2,
        vec![TxIn {
            prevout,
            script_sig: Script::new(),
            sequence: SEQUENCE_FINAL,
            witness: Witness { stack: vec![vec![0x51]] },
        }],
        vec![TxOut::new(Amount::from_sat(value - fee), Script::from_bytes(wsh_op_true()))],
        0,
    ))
}

#[test]
fn test_pool_flow_gbt_solve_submitblock() {
    let params = ChainParams::regtest();
    let mut cs = ChainstateManager::new(params.clone(), Box::new(EmptyCoinsView));
    cs.load_genesis_block(&params.create_genesis_block()).unwrap();
    let cs = Arc::new(Mutex::new(cs));
    let mempool = Arc::new(TxMemPool::new());
    let tip_watch = Arc::new(TipWatch::new(params.genesis_block_hash));
    let sink = Arc::new(RecordingSink {
        inner: MemoryBlockSink {
            chainstate: cs.clone(),
            mempool: mempool.clone(),
            tip_watch: tip_watch.clone(),
        },
        blocks: Mutex::new(Vec::new()),
    });
    let ctx = Arc::new(MiningContext::new(
        cs.clone(),
        mempool.clone(),
        sink.clone(),
        tip_watch,
        BlockAssemblerOptions::default(),
        Arc::new(|| 0),
        true,
        "regtest",
        true,
    ));
    let mut registry = RpcRegistry::new();
    register_mining_rpcs(&mut registry, ctx);

    // A free port picked by the OS (fixed ports collide on shared build hosts).
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let server = RpcServer::new(
        RpcServerConfig {
            bind_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            rpc_user: Some("u".into()),
            rpc_password: Some("p".into()),
        },
        registry,
    );
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let _ = server.serve().await;
        })
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // 1. Mature 2 coinbases paying P2WSH(OP_TRUE).
    let program = wsh_op_true()[2..].to_vec();
    let addr = bech32::segwit::encode(bech32::Hrp::parse("bcrt").unwrap(), bech32::segwit::VERSION_0, &program)
        .unwrap();
    let r = rpc(port, "generatetoaddress", json!([101, addr]));
    assert_eq!(r["error"], Value::Null);
    assert_eq!(r["result"].as_array().unwrap().len(), 101);
    let blocks = sink.blocks.lock().clone();
    assert_eq!(blocks[0].vtx[0].vout[0].script_pubkey.as_bytes(), &wsh_op_true()[..]);

    // 2. Mempool: CPFP pair + unrelated.
    let cb = |i: usize| (OutPoint::new(*blocks[i].vtx[0].txid(), 0), blocks[i].vtx[0].vout[0].value.to_sat());
    let (op1, v1) = cb(0);
    let (op2, v2) = cb(1);
    let parent = spend(op1, v1, 1_000);
    let child = spend(OutPoint::new(*parent.txid(), 0), v1 - 1_000, 40_000);
    let other = spend(op2, v2, 7_000);
    let height = cs.lock().height();
    for (tx, fee) in [(&parent, 1_000), (&child, 40_000), (&other, 7_000)] {
        match accept_to_mempool(&mempool, tx, Amount::from_sat(fee), tx.get_virtual_size() as u32, height) {
            MempoolAcceptResult::Accepted { .. } => {}
            MempoolAcceptResult::Rejected { reason } => panic!("{}", reason),
        }
    }

    // 3. getblocktemplate (JSON-RPC 1.0 reply has both result and error).
    let r = rpc(port, "getblocktemplate", json!([{"rules": ["segwit"]}]));
    assert!(r.as_object().unwrap().contains_key("error"));
    assert_eq!(r["error"], Value::Null);
    let t = &r["result"];
    let txs = t["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 3);
    assert_eq!(txs[0]["txid"], json!(parent.txid().to_hex()));
    assert_eq!(txs[1]["txid"], json!(child.txid().to_hex()));
    assert_eq!(txs[1]["depends"], json!([1]));
    assert_eq!(txs[1]["hash"], json!(child.wtxid().to_hex()));
    assert_eq!(txs[2]["depends"], json!([]));
    let fees: i64 = txs.iter().map(|t| t["fee"].as_i64().unwrap()).sum();
    assert_eq!(fees, 48_000);
    let tmpl_height = t["height"].as_i64().unwrap() as i32;
    assert_eq!(tmpl_height, 102);
    let subsidy = get_block_subsidy(tmpl_height, &params.consensus).to_sat();
    assert_eq!(t["coinbasevalue"].as_i64().unwrap(), subsidy + fees);
    for tx in txs {
        assert!(tx["weight"].as_u64().unwrap() > 0);
        assert_eq!(tx["sigops"], json!(0));
    }

    // 4. Build the block from the template alone.
    let mut script_sig = Script::new();
    script_sig.push_int(tmpl_height as i64);
    script_sig.push_data(b"qbtcpool/extranonce");
    let coinbase = Transaction::new(
        1,
        vec![TxIn {
            prevout: OutPoint::null(),
            script_sig,
            sequence: SEQUENCE_FINAL,
            witness: Witness { stack: vec![vec![0u8; 32]] },
        }],
        vec![
            TxOut::new(
                Amount::from_sat(t["coinbasevalue"].as_i64().unwrap()),
                Script::from_bytes(wsh_op_true()),
            ),
            TxOut::new(
                Amount::ZERO,
                Script::from_bytes(unhex(t["default_witness_commitment"].as_str().unwrap())),
            ),
        ],
        0,
    );
    let mut vtx: Vec<TransactionRef> = vec![Arc::new(coinbase)];
    for tx in txs {
        let parsed: Transaction = deserialize(&unhex(tx["data"].as_str().unwrap())).unwrap();
        assert_eq!(parsed.txid().to_hex(), tx["txid"].as_str().unwrap());
        vtx.push(Arc::new(parsed));
    }
    let mut mutated = false;
    let merkle_root = block_merkle_root(&vtx, &mut mutated);
    let mut block = Block {
        header: BlockHeader {
            version: t["version"].as_i64().unwrap() as i32,
            prev_blockhash: BlockHash::from_hex(t["previousblockhash"].as_str().unwrap()).unwrap(),
            merkle_root,
            time: t["curtime"].as_u64().unwrap() as u32,
            bits: u32::from_str_radix(t["bits"].as_str().unwrap(), 16).unwrap(),
            nonce: 0,
        },
        vtx,
    };
    let target = uint256_to_arith(&qubitcoin_primitives::Uint256::from_hex(t["target"].as_str().unwrap()).unwrap());
    let mut compact = ArithUint256::zero();
    compact.set_compact(block.header.bits);
    assert_eq!(target, compact, "target matches bits");
    while uint256_to_arith(&block.header.block_hash().into_uint256()) > target {
        block.header.nonce += 1;
    }

    // BIP23: the solved block is a valid proposal too.
    let block_hex = hex(&serialize(&block).unwrap());
    let r = rpc(port, "getblocktemplate", json!([{"mode": "proposal", "data": block_hex}]));
    assert_eq!(r["error"], Value::Null);
    assert_eq!(r["result"], Value::Null);

    // 5. submitblock -> null, tip advances, coinbase = subsidy + fees.
    let r = rpc(port, "submitblock", json!([block_hex.clone()]));
    let o = r.as_object().unwrap();
    assert!(o.contains_key("result") && o.contains_key("error"), "{}", r);
    assert_eq!(r["result"], Value::Null, "{}", r);
    assert_eq!(r["error"], Value::Null);
    let hash = block.header.block_hash();
    {
        let cs = cs.lock();
        assert_eq!(cs.height(), 102);
        assert_eq!(cs.block_index().get(cs.tip().unwrap()).block_hash, hash);
    }
    assert_eq!(mempool.size(), 0);
    let mined = sink.blocks.lock().last().unwrap().clone();
    assert_eq!(mined.vtx[0].vout[0].value.to_sat(), subsidy + 48_000);
    let r = rpc(port, "getblockheader", json!([hash.to_hex()]));
    assert_eq!(r["result"]["confirmations"], json!(1));
    assert_eq!(r["result"]["nTx"], json!(4));

    // Re-submission is a duplicate; the next template builds on the new tip.
    let r = rpc(port, "submitblock", json!([block_hex]));
    assert_eq!(r["result"], json!("duplicate"));
    let r = rpc(port, "getblocktemplate", json!([{"rules": ["segwit"]}]));
    assert_eq!(r["result"]["previousblockhash"], json!(hash.to_hex()));
    assert_eq!(r["result"]["transactions"], json!([]));

    // JSON-RPC 1.0 errors still carry "result": null.
    let r = rpc(port, "getblocktemplate", json!([]));
    assert_eq!(r["error"]["code"], json!(-8));
    assert_eq!(r["result"], Value::Null);
}
