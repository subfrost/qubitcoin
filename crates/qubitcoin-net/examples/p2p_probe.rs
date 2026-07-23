//! Standalone P2P handshake probe — connects to a bitcoin Core node via
//! qubitcoin-net's ConnManager, logs every connection event, and (on a
//! successful handshake) requests the mempool. Used in isolation to debug the
//! qubitcoin-net <-> bitcoin-Core handshake without touching prod.
//!
//! Usage:
//!   cargo run --example p2p_probe -- <host:port> <regtest|mainnet|signet|testnet>
//! Default: 127.0.0.1:18444 regtest

use std::time::Duration;

use qubitcoin_net::connection::{serialize_message, ConnConfig, ConnManager, ConnectionEvent};
use qubitcoin_net::protocol::{InvType, InvVect, NetMessage, NetworkMagic, ServiceFlags};

#[tokio::main]
async fn main() {
    let addr_s = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:18444".to_string());
    let net = std::env::args().nth(2).unwrap_or_else(|| "regtest".to_string());
    let addr: std::net::SocketAddr = addr_s.parse().expect("valid host:port");
    let magic = match net.as_str() {
        "mainnet" => NetworkMagic::MAINNET,
        "testnet" => NetworkMagic::TESTNET,
        "signet" => NetworkMagic::SIGNET,
        _ => NetworkMagic::REGTEST,
    };

    println!("[probe] target={addr} net={net} magic={magic:?}");

    let config = ConnConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        magic,
        max_inbound: 0,
        max_outbound: 1,
        our_services: ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS,
        user_agent: "/qubitcoin-probe:0.1.0/".to_string(),
        best_height: 0,
    };

    let mut cm = ConnManager::new(config);
    let mut events = cm.take_events().expect("events");

    println!("[probe] connecting...");
    match cm.connect_to(addr).await {
        Ok(id) => println!("[probe] connect_to returned Ok(peer_id={id})"),
        Err(e) => {
            println!("[probe] connect_to FAILED: {e}");
            return;
        }
    }

    // Overall watchdog: if no handshake within 15s, dump state and exit.
    let watchdog = tokio::time::sleep(Duration::from_secs(25));
    tokio::pin!(watchdog);
    let mut handshaked = false;
    let mut recv_count = 0u32;

    loop {
        tokio::select! {
            _ = &mut watchdog => {
                println!("[probe] WATCHDOG 25s: handshaked={handshaked} msgs_received={recv_count}");
                if !handshaked {
                    println!("[probe] -> handshake never completed (hang). Peer sent {recv_count} msgs.");
                }
                break;
            }
            ev = events.recv() => {
                let Some(ev) = ev else { println!("[probe] event channel closed"); break; };
                match ev {
                    ConnectionEvent::NewOutbound { peer_id, addr } =>
                        println!("[probe] EVENT NewOutbound peer={peer_id} addr={addr}"),
                    ConnectionEvent::NewInbound { peer_id, addr } =>
                        println!("[probe] EVENT NewInbound peer={peer_id} addr={addr}"),
                    ConnectionEvent::HandshakeComplete { peer_id } => {
                        handshaked = true;
                        // DO NOT send "mempool" — Core disconnects peers that request it
                        // without peerbloomfilters (BIP35). New txs arrive via inv relay
                        // (txrelay negotiated in version); initial snapshot is via RPC.
                        println!("[probe] EVENT *** HandshakeComplete *** peer={peer_id} — staying connected, awaiting inv/tx relay");
                    }
                    ConnectionEvent::MessageReceived { peer_id, message } => {
                        recv_count += 1;
                        let desc = match &message {
                            NetMessage::Version(_) => "version".to_string(),
                            NetMessage::Verack => "verack".to_string(),
                            NetMessage::Ping(n) => format!("ping({n})"),
                            NetMessage::Inv(v) => format!("inv({} items)", v.len()),
                            NetMessage::Tx(b) => format!("tx({} bytes)", b.len()),
                            other => format!("{other:?}").chars().take(60).collect(),
                        };
                        println!("[probe] EVENT MessageReceived peer={peer_id} msg={desc}");
                        // Reproduce the driver: on inv, request tx invs via getdata
                        // (upgrading bare Tx -> WitnessTx to pull witnesses).
                        if let NetMessage::Inv(invs) = message {
                            let wanted: Vec<InvVect> = invs
                                .into_iter()
                                .filter_map(|iv| match iv.inv_type {
                                    InvType::Tx => Some(InvVect::new(InvType::WitnessTx, iv.hash)),
                                    InvType::WTx | InvType::WitnessTx => Some(iv),
                                    _ => None,
                                })
                                .collect();
                            if !wanted.is_empty() {
                                println!("[probe]   -> getdata for {} tx inv(s)", wanted.len());
                                let payload = serialize_message(&NetMessage::GetData(wanted));
                                cm.send_to_peer(peer_id, "getdata", payload);
                            }
                        }
                    }
                    ConnectionEvent::Disconnected { peer_id, reason } =>
                        println!("[probe] EVENT Disconnected peer={peer_id} reason={reason}"),
                }
            }
        }
    }
    cm.shutdown();
    println!("[probe] done.");
}
