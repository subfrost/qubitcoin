//! ZMQ publishers.
//!
//! Port of Bitcoin Core's `src/zmq/` (`CZMQNotificationInterface`,
//! `CZMQPublishHashBlockNotifier`, `...RawBlock...`, `...HashTransaction...`,
//! `...RawTransaction...`, `...Sequence...`) on the pure-Rust `zeromq`
//! crate.
//!
//! Wire format matches Core exactly: every message is three frames,
//! `[topic, body, sequence]`, where `sequence` is a 4-byte little-endian
//! counter kept per notifier (topic + address) starting at 0. Hashes are
//! sent in display (big-endian) byte order. `sequence` bodies are
//! `<32-byte hash><label>` with an 8-byte little-endian mempool sequence
//! appended for the `A` (accepted) and `R` (removed) labels.
//!
//! Notifiers configured with the same address share one PUB socket, as in
//! Core. Publishing happens on a dedicated task fed by a bounded queue; when
//! the queue is full, messages are dropped (Core's high-water mark has the
//! same effect for slow subscribers).

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use zeromq::{PubSocket, Socket, SocketSend, ZmqMessage};

use qubitcoin_consensus::block::Block;
use qubitcoin_node::mempool::{MemPoolRemovalReason, MempoolEvent};
use qubitcoin_primitives::BlockHash;
use qubitcoin_serialize::serialize;

/// Notifier topics (Core's `-zmqpub<topic>` names).
pub const TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

/// Queue depth before messages are dropped.
const QUEUE_DEPTH: usize = 10_000;

/// One `-zmqpub<topic>=<address>` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZmqConfig {
    pub topic: &'static str,
    pub address: String,
}

/// Collect the `-zmqpub*` settings from the command line. Each option may be
/// given more than once (Core allows several addresses per topic).
pub fn configs_from_args(get_args: impl Fn(&str) -> Vec<String>) -> Vec<ZmqConfig> {
    let mut out = Vec::new();
    for topic in TOPICS {
        for address in get_args(&format!("zmqpub{}", topic)) {
            out.push(ZmqConfig { topic, address });
        }
    }
    out
}

/// What to publish (topic, body). The sequence frame is added per notifier.
type Outgoing = (&'static str, Bytes);

/// Handle used by the node to publish notifications.
pub struct ZmqNotifier {
    topics: std::collections::HashSet<&'static str>,
    queue: tokio::sync::mpsc::Sender<Outgoing>,
}

/// Display-order (big-endian) bytes of a hash, as Core's notifiers send.
fn display_bytes(le: &[u8]) -> Vec<u8> {
    let mut v = le.to_vec();
    v.reverse();
    v
}

/// The `sequence` topic body. Port of `CZMQPublishSequenceNotifier`'s
/// `SendSequenceMsg`.
pub fn sequence_body(hash_le: &[u8], label: u8, mempool_sequence: Option<u64>) -> Vec<u8> {
    let mut body = display_bytes(hash_le);
    body.push(label);
    if let Some(seq) = mempool_sequence {
        body.extend_from_slice(&seq.to_le_bytes());
    }
    body
}

/// Build the three-frame message Core sends (`SendZmqMessage`).
pub fn frame(topic: &str, body: Bytes, sequence: u32) -> ZmqMessage {
    let mut msg = ZmqMessage::from(topic.as_bytes().to_vec());
    msg.push_back(body);
    msg.push_back(Bytes::copy_from_slice(&sequence.to_le_bytes()));
    msg
}

impl ZmqNotifier {
    /// Bind every configured address and start the publishing task.
    /// Fails if any address cannot be bound (Core refuses to start then).
    pub async fn start(configs: &[ZmqConfig]) -> Result<Arc<ZmqNotifier>, String> {
        // One socket per distinct address; each (topic, address) pair is a
        // notifier with its own sequence counter.
        let mut sockets: HashMap<String, PubSocket> = HashMap::new();
        for c in configs {
            if sockets.contains_key(&c.address) {
                continue;
            }
            let mut sock = PubSocket::new();
            sock.bind(&c.address)
                .await
                .map_err(|e| format!("zmq bind {} ({}): {}", c.address, c.topic, e))?;
            tracing::info!(address = %c.address, "ZMQ publisher bound");
            sockets.insert(c.address.clone(), sock);
        }
        let mut notifiers: HashMap<&'static str, Vec<(String, u32)>> = HashMap::new();
        for c in configs {
            tracing::info!(topic = c.topic, address = %c.address, "ZMQ notifier enabled");
            notifiers.entry(c.topic).or_default().push((c.address.clone(), 0));
        }
        let topics = notifiers.keys().copied().collect();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Outgoing>(QUEUE_DEPTH);
        tokio::spawn(async move {
            while let Some((topic, body)) = rx.recv().await {
                if let Some(list) = notifiers.get_mut(topic) {
                    for (address, seq) in list.iter_mut() {
                        if let Some(sock) = sockets.get_mut(address.as_str()) {
                            if let Err(e) = sock.send(frame(topic, body.clone(), *seq)).await {
                                tracing::warn!(topic, address = %address, error = %e, "ZMQ send failed");
                            }
                        }
                        *seq = seq.wrapping_add(1);
                    }
                }
            }
        });
        Ok(Arc::new(ZmqNotifier { topics, queue: tx }))
    }

    fn wants(&self, topic: &str) -> bool {
        self.topics.contains(topic)
    }

    fn publish(&self, topic: &'static str, body: Vec<u8>) {
        if let Err(e) = self.queue.try_send((topic, Bytes::from(body))) {
            tracing::warn!(topic, error = %e, "ZMQ queue full, dropping notification");
        }
    }

    fn notify_transaction(&self, tx: &qubitcoin_consensus::transaction::Transaction) {
        if self.wants("hashtx") {
            self.publish("hashtx", display_bytes(tx.txid().as_bytes()));
        }
        if self.wants("rawtx") {
            if let Ok(raw) = serialize(tx) {
                self.publish("rawtx", raw);
            }
        }
    }

    /// Core's `BlockConnected`: `hashtx`/`rawtx` for every transaction,
    /// then the `C` sequence entry.
    pub fn block_connected(&self, block: &Block) {
        for tx in &block.vtx {
            self.notify_transaction(tx);
        }
        if self.wants("sequence") {
            self.publish("sequence", sequence_body(block.header.block_hash().as_bytes(), b'C', None));
        }
    }

    /// Core's `BlockDisconnected`: `hashtx`/`rawtx` for every transaction,
    /// then the `D` sequence entry.
    pub fn block_disconnected(&self, block: &Block) {
        for tx in &block.vtx {
            self.notify_transaction(tx);
        }
        if self.wants("sequence") {
            self.publish("sequence", sequence_body(block.header.block_hash().as_bytes(), b'D', None));
        }
    }

    /// Core's `UpdatedBlockTip`: `hashblock`/`rawblock` for the new tip,
    /// except during initial block download.
    pub fn updated_block_tip(&self, tip: &Block, hash: BlockHash, initial_download: bool) {
        if initial_download {
            return;
        }
        if self.wants("hashblock") {
            self.publish("hashblock", display_bytes(hash.as_bytes()));
        }
        if self.wants("rawblock") {
            if let Ok(raw) = serialize(tip) {
                self.publish("rawblock", raw);
            }
        }
    }

    /// Mempool acceptance (`A`, plus hashtx/rawtx) or removal for any reason
    /// other than inclusion in a block (`R`).
    pub fn mempool_event(&self, event: &MempoolEvent) {
        match event {
            MempoolEvent::Added { tx, mempool_sequence } => {
                self.notify_transaction(tx);
                if self.wants("sequence") {
                    self.publish(
                        "sequence",
                        sequence_body(tx.txid().as_bytes(), b'A', Some(*mempool_sequence)),
                    );
                }
            }
            MempoolEvent::Removed {
                tx,
                reason,
                mempool_sequence,
            } => {
                if *reason != MemPoolRemovalReason::Block && self.wants("sequence") {
                    self.publish(
                        "sequence",
                        sequence_body(tx.txid().as_bytes(), b'R', Some(*mempool_sequence)),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeromq::{SocketRecv, SubSocket};

    #[test]
    fn test_sequence_body_layout() {
        let mut le = [0u8; 32];
        le[0] = 0xaa; // least significant byte first in memory
        let b = sequence_body(&le, b'A', Some(0x0102));
        assert_eq!(b.len(), 32 + 1 + 8);
        assert_eq!(b[31], 0xaa, "hash is sent in display order");
        assert_eq!(b[32], b'A');
        assert_eq!(&b[33..], &0x0102u64.to_le_bytes());
        assert_eq!(sequence_body(&le, b'C', None).len(), 33);
    }

    #[test]
    fn test_frame_has_core_three_parts() {
        let m = frame("hashblock", Bytes::from_static(&[1, 2, 3]), 7);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(0).unwrap().as_ref(), b"hashblock");
        assert_eq!(m.get(1).unwrap().as_ref(), &[1, 2, 3]);
        assert_eq!(m.get(2).unwrap().as_ref(), &7u32.to_le_bytes());
    }

    #[test]
    fn test_configs_from_args() {
        let cfgs = configs_from_args(|k| match k {
            "zmqpubhashblock" => vec!["tcp://127.0.0.1:1".into(), "tcp://127.0.0.1:2".into()],
            "zmqpubrawtx" => vec!["tcp://127.0.0.1:1".into()],
            _ => vec![],
        });
        assert_eq!(cfgs.len(), 3);
        assert_eq!(cfgs[2].topic, "rawtx");
    }

    #[tokio::test]
    async fn test_publish_hashblock_and_sequence_to_subscriber() {
        let port = 41000 + (std::process::id() % 10000) as u16;
        let addr = format!("tcp://127.0.0.1:{}", port);
        let n = ZmqNotifier::start(&[
            ZmqConfig { topic: "hashblock", address: addr.clone() },
            ZmqConfig { topic: "sequence", address: addr.clone() },
        ])
        .await
        .unwrap();
        let mut sub = SubSocket::new();
        sub.connect(&addr).await.unwrap();
        sub.subscribe("").await.unwrap();
        // Let the subscription propagate (PUB drops messages for unknown subs).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let params = qubitcoin_common::chainparams::ChainParams::regtest();
        let genesis = params.create_genesis_block();
        let hash = genesis.header.block_hash();
        n.block_connected(&genesis);
        n.updated_block_tip(&genesis, hash, false);

        let mut got = Vec::new();
        for _ in 0..2 {
            let m = tokio::time::timeout(std::time::Duration::from_secs(5), sub.recv())
                .await
                .expect("zmq message")
                .unwrap();
            got.push(m);
        }
        let seq = got.iter().find(|m| m.get(0).unwrap().as_ref() == b"sequence").unwrap();
        assert_eq!(seq.get(1).unwrap().len(), 33);
        assert_eq!(seq.get(1).unwrap()[32], b'C');
        let hb = got.iter().find(|m| m.get(0).unwrap().as_ref() == b"hashblock").unwrap();
        assert_eq!(hb.get(1).unwrap().as_ref(), &display_bytes(hash.as_bytes())[..]);
        assert_eq!(hb.get(2).unwrap().as_ref(), &0u32.to_le_bytes());

        // During IBD only the connect sequence entry is published.
        n.block_connected(&genesis);
        n.updated_block_tip(&genesis, hash, true);
        let m = tokio::time::timeout(std::time::Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m.get(0).unwrap().as_ref(), b"sequence");
        assert_eq!(m.get(2).unwrap().as_ref(), &1u32.to_le_bytes());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(300), sub.recv())
            .await
            .is_err());

        // A disconnect publishes the D entry.
        n.block_disconnected(&genesis);
        let m = tokio::time::timeout(std::time::Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m.get(1).unwrap()[32], b'D');
        assert_eq!(m.get(2).unwrap().as_ref(), &2u32.to_le_bytes());
    }
}
