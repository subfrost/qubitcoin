//! External notifications: `-blocknotify` and ZMQ publishers.
//!
//! Port of the `-blocknotify` handler in Bitcoin Core's `init.cpp`
//! (`NotifyBlockTip` -> `runCommand`), plus the ZMQ publishers of
//! `src/zmq/` (see `crate::zmq`, built with the `zmq` feature).

use qubitcoin_consensus::block::Block;
use qubitcoin_node::mempool::MempoolEvent;
use qubitcoin_primitives::BlockHash;

/// Run `-blocknotify` for a new tip: `%s` in the command is replaced by the
/// block hash and the command runs through `sh -c` on a detached thread,
/// as Core's `runCommand` does with `system()`.
fn run_block_notify(template: &str, hash: &BlockHash) {
    let command = template.replace("%s", &hash.to_hex());
    std::thread::spawn(move || {
        match std::process::Command::new("sh").arg("-c").arg(&command).status() {
            Ok(st) if st.success() => {}
            Ok(st) => tracing::warn!(command = %command, status = %st, "blocknotify command failed"),
            Err(e) => tracing::warn!(command = %command, error = %e, "blocknotify command failed to start"),
        }
    });
}

/// Fan-out to every configured external notifier.
#[derive(Default)]
pub struct Notifications {
    /// `-blocknotify=<cmd>`.
    pub block_notify: Option<String>,
    /// ZMQ publishers (`-zmqpub*`).
    #[cfg(feature = "zmq")]
    pub zmq: Option<std::sync::Arc<crate::zmq::ZmqNotifier>>,
}

impl Notifications {
    /// Core's `BlockDisconnected` (a block left the active chain).
    pub fn block_disconnected(&self, block: &Block) {
        #[cfg(feature = "zmq")]
        if let Some(z) = &self.zmq {
            z.block_disconnected(block);
        }
        let _ = block;
    }

    /// Core's `BlockConnected` (a block joined the active chain).
    pub fn block_connected(&self, block: &Block) {
        #[cfg(feature = "zmq")]
        if let Some(z) = &self.zmq {
            z.block_connected(block);
        }
        let _ = block;
    }

    /// Core's `UpdatedBlockTip` / `NotifyBlockTip`: the active tip moved to
    /// `tip` (after any reorganisation completed).
    pub fn updated_block_tip(&self, tip: &Block, hash: BlockHash, initial_download: bool) {
        // Core only runs -blocknotify once out of initial sync
        // (SynchronizationState::POST_INIT).
        if !initial_download {
            if let Some(cmd) = &self.block_notify {
                run_block_notify(cmd, &hash);
            }
        }
        #[cfg(feature = "zmq")]
        if let Some(z) = &self.zmq {
            z.updated_block_tip(tip, hash, initial_download);
        }
        let _ = tip;
    }

    /// Mempool listener entry point.
    pub fn mempool_event(&self, event: &MempoolEvent) {
        #[cfg(feature = "zmq")]
        if let Some(z) = &self.zmq {
            z.mempool_event(event);
        }
        let _ = event;
    }
}
