//! External notifications: `-blocknotify` and ZMQ publishers.
//!
//! Port of the `-blocknotify` handler in Bitcoin Core's `init.cpp`
//! (`NotifyBlockTip` -> `runCommand`).

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
}

impl Notifications {
    /// A new tip was connected (Core: `UpdatedBlockTip` + `BlockConnected`).
    pub fn block_connected(&self, block: &Block, hash: BlockHash, initial_download: bool) {
        // Core only runs -blocknotify once out of initial sync
        // (SynchronizationState::POST_INIT).
        if !initial_download {
            if let Some(cmd) = &self.block_notify {
                run_block_notify(cmd, &hash);
            }
        }
        let _ = block;
    }

    /// Mempool listener entry point.
    pub fn mempool_event(&self, event: &MempoolEvent) {
        let _ = event;
    }
}
