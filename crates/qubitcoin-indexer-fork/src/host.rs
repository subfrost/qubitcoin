//! Extended host context and execution limits for DAG execution.
//!
//! The base fork runtime exposes the plain metashrew ABI. Indexer DAGs need
//! two more things:
//!
//!   * **Upstream reads.** A tertiary indexer reads another indexer's KV
//!     through `__secondary_get_len` / `__secondary_get` (the ABI of
//!     `qubitcoin-tertiary-support`). A transform program may also call any
//!     view of a declared upstream through `__upstream_view` /
//!     `__upstream_view_read`. Both go through a caller-supplied
//!     [`HostContext`]; the caller decides which upstreams exist, at which
//!     height they are read, and whether the read hits a persistent DB or a
//!     simulation overlay. Anything the context refuses fails the run.
//!   * **Caps.** [`ExecLimits`] bounds fuel, linear memory and wall-clock
//!     time for one invocation. The outcome reports the fuel used either way.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// Reads another node's KV store (`__secondary_get`).
pub trait SecondaryReader: Send + Sync {
    /// Value of `key` in the store of `indexer`. `Ok(None)` = absent.
    /// `Err` = refused or failed; the run is failed with that message.
    fn secondary_get(&self, indexer: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
}

/// Calls a view function of another node (`__upstream_view`).
#[async_trait]
pub trait UpstreamViewCaller: Send + Sync {
    /// Result bytes of `view_fn(input)` on `indexer`. `Err` fails the run.
    async fn upstream_view(
        &self,
        indexer: &str,
        view_fn: &str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, String>;
}

/// Optional host services for one invocation.
#[derive(Clone, Default)]
pub struct HostContext {
    pub secondary: Option<Arc<dyn SecondaryReader>>,
    pub views: Option<Arc<dyn UpstreamViewCaller>>,
}

/// Caps for one invocation. `None` = uncapped.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecLimits {
    /// wasmtime fuel (≈ instructions).
    pub fuel: Option<u64>,
    /// Maximum linear memory in bytes.
    pub max_memory_bytes: Option<usize>,
    /// Wall-clock deadline for the invocation.
    pub deadline: Option<Duration>,
}

/// Why an invocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecErrorKind {
    OutOfFuel,
    Deadline,
    Memory,
    /// The host context refused or failed a request (e.g. an undeclared upstream).
    Host,
    /// Trap, abort, missing export, missing `__flush`, compile error, ...
    Failed,
}

impl ExecErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecErrorKind::OutOfFuel => "out_of_fuel",
            ExecErrorKind::Deadline => "deadline",
            ExecErrorKind::Memory => "memory",
            ExecErrorKind::Host => "host",
            ExecErrorKind::Failed => "failed",
        }
    }
}

/// A failed invocation.
#[derive(Clone, Debug)]
pub struct ExecError {
    pub kind: ExecErrorKind,
    pub message: String,
    pub fuel_used: u64,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)
    }
}

/// A successful invocation.
#[derive(Clone, Debug)]
pub struct ExecOutcome<T> {
    pub value: T,
    pub fuel_used: u64,
}
