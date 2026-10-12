//! Transform nodes: derived blocks for downstream indexers.
//!
//! A transform is a pure function of `(raw block, height, upstream state at
//! that height)` producing the block bytes a downstream indexer receives as
//! its `_start` input (`height_le32 ++ T(block)`). Transforms keep no state.
//!
//! * [`embed_in_coinbase`] is the built-in `embed-view-in-coinbase`: append
//!   one coinbase output `OP_RETURN <push(magic ++ view_result)>`. The header
//!   is untouched, so the block hash is unchanged. With
//!   `{upstream: alkanes, view: traceblock, magic: ASP0}` it reproduces
//!   alspo's `embed_traces` and the `/v4/{apikey}/traces` facade byte for byte.
//! * A wasm transform exports `transform() -> i32` (an ArrayBuffer pointer to
//!   the output block). Its input (`__host_len`/`__load_input`) is
//!   `height_le32 ++ raw block`; it may read its declared upstreams through
//!   `__secondary_get_len`/`__secondary_get` and call their views through
//!   `__upstream_view(name, fn, input) -> len` + `__upstream_view_read(ptr)`.

use crate::dag::DagAccess;
use qubitcoin_consensus::block::Block;
use qubitcoin_consensus::transaction::{Transaction, TxOut};
use qubitcoin_indexer_fork::{ExecError, ExecErrorKind, ExecLimits, ExecOutcome, ForkRuntime};
use qubitcoin_primitives::Amount;
use qubitcoin_script::Script;
use std::sync::Arc;

/// `OP_RETURN` followed by one push of `data`, using the same push opcode as
/// rust-bitcoin's `Builder::push_slice` (direct length below 0x4c, then
/// `OP_PUSHDATA1/2/4`).
pub fn op_return_push(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut s = Vec::with_capacity(n + 6);
    s.push(0x6a);
    if n < 0x4c {
        s.push(n as u8);
    } else if n <= 0xff {
        s.push(0x4c);
        s.push(n as u8);
    } else if n <= 0xffff {
        s.push(0x4d);
        s.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        s.push(0x4e);
        s.extend_from_slice(&(n as u32).to_le_bytes());
    }
    s.extend_from_slice(data);
    s
}

/// Append `OP_RETURN <push(magic ++ payload)>` (value 0) to the coinbase of a
/// serialized block and re-serialize it. A block without transactions is
/// returned unchanged, as alspo's `embed_traces` does.
pub fn embed_in_coinbase(block: &[u8], magic: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut b: Block = qubitcoin_serialize::deserialize(block).map_err(|e| format!("block decode: {}", e))?;
    if let Some(cb) = b.vtx.first().cloned() {
        let mut data = Vec::with_capacity(magic.len() + payload.len());
        data.extend_from_slice(magic);
        data.extend_from_slice(payload);
        let mut vout = cb.vout.clone();
        vout.push(TxOut::new(Amount::ZERO, Script::from_bytes(op_return_push(&data))));
        b.vtx[0] = Arc::new(Transaction::new(cb.version, cb.vin.clone(), vout, cb.lock_time));
    }
    qubitcoin_serialize::serialize(&b).map_err(|e| format!("block encode: {}", e))
}

/// What a transform runs.
pub enum TransformExec {
    EmbedViewInCoinbase {
        upstream: String,
        view: String,
        magic: Vec<u8>,
        view_input: Vec<u8>,
    },
    Wasm {
        runtime: Arc<ForkRuntime>,
        sha256: [u8; 32],
        upstreams: Vec<String>,
    },
}

/// A transform node of the DAG.
pub struct TransformNode {
    pub name: String,
    pub exec: TransformExec,
    /// Fuel cap per block (wasm only).
    pub fuel: Option<u64>,
}

impl TransformNode {
    /// Nodes this transform reads (its DAG upstreams).
    pub fn upstreams(&self) -> Vec<String> {
        match &self.exec {
            TransformExec::EmbedViewInCoinbase { upstream, .. } => vec![upstream.clone()],
            TransformExec::Wasm { upstreams, .. } => upstreams.clone(),
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match &self.exec {
            TransformExec::EmbedViewInCoinbase { .. } => "embed-view-in-coinbase",
            TransformExec::Wasm { .. } => "wasm",
        }
    }

    /// Build from config, reading and hash-checking a wasm program.
    pub fn from_config(cfg: &crate::config::TransformConfig) -> Result<Self, String> {
        use crate::config::TransformKindConfig as K;
        let exec = match &cfg.kind {
            K::EmbedViewInCoinbase { upstream, view, magic, view_input } => TransformExec::EmbedViewInCoinbase {
                upstream: upstream.clone(),
                view: view.clone(),
                magic: magic.clone(),
                view_input: view_input.clone(),
            },
            K::Wasm { path, sha256, upstreams } => {
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("transform '{}': read {}: {}", cfg.name, path.display(), e))?;
                Self::wasm_exec(&cfg.name, &bytes, sha256.as_deref(), upstreams.clone())?
            }
        };
        Ok(TransformNode { name: cfg.name.clone(), exec, fuel: cfg.fuel })
    }

    /// Compile a wasm transform, verifying `expected_sha256` (hex) if given.
    pub fn wasm_exec(
        name: &str,
        bytes: &[u8],
        expected_sha256: Option<&str>,
        upstreams: Vec<String>,
    ) -> Result<TransformExec, String> {
        use sha2::{Digest, Sha256};
        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(want) = expected_sha256 {
            if hex::encode(sha256) != want.to_lowercase() {
                return Err(format!("transform '{}': sha256 mismatch (have {})", name, hex::encode(sha256)));
            }
        }
        let runtime = ForkRuntime::new(bytes).map_err(|e| format!("transform '{}': {}", name, e))?;
        if !runtime.has_export("transform") {
            return Err(format!("transform '{}': wasm does not export `transform`", name));
        }
        Ok(TransformExec::Wasm { runtime: Arc::new(runtime), sha256, upstreams })
    }

    /// Apply the transform to `raw_block` at `height`.
    pub async fn apply(
        &self,
        height: u32,
        raw_block: &[u8],
        access: DagAccess,
        limits: ExecLimits,
    ) -> Result<ExecOutcome<Vec<u8>>, ExecError> {
        match &self.exec {
            TransformExec::EmbedViewInCoinbase { upstream, view, magic, view_input } => {
                let payload = access.view(upstream, view, view_input.clone()).await.map_err(|e| ExecError {
                    kind: ExecErrorKind::Host,
                    message: e,
                    fuel_used: 0,
                })?;
                let out = embed_in_coinbase(raw_block, magic, &payload).map_err(|e| ExecError {
                    kind: ExecErrorKind::Failed,
                    message: e,
                    fuel_used: 0,
                })?;
                Ok(ExecOutcome { value: out, fuel_used: 0 })
            }
            TransformExec::Wasm { runtime, .. } => {
                let mut input = Vec::with_capacity(4 + raw_block.len());
                input.extend_from_slice(&height.to_le_bytes());
                input.extend_from_slice(raw_block);
                let limits = ExecLimits { fuel: self.fuel.or(limits.fuel), ..limits };
                runtime
                    .call_export_ctx(
                        "transform",
                        input,
                        qubitcoin_indexer_fork::MemStorage::new_local(height),
                        &self.name,
                        access.host(),
                        limits,
                    )
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_opcodes_match_rust_bitcoin() {
        use bitcoin::script::{Builder, PushBytesBuf};
        for n in [4usize, 0x4b, 0x4c, 0xff, 0x100, 0xffff, 0x10000, 70_000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let pb = PushBytesBuf::try_from(data.clone()).unwrap();
            let want = Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                .push_slice(pb)
                .into_script();
            assert_eq!(op_return_push(&data), want.as_bytes(), "len {}", n);
        }
    }
}
