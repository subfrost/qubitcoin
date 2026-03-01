use thiserror::Error;

/// Errors from Q-Day regression validation.
#[derive(Debug, Error)]
pub enum QdayError {
    /// Transaction spends a frozen (quantum-vulnerable) outpoint.
    #[error("tx spends frozen outpoint {txid}:{vout} (score {score})")]
    FrozenOutpointSpent {
        txid: String,
        vout: u32,
        score: u16,
    },

    /// Failed to compute the frozen set at activation height.
    #[error("failed to compute frozen set: {0}")]
    FrozenSetComputation(String),

    /// Policy configuration error.
    #[error("invalid qday policy: {0}")]
    InvalidPolicy(String),

    /// UTXO iteration error during frozen set computation.
    #[error("utxo iteration error: {0}")]
    UtxoIteration(String),
}
