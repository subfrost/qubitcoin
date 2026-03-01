//! Q-Day policy configuration.

use crate::frozen_set::FrozenOutpoints;

/// Policy parameters for the Q-Day regression consensus rule.
///
/// Defines when the quantum-vulnerability freeze activates and what
/// score threshold determines which outputs get frozen.
#[derive(Debug, Clone)]
pub struct QdayPolicy {
    /// Block height at which the Q-Day freeze activates.
    /// Set to -1 (or i32::MAX) to disable.
    pub activation_height: i32,

    /// Minimum safety score (0-1000) for an outpoint to be frozen.
    /// Higher threshold = fewer outputs frozen = more conservative.
    pub score_threshold: u16,

    /// The computed frozen outpoints set. Built at activation height
    /// by scanning the UTXO set and scoring each vulnerable output.
    pub frozen_outpoints: FrozenOutpoints,
}

impl QdayPolicy {
    /// Create a disabled Q-Day policy (no freeze).
    pub fn disabled() -> Self {
        QdayPolicy {
            activation_height: i32::MAX,
            score_threshold: 1000,
            frozen_outpoints: FrozenOutpoints::new(),
        }
    }

    /// Create a new policy with the given parameters.
    pub fn new(activation_height: i32, score_threshold: u16) -> Self {
        QdayPolicy {
            activation_height,
            score_threshold,
            frozen_outpoints: FrozenOutpoints::new(),
        }
    }

    /// Check if the Q-Day freeze is active at the given height.
    pub fn is_active(&self, height: i32) -> bool {
        self.activation_height != i32::MAX && height >= self.activation_height
    }
}

impl Default for QdayPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_policy() {
        let policy = QdayPolicy::disabled();
        assert!(!policy.is_active(0));
        assert!(!policy.is_active(1_000_000));
        assert!(!policy.is_active(i32::MAX - 1));
    }

    #[test]
    fn test_active_policy() {
        let policy = QdayPolicy::new(850_000, 500);
        assert!(!policy.is_active(849_999));
        assert!(policy.is_active(850_000));
        assert!(policy.is_active(900_000));
    }
}
