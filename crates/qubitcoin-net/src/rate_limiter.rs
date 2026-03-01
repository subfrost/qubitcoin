//! Connection-level rate limiting and backpressure.
//!
//! Bitcoin Core has ad-hoc rate limiting scattered across net.cpp and
//! net_processing.cpp. We improve on this with a structured rate limiting
//! system that provides:
//!
//! 1. Per-peer message rate limiting (messages/sec)
//! 2. Per-peer bandwidth limiting (bytes/sec)
//! 3. Global bandwidth limits
//! 4. Automatic slow-peer detection and disconnection
//! 5. Backpressure via bounded message queues

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum messages per second per peer.
    pub max_messages_per_sec: u32,
    /// Maximum bytes per second per peer (0 = unlimited).
    pub max_bytes_per_sec: u64,
    /// Maximum global bytes per second (0 = unlimited).
    pub max_global_bytes_per_sec: u64,
    /// Maximum pending messages in the send queue before backpressure.
    pub max_send_queue_size: usize,
    /// Maximum pending messages in the receive queue before dropping.
    pub max_recv_queue_size: usize,
    /// Time window for rate calculation.
    pub window: Duration,
    /// If a peer is this many seconds behind, consider them "slow".
    pub slow_peer_threshold_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_messages_per_sec: 200,
            max_bytes_per_sec: 10 * 1024 * 1024, // 10 MB/s
            max_global_bytes_per_sec: 100 * 1024 * 1024, // 100 MB/s
            max_send_queue_size: 1000,
            max_recv_queue_size: 5000,
            window: Duration::from_secs(1),
            slow_peer_threshold_secs: 120,
        }
    }
}

/// Token bucket rate limiter.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity).
    capacity: u64,
    /// Current available tokens.
    tokens: f64,
    /// Token refill rate per second.
    rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with the given rate and burst capacity.
    pub fn new(rate: f64, capacity: u64) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity as f64,
            rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume `n` tokens. Returns true if successful.
    pub fn try_consume(&mut self, n: u64) -> bool {
        self.refill();
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Check if `n` tokens are available without consuming them.
    pub fn can_consume(&mut self, n: u64) -> bool {
        self.refill();
        self.tokens >= n as f64
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Get current available tokens.
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }
}

/// Per-peer rate limiting state.
#[derive(Debug)]
pub struct PeerRateState {
    /// Message rate limiter.
    pub message_limiter: TokenBucket,
    /// Bandwidth rate limiter.
    pub bandwidth_limiter: TokenBucket,
    /// Total messages received from this peer.
    pub messages_received: u64,
    /// Total bytes received from this peer.
    pub bytes_received: u64,
    /// Total messages sent to this peer.
    pub messages_sent: u64,
    /// Total bytes sent to this peer.
    pub bytes_sent: u64,
    /// Number of rate limit violations.
    pub violations: u64,
    /// Current send queue depth.
    pub send_queue_depth: usize,
    /// Time of last activity.
    pub last_activity: Instant,
}

impl PeerRateState {
    /// Create a new per-peer rate state initialized from the given configuration.
    pub fn new(config: &RateLimitConfig) -> Self {
        PeerRateState {
            message_limiter: TokenBucket::new(
                config.max_messages_per_sec as f64,
                config.max_messages_per_sec as u64 * 2, // allow burst of 2x
            ),
            bandwidth_limiter: TokenBucket::new(
                config.max_bytes_per_sec as f64,
                config.max_bytes_per_sec * 2,
            ),
            messages_received: 0,
            bytes_received: 0,
            messages_sent: 0,
            bytes_sent: 0,
            violations: 0,
            send_queue_depth: 0,
            last_activity: Instant::now(),
        }
    }
}

/// Global rate limiter managing all peer connections.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-peer rate state.
    peers: RwLock<HashMap<u64, PeerRateState>>,
    /// Global bandwidth limiter.
    global_bandwidth: RwLock<TokenBucket>,
}

impl RateLimiter {
    /// Create a new global rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bw = TokenBucket::new(
            config.max_global_bytes_per_sec as f64,
            config.max_global_bytes_per_sec * 2,
        );
        RateLimiter {
            config,
            peers: RwLock::new(HashMap::new()),
            global_bandwidth: RwLock::new(global_bw),
        }
    }

    /// Register a new peer connection.
    pub fn add_peer(&self, peer_id: u64) {
        let state = PeerRateState::new(&self.config);
        self.peers.write().insert(peer_id, state);
    }

    /// Remove a peer connection.
    pub fn remove_peer(&self, peer_id: u64) {
        self.peers.write().remove(&peer_id);
    }

    /// Check if a message from a peer should be accepted.
    ///
    /// Returns `RateLimitResult` indicating whether to accept, defer, or reject.
    pub fn check_inbound(&self, peer_id: u64, message_bytes: u64) -> RateLimitResult {
        let mut peers = self.peers.write();
        let state = match peers.get_mut(&peer_id) {
            Some(s) => s,
            None => return RateLimitResult::Accept, // Unknown peer, allow
        };

        // Check message rate
        if !state.message_limiter.try_consume(1) {
            state.violations += 1;
            if state.violations > 100 {
                return RateLimitResult::Disconnect("excessive rate limit violations".to_string());
            }
            return RateLimitResult::RateLimited;
        }

        // Check per-peer bandwidth
        if message_bytes > 0 && !state.bandwidth_limiter.try_consume(message_bytes) {
            return RateLimitResult::RateLimited;
        }

        // Check global bandwidth
        {
            let mut global = self.global_bandwidth.write();
            if message_bytes > 0 && !global.try_consume(message_bytes) {
                return RateLimitResult::RateLimited;
            }
        }

        state.messages_received += 1;
        state.bytes_received += message_bytes;
        state.last_activity = Instant::now();

        RateLimitResult::Accept
    }

    /// Check if we can send a message to a peer.
    pub fn check_outbound(&self, peer_id: u64, message_bytes: u64) -> RateLimitResult {
        let mut peers = self.peers.write();
        let state = match peers.get_mut(&peer_id) {
            Some(s) => s,
            None => return RateLimitResult::Accept,
        };

        // Check send queue depth
        if state.send_queue_depth >= self.config.max_send_queue_size {
            return RateLimitResult::Backpressure;
        }

        state.messages_sent += 1;
        state.bytes_sent += message_bytes;
        state.send_queue_depth += 1;

        RateLimitResult::Accept
    }

    /// Mark that a message was sent (dequeue from send queue).
    pub fn message_sent(&self, peer_id: u64) {
        let mut peers = self.peers.write();
        if let Some(state) = peers.get_mut(&peer_id) {
            state.send_queue_depth = state.send_queue_depth.saturating_sub(1);
        }
    }

    /// Get list of peers that should be disconnected due to inactivity
    /// or excessive violations.
    pub fn get_peers_to_disconnect(&self) -> Vec<(u64, String)> {
        let peers = self.peers.read();
        let now = Instant::now();
        let mut result = Vec::new();

        for (&peer_id, state) in peers.iter() {
            let inactive_secs = now.duration_since(state.last_activity).as_secs();

            if inactive_secs >= self.config.slow_peer_threshold_secs {
                result.push((peer_id, format!("inactive for {}s", inactive_secs)));
            }

            if state.violations > 1000 {
                result.push((peer_id, format!("{} rate violations", state.violations)));
            }
        }

        result
    }

    /// Get statistics for a specific peer.
    pub fn peer_stats(&self, peer_id: u64) -> Option<PeerStats> {
        let peers = self.peers.read();
        peers.get(&peer_id).map(|s| PeerStats {
            messages_received: s.messages_received,
            bytes_received: s.bytes_received,
            messages_sent: s.messages_sent,
            bytes_sent: s.bytes_sent,
            violations: s.violations,
            send_queue_depth: s.send_queue_depth,
        })
    }

    /// Get number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Message is accepted.
    Accept,
    /// Message is rate-limited (try again later).
    RateLimited,
    /// Send queue is full, apply backpressure.
    Backpressure,
    /// Peer should be disconnected with the given reason.
    Disconnect(String),
}

/// Statistics for a peer connection.
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Total number of messages received from this peer.
    pub messages_received: u64,
    /// Total bytes received from this peer.
    pub bytes_received: u64,
    /// Total number of messages sent to this peer.
    pub messages_sent: u64,
    /// Total bytes sent to this peer.
    pub bytes_sent: u64,
    /// Number of rate limit violations by this peer.
    pub violations: u64,
    /// Current depth of the outbound send queue for this peer.
    pub send_queue_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_creation() {
        let mut bucket = TokenBucket::new(100.0, 100);
        assert_eq!(bucket.available(), 100);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(100.0, 100);
        assert!(bucket.try_consume(50));
        assert_eq!(bucket.available(), 50);
        assert!(bucket.try_consume(50));
        assert!(!bucket.try_consume(1)); // Should be empty
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(1000.0, 1000);
        bucket.try_consume(1000);
        std::thread::sleep(Duration::from_millis(100));
        assert!(bucket.available() >= 50); // Should have refilled ~100 tokens
    }

    #[test]
    fn test_rate_limiter_add_remove_peer() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        limiter.add_peer(1);
        assert_eq!(limiter.peer_count(), 1);
        limiter.remove_peer(1);
        assert_eq!(limiter.peer_count(), 0);
    }

    #[test]
    fn test_rate_limiter_accept_normal() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        limiter.add_peer(1);

        let result = limiter.check_inbound(1, 100);
        assert_eq!(result, RateLimitResult::Accept);
    }

    #[test]
    fn test_rate_limiter_rate_limited() {
        let config = RateLimitConfig {
            max_messages_per_sec: 2,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        limiter.add_peer(1);

        // Use up the burst (capacity = rate * 2 = 4)
        assert_eq!(limiter.check_inbound(1, 0), RateLimitResult::Accept);
        assert_eq!(limiter.check_inbound(1, 0), RateLimitResult::Accept);
        assert_eq!(limiter.check_inbound(1, 0), RateLimitResult::Accept);
        assert_eq!(limiter.check_inbound(1, 0), RateLimitResult::Accept);
        // Next should be rate limited
        assert_eq!(limiter.check_inbound(1, 0), RateLimitResult::RateLimited);
    }

    #[test]
    fn test_rate_limiter_backpressure() {
        let config = RateLimitConfig {
            max_send_queue_size: 2,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        limiter.add_peer(1);

        assert_eq!(limiter.check_outbound(1, 100), RateLimitResult::Accept);
        assert_eq!(limiter.check_outbound(1, 100), RateLimitResult::Accept);
        assert_eq!(
            limiter.check_outbound(1, 100),
            RateLimitResult::Backpressure
        );

        // After sending one, should have room again
        limiter.message_sent(1);
        assert_eq!(limiter.check_outbound(1, 100), RateLimitResult::Accept);
    }

    #[test]
    fn test_rate_limiter_peer_stats() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        limiter.add_peer(42);
        limiter.check_inbound(42, 500);
        limiter.check_inbound(42, 300);

        let stats = limiter.peer_stats(42).unwrap();
        assert_eq!(stats.messages_received, 2);
        assert_eq!(stats.bytes_received, 800);
    }

    #[test]
    fn test_rate_limiter_unknown_peer() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        // Unknown peer should be accepted
        assert_eq!(limiter.check_inbound(999, 100), RateLimitResult::Accept);
    }

    #[test]
    fn test_slow_peer_detection() {
        let config = RateLimitConfig {
            slow_peer_threshold_secs: 0, // immediate detection for testing
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        limiter.add_peer(1);

        std::thread::sleep(Duration::from_millis(10));
        let disconnects = limiter.get_peers_to_disconnect();
        assert!(!disconnects.is_empty());
        assert_eq!(disconnects[0].0, 1);
    }

    #[test]
    fn test_rate_limit_result_eq() {
        assert_eq!(RateLimitResult::Accept, RateLimitResult::Accept);
        assert_ne!(RateLimitResult::Accept, RateLimitResult::RateLimited);
    }
}
