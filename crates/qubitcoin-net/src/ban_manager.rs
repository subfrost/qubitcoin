//! Ban management for misbehaving peers.
//!
//! Maps to: src/banman.h / src/banman.cpp (BanMan)
//!
//! Provides:
//! - `BanEntry`: A single ban record with expiry timestamp
//! - `BanManager`: Thread-safe ban list with expiry support
//!
//! When a peer is detected as misbehaving (sending invalid data, violating
//! protocol rules, etc.) its IP address is added to the ban list with a
//! duration. Subsequent connection attempts from banned IPs are rejected.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

// ---------------------------------------------------------------------------
// BanEntry
// ---------------------------------------------------------------------------

/// A single ban record.
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// The banned IP address.
    pub ip: IpAddr,
    /// Unix timestamp when the ban expires.
    pub ban_until: u64,
    /// Human-readable reason for the ban.
    pub reason: String,
}

impl BanEntry {
    /// Check whether this ban has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.ban_until
    }
}

// ---------------------------------------------------------------------------
// BanManager
// ---------------------------------------------------------------------------

/// Thread-safe ban list manager.
///
/// Maintains a map from IP address to ban entries. Expired bans
/// are cleaned up explicitly via `clear_expired()` or checked
/// lazily via `is_banned()`.
pub struct BanManager {
    /// Map from IP to ban entry.
    banned: RwLock<HashMap<IpAddr, BanEntry>>,
}

impl BanManager {
    /// Create a new empty ban manager.
    pub fn new() -> Self {
        BanManager {
            banned: RwLock::new(HashMap::new()),
        }
    }

    /// Ban an IP address for the given duration (in seconds).
    ///
    /// If the IP is already banned, the ban is updated (extended or replaced).
    pub fn ban(&self, ip: IpAddr, duration_secs: u64, reason: String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = BanEntry {
            ip,
            ban_until: now.saturating_add(duration_secs),
            reason,
        };

        self.banned.write().insert(ip, entry);
    }

    /// Check whether an IP address is currently banned.
    ///
    /// Returns `false` if the IP is not in the ban list or if the ban
    /// has expired (expired entries are removed lazily).
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        // First check with a read lock.
        {
            let banned = self.banned.read();
            match banned.get(ip) {
                None => return false,
                Some(entry) => {
                    if !entry.is_expired() {
                        return true;
                    }
                    // Ban has expired; fall through to remove it.
                }
            }
        }

        // Remove the expired entry with a write lock.
        self.banned.write().remove(ip);
        false
    }

    /// Remove a ban for the given IP address.
    pub fn unban(&self, ip: &IpAddr) {
        self.banned.write().remove(ip);
    }

    /// List all currently active (non-expired) ban entries.
    pub fn list_banned(&self) -> Vec<BanEntry> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.banned
            .read()
            .values()
            .filter(|entry| now < entry.ban_until)
            .cloned()
            .collect()
    }

    /// Remove all expired ban entries.
    pub fn clear_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.banned.write().retain(|_, entry| now < entry.ban_until);
    }

    /// Total number of entries in the ban list (including potentially expired ones).
    pub fn size(&self) -> usize {
        self.banned.read().len()
    }

    /// Remove all ban entries.
    pub fn clear_all(&self) {
        self.banned.write().clear();
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn test_ban_manager_new() {
        let bm = BanManager::new();
        assert_eq!(bm.size(), 0);
        assert!(bm.list_banned().is_empty());
    }

    #[test]
    fn test_ban_and_is_banned() {
        let bm = BanManager::new();
        let ip = test_ip(1);

        assert!(!bm.is_banned(&ip));

        bm.ban(ip, 3600, "misbehaving".to_string());
        assert!(bm.is_banned(&ip));
        assert_eq!(bm.size(), 1);
    }

    #[test]
    fn test_ban_multiple_ips() {
        let bm = BanManager::new();
        bm.ban(test_ip(1), 3600, "reason1".to_string());
        bm.ban(test_ip(2), 3600, "reason2".to_string());
        bm.ban(test_ip(3), 3600, "reason3".to_string());

        assert!(bm.is_banned(&test_ip(1)));
        assert!(bm.is_banned(&test_ip(2)));
        assert!(bm.is_banned(&test_ip(3)));
        assert!(!bm.is_banned(&test_ip(4)));
        assert_eq!(bm.size(), 3);
    }

    #[test]
    fn test_unban() {
        let bm = BanManager::new();
        let ip = test_ip(1);
        bm.ban(ip, 3600, "test".to_string());
        assert!(bm.is_banned(&ip));

        bm.unban(&ip);
        assert!(!bm.is_banned(&ip));
        assert_eq!(bm.size(), 0);
    }

    #[test]
    fn test_unban_nonexistent() {
        let bm = BanManager::new();
        // Should not panic.
        bm.unban(&test_ip(42));
    }

    #[test]
    fn test_ban_expired_immediately() {
        let bm = BanManager::new();
        let ip = test_ip(1);

        // Ban with 0 seconds duration (already expired).
        bm.ban(ip, 0, "expired".to_string());

        // is_banned should return false for expired entries.
        assert!(!bm.is_banned(&ip));

        // The expired entry should have been cleaned up lazily.
        assert_eq!(bm.size(), 0);
    }

    #[test]
    fn test_clear_expired() {
        let bm = BanManager::new();
        // One ban that expires immediately.
        bm.ban(test_ip(1), 0, "expired".to_string());
        // One ban that lasts an hour.
        bm.ban(test_ip(2), 3600, "active".to_string());

        assert_eq!(bm.size(), 2);

        bm.clear_expired();

        assert_eq!(bm.size(), 1);
        assert!(!bm.is_banned(&test_ip(1)));
        assert!(bm.is_banned(&test_ip(2)));
    }

    #[test]
    fn test_list_banned() {
        let bm = BanManager::new();
        bm.ban(test_ip(1), 3600, "active1".to_string());
        bm.ban(test_ip(2), 3600, "active2".to_string());
        bm.ban(test_ip(3), 0, "expired".to_string());

        let list = bm.list_banned();
        // Only the two active bans should appear.
        assert_eq!(list.len(), 2);

        let ips: Vec<IpAddr> = list.iter().map(|e| e.ip).collect();
        assert!(ips.contains(&test_ip(1)));
        assert!(ips.contains(&test_ip(2)));
    }

    #[test]
    fn test_ban_overwrite() {
        let bm = BanManager::new();
        let ip = test_ip(1);

        bm.ban(ip, 3600, "first ban".to_string());
        bm.ban(ip, 7200, "second ban".to_string());

        // Should still be banned, with updated reason.
        assert!(bm.is_banned(&ip));
        assert_eq!(bm.size(), 1);

        let list = bm.list_banned();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].reason, "second ban");
    }

    #[test]
    fn test_ban_entry_is_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let active = BanEntry {
            ip: test_ip(1),
            ban_until: now + 3600,
            reason: "active".to_string(),
        };
        assert!(!active.is_expired());

        let expired = BanEntry {
            ip: test_ip(2),
            ban_until: now.saturating_sub(1),
            reason: "expired".to_string(),
        };
        assert!(expired.is_expired());
    }

    #[test]
    fn test_clear_all() {
        let bm = BanManager::new();
        bm.ban(test_ip(1), 3600, "a".to_string());
        bm.ban(test_ip(2), 3600, "b".to_string());
        assert_eq!(bm.size(), 2);

        bm.clear_all();
        assert_eq!(bm.size(), 0);
        assert!(!bm.is_banned(&test_ip(1)));
    }

    #[test]
    fn test_ban_manager_default() {
        let bm = BanManager::default();
        assert_eq!(bm.size(), 0);
    }

    #[test]
    fn test_ban_ipv6() {
        let bm = BanManager::new();
        let ipv6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        bm.ban(ipv6, 3600, "ipv6 ban".to_string());
        assert!(bm.is_banned(&ipv6));
        assert!(!bm.is_banned(&test_ip(1)));
    }

    #[test]
    fn test_ban_list_reasons() {
        let bm = BanManager::new();
        bm.ban(test_ip(1), 3600, "dos attack".to_string());
        bm.ban(test_ip(2), 3600, "invalid blocks".to_string());

        let list = bm.list_banned();
        let reasons: Vec<&str> = list.iter().map(|e| e.reason.as_str()).collect();
        assert!(reasons.contains(&"dos attack"));
        assert!(reasons.contains(&"invalid blocks"));
    }
}
