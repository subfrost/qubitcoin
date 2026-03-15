//! Rollback logic for append-only indexer state.
//!
//! Walks all keys in the database and truncates any entries that were
//! appended at a height above the rollback target.

use crate::state;
use crate::storage::IndexerStorage;

/// Roll back `storage` so that no entries above `target_height` remain.
///
/// For each logical key, finds entries whose recorded height exceeds
/// `target_height`, deletes them, and updates the length counter.
pub fn rollback_to_height(storage: &IndexerStorage, target_height: u32) -> Result<u32, String> {
    let mut deleted = 0u32;

    // Scan all keys ending with u32::MAX_le (the metashrew length sentinel)
    // to discover logical keys.
    let length_sentinel = u32::MAX.to_le_bytes();
    let iter = storage.raw_iterator();

    let mut length_keys: Vec<(Vec<u8>, u32)> = Vec::new();

    for item in iter {
        let (key, value) = item.map_err(|e| format!("iterator error: {}", e))?;
        if key.len() >= 4 && key.ends_with(&length_sentinel) {
            if value.len() >= 4 {
                let len =
                    u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                // Extract the base key (strip the 4-byte u32::MAX suffix).
                let base_key = key[..key.len() - 4].to_vec();
                length_keys.push((base_key, len));
            }
        }
    }

    // For each logical key, check entries from the end and truncate.
    for (base_key, len) in &length_keys {
        let mut new_len = *len;
        let mut keys_to_delete = Vec::new();

        // Walk backwards from the last entry.
        for idx in (0..*len).rev() {
            let h_key = state::entry_height_key(&base_key, idx);
            if let Some(h_data) = storage.get(&h_key) {
                if h_data.len() >= 4 {
                    let entry_height = u32::from_le_bytes([
                        h_data[0], h_data[1], h_data[2], h_data[3],
                    ]);
                    if entry_height > target_height {
                        // Delete this entry and its height record.
                        keys_to_delete.push(state::index_key(&base_key, idx));
                        keys_to_delete.push(h_key);
                        new_len = idx;
                        deleted += 1;
                    } else {
                        // All earlier entries are at or below target height.
                        break;
                    }
                }
            }
        }

        if !keys_to_delete.is_empty() {
            storage.delete_batch(&keys_to_delete)?;
            // Update the length counter.
            let len_key = state::length_key(&base_key);
            storage.put(&len_key, &new_len.to_le_bytes())?;
        }
    }

    // Update the tip height.
    storage.set_tip_height(target_height)?;

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::IndexerStorage;

    fn temp_storage() -> (IndexerStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = IndexerStorage::open(dir.path()).unwrap();
        (storage, dir)
    }

    #[test]
    fn test_rollback_empty_db() {
        let (storage, _dir) = temp_storage();
        let deleted = rollback_to_height(&storage, 100).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.tip_height(), 100);
    }

    #[test]
    fn test_rollback_removes_entries_above_target() {
        let (storage, _dir) = temp_storage();

        // Append entries at increasing heights.
        storage.append(b"counter", b"val_100", 100).unwrap();
        storage.append(b"counter", b"val_200", 200).unwrap();
        storage.append(b"counter", b"val_300", 300).unwrap();
        storage.set_tip_height(300).unwrap();

        assert_eq!(storage.get_length(b"counter"), 3);

        // Roll back to height 150 — should remove entries at 200 and 300.
        let deleted = rollback_to_height(&storage, 150).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"counter"), 1);
        assert_eq!(storage.get_latest(b"counter"), Some(b"val_100".to_vec()));
        assert_eq!(storage.tip_height(), 150);
    }

    #[test]
    fn test_rollback_keeps_entries_at_target() {
        let (storage, _dir) = temp_storage();

        storage.append(b"key", b"val_10", 10).unwrap();
        storage.append(b"key", b"val_20", 20).unwrap();
        storage.set_tip_height(20).unwrap();

        // Roll back to exactly height 20 — should keep both entries.
        let deleted = rollback_to_height(&storage, 20).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.get_length(b"key"), 2);
    }

    #[test]
    fn test_rollback_multiple_keys() {
        let (storage, _dir) = temp_storage();

        storage.append(b"alpha", b"a1", 10).unwrap();
        storage.append(b"alpha", b"a2", 20).unwrap();
        storage.append(b"beta", b"b1", 15).unwrap();
        storage.append(b"beta", b"b2", 25).unwrap();
        storage.set_tip_height(25).unwrap();

        // Roll back to 18 — alpha loses entry at 20, beta loses entry at 25.
        let deleted = rollback_to_height(&storage, 18).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"alpha"), 1);
        assert_eq!(storage.get_latest(b"alpha"), Some(b"a1".to_vec()));
        assert_eq!(storage.get_length(b"beta"), 1);
        assert_eq!(storage.get_latest(b"beta"), Some(b"b1".to_vec()));
    }

    #[test]
    fn test_rollback_to_zero() {
        let (storage, _dir) = temp_storage();

        storage.append(b"data", b"v1", 1).unwrap();
        storage.append(b"data", b"v2", 2).unwrap();
        storage.set_tip_height(2).unwrap();

        let deleted = rollback_to_height(&storage, 0).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"data"), 0);
        assert_eq!(storage.get_latest(b"data"), None);
        assert_eq!(storage.tip_height(), 0);
    }

    #[test]
    fn test_rollback_noop_when_below_target() {
        let (storage, _dir) = temp_storage();

        storage.append(b"x", b"v", 50).unwrap();
        storage.set_tip_height(50).unwrap();

        // Roll back to 100 — nothing to do (target is above all entries).
        let deleted = rollback_to_height(&storage, 100).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.get_length(b"x"), 1);
    }
}
