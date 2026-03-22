//! Rollback logic for append-only indexer state.
//!
//! Uses per-height key sets (written by `append_batch`) for O(K) rollback
//! where K is the number of keys modified above the target height.
//! Falls back to a full DB scan for heights that lack key set data
//! (e.g., blocks processed before the key set feature was added).

use crate::state;
use crate::storage::IndexerStorage;
use std::collections::HashMap;

/// Roll back `storage` so that no entries above `target_height` remain.
///
/// Prefers the fast path via per-height key sets. Falls back to a full
/// DB scan for heights where no key set exists (legacy data).
pub fn rollback_to_height(storage: &IndexerStorage, target_height: u32) -> Result<u32, String> {
    let current_tip = storage.tip_height();
    if current_tip <= target_height {
        storage.set_tip_height(target_height)?;
        return Ok(0);
    }

    let mut deleted = 0u32;
    let mut batch = rocksdb::WriteBatch::default();
    let mut needs_legacy_scan = false;
    // Track in-flight length changes (same key may be modified at multiple heights).
    let mut length_cache: HashMap<Vec<u8>, u32> = HashMap::new();

    // Walk from current tip down to target+1, using per-height key sets.
    for h in (target_height + 1..=current_tip).rev() {
        let keyset_key = state::height_keyset_key(h);
        if let Some(keyset_data) = storage.get(&keyset_key) {
            let keys = state::decode_key_set(&keyset_data);
            for key in &keys {
                let current_len = length_cache
                    .get(key)
                    .copied()
                    .unwrap_or_else(|| storage.get_length(key));
                if current_len > 0 {
                    let idx = current_len - 1;
                    batch.delete(state::index_key(key, idx));
                    batch.delete(state::entry_height_key(key, idx));
                    let len_key = state::length_key(key);
                    batch.put(&len_key, &idx.to_le_bytes());
                    length_cache.insert(key.clone(), idx);
                    deleted += 1;
                }
            }
            batch.delete(&keyset_key);
        } else {
            // No keyset for this height — need legacy full-scan fallback.
            needs_legacy_scan = true;
            break;
        }
    }

    // Commit what we have so far.
    batch.put(state::HEIGHT_KEY, &target_height.to_le_bytes());
    storage.write_raw_batch(batch)?;

    // If any heights lacked key set data, fall back to legacy scan.
    if needs_legacy_scan {
        let legacy_deleted = rollback_legacy(storage, target_height)?;
        deleted += legacy_deleted;
    }

    Ok(deleted)
}

/// Legacy rollback: full DB scan for entries above `target_height`.
///
/// This is the slow path used for data written before per-height key sets
/// were introduced. Scans all length sentinels and walks entries backwards.
fn rollback_legacy(storage: &IndexerStorage, target_height: u32) -> Result<u32, String> {
    let mut deleted = 0u32;
    let length_sentinel = u32::MAX.to_le_bytes();
    let iter = storage.raw_iterator();

    let mut length_keys: Vec<(Vec<u8>, u32)> = Vec::new();

    for item in iter {
        let (key, value) = item.map_err(|e| format!("iterator error: {}", e))?;
        if key.len() >= 4 && key.ends_with(&length_sentinel) {
            if value.len() >= 4 {
                let len = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                let base_key = key[..key.len() - 4].to_vec();
                length_keys.push((base_key, len));
            }
        }
    }

    for (base_key, len) in &length_keys {
        let mut new_len = *len;
        let mut keys_to_delete = Vec::new();

        for idx in (0..*len).rev() {
            let h_key = state::entry_height_key(&base_key, idx);
            if let Some(h_data) = storage.get(&h_key) {
                if h_data.len() >= 4 {
                    let entry_height =
                        u32::from_le_bytes([h_data[0], h_data[1], h_data[2], h_data[3]]);
                    if entry_height > target_height {
                        keys_to_delete.push(state::index_key(&base_key, idx));
                        keys_to_delete.push(h_key);
                        new_len = idx;
                        deleted += 1;
                    } else {
                        break;
                    }
                }
            }
        }

        if !keys_to_delete.is_empty() {
            storage.delete_batch(&keys_to_delete)?;
            let len_key = state::length_key(&base_key);
            storage.put(&len_key, &new_len.to_le_bytes())?;
        }
    }

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
    fn test_rollback_with_keyset_fast_path() {
        let (storage, _dir) = temp_storage();

        // Use append_batch which writes per-height key sets.
        storage
            .append_batch(&[(b"counter".to_vec(), b"val_100".to_vec())], 100)
            .unwrap();
        storage
            .append_batch(&[(b"counter".to_vec(), b"val_200".to_vec())], 200)
            .unwrap();
        storage
            .append_batch(&[(b"counter".to_vec(), b"val_300".to_vec())], 300)
            .unwrap();

        assert_eq!(storage.get_length(b"counter"), 3);

        // Roll back to 150 — removes entries at 200 and 300.
        let deleted = rollback_to_height(&storage, 150).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"counter"), 1);
        assert_eq!(
            storage.get_latest(b"counter"),
            Some(b"val_100".to_vec())
        );
        assert_eq!(storage.tip_height(), 150);
    }

    #[test]
    fn test_rollback_legacy_fallback() {
        let (storage, _dir) = temp_storage();

        // Use individual append (no keyset written — simulates legacy data).
        storage.append(b"counter", b"val_100", 100).unwrap();
        storage.append(b"counter", b"val_200", 200).unwrap();
        storage.append(b"counter", b"val_300", 300).unwrap();
        storage.set_tip_height(300).unwrap();

        let deleted = rollback_to_height(&storage, 150).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"counter"), 1);
        assert_eq!(
            storage.get_latest(b"counter"),
            Some(b"val_100".to_vec())
        );
    }

    #[test]
    fn test_rollback_keeps_entries_at_target() {
        let (storage, _dir) = temp_storage();

        storage
            .append_batch(&[(b"key".to_vec(), b"val_10".to_vec())], 10)
            .unwrap();
        storage
            .append_batch(&[(b"key".to_vec(), b"val_20".to_vec())], 20)
            .unwrap();

        let deleted = rollback_to_height(&storage, 20).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.get_length(b"key"), 2);
    }

    #[test]
    fn test_rollback_multiple_keys() {
        let (storage, _dir) = temp_storage();

        storage
            .append_batch(
                &[
                    (b"alpha".to_vec(), b"a1".to_vec()),
                    (b"beta".to_vec(), b"b1".to_vec()),
                ],
                10,
            )
            .unwrap();
        storage
            .append_batch(
                &[
                    (b"alpha".to_vec(), b"a2".to_vec()),
                    (b"beta".to_vec(), b"b2".to_vec()),
                ],
                25,
            )
            .unwrap();

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

        storage
            .append_batch(&[(b"data".to_vec(), b"v1".to_vec())], 1)
            .unwrap();
        storage
            .append_batch(&[(b"data".to_vec(), b"v2".to_vec())], 2)
            .unwrap();

        let deleted = rollback_to_height(&storage, 0).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(storage.get_length(b"data"), 0);
        assert_eq!(storage.get_latest(b"data"), None);
        assert_eq!(storage.tip_height(), 0);
    }

    #[test]
    fn test_rollback_noop_when_below_target() {
        let (storage, _dir) = temp_storage();

        storage
            .append_batch(&[(b"x".to_vec(), b"v".to_vec())], 50)
            .unwrap();

        let deleted = rollback_to_height(&storage, 100).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.get_length(b"x"), 1);
    }
}
