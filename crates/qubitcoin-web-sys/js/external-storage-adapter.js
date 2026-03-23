/**
 * External Storage Adapter for Qubitcoin WASM Devnet
 *
 * Provides globalThis.__qubitcoin_storage with a Map-based backend
 * for Node.js environments. Stores data on the JS heap instead of
 * WASM linear memory, preventing OOM when indexing many blocks/contracts.
 *
 * Usage:
 *   import { installMapStorageAdapter } from './external-storage-adapter.js';
 *   installMapStorageAdapter();
 *   // Then create DevnetServer with use_external_storage = true
 *
 * For browser environments, swap MapStore with an IndexedDB-backed
 * implementation that has the same synchronous interface.
 */

const SENTINEL = new Uint8Array([0xff, 0xff, 0xff, 0xff]);

/**
 * Convert a Uint8Array key to a hex string for Map lookup.
 * JS Maps compare by reference, not by value, so we need string keys.
 */
function keyToHex(key) {
  let hex = '';
  for (let i = 0; i < key.length; i++) {
    hex += (key[i] < 16 ? '0' : '') + key[i].toString(16);
  }
  return hex;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

class MapStore {
  constructor() {
    /** @type {Map<string, Uint8Array>} hex-encoded key → value */
    this.data = new Map();
  }

  get(key) {
    return this.data.get(keyToHex(key)) ?? null;
  }

  put(key, value) {
    this.data.set(keyToHex(key), new Uint8Array(value));
  }

  deleteBatch(keys) {
    for (const key of keys) {
      this.data.delete(keyToHex(key));
    }
  }

  /**
   * Export all data as a flat binary blob.
   * Format: u32 count, then per entry: u32 key_len, key, u32 val_len, val
   */
  exportBytes() {
    const entries = [...this.data.entries()];
    // Calculate total size
    let size = 4; // count
    for (const [hexKey, value] of entries) {
      const keyBytes = hexToBytes(hexKey);
      size += 4 + keyBytes.length + 4 + value.length;
    }

    const buf = new Uint8Array(size);
    const view = new DataView(buf.buffer);
    let pos = 0;

    view.setUint32(pos, entries.length, true);
    pos += 4;

    for (const [hexKey, value] of entries) {
      const keyBytes = hexToBytes(hexKey);
      view.setUint32(pos, keyBytes.length, true);
      pos += 4;
      buf.set(keyBytes, pos);
      pos += keyBytes.length;
      view.setUint32(pos, value.length, true);
      pos += 4;
      buf.set(value, pos);
      pos += value.length;
    }

    return buf;
  }

  /**
   * Import data from a flat binary blob, replacing all existing data.
   * Returns the number of entries imported.
   */
  importBytes(data) {
    this.data.clear();
    if (data.length < 4) return 0;

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const count = view.getUint32(0, true);
    let pos = 4;

    for (let i = 0; i < count; i++) {
      if (pos + 4 > data.length) break;
      const keyLen = view.getUint32(pos, true);
      pos += 4;
      if (pos + keyLen > data.length) break;
      const key = data.slice(pos, pos + keyLen);
      pos += keyLen;

      if (pos + 4 > data.length) break;
      const valLen = view.getUint32(pos, true);
      pos += 4;
      if (pos + valLen > data.length) break;
      const value = data.slice(pos, pos + valLen);
      pos += valLen;

      this.data.set(keyToHex(key), value);
    }

    return count;
  }

  /**
   * Find all keys that end with the u32::MAX sentinel (length markers)
   * and return their base keys + stored lengths.
   *
   * Returns packed binary: [count_u32, (key_len_u32, key_bytes, length_u32)*]
   */
  keysWithLengths() {
    const sentinelHex = 'ffffffff';
    const results = [];

    for (const [hexKey, value] of this.data.entries()) {
      if (hexKey.endsWith(sentinelHex) && value.length >= 4) {
        const baseKeyHex = hexKey.slice(0, -8); // remove 4 bytes (8 hex chars)
        const baseKey = hexToBytes(baseKeyHex);
        const length = new DataView(value.buffer, value.byteOffset, value.byteLength)
          .getUint32(0, true);
        results.push({ baseKey, length });
      }
    }

    // Pack into binary
    let size = 4;
    for (const { baseKey } of results) {
      size += 4 + baseKey.length + 4;
    }

    const buf = new Uint8Array(size);
    const view = new DataView(buf.buffer);
    let pos = 0;

    view.setUint32(pos, results.length, true);
    pos += 4;

    for (const { baseKey, length } of results) {
      view.setUint32(pos, baseKey.length, true);
      pos += 4;
      buf.set(baseKey, pos);
      pos += baseKey.length;
      view.setUint32(pos, length, true);
      pos += 4;
    }

    return buf;
  }
}

/**
 * Install the Map-based storage adapter on globalThis.
 *
 * Must be called BEFORE any qubitcoin WASM module is instantiated.
 */
export function installMapStorageAdapter() {
  /** @type {Map<number, MapStore>} */
  const stores = new Map();
  let nextId = 1;

  globalThis.__qubitcoin_storage = {
    storageCreate() {
      const id = nextId++;
      stores.set(id, new MapStore());
      return id;
    },

    storageGet(storeId, key) {
      const store = stores.get(storeId);
      if (!store) return null;
      return store.get(key);
    },

    storagePut(storeId, key, value) {
      const store = stores.get(storeId);
      if (!store) return;
      store.put(key, value);
    },

    storageDeleteBatch(storeId, packed) {
      const store = stores.get(storeId);
      if (!store || packed.length < 4) return;
      const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
      const count = view.getUint32(0, true);
      let pos = 4;
      const keys = [];
      for (let i = 0; i < count; i++) {
        if (pos + 4 > packed.length) break;
        const keyLen = view.getUint32(pos, true);
        pos += 4;
        if (pos + keyLen > packed.length) break;
        keys.push(packed.slice(pos, pos + keyLen));
        pos += keyLen;
      }
      store.deleteBatch(keys);
    },

    storageExport(storeId) {
      const store = stores.get(storeId);
      if (!store) return new Uint8Array(4); // empty: count=0
      return store.exportBytes();
    },

    storageImport(storeId, data) {
      const store = stores.get(storeId);
      if (!store) return 0;
      return store.importBytes(data);
    },

    storageKeysWithLengths(storeId) {
      const store = stores.get(storeId);
      if (!store) return new Uint8Array(4); // empty: count=0
      return store.keysWithLengths();
    },
  };
}

// Auto-install when imported in Node.js test environments
if (typeof globalThis !== 'undefined' && !globalThis.__qubitcoin_storage) {
  installMapStorageAdapter();
}
