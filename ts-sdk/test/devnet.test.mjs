/**
 * Comprehensive integration test for the Qubitcoin WASM devnet.
 *
 * Run with:
 *   node --experimental-vm-modules test/devnet.test.mjs
 */

import { readFileSync } from 'fs';
import { initSync, QubitcoinDevnet } from '../src/wasm/qubitcoin_web_sys.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (!condition) {
    failed++;
    console.error(`  FAIL: ${msg}`);
    throw new Error(`Assertion failed: ${msg}`);
  }
  passed++;
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    failed++;
    console.error(`  FAIL: ${msg} — expected ${expected}, got ${actual}`);
    throw new Error(`Assertion failed: ${msg}`);
  }
  passed++;
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Initialize WASM
// ---------------------------------------------------------------------------

section('1. Import and initialize WASM');

const wasmPath = new URL('../src/wasm/qubitcoin_web_sys_bg.wasm', import.meta.url);
const wasmBytes = readFileSync(wasmPath);
initSync({ module: wasmBytes });
console.log('  WASM module initialized successfully');
passed++;

// ---------------------------------------------------------------------------
// Create devnet
// ---------------------------------------------------------------------------

section('2. Create a devnet');

// A known 32-byte secret key (deterministic for testing).
const secretKey = new Uint8Array(32).fill(0x01);
const devnet = new QubitcoinDevnet(secretKey);
console.log(`  Devnet created, height=${devnet.height}, tipHash=${devnet.tipHashHex}`);
passed++;

// ---------------------------------------------------------------------------
// Verify genesis state
// ---------------------------------------------------------------------------

section('3. Verify genesis state');

assertEqual(devnet.height, 0, 'genesis height should be 0');

const tipHash = devnet.tipHash;
assert(tipHash.length === 32, 'tipHash should be 32 bytes');
const allZeros = tipHash.every(b => b === 0);
assert(!allZeros, 'tipHash should not be all zeros');
console.log(`  tipHash: ${devnet.tipHashHex}`);

assert(devnet.utxoCount > 0, `utxoCount should be > 0 (got ${devnet.utxoCount})`);
console.log(`  utxoCount: ${devnet.utxoCount}`);

// ---------------------------------------------------------------------------
// Mine blocks
// ---------------------------------------------------------------------------

section('4. Mine blocks');

// Mine 100 empty blocks (genesis is height 0, so after 100 more we are at 100).
devnet.mineBlocks(100);
assertEqual(devnet.height, 100, 'height should be 100 after mining 100 blocks');
console.log(`  Height after mineBlocks(100): ${devnet.height}`);

// Mine 1 more to reach 101 total mined (height 101).
devnet.mineBlock();
assertEqual(devnet.height, 101, 'height should be 101 after one more mineBlock');
console.log(`  Height after mineBlock(): ${devnet.height}`);

// After 101 blocks on top of genesis, the genesis coinbase (height 0) should be mature.
assert(devnet.matureCoinbaseCount >= 1,
  `matureCoinbaseCount should be >= 1 (got ${devnet.matureCoinbaseCount})`);
console.log(`  matureCoinbaseCount: ${devnet.matureCoinbaseCount}`);

// ---------------------------------------------------------------------------
// Get spendable output
// ---------------------------------------------------------------------------

section('5. Get spendable output');

const utxo = devnet.getSpendableOutput();
assert(utxo !== null && utxo !== undefined, 'getSpendableOutput should return a value');
assert(utxo.txid instanceof Uint8Array, 'utxo.txid should be Uint8Array');
assertEqual(utxo.txid.length, 32, 'utxo.txid should be 32 bytes');
assert(typeof utxo.vout === 'number', 'utxo.vout should be a number');
assert(typeof utxo.valueSat === 'number', 'utxo.valueSat should be a number');

const expectedValue = 50 * 100_000_000; // 50 BTC in satoshis
assertEqual(utxo.valueSat, expectedValue,
  `valueSat should be ${expectedValue} (50 BTC)`);
console.log(`  Spendable UTXO: txid=${toHex(utxo.txid)}, vout=${utxo.vout}, valueSat=${utxo.valueSat}`);

// ---------------------------------------------------------------------------
// Create and mine a transaction
// ---------------------------------------------------------------------------

section('6. Create and mine a transaction');

// Derive pubkey from secret, hash160 it, and build a P2PKH script for recipient.
const pubkey = QubitcoinDevnet.pubkeyFromSecret(secretKey);
const pubkeyHash = QubitcoinDevnet.hash160(pubkey);
const destScript = QubitcoinDevnet.buildP2pkhScript(pubkeyHash);
console.log(`  Recipient pubkey hash: ${toHex(pubkeyHash)}`);
console.log(`  P2PKH script (${destScript.length} bytes): ${toHex(destScript)}`);

// Remember the UTXO we are about to spend.
const spentTxid = utxo.txid;
const spentVout = utxo.vout;

// Verify it exists before spending.
assert(devnet.hasUtxo(spentTxid, spentVout), 'UTXO should exist before spending');

// Create a tx sending 10 BTC.
const sendAmount = 10 * 100_000_000;
const rawTx = devnet.createTransaction(spentTxid, spentVout, sendAmount, destScript);
assert(rawTx instanceof Uint8Array, 'createTransaction should return Uint8Array');
assert(rawTx.length > 0, 'raw transaction should be non-empty');
console.log(`  Created transaction: ${rawTx.length} bytes`);

// Mine a block containing the transaction.
const blockWithTx = devnet.mineBlockWithTxs([rawTx]);
assert(blockWithTx instanceof Uint8Array, 'mineBlockWithTxs should return Uint8Array');
assert(blockWithTx.length > 0, 'mined block should be non-empty');
console.log(`  Mined block with tx at height ${devnet.height}`);

// The spent UTXO should now be gone.
assert(!devnet.hasUtxo(spentTxid, spentVout),
  'spent UTXO should no longer exist after mining');
console.log('  Spent UTXO confirmed absent from UTXO set');

// ---------------------------------------------------------------------------
// Query block data
// ---------------------------------------------------------------------------

section('7. Query block data');

// getBlock(0) should return non-null (genesis block).
const genesisBlock = devnet.getBlock(0);
assert(genesisBlock !== null && genesisBlock !== undefined,
  'getBlock(0) should return non-null');
assert(genesisBlock instanceof Uint8Array, 'getBlock(0) should return Uint8Array');
assert(genesisBlock.length > 0, 'genesis block should be non-empty');
console.log(`  getBlock(0): ${genesisBlock.length} bytes`);

// getBlockHash(0) should return a 64-char hex string.
const genesisHash = devnet.getBlockHash(0);
assert(typeof genesisHash === 'string', 'getBlockHash(0) should return a string');
assertEqual(genesisHash.length, 64, 'block hash hex should be 64 characters');
assert(/^[0-9a-f]{64}$/.test(genesisHash), 'block hash should be lowercase hex');
console.log(`  getBlockHash(0): ${genesisHash}`);

// getBlock(-1) should return null (invalid height).
const noBlock = devnet.getBlock(-1);
assert(noBlock === null || noBlock === undefined,
  'getBlock(-1) should return null/undefined');
console.log('  getBlock(-1): null (as expected)');

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

section('8. Static helpers');

// pubkeyFromSecret returns 33 bytes starting with 0x02 or 0x03.
const pub = QubitcoinDevnet.pubkeyFromSecret(secretKey);
assertEqual(pub.length, 33, 'pubkeyFromSecret should return 33 bytes');
assert(pub[0] === 0x02 || pub[0] === 0x03,
  `compressed pubkey should start with 0x02 or 0x03 (got 0x${pub[0].toString(16)})`);
console.log(`  pubkeyFromSecret: ${toHex(pub)}`);

// hash160 returns 20 bytes.
const h160 = QubitcoinDevnet.hash160(pub);
assertEqual(h160.length, 20, 'hash160 should return 20 bytes');
console.log(`  hash160: ${toHex(h160)}`);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('\n===================================');
console.log(`  ${passed} passed, ${failed} failed`);
console.log('===================================');

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\nAll tests passed!\n');
}

// Clean up WASM resources.
devnet.free();
