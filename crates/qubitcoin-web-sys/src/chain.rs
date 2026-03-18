//! In-process Qubitcoin devnet — the hardhat/ganache equivalent.
//!
//! Wraps [`TestChain`] with `wasm_bindgen` exports so JavaScript can create
//! a chain, mine blocks, create transactions, and query UTXO state entirely
//! in-memory.

use std::sync::Arc;

use qubitcoin_common::coins::CoinsView;
use qubitcoin_common::keys::Key;
use qubitcoin_consensus::transaction::{OutPoint, TransactionRef};
use qubitcoin_node::test_framework::TestChain;
use qubitcoin_primitives::Amount;
use qubitcoin_script::{build_p2pkh, Script};
use wasm_bindgen::prelude::*;

use crate::types;

// ---------------------------------------------------------------------------
// QubitcoinDevnet — the main entry point for JS
// ---------------------------------------------------------------------------

/// An in-process Qubitcoin regtest chain.
///
/// This is the WASM equivalent of running a local qubitcoind in regtest mode.
/// The entire blockchain lives in memory — no disk, no network.
#[wasm_bindgen]
pub struct QubitcoinDevnet {
    inner: TestChain,
}

#[wasm_bindgen]
impl QubitcoinDevnet {
    /// Create a new devnet chain from a 32-byte private key.
    ///
    /// The key is used as the coinbase recipient for all mined blocks.
    /// The chain starts at height 0 with a genesis block already mined.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: &[u8]) -> Result<QubitcoinDevnet, JsValue> {
        if secret_key.len() != 32 {
            return Err(JsValue::from_str("secret_key must be exactly 32 bytes"));
        }
        let key = Key::new(secret_key, true)
            .map_err(|e| JsValue::from_str(&format!("invalid secret key: {e}")))?;
        Ok(QubitcoinDevnet {
            inner: TestChain::new_with_key(key),
        })
    }

    // -- Chain state --------------------------------------------------------

    /// Current chain height (0 = genesis only).
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> i32 {
        self.inner.height()
    }

    /// Tip block hash as a 32-byte array.
    #[wasm_bindgen(getter, js_name = "tipHash")]
    pub fn tip_hash(&self) -> Vec<u8> {
        self.inner.tip_hash().as_bytes().to_vec()
    }

    /// Tip block hash as a hex string.
    #[wasm_bindgen(getter, js_name = "tipHashHex")]
    pub fn tip_hash_hex(&self) -> String {
        self.inner.tip_hash().to_hex()
    }

    /// Number of UTXOs in the in-memory cache.
    #[wasm_bindgen(getter, js_name = "utxoCount")]
    pub fn utxo_count(&self) -> usize {
        self.inner.coins().cache_size()
    }

    /// Coinbase public key (33-byte compressed).
    #[wasm_bindgen(getter, js_name = "coinbasePubkey")]
    pub fn coinbase_pubkey(&self) -> Vec<u8> {
        self.inner.coinbase_pubkey().serialize()
    }

    /// Number of mature (spendable) coinbase outputs.
    #[wasm_bindgen(getter, js_name = "matureCoinbaseCount")]
    pub fn mature_coinbase_count(&self) -> usize {
        self.inner.mature_coinbase_count()
    }

    // -- Mining -------------------------------------------------------------

    /// Mine a single empty block. Returns the block in Bitcoin wire format.
    #[wasm_bindgen(js_name = "mineBlock")]
    pub fn mine_block(&mut self) -> Result<Vec<u8>, JsValue> {
        let block = self.inner.mine_block(vec![]);
        types::block_to_bytes(&block)
    }

    /// Mine a block containing the given transactions (each in wire format).
    ///
    /// `raw_txs` is an array of `Uint8Array`, each a serialized transaction.
    #[wasm_bindgen(js_name = "mineBlockWithTxs")]
    pub fn mine_block_with_txs(&mut self, raw_txs: js_sys::Array) -> Result<Vec<u8>, JsValue> {
        let mut txs: Vec<TransactionRef> = Vec::with_capacity(raw_txs.length() as usize);
        for i in 0..raw_txs.length() {
            let val = raw_txs.get(i);
            let arr = js_sys::Uint8Array::from(val);
            let bytes = arr.to_vec();
            let tx = types::tx_from_bytes(&bytes)?;
            txs.push(Arc::new(tx));
        }
        let block = self.inner.mine_block(txs);
        types::block_to_bytes(&block)
    }

    /// Mine `count` empty blocks. Returns the final block in wire format.
    #[wasm_bindgen(js_name = "mineBlocks")]
    pub fn mine_blocks(&mut self, count: u32) -> Result<Vec<u8>, JsValue> {
        if count == 0 {
            return Err(JsValue::from_str("count must be > 0"));
        }
        let blocks = self.inner.mine_empty_blocks(count as usize);
        types::block_to_bytes(blocks.last().unwrap())
    }

    // -- Blocks -------------------------------------------------------------

    /// Get a block by height in Bitcoin wire format, or `null` if not found.
    #[wasm_bindgen(js_name = "getBlock")]
    pub fn get_block(&self, height: i32) -> Result<JsValue, JsValue> {
        match self.inner.block_at(height) {
            Some(block) => {
                let bytes = types::block_to_bytes(block)?;
                Ok(js_sys::Uint8Array::from(&bytes[..]).into())
            }
            None => Ok(JsValue::NULL),
        }
    }

    /// Get the block hash at a given height as hex, or `null`.
    #[wasm_bindgen(js_name = "getBlockHash")]
    pub fn get_block_hash(&self, height: i32) -> JsValue {
        match self.inner.block_at(height) {
            Some(block) => JsValue::from_str(&block.block_hash().to_hex()),
            None => JsValue::NULL,
        }
    }

    // -- Transactions -------------------------------------------------------

    /// Create a simple transaction spending a UTXO.
    ///
    /// * `txid` — 32-byte txid of the UTXO to spend.
    /// * `vout` — output index within that transaction.
    /// * `value_sat` — amount in satoshis to send to `dest_script`.
    /// * `dest_script` — the locking script for the recipient output.
    ///
    /// Returns the serialized transaction, or throws if insufficient funds.
    /// Change (minus 1000-sat fee) goes back to the coinbase address.
    #[wasm_bindgen(js_name = "createTransaction")]
    pub fn create_transaction(
        &self,
        txid: &[u8],
        vout: u32,
        value_sat: f64,
        dest_script: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        if txid.len() != 32 {
            return Err(JsValue::from_str("txid must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(txid);
        let outpoint = OutPoint::new(hash_bytes.into(), vout);

        let amount = Amount::from_sat(value_sat as i64);
        let script = Script::from_bytes(dest_script.to_vec());

        let tx = self
            .inner
            .create_transaction(&outpoint, amount, &script)
            .ok_or_else(|| JsValue::from_str("insufficient funds or UTXO not found"))?;

        types::tx_to_bytes(&tx)
    }

    /// Find the first spendable (mature, unspent) coinbase output.
    ///
    /// Returns a JS object `{ txid: Uint8Array, vout: number, valueSat: number }`
    /// or `null` if no mature coinbase is available.
    #[wasm_bindgen(js_name = "getSpendableOutput")]
    pub fn get_spendable_output(&self) -> Result<JsValue, JsValue> {
        match self.inner.get_spendable_output() {
            Some((outpoint, value)) => {
                let obj = js_sys::Object::new();
                let txid_bytes: &[u8] = outpoint.hash.as_bytes();
                js_sys::Reflect::set(
                    &obj,
                    &"txid".into(),
                    &js_sys::Uint8Array::from(txid_bytes).into(),
                )?;
                js_sys::Reflect::set(&obj, &"vout".into(), &JsValue::from_f64(outpoint.n as f64))?;
                js_sys::Reflect::set(
                    &obj,
                    &"valueSat".into(),
                    &JsValue::from_f64(value.to_sat() as f64),
                )?;
                Ok(obj.into())
            }
            None => Ok(JsValue::NULL),
        }
    }

    // -- UTXO queries -------------------------------------------------------

    /// Check whether a UTXO exists.
    #[wasm_bindgen(js_name = "hasUtxo")]
    pub fn has_utxo(&self, txid: &[u8], vout: u32) -> Result<bool, JsValue> {
        if txid.len() != 32 {
            return Err(JsValue::from_str("txid must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(txid);
        let outpoint = OutPoint::new(hash_bytes.into(), vout);
        Ok(self.inner.coins().have_coin(&outpoint))
    }

    /// Get a UTXO's value in satoshis, or `null` if it doesn't exist.
    #[wasm_bindgen(js_name = "getUtxoValue")]
    pub fn get_utxo_value(&self, txid: &[u8], vout: u32) -> Result<JsValue, JsValue> {
        if txid.len() != 32 {
            return Err(JsValue::from_str("txid must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(txid);
        let outpoint = OutPoint::new(hash_bytes.into(), vout);
        match self.inner.coins().get_coin(&outpoint) {
            Some(coin) => Ok(JsValue::from_f64(coin.tx_out.value.to_sat() as f64)),
            None => Ok(JsValue::NULL),
        }
    }

    // -- Key / address helpers ----------------------------------------------

    /// Build a P2PKH script from a 20-byte pubkey hash.
    #[wasm_bindgen(js_name = "buildP2pkhScript")]
    pub fn build_p2pkh_script(pubkey_hash: &[u8]) -> Result<Vec<u8>, JsValue> {
        if pubkey_hash.len() != 20 {
            return Err(JsValue::from_str("pubkey_hash must be 20 bytes"));
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(pubkey_hash);
        let script = build_p2pkh(&hash);
        Ok(script.as_bytes().to_vec())
    }

    /// Derive the compressed public key (33 bytes) from a 32-byte secret key.
    #[wasm_bindgen(js_name = "pubkeyFromSecret")]
    pub fn pubkey_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        if secret_key.len() != 32 {
            return Err(JsValue::from_str("secret_key must be 32 bytes"));
        }
        let key = Key::new(secret_key, true)
            .map_err(|e| JsValue::from_str(&format!("invalid secret key: {e}")))?;
        Ok(key.get_pubkey().serialize())
    }

    /// Compute Hash160 (RIPEMD160(SHA256(data))) — used for P2PKH address derivation.
    #[wasm_bindgen(js_name = "hash160")]
    pub fn hash160(data: &[u8]) -> Vec<u8> {
        qubitcoin_crypto::hash::hash160(data).to_vec()
    }
}
