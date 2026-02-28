//! Raw transaction builder/decoder utility.
//!
//! Maps to: the `bitcoin-tx` command-line tool in Bitcoin Core.
//!
//! Provides functions for:
//! - Decoding a raw transaction hex into JSON
//! - Creating a new raw transaction from inputs/outputs
//! - Computing the txid of a raw transaction
//! - Computing the virtual size of a raw transaction

use qubitcoin_consensus::transaction::{
    deserialize_transaction, serialize_transaction, OutPoint, Transaction, TxIn, TxOut,
    SEQUENCE_FINAL,
};
use qubitcoin_primitives::{Amount, Txid};
use qubitcoin_script::Script;

/// Decode a raw transaction hex string and return its JSON representation.
///
/// The JSON output includes version, locktime, inputs (with prevout, scriptSig,
/// sequence, witness), outputs (with value, scriptPubKey), txid, wtxid, size,
/// vsize, and weight.
pub fn decode_raw_transaction(hex_str: &str) -> Result<serde_json::Value, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex: {}", e))?;

    let tx = deserialize_transaction(&mut &bytes[..], true)
        .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

    Ok(transaction_to_json(&tx))
}

/// Convert a Transaction to a JSON value.
fn transaction_to_json(tx: &Transaction) -> serde_json::Value {
    let vin: Vec<serde_json::Value> = tx
        .vin
        .iter()
        .map(|input| {
            let mut obj = serde_json::json!({
                "txid": input.prevout.hash.to_hex(),
                "vout": input.prevout.n,
                "scriptSig": {
                    "hex": hex::encode(input.script_sig.as_bytes()),
                },
                "sequence": input.sequence,
            });

            if !input.witness.is_empty() {
                let witness_items: Vec<String> = input
                    .witness
                    .stack
                    .iter()
                    .map(|item| hex::encode(item))
                    .collect();
                obj["txinwitness"] = serde_json::json!(witness_items);
            }

            obj
        })
        .collect();

    let vout: Vec<serde_json::Value> = tx
        .vout
        .iter()
        .enumerate()
        .map(|(n, output)| {
            serde_json::json!({
                "value": output.value.to_btc(),
                "n": n,
                "scriptPubKey": {
                    "hex": hex::encode(output.script_pubkey.as_bytes()),
                },
            })
        })
        .collect();

    serde_json::json!({
        "txid": tx.txid().to_hex(),
        "wtxid": tx.wtxid().to_hex(),
        "version": tx.version,
        "locktime": tx.lock_time,
        "vin": vin,
        "vout": vout,
        "size": tx.get_total_size(),
        "vsize": tx.get_virtual_size(),
        "weight": tx.get_weight(),
    })
}

/// Create a new raw transaction from input/output specifications.
///
/// # Arguments
/// - `inputs`: Vector of (txid_hex, vout_index) pairs.
/// - `outputs`: Vector of (script_hex, amount_satoshis) pairs.
///   The script_hex is the raw scriptPubKey bytes encoded as hex.
/// - `locktime`: Transaction locktime (nLockTime).
/// - `version`: Transaction version number.
///
/// # Returns
/// Hex-encoded serialized transaction on success.
pub fn create_raw_transaction(
    inputs: &[(String, u32)],
    outputs: &[(String, i64)],
    locktime: u32,
    version: i32,
) -> Result<String, String> {
    // Build inputs
    let mut vin = Vec::with_capacity(inputs.len());
    for (txid_hex, vout) in inputs {
        let txid =
            Txid::from_hex(txid_hex).ok_or_else(|| format!("Invalid txid hex: {}", txid_hex))?;
        let outpoint = OutPoint::new(txid, *vout);
        vin.push(TxIn::new(outpoint, Script::new(), SEQUENCE_FINAL));
    }

    // Build outputs
    let mut vout = Vec::with_capacity(outputs.len());
    for (script_hex, amount) in outputs {
        let script_bytes = hex::decode(script_hex)
            .map_err(|e| format!("Invalid script hex '{}': {}", script_hex, e))?;
        let script = Script::from_bytes(script_bytes);
        vout.push(TxOut::new(Amount::from_sat(*amount), script));
    }

    let tx = Transaction::new(version as u32, vin, vout, locktime);
    let serialized = serialize_transaction(&tx, true);
    Ok(hex::encode(serialized))
}

/// Compute and return the txid of a raw transaction given as hex.
///
/// The txid is the double-SHA256 of the non-witness serialization, displayed
/// in reversed byte order (standard Bitcoin hex display convention).
pub fn get_txid(hex_str: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex: {}", e))?;

    let tx = deserialize_transaction(&mut &bytes[..], true)
        .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

    Ok(tx.txid().to_hex())
}

/// Compute the virtual size of a raw transaction given as hex.
///
/// Virtual size is defined as `(weight + 3) / 4` (BIP141).
pub fn get_virtual_size(hex_str: &str) -> Result<usize, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex: {}", e))?;

    let tx = deserialize_transaction(&mut &bytes[..], true)
        .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

    Ok(tx.get_virtual_size())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a simple test transaction and return its hex.
    fn make_test_tx_hex() -> String {
        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::from_bytes([0xaa; 32]), 0),
                Script::from_bytes(vec![0x00]),
                SEQUENCE_FINAL,
            )],
            vec![TxOut::new(
                Amount::from_sat(50_000),
                Script::from_bytes(vec![0x76, 0xa9, 0x14]),
            )],
            0,
        );
        let serialized = serialize_transaction(&tx, false);
        hex::encode(serialized)
    }

    #[test]
    fn test_decode_raw_transaction() {
        let hex_str = make_test_tx_hex();
        let json = decode_raw_transaction(&hex_str).unwrap();

        assert_eq!(json["version"], 2);
        assert_eq!(json["locktime"], 0);
        assert_eq!(json["vin"].as_array().unwrap().len(), 1);
        assert_eq!(json["vout"].as_array().unwrap().len(), 1);

        // Check the output value (50000 sat = 0.0005 BTC)
        let vout_value = json["vout"][0]["value"].as_f64().unwrap();
        assert!((vout_value - 0.0005).abs() < 1e-10);

        // Check txid is a valid hex string
        let txid = json["txid"].as_str().unwrap();
        assert_eq!(txid.len(), 64);

        // Check sizes are present and positive
        assert!(json["size"].as_u64().unwrap() > 0);
        assert!(json["vsize"].as_u64().unwrap() > 0);
        assert!(json["weight"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_raw_transaction("not_hex");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex"));
    }

    #[test]
    fn test_decode_truncated_tx() {
        let result = decode_raw_transaction("0100");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_raw_transaction() {
        let txid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let script_hex = "76a914";

        let hex_str = create_raw_transaction(
            &[(txid_hex.to_string(), 0)],
            &[(script_hex.to_string(), 50_000)],
            0,
            2,
        )
        .unwrap();

        // Verify it can be decoded back
        let json = decode_raw_transaction(&hex_str).unwrap();
        assert_eq!(json["version"], 2);
        assert_eq!(json["locktime"], 0);
        assert_eq!(json["vin"].as_array().unwrap().len(), 1);
        assert_eq!(json["vout"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_create_raw_transaction_invalid_txid() {
        let result = create_raw_transaction(
            &[("invalid_txid".to_string(), 0)],
            &[("76a914".to_string(), 50_000)],
            0,
            2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_raw_transaction_invalid_script() {
        let txid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = create_raw_transaction(
            &[(txid_hex.to_string(), 0)],
            &[("not_hex".to_string(), 50_000)],
            0,
            2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_raw_transaction_multiple_outputs() {
        let txid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_str = create_raw_transaction(
            &[(txid_hex.to_string(), 0)],
            &[("76a914".to_string(), 25_000), ("a914".to_string(), 25_000)],
            0,
            2,
        )
        .unwrap();

        let json = decode_raw_transaction(&hex_str).unwrap();
        assert_eq!(json["vout"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_get_txid() {
        let hex_str = make_test_tx_hex();
        let txid = get_txid(&hex_str).unwrap();

        // txid should be a 64-character hex string
        assert_eq!(txid.len(), 64);

        // Calling twice should give the same result
        let txid2 = get_txid(&hex_str).unwrap();
        assert_eq!(txid, txid2);
    }

    #[test]
    fn test_get_txid_matches_decode() {
        let hex_str = make_test_tx_hex();
        let txid = get_txid(&hex_str).unwrap();
        let json = decode_raw_transaction(&hex_str).unwrap();
        assert_eq!(txid, json["txid"].as_str().unwrap());
    }

    #[test]
    fn test_get_virtual_size() {
        let hex_str = make_test_tx_hex();
        let vsize = get_virtual_size(&hex_str).unwrap();

        // For a non-witness transaction, vsize == size
        let json = decode_raw_transaction(&hex_str).unwrap();
        let size = json["size"].as_u64().unwrap() as usize;
        assert_eq!(vsize, size);
    }

    #[test]
    fn test_get_virtual_size_invalid() {
        let result = get_virtual_size("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_and_decode_roundtrip() {
        let txid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let script_hex = "0014abcdef01234567890abcdef01234567890abcdef";

        let hex_str = create_raw_transaction(
            &[(txid_hex.to_string(), 1)],
            &[(script_hex.to_string(), 100_000)],
            500000,
            2,
        )
        .unwrap();

        let json = decode_raw_transaction(&hex_str).unwrap();
        assert_eq!(json["version"], 2);
        assert_eq!(json["locktime"], 500000);

        let vin = json["vin"].as_array().unwrap();
        assert_eq!(vin[0]["txid"].as_str().unwrap(), txid_hex);
        assert_eq!(vin[0]["vout"].as_u64().unwrap(), 1);

        let vout = json["vout"].as_array().unwrap();
        assert_eq!(vout[0]["scriptPubKey"]["hex"].as_str().unwrap(), script_hex);
    }

    #[test]
    fn test_create_with_locktime() {
        let txid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_str = create_raw_transaction(
            &[(txid_hex.to_string(), 0)],
            &[("76a914".to_string(), 50_000)],
            700_000,
            1,
        )
        .unwrap();

        let json = decode_raw_transaction(&hex_str).unwrap();
        assert_eq!(json["locktime"], 700_000);
        assert_eq!(json["version"], 1);
    }
}
