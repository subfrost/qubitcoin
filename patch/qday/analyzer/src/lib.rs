extern crate alloc;

pub mod proto;
pub mod scoring;
pub mod types;

use metashrew_core::index_pointer::IndexPointer;
use metashrew_core::{export_bytes, flush, initialize, input};
use metashrew_support::index_pointer::KeyValuePointer;

use bitcoin::blockdata::script::Script;
use bitcoin::consensus::deserialize;
use bitcoin::Block;
use prost::Message;

use crate::proto::qday;
use crate::scoring::{
    compute_score, extract_p2pkh_pubkey, hash160, is_p2pk, is_p2pkh, is_p2tr,
};
use crate::types::{outpoint_key, parse_outpoint_key, VulnType};

// ---------------------------------------------------------------------------
// Storage key helpers (IndexPointer hierarchy)
// ---------------------------------------------------------------------------

fn height_ptr() -> IndexPointer {
    IndexPointer::from_keyword("/qday/height")
}

fn vuln_count_ptr() -> IndexPointer {
    IndexPointer::from_keyword("/qday/vulnerable/count")
}

fn vuln_total_sats_ptr() -> IndexPointer {
    IndexPointer::from_keyword("/qday/vulnerable/total_sats")
}

fn type_count_ptr(vtype: u8) -> IndexPointer {
    IndexPointer::from_keyword(&format!("/qday/vulnerable/by_type/{}/count", vtype))
}

fn type_sats_ptr(vtype: u8) -> IndexPointer {
    IndexPointer::from_keyword(&format!("/qday/vulnerable/by_type/{}/sats", vtype))
}

fn outpoint_value_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/value")
}

fn outpoint_vtype_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/vtype")
}

fn outpoint_height_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/height")
}

fn outpoint_pubkey_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/pubkey")
}

fn outpoint_coinbase_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/coinbase")
}

fn outpoint_pkh_ptr(op_key: &[u8]) -> IndexPointer {
    let mut base = IndexPointer::from_keyword("/qday/outpoints/");
    base = base.select(&op_key.to_vec());
    base.keyword("/pkh")
}

fn scored_list_ptr() -> IndexPointer {
    IndexPointer::from_keyword("/qday/scored_list")
}

fn exposed_keys_ptr(pubkey_hash: &[u8; 20]) -> IndexPointer {
    let base = IndexPointer::from_keyword("/qday/exposed_keys/");
    base.select(&pubkey_hash.to_vec())
}

fn pkh_outpoints_ptr(pkh: &[u8; 20]) -> IndexPointer {
    let base = IndexPointer::from_keyword("/qday/pkh_outpoints/");
    base.select(&pkh.to_vec())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Recompute score dynamically at query time.
fn recompute_score(op_key: &[u8], current_height: u32) -> u16 {
    let creation_height: u32 = outpoint_height_ptr(op_key).get_value();
    let value: u64 = outpoint_value_ptr(op_key).get_value();
    let is_coinbase: u8 = outpoint_coinbase_ptr(op_key).get_value();
    compute_score(creation_height, current_height, value, is_coinbase != 0)
}

/// Add a vulnerable outpoint to the index.
fn add_vulnerable(
    txid: &[u8; 32],
    vout: u32,
    value: u64,
    vtype: VulnType,
    height: u32,
    pubkey: &[u8],
    is_coinbase: bool,
) {
    let op_key = outpoint_key(txid, vout);

    outpoint_value_ptr(&op_key).set_value(value);
    outpoint_vtype_ptr(&op_key).set_value(vtype as u8);
    outpoint_height_ptr(&op_key).set_value(height);
    outpoint_coinbase_ptr(&op_key).set_value(is_coinbase as u8);
    outpoint_pubkey_ptr(&op_key).set(std::sync::Arc::new(pubkey.to_vec()));

    // Append to scored list
    scored_list_ptr().append(std::sync::Arc::new(op_key));

    // Update aggregate counters
    let count: u64 = vuln_count_ptr().get_value();
    vuln_count_ptr().set_value(count + 1);

    let total: u64 = vuln_total_sats_ptr().get_value();
    vuln_total_sats_ptr().set_value(total + value);

    let tc: u64 = type_count_ptr(vtype as u8).get_value();
    type_count_ptr(vtype as u8).set_value(tc + 1);

    let ts: u64 = type_sats_ptr(vtype as u8).get_value();
    type_sats_ptr(vtype as u8).set_value(ts + value);
}

/// Remove a vulnerable outpoint (it was spent).
fn remove_vulnerable(op_key: &[u8]) {
    let value: u64 = outpoint_value_ptr(op_key).get_value();
    let vtype: u8 = outpoint_vtype_ptr(op_key).get_value();

    if value == 0 {
        return; // Not tracked
    }

    // Only decrement counters for real vulnerable types (0=P2PK, 1=ExposedP2PKH, 2=P2TR)
    // Skip sentinel vtype=255 (tracked-but-not-vulnerable P2PKH)
    if vtype <= 2 {
        let count: u64 = vuln_count_ptr().get_value();
        vuln_count_ptr().set_value(count.saturating_sub(1));

        let total: u64 = vuln_total_sats_ptr().get_value();
        vuln_total_sats_ptr().set_value(total.saturating_sub(value));

        let tc: u64 = type_count_ptr(vtype).get_value();
        type_count_ptr(vtype).set_value(tc.saturating_sub(1));

        let ts: u64 = type_sats_ptr(vtype).get_value();
        type_sats_ptr(vtype).set_value(ts.saturating_sub(value));
    }

    // Zero out the outpoint data
    outpoint_value_ptr(op_key).set_value(0u64);
    outpoint_vtype_ptr(op_key).set_value(0u8);
    outpoint_height_ptr(op_key).set_value(0u32);
    outpoint_coinbase_ptr(op_key).set_value(0u8);
    outpoint_pubkey_ptr(op_key).set(std::sync::Arc::new(vec![]));

    // Clean up pkh reverse mapping
    let pkh_data = outpoint_pkh_ptr(op_key).get();
    if pkh_data.len() == 20 {
        outpoint_pkh_ptr(op_key).set(std::sync::Arc::new(vec![]));
    }
}

// ---------------------------------------------------------------------------
// Block processing entry point
// ---------------------------------------------------------------------------

/// Main indexer entry point called by metashrew for each block.
///
/// Input format: 4 bytes height (LE) + serialized block.
#[no_mangle]
pub extern "C" fn _start() {
    initialize();

    let data = input();
    if data.len() < 4 {
        return;
    }

    let height = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let block_data = &data[4..];

    let block: Block = match deserialize(block_data) {
        Ok(b) => b,
        Err(_) => return,
    };

    let is_first_tx_coinbase = true;

    // Phase 1: Scan all inputs to extract pubkeys from P2PKH spends.
    // When a pubkey is FIRST exposed, retroactively mark existing P2PKH UTXOs.
    for tx in block.txdata.iter() {
        if tx.is_coinbase() {
            continue;
        }
        for input in tx.input.iter() {
            let script_sig = Script::from_bytes(input.script_sig.as_bytes());
            if let Some(pubkey) = extract_p2pkh_pubkey(script_sig) {
                let pkh = hash160(&pubkey);
                let existing: u32 = exposed_keys_ptr(&pkh).get_value();
                if existing == 0 {
                    exposed_keys_ptr(&pkh).set_value(height);

                    // Retroactively promote existing P2PKH UTXOs for this pkh
                    let list_len: u32 = pkh_outpoints_ptr(&pkh).length();
                    for idx in 0..list_len {
                        let op_data = pkh_outpoints_ptr(&pkh).select_index(idx).get();
                        if op_data.len() < 36 {
                            continue;
                        }
                        let val: u64 = outpoint_value_ptr(&op_data).get_value();
                        if val == 0 {
                            continue; // Already spent
                        }
                        let vt: u8 = outpoint_vtype_ptr(&op_data).get_value();
                        if vt != 255 {
                            continue; // Already promoted or different type
                        }
                        // Update vtype from sentinel to ExposedP2PKH
                        // We directly update rather than calling add_vulnerable to avoid
                        // double-appending to scored_list (it was already appended as sentinel)
                        outpoint_vtype_ptr(&op_data).set_value(VulnType::ExposedP2PKH as u8);
                        outpoint_pubkey_ptr(&op_data).set(std::sync::Arc::new(pkh.to_vec()));

                        // Now add to aggregate counters (sentinel wasn't counted)
                        let count: u64 = vuln_count_ptr().get_value();
                        vuln_count_ptr().set_value(count + 1);
                        let total: u64 = vuln_total_sats_ptr().get_value();
                        vuln_total_sats_ptr().set_value(total + val);
                        let tc: u64 = type_count_ptr(VulnType::ExposedP2PKH as u8).get_value();
                        type_count_ptr(VulnType::ExposedP2PKH as u8).set_value(tc + 1);
                        let ts: u64 = type_sats_ptr(VulnType::ExposedP2PKH as u8).get_value();
                        type_sats_ptr(VulnType::ExposedP2PKH as u8).set_value(ts + val);
                    }
                }
            }
        }
    }

    // Phase 3: Scan outputs for vulnerable types.
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        let is_coinbase = tx_idx == 0 && is_first_tx_coinbase;
        let txid_hash = tx.compute_txid();
        let txid_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(txid_hash.as_ref());
            arr
        };

        for (vout, output) in tx.output.iter().enumerate() {
            let script = Script::from_bytes(output.script_pubkey.as_bytes());
            let value = output.value.to_sat();

            // Check P2PK
            if let Some(pubkey) = is_p2pk(script) {
                add_vulnerable(
                    &txid_bytes,
                    vout as u32,
                    value,
                    VulnType::P2PK,
                    height,
                    &pubkey,
                    is_coinbase,
                );
                continue;
            }

            // Check P2TR (witness v1)
            if let Some(xonly_key) = is_p2tr(script) {
                add_vulnerable(
                    &txid_bytes,
                    vout as u32,
                    value,
                    VulnType::P2TR,
                    height,
                    &xonly_key,
                    is_coinbase,
                );
                continue;
            }

            // Check P2PKH — track ALL P2PKH outputs
            if let Some(pkh) = is_p2pkh(script) {
                let op_key = outpoint_key(&txid_bytes, vout as u32);

                // Always track: append to pkh_outpoints list and store reverse mapping
                pkh_outpoints_ptr(&pkh).append(std::sync::Arc::new(op_key.clone()));
                outpoint_pkh_ptr(&op_key).set(std::sync::Arc::new(pkh.to_vec()));

                let exposed_height: u32 = exposed_keys_ptr(&pkh).get_value();
                if exposed_height > 0 {
                    // The pubkey for this address was previously revealed
                    add_vulnerable(
                        &txid_bytes,
                        vout as u32,
                        value,
                        VulnType::ExposedP2PKH,
                        height,
                        &pkh,
                        is_coinbase,
                    );
                } else {
                    // Not yet exposed — store with sentinel vtype=255
                    // so we can promote later if the key gets exposed
                    outpoint_value_ptr(&op_key).set_value(value);
                    outpoint_vtype_ptr(&op_key).set_value(255u8);
                    outpoint_height_ptr(&op_key).set_value(height);
                    outpoint_coinbase_ptr(&op_key).set_value(is_coinbase as u8);
                    // Append to scored list so view functions can find it
                    // (they'll skip it via value==0 check or vtype filter)
                    scored_list_ptr().append(std::sync::Arc::new(op_key));
                }
            }
        }
    }

    // Phase 4: Remove spent vulnerable outpoints.
    for tx in block.txdata.iter() {
        if tx.is_coinbase() {
            continue;
        }
        for input in tx.input.iter() {
            let prev_txid: [u8; 32] = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(input.previous_output.txid.as_ref());
                arr
            };
            let op_key = outpoint_key(&prev_txid, input.previous_output.vout);
            remove_vulnerable(&op_key);
        }
    }

    // Update processed height
    height_ptr().set_value(height);

    flush();
}

// ---------------------------------------------------------------------------
// View functions (read-only queries)
// ---------------------------------------------------------------------------

/// Returns total vulnerable BTC stats.
#[no_mangle]
pub extern "C" fn total_vulnerable_btc() -> i32 {
    initialize();
    let total_sats: u64 = vuln_total_sats_ptr().get_value();
    let count: u64 = vuln_count_ptr().get_value();

    let resp = qday::TotalVulnerableResponse { total_sats, count };
    export_bytes(resp.encode_to_vec())
}

/// Returns breakdown by vulnerability type.
#[no_mangle]
pub extern "C" fn vulnerable_stats() -> i32 {
    initialize();
    let mut by_type = Vec::new();
    for vt in 0u8..=2 {
        let count: u64 = type_count_ptr(vt).get_value();
        let sats: u64 = type_sats_ptr(vt).get_value();
        by_type.push(qday::TypeStats {
            vuln_type: vt as u32,
            count,
            sats,
        });
    }

    let resp = qday::VulnerableStatsResponse {
        by_type,
        total_sats: vuln_total_sats_ptr().get_value(),
        total_count: vuln_count_ptr().get_value(),
    };
    export_bytes(resp.encode_to_vec())
}

/// Simulates seizing all outputs above a score threshold.
#[no_mangle]
pub extern "C" fn simulate_seize() -> i32 {
    initialize();
    let data = input();
    let req = match qday::SimulateSeizeRequest::decode(data.as_slice()) {
        Ok(r) => r,
        Err(_) => return export_bytes(vec![]),
    };
    let threshold = req.threshold as u16;
    let current_height: u32 = height_ptr().get_value();

    let list_len: u32 = scored_list_ptr().length();
    let mut seized_sats: u64 = 0;
    let mut seized_count: u64 = 0;
    let mut total_score: u64 = 0;

    for i in 0..list_len {
        let op_data = scored_list_ptr().select_index(i).get();
        if op_data.len() < 36 {
            continue;
        }

        let value: u64 = outpoint_value_ptr(&op_data).get_value();
        if value == 0 {
            continue; // Already spent
        }
        let vtype: u8 = outpoint_vtype_ptr(&op_data).get_value();
        if vtype > 2 {
            continue; // Skip sentinel (non-vulnerable) entries
        }
        let score = recompute_score(&op_data, current_height);

        if score >= threshold {
            seized_sats += value;
            seized_count += 1;
            total_score += score as u64;
        }
    }

    let total_sats: u64 = vuln_total_sats_ptr().get_value();
    let avg_score = if seized_count > 0 {
        (total_score / seized_count) as u32
    } else {
        0
    };

    let resp = qday::SimulateSeizeResponse {
        seized_sats,
        seized_count,
        safety_rating: avg_score,
        remaining_sats: total_sats.saturating_sub(seized_sats),
    };
    export_bytes(resp.encode_to_vec())
}

/// Enumerate outpoints with pagination and minimum score filter.
#[no_mangle]
pub extern "C" fn enumerate_outpoints() -> i32 {
    initialize();
    let data = input();
    let req = match qday::EnumerateRequest::decode(data.as_slice()) {
        Ok(r) => r,
        Err(_) => return export_bytes(vec![]),
    };
    let current_height: u32 = height_ptr().get_value();

    let list_len: u32 = scored_list_ptr().length();
    let mut outpoints = Vec::new();
    let mut skipped = 0u32;
    let mut collected = 0u32;

    for i in 0..list_len {
        if collected >= req.limit {
            break;
        }

        let op_data = scored_list_ptr().select_index(i).get();
        if op_data.len() < 36 {
            continue;
        }

        let value: u64 = outpoint_value_ptr(&op_data).get_value();
        if value == 0 {
            continue;
        }

        let vtype: u8 = outpoint_vtype_ptr(&op_data).get_value();
        if vtype > 2 {
            continue; // Skip sentinel entries
        }

        let score = recompute_score(&op_data, current_height);
        if (score as u32) < req.min_score {
            continue;
        }

        if skipped < req.offset {
            skipped += 1;
            continue;
        }

        let (txid, vout) = match parse_outpoint_key(&op_data) {
            Some(v) => v,
            None => continue,
        };

        let height: u32 = outpoint_height_ptr(&op_data).get_value();

        outpoints.push(qday::OutpointInfo {
            txid: txid.to_vec(),
            vout,
            value,
            vuln_type: vtype as u32,
            height,
            score: score as u32,
        });
        collected += 1;
    }

    let resp = qday::EnumerateResponse { outpoints };
    export_bytes(resp.encode_to_vec())
}

/// Get details for a specific outpoint.
#[no_mangle]
pub extern "C" fn outpoint_details() -> i32 {
    initialize();
    let data = input();
    let req = match qday::OutpointDetailsRequest::decode(data.as_slice()) {
        Ok(r) => r,
        Err(_) => return export_bytes(vec![]),
    };

    let mut txid = [0u8; 32];
    if req.txid.len() == 32 {
        txid.copy_from_slice(&req.txid);
    }
    let op_key = outpoint_key(&txid, req.vout);
    let current_height: u32 = height_ptr().get_value();

    let value: u64 = outpoint_value_ptr(&op_key).get_value();
    let vtype: u8 = outpoint_vtype_ptr(&op_key).get_value();
    let height: u32 = outpoint_height_ptr(&op_key).get_value();
    let score = recompute_score(&op_key, current_height);
    let pubkey = outpoint_pubkey_ptr(&op_key).get();

    let resp = qday::OutpointDetailsResponse {
        value,
        vuln_type: vtype as u32,
        height,
        score: score as u32,
        pubkey: pubkey.as_ref().clone(),
    };
    export_bytes(resp.encode_to_vec())
}
