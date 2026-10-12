//! Transaction standardness.
//!
//! Port of Bitcoin Core's `script/solver.cpp` (`Solver`, output template
//! classification) and the output half of `policy/policy.cpp`
//! (`IsStandard`, `IsStandardTx`), with Core v30's data-carrier rules:
//! any number of `OP_RETURN` outputs whose scriptPubKeys total at most
//! `-datacarriersize` bytes (default 100 000), or none with
//! `-datacarrier=0`.

use qubitcoin_consensus::transaction::Transaction;
use qubitcoin_script::Script;

use crate::mempool::MempoolPolicy;

/// Output template (Core's `TxoutType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxoutType {
    /// Not a recognised template.
    NonStandard,
    /// `<pubkey> OP_CHECKSIG`.
    PubKey,
    /// P2PKH.
    PubKeyHash,
    /// P2SH.
    ScriptHash,
    /// Bare `m <pubkeys> n OP_CHECKMULTISIG`.
    Multisig {
        /// Required signatures.
        m: u8,
        /// Keys.
        n: u8,
    },
    /// `OP_RETURN <pushes>`.
    NullData,
    /// P2WPKH.
    WitnessV0KeyHash,
    /// P2WSH.
    WitnessV0ScriptHash,
    /// P2TR.
    WitnessV1Taproot,
    /// Pay-to-Anchor.
    Anchor,
    /// Any other witness program with version 1..16.
    WitnessUnknown,
}

fn is_pubkey(data: &[u8]) -> bool {
    match data.len() {
        33 => data[0] == 0x02 || data[0] == 0x03,
        65 => data[0] == 0x04,
        _ => false,
    }
}

/// Decode a small-integer opcode (`OP_1`..`OP_16`).
fn small_int(op: u8) -> Option<u8> {
    if (0x51..=0x60).contains(&op) {
        Some(op - 0x50)
    } else {
        None
    }
}

/// Classify a scriptPubKey. Port of Core's `Solver()`.
pub fn solver(spk: &Script) -> TxoutType {
    let b = spk.as_bytes();
    if spk.is_p2sh() {
        return TxoutType::ScriptHash;
    }
    if let Some((version, program)) = spk.is_witness_program() {
        return match (version, program.len()) {
            (0, 20) => TxoutType::WitnessV0KeyHash,
            (0, 32) => TxoutType::WitnessV0ScriptHash,
            (0, _) => TxoutType::NonStandard,
            (1, 32) => TxoutType::WitnessV1Taproot,
            _ if Script::is_pay_to_anchor_program(version, program) => TxoutType::Anchor,
            _ => TxoutType::WitnessUnknown,
        };
    }
    // OP_RETURN followed only by pushes.
    if !b.is_empty() && b[0] == 0x6a {
        let rest = Script::from_slice(&b[1..]);
        return if rest.is_push_only() { TxoutType::NullData } else { TxoutType::NonStandard };
    }
    if spk.is_p2pkh() {
        return TxoutType::PubKeyHash;
    }
    // Walk the ops for P2PK / multisig.
    let mut ops: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        match spk.get_op(pos) {
            Some((op, data, next)) => {
                ops.push((op, data));
                pos = next;
            }
            None => return TxoutType::NonStandard,
        }
    }
    if ops.len() == 2 && ops[1].0 == 0xac && is_pubkey(&ops[0].1) {
        return TxoutType::PubKey;
    }
    if ops.len() >= 4 && ops[ops.len() - 1].0 == 0xae {
        let m = small_int(ops[0].0);
        let n = small_int(ops[ops.len() - 2].0);
        let keys = &ops[1..ops.len() - 2];
        if let (Some(m), Some(n)) = (m, n) {
            if keys.len() == n as usize && m >= 1 && m <= n && keys.iter().all(|(_, d)| is_pubkey(d)) {
                return TxoutType::Multisig { m, n };
            }
        }
    }
    TxoutType::NonStandard
}

/// Port of Core's `IsStandard(scriptPubKey)`: recognised template, bare
/// multisig limited to at most 3 keys.
pub fn is_standard_output(spk: &Script) -> (bool, TxoutType) {
    let t = solver(spk);
    let ok = match t {
        TxoutType::NonStandard => false,
        TxoutType::Multisig { n, .. } => n <= 3,
        _ => true,
    };
    (ok, t)
}

/// The output checks of Core's `IsStandardTx()`: every output standard
/// (`"scriptpubkey"`), bare multisig only with `-permitbaremultisig`
/// (`"bare-multisig"`), data-carrier bytes within `-datacarriersize`
/// (`"datacarrier"`). Returns the reject reason.
pub fn check_standard_outputs(tx: &Transaction, policy: &MempoolPolicy) -> Result<(), &'static str> {
    let mut datacarrier_left = policy.max_datacarrier_bytes;
    for out in &tx.vout {
        let (ok, t) = is_standard_output(&out.script_pubkey);
        if !ok {
            return Err("scriptpubkey");
        }
        match t {
            TxoutType::NullData => match datacarrier_left {
                Some(left) if out.script_pubkey.len() <= left => {
                    datacarrier_left = Some(left - out.script_pubkey.len());
                }
                _ => return Err("datacarrier"),
            },
            TxoutType::Multisig { .. } if !policy.permit_bare_multisig => return Err("bare-multisig"),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8]) -> Script {
        Script::from_bytes(b.to_vec())
    }

    #[test]
    fn test_solver_templates() {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend([0u8; 20]);
        p2pkh.extend([0x88, 0xac]);
        assert_eq!(solver(&s(&p2pkh)), TxoutType::PubKeyHash);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend([0u8; 20]);
        assert_eq!(solver(&s(&p2wpkh)), TxoutType::WitnessV0KeyHash);
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend([0u8; 32]);
        assert_eq!(solver(&s(&p2tr)), TxoutType::WitnessV1Taproot);
        assert_eq!(solver(&s(&[0x51, 0x02, 0x4e, 0x73])), TxoutType::Anchor);
        assert_eq!(solver(&s(&[0x6a, 0x04, 1, 2, 3, 4])), TxoutType::NullData);
        assert_eq!(solver(&s(&[0x6a])), TxoutType::NullData);
        assert_eq!(solver(&s(&[0x6a, 0x51, 0xac])), TxoutType::NonStandard);
        assert_eq!(solver(&s(&[0x51])), TxoutType::NonStandard);
        let mut v0bad = vec![0x00, 0x15];
        v0bad.extend([0u8; 21]);
        assert_eq!(solver(&s(&v0bad)), TxoutType::NonStandard);
        let mut p2pk = vec![0x21, 0x02];
        p2pk.extend([7u8; 32]);
        p2pk.push(0xac);
        assert_eq!(solver(&s(&p2pk)), TxoutType::PubKey);
        // 1-of-2 bare multisig.
        let mut ms = vec![0x51, 0x21, 0x02];
        ms.extend([1u8; 32]);
        ms.extend([0x21, 0x03]);
        ms.extend([2u8; 32]);
        ms.extend([0x52, 0xae]);
        assert_eq!(solver(&s(&ms)), TxoutType::Multisig { m: 1, n: 2 });
    }

    #[test]
    fn test_datacarrier_limits() {
        use qubitcoin_consensus::transaction::{OutPoint, TxIn, TxOut};
        use qubitcoin_primitives::{Amount, Txid};
        let mk = |outs: Vec<Script>| {
            Transaction::new(
                2,
                vec![TxIn::new(OutPoint::new(Txid::from_bytes([1; 32]), 0), Script::new(), 0)],
                outs.into_iter().map(|o| TxOut::new(Amount::ZERO, o)).collect(),
                0,
            )
        };
        let mut op_return = vec![0x6a, 0x4c, 80];
        op_return.extend([0u8; 80]);
        let tx = mk(vec![s(&op_return), s(&op_return)]);
        assert!(check_standard_outputs(&tx, &MempoolPolicy::default()).is_ok());
        let tight = MempoolPolicy { max_datacarrier_bytes: Some(83), ..Default::default() };
        assert!(check_standard_outputs(&mk(vec![s(&op_return)]), &tight).is_ok());
        assert_eq!(check_standard_outputs(&tx, &tight), Err("datacarrier"));
        let off = MempoolPolicy { max_datacarrier_bytes: None, ..Default::default() };
        assert_eq!(check_standard_outputs(&mk(vec![s(&[0x6a])]), &off), Err("datacarrier"));
        assert_eq!(check_standard_outputs(&mk(vec![s(&[0x51])]), &MempoolPolicy::default()), Err("scriptpubkey"));
    }
}
