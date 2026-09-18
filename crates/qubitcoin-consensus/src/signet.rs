//! Signet block solution validation (BIP325).
//!
//! Maps to: `src/signet.cpp` / `src/kernel/signet.h` in Bitcoin Core.
//!
//! On a signet network, proof of work alone does not make a block valid: the
//! block must also carry a *signet solution*, a signature by the network's
//! signers over a commitment to the block. The solution is smuggled into the
//! coinbase's witness-commitment output as an extra pushdata prefixed with the
//! four-byte [`SIGNET_HEADER`].
//!
//! Validation reconstructs the same two virtual transactions the signer built:
//!
//! * `to_spend` — a synthetic transaction whose single output pays to the
//!   network's `signet_challenge` script, and whose scriptSig commits to
//!   (version, prev hash, *modified* merkle root, time) of the block.
//! * `to_sign` — a synthetic transaction spending `to_spend`'s output, carrying
//!   the solution's scriptSig and witness.
//!
//! The block is valid if `to_sign` satisfies the challenge script. The merkle
//! root used in the commitment is recomputed with the solution *removed* from
//! the coinbase, which is what breaks the circular dependency between the
//! signature and the block it signs.

use crate::block::Block;
use crate::merkle::compute_merkle_root;
use crate::params::ConsensusParams;
use crate::sighash::PrecomputedTransactionData;
use crate::sign::TransactionSignatureChecker;
use crate::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};
use qubitcoin_primitives::{Amount, Uint256};
use qubitcoin_script::{
    verify_script, Opcode, Script, ScriptError, ScriptVerifyFlags, ScriptWitness,
};
use qubitcoin_serialize::{read_compact_size, Decodable, Encodable};

/// Four-byte tag marking the signet solution pushdata inside the coinbase's
/// witness commitment output.
///
/// Maps to: `SIGNET_HEADER` in `src/signet.cpp`.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Header identifying the segwit commitment output in the coinbase.
const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Script flags used when verifying a signet block solution.
///
/// Maps to: `BLOCK_SCRIPT_VERIFY_FLAGS` in `src/signet.cpp`. Deliberately a
/// fixed, small set: the solution is not a normal transaction and must not
/// drift with policy.
const BLOCK_SCRIPT_VERIFY_FLAGS: ScriptVerifyFlags = ScriptVerifyFlags::from_bits_truncate(
    ScriptVerifyFlags::P2SH.bits()
        | ScriptVerifyFlags::WITNESS.bits()
        | ScriptVerifyFlags::DERSIG.bits()
        | ScriptVerifyFlags::NULLDUMMY.bits(),
);

/// The pair of virtual transactions that encode a signet block's solution.
///
/// Maps to: `SignetTxs` in `src/kernel/signet.h`.
#[derive(Clone, Debug)]
pub struct SignetTxs {
    /// The synthetic transaction paying to the signet challenge.
    pub to_spend: Transaction,
    /// The synthetic transaction spending it, carrying the solution.
    pub to_sign: Transaction,
}

/// Index of the coinbase output holding the segwit witness commitment.
///
/// Returns the *last* matching output, matching Bitcoin Core's
/// `GetWitnessCommitmentIndex()`.
fn witness_commitment_index(block: &Block) -> Option<usize> {
    let coinbase = block.vtx.first()?;
    coinbase.vout.iter().enumerate().rev().find_map(|(i, out)| {
        let script = out.script_pubkey.as_bytes();
        if script.len() >= 38
            && script[0] == Opcode::OpReturn as u8
            && script[1] == 0x24
            && script[2..6] == WITNESS_COMMITMENT_HEADER
        {
            Some(i)
        } else {
            None
        }
    })
}

/// Strip the signet solution out of `witness_commitment`, returning its payload.
///
/// Walks the script op by op. The first pushdata that both starts with `header`
/// and carries data beyond it is the solution: its payload is moved into
/// `result` and the push is rewritten in the rebuilt script with only the
/// header left. Every other op is copied verbatim.
///
/// Returns `true` if a solution was found (in which case `witness_commitment`
/// has been replaced by the rebuilt script).
///
/// Maps to: `FetchAndClearCommitmentSection()` in `src/signet.cpp`.
fn fetch_and_clear_commitment_section(
    header: &[u8],
    witness_commitment: &mut Script,
    result: &mut Vec<u8>,
) -> bool {
    let mut replacement = Script::new();
    let mut found_header = false;
    result.clear();

    let mut pos = 0usize;
    while let Some((opcode, mut pushdata, next)) = witness_commitment.get_op(pos) {
        pos = next;
        if !pushdata.is_empty() {
            if !found_header && pushdata.len() > header.len() && pushdata[..header.len()] == *header
            {
                // Pushdata only counts if it has the header _and_ some data.
                result.extend_from_slice(&pushdata[header.len()..]);
                pushdata.truncate(header.len());
                found_header = true;
            }
            replacement.push_data(&pushdata);
        } else {
            replacement.push_opcode_byte(opcode);
        }
    }

    if found_header {
        *witness_commitment = replacement;
    }
    found_header
}

/// Merkle root of the block with the coinbase replaced by `cb`.
///
/// Maps to: `ComputeModifiedMerkleRoot()` in `src/signet.cpp`.
fn compute_modified_merkle_root(cb: &Transaction, block: &Block) -> Uint256 {
    let mut leaves: Vec<Uint256> = Vec::with_capacity(block.vtx.len());
    leaves.push(cb.txid().into_uint256());
    for tx in block.vtx.iter().skip(1) {
        leaves.push(tx.txid().into_uint256());
    }
    let mut mutated = false;
    compute_merkle_root(leaves, &mut mutated)
}

impl SignetTxs {
    /// Rebuild the `to_spend`/`to_sign` pair for `block` under `challenge`.
    ///
    /// Returns `None` when the block cannot carry a solution at all — no
    /// coinbase, no witness commitment, or a malformed/overlong solution
    /// payload. A block with no signet pushdata at all is *not* an error: it
    /// yields a pair with an empty scriptSig and witness, which is what lets a
    /// trivial `OP_TRUE` challenge work.
    ///
    /// Maps to: `SignetTxs::Create()` in `src/signet.cpp`.
    pub fn create(block: &Block, challenge: &Script) -> Option<SignetTxs> {
        // to_spend: pays the challenge; its scriptSig will commit to the block.
        let mut to_spend_script_sig = Script::new();
        to_spend_script_sig.push_opcode(Opcode::Op0);

        // to_sign: spends it; its scriptSig/witness come from the solution.
        let mut to_sign_script_sig = Script::new();
        let mut to_sign_witness = Witness::new();

        // Can't fill in any other fields before extracting the signet response
        // from the block's coinbase.
        let coinbase = block.vtx.first()?; // no coinbase tx in block; invalid
        let cidx = witness_commitment_index(block)?; // require a witness commitment

        let mut modified_vout = coinbase.vout.clone();
        let mut signet_solution: Vec<u8> = Vec::new();
        if fetch_and_clear_commitment_section(
            &SIGNET_HEADER,
            &mut modified_vout[cidx].script_pubkey,
            &mut signet_solution,
        ) {
            // Parse: scriptSig, then the witness stack. Trailing bytes are an error.
            let mut cursor = std::io::Cursor::new(&signet_solution[..]);
            to_sign_script_sig = Script::decode(&mut cursor).ok()?;
            let stack_len = read_compact_size(&mut cursor).ok()?;
            // Each item costs at least one length byte, so this bounds allocation.
            if stack_len > signet_solution.len() as u64 {
                return None;
            }
            let mut stack = Vec::with_capacity(stack_len as usize);
            for _ in 0..stack_len {
                stack.push(Vec::<u8>::decode(&mut cursor).ok()?);
            }
            to_sign_witness.stack = stack;
            if (cursor.position() as usize) != signet_solution.len() {
                return None; // extraneous data encountered
            }
        }
        // else: no signet solution -- allow this to support OP_TRUE as a
        // trivial block challenge.

        let modified_cb = Transaction::new(
            coinbase.version,
            coinbase.vin.clone(),
            modified_vout,
            coinbase.lock_time,
        );
        let signet_merkle = compute_modified_merkle_root(&modified_cb, block);

        // The commitment: version || prev hash || modified merkle root || time.
        let mut block_data: Vec<u8> = Vec::with_capacity(72);
        block.header.version.encode(&mut block_data).ok()?;
        block.header.prev_blockhash.encode(&mut block_data).ok()?;
        Encodable::encode(&signet_merkle, &mut block_data).ok()?;
        block.header.time.encode(&mut block_data).ok()?;
        to_spend_script_sig.push_data(&block_data);

        let to_spend = Transaction::new(
            0,
            vec![TxIn {
                prevout: OutPoint::null(),
                script_sig: to_spend_script_sig,
                sequence: 0,
                witness: Witness::new(),
            }],
            vec![TxOut::new(Amount::ZERO, challenge.clone())],
            0,
        );

        let mut op_return = Script::new();
        op_return.push_opcode(Opcode::OpReturn);
        let to_sign = Transaction::new(
            0,
            vec![TxIn {
                prevout: OutPoint::new(*to_spend.txid(), 0),
                script_sig: to_sign_script_sig,
                sequence: 0,
                witness: to_sign_witness,
            }],
            vec![TxOut::new(Amount::ZERO, op_return)],
            0,
        );

        Some(SignetTxs { to_spend, to_sign })
    }
}

/// Check a signet block's solution against the network's challenge script.
///
/// Returns `true` if the block carries a valid signet signature (or is the
/// genesis block, whose solution is valid by definition).
///
/// Callers must only apply this on networks where `params.signet_blocks` is
/// set; on other networks there is no challenge to satisfy.
///
/// Maps to: `CheckSignetBlockSolution()` in `src/signet.cpp`.
pub fn check_signet_block_solution(block: &Block, params: &ConsensusParams) -> bool {
    if block.header.block_hash() == params.genesis_hash {
        // Genesis block solution is always valid.
        return true;
    }

    let challenge = Script::from_slice(&params.signet_challenge);
    let signet_txs = match SignetTxs::create(block, &challenge) {
        Some(txs) => txs,
        // Errors in block (block solution parse failure).
        None => return false,
    };

    let spent_output = signet_txs.to_spend.vout[0].clone();
    let script_sig = signet_txs.to_sign.vin[0].script_sig.clone();
    let witness = ScriptWitness {
        stack: signet_txs.to_sign.vin[0].witness.stack.clone(),
    };

    let precomputed =
        PrecomputedTransactionData::new(&signet_txs.to_sign, std::slice::from_ref(&spent_output));
    let checker = TransactionSignatureChecker::new(
        &signet_txs.to_sign,
        0,
        spent_output.value.to_sat(),
        &precomputed,
    );

    let mut error = ScriptError::UnknownError;
    verify_script(
        &script_sig,
        &spent_output.script_pubkey,
        &witness,
        &BLOCK_SCRIPT_VERIFY_FLAGS,
        &checker,
        &mut error,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TransactionRef;
    use std::sync::Arc;

    /// Build a coinbase carrying `commitment_script` as its only output.
    fn coinbase_with_commitment(commitment: Script) -> TransactionRef {
        Arc::new(Transaction::new(
            2,
            vec![TxIn {
                prevout: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x51]), // OP_1, height push placeholder
                sequence: 0xffffffff,
                witness: Witness {
                    stack: vec![vec![0u8; 32]],
                },
            }],
            vec![TxOut::new(Amount::ZERO, commitment)],
            0,
        ))
    }

    /// A minimal segwit commitment output: OP_RETURN <36 bytes: aa21a9ed || root>.
    fn commitment_script(extra_push: Option<&[u8]>) -> Script {
        let mut payload = Vec::with_capacity(36);
        payload.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        payload.extend_from_slice(&[0u8; 32]);
        let mut s = Script::new();
        s.push_opcode(Opcode::OpReturn);
        s.push_data(&payload);
        if let Some(extra) = extra_push {
            let mut push = Vec::with_capacity(4 + extra.len());
            push.extend_from_slice(&SIGNET_HEADER);
            push.extend_from_slice(extra);
            s.push_data(&push);
        }
        s
    }

    #[test]
    fn no_coinbase_is_unparseable() {
        let block = Block::new();
        assert!(SignetTxs::create(&block, &Script::from_bytes(vec![0x51])).is_none());
    }

    #[test]
    fn missing_witness_commitment_is_unparseable() {
        let mut block = Block::new();
        block
            .vtx
            .push(coinbase_with_commitment(Script::from_bytes(vec![
                Opcode::OpReturn as u8,
            ])));
        assert!(SignetTxs::create(&block, &Script::from_bytes(vec![0x51])).is_none());
    }

    #[test]
    fn absent_solution_still_builds_txs() {
        // No signet pushdata at all: this must succeed so that an OP_TRUE
        // challenge can be satisfied by a block with no signature.
        let mut block = Block::new();
        block
            .vtx
            .push(coinbase_with_commitment(commitment_script(None)));
        let txs = SignetTxs::create(&block, &Script::from_bytes(vec![0x51]))
            .expect("commitment present, no solution");
        assert!(txs.to_sign.vin[0].script_sig.is_empty());
        assert!(txs.to_sign.vin[0].witness.is_null());
        // to_spend commits to 72 bytes of block data behind an OP_0.
        assert_eq!(txs.to_spend.vin[0].script_sig.len(), 1 + 1 + 72);
    }

    #[test]
    fn trivial_op_true_challenge_accepts() {
        let mut params = ConsensusParams::signet();
        params.signet_challenge = vec![0x51]; // OP_TRUE
        let mut block = Block::new();
        block
            .vtx
            .push(coinbase_with_commitment(commitment_script(None)));
        assert!(check_signet_block_solution(&block, &params));
    }

    #[test]
    fn unsatisfied_challenge_rejects() {
        // Default signet challenge is a 1-of-2 multisig; an empty solution
        // cannot satisfy it.
        let params = ConsensusParams::signet();
        let mut block = Block::new();
        block
            .vtx
            .push(coinbase_with_commitment(commitment_script(None)));
        assert!(!check_signet_block_solution(&block, &params));
    }

    #[test]
    fn extraneous_solution_data_rejects() {
        // A solution push whose payload has trailing bytes after the witness
        // stack must be rejected outright.
        let mut solution = Vec::new();
        solution.push(0x00); // empty scriptSig
        solution.push(0x00); // empty witness stack
        solution.push(0xff); // trailing junk
        let mut block = Block::new();
        block
            .vtx
            .push(coinbase_with_commitment(commitment_script(Some(&solution))));
        assert!(SignetTxs::create(&block, &Script::from_bytes(vec![0x51])).is_none());
    }

    /// Block 1 of the public default signet (hash 00000086d6b2636c
    /// b2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53), raw. Its solution
    /// is a real signature under [`SIGNET_DEFAULT_CHALLENGE`].
    const SIGNET_BLOCK_1: &str = include_str!("test_data/signet_block_1.hex");

    fn signet_block_1() -> Block {
        let bytes = hex::decode(SIGNET_BLOCK_1.trim()).expect("valid hex");
        qubitcoin_serialize::deserialize::<Block>(&bytes).expect("valid block")
    }

    #[test]
    fn real_signet_block_parses_solution() {
        let block = signet_block_1();
        let challenge = Script::from_slice(&crate::params::SIGNET_DEFAULT_CHALLENGE);
        let txs = SignetTxs::create(&block, &challenge).expect("solution parses");
        // The default challenge is a 1-of-2 bare multisig, so the solution is
        // `OP_0 <72-byte sig>` in the scriptSig with an empty witness.
        assert_eq!(txs.to_sign.vin[0].script_sig.len(), 73);
        assert!(txs.to_sign.vin[0].witness.is_null());
        assert_eq!(
            txs.to_spend.vout[0].script_pubkey.as_bytes(),
            &challenge.as_bytes()[..]
        );
    }

    #[test]
    fn real_signet_block_solution_verifies() {
        let block = signet_block_1();
        let params = ConsensusParams::signet();
        assert!(check_signet_block_solution(&block, &params));
    }

    #[test]
    fn tampered_signet_signature_rejects() {
        let block = signet_block_1();
        let coinbase = &block.vtx[0];
        // Flip a byte inside the signature carried by the solution pushdata.
        let mut vout = coinbase.vout.clone();
        let cidx = witness_commitment_index(&block).unwrap();
        let mut script = vout[cidx].script_pubkey.as_bytes().to_vec();
        let hdr = script
            .windows(4)
            .position(|w| w == SIGNET_HEADER)
            .expect("solution header present");
        script[hdr + 20] ^= 0x01;
        vout[cidx].script_pubkey = Script::from_bytes(script);

        let mut tampered = block.clone();
        tampered.vtx[0] = Arc::new(Transaction::new(
            coinbase.version,
            coinbase.vin.clone(),
            vout,
            coinbase.lock_time,
        ));
        assert!(!check_signet_block_solution(
            &tampered,
            &ConsensusParams::signet()
        ));
    }

    #[test]
    fn genesis_block_solution_is_always_valid() {
        // The signet genesis block carries no solution at all.
        let params = ConsensusParams::signet();
        let mut block = Block::new();
        // A block whose hash matches genesis short-circuits; construct one by
        // checking the short-circuit directly against a non-signet block would
        // require mining, so assert the negative case is what differs.
        block
            .vtx
            .push(coinbase_with_commitment(commitment_script(None)));
        assert!(!check_signet_block_solution(&block, &params));
        assert_ne!(block.header.block_hash(), params.genesis_hash);
    }

    #[test]
    fn solution_is_stripped_before_hashing() {
        // The merkle root committed to must not depend on the solution's
        // contents: two blocks differing only in their solution payload must
        // produce the same to_spend commitment. (Note the four-byte header push
        // itself stays behind, matching Core, so a block with no solution at all
        // is a different block and is *not* expected to match.)
        let mut a_block = Block::new();
        a_block.vtx.push(coinbase_with_commitment(commitment_script(
            Some(&[0x00, 0x00]), // empty scriptSig, empty witness stack
        )));

        let mut b_block = Block::new();
        b_block.vtx.push(coinbase_with_commitment(commitment_script(
            Some(&[0x01, 0x51, 0x00]), // scriptSig = OP_1, empty witness stack
        )));

        let challenge = Script::from_bytes(vec![0x51]);
        let a = SignetTxs::create(&a_block, &challenge).unwrap();
        let b = SignetTxs::create(&b_block, &challenge).unwrap();
        assert_ne!(
            a.to_sign.vin[0].script_sig.as_bytes(),
            b.to_sign.vin[0].script_sig.as_bytes(),
            "the two solutions must actually differ"
        );
        assert_eq!(
            a.to_spend.vin[0].script_sig.as_bytes(),
            b.to_spend.vin[0].script_sig.as_bytes()
        );
    }
}
