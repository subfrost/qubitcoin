//! Fuzz target: Script interpreter (eval_script).
//!
//! Feeds arbitrary bytes as a Script to the interpreter. Uses
//! BaseSignatureChecker (which rejects all signatures) and default flags.
//! The goal is to find panics or undefined behaviour in the interpreter loop.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qubitcoin_script::{
    BaseSignatureChecker, Script, ScriptError, ScriptExecutionData, ScriptStack,
    ScriptVerifyFlags, ScriptWitness, SigVersion,
};

fuzz_target!(|data: &[u8]| {
    // --- Test 1: eval_script with raw bytes as a script ---
    {
        let script = Script::from_bytes(data.to_vec());
        let mut stack = ScriptStack::new();
        let checker = BaseSignatureChecker;
        let mut exec_data = ScriptExecutionData::default();
        let mut error = ScriptError::Ok;

        // Run the interpreter; we don't care about the result, only that it
        // does not panic.
        let _ok = qubitcoin_script::eval_script(
            &mut stack,
            &script,
            &ScriptVerifyFlags::empty(),
            &checker,
            SigVersion::Base,
            &mut exec_data,
            &mut error,
        );
    }

    // --- Test 2: eval_script with common verification flags ---
    {
        let script = Script::from_bytes(data.to_vec());
        let mut stack = ScriptStack::new();
        let checker = BaseSignatureChecker;
        let mut exec_data = ScriptExecutionData::default();
        let mut error = ScriptError::Ok;

        let flags = ScriptVerifyFlags::P2SH
            | ScriptVerifyFlags::DERSIG
            | ScriptVerifyFlags::CHECKLOCKTIMEVERIFY
            | ScriptVerifyFlags::CHECKSEQUENCEVERIFY
            | ScriptVerifyFlags::WITNESS;

        let _ok = qubitcoin_script::eval_script(
            &mut stack,
            &script,
            &flags,
            &checker,
            SigVersion::Base,
            &mut exec_data,
            &mut error,
        );
    }

    // --- Test 3: verify_script with script split in half (scriptSig + scriptPubKey) ---
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let script_sig = Script::from_bytes(data[..mid].to_vec());
        let script_pubkey = Script::from_bytes(data[mid..].to_vec());
        let witness = ScriptWitness::new();
        let checker = BaseSignatureChecker;
        let mut error = ScriptError::Ok;

        let _ok = qubitcoin_script::verify_script(
            &script_sig,
            &script_pubkey,
            &witness,
            &ScriptVerifyFlags::empty(),
            &checker,
            &mut error,
        );
    }
});
