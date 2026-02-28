//! qubitcoin-script: Bitcoin Script types and VM.
//!
//! Maps to: src/script/ in Bitcoin Core
//!
//! Provides:
//! - `Opcode` enum (all opcodes OP_0..OP_NOP10, OP_CHECKSIGADD)
//! - `Script` type (byte vector with helper methods)
//! - `ScriptNum` (consensus-critical numeric type)
//! - `ScriptError` (all script verification errors)
//! - `ScriptVerifyFlags` (P2SH, DERSIG, WITNESS, TAPROOT, etc.)
//!
//! Phase 2 will add: eval_script(), verify_script(), SignatureChecker

pub mod interpreter;
pub mod opcode;
pub mod script;
pub mod script_error;
pub mod script_num;
pub mod verify_flags;

pub use interpreter::{
    cast_to_bool, eval_script, eval_script_simple, verify_script, BaseSignatureChecker,
    ScriptExecutionData, ScriptStack, ScriptWitness, SigVersion, SignatureChecker,
};
pub use opcode::Opcode;
pub use script::{
    build_op_return, build_p2pkh, build_p2sh, build_p2tr, build_p2wpkh, build_p2wsh, Script,
    ScriptOpsIter, LOCKTIME_THRESHOLD, MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG,
    MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_SIZE,
};
pub use script_error::ScriptError;
pub use script_num::ScriptNum;
pub use verify_flags::ScriptVerifyFlags;
