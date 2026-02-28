//! Script execution error types.
//! Maps to: src/script/script_error.h

/// All possible script verification errors.
///
/// Port of Bitcoin Core's `ScriptError` enum. Values match 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptError {
    Ok = 0,
    UnknownError = 1,
    EvalFalse = 2,
    OpReturn = 3,

    // Max sizes
    ScriptNum = 4,
    ScriptSize = 5,
    PushSize = 6,
    OpCount = 7,
    StackSize = 8,
    SigCount = 9,
    PubkeyCount = 10,

    // Verify operations
    Verify = 11,
    EqualVerify = 12,
    CheckMultiSigVerify = 13,
    CheckSigVerify = 14,
    NumEqualVerify = 15,

    // Logical/format errors
    BadOpcode = 16,
    DisabledOpcode = 17,
    InvalidStackOperation = 18,
    InvalidAltstackOperation = 19,
    UnbalancedConditional = 20,

    // CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY
    NegativeLocktime = 21,
    UnsatisfiedLocktime = 22,

    // Malleability
    SigHashtype = 23,
    SigDer = 24,
    MinimalData = 25,
    SigPushOnly = 26,
    SigHighS = 27,
    SigNullDummy = 28,
    PubKeyType = 29,
    CleanStack = 30,
    MinimalIf = 31,
    SigNullFail = 32,

    // Softfork safeness
    DiscourageUpgradableNops = 33,
    DiscourageUpgradableWitnessProgram = 34,
    DiscourageUpgradableTaprootVersion = 35,
    DiscourageOpSuccess = 36,
    DiscourageUpgradablePubkeyType = 37,

    // Segregated witness
    WitnessProgramWrongLength = 38,
    WitnessProgramWitnessEmpty = 39,
    WitnessProgramMismatch = 40,
    WitnessMalleated = 41,
    WitnessMalleatedP2sh = 42,
    WitnessUnexpected = 43,
    WitnessPubKeyType = 44,

    // Taproot / Tapscript
    SchnorrSigSize = 45,
    SchnorrSigHashtype = 46,
    SchnorrSig = 47,
    TaprootWrongControlSize = 48,
    TapscriptValidationWeight = 49,
    TapscriptCheckMultiSig = 50,
    TapscriptMinimalIf = 51,
    TapscriptEmptyPubkey = 52,

    // Additional
    OpCodeSeparator = 53,
    SigFindAndDelete = 54,

    ErrorCount = 55,
}

impl ScriptError {
    /// Get a human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            ScriptError::Ok => "No error",
            ScriptError::UnknownError => "Unknown error",
            ScriptError::EvalFalse => {
                "Script evaluated without error but finished with a false/empty top stack element"
            }
            ScriptError::OpReturn => "OP_RETURN was encountered",
            ScriptError::ScriptNum => "Script number overflow",
            ScriptError::ScriptSize => "Script is too big",
            ScriptError::PushSize => "Push value size limit exceeded",
            ScriptError::OpCount => "Operation limit exceeded",
            ScriptError::StackSize => "Stack size limit exceeded",
            ScriptError::SigCount => "Signature count negative or greater than pubkey count",
            ScriptError::PubkeyCount => "Pubkey count negative or limit exceeded",
            ScriptError::Verify => "Script failed an OP_VERIFY operation",
            ScriptError::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            ScriptError::CheckMultiSigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            ScriptError::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            ScriptError::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            ScriptError::BadOpcode => "Opcode missing or not understood",
            ScriptError::DisabledOpcode => "Attempted to use a disabled opcode",
            ScriptError::InvalidStackOperation => "Operation not valid with the current stack size",
            ScriptError::InvalidAltstackOperation => {
                "Operation not valid with the current altstack size"
            }
            ScriptError::UnbalancedConditional => "Invalid OP_IF construction",
            ScriptError::NegativeLocktime => "Negative locktime",
            ScriptError::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            ScriptError::SigHashtype => "Signature hash type missing or not understood",
            ScriptError::SigDer => "Non-canonical DER signature",
            ScriptError::MinimalData => "Data push larger than necessary",
            ScriptError::SigPushOnly => "Only push operators allowed in signatures",
            ScriptError::SigHighS => "Non-canonical signature: S value is unnecessarily high",
            ScriptError::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            ScriptError::PubKeyType => "Public key is neither compressed or uncompressed",
            ScriptError::CleanStack => "Stack size must be exactly one after execution",
            ScriptError::MinimalIf => "OP_IF/NOTIF argument must be minimal",
            ScriptError::SigNullFail => {
                "Signature must be zero for failed CHECK(MULTI)SIG operation"
            }
            ScriptError::DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            ScriptError::DiscourageUpgradableWitnessProgram => {
                "Witness version reserved for soft-fork upgrades"
            }
            ScriptError::DiscourageUpgradableTaprootVersion => {
                "Taproot version reserved for soft-fork upgrades"
            }
            ScriptError::DiscourageOpSuccess => "OP_SUCCESSx reserved for soft-fork upgrades",
            ScriptError::DiscourageUpgradablePubkeyType => {
                "Public key version reserved for soft-fork upgrades"
            }
            ScriptError::WitnessProgramWrongLength => "Witness program has incorrect length",
            ScriptError::WitnessProgramWitnessEmpty => {
                "Witness program was passed an empty witness"
            }
            ScriptError::WitnessProgramMismatch => "Witness program hash mismatch",
            ScriptError::WitnessMalleated => "Witness requires empty scriptSig",
            ScriptError::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            ScriptError::WitnessUnexpected => "Witness provided for non-witness script",
            ScriptError::WitnessPubKeyType => "Using non-compressed keys in segwit",
            ScriptError::SchnorrSigSize => "Invalid Schnorr signature size",
            ScriptError::SchnorrSigHashtype => "Invalid Schnorr signature hash type",
            ScriptError::SchnorrSig => "Invalid Schnorr signature",
            ScriptError::TaprootWrongControlSize => "Invalid control block size",
            ScriptError::TapscriptValidationWeight => {
                "Too much signature validation relative to witness weight"
            }
            ScriptError::TapscriptCheckMultiSig => {
                "OP_CHECKMULTISIG(VERIFY) is not available in tapscript"
            }
            ScriptError::TapscriptMinimalIf => "OP_IF/NOTIF argument must be minimal in tapscript",
            ScriptError::TapscriptEmptyPubkey => "Tapscript public key must not be empty",
            ScriptError::OpCodeSeparator => "Using OP_CODESEPARATOR in non-witness script",
            ScriptError::SigFindAndDelete => "Signature is found in scriptCode",
            ScriptError::ErrorCount => "(error count sentinel)",
        }
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::error::Error for ScriptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_values() {
        assert_eq!(ScriptError::Ok as u8, 0);
        assert_eq!(ScriptError::ErrorCount as u8, 55);
    }
}
