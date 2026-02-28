//! Bitcoin Script opcodes.
//! Maps to: src/script/script.h (opcodetype enum)
//!
//! Complete enumeration of all Bitcoin Script opcodes including
//! disabled, reserved, and tapscript opcodes.

/// All Bitcoin Script opcodes.
///
/// Port of Bitcoin Core's `opcodetype` enum. Values match byte values in script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // Push value
    Op0 = 0x00,
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    OpPushData4 = 0x4e,
    Op1Negate = 0x4f,
    OpReserved = 0x50,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // Control flow
    OpNop = 0x61,
    OpVer = 0x62,
    OpIf = 0x63,
    OpNotIf = 0x64,
    OpVerIf = 0x65,
    OpVerNotIf = 0x66,
    OpElse = 0x67,
    OpEndIf = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // Stack
    OpToAltStack = 0x6b,
    OpFromAltStack = 0x6c,
    Op2Drop = 0x6d,
    Op2Dup = 0x6e,
    Op3Dup = 0x6f,
    Op2Over = 0x70,
    Op2Rot = 0x71,
    Op2Swap = 0x72,
    OpIfDup = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,

    // Splice (disabled)
    OpCat = 0x7e,
    OpSubStr = 0x7f,
    OpLeft = 0x80,
    OpRight = 0x81,
    OpSize = 0x82,

    // Bit logic (disabled except EQUAL)
    OpInvert = 0x83,
    OpAnd = 0x84,
    OpOr = 0x85,
    OpXor = 0x86,
    OpEqual = 0x87,
    OpEqualVerify = 0x88,
    OpReserved1 = 0x89,
    OpReserved2 = 0x8a,

    // Numeric
    Op1Add = 0x8b,
    Op1Sub = 0x8c,
    Op2Mul = 0x8d,
    Op2Div = 0x8e,
    OpNegate = 0x8f,
    OpAbs = 0x90,
    OpNot = 0x91,
    Op0NotEqual = 0x92,
    OpAdd = 0x93,
    OpSub = 0x94,
    OpMul = 0x95,
    OpDiv = 0x96,
    OpMod = 0x97,
    OpLShift = 0x98,
    OpRShift = 0x99,
    OpBoolAnd = 0x9a,
    OpBoolOr = 0x9b,
    OpNumEqual = 0x9c,
    OpNumEqualVerify = 0x9d,
    OpNumNotEqual = 0x9e,
    OpLessThan = 0x9f,
    OpGreaterThan = 0xa0,
    OpLessThanOrEqual = 0xa1,
    OpGreaterThanOrEqual = 0xa2,
    OpMin = 0xa3,
    OpMax = 0xa4,
    OpWithin = 0xa5,

    // Crypto
    OpRipemd160 = 0xa6,
    OpSha1 = 0xa7,
    OpSha256 = 0xa8,
    OpHash160 = 0xa9,
    OpHash256 = 0xaa,
    OpCodeSeparator = 0xab,
    OpCheckSig = 0xac,
    OpCheckSigVerify = 0xad,
    OpCheckMultiSig = 0xae,
    OpCheckMultiSigVerify = 0xaf,

    // Expansion / NOP
    OpNop1 = 0xb0,
    OpCheckLockTimeVerify = 0xb1,
    OpCheckSequenceVerify = 0xb2,
    OpNop4 = 0xb3,
    OpNop5 = 0xb4,
    OpNop6 = 0xb5,
    OpNop7 = 0xb6,
    OpNop8 = 0xb7,
    OpNop9 = 0xb8,
    OpNop10 = 0xb9,

    // BIP342 Tapscript
    OpCheckSigAdd = 0xba,

    // Invalid
    OpInvalidOpcode = 0xff,
}

/// Aliases for common opcodes.
pub const OP_FALSE: Opcode = Opcode::Op0;
pub const OP_TRUE: Opcode = Opcode::Op1;
pub const OP_NOP2: Opcode = Opcode::OpCheckLockTimeVerify;
pub const OP_NOP3: Opcode = Opcode::OpCheckSequenceVerify;

/// Maximum valid opcode value (OP_NOP10).
pub const MAX_OPCODE: u8 = Opcode::OpNop10 as u8;

impl Opcode {
    /// Try to convert a byte to an Opcode.
    /// Returns None for values between OP_NOP10+1 (0xba+1) and 0xfe that aren't OP_CHECKSIGADD.
    pub fn from_u8(byte: u8) -> Option<Opcode> {
        // Direct data push opcodes (0x01..=0x4b) are not in the enum
        // They represent "push next N bytes" and are handled by the script parser
        match byte {
            0x00 => Some(Opcode::Op0),
            0x4c => Some(Opcode::OpPushData1),
            0x4d => Some(Opcode::OpPushData2),
            0x4e => Some(Opcode::OpPushData4),
            0x4f => Some(Opcode::Op1Negate),
            0x50 => Some(Opcode::OpReserved),
            0x51 => Some(Opcode::Op1),
            0x52 => Some(Opcode::Op2),
            0x53 => Some(Opcode::Op3),
            0x54 => Some(Opcode::Op4),
            0x55 => Some(Opcode::Op5),
            0x56 => Some(Opcode::Op6),
            0x57 => Some(Opcode::Op7),
            0x58 => Some(Opcode::Op8),
            0x59 => Some(Opcode::Op9),
            0x5a => Some(Opcode::Op10),
            0x5b => Some(Opcode::Op11),
            0x5c => Some(Opcode::Op12),
            0x5d => Some(Opcode::Op13),
            0x5e => Some(Opcode::Op14),
            0x5f => Some(Opcode::Op15),
            0x60 => Some(Opcode::Op16),
            0x61 => Some(Opcode::OpNop),
            0x62 => Some(Opcode::OpVer),
            0x63 => Some(Opcode::OpIf),
            0x64 => Some(Opcode::OpNotIf),
            0x65 => Some(Opcode::OpVerIf),
            0x66 => Some(Opcode::OpVerNotIf),
            0x67 => Some(Opcode::OpElse),
            0x68 => Some(Opcode::OpEndIf),
            0x69 => Some(Opcode::OpVerify),
            0x6a => Some(Opcode::OpReturn),
            0x6b => Some(Opcode::OpToAltStack),
            0x6c => Some(Opcode::OpFromAltStack),
            0x6d => Some(Opcode::Op2Drop),
            0x6e => Some(Opcode::Op2Dup),
            0x6f => Some(Opcode::Op3Dup),
            0x70 => Some(Opcode::Op2Over),
            0x71 => Some(Opcode::Op2Rot),
            0x72 => Some(Opcode::Op2Swap),
            0x73 => Some(Opcode::OpIfDup),
            0x74 => Some(Opcode::OpDepth),
            0x75 => Some(Opcode::OpDrop),
            0x76 => Some(Opcode::OpDup),
            0x77 => Some(Opcode::OpNip),
            0x78 => Some(Opcode::OpOver),
            0x79 => Some(Opcode::OpPick),
            0x7a => Some(Opcode::OpRoll),
            0x7b => Some(Opcode::OpRot),
            0x7c => Some(Opcode::OpSwap),
            0x7d => Some(Opcode::OpTuck),
            0x7e => Some(Opcode::OpCat),
            0x7f => Some(Opcode::OpSubStr),
            0x80 => Some(Opcode::OpLeft),
            0x81 => Some(Opcode::OpRight),
            0x82 => Some(Opcode::OpSize),
            0x83 => Some(Opcode::OpInvert),
            0x84 => Some(Opcode::OpAnd),
            0x85 => Some(Opcode::OpOr),
            0x86 => Some(Opcode::OpXor),
            0x87 => Some(Opcode::OpEqual),
            0x88 => Some(Opcode::OpEqualVerify),
            0x89 => Some(Opcode::OpReserved1),
            0x8a => Some(Opcode::OpReserved2),
            0x8b => Some(Opcode::Op1Add),
            0x8c => Some(Opcode::Op1Sub),
            0x8d => Some(Opcode::Op2Mul),
            0x8e => Some(Opcode::Op2Div),
            0x8f => Some(Opcode::OpNegate),
            0x90 => Some(Opcode::OpAbs),
            0x91 => Some(Opcode::OpNot),
            0x92 => Some(Opcode::Op0NotEqual),
            0x93 => Some(Opcode::OpAdd),
            0x94 => Some(Opcode::OpSub),
            0x95 => Some(Opcode::OpMul),
            0x96 => Some(Opcode::OpDiv),
            0x97 => Some(Opcode::OpMod),
            0x98 => Some(Opcode::OpLShift),
            0x99 => Some(Opcode::OpRShift),
            0x9a => Some(Opcode::OpBoolAnd),
            0x9b => Some(Opcode::OpBoolOr),
            0x9c => Some(Opcode::OpNumEqual),
            0x9d => Some(Opcode::OpNumEqualVerify),
            0x9e => Some(Opcode::OpNumNotEqual),
            0x9f => Some(Opcode::OpLessThan),
            0xa0 => Some(Opcode::OpGreaterThan),
            0xa1 => Some(Opcode::OpLessThanOrEqual),
            0xa2 => Some(Opcode::OpGreaterThanOrEqual),
            0xa3 => Some(Opcode::OpMin),
            0xa4 => Some(Opcode::OpMax),
            0xa5 => Some(Opcode::OpWithin),
            0xa6 => Some(Opcode::OpRipemd160),
            0xa7 => Some(Opcode::OpSha1),
            0xa8 => Some(Opcode::OpSha256),
            0xa9 => Some(Opcode::OpHash160),
            0xaa => Some(Opcode::OpHash256),
            0xab => Some(Opcode::OpCodeSeparator),
            0xac => Some(Opcode::OpCheckSig),
            0xad => Some(Opcode::OpCheckSigVerify),
            0xae => Some(Opcode::OpCheckMultiSig),
            0xaf => Some(Opcode::OpCheckMultiSigVerify),
            0xb0 => Some(Opcode::OpNop1),
            0xb1 => Some(Opcode::OpCheckLockTimeVerify),
            0xb2 => Some(Opcode::OpCheckSequenceVerify),
            0xb3 => Some(Opcode::OpNop4),
            0xb4 => Some(Opcode::OpNop5),
            0xb5 => Some(Opcode::OpNop6),
            0xb6 => Some(Opcode::OpNop7),
            0xb7 => Some(Opcode::OpNop8),
            0xb8 => Some(Opcode::OpNop9),
            0xb9 => Some(Opcode::OpNop10),
            0xba => Some(Opcode::OpCheckSigAdd),
            0xff => Some(Opcode::OpInvalidOpcode),
            // 0x01..=0x4b are direct push opcodes, handled by script parser
            // 0xbb..=0xfe are undefined but still valid bytes in script
            _ => None,
        }
    }

    /// Get the opcode name as a string (matching Bitcoin Core's GetOpName).
    pub fn name(&self) -> &'static str {
        match self {
            Opcode::Op0 => "OP_0",
            Opcode::OpPushData1 => "OP_PUSHDATA1",
            Opcode::OpPushData2 => "OP_PUSHDATA2",
            Opcode::OpPushData4 => "OP_PUSHDATA4",
            Opcode::Op1Negate => "OP_1NEGATE",
            Opcode::OpReserved => "OP_RESERVED",
            Opcode::Op1 => "OP_1",
            Opcode::Op2 => "OP_2",
            Opcode::Op3 => "OP_3",
            Opcode::Op4 => "OP_4",
            Opcode::Op5 => "OP_5",
            Opcode::Op6 => "OP_6",
            Opcode::Op7 => "OP_7",
            Opcode::Op8 => "OP_8",
            Opcode::Op9 => "OP_9",
            Opcode::Op10 => "OP_10",
            Opcode::Op11 => "OP_11",
            Opcode::Op12 => "OP_12",
            Opcode::Op13 => "OP_13",
            Opcode::Op14 => "OP_14",
            Opcode::Op15 => "OP_15",
            Opcode::Op16 => "OP_16",
            Opcode::OpNop => "OP_NOP",
            Opcode::OpVer => "OP_VER",
            Opcode::OpIf => "OP_IF",
            Opcode::OpNotIf => "OP_NOTIF",
            Opcode::OpVerIf => "OP_VERIF",
            Opcode::OpVerNotIf => "OP_VERNOTIF",
            Opcode::OpElse => "OP_ELSE",
            Opcode::OpEndIf => "OP_ENDIF",
            Opcode::OpVerify => "OP_VERIFY",
            Opcode::OpReturn => "OP_RETURN",
            Opcode::OpToAltStack => "OP_TOALTSTACK",
            Opcode::OpFromAltStack => "OP_FROMALTSTACK",
            Opcode::Op2Drop => "OP_2DROP",
            Opcode::Op2Dup => "OP_2DUP",
            Opcode::Op3Dup => "OP_3DUP",
            Opcode::Op2Over => "OP_2OVER",
            Opcode::Op2Rot => "OP_2ROT",
            Opcode::Op2Swap => "OP_2SWAP",
            Opcode::OpIfDup => "OP_IFDUP",
            Opcode::OpDepth => "OP_DEPTH",
            Opcode::OpDrop => "OP_DROP",
            Opcode::OpDup => "OP_DUP",
            Opcode::OpNip => "OP_NIP",
            Opcode::OpOver => "OP_OVER",
            Opcode::OpPick => "OP_PICK",
            Opcode::OpRoll => "OP_ROLL",
            Opcode::OpRot => "OP_ROT",
            Opcode::OpSwap => "OP_SWAP",
            Opcode::OpTuck => "OP_TUCK",
            Opcode::OpCat => "OP_CAT",
            Opcode::OpSubStr => "OP_SUBSTR",
            Opcode::OpLeft => "OP_LEFT",
            Opcode::OpRight => "OP_RIGHT",
            Opcode::OpSize => "OP_SIZE",
            Opcode::OpInvert => "OP_INVERT",
            Opcode::OpAnd => "OP_AND",
            Opcode::OpOr => "OP_OR",
            Opcode::OpXor => "OP_XOR",
            Opcode::OpEqual => "OP_EQUAL",
            Opcode::OpEqualVerify => "OP_EQUALVERIFY",
            Opcode::OpReserved1 => "OP_RESERVED1",
            Opcode::OpReserved2 => "OP_RESERVED2",
            Opcode::Op1Add => "OP_1ADD",
            Opcode::Op1Sub => "OP_1SUB",
            Opcode::Op2Mul => "OP_2MUL",
            Opcode::Op2Div => "OP_2DIV",
            Opcode::OpNegate => "OP_NEGATE",
            Opcode::OpAbs => "OP_ABS",
            Opcode::OpNot => "OP_NOT",
            Opcode::Op0NotEqual => "OP_0NOTEQUAL",
            Opcode::OpAdd => "OP_ADD",
            Opcode::OpSub => "OP_SUB",
            Opcode::OpMul => "OP_MUL",
            Opcode::OpDiv => "OP_DIV",
            Opcode::OpMod => "OP_MOD",
            Opcode::OpLShift => "OP_LSHIFT",
            Opcode::OpRShift => "OP_RSHIFT",
            Opcode::OpBoolAnd => "OP_BOOLAND",
            Opcode::OpBoolOr => "OP_BOOLOR",
            Opcode::OpNumEqual => "OP_NUMEQUAL",
            Opcode::OpNumEqualVerify => "OP_NUMEQUALVERIFY",
            Opcode::OpNumNotEqual => "OP_NUMNOTEQUAL",
            Opcode::OpLessThan => "OP_LESSTHAN",
            Opcode::OpGreaterThan => "OP_GREATERTHAN",
            Opcode::OpLessThanOrEqual => "OP_LESSTHANOREQUAL",
            Opcode::OpGreaterThanOrEqual => "OP_GREATERTHANOREQUAL",
            Opcode::OpMin => "OP_MIN",
            Opcode::OpMax => "OP_MAX",
            Opcode::OpWithin => "OP_WITHIN",
            Opcode::OpRipemd160 => "OP_RIPEMD160",
            Opcode::OpSha1 => "OP_SHA1",
            Opcode::OpSha256 => "OP_SHA256",
            Opcode::OpHash160 => "OP_HASH160",
            Opcode::OpHash256 => "OP_HASH256",
            Opcode::OpCodeSeparator => "OP_CODESEPARATOR",
            Opcode::OpCheckSig => "OP_CHECKSIG",
            Opcode::OpCheckSigVerify => "OP_CHECKSIGVERIFY",
            Opcode::OpCheckMultiSig => "OP_CHECKMULTISIG",
            Opcode::OpCheckMultiSigVerify => "OP_CHECKMULTISIGVERIFY",
            Opcode::OpNop1 => "OP_NOP1",
            Opcode::OpCheckLockTimeVerify => "OP_CHECKLOCKTIMEVERIFY",
            Opcode::OpCheckSequenceVerify => "OP_CHECKSEQUENCEVERIFY",
            Opcode::OpNop4 => "OP_NOP4",
            Opcode::OpNop5 => "OP_NOP5",
            Opcode::OpNop6 => "OP_NOP6",
            Opcode::OpNop7 => "OP_NOP7",
            Opcode::OpNop8 => "OP_NOP8",
            Opcode::OpNop9 => "OP_NOP9",
            Opcode::OpNop10 => "OP_NOP10",
            Opcode::OpCheckSigAdd => "OP_CHECKSIGADD",
            Opcode::OpInvalidOpcode => "OP_INVALIDOPCODE",
        }
    }

    /// Check if this is a push-data opcode (includes OP_0 and OP_1..OP_16).
    pub fn is_push(&self) -> bool {
        (*self as u8) <= Opcode::Op16 as u8
    }

    /// Check if this opcode is disabled.
    pub fn is_disabled(&self) -> bool {
        matches!(
            self,
            Opcode::OpCat
                | Opcode::OpSubStr
                | Opcode::OpLeft
                | Opcode::OpRight
                | Opcode::OpInvert
                | Opcode::OpAnd
                | Opcode::OpOr
                | Opcode::OpXor
                | Opcode::Op2Mul
                | Opcode::Op2Div
                | Opcode::OpMul
                | Opcode::OpDiv
                | Opcode::OpMod
                | Opcode::OpLShift
                | Opcode::OpRShift
        )
    }
}

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Decode an opcode name string to Opcode value.
/// Returns None for unrecognized names.
pub fn name_to_opcode(name: &str) -> Option<Opcode> {
    match name {
        "OP_0" | "OP_FALSE" | "0" => Some(Opcode::Op0),
        "OP_PUSHDATA1" => Some(Opcode::OpPushData1),
        "OP_PUSHDATA2" => Some(Opcode::OpPushData2),
        "OP_PUSHDATA4" => Some(Opcode::OpPushData4),
        "OP_1NEGATE" => Some(Opcode::Op1Negate),
        "OP_RESERVED" => Some(Opcode::OpReserved),
        "OP_1" | "OP_TRUE" | "1" => Some(Opcode::Op1),
        "OP_2" | "2" => Some(Opcode::Op2),
        "OP_3" | "3" => Some(Opcode::Op3),
        "OP_4" | "4" => Some(Opcode::Op4),
        "OP_5" | "5" => Some(Opcode::Op5),
        "OP_6" | "6" => Some(Opcode::Op6),
        "OP_7" | "7" => Some(Opcode::Op7),
        "OP_8" | "8" => Some(Opcode::Op8),
        "OP_9" | "9" => Some(Opcode::Op9),
        "OP_10" | "10" => Some(Opcode::Op10),
        "OP_11" | "11" => Some(Opcode::Op11),
        "OP_12" | "12" => Some(Opcode::Op12),
        "OP_13" | "13" => Some(Opcode::Op13),
        "OP_14" | "14" => Some(Opcode::Op14),
        "OP_15" | "15" => Some(Opcode::Op15),
        "OP_16" | "16" => Some(Opcode::Op16),
        "OP_NOP" => Some(Opcode::OpNop),
        "OP_IF" => Some(Opcode::OpIf),
        "OP_NOTIF" => Some(Opcode::OpNotIf),
        "OP_ELSE" => Some(Opcode::OpElse),
        "OP_ENDIF" => Some(Opcode::OpEndIf),
        "OP_VERIFY" => Some(Opcode::OpVerify),
        "OP_RETURN" => Some(Opcode::OpReturn),
        "OP_DUP" => Some(Opcode::OpDup),
        "OP_EQUAL" => Some(Opcode::OpEqual),
        "OP_EQUALVERIFY" => Some(Opcode::OpEqualVerify),
        "OP_HASH160" => Some(Opcode::OpHash160),
        "OP_HASH256" => Some(Opcode::OpHash256),
        "OP_CHECKSIG" => Some(Opcode::OpCheckSig),
        "OP_CHECKMULTISIG" => Some(Opcode::OpCheckMultiSig),
        "OP_CHECKLOCKTIMEVERIFY" | "OP_NOP2" => Some(Opcode::OpCheckLockTimeVerify),
        "OP_CHECKSEQUENCEVERIFY" | "OP_NOP3" => Some(Opcode::OpCheckSequenceVerify),
        "OP_CHECKSIGADD" => Some(Opcode::OpCheckSigAdd),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_values() {
        assert_eq!(Opcode::Op0 as u8, 0x00);
        assert_eq!(Opcode::OpDup as u8, 0x76);
        assert_eq!(Opcode::OpCheckSig as u8, 0xac);
        assert_eq!(Opcode::OpCheckSigAdd as u8, 0xba);
        assert_eq!(Opcode::OpInvalidOpcode as u8, 0xff);
    }

    #[test]
    fn test_from_u8() {
        assert_eq!(Opcode::from_u8(0x00), Some(Opcode::Op0));
        assert_eq!(Opcode::from_u8(0x76), Some(Opcode::OpDup));
        assert_eq!(Opcode::from_u8(0xba), Some(Opcode::OpCheckSigAdd));
        // Direct push bytes are not in the enum
        assert_eq!(Opcode::from_u8(0x01), None);
        assert_eq!(Opcode::from_u8(0x4b), None);
    }

    #[test]
    fn test_aliases() {
        assert_eq!(OP_FALSE as u8, Opcode::Op0 as u8);
        assert_eq!(OP_TRUE as u8, Opcode::Op1 as u8);
    }

    #[test]
    fn test_is_disabled() {
        assert!(Opcode::OpCat.is_disabled());
        assert!(Opcode::OpMul.is_disabled());
        assert!(!Opcode::OpAdd.is_disabled());
        assert!(!Opcode::OpDup.is_disabled());
    }
}
