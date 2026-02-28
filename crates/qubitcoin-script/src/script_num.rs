//! Bitcoin Script number type with consensus-critical overflow semantics.
//! Maps to: src/script/script.h (CScriptNum)
//!
//! Script numbers are limited to 4-byte integers during operations.
//! The range is [-2^31+1 ... 2^31-1] for operands, but the internal
//! representation uses i64 to detect overflows.
//!
//! Encoding: little-endian with sign bit in the MSB of the last byte.

/// Error for script number operations.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Script number error: {0}")]
pub struct ScriptNumError(pub String);

/// Bitcoin Script number.
///
/// Stores as i64 internally for overflow detection.
/// Serializes to/from variable-length byte encoding:
/// - Little-endian magnitude
/// - Sign bit is MSB of last byte
/// - Minimal encoding required
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptNum(i64);

/// Default maximum number size in bytes for script operations.
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

impl ScriptNum {
    /// Create from an i64 value.
    pub const fn new(n: i64) -> Self {
        ScriptNum(n)
    }

    /// Create from byte vector with consensus rules.
    ///
    /// `require_minimal`: reject non-minimal encodings (e.g., 0x00 for zero, extra padding)
    /// `max_num_size`: maximum allowed byte length (default 4)
    pub fn from_bytes(
        vch: &[u8],
        require_minimal: bool,
        max_num_size: usize,
    ) -> Result<Self, ScriptNumError> {
        if vch.len() > max_num_size {
            return Err(ScriptNumError("script number overflow".to_string()));
        }

        if require_minimal && !vch.is_empty() {
            // Check that the number is encoded with the minimum possible number of bytes.
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if (vch.last().unwrap() & 0x7f) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit, so an extra byte is justified.
                if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
                    return Err(ScriptNumError(
                        "non-minimally encoded script number".to_string(),
                    ));
                }
            }
        }

        Ok(ScriptNum(Self::decode_bytes(vch)))
    }

    /// Get as i32 with clamping to INT_MAX/INT_MIN.
    pub fn getint(&self) -> i32 {
        if self.0 > i32::MAX as i64 {
            i32::MAX
        } else if self.0 < i32::MIN as i64 {
            i32::MIN
        } else {
            self.0 as i32
        }
    }

    /// Get as i64.
    pub const fn get_i64(&self) -> i64 {
        self.0
    }

    /// Serialize to byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        Self::encode_i64(self.0)
    }

    /// Encode an i64 value to script number bytes.
    pub fn encode_i64(value: i64) -> Vec<u8> {
        if value == 0 {
            return vec![];
        }

        let mut result = Vec::new();
        let negative = value < 0;
        let mut absvalue = if negative {
            (value as i128).wrapping_neg() as u64
        } else {
            value as u64
        };

        while absvalue > 0 {
            result.push((absvalue & 0xff) as u8);
            absvalue >>= 8;
        }

        // If the last byte has the sign bit set, we need an extra byte
        // to indicate the actual sign.
        if result.last().unwrap() & 0x80 != 0 {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            *result.last_mut().unwrap() |= 0x80;
        }

        result
    }

    /// Decode bytes to i64 value.
    fn decode_bytes(vch: &[u8]) -> i64 {
        if vch.is_empty() {
            return 0;
        }

        let mut result: i64 = 0;
        for (i, &byte) in vch.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if vch.last().unwrap() & 0x80 != 0 {
            result &= !(0x80i64 << (8 * (vch.len() - 1)));
            -result
        } else {
            result
        }
    }
}

impl std::ops::Add for ScriptNum {
    type Output = ScriptNum;
    fn add(self, rhs: ScriptNum) -> ScriptNum {
        ScriptNum(self.0 + rhs.0)
    }
}

impl std::ops::Sub for ScriptNum {
    type Output = ScriptNum;
    fn sub(self, rhs: ScriptNum) -> ScriptNum {
        ScriptNum(self.0 - rhs.0)
    }
}

impl std::ops::Neg for ScriptNum {
    type Output = ScriptNum;
    fn neg(self) -> ScriptNum {
        ScriptNum(-self.0)
    }
}

impl std::ops::AddAssign for ScriptNum {
    fn add_assign(&mut self, rhs: ScriptNum) {
        self.0 += rhs.0;
    }
}

impl std::ops::SubAssign for ScriptNum {
    fn sub_assign(&mut self, rhs: ScriptNum) {
        self.0 -= rhs.0;
    }
}

impl std::ops::BitAnd for ScriptNum {
    type Output = ScriptNum;
    fn bitand(self, rhs: ScriptNum) -> ScriptNum {
        ScriptNum(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for ScriptNum {
    fn bitand_assign(&mut self, rhs: ScriptNum) {
        self.0 &= rhs.0;
    }
}

impl std::fmt::Display for ScriptNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i64> for ScriptNum {
    fn from(n: i64) -> Self {
        ScriptNum(n)
    }
}

impl From<ScriptNum> for i64 {
    fn from(n: ScriptNum) -> i64 {
        n.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let n = ScriptNum::new(0);
        assert_eq!(n.get_i64(), 0);
        assert_eq!(n.to_bytes(), vec![]);
    }

    #[test]
    fn test_positive() {
        let n = ScriptNum::new(1);
        assert_eq!(n.to_bytes(), vec![0x01]);

        let n = ScriptNum::new(127);
        assert_eq!(n.to_bytes(), vec![0x7f]);

        let n = ScriptNum::new(128);
        assert_eq!(n.to_bytes(), vec![0x80, 0x00]);

        let n = ScriptNum::new(255);
        assert_eq!(n.to_bytes(), vec![0xff, 0x00]);

        let n = ScriptNum::new(256);
        assert_eq!(n.to_bytes(), vec![0x00, 0x01]);
    }

    #[test]
    fn test_negative() {
        let n = ScriptNum::new(-1);
        assert_eq!(n.to_bytes(), vec![0x81]);

        let n = ScriptNum::new(-127);
        assert_eq!(n.to_bytes(), vec![0xff]);

        let n = ScriptNum::new(-128);
        assert_eq!(n.to_bytes(), vec![0x80, 0x80]);

        let n = ScriptNum::new(-255);
        assert_eq!(n.to_bytes(), vec![0xff, 0x80]);
    }

    #[test]
    fn test_roundtrip() {
        for val in [-1000, -1, 0, 1, 127, 128, 255, 256, 1000, 65535, -65535] {
            let n = ScriptNum::new(val);
            let bytes = n.to_bytes();
            let decoded = ScriptNum::from_bytes(&bytes, false, 4).unwrap();
            assert_eq!(decoded.get_i64(), val, "Roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_minimal_encoding() {
        // Non-minimal: 0x00 for zero
        assert!(ScriptNum::from_bytes(&[0x00], true, 4).is_err());
        // Non-minimal: negative zero
        assert!(ScriptNum::from_bytes(&[0x80], true, 4).is_err());
        // Non-minimal: extra zero byte for 1
        assert!(ScriptNum::from_bytes(&[0x01, 0x00], true, 4).is_err());
    }

    #[test]
    fn test_overflow() {
        // 5 bytes exceeds max_num_size of 4
        assert!(ScriptNum::from_bytes(&[1, 2, 3, 4, 5], false, 4).is_err());
        // But 5 bytes is fine with max_num_size of 5
        assert!(ScriptNum::from_bytes(&[1, 2, 3, 4, 5], false, 5).is_ok());
    }

    #[test]
    fn test_arithmetic() {
        let a = ScriptNum::new(10);
        let b = ScriptNum::new(20);
        assert_eq!((a + b).get_i64(), 30);
        assert_eq!((b - a).get_i64(), 10);
        assert_eq!((-a).get_i64(), -10);
    }

    #[test]
    fn test_getint_clamping() {
        let n = ScriptNum::new(i64::MAX);
        assert_eq!(n.getint(), i32::MAX);

        let n = ScriptNum::new(i64::MIN);
        assert_eq!(n.getint(), i32::MIN);
    }
}
