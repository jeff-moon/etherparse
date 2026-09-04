/// Maximum response code of an MLDv2 "Multicast Listener Query"
/// (specifies the maximum time allowed before sending a responding
/// report).
///
/// The actual time allowed, called the Maximum Response Delay, is
/// represented in units of milliseconds and is derived from the Maximum
/// Response Code as follows (see
/// [RFC 3810 section 5.1.3](https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.3)):
///
/// If Maximum Response Code < 32768, Maximum Response Delay = Maximum
/// Response Code.
///
/// If Maximum Response Code >= 32768, Maximum Response Code represents a
/// floating-point value as follows:
///
/// ```text
///  0 1 2 3 4 5 6 7 8 9 A B C D E F
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1| exp |          mant         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Maximum Response Delay = (mant | 0x1000) << (exp + 3)
///
/// Note that this differs from the IGMPv3
/// [`crate::igmp::MaxResponseCode`] which is an 8 bit value in units of
/// 1/10 second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MldMaxResponseCode(pub u16);

impl MldMaxResponseCode {
    /// Mask of the "exp" part in the exponential range.
    pub const MASK_EXP: u16 = 0b0111_0000_0000_0000;

    /// Mask of the "mant" part in the exponential range.
    pub const MASK_MANT: u16 = 0b0000_1111_1111_1111;

    /// Returns the maximum response delay in milliseconds (converts the
    /// raw value).
    ///
    /// An `u32` is returned as values in the exponential range can
    /// exceed what is representable in an `u16`.
    pub fn as_millis(&self) -> u32 {
        if 0 != self.0 & 0b1000_0000_0000_0000 {
            let mant = u32::from(self.0 & Self::MASK_MANT);
            let exp = u32::from((self.0 & Self::MASK_EXP) >> 12);
            (mant | 0x1000) << (exp + 3)
        } else {
            u32::from(self.0)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn debug() {
        assert_eq!(
            format!("{:?}", MldMaxResponseCode(1234)),
            "MldMaxResponseCode(1234)"
        );
    }

    #[test]
    fn as_millis_examples() {
        // linear range
        assert_eq!(MldMaxResponseCode(0).as_millis(), 0);
        assert_eq!(MldMaxResponseCode(1000).as_millis(), 1000);
        assert_eq!(MldMaxResponseCode(32767).as_millis(), 32767);

        // exponential range, smallest value (exp = 0, mant = 0)
        assert_eq!(MldMaxResponseCode(0x8000).as_millis(), 0x1000 << 3);

        // exponential range, largest value (exp = 7, mant = 0xFFF)
        assert_eq!(
            MldMaxResponseCode(0xFFFF).as_millis(),
            (0xFFFu32 | 0x1000) << 10
        );
    }

    #[test]
    fn as_millis_can_exceed_u16() {
        // guards against a regression to an u16 return type
        assert!(MldMaxResponseCode(0xFFFF).as_millis() > u32::from(u16::MAX));
    }

    proptest! {
        #[test]
        fn as_millis_linear_range(raw in 0u16..=32767u16) {
            prop_assert_eq!(MldMaxResponseCode(raw).as_millis(), u32::from(raw));
        }

        #[test]
        fn as_millis_exponential_range(mant in 0u16..=0b1111_1111_1111u16, exp in 0u16..=0b111u16) {
            let raw = 0b1000_0000_0000_0000 | (exp << 12) | mant;
            let expected = (u32::from(mant) | 0x1000) << (u32::from(exp) + 3);
            prop_assert_eq!(MldMaxResponseCode(raw).as_millis(), expected);
        }
    }
}
