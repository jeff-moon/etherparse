use crate::*;

/// A slice containing an IGMPv1 packet.
///
/// Struct allows the selective read of fields in the IGMPv1
/// packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Igmpv1Slice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Igmpv1Slice<'a> {
    /// Creates a slice containing an IGMPv1 packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`]
    /// if the given slice is too small (less than 8 bytes).
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Igmpv1Slice<'a>, err::LenError> {
        if slice.len() < Igmpv1Header::LEN {
            return Err(err::LenError {
                required_len: Igmpv1Header::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv1,
                layer_start_offset: 0,
            });
        }

        Ok(Igmpv1Slice {
            slice: &slice[..Igmpv1Header::LEN],
        })
    }

    /// Decode the header values into an [`Igmpv1Header`] struct.
    #[inline]
    pub fn header(&self) -> Igmpv1Header {
        Igmpv1Header {
            version_type: self.igmpv1_type(),
            checksum: self.checksum(),
            group_address: self.group_address(),
        }
    }

    /// Number of bytes/octets that will be converted into an
    /// [`Igmpv1Header`] when [`Igmpv1Slice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        Igmpv1Header::LEN
    }

    /// Decode the version/type from the slice.
    #[inline]
    pub fn igmpv1_type(&self) -> Igmpv1Type {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        let type_u8 = unsafe { *self.slice.get_unchecked(0) };
        Igmpv1Type::from_u8(type_u8).unwrap_or(Igmpv1Type::MembershipQuery)
    }

    /// Returns the raw "type" value in the IGMPv1 header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the "checksum" value in the IGMPv1 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the "group address" value in the IGMPv1 header.
    #[inline]
    pub fn group_address(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns the slice containing the IGMPv1 packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn from_slice() {
        // normal case
        {
            let bytes = [0x11u8, 0, 0, 0, 224, 0, 0, 1];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        // with extra bytes (only first 8 used)
        {
            let bytes = [0x11u8, 0, 0, 0, 224, 0, 0, 1, 0xff, 0xff];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes[..8]);
        }

        // smaller than min size error
        for bad_len in 0..8 {
            let bytes = [0x11u8, 0, 0, 0, 224, 0, 0, 1];
            assert_eq!(
                Igmpv1Slice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: Igmpv1Header::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Igmpv1,
                    layer_start_offset: 0,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn header(
            type_u8 in prop_oneof![Just(0x11u8), Just(0x12u8)],
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let bytes = [
                type_u8, 0,
                checksum_be[0], checksum_be[1],
                group_address[0], group_address[1], group_address[2], group_address[3],
            ];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            let header = slice.header();
            assert_eq!(header.version_type, Igmpv1Type::from_u8(type_u8).unwrap());
            assert_eq!(header.checksum, checksum);
            assert_eq!(header.group_address, group_address);
        }
    }

    #[test]
    fn header_len() {
        let bytes = [0x11u8, 0, 0, 0, 0, 0, 0, 0];
        let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
        assert_eq!(slice.header_len(), 8);
    }

    proptest! {
        #[test]
        fn type_u8(type_val in any::<u8>()) {
            let mut bytes = [0u8; 8];
            bytes[0] = type_val;
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(type_val, slice.type_u8());
        }
    }

    proptest! {
        #[test]
        fn checksum(checksum_val in any::<u16>()) {
            let checksum_be = checksum_val.to_be_bytes();
            let bytes = [0x11, 0, checksum_be[0], checksum_be[1], 0, 0, 0, 0];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(checksum_val, slice.checksum());
        }
    }

    proptest! {
        #[test]
        fn group_address(group in any::<[u8; 4]>()) {
            let bytes = [0x11, 0, 0, 0, group[0], group[1], group[2], group[3]];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(group, slice.group_address());
        }
    }

    proptest! {
        #[test]
        fn slice_method(
            type_u8 in prop_oneof![Just(0x11u8), Just(0x12u8)],
            rest in any::<[u8; 7]>(),
        ) {
            let mut bytes = [0u8; 8];
            bytes[0] = type_u8;
            bytes[1..].copy_from_slice(&rest);
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes[..]);
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            type_u8 in prop_oneof![Just(0x11u8), Just(0x12u8)],
            rest in any::<[u8; 7]>(),
        ) {
            let mut bytes = [0u8; 8];
            bytes[0] = type_u8;
            bytes[1..].copy_from_slice(&rest);
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    #[test]
    fn debug() {
        let bytes = [0x11u8, 0, 0, 0, 0, 0, 0, 0];
        let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
        assert_eq!(
            format!("{:?}", slice),
            format!("Igmpv1Slice {{ slice: {:?} }}", &bytes[..])
        );
    }
}
