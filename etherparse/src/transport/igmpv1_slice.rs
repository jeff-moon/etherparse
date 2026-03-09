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
    /// if the given slice is too small (smaller than [`Igmpv1Header::LEN`]).
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
        Ok(Igmpv1Slice { slice })
    }

    /// Decode the header values into an [`Igmpv1Header`] struct.
    #[inline]
    pub fn header(&self) -> Igmpv1Header {
        Igmpv1Header {
            igmp_type: self.igmp_type(),
            reserved: self.reserved(),
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

    /// Returns the IGMP message type value.
    #[inline]
    pub fn igmp_type(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the reserved byte value.
    #[inline]
    pub fn reserved(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the checksum value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the group address.
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

    /// Returns a slice to the bytes not covered by `.header()`.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv1Header::LEN (8).
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(Igmpv1Header::LEN),
                self.slice.len() - Igmpv1Header::LEN,
            )
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
    use crate::err::{Layer, LenError};
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn from_slice() {
        // normal case
        {
            let bytes = [0u8; 8];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        // with trailing data
        {
            let bytes = [1u8; 12];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes[..]);
        }

        // too small error
        for bad_len in 0..Igmpv1Header::LEN {
            let bytes = [0u8; 8];
            assert_eq!(
                Igmpv1Slice::from_slice(&bytes[..bad_len]).unwrap_err(),
                LenError {
                    required_len: Igmpv1Header::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: Layer::Igmpv1,
                    layer_start_offset: 0,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn header(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            let bytes = input.to_bytes();
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(input, slice.header());
        }
    }

    proptest! {
        #[test]
        fn header_len(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                Igmpv1Header::LEN,
                Igmpv1Slice::from_slice(&bytes).unwrap().header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn igmp_type(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                bytes[0],
                Igmpv1Slice::from_slice(&bytes).unwrap().igmp_type(),
            );
        }
    }

    proptest! {
        #[test]
        fn reserved(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                bytes[1],
                Igmpv1Slice::from_slice(&bytes).unwrap().reserved(),
            );
        }
    }

    proptest! {
        #[test]
        fn checksum(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]),
                Igmpv1Slice::from_slice(&bytes).unwrap().checksum(),
            );
        }
    }

    proptest! {
        #[test]
        fn group_address(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                [bytes[4], bytes[5], bytes[6], bytes[7]],
                Igmpv1Slice::from_slice(&bytes).unwrap().group_address(),
            );
        }
    }

    proptest! {
        #[test]
        fn payload(
            header_bytes in any::<[u8; 8]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let mut bytes = Vec::with_capacity(8 + payload.len());
            bytes.extend_from_slice(&header_bytes);
            bytes.extend_from_slice(&payload);

            assert_eq!(
                &payload[..],
                Igmpv1Slice::from_slice(&bytes).unwrap().payload(),
            );
        }
    }

    proptest! {
        #[test]
        fn slice(bytes in proptest::collection::vec(any::<u8>(), 8..24)) {
            assert_eq!(
                &bytes[..],
                Igmpv1Slice::from_slice(&bytes).unwrap().slice(),
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(bytes in any::<[u8; 8]>()) {
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(bytes in any::<[u8; 8]>()) {
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("Igmpv1Slice {{ slice: {:?} }}", &bytes[..])
            );
        }
    }
}
