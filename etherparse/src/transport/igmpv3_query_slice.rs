use crate::*;

/// A slice containing an IGMPv3 Membership Query packet.
///
/// Provides zero-copy access to the 12-byte fixed header fields
/// and the variable-length source address list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Igmpv3QuerySlice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Igmpv3QuerySlice<'a> {
    /// Creates a slice containing an IGMPv3 Membership Query packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`]
    /// if the given slice is too small (smaller than [`Igmpv3QueryHeader::LEN`]).
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Igmpv3QuerySlice<'a>, err::LenError> {
        if slice.len() < Igmpv3QueryHeader::LEN {
            return Err(err::LenError {
                required_len: Igmpv3QueryHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }
        Ok(Igmpv3QuerySlice { slice })
    }

    /// Decode the header values into an [`Igmpv3QueryHeader`] struct.
    #[inline]
    pub fn header(&self) -> Igmpv3QueryHeader {
        Igmpv3QueryHeader {
            igmp_type: self.igmp_type(),
            max_resp_code: self.max_resp_code(),
            checksum: self.checksum(),
            group_address: self.group_address(),
            flags: self.flags(),
            qqic: self.qqic(),
            number_of_sources: self.number_of_sources(),
        }
    }

    /// Number of bytes/octets that will be converted into an
    /// [`Igmpv3QueryHeader`] when [`Igmpv3QuerySlice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        Igmpv3QueryHeader::LEN
    }

    /// Returns the IGMP message type value.
    #[inline]
    pub fn igmp_type(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the Max Response Code value.
    #[inline]
    pub fn max_resp_code(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the checksum value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the group address.
    #[inline]
    pub fn group_address(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns the flags byte (contains S flag and QRV).
    #[inline]
    pub fn flags(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { *self.slice.get_unchecked(8) }
    }

    /// Returns the Suppress Router-Side Processing flag (S bit).
    #[inline]
    pub fn suppress(&self) -> bool {
        (self.flags() & 0x08) != 0
    }

    /// Returns the Querier's Robustness Variable (QRV, lower 3 bits of flags).
    #[inline]
    pub fn qrv(&self) -> u8 {
        self.flags() & 0x07
    }

    /// Returns the Querier's Query Interval Code.
    #[inline]
    pub fn qqic(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { *self.slice.get_unchecked(9) }
    }

    /// Returns the number of sources field.
    #[inline]
    pub fn number_of_sources(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(10)) }
    }

    /// Returns a slice to the bytes not covered by `.header()`
    /// (the source address list and any trailing data).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3QueryHeader::LEN (12).
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(Igmpv3QueryHeader::LEN),
                self.slice.len() - Igmpv3QueryHeader::LEN,
            )
        }
    }

    /// Returns the slice containing the IGMPv3 query packet.
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
            let bytes = [0u8; 12];
            let slice = Igmpv3QuerySlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        // with trailing data
        {
            let bytes = [1u8; 20];
            let slice = Igmpv3QuerySlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes[..]);
        }

        // too small error
        for bad_len in 0..Igmpv3QueryHeader::LEN {
            let bytes = [0u8; 12];
            assert_eq!(
                Igmpv3QuerySlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                LenError {
                    required_len: Igmpv3QueryHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: Layer::Igmpv3,
                    layer_start_offset: 0,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn header(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            let bytes = input.to_bytes();
            let slice = Igmpv3QuerySlice::from_slice(&bytes).unwrap();
            assert_eq!(input, slice.header());
        }
    }

    proptest! {
        #[test]
        fn header_len(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                Igmpv3QueryHeader::LEN,
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn igmp_type(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                bytes[0],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().igmp_type(),
            );
        }
    }

    proptest! {
        #[test]
        fn max_resp_code(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                bytes[1],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().max_resp_code(),
            );
        }
    }

    proptest! {
        #[test]
        fn checksum(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]),
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().checksum(),
            );
        }
    }

    proptest! {
        #[test]
        fn group_address(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                [bytes[4], bytes[5], bytes[6], bytes[7]],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().group_address(),
            );
        }
    }

    proptest! {
        #[test]
        fn flags(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                bytes[8],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().flags(),
            );
        }
    }

    #[test]
    fn suppress() {
        let mut bytes = [0u8; 12];

        bytes[8] = 0x00;
        assert!(!Igmpv3QuerySlice::from_slice(&bytes).unwrap().suppress());

        bytes[8] = 0x08;
        assert!(Igmpv3QuerySlice::from_slice(&bytes).unwrap().suppress());

        bytes[8] = 0x0F;
        assert!(Igmpv3QuerySlice::from_slice(&bytes).unwrap().suppress());

        bytes[8] = 0xF7;
        assert!(!Igmpv3QuerySlice::from_slice(&bytes).unwrap().suppress());
    }

    #[test]
    fn qrv() {
        let mut bytes = [0u8; 12];

        bytes[8] = 0x00;
        assert_eq!(0, Igmpv3QuerySlice::from_slice(&bytes).unwrap().qrv());

        bytes[8] = 0x07;
        assert_eq!(7, Igmpv3QuerySlice::from_slice(&bytes).unwrap().qrv());

        bytes[8] = 0x03;
        assert_eq!(3, Igmpv3QuerySlice::from_slice(&bytes).unwrap().qrv());

        bytes[8] = 0xF8;
        assert_eq!(0, Igmpv3QuerySlice::from_slice(&bytes).unwrap().qrv());
    }

    proptest! {
        #[test]
        fn qqic(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                bytes[9],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().qqic(),
            );
        }
    }

    proptest! {
        #[test]
        fn number_of_sources(bytes in any::<[u8; 12]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[10], bytes[11]]),
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().number_of_sources(),
            );
        }
    }

    proptest! {
        #[test]
        fn payload(
            header_bytes in any::<[u8; 12]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let mut bytes = Vec::with_capacity(12 + payload.len());
            bytes.extend_from_slice(&header_bytes);
            bytes.extend_from_slice(&payload);

            assert_eq!(
                &payload[..],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().payload(),
            );
        }
    }

    proptest! {
        #[test]
        fn slice(bytes in proptest::collection::vec(any::<u8>(), 12..32)) {
            assert_eq!(
                &bytes[..],
                Igmpv3QuerySlice::from_slice(&bytes).unwrap().slice(),
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(bytes in any::<[u8; 12]>()) {
            let slice = Igmpv3QuerySlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(bytes in any::<[u8; 12]>()) {
            let slice = Igmpv3QuerySlice::from_slice(&bytes).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("Igmpv3QuerySlice {{ slice: {:?} }}", &bytes[..])
            );
        }
    }
}
