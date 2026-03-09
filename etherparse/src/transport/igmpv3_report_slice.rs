use crate::igmp::*;
use crate::*;

/// A slice containing an IGMPv3 Membership Report packet.
///
/// Provides zero-copy access to the 8-byte fixed header fields
/// and an iterator over the variable-length group records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Igmpv3ReportSlice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Igmpv3ReportSlice<'a> {
    /// Creates a slice containing an IGMPv3 Membership Report packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`]
    /// if the given slice is too small (smaller than [`Igmpv3ReportHeader::LEN`]).
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Igmpv3ReportSlice<'a>, err::LenError> {
        if slice.len() < Igmpv3ReportHeader::LEN {
            return Err(err::LenError {
                required_len: Igmpv3ReportHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }
        Ok(Igmpv3ReportSlice { slice })
    }

    /// Number of bytes/octets of the fixed header.
    #[inline]
    pub fn header_len(&self) -> usize {
        Igmpv3ReportHeader::LEN
    }

    /// Returns the IGMP message type value.
    #[inline]
    pub fn igmp_type(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the reserved byte (byte 1).
    #[inline]
    pub fn reserved0(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the checksum value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the reserved field (bytes 4-5).
    #[inline]
    pub fn reserved1(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// Returns the number of group records field.
    #[inline]
    pub fn number_of_group_records(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(6)) }
    }

    /// Returns an iterator over the group records in this report.
    ///
    /// Each call to `next()` returns a `Result<Igmpv3GroupRecordSlice, err::LenError>`.
    /// Iteration stops after `number_of_group_records()` records or on the
    /// first error.
    #[inline]
    pub fn group_record_slices(&self) -> Igmpv3GroupRecordSliceIterator<'a> {
        Igmpv3GroupRecordSliceIterator::new(self.payload(), self.number_of_group_records())
    }

    /// Returns a slice to the bytes not covered by the fixed header
    /// (the group record data and any trailing bytes).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of Igmpv3ReportHeader::LEN (8).
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(Igmpv3ReportHeader::LEN),
                self.slice.len() - Igmpv3ReportHeader::LEN,
            )
        }
    }

    /// Returns the slice containing the IGMPv3 report packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::{Layer, LenError};
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn from_slice() {
        // normal case
        {
            let bytes = [0u8; 8];
            let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        // with trailing data
        {
            let bytes = [1u8; 16];
            let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes[..]);
        }

        // too small error
        for bad_len in 0..Igmpv3ReportHeader::LEN {
            let bytes = [0u8; 8];
            assert_eq!(
                Igmpv3ReportSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                LenError {
                    required_len: Igmpv3ReportHeader::LEN,
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
        fn header_len(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                Igmpv3ReportHeader::LEN,
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn igmp_type(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                bytes[0],
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().igmp_type(),
            );
        }
    }

    proptest! {
        #[test]
        fn reserved0(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                bytes[1],
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().reserved0(),
            );
        }
    }

    proptest! {
        #[test]
        fn checksum(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]),
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().checksum(),
            );
        }
    }

    proptest! {
        #[test]
        fn reserved1(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[4], bytes[5]]),
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().reserved1(),
            );
        }
    }

    proptest! {
        #[test]
        fn number_of_group_records(bytes in any::<[u8; 8]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[6], bytes[7]]),
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().number_of_group_records(),
            );
        }
    }

    #[test]
    fn group_record_slices_empty() {
        // 0 group records
        let bytes = [0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
        assert_eq!(0, slice.group_record_slices().count());
    }

    #[test]
    fn group_record_slices_single() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let mut bytes = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        bytes.extend_from_slice(&rec.to_bytes());

        let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
        let records: Vec<_> = slice
            .group_record_slices()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(1, records.len());
        assert_eq!(rec, records[0].header());
    }

    #[test]
    fn group_record_slices_multiple_with_sources() {
        let rec1 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 1, [224, 0, 0, 1]);
        let rec2 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 0, [224, 0, 0, 2]);

        let mut bytes = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        bytes.extend_from_slice(&rec1.to_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 1]); // 1 source for rec1
        bytes.extend_from_slice(&rec2.to_bytes());

        let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
        let records: Vec<_> = slice
            .group_record_slices()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(2, records.len());
        assert_eq!(rec1, records[0].header());
        assert_eq!(&[10, 0, 0, 1], records[0].source_addrs());
        assert_eq!(rec2, records[1].header());
        assert!(records[1].source_addrs().is_empty());
    }

    #[test]
    fn group_record_slices_error_on_truncated() {
        // Declare 1 record with 2 sources but don't provide source bytes
        let mut bytes = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 2, [224, 0, 0, 1]);
        bytes.extend_from_slice(&rec.to_bytes());
        // No source bytes provided

        let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
        let results: Vec<_> = slice.group_record_slices().collect();
        assert_eq!(1, results.len());
        assert!(results[0].is_err());
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
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().payload(),
            );
        }
    }

    proptest! {
        #[test]
        fn slice(bytes in proptest::collection::vec(any::<u8>(), 8..24)) {
            assert_eq!(
                &bytes[..],
                Igmpv3ReportSlice::from_slice(&bytes).unwrap().slice(),
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(bytes in any::<[u8; 8]>()) {
            let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(bytes in any::<[u8; 8]>()) {
            let slice = Igmpv3ReportSlice::from_slice(&bytes).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("Igmpv3ReportSlice {{ slice: {:?} }}", &bytes[..])
            );
        }
    }
}
