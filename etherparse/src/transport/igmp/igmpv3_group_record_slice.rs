use crate::igmp::*;
use crate::*;

/// A zero-copy slice of a single IGMPv3 group record.
///
/// Provides access to the 8-byte fixed header fields, the
/// source address list, and the auxiliary data without copying.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Igmpv3GroupRecordSlice<'a> {
    /// The full record bytes (header + sources + aux data).
    slice: &'a [u8],
}

impl<'a> Igmpv3GroupRecordSlice<'a> {
    /// Creates a group record slice from raw bytes.
    ///
    /// Validates that the slice is at least [`Igmpv3GroupRecordHeader::LEN`]
    /// bytes and that it contains enough data for the declared source
    /// addresses and auxiliary data.
    ///
    /// # Errors
    ///
    /// Returns an [`err::LenError`] if the slice is too short.
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<(Igmpv3GroupRecordSlice<'a>, &'a [u8]), err::LenError> {
        if slice.len() < Igmpv3GroupRecordHeader::LEN {
            return Err(err::LenError {
                required_len: Igmpv3GroupRecordHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }

        let number_of_sources = u16::from_be_bytes([slice[2], slice[3]]);
        let aux_data_len = slice[1];
        let record_len = Igmpv3GroupRecordHeader::LEN
            + usize::from(number_of_sources) * 4
            + usize::from(aux_data_len) * 4;

        if slice.len() < record_len {
            return Err(err::LenError {
                required_len: record_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }

        Ok((
            Igmpv3GroupRecordSlice {
                slice: &slice[..record_len],
            },
            &slice[record_len..],
        ))
    }

    /// Decode the fixed header into an [`Igmpv3GroupRecordHeader`] struct.
    #[inline]
    pub fn header(&self) -> Igmpv3GroupRecordHeader {
        Igmpv3GroupRecordHeader {
            record_type: self.record_type(),
            aux_data_len: self.aux_data_len(),
            number_of_sources: self.number_of_sources(),
            multicast_address: self.multicast_address(),
        }
    }

    /// Returns the group record type.
    #[inline]
    pub fn record_type(&self) -> u8 {
        // SAFETY:
        // Safe as from_slice checks that the slice has at least
        // Igmpv3GroupRecordHeader::LEN (8) bytes.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the auxiliary data length in units of 32-bit words.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        // SAFETY:
        // Safe as from_slice checks that the slice has at least
        // Igmpv3GroupRecordHeader::LEN (8) bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the number of source addresses.
    #[inline]
    pub fn number_of_sources(&self) -> u16 {
        // SAFETY:
        // Safe as from_slice checks that the slice has at least
        // Igmpv3GroupRecordHeader::LEN (8) bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the multicast address.
    #[inline]
    pub fn multicast_address(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as from_slice checks that the slice has at least
        // Igmpv3GroupRecordHeader::LEN (8) bytes.
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `number_of_sources * 4` bytes.
    /// Each 4 consecutive bytes are one IPv4 source address.
    #[inline]
    pub fn source_addrs(&self) -> &'a [u8] {
        let start = Igmpv3GroupRecordHeader::LEN;
        let len = usize::from(self.number_of_sources()) * 4;
        // SAFETY:
        // Safe as from_slice validates that the slice is large enough
        // for the header + sources + aux data.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the auxiliary data bytes.
    #[inline]
    pub fn aux_data(&self) -> &'a [u8] {
        let start = Igmpv3GroupRecordHeader::LEN + usize::from(self.number_of_sources()) * 4;
        let len = usize::from(self.aux_data_len()) * 4;
        // SAFETY:
        // Safe as from_slice validates that the slice is large enough
        // for the header + sources + aux data.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the full slice of this group record.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

/// An iterator over IGMPv3 group record slices in a report payload.
#[derive(Clone, Debug)]
pub struct Igmpv3GroupRecordSliceIterator<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> Igmpv3GroupRecordSliceIterator<'a> {
    /// Creates a new iterator over `count` group records starting
    /// at the beginning of `slice`.
    #[inline]
    pub(crate) fn new(slice: &'a [u8], count: u16) -> Igmpv3GroupRecordSliceIterator<'a> {
        Igmpv3GroupRecordSliceIterator {
            remaining: slice,
            count,
        }
    }
}

impl<'a> Iterator for Igmpv3GroupRecordSliceIterator<'a> {
    type Item = Result<Igmpv3GroupRecordSlice<'a>, err::LenError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match Igmpv3GroupRecordSlice::from_slice(self.remaining) {
            Ok((record, rest)) => {
                self.remaining = rest;
                Some(Ok(record))
            }
            Err(e) => {
                // Stop iteration on error.
                self.count = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(usize::from(self.count)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::{Layer, LenError};
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn from_slice_no_sources() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xEE]);

        let (slice, rest) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
        assert_eq!(rec, slice.header());
        assert_eq!(&[0xEE], rest);
        assert_eq!(rec.to_bytes().as_slice(), slice.slice());
    }

    #[test]
    fn from_slice_with_sources() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 2, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[10, 0, 0, 2]);
        bytes.extend_from_slice(&[0xFF]); // trailing

        let (slice, rest) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
        assert_eq!(rec, slice.header());
        assert_eq!(&[10, 0, 0, 1, 10, 0, 0, 2], slice.source_addrs());
        assert_eq!(0, slice.aux_data().len());
        assert_eq!(&[0xFF], rest);
    }

    #[test]
    fn from_slice_with_aux_data() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 1, 1, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        bytes.extend_from_slice(&[10, 0, 0, 1]); // 1 source
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 1 word aux data

        let (slice, rest) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
        assert_eq!(rec, slice.header());
        assert_eq!(&[10, 0, 0, 1], slice.source_addrs());
        assert_eq!(&[0xAA, 0xBB, 0xCC, 0xDD], slice.aux_data());
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_too_short_header() {
        for bad_len in 0..Igmpv3GroupRecordHeader::LEN {
            let bytes = vec![0u8; bad_len];
            assert_eq!(
                Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap_err(),
                LenError {
                    required_len: Igmpv3GroupRecordHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: Layer::Igmpv3,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_too_short_sources() {
        // 2 sources declared but only 1 provided
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 2, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        bytes.extend_from_slice(&[10, 0, 0, 1]); // only 4 bytes, need 8

        assert_eq!(
            Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap_err(),
            LenError {
                required_len: 8 + 8, // header + 2 sources
                len: 12,
                len_source: LenSource::Slice,
                layer: Layer::Igmpv3,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn from_slice_too_short_aux_data() {
        // 1 word aux data declared but not provided
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 1, 0, [224, 0, 0, 1]);
        let bytes = rec.to_bytes();

        assert_eq!(
            Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap_err(),
            LenError {
                required_len: 8 + 4, // header + 1 word aux
                len: 8,
                len_source: LenSource::Slice,
                layer: Layer::Igmpv3,
                layer_start_offset: 0,
            }
        );
    }

    proptest! {
        #[test]
        fn field_accessors(
            record_type in any::<u8>(),
            aux_data_len in 0u8..4,
            number_of_sources in 0u16..4,
            multicast_address in any::<[u8; 4]>(),
            source_bytes in proptest::collection::vec(any::<u8>(), 16..32),
        ) {
            let rec = Igmpv3GroupRecordHeader::new(
                record_type, aux_data_len, number_of_sources, multicast_address,
            );
            let sources_len = usize::from(number_of_sources) * 4;
            let aux_len = usize::from(aux_data_len) * 4;
            let total_var = sources_len + aux_len;

            // Ensure we have enough filler bytes.
            if source_bytes.len() >= total_var {
                let mut bytes = rec.to_bytes().to_vec();
                bytes.extend_from_slice(&source_bytes[..total_var]);

                let (slice, _) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
                assert_eq!(record_type, slice.record_type());
                assert_eq!(aux_data_len, slice.aux_data_len());
                assert_eq!(number_of_sources, slice.number_of_sources());
                assert_eq!(multicast_address, slice.multicast_address());
                assert_eq!(&source_bytes[..sources_len], slice.source_addrs());
                assert_eq!(&source_bytes[sources_len..total_var], slice.aux_data());
            }
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            multicast_address in any::<[u8; 4]>(),
        ) {
            let rec = Igmpv3GroupRecordHeader::new(1, 0, 0, multicast_address);
            let bytes = rec.to_bytes();
            let (slice, _) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    #[test]
    fn debug() {
        let rec = Igmpv3GroupRecordHeader::new(1, 0, 0, [224, 0, 0, 1]);
        let bytes = rec.to_bytes();
        let (slice, _) = Igmpv3GroupRecordSlice::from_slice(&bytes).unwrap();
        let dbg = format!("{:?}", slice);
        assert!(dbg.starts_with("Igmpv3GroupRecordSlice"));
    }

    // Iterator tests

    #[test]
    fn iterator_empty() {
        let iter = Igmpv3GroupRecordSliceIterator::new(&[], 0);
        assert_eq!(0, iter.count());
    }

    #[test]
    fn iterator_single() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let bytes = rec.to_bytes();

        let mut iter = Igmpv3GroupRecordSliceIterator::new(&bytes, 1);
        let record = iter.next().unwrap().unwrap();
        assert_eq!(rec, record.header());
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_multiple() {
        let rec1 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 1, [224, 0, 0, 1]);
        let rec2 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 0, [224, 0, 0, 2]);

        let mut bytes = rec1.to_bytes().to_vec();
        bytes.extend_from_slice(&[10, 0, 0, 1]); // 1 source for rec1
        bytes.extend_from_slice(&rec2.to_bytes());

        let records: Vec<_> = Igmpv3GroupRecordSliceIterator::new(&bytes, 2)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(2, records.len());
        assert_eq!(rec1, records[0].header());
        assert_eq!(rec2, records[1].header());
    }

    #[test]
    fn iterator_error_stops() {
        // Declare 2 records but only provide 1
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let bytes = rec.to_bytes();

        let mut iter = Igmpv3GroupRecordSliceIterator::new(&bytes, 2);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_size_hint() {
        let rec = Igmpv3GroupRecordHeader::new(1, 0, 0, [224, 0, 0, 1]);
        let bytes = rec.to_bytes();
        let iter = Igmpv3GroupRecordSliceIterator::new(&bytes, 1);
        assert_eq!((0, Some(1)), iter.size_hint());
    }
}
