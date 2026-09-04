use crate::{mld::*, *};

/// A zero-copy slice of a single MLDv2 "Multicast Address Record".
///
/// Provides access to the 20-byte fixed header fields, the source
/// address list, and the auxiliary data without copying.
///
/// Defined in
/// [RFC 3810 section 5.2.4](https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.4).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       Multicast Address                       +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       Source Address [1]                      +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                               .                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       Source Address [N]                      +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                         Auxiliary Data                        .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulticastAddressRecordSlice<'a> {
    /// The full record bytes (header + sources + aux data).
    slice: &'a [u8],
}

impl<'a> MulticastAddressRecordSlice<'a> {
    /// Creates a multicast address record slice from raw bytes.
    ///
    /// Validates that the slice is at least
    /// [`MulticastAddressRecordHeader::LEN`] bytes and that it contains
    /// enough data for the declared source addresses and auxiliary data.
    ///
    /// Returns a tuple of the record slice and the remaining bytes after
    /// this record.
    ///
    /// # Errors
    ///
    /// Returns an [`err::LenError`] if the slice is too short.
    #[inline]
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<(MulticastAddressRecordSlice<'a>, &'a [u8]), err::LenError> {
        if slice.len() < MulticastAddressRecordHeader::LEN {
            return Err(err::LenError {
                required_len: MulticastAddressRecordHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        // SAFETY: Safe as the length was checked to be >= LEN (20).
        let num_of_sources =
            u16::from_be_bytes(unsafe { [*slice.get_unchecked(2), *slice.get_unchecked(3)] });
        let aux_data_len = unsafe { *slice.get_unchecked(1) };

        let record_len = MulticastAddressRecordHeader::LEN
            + usize::from(num_of_sources) * 16
            + usize::from(aux_data_len) * 4;

        if slice.len() < record_len {
            return Err(err::LenError {
                required_len: record_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        Ok((
            MulticastAddressRecordSlice {
                slice: &slice[..record_len],
            },
            &slice[record_len..],
        ))
    }

    /// Returns the multicast address record type.
    #[inline]
    pub fn record_type(&self) -> MulticastAddressRecordType {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        MulticastAddressRecordType(unsafe { *self.slice.get_unchecked(0) })
    }

    /// Returns the auxiliary data length in units of 32-bit words.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the number of source addresses.
    #[inline]
    pub fn num_of_sources(&self) -> u16 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the multicast address.
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // LEN (20) bytes, so the 16 bytes at offset 4 are in bounds.
        MulticastAddress::new(unsafe {
            let mut octets = [0u8; 16];
            core::ptr::copy_nonoverlapping(self.slice.as_ptr().add(4), octets.as_mut_ptr(), 16);
            octets
        })
    }

    /// Decodes the fixed header into a [`MulticastAddressRecordHeader`].
    #[inline]
    pub fn to_header(&self) -> MulticastAddressRecordHeader {
        MulticastAddressRecordHeader {
            record_type: self.record_type(),
            aux_data_len: self.aux_data_len(),
            num_of_sources: self.num_of_sources(),
            multicast_address: self.multicast_address(),
        }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `num_of_sources * 16` bytes. Each 16
    /// consecutive bytes represent one IPv6 source address.
    #[inline]
    pub fn source_addrs_bytes(&self) -> &'a [u8] {
        let start = MulticastAddressRecordHeader::LEN;
        let len = usize::from(self.num_of_sources()) * 16;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns an iterator over the source addresses as `[u8; 16]` arrays.
    #[inline]
    pub fn source_addresses(&self) -> impl ExactSizeIterator<Item = [u8; 16]> + 'a {
        self.source_addrs_bytes().chunks_exact(16).map(|c| {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(c);
            octets
        })
    }

    /// Returns the auxiliary data bytes.
    #[inline]
    pub fn aux_data(&self) -> &'a [u8] {
        let start = MulticastAddressRecordHeader::LEN + usize::from(self.num_of_sources()) * 16;
        let len = usize::from(self.aux_data_len()) * 4;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the full slice of this multicast address record.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

/// An iterator over MLDv2 multicast address record slices in a report
/// payload.
#[derive(Clone, Debug)]
pub struct MulticastAddressRecordSliceIter<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> MulticastAddressRecordSliceIter<'a> {
    /// Creates a new iterator over `count` multicast address records
    /// starting at the beginning of `slice`.
    #[inline]
    pub fn new(slice: &'a [u8], count: u16) -> MulticastAddressRecordSliceIter<'a> {
        MulticastAddressRecordSliceIter {
            remaining: slice,
            count,
        }
    }
}

impl<'a> Iterator for MulticastAddressRecordSliceIter<'a> {
    type Item = Result<MulticastAddressRecordSlice<'a>, err::LenError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match MulticastAddressRecordSlice::from_slice(self.remaining) {
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
    use alloc::{format, vec::Vec};

    /// Builds a multicast address record with the given sources & aux data.
    fn build_record(
        record_type: u8,
        multicast_address: [u8; 16],
        sources: &[[u8; 16]],
        aux_data_words: &[[u8; 4]],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(record_type);
        bytes.push(aux_data_words.len() as u8);
        bytes.extend_from_slice(&(sources.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&multicast_address);
        for source in sources {
            bytes.extend_from_slice(source);
        }
        for word in aux_data_words {
            bytes.extend_from_slice(word);
        }
        bytes
    }

    #[test]
    fn from_slice_too_small() {
        for bad_len in 0..MulticastAddressRecordHeader::LEN {
            let bytes = [0u8; MulticastAddressRecordHeader::LEN];
            assert_eq!(
                MulticastAddressRecordSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: MulticastAddressRecordHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_missing_sources() {
        // declares 2 sources but only provides 1
        let mut bytes = build_record(1, [0xff; 16], &[[1u8; 16]], &[]);
        bytes[2..4].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            MulticastAddressRecordSlice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: MulticastAddressRecordHeader::LEN + 2 * 16,
                len: bytes.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn from_slice_missing_aux_data() {
        // declares 2 aux data words but provides none
        let mut bytes = build_record(1, [0xff; 16], &[], &[]);
        bytes[1] = 2;
        assert_eq!(
            MulticastAddressRecordSlice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: MulticastAddressRecordHeader::LEN + 2 * 4,
                len: bytes.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn accessors_and_trailing_bytes() {
        let sources = [[1u8; 16], [2u8; 16]];
        let aux = [[0xAAu8, 0xBB, 0xCC, 0xDD]];
        let mut bytes = build_record(
            MulticastAddressRecordType::MODE_IS_EXCLUDE.0,
            [0xff; 16],
            &sources,
            &aux,
        );
        // trailing bytes must be returned as "rest"
        bytes.extend_from_slice(&[0x99, 0x88]);

        let (record, rest) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
        assert_eq!(rest, &[0x99, 0x88]);
        assert_eq!(
            record.record_type(),
            MulticastAddressRecordType::MODE_IS_EXCLUDE
        );
        assert_eq!(record.aux_data_len(), 1);
        assert_eq!(record.num_of_sources(), 2);
        assert_eq!(record.multicast_address().octets, [0xff; 16]);
        assert_eq!(record.source_addrs_bytes().len(), 32);
        assert_eq!(
            record.source_addresses().collect::<Vec<_>>(),
            alloc::vec![[1u8; 16], [2u8; 16]]
        );
        assert_eq!(record.aux_data(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(
            record.slice().len(),
            MulticastAddressRecordHeader::LEN + 32 + 4
        );

        // to_header
        assert_eq!(
            record.to_header(),
            MulticastAddressRecordHeader {
                record_type: MulticastAddressRecordType::MODE_IS_EXCLUDE,
                aux_data_len: 1,
                num_of_sources: 2,
                multicast_address: MulticastAddress::new([0xff; 16]),
            }
        );

        // clone & debug
        assert_eq!(record, record.clone());
        assert!(format!("{:?}", record).contains("MulticastAddressRecordSlice"));
    }

    #[test]
    fn iter_ok() {
        let a = build_record(1, [0xa; 16], &[[1u8; 16]], &[]);
        let b = build_record(2, [0xb; 16], &[], &[[9u8; 4]]);
        let mut bytes = a.clone();
        bytes.extend_from_slice(&b);

        let mut iter = MulticastAddressRecordSliceIter::new(&bytes, 2);
        assert_eq!(iter.size_hint(), (0, Some(2)));

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.multicast_address().octets, [0xa; 16]);
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.multicast_address().octets, [0xb; 16]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iter_stops_on_error() {
        // claims 2 records but only 1 is present
        let bytes = build_record(1, [0xa; 16], &[], &[]);
        let mut iter = MulticastAddressRecordSliceIter::new(&bytes, 2);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        // iteration must stop after the error
        assert!(iter.next().is_none());
    }

    #[test]
    fn iter_zero_count() {
        let bytes = build_record(1, [0xa; 16], &[], &[]);
        let mut iter = MulticastAddressRecordSliceIter::new(&bytes, 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iter_clone_debug() {
        let bytes = build_record(1, [0xa; 16], &[], &[]);
        let iter = MulticastAddressRecordSliceIter::new(&bytes, 1);
        let mut cloned = iter.clone();
        assert!(cloned.next().unwrap().is_ok());
        assert!(format!("{:?}", iter).contains("MulticastAddressRecordSliceIter"));
    }
}
