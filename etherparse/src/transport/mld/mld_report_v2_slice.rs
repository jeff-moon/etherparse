use crate::{mld::*, *};

/// Zero-copy slice of an MLDv2 "Multicast Listener Report" (ICMPv6 type
/// `143`) including the list of multicast address records.
///
/// Defined in
/// [RFC 3810 section 5.2](https://datatracker.ietf.org/doc/html/rfc3810#section-5.2).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 143   |    Reserved   |           Checksum            |  | part of header &
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
/// |           Reserved            |Nr of Mcast Address Records (M)|  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .               Multicast Address Record [1]                    .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                               .                               |  | part of payload
/// .                               .                               .  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .               Multicast Address Record [M]                    .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldReportV2Slice<'a> {
    slice: &'a [u8],
}

impl<'a> MldReportV2Slice<'a> {
    /// Creates a slice from bytes without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` is at least
    /// [`MldReportV2Header::LEN`] (8) bytes long.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &'a [u8]) -> MldReportV2Slice<'a> {
        debug_assert!(slice.len() >= MldReportV2Header::LEN);
        MldReportV2Slice { slice }
    }

    /// Returns the ICMPv6 "code" byte value (sent as zero, ignored by
    /// receivers).
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the "checksum" value stored in the ICMPv6 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// The reserved bytes 4-5 of the report header.
    #[inline]
    pub fn reserved(&self) -> [u8; 2] {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe { [*self.slice.get_unchecked(4), *self.slice.get_unchecked(5)] }
    }

    /// Number of multicast address records declared in the report header.
    #[inline]
    pub fn num_of_records(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(6)) }
    }

    /// Decodes the fixed fields into an owned [`MldReportV2Header`].
    #[inline]
    pub fn to_header(&self) -> MldReportV2Header {
        MldReportV2Header {
            reserved: self.reserved(),
            num_of_records: self.num_of_records(),
        }
    }

    /// Returns an iterator over the multicast address records.
    ///
    /// The iterator yields at most [`MldReportV2Slice::num_of_records`]
    /// items and stops early with an [`err::LenError`] if the payload is
    /// shorter than the records claim.
    #[inline]
    pub fn multicast_address_records(&self) -> MulticastAddressRecordSliceIter<'a> {
        MulticastAddressRecordSliceIter::new(self.payload(), self.num_of_records())
    }

    /// Returns the bytes after the 8-byte header (the multicast address
    /// records).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(MldReportV2Header::LEN),
                self.slice.len() - MldReportV2Header::LEN,
            )
        }
    }

    /// Returns the slice containing the entire MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
