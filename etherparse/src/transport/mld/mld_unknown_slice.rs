use crate::{mld::*, *};

/// Zero-copy slice of an MLD message with a type unknown to etherparse.
///
/// See [`MldUnknownHeader`] for the field layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldUnknownSlice<'a> {
    slice: &'a [u8],
}

impl<'a> MldUnknownSlice<'a> {
    /// Creates a slice from bytes without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` is at least
    /// [`MldUnknownHeader::LEN`] (8) bytes long.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &'a [u8]) -> MldUnknownSlice<'a> {
        debug_assert!(slice.len() >= MldUnknownHeader::LEN);
        MldUnknownSlice { slice }
    }

    /// Returns the ICMPv6 "type" byte value of the message.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the ICMPv6 "code" byte value of the message.
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

    /// Returns the raw byte values after the checksum (bytes 4-7).
    #[inline]
    pub fn raw_bytes_4_7(&self) -> [u8; 4] {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Decodes the fixed fields into an owned [`MldUnknownHeader`].
    #[inline]
    pub fn to_header(&self) -> MldUnknownHeader {
        MldUnknownHeader {
            mld_type: self.type_u8(),
            code: self.code_u8(),
            raw_bytes_4_7: self.raw_bytes_4_7(),
        }
    }

    /// Returns the bytes after the 8-byte header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 8 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(MldUnknownHeader::LEN),
                self.slice.len() - MldUnknownHeader::LEN,
            )
        }
    }

    /// Returns the slice containing the entire MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
