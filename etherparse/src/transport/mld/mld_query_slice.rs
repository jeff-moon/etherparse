use crate::{mld::*, *};

/// Zero-copy slice of an MLDv1 "Multicast Listener Query" (ICMPv6 type
/// `130`, exactly 24 octets long).
///
/// Defined in
/// [RFC 2710 section 3](https://datatracker.ietf.org/doc/html/rfc2710#section-3).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 130   |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Maximum Response Delay    |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Multicast Address                       +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldQuerySlice<'a> {
    slice: &'a [u8],
}

impl<'a> MldQuerySlice<'a> {
    /// Creates a slice from bytes without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` is at least
    /// [`MldV1Header::LEN`] (24) bytes long.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &'a [u8]) -> MldQuerySlice<'a> {
        debug_assert!(slice.len() >= MldV1Header::LEN);
        MldQuerySlice { slice }
    }

    /// Returns the ICMPv6 "code" byte value (sent as zero, ignored by
    /// receivers).
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the "checksum" value stored in the ICMPv6 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// The maximum response delay in milliseconds.
    #[inline]
    pub fn max_response_delay(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// The reserved bytes 6-7 (sent as zero, ignored by receivers).
    #[inline]
    pub fn reserved(&self) -> [u8; 2] {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes.
        unsafe { [*self.slice.get_unchecked(6), *self.slice.get_unchecked(7)] }
    }

    /// The multicast address being queried.
    ///
    /// Set to zero for a "General Query", to a specific IPv6 multicast
    /// address for a "Multicast-Address-Specific Query".
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes, so
        // the 16 bytes starting at offset 8 are in bounds.
        MulticastAddress::new(unsafe {
            let mut octets = [0u8; 16];
            core::ptr::copy_nonoverlapping(self.slice.as_ptr().add(8), octets.as_mut_ptr(), 16);
            octets
        })
    }

    /// Decodes the fixed fields into an owned [`MldV1Header`].
    #[inline]
    pub fn to_header(&self) -> MldV1Header {
        MldV1Header {
            max_response_delay: self.max_response_delay(),
            multicast_address: self.multicast_address(),
        }
    }

    /// Returns the bytes after the 24-byte header (usually empty).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 24 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(MldV1Header::LEN),
                self.slice.len() - MldV1Header::LEN,
            )
        }
    }

    /// Returns the slice containing the entire MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
