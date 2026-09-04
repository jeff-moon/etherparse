use crate::{igmp::Qrv, mld::*, *};

/// Zero-copy slice of an MLDv2 "Multicast Listener Query" (ICMPv6 type
/// `130`, at least 28 octets long) including the source address list.
///
/// Defined in
/// [RFC 3810 section 5.1](https://datatracker.ietf.org/doc/html/rfc3810#section-5.1).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 130   |      Code     |           Checksum            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |    Maximum Response Code      |           Reserved            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  | part of header &
/// +                                                               +  | this type
/// |                                                               |  |
/// +                       Multicast Address                       +  |
/// |                                                               |  |
/// +                                                               +  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// +                                                               +  |
/// |                       Source Address [1]                      |  |
/// +                                                               +  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | part of payload
/// .                               .                               .  |
/// .                               .                               .  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// +                                                               +  |
/// |                       Source Address [N]                      |  |
/// +                                                               +  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldQueryWithSourcesSlice<'a> {
    slice: &'a [u8],
}

impl<'a> MldQueryWithSourcesSlice<'a> {
    /// Creates a slice from bytes without checking that they contain a
    /// valid MLDv2 query.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` contains the complete
    /// declared payload:
    ///
    /// * at least [`MldQueryWithSourcesHeader::LEN`] (28) bytes for the
    ///   header, and
    /// * additionally `num_of_sources * 16` bytes for the source address
    ///   list, where `num_of_sources` is the `u16` read from bytes 26..28
    ///   of the header.
    ///
    /// In other words `slice.len()` must be at least
    /// `28 + num_of_sources * 16` so that all source addresses accessed
    /// by [`MldQueryWithSourcesSlice::source_addrs_bytes`] are in bounds.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &'a [u8]) -> MldQueryWithSourcesSlice<'a> {
        debug_assert!(slice.len() >= MldQueryWithSourcesHeader::LEN);
        // The slice must also be long enough to hold all declared source
        // addresses (16 bytes each). `MldSlice::from_slice` guarantees this.
        debug_assert!(
            slice.len()
                >= MldQueryWithSourcesHeader::LEN
                    + usize::from(u16::from_be_bytes([slice[26], slice[27]])) * 16
        );
        MldQueryWithSourcesSlice { slice }
    }

    /// Returns the ICMPv6 "code" byte value (sent as zero, ignored by
    /// receivers).
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the "checksum" value stored in the ICMPv6 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// The Maximum Response Code field.
    #[inline]
    pub fn max_response_code(&self) -> MldMaxResponseCode {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        MldMaxResponseCode(unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) })
    }

    /// The reserved bytes 6-7 (sent as zero, ignored by receivers).
    #[inline]
    pub fn reserved(&self) -> [u8; 2] {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { [*self.slice.get_unchecked(6), *self.slice.get_unchecked(7)] }
    }

    /// The multicast address being queried.
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes, so
        // the 16 bytes starting at offset 8 are in bounds.
        MulticastAddress::new(unsafe {
            let mut octets = [0u8; 16];
            core::ptr::copy_nonoverlapping(self.slice.as_ptr().add(8), octets.as_mut_ptr(), 16);
            octets
        })
    }

    /// Raw byte containing "Resv", the "S" flag & "QRV".
    #[inline]
    pub fn raw_byte_24(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { *self.slice.get_unchecked(24) }
    }

    /// Extracts the "Resv" (reserved) field from the `raw_byte_24` field.
    #[inline]
    pub fn resv(&self) -> u8 {
        (self.raw_byte_24() & MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_RESV)
            >> MldQueryWithSourcesHeader::RAW_BYTE_24_OFFSET_RESV
    }

    /// Extracts the S flag (Suppress Router-Side Processing).
    #[inline]
    pub fn s_flag(&self) -> bool {
        0 != (self.raw_byte_24() & MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_S_FLAG)
    }

    /// Extracts the QRV (Querier's Robustness Variable).
    #[inline]
    pub fn qrv(&self) -> Qrv {
        // SAFETY: the value is guaranteed to be within range after the mask.
        unsafe {
            Qrv::new_unchecked(self.raw_byte_24() & MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_QRV)
        }
    }

    /// QQIC (Querier's Query Interval Code).
    #[inline]
    pub fn qqic(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { *self.slice.get_unchecked(25) }
    }

    /// Number of source addresses declared in the query header.
    #[inline]
    pub fn num_of_sources(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(26)) }
    }

    /// Decodes the fixed fields into an owned [`MldQueryWithSourcesHeader`].
    #[inline]
    pub fn to_header(&self) -> MldQueryWithSourcesHeader {
        MldQueryWithSourcesHeader {
            max_response_code: self.max_response_code(),
            multicast_address: self.multicast_address(),
            raw_byte_24: self.raw_byte_24(),
            qqic: self.qqic(),
            num_of_sources: self.num_of_sources(),
        }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `num_of_sources * 16` bytes (each 16
    /// consecutive bytes are one IPv6 source address).
    #[inline]
    pub fn source_addrs_bytes(&self) -> &'a [u8] {
        let payload = self.payload();
        let len = usize::from(self.num_of_sources()) * 16;
        // SAFETY: `MldSlice::from_slice` guarantees the payload contains
        // all declared source addresses (num_of_sources * 16 bytes).
        unsafe { core::slice::from_raw_parts(payload.as_ptr(), len) }
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

    /// Returns the bytes after the 28-byte header (the source address list).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 28 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(MldQueryWithSourcesHeader::LEN),
                self.slice.len() - MldQueryWithSourcesHeader::LEN,
            )
        }
    }

    /// Returns the slice containing the entire MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
