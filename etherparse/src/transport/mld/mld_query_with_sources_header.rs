use crate::mld::{MldMaxResponseCode, MulticastAddress};

/// MLDv2 "Multicast Listener Query" message header part (the fixed
/// fields preceding the source address list).
///
/// Note that the ICMPv6 "Type", "Code" & "Checksum" fields are not
/// stored in this type.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MldQueryWithSourcesHeader {
    /// The maximum response code.
    ///
    /// Use [`MldMaxResponseCode::as_millis`] to convert this into the
    /// maximum response delay in milliseconds.
    pub max_response_code: MldMaxResponseCode,

    /// The multicast address being queried.
    ///
    /// Set to zero for a "General Query", to a specific IPv6 multicast
    /// address for a "Multicast-Address-Specific Query" or a
    /// "Multicast-Address-and-Source-Specific Query".
    pub multicast_address: MulticastAddress,

    /// Raw byte containing the "Resv" field, the "S" flag & the "QRV".
    pub raw_byte_24: u8,

    /// QQIC (Querier's Query Interval Code).
    pub qqic: u8,

    /// The number of source addresses following the header.
    pub num_of_sources: u16,
}

impl MldQueryWithSourcesHeader {
    /// Number of bytes/octets an [`MldQueryWithSourcesHeader`] takes up
    /// in serialized form (including the ICMPv6 type, code & checksum).
    pub const LEN: usize = 28;

    /// Mask of the "Resv" (reserved) field in `raw_byte_24`.
    pub const RAW_BYTE_24_MASK_RESV: u8 = 0b1111_0000;

    /// Bit offset of the "Resv" (reserved) field in `raw_byte_24`.
    pub const RAW_BYTE_24_OFFSET_RESV: u8 = 4;

    /// Mask of the "S" flag (Suppress Router-Side Processing) in `raw_byte_24`.
    pub const RAW_BYTE_24_MASK_S_FLAG: u8 = 0b0000_1000;

    /// Mask of the "QRV" (Querier's Robustness Variable) in `raw_byte_24`.
    pub const RAW_BYTE_24_MASK_QRV: u8 = 0b0000_0111;
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert_eq!(28, MldQueryWithSourcesHeader::LEN);
        assert_eq!(
            0b1111_0000,
            MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_RESV
        );
        assert_eq!(4, MldQueryWithSourcesHeader::RAW_BYTE_24_OFFSET_RESV);
        assert_eq!(
            0b0000_1000,
            MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_S_FLAG
        );
        assert_eq!(0b0000_0111, MldQueryWithSourcesHeader::RAW_BYTE_24_MASK_QRV);
    }

    #[test]
    fn debug_clone_eq() {
        let header = MldQueryWithSourcesHeader {
            max_response_code: MldMaxResponseCode(1000),
            multicast_address: MulticastAddress::new([0xff; 16]),
            raw_byte_24: 0,
            qqic: 0,
            num_of_sources: 0,
        };
        assert_eq!(header, header.clone());
        assert!(format!("{:?}", header).contains("max_response_code"));
    }
}
