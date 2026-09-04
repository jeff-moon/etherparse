/// MLDv2 "Multicast Listener Report" message header part (the fixed
/// fields preceding the multicast address records).
///
/// Note that the ICMPv6 "Type", "Code" & "Checksum" fields are not
/// stored in this type.
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
/// .                                                               .  |
/// .               Multicast Address Record [1]                    .  |
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  | part of payload
/// .               Multicast Address Record [2]                    .  |
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                               .                               |  |
/// .                               .                               .  |
/// |                               .                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .               Multicast Address Record [M]                    .  |
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MldReportV2Header {
    /// The reserved bytes 4-5 of the report header.
    ///
    /// Sent as zero and ignored by receivers, but preserved here so the
    /// raw contents remain accessible.
    pub reserved: [u8; 2],

    /// The number of multicast address records in the report.
    pub num_of_records: u16,
}

impl MldReportV2Header {
    /// Number of bytes/octets an [`MldReportV2Header`] takes up in
    /// serialized form (including the ICMPv6 type, code & checksum).
    pub const LEN: usize = 8;
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert_eq!(8, MldReportV2Header::LEN);
    }

    #[test]
    fn debug_clone_eq() {
        let header = MldReportV2Header {
            reserved: [0, 0],
            num_of_records: 3,
        };
        assert_eq!(header, header.clone());
        assert!(format!("{:?}", header).contains("num_of_records"));
    }
}
