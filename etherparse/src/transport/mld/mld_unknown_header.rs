/// Header of an MLD message with a type unknown to etherparse.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Unknown Content                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MldUnknownHeader {
    /// The ICMPv6 "Type" value of the message.
    pub mld_type: u8,

    /// The ICMPv6 "Code" value of the message.
    pub code: u8,

    /// The raw bytes 4-7 following the checksum.
    pub raw_bytes_4_7: [u8; 4],
}

impl MldUnknownHeader {
    /// Minimum number of bytes/octets an [`MldUnknownHeader`] takes up in
    /// serialized form (including the ICMPv6 type, code & checksum).
    pub const LEN: usize = 8;
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert_eq!(8, MldUnknownHeader::LEN);
    }

    #[test]
    fn debug_clone_eq() {
        let header = MldUnknownHeader {
            mld_type: 200,
            code: 0,
            raw_bytes_4_7: [1, 2, 3, 4],
        };
        assert_eq!(header, header.clone());
        assert!(format!("{:?}", header).contains("mld_type"));
    }
}
