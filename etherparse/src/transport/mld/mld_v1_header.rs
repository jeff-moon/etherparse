use crate::mld::MulticastAddress;

/// MLDv1 "Multicast Listener Query", "Multicast Listener Report" &
/// "Multicast Listener Done" message header part.
///
/// All three MLDv1 message types share the same layout and only differ
/// in their ICMPv6 "Type" value, so they are represented by this single
/// type.
///
/// Note that the ICMPv6 "Type", "Code" & "Checksum" fields are not
/// stored in this type.
///
/// Defined in
/// [RFC 2710 section 3](https://datatracker.ietf.org/doc/html/rfc2710#section-3).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MldV1Header {
    /// The maximum response delay in milliseconds.
    ///
    /// Only meaningful in "Multicast Listener Query" messages, set to
    /// zero in "Report" & "Done" messages and ignored by receivers
    /// there.
    pub max_response_delay: u16,

    /// The multicast address.
    ///
    /// Set to zero in a "General Query", to a specific IPv6 multicast
    /// address in a "Multicast-Address-Specific Query". In "Report" &
    /// "Done" messages this holds the address the sender is listening
    /// to or done listening to.
    pub multicast_address: MulticastAddress,
}

impl MldV1Header {
    /// Number of bytes/octets an [`MldV1Header`] takes up in serialized
    /// form (including the ICMPv6 type, code & checksum).
    pub const LEN: usize = 24;
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert_eq!(24, MldV1Header::LEN);
    }

    #[test]
    fn debug_clone_eq_hash() {
        let header = MldV1Header {
            max_response_delay: 1000,
            multicast_address: MulticastAddress::new([0xff; 16]),
        };
        assert_eq!(header, header.clone());
        assert!(format!("{:?}", header).contains("max_response_delay"));
    }
}
