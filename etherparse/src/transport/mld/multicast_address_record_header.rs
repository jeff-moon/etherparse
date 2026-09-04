use crate::mld::MulticastAddress;

/// A single "Multicast Address Record" of an MLDv2 "Multicast Listener
/// Report" (the fixed fields preceding the source list & auxiliary
/// data).
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
/// +                                                               +
/// |                                                               |
/// +                       Multicast Address                       +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Source Address [1]                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                               .                               .
/// .                               .                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Source Address [N]                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                                                               .
/// .                         Auxiliary Data                        .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddressRecordHeader {
    /// The type of the multicast address record.
    pub record_type: MulticastAddressRecordType,

    /// The length of the auxiliary data in units of 32-bit words.
    pub aux_data_len: u8,

    /// The number of source addresses in this record.
    pub num_of_sources: u16,

    /// The multicast address this record refers to.
    pub multicast_address: MulticastAddress,
}

impl MulticastAddressRecordHeader {
    /// Number of bytes/octets an [`MulticastAddressRecordHeader`] takes
    /// up in serialized form.
    pub const LEN: usize = 20;
}

/// Type value within a [`MulticastAddressRecordHeader`].
///
/// Defined in
/// [RFC 3810 section 5.2.12](https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.12).
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MulticastAddressRecordType(pub u8);

impl MulticastAddressRecordType {
    /// Indicates that the interface has a filter mode of INCLUDE for the
    /// specified multicast address. The Source Address \[i\] fields in
    /// this Multicast Address Record contain the interface's source list
    /// for the specified multicast address, if it is non-empty.
    pub const MODE_IS_INCLUDE: MulticastAddressRecordType = MulticastAddressRecordType(1);

    /// Indicates that the interface has a filter mode of EXCLUDE for the
    /// specified multicast address. The Source Address \[i\] fields in
    /// this Multicast Address Record contain the interface's source list
    /// for the specified multicast address, if it is non-empty.
    pub const MODE_IS_EXCLUDE: MulticastAddressRecordType = MulticastAddressRecordType(2);

    /// Indicates that the interface has changed to INCLUDE filter mode
    /// for the specified multicast address. The Source Address \[i\]
    /// fields in this Multicast Address Record contain the interface's
    /// new source list for the specified multicast address, if it is
    /// non-empty.
    pub const CHANGE_TO_INCLUDE_MODE: MulticastAddressRecordType = MulticastAddressRecordType(3);

    /// Indicates that the interface has changed to EXCLUDE filter mode
    /// for the specified multicast address. The Source Address \[i\]
    /// fields in this Multicast Address Record contain the interface's
    /// new source list for the specified multicast address, if it is
    /// non-empty.
    pub const CHANGE_TO_EXCLUDE_MODE: MulticastAddressRecordType = MulticastAddressRecordType(4);

    /// Indicates that the Source Address \[i\] fields in this Multicast
    /// Address Record contain a list of the additional sources that the
    /// node wishes to listen to, for packets sent to the specified
    /// multicast address.
    pub const ALLOW_NEW_SOURCES: MulticastAddressRecordType = MulticastAddressRecordType(5);

    /// Indicates that the Source Address \[i\] fields in this Multicast
    /// Address Record contain a list of the sources that the node no
    /// longer wishes to listen to, for packets sent to the specified
    /// multicast address.
    pub const BLOCK_OLD_SOURCES: MulticastAddressRecordType = MulticastAddressRecordType(6);
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert_eq!(20, MulticastAddressRecordHeader::LEN);
        assert_eq!(1, MulticastAddressRecordType::MODE_IS_INCLUDE.0);
        assert_eq!(2, MulticastAddressRecordType::MODE_IS_EXCLUDE.0);
        assert_eq!(3, MulticastAddressRecordType::CHANGE_TO_INCLUDE_MODE.0);
        assert_eq!(4, MulticastAddressRecordType::CHANGE_TO_EXCLUDE_MODE.0);
        assert_eq!(5, MulticastAddressRecordType::ALLOW_NEW_SOURCES.0);
        assert_eq!(6, MulticastAddressRecordType::BLOCK_OLD_SOURCES.0);
    }

    #[test]
    fn debug_clone_eq_default() {
        let record_type = MulticastAddressRecordType::MODE_IS_INCLUDE;
        assert_eq!(record_type, record_type.clone());
        assert_eq!(
            MulticastAddressRecordType::default(),
            MulticastAddressRecordType(0)
        );
        assert_eq!(
            format!("{:?}", record_type),
            "MulticastAddressRecordType(1)"
        );

        let header = MulticastAddressRecordHeader {
            record_type,
            aux_data_len: 0,
            num_of_sources: 0,
            multicast_address: MulticastAddress::new([0xff; 16]),
        };
        assert_eq!(header, header.clone());
        assert!(format!("{:?}", header).contains("record_type"));
    }
}
