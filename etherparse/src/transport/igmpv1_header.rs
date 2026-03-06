use crate::*;

/// A header of an IGMPv1 packet.
///
/// IGMPv1 messages are 8 bytes long with the following layout:
///
/// * Type (1 byte): `0x11` for Membership Query, `0x12` for Membership Report
/// * Unused (1 byte): set to 0
/// * Checksum (2 bytes)
/// * Group Address (4 bytes): IPv4 multicast group address
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv1Header {
    /// Version & type of the message.
    pub version_type: Igmpv1Type,
    /// Checksum over the entire IGMP message.
    pub checksum: u16,
    /// Multicast group address (0 for general queries).
    pub group_address: [u8; 4],
}

impl Igmpv1Header {
    /// Size of an IGMPv1 header in bytes/octets.
    pub const LEN: usize = 8;

    /// Constructs an [`Igmpv1Header`] with the checksum set to 0.
    pub fn new(version_type: Igmpv1Type, group_address: [u8; 4]) -> Igmpv1Header {
        Igmpv1Header {
            version_type,
            checksum: 0,
            group_address,
        }
    }

    /// Creates an [`Igmpv1Header`] with a checksum calculated from the header fields.
    pub fn with_checksum(version_type: Igmpv1Type, group_address: [u8; 4]) -> Igmpv1Header {
        let mut header = Igmpv1Header {
            version_type,
            checksum: 0,
            group_address,
        };
        header.update_checksum();
        header
    }

    /// Reads an IGMPv1 header from a slice and returns the header and the
    /// remaining slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv1Header, &[u8]), err::LenError> {
        let header = Igmpv1Slice::from_slice(slice)?.header();
        let rest = &slice[Igmpv1Header::LEN..];
        Ok((header, rest))
    }

    /// Reads an IGMPv1 header from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(reader: &mut T) -> Result<Igmpv1Header, std::io::Error> {
        let mut bytes = [0u8; Igmpv1Header::LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv1Slice { slice: &bytes }.header())
    }

    /// Write the IGMPv1 header to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length in bytes/octets of this header (always 8).
    #[inline]
    pub fn header_len(&self) -> usize {
        Igmpv1Header::LEN
    }

    /// Calculates & updates the checksum in the header.
    pub fn update_checksum(&mut self) {
        self.checksum = 0;
        self.checksum = checksum::Sum16BitWords::new()
            .add_slice(&self.to_bytes())
            .ones_complement();
    }

    /// Calculates the checksum for the header.
    pub fn calc_checksum(&self) -> u16 {
        let mut copy = self.clone();
        copy.checksum = 0;
        checksum::Sum16BitWords::new()
            .add_slice(&copy.to_bytes())
            .ones_complement()
    }

    /// Converts the header to the on the wire bytes.
    pub fn to_bytes(&self) -> [u8; Igmpv1Header::LEN] {
        let checksum_be = self.checksum.to_be_bytes();
        [
            self.version_type.type_u8(),
            0, // unused
            checksum_be[0],
            checksum_be[1],
            self.group_address[0],
            self.group_address[1],
            self.group_address[2],
            self.group_address[3],
        ]
    }
}

#[cfg(test)]
mod test {
    use crate::{
        err::{Layer, LenError},
        test_gens::*,
        *,
    };
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn constants() {
        assert_eq!(8, Igmpv1Header::LEN);
    }

    proptest! {
        #[test]
        fn new(
            igmpv1_type in igmpv1_type_any(),
            group_address in any::<[u8; 4]>(),
        ) {
            let header = Igmpv1Header::new(igmpv1_type, group_address);
            assert_eq!(header.version_type, igmpv1_type);
            assert_eq!(header.checksum, 0);
            assert_eq!(header.group_address, group_address);
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            igmpv1_type in igmpv1_type_any(),
            group_address in any::<[u8; 4]>(),
        ) {
            let header = Igmpv1Header::with_checksum(igmpv1_type, group_address);
            assert_eq!(header.version_type, igmpv1_type);
            assert_eq!(header.group_address, group_address);
            assert_eq!(header.checksum, header.calc_checksum());
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            igmpv1_type in igmpv1_type_any(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
            extra in proptest::collection::vec(any::<u8>(), 0..20),
        ) {
            let header = Igmpv1Header {
                version_type: igmpv1_type,
                checksum,
                group_address,
            };
            let mut buffer = Vec::with_capacity(Igmpv1Header::LEN + extra.len());
            buffer.extend_from_slice(&header.to_bytes());
            buffer.extend_from_slice(&extra);

            // ok case
            {
                let (actual, rest) = Igmpv1Header::from_slice(&buffer).unwrap();
                assert_eq!(actual, header);
                assert_eq!(rest, &buffer[Igmpv1Header::LEN..]);
            }

            // error case
            for bad_len in 0..Igmpv1Header::LEN {
                assert_eq!(
                    Igmpv1Header::from_slice(&buffer[..bad_len]),
                    Err(LenError {
                        required_len: Igmpv1Header::LEN,
                        len: bad_len,
                        len_source: LenSource::Slice,
                        layer: Layer::Igmpv1,
                        layer_start_offset: 0,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            igmpv1_type in igmpv1_type_any(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let header = Igmpv1Header {
                version_type: igmpv1_type,
                checksum,
                group_address,
            };
            let bytes = header.to_bytes();

            // ok case
            {
                let mut cursor = std::io::Cursor::new(&bytes[..]);
                let actual = Igmpv1Header::read(&mut cursor).unwrap();
                assert_eq!(actual, header);
                assert_eq!(Igmpv1Header::LEN as u64, cursor.position());
            }

            // size error case
            for bad_len in 0..Igmpv1Header::LEN {
                let mut cursor = std::io::Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv1Header::read(&mut cursor).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn write(
            igmpv1_type in igmpv1_type_any(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let header = Igmpv1Header {
                version_type: igmpv1_type,
                checksum,
                group_address,
            };

            // normal write
            {
                let bytes = header.to_bytes();
                let mut buffer = Vec::with_capacity(Igmpv1Header::LEN);
                header.write(&mut buffer).unwrap();
                assert_eq!(&bytes[..], &buffer[..]);
            }

            // error case
            {
                for bad_len in 0..Igmpv1Header::LEN {
                    let mut bytes = [0u8; Igmpv1Header::LEN];
                    let mut writer = std::io::Cursor::new(&mut bytes[..bad_len]);
                    header.write(&mut writer).unwrap_err();
                }
            }
        }
    }

    #[test]
    fn header_len() {
        let header = Igmpv1Header::new(Igmpv1Type::MembershipQuery, [0; 4]);
        assert_eq!(header.header_len(), 8);
    }

    proptest! {
        #[test]
        fn update_checksum(
            igmpv1_type in igmpv1_type_any(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let mut header = Igmpv1Header {
                version_type: igmpv1_type,
                checksum,
                group_address,
            };
            header.update_checksum();
            assert_eq!(header.checksum, header.calc_checksum());
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            igmpv1_type in igmpv1_type_any(),
            checksum in any::<u16>(),
            group_address in any::<[u8; 4]>(),
        ) {
            let header = Igmpv1Header {
                version_type: igmpv1_type,
                checksum,
                group_address,
            };
            let checksum_be = checksum.to_be_bytes();
            let expected = [
                igmpv1_type.type_u8(), 0,
                checksum_be[0], checksum_be[1],
                group_address[0], group_address[1], group_address[2], group_address[3],
            ];
            assert_eq!(expected, header.to_bytes());
        }
    }

    #[test]
    fn clone_eq() {
        let header = Igmpv1Header::new(Igmpv1Type::MembershipQuery, [224, 0, 0, 1]);
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn debug() {
        let header = Igmpv1Header::new(Igmpv1Type::MembershipQuery, [0; 4]);
        assert_eq!(
            format!("{:?}", header),
            format!(
                "Igmpv1Header {{ version_type: {:?}, checksum: {:?}, group_address: {:?} }}",
                header.version_type, header.checksum, header.group_address
            )
        );
    }
}
