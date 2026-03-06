use crate::*;
use arrayvec::ArrayVec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv1Header {
    pub igmp_type: Igmpv1Type,
    pub checksum: u16,
}

impl Igmpv1Header {
    pub const MIN_LEN: usize = 8;

    pub const MAX_LEN: usize = 8;

    pub fn new(igmp_type: Igmpv1Type) -> Igmpv1Header {
        Igmpv1Header {
            igmp_type,
            checksum: 0,
        }
    }

    pub fn with_checksum(igmp_type: Igmpv1Type, payload: &[u8]) -> Igmpv1Header {
        let checksum = igmp_type.calc_checksum(payload);
        Igmpv1Header {
            igmp_type,
            checksum,
        }
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv1Header, &[u8]), err::LenError> {
        let header = Igmpv1Slice::from_slice(slice)?.header();
        let rest = &slice[header.header_len()..];
        Ok((header, rest))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(reader: &mut T) -> Result<Igmpv1Header, std::io::Error> {
        let mut bytes = [0u8; Igmpv1Header::MAX_LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv1Slice { slice: &bytes }.header())
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        self.igmp_type.header_len()
    }

    pub fn update_checksum(&mut self, payload: &[u8]) {
        self.checksum = self.igmp_type.calc_checksum(payload);
    }

    #[rustfmt::skip]
    pub fn to_bytes(&self) -> ArrayVec<u8, { Igmpv1Header::MAX_LEN }> {
        let checksum_be = self.checksum.to_be_bytes();

        use Igmpv1Type::*;
        use igmpv1::*;
        match self.igmp_type {
            Unknown { type_u8, bytes4to7 } => {
                ArrayVec::from([
                    type_u8, 0, checksum_be[0], checksum_be[1],
                    bytes4to7[0], bytes4to7[1], bytes4to7[2], bytes4to7[3],
                ])
            }
            MembershipQuery { group_address } => {
                ArrayVec::from([
                    TYPE_MEMBERSHIP_QUERY, 0, checksum_be[0], checksum_be[1],
                    group_address[0], group_address[1], group_address[2], group_address[3],
                ])
            }
            MembershipReport { group_address } => {
                ArrayVec::from([
                    TYPE_MEMBERSHIP_REPORT, 0, checksum_be[0], checksum_be[1],
                    group_address[0], group_address[1], group_address[2], group_address[3],
                ])
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{err::{Layer, LenError}, igmpv1::*, Igmpv1Type::*, *};
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn constants() {
        assert_eq!(8, Igmpv1Header::MIN_LEN);
        assert_eq!(8, Igmpv1Header::MAX_LEN);
    }

    proptest! {
        #[test]
        fn new(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];
            for igmp_type in tests {
                assert_eq!(
                    Igmpv1Header {
                        igmp_type: igmp_type.clone(),
                        checksum: 0,
                    },
                    Igmpv1Header::new(igmp_type)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];
            for igmp_type in tests {
                assert_eq!(
                    Igmpv1Header {
                        igmp_type: igmp_type.clone(),
                        checksum: igmp_type.calc_checksum(&payload),
                    },
                    Igmpv1Header::with_checksum(igmp_type, &payload)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            checksum in any::<u16>(),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];

            for igmp_type in tests {
                let header = Igmpv1Header {
                    igmp_type: igmp_type.clone(),
                    checksum,
                };
                let buffer = {
                    let mut buffer = Vec::with_capacity(header.header_len() + 36);
                    buffer.extend_from_slice(&header.to_bytes());
                    buffer.extend_from_slice(&[0u8; 36]);
                    buffer
                };
                {
                    let (actual, rest) = Igmpv1Header::from_slice(&buffer).unwrap();
                    assert_eq!(actual, header);
                    assert_eq!(rest, &buffer[header.header_len()..]);
                }

                for bad_len in 0..header.header_len() {
                    assert_eq!(
                        Igmpv1Header::from_slice(&buffer[..bad_len]),
                        Err(LenError {
                            required_len: Igmpv1Header::MIN_LEN,
                            len: bad_len,
                            len_source: LenSource::Slice,
                            layer: Layer::Igmpv1,
                            layer_start_offset: 0,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn read(bytes in any::<[u8;8]>()) {
            let expected = Igmpv1Header::from_slice(&bytes).unwrap().0;

            {
                let mut cursor = std::io::Cursor::new(&bytes);
                let actual = Igmpv1Header::read(&mut cursor).unwrap();
                assert_eq!(expected, actual);
                assert_eq!(expected.header_len() as u64, cursor.position());
            }

            for bad_len in 0..expected.header_len() {
                let mut cursor = std::io::Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv1Header::read(&mut cursor).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn write(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            checksum in any::<u16>(),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];

            for igmp_type in tests {
                let header = Igmpv1Header {
                    igmp_type,
                    checksum,
                };

                {
                    let bytes = header.to_bytes();
                    let mut buffer = Vec::with_capacity(header.header_len());
                    header.write(&mut buffer).unwrap();
                    assert_eq!(&bytes[..], &buffer[..]);
                }

                {
                    for bad_len in 0..header.header_len() {
                        let mut bytes = [0u8; Igmpv1Header::MAX_LEN];
                        let mut writer = std::io::Cursor::new(&mut bytes[..bad_len]);
                        header.write(&mut writer).unwrap_err();
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            checksum in any::<u16>(),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];
            for igmp_type in tests {
                let header = Igmpv1Header {
                    igmp_type: igmp_type.clone(),
                    checksum,
                };
                assert_eq!(header.header_len(), igmp_type.header_len());
            }
        }
    }

    proptest! {
        #[test]
        fn update_checksum(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            checksum in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];
            for igmp_type in tests {
                let mut header = Igmpv1Header {
                    igmp_type: igmp_type.clone(),
                    checksum,
                };
                header.update_checksum(&payload);
                assert_eq!(header.checksum, igmp_type.calc_checksum(&payload));
            }
        }
    }

    proptest! {
        #[test]
        #[rustfmt::skip]
        fn to_bytes(
            checksum in any::<u16>(),
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
        ) {
            use arrayvec::ArrayVec;

            let tests = [
                (
                    Unknown { type_u8, bytes4to7 },
                    [
                        type_u8, 0, 0, 0,
                        bytes4to7[0], bytes4to7[1], bytes4to7[2], bytes4to7[3],
                    ],
                ),
                (
                    MembershipQuery { group_address },
                    [
                        TYPE_MEMBERSHIP_QUERY, 0, 0, 0,
                        group_address[0], group_address[1], group_address[2], group_address[3],
                    ],
                ),
                (
                    MembershipReport { group_address },
                    [
                        TYPE_MEMBERSHIP_REPORT, 0, 0, 0,
                        group_address[0], group_address[1], group_address[2], group_address[3],
                    ],
                ),
            ];

            for (igmp_type, expected_bytes) in tests {
                let actual = Igmpv1Header {
                    igmp_type,
                    checksum,
                }.to_bytes();

                let mut expected = ArrayVec::from(expected_bytes);
                let checksum_be = checksum.to_be_bytes();
                expected[2] = checksum_be[0];
                expected[3] = checksum_be[1];
                assert_eq!(expected, actual);
            }
        }
    }

    #[test]
    fn clone_eq() {
        let header = Igmpv1Header {
            igmp_type: MembershipQuery {
                group_address: [0; 4],
            },
            checksum: 0,
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn debug() {
        let header = Igmpv1Header {
            igmp_type: MembershipQuery {
                group_address: [0; 4],
            },
            checksum: 0,
        };
        assert_eq!(
            format!("{:?}", header),
            format!(
                "Igmpv1Header {{ igmp_type: {:?}, checksum: {:?} }}",
                header.igmp_type, header.checksum
            )
        );
    }
}
