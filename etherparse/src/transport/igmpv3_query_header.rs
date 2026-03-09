use crate::*;

/// IGMPv3 Membership Query message type.
pub const IGMPV3_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;

/// The fixed-size header of an IGMPv3 Membership Query (RFC 3376).
///
/// This represents the 12-byte fixed portion of the query message.
/// The variable-length source address list that follows is not stored
/// in this struct; it is available from the remaining slice returned
/// by [`Igmpv3QueryHeader::from_slice`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv3QueryHeader {
    /// IGMP message type (0x11 for Membership Query).
    pub igmp_type: u8,
    /// Max Response Code.
    pub max_resp_code: u8,
    /// Checksum over the entire IGMP message (header + sources).
    pub checksum: u16,
    /// Group address.
    pub group_address: [u8; 4],
    /// Flags byte containing Reserved (4 bits), Suppress Router-Side
    /// Processing (1 bit), and Querier's Robustness Variable (3 bits).
    pub flags: u8,
    /// Querier's Query Interval Code.
    pub qqic: u8,
    /// Number of source addresses that follow this header.
    pub number_of_sources: u16,
}

impl Igmpv3QueryHeader {
    /// Number of bytes/octets the fixed portion of an [`Igmpv3QueryHeader`]
    /// takes up in serialized form.
    pub const LEN: usize = 12;

    /// Constructs an [`Igmpv3QueryHeader`] with checksum set to 0.
    #[inline]
    pub fn new(
        igmp_type: u8,
        max_resp_code: u8,
        group_address: [u8; 4],
        flags: u8,
        qqic: u8,
        number_of_sources: u16,
    ) -> Igmpv3QueryHeader {
        Igmpv3QueryHeader {
            igmp_type,
            max_resp_code,
            checksum: 0,
            group_address,
            flags,
            qqic,
            number_of_sources,
        }
    }

    /// Creates an [`Igmpv3QueryHeader`] with a checksum calculated from the
    /// header values and the given source addresses.
    #[inline]
    pub fn with_checksum(
        igmp_type: u8,
        max_resp_code: u8,
        group_address: [u8; 4],
        flags: u8,
        qqic: u8,
        number_of_sources: u16,
        sources: &[[u8; 4]],
    ) -> Igmpv3QueryHeader {
        let mut result =
            Igmpv3QueryHeader::new(igmp_type, max_resp_code, group_address, flags, qqic, number_of_sources);
        result.update_checksum(sources);
        result
    }

    /// Reads the fixed 12-byte IGMPv3 query header from a slice and returns
    /// a tuple of the header and the remaining slice (which contains the
    /// source addresses and any trailing data).
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv3QueryHeader, &[u8]), err::LenError> {
        if slice.len() < Self::LEN {
            return Err(err::LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }

        Ok((
            Igmpv3QueryHeader::from_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
                slice[8], slice[9], slice[10], slice[11],
            ]),
            &slice[Self::LEN..],
        ))
    }

    /// Read an [`Igmpv3QueryHeader`] from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 12]) -> Igmpv3QueryHeader {
        Igmpv3QueryHeader {
            igmp_type: bytes[0],
            max_resp_code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            group_address: [bytes[4], bytes[5], bytes[6], bytes[7]],
            flags: bytes[8],
            qqic: bytes[9],
            number_of_sources: u16::from_be_bytes([bytes[10], bytes[11]]),
        }
    }

    /// Reads the fixed 12-byte IGMPv3 query header from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(
        reader: &mut T,
    ) -> Result<Igmpv3QueryHeader, std::io::Error> {
        let mut bytes = [0u8; Self::LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv3QueryHeader::from_bytes(bytes))
    }

    /// Write the fixed 12-byte IGMPv3 query header to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length in bytes/octets of this header type.
    #[inline]
    pub const fn header_len(&self) -> usize {
        Self::LEN
    }

    /// Returns the Suppress Router-Side Processing flag (S bit).
    #[inline]
    pub const fn suppress(&self) -> bool {
        (self.flags & 0x08) != 0
    }

    /// Returns the Querier's Robustness Variable (QRV, lower 3 bits of flags).
    #[inline]
    pub const fn qrv(&self) -> u8 {
        self.flags & 0x07
    }

    /// Calculates and returns the checksum based on the current header values
    /// and the given source addresses.
    ///
    /// The IGMPv3 checksum covers the entire message including source
    /// addresses, so they must be provided for a correct result.
    #[inline]
    pub fn calc_checksum(&self, sources: &[[u8; 4]]) -> u16 {
        let mut sum = checksum::Sum16BitWords::new()
            .add_2bytes([self.igmp_type, self.max_resp_code])
            .add_4bytes(self.group_address)
            .add_2bytes([self.flags, self.qqic])
            .add_2bytes(self.number_of_sources.to_be_bytes());
        for src in sources {
            sum = sum.add_4bytes(*src);
        }
        sum.ones_complement().to_be()
    }

    /// Calculates and updates the checksum in the header.
    ///
    /// The IGMPv3 checksum covers the entire message including source
    /// addresses, so they must be provided for a correct result.
    #[inline]
    pub fn update_checksum(&mut self, sources: &[[u8; 4]]) {
        self.checksum = self.calc_checksum(sources);
    }

    /// Converts the fixed header to on-the-wire bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 12] {
        let checksum_be = self.checksum.to_be_bytes();
        let nos_be = self.number_of_sources.to_be_bytes();
        [
            self.igmp_type,
            self.max_resp_code,
            checksum_be[0],
            checksum_be[1],
            self.group_address[0],
            self.group_address[1],
            self.group_address[2],
            self.group_address[3],
            self.flags,
            self.qqic,
            nos_be[0],
            nos_be[1],
        ]
    }
}

#[cfg(test)]
mod test {
    use crate::{
        err::{Layer, LenError},
        *,
    };
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;
    #[cfg(feature = "std")]
    use std::io::Cursor;

    #[test]
    fn constants() {
        assert_eq!(12, Igmpv3QueryHeader::LEN);
        assert_eq!(0x11, IGMPV3_TYPE_MEMBERSHIP_QUERY);
    }

    proptest! {
        #[test]
        fn new(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            assert_eq!(
                Igmpv3QueryHeader {
                    igmp_type,
                    max_resp_code,
                    checksum: 0,
                    group_address,
                    flags,
                    qqic,
                    number_of_sources,
                },
                Igmpv3QueryHeader::new(igmp_type, max_resp_code, group_address, flags, qqic, number_of_sources)
            );
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
            sources in proptest::collection::vec(any::<[u8;4]>(), 0..4),
        ) {
            let header = Igmpv3QueryHeader::with_checksum(
                igmp_type, max_resp_code, group_address, flags, qqic, number_of_sources, &sources,
            );
            assert_eq!(igmp_type, header.igmp_type);
            assert_eq!(max_resp_code, header.max_resp_code);
            assert_eq!(group_address, header.group_address);
            assert_eq!(flags, header.flags);
            assert_eq!(qqic, header.qqic);
            assert_eq!(number_of_sources, header.number_of_sources);
            assert_eq!(header.calc_checksum(&sources), header.checksum);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let nos_be = number_of_sources.to_be_bytes();
            let mut bytes = vec![
                igmp_type,
                max_resp_code,
                checksum_be[0],
                checksum_be[1],
                group_address[0],
                group_address[1],
                group_address[2],
                group_address[3],
                flags,
                qqic,
                nos_be[0],
                nos_be[1],
            ];
            bytes.extend_from_slice(&suffix);

            let (actual, rest) = Igmpv3QueryHeader::from_slice(&bytes).unwrap();
            assert_eq!(
                Igmpv3QueryHeader {
                    igmp_type,
                    max_resp_code,
                    checksum,
                    group_address,
                    flags,
                    qqic,
                    number_of_sources,
                },
                actual
            );
            assert_eq!(suffix.as_slice(), rest);

            for bad_len in 0..Igmpv3QueryHeader::LEN {
                assert_eq!(
                    Igmpv3QueryHeader::from_slice(&bytes[..bad_len]),
                    Err(LenError {
                        required_len: Igmpv3QueryHeader::LEN,
                        len: bad_len,
                        len_source: LenSource::Slice,
                        layer: Layer::Igmpv3,
                        layer_start_offset: 0,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_bytes(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let nos_be = number_of_sources.to_be_bytes();
            let bytes = [
                igmp_type,
                max_resp_code,
                checksum_be[0],
                checksum_be[1],
                group_address[0],
                group_address[1],
                group_address[2],
                group_address[3],
                flags,
                qqic,
                nos_be[0],
                nos_be[1],
            ];

            assert_eq!(
                Igmpv3QueryHeader {
                    igmp_type,
                    max_resp_code,
                    checksum,
                    group_address,
                    flags,
                    qqic,
                    number_of_sources,
                },
                Igmpv3QueryHeader::from_bytes(bytes)
            );
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn read(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            let mut bytes = input.to_bytes().to_vec();
            bytes.extend_from_slice(&suffix);

            let mut cursor = Cursor::new(&bytes);
            let actual = Igmpv3QueryHeader::read(&mut cursor).unwrap();
            assert_eq!(input, actual);
            assert_eq!(Igmpv3QueryHeader::LEN as u64, cursor.position());

            for bad_len in 0..Igmpv3QueryHeader::LEN {
                let mut c = Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv3QueryHeader::read(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };

            let mut out = Vec::new();
            input.write(&mut out).unwrap();
            assert_eq!(input.to_bytes().as_slice(), out.as_slice());

            for bad_len in 0..Igmpv3QueryHeader::LEN {
                let mut buf = [0u8; Igmpv3QueryHeader::LEN];
                let mut c = Cursor::new(&mut buf[..bad_len]);
                assert!(input.write(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            assert_eq!(Igmpv3QueryHeader::LEN, input.header_len());
        }
    }

    #[test]
    fn suppress() {
        let mut header = Igmpv3QueryHeader::new(0x11, 0, [0; 4], 0x00, 0, 0);
        assert!(!header.suppress());

        header.flags = 0x08;
        assert!(header.suppress());

        header.flags = 0x0F;
        assert!(header.suppress());

        header.flags = 0xF7;
        assert!(!header.suppress());
    }

    #[test]
    fn qrv() {
        let mut header = Igmpv3QueryHeader::new(0x11, 0, [0; 4], 0x00, 0, 0);
        assert_eq!(0, header.qrv());

        header.flags = 0x07;
        assert_eq!(7, header.qrv());

        header.flags = 0x03;
        assert_eq!(3, header.qrv());

        header.flags = 0xF8;
        assert_eq!(0, header.qrv());
    }

    proptest! {
        #[test]
        fn calc_checksum(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
            sources in proptest::collection::vec(any::<[u8;4]>(), 0..4),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };

            let mut expected = checksum::Sum16BitWords::new()
                .add_2bytes([igmp_type, max_resp_code])
                .add_4bytes(group_address)
                .add_2bytes([flags, qqic])
                .add_2bytes(number_of_sources.to_be_bytes());
            for src in &sources {
                expected = expected.add_4bytes(*src);
            }
            assert_eq!(expected.ones_complement().to_be(), input.calc_checksum(&sources));
        }
    }

    proptest! {
        #[test]
        fn update_checksum(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
            sources in proptest::collection::vec(any::<[u8;4]>(), 0..4),
        ) {
            let mut input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            input.update_checksum(&sources);
            assert_eq!(input.calc_checksum(&sources), input.checksum);
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            let checksum_be = checksum.to_be_bytes();
            let nos_be = number_of_sources.to_be_bytes();
            assert_eq!(
                [
                    igmp_type,
                    max_resp_code,
                    checksum_be[0],
                    checksum_be[1],
                    group_address[0],
                    group_address[1],
                    group_address[2],
                    group_address[3],
                    flags,
                    qqic,
                    nos_be[0],
                    nos_be[1],
                ],
                input.to_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let input = Igmpv3QueryHeader {
                igmp_type,
                max_resp_code,
                checksum,
                group_address,
                flags,
                qqic,
                number_of_sources,
            };
            assert_eq!(
                format!(
                    "Igmpv3QueryHeader {{ igmp_type: {}, max_resp_code: {}, checksum: {}, group_address: {:?}, flags: {}, qqic: {}, number_of_sources: {} }}",
                    igmp_type,
                    max_resp_code,
                    checksum,
                    group_address,
                    flags,
                    qqic,
                    number_of_sources,
                ),
                format!("{:?}", input)
            );
        }
    }
}
