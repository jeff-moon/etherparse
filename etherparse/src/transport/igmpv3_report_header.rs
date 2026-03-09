use crate::*;

/// IGMPv3 Membership Report message type.
pub const IGMPV3_TYPE_MEMBERSHIP_REPORT: u8 = 0x22;

/// The fixed-size header of an IGMPv3 Membership Report (RFC 3376).
///
/// This represents the 8-byte fixed portion of the report message.
/// The variable-length group records that follow are not stored in
/// this struct; they are available from the remaining slice returned
/// by [`Igmpv3ReportHeader::from_slice`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv3ReportHeader {
    /// IGMP message type (0x22 for Membership Report).
    pub igmp_type: u8,
    /// Reserved octet (byte 1).
    pub reserved0: u8,
    /// Checksum over the entire IGMP message (header + group records).
    pub checksum: u16,
    /// Reserved field (bytes 4-5).
    pub reserved1: u16,
    /// Number of group records that follow this header.
    pub number_of_group_records: u16,
}

impl Igmpv3ReportHeader {
    /// Number of bytes/octets the fixed portion of an [`Igmpv3ReportHeader`]
    /// takes up in serialized form.
    pub const LEN: usize = 8;

    /// Constructs an [`Igmpv3ReportHeader`] with reserved fields & checksum set to 0.
    #[inline]
    pub fn new(igmp_type: u8, number_of_group_records: u16) -> Igmpv3ReportHeader {
        Igmpv3ReportHeader {
            igmp_type,
            reserved0: 0,
            checksum: 0,
            reserved1: 0,
            number_of_group_records,
        }
    }

    /// Creates an [`Igmpv3ReportHeader`] with a checksum calculated from the
    /// header values and the given raw group record bytes.
    #[inline]
    pub fn with_checksum(
        igmp_type: u8,
        number_of_group_records: u16,
        group_records: &[u8],
    ) -> Igmpv3ReportHeader {
        let mut result = Igmpv3ReportHeader::new(igmp_type, number_of_group_records);
        result.update_checksum(group_records);
        result
    }

    /// Reads the fixed 8-byte IGMPv3 report header from a slice and returns
    /// a tuple of the header and the remaining slice (which contains the
    /// group records and any trailing data).
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv3ReportHeader, &[u8]), err::LenError> {
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
            Igmpv3ReportHeader::from_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            &slice[Self::LEN..],
        ))
    }

    /// Read an [`Igmpv3ReportHeader`] from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 8]) -> Igmpv3ReportHeader {
        Igmpv3ReportHeader {
            igmp_type: bytes[0],
            reserved0: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            reserved1: u16::from_be_bytes([bytes[4], bytes[5]]),
            number_of_group_records: u16::from_be_bytes([bytes[6], bytes[7]]),
        }
    }

    /// Reads the fixed 8-byte IGMPv3 report header from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(
        reader: &mut T,
    ) -> Result<Igmpv3ReportHeader, std::io::Error> {
        let mut bytes = [0u8; Self::LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv3ReportHeader::from_bytes(bytes))
    }

    /// Write the fixed 8-byte IGMPv3 report header to the given writer.
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

    /// Calculates and returns the checksum based on the current header values
    /// and the given raw group record bytes.
    ///
    /// The IGMPv3 checksum covers the entire message including group records,
    /// so the raw bytes must be provided for a correct result.
    #[inline]
    pub fn calc_checksum(&self, group_records: &[u8]) -> u16 {
        let mut sum = checksum::Sum16BitWords::new()
            .add_2bytes([self.igmp_type, self.reserved0])
            .add_2bytes(self.reserved1.to_be_bytes())
            .add_2bytes(self.number_of_group_records.to_be_bytes());
        // Process group record bytes in 2-byte chunks for the checksum.
        let mut i = 0;
        while i + 1 < group_records.len() {
            sum = sum.add_2bytes([group_records[i], group_records[i + 1]]);
            i += 2;
        }
        // Handle a trailing odd byte.
        if i < group_records.len() {
            sum = sum.add_2bytes([group_records[i], 0]);
        }
        sum.ones_complement().to_be()
    }

    /// Calculates and updates the checksum in the header.
    ///
    /// The IGMPv3 checksum covers the entire message including group records,
    /// so the raw bytes must be provided for a correct result.
    #[inline]
    pub fn update_checksum(&mut self, group_records: &[u8]) {
        self.checksum = self.calc_checksum(group_records);
    }

    /// Converts the fixed header to on-the-wire bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 8] {
        let checksum_be = self.checksum.to_be_bytes();
        let reserved1_be = self.reserved1.to_be_bytes();
        let nogr_be = self.number_of_group_records.to_be_bytes();
        [
            self.igmp_type,
            self.reserved0,
            checksum_be[0],
            checksum_be[1],
            reserved1_be[0],
            reserved1_be[1],
            nogr_be[0],
            nogr_be[1],
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
        assert_eq!(8, Igmpv3ReportHeader::LEN);
        assert_eq!(0x22, IGMPV3_TYPE_MEMBERSHIP_REPORT);
    }

    proptest! {
        #[test]
        fn new(
            igmp_type in any::<u8>(),
            number_of_group_records in any::<u16>(),
        ) {
            assert_eq!(
                Igmpv3ReportHeader {
                    igmp_type,
                    reserved0: 0,
                    checksum: 0,
                    reserved1: 0,
                    number_of_group_records,
                },
                Igmpv3ReportHeader::new(igmp_type, number_of_group_records)
            );
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            igmp_type in any::<u8>(),
            number_of_group_records in any::<u16>(),
            group_records in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let header = Igmpv3ReportHeader::with_checksum(
                igmp_type, number_of_group_records, &group_records,
            );
            assert_eq!(igmp_type, header.igmp_type);
            assert_eq!(0, header.reserved0);
            assert_eq!(0, header.reserved1);
            assert_eq!(number_of_group_records, header.number_of_group_records);
            assert_eq!(header.calc_checksum(&group_records), header.checksum);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let reserved1_be = reserved1.to_be_bytes();
            let nogr_be = number_of_group_records.to_be_bytes();
            let mut bytes = vec![
                igmp_type,
                reserved0,
                checksum_be[0],
                checksum_be[1],
                reserved1_be[0],
                reserved1_be[1],
                nogr_be[0],
                nogr_be[1],
            ];
            bytes.extend_from_slice(&suffix);

            let (actual, rest) = Igmpv3ReportHeader::from_slice(&bytes).unwrap();
            assert_eq!(
                Igmpv3ReportHeader {
                    igmp_type,
                    reserved0,
                    checksum,
                    reserved1,
                    number_of_group_records,
                },
                actual
            );
            assert_eq!(suffix.as_slice(), rest);

            for bad_len in 0..Igmpv3ReportHeader::LEN {
                assert_eq!(
                    Igmpv3ReportHeader::from_slice(&bytes[..bad_len]),
                    Err(LenError {
                        required_len: Igmpv3ReportHeader::LEN,
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
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let reserved1_be = reserved1.to_be_bytes();
            let nogr_be = number_of_group_records.to_be_bytes();
            let bytes = [
                igmp_type,
                reserved0,
                checksum_be[0],
                checksum_be[1],
                reserved1_be[0],
                reserved1_be[1],
                nogr_be[0],
                nogr_be[1],
            ];

            assert_eq!(
                Igmpv3ReportHeader {
                    igmp_type,
                    reserved0,
                    checksum,
                    reserved1,
                    number_of_group_records,
                },
                Igmpv3ReportHeader::from_bytes(bytes)
            );
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn read(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            let mut bytes = input.to_bytes().to_vec();
            bytes.extend_from_slice(&suffix);

            let mut cursor = Cursor::new(&bytes);
            let actual = Igmpv3ReportHeader::read(&mut cursor).unwrap();
            assert_eq!(input, actual);
            assert_eq!(Igmpv3ReportHeader::LEN as u64, cursor.position());

            for bad_len in 0..Igmpv3ReportHeader::LEN {
                let mut c = Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv3ReportHeader::read(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };

            let mut out = Vec::new();
            input.write(&mut out).unwrap();
            assert_eq!(input.to_bytes().as_slice(), out.as_slice());

            for bad_len in 0..Igmpv3ReportHeader::LEN {
                let mut buf = [0u8; Igmpv3ReportHeader::LEN];
                let mut c = Cursor::new(&mut buf[..bad_len]);
                assert!(input.write(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            assert_eq!(Igmpv3ReportHeader::LEN, input.header_len());
        }
    }

    proptest! {
        #[test]
        fn calc_checksum(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
            group_records in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };

            // Build the expected checksum manually over the full message.
            let mut msg = input.to_bytes().to_vec();
            // Zero out the checksum field for computation.
            msg[2] = 0;
            msg[3] = 0;
            msg.extend_from_slice(&group_records);

            let mut sum = crate::checksum::Sum16BitWords::new();
            let mut i = 0;
            while i + 1 < msg.len() {
                sum = sum.add_2bytes([msg[i], msg[i + 1]]);
                i += 2;
            }
            if i < msg.len() {
                sum = sum.add_2bytes([msg[i], 0]);
            }
            let expected = sum.ones_complement().to_be();

            assert_eq!(expected, input.calc_checksum(&group_records));
        }
    }

    proptest! {
        #[test]
        fn update_checksum(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
            group_records in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let mut input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            input.update_checksum(&group_records);
            assert_eq!(input.calc_checksum(&group_records), input.checksum);
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            let checksum_be = checksum.to_be_bytes();
            let reserved1_be = reserved1.to_be_bytes();
            let nogr_be = number_of_group_records.to_be_bytes();
            assert_eq!(
                [
                    igmp_type,
                    reserved0,
                    checksum_be[0],
                    checksum_be[1],
                    reserved1_be[0],
                    reserved1_be[1],
                    nogr_be[0],
                    nogr_be[1],
                ],
                input.to_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
        ) {
            let input = Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
            };
            assert_eq!(
                format!(
                    "Igmpv3ReportHeader {{ igmp_type: {}, reserved0: {}, checksum: {}, reserved1: {}, number_of_group_records: {} }}",
                    igmp_type,
                    reserved0,
                    checksum,
                    reserved1,
                    number_of_group_records,
                ),
                format!("{:?}", input)
            );
        }
    }
}
