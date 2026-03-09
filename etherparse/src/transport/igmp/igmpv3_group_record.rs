use arrayvec::ArrayVec;

use crate::*;

/// Record types for IGMPv3 group records (RFC 3376, Section 4.2.12).
pub const IGMPV3_MODE_IS_INCLUDE: u8 = 1;
/// Current-State Record: interface in EXCLUDE mode.
pub const IGMPV3_MODE_IS_EXCLUDE: u8 = 2;
/// Filter-Mode-Change Record: changed to INCLUDE.
pub const IGMPV3_CHANGE_TO_INCLUDE_MODE: u8 = 3;
/// Filter-Mode-Change Record: changed to EXCLUDE.
pub const IGMPV3_CHANGE_TO_EXCLUDE_MODE: u8 = 4;
/// Source-List-Change Record: allow new sources.
pub const IGMPV3_ALLOW_NEW_SOURCES: u8 = 5;
/// Source-List-Change Record: block old sources.
pub const IGMPV3_BLOCK_OLD_SOURCES: u8 = 6;

/// The fixed-size header of an IGMPv3 group record (RFC 3376).
///
/// This represents the 8-byte fixed portion of each group record
/// within an IGMPv3 Membership Report. The variable-length source
/// addresses and auxiliary data that follow are not stored in this
/// struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv3GroupRecordHeader {
    /// Group record type.
    pub record_type: u8,
    /// Auxiliary data length in units of 32-bit words.
    pub aux_data_len: u8,
    /// Number of source addresses in this group record.
    pub number_of_sources: u16,
    /// Multicast address.
    pub multicast_address: [u8; 4],
}

impl Igmpv3GroupRecordHeader {
    /// Number of bytes/octets the fixed portion of an [`Igmpv3GroupRecordHeader`]
    /// takes up in serialized form.
    pub const LEN: usize = 8;

    /// Constructs an [`Igmpv3GroupRecordHeader`].
    #[inline]
    pub fn new(
        record_type: u8,
        aux_data_len: u8,
        number_of_sources: u16,
        multicast_address: [u8; 4],
    ) -> Igmpv3GroupRecordHeader {
        Igmpv3GroupRecordHeader {
            record_type,
            aux_data_len,
            number_of_sources,
            multicast_address,
        }
    }

    /// Reads the fixed 8-byte group record header from a slice and returns
    /// a tuple of the header and the remaining slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv3GroupRecordHeader, &[u8]), err::LenError> {
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
            Igmpv3GroupRecordHeader::from_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            &slice[Self::LEN..],
        ))
    }

    /// Read an [`Igmpv3GroupRecordHeader`] from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 8]) -> Igmpv3GroupRecordHeader {
        Igmpv3GroupRecordHeader {
            record_type: bytes[0],
            aux_data_len: bytes[1],
            number_of_sources: u16::from_be_bytes([bytes[2], bytes[3]]),
            multicast_address: [bytes[4], bytes[5], bytes[6], bytes[7]],
        }
    }

    /// Reads the fixed 8-byte group record header from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(
        reader: &mut T,
    ) -> Result<Igmpv3GroupRecordHeader, std::io::Error> {
        let mut bytes = [0u8; Self::LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv3GroupRecordHeader::from_bytes(bytes))
    }

    /// Write the fixed 8-byte group record header to the given writer.
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

    /// Returns the total length in bytes of this group record on the wire,
    /// including source addresses and auxiliary data.
    #[inline]
    pub fn record_len(&self) -> usize {
        Self::LEN
            + usize::from(self.number_of_sources) * 4
            + usize::from(self.aux_data_len) * 4
    }

    /// Converts the fixed header to on-the-wire bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 8] {
        let nos_be = self.number_of_sources.to_be_bytes();
        [
            self.record_type,
            self.aux_data_len,
            nos_be[0],
            nos_be[1],
            self.multicast_address[0],
            self.multicast_address[1],
            self.multicast_address[2],
            self.multicast_address[3],
        ]
    }

    /// Parses group record headers from a slice containing the group record
    /// data of an IGMPv3 Membership Report. Each record's source addresses
    /// and auxiliary data are skipped to advance to the next record.
    ///
    /// Returns an [`ArrayVec`] of parsed group record headers and the
    /// remaining slice after all records. Returns an error if the slice
    /// is too short for any declared record or if the number of group
    /// records exceeds [`IGMPV3_MAX_GROUP_RECORDS`].
    pub fn parse_records(
        mut slice: &[u8],
        number_of_group_records: u16,
    ) -> Result<(ArrayVec<Igmpv3GroupRecordHeader, IGMPV3_MAX_GROUP_RECORDS>, &[u8]), err::LenError> {
        let count = usize::from(number_of_group_records);
        if count > IGMPV3_MAX_GROUP_RECORDS {
            return Err(err::LenError {
                required_len: count * Igmpv3GroupRecordHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }
        let mut records = ArrayVec::new();
        for _ in 0..number_of_group_records {
            let (record, rest) = Igmpv3GroupRecordHeader::from_slice(slice)?;
            let variable_len =
                usize::from(record.number_of_sources) * 4 + usize::from(record.aux_data_len) * 4;
            if rest.len() < variable_len {
                return Err(err::LenError {
                    required_len: Igmpv3GroupRecordHeader::LEN + variable_len,
                    len: slice.len(),
                    len_source: LenSource::Slice,
                    layer: err::Layer::Igmpv3,
                    layer_start_offset: 0,
                });
            }
            slice = &rest[variable_len..];
            records.push(record);
        }
        Ok((records, slice))
    }
}

/// Maximum number of group records supported by
/// [`Igmpv3GroupRecordHeader::parse_records`]. This corresponds to the
/// maximum number of minimum-size (8-byte) group records that fit in a
/// standard 1500-byte MTU after the IP and report headers.
pub const IGMPV3_MAX_GROUP_RECORDS: usize = 184;

#[cfg(test)]
mod test {
    use super::*;
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
        assert_eq!(8, Igmpv3GroupRecordHeader::LEN);
        assert_eq!(1, IGMPV3_MODE_IS_INCLUDE);
        assert_eq!(2, IGMPV3_MODE_IS_EXCLUDE);
        assert_eq!(3, IGMPV3_CHANGE_TO_INCLUDE_MODE);
        assert_eq!(4, IGMPV3_CHANGE_TO_EXCLUDE_MODE);
        assert_eq!(5, IGMPV3_ALLOW_NEW_SOURCES);
        assert_eq!(6, IGMPV3_BLOCK_OLD_SOURCES);
    }

    proptest! {
        #[test]
        fn new(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            assert_eq!(
                Igmpv3GroupRecordHeader {
                    record_type,
                    aux_data_len,
                    number_of_sources,
                    multicast_address,
                },
                Igmpv3GroupRecordHeader::new(record_type, aux_data_len, number_of_sources, multicast_address)
            );
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let nos_be = number_of_sources.to_be_bytes();
            let mut bytes = vec![
                record_type,
                aux_data_len,
                nos_be[0],
                nos_be[1],
                multicast_address[0],
                multicast_address[1],
                multicast_address[2],
                multicast_address[3],
            ];
            bytes.extend_from_slice(&suffix);

            let (actual, rest) = Igmpv3GroupRecordHeader::from_slice(&bytes).unwrap();
            assert_eq!(
                Igmpv3GroupRecordHeader {
                    record_type,
                    aux_data_len,
                    number_of_sources,
                    multicast_address,
                },
                actual
            );
            assert_eq!(suffix.as_slice(), rest);

            for bad_len in 0..Igmpv3GroupRecordHeader::LEN {
                assert_eq!(
                    Igmpv3GroupRecordHeader::from_slice(&bytes[..bad_len]),
                    Err(LenError {
                        required_len: Igmpv3GroupRecordHeader::LEN,
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
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let nos_be = number_of_sources.to_be_bytes();
            let bytes = [
                record_type,
                aux_data_len,
                nos_be[0],
                nos_be[1],
                multicast_address[0],
                multicast_address[1],
                multicast_address[2],
                multicast_address[3],
            ];

            assert_eq!(
                Igmpv3GroupRecordHeader {
                    record_type,
                    aux_data_len,
                    number_of_sources,
                    multicast_address,
                },
                Igmpv3GroupRecordHeader::from_bytes(bytes)
            );
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn read(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let input = Igmpv3GroupRecordHeader {
                record_type,
                aux_data_len,
                number_of_sources,
                multicast_address,
            };
            let mut bytes = input.to_bytes().to_vec();
            bytes.extend_from_slice(&suffix);

            let mut cursor = Cursor::new(&bytes);
            let actual = Igmpv3GroupRecordHeader::read(&mut cursor).unwrap();
            assert_eq!(input, actual);
            assert_eq!(Igmpv3GroupRecordHeader::LEN as u64, cursor.position());

            for bad_len in 0..Igmpv3GroupRecordHeader::LEN {
                let mut c = Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv3GroupRecordHeader::read(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let input = Igmpv3GroupRecordHeader {
                record_type,
                aux_data_len,
                number_of_sources,
                multicast_address,
            };

            let mut out = Vec::new();
            input.write(&mut out).unwrap();
            assert_eq!(input.to_bytes().as_slice(), out.as_slice());

            for bad_len in 0..Igmpv3GroupRecordHeader::LEN {
                let mut buf = [0u8; Igmpv3GroupRecordHeader::LEN];
                let mut c = Cursor::new(&mut buf[..bad_len]);
                assert!(input.write(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let input = Igmpv3GroupRecordHeader::new(record_type, aux_data_len, number_of_sources, multicast_address);
            assert_eq!(Igmpv3GroupRecordHeader::LEN, input.header_len());
        }
    }

    #[test]
    fn record_len() {
        let h = Igmpv3GroupRecordHeader::new(1, 0, 0, [0; 4]);
        assert_eq!(8, h.record_len());

        let h = Igmpv3GroupRecordHeader::new(1, 0, 3, [0; 4]);
        assert_eq!(8 + 12, h.record_len());

        let h = Igmpv3GroupRecordHeader::new(1, 2, 3, [0; 4]);
        assert_eq!(8 + 12 + 8, h.record_len());
    }

    proptest! {
        #[test]
        fn to_bytes(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let input = Igmpv3GroupRecordHeader::new(record_type, aux_data_len, number_of_sources, multicast_address);
            let nos_be = number_of_sources.to_be_bytes();
            assert_eq!(
                [
                    record_type,
                    aux_data_len,
                    nos_be[0],
                    nos_be[1],
                    multicast_address[0],
                    multicast_address[1],
                    multicast_address[2],
                    multicast_address[3],
                ],
                input.to_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let input = Igmpv3GroupRecordHeader::new(record_type, aux_data_len, number_of_sources, multicast_address);
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            number_of_sources in any::<u16>(),
            multicast_address in any::<[u8;4]>(),
        ) {
            let input = Igmpv3GroupRecordHeader::new(record_type, aux_data_len, number_of_sources, multicast_address);
            assert_eq!(
                format!(
                    "Igmpv3GroupRecordHeader {{ record_type: {}, aux_data_len: {}, number_of_sources: {}, multicast_address: {:?} }}",
                    record_type,
                    aux_data_len,
                    number_of_sources,
                    multicast_address,
                ),
                format!("{:?}", input)
            );
        }
    }

    #[test]
    fn parse_group_records_empty() {
        let (records, rest) = Igmpv3GroupRecordHeader::parse_records(&[], 0).unwrap();
        assert!(records.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_group_records_single_no_sources() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xEE]);

        let (records, rest) = Igmpv3GroupRecordHeader::parse_records(&bytes, 1).unwrap();
        assert_eq!(1, records.len());
        assert_eq!(rec, records[0]);
        assert_eq!(rest, &[0xEE]);
    }

    #[test]
    fn parse_group_records_with_sources() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 2, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        // 2 source addresses
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[10, 0, 0, 2]);

        let (records, rest) = Igmpv3GroupRecordHeader::parse_records(&bytes, 1).unwrap();
        assert_eq!(1, records.len());
        assert_eq!(rec, records[0]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_group_records_with_aux_data() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 1, 1, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        // 1 source address
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        // 1 word (4 bytes) of aux data
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let (records, rest) = Igmpv3GroupRecordHeader::parse_records(&bytes, 1).unwrap();
        assert_eq!(1, records.len());
        assert_eq!(rec, records[0]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_group_records_multiple() {
        let rec1 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 1, [224, 0, 0, 1]);
        let rec2 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 0, [224, 0, 0, 2]);

        let mut bytes = rec1.to_bytes().to_vec();
        bytes.extend_from_slice(&[10, 0, 0, 1]); // 1 source for rec1
        bytes.extend_from_slice(&rec2.to_bytes());

        let (records, rest) = Igmpv3GroupRecordHeader::parse_records(&bytes, 2).unwrap();
        assert_eq!(2, records.len());
        assert_eq!(rec1, records[0]);
        assert_eq!(rec2, records[1]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_group_records_too_short_header() {
        let bytes = [0x01, 0x00, 0x00]; // only 3 bytes
        assert!(Igmpv3GroupRecordHeader::parse_records(&bytes, 1).is_err());
    }

    #[test]
    fn parse_group_records_exceeds_max() {
        assert!(Igmpv3GroupRecordHeader::parse_records(&[], (IGMPV3_MAX_GROUP_RECORDS + 1) as u16).is_err());
    }

    #[test]
    fn parse_group_records_too_short_sources() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 2, [224, 0, 0, 1]);
        let mut bytes = rec.to_bytes().to_vec();
        // Only 1 source instead of 2
        bytes.extend_from_slice(&[10, 0, 0, 1]);

        assert!(Igmpv3GroupRecordHeader::parse_records(&bytes, 1).is_err());
    }
}
