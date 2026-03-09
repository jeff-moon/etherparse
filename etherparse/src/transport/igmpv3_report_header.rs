use arrayvec::ArrayVec;

use crate::igmp::*;
use crate::*;

/// IGMPv3 Membership Report message type.
pub const IGMPV3_TYPE_MEMBERSHIP_REPORT: u8 = 0x22;

/// An IGMPv3 Membership Report header (RFC 3376) including parsed
/// group records.
///
/// The fixed 8-byte header is followed by variable-length group records.
/// [`Igmpv3ReportHeader::from_slice`] parses both the fixed header and
/// the group record headers, skipping each record's source addresses
/// and auxiliary data.
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
    /// Number of group records declared in the header.
    pub number_of_group_records: u16,
    /// Parsed group record headers.
    pub group_records: ArrayVec<Igmpv3GroupRecordHeader, IGMPV3_MAX_GROUP_RECORDS>,
}

impl Igmpv3ReportHeader {
    /// Number of bytes/octets the fixed portion of an [`Igmpv3ReportHeader`]
    /// takes up in serialized form.
    pub const LEN: usize = 8;

    /// Constructs an [`Igmpv3ReportHeader`] with reserved fields & checksum
    /// set to 0 and an empty group records list.
    #[inline]
    pub fn new(igmp_type: u8, number_of_group_records: u16) -> Igmpv3ReportHeader {
        Igmpv3ReportHeader {
            igmp_type,
            reserved0: 0,
            checksum: 0,
            reserved1: 0,
            number_of_group_records,
            group_records: ArrayVec::new(),
        }
    }

    /// Creates an [`Igmpv3ReportHeader`] with a checksum calculated from the
    /// header values and the given raw group record bytes.
    #[inline]
    pub fn with_checksum(
        igmp_type: u8,
        number_of_group_records: u16,
        group_records_raw: &[u8],
    ) -> Igmpv3ReportHeader {
        let mut result = Igmpv3ReportHeader::new(igmp_type, number_of_group_records);
        result.update_checksum(group_records_raw);
        result
    }

    /// Reads the IGMPv3 report header and group records from a slice.
    ///
    /// Parses the fixed 8-byte header, then iterates through the declared
    /// group records (skipping each record's source addresses and auxiliary
    /// data). Returns the header with parsed group records and the
    /// remaining slice after all records.
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

        let igmp_type = slice[0];
        let reserved0 = slice[1];
        let checksum = u16::from_be_bytes([slice[2], slice[3]]);
        let reserved1 = u16::from_be_bytes([slice[4], slice[5]]);
        let number_of_group_records = u16::from_be_bytes([slice[6], slice[7]]);

        let (group_records, rest) =
            Igmpv3GroupRecordHeader::parse_records(&slice[Self::LEN..], number_of_group_records)?;

        Ok((
            Igmpv3ReportHeader {
                igmp_type,
                reserved0,
                checksum,
                reserved1,
                number_of_group_records,
                group_records,
            },
            rest,
        ))
    }

    /// Read an [`Igmpv3ReportHeader`] from a static sized byte array.
    ///
    /// Only the fixed 8-byte header is parsed; the group records list
    /// will be empty.
    #[inline]
    pub fn from_bytes(bytes: [u8; 8]) -> Igmpv3ReportHeader {
        Igmpv3ReportHeader {
            igmp_type: bytes[0],
            reserved0: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            reserved1: u16::from_be_bytes([bytes[4], bytes[5]]),
            number_of_group_records: u16::from_be_bytes([bytes[6], bytes[7]]),
            group_records: ArrayVec::new(),
        }
    }

    /// Reads the fixed 8-byte IGMPv3 report header from the given reader.
    ///
    /// Only the fixed header is read; the group records list will be empty.
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

    /// Length in bytes/octets of the fixed header.
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
    pub fn calc_checksum(&self, group_records_raw: &[u8]) -> u16 {
        let mut sum = checksum::Sum16BitWords::new()
            .add_2bytes([self.igmp_type, self.reserved0])
            .add_2bytes(self.reserved1.to_be_bytes())
            .add_2bytes(self.number_of_group_records.to_be_bytes());
        let mut i = 0;
        while i + 1 < group_records_raw.len() {
            sum = sum.add_2bytes([group_records_raw[i], group_records_raw[i + 1]]);
            i += 2;
        }
        if i < group_records_raw.len() {
            sum = sum.add_2bytes([group_records_raw[i], 0]);
        }
        sum.ones_complement().to_be()
    }

    /// Calculates and updates the checksum in the header.
    ///
    /// The IGMPv3 checksum covers the entire message including group records,
    /// so the raw bytes must be provided for a correct result.
    #[inline]
    pub fn update_checksum(&mut self, group_records_raw: &[u8]) {
        self.checksum = self.calc_checksum(group_records_raw);
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
        igmp::*,
        *,
    };
    use alloc::{format, vec, vec::Vec};
    use arrayvec::ArrayVec;
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
            let h = Igmpv3ReportHeader::new(igmp_type, number_of_group_records);
            assert_eq!(igmp_type, h.igmp_type);
            assert_eq!(0, h.reserved0);
            assert_eq!(0, h.checksum);
            assert_eq!(0, h.reserved1);
            assert_eq!(number_of_group_records, h.number_of_group_records);
            assert!(h.group_records.is_empty());
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            igmp_type in any::<u8>(),
            number_of_group_records in any::<u16>(),
            group_records_raw in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let header = Igmpv3ReportHeader::with_checksum(
                igmp_type, number_of_group_records, &group_records_raw,
            );
            assert_eq!(igmp_type, header.igmp_type);
            assert_eq!(0, header.reserved0);
            assert_eq!(0, header.reserved1);
            assert_eq!(number_of_group_records, header.number_of_group_records);
            assert_eq!(header.calc_checksum(&group_records_raw), header.checksum);
            assert!(header.group_records.is_empty());
        }
    }

    #[test]
    fn from_slice_no_records() {
        let h = Igmpv3ReportHeader::new(IGMPV3_TYPE_MEMBERSHIP_REPORT, 0);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xAA]);

        let (actual, rest) = Igmpv3ReportHeader::from_slice(&bytes).unwrap();
        assert_eq!(IGMPV3_TYPE_MEMBERSHIP_REPORT, actual.igmp_type);
        assert_eq!(0, actual.number_of_group_records);
        assert!(actual.group_records.is_empty());
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn from_slice_with_records() {
        let rec1 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 1, [224, 0, 0, 1]);
        let rec2 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 0, [224, 0, 0, 2]);

        let mut h = Igmpv3ReportHeader::new(IGMPV3_TYPE_MEMBERSHIP_REPORT, 2);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&rec1.to_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 1]); // 1 source for rec1
        bytes.extend_from_slice(&rec2.to_bytes());
        bytes.extend_from_slice(&[0xBB]); // trailing

        let (actual, rest) = Igmpv3ReportHeader::from_slice(&bytes).unwrap();
        assert_eq!(2, actual.number_of_group_records);
        assert_eq!(2, actual.group_records.len());
        assert_eq!(rec1, actual.group_records[0]);
        assert_eq!(rec2, actual.group_records[1]);
        assert_eq!(rest, &[0xBB]);
    }

    #[test]
    fn from_slice_too_short() {
        for bad_len in 0..Igmpv3ReportHeader::LEN {
            let bytes = vec![0u8; bad_len];
            assert_eq!(
                Igmpv3ReportHeader::from_slice(&bytes),
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

    #[test]
    fn from_slice_records_too_short() {
        // Declare 1 record but don't provide it
        let mut bytes = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(Igmpv3ReportHeader::from_slice(&bytes).is_err());
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

            let actual = Igmpv3ReportHeader::from_bytes(bytes);
            assert_eq!(igmp_type, actual.igmp_type);
            assert_eq!(reserved0, actual.reserved0);
            assert_eq!(checksum, actual.checksum);
            assert_eq!(reserved1, actual.reserved1);
            assert_eq!(number_of_group_records, actual.number_of_group_records);
            assert!(actual.group_records.is_empty());
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
            let input = Igmpv3ReportHeader::from_bytes([
                igmp_type,
                reserved0,
                checksum.to_be_bytes()[0],
                checksum.to_be_bytes()[1],
                reserved1.to_be_bytes()[0],
                reserved1.to_be_bytes()[1],
                number_of_group_records.to_be_bytes()[0],
                number_of_group_records.to_be_bytes()[1],
            ]);
            let mut bytes = input.to_bytes().to_vec();
            bytes.extend_from_slice(&suffix);

            let mut cursor = Cursor::new(&bytes);
            let actual = Igmpv3ReportHeader::read(&mut cursor).unwrap();
            assert_eq!(input.igmp_type, actual.igmp_type);
            assert_eq!(input.reserved0, actual.reserved0);
            assert_eq!(input.checksum, actual.checksum);
            assert_eq!(input.reserved1, actual.reserved1);
            assert_eq!(input.number_of_group_records, actual.number_of_group_records);
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
            let input = Igmpv3ReportHeader::from_bytes([
                igmp_type,
                reserved0,
                checksum.to_be_bytes()[0],
                checksum.to_be_bytes()[1],
                reserved1.to_be_bytes()[0],
                reserved1.to_be_bytes()[1],
                number_of_group_records.to_be_bytes()[0],
                number_of_group_records.to_be_bytes()[1],
            ]);

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

    #[test]
    fn header_len() {
        let input = Igmpv3ReportHeader::new(0x22, 0);
        assert_eq!(Igmpv3ReportHeader::LEN, input.header_len());
    }

    proptest! {
        #[test]
        fn calc_checksum(
            igmp_type in any::<u8>(),
            reserved0 in any::<u8>(),
            checksum in any::<u16>(),
            reserved1 in any::<u16>(),
            number_of_group_records in any::<u16>(),
            group_records_raw in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let input = Igmpv3ReportHeader::from_bytes([
                igmp_type,
                reserved0,
                checksum.to_be_bytes()[0],
                checksum.to_be_bytes()[1],
                reserved1.to_be_bytes()[0],
                reserved1.to_be_bytes()[1],
                number_of_group_records.to_be_bytes()[0],
                number_of_group_records.to_be_bytes()[1],
            ]);

            // Build the expected checksum manually over the full message.
            let mut msg = input.to_bytes().to_vec();
            msg[2] = 0;
            msg[3] = 0;
            msg.extend_from_slice(&group_records_raw);

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

            assert_eq!(expected, input.calc_checksum(&group_records_raw));
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
            group_records_raw in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let mut input = Igmpv3ReportHeader::from_bytes([
                igmp_type,
                reserved0,
                checksum.to_be_bytes()[0],
                checksum.to_be_bytes()[1],
                reserved1.to_be_bytes()[0],
                reserved1.to_be_bytes()[1],
                number_of_group_records.to_be_bytes()[0],
                number_of_group_records.to_be_bytes()[1],
            ]);
            input.update_checksum(&group_records_raw);
            assert_eq!(input.calc_checksum(&group_records_raw), input.checksum);
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
            let input = Igmpv3ReportHeader::from_bytes([
                igmp_type,
                reserved0,
                checksum.to_be_bytes()[0],
                checksum.to_be_bytes()[1],
                reserved1.to_be_bytes()[0],
                reserved1.to_be_bytes()[1],
                number_of_group_records.to_be_bytes()[0],
                number_of_group_records.to_be_bytes()[1],
            ]);
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

    #[test]
    fn clone_eq() {
        let input = Igmpv3ReportHeader::new(0x22, 0);
        assert_eq!(input, input.clone());
    }

    #[test]
    fn debug() {
        let input = Igmpv3ReportHeader::new(0x22, 0);
        let dbg = format!("{:?}", input);
        assert!(dbg.starts_with("Igmpv3ReportHeader"));
    }
}
