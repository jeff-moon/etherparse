use crate::*;

/// A slice containing an IGMP packet (v1, v2, or v3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IgmpSlice<'a> {
    /// IGMPv1 packet slice.
    V1(Igmpv1Slice<'a>),
    /// IGMPv2 packet slice.
    V2(Igmpv2Slice<'a>),
    /// IGMPv3 Membership Query packet slice.
    V3Query(Igmpv3QuerySlice<'a>),
    /// IGMPv3 Membership Report packet slice.
    V3Report(Igmpv3ReportSlice<'a>),
}

impl<'a> IgmpSlice<'a> {
    /// Reads an [`IgmpSlice`] from a slice, using the type byte and
    /// slice length to determine the IGMP version.
    ///
    /// For type `0x11` (Membership Query), the version is determined by
    /// slice length per RFC 3376: >= 12 bytes is IGMPv3, 8 bytes is
    /// IGMPv1 (if max response code is 0) or IGMPv2. The caller should
    /// trim the slice to the IGMP message boundary (e.g. from the IP
    /// payload length) before calling this method so that query version
    /// detection works correctly.
    ///
    /// Type dispatch:
    /// - `0x11`: Membership Query (v1, v2, or v3 based on length)
    /// - `0x12`: IGMPv1 Membership Report
    /// - `0x16`: IGMPv2 Membership Report
    /// - `0x17`: IGMPv2 Leave Group
    /// - `0x22`: IGMPv3 Membership Report
    /// - Other: parsed as IGMPv1 (the most general 8-byte format)
    pub fn from_slice(slice: &'a [u8]) -> Result<IgmpSlice<'a>, err::LenError> {
        if slice.is_empty() {
            return Err(err::LenError {
                required_len: 1,
                len: 0,
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            });
        }

        match slice[0] {
            IGMPV3_TYPE_MEMBERSHIP_REPORT => {
                Ok(IgmpSlice::V3Report(Igmpv3ReportSlice::from_slice(slice)?))
            }
            IGMPV1_TYPE_MEMBERSHIP_QUERY if slice.len() >= Igmpv3QueryHeader::LEN => {
                Ok(IgmpSlice::V3Query(Igmpv3QuerySlice::from_slice(slice)?))
            }
            IGMPV1_TYPE_MEMBERSHIP_QUERY if slice.len() >= 2 && slice[1] != 0 => {
                Ok(IgmpSlice::V2(Igmpv2Slice::from_slice(slice)?))
            }
            IGMPV1_TYPE_MEMBERSHIP_REPORT => {
                Ok(IgmpSlice::V1(Igmpv1Slice::from_slice(slice)?))
            }
            IGMPV2_TYPE_MEMBERSHIP_REPORT | IGMPV2_TYPE_LEAVE_GROUP => {
                Ok(IgmpSlice::V2(Igmpv2Slice::from_slice(slice)?))
            }
            _ => {
                // Default: parse as IGMPv1 (most general 8-byte format)
                Ok(IgmpSlice::V1(Igmpv1Slice::from_slice(slice)?))
            }
        }
    }

    /// Returns a reference to the [`Igmpv1Slice`] if this is a V1 variant.
    pub fn v1(&self) -> Option<&Igmpv1Slice<'a>> {
        if let IgmpSlice::V1(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv2Slice`] if this is a V2 variant.
    pub fn v2(&self) -> Option<&Igmpv2Slice<'a>> {
        if let IgmpSlice::V2(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv3QuerySlice`] if this is a V3Query variant.
    pub fn v3_query(&self) -> Option<&Igmpv3QuerySlice<'a>> {
        if let IgmpSlice::V3Query(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv3ReportSlice`] if this is a V3Report variant.
    pub fn v3_report(&self) -> Option<&Igmpv3ReportSlice<'a>> {
        if let IgmpSlice::V3Report(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Returns the size of the fixed header in bytes/octets.
    pub fn header_len(&self) -> usize {
        match self {
            IgmpSlice::V1(s) => s.header_len(),
            IgmpSlice::V2(s) => s.header_len(),
            IgmpSlice::V3Query(s) => s.header_len(),
            IgmpSlice::V3Report(s) => s.header_len(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::igmp::*;
    use crate::*;
    use alloc::{format, vec, vec::Vec};

    #[test]
    fn from_slice_empty() {
        assert_eq!(
            IgmpSlice::from_slice(&[]),
            Err(err::LenError {
                required_len: 1,
                len: 0,
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv3,
                layer_start_offset: 0,
            })
        );
    }

    #[test]
    fn from_slice_v1_membership_report() {
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_REPORT, [224, 0, 0, 1]);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xAA, 0xBB]);

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_some());
        assert_eq!(slice.v1().unwrap().igmp_type(), IGMPV1_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(slice.v1().unwrap().slice(), &bytes[..]);
    }

    #[test]
    fn from_slice_v1_query() {
        // Type 0x11 with max_resp_code == 0 and exactly 8 bytes => v1
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_QUERY, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_some());
    }

    #[test]
    fn from_slice_v2_query() {
        // Type 0x11 with max_resp_code != 0 and exactly 8 bytes => v2
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v2().is_some());
        assert_eq!(slice.v2().unwrap().max_resp_time(), 100);
    }

    #[test]
    fn from_slice_v2_membership_report() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_REPORT, 0, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v2().is_some());
    }

    #[test]
    fn from_slice_v2_leave_group() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_LEAVE_GROUP, 0, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v2().is_some());
    }

    #[test]
    fn from_slice_v3_query() {
        // Type 0x11 with >= 12 bytes => v3 query
        let h = Igmpv3QueryHeader::new(
            IGMPV3_TYPE_MEMBERSHIP_QUERY,
            100,
            [224, 0, 0, 1],
            0x0A,
            125,
            0,
        );
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xCC, 0xDD]);

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v3_query().is_some());
        assert_eq!(slice.v3_query().unwrap().max_resp_code(), 100);
        assert_eq!(slice.v3_query().unwrap().flags(), 0x0A);
    }

    #[test]
    fn from_slice_v3_report() {
        let rec = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let mut bytes: Vec<u8> = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        bytes.extend_from_slice(&rec.to_bytes());

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v3_report().is_some());
        assert_eq!(slice.v3_report().unwrap().number_of_group_records(), 1);

        // Verify the iterator works through the enum
        let records: Vec<_> = slice
            .v3_report()
            .unwrap()
            .group_record_slices()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(1, records.len());
        assert_eq!(rec, records[0].header());
    }

    #[test]
    fn from_slice_unknown_type() {
        // Unknown type => falls back to v1
        let bytes = [0xFF, 0x00, 0x00, 0x00, 224, 0, 0, 1];
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_some());
        assert_eq!(slice.v1().unwrap().igmp_type(), 0xFF);
    }

    #[test]
    fn from_slice_too_short() {
        // 4 bytes is too short for any IGMP header
        let bytes = [0x11, 0x00, 0x00, 0x00];
        assert!(IgmpSlice::from_slice(&bytes).is_err());
    }

    #[test]
    fn v1_accessors() {
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_QUERY, [224, 0, 0, 1]);
        let bytes = h.to_bytes();
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_some());
        assert!(slice.v2().is_none());
        assert!(slice.v3_query().is_none());
        assert!(slice.v3_report().is_none());
    }

    #[test]
    fn v2_accessors() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_REPORT, 0, [224, 0, 0, 1]);
        let bytes = h.to_bytes();
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_none());
        assert!(slice.v2().is_some());
        assert!(slice.v3_query().is_none());
        assert!(slice.v3_report().is_none());
    }

    #[test]
    fn v3_query_accessors() {
        let h = Igmpv3QueryHeader::new(IGMPV3_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1], 0, 0, 0);
        let bytes = h.to_bytes();
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_none());
        assert!(slice.v2().is_none());
        assert!(slice.v3_query().is_some());
        assert!(slice.v3_report().is_none());
    }

    #[test]
    fn v3_report_accessors() {
        let bytes = [0x22u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert!(slice.v1().is_none());
        assert!(slice.v2().is_none());
        assert!(slice.v3_query().is_none());
        assert!(slice.v3_report().is_some());
    }

    #[test]
    fn header_len() {
        // v1
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_REPORT, [0; 4]);
        let bytes = h.to_bytes();
        assert_eq!(Igmpv1Header::LEN, IgmpSlice::from_slice(&bytes).unwrap().header_len());

        // v2
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_REPORT, 0, [0; 4]);
        let bytes = h.to_bytes();
        assert_eq!(Igmpv2Header::LEN, IgmpSlice::from_slice(&bytes).unwrap().header_len());

        // v3 query
        let h = Igmpv3QueryHeader::new(0x11, 0, [0; 4], 0, 0, 0);
        let bytes = h.to_bytes();
        assert_eq!(Igmpv3QueryHeader::LEN, IgmpSlice::from_slice(&bytes).unwrap().header_len());

        // v3 report
        let bytes = [0x22u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Igmpv3ReportHeader::LEN, IgmpSlice::from_slice(&bytes).unwrap().header_len());
    }

    #[test]
    fn clone_eq() {
        let h = Igmpv1Header::new(0x12, [224, 0, 0, 1]);
        let bytes = h.to_bytes();
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice, slice.clone());
    }

    #[test]
    fn debug() {
        let h = Igmpv1Header::new(0x12, [0; 4]);
        let bytes = h.to_bytes();
        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        let dbg = format!("{:?}", slice);
        assert!(dbg.starts_with("V1("));
    }
}
