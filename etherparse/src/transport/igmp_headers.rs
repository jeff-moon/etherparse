use crate::*;

/// Headers of an IGMP packet (v1, v2, or v3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgmpHeaders {
    /// IGMPv1 header.
    V1(Igmpv1Header),
    /// IGMPv2 header.
    V2(Igmpv2Header),
    /// IGMPv3 Membership Query header.
    V3Query(Igmpv3QueryHeader),
    /// IGMPv3 Membership Report header.
    V3Report(Igmpv3ReportHeader),
}

impl IgmpHeaders {
    /// Reads an [`IgmpHeaders`] from a slice, using the type byte and
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
    pub fn from_slice(slice: &[u8]) -> Result<(IgmpHeaders, &[u8]), err::LenError> {
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
                let (h, rest) = Igmpv3ReportHeader::from_slice(slice)?;
                Ok((IgmpHeaders::V3Report(h), rest))
            }
            IGMPV1_TYPE_MEMBERSHIP_QUERY if slice.len() >= Igmpv3QueryHeader::LEN => {
                let (h, rest) = Igmpv3QueryHeader::from_slice(slice)?;
                Ok((IgmpHeaders::V3Query(h), rest))
            }
            IGMPV1_TYPE_MEMBERSHIP_QUERY if slice.len() >= 2 && slice[1] != 0 => {
                let (h, rest) = Igmpv2Header::from_slice(slice)?;
                Ok((IgmpHeaders::V2(h), rest))
            }
            IGMPV1_TYPE_MEMBERSHIP_REPORT => {
                let (h, rest) = Igmpv1Header::from_slice(slice)?;
                Ok((IgmpHeaders::V1(h), rest))
            }
            IGMPV2_TYPE_MEMBERSHIP_REPORT | IGMPV2_TYPE_LEAVE_GROUP => {
                let (h, rest) = Igmpv2Header::from_slice(slice)?;
                Ok((IgmpHeaders::V2(h), rest))
            }
            _ => {
                // Default: parse as IGMPv1 (most general 8-byte format)
                let (h, rest) = Igmpv1Header::from_slice(slice)?;
                Ok((IgmpHeaders::V1(h), rest))
            }
        }
    }

    /// Returns a reference to the [`Igmpv1Header`] if this is a V1 variant.
    pub fn v1(&self) -> Option<&Igmpv1Header> {
        if let IgmpHeaders::V1(header) = self {
            Some(header)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv2Header`] if this is a V2 variant.
    pub fn v2(&self) -> Option<&Igmpv2Header> {
        if let IgmpHeaders::V2(header) = self {
            Some(header)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv3QueryHeader`] if this is a V3Query variant.
    pub fn v3_query(&self) -> Option<&Igmpv3QueryHeader> {
        if let IgmpHeaders::V3Query(header) = self {
            Some(header)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Igmpv3ReportHeader`] if this is a V3Report variant.
    pub fn v3_report(&self) -> Option<&Igmpv3ReportHeader> {
        if let IgmpHeaders::V3Report(header) = self {
            Some(header)
        } else {
            None
        }
    }

    /// Returns the size of the header in bytes/octets when serialized.
    pub fn header_len(&self) -> usize {
        match self {
            IgmpHeaders::V1(h) => h.header_len(),
            IgmpHeaders::V2(h) => h.header_len(),
            IgmpHeaders::V3Query(h) => h.header_len(),
            IgmpHeaders::V3Report(h) => h.header_len(),
        }
    }

    /// Write the IGMP header to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        match self {
            IgmpHeaders::V1(h) => h.write(writer),
            IgmpHeaders::V2(h) => h.write(writer),
            IgmpHeaders::V3Query(h) => h.write(writer),
            IgmpHeaders::V3Report(h) => h.write(writer),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;
    #[cfg(feature = "std")]
    use std::io::Cursor;

    #[test]
    fn from_slice_empty() {
        assert_eq!(
            IgmpHeaders::from_slice(&[]),
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

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert_eq!(headers.v1().unwrap().igmp_type, IGMPV1_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(rest, &[0xAA, 0xBB]);
    }

    #[test]
    fn from_slice_v1_query() {
        // Type 0x11 with max_resp_time == 0 and exactly 8 bytes => v1
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_QUERY, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v1().is_some());
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_v2_query() {
        // Type 0x11 with max_resp_time != 0 and exactly 8 bytes => v2
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v2().is_some());
        assert_eq!(headers.v2().unwrap().max_resp_time, 100);
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_v2_membership_report() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_REPORT, 0, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v2().is_some());
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_v2_leave_group() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_LEAVE_GROUP, 0, [224, 0, 0, 1]);
        let bytes = h.to_bytes();

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v2().is_some());
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_v3_query() {
        // Type 0x11 with >= 12 bytes => v3 query
        let h = Igmpv3QueryHeader::new(IGMPV3_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1], 0x0A, 125, 0);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&[0xCC, 0xDD]);

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v3_query().is_some());
        assert_eq!(headers.v3_query().unwrap().max_resp_code, 100);
        assert_eq!(headers.v3_query().unwrap().flags, 0x0A);
        assert_eq!(rest, &[0xCC, 0xDD]);
    }

    #[test]
    fn from_slice_v3_report() {
        use crate::igmp::*;

        let rec1 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_INCLUDE, 0, 0, [224, 0, 0, 1]);
        let rec2 = Igmpv3GroupRecordHeader::new(IGMPV3_MODE_IS_EXCLUDE, 0, 0, [224, 0, 0, 2]);

        let h = Igmpv3ReportHeader::new(IGMPV3_TYPE_MEMBERSHIP_REPORT, 2);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&rec1.to_bytes());
        bytes.extend_from_slice(&rec2.to_bytes());
        bytes.extend_from_slice(&[0xEE]);

        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v3_report().is_some());
        let report = headers.v3_report().unwrap();
        assert_eq!(2, report.number_of_group_records);
        assert_eq!(2, report.group_records.len());
        assert_eq!(rec1, report.group_records[0]);
        assert_eq!(rec2, report.group_records[1]);
        assert_eq!(rest, &[0xEE]);
    }

    #[test]
    fn from_slice_unknown_type() {
        // Unknown type => falls back to v1
        let bytes = [0xFF, 0x00, 0x00, 0x00, 224, 0, 0, 1];
        let (headers, rest) = IgmpHeaders::from_slice(&bytes).unwrap();
        assert!(headers.v1().is_some());
        assert_eq!(headers.v1().unwrap().igmp_type, 0xFF);
        assert!(rest.is_empty());
    }

    #[test]
    fn from_slice_too_short() {
        // 4 bytes is too short for any IGMP header
        let bytes = [0x11, 0x00, 0x00, 0x00];
        assert!(IgmpHeaders::from_slice(&bytes).is_err());
    }

    #[test]
    fn v1_accessors() {
        let h = Igmpv1Header::new(IGMPV1_TYPE_MEMBERSHIP_QUERY, [224, 0, 0, 1]);
        let headers = IgmpHeaders::V1(h.clone());
        assert_eq!(Some(&h), headers.v1());
        assert_eq!(None, headers.v2());
        assert_eq!(None, headers.v3_query());
        assert_eq!(None, headers.v3_report());
    }

    #[test]
    fn v2_accessors() {
        let h = Igmpv2Header::new(IGMPV2_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1]);
        let headers = IgmpHeaders::V2(h.clone());
        assert_eq!(None, headers.v1());
        assert_eq!(Some(&h), headers.v2());
        assert_eq!(None, headers.v3_query());
        assert_eq!(None, headers.v3_report());
    }

    #[test]
    fn v3_query_accessors() {
        let h = Igmpv3QueryHeader::new(IGMPV3_TYPE_MEMBERSHIP_QUERY, 100, [224, 0, 0, 1], 0, 0, 0);
        let headers = IgmpHeaders::V3Query(h.clone());
        assert_eq!(None, headers.v1());
        assert_eq!(None, headers.v2());
        assert_eq!(Some(&h), headers.v3_query());
        assert_eq!(None, headers.v3_report());
    }

    #[test]
    fn v3_report_accessors() {
        let h = Igmpv3ReportHeader::new(IGMPV3_TYPE_MEMBERSHIP_REPORT, 0);
        let headers = IgmpHeaders::V3Report(h.clone());
        assert_eq!(None, headers.v1());
        assert_eq!(None, headers.v2());
        assert_eq!(None, headers.v3_query());
        assert_eq!(Some(&h), headers.v3_report());
    }

    #[test]
    fn header_len() {
        let v1 = IgmpHeaders::V1(Igmpv1Header::new(0x11, [0; 4]));
        assert_eq!(Igmpv1Header::LEN, v1.header_len());

        let v2 = IgmpHeaders::V2(Igmpv2Header::new(0x11, 0, [0; 4]));
        assert_eq!(Igmpv2Header::LEN, v2.header_len());

        let v3q = IgmpHeaders::V3Query(Igmpv3QueryHeader::new(0x11, 0, [0; 4], 0, 0, 0));
        assert_eq!(Igmpv3QueryHeader::LEN, v3q.header_len());

        let v3r = IgmpHeaders::V3Report(Igmpv3ReportHeader::new(0x22, 0));
        assert_eq!(Igmpv3ReportHeader::LEN, v3r.header_len());
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write_v1(igmp_type in any::<u8>(), group_address in any::<[u8;4]>()) {
            let h = Igmpv1Header::new(igmp_type, group_address);
            let headers = IgmpHeaders::V1(h.clone());

            let mut out = Vec::new();
            headers.write(&mut out).unwrap();
            assert_eq!(h.to_bytes().as_slice(), out.as_slice());
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write_v2(igmp_type in any::<u8>(), max_resp_time in any::<u8>(), group_address in any::<[u8;4]>()) {
            let h = Igmpv2Header::new(igmp_type, max_resp_time, group_address);
            let headers = IgmpHeaders::V2(h.clone());

            let mut out = Vec::new();
            headers.write(&mut out).unwrap();
            assert_eq!(h.to_bytes().as_slice(), out.as_slice());
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write_v3_query(
            igmp_type in any::<u8>(),
            max_resp_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            flags in any::<u8>(),
            qqic in any::<u8>(),
            number_of_sources in any::<u16>(),
        ) {
            let h = Igmpv3QueryHeader::new(igmp_type, max_resp_code, group_address, flags, qqic, number_of_sources);
            let headers = IgmpHeaders::V3Query(h.clone());

            let mut out = Vec::new();
            headers.write(&mut out).unwrap();
            assert_eq!(h.to_bytes().as_slice(), out.as_slice());
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write_v3_report(
            igmp_type in any::<u8>(),
            number_of_group_records in any::<u16>(),
        ) {
            let h = Igmpv3ReportHeader::new(igmp_type, number_of_group_records);
            let headers = IgmpHeaders::V3Report(h.clone());

            let mut out = Vec::new();
            headers.write(&mut out).unwrap();
            assert_eq!(h.to_bytes().as_slice(), out.as_slice());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn write_error() {
        let headers = IgmpHeaders::V1(Igmpv1Header::new(0x11, [0; 4]));
        let mut buf = [0u8; 4];
        let mut c = Cursor::new(&mut buf[..]);
        assert!(headers.write(&mut c).is_err());
    }

    #[test]
    fn clone_eq() {
        let headers = IgmpHeaders::V1(Igmpv1Header::new(0x11, [224, 0, 0, 1]));
        assert_eq!(headers, headers.clone());
    }

    #[test]
    fn debug() {
        let h = Igmpv1Header::new(0x11, [0; 4]);
        let headers = IgmpHeaders::V1(h.clone());
        let dbg = format!("{:?}", headers);
        assert!(dbg.starts_with("V1("));
    }
}
