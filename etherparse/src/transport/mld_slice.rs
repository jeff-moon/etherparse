use crate::{mld::*, *};

/// A zero-copy slice of an MLD (Multicast Listener Discovery) message,
/// decoded into one variant per message type.
///
/// MLD is carried inside ICMPv6, so the slice passed to
/// [`MldSlice::from_slice`] must start at the ICMPv6 header (the "Type"
/// byte is the first byte of the slice).
///
/// Match on the variant to get typed, compile-time-checked access to the
/// message specific accessors (e.g. `multicast_address_records` is only
/// reachable on [`MldSlice::MulticastListenerReportV2`]).
///
/// # Important: Caller must trim to the MLD message length
///
/// For type `130` "Multicast Listener Query" messages, the MLD version is
/// determined by message length per
/// [RFC 3810 §8.1](https://datatracker.ietf.org/doc/html/rfc3810#section-8.1):
///
/// * MLDv1 Query: length = 24 octets
/// * MLDv2 Query: length >= 28 octets
///
/// The caller **must** trim the input slice to the exact MLD message
/// boundary (typically derived from the IPv6 payload length minus any
/// extension headers) before calling [`MldSlice::from_slice`]. If extra
/// trailing bytes are present, a query may be misidentified as MLDv2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MldSlice<'a> {
    /// Multicast Listener Query message (MLDv1, type `130`, 24 octets).
    MulticastListenerQuery(MldQuerySlice<'a>),

    /// Multicast Listener Query message (MLDv2, type `130`, >= 28 octets)
    /// with sources.
    MulticastListenerQueryWithSources(MldQueryWithSourcesSlice<'a>),

    /// Multicast Listener Report message (MLDv1, type `131`).
    MulticastListenerReport(MldReportSlice<'a>),

    /// Multicast Listener Done message (MLDv1, type `132`).
    MulticastListenerDone(MldDoneSlice<'a>),

    /// Multicast Listener Report message (MLDv2, type `143`) with
    /// multicast address records.
    MulticastListenerReportV2(MldReportV2Slice<'a>),

    /// Unknown type of MLD message.
    Unknown(MldUnknownSlice<'a>),
}

impl<'a> MldSlice<'a> {
    /// Creates a slice containing an MLD message.
    ///
    /// # Example
    ///
    /// ```
    /// use etherparse::{MldSlice, mld::MulticastAddressRecordType};
    ///
    /// // an MLDv2 "Multicast Listener Report" (ICMPv6 type 143) with
    /// // a single "MODE_IS_EXCLUDE" record for ff02::1
    /// let bytes = [
    ///     143, 0, 0, 0, // type, reserved & checksum
    ///     0, 0, 0, 1, // reserved & number of records
    ///     2, 0, 0, 0, // record type, aux data len & number of sources
    ///     0xff, 0x02, 0, 0, 0, 0, 0, 0, // multicast address
    ///     0, 0, 0, 0, 0, 0, 0, 1,
    /// ];
    ///
    /// match MldSlice::from_slice(&bytes).unwrap() {
    ///     MldSlice::MulticastListenerReportV2(report) => {
    ///         assert_eq!(report.num_of_records(), 1);
    ///         for record in report.multicast_address_records() {
    ///             let record = record.unwrap();
    ///             assert_eq!(
    ///                 record.record_type(),
    ///                 MulticastAddressRecordType::MODE_IS_EXCLUDE
    ///             );
    ///             assert_eq!(record.num_of_sources(), 0);
    ///         }
    ///     }
    ///     _ => panic!("expected an MLDv2 report"),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`] if the given
    /// slice is too small to contain the message indicated by its type
    /// byte:
    ///
    /// * Fewer than 8 bytes (the minimum for any ICMPv6 message).
    /// * Fewer than 24 bytes for a type `130`/`131`/`132` MLDv1 message.
    /// * A length of 25-27 bytes for a type `130` query (which is neither
    ///   a valid MLDv1 nor a valid MLDv2 query).
    /// * An MLDv2 query (type `130`, >= 28 bytes) that does not contain
    ///   all of its declared source addresses.
    pub fn from_slice(slice: &'a [u8]) -> Result<MldSlice<'a>, err::LenError> {
        // Ensure the slice is large enough for the minimum ICMPv6 header.
        if slice.len() < MldUnknownHeader::LEN {
            return Err(err::LenError {
                required_len: MldUnknownHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        // SAFETY: length checked above to be >= MldUnknownHeader::LEN (8).
        let type_u8 = unsafe { *slice.get_unchecked(0) };
        Ok(match type_u8 {
            MLD_TYPE_MULTICAST_LISTENER_QUERY => {
                if slice.len() == MldV1Header::LEN {
                    // A query of exactly 24 bytes is an MLDv1 query.
                    // SAFETY: length is exactly MldV1Header::LEN (24).
                    MldSlice::MulticastListenerQuery(unsafe {
                        MldQuerySlice::from_slice_unchecked(slice)
                    })
                } else if slice.len() >= MldQueryWithSourcesHeader::LEN {
                    // A query of at least 28 bytes is an MLDv2 query.
                    // Validate that all declared source addresses (16 bytes
                    // each) are actually present in the payload.
                    // SAFETY: length checked above to be >= 28, so bytes 26..28 exist.
                    let num_of_sources =
                        usize::from(unsafe { get_unchecked_be_u16(slice.as_ptr().add(26)) });
                    let required_len = MldQueryWithSourcesHeader::LEN + num_of_sources * 16;
                    if slice.len() < required_len {
                        return Err(err::LenError {
                            required_len,
                            len: slice.len(),
                            len_source: LenSource::Slice,
                            layer: err::Layer::Mld,
                            layer_start_offset: 0,
                        });
                    }
                    // SAFETY: length checked to be >= MldQueryWithSourcesHeader::LEN
                    // (28) and to contain all declared source addresses.
                    MldSlice::MulticastListenerQueryWithSources(unsafe {
                        MldQueryWithSourcesSlice::from_slice_unchecked(slice)
                    })
                } else {
                    // A query shorter than 24 bytes, or with a length of
                    // 25-27 bytes, is neither a valid MLDv1 nor MLDv2 query.
                    return Err(err::LenError {
                        required_len: if slice.len() < MldV1Header::LEN {
                            MldV1Header::LEN
                        } else {
                            MldQueryWithSourcesHeader::LEN
                        },
                        len: slice.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
            }
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT => {
                if slice.len() < MldV1Header::LEN {
                    return Err(err::LenError {
                        required_len: MldV1Header::LEN,
                        len: slice.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
                // SAFETY: length checked above to be >= MldV1Header::LEN (24).
                MldSlice::MulticastListenerReport(unsafe {
                    MldReportSlice::from_slice_unchecked(slice)
                })
            }
            MLDV1_TYPE_MULTICAST_LISTENER_DONE => {
                if slice.len() < MldV1Header::LEN {
                    return Err(err::LenError {
                        required_len: MldV1Header::LEN,
                        len: slice.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
                // SAFETY: length checked above to be >= MldV1Header::LEN (24).
                MldSlice::MulticastListenerDone(unsafe {
                    MldDoneSlice::from_slice_unchecked(slice)
                })
            }
            // The multicast address records of a v2 report are variable
            // length and are NOT validated here. Use
            // `MldReportV2Slice::multicast_address_records` to iterate them;
            // the iterator reports length errors lazily.
            // SAFETY: length checked above to be >= 8.
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT => MldSlice::MulticastListenerReportV2(unsafe {
                MldReportV2Slice::from_slice_unchecked(slice)
            }),
            // SAFETY: length checked above to be >= 8.
            _ => MldSlice::Unknown(unsafe { MldUnknownSlice::from_slice_unchecked(slice) }),
        })
    }

    /// Number of bytes/octets the header of this message takes up.
    #[inline]
    pub fn header_len(&self) -> usize {
        match self {
            MldSlice::MulticastListenerQuery(_) => MldV1Header::LEN,
            MldSlice::MulticastListenerQueryWithSources(_) => MldQueryWithSourcesHeader::LEN,
            MldSlice::MulticastListenerReport(_) => MldV1Header::LEN,
            MldSlice::MulticastListenerDone(_) => MldV1Header::LEN,
            MldSlice::MulticastListenerReportV2(_) => MldReportV2Header::LEN,
            MldSlice::Unknown(_) => MldUnknownHeader::LEN,
        }
    }

    /// Returns the ICMPv6 "type" byte value of the MLD message.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY: from_slice guarantees at least 8 bytes.
        unsafe { *self.slice().get_unchecked(0) }
    }

    /// Returns the ICMPv6 "code" byte value of the MLD message.
    ///
    /// This is sent as zero and ignored by receivers in all MLD message
    /// types.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY: from_slice guarantees at least 8 bytes.
        unsafe { *self.slice().get_unchecked(1) }
    }

    /// Returns the "checksum" value in the ICMPv6 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: from_slice guarantees at least 8 bytes.
        unsafe { get_unchecked_be_u16(self.slice().as_ptr().add(2)) }
    }

    /// Returns a slice to the bytes not covered by the header.
    ///
    /// The contents of the payload depend on the message type:
    ///
    /// | Message Type | Payload Content |
    /// |---|---|
    /// | [`MldSlice::MulticastListenerQuery`] (v1) | Nothing (empty) |
    /// | [`MldSlice::MulticastListenerQueryWithSources`] (v2) | Source Address list |
    /// | [`MldSlice::MulticastListenerReport`] (v1) | Nothing (empty, unless trailing data) |
    /// | [`MldSlice::MulticastListenerDone`] (v1) | Nothing (empty, unless trailing data) |
    /// | [`MldSlice::MulticastListenerReportV2`] (v2) | Multicast Address Records |
    /// | [`MldSlice::Unknown`] | Everything after the 8th byte |
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match self {
            MldSlice::MulticastListenerQuery(s) => s.payload(),
            MldSlice::MulticastListenerQueryWithSources(s) => s.payload(),
            MldSlice::MulticastListenerReport(s) => s.payload(),
            MldSlice::MulticastListenerDone(s) => s.payload(),
            MldSlice::MulticastListenerReportV2(s) => s.payload(),
            MldSlice::Unknown(s) => s.payload(),
        }
    }

    /// Returns the slice containing the entire MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        match self {
            MldSlice::MulticastListenerQuery(s) => s.slice(),
            MldSlice::MulticastListenerQueryWithSources(s) => s.slice(),
            MldSlice::MulticastListenerReport(s) => s.slice(),
            MldSlice::MulticastListenerDone(s) => s.slice(),
            MldSlice::MulticastListenerReportV2(s) => s.slice(),
            MldSlice::Unknown(s) => s.slice(),
        }
    }

    /// Verifies the checksum of the MLD message.
    ///
    /// MLD is carried inside ICMPv6, so (in contrast to
    /// [`crate::IgmpSlice::is_checksum_valid`]) the checksum is computed
    /// over an IPv6 pseudo header followed by the whole ICMPv6 message.
    /// This is why the source & destination IPv6 addresses are required
    /// here. See
    /// [RFC 4443 section 2.3](https://datatracker.ietf.org/doc/html/rfc4443#section-2.3).
    ///
    /// Returns `true` if the checksum stored in the message matches the
    /// one calculated over the pseudo header and the entire slice.
    pub fn is_checksum_valid(&self, source_ip: [u8; 16], destination_ip: [u8; 16]) -> bool {
        checksum::Sum16BitWords::new()
            .add_16bytes(source_ip)
            .add_16bytes(destination_ip)
            .add_4bytes((self.slice().len() as u32).to_be_bytes())
            .add_2bytes([0, ip_number::IPV6_ICMP.0])
            // NOTE: From RFC 1071
            // To check a checksum, the 1's complement sum is computed over the
            // same set of octets, including the checksum field.  If the result
            // is all 1 bits (-0 in 1's complement arithmetic), the check
            // succeeds.
            .add_slice(self.slice())
            .ones_complement()
            == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    /// Builds a 24 byte MLDv1 message of the given type.
    fn build_v1(mld_type: u8, max_response_delay: u16, multicast_address: [u8; 16]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MldV1Header::LEN);
        bytes.push(mld_type);
        bytes.push(0); // code
        bytes.extend_from_slice(&[0, 0]); // checksum
        bytes.extend_from_slice(&max_response_delay.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]); // reserved
        bytes.extend_from_slice(&multicast_address);
        bytes
    }

    /// Builds an MLDv2 query with the given source addresses.
    fn build_v2_query(multicast_address: [u8; 16], sources: &[[u8; 16]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(MLD_TYPE_MULTICAST_LISTENER_QUERY);
        bytes.push(0); // code
        bytes.extend_from_slice(&[0, 0]); // checksum
        bytes.extend_from_slice(&1000u16.to_be_bytes()); // max resp code
        bytes.extend_from_slice(&[0, 0]); // reserved
        bytes.extend_from_slice(&multicast_address);
        bytes.push(0b0000_1010); // resv=0, s_flag=1, qrv=2
        bytes.push(0x7F); // qqic
        bytes.extend_from_slice(&(sources.len() as u16).to_be_bytes());
        for source in sources {
            bytes.extend_from_slice(source);
        }
        bytes
    }

    /// Builds an MLDv2 report header with the given record count & payload.
    fn build_v2_report(num_of_records: u16, records: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(MLDV2_TYPE_MULTICAST_LISTENER_REPORT);
        bytes.push(0); // reserved
        bytes.extend_from_slice(&[0, 0]); // checksum
        bytes.extend_from_slice(&[0, 0]); // reserved
        bytes.extend_from_slice(&num_of_records.to_be_bytes());
        bytes.extend_from_slice(records);
        bytes
    }

    /// Builds a multicast address record.
    fn build_record(
        record_type: u8,
        multicast_address: [u8; 16],
        sources: &[[u8; 16]],
        aux_data_words: &[[u8; 4]],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(record_type);
        bytes.push(aux_data_words.len() as u8);
        bytes.extend_from_slice(&(sources.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&multicast_address);
        for source in sources {
            bytes.extend_from_slice(source);
        }
        for word in aux_data_words {
            bytes.extend_from_slice(word);
        }
        bytes
    }

    /// Calculates the ICMPv6 checksum bytes for `bytes` as they appear on
    /// the wire.
    ///
    /// Note that `Sum16BitWords` accumulates in native endianness (it uses
    /// `from_ne_bytes` internally), so `ones_complement()` returns a value
    /// whose *native* byte representation is the wire order. This is why
    /// `to_ne_bytes` (and not `to_be_bytes`) is correct here, on both little
    /// and big endian systems.
    fn calc_checksum_bytes(bytes: &[u8], source_ip: [u8; 16], destination_ip: [u8; 16]) -> [u8; 2] {
        checksum::Sum16BitWords::new()
            .add_16bytes(source_ip)
            .add_16bytes(destination_ip)
            .add_4bytes((bytes.len() as u32).to_be_bytes())
            .add_2bytes([0, ip_number::IPV6_ICMP.0])
            .add_slice(bytes)
            .ones_complement()
            .to_ne_bytes()
    }

    #[test]
    fn from_slice_too_small() {
        for bad_len in 0..MldUnknownHeader::LEN {
            let bytes = [0u8; MldUnknownHeader::LEN];
            assert_eq!(
                MldSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: MldUnknownHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_query_invalid_length() {
        // 25-27 bytes with type 130 is neither a valid v1 nor v2 query
        for bad_len in 25..28 {
            let mut bytes = [0u8; 28];
            bytes[0] = MLD_TYPE_MULTICAST_LISTENER_QUERY;
            assert_eq!(
                MldSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: MldQueryWithSourcesHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }

        // 8-23 bytes with type 130 is too short for a v1 query
        for bad_len in MldUnknownHeader::LEN..MldV1Header::LEN {
            let mut bytes = [0u8; 24];
            bytes[0] = MLD_TYPE_MULTICAST_LISTENER_QUERY;
            assert_eq!(
                MldSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: MldV1Header::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_v1_report_and_done_too_small() {
        for mld_type in [
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
            MLDV1_TYPE_MULTICAST_LISTENER_DONE,
        ] {
            for bad_len in MldUnknownHeader::LEN..MldV1Header::LEN {
                let mut bytes = [0u8; 24];
                bytes[0] = mld_type;
                assert_eq!(
                    MldSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                    err::LenError {
                        required_len: MldV1Header::LEN,
                        len: bad_len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    }
                );
            }
        }
    }

    #[test]
    fn from_slice_v1_query() {
        let addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bytes = build_v1(MLD_TYPE_MULTICAST_LISTENER_QUERY, 10000, addr);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), MLD_TYPE_MULTICAST_LISTENER_QUERY);
        assert_eq!(slice.code_u8(), 0);
        assert_eq!(slice.header_len(), MldV1Header::LEN);
        assert_eq!(slice.payload(), &[]);
        assert_eq!(slice.slice(), &bytes);

        match &slice {
            MldSlice::MulticastListenerQuery(q) => {
                assert_eq!(q.max_response_delay(), 10000);
                assert_eq!(q.multicast_address().octets, addr);
                assert_eq!(q.reserved(), [0, 0]);
                assert_eq!(q.code_u8(), 0);
                assert_eq!(q.checksum(), 0);
                assert_eq!(
                    q.to_header(),
                    MldV1Header {
                        max_response_delay: 10000,
                        multicast_address: MulticastAddress::new(addr),
                    }
                );
            }
            _ => panic!("expected MulticastListenerQuery"),
        }
    }

    #[test]
    fn from_slice_v1_report() {
        let addr = [0xff; 16];
        let bytes = build_v1(MLDV1_TYPE_MULTICAST_LISTENER_REPORT, 0, addr);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), MLDV1_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(slice.header_len(), MldV1Header::LEN);

        match &slice {
            MldSlice::MulticastListenerReport(r) => {
                assert_eq!(r.multicast_address().octets, addr);
                assert_eq!(r.max_response_delay(), 0);
                assert_eq!(r.reserved(), [0, 0]);
                assert_eq!(r.code_u8(), 0);
                assert_eq!(r.checksum(), 0);
                assert_eq!(r.payload(), &[]);
                assert_eq!(
                    r.to_header(),
                    MldV1Header {
                        max_response_delay: 0,
                        multicast_address: MulticastAddress::new(addr),
                    }
                );
            }
            _ => panic!("expected MulticastListenerReport"),
        }
    }

    #[test]
    fn from_slice_v1_done() {
        let addr = [0xab; 16];
        let bytes = build_v1(MLDV1_TYPE_MULTICAST_LISTENER_DONE, 0, addr);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), MLDV1_TYPE_MULTICAST_LISTENER_DONE);
        assert_eq!(slice.header_len(), MldV1Header::LEN);

        match &slice {
            MldSlice::MulticastListenerDone(d) => {
                assert_eq!(d.multicast_address().octets, addr);
                assert_eq!(d.max_response_delay(), 0);
                assert_eq!(d.reserved(), [0, 0]);
                assert_eq!(d.code_u8(), 0);
                assert_eq!(d.checksum(), 0);
                assert_eq!(d.payload(), &[]);
                assert_eq!(
                    d.to_header(),
                    MldV1Header {
                        max_response_delay: 0,
                        multicast_address: MulticastAddress::new(addr),
                    }
                );
            }
            _ => panic!("expected MulticastListenerDone"),
        }
    }

    #[test]
    fn from_slice_v1_report_with_trailing_data() {
        // trailing bytes beyond the 24 byte header land in the payload
        let mut bytes = build_v1(MLDV1_TYPE_MULTICAST_LISTENER_REPORT, 0, [0; 16]);
        bytes.extend_from_slice(&[1, 2, 3]);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.payload(), &[1, 2, 3]);
    }

    #[test]
    fn from_slice_v2_query() {
        let addr = [0xff; 16];
        let sources = [[1u8; 16], [2u8; 16]];
        let bytes = build_v2_query(addr, &sources);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), MLD_TYPE_MULTICAST_LISTENER_QUERY);
        assert_eq!(slice.header_len(), MldQueryWithSourcesHeader::LEN);
        assert_eq!(slice.payload().len(), 32);

        match &slice {
            MldSlice::MulticastListenerQueryWithSources(q) => {
                assert_eq!(q.max_response_code(), MldMaxResponseCode(1000));
                assert_eq!(q.max_response_code().as_millis(), 1000);
                assert_eq!(q.multicast_address().octets, addr);
                assert_eq!(q.reserved(), [0, 0]);
                assert_eq!(q.code_u8(), 0);
                assert_eq!(q.checksum(), 0);
                assert_eq!(q.raw_byte_24(), 0b0000_1010);
                assert_eq!(q.resv(), 0);
                assert!(q.s_flag());
                assert_eq!(q.qrv().value(), 2);
                assert_eq!(q.qqic(), 0x7F);
                assert_eq!(q.num_of_sources(), 2);
                assert_eq!(q.source_addrs_bytes().len(), 32);
                assert_eq!(
                    q.source_addresses().collect::<Vec<_>>(),
                    vec![[1u8; 16], [2u8; 16]]
                );
                assert_eq!(
                    q.to_header(),
                    MldQueryWithSourcesHeader {
                        max_response_code: MldMaxResponseCode(1000),
                        multicast_address: MulticastAddress::new(addr),
                        raw_byte_24: 0b0000_1010,
                        qqic: 0x7F,
                        num_of_sources: 2,
                    }
                );
            }
            _ => panic!("expected MulticastListenerQueryWithSources"),
        }
    }

    #[test]
    fn from_slice_v2_query_no_sources() {
        // exactly 28 bytes, zero sources => still a v2 query
        let bytes = build_v2_query([0xff; 16], &[]);
        assert_eq!(bytes.len(), MldQueryWithSourcesHeader::LEN);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        match &slice {
            MldSlice::MulticastListenerQueryWithSources(q) => {
                assert_eq!(q.num_of_sources(), 0);
                assert_eq!(q.source_addrs_bytes(), &[]);
                assert_eq!(q.source_addresses().count(), 0);
            }
            _ => panic!("expected MulticastListenerQueryWithSources"),
        }
    }

    #[test]
    fn from_slice_v2_query_missing_sources() {
        // declares 3 sources but only provides 1
        let mut bytes = build_v2_query([0xff; 16], &[[1u8; 16]]);
        bytes[26..28].copy_from_slice(&3u16.to_be_bytes());

        assert_eq!(
            MldSlice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: MldQueryWithSourcesHeader::LEN + 3 * 16,
                len: bytes.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn from_slice_v2_report() {
        let record_a = build_record(
            MulticastAddressRecordType::MODE_IS_INCLUDE.0,
            [0xaa; 16],
            &[[1u8; 16]],
            &[],
        );
        let record_b = build_record(
            MulticastAddressRecordType::BLOCK_OLD_SOURCES.0,
            [0xbb; 16],
            &[],
            &[[9u8; 4]],
        );
        let mut records = record_a.clone();
        records.extend_from_slice(&record_b);
        let bytes = build_v2_report(2, &records);

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), MLDV2_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(slice.header_len(), MldReportV2Header::LEN);

        match &slice {
            MldSlice::MulticastListenerReportV2(r) => {
                assert_eq!(r.num_of_records(), 2);
                assert_eq!(r.reserved(), [0, 0]);
                assert_eq!(r.code_u8(), 0);
                assert_eq!(r.checksum(), 0);
                assert_eq!(
                    r.to_header(),
                    MldReportV2Header {
                        reserved: [0, 0],
                        num_of_records: 2,
                    }
                );

                let records: Vec<_> = r.multicast_address_records().map(|r| r.unwrap()).collect();
                assert_eq!(records.len(), 2);
                assert_eq!(
                    records[0].record_type(),
                    MulticastAddressRecordType::MODE_IS_INCLUDE
                );
                assert_eq!(records[0].multicast_address().octets, [0xaa; 16]);
                assert_eq!(
                    records[0].source_addresses().collect::<Vec<_>>(),
                    vec![[1u8; 16]]
                );
                assert_eq!(
                    records[1].record_type(),
                    MulticastAddressRecordType::BLOCK_OLD_SOURCES
                );
                assert_eq!(records[1].multicast_address().octets, [0xbb; 16]);
                assert_eq!(records[1].aux_data(), &[9, 9, 9, 9]);
            }
            _ => panic!("expected MulticastListenerReportV2"),
        }
    }

    #[test]
    fn from_slice_v2_report_records_validated_lazily() {
        // A v2 report claiming 5 records but containing none is accepted by
        // from_slice; the error surfaces during iteration.
        let bytes = build_v2_report(5, &[]);
        let slice = MldSlice::from_slice(&bytes).unwrap();

        match &slice {
            MldSlice::MulticastListenerReportV2(r) => {
                assert_eq!(r.num_of_records(), 5);
                let mut iter = r.multicast_address_records();
                assert!(iter.next().unwrap().is_err());
                assert!(iter.next().is_none());
            }
            _ => panic!("expected MulticastListenerReportV2"),
        }
    }

    #[test]
    fn from_slice_unknown() {
        let mut bytes = [0u8; 12];
        bytes[0] = 200; // unknown type
        bytes[1] = 3; // code
        bytes[4] = 1;
        bytes[5] = 2;
        bytes[6] = 3;
        bytes[7] = 4;
        bytes[8] = 0xAA;

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), 200);
        assert_eq!(slice.code_u8(), 3);
        assert_eq!(slice.header_len(), MldUnknownHeader::LEN);

        match &slice {
            MldSlice::Unknown(u) => {
                assert_eq!(u.type_u8(), 200);
                assert_eq!(u.code_u8(), 3);
                assert_eq!(u.checksum(), 0);
                assert_eq!(u.raw_bytes_4_7(), [1, 2, 3, 4]);
                assert_eq!(u.payload(), &[0xAA, 0, 0, 0]);
                assert_eq!(
                    u.to_header(),
                    MldUnknownHeader {
                        mld_type: 200,
                        code: 3,
                        raw_bytes_4_7: [1, 2, 3, 4],
                    }
                );
            }
            _ => panic!("expected Unknown"),
        }
    }

    /// An MLDv1 query with trailing bytes gets misidentified as MLDv2,
    /// which is exactly what the `from_slice` docs warn about.
    #[test]
    fn from_slice_untrimmed_v1_query_is_misidentified() {
        let mut bytes = build_v1(MLD_TYPE_MULTICAST_LISTENER_QUERY, 10000, [0xff; 16]);
        bytes.extend_from_slice(&[0u8; 4]);
        assert_eq!(bytes.len(), MldQueryWithSourcesHeader::LEN);

        assert!(matches!(
            MldSlice::from_slice(&bytes).unwrap(),
            MldSlice::MulticastListenerQueryWithSources(_)
        ));
    }

    #[test]
    fn clone_eq_debug() {
        let bytes = build_v1(MLDV1_TYPE_MULTICAST_LISTENER_REPORT, 0, [0xff; 16]);
        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice, slice.clone());
        assert!(format!("{:?}", slice).contains("MulticastListenerReport"));
    }

    #[test]
    fn is_checksum_valid() {
        let source_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut bytes = build_v1(MLD_TYPE_MULTICAST_LISTENER_QUERY, 10000, destination_ip);

        // calculate & insert the correct checksum
        let checksum = calc_checksum_bytes(&bytes, source_ip, destination_ip);
        bytes[2] = checksum[0];
        bytes[3] = checksum[1];

        let slice = MldSlice::from_slice(&bytes).unwrap();
        assert!(slice.is_checksum_valid(source_ip, destination_ip));

        // a different destination must invalidate the checksum
        assert!(!slice.is_checksum_valid(source_ip, source_ip));
    }

    proptest! {
        /// Any 8+ byte slice must either parse or return a length error,
        /// never panic.
        #[test]
        fn from_slice_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..600)
        ) {
            let _ = MldSlice::from_slice(&bytes);
        }

        /// A corrupted byte must invalidate the checksum.
        #[test]
        fn is_checksum_valid_detects_corruption(
            source_ip in any::<[u8; 16]>(),
            destination_ip in any::<[u8; 16]>(),
            multicast_address in any::<[u8; 16]>(),
            max_response_delay in any::<u16>(),
            flip_byte in 0usize..24,
        ) {
            let mut bytes = build_v1(
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                max_response_delay,
                multicast_address,
            );
            let checksum = calc_checksum_bytes(&bytes, source_ip, destination_ip);
            bytes[2] = checksum[0];
            bytes[3] = checksum[1];

            prop_assert!(
                MldSlice::from_slice(&bytes)
                    .unwrap()
                    .is_checksum_valid(source_ip, destination_ip)
            );

            // corrupt one byte
            let mut corrupted = bytes.clone();
            corrupted[flip_byte] = !corrupted[flip_byte];
            // flipping the type byte can change which variant is parsed, but
            // the checksum must still be reported as invalid
            prop_assert_eq!(
                false,
                MldSlice::from_slice(&corrupted)
                    .unwrap()
                    .is_checksum_valid(source_ip, destination_ip)
            );
        }

        /// Round trip the source address list of a v2 query.
        #[test]
        fn v2_query_source_roundtrip(
            sources in proptest::collection::vec(any::<[u8; 16]>(), 0..16)
        ) {
            let bytes = build_v2_query([0xff; 16], &sources);
            let slice = MldSlice::from_slice(&bytes).unwrap();
            match slice {
                MldSlice::MulticastListenerQueryWithSources(q) => {
                    prop_assert_eq!(usize::from(q.num_of_sources()), sources.len());
                    prop_assert_eq!(q.source_addresses().collect::<Vec<_>>(), sources);
                }
                _ => panic!("expected MulticastListenerQueryWithSources"),
            }
        }
    }
}
