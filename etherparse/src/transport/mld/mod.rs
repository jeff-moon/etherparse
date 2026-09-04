mod max_response_code;
pub use max_response_code::*;

mod mld_done_slice;
pub use mld_done_slice::*;

mod mld_query_slice;
pub use mld_query_slice::*;

mod mld_query_with_sources_header;
pub use mld_query_with_sources_header::*;

mod mld_query_with_sources_slice;
pub use mld_query_with_sources_slice::*;

mod mld_report_slice;
pub use mld_report_slice::*;

mod mld_report_v2_header;
pub use mld_report_v2_header::*;

mod mld_report_v2_slice;
pub use mld_report_v2_slice::*;

mod mld_unknown_header;
pub use mld_unknown_header::*;

mod mld_unknown_slice;
pub use mld_unknown_slice::*;

mod mld_v1_header;
pub use mld_v1_header::*;

mod multicast_address;
pub use multicast_address::*;

mod multicast_address_record_header;
pub use multicast_address_record_header::*;

mod multicast_address_record_slice;
pub use multicast_address_record_slice::*;

/// "Multicast Listener Query" message type (same in MLDv1 & MLDv2).
///
/// Identical to [`crate::icmpv6::TYPE_MULTICAST_LISTENER_QUERY`].
pub const MLD_TYPE_MULTICAST_LISTENER_QUERY: u8 = 130;

/// MLDv1 "Multicast Listener Report" message type.
///
/// Identical to [`crate::icmpv6::TYPE_MULTICAST_LISTENER_REPORT`].
pub const MLDV1_TYPE_MULTICAST_LISTENER_REPORT: u8 = 131;

/// MLDv1 "Multicast Listener Done" message type.
///
/// Identical to [`crate::icmpv6::TYPE_MULTICAST_LISTENER_REDUCTION`].
pub const MLDV1_TYPE_MULTICAST_LISTENER_DONE: u8 = 132;

/// MLDv2 "Multicast Listener Report" message type.
///
/// Defined in
/// [RFC 3810 section 5.2](https://datatracker.ietf.org/doc/html/rfc3810#section-5.2).
pub const MLDV2_TYPE_MULTICAST_LISTENER_REPORT: u8 = 143;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(130, MLD_TYPE_MULTICAST_LISTENER_QUERY);
        assert_eq!(131, MLDV1_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(132, MLDV1_TYPE_MULTICAST_LISTENER_DONE);
        assert_eq!(143, MLDV2_TYPE_MULTICAST_LISTENER_REPORT);
    }

    /// The MLD constants must agree with the ICMPv6 type constants.
    #[test]
    fn constants_match_icmpv6() {
        use crate::icmpv6;
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_QUERY,
            MLD_TYPE_MULTICAST_LISTENER_QUERY
        );
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_REPORT,
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT
        );
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_REDUCTION,
            MLDV1_TYPE_MULTICAST_LISTENER_DONE
        );
    }
}
