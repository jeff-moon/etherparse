/// Type of an IGMPv1 message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Igmpv1Type {
    /// Membership Query (type 0x11).
    MembershipQuery,
    /// Membership Report (type 0x12).
    MembershipReport,
}

impl Igmpv1Type {
    /// IGMPv1 Membership Query type value.
    pub const MEMBERSHIP_QUERY_TYPE_U8: u8 = 0x11;

    /// IGMPv1 Membership Report type value.
    pub const MEMBERSHIP_REPORT_TYPE_U8: u8 = 0x12;

    /// Returns the raw type byte for this message type.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        match self {
            Igmpv1Type::MembershipQuery => Self::MEMBERSHIP_QUERY_TYPE_U8,
            Igmpv1Type::MembershipReport => Self::MEMBERSHIP_REPORT_TYPE_U8,
        }
    }

    /// Try to create an [`Igmpv1Type`] from a raw type byte.
    ///
    /// Returns `None` if the type is not a known IGMPv1 type.
    #[inline]
    pub fn from_u8(value: u8) -> Option<Igmpv1Type> {
        match value {
            Self::MEMBERSHIP_QUERY_TYPE_U8 => Some(Igmpv1Type::MembershipQuery),
            Self::MEMBERSHIP_REPORT_TYPE_U8 => Some(Igmpv1Type::MembershipReport),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn type_u8() {
        assert_eq!(0x11, Igmpv1Type::MembershipQuery.type_u8());
        assert_eq!(0x12, Igmpv1Type::MembershipReport.type_u8());
    }

    #[test]
    fn from_u8() {
        assert_eq!(
            Some(Igmpv1Type::MembershipQuery),
            Igmpv1Type::from_u8(0x11)
        );
        assert_eq!(
            Some(Igmpv1Type::MembershipReport),
            Igmpv1Type::from_u8(0x12)
        );
        assert_eq!(None, Igmpv1Type::from_u8(0x00));
        assert_eq!(None, Igmpv1Type::from_u8(0x13));
        assert_eq!(None, Igmpv1Type::from_u8(0xFF));
    }

    #[test]
    fn constants() {
        assert_eq!(0x11, Igmpv1Type::MEMBERSHIP_QUERY_TYPE_U8);
        assert_eq!(0x12, Igmpv1Type::MEMBERSHIP_REPORT_TYPE_U8);
    }

    #[test]
    fn clone_eq() {
        let t = Igmpv1Type::MembershipQuery;
        assert_eq!(t, t.clone());
    }

    #[test]
    fn copy() {
        let t = Igmpv1Type::MembershipQuery;
        let t2: Igmpv1Type = t;
        assert_eq!(t, t2);
    }

    #[test]
    fn debug() {
        assert_eq!("MembershipQuery", format!("{:?}", Igmpv1Type::MembershipQuery));
        assert_eq!("MembershipReport", format!("{:?}", Igmpv1Type::MembershipReport));
    }
}
