pub const TYPE_MEMBERSHIP_QUERY: u8 = 0x11;

pub const TYPE_MEMBERSHIP_REPORT: u8 = 0x12;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(TYPE_MEMBERSHIP_QUERY, 0x11);
        assert_eq!(TYPE_MEMBERSHIP_REPORT, 0x12);
    }
}
