use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Igmpv1Type {
    Unknown {
        type_u8: u8,
        bytes4to7: [u8; 4],
    },
    MembershipQuery {
        group_address: [u8; 4],
    },
    MembershipReport {
        group_address: [u8; 4],
    },
}

impl Igmpv1Type {
    #[inline]
    pub fn header_len(&self) -> usize {
        8
    }

    pub fn calc_checksum(&self, payload: &[u8]) -> u16 {
        use crate::igmpv1::*;
        use Igmpv1Type::*;

        let sum = match self {
            Unknown { type_u8, bytes4to7 } => checksum::Sum16BitWords::new()
                .add_2bytes([*type_u8, 0])
                .add_4bytes(*bytes4to7),
            MembershipQuery { group_address } => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_MEMBERSHIP_QUERY, 0])
                .add_4bytes(*group_address),
            MembershipReport { group_address } => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_MEMBERSHIP_REPORT, 0])
                .add_4bytes(*group_address),
        };

        sum.add_slice(payload).ones_complement().to_be()
    }
}

#[cfg(test)]
mod test {
    use crate::{Igmpv1Type::*, *};
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn header_len() {
        let tests = [
            Unknown {
                type_u8: 0,
                bytes4to7: [0; 4],
            },
            MembershipQuery {
                group_address: [0; 4],
            },
            MembershipReport {
                group_address: [0; 4],
            },
        ];
        for t in tests {
            assert_eq!(8, t.header_len());
        }
    }

    proptest! {
        #[test]
        fn calc_checksum(
            type_u8 in any::<u8>(),
            bytes4to7 in any::<[u8;4]>(),
            group_address in any::<[u8;4]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            let tests = [
                Unknown { type_u8, bytes4to7 },
                MembershipQuery { group_address },
                MembershipReport { group_address },
            ];

            for t in tests {
                let bytes = Igmpv1Header {
                    igmp_type: t.clone(),
                    checksum: 0,
                }.to_bytes();
                let expected = crate::checksum::Sum16BitWords::new()
                    .add_slice(bytes.as_ref())
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                assert_eq!(expected, t.calc_checksum(&payload));
            }
        }
    }

    #[test]
    fn clone_eq() {
        let tests = [
            Unknown {
                type_u8: 0,
                bytes4to7: [0; 4],
            },
            MembershipQuery {
                group_address: [0; 4],
            },
            MembershipReport {
                group_address: [0; 4],
            },
        ];
        for t in tests {
            assert_eq!(t.clone(), t);
        }
    }

    #[test]
    fn debug() {
        assert_eq!(
            format!(
                "{:?}",
                Unknown {
                    type_u8: 0,
                    bytes4to7: [0; 4]
                }
            ),
            format!(
                "Unknown {{ type_u8: {:?}, bytes4to7: {:?} }}",
                0u8,
                [0u8; 4]
            )
        );
        assert_eq!(
            format!(
                "{:?}",
                MembershipQuery {
                    group_address: [0; 4]
                }
            ),
            format!("MembershipQuery {{ group_address: {:?} }}", [0u8; 4])
        );
        assert_eq!(
            format!(
                "{:?}",
                MembershipReport {
                    group_address: [0; 4]
                }
            ),
            format!("MembershipReport {{ group_address: {:?} }}", [0u8; 4])
        );
    }
}
