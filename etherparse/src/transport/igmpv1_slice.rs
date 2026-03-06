use crate::{igmpv1::*, *};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Igmpv1Slice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Igmpv1Slice<'a> {
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Igmpv1Slice<'a>, err::LenError> {
        if slice.len() < Igmpv1Header::MIN_LEN {
            return Err(err::LenError {
                required_len: Igmpv1Header::MIN_LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv1,
                layer_start_offset: 0,
            });
        }

        Ok(Igmpv1Slice { slice })
    }

    #[inline]
    pub fn header(&self) -> Igmpv1Header {
        let igmp_type = self.igmp_type();
        Igmpv1Header {
            igmp_type,
            checksum: self.checksum(),
        }
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        8
    }

    pub fn igmp_type(&self) -> Igmpv1Type {
        use Igmpv1Type::*;

        match self.type_u8() {
            TYPE_MEMBERSHIP_QUERY => MembershipQuery {
                group_address: self.group_address(),
            },
            TYPE_MEMBERSHIP_REPORT => MembershipReport {
                group_address: self.group_address(),
            },
            type_u8 => Unknown {
                type_u8,
                bytes4to7: unsafe {
                    [
                        *self.slice.get_unchecked(4),
                        *self.slice.get_unchecked(5),
                        *self.slice.get_unchecked(6),
                        *self.slice.get_unchecked(7),
                    ]
                },
            },
        }
    }

    #[inline]
    pub fn type_u8(&self) -> u8 {
        unsafe { *self.slice.get_unchecked(0) }
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    #[inline]
    pub fn group_address(&self) -> [u8; 4] {
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(8),
                self.slice.len() - 8,
            )
        }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn from_slice() {
        {
            let bytes = [0u8; 8];
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        for bad_len in 0..8 {
            let bytes = [0u8; 8];
            assert_eq!(
                Igmpv1Slice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: Igmpv1Header::MIN_LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Igmpv1,
                    layer_start_offset: 0,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn header(bytes in any::<[u8;8]>()) {
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(
                Igmpv1Header {
                    igmp_type: slice.igmp_type(),
                    checksum: slice.checksum(),
                },
                slice.header()
            );
        }
    }

    #[test]
    fn header_len() {
        use Igmpv1Type::*;

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
            assert_eq!(
                t.header_len(),
                Igmpv1Slice::from_slice(&Igmpv1Header::new(t).to_bytes())
                    .unwrap()
                    .header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn igmp_type(base_bytes in any::<[u8;8]>()) {
            use Igmpv1Type::*;

            let gen_bytes = |type_u8: u8| -> [u8; 8] {
                let mut bytes = base_bytes;
                bytes[0] = type_u8;
                bytes
            };

            let assert_unknown = |type_u8: u8| {
                let bytes = gen_bytes(type_u8);
                let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
                assert_eq!(
                    slice.igmp_type(),
                    Unknown {
                        type_u8,
                        bytes4to7: [bytes[4], bytes[5], bytes[6], bytes[7]],
                    }
                );
            };

            for type_u8 in 0..=u8::MAX {
                match type_u8 {
                    TYPE_MEMBERSHIP_QUERY | TYPE_MEMBERSHIP_REPORT => {},
                    type_u8 => {
                        assert_unknown(type_u8);
                    }
                }
            }

            {
                let bytes = gen_bytes(TYPE_MEMBERSHIP_QUERY);
                let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
                assert_eq!(
                    slice.igmp_type(),
                    MembershipQuery {
                        group_address: slice.group_address()
                    }
                );
            }

            {
                let bytes = gen_bytes(TYPE_MEMBERSHIP_REPORT);
                let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
                assert_eq!(
                    slice.igmp_type(),
                    MembershipReport {
                        group_address: slice.group_address()
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn type_u8(bytes in any::<[u8;8]>()) {
            assert_eq!(
                bytes[0],
                Igmpv1Slice::from_slice(&bytes).unwrap().type_u8(),
            );
        }
    }

    proptest! {
        #[test]
        fn checksum(bytes in any::<[u8;8]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]),
                Igmpv1Slice::from_slice(&bytes).unwrap().checksum(),
            );
        }
    }

    proptest! {
        #[test]
        fn group_address(bytes in any::<[u8;8]>()) {
            assert_eq!(
                [bytes[4], bytes[5], bytes[6], bytes[7]],
                Igmpv1Slice::from_slice(&bytes).unwrap().group_address(),
            );
        }
    }

    proptest! {
        #[test]
        fn payload(
            payload in proptest::collection::vec(any::<u8>(), 8..26)
        ) {
            use Igmpv1Type::*;

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
                let mut bytes = Vec::with_capacity(t.header_len() + payload.len());
                Igmpv1Header::new(t.clone()).write(&mut bytes).unwrap();
                bytes.extend_from_slice(&payload);

                assert_eq!(
                    &payload[..],
                    Igmpv1Slice::from_slice(&bytes).unwrap().payload()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn slice(bytes in proptest::collection::vec(any::<u8>(), 8..1024)) {
            let slice = &bytes[..];
            assert_eq!(
                slice,
                Igmpv1Slice::from_slice(slice).unwrap().slice(),
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(bytes in any::<[u8;8]>()) {
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(bytes in any::<[u8;8]>()) {
            let slice = Igmpv1Slice::from_slice(&bytes).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("Igmpv1Slice {{ slice: {:?} }}", &bytes[..])
            );
        }
    }
}
