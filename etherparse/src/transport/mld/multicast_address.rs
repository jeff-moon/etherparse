/// A multicast address in an MLD packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddress {
    pub octets: [u8; 16],
}

impl MulticastAddress {
    pub fn new(address: [u8; 16]) -> Self {
        Self { octets: address }
    }

    pub fn is_zero(&self) -> bool {
        [0u8; 16] == self.octets
    }
}

impl From<MulticastAddress> for [u8; 16] {
    fn from(value: MulticastAddress) -> Self {
        value.octets
    }
}

impl From<[u8; 16]> for MulticastAddress {
    fn from(value: [u8; 16]) -> Self {
        MulticastAddress { octets: value }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<std::net::Ipv6Addr> for MulticastAddress {
    fn from(value: std::net::Ipv6Addr) -> Self {
        MulticastAddress {
            octets: value.octets(),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<MulticastAddress> for std::net::Ipv6Addr {
    fn from(value: MulticastAddress) -> Self {
        std::net::Ipv6Addr::from(value.octets)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn test_is_zero() {
        assert!(MulticastAddress::new([0; 16]).is_zero());
        for i in 0..16 {
            let mut octets = [0u8; 16];
            octets[i] = 1;
            assert!(!MulticastAddress::new(octets).is_zero());
        }
    }

    #[test]
    fn debug() {
        let addr = MulticastAddress::new([0; 16]);
        assert_eq!(
            format!("{:?}", addr),
            format!("MulticastAddress {{ octets: {:?} }}", [0u8; 16])
        );
    }

    proptest! {
        #[test]
        fn from_array_to_multicast_address_roundtrip(octets in any::<[u8;16]>()) {
            let addr = MulticastAddress::from(octets);
            prop_assert_eq!(addr.octets, octets);

            let back: [u8;16] = addr.into();
            prop_assert_eq!(back, octets);
        }
    }

    proptest! {
        #[test]
        fn from_multicast_address_to_array_roundtrip(octets in any::<[u8;16]>()) {
            let addr = MulticastAddress { octets };
            let arr: [u8;16] = addr.into();
            prop_assert_eq!(arr, octets);

            let back = MulticastAddress::from(arr);
            prop_assert_eq!(back, addr);
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn from_ipv6addr_to_multicast_address_roundtrip(octets in any::<[u8;16]>()) {
            let ip = std::net::Ipv6Addr::from(octets);
            let addr = MulticastAddress::from(ip);
            prop_assert_eq!(addr.octets, octets);

            let back: std::net::Ipv6Addr = addr.into();
            prop_assert_eq!(back.octets(), octets);
        }
    }
}
