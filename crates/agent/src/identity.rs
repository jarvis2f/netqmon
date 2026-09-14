use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub(super) struct MacAddress([u8; 6]);

impl MacAddress {
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, MacAddressParseError> {
        let octets: [u8; 6] = bytes
            .try_into()
            .map_err(|_| MacAddressParseError::OctetCount(bytes.len()))?;
        Ok(Self(octets))
    }

    pub(super) fn is_unicast(self) -> bool {
        self.0 != [0; 6] && self.0[0] & 1 == 0
    }

    pub(super) const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut octets = [0; 6];
        let mut count = 0;
        for (index, part) in value.split(':').enumerate() {
            if index >= octets.len() {
                return Err(MacAddressParseError::OctetCount(index + 1));
            }
            if part.len() != 2 {
                return Err(MacAddressParseError::InvalidOctet(part.to_owned()));
            }
            octets[index] = u8::from_str_radix(part, 16)
                .map_err(|_| MacAddressParseError::InvalidOctet(part.to_owned()))?;
            count += 1;
        }
        if count != octets.len() {
            return Err(MacAddressParseError::OctetCount(count));
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MacAddressParseError {
    OctetCount(usize),
    InvalidOctet(String),
}

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OctetCount(count) => {
                write!(formatter, "MAC address has {count} octets, expected 6")
            }
            Self::InvalidOctet(octet) => write!(formatter, "invalid MAC address octet {octet:?}"),
        }
    }
}

impl Error for MacAddressParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_a_canonical_mac_address() {
        let address: MacAddress = "AA:bb:0C:0d:EE:ff".parse().expect("valid MAC address");

        assert_eq!(address.to_string(), "aa:bb:0c:0d:ee:ff");
        assert_eq!(
            MacAddress::from_bytes(&[0xaa, 0xbb, 0x0c, 0x0d, 0xee, 0xff]),
            Ok(address)
        );
        assert!(address.is_unicast());
        assert!(
            !"33:33:00:00:00:16"
                .parse::<MacAddress>()
                .unwrap()
                .is_unicast()
        );
        assert!(
            !"00:00:00:00:00:00"
                .parse::<MacAddress>()
                .unwrap()
                .is_unicast()
        );
    }

    #[test]
    fn rejects_invalid_mac_addresses() {
        assert!(matches!(
            "aa:bb:cc".parse::<MacAddress>(),
            Err(MacAddressParseError::OctetCount(3))
        ));
        assert!(matches!(
            "aa:bb:cc:dd:ee:gg".parse::<MacAddress>(),
            Err(MacAddressParseError::InvalidOctet(_))
        ));
    }
}
