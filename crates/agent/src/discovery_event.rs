use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::identity::MacAddress;

pub const DISCOVERY_MAX_PAYLOAD_LENGTH: usize = 2048;
pub const DISCOVERY_EVENT_SIZE: usize = 2096;

#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveryEvent {
    pub source_ip: IpAddr,
    pub source_mac: MacAddress,
    pub source_port: u16,
    pub destination_port: u16,
    pub captured_payload_length: u16,
    pub original_payload_length: u16,
    pub truncated: bool,
    pub payload: Vec<u8>,
}

impl fmt::Debug for DiscoveryEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryEvent")
            .field("source_ip", &self.source_ip)
            .field("source_mac", &self.source_mac)
            .field("source_port", &self.source_port)
            .field("destination_port", &self.destination_port)
            .field("captured_payload_length", &self.captured_payload_length)
            .field("original_payload_length", &self.original_payload_length)
            .field("truncated", &self.truncated)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl TryFrom<&[u8]> for DiscoveryEvent {
    type Error = DiscoveryEventDecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != DISCOVERY_EVENT_SIZE {
            return Err(DiscoveryEventDecodeError::EventSize(bytes.len()));
        }
        let payload_length = usize::from(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()));
        if payload_length > DISCOVERY_MAX_PAYLOAD_LENGTH {
            return Err(DiscoveryEventDecodeError::PayloadLength(payload_length));
        }
        let source_ip = match bytes[18] {
            4 => IpAddr::V4(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[20..36]).unwrap(),
            )),
            version => return Err(DiscoveryEventDecodeError::IpVersion(version)),
        };
        let source_mac =
            MacAddress::from_bytes(&bytes[36..42]).map_err(|_| DiscoveryEventDecodeError::Mac)?;
        let captured_payload_length = u16::try_from(payload_length).unwrap();
        let original_payload_length = u16::from_ne_bytes(bytes[46..48].try_into().unwrap());
        if original_payload_length < captured_payload_length {
            return Err(DiscoveryEventDecodeError::PayloadLength(payload_length));
        }
        if bytes[19] > 1 || (bytes[19] != 0) != (captured_payload_length < original_payload_length)
        {
            return Err(DiscoveryEventDecodeError::TruncationFlag(bytes[19]));
        }
        Ok(Self {
            captured_payload_length,
            original_payload_length,
            truncated: bytes[19] != 0,
            source_ip,
            source_mac,
            source_port: u16::from_be_bytes(bytes[42..44].try_into().unwrap()),
            destination_port: u16::from_be_bytes(bytes[44..46].try_into().unwrap()),
            payload: bytes[48..48 + payload_length].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryEventDecodeError {
    EventSize(usize),
    PayloadLength(usize),
    IpVersion(u8),
    TruncationFlag(u8),
    Mac,
}

impl fmt::Display for DiscoveryEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid discovery event: {self:?}")
    }
}

impl std::error::Error for DiscoveryEventDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inconsistent_capture_metadata_and_old_abi() {
        let mut bytes = vec![0; DISCOVERY_EVENT_SIZE];
        bytes[18] = 4;
        bytes[36..42].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes[16..18].copy_from_slice(&2048_u16.to_ne_bytes());
        bytes[46..48].copy_from_slice(&2049_u16.to_ne_bytes());
        assert!(matches!(
            DiscoveryEvent::try_from(bytes.as_slice()),
            Err(DiscoveryEventDecodeError::TruncationFlag(0))
        ));
        bytes[19] = 1;
        assert!(
            DiscoveryEvent::try_from(bytes.as_slice())
                .unwrap()
                .truncated
        );
        bytes[16..18].copy_from_slice(&2049_u16.to_ne_bytes());
        assert!(matches!(
            DiscoveryEvent::try_from(bytes.as_slice()),
            Err(DiscoveryEventDecodeError::PayloadLength(2049))
        ));
        bytes.resize(4144, 0);
        assert!(matches!(
            DiscoveryEvent::try_from(bytes.as_slice()),
            Err(DiscoveryEventDecodeError::EventSize(4144))
        ));
    }

    #[test]
    fn decodes_source_identity_and_bounded_payload() {
        let mut bytes = [0_u8; DISCOVERY_EVENT_SIZE];
        bytes[16..18].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[18] = 4;
        bytes[46..48].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[20..24].copy_from_slice(&[192, 0, 2, 8]);
        bytes[36..42].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes[42..44].copy_from_slice(&5353_u16.to_be_bytes());
        bytes[44..46].copy_from_slice(&5353_u16.to_be_bytes());
        bytes[48..52].copy_from_slice(b"mdns");

        let event = DiscoveryEvent::try_from(bytes.as_slice()).unwrap();
        assert_eq!(event.source_ip, "192.0.2.8".parse::<IpAddr>().unwrap());
        assert_eq!(event.source_port, 5353);
        assert_eq!(event.payload, b"mdns");
        assert!(!format!("{event:?}").contains("mdns"));
    }
}
