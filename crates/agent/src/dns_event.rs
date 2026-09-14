use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DNS_MAX_PAYLOAD_LENGTH: usize = 512;
pub const DNS_EVENT_SIZE: usize = 552;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsEvent {
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub packet_length: u32,
    pub client_address: IpAddr,
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for DnsEvent {
    type Error = DnsEventDecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != DNS_EVENT_SIZE {
            return Err(DnsEventDecodeError::EventSize(bytes.len()));
        }
        let payload_length = usize::from(u16::from_ne_bytes(
            bytes[16..18].try_into().expect("fixed slice"),
        ));
        if payload_length > DNS_MAX_PAYLOAD_LENGTH {
            return Err(DnsEventDecodeError::PayloadLength(payload_length));
        }
        let client_address = match bytes[18] {
            4 => IpAddr::V4(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
            6 => {
                let address: [u8; 16] = bytes[20..36].try_into().expect("fixed slice");
                IpAddr::V6(Ipv6Addr::from(address))
            }
            version => return Err(DnsEventDecodeError::IpVersion(version)),
        };
        Ok(Self {
            timestamp_ns: u64::from_ne_bytes(bytes[0..8].try_into().expect("fixed slice")),
            ifindex: u32::from_ne_bytes(bytes[8..12].try_into().expect("fixed slice")),
            packet_length: u32::from_ne_bytes(bytes[12..16].try_into().expect("fixed slice")),
            client_address,
            payload: bytes[36..36 + payload_length].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsEventDecodeError {
    EventSize(usize),
    PayloadLength(usize),
    IpVersion(u8),
}

impl fmt::Display for DnsEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventSize(size) => write!(
                formatter,
                "DNS event has {size} bytes, expected {DNS_EVENT_SIZE}"
            ),
            Self::PayloadLength(length) => write!(
                formatter,
                "DNS event payload has {length} bytes, maximum is {DNS_MAX_PAYLOAD_LENGTH}"
            ),
            Self::IpVersion(version) => {
                write!(formatter, "DNS event has unsupported IP version {version}")
            }
        }
    }
}

impl std::error::Error for DnsEventDecodeError {}

#[cfg(test)]
mod tests {
    use super::{DNS_EVENT_SIZE, DNS_MAX_PAYLOAD_LENGTH, DnsEvent, DnsEventDecodeError};
    use std::net::IpAddr;

    #[test]
    fn decodes_bounded_ipv4_event() {
        let mut bytes = event(4, DNS_MAX_PAYLOAD_LENGTH);
        bytes[20..24].copy_from_slice(&[192, 0, 2, 20]);
        for (index, byte) in bytes[36..36 + DNS_MAX_PAYLOAD_LENGTH]
            .iter_mut()
            .enumerate()
        {
            *byte = u8::try_from(index % 256).unwrap();
        }
        let event = DnsEvent::try_from(bytes.as_slice()).unwrap();
        assert_eq!(event.timestamp_ns, 123);
        assert_eq!(event.ifindex, 7);
        assert_eq!(event.packet_length, 742);
        assert_eq!(
            event.client_address,
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(event.payload.len(), DNS_MAX_PAYLOAD_LENGTH);
    }

    #[test]
    fn decodes_ipv6_client_address() {
        let mut bytes = event(6, 12);
        bytes[20..36].copy_from_slice(
            &"2001:db8::20"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let event = DnsEvent::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            event.client_address,
            "2001:db8::20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(event.payload.len(), 12);
    }

    #[test]
    fn rejects_invalid_size_length_and_version() {
        assert_eq!(
            DnsEvent::try_from(&[0_u8; 1][..]).unwrap_err(),
            DnsEventDecodeError::EventSize(1)
        );
        let bytes = event(4, DNS_MAX_PAYLOAD_LENGTH + 1);
        assert!(matches!(
            DnsEvent::try_from(bytes.as_slice()),
            Err(DnsEventDecodeError::PayloadLength(_))
        ));
        let bytes = event(5, 0);
        assert_eq!(
            DnsEvent::try_from(bytes.as_slice()).unwrap_err(),
            DnsEventDecodeError::IpVersion(5)
        );
    }

    fn event(ip_version: u8, payload_length: usize) -> [u8; DNS_EVENT_SIZE] {
        let mut bytes = [0; DNS_EVENT_SIZE];
        bytes[0..8].copy_from_slice(&123_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&742_u32.to_ne_bytes());
        bytes[16..18].copy_from_slice(&u16::try_from(payload_length).unwrap().to_ne_bytes());
        bytes[18] = ip_version;
        bytes
    }
}
