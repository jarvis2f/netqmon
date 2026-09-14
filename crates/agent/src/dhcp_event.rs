use std::fmt;

pub const DHCP_MAX_PAYLOAD_LENGTH: usize = 576;
pub const DHCP_EVENT_SIZE: usize = 600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpEvent {
    pub packet_length: u32,
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for DhcpEvent {
    type Error = DhcpEventDecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != DHCP_EVENT_SIZE {
            return Err(DhcpEventDecodeError::EventSize(bytes.len()));
        }
        let payload_length = usize::from(u16::from_ne_bytes(
            bytes[16..18].try_into().expect("fixed slice"),
        ));
        if payload_length > DHCP_MAX_PAYLOAD_LENGTH {
            return Err(DhcpEventDecodeError::PayloadLength(payload_length));
        }
        Ok(Self {
            packet_length: u32::from_ne_bytes(bytes[12..16].try_into().expect("fixed slice")),
            payload: bytes[20..20 + payload_length].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpEventDecodeError {
    EventSize(usize),
    PayloadLength(usize),
}

impl fmt::Display for DhcpEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventSize(size) => {
                write!(
                    formatter,
                    "DHCP event has {size} bytes, expected {DHCP_EVENT_SIZE}"
                )
            }
            Self::PayloadLength(length) => write!(
                formatter,
                "DHCP event payload has {length} bytes, maximum is {DHCP_MAX_PAYLOAD_LENGTH}"
            ),
        }
    }
}

impl std::error::Error for DhcpEventDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bounded_dhcp_event() {
        let mut bytes = [0_u8; DHCP_EVENT_SIZE];
        bytes[12..16].copy_from_slice(&342_u32.to_ne_bytes());
        bytes[16..18].copy_from_slice(&240_u16.to_ne_bytes());
        bytes[20..23].copy_from_slice(&[1, 1, 6]);

        let event = DhcpEvent::try_from(bytes.as_slice()).unwrap();

        assert_eq!(event.packet_length, 342);
        assert_eq!(event.payload.len(), 240);
        assert_eq!(&event.payload[..3], &[1, 1, 6]);
    }

    #[test]
    fn rejects_invalid_size_and_payload_length() {
        assert_eq!(
            DhcpEvent::try_from(&[0_u8; 1][..]).unwrap_err(),
            DhcpEventDecodeError::EventSize(1)
        );
        let mut bytes = [0_u8; DHCP_EVENT_SIZE];
        bytes[16..18].copy_from_slice(&577_u16.to_ne_bytes());
        assert!(matches!(
            DhcpEvent::try_from(bytes.as_slice()),
            Err(DhcpEventDecodeError::PayloadLength(577))
        ));
    }
}
