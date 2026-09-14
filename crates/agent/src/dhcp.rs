use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

use crate::identity::{MacAddress, MacAddressParseError};

#[cfg(target_os = "linux")]
pub(super) const DEFAULT_LEASE_PATH: &str = "/tmp/dhcp.leases";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DhcpLease {
    pub(super) expiry_unix_seconds: u64,
    pub(super) mac: MacAddress,
    pub(super) ip: IpAddr,
    pub(super) hostname: Option<String>,
    pub(super) client_identifier: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct DhcpMetadata {
    pub(super) parameter_request_list: Vec<u8>,
    pub(super) vendor_class: Option<String>,
    pub(super) client_identifier: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DhcpObservation {
    pub(super) mac: MacAddress,
    pub(super) ip: Option<IpAddr>,
    pub(super) hostname: Option<String>,
    pub(super) metadata: DhcpMetadata,
}

#[cfg(target_os = "linux")]
pub(super) fn read_leases(path: &Path) -> Result<Vec<DhcpLease>, DhcpLeaseReadError> {
    let contents = fs::read_to_string(path).map_err(DhcpLeaseReadError::Io)?;
    parse_leases(&contents).map_err(DhcpLeaseReadError::Parse)
}

pub(super) fn parse_leases(contents: &str) -> Result<Vec<DhcpLease>, DhcpLeaseParseError> {
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_lease(line, index + 1))
        .collect()
}

fn parse_lease(line: &str, line_number: usize) -> Result<DhcpLease, DhcpLeaseParseError> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return Err(DhcpLeaseParseError::FieldCount {
            line: line_number,
            count: fields.len(),
        });
    }
    let expiry_unix_seconds = fields[0].parse().map_err(|_| DhcpLeaseParseError::Expiry {
        line: line_number,
        value: fields[0].to_owned(),
    })?;
    let mac = fields[1]
        .parse()
        .map_err(|source| DhcpLeaseParseError::Mac {
            line: line_number,
            source,
        })?;
    let ip = fields[2].parse().map_err(|_| DhcpLeaseParseError::Ip {
        line: line_number,
        value: fields[2].to_owned(),
    })?;
    let hostname = (fields[3] != "*").then(|| fields[3].to_owned());
    let client_identifier = fields
        .get(4)
        .and_then(|value| (value != &"*").then(|| parse_client_identifier(value)));
    Ok(DhcpLease {
        expiry_unix_seconds,
        mac,
        ip,
        hostname,
        client_identifier,
    })
}

pub(super) fn parse_packet(payload: &[u8]) -> Result<DhcpObservation, DhcpPacketParseError> {
    if payload.len() < 240 {
        return Err(DhcpPacketParseError::Truncated);
    }
    let hlen = usize::from(payload[2]);
    if hlen != 6 {
        return Err(DhcpPacketParseError::UnsupportedHardwareLength(hlen));
    }
    let mac = MacAddress::from_bytes(&payload[28..34]).map_err(DhcpPacketParseError::InvalidMac)?;
    if payload[236..240] != [99, 130, 83, 99] {
        return Err(DhcpPacketParseError::MissingMagicCookie);
    }

    let mut hostname = None;
    let mut requested_ip = None;
    let mut parameter_request_list = Vec::new();
    let mut vendor_class = None;
    let mut client_identifier = Vec::new();
    let mut index = 240;
    while index < payload.len() {
        let option = payload[index];
        index += 1;
        if option == 0 {
            continue;
        }
        if option == 255 {
            break;
        }
        if index >= payload.len() {
            break;
        }
        let length = usize::from(payload[index]);
        index += 1;
        if index.saturating_add(length) > payload.len() {
            break;
        }
        let value = &payload[index..index + length];
        match option {
            12 => hostname = ascii_option(value),
            50 if value.len() == 4 => {
                requested_ip = Some(IpAddr::V4(Ipv4Addr::new(
                    value[0], value[1], value[2], value[3],
                )));
            }
            55 => parameter_request_list = value.to_vec(),
            60 => vendor_class = ascii_option(value),
            61 => client_identifier = value.to_vec(),
            _ => {}
        }
        index += length;
    }

    let ciaddr = ipv4_at(payload, 12);
    let yiaddr = ipv4_at(payload, 16);
    let ip = yiaddr.or(ciaddr).or(requested_ip);
    Ok(DhcpObservation {
        mac,
        ip,
        hostname,
        metadata: DhcpMetadata {
            parameter_request_list,
            vendor_class,
            client_identifier,
        },
    })
}

fn ipv4_at(payload: &[u8], offset: usize) -> Option<IpAddr> {
    let bytes: [u8; 4] = payload.get(offset..offset + 4)?.try_into().ok()?;
    (bytes != [0, 0, 0, 0]).then(|| IpAddr::V4(Ipv4Addr::from(bytes)))
}

fn ascii_option(value: &[u8]) -> Option<String> {
    std::str::from_utf8(value)
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_client_identifier(value: &str) -> Vec<u8> {
    if value.contains(':') {
        let bytes = value
            .split(':')
            .map(|part| u8::from_str_radix(part, 16).ok())
            .collect::<Option<Vec<_>>>();
        if let Some(bytes) = bytes {
            return bytes;
        }
    }
    value.as_bytes().to_vec()
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(super) enum DhcpLeaseReadError {
    Io(std::io::Error),
    Parse(DhcpLeaseParseError),
}

#[cfg(target_os = "linux")]
impl fmt::Display for DhcpLeaseReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not read DHCP leases: {error}"),
            Self::Parse(error) => error.fmt(formatter),
        }
    }
}

#[cfg(target_os = "linux")]
impl Error for DhcpLeaseReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DhcpLeaseParseError {
    FieldCount {
        line: usize,
        count: usize,
    },
    Expiry {
        line: usize,
        value: String,
    },
    Mac {
        line: usize,
        source: MacAddressParseError,
    },
    Ip {
        line: usize,
        value: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DhcpPacketParseError {
    Truncated,
    UnsupportedHardwareLength(usize),
    MissingMagicCookie,
    InvalidMac(MacAddressParseError),
}

impl fmt::Display for DhcpPacketParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("DHCP packet is shorter than the BOOTP header"),
            Self::UnsupportedHardwareLength(length) => {
                write!(
                    formatter,
                    "DHCP packet has unsupported hardware length {length}"
                )
            }
            Self::MissingMagicCookie => formatter.write_str("DHCP packet is missing magic cookie"),
            Self::InvalidMac(error) => write!(formatter, "DHCP packet has invalid MAC: {error}"),
        }
    }
}

impl Error for DhcpPacketParseError {}

impl fmt::Display for DhcpLeaseParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldCount { line, count } => {
                write!(
                    formatter,
                    "DHCP lease line {line} has {count} fields, expected at least 4"
                )
            }
            Self::Expiry { line, value } => {
                write!(
                    formatter,
                    "DHCP lease line {line} has invalid expiry {value:?}"
                )
            }
            Self::Mac { line, source } => {
                write!(
                    formatter,
                    "DHCP lease line {line} has invalid MAC address: {source}"
                )
            }
            Self::Ip { line, value } => {
                write!(
                    formatter,
                    "DHCP lease line {line} has invalid IP address {value:?}"
                )
            }
        }
    }
}

impl Error for DhcpLeaseParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../tests/fixtures/dhcp.leases");

    #[test]
    fn parses_dnsmasq_ipv4_and_ipv6_fixture() {
        let leases = parse_leases(FIXTURE).expect("fixture should parse");

        assert_eq!(leases.len(), 3);
        assert_eq!(leases[0].expiry_unix_seconds, 4_102_444_800);
        assert_eq!(leases[0].mac.to_string(), "02:00:00:00:00:10");
        assert_eq!(leases[0].ip, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].hostname.as_deref(), Some("laptop"));
        assert_eq!(leases[1].hostname, None);
        assert!(leases[2].ip.is_ipv6());
    }

    #[test]
    fn parses_dnsmasq_client_identifier_when_present() {
        let leases =
            parse_leases("4102444800 02:00:00:00:00:10 192.0.2.10 laptop 01:02:00:00:00:00:10")
                .expect("lease with client-id should parse");

        assert_eq!(
            leases[0].client_identifier.as_deref(),
            Some(&[1, 2, 0, 0, 0, 0, 0x10][..])
        );
    }

    #[test]
    fn parses_dhcp_options_from_a_packet_capture() {
        let mut packet = vec![0_u8; 300];
        packet[0] = 1;
        packet[1] = 1;
        packet[2] = 6;
        packet[16..20].copy_from_slice(&[192, 0, 2, 20]);
        packet[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 20]);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet[240..246].copy_from_slice(&[55, 4, 1, 3, 6, 252]);
        packet[246..255].copy_from_slice(&[60, 7, b'a', b'n', b'd', b'r', b'o', b'i', b'd']);
        packet[255..262].copy_from_slice(&[12, 5, b'p', b'h', b'o', b'n', b'e']);
        packet[262..270].copy_from_slice(&[61, 6, 1, 2, 0, 0, 0, 20]);
        packet[270] = 255;

        let observation = parse_packet(&packet).expect("DHCP packet should parse");

        assert_eq!(observation.mac.to_string(), "02:00:00:00:00:14");
        assert_eq!(observation.ip, Some("192.0.2.20".parse().unwrap()));
        assert_eq!(observation.hostname.as_deref(), Some("phone"));
        assert_eq!(
            observation.metadata.parameter_request_list,
            vec![1, 3, 6, 252]
        );
        assert_eq!(
            observation.metadata.vendor_class.as_deref(),
            Some("android")
        );
        assert_eq!(
            observation.metadata.client_identifier,
            vec![1, 2, 0, 0, 0, 20]
        );
    }

    #[test]
    fn reports_the_malformed_fixture_line() {
        let error = parse_leases("not-a-time 02:00:00:00:00:10 192.0.2.10 laptop")
            .expect_err("invalid expiry should fail");

        assert!(matches!(error, DhcpLeaseParseError::Expiry { line: 1, .. }));
    }
}
