use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DnsResponse {
    pub(super) qname: String,
    pub(super) rcode: DnsResponseCode,
    pub(super) answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsResponseCode {
    NoError,
    NxDomain,
    Other(u16),
}

impl fmt::Display for DnsResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => formatter.write_str("NOERROR"),
            Self::NxDomain => formatter.write_str("NXDOMAIN"),
            Self::Other(code) => write!(formatter, "RCODE{code}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DnsAnswer {
    pub(super) name: String,
    pub(super) ttl: u32,
    pub(super) data: DnsAnswerData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DnsAnswerData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DnsParseError {
    InvalidMessage(String),
    MissingQuestion,
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(detail) => write!(formatter, "invalid DNS message: {detail}"),
            Self::MissingQuestion => formatter.write_str("DNS response has no question"),
        }
    }
}

impl Error for DnsParseError {}

pub(super) fn parse_response(payload: &[u8]) -> Result<DnsResponse, DnsParseError> {
    let message = Message::from_vec(payload)
        .map_err(|error| DnsParseError::InvalidMessage(error.to_string()))?;
    let qname = message
        .queries()
        .first()
        .map(|query| display_name(query.name()))
        .ok_or(DnsParseError::MissingQuestion)?;
    let answers = message
        .answers()
        .iter()
        .filter_map(|record| {
            let data = match record.data() {
                RData::A(address) => DnsAnswerData::A(address.0),
                RData::AAAA(address) => DnsAnswerData::Aaaa(address.0),
                RData::CNAME(name) => DnsAnswerData::Cname(display_name(&name.0)),
                _ => return None,
            };
            Some(DnsAnswer {
                name: display_name(record.name()),
                ttl: record.ttl(),
                data,
            })
        })
        .collect();

    Ok(DnsResponse {
        qname,
        rcode: response_code(message.response_code()),
        answers,
    })
}

fn response_code(code: ResponseCode) -> DnsResponseCode {
    match code {
        ResponseCode::NoError => DnsResponseCode::NoError,
        ResponseCode::NXDomain => DnsResponseCode::NxDomain,
        other => DnsResponseCode::Other(other.into()),
    }
}

fn display_name(name: &hickory_proto::rr::Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_RESPONSE: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 203, 0, 113, 10,
    ];

    const AAAA_RESPONSE: &[u8] = &[
        0x12, 0x35, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x1c, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x10, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    const CNAME_RESPONSE: &[u8] = &[
        0x12, 0x36, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, b'a', b'l',
        b'i', b'a', b's', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's',
        b't', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x09, 0x06, b't', b'a', b'r', b'g', b'e', b't', 0xc0, 0x12,
    ];

    const NXDOMAIN_RESPONSE: &[u8] = &[
        0x12, 0x37, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'm', b'i',
        b's', b's', b'i', b'n', b'g', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x04, b't',
        b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn parses_a_response_fixture() {
        let response = parse_response(A_RESPONSE).expect("A fixture should parse");

        assert_eq!(response.qname, "example.test");
        assert_eq!(response.rcode, DnsResponseCode::NoError);
        assert_eq!(
            response.answers,
            vec![DnsAnswer {
                name: "example.test".to_owned(),
                ttl: 300,
                data: DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 10)),
            }]
        );
    }

    #[test]
    fn parses_a_bounded_capture_with_trailing_packet_bytes() {
        let mut payload = A_RESPONSE.to_vec();
        payload.resize(512, b'D');

        let response = parse_response(&payload).expect("bounded A capture should parse");

        assert_eq!(response.qname, "example.test");
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn parses_aaaa_response_fixture() {
        let response = parse_response(AAAA_RESPONSE).expect("AAAA fixture should parse");

        assert_eq!(response.qname, "example.test");
        assert_eq!(response.rcode, DnsResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 600);
        assert_eq!(
            response.answers[0].data,
            DnsAnswerData::Aaaa("2001:db8::10".parse().expect("valid IPv6 address"))
        );
    }

    #[test]
    fn parses_cname_response_fixture() {
        let response = parse_response(CNAME_RESPONSE).expect("CNAME fixture should parse");

        assert_eq!(response.qname, "alias.example.test");
        assert_eq!(response.rcode, DnsResponseCode::NoError);
        assert_eq!(
            response.answers,
            vec![DnsAnswer {
                name: "alias.example.test".to_owned(),
                ttl: 120,
                data: DnsAnswerData::Cname("target.example.test".to_owned()),
            }]
        );
    }

    #[test]
    fn parses_nxdomain_response_fixture() {
        let response = parse_response(NXDOMAIN_RESPONSE).expect("NXDOMAIN fixture should parse");

        assert_eq!(response.qname, "missing.example.test");
        assert_eq!(response.rcode, DnsResponseCode::NxDomain);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn rejects_a_response_without_a_question() {
        let payload = [
            0x12, 0x38, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(
            parse_response(&payload),
            Err(DnsParseError::MissingQuestion)
        );
    }

    #[test]
    fn rejects_a_malformed_response() {
        assert!(matches!(
            parse_response(&[0x12, 0x34]),
            Err(DnsParseError::InvalidMessage(_))
        ));
    }
}
