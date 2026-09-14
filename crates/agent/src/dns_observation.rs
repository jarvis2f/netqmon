use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::dns_parser::{DnsAnswerData, DnsResponse, DnsResponseCode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DnsObservation {
    pub(super) client_addr: IpAddr,
    pub(super) domain: String,
    pub(super) answer_ip: IpAddr,
    pub(super) record_type: DnsRecordType,
    pub(super) ttl: u32,
    pub(super) observed_at: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DnsRecordType {
    A,
    Aaaa,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        })
    }
}

pub(super) fn observations(
    client_addr: IpAddr,
    response: DnsResponse,
    observed_at: SystemTime,
) -> Vec<DnsObservation> {
    if response.rcode != DnsResponseCode::NoError {
        return Vec::new();
    }

    let cname_path = cname_path(&response);
    response
        .answers
        .into_iter()
        .filter_map(|answer| {
            let cname_ttl = cname_path
                .iter()
                .find_map(|(name, ttl)| (name == &answer.name).then_some(*ttl))?;
            let (answer_ip, record_type) = match answer.data {
                DnsAnswerData::A(address) => (IpAddr::V4(address), DnsRecordType::A),
                DnsAnswerData::Aaaa(address) => (IpAddr::V6(address), DnsRecordType::Aaaa),
                DnsAnswerData::Cname(_) => return None,
            };
            Some(DnsObservation {
                client_addr,
                domain: response.qname.clone(),
                answer_ip,
                record_type,
                ttl: answer.ttl.min(cname_ttl),
                observed_at,
            })
        })
        .collect()
}

fn cname_path(response: &DnsResponse) -> Vec<(String, u32)> {
    let mut path = vec![(response.qname.clone(), u32::MAX)];
    for _ in 0..response.answers.len() {
        let (current_name, current_ttl) = path.last().expect("path starts with qname");
        let Some((target, ttl)) = response.answers.iter().find_map(|answer| {
            if &answer.name != current_name {
                return None;
            }
            match &answer.data {
                DnsAnswerData::Cname(target) => Some((target.clone(), answer.ttl)),
                _ => None,
            }
        }) else {
            break;
        };
        if path.iter().any(|(name, _)| name == &target) {
            break;
        }
        path.push((target, (*current_ttl).min(ttl)));
    }
    path
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, UNIX_EPOCH};

    use crate::dns_parser::{DnsAnswer, DnsAnswerData};

    use super::*;

    #[test]
    fn converts_a_and_aaaa_answers_to_client_domain_ip_observations() {
        let client_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let response = DnsResponse {
            qname: "www.example.test".to_owned(),
            rcode: DnsResponseCode::NoError,
            answers: vec![
                DnsAnswer {
                    name: "www.example.test".to_owned(),
                    ttl: 300,
                    data: DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 10)),
                },
                DnsAnswer {
                    name: "www.example.test".to_owned(),
                    ttl: 600,
                    data: DnsAnswerData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
                },
            ],
        };

        assert_eq!(
            observations(client_addr, response, observed_at),
            vec![
                DnsObservation {
                    client_addr,
                    domain: "www.example.test".to_owned(),
                    answer_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    record_type: DnsRecordType::A,
                    ttl: 300,
                    observed_at,
                },
                DnsObservation {
                    client_addr,
                    domain: "www.example.test".to_owned(),
                    answer_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10,)),
                    record_type: DnsRecordType::Aaaa,
                    ttl: 600,
                    observed_at,
                },
            ]
        );
    }

    #[test]
    fn associates_cname_chain_addresses_with_the_original_query_domain() {
        let client_addr = "2001:db8::20".parse().expect("valid client address");
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_001);
        let response = DnsResponse {
            qname: "alias.example.test".to_owned(),
            rcode: DnsResponseCode::NoError,
            answers: vec![
                DnsAnswer {
                    name: "alias.example.test".to_owned(),
                    ttl: 30,
                    data: DnsAnswerData::Cname("target.example.test".to_owned()),
                },
                DnsAnswer {
                    name: "target.example.test".to_owned(),
                    ttl: 60,
                    data: DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 42)),
                },
            ],
        };

        assert_eq!(
            observations(client_addr, response, observed_at),
            vec![DnsObservation {
                client_addr,
                domain: "alias.example.test".to_owned(),
                answer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
                record_type: DnsRecordType::A,
                ttl: 30,
                observed_at,
            }]
        );
    }

    #[test]
    fn ignores_address_answers_unrelated_to_the_query_or_its_cname_chain() {
        let response = DnsResponse {
            qname: "www.example.test".to_owned(),
            rcode: DnsResponseCode::NoError,
            answers: vec![DnsAnswer {
                name: "unrelated.example.test".to_owned(),
                ttl: 300,
                data: DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 99)),
            }],
        };

        assert!(observations(IpAddr::V4(Ipv4Addr::LOCALHOST), response, UNIX_EPOCH).is_empty());
    }

    #[test]
    fn does_not_create_an_address_observation_for_nxdomain() {
        let response = DnsResponse {
            qname: "missing.example.test".to_owned(),
            rcode: DnsResponseCode::NxDomain,
            answers: Vec::new(),
        };

        assert!(observations(IpAddr::V4(Ipv4Addr::LOCALHOST), response, UNIX_EPOCH).is_empty());
    }

    #[test]
    fn does_not_create_an_address_observation_for_other_error_responses() {
        let response = DnsResponse {
            qname: "servfail.example.test".to_owned(),
            rcode: DnsResponseCode::Other(2),
            answers: vec![DnsAnswer {
                name: "servfail.example.test".to_owned(),
                ttl: 30,
                data: DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 20)),
            }],
        };

        assert!(observations(IpAddr::V4(Ipv4Addr::LOCALHOST), response, UNIX_EPOCH).is_empty());
    }
}
