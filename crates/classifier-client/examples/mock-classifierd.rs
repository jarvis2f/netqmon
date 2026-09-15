//! Deterministic classifierd stand-in for integration and CI tests.
//!
//! This is deliberately an example rather than a production binary: it speaks
//! the public NDJSON socket protocol without shipping any rule material.

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    thread,
};

use netqmon_classifier_client::{
    ClassificationBatchResult, ClassificationEvidence, ClassificationResult, ClassifiedEntity,
    ClassifierEntitlement, ClassifierHealth, ClassifierVersion, ClientRequest,
    DeviceEvidenceResult, EntityKind, EntityMetadata, FlowSampleMatchResult, RuleStats,
    RuleVersion, ServerResponse,
};

const MOCK_CLASSIFIER_VERSION: &str = "mock-1.0.0";
const MOCK_RULE_VERSION: &str = "mock-community-2026.09";

#[derive(Clone)]
struct MockState {
    entitlement: ClassifierEntitlement,
}

fn main() -> Result<(), Box<dyn Error>> {
    let socket_path = socket_path_from_args()?;
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    let state = Arc::new(Mutex::new(MockState {
        entitlement: community_entitlement(),
    }));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || serve_connection(stream, &state));
            }
            Err(error) => eprintln!("mock classifierd accept failed: {error}"),
        }
    }
    Ok(())
}

fn socket_path_from_args() -> Result<PathBuf, Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    match (arguments.next().as_deref(), arguments.next()) {
        (Some("--socket"), Some(path)) if arguments.next().is_none() => Ok(path.into()),
        _ => Err("usage: mock-classifierd --socket <path>".into()),
    }
}

fn serve_connection(stream: UnixStream, state: &Arc<Mutex<MockState>>) {
    let mut reader = match stream.try_clone() {
        Ok(clone) => BufReader::new(clone),
        Err(error) => {
            eprintln!("mock classifierd could not clone stream: {error}");
            return;
        }
    };
    let mut writer = stream;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) => {
                eprintln!("mock classifierd could not read request: {error}");
                return;
            }
        }
        let response = match serde_json::from_str::<ClientRequest>(line.trim_end()) {
            Ok(request) => response_for(request, state),
            Err(error) => ServerResponse::Error {
                request_id: malformed_request_id(&line),
                code: "invalid_request".to_owned(),
                message: format!("invalid classifier request: {error}"),
            },
        };
        if writeln!(
            writer,
            "{}",
            serde_json::to_string(&response).expect("mock response serializes")
        )
        .and_then(|()| writer.flush())
        .is_err()
        {
            return;
        }
    }
}

fn malformed_request_id(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-request".to_owned())
}

fn response_for(request: ClientRequest, state: &Arc<Mutex<MockState>>) -> ServerResponse {
    match request {
        ClientRequest::ClassifyBatch {
            request_id,
            request,
        } => ServerResponse::ClassificationBatch {
            request_id,
            result: ClassificationBatchResult {
                entries: request.entries.iter().map(classify).collect(),
            },
        },
        ClientRequest::MatchFlowSamples {
            request_id,
            request,
        } => ServerResponse::FlowSampleMatch {
            request_id,
            result: FlowSampleMatchResult {
                matches: mock_signature_matches(&request),
            },
        },
        ClientRequest::Health { request_id } => ServerResponse::Health {
            request_id,
            health: ClassifierHealth {
                ready: true,
                detail: Some("deterministic CI mock".to_owned()),
            },
        },
        ClientRequest::Version { request_id } => ServerResponse::Version {
            request_id,
            version: ClassifierVersion {
                version: MOCK_CLASSIFIER_VERSION.to_owned(),
                build: Some("ci-fixture".to_owned()),
            },
        },
        ClientRequest::RuleVersion { request_id } => ServerResponse::RuleVersion {
            request_id,
            version: RuleVersion {
                version: state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entitlement
                    .rule_version
                    .clone()
                    .unwrap_or_else(|| MOCK_RULE_VERSION.to_owned()),
                revision: Some("ci-fixture".to_owned()),
            },
        },
        ClientRequest::RuleStats { request_id } => ServerResponse::RuleStats {
            request_id,
            stats: mock_stats(state),
        },
        ClientRequest::ReloadRules { request_id } => ServerResponse::ReloadRules {
            request_id,
            stats: mock_stats(state),
        },
        ClientRequest::Metadata {
            request_id,
            kind,
            id,
        } => ServerResponse::Metadata {
            request_id,
            metadata: metadata(kind, &id),
        },
        ClientRequest::ApplyEntitlement {
            request_id,
            entitlement,
        } => {
            let entitlement = ClassifierEntitlement {
                edition: entitlement.edition,
                license_status: entitlement.license_status,
                lease_valid_until: Some(entitlement.lease_valid_until),
                rule_version: entitlement
                    .allowed_rule
                    .map(|rule| rule.rule_version)
                    .or_else(|| Some(MOCK_RULE_VERSION.to_owned())),
            };
            state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entitlement = entitlement.clone();
            ServerResponse::EntitlementApplied {
                request_id,
                entitlement,
            }
        }
        ClientRequest::EntitlementStatus { request_id } => ServerResponse::EntitlementStatus {
            request_id,
            entitlement: state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entitlement
                .clone(),
        },
        ClientRequest::Identity { request_id } => ServerResponse::Identity {
            request_id,
            identity: netqmon_classifier_client::ClassifierIdentity {
                key_id: "mock-classifier-key".to_owned(),
                public_key: "00".repeat(32),
            },
        },
    }
}

/// Deterministic mini signature table mirroring the Pro matcher behaviour:
/// a fixed-offset byte compare on the TCP/UDP application payload.
fn mock_signature_matches(
    request: &netqmon_classifier_client::FlowSampleMatchRequest,
) -> Vec<netqmon_classifier_client::FlowSampleApplicationMatch> {
    const SIGNATURES: [(&str, bool, &[u8]); 2] = [
        ("honor_of_kings", true, &[0x33, 0x66, 0x00, 0x0b]),
        ("qq_speed", false, &[0x28, 0x28]),
    ];
    let mut matches = Vec::new();
    for (application_id, tcp, pattern) in SIGNATURES {
        let hit = request.packets.iter().any(|packet| {
            let tcp_payload = tcp.then(|| l4_payload(&packet.payload, 6));
            let udp_payload = (!tcp).then(|| l4_payload(&packet.payload, 17));
            tcp_payload.or(udp_payload).is_some_and(|payload| {
                payload.len() >= pattern.len() && &payload[..pattern.len()] == pattern
            })
        });
        if hit {
            matches.push(netqmon_classifier_client::FlowSampleApplicationMatch {
                application_id: application_id.to_owned(),
                confidence: 0.95,
            });
        }
    }
    matches
}

fn l4_payload(raw: &[u8], transport: u8) -> Vec<u8> {
    let (header_len, l4) = match (raw.first().map(|byte| byte >> 4), raw.len()) {
        (Some(4), length) if length >= 20 => {
            let ihl = usize::from(raw[0] & 0x0f) * 4;
            (ihl, transport == raw[9])
        }
        (Some(6), length) if length >= 40 => (40, transport == raw[6]),
        _ => return Vec::new(),
    };
    if !l4 || raw.len() < header_len {
        return Vec::new();
    }
    match transport {
        6 => {
            let Some(byte) = raw.get(header_len + 12) else {
                return Vec::new();
            };
            let offset = usize::from(byte >> 4) * 4;
            if header_len + offset <= raw.len() {
                raw[header_len + offset..].to_vec()
            } else {
                Vec::new()
            }
        }
        _ => raw
            .get(header_len + 8..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
    }
}

fn classify(request: &netqmon_classifier_client::ClassificationRequest) -> ClassificationResult {
    let domain = request
        .domain
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let dpi_protocol = request
        .dpi_evidence
        .as_ref()
        .and_then(|evidence| evidence.attributes.get("protocol"))
        .map(|value| value.to_ascii_lowercase());
    let dpi_application = request
        .dpi_evidence
        .as_ref()
        .and_then(|evidence| evidence.attributes.get("application_protocol"))
        .map(|value| value.to_ascii_lowercase());

    let (organization, application, traffic_class, traffic_role, protocol_id) =
        if domain.contains("youtube.com") || domain.contains("googlevideo.com") {
            (Some("google"), Some("youtube"), "streaming", None, None)
        } else if domain == "github.com" || domain.ends_with(".github.com") {
            (
                Some("github"),
                Some("github"),
                "developer_tools",
                None,
                None,
            )
        } else if domain == "claude.ai" || domain.ends_with(".claude.ai") {
            (Some("anthropic"), Some("claude"), "ai", None, None)
        } else if is_bittorrent(request, dpi_protocol.as_deref()) {
            (None, None, "p2p", None, Some("bittorrent"))
        } else if dpi_application.as_deref() == Some("youtube") {
            (Some("google"), Some("youtube"), "streaming", None, None)
        } else if dpi_application.as_deref() == Some("github") {
            (
                Some("github"),
                Some("github"),
                "developer_tools",
                None,
                None,
            )
        } else if dpi_application.as_deref() == Some("claude") {
            (Some("anthropic"), Some("claude"), "ai", None, None)
        } else if let Some(signature) = request.signature_evidence.first() {
            match signature.application_id.as_str() {
                "honor_of_kings" => (
                    Some("tencent"),
                    Some("honor_of_kings"),
                    "gaming",
                    None,
                    None,
                ),
                "qq_speed" => (Some("tencent"), Some("qq_speed"), "gaming", None, None),
                _ => (None, None, "unknown", None, dpi_protocol.as_deref()),
            }
        } else {
            (None, None, "unknown", None, dpi_protocol.as_deref())
        };

    let mut evidence = Vec::new();
    if !domain.is_empty() && application.is_some() {
        evidence.push(ClassificationEvidence {
            evidence_type: "domain_application".to_owned(),
            value: domain,
            source: "mock-classifierd".to_owned(),
            weight: 1.0,
        });
    }
    if let Some(protocol) = &dpi_protocol {
        evidence.push(ClassificationEvidence {
            evidence_type: "dpi".to_owned(),
            value: protocol.clone(),
            source: "mock-classifierd".to_owned(),
            weight: 1.0,
        });
    }
    if let Some(signature) = request.signature_evidence.first() {
        evidence.push(ClassificationEvidence {
            evidence_type: "payload_signature".to_owned(),
            value: signature.application_id.clone(),
            source: "payload_signature".to_owned(),
            weight: signature.confidence,
        });
    }

    ClassificationResult {
        entry_id: request.entry_id.clone(),
        organization: organization.map(entity),
        application: application.map(entity),
        traffic_class: Some(ClassifiedEntity {
            id: traffic_class.to_owned(),
            confidence: if traffic_class == "unknown" { 0.0 } else { 1.0 },
        }),
        traffic_role: traffic_role.map(str::to_owned),
        protocol: protocol_id.map(entity),
        evidence,
        device_evidence: device_evidence(&request.device_evidence),
        error: None,
    }
}

fn is_bittorrent(
    request: &netqmon_classifier_client::ClassificationRequest,
    dpi_protocol: Option<&str>,
) -> bool {
    request.remote_port == Some(51_413)
        || dpi_protocol == Some("bittorrent")
        || request.dpi_evidence.as_ref().is_some_and(|evidence| {
            evidence
                .signals
                .iter()
                .any(|signal| signal.eq_ignore_ascii_case("bittorrent"))
        })
}

fn entity(id: &str) -> ClassifiedEntity {
    ClassifiedEntity {
        id: id.to_owned(),
        confidence: 1.0,
    }
}

fn device_evidence(
    evidence: &[netqmon_classifier_client::DeviceEvidenceInput],
) -> Vec<DeviceEvidenceResult> {
    evidence
        .iter()
        .filter(|item| {
            let text = item
                .text
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            text.contains("printer")
                || text.contains("laserjet")
                || item.field == "service" && text.contains("_ipp")
        })
        .map(|_| DeviceEvidenceResult {
            source: "mock-classifierd".to_owned(),
            field: "device_type".to_owned(),
            value: "printer".to_owned(),
            confidence: 1.0,
            rule_id: Some("mock-printer".to_owned()),
            priority: 100,
            metadata: BTreeMap::from([("device_type".to_owned(), "printer".to_owned())]),
        })
        .collect()
}

fn metadata(kind: EntityKind, id: &str) -> Option<EntityMetadata> {
    let (name, icon_domain, fallback_domains) = match (kind, id) {
        (EntityKind::Application, "youtube") => {
            ("YouTube", Some("youtube.com"), vec!["google.com"])
        }
        (EntityKind::Application | EntityKind::Organization, "github") => {
            ("GitHub", Some("github.com"), Vec::new())
        }
        (EntityKind::Application, "claude") => ("Claude", Some("claude.ai"), Vec::new()),
        (EntityKind::Organization, "google") => ("Google", Some("google.com"), Vec::new()),
        (EntityKind::Organization, "anthropic") => ("Anthropic", Some("anthropic.com"), Vec::new()),
        _ => return None,
    };
    Some(EntityMetadata {
        id: id.to_owned(),
        name: name.to_owned(),
        icon_domain: icon_domain.map(str::to_owned),
        fallback_domains: fallback_domains.into_iter().map(str::to_owned).collect(),
        local_fallback: None,
    })
}

fn community_entitlement() -> ClassifierEntitlement {
    ClassifierEntitlement {
        edition: "community".to_owned(),
        license_status: "unlicensed".to_owned(),
        lease_valid_until: None,
        rule_version: Some(MOCK_RULE_VERSION.to_owned()),
    }
}

/// Deterministic rule statistics mirroring the mock's mini rule tables.
fn mock_stats(state: &Arc<Mutex<MockState>>) -> RuleStats {
    RuleStats {
        application_count: 3,
        selfhost_application_count: 1,
        client_count: 1,
        protocol_count: 2,
        rule_version: state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entitlement
            .rule_version
            .clone()
            .unwrap_or_else(|| MOCK_RULE_VERSION.to_owned()),
        updated_at_unix_ms: 1_800_000_000_000,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_classifier_client::{
        AllowedRule, ApplicationSignatureEvidence, ClassificationBatchRequest,
        ClassificationRequest, EntitlementLease, FlowSampleMatchRequest, SamplePacketDirection,
        SamplePacketInput,
    };

    fn state() -> Arc<Mutex<MockState>> {
        Arc::new(Mutex::new(MockState {
            entitlement: community_entitlement(),
        }))
    }

    fn request(
        entry_id: &str,
        domain: Option<&str>,
        remote_port: Option<u16>,
    ) -> ClassificationRequest {
        ClassificationRequest {
            entry_id: entry_id.to_owned(),
            domain: domain.map(str::to_owned),
            remote_ip: None,
            remote_asn: None,
            remote_port,
            protocol: Some("6".to_owned()),
            favicon_sha256: None,
            dpi_evidence: None,
            device_evidence: Vec::new(),
            signature_evidence: Vec::new(),
        }
    }

    #[test]
    fn classifies_ci_domains_and_bittorrent_deterministically() {
        let response = response_for(
            ClientRequest::ClassifyBatch {
                request_id: "batch".to_owned(),
                request: ClassificationBatchRequest {
                    entries: vec![
                        request("youtube", Some("www.youtube.com"), Some(443)),
                        request("github", Some("github.com"), Some(443)),
                        request("claude", Some("claude.ai"), Some(443)),
                        request("bittorrent", None, Some(51_413)),
                    ],
                },
            },
            &state(),
        );
        let ServerResponse::ClassificationBatch { result, .. } = response else {
            panic!("mock returned the wrong response type");
        };
        let applications = result
            .entries
            .iter()
            .map(|entry| entry.application.as_ref().map(|value| value.id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            applications,
            vec![Some("youtube"), Some("github"), Some("claude"), None]
        );
        assert_eq!(
            result.entries[3]
                .protocol
                .as_ref()
                .map(|value| value.id.as_str()),
            Some("bittorrent")
        );
    }

    fn ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut packet = vec![0x45, 0x00];
        packet.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 6, 0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[203, 0, 113, 9]);
        packet.extend_from_slice(&51_000u16.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.push(0x50);
        packet.push(0x10);
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut packet = vec![0x45, 0x00];
        packet.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[203, 0, 113, 9]);
        packet.extend_from_slice(&51_000u16.to_be_bytes());
        packet.extend_from_slice(&40000u16.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(payload);
        packet
    }

    fn sample_request(packets: Vec<SamplePacketInput>) -> FlowSampleMatchRequest {
        FlowSampleMatchRequest {
            flow: netqmon_classifier_client::FlowSampleKey {
                client_ip: "192.168.1.10".to_owned(),
                client_port: 51_000,
                remote_ip: "203.0.113.9".to_owned(),
                remote_port: 443,
                protocol: "tcp".to_owned(),
                first_seen_unix_ms: 1,
            },
            packets,
        }
    }

    #[test]
    fn matches_payload_signatures_deterministically() {
        let hit = ipv4_tcp_packet(&[0x33, 0x66, 0x00, 0x0b, 0xff]);
        let miss = ipv4_tcp_packet(&[0x33, 0x66, 0x00, 0x0c, 0xff]);
        let response = response_for(
            ClientRequest::MatchFlowSamples {
                request_id: "sample-1".to_owned(),
                request: sample_request(vec![
                    SamplePacketInput {
                        direction: SamplePacketDirection::Upload,
                        captured_length: u32::try_from(miss.len()).unwrap(),
                        payload: miss,
                    },
                    SamplePacketInput {
                        direction: SamplePacketDirection::Upload,
                        captured_length: u32::try_from(hit.len()).unwrap(),
                        payload: hit,
                    },
                ]),
            },
            &state(),
        );
        let ServerResponse::FlowSampleMatch { result, .. } = response else {
            panic!("mock returned the wrong response type");
        };
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].application_id, "honor_of_kings");
        assert!((result.matches[0].confidence - 0.95).abs() < f64::EPSILON);

        let udp = ipv4_udp_packet(&[0x28, 0x28, 0x00]);
        let response = response_for(
            ClientRequest::MatchFlowSamples {
                request_id: "sample-2".to_owned(),
                request: sample_request(vec![SamplePacketInput {
                    direction: SamplePacketDirection::Upload,
                    captured_length: u32::try_from(udp.len()).unwrap(),
                    payload: udp,
                }]),
            },
            &state(),
        );
        let ServerResponse::FlowSampleMatch { result, .. } = response else {
            panic!("mock returned the wrong response type");
        };
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].application_id, "qq_speed");
    }

    #[test]
    fn classifies_signature_evidence_as_application() {
        let mut entry = request("sig", None, Some(443));
        entry.signature_evidence = vec![ApplicationSignatureEvidence {
            application_id: "honor_of_kings".to_owned(),
            source: "payload_signature".to_owned(),
            confidence: 0.95,
        }];
        let response = response_for(
            ClientRequest::ClassifyBatch {
                request_id: "batch".to_owned(),
                request: ClassificationBatchRequest {
                    entries: vec![entry],
                },
            },
            &state(),
        );
        let ServerResponse::ClassificationBatch { result, .. } = response else {
            panic!("mock returned the wrong response type");
        };
        let entry = &result.entries[0];
        assert_eq!(
            entry.application.as_ref().map(|value| value.id.as_str()),
            Some("honor_of_kings")
        );
        assert_eq!(
            entry.organization.as_ref().map(|value| value.id.as_str()),
            Some("tencent")
        );
        assert!(
            entry
                .evidence
                .iter()
                .any(|evidence| evidence.evidence_type == "payload_signature")
        );
    }

    #[test]
    fn handles_control_messages_and_never_retains_credentials() {
        let state = state();
        let health = response_for(
            ClientRequest::Health {
                request_id: "health".to_owned(),
            },
            &state,
        );
        assert!(matches!(
            health,
            ServerResponse::Health {
                health: ClassifierHealth { ready: true, .. },
                ..
            }
        ));
        assert!(matches!(
            response_for(
                ClientRequest::Version { request_id: "version".to_owned() },
                &state,
            ),
            ServerResponse::Version { version: ClassifierVersion { version, .. }, .. } if version == MOCK_CLASSIFIER_VERSION
        ));
        assert!(matches!(
            response_for(
                ClientRequest::RuleVersion { request_id: "rules".to_owned() },
                &state,
            ),
            ServerResponse::RuleVersion { version: RuleVersion { version, .. }, .. } if version == MOCK_RULE_VERSION
        ));
        assert!(matches!(
            response_for(
                ClientRequest::RuleStats { request_id: "stats".to_owned() },
                &state,
            ),
            ServerResponse::RuleStats { stats: RuleStats { application_count: 3, rule_version, .. }, .. }
                if rule_version == MOCK_RULE_VERSION
        ));
        assert!(matches!(
            response_for(
                ClientRequest::ReloadRules {
                    request_id: "reload".to_owned()
                },
                &state,
            ),
            ServerResponse::ReloadRules {
                stats: RuleStats {
                    client_count: 1,
                    protocol_count: 2,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            response_for(
                ClientRequest::Metadata {
                    request_id: "metadata".to_owned(),
                    kind: EntityKind::Application,
                    id: "youtube".to_owned(),
                },
                &state,
            ),
            ServerResponse::Metadata { metadata: Some(EntityMetadata { name, .. }), .. } if name == "YouTube"
        ));

        let applied = response_for(
            ClientRequest::ApplyEntitlement {
                request_id: "apply".to_owned(),
                entitlement: EntitlementLease {
                    edition: "pro".to_owned(),
                    license_status: "active".to_owned(),
                    lease_valid_until: 1_800_000_000,
                    allowed_rule: Some(AllowedRule {
                        artifact_id: "pro-rules".to_owned(),
                        rule_version: "pro-2026.09".to_owned(),
                        edition: "pro".to_owned(),
                    }),
                    cloud_api_url: "https://cloud.example".to_owned(),
                    installation_credential: Some("must-not-be-retained".to_owned()),
                    sealed_rule_key: None,
                },
            },
            &state,
        );
        assert!(matches!(
            applied,
            ServerResponse::EntitlementApplied { entitlement: ClassifierEntitlement { edition, rule_version: Some(rule_version), .. }, .. }
                if edition == "pro" && rule_version == "pro-2026.09"
        ));
        assert!(matches!(
            response_for(
                ClientRequest::EntitlementStatus { request_id: "status".to_owned() },
                &state,
            ),
            ServerResponse::EntitlementStatus { entitlement: ClassifierEntitlement { edition, rule_version: Some(rule_version), .. }, .. }
                if edition == "pro" && rule_version == "pro-2026.09"
        ));
    }
}
