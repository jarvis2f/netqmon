//! Collector-facing adapter for the private classifier IPC service.
//!
//! This module intentionally contains only wire conversion and diagnostics;
//! classification is performed by `netqmon-classifierd`.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use netqmon_classifier_client::{
    ApplicationSignatureEvidence, ClassificationBatchRequest, ClassificationRequest,
    ClassifierClient, ClassifierClientConfig, ClassifierEntitlement, DeviceEvidenceInput,
    DeviceEvidenceResult, DpiEvidence as WireDpiEvidence, EntitlementLease, EntityKind,
    EntityMetadata as WireMetadata, FlowSampleMatchRequest, SamplePacketDirection,
    SamplePacketInput as WireSamplePacketInput,
};

use crate::dpi::{SignatureApplicationMatch, SignatureMatcher};
use netqmon_protocol::v1::{FlowSampleKey, SamplePacket};

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct EntityClassification {
    pub id: String,
    pub confidence: f64,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct TrafficClassClassification {
    pub id: String,
    pub confidence: f64,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ProtocolClassification {
    pub id: String,
    pub confidence: f64,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ClassificationEvidence {
    pub evidence_type: String,
    pub value: String,
    pub source: String,
    pub weight: f64,
}
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct ClassificationResult {
    pub organization: Option<EntityClassification>,
    pub application: Option<EntityClassification>,
    pub traffic_class: Option<TrafficClassClassification>,
    pub traffic_role: Option<String>,
    pub protocol: Option<ProtocolClassification>,
    pub evidence: Vec<ClassificationEvidence>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct IconMetadata {
    pub domain: Option<String>,
    pub fallback_domains: Vec<String>,
    pub local_fallback: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EntityMetadata {
    pub id: String,
    pub name: String,
    pub icon: IconMetadata,
}
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct RuleDiagnostics {
    /// Version of the connected classifierd, when reachable.
    pub classifier_version: Option<String>,
    /// Rule-set statistics reported by classifierd, when reachable.
    pub stats: Option<netqmon_classifier_client::RuleStats>,
    /// Connection state of the separately managed classifier process.
    pub availability: String,
    /// Most recent IPC failure. This deliberately contains no request data.
    pub last_error: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ClassificationInput<'a> {
    pub domain: Option<&'a str>,
    pub remote_ip: IpAddr,
    pub remote_asn: Option<u32>,
    pub remote_port: u16,
    pub protocol: u8,
    pub dpi: Option<DpiEvidence<'a>>,
    pub signatures: Vec<SignatureApplicationMatch>,
}
#[derive(Clone, Copy, Debug)]
pub struct DpiEvidence<'a> {
    pub application_protocol: Option<&'a str>,
    pub protocol: &'a str,
    pub source: &'a str,
    pub confidence: f64,
}

pub(crate) struct DeviceFingerprintInput {
    pub entry_id: String,
    pub evidence: Vec<DeviceEvidenceInput>,
}

#[derive(Clone)]
pub struct ClassifierHandle {
    client: Arc<ClassifierClient>,
    availability: Arc<Mutex<AvailabilityState>>,
    #[cfg(test)]
    test_mode: bool,
    #[cfg(test)]
    test_entitlement: Arc<Mutex<Option<ClassifierEntitlement>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Availability {
    Unavailable,
    Connecting,
    Ready,
}

impl Availability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Connecting => "connecting",
            Self::Ready => "ready",
        }
    }
}

#[derive(Debug)]
struct AvailabilityState {
    state: Availability,
    next_probe: Instant,
    failure_delay: Duration,
    last_error: Option<String>,
}

impl Default for AvailabilityState {
    fn default() -> Self {
        Self {
            state: Availability::Unavailable,
            next_probe: Instant::now(),
            failure_delay: Duration::from_secs(1),
            last_error: None,
        }
    }
}

const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const CIRCUIT_OPEN_ERROR: &str = "classifier unavailable (reconnect scheduled)";

impl ClassifierHandle {
    pub fn connect(socket_path: PathBuf) -> Result<Self, String> {
        let client = ClassifierClient::new(ClassifierClientConfig {
            socket_path,
            // A missing dynamic component must not hold ingestion for the
            // client library's multi-second defaults. The availability circuit
            // prevents subsequent flows from attempting an IPC call at all.
            connect_timeout: Duration::from_millis(250),
            read_timeout: Duration::from_millis(500),
            write_timeout: Duration::from_millis(500),
            ..ClassifierClientConfig::default()
        })
        .map_err(|error| error.to_string())?;
        Ok(Self {
            client: Arc::new(client),
            availability: Arc::new(Mutex::new(AvailabilityState::default())),
            #[cfg(test)]
            test_mode: false,
            #[cfg(test)]
            test_entitlement: Arc::new(Mutex::new(None)),
        })
    }

    pub fn disabled() -> Self {
        Self {
            client: Arc::new(
                ClassifierClient::new(ClassifierClientConfig {
                    socket_path: PathBuf::from("/disabled/classifierd.sock"),
                    connect_timeout: Duration::from_millis(1),
                    ..Default::default()
                })
                .expect("disabled classifier client config"),
            ),
            availability: Arc::new(Mutex::new(AvailabilityState {
                state: Availability::Ready,
                ..AvailabilityState::default()
            })),
            #[cfg(test)]
            test_mode: false,
            #[cfg(test)]
            test_entitlement: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub fn test_default() -> Self {
        Self {
            client: Arc::new(
                ClassifierClient::new(ClassifierClientConfig {
                    socket_path: PathBuf::from("/missing/classifierd.sock"),
                    connect_timeout: std::time::Duration::from_millis(1),
                    ..Default::default()
                })
                .expect("test client config"),
            ),
            availability: Arc::new(Mutex::new(AvailabilityState {
                state: Availability::Ready,
                ..AvailabilityState::default()
            })),
            test_mode: true,
            test_entitlement: Arc::new(Mutex::new(None)),
        }
    }

    pub fn classify(
        &self,
        input: &ClassificationInput<'_>,
    ) -> Result<ClassificationResult, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(fixture_classification(input));
        }
        self.classify_request(ClassificationRequest {
            entry_id: "collector".to_owned(),
            domain: input.domain.map(str::to_owned),
            remote_ip: Some(input.remote_ip.to_string()),
            remote_asn: input.remote_asn,
            remote_port: Some(input.remote_port),
            protocol: Some(input.protocol.to_string()),
            favicon_sha256: None,
            signature_evidence: signature_evidence(&input.signatures),
            dpi_evidence: input.dpi.map(|dpi| WireDpiEvidence {
                source: dpi.source.to_owned(),
                signals: vec![format!("protocol={}", dpi.protocol)],
                attributes: [
                    ("protocol".to_owned(), dpi.protocol.to_owned()),
                    ("confidence".to_owned(), dpi.confidence.to_string()),
                ]
                .into_iter()
                .chain(
                    dpi.application_protocol
                        .map(|value| ("application_protocol".to_owned(), value.to_owned())),
                )
                .collect(),
            }),
            device_evidence: Vec::new(),
        })
    }

    pub fn health(&self) -> Result<(), String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(());
        }
        self.request(|client| client.health().map(|_| ()))
    }

    pub fn classifier_version(&self) -> Result<String, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok("test".to_owned());
        }
        self.request(|client| client.classifier_version().map(|value| value.version))
    }

    pub fn rule_version(&self) -> Result<String, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok("test".to_owned());
        }
        self.request(|client| client.rule_version().map(|value| value.version))
    }

    pub fn rule_stats(&self) -> Result<netqmon_classifier_client::RuleStats, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(fixture_rule_stats());
        }
        self.request(ClassifierClient::rule_stats)
    }

    pub fn reload_rules(&self) -> Result<netqmon_classifier_client::RuleStats, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(fixture_rule_stats());
        }
        self.request(ClassifierClient::reload_rules)
    }

    pub fn identity(&self) -> Result<netqmon_classifier_client::ClassifierIdentity, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(netqmon_classifier_client::ClassifierIdentity {
                key_id: "test-key-id".to_owned(),
                public_key: "00".repeat(32),
            });
        }
        self.request(ClassifierClient::identity)
    }

    pub fn apply_entitlement(
        &self,
        entitlement: EntitlementLease,
    ) -> Result<ClassifierEntitlement, String> {
        #[cfg(test)]
        if self.test_mode {
            let res = ClassifierEntitlement {
                edition: entitlement.edition,
                license_status: entitlement.license_status,
                lease_valid_until: Some(entitlement.lease_valid_until),
                rule_version: Some("test".into()),
            };
            *self
                .test_entitlement
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(res.clone());
            return Ok(res);
        }
        self.request(|client| client.apply_entitlement(entitlement))
    }

    pub fn entitlement_status(&self) -> Result<ClassifierEntitlement, String> {
        #[cfg(test)]
        if self.test_mode {
            if let Some(stored) = self
                .test_entitlement
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
            {
                return Ok(stored);
            }
            return Ok(ClassifierEntitlement {
                edition: "community".into(),
                license_status: "unlicensed".into(),
                lease_valid_until: None,
                rule_version: Some("test".into()),
            });
        }
        self.request(ClassifierClient::entitlement_status)
    }

    fn classify_request(
        &self,
        request: ClassificationRequest,
    ) -> Result<ClassificationResult, String> {
        let response = self.request(|client| {
            client.classify_batch(ClassificationBatchRequest {
                entries: vec![request],
            })
        })?;
        let result = response
            .entries
            .into_iter()
            .next()
            .ok_or_else(|| "classifier returned an empty result".to_owned())?;
        if let Some(error) = result.error {
            return Err(format!("{}: {}", error.code, error.message));
        }
        Ok(ClassificationResult {
            organization: result.organization.map(|v| EntityClassification {
                id: v.id,
                confidence: v.confidence,
            }),
            application: result.application.map(|v| EntityClassification {
                id: v.id,
                confidence: v.confidence,
            }),
            traffic_class: result.traffic_class.map(|v| TrafficClassClassification {
                id: v.id,
                confidence: v.confidence,
            }),
            traffic_role: result.traffic_role,
            protocol: result.protocol.map(|v| ProtocolClassification {
                id: v.id,
                confidence: v.confidence,
            }),
            evidence: result
                .evidence
                .into_iter()
                .map(|v| ClassificationEvidence {
                    evidence_type: v.evidence_type,
                    value: v.value,
                    source: v.source,
                    weight: v.weight,
                })
                .collect(),
        })
    }

    pub fn classify_favicon_sha256(&self, digest: &[u8]) -> Result<ClassificationResult, String> {
        #[cfg(test)]
        if self.test_mode {
            let _ = digest;
            return Ok(ClassificationResult {
                organization: Some(EntityClassification {
                    id: "selfhost".to_owned(),
                    confidence: 1.0,
                }),
                application: Some(EntityClassification {
                    id: "selfhost_jellyfin".to_owned(),
                    confidence: 1.0,
                }),
                traffic_class: Some(TrafficClassClassification {
                    id: "streaming".to_owned(),
                    confidence: 1.0,
                }),
                traffic_role: None,
                protocol: None,
                evidence: Vec::new(),
            });
        }
        let request = ClassificationRequest {
            entry_id: "favicon".to_owned(),
            domain: None,
            remote_ip: None,
            remote_asn: None,
            remote_port: None,
            protocol: None,
            favicon_sha256: Some(hex_digest(digest)),
            dpi_evidence: None,
            device_evidence: Vec::new(),
            signature_evidence: Vec::new(),
        };
        self.classify_request(request)
    }

    pub fn classify_devices(
        &self,
        inputs: Vec<DeviceFingerprintInput>,
    ) -> Result<HashMap<String, Vec<DeviceEvidenceResult>>, String> {
        #[cfg(test)]
        if self.test_mode {
            let mut results = HashMap::new();
            for input in inputs {
                let mut evidence = Vec::new();
                for ev in &input.evidence {
                    let text = ev.text.as_deref().unwrap_or_default();
                    if (ev.field == "service" && text.contains("_ipp"))
                        || (ev.field == "hostname" && text.contains("printer"))
                        || (ev.field == "mdns_model" && text.contains("LaserJet"))
                        || text.contains("printer")
                        || text.contains("LaserJet")
                    {
                        let mut metadata = std::collections::BTreeMap::new();
                        metadata.insert("device_type".to_owned(), "printer".to_owned());
                        evidence.push(DeviceEvidenceResult {
                            source: "test-fixture".to_owned(),
                            field: "device_type".to_owned(),
                            value: "printer".to_owned(),
                            confidence: 1.0,
                            rule_id: Some("printer-fixture".to_owned()),
                            priority: 100,
                            metadata,
                        });
                    }
                }
                results.insert(input.entry_id, evidence);
            }
            return Ok(results);
        }
        let requests = inputs
            .into_iter()
            .map(|input| ClassificationRequest {
                entry_id: input.entry_id,
                domain: None,
                remote_ip: None,
                remote_asn: None,
                remote_port: None,
                protocol: None,
                favicon_sha256: None,
                dpi_evidence: None,
                device_evidence: input.evidence,
                signature_evidence: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut results = HashMap::new();
        for chunk in requests.chunks(1024) {
            let response = self.request(|client| {
                client.classify_batch(ClassificationBatchRequest {
                    entries: chunk.to_vec(),
                })
            })?;
            for result in response.entries {
                if let Some(error) = result.error {
                    return Err(format!("{}: {}", error.code, error.message));
                }
                results.insert(result.entry_id, result.device_evidence);
            }
        }
        Ok(results)
    }

    pub fn application_metadata(&self, id: &str) -> Option<EntityMetadata> {
        self.metadata(EntityKind::Application, id)
    }
    pub fn organization_metadata(&self, id: &str) -> Option<EntityMetadata> {
        self.metadata(EntityKind::Organization, id)
    }
    #[allow(clippy::unused_self)]
    pub fn application_organization_id(&self, id: &str) -> Option<String> {
        fallback_application_org_id(id)
    }
    fn metadata(&self, kind: EntityKind, id: &str) -> Option<EntityMetadata> {
        #[cfg(test)]
        if self.test_mode {
            return fixture_metadata(kind, id);
        }
        if let Some(metadata) = self
            .request(|client| client.metadata(kind, id))
            .ok()
            .flatten()
            .map(map_metadata)
        {
            return Some(metadata);
        }
        fallback_metadata(kind, id)
    }
    /// Matches bounded flow samples through classifierd's payload-signature
    /// engine. A missing or older classifierd yields no matches and never
    /// blocks sampling.
    pub fn match_flow_samples(
        &self,
        request: FlowSampleMatchRequest,
    ) -> Result<Vec<SignatureApplicationMatch>, String> {
        #[cfg(test)]
        if self.test_mode {
            return Ok(fixture_signature_matches(&request));
        }
        let result = self.request(|client| client.match_flow_samples(request))?;
        Ok(result
            .matches
            .into_iter()
            .map(|matched| SignatureApplicationMatch {
                application_id: matched.application_id,
                confidence: matched.confidence,
            })
            .collect())
    }

    pub fn diagnostics(&self) -> RuleDiagnostics {
        let stats = self.rule_stats().ok();
        let classifier_version = self.classifier_version().ok();
        let state = self
            .availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        RuleDiagnostics {
            classifier_version,
            stats,
            availability: state.state.as_str().to_owned(),
            last_error: state.last_error.clone(),
        }
    }

    /// Runs an IPC operation when the circuit is closed. A failed operation
    /// opens the circuit and schedules a 1–30 second retry; successful calls
    /// immediately make the component ready again.
    fn request<T>(
        &self,
        operation: impl FnOnce(
            &ClassifierClient,
        ) -> Result<T, netqmon_classifier_client::ClassifierClientError>,
    ) -> Result<T, String> {
        self.begin_request()?;
        match operation(&self.client) {
            Ok(value) => {
                self.mark_ready();
                Ok(value)
            }
            Err(error) => {
                let error = error.to_string();
                self.mark_unavailable(&error);
                Err(error)
            }
        }
    }

    fn begin_request(&self) -> Result<(), String> {
        let mut state = self
            .availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.state == Availability::Ready {
            return Ok(());
        }
        if state.state == Availability::Unavailable && Instant::now() >= state.next_probe {
            state.state = Availability::Connecting;
            return Ok(());
        }
        Err(CIRCUIT_OPEN_ERROR.to_owned())
    }

    fn mark_ready(&self) {
        let mut state = self
            .availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let recovered = state.state != Availability::Ready;
        state.state = Availability::Ready;
        state.failure_delay = Duration::from_secs(1);
        state.last_error = None;
        if recovered {
            tracing::info!("classifier IPC became ready");
        }
    }

    fn mark_unavailable(&self, error: &str) {
        let mut state = self
            .availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let was_available = state.state == Availability::Ready;
        let delay = state.failure_delay;
        state.state = Availability::Unavailable;
        state.next_probe = Instant::now() + delay;
        state.failure_delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        state.last_error = Some(error.to_owned());
        if was_available {
            tracing::warn!(%error, "classifier IPC became unavailable");
        }
    }

    #[allow(dead_code)]
    #[allow(clippy::unused_self)]
    pub fn ndpi_applications(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        EMPTY.get_or_init(HashMap::new)
    }
    pub fn valid_icon_hostname_for_metadata(hostname: &str) -> bool {
        !hostname.is_empty()
            && hostname.len() <= 253
            && hostname.contains('.')
            && !hostname.chars().any(|ch| matches!(ch, '/' | ':' | '*'))
            && hostname.parse::<IpAddr>().is_err()
            && hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    }
}

#[cfg(test)]
fn fixture_signature_classification(
    signature: &SignatureApplicationMatch,
    dpi_protocol: Option<&str>,
) -> ClassificationResult {
    let organization = match signature.application_id.as_str() {
        "honor_of_kings" | "qq_speed" => Some("tencent"),
        _ => None,
    };
    ClassificationResult {
        organization: organization.map(|id| EntityClassification {
            id: id.to_owned(),
            confidence: 1.0,
        }),
        application: Some(EntityClassification {
            id: signature.application_id.clone(),
            confidence: signature.confidence,
        }),
        traffic_class: Some(TrafficClassClassification {
            id: "gaming".to_owned(),
            confidence: signature.confidence,
        }),
        traffic_role: None,
        protocol: dpi_protocol.map(|protocol| ProtocolClassification {
            id: protocol.to_ascii_lowercase(),
            confidence: 1.0,
        }),
        evidence: vec![ClassificationEvidence {
            evidence_type: "payload_signature".to_owned(),
            value: signature.application_id.clone(),
            source: "payload_signature".to_owned(),
            weight: signature.confidence,
        }],
    }
}

#[cfg(test)]
fn fixture_rule_stats() -> netqmon_classifier_client::RuleStats {
    netqmon_classifier_client::RuleStats {
        application_count: 3,
        selfhost_application_count: 1,
        client_count: 1,
        protocol_count: 2,
        rule_version: "test-rule-version".to_owned(),
        updated_at_unix_ms: 1_800_000_000_000,
        ..Default::default()
    }
}

#[cfg(test)]
fn fixture_classification(input: &ClassificationInput<'_>) -> ClassificationResult {
    if let Some(signature) = input.signatures.first() {
        let dpi_protocol = input.dpi.map(|dpi| dpi.protocol);
        return fixture_signature_classification(signature, dpi_protocol);
    }
    let domain = input.domain.unwrap_or_default().to_ascii_lowercase();
    let dpi_protocol = input.dpi.map(|d| d.protocol.to_ascii_lowercase());
    let dpi_app = input
        .dpi
        .and_then(|d| d.application_protocol.map(str::to_ascii_lowercase));

    let (organization, application, traffic_class, traffic_role) =
        if domain.contains("youtube.com") || domain.contains("googlevideo.com") {
            (Some("google"), Some("youtube"), "streaming", None)
        } else if domain.contains("netflix.com") {
            (Some("netflix"), Some("netflix"), "streaming", None)
        } else if domain.contains("openai.com") {
            (Some("openai"), Some("openai"), "ai", None)
        } else if domain.contains("tracker") || domain.contains("hdtime.org") {
            (None, None, "p2p", Some("tracker_service".to_owned()))
        } else if dpi_protocol.as_deref() == Some("jellyfin") {
            (
                Some("selfhost"),
                Some("selfhost_jellyfin"),
                "streaming",
                None,
            )
        } else if dpi_protocol.as_deref() == Some("bittorrent") {
            (None, None, "p2p", None)
        } else if dpi_app.as_deref() == Some("youtube") {
            (Some("google"), Some("youtube"), "streaming", None)
        } else if dpi_app.as_deref() == Some("netflix") {
            (Some("netflix"), Some("netflix"), "streaming", None)
        } else {
            (None, None, "unknown", None)
        };

    let protocol = dpi_protocol.map(|proto| ProtocolClassification {
        id: proto,
        confidence: 1.0,
    });

    let mut evidence = Vec::new();
    if application.is_some()
        && (domain.contains("youtube.com")
            || domain.contains("googlevideo.com")
            || domain.contains("netflix.com")
            || domain.contains("openai.com"))
    {
        evidence.push(ClassificationEvidence {
            evidence_type: "domain_application".to_owned(),
            value: domain,
            source: "test-fixture".to_owned(),
            weight: 1.0,
        });
    } else if let Some(app) = dpi_app
        .as_deref()
        .filter(|a| matches!(*a, "youtube" | "netflix"))
    {
        evidence.push(ClassificationEvidence {
            evidence_type: "ndpi_application".to_owned(),
            value: app.to_owned(),
            source: "ndpi".to_owned(),
            weight: 1.0,
        });
    } else if !domain.is_empty() && (domain.contains("tracker") || domain.contains("hdtime.org")) {
        evidence.push(ClassificationEvidence {
            evidence_type: "domain_application".to_owned(),
            value: domain,
            source: "test-fixture".to_owned(),
            weight: 1.0,
        });
    }
    if let Some(dpi) = input.dpi {
        evidence.push(ClassificationEvidence {
            evidence_type: "dpi".to_owned(),
            value: dpi.protocol.to_owned(),
            source: dpi.source.to_owned(),
            weight: 1.0,
        });
    }

    ClassificationResult {
        organization: organization.map(|id| EntityClassification {
            id: id.to_owned(),
            confidence: 1.0,
        }),
        application: application.map(|id| EntityClassification {
            id: id.to_owned(),
            confidence: 1.0,
        }),
        traffic_class: Some(TrafficClassClassification {
            id: traffic_class.to_owned(),
            confidence: if traffic_class == "unknown" { 0.0 } else { 1.0 },
        }),
        traffic_role,
        protocol,
        evidence,
    }
}

fn fallback_metadata(kind: EntityKind, id: &str) -> Option<EntityMetadata> {
    let (name, icon_domain, fallback_domains, local_fallback) = match (kind, id) {
        // Applications
        (EntityKind::Application, "youtube") => (
            "YouTube",
            Some("youtube.com"),
            vec!["googlevideo.com"],
            Some("youtube"),
        ),
        (EntityKind::Application, "netflix") => (
            "Netflix",
            Some("netflix.com"),
            vec!["nflxvideo.net"],
            Some("netflix"),
        ),
        (EntityKind::Application, "bilibili") => (
            "Bilibili",
            Some("bilibili.com"),
            vec!["bilivideo.com"],
            Some("bilibili"),
        ),
        (EntityKind::Application, "github") => (
            "GitHub",
            Some("github.com"),
            vec!["githubassets.com"],
            Some("github"),
        ),
        (EntityKind::Application, "openai") => (
            "OpenAI",
            Some("openai.com"),
            vec!["chatgpt.com"],
            Some("openai"),
        ),
        (EntityKind::Application, "steam") => (
            "Steam",
            Some("steampowered.com"),
            vec!["steamcommunity.com"],
            Some("steam"),
        ),
        (EntityKind::Application, "playstation-network" | "playstation") => (
            "PlayStation Network",
            Some("playstation.com"),
            vec!["playstation.net"],
            Some("playstation"),
        ),
        (EntityKind::Application, "nintendo-eshop" | "nintendo") => (
            "Nintendo eShop",
            Some("nintendo.com"),
            vec!["nintendo.net"],
            None,
        ),
        (EntityKind::Application, "spotify") => {
            ("Spotify", Some("spotify.com"), vec![], Some("spotify"))
        }
        (EntityKind::Application, "apple-music") => (
            "Apple Music",
            Some("music.apple.com"),
            vec!["apple.com"],
            Some("applemusic"),
        ),
        (EntityKind::Application, "icloud") => (
            "Apple iCloud",
            Some("icloud.com"),
            vec!["apple.com"],
            Some("icloud"),
        ),
        (EntityKind::Application, "slack") => ("Slack", Some("slack.com"), vec![], Some("slack")),
        (EntityKind::Application, "discord") => (
            "Discord",
            Some("discord.com"),
            vec!["discord.gg"],
            Some("discord"),
        ),
        (EntityKind::Application, "wechat") => (
            "WeChat",
            Some("weixin.qq.com"),
            vec!["qq.com"],
            Some("wechat"),
        ),
        (EntityKind::Application, "telegram") => {
            ("Telegram", Some("telegram.org"), vec![], Some("telegram"))
        }
        (EntityKind::Application, "reddit") => (
            "Reddit",
            Some("reddit.com"),
            vec!["redd.it"],
            Some("reddit"),
        ),
        (EntityKind::Application, "microsoft-365" | "microsoft") => (
            "Microsoft 365",
            Some("office.com"),
            vec!["microsoft.com"],
            Some("microsoft"),
        ),
        (EntityKind::Application, "notion") => {
            ("Notion", Some("notion.so"), vec![], Some("notion"))
        }
        (EntityKind::Application, "amazon-prime-video" | "primevideo") => (
            "Prime Video",
            Some("primevideo.com"),
            vec!["amazon.com"],
            Some("primevideo"),
        ),
        (EntityKind::Application, "docker-hub" | "docker") => (
            "Docker Hub",
            Some("docker.com"),
            vec!["docker.io"],
            Some("docker"),
        ),
        (EntityKind::Application, "wikipedia") => (
            "Wikipedia",
            Some("wikipedia.org"),
            vec![],
            Some("wikipedia"),
        ),
        (EntityKind::Application, "cloudflare-dns" | "cloudflare") => (
            "Cloudflare",
            Some("cloudflare.com"),
            vec!["1.1.1.1"],
            Some("cloudflare"),
        ),
        (EntityKind::Application, "google-dns" | "google") => (
            "Google",
            Some("google.com"),
            vec!["dns.google"],
            Some("google"),
        ),
        (EntityKind::Application, "ntp") => (
            "NTP Service",
            Some("cloudflare.com"),
            vec!["pool.ntp.org"],
            None,
        ),
        (EntityKind::Application, "twitch") => {
            ("Twitch", Some("twitch.tv"), vec![], Some("twitch"))
        }
        (EntityKind::Application, "aqara-cloud" | "aqara") => {
            ("Aqara IoT", Some("aqara.com"), vec![], None)
        }
        (EntityKind::Application, "cloudflare-backup") => (
            "Cloudflare R2",
            Some("cloudflare.com"),
            vec![],
            Some("cloudflare"),
        ),
        (EntityKind::Application, "nas-smb") => ("LAN File Sharing", None, vec![], None),
        (EntityKind::Application, "plex") => {
            ("Plex Media Server", Some("plex.tv"), vec![], Some("plex"))
        }
        (EntityKind::Application, "synology-dsm" | "synology") => (
            "Synology DSM",
            Some("synology.com"),
            vec![],
            Some("synology"),
        ),
        (EntityKind::Application, "speedtest") => (
            "Speedtest",
            Some("speedtest.net"),
            vec![],
            Some("speedtest"),
        ),
        (EntityKind::Application, "xiaohongshu") => {
            ("Xiaohongshu", None, vec![], Some("xiaohongshu"))
        }
        (EntityKind::Application, "tiktok") => {
            ("TikTok", Some("tiktok.com"), vec![], Some("tiktok"))
        }
        (EntityKind::Application, "twitter" | "x") => {
            ("X", Some("x.com"), vec!["twitter.com"], Some("x"))
        }
        (EntityKind::Application, "facebook") => {
            ("Facebook", Some("facebook.com"), vec![], Some("facebook"))
        }
        (EntityKind::Application, "instagram") => (
            "Instagram",
            Some("instagram.com"),
            vec![],
            Some("instagram"),
        ),
        (EntityKind::Application, "zoom") => ("Zoom", Some("zoom.us"), vec![], Some("zoom")),
        (EntityKind::Application, "whatsapp") => {
            ("WhatsApp", Some("whatsapp.com"), vec![], Some("whatsapp"))
        }

        // Organizations
        (EntityKind::Organization, "google") => {
            ("Google", Some("google.com"), vec![], Some("google"))
        }
        (EntityKind::Organization, "apple") => ("Apple", Some("apple.com"), vec![], Some("apple")),
        (EntityKind::Organization, "microsoft") => (
            "Microsoft",
            Some("microsoft.com"),
            vec![],
            Some("microsoft"),
        ),
        (EntityKind::Organization, "amazon") => {
            ("Amazon", Some("amazon.com"), vec![], Some("amazon"))
        }
        (EntityKind::Organization, "meta") => ("Meta", Some("meta.com"), vec![], Some("meta")),
        (EntityKind::Organization, "netflix") => {
            ("Netflix", Some("netflix.com"), vec![], Some("netflix"))
        }
        (EntityKind::Organization, "bilibili") => {
            ("Bilibili", Some("bilibili.com"), vec![], Some("bilibili"))
        }
        (EntityKind::Organization, "github") => {
            ("GitHub", Some("github.com"), vec![], Some("github"))
        }
        (EntityKind::Organization, "openai") => {
            ("OpenAI", Some("openai.com"), vec![], Some("openai"))
        }
        (EntityKind::Organization, "valve") => {
            ("Valve", Some("valvesoftware.com"), vec![], Some("valve"))
        }
        (EntityKind::Organization, "sony") => ("Sony", Some("sony.com"), vec![], Some("sony")),
        (EntityKind::Organization, "nintendo") => ("Nintendo", Some("nintendo.com"), vec![], None),
        (EntityKind::Organization, "spotify") => {
            ("Spotify", Some("spotify.com"), vec![], Some("spotify"))
        }
        (EntityKind::Organization, "salesforce") => (
            "Salesforce",
            Some("salesforce.com"),
            vec![],
            Some("salesforce"),
        ),
        (EntityKind::Organization, "discord") => {
            ("Discord", Some("discord.com"), vec![], Some("discord"))
        }
        (EntityKind::Organization, "tencent") => ("Tencent", Some("tencent.com"), vec![], None),
        (EntityKind::Organization, "telegram") => {
            ("Telegram", Some("telegram.org"), vec![], Some("telegram"))
        }
        (EntityKind::Organization, "reddit") => {
            ("Reddit", Some("reddit.com"), vec![], Some("reddit"))
        }
        (EntityKind::Organization, "notion") => {
            ("Notion Labs", Some("notion.so"), vec![], Some("notion"))
        }
        (EntityKind::Organization, "docker") => {
            ("Docker", Some("docker.com"), vec![], Some("docker"))
        }
        (EntityKind::Organization, "wikimedia") => (
            "Wikimedia",
            Some("wikimedia.org"),
            vec![],
            Some("wikipedia"),
        ),
        (EntityKind::Organization, "cloudflare") => (
            "Cloudflare",
            Some("cloudflare.com"),
            vec![],
            Some("cloudflare"),
        ),
        (EntityKind::Organization, "synology") => {
            ("Synology", Some("synology.com"), vec![], Some("synology"))
        }
        (EntityKind::Organization, "lumi") => ("Lumi / Aqara", Some("aqara.com"), vec![], None),
        (EntityKind::Organization, "xingyin") => ("Xingyin", Some("xiaohongshu.com"), vec![], None),
        _ => return None,
    };
    Some(EntityMetadata {
        id: id.to_owned(),
        name: name.to_owned(),
        icon: IconMetadata {
            domain: icon_domain.map(str::to_owned),
            fallback_domains: fallback_domains.into_iter().map(str::to_owned).collect(),
            local_fallback: local_fallback.map(str::to_owned),
        },
    })
}

fn fallback_application_org_id(id: &str) -> Option<String> {
    let org = match id {
        "youtube" | "google-dns" => "google",
        "netflix" => "netflix",
        "bilibili" => "bilibili",
        "github" => "github",
        "openai" => "openai",
        "steam" => "valve",
        "playstation-network" => "sony",
        "nintendo-eshop" => "nintendo",
        "spotify" => "spotify",
        "apple-music" | "icloud" => "apple",
        "slack" => "salesforce",
        "discord" => "discord",
        "wechat" => "tencent",
        "telegram" => "telegram",
        "reddit" => "reddit",
        "microsoft-365" => "microsoft",
        "notion" => "notion",
        "amazon-prime-video" | "twitch" => "amazon",
        "docker-hub" => "docker",
        "wikipedia" => "wikimedia",
        "cloudflare-dns" | "cloudflare-backup" => "cloudflare",
        "synology-dsm" => "synology",
        "aqara-cloud" => "lumi",
        "xiaohongshu" => "xingyin",
        _ => return None,
    };
    Some(org.to_owned())
}

#[cfg(test)]
fn fixture_metadata(kind: EntityKind, id: &str) -> Option<EntityMetadata> {
    fallback_metadata(kind, id)
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Bridges the DPI worker to classifierd's sample-matching IPC. The handle's
/// circuit breaker and sub-second timeouts keep a missing daemon from ever
/// stalling the sampling pipeline.
pub struct ClassifierdSignatureMatcher {
    handle: ClassifierHandle,
}

impl ClassifierdSignatureMatcher {
    #[must_use]
    pub fn new(handle: ClassifierHandle) -> Self {
        Self { handle }
    }
}

impl SignatureMatcher for ClassifierdSignatureMatcher {
    fn match_sample(
        &self,
        key: &FlowSampleKey,
        packets: &[SamplePacket],
    ) -> Vec<SignatureApplicationMatch> {
        let request = FlowSampleMatchRequest {
            flow: netqmon_classifier_client::FlowSampleKey {
                client_ip: ip_text(&key.client_ip),
                client_port: u16::try_from(key.client_port).unwrap_or(0),
                remote_ip: ip_text(&key.remote_ip),
                remote_port: u16::try_from(key.remote_port).unwrap_or(0),
                protocol: flow_protocol(key.protocol),
                first_seen_unix_ms: key.first_seen_unix_ms,
            },
            packets: packets
                .iter()
                .map(|packet| WireSamplePacketInput {
                    direction: if packet.direction == 2 {
                        SamplePacketDirection::Download
                    } else {
                        SamplePacketDirection::Upload
                    },
                    captured_length: packet.captured_length,
                    payload: packet.payload.clone(),
                })
                .collect(),
        };
        self.handle
            .match_flow_samples(request)
            .unwrap_or_else(|error| {
                tracing::debug!(%error, "classifierd sample matching skipped");
                Vec::new()
            })
    }
}

fn flow_protocol(protocol: u32) -> String {
    match protocol {
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        other => other.to_string(),
    }
}

fn ip_text(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string(),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().expect("length checked");
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => String::new(),
    }
}

fn signature_evidence(
    signatures: &[SignatureApplicationMatch],
) -> Vec<ApplicationSignatureEvidence> {
    signatures
        .iter()
        .map(|matched| ApplicationSignatureEvidence {
            application_id: matched.application_id.clone(),
            source: "payload_signature".to_owned(),
            confidence: matched.confidence,
        })
        .collect()
}

#[cfg(test)]
fn fixture_signature_matches(request: &FlowSampleMatchRequest) -> Vec<SignatureApplicationMatch> {
    const HONOR_OF_KINGS: [u8; 4] = [0x33, 0x66, 0x00, 0x0b];
    let hit = request
        .packets
        .iter()
        .any(|packet| fixture_l4_payload(&packet.payload).starts_with(&HONOR_OF_KINGS));
    if hit {
        vec![SignatureApplicationMatch {
            application_id: "honor_of_kings".to_owned(),
            confidence: 0.95,
        }]
    } else {
        Vec::new()
    }
}

/// Minimal raw-packet payload extraction mirroring classifierd's parser.
#[cfg(test)]
fn fixture_l4_payload(raw: &[u8]) -> &[u8] {
    let Some(&first) = raw.first() else {
        return &[];
    };
    let (header_len, transport) = match first >> 4 {
        4 if raw.len() >= 20 => (usize::from(raw[0] & 0x0f) * 4, raw[9]),
        6 if raw.len() >= 40 => (40, raw[6]),
        _ => return &[],
    };
    if header_len > raw.len() || header_len + 20 > raw.len() {
        return &[];
    }
    match transport {
        6 => {
            let offset = usize::from(raw[header_len + 12] >> 4) * 4;
            if header_len + offset <= raw.len() {
                &raw[header_len + offset..]
            } else {
                &[]
            }
        }
        17 if header_len + 8 <= raw.len() => &raw[header_len + 8..],
        _ => &[],
    }
}

fn map_metadata(value: WireMetadata) -> EntityMetadata {
    EntityMetadata {
        id: value.id,
        name: value.name,
        icon: IconMetadata {
            domain: value.icon_domain,
            fallback_domains: value.fallback_domains,
            local_fallback: value.local_fallback,
        },
    }
}
