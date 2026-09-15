//! A lightweight, synchronous client for the netqmon local classifier IPC.
//!
//! The public DTOs in this crate deliberately mirror the versioned JSON wire
//! protocol.  This crate contains neither a rule engine nor any rule package
//! loading, decryption, or indexing code.

use std::{
    collections::BTreeMap,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The version understood by both ends of this IPC protocol.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default location used by [`ClassifierClientConfig`].
pub const DEFAULT_SOCKET_PATH: &str = "/run/netqmon/classifierd.sock";

/// One flow to classify.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassificationRequest {
    /// Caller-chosen identifier for correlating this entry with its result.
    pub entry_id: String,
    /// Observed domain name, when available.
    pub domain: Option<String>,
    /// Remote IP address in textual form, when available.
    pub remote_ip: Option<String>,
    /// Remote autonomous system number, when available.
    pub remote_asn: Option<u32>,
    /// Remote transport port, when available.
    pub remote_port: Option<u16>,
    /// Observed transport or application protocol, when available.
    pub protocol: Option<String>,
    /// SHA-256 digest of the observed favicon, when available.
    pub favicon_sha256: Option<String>,
    /// Optional evidence produced by a DPI component.
    pub dpi_evidence: Option<DpiEvidence>,
    /// Device observations to match inside the private classifier.
    #[serde(default)]
    pub device_evidence: Vec<DeviceEvidenceInput>,
    /// Application matches produced by the local payload-signature engine
    /// from bounded flow samples. Each entry is high-confidence evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_evidence: Vec<ApplicationSignatureEvidence>,
}

/// One application identified from sampled packet payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApplicationSignatureEvidence {
    /// Stable identifier of the matched application.
    pub application_id: String,
    /// Component that supplied the evidence, for example `payload_signature`.
    pub source: String,
    /// Confidence assigned to this match.
    pub confidence: f64,
}

/// One normalized device observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvidenceInput {
    pub field: String,
    pub text: Option<String>,
    pub sequence: Option<Vec<u32>>,
}

/// One device fingerprint or private dataset match.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvidenceResult {
    pub source: String,
    pub field: String,
    pub value: String,
    pub confidence: f64,
    pub rule_id: Option<String>,
    pub priority: i32,
    pub metadata: BTreeMap<String, String>,
}

/// A set of independent classifications.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassificationBatchRequest {
    /// Flows to classify.
    pub entries: Vec<ClassificationRequest>,
}

/// Structured evidence supplied by DPI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DpiEvidence {
    /// Component that supplied the evidence.
    pub source: String,
    /// Signals observed by that component.
    pub signals: Vec<String>,
    /// Additional string-valued attributes, ordered for stable JSON output.
    pub attributes: BTreeMap<String, String>,
}

/// The result for one requested flow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Identifier copied from the corresponding request entry.
    pub entry_id: String,
    /// Identified organization, if any.
    pub organization: Option<ClassifiedEntity>,
    /// Identified application, if any.
    pub application: Option<ClassifiedEntity>,
    /// Traffic classification, if any.
    pub traffic_class: Option<ClassifiedEntity>,
    /// Traffic role, if any.
    pub traffic_role: Option<String>,
    /// Classified protocol, if any.
    pub protocol: Option<ClassifiedEntity>,
    /// Evidence supporting the classification.
    pub evidence: Vec<ClassificationEvidence>,
    #[serde(default)]
    pub device_evidence: Vec<DeviceEvidenceResult>,
    /// Per-entry failure. Other output fields remain available when applicable.
    pub error: Option<ClassificationError>,
}

/// A classified value and the confidence assigned to it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedEntity {
    /// Stable identifier of the classified entity.
    pub id: String,
    /// Confidence assigned to this entity.
    pub confidence: f64,
}

/// One structured fact used to support a classification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassificationEvidence {
    /// Kind of evidence, such as a domain match or DPI signal.
    pub evidence_type: String,
    /// Evidence value as observed.
    pub value: String,
    /// Component or data source that supplied this evidence.
    pub source: String,
    /// Relative weight assigned to this evidence.
    pub weight: f64,
}

/// Kind of entity whose display metadata is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// An end-user application or service.
    Application,
    /// An organization that owns or operates applications.
    Organization,
}

/// Public display metadata for a known entity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntityMetadata {
    /// Stable entity identifier.
    pub id: String,
    /// Human-readable entity name.
    pub name: String,
    /// Primary domain from which a client may obtain an icon.
    pub icon_domain: Option<String>,
    /// Alternate icon domains, in preference order.
    pub fallback_domains: Vec<String>,
    /// Local fallback icon identifier, when one is packaged with the client.
    pub local_fallback: Option<String>,
}

/// A batch result whose entries align by `entry_id`, not positional order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassificationBatchResult {
    /// One result for each processed request entry.
    pub entries: Vec<ClassificationResult>,
}

/// A failure associated with a single classification entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassificationError {
    /// Stable, machine-readable error code.
    pub code: String,
    /// Human-readable error description.
    pub message: String,
}

/// Classifier liveness and readiness information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassifierHealth {
    /// Whether the service can accept classification requests.
    pub ready: bool,
    /// Optional detail intended for diagnostics.
    pub detail: Option<String>,
}

/// Identity of the running classifier implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassifierVersion {
    /// Classifier implementation version.
    pub version: String,
    /// Optional build identifier or revision.
    pub build: Option<String>,
}

/// Identity of the rule set currently used by the classifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleVersion {
    /// Rule-set version.
    pub version: String,
    /// Optional content digest or revision.
    pub revision: Option<String>,
}

/// Rule-set statistics owned and reported by the classifier.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleStats {
    /// Number of known applications.
    pub application_count: u64,
    /// Number of self-hosted applications.
    pub selfhost_application_count: u64,
    /// Number of client fingerprint rules.
    pub client_count: u64,
    /// Number of protocol rules.
    pub protocol_count: u64,
    /// Active rule-set version.
    pub rule_version: String,
    /// Rule-set last update time in Unix milliseconds.
    pub updated_at_unix_ms: u64,
    /// Number of valid flow-sample matching requests received by the classifier.
    pub sample_match_requests: u64,
    /// Number of flow-sample matching requests with at least one signature hit.
    pub signature_match_count: u64,
    /// Number of application matches returned by signature matching.
    pub signature_match_application_count: u64,
}

/// The one Cloud-selected artifact an installation may activate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllowedRule {
    pub artifact_id: String,
    pub rule_version: String,
    pub edition: String,
}

/// Public cryptographic identity used to seal authorization keys to a classifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassifierIdentity {
    pub key_id: String,
    pub public_key: String,
}

/// A short-lived authorization lease delivered by Collector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntitlementLease {
    pub edition: String,
    pub license_status: String,
    pub lease_valid_until: i64,
    pub allowed_rule: Option<AllowedRule>,
    pub cloud_api_url: String,
    /// Device credential is transported over the protected local socket and
    /// retained in memory only by classifierd.
    pub installation_credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_rule_key: Option<String>,
}

/// Public authorization state. Credentials are intentionally never returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassifierEntitlement {
    pub edition: String,
    pub license_status: String,
    pub lease_valid_until: Option<i64>,
    pub rule_version: Option<String>,
}

/// Direction of one sampled packet relative to the observed client.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SamplePacketDirection {
    /// Client to remote.
    Upload,
    /// Remote to client.
    Download,
}

/// Canonical identity of the flow the sampled packets belong to.
/// Matching itself derives transport and ports from the packet bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowSampleKey {
    /// Textual client IP address.
    pub client_ip: String,
    /// Client transport port.
    pub client_port: u16,
    /// Textual remote IP address.
    pub remote_ip: String,
    /// Remote transport port.
    pub remote_port: u16,
    /// Transport protocol, `tcp` or `udp`.
    pub protocol: String,
    /// Flow creation time in Unix milliseconds.
    pub first_seen_unix_ms: u64,
}

/// One bounded packet capture belonging to a sampled flow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SamplePacketInput {
    /// Direction relative to the observed client.
    pub direction: SamplePacketDirection,
    /// Captured bytes, equal to the payload length.
    pub captured_length: u32,
    /// Raw packet bytes starting at the IPv4/IPv6 header (no Ethernet
    /// header), possibly truncated. Memory-only input: never persisted,
    /// logged, or forwarded beyond the local classifier.
    pub payload: Vec<u8>,
}

/// Bounded packets of one flow to match against Pro payload signatures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowSampleMatchRequest {
    /// Flow the packets belong to.
    pub flow: FlowSampleKey,
    /// Sampled packets, subject to the sampling budget limits.
    pub packets: Vec<SamplePacketInput>,
}

/// One application matched from the sampled packets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowSampleApplicationMatch {
    /// Stable identifier of the matched application.
    pub application_id: String,
    /// Confidence assigned to the match.
    pub confidence: f64,
}

/// Signature-matching result for one flow.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowSampleMatchResult {
    /// Distinct applications whose signatures matched, in match order.
    pub matches: Vec<FlowSampleApplicationMatch>,
}

/// A request sent by an IPC client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    /// Classify multiple flow entries.
    ClassifyBatch {
        /// Client-generated correlation identifier.
        request_id: String,
        /// Batch to classify.
        request: ClassificationBatchRequest,
    },
    /// Match bounded flow samples against Pro payload signatures.
    MatchFlowSamples {
        /// Client-generated correlation identifier.
        request_id: String,
        /// Flow sample to match.
        request: FlowSampleMatchRequest,
    },
    /// Read liveness and readiness information.
    Health {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Read the classifier implementation version.
    Version {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Read the active rule-set version.
    RuleVersion {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Read the rule-set statistics owned by the classifier.
    RuleStats {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Ask the classifier to reload its rule set and report the result.
    ReloadRules {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Read public display metadata for a known entity.
    Metadata {
        /// Client-generated correlation identifier.
        request_id: String,
        /// Kind of entity to look up.
        kind: EntityKind,
        /// Stable entity identifier to look up.
        id: String,
    },
    /// Read the classifier's local cryptographic identity for rule key sealing.
    Identity {
        /// Client-generated correlation identifier.
        request_id: String,
    },
    /// Apply a Cloud authorization lease.
    ApplyEntitlement {
        request_id: String,
        entitlement: EntitlementLease,
    },
    /// Read the current authorization state.
    EntitlementStatus { request_id: String },
}

/// A response sent by an IPC server.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerResponse {
    /// Completed classification batch.
    ClassificationBatch {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Per-entry classification results.
        result: ClassificationBatchResult,
    },
    /// Signature-matching result for a flow sample.
    FlowSampleMatch {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Applications matched from the sampled packets.
        result: FlowSampleMatchResult,
    },
    /// Health response.
    Health {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Current classifier health.
        health: ClassifierHealth,
    },
    /// Classifier version response.
    Version {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Running classifier version.
        version: ClassifierVersion,
    },
    /// Rule-set version response.
    RuleVersion {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Active rule-set version.
        version: RuleVersion,
    },
    /// Rule-set statistics response.
    RuleStats {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Rule-set statistics reported by the classifier.
        stats: RuleStats,
    },
    /// Rule reload completed and the fresh statistics are reported.
    ReloadRules {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Rule-set statistics after the reload.
        stats: RuleStats,
    },
    /// Public display metadata for an entity, when known.
    Metadata {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Requested entity metadata, if the entity is known.
        metadata: Option<EntityMetadata>,
    },
    /// The lease was accepted for asynchronous rule activation.
    EntitlementApplied {
        request_id: String,
        entitlement: ClassifierEntitlement,
    },
    /// Current authorization state.
    EntitlementStatus {
        request_id: String,
        entitlement: ClassifierEntitlement,
    },
    /// Response with the classifier's cryptographic identity.
    Identity {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Public identity of this running classifier.
        identity: ClassifierIdentity,
    },
    /// Failure that applies to the complete IPC request.
    Error {
        /// Identifier copied from the corresponding client request.
        request_id: String,
        /// Stable, machine-readable error code.
        code: String,
        /// Human-readable error description.
        message: String,
    },
}

/// Configuration for a [`ClassifierClient`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifierClientConfig {
    /// Path of the classifier's Unix domain socket.
    pub socket_path: PathBuf,
    /// Maximum time to wait while establishing a Unix socket connection.
    pub connect_timeout: Duration,
    /// Maximum time to wait for a complete NDJSON response line.
    pub read_timeout: Duration,
    /// Maximum time to wait while writing one NDJSON request line.
    pub write_timeout: Duration,
    /// Largest accepted request or response line, excluding its trailing newline.
    pub max_line_bytes: usize,
}

impl Default for ClassifierClientConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_line_bytes: 1024 * 1024,
        }
    }
}

/// The stage of an IPC operation that exceeded its configured timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutOperation {
    /// Establishing the Unix socket connection.
    Connect,
    /// Writing the NDJSON request.
    Write,
    /// Reading the NDJSON response.
    Read,
}

/// Errors returned by [`ClassifierClient`].
#[derive(Debug, Error)]
pub enum ClassifierClientError {
    /// The supplied client configuration is invalid.
    #[error("invalid classifier client configuration: {message}")]
    Configuration {
        /// Description of the invalid configuration.
        message: String,
    },
    /// A connection to the Unix socket could not be established.
    #[error("failed to connect to classifier socket {path}: {source}")]
    Connect {
        /// Socket path that could not be connected.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// An IPC stage exceeded its configured timeout.
    #[error("classifier {operation:?} operation exceeded timeout of {timeout:?}")]
    Timeout {
        /// Timed-out stage.
        operation: TimeoutOperation,
        /// Configured timeout for that stage.
        timeout: Duration,
    },
    /// An operating-system error occurred after connecting.
    #[error("classifier {operation} failed: {source}")]
    Io {
        /// Human-readable I/O operation name.
        operation: &'static str,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// The peer sent malformed, oversized, mismatched, or unexpected JSON.
    #[error("classifier protocol error: {message}")]
    Protocol {
        /// Description of the protocol violation.
        message: String,
    },
    /// The classifier rejected the request.
    #[error("classifier server error {code}: {message}")]
    Server {
        /// Stable server-provided error code.
        code: String,
        /// Server-provided diagnostic message.
        message: String,
    },
    /// The classifier is reachable but not ready to classify traffic.
    #[error("classifier is not ready{detail}")]
    NotReady {
        /// Optional service-provided detail, including its leading separator.
        detail: String,
    },
}

/// Thread-safe, synchronous client that reuses a healthy Unix socket connection.
pub struct ClassifierClient {
    config: ClassifierClientConfig,
    connection: Mutex<Option<Connection>>,
    request_sequence: AtomicU64,
}

struct Connection {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

#[derive(Clone, Copy)]
enum ExpectedResponse {
    ClassificationBatch,
    FlowSampleMatch,
    Health,
    Version,
    RuleVersion,
    RuleStats,
    ReloadRules,
    Metadata,
    EntitlementApplied,
    EntitlementStatus,
    Identity,
}

impl ClassifierClient {
    /// Creates a client. Connections are established lazily on the first call.
    ///
    /// # Errors
    ///
    /// Returns [`ClassifierClientError::Configuration`] if a timeout is zero,
    /// the socket path is empty, or the maximum line length cannot be read
    /// safely as an NDJSON limit.
    pub fn new(config: ClassifierClientConfig) -> Result<Self, ClassifierClientError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            connection: Mutex::new(None),
            request_sequence: AtomicU64::new(1),
        })
    }

    /// Returns the configuration with which this client was created.
    #[must_use]
    pub fn config(&self) -> &ClassifierClientConfig {
        &self.config
    }

    /// Classifies a batch of independent flows.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, does not
    /// respond before the configured timeout, violates the IPC protocol, is not
    /// ready, or rejects the batch.
    pub fn classify_batch(
        &self,
        request: ClassificationBatchRequest,
    ) -> Result<ClassificationBatchResult, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::ClassifyBatch {
            request_id,
            request,
        };
        match self.request(&request, ExpectedResponse::ClassificationBatch)? {
            ServerResponse::ClassificationBatch { result, .. } => Ok(result),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Matches bounded flow-sample packets against Pro payload signatures.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, does not
    /// support sample matching, times out, or violates the IPC protocol.
    pub fn match_flow_samples(
        &self,
        request: FlowSampleMatchRequest,
    ) -> Result<FlowSampleMatchResult, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::MatchFlowSamples {
            request_id,
            request,
        };
        match self.request(&request, ExpectedResponse::FlowSampleMatch)? {
            ServerResponse::FlowSampleMatch { result, .. } => Ok(result),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Returns liveness information, or [`ClassifierClientError::NotReady`].
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, rejects the request, or reports not-ready.
    pub fn health(&self) -> Result<ClassifierHealth, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::Health { request_id };
        match self.request(&request, ExpectedResponse::Health)? {
            ServerResponse::Health { health, .. } if health.ready => Ok(health),
            ServerResponse::Health { health, .. } => Err(not_ready(health.detail)),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Returns the running classifier implementation version.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, is not ready, or rejects the request.
    pub fn classifier_version(&self) -> Result<ClassifierVersion, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::Version { request_id };
        match self.request(&request, ExpectedResponse::Version)? {
            ServerResponse::Version { version, .. } => Ok(version),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Returns the active rule-set version.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, is not ready, or rejects the request.
    pub fn rule_version(&self) -> Result<RuleVersion, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::RuleVersion { request_id };
        match self.request(&request, ExpectedResponse::RuleVersion)? {
            ServerResponse::RuleVersion { version, .. } => Ok(version),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Reads the rule-set statistics owned by the classifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, or is not ready.
    pub fn rule_stats(&self) -> Result<RuleStats, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::RuleStats { request_id };
        match self.request(&request, ExpectedResponse::RuleStats)? {
            ServerResponse::RuleStats { stats, .. } => Ok(stats),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Asks the classifier to reload its rule set and returns the fresh
    /// statistics.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, is not ready, or the reload failed.
    pub fn reload_rules(&self) -> Result<RuleStats, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::ReloadRules { request_id };
        match self.request(&request, ExpectedResponse::ReloadRules)? {
            ServerResponse::ReloadRules { stats, .. } => Ok(stats),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Returns public display metadata for an application or organization.
    ///
    /// # Errors
    ///
    /// Returns an error when the classifier cannot be contacted, times out,
    /// violates the IPC protocol, is not ready, or rejects the request.
    pub fn metadata(
        &self,
        kind: EntityKind,
        id: impl Into<String>,
    ) -> Result<Option<EntityMetadata>, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::Metadata {
            request_id,
            kind,
            id: id.into(),
        };
        match self.request(&request, ExpectedResponse::Metadata)? {
            ServerResponse::Metadata { metadata, .. } => Ok(metadata),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Applies a short-lived entitlement lease.
    ///
    /// # Errors
    /// Returns an error when classifierd is unavailable or rejects the lease.
    pub fn apply_entitlement(
        &self,
        entitlement: EntitlementLease,
    ) -> Result<ClassifierEntitlement, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::ApplyEntitlement {
            request_id,
            entitlement,
        };
        match self.request(&request, ExpectedResponse::EntitlementApplied)? {
            ServerResponse::EntitlementApplied { entitlement, .. } => Ok(entitlement),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Reads classifierd's current entitlement state.
    ///
    /// # Errors
    /// Returns an error when classifierd is unavailable or violates the protocol.
    pub fn entitlement_status(&self) -> Result<ClassifierEntitlement, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::EntitlementStatus { request_id };
        match self.request(&request, ExpectedResponse::EntitlementStatus)? {
            ServerResponse::EntitlementStatus { entitlement, .. } => Ok(entitlement),
            _ => unreachable!("response type was validated"),
        }
    }

    /// Reads classifierd's cryptographic identity for rule key sealing.
    ///
    /// # Errors
    /// Returns an error when classifierd is unavailable or violates the protocol.
    pub fn identity(&self) -> Result<ClassifierIdentity, ClassifierClientError> {
        let request_id = self.next_request_id();
        let request = ClientRequest::Identity { request_id };
        match self.request(&request, ExpectedResponse::Identity)? {
            ServerResponse::Identity { identity, .. } => Ok(identity),
            _ => unreachable!("response type was validated"),
        }
    }

    fn next_request_id(&self) -> String {
        format!(
            "classifier-client-{}",
            self.request_sequence.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn request(
        &self,
        request: &ClientRequest,
        expected: ExpectedResponse,
    ) -> Result<ServerResponse, ClassifierClientError> {
        let request_id = request_id(request).to_owned();
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if connection.is_none() {
            *connection = Some(Connection::connect(&self.config)?);
        }

        let result = connection
            .as_mut()
            .expect("connection is populated above")
            .exchange(request, &self.config)
            .and_then(|response| validate_response(response, &request_id, expected));
        if result
            .as_ref()
            .is_err_and(ClassifierClientError::invalidates_connection)
        {
            *connection = None;
        }
        result
    }
}

impl Connection {
    fn connect(config: &ClassifierClientConfig) -> Result<Self, ClassifierClientError> {
        let stream = connect_with_timeout(&config.socket_path, config.connect_timeout)?;
        stream
            .set_read_timeout(Some(config.read_timeout))
            .map_err(|source| ClassifierClientError::Io {
                operation: "setting read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(config.write_timeout))
            .map_err(|source| ClassifierClientError::Io {
                operation: "setting write timeout",
                source,
            })?;
        let writer = stream
            .try_clone()
            .map_err(|source| ClassifierClientError::Io {
                operation: "cloning connected socket",
                source,
            })?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }

    fn exchange(
        &mut self,
        request: &ClientRequest,
        config: &ClassifierClientConfig,
    ) -> Result<ServerResponse, ClassifierClientError> {
        let mut encoded =
            serde_json::to_vec(request).map_err(|error| ClassifierClientError::Protocol {
                message: format!("could not serialize request: {error}"),
            })?;
        if encoded.len() > config.max_line_bytes {
            return Err(ClassifierClientError::Protocol {
                message: format!(
                    "encoded request is {} bytes, exceeding max_line_bytes {}",
                    encoded.len(),
                    config.max_line_bytes
                ),
            });
        }
        encoded.push(b'\n');
        self.writer.write_all(&encoded).map_err(|source| {
            map_io_error(
                "writing request",
                TimeoutOperation::Write,
                config.write_timeout,
                source,
            )
        })?;
        self.writer.flush().map_err(|source| {
            map_io_error(
                "flushing request",
                TimeoutOperation::Write,
                config.write_timeout,
                source,
            )
        })?;

        let mut line = Vec::new();
        let limit = u64::try_from(config.max_line_bytes)
            .expect("configuration validation ensures max_line_bytes fits u64")
            + 1;
        let count = self
            .reader
            .by_ref()
            .take(limit)
            .read_until(b'\n', &mut line)
            .map_err(|source| {
                map_io_error(
                    "reading response",
                    TimeoutOperation::Read,
                    config.read_timeout,
                    source,
                )
            })?;
        if count == 0 {
            return Err(ClassifierClientError::Protocol {
                message: "classifier closed the connection before sending a response".into(),
            });
        }
        if count > config.max_line_bytes || line.last() != Some(&b'\n') {
            return Err(ClassifierClientError::Protocol {
                message: format!(
                    "classifier response exceeds max_line_bytes {} or is not newline-delimited",
                    config.max_line_bytes
                ),
            });
        }
        line.pop();
        serde_json::from_slice(&line).map_err(|error| ClassifierClientError::Protocol {
            message: format!("could not decode classifier response: {error}"),
        })
    }
}

impl ClassifierClientError {
    fn invalidates_connection(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::Io { .. } | Self::Protocol { .. }
        )
    }
}

fn validate_config(config: &ClassifierClientConfig) -> Result<(), ClassifierClientError> {
    if config.socket_path.as_os_str().is_empty() {
        return Err(ClassifierClientError::Configuration {
            message: "socket_path must not be empty".into(),
        });
    }
    if config.connect_timeout.is_zero()
        || config.read_timeout.is_zero()
        || config.write_timeout.is_zero()
    {
        return Err(ClassifierClientError::Configuration {
            message: "connect_timeout, read_timeout, and write_timeout must be non-zero".into(),
        });
    }
    if config.max_line_bytes == 0
        || u64::try_from(config.max_line_bytes)
            .ok()
            .is_none_or(|max_line_bytes| max_line_bytes == u64::MAX)
    {
        return Err(ClassifierClientError::Configuration {
            message: "max_line_bytes must be positive and fit in u64".into(),
        });
    }
    Ok(())
}

fn connect_with_timeout(
    path: &Path,
    timeout: Duration,
) -> Result<UnixStream, ClassifierClientError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let path_for_thread = path.to_owned();
    thread::Builder::new()
        .name("netqmon-classifier-connect".into())
        .spawn(move || {
            let _ = sender.send(UnixStream::connect(path_for_thread));
        })
        .map_err(|source| ClassifierClientError::Connect {
            path: path.to_owned(),
            source,
        })?;
    match receiver.recv_timeout(timeout) {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(source)) => Err(ClassifierClientError::Connect {
            path: path.to_owned(),
            source,
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ClassifierClientError::Timeout {
            operation: TimeoutOperation::Connect,
            timeout,
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(ClassifierClientError::Connect {
            path: path.to_owned(),
            source: io::Error::other("classifier connection worker stopped unexpectedly"),
        }),
    }
}

fn map_io_error(
    operation: &'static str,
    timeout_operation: TimeoutOperation,
    timeout: Duration,
    source: io::Error,
) -> ClassifierClientError {
    if matches!(
        source.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        ClassifierClientError::Timeout {
            operation: timeout_operation,
            timeout,
        }
    } else {
        ClassifierClientError::Io { operation, source }
    }
}

fn request_id(request: &ClientRequest) -> &str {
    match request {
        ClientRequest::ClassifyBatch { request_id, .. }
        | ClientRequest::MatchFlowSamples { request_id, .. }
        | ClientRequest::Health { request_id }
        | ClientRequest::Version { request_id }
        | ClientRequest::RuleVersion { request_id }
        | ClientRequest::RuleStats { request_id }
        | ClientRequest::ReloadRules { request_id }
        | ClientRequest::Metadata { request_id, .. }
        | ClientRequest::Identity { request_id }
        | ClientRequest::ApplyEntitlement { request_id, .. }
        | ClientRequest::EntitlementStatus { request_id } => request_id,
    }
}

fn response_request_id(response: &ServerResponse) -> &str {
    match response {
        ServerResponse::ClassificationBatch { request_id, .. }
        | ServerResponse::FlowSampleMatch { request_id, .. }
        | ServerResponse::Health { request_id, .. }
        | ServerResponse::Version { request_id, .. }
        | ServerResponse::RuleVersion { request_id, .. }
        | ServerResponse::RuleStats { request_id, .. }
        | ServerResponse::ReloadRules { request_id, .. }
        | ServerResponse::Metadata { request_id, .. }
        | ServerResponse::Identity { request_id, .. }
        | ServerResponse::EntitlementApplied { request_id, .. }
        | ServerResponse::EntitlementStatus { request_id, .. }
        | ServerResponse::Error { request_id, .. } => request_id,
    }
}

fn validate_response(
    response: ServerResponse,
    expected_request_id: &str,
    expected: ExpectedResponse,
) -> Result<ServerResponse, ClassifierClientError> {
    if response_request_id(&response) != expected_request_id {
        return Err(ClassifierClientError::Protocol {
            message: format!(
                "response request_id {:?} does not match request_id {:?}",
                response_request_id(&response),
                expected_request_id
            ),
        });
    }
    if let ServerResponse::Error { code, message, .. } = response {
        return if code == "not_ready" {
            Err(not_ready(Some(message)))
        } else {
            Err(ClassifierClientError::Server { code, message })
        };
    }
    let matches_expected = matches!(
        (&expected, &response),
        (
            ExpectedResponse::ClassificationBatch,
            ServerResponse::ClassificationBatch { .. }
        ) | (
            ExpectedResponse::FlowSampleMatch,
            ServerResponse::FlowSampleMatch { .. }
        ) | (ExpectedResponse::Health, ServerResponse::Health { .. })
            | (ExpectedResponse::Version, ServerResponse::Version { .. })
            | (
                ExpectedResponse::RuleVersion,
                ServerResponse::RuleVersion { .. },
            )
            | (
                ExpectedResponse::RuleStats,
                ServerResponse::RuleStats { .. }
            )
            | (
                ExpectedResponse::ReloadRules,
                ServerResponse::ReloadRules { .. },
            )
            | (ExpectedResponse::Metadata, ServerResponse::Metadata { .. })
            | (ExpectedResponse::Identity, ServerResponse::Identity { .. })
            | (
                ExpectedResponse::EntitlementApplied,
                ServerResponse::EntitlementApplied { .. }
            )
            | (
                ExpectedResponse::EntitlementStatus,
                ServerResponse::EntitlementStatus { .. }
            )
    );
    if matches_expected {
        Ok(response)
    } else {
        Err(ClassifierClientError::Protocol {
            message: "response type does not match the request type".into(),
        })
    }
}

fn not_ready(detail: Option<String>) -> ClassifierClientError {
    ClassifierClientError::NotReady {
        detail: detail.map_or_else(String::new, |detail| format!(": {detail}")),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        thread,
    };

    use super::*;

    #[test]
    fn dto_golden_json_matches_classifier_protocol_wire_shape() {
        let request = ClientRequest::ClassifyBatch {
            request_id: "request-42".into(),
            request: ClassificationBatchRequest {
                entries: vec![ClassificationRequest {
                    entry_id: "flow-1".into(),
                    domain: Some("video.example".into()),
                    remote_ip: Some("203.0.113.10".into()),
                    remote_asn: Some(64_496),
                    remote_port: Some(443),
                    protocol: Some("tls".into()),
                    favicon_sha256: Some("a1b2c3".into()),
                    dpi_evidence: Some(DpiEvidence {
                        source: "nDPI".into(),
                        signals: vec!["sni=video.example".into()],
                        attributes: BTreeMap::from([("ja4".into(), "t13d".into())]),
                    }),
                    device_evidence: vec![DeviceEvidenceInput {
                        field: "hostname".into(),
                        text: Some("device.local".into()),
                        sequence: None,
                    }],
                    signature_evidence: Vec::new(),
                }],
            },
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"type":"classify_batch","request_id":"request-42","request":{"entries":[{"entry_id":"flow-1","domain":"video.example","remote_ip":"203.0.113.10","remote_asn":64496,"remote_port":443,"protocol":"tls","favicon_sha256":"a1b2c3","dpi_evidence":{"source":"nDPI","signals":["sni=video.example"],"attributes":{"ja4":"t13d"}},"device_evidence":[{"field":"hostname","text":"device.local","sequence":null}]}]}}"#
        );

        assert_control_message_golden();
    }

    fn assert_control_message_golden() {
        let messages = [
            serde_json::to_string(&ClientRequest::Health {
                request_id: "h".into(),
            })
            .unwrap(),
            serde_json::to_string(&ClientRequest::Version {
                request_id: "v".into(),
            })
            .unwrap(),
            serde_json::to_string(&ClientRequest::RuleVersion {
                request_id: "r".into(),
            })
            .unwrap(),
            serde_json::to_string(&ClientRequest::Metadata {
                request_id: "m".into(),
                kind: EntityKind::Application,
                id: "app".into(),
            })
            .unwrap(),
            serde_json::to_string(&ServerResponse::Health {
                request_id: "h".into(),
                health: ClassifierHealth {
                    ready: true,
                    detail: None,
                },
            })
            .unwrap(),
            serde_json::to_string(&ServerResponse::Version {
                request_id: "v".into(),
                version: ClassifierVersion {
                    version: "1.2.3".into(),
                    build: None,
                },
            })
            .unwrap(),
            serde_json::to_string(&ServerResponse::RuleVersion {
                request_id: "r".into(),
                version: RuleVersion {
                    version: "2026.1".into(),
                    revision: None,
                },
            })
            .unwrap(),
            serde_json::to_string(&ServerResponse::Metadata {
                request_id: "m".into(),
                metadata: None,
            })
            .unwrap(),
            serde_json::to_string(&ServerResponse::Error {
                request_id: "e".into(),
                code: "invalid_request".into(),
                message: "bad request".into(),
            })
            .unwrap(),
        ];
        assert_eq!(messages[0], r#"{"type":"health","request_id":"h"}"#);
        assert_eq!(messages[1], r#"{"type":"version","request_id":"v"}"#);
        assert_eq!(messages[2], r#"{"type":"rule_version","request_id":"r"}"#);
        assert_eq!(
            messages[3],
            r#"{"type":"metadata","request_id":"m","kind":"application","id":"app"}"#
        );
        assert_eq!(
            messages[4],
            r#"{"type":"health","request_id":"h","health":{"ready":true,"detail":null}}"#
        );
        assert_eq!(
            messages[5],
            r#"{"type":"version","request_id":"v","version":{"version":"1.2.3","build":null}}"#
        );
        assert_eq!(
            messages[6],
            r#"{"type":"rule_version","request_id":"r","version":{"version":"2026.1","revision":null}}"#
        );
        assert_eq!(
            messages[7],
            r#"{"type":"metadata","request_id":"m","metadata":null}"#
        );
        assert_eq!(
            messages[8],
            r#"{"type":"error","request_id":"e","code":"invalid_request","message":"bad request"}"#
        );
    }

    #[test]
    fn client_reuses_connection_and_handles_all_supported_calls() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("classifier.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            for _ in 0..5 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
                let response = response_for(request);
                writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            }
        });
        let client = ClassifierClient::new(test_config(socket_path)).unwrap();

        assert_eq!(
            client
                .classify_batch(ClassificationBatchRequest { entries: vec![] })
                .unwrap()
                .entries,
            vec![]
        );
        assert!(client.health().unwrap().ready);
        assert_eq!(client.classifier_version().unwrap().version, "1.2.3");
        assert_eq!(client.rule_version().unwrap().version, "2026.1");
        assert_eq!(
            client
                .metadata(EntityKind::Application, "app")
                .unwrap()
                .unwrap()
                .name,
            "Example App"
        );
        server.join().unwrap();
    }

    #[test]
    fn next_call_reconnects_after_connection_failure() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("classifier.sock");
        let client = ClassifierClient::new(test_config(socket_path.clone())).unwrap();
        assert!(matches!(
            client.health(),
            Err(ClassifierClientError::Connect { .. })
        ));

        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
            writeln!(
                stream,
                "{}",
                serde_json::to_string(&response_for(request)).unwrap()
            )
            .unwrap();
        });
        assert!(client.health().unwrap().ready);
        server.join().unwrap();
    }

    fn test_config(socket_path: PathBuf) -> ClassifierClientConfig {
        ClassifierClientConfig {
            socket_path,
            connect_timeout: Duration::from_millis(250),
            read_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            max_line_bytes: 4096,
        }
    }

    fn response_for(request: ClientRequest) -> ServerResponse {
        match request {
            ClientRequest::ClassifyBatch { request_id, .. } => {
                ServerResponse::ClassificationBatch {
                    request_id,
                    result: ClassificationBatchResult { entries: vec![] },
                }
            }
            ClientRequest::MatchFlowSamples { request_id, .. } => ServerResponse::FlowSampleMatch {
                request_id,
                result: FlowSampleMatchResult::default(),
            },
            ClientRequest::Health { request_id } => ServerResponse::Health {
                request_id,
                health: ClassifierHealth {
                    ready: true,
                    detail: None,
                },
            },
            ClientRequest::Version { request_id } => ServerResponse::Version {
                request_id,
                version: ClassifierVersion {
                    version: "1.2.3".into(),
                    build: None,
                },
            },
            ClientRequest::RuleVersion { request_id } => ServerResponse::RuleVersion {
                request_id,
                version: RuleVersion {
                    version: "2026.1".into(),
                    revision: None,
                },
            },
            ClientRequest::Metadata { request_id, .. } => ServerResponse::Metadata {
                request_id,
                metadata: Some(EntityMetadata {
                    id: "app".into(),
                    name: "Example App".into(),
                    icon_domain: None,
                    fallback_domains: vec![],
                    local_fallback: None,
                }),
            },
            ClientRequest::ApplyEntitlement {
                request_id,
                entitlement,
            } => ServerResponse::EntitlementApplied {
                request_id,
                entitlement: ClassifierEntitlement {
                    edition: entitlement.edition,
                    license_status: entitlement.license_status,
                    lease_valid_until: Some(entitlement.lease_valid_until),
                    rule_version: entitlement.allowed_rule.map(|rule| rule.rule_version),
                },
            },
            ClientRequest::Identity { request_id } => ServerResponse::Identity {
                request_id,
                identity: ClassifierIdentity {
                    key_id: "test-key-id".into(),
                    public_key: "00".repeat(32),
                },
            },
            ClientRequest::EntitlementStatus { request_id } => ServerResponse::EntitlementStatus {
                request_id,
                entitlement: ClassifierEntitlement {
                    edition: "community".into(),
                    license_status: "unlicensed".into(),
                    lease_valid_until: None,
                    rule_version: Some("2026.1".into()),
                },
            },
            ClientRequest::RuleStats { request_id } => ServerResponse::RuleStats {
                request_id,
                stats: RuleStats::default(),
            },
            ClientRequest::ReloadRules { request_id } => ServerResponse::ReloadRules {
                request_id,
                stats: RuleStats::default(),
            },
        }
    }

    #[test]
    fn flow_sample_match_wire_contract_is_stable() {
        let request = ClientRequest::MatchFlowSamples {
            request_id: "sample-42".into(),
            request: FlowSampleMatchRequest {
                flow: FlowSampleKey {
                    client_ip: "192.168.1.10".into(),
                    client_port: 51_000,
                    remote_ip: "203.0.113.20".into(),
                    remote_port: 443,
                    protocol: "tcp".into(),
                    first_seen_unix_ms: 1_800_000_000_000,
                },
                packets: vec![SamplePacketInput {
                    direction: SamplePacketDirection::Upload,
                    captured_length: 4,
                    payload: vec![0x33, 0x66, 0x00, 0x0b],
                }],
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"type":"match_flow_samples","request_id":"sample-42","request":{"flow":{"client_ip":"192.168.1.10","client_port":51000,"remote_ip":"203.0.113.20","remote_port":443,"protocol":"tcp","first_seen_unix_ms":1800000000000},"packets":[{"direction":"upload","captured_length":4,"payload":[51,102,0,11]}]}}"#
        );
        let decoded: ClientRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);

        let response = ServerResponse::FlowSampleMatch {
            request_id: "sample-42".into(),
            result: FlowSampleMatchResult {
                matches: vec![FlowSampleApplicationMatch {
                    application_id: "honor_of_kings".into(),
                    confidence: 0.95,
                }],
            },
        };
        let response_json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            response_json,
            r#"{"type":"flow_sample_match","request_id":"sample-42","result":{"matches":[{"application_id":"honor_of_kings","confidence":0.95}]}}"#
        );
        let decoded: ServerResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn signature_evidence_round_trips_in_classification_request() {
        let request = ClientRequest::ClassifyBatch {
            request_id: "request-43".into(),
            request: ClassificationBatchRequest {
                entries: vec![ClassificationRequest {
                    entry_id: "flow-1".into(),
                    domain: None,
                    remote_ip: None,
                    remote_asn: None,
                    remote_port: None,
                    protocol: None,
                    favicon_sha256: None,
                    dpi_evidence: None,
                    device_evidence: Vec::new(),
                    signature_evidence: vec![ApplicationSignatureEvidence {
                        application_id: "honor_of_kings".into(),
                        source: "payload_signature".into(),
                        confidence: 0.95,
                    }],
                }],
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"signature_evidence\""));
        assert!(json.contains("\"payload_signature\""));
        let decoded: ClientRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);

        let empty = serde_json::to_string(&ClientRequest::ClassifyBatch {
            request_id: "request-44".into(),
            request: ClassificationBatchRequest {
                entries: vec![ClassificationRequest {
                    entry_id: "flow-2".into(),
                    domain: None,
                    remote_ip: None,
                    remote_asn: None,
                    remote_port: None,
                    protocol: None,
                    favicon_sha256: None,
                    dpi_evidence: None,
                    device_evidence: Vec::new(),
                    signature_evidence: Vec::new(),
                }],
            },
        })
        .unwrap();
        assert!(
            !empty.contains("signature_evidence"),
            "absent evidence must stay out of the wire shape"
        );
    }

    #[test]
    fn entitlement_wire_contract_is_stable() {
        let request = ClientRequest::ApplyEntitlement {
            request_id: "lease-1".into(),
            entitlement: EntitlementLease {
                edition: "pro".into(),
                license_status: "active".into(),
                lease_valid_until: 1_800_000_000,
                allowed_rule: Some(AllowedRule {
                    artifact_id: "artifact-1".into(),
                    rule_version: "2026.09".into(),
                    edition: "pro".into(),
                }),
                cloud_api_url: "https://cloud.example".into(),
                installation_credential: Some("secret".into()),
                sealed_rule_key: None,
            },
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            "{\"type\":\"apply_entitlement\",\"request_id\":\"lease-1\",\"entitlement\":{\"edition\":\"pro\",\"license_status\":\"active\",\"lease_valid_until\":1800000000,\"allowed_rule\":{\"artifact_id\":\"artifact-1\",\"rule_version\":\"2026.09\",\"edition\":\"pro\"},\"cloud_api_url\":\"https://cloud.example\",\"installation_credential\":\"secret\"}}"
        );
    }

    #[test]
    fn rule_stats_wire_contract_is_stable() {
        let stats = RuleStats {
            application_count: 120,
            selfhost_application_count: 8,
            client_count: 45,
            protocol_count: 200,
            rule_version: "2026.09".into(),
            updated_at_unix_ms: 1_800_000_012_345,
            sample_match_requests: 7,
            signature_match_count: 3,
            signature_match_application_count: 4,
        };
        let json = serde_json::to_string(&ServerResponse::ReloadRules {
            request_id: "reload-1".into(),
            stats: stats.clone(),
        })
        .unwrap();
        assert_eq!(
            json,
            "{\"type\":\"reload_rules\",\"request_id\":\"reload-1\",\"stats\":{\"application_count\":120,\"selfhost_application_count\":8,\"client_count\":45,\"protocol_count\":200,\"rule_version\":\"2026.09\",\"updated_at_unix_ms\":1800000012345,\"sample_match_requests\":7,\"signature_match_count\":3,\"signature_match_application_count\":4}}"
        );
        let decoded: ServerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded,
            ServerResponse::ReloadRules {
                request_id: "reload-1".into(),
                stats,
            }
        );

        let request_json = serde_json::to_string(&ClientRequest::RuleStats {
            request_id: "stats-1".into(),
        })
        .unwrap();
        assert_eq!(
            request_json,
            "{\"type\":\"rule_stats\",\"request_id\":\"stats-1\"}"
        );
        let decoded: ClientRequest = serde_json::from_str(&request_json).unwrap();
        assert_eq!(
            decoded,
            ClientRequest::RuleStats {
                request_id: "stats-1".into(),
            }
        );
    }
}
