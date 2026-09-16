use serde::{Deserialize, Serialize};

/// A classified, backend-independent unit of analytics ingestion.
///
/// The collector writes this value to SQLite's transactional outbox together
/// with metadata updates. Analytics backends never need to understand the
/// agent's protobuf telemetry model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalyticsBatch {
    pub gateway_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub received_at: u64,
    pub flows: Vec<AnalyticsFlow>,
    pub traffic: Vec<TrafficDelta>,
}

/// A complete flow version for append-only historical storage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalyticsFlow {
    pub flow_id: String,
    pub gateway_id: String,
    pub device_id: u64,
    pub ip_version: u8,
    pub protocol: u8,
    pub client_ip: Vec<u8>,
    pub client_port: u16,
    pub remote_ip: Vec<u8>,
    pub remote_port: u16,
    pub direction: u8,
    pub domain: String,
    pub organization_id: String,
    pub application_id: String,
    pub category_id: String,
    pub traffic_role: String,
    pub protocol_id: String,
    pub organization_confidence: f64,
    pub application_confidence: f64,
    pub protocol_confidence: f64,
    pub classification_confidence: f64,
    pub classification_reason: String,
    pub classification_evidence_json: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub packets: u64,
    pub started_at: u64,
    pub last_seen_at: u64,
    pub ended_at: Option<u64>,
    pub checkpointed_at: u64,
    pub scope: u8,
    pub path_type: u8,
    pub nat: u8,
    pub source_segment: String,
    pub destination_segment: String,
}

/// Stable network identity used to find a stored flow when late DPI results
/// arrive without the collector's direction field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyticsFlowIdentity {
    pub gateway_id: String,
    pub ip_version: u8,
    pub protocol: u8,
    pub client_ip: Vec<u8>,
    pub client_port: u16,
    pub remote_ip: Vec<u8>,
    pub remote_port: u16,
    pub started_at: u64,
}

/// A per-flow traffic contribution, enriched by the collector.
///
/// Implementations aggregate these rows in memory by all dimensions before
/// writing `traffic_minute`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrafficDelta {
    pub timestamp: u64,
    pub gateway_id: String,
    pub scope: u8,
    pub direction: u8,
    pub transport_protocol: u8,
    pub path_type: u8,
    pub nat: u8,
    pub device_id: u64,
    pub organization_id: String,
    pub application_id: String,
    pub category_id: String,
    pub protocol_id: String,
    pub domain: String,
    pub remote_ip: Vec<u8>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub packets: u64,
    pub flow_count: u64,
}

impl AnalyticsBatch {
    /// Encodes a compact, compressed outbox payload.
    ///
    /// # Errors
    /// Returns an error if serialization or compression fails.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        zstd::encode_all(json.as_slice(), 3).map_err(|error| error.to_string())
    }

    /// Decodes a compact, compressed outbox payload.
    ///
    /// # Errors
    /// Returns an error if decompression or deserialization fails.
    pub fn decode(payload: &[u8]) -> Result<Self, String> {
        let json = zstd::decode_all(payload).map_err(|error| error.to_string())?;
        serde_json::from_slice(&json).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalyticsResolution {
    Minute,
    Hour,
    Day,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficQuery {
    pub from: u64,
    pub to: u64,
    pub resolution: AnalyticsResolution,
    pub gateway_id: Option<String>,
    pub scope: Option<u8>,
    pub direction: Option<u8>,
    pub device_id: Option<u64>,
    pub organization_id: Option<String>,
    pub application_id: Option<String>,
    pub category_id: Option<String>,
    pub protocol_id: Option<String>,
    pub domain: Option<String>,
    pub remote_ip: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficBreakdownQuery {
    pub traffic: TrafficQuery,
    pub dimension: TrafficDimension,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficDimension {
    Device,
    Organization,
    Application,
    Category,
    Protocol,
    Domain,
    Destination,
    TransportProtocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficPoint {
    pub timestamp: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub packets: u64,
    pub flow_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficBreakdown {
    pub key: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub packets: u64,
    pub flow_count: u64,
    pub last_seen_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowQuery {
    pub from: u64,
    pub to: u64,
    pub gateway_id: Option<String>,
    pub device_id: Option<u64>,
    pub application_id: Option<String>,
    pub organization_id: Option<String>,
    pub protocol_id: Option<String>,
    pub domain: Option<String>,
    pub client_ip: Option<Vec<u8>>,
    pub remote_ip: Option<Vec<u8>>,
    pub any_ip: Option<Vec<u8>>,
    pub transport_protocol: Option<u8>,
    pub port: Option<u16>,
    pub direction: Option<u8>,
    pub scope: Option<u8>,
    pub path_type: Option<u8>,
    pub nat: Option<u8>,
    pub search: Option<String>,
    pub sort_by: FlowSort,
    pub descending: bool,
    pub after_sort_value: Option<i64>,
    pub after_flow_id: Option<String>,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FlowSort {
    #[default]
    LastSeen,
    Started,
    UploadBytes,
    DownloadBytes,
    TotalBytes,
    Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FlowPage {
    pub rows: Vec<AnalyticsFlow>,
    pub total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryQuery {
    pub from: u64,
    pub to: u64,
    pub resolution: AnalyticsResolution,
    pub gateway_id: Option<String>,
    pub device_id: Option<u64>,
    pub scope: Option<u8>,
    pub direction: Option<u8>,
    pub organization_id: Option<String>,
    pub application_id: Option<String>,
    pub category_id: Option<String>,
    pub protocol_id: Option<String>,
    pub domain: Option<String>,
    pub remote_ip: Option<Vec<u8>>,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyticsSummary {
    pub key: String,
    pub device_id: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub packets: u64,
    pub flow_count: u64,
    pub last_seen_at: u64,
    pub distinct_devices: u64,
    pub last_domain: Option<String>,
    pub application_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoTraffic {
    pub remote_ip: Vec<u8>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyticsOverview {
    pub application_count: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyBatchResult {
    Applied,
    Duplicate,
}

/// Converts a time span to one shared analytics resolution for all APIs.
#[must_use]
pub const fn resolution_for_range(from: u64, to: u64) -> AnalyticsResolution {
    let span = to.saturating_sub(from);
    if span <= 48 * 60 * 60 * 1_000 {
        AnalyticsResolution::Minute
    } else if span <= 90 * 24 * 60 * 60 * 1_000 {
        AnalyticsResolution::Hour
    } else {
        AnalyticsResolution::Day
    }
}
