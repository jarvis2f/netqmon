use crate::analytics::AnalyticsFlow;
use crate::{
    DeviceEvidenceRecord, DeviceIdentityUpdate, FlowAttribution, GatewayRecord, PersistDisposition,
    RetentionPolicy, SessionRecord, StorageResult, UserRecord,
};
use netqmon_protocol::v1::TelemetryBatch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRecord {
    pub id: i64,
    pub payload: Vec<u8>,
}

/// Identity and version of an ended flow whose analytics write was confirmed.
#[derive(Clone, Debug, PartialEq)]
pub struct CompletedFlowCheckpoint {
    pub flow: AnalyticsFlow,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceRecord {
    pub id: i64,
    pub gateway_id: String,
    pub mac: Vec<u8>,
    pub hostname: Option<String>,
    pub display_name: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub os_family: Option<String>,
    pub model: Option<String>,
    pub identity_confidence: String,
    pub identity_evidence_json: String,
    pub vendor_confidence: f64,
    pub device_type_confidence: f64,
    pub os_confidence: f64,
    pub model_confidence: f64,
    pub private_mac: bool,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAddressRecord {
    pub ip: Vec<u8>,
    pub ip_version: u8,
    pub first_seen: u64,
    pub last_seen: u64,
    pub application_id: Option<String>,
    pub application_confidence: f64,
    pub application_source: Option<String>,
    pub application_last_seen: Option<u64>,
    pub self_host_source: Option<String>,
    pub self_host_last_seen: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GatewayDetails {
    pub id: String,
    pub name: String,
    pub agent_version: String,
    pub arch: String,
    pub kernel_version: String,
    pub openwrt_version: String,
    pub last_seen: u64,
}

/// Control-plane, current-state, and reliable-delivery persistence contract.
///
/// This interface is implemented only by SQLite. It intentionally has no
/// analytics query methods and never exposes a database connection.
pub trait MetadataStore: Send {
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn gateway_details(&self) -> StorageResult<Option<GatewayDetails>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn admin_exists(&self) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn append_reclassification(
        &mut self,
        gateway_id: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// Appends a late classification update, using the latest analytics version
    /// when the ended flow has already left SQLite recovery state.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot append the reclassification outbox row.
    fn append_reclassification_with_latest(
        &mut self,
        gateway_id: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
        latest: Option<&AnalyticsFlow>,
    ) -> StorageResult<bool>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn devices(&self, limit: u32, offset: u64) -> StorageResult<(Vec<DeviceRecord>, u64)>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn device(&self, id: i64) -> StorageResult<Option<DeviceRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn device_addresses(&self, id: i64) -> StorageResult<Vec<DeviceAddressRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn device_count(&self) -> StorageResult<u64>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn save_retention_policy(&mut self, policy: &RetentionPolicy, now_ms: u64)
    -> StorageResult<()>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn run_metadata_retention(&mut self, now_ms: u64, policy: RetentionPolicy)
    -> StorageResult<()>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn active_flow_count(&self) -> StorageResult<i64>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn outbox_batch(&self, limit: u32) -> StorageResult<Vec<OutboxRecord>>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn acknowledge_outbox(&mut self, id: i64) -> StorageResult<()>;
    /// Acknowledges a committed analytics batch and removes only ended flow
    /// checkpoints that are no newer than the confirmed analytics versions.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot atomically acknowledge and clean up.
    fn acknowledge_outbox_with_completed_flows(
        &mut self,
        id: i64,
        completed_flows: &[CompletedFlowCheckpoint],
    ) -> StorageResult<()>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn outbox_depth(&self) -> StorageResult<u64>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn outbox_oldest_age_ms(&self, now_ms: u64) -> StorageResult<u64>;
    /// # Errors
    /// Returns an error if SQLite cannot complete the metadata operation.
    fn metadata_database_size_bytes(&self) -> StorageResult<u64>;
}
pub mod sqlite;
pub use sqlite::SqliteMetadataStore;
