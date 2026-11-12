//! SQLite-backed persistence and aggregation for netqmon.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use netqmon_protocol::v1::{Direction, FlowDelta, FlowLifecycle, TelemetryBatch};
use rusqlite::types::{Type, Value};
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};

mod attribution;

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/sqlite/0001_initial.sql");
const PROTOCOL_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0002_traffic_scope_protocol.sql");
const SCOPE_TIMESTAMP_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0003_traffic_scope_timestamp.sql");
const PROTOCOL_ONLY_APPLICATION_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0004_protocol_only_app_rollup.sql");
const PROTOCOL_APPLICATION_ROLLUP_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0005_protocol_application_rollup.sql");
const MIGRATIONS: [(i64, &str); 17] = [
    (1, INITIAL_MIGRATION),
    (2, PROTOCOL_MIGRATION),
    (3, SCOPE_TIMESTAMP_MIGRATION),
    (4, PROTOCOL_ONLY_APPLICATION_MIGRATION),
    (5, PROTOCOL_APPLICATION_ROLLUP_MIGRATION),
    (
        6,
        include_str!("../../../migrations/sqlite/0006_flow_rollup_contributions.sql"),
    ),
    (
        7,
        include_str!("../../../migrations/sqlite/0007_dns_answer_lookup.sql"),
    ),
    (
        8,
        include_str!("../../../migrations/sqlite/0008_flow_lookup.sql"),
    ),
    (
        9,
        include_str!("../../../migrations/sqlite/0009_incremental_rollups.sql"),
    ),
    (
        10,
        include_str!("../../../migrations/sqlite/0010_scope_query_covering.sql"),
    ),
    (
        11,
        include_str!("../../../migrations/sqlite/0011_scope_totals.sql"),
    ),
    (
        12,
        include_str!("../../../migrations/sqlite/0012_device_type_override.sql"),
    ),
    (
        13,
        include_str!("../../../migrations/sqlite/0013_policy_option_indexes.sql"),
    ),
    (
        14,
        include_str!("../../../migrations/sqlite/0014_application_client_covering.sql"),
    ),
    (
        15,
        include_str!("../../../migrations/sqlite/0015_client_traffic_ranking.sql"),
    ),
    (
        16,
        include_str!("../../../migrations/sqlite/0016_flow_last_seen_order.sql"),
    ),
    (
        17,
        include_str!("../../../migrations/sqlite/0017_flow_sample_lookup_tuple_only.sql"),
    ),
];
const SAME_DEVICE_DNS_QUERY: &str =
    "SELECT dns.domain FROM device_addresses client
     JOIN devices d ON d.id=client.device_id
     JOIN device_addresses source ON source.device_id=d.id
     JOIN dns_observations dns ON dns.gateway_id=d.gateway_id AND dns.client_ip=source.ip
     WHERE d.gateway_id=?1 AND client.ip=?2 AND dns.answer_ip = ?3
       AND dns.observed_at <= ?4 AND dns.expires_at > ?4
       AND client.first_seen<=?4 AND client.last_seen>=?4-300000
           AND source.first_seen<=dns.observed_at AND source.last_seen>=dns.observed_at-300000
           AND NOT EXISTS (
             SELECT 1 FROM device_addresses other JOIN devices od ON od.id=other.device_id
             WHERE od.gateway_id=?1 AND other.device_id!=d.id AND (
               (other.ip=?2 AND other.first_seen<=?4 AND other.last_seen>=?4-300000) OR
               (other.ip=dns.client_ip AND other.first_seen<=dns.observed_at AND other.last_seen>=dns.observed_at-300000)
             )
           )
     ORDER BY dns.observed_at DESC, dns.id DESC LIMIT 1";
pub(crate) const PROTOCOL_APPLICATION_PREFIX: &str = "protocol:";
const MINUTE_MS: i64 = 60 * 1_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const FLOW_CHECKPOINT_MS: i64 = 5 * MINUTE_MS;
// A safety net for missing End events, well beyond the Agent's default idle
// timeouts. Use collector receipt time, including zero-traffic lifecycle events.
const ACTIVE_FLOW_TTL_MS: i64 = 30 * MINUTE_MS;
// Flow deltas and attribution remain durable in SQLite when a colder entry is
// evicted; new deltas restore the exact session from the recovery ledger.
const ACTIVE_FLOW_CACHE_CAPACITY: usize = 50_000;
// One gateway plus four parameters per lookup stays below SQLite's legacy
// 999-variable default: 1 + 4 * 249 = 997.
const DNS_RECENT_LOOKUP_CHUNK_SIZE: usize = 249;
const DIMENSIONS: [&str; 5] = ["total", "device", "application", "domain", "destination"];

/// Default database location for the single-container deployment.
pub const DEFAULT_DATABASE_PATH: &str = "/data/netqmon.db";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRecord {
    pub id: String,
    pub agent_token_hash: [u8; 32],
    pub last_seen_ms: u64,
}

/// One client-scoped DNS history lookup with a caller-bounded time window.
#[derive(Clone, Copy, Debug)]
pub struct RecentDomainLookup<'a> {
    pub client_ip: &'a [u8],
    pub answer_ip: &'a [u8],
    pub at_ms: u64,
    pub not_before_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub user_id: String,
    pub username: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficTotal {
    pub timestamp: i64,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub packets: i64,
    pub flow_count: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowAttribution {
    pub domain: Option<String>,
    pub organization_id: String,
    pub application_id: String,
    pub category_id: String,
    pub traffic_role: String,
    pub protocol_id: String,
    pub organization_confidence: f64,
    pub application_confidence: f64,
    pub protocol_confidence: f64,
    pub confidence: f64,
    pub reason: String,
    pub evidence_json: String,
}

impl FlowAttribution {
    fn is_default(&self) -> bool {
        self.domain.is_none()
            && self.organization_id == "unknown"
            && self.application_id == "unknown"
            && self.category_id == "unknown"
            && self.traffic_role == "unknown"
            && self.protocol_id == "unknown"
            && self.organization_confidence == 0.0
            && self.application_confidence == 0.0
            && self.protocol_confidence == 0.0
            && self.confidence == 0.0
            && self.reason == "no matching rule"
            && self.evidence_json == "[]"
    }
}

impl Default for FlowAttribution {
    fn default() -> Self {
        Self {
            domain: None,
            organization_id: "unknown".to_owned(),
            application_id: "unknown".to_owned(),
            category_id: "unknown".to_owned(),
            traffic_role: "unknown".to_owned(),
            protocol_id: "unknown".to_owned(),
            organization_confidence: 0.0,
            application_confidence: 0.0,
            protocol_confidence: 0.0,
            confidence: 0.0,
            reason: "no matching rule".to_owned(),
            evidence_json: "[]".to_owned(),
        }
    }
}

fn default_active_attribution() -> &'static Arc<FlowAttribution> {
    static DEFAULT: OnceLock<Arc<FlowAttribution>> = OnceLock::new();
    DEFAULT.get_or_init(|| Arc::new(FlowAttribution::default()))
}

fn shared_active_attribution(attribution: FlowAttribution) -> Arc<FlowAttribution> {
    if attribution.is_default() {
        Arc::clone(default_active_attribution())
    } else {
        Arc::new(attribution)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceIdentityUpdate {
    pub mac: Vec<u8>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub os_family: Option<String>,
    pub model: Option<String>,
    pub confidence: Option<String>,
    pub vendor_confidence: f64,
    pub device_type_confidence: f64,
    pub os_confidence: f64,
    pub model_confidence: f64,
    pub private_mac: bool,
    pub evidence_json: String,
    pub evidence: Vec<DeviceEvidenceUpdate>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvidenceUpdate {
    pub source: String,
    pub field: String,
    pub value: String,
    pub confidence: f64,
    pub observed_at: u64,
    pub metadata_json: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvidenceRecord {
    pub gateway_id: String,
    pub mac: Vec<u8>,
    pub source: String,
    pub field: String,
    pub value: String,
    pub confidence: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub hit_count: u64,
    pub metadata_json: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistDisposition {
    Accepted,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub flow_sessions_days: u32,
    pub dns_days: u32,
    pub minute_days: u32,
    pub hour_days: u32,
    pub day_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            flow_sessions_days: 7,
            dns_days: 7,
            minute_days: 30,
            hour_days: 365,
            day_days: 0,
        }
    }
}

/// Limits work per SQLite retention invocation. Transaction time is a target:
/// an individual SQLite statement or trigger cannot be preempted safely here.
#[derive(Clone, Copy, Debug)]
pub struct RetentionBudget {
    pub max_rows_per_batch: usize,
    pub transaction_target: Duration,
    pub total_budget: Duration,
}

impl Default for RetentionBudget {
    fn default() -> Self {
        Self {
            max_rows_per_batch: 500,
            transaction_target: Duration::from_millis(100),
            total_budget: Duration::from_secs(5),
        }
    }
}

fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

#[cfg(test)]
thread_local! {
    static RETENTION_TRANSACTION_TIMES: std::cell::RefCell<Vec<Duration>> = const { std::cell::RefCell::new(Vec::new()) };
    static RETENTION_PHASE_TIMES: std::cell::RefCell<Vec<(Duration, Duration, Duration)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[derive(Default, Debug)]
struct SqlProfileEntry {
    calls: u64,
    nanos: u128,
    keys: HashSet<String>,
}

#[cfg(test)]
thread_local! {
    static BENCH_SQL_PROFILE: std::cell::RefCell<Option<HashMap<String, SqlProfileEntry>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn benchmark_sql_profile(label: &str, elapsed: Option<Duration>, keys: Option<&[Value]>) {
    BENCH_SQL_PROFILE.with(|profile| {
        if let Some(entries) = profile.borrow_mut().as_mut() {
            let entry = entries.entry(label.to_owned()).or_default();
            entry.calls += 1;
            entry.nanos += elapsed.map_or(0, |duration| duration.as_nanos());
            if let Some(keys) = keys {
                entry.keys.insert(format!("{keys:?}"));
            }
        }
    });
}

#[cfg(test)]
fn benchmark_sql_profile_enabled() -> bool {
    BENCH_SQL_PROFILE.with(|profile| profile.borrow().is_some())
}

pub mod clickhouse;
pub use clickhouse::{ClickHouseClient, ClickHouseConfig, ClickHouseStorage, from_hex, to_hex};

/// Unified storage error covering SQLite and `ClickHouse` operations.
#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    ClickHouse(String),
    Connection(String),
    Serialization(String),
    Other(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(err) => write!(f, "sqlite error: {err}"),
            Self::ClickHouse(err) => write!(f, "clickhouse error: {err}"),
            Self::Connection(err) => write!(f, "storage connection error: {err}"),
            Self::Serialization(err) => write!(f, "storage serialization error: {err}"),
            Self::Other(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

pub trait StorageBackend {
    /// Loads the enrolled Gateway, if present.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cannot execute or decode the query.
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>>;
    /// Creates the v1 Gateway if none is enrolled.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cannot execute the insert.
    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// Replaces credentials for a stale Gateway without changing its identity.
    ///
    /// The replacement must be conditional on `last_seen` being at or before
    /// `stale_before_ms`, so concurrent enrollment attempts cannot both rotate
    /// the same Gateway.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot execute the conditional update.
    fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// Returns whether the administrator account exists.
    ///
    /// # Errors
    ///
    /// Returns an error if lookup fails.
    fn admin_exists(&self) -> StorageResult<bool>;
    /// Creates the first administrator.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails.
    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool>;
    /// Looks up user by username.
    ///
    /// # Errors
    ///
    /// Returns an error if query fails.
    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>>;
    /// Creates an authentication session.
    ///
    /// # Errors
    ///
    /// Returns an error if session cannot be saved.
    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()>;
    /// Loads an active session by token hash.
    ///
    /// # Errors
    ///
    /// Returns an error if lookup fails.
    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>>;
    /// Deletes a session by token hash.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool>;
    /// Persists one idempotent telemetry batch.
    ///
    /// # Errors
    ///
    /// Returns an error when the batch cannot be persisted.
    fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition>;
    /// Persists a classified batch.
    ///
    /// # Errors
    ///
    /// Returns an error if batch cannot be persisted.
    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition>;
    /// Loads all accumulated identity evidence for one Gateway-scoped device.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence cannot be queried or decoded.
    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>>;
    /// Resolves the most recent client-scoped DNS answer valid at a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cannot execute or decode the query.
    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>>;
    /// Resolves the latest DNS observation within an explicit history window,
    /// including observations whose advertised DNS TTL has elapsed.
    fn resolve_recent_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
        not_before_ms: u64,
    ) -> StorageResult<Option<(String, u64)>> {
        Ok(self
            .resolve_domain(gateway_id, client_ip, answer_ip, at_ms)?
            .map(|domain| (domain, at_ms.max(not_before_ms))))
    }
    /// Resolves multiple recent-domain windows in order. Backends with batch
    /// query support should override this method to avoid one query per key.
    fn resolve_recent_domains(
        &self,
        gateway_id: &str,
        lookups: &[RecentDomainLookup<'_>],
    ) -> StorageResult<Vec<Option<(String, u64)>>> {
        lookups
            .iter()
            .map(|lookup| {
                self.resolve_recent_domain(
                    gateway_id,
                    lookup.client_ip,
                    lookup.answer_ip,
                    lookup.at_ms,
                    lookup.not_before_ms,
                )
            })
            .collect()
    }
    /// Queries minute totals in the half-open time range.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cannot execute or decode the query.
    fn query_total_traffic(&self, from_ms: u64, to_ms: u64) -> StorageResult<Vec<TrafficTotal>>;
    /// Aggregates complete minute buckets into hour and day tables.
    ///
    /// # Errors
    ///
    /// Returns an error when the aggregation cannot be executed.
    fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<()>;
    /// Applies the configured retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention execution fails.
    fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()>;
    /// Loads the persisted retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error if policy cannot be read.
    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy>;
    /// Saves the retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error if policy cannot be saved.
    fn save_retention_policy(&mut self, policy: &RetentionPolicy, now_ms: u64)
    -> StorageResult<()>;
    /// Counts currently active flows.
    ///
    /// # Errors
    ///
    /// Returns an error if count fails.
    fn active_flow_count(&self) -> StorageResult<i64>;
    /// Calculates the ratio of unknown traffic since timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if calculation fails.
    fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64>;
    /// Returns database size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if size cannot be determined.
    fn database_size_bytes(&self) -> StorageResult<i64>;
    /// Returns backend name identifier.
    fn backend_name(&self) -> &'static str;
}

/// A SQLite connection and its optional live-flow cache.
#[derive(Debug)]
pub struct SqliteStorage {
    connection: Connection,
    active_flows: ActiveFlowCache,
    active_flow_count: i64,
    owner_prune_rows: Option<usize>,
    recovery_prune_rows: Option<usize>,
    rollup_progress: Option<RollupProgress>,
}

/// Result of an optional threshold-triggered WAL truncate checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalCheckpointStats {
    pub wal_bytes_before: u64,
    pub wal_bytes_after: u64,
    pub elapsed_us: u64,
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RollupMarkerCursor {
    pub(crate) session_ref: i64,
    pub(crate) timestamp: i64,
    pub(crate) scope: i64,
    pub(crate) direction: i64,
    pub(crate) device_id: i64,
    pub(crate) remote_ip: Vec<u8>,
    pub(crate) protocol: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RollupMarkerPhase {
    Hour,
    Day,
    Complete,
}

#[derive(Clone, Debug)]
struct RollupProgress {
    hour_cutoff: i64,
    day_cutoff: i64,
    phase: RollupMarkerPhase,
    cursor: Option<RollupMarkerCursor>,
}

/// Each live key is shared by the lookup map and the ordered expiry index.
/// Removing an entry also removes its expiry record, so the index cannot grow
/// with the number of updates received for a long-lived flow.
#[derive(Debug, Default)]
struct ActiveFlowCache {
    flows: HashMap<Arc<FlowKey>, ActiveFlow>,
    expiry: BTreeSet<(i64, Arc<FlowKey>)>,
}

type EmptyFlowTable = HashMap<Arc<FlowKey>, ActiveFlow>;

// At most one retired table waits behind the one being freed. If that slot is
// busy or the worker cannot be started, keep the empty table for reuse and
// retry on a later maintenance pass instead of blocking the writer.
fn empty_flow_table_reclaimer() -> Option<&'static mpsc::SyncSender<EmptyFlowTable>> {
    static SENDER: OnceLock<Option<mpsc::SyncSender<EmptyFlowTable>>> = OnceLock::new();
    SENDER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<EmptyFlowTable>(1);
            std::thread::Builder::new()
                .name("active-flow-reclaimer".to_owned())
                .spawn(move || {
                    while let Ok(table) = receiver.recv() {
                        drop(table);
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

impl ActiveFlowCache {
    fn get(&self, key: &FlowKey) -> Option<&ActiveFlow> {
        self.flows.get(key)
    }
    #[cfg(test)]
    fn values(&self) -> impl Iterator<Item = &ActiveFlow> {
        self.flows.values()
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.flows.len()
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn insert(&mut self, key: FlowKey, flow: ActiveFlow) {
        if let Some((shared, previous)) = self.flows.get_key_value(&key) {
            let shared = Arc::clone(shared);
            if previous.last_received_at != flow.last_received_at {
                self.expiry
                    .remove(&(previous.last_received_at, Arc::clone(&shared)));
                self.expiry
                    .insert((flow.last_received_at, Arc::clone(&shared)));
            }
            *self.flows.get_mut(shared.as_ref()).expect("existing flow") = flow;
        } else {
            let shared = Arc::new(key);
            self.expiry
                .insert((flow.last_received_at, Arc::clone(&shared)));
            self.flows.insert(shared, flow);
        }
    }

    fn remove(&mut self, key: &FlowKey) {
        if let Some((shared, flow)) = self.flows.remove_entry(key) {
            self.expiry.remove(&(flow.last_received_at, shared));
        }
    }

    // Call from maintenance, not the ingestion path: freeing a large table
    // can take measurable time. Keep small allocations for reuse.
    fn release_large_empty_allocation(&mut self) {
        if self.flows.is_empty() && self.flows.capacity() >= 65_536 {
            if let Some(sender) = empty_flow_table_reclaimer() {
                self.try_send_empty_allocation(sender);
            }
        }
    }

    fn try_send_empty_allocation(&mut self, sender: &mpsc::SyncSender<EmptyFlowTable>) {
        debug_assert!(self.flows.is_empty());
        let table = std::mem::take(&mut self.flows);
        if let Err(error) = sender.try_send(table) {
            self.flows = match error {
                mpsc::TrySendError::Full(table) | mpsc::TrySendError::Disconnected(table) => table,
            };
        }
    }

    fn extend(&mut self, flows: impl IntoIterator<Item = (FlowKey, ActiveFlow)>) {
        for (key, flow) in flows {
            self.insert(key, flow);
        }
        self.trim_to_capacity(ACTIVE_FLOW_CACHE_CAPACITY);
    }

    fn trim_to_capacity(&mut self, capacity: usize) {
        while self.flows.len() > capacity {
            let Some((_, key)) = self.expiry.first() else {
                break;
            };
            let key = Arc::clone(key);
            self.remove(key.as_ref());
        }
    }

    fn expired(&self, cutoff: i64, limit: usize) -> Vec<(Arc<FlowKey>, ActiveFlow)> {
        self.expiry
            .iter()
            .take_while(|(received, _)| *received <= cutoff)
            .take(limit.max(1))
            .map(|(_, key)| {
                (
                    Arc::clone(key),
                    self.flows
                        .get(key.as_ref())
                        .expect("expiry index matches cache")
                        .clone(),
                )
            })
            .collect()
    }

    fn has_expired(&self, cutoff: i64) -> bool {
        self.expiry
            .first()
            .is_some_and(|(received, _)| *received <= cutoff)
    }
}

impl<'a> IntoIterator for &'a ActiveFlowCache {
    type Item = (&'a Arc<FlowKey>, &'a ActiveFlow);
    type IntoIter = std::collections::hash_map::Iter<'a, Arc<FlowKey>, ActiveFlow>;
    fn into_iter(self) -> Self::IntoIter {
        self.flows.iter()
    }
}

enum RecoveryPruneBatch {
    Complete,
    MoreWork(Duration),
    Busy,
    Interrupted,
}

fn next_recovery_prune_rows(rows: usize, max_rows: usize, complete: bool) -> Option<usize> {
    if complete {
        None
    } else {
        Some((rows / 2).max(1).min(max_rows.max(1)))
    }
}

fn recovery_prune_rows_after_progress(
    rows: usize,
    max_rows: usize,
    elapsed: Duration,
    transaction_target: Duration,
) -> usize {
    if rows < max_rows && elapsed < transaction_target / 2 {
        rows.saturating_mul(2).min(max_rows)
    } else {
        rows.min(max_rows)
    }
}

impl SqliteStorage {
    fn independent_connection(&self, read_only: bool) -> StorageResult<Option<Self>> {
        let Some(path) = self
            .connection
            .path()
            .filter(|path| !path.is_empty() && *path != ":memory:")
        else {
            return Ok(None);
        };
        let flags = if read_only {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let mut connection =
            Connection::open_with_flags(path, flags | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        // Maintenance uses a short lock wait so it yields to Collector writes.
        // A BUSY result leaves the current batch uncommitted and retryable.
        connection.busy_timeout(if read_only {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(50)
        })?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "query_only", read_only)?;
        if read_only {
            connection.execute_batch("BEGIN DEFERRED")?;
        }
        if !read_only {
            connection.pragma_update(None, "synchronous", "NORMAL")?;
            connection.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
        }
        connection.set_prepared_statement_cache_capacity(64);
        Ok(Some(Self {
            // This connection is a maintenance writer with no ingestion cache.
            // The owning store recomputes its count when maintenance completes.
            active_flow_count: 0,
            connection,
            active_flows: ActiveFlowCache::default(),
            owner_prune_rows: None,
            recovery_prune_rows: if read_only {
                None
            } else {
                self.recovery_prune_rows
            },
            rollup_progress: if read_only {
                None
            } else {
                self.rollup_progress.clone()
            },
        }))
    }

    /// Opens or creates a database, configures it, and applies migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened, configured, or migrated.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Creates a migrated in-memory backend.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot initialize or migrate the database.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> rusqlite::Result<Self> {
        Self::from_connection_at(connection, unix_time_ms())
    }

    fn from_connection_at(mut connection: Connection, now_ms: u64) -> rusqlite::Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        // Reserve the writer before reading. With independent maintenance writers,
        // upgrading a deferred read snapshot can fail immediately with BUSY_SNAPSHOT
        // instead of honoring busy_timeout and waiting for the other writer.
        connection.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.set_prepared_statement_cache_capacity(64);
        migrate(&connection)?;
        let mut storage = Self {
            connection,
            active_flows: ActiveFlowCache::default(),
            active_flow_count: 0,
            owner_prune_rows: None,
            recovery_prune_rows: None,
            rollup_progress: None,
        };
        // Close stale persisted state before loading it into memory again.
        // Recovery commits bounded slices. If a slice exceeds the cooperative
        // transaction target, startup shrinks the slice and grows its budget;
        // otherwise an interrupted batch would be retried forever with the
        // same limit before the Collector can bind its listeners.
        storage.connection.busy_timeout(Duration::from_millis(50))?;
        storage.prune_reclassification_at_startup(now_ms)?;
        storage.connection.busy_timeout(Duration::from_secs(5))?;
        storage.active_flows = load_active_flows(&storage.connection, now_ms)?;
        storage.active_flow_count = count_active_sessions(&storage.connection)?;
        Ok(storage)
    }

    /// Loads the single enrolled Gateway.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn gateway(&self) -> rusqlite::Result<Option<GatewayRecord>> {
        self.connection
            .query_row(
                "SELECT id, agent_token_hash, last_seen FROM gateways ORDER BY created_at LIMIT 1",
                [],
                |row| {
                    let token_hash: Vec<u8> = row.get(1)?;
                    let agent_token_hash = token_hash.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            Type::Blob,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "agent token hash must contain 32 bytes",
                            )),
                        )
                    })?;
                    let last_seen = row.get::<_, i64>(2)?;
                    let last_seen_ms = u64::try_from(last_seen).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            Type::Integer,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "gateway last_seen must be non-negative",
                            )),
                        )
                    })?;
                    Ok(GatewayRecord {
                        id: row.get(0)?,
                        agent_token_hash,
                        last_seen_ms,
                    })
                },
            )
            .optional()
    }

    /// Creates the v1 Gateway if none is enrolled.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the insert.
    pub fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> rusqlite::Result<bool> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM gateways", [], |row| row.get(0))?;
        if count != 0 {
            return Ok(false);
        }
        self.connection.execute(
            "INSERT INTO gateways(
                id, site_id, name, agent_token_hash, agent_version, status, last_seen, created_at
             ) VALUES (?1, 'default', ?2, ?3, ?4, 'online', ?5, ?5)",
            params![
                gateway_id,
                name,
                agent_token_hash,
                agent_version,
                to_i64(now_ms)
            ],
        )?;
        Ok(true)
    }

    /// Rotates credentials when the persisted Gateway has been stale long
    /// enough, preserving the Gateway ID and all child history.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the conditional update.
    pub fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> rusqlite::Result<bool> {
        let updated = self.connection.execute(
            "UPDATE gateways SET name = ?2, agent_token_hash = ?3,
                agent_version = ?4, status = 'online', last_seen = ?5
             WHERE id = ?1 AND last_seen <= ?6",
            params![
                gateway_id,
                name,
                agent_token_hash,
                agent_version,
                to_i64(now_ms),
                to_i64(stale_before_ms),
            ],
        )?;
        Ok(updated == 1)
    }

    /// Returns whether the first local administrator has been created.
    ///
    /// # Errors
    ///
    /// Returns an error if the administrator lookup cannot be executed.
    pub fn admin_exists(&self) -> rusqlite::Result<bool> {
        self.connection
            .query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))
    }

    /// Atomically creates the only local administrator.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started, queried, committed, or rolled
    /// back, or if the administrator record cannot be inserted.
    pub fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> rusqlite::Result<bool> {
        let transaction = self.connection.transaction()?;
        let exists = transaction.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| {
            row.get::<_, bool>(0)
        })?;
        if exists {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO users(id, username, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, username, password_hash, to_i64(now_ms)],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Loads a local administrator by username.
    ///
    /// # Errors
    ///
    /// Returns an error if the administrator lookup cannot be executed or decoded.
    pub fn user_by_username(&self, username: &str) -> rusqlite::Result<Option<UserRecord>> {
        self.connection
            .query_row(
                "SELECT id, username, password_hash FROM users WHERE username = ?1",
                [username],
                |row| {
                    Ok(UserRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    /// Updates client editable attributes (display_name, device_type).
    ///
    /// # Errors
    ///
    /// Returns an error if the update query fails.
    pub fn update_client(
        &self,
        id: i64,
        display_name: Option<Option<&str>>,
        device_type: Option<Option<&str>>,
    ) -> rusqlite::Result<bool> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM devices WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Ok(false);
        }
        if display_name.is_none() && device_type.is_none() {
            return Ok(true);
        }
        let mut sets = Vec::new();
        let mut params: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(name_opt) = display_name {
            sets.push(format!("display_name = ?{}", params.len() + 1));
            match name_opt {
                Some(name) if !name.trim().is_empty() => {
                    params.push(rusqlite::types::Value::Text(name.trim().to_owned()));
                }
                _ => {
                    params.push(rusqlite::types::Value::Null);
                }
            }
        }

        if let Some(type_opt) = device_type {
            sets.push(format!("device_type_override = ?{}", params.len() + 1));
            match type_opt {
                Some(dtype) if !dtype.trim().is_empty() => {
                    params.push(rusqlite::types::Value::Text(dtype.trim().to_owned()));
                }
                _ => {
                    params.push(rusqlite::types::Value::Null);
                }
            }
        }

        let id_param_idx = params.len() + 1;
        params.push(rusqlite::types::Value::Integer(id));

        let sql = format!(
            "UPDATE devices SET {} WHERE id = ?{}",
            sets.join(", "),
            id_param_idx
        );
        self.connection
            .execute(&sql, rusqlite::params_from_iter(params))?;
        Ok(true)
    }

    /// Replaces expired sessions and stores a new hashed session token.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started or committed, expired sessions
    /// cannot be removed, or the new session cannot be inserted.
    pub fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at_ms: u64,
    ) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?1",
            [to_i64(now_ms)],
        )?;
        transaction.execute(
            "INSERT INTO auth_sessions(token_hash, user_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, user_id, to_i64(now_ms), to_i64(expires_at_ms)],
        )?;
        transaction.commit()
    }

    /// Resolves an unexpired session from a hashed token.
    ///
    /// # Errors
    ///
    /// Returns an error if the session lookup cannot be executed or decoded.
    pub fn session(
        &self,
        token_hash: &[u8],
        now_ms: u64,
    ) -> rusqlite::Result<Option<SessionRecord>> {
        self.connection
            .query_row(
                "SELECT users.id, users.username, auth_sessions.expires_at
                 FROM auth_sessions JOIN users ON users.id = auth_sessions.user_id
                 WHERE auth_sessions.token_hash = ?1 AND auth_sessions.expires_at > ?2",
                params![token_hash, to_i64(now_ms)],
                |row| {
                    let expires_at: i64 = row.get(2)?;
                    Ok(SessionRecord {
                        user_id: row.get(0)?,
                        username: row.get(1)?,
                        expires_at: u64::try_from(expires_at).unwrap_or(0),
                    })
                },
            )
            .optional()
    }

    /// Revokes a session by its hashed token.
    ///
    /// # Errors
    ///
    /// Returns an error if the session deletion cannot be executed.
    pub fn delete_session(&mut self, token_hash: &[u8]) -> rusqlite::Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?1",
            [token_hash],
        )? != 0)
    }

    /// Atomically deduplicates and persists all durable effects of a batch.
    ///
    /// # Errors
    ///
    /// Returns an error when any statement fails; the transaction is then rolled back.
    pub fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> rusqlite::Result<PersistDisposition> {
        self.persist_classified_batch(batch, &[], &[], received_at_ms)
    }

    /// Atomically persists a batch with one optional attribution per Flow.
    ///
    /// # Errors
    ///
    /// Returns an error when any statement fails; the transaction is then rolled back.
    pub fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> rusqlite::Result<PersistDisposition> {
        self.persist_classified_batch_with_total_batching(
            batch,
            attributions,
            device_identities,
            received_at_ms,
            true,
        )
    }

    fn persist_classified_batch_with_total_batching(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
        batch_total: bool,
    ) -> rusqlite::Result<PersistDisposition> {
        let received_at = to_i64(received_at_ms);
        let transaction = self.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO ingest_batches(gateway_id, boot_id, sequence, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                batch.gateway_id,
                batch.boot_id,
                to_i64(batch.sequence),
                received_at
            ],
        )?;
        if inserted == 0 {
            transaction.rollback()?;
            return Ok(PersistDisposition::Duplicate);
        }

        update_gateway(&transaction, batch, received_at)?;
        persist_devices(&transaction, batch, device_identities)?;
        persist_self_host_endpoint_evidence(&transaction, batch, attributions)?;
        persist_dns(&transaction, batch)?;
        let mut staged_active_flows = stage_sqlite_active_flows(&self.active_flows, batch);
        let active_count_delta = update_active_flows(
            &transaction,
            &mut staged_active_flows,
            batch,
            attributions,
            received_at,
            batch_total,
        )?;
        transaction.commit()?;
        self.active_flow_count = self
            .active_flow_count
            .saturating_add(active_count_delta)
            .max(0);
        for flow in &batch.flows {
            let key = FlowKey::from_batch(&batch.gateway_id, flow);
            if !staged_active_flows.contains_key(&key) {
                self.active_flows.remove(&key);
            }
        }
        self.active_flows.extend(staged_active_flows);
        Ok(PersistDisposition::Accepted)
    }

    /// Loads the accumulated identity evidence for one device.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> rusqlite::Result<Vec<DeviceEvidenceRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT gateway_id, mac, source, field, value, confidence,
                    first_seen, last_seen, hit_count, metadata_json
             FROM device_evidence
             WHERE gateway_id = ?1 AND mac = ?2
             ORDER BY field, source, value",
        )?;
        statement
            .query_map(params![gateway_id, mac], |row| {
                Ok(DeviceEvidenceRecord {
                    gateway_id: row.get(0)?,
                    mac: row.get(1)?,
                    source: row.get(2)?,
                    field: row.get(3)?,
                    value: row.get(4)?,
                    confidence: row.get(5)?,
                    first_seen: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
                    last_seen: u64::try_from(row.get::<_, i64>(7)?).unwrap_or(0),
                    hit_count: u64::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
                    metadata_json: row.get(9)?,
                })
            })?
            .collect()
    }

    /// Resolves the latest DNS answer scoped by Gateway and client, provided
    /// the observation was already present and has not exceeded its TTL.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> rusqlite::Result<Option<String>> {
        let exact = self.connection.query_row(
            "SELECT domain FROM dns_observations WHERE gateway_id=?1 AND client_ip=?2 AND answer_ip=?3
             AND observed_at<=?4 AND expires_at>?4 ORDER BY observed_at DESC,id DESC LIMIT 1",
            params![gateway_id, client_ip, answer_ip, to_i64(at_ms)], |row| row.get(0),
        ).optional()?;
        if exact.is_some() {
            return Ok(exact);
        }
        self.connection
            .query_row(
                SAME_DEVICE_DNS_QUERY,
                params![gateway_id, client_ip, answer_ip, to_i64(at_ms)],
                |row| row.get(0),
            )
            .optional()
    }

    /// Resolves the latest client-scoped DNS observation in a caller-bounded
    /// history window, even when its DNS TTL has elapsed.
    pub fn resolve_recent_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
        not_before_ms: u64,
    ) -> rusqlite::Result<Option<(String, u64)>> {
        self.connection
            .query_row(
                "SELECT domain, observed_at FROM dns_observations
                 WHERE gateway_id=?1 AND client_ip=?2 AND answer_ip=?3
                   AND observed_at>=?4 AND observed_at<=?5
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![
                    gateway_id,
                    client_ip,
                    answer_ip,
                    to_i64(not_before_ms),
                    to_i64(at_ms)
                ],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
            )
            .optional()
    }

    /// Resolves recent DNS history for several client/answer pairs using
    /// bounded SQL chunks. Each lookup still uses the existing DNS index.
    pub fn resolve_recent_domains(
        &self,
        gateway_id: &str,
        lookups: &[RecentDomainLookup<'_>],
    ) -> rusqlite::Result<Vec<Option<(String, u64)>>> {
        let mut results = vec![None; lookups.len()];
        for (chunk_number, chunk) in lookups.chunks(DNS_RECENT_LOOKUP_CHUNK_SIZE).enumerate() {
            let chunk_start = chunk_number * DNS_RECENT_LOOKUP_CHUNK_SIZE;
            let mut values = Vec::with_capacity(1 + chunk.len() * 4);
            values.push(Value::Text(gateway_id.to_owned()));
            let mut rows = Vec::with_capacity(chunk.len());
            for (local_index, lookup) in chunk.iter().enumerate() {
                let lookup_id = chunk_start + local_index;
                let first_parameter = 2 + local_index * 4;
                rows.push(format!(
                    "({lookup_id},?{first_parameter},?{},?{},?{})",
                    first_parameter + 1,
                    first_parameter + 2,
                    first_parameter + 3
                ));
                values.push(Value::Blob(lookup.client_ip.to_vec()));
                values.push(Value::Blob(lookup.answer_ip.to_vec()));
                values.push(Value::Integer(to_i64(lookup.at_ms)));
                values.push(Value::Integer(to_i64(lookup.not_before_ms)));
            }
            let sql = format!(
                "WITH lookups(lookup_id,client_ip,answer_ip,at_ms,not_before_ms) AS (
                    VALUES {}
                 )
                 SELECT q.lookup_id,d.domain,d.observed_at
                 FROM lookups q
                 LEFT JOIN dns_observations d ON d.id=(
                    SELECT id FROM dns_observations
                    WHERE gateway_id=?1 AND client_ip=q.client_ip AND answer_ip=q.answer_ip
                      AND observed_at>=q.not_before_ms AND observed_at<=q.at_ms
                    ORDER BY observed_at DESC,id DESC LIMIT 1
                 )",
                rows.join(",")
            );
            let mut statement = self.connection.prepare(&sql)?;
            let resolved = statement.query_map(params_from_iter(values), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?;
            for row in resolved {
                let (lookup_id, domain, observed_at) = row?;
                if let (Some(domain), Some(observed_at)) = (domain, observed_at) {
                    let lookup_id = usize::try_from(lookup_id).unwrap_or(usize::MAX);
                    if let Some(result) = results.get_mut(lookup_id) {
                        *result = Some((domain, observed_at.max(0) as u64));
                    }
                }
            }
        }
        Ok(results)
    }

    /// Aggregates complete minute buckets into hour and day tables.
    ///
    /// # Errors
    ///
    /// Returns an error when the aggregation transaction cannot be committed.
    pub fn roll_up_hour_and_day(&mut self, now_ms: u64) -> rusqlite::Result<()> {
        let budget = RetentionBudget::default();
        while !self.roll_up_hour_and_day_bounded(now_ms, budget)? {
            std::thread::yield_now();
        }
        Ok(())
    }

    /// Commits at most one bounded slice of hour/day rollup work.
    ///
    /// Pending rows remain durable between calls, so callers can yield to
    /// ingestion and resume on the next maintenance pass. Returns true when
    /// all eligible pending rows have been materialized.
    pub fn roll_up_hour_and_day_bounded(
        &mut self,
        now_ms: u64,
        budget: RetentionBudget,
    ) -> rusqlite::Result<bool> {
        let now = to_i64(now_ms);
        let cutoffs = [
            ("hour", now / HOUR_MS * HOUR_MS),
            ("day", now / DAY_MS * DAY_MS),
        ];
        let tasks = [
            ("total", cutoffs[0].0, cutoffs[0].1),
            ("device", cutoffs[0].0, cutoffs[0].1),
            ("application", cutoffs[0].0, cutoffs[0].1),
            ("domain", cutoffs[0].0, cutoffs[0].1),
            ("destination", cutoffs[0].0, cutoffs[0].1),
            ("total", cutoffs[1].0, cutoffs[1].1),
            ("device", cutoffs[1].0, cutoffs[1].1),
            ("application", cutoffs[1].0, cutoffs[1].1),
            ("domain", cutoffs[1].0, cutoffs[1].1),
            ("destination", cutoffs[1].0, cutoffs[1].1),
        ];
        let mut row_limit = budget.max_rows_per_batch.max(1);
        loop {
            let started = std::time::Instant::now();
            let deadline = started + budget.transaction_target.max(Duration::from_millis(1));
            let transaction = match self.connection.transaction() {
                Ok(transaction) => transaction,
                Err(error) if sqlite_is_busy(&error) => return Ok(false),
                Err(error) => return Err(error),
            };
            transaction
                .progress_handler(1_000, Some(move || std::time::Instant::now() >= deadline))?;
            let initial_progress = self
                .rollup_progress
                .as_ref()
                .filter(|progress| {
                    progress.hour_cutoff == cutoffs[0].1 && progress.day_cutoff == cutoffs[1].1
                })
                .cloned()
                .unwrap_or(RollupProgress {
                    hour_cutoff: cutoffs[0].1,
                    day_cutoff: cutoffs[1].1,
                    phase: RollupMarkerPhase::Hour,
                    cursor: None,
                });
            let result = (|| -> rusqlite::Result<(bool, Option<RollupProgress>)> {
                let mut remaining = row_limit;
                for (index, (dimension, target, cutoff)) in tasks.iter().enumerate() {
                    if remaining == 0 {
                        break;
                    }
                    let tasks_left = tasks.len() - index;
                    let slice_limit = remaining.div_ceil(tasks_left).max(1);
                    let processed =
                        aggregate_bounded(&transaction, dimension, target, *cutoff, slice_limit)?;
                    remaining = remaining.saturating_sub(processed);
                }
                if rollup_pending(&transaction, &tasks)? {
                    return Ok((
                        false,
                        Some(RollupProgress {
                            hour_cutoff: cutoffs[0].1,
                            day_cutoff: cutoffs[1].1,
                            phase: RollupMarkerPhase::Hour,
                            cursor: None,
                        }),
                    ));
                }
                if initial_progress.phase == RollupMarkerPhase::Complete {
                    return Ok((true, Some(initial_progress.clone())));
                }
                if remaining == 0 {
                    return Ok((false, Some(initial_progress.clone())));
                }

                let mut progress = initial_progress.clone();
                if progress.phase == RollupMarkerPhase::Hour {
                    let (marked, cursor) = attribution::mark_aggregated_batch(
                        &transaction,
                        RollupMarkerPhase::Hour,
                        cutoffs[0].1,
                        progress.cursor.as_ref(),
                        remaining,
                    )?;
                    if marked == remaining {
                        progress.cursor = cursor;
                        return Ok((false, Some(progress)));
                    }
                    remaining = remaining.saturating_sub(marked);
                    progress.phase = RollupMarkerPhase::Day;
                    progress.cursor = None;
                    if remaining == 0 {
                        return Ok((false, Some(progress)));
                    }
                }
                let (marked, cursor) = attribution::mark_aggregated_batch(
                    &transaction,
                    RollupMarkerPhase::Day,
                    cutoffs[1].1,
                    progress.cursor.as_ref(),
                    remaining,
                )?;
                if marked == remaining {
                    progress.cursor = cursor;
                    return Ok((false, Some(progress)));
                }
                progress.phase = RollupMarkerPhase::Complete;
                progress.cursor = None;
                Ok((true, Some(progress)))
            })();
            transaction.progress_handler(0, None::<fn() -> bool>)?;
            match result {
                Ok((complete, progress)) => match transaction.commit() {
                    Ok(()) => {
                        self.rollup_progress = progress;
                        return Ok(complete);
                    }
                    Err(error) if sqlite_is_busy(&error) => return Ok(false),
                    Err(error) => return Err(error),
                },
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::OperationInterrupted =>
                {
                    drop(transaction);
                    if row_limit <= 1 {
                        return Ok(false);
                    }
                    row_limit = (row_limit / 2).max(1);
                }
                Err(error) if sqlite_is_busy(&error) => {
                    drop(transaction);
                    return Ok(false);
                }
                Err(error) => {
                    drop(transaction);
                    return Err(error);
                }
            }
        }
    }

    /// Removes expired correction work after checkpointing recovery state.
    ///
    /// # Errors
    /// Returns an error if the cleanup transaction cannot be committed.
    pub fn prune_reclassification(&mut self, now_ms: u64) -> rusqlite::Result<()> {
        let tx = self.connection.transaction()?;
        prune_flow_state(&tx, &self.active_flows, to_i64(now_ms))?;
        tx.commit()?;
        let cutoff = to_i64(now_ms).saturating_sub(ACTIVE_FLOW_TTL_MS);
        while let Some((_, key)) = self.active_flows.expiry.first().cloned() {
            if !self.active_flows.has_expired(cutoff) {
                break;
            }
            self.active_flows.remove(&key);
            self.active_flow_count = self.active_flow_count.saturating_sub(1).max(0);
        }
        self.active_flows.release_large_empty_allocation();
        self.active_flow_count = count_active_sessions(&self.connection)?;
        Ok(())
    }

    /// Deletes data older than its retention window and expired DNS answers.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention transaction cannot be committed.
    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> rusqlite::Result<()> {
        self.run_retention_bounded(now_ms, policy, RetentionBudget::default())
            .map(|_| ())
    }

    /// Returns true when a complete pass found no further expired rows.
    pub fn run_retention_bounded(
        &mut self,
        now_ms: u64,
        policy: RetentionPolicy,
        budget: RetentionBudget,
    ) -> rusqlite::Result<bool> {
        let started = std::time::Instant::now();
        let now = to_i64(now_ms);
        if !self.prune_reclassification_bounded(
            now_ms,
            budget.max_rows_per_batch,
            budget.transaction_target,
        )? {
            return Ok(false);
        }
        let mut tasks = Vec::new();
        let mut add = |table: String, keys: String, column: &'static str, days: u32| {
            if days != 0 {
                tasks.push((
                    table,
                    keys,
                    column,
                    now.saturating_sub(i64::from(days) * DAY_MS),
                    false,
                ));
            }
        };
        // Pending work must expire before its aggregate, otherwise another
        // maintenance connection can rematerialize an expired aggregate.
        for dimension in DIMENSIONS {
            for (tier, days) in [("hour", policy.hour_days), ("day", policy.day_days)] {
                add(
                    format!("traffic_{dimension}_{tier}_pending"),
                    format!("timestamp, {}", dimension_columns(dimension)),
                    "timestamp",
                    days,
                );
            }
        }
        add(
            "flow_sessions".into(),
            "rowid".into(),
            "last_seen_at",
            policy.flow_sessions_days,
        );
        add(
            "ingest_batches".into(),
            "rowid".into(),
            "received_at",
            policy.minute_days,
        );
        add(
            "traffic_scope_minute".into(),
            "rowid".into(),
            "timestamp",
            policy.minute_days,
        );
        for dimension in DIMENSIONS {
            for (tier, days) in [
                ("minute", policy.minute_days),
                ("hour", policy.hour_days),
                ("day", policy.day_days),
            ] {
                add(
                    format!("traffic_{dimension}_{tier}"),
                    "rowid".into(),
                    "timestamp",
                    days,
                );
            }
        }
        let dns_cutoff = if policy.dns_days == 0 {
            i64::MIN
        } else {
            now.saturating_sub(i64::from(policy.dns_days) * DAY_MS)
        };
        tasks.push((
            "dns_observations".into(),
            "rowid".into(),
            "expires_at",
            dns_cutoff,
            true,
        ));
        let mut rows_limit = budget.max_rows_per_batch.clamp(1, i64::MAX as usize);
        let mut done = vec![false; tasks.len()];
        let mut remaining = tasks.len();
        let mut stalled = 0;
        // Rotate the start across invocations so a busy early table cannot
        // permanently starve later tables when the job budget is short.
        let mut index = usize::try_from(now_ms / 60_000).unwrap_or(0) % tasks.len();
        while remaining != 0 {
            if started.elapsed() >= budget.total_budget {
                return Ok(false);
            }
            if done[index] {
                index = (index + 1) % tasks.len();
                continue;
            }
            let (table, keys, column, cutoff, dns) = &tasks[index];
            let lhs = if keys == "rowid" {
                keys.clone()
            } else {
                format!("({keys})")
            };
            let dependent = !*dns && (table.ends_with("_hour") || table.ends_with("_day"));
            let predicate = if *dns {
                "expires_at < ?1 OR observed_at < ?2".to_owned()
            } else {
                format!("{column} < ?1")
            };
            let sql = format!(
                "DELETE FROM {table} WHERE {lhs} IN (SELECT {keys} FROM {table} WHERE {predicate} LIMIT ?3)"
            );
            let tx_started = std::time::Instant::now();
            let begin_started = std::time::Instant::now();
            let tx = match self.connection.transaction() {
                Ok(tx) => tx,
                Err(error) if sqlite_is_busy(&error) => return Ok(false),
                Err(error) => return Err(error),
            };
            let begin_elapsed = begin_started.elapsed();
            // SQLite can interrupt long VM execution inside DELETE/trigger
            // programs. This is cooperative and does not cover lock acquisition,
            // fsync, or an individual OS scheduling stall.
            let statement_deadline = tx_started + budget.transaction_target;
            tx.progress_handler(
                1_000,
                Some(move || std::time::Instant::now() >= statement_deadline),
            )?;
            let delete_started = std::time::Instant::now();
            let work = (|| -> rusqlite::Result<(bool, usize)> {
                let blocked = dependent
                    && tx.query_row(
                        &format!(
                            "SELECT EXISTS(SELECT 1 FROM {table}_pending WHERE timestamp < ?1)"
                        ),
                        [cutoff],
                        |row| row.get::<_, bool>(0),
                    )?;
                let deleted = if blocked {
                    0
                } else {
                    tx.execute(
                        &sql,
                        params![
                            if *dns { now } else { *cutoff },
                            if *dns { *cutoff } else { 0 },
                            i64::try_from(rows_limit).unwrap_or(i64::MAX)
                        ],
                    )?
                };
                Ok((blocked, deleted))
            })();
            let delete_elapsed = delete_started.elapsed();
            tx.progress_handler(0, None::<fn() -> bool>)?;
            let (blocked, deleted) = match work {
                Ok(result) => result,
                Err(error) => {
                    drop(tx); // Drop rolls back this batch; previous commits stand.
                    if sqlite_is_busy(&error) {
                        return Ok(false);
                    }
                    if matches!(
                        &error,
                        rusqlite::Error::SqliteFailure(code, _)
                            if code.code == rusqlite::ErrorCode::OperationInterrupted
                    ) {
                        rows_limit = (rows_limit / 2).max(1);
                        if started.elapsed() >= budget.total_budget {
                            return Ok(false);
                        }
                        continue;
                    }
                    return Err(error);
                }
            };
            let commit_started = std::time::Instant::now();
            if let Err(error) = tx.commit() {
                if sqlite_is_busy(&error) {
                    return Ok(false);
                }
                return Err(error);
            }
            let commit_elapsed = commit_started.elapsed();
            let elapsed = tx_started.elapsed();
            #[cfg(test)]
            RETENTION_TRANSACTION_TIMES.with(|times| times.borrow_mut().push(elapsed));
            #[cfg(test)]
            RETENTION_PHASE_TIMES.with(|times| {
                times
                    .borrow_mut()
                    .push((begin_elapsed, delete_elapsed, commit_elapsed))
            });
            tracing::debug!(
                table,
                rows = deleted,
                elapsed_us = elapsed.as_micros(),
                begin_us = begin_elapsed.as_micros(),
                delete_and_trigger_us = delete_elapsed.as_micros(),
                commit_us = commit_elapsed.as_micros(),
                "retention batch committed"
            );
            if elapsed > budget.transaction_target {
                rows_limit = (rows_limit / 2).max(1);
            }
            if blocked {
                stalled += 1;
                if stalled >= remaining {
                    return Ok(false);
                }
            } else {
                stalled = 0;
                if deleted == 0 {
                    done[index] = true;
                    remaining -= 1;
                }
            }
            if deleted != 0 {
                // Allow an ingestion writer waiting in SQLite's busy handler
                // to acquire the lock between maintenance transactions.
                std::thread::sleep(Duration::from_millis(1));
            }
            index = (index + 1) % tasks.len();
        }
        Ok(true)
    }

    /// Executes one bounded recovery-state checkpoint/GC transaction.
    /// Committed slices are safe to repeat after restart; an interrupted slice
    /// rolls back and the next maintenance pass resumes from the remaining rows.
    pub fn prune_reclassification_bounded(
        &mut self,
        now_ms: u64,
        limit: usize,
        transaction_target: Duration,
    ) -> rusqlite::Result<bool> {
        self.prune_reclassification_bounded_adaptive(now_ms, limit, transaction_target, true)
    }

    fn prune_reclassification_bounded_adaptive(
        &mut self,
        now_ms: u64,
        max_rows: usize,
        transaction_target: Duration,
        recount_active: bool,
    ) -> rusqlite::Result<bool> {
        let max_rows = max_rows.max(1);
        let rows = self
            .recovery_prune_rows
            .unwrap_or(max_rows)
            .min(max_rows)
            .max(1);
        match self.prune_reclassification_batch(now_ms, rows, Some(transaction_target), true)? {
            RecoveryPruneBatch::Complete => {
                self.recovery_prune_rows = next_recovery_prune_rows(rows, max_rows, true);
                if recount_active {
                    self.active_flow_count = count_active_sessions(&self.connection)?;
                }
                Ok(true)
            }
            RecoveryPruneBatch::Interrupted => {
                self.recovery_prune_rows = next_recovery_prune_rows(rows, max_rows, false);
                Ok(false)
            }
            RecoveryPruneBatch::MoreWork(elapsed) => {
                self.recovery_prune_rows = Some(recovery_prune_rows_after_progress(
                    rows,
                    max_rows,
                    elapsed,
                    transaction_target,
                ));
                Ok(false)
            }
            RecoveryPruneBatch::Busy => Ok(false),
        }
    }

    fn prune_reclassification_at_startup(&mut self, now_ms: u64) -> rusqlite::Result<()> {
        let budget = RetentionBudget::default();
        let max_rows = budget.max_rows_per_batch.max(1);
        self.prune_reclassification_at_startup_with_budget(
            now_ms,
            max_rows,
            Some(budget.transaction_target),
            budget.total_budget,
        )
    }

    fn prune_reclassification_at_startup_with_budget(
        &mut self,
        now_ms: u64,
        max_rows: usize,
        mut target: Option<Duration>,
        total_budget: Duration,
    ) -> rusqlite::Result<()> {
        let max_rows = max_rows.max(1);
        let mut rows = max_rows;
        let started = std::time::Instant::now();
        loop {
            if started.elapsed() >= total_budget {
                tracing::warn!(
                    elapsed_ms = started.elapsed().as_millis(),
                    "startup recovery GC yielded to background maintenance"
                );
                return Ok(());
            }
            match self.prune_reclassification_batch(now_ms, rows, target, true)? {
                RecoveryPruneBatch::Complete => return Ok(()),
                RecoveryPruneBatch::MoreWork(elapsed) => {
                    let ramp_threshold = target
                        .map(|duration| duration / 2)
                        .unwrap_or(Duration::from_millis(10));
                    if rows < max_rows && elapsed < ramp_threshold {
                        rows = rows.saturating_mul(2).min(max_rows);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                RecoveryPruneBatch::Busy => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                RecoveryPruneBatch::Interrupted => {
                    if rows > 1 {
                        rows = (rows / 2).max(1);
                    } else {
                        target = match target {
                            Some(current) if current < Duration::from_secs(1) => {
                                Some(Duration::from_secs(1))
                            }
                            Some(current) if current < Duration::from_secs(30) => {
                                Some((current * 2).min(Duration::from_secs(30)))
                            }
                            Some(_) | None => None,
                        };
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn prune_reclassification_batch(
        &mut self,
        now_ms: u64,
        limit: usize,
        transaction_target: Option<Duration>,
        recovery_gc: bool,
    ) -> rusqlite::Result<RecoveryPruneBatch> {
        let now = to_i64(now_ms);
        let cutoff = now.saturating_sub(ACTIVE_FLOW_TTL_MS);
        let candidates = self.active_flows.expired(cutoff, limit);
        if candidates.is_empty() && !recovery_gc {
            self.active_flows.release_large_empty_allocation();
            return Ok(RecoveryPruneBatch::Complete);
        }
        let started = std::time::Instant::now();
        let tx = match self.connection.transaction() {
            Ok(tx) => tx,
            Err(error) if sqlite_is_busy(&error) => return Ok(RecoveryPruneBatch::Busy),
            Err(error) => return Err(error),
        };
        let begin_elapsed = started.elapsed();
        if let Some(transaction_target) = transaction_target {
            let deadline = started + transaction_target;
            tx.progress_handler(1_000, Some(move || std::time::Instant::now() >= deadline))?;
        } else {
            tx.progress_handler(0, None::<fn() -> bool>)?;
        }
        let result = (|| -> rusqlite::Result<bool> {
            for (key, flow) in &candidates {
                if flow.last_seen_at > 0 {
                    write_flow_session(&tx, key, flow, Some(flow.last_seen_at), now)?;
                }
                tx.prepare_cached(
                    "UPDATE flow_rollup_sessions SET ended_at=?2
                     WHERE session_id=?1 AND ended_at IS NULL",
                )?
                .execute(params![flow.session_id(key).as_ref(), now])?;
            }
            if recovery_gc {
                attribution::prune_bounded(&tx, now, limit.max(1))
            } else {
                Ok(false)
            }
        })();
        tx.progress_handler(0, None::<fn() -> bool>)?;
        let prune_elapsed = started.elapsed().saturating_sub(begin_elapsed);
        let pending = match result {
            Ok(pending) => pending,
            Err(rusqlite::Error::SqliteFailure(code, _))
                if code.code == rusqlite::ErrorCode::OperationInterrupted =>
            {
                drop(tx);
                return Ok(RecoveryPruneBatch::Interrupted);
            }
            Err(error) if sqlite_is_busy(&error) => {
                drop(tx);
                return Ok(RecoveryPruneBatch::Busy);
            }
            Err(error) => {
                drop(tx);
                return Err(error);
            }
        };
        let commit_started = std::time::Instant::now();
        if let Err(error) = tx.commit() {
            if sqlite_is_busy(&error) {
                return Ok(RecoveryPruneBatch::Busy);
            }
            return Err(error);
        }
        let commit_elapsed = commit_started.elapsed();
        let elapsed = started.elapsed();
        #[cfg(test)]
        {
            RETENTION_TRANSACTION_TIMES.with(|times| times.borrow_mut().push(elapsed));
            RETENTION_PHASE_TIMES.with(|times| {
                times
                    .borrow_mut()
                    .push((begin_elapsed, prune_elapsed, commit_elapsed))
            });
        }
        tracing::debug!(
            elapsed_us = elapsed.as_micros(),
            begin_us = begin_elapsed.as_micros(),
            recovery_gc_us = prune_elapsed.as_micros(),
            commit_us = commit_elapsed.as_micros(),
            "retention recovery batch committed"
        );
        for (key, _) in candidates {
            self.active_flows.remove(&key);
            self.active_flow_count = self.active_flow_count.saturating_sub(1).max(0);
        }
        self.active_flows.release_large_empty_allocation();
        if pending || self.active_flows.has_expired(cutoff) {
            return Ok(RecoveryPruneBatch::MoreWork(elapsed));
        }
        Ok(RecoveryPruneBatch::Complete)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Returns the path for a file-backed database.
    pub fn database_file_path(&self) -> Option<PathBuf> {
        self.connection
            .path()
            .filter(|path| !path.is_empty() && *path != ":memory:")
            .map(PathBuf::from)
    }

    /// Truncates a file-backed WAL only when its sidecar reaches `threshold_bytes`.
    ///
    /// This opens a short-lived independent connection so callers can run the
    /// checkpoint after releasing the Collector's state lock. A zero threshold
    /// disables the operation.
    pub fn checkpoint_wal_if_larger_than(
        path: impl AsRef<Path>,
        threshold_bytes: u64,
    ) -> rusqlite::Result<Option<WalCheckpointStats>> {
        if threshold_bytes == 0 {
            return Ok(None);
        }
        let path = path.as_ref();
        let wal_path = wal_sidecar_path(path);
        let wal_bytes_before = std::fs::metadata(&wal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if wal_bytes_before < threshold_bytes {
            return Ok(None);
        }

        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Keep the independent checkpoint connection responsive to an active
        // writer. A busy checkpoint is reported to the caller and can retry on
        // the next maintenance pass.
        connection.busy_timeout(Duration::from_millis(50))?;
        let started = std::time::Instant::now();
        let (busy, log_frames, checkpointed_frames) =
            connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let wal_bytes_after = std::fs::metadata(&wal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(Some(WalCheckpointStats {
            wal_bytes_before,
            wal_bytes_after,
            elapsed_us,
            busy,
            log_frames,
            checkpointed_frames,
        }))
    }

    /// Loads the persisted retention policy or returns the default.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn load_retention_policy(&self) -> rusqlite::Result<RetentionPolicy> {
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM settings WHERE key = 'retention'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(json
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default())
    }

    /// Persists the retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the upsert.
    pub fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> rusqlite::Result<()> {
        let json = serde_json::to_string(policy).unwrap_or_else(|_| "null".to_owned());
        self.connection.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES ('retention', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![json, to_i64(now_ms)],
        )?;
        Ok(())
    }

    /// Counts active sessions across the bounded cache and SQLite recovery state.
    ///
    /// # Errors
    ///
    pub fn active_flow_count(&self) -> rusqlite::Result<i64> {
        Ok(self.active_flow_count)
    }

    /// Returns the ratio of unknown-classified flows to total recent flows.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the query.
    #[allow(clippy::cast_precision_loss)]
    pub fn unknown_ratio(&self, since_ms: u64) -> rusqlite::Result<f64> {
        let result: (i64, i64) = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN application_id = 'unknown' THEN 1 ELSE 0 END), 0)
             FROM flow_sessions WHERE last_seen_at >= ?1",
            [to_i64(since_ms)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if result.0 == 0 {
            Ok(0.0)
        } else {
            Ok(result.1 as f64 / result.0 as f64)
        }
    }

    /// Returns the database file size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the PRAGMA queries.
    pub fn database_size_bytes(&self) -> rusqlite::Result<i64> {
        let page_count: i64 =
            self.connection
                .query_row("SELECT page_count FROM pragma_page_count", [], |row| {
                    row.get(0)
                })?;
        let page_size: i64 =
            self.connection
                .query_row("SELECT page_size FROM pragma_page_size", [], |row| {
                    row.get(0)
                })?;
        Ok(page_count * page_size)
    }

    /// Queries minute totals in the half-open time range.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn query_total_traffic(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> rusqlite::Result<Vec<TrafficTotal>> {
        let mut statement = self.connection.prepare(
            "SELECT timestamp, upload_bytes, download_bytes, packets, flow_count
             FROM traffic_total_minute WHERE timestamp >= ?1 AND timestamp < ?2
             ORDER BY timestamp",
        )?;
        statement
            .query_map(params![to_i64(from_ms), to_i64(to_ms)], |row| {
                Ok(TrafficTotal {
                    timestamp: row.get(0)?,
                    upload_bytes: row.get(1)?,
                    download_bytes: row.get(2)?,
                    packets: row.get(3)?,
                    flow_count: row.get(4)?,
                })
            })?
            .collect()
    }
}

fn wal_sidecar_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push("-wal");
    PathBuf::from(path)
}

impl StorageBackend for SqliteStorage {
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        Self::gateway(self).map_err(Into::into)
    }

    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        Self::save_gateway(
            self,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            now_ms,
        )
        .map_err(Into::into)
    }

    fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        Self::replace_stale_gateway(
            self,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            stale_before_ms,
            now_ms,
        )
        .map_err(Into::into)
    }

    fn admin_exists(&self) -> StorageResult<bool> {
        Self::admin_exists(self).map_err(Into::into)
    }

    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        Self::create_admin(self, id, username, password_hash, now_ms).map_err(Into::into)
    }

    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        Self::user_by_username(self, username).map_err(Into::into)
    }

    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        Self::create_session(self, user_id, token_hash, now_ms, expires_at).map_err(Into::into)
    }

    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        Self::session(self, token_hash, now_ms).map_err(Into::into)
    }

    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        Self::delete_session(self, token_hash).map_err(Into::into)
    }

    fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        Self::persist_batch(self, batch, received_at_ms).map_err(Into::into)
    }

    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        Self::persist_classified_batch(self, batch, attributions, device_identities, received_at_ms)
            .map_err(Into::into)
    }

    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        Self::device_evidence(self, gateway_id, mac).map_err(Into::into)
    }

    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        Self::resolve_domain(self, gateway_id, client_ip, answer_ip, at_ms).map_err(Into::into)
    }

    fn resolve_recent_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
        not_before_ms: u64,
    ) -> StorageResult<Option<(String, u64)>> {
        Self::resolve_recent_domain(self, gateway_id, client_ip, answer_ip, at_ms, not_before_ms)
            .map_err(Into::into)
    }

    fn resolve_recent_domains(
        &self,
        gateway_id: &str,
        lookups: &[RecentDomainLookup<'_>],
    ) -> StorageResult<Vec<Option<(String, u64)>>> {
        Self::resolve_recent_domains(self, gateway_id, lookups).map_err(Into::into)
    }

    fn query_total_traffic(&self, from_ms: u64, to_ms: u64) -> StorageResult<Vec<TrafficTotal>> {
        Self::query_total_traffic(self, from_ms, to_ms).map_err(Into::into)
    }

    fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<()> {
        Self::roll_up_hour_and_day(self, now_ms).map_err(Into::into)
    }

    fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        Self::run_retention(self, now_ms, policy).map_err(Into::into)
    }

    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        Self::load_retention_policy(self).map_err(Into::into)
    }

    fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        Self::save_retention_policy(self, policy, now_ms).map_err(Into::into)
    }

    fn active_flow_count(&self) -> StorageResult<i64> {
        Self::active_flow_count(self).map_err(Into::into)
    }

    fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        Self::unknown_ratio(self, since_ms).map_err(Into::into)
    }

    fn database_size_bytes(&self) -> StorageResult<i64> {
        Self::database_size_bytes(self).map_err(Into::into)
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }
}

/// Unified storage wrapper switching between SQLite and `ClickHouse` backends.
#[derive(Debug)]
pub enum Storage {
    Sqlite(SqliteStorage),
    ClickHouse(ClickHouseStorage),
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
impl Storage {
    /// Returns the file path when this backend is a file-backed SQLite database.
    pub fn database_file_path(&self) -> Option<PathBuf> {
        match self {
            Self::Sqlite(storage) => storage.database_file_path(),
            Self::ClickHouse(_) => None,
        }
    }

    /// Opens an independent WAL reader without migrations or active-flow recovery.
    /// In-memory databases keep using the owning connection.
    pub fn query_reader(&self) -> StorageResult<Option<Self>> {
        match self {
            Self::Sqlite(storage) => storage
                .independent_connection(true)
                .map(|reader| reader.map(Self::Sqlite)),
            Self::ClickHouse(storage) => Ok(Some(Self::ClickHouse(storage.query_reader()))),
        }
    }

    /// Opens a separate file-backed SQLite writer for bounded maintenance work.
    pub fn maintenance_writer(&self) -> StorageResult<Option<Self>> {
        match self {
            Self::Sqlite(storage) => storage
                .independent_connection(false)
                .map(|writer| writer.map(Self::Sqlite)),
            Self::ClickHouse(storage) => Ok(Some(Self::ClickHouse(storage.query_reader()))),
        }
    }

    /// Copies resumable SQLite maintenance cursors back to their owning store.
    pub fn sync_maintenance_state_from(&mut self, maintenance: &Self) {
        if let (Self::Sqlite(owner), Self::Sqlite(maintenance)) = (self, maintenance) {
            owner.rollup_progress = maintenance.rollup_progress.clone();
            owner.recovery_prune_rows = maintenance.recovery_prune_rows;
        }
    }

    /// Commits one bounded, resumable recovery-state cleanup slice.
    pub fn prune_reclassification_bounded(
        &mut self,
        now_ms: u64,
        budget: RetentionBudget,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(storage) => storage
                .prune_reclassification_bounded(
                    now_ms,
                    budget.max_rows_per_batch,
                    budget.transaction_target,
                )
                .map_err(Into::into),
            Self::ClickHouse(_) => Ok(true),
        }
    }

    /// Commits one bounded recovery-state cleanup slice on an independent
    /// maintenance connection. Its ActiveFlow count is not used by the owning
    /// Storage, so avoid rescanning all open sessions after the slice.
    pub fn prune_reclassification_for_maintenance_bounded(
        &mut self,
        now_ms: u64,
        budget: RetentionBudget,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(storage) => storage
                .prune_reclassification_bounded_adaptive(
                    now_ms,
                    budget.max_rows_per_batch,
                    budget.transaction_target,
                    false,
                )
                .map_err(Into::into),
            Self::ClickHouse(_) => Ok(true),
        }
    }

    /// Checkpoints and evicts expired flows from the owning SQLite cache.
    /// A separate maintenance connection has its own empty cache and cannot do this.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot checkpoint a flow or restore the busy timeout.
    pub fn prune_owned_flow_cache(
        &mut self,
        now_ms: u64,
        budget: RetentionBudget,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(storage) => {
                storage.connection.busy_timeout(Duration::from_millis(50))?;
                let max_rows = budget.max_rows_per_batch.max(1);
                let rows = storage
                    .owner_prune_rows
                    .unwrap_or(max_rows)
                    .min(max_rows)
                    .max(1);
                let result = storage.prune_reclassification_batch(
                    now_ms,
                    rows,
                    Some(budget.transaction_target),
                    false,
                );
                storage.connection.busy_timeout(Duration::from_secs(5))?;
                match result? {
                    RecoveryPruneBatch::Complete => {
                        storage.owner_prune_rows = None;
                        Ok(true)
                    }
                    RecoveryPruneBatch::MoreWork(_) => {
                        storage.owner_prune_rows = Some(rows.saturating_mul(2).min(max_rows));
                        Ok(false)
                    }
                    RecoveryPruneBatch::Interrupted => {
                        storage.owner_prune_rows = Some((rows / 2).max(1));
                        Ok(false)
                    }
                    RecoveryPruneBatch::Busy => Ok(false),
                }
            }
            Self::ClickHouse(_) => Ok(true),
        }
    }

    /// Applies late DPI metadata without inserting telemetry or changing counters.
    ///
    /// # Errors
    /// Returns backend errors while updating existing sessions.
    pub fn reclassify_flow(
        &mut self,
        gateway: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
    ) -> StorageResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        self.reclassify_flow_at(gateway, flow, attribution, now)
    }

    /// Applies late classification using collector receipt time for the bounded
    /// correction window, independently of device packet timestamps.
    pub fn reclassify_flow_at(
        &mut self,
        gateway: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
        received_at_ms: u64,
    ) -> StorageResult<()> {
        match self {
            Self::ClickHouse(storage) => storage.reclassify_flow(gateway, flow, attribution),
            Self::Sqlite(storage) => {
                attribution::reclassify_sqlite(
                    storage,
                    gateway,
                    flow,
                    attribution,
                    to_i64(received_at_ms),
                )?;
                Ok(())
            }
        }
    }

    /// Reclaims expired SQLite correction work; historical rollups are retained.
    pub fn prune_reclassification(&mut self, now_ms: u64) -> StorageResult<()> {
        if let Self::Sqlite(storage) = self {
            storage.prune_reclassification(now_ms)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn sqlite(storage: SqliteStorage) -> Self {
        Self::Sqlite(storage)
    }

    #[must_use]
    pub fn clickhouse(storage: ClickHouseStorage) -> Self {
        Self::ClickHouse(storage)
    }

    #[must_use]
    pub fn sqlite_connection(&self) -> Option<&Connection> {
        match self {
            Self::Sqlite(s) => Some(s.connection()),
            Self::ClickHouse(_) => None,
        }
    }

    #[must_use]
    pub fn clickhouse_storage(&self) -> Option<&ClickHouseStorage> {
        match self {
            Self::Sqlite(_) => None,
            Self::ClickHouse(c) => Some(c),
        }
    }

    pub fn clickhouse_storage_mut(&mut self) -> Option<&mut ClickHouseStorage> {
        match self {
            Self::Sqlite(_) => None,
            Self::ClickHouse(c) => Some(c),
        }
    }

    #[must_use]
    pub fn connection(&self) -> &Connection {
        match self {
            Self::Sqlite(s) => s.connection(),
            Self::ClickHouse(_) => panic!("connection() called on ClickHouse storage backend"),
        }
    }

    pub fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        StorageBackend::gateway(self)
    }

    pub fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        StorageBackend::save_gateway(
            self,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            now_ms,
        )
    }

    pub fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        StorageBackend::replace_stale_gateway(
            self,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            stale_before_ms,
            now_ms,
        )
    }

    pub fn admin_exists(&self) -> StorageResult<bool> {
        StorageBackend::admin_exists(self)
    }

    pub fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        StorageBackend::create_admin(self, id, username, password_hash, now_ms)
    }

    pub fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        StorageBackend::user_by_username(self, username)
    }

    pub fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        StorageBackend::create_session(self, user_id, token_hash, now_ms, expires_at)
    }

    pub fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        StorageBackend::session(self, token_hash, now_ms)
    }

    pub fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        StorageBackend::delete_session(self, token_hash)
    }

    pub fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        StorageBackend::persist_batch(self, batch, received_at_ms)
    }

    pub fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        StorageBackend::persist_classified_batch(
            self,
            batch,
            attributions,
            device_identities,
            received_at_ms,
        )
    }

    pub fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        StorageBackend::device_evidence(self, gateway_id, mac)
    }

    pub fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        StorageBackend::resolve_domain(self, gateway_id, client_ip, answer_ip, at_ms)
    }

    pub fn resolve_recent_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
        not_before_ms: u64,
    ) -> StorageResult<Option<(String, u64)>> {
        StorageBackend::resolve_recent_domain(
            self,
            gateway_id,
            client_ip,
            answer_ip,
            at_ms,
            not_before_ms,
        )
    }

    pub fn resolve_recent_domains(
        &self,
        gateway_id: &str,
        lookups: &[RecentDomainLookup<'_>],
    ) -> StorageResult<Vec<Option<(String, u64)>>> {
        StorageBackend::resolve_recent_domains(self, gateway_id, lookups)
    }

    pub fn query_total_traffic(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> StorageResult<Vec<TrafficTotal>> {
        StorageBackend::query_total_traffic(self, from_ms, to_ms)
    }

    pub fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<()> {
        StorageBackend::roll_up_hour_and_day(self, now_ms)
    }

    /// Runs one bounded SQLite rollup slice, yielding between maintenance passes.
    pub fn roll_up_hour_and_day_bounded(
        &mut self,
        now_ms: u64,
        budget: RetentionBudget,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(storage) => storage
                .roll_up_hour_and_day_bounded(now_ms, budget)
                .map_err(Into::into),
            Self::ClickHouse(storage) => {
                storage.roll_up_hour_and_day(now_ms)?;
                Ok(true)
            }
        }
    }

    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        StorageBackend::run_retention(self, now_ms, policy)
    }

    pub fn run_retention_bounded(
        &mut self,
        now_ms: u64,
        policy: RetentionPolicy,
        budget: RetentionBudget,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(storage) => storage
                .run_retention_bounded(now_ms, policy, budget)
                .map_err(Into::into),
            Self::ClickHouse(storage) => {
                StorageBackend::run_retention(storage, now_ms, policy).map(|()| true)
            }
        }
    }

    pub fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        StorageBackend::load_retention_policy(self)
    }

    pub fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        StorageBackend::save_retention_policy(self, policy, now_ms)
    }

    pub fn active_flow_count(&self) -> StorageResult<i64> {
        StorageBackend::active_flow_count(self)
    }

    pub fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        StorageBackend::unknown_ratio(self, since_ms)
    }

    pub fn database_size_bytes(&self) -> StorageResult<i64> {
        StorageBackend::database_size_bytes(self)
    }

    pub fn backend_name(&self) -> &'static str {
        StorageBackend::backend_name(self)
    }

    /// Updates client editable attributes (display_name, device_type).
    ///
    /// # Errors
    ///
    /// Returns `StorageError` if the update query or mutation fails.
    pub fn update_client(
        &self,
        id: i64,
        display_name: Option<Option<&str>>,
        device_type: Option<Option<&str>>,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => s
                .update_client(id, display_name, device_type)
                .map_err(Into::into),
            Self::ClickHouse(c) => c.update_client(id, display_name, device_type),
        }
    }
}

impl StorageBackend for Storage {
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        match self {
            Self::Sqlite(s) => StorageBackend::gateway(s),
            Self::ClickHouse(c) => StorageBackend::gateway(c),
        }
    }

    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => StorageBackend::save_gateway(
                s,
                gateway_id,
                name,
                agent_version,
                agent_token_hash,
                now_ms,
            ),
            Self::ClickHouse(c) => StorageBackend::save_gateway(
                c,
                gateway_id,
                name,
                agent_version,
                agent_token_hash,
                now_ms,
            ),
        }
    }

    fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => StorageBackend::replace_stale_gateway(
                s,
                gateway_id,
                name,
                agent_version,
                agent_token_hash,
                stale_before_ms,
                now_ms,
            ),
            Self::ClickHouse(c) => StorageBackend::replace_stale_gateway(
                c,
                gateway_id,
                name,
                agent_version,
                agent_token_hash,
                stale_before_ms,
                now_ms,
            ),
        }
    }

    fn admin_exists(&self) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => StorageBackend::admin_exists(s),
            Self::ClickHouse(c) => StorageBackend::admin_exists(c),
        }
    }

    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => StorageBackend::create_admin(s, id, username, password_hash, now_ms),
            Self::ClickHouse(c) => {
                StorageBackend::create_admin(c, id, username, password_hash, now_ms)
            }
        }
    }

    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        match self {
            Self::Sqlite(s) => StorageBackend::user_by_username(s, username),
            Self::ClickHouse(c) => StorageBackend::user_by_username(c, username),
        }
    }

    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        match self {
            Self::Sqlite(s) => {
                StorageBackend::create_session(s, user_id, token_hash, now_ms, expires_at)
            }
            Self::ClickHouse(c) => {
                StorageBackend::create_session(c, user_id, token_hash, now_ms, expires_at)
            }
        }
    }

    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        match self {
            Self::Sqlite(s) => StorageBackend::session(s, token_hash, now_ms),
            Self::ClickHouse(c) => StorageBackend::session(c, token_hash, now_ms),
        }
    }

    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        match self {
            Self::Sqlite(s) => StorageBackend::delete_session(s, token_hash),
            Self::ClickHouse(c) => StorageBackend::delete_session(c, token_hash),
        }
    }

    fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        match self {
            Self::Sqlite(s) => StorageBackend::persist_batch(s, batch, received_at_ms),
            Self::ClickHouse(c) => StorageBackend::persist_batch(c, batch, received_at_ms),
        }
    }

    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        match self {
            Self::Sqlite(s) => StorageBackend::persist_classified_batch(
                s,
                batch,
                attributions,
                device_identities,
                received_at_ms,
            ),
            Self::ClickHouse(c) => StorageBackend::persist_classified_batch(
                c,
                batch,
                attributions,
                device_identities,
                received_at_ms,
            ),
        }
    }

    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        match self {
            Self::Sqlite(s) => StorageBackend::device_evidence(s, gateway_id, mac),
            Self::ClickHouse(c) => StorageBackend::device_evidence(c, gateway_id, mac),
        }
    }

    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        match self {
            Self::Sqlite(s) => {
                StorageBackend::resolve_domain(s, gateway_id, client_ip, answer_ip, at_ms)
            }
            Self::ClickHouse(c) => {
                StorageBackend::resolve_domain(c, gateway_id, client_ip, answer_ip, at_ms)
            }
        }
    }

    fn resolve_recent_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
        not_before_ms: u64,
    ) -> StorageResult<Option<(String, u64)>> {
        match self {
            Self::Sqlite(s) => StorageBackend::resolve_recent_domain(
                s,
                gateway_id,
                client_ip,
                answer_ip,
                at_ms,
                not_before_ms,
            ),
            Self::ClickHouse(c) => StorageBackend::resolve_recent_domain(
                c,
                gateway_id,
                client_ip,
                answer_ip,
                at_ms,
                not_before_ms,
            ),
        }
    }

    fn resolve_recent_domains(
        &self,
        gateway_id: &str,
        lookups: &[RecentDomainLookup<'_>],
    ) -> StorageResult<Vec<Option<(String, u64)>>> {
        match self {
            Self::Sqlite(storage) => {
                StorageBackend::resolve_recent_domains(storage, gateway_id, lookups)
            }
            Self::ClickHouse(storage) => {
                StorageBackend::resolve_recent_domains(storage, gateway_id, lookups)
            }
        }
    }

    fn query_total_traffic(&self, from_ms: u64, to_ms: u64) -> StorageResult<Vec<TrafficTotal>> {
        match self {
            Self::Sqlite(s) => StorageBackend::query_total_traffic(s, from_ms, to_ms),
            Self::ClickHouse(c) => StorageBackend::query_total_traffic(c, from_ms, to_ms),
        }
    }

    fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<()> {
        match self {
            Self::Sqlite(s) => StorageBackend::roll_up_hour_and_day(s, now_ms),
            Self::ClickHouse(c) => StorageBackend::roll_up_hour_and_day(c, now_ms),
        }
    }

    fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        match self {
            Self::Sqlite(s) => StorageBackend::run_retention(s, now_ms, policy),
            Self::ClickHouse(c) => StorageBackend::run_retention(c, now_ms, policy),
        }
    }

    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        match self {
            Self::Sqlite(s) => StorageBackend::load_retention_policy(s),
            Self::ClickHouse(c) => StorageBackend::load_retention_policy(c),
        }
    }

    fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        match self {
            Self::Sqlite(s) => StorageBackend::save_retention_policy(s, policy, now_ms),
            Self::ClickHouse(c) => StorageBackend::save_retention_policy(c, policy, now_ms),
        }
    }

    fn active_flow_count(&self) -> StorageResult<i64> {
        match self {
            Self::Sqlite(s) => StorageBackend::active_flow_count(s),
            Self::ClickHouse(c) => StorageBackend::active_flow_count(c),
        }
    }

    fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        match self {
            Self::Sqlite(s) => StorageBackend::unknown_ratio(s, since_ms),
            Self::ClickHouse(c) => StorageBackend::unknown_ratio(c, since_ms),
        }
    }

    fn database_size_bytes(&self) -> StorageResult<i64> {
        match self {
            Self::Sqlite(s) => StorageBackend::database_size_bytes(s),
            Self::ClickHouse(c) => StorageBackend::database_size_bytes(c),
        }
    }

    fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(s) => StorageBackend::backend_name(s),
            Self::ClickHouse(c) => StorageBackend::backend_name(c),
        }
    }
}

fn migrate(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL
        );",
    )?;
    for (version, sql) in MIGRATIONS {
        let applied = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
            [version],
            |row| row.get::<_, bool>(0),
        )?;
        if applied {
            continue;
        }
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at)
             VALUES (?1, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
            [version],
        )?;
        transaction.commit()?;
    }
    Ok(())
}

fn load_active_flows(connection: &Connection, now_ms: u64) -> rusqlite::Result<ActiveFlowCache> {
    let mut statement = connection.prepare(
        "SELECT gateway_id, ip_version, protocol, client_ip, client_port, remote_ip,
                remote_port, direction, upload_bytes, download_bytes, packets,
                started_at, last_seen_at, checkpointed_at, domain, organization_id,
                application_id, category_id, traffic_role, protocol_id, organization_confidence,
                application_confidence, protocol_confidence, classification_confidence,
                classification_reason, classification_evidence_json, scope, path_type, nat,
                source_segment, destination_segment, device_id, id
         FROM flow_sessions WHERE ended_at IS NULL AND checkpointed_at>?1
         ORDER BY checkpointed_at DESC LIMIT ?2",
    )?;
    let mut active = ActiveFlowCache::default();
    let rows = statement.query_map(
        params![
            to_i64(now_ms).saturating_sub(ACTIVE_FLOW_TTL_MS),
            i64::try_from(ACTIVE_FLOW_CACHE_CAPACITY).unwrap_or(i64::MAX)
        ],
        |row| {
            let key = FlowKey {
                gateway_id: row.get(0)?,
                ip_version: row.get(1)?,
                protocol: row.get(2)?,
                client_ip: row.get(3)?,
                client_port: row.get(4)?,
                remote_ip: row.get(5)?,
                remote_port: row.get(6)?,
                direction: row.get(7)?,
            };
            let started_at: i64 = row.get(11)?;
            let session_id: String = row.get(32)?;
            let canonical_session_id = key.session_id(started_at);
            let session_id_override =
                (session_id != canonical_session_id).then(|| session_id.into_boxed_str());
            Ok((
                key,
                ActiveFlow {
                    session_id_override,
                    client_mac: Vec::new(),
                    device_id: row.get(31)?,
                    upload_bytes: row.get(8)?,
                    download_bytes: row.get(9)?,
                    packets: row.get(10)?,
                    started_at,
                    last_seen_at: row.get(12)?,
                    checkpointed_at: row.get(13)?,
                    last_received_at: row.get(13)?,
                    scope: row.get(26)?,
                    path_type: row.get(27)?,
                    nat: row.get(28)?,
                    source_segment: row.get(29)?,
                    destination_segment: row.get(30)?,
                    attribution: shared_active_attribution(FlowAttribution {
                        domain: row.get(14)?,
                        organization_id: row
                            .get::<_, Option<String>>(15)?
                            .unwrap_or_else(|| "unknown".to_owned()),
                        application_id: row
                            .get::<_, Option<String>>(16)?
                            .unwrap_or_else(|| "unknown".to_owned()),
                        category_id: row
                            .get::<_, Option<String>>(17)?
                            .unwrap_or_else(|| "unknown".to_owned()),
                        traffic_role: row
                            .get::<_, Option<String>>(18)?
                            .unwrap_or_else(|| "unknown".to_owned()),
                        protocol_id: row
                            .get::<_, Option<String>>(19)?
                            .unwrap_or_else(|| "unknown".to_owned()),
                        organization_confidence: row.get::<_, Option<f64>>(20)?.unwrap_or(0.0),
                        application_confidence: row.get::<_, Option<f64>>(21)?.unwrap_or(0.0),
                        protocol_confidence: row.get::<_, Option<f64>>(22)?.unwrap_or(0.0),
                        confidence: row.get::<_, Option<f64>>(23)?.unwrap_or(0.0),
                        reason: row
                            .get::<_, Option<String>>(24)?
                            .unwrap_or_else(|| "no matching rule".to_owned()),
                        evidence_json: row
                            .get::<_, Option<String>>(25)?
                            .unwrap_or_else(|| "[]".to_owned()),
                    }),
                },
            ))
        },
    )?;
    for row in rows {
        let (key, flow) = row?;
        active.insert(key, flow);
    }
    drop(statement);
    attribution::restore_active(connection, &mut active, to_i64(now_ms))?;
    active.trim_to_capacity(ACTIVE_FLOW_CACHE_CAPACITY);
    Ok(active)
}

fn count_active_sessions(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NULL) +
            (SELECT COUNT(*) FROM flow_rollup_sessions r WHERE r.ended_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM flow_sessions f
                    WHERE f.id=r.session_id AND f.ended_at IS NULL))",
        [],
        |row| row.get(0),
    )
}

fn stage_sqlite_active_flows(
    active: &ActiveFlowCache,
    batch: &TelemetryBatch,
) -> HashMap<FlowKey, ActiveFlow> {
    let mut staged = HashMap::new();
    for flow in &batch.flows {
        let key = FlowKey::from_batch(&batch.gateway_id, flow);
        if let std::collections::hash_map::Entry::Vacant(entry) = staged.entry(key)
            && let Some(current) = active.get(entry.key())
        {
            entry.insert(current.clone());
        }
    }
    staged
}

fn stage_active_flows(
    active: &HashMap<FlowKey, ActiveFlow>,
    batch: &TelemetryBatch,
) -> HashMap<FlowKey, ActiveFlow> {
    let mut staged = HashMap::new();
    for flow in &batch.flows {
        let key = FlowKey::from_batch(&batch.gateway_id, flow);
        if let std::collections::hash_map::Entry::Vacant(entry) = staged.entry(key)
            && let Some(current) = active.get(entry.key())
        {
            entry.insert(current.clone());
        }
    }
    staged
}

fn commit_active_flows(
    active: &mut HashMap<FlowKey, ActiveFlow>,
    batch: &TelemetryBatch,
    staged: HashMap<FlowKey, ActiveFlow>,
) {
    // An End can remove a staged entry, so publish deletions as well as updates.
    for flow in &batch.flows {
        active.remove(&FlowKey::from_batch(&batch.gateway_id, flow));
    }
    active.extend(staged);
}

fn prune_flow_state(
    tx: &Transaction<'_>,
    active: &ActiveFlowCache,
    now: i64,
) -> rusqlite::Result<()> {
    let cutoff = now.saturating_sub(ACTIVE_FLOW_TTL_MS);
    for (key, flow) in active {
        if flow.last_received_at <= cutoff && flow.last_seen_at > 0 {
            write_flow_session(tx, key, flow, Some(flow.last_seen_at), now)?;
            tx.prepare_cached(
                "UPDATE flow_rollup_sessions SET ended_at=?2
                 WHERE session_id=?1 AND ended_at IS NULL",
            )?
            .execute(params![flow.session_id(key).as_ref(), now])?;
        }
    }
    attribution::prune(tx, now)?;
    // Legacy checkpoints can outlive their short-lived recovery records. A
    // recent recovery record protects a flow updated since its last checkpoint.
    tx.prepare_cached(
        "UPDATE flow_sessions SET ended_at=last_seen_at
         WHERE ended_at IS NULL AND checkpointed_at<=?1
           AND NOT EXISTS (SELECT 1 FROM flow_rollup_sessions r
             WHERE r.session_id=flow_sessions.id AND r.ended_at IS NULL AND r.updated_at>?1)",
    )?
    .execute([cutoff])?;
    Ok(())
}

fn update_gateway(tx: &Transaction<'_>, batch: &TelemetryBatch, now: i64) -> rusqlite::Result<()> {
    let health = batch.health.as_ref();
    tx.execute(
        "UPDATE gateways SET agent_version = ?2, kernel_version = ?3,
            openwrt_version = ?4, status = 'online', last_seen = ?5 WHERE id = ?1",
        params![
            batch.gateway_id,
            batch.agent_version,
            health.map_or("", |value| value.kernel_version.as_str()),
            health.map_or("", |value| value.openwrt_version.as_str()),
            now,
        ],
    )?;
    Ok(())
}

fn persist_devices(
    tx: &Transaction<'_>,
    batch: &TelemetryBatch,
    identities: &[DeviceIdentityUpdate],
) -> rusqlite::Result<()> {
    let mut identities_by_mac = HashMap::with_capacity(identities.len());
    for identity in identities {
        identities_by_mac
            .entry(identity.mac.as_slice())
            .or_insert(identity);
    }
    for device in &batch.device_observations {
        let seen = to_i64(device.last_seen_unix_ms);
        let identity = identities_by_mac.get(device.mac.as_slice()).copied();
        tx.execute(
            "INSERT INTO devices(
                gateway_id, mac, hostname, vendor, device_type, os_family, model,
                identity_confidence, vendor_confidence, device_type_confidence,
                os_confidence, model_confidence, private_mac,
                identity_evidence_json, first_seen, last_seen
             )
             VALUES (?1, ?2, NULLIF(?3, ''), ?4, ?5, ?6, ?7, COALESCE(?8, 'unknown'),
                     ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)
             ON CONFLICT(gateway_id, mac) DO UPDATE SET
               hostname = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
               vendor = COALESCE(excluded.vendor, devices.vendor),
               device_type = COALESCE(excluded.device_type, devices.device_type),
               os_family = COALESCE(excluded.os_family, devices.os_family),
               model = COALESCE(excluded.model, devices.model),
               identity_confidence = excluded.identity_confidence,
               vendor_confidence = excluded.vendor_confidence,
               device_type_confidence = excluded.device_type_confidence,
               os_confidence = excluded.os_confidence,
               model_confidence = excluded.model_confidence,
               private_mac = excluded.private_mac,
               identity_evidence_json = excluded.identity_evidence_json,
               last_seen = MAX(devices.last_seen, excluded.last_seen)",
            params![
                batch.gateway_id,
                device.mac,
                device.hostname,
                identity.and_then(|value| value.vendor.as_deref()),
                identity.and_then(|value| value.device_type.as_deref()),
                identity.and_then(|value| value.os_family.as_deref()),
                identity.and_then(|value| value.model.as_deref()),
                identity.and_then(|value| value.confidence.as_deref()),
                identity.map_or(0.0, |value| value.vendor_confidence),
                identity.map_or(0.0, |value| value.device_type_confidence),
                identity.map_or(0.0, |value| value.os_confidence),
                identity.map_or(0.0, |value| value.model_confidence),
                identity.is_some_and(|value| value.private_mac),
                identity.map_or("[]", |value| value.evidence_json.as_str()),
                seen,
            ],
        )?;
        let device_id: i64 = tx.query_row(
            "SELECT id FROM devices WHERE gateway_id = ?1 AND mac = ?2",
            params![batch.gateway_id, device.mac],
            |row| row.get(0),
        )?;
        if let Some(ip_version) = ip_version(&device.ip) {
            tx.execute(
                "INSERT INTO device_addresses(device_id, ip, ip_version, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(device_id, ip) DO UPDATE SET
                   last_seen = MAX(device_addresses.last_seen, excluded.last_seen)",
                params![device_id, device.ip, ip_version, seen],
            )?;
        }
    }
    for identity in identities {
        persist_device_evidence(tx, &batch.gateway_id, &identity.mac, &identity.evidence)?;
    }
    Ok(())
}

fn persist_self_host_endpoint_evidence(
    tx: &Transaction<'_>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
) -> rusqlite::Result<()> {
    const EVIDENCE_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
    let newest = batch
        .flows
        .iter()
        .map(|flow| to_i64(flow.last_seen_unix_ms))
        .max()
        .unwrap_or_else(|| to_i64(batch.sent_at));
    tx.execute(
        "DELETE FROM self_host_endpoint_evidence WHERE gateway_id = ?1 AND expires_at <= ?2",
        params![batch.gateway_id, newest],
    )?;
    tx.execute(
        "UPDATE device_addresses SET application_id=NULL, application_confidence=0,
            application_source=NULL, application_last_seen=NULL
         WHERE application_id IS NOT NULL
           AND device_id IN (SELECT id FROM devices WHERE gateway_id=?1)
           AND NOT EXISTS (
             SELECT 1 FROM self_host_endpoint_evidence e
             WHERE e.gateway_id=?1 AND e.ip=device_addresses.ip AND e.expires_at>?2)",
        params![batch.gateway_id, newest],
    )?;
    let mut affected = HashSet::<Vec<u8>>::new();
    for (index, flow) in batch.flows.iter().enumerate() {
        let Some(attribution) = attributions.get(index) else {
            continue;
        };
        if attribution_evidence_type(attribution, "self_host_shared_ip") {
            tx.execute(
                "DELETE FROM self_host_endpoint_evidence WHERE gateway_id=?1 AND ip=?2",
                params![batch.gateway_id, flow.remote_ip],
            )?;
            affected.insert(flow.remote_ip.clone());
            continue;
        }
        if attribution.application_id == "unknown"
            || attribution.application_confidence < 0.9
            || matches!(flow.remote_port, 80 | 443)
            || !attribution_evidence_type(attribution, "self_host_application")
        {
            continue;
        }
        let observed_at = to_i64(flow.last_seen_unix_ms.max(batch.sent_at));
        let source = if attribution_evidence_type(attribution, "service_binding") {
            "service_binding"
        } else {
            "classifier"
        };
        tx.execute(
            "INSERT INTO self_host_endpoint_evidence(
                gateway_id, ip, protocol, port, application_id, confidence,
                source, last_seen, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(gateway_id, ip, protocol, port, application_id) DO UPDATE SET
               confidence = MAX(self_host_endpoint_evidence.confidence, excluded.confidence),
               source = excluded.source,
               last_seen = MAX(self_host_endpoint_evidence.last_seen, excluded.last_seen),
               expires_at = MAX(self_host_endpoint_evidence.expires_at, excluded.expires_at)",
            params![
                batch.gateway_id,
                flow.remote_ip,
                flow.protocol,
                flow.remote_port,
                attribution.application_id,
                attribution.application_confidence,
                source,
                observed_at,
                observed_at.saturating_add(EVIDENCE_TTL_MS),
            ],
        )?;
        affected.insert(flow.remote_ip.clone());
    }
    refresh_self_host_addresses(tx, &batch.gateway_id, newest, affected)
}

fn refresh_self_host_addresses(
    tx: &Transaction<'_>,
    gateway_id: &str,
    newest: i64,
    affected: HashSet<Vec<u8>>,
) -> rusqlite::Result<()> {
    for ip in affected {
        let application_count: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT application_id) FROM self_host_endpoint_evidence
             WHERE gateway_id = ?1 AND ip = ?2 AND expires_at > ?3",
            params![gateway_id, ip, newest],
            |row| row.get(0),
        )?;
        if application_count == 1 {
            let (application_id, confidence, source, last_seen): (String, f64, String, i64) = tx
                .query_row(
                    "SELECT application_id, MAX(confidence), MIN(source), MAX(last_seen)
                     FROM self_host_endpoint_evidence
                     WHERE gateway_id = ?1 AND ip = ?2 AND expires_at > ?3
                     GROUP BY application_id",
                    params![gateway_id, ip, newest],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
            tx.execute(
                "UPDATE device_addresses SET application_id=?1, application_confidence=?2,
                    application_source=?3, application_last_seen=?4
                 WHERE ip=?5 AND device_id IN (SELECT id FROM devices WHERE gateway_id=?6)",
                params![
                    application_id,
                    confidence,
                    source,
                    last_seen,
                    ip,
                    gateway_id
                ],
            )?;
        } else {
            tx.execute(
                "UPDATE device_addresses SET application_id=NULL, application_confidence=0,
                    application_source=NULL, application_last_seen=NULL
                 WHERE ip=?1 AND device_id IN (SELECT id FROM devices WHERE gateway_id=?2)",
                params![ip, gateway_id],
            )?;
        }
    }
    Ok(())
}

fn attribution_evidence_type(attribution: &FlowAttribution, evidence_type: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(&attribution.evidence_json)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("type").and_then(serde_json::Value::as_str) == Some(evidence_type)
            })
        })
}

fn persist_device_evidence(
    tx: &Transaction<'_>,
    gateway_id: &str,
    mac: &[u8],
    evidence: &[DeviceEvidenceUpdate],
) -> rusqlite::Result<()> {
    for item in evidence {
        let observed_at = to_i64(item.observed_at);
        tx.execute(
            "INSERT INTO device_evidence(
                gateway_id, mac, source, field, value, confidence,
                first_seen, last_seen, hit_count, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1, ?8)
             ON CONFLICT(gateway_id, mac, source, field, value) DO UPDATE SET
               confidence = MAX(device_evidence.confidence, excluded.confidence),
               first_seen = MIN(device_evidence.first_seen, excluded.first_seen),
               last_seen = MAX(device_evidence.last_seen, excluded.last_seen),
               hit_count = device_evidence.hit_count + 1,
               metadata_json = CASE
                 WHEN excluded.metadata_json <> '{}' THEN excluded.metadata_json
                 ELSE device_evidence.metadata_json
               END",
            params![
                gateway_id,
                mac,
                item.source,
                item.field,
                item.value,
                item.confidence.clamp(0.0, 1.0),
                observed_at,
                item.metadata_json,
            ],
        )?;
    }
    Ok(())
}

fn persist_dns(tx: &Transaction<'_>, batch: &TelemetryBatch) -> rusqlite::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO dns_observations(
            gateway_id, client_ip, domain, answer_ip, record_type, ttl,
            observed_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for observation in &batch.dns_observations {
        let observed_at = to_i64(observation.observed_at_unix_ms);
        let ttl_ms = i64::from(observation.ttl_seconds).saturating_mul(1_000);
        insert.execute(params![
            batch.gateway_id,
            observation.client_ip,
            observation.domain,
            observation.answer_ip,
            observation.record_type,
            observation.ttl_seconds,
            observed_at,
            observed_at.saturating_add(ttl_ms),
        ])?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn persist_minute_rollups(
    tx: &Transaction<'_>,
    batch: &TelemetryBatch,
    flow: &FlowDelta,
    attribution: &FlowAttribution,
    device_id: Option<i64>,
    device_batch: &mut RepeatedRollupBatch,
    destination_batch: &mut RepeatedRollupBatch,
) -> rusqlite::Result<()> {
    let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
    let upload = to_i64(flow.upload_bytes);
    let download = to_i64(flow.download_bytes);
    let packets = to_i64(flow.packets);
    let protocol_application_id = (attribution.application_id == "unknown"
        && !attribution.protocol_id.is_empty()
        && attribution.protocol_id != "unknown")
        .then(|| format!("{PROTOCOL_APPLICATION_PREFIX}{}", attribution.protocol_id));
    let (application_id, category_id) = protocol_application_id.as_deref().map_or_else(
        || {
            (
                attribution.application_id.as_str(),
                attribution.category_id.as_str(),
            )
        },
        |id| (id, "unknown"),
    );
    if let Some(device_id) = device_id {
        device_batch.add(
            tx,
            &[
                timestamp.into(),
                batch.gateway_id.clone().into(),
                device_id.into(),
            ],
            upload,
            download,
            packets,
        )?;
    }
    upsert_rollup(
        tx,
        "traffic_application_minute",
        Some("application_id, category_id"),
        &[
            timestamp.into(),
            batch.gateway_id.clone().into(),
            application_id.to_owned().into(),
            category_id.to_owned().into(),
        ],
        upload,
        download,
        packets,
    )?;
    upsert_rollup(
        tx,
        "traffic_domain_minute",
        Some("domain"),
        &[
            timestamp.into(),
            batch.gateway_id.clone().into(),
            attribution
                .domain
                .clone()
                .unwrap_or_else(|| "unknown".to_owned())
                .into(),
        ],
        upload,
        download,
        packets,
    )?;
    destination_batch.add(
        tx,
        &[
            timestamp.into(),
            batch.gateway_id.clone().into(),
            flow.remote_ip.clone().into(),
        ],
        upload,
        download,
        packets,
    )?;
    let device_id = device_id.unwrap_or(0);
    upsert_rollup(
        tx,
        "traffic_scope_minute",
        Some(
            "scope, direction, device_id, application_id, category_id, domain, remote_ip, protocol, protocol_id",
        ),
        &[
            timestamp.into(),
            batch.gateway_id.clone().into(),
            i64::from(flow.scope).into(),
            i64::from(flow.direction).into(),
            device_id.into(),
            attribution.application_id.clone().into(),
            attribution.category_id.clone().into(),
            attribution
                .domain
                .clone()
                .unwrap_or_else(|| "unknown".to_owned())
                .into(),
            flow.remote_ip.clone().into(),
            i64::from(flow.protocol).into(),
            attribution.protocol_id.clone().into(),
        ],
        upload,
        download,
        packets,
    )?;
    Ok(())
}

// Total, device and destination batching each retain at most one key. Device
// and destination rollups do not participate in attribution transfers.
const ROLLUP_MAX_DELTAS: i64 = 1024;

struct RepeatedRollupBatch {
    table: &'static str,
    dimension: &'static str,
    source_sql: &'static str,
    pending_sql: &'static str,
    key: Option<Vec<Value>>,
    consecutive: u8,
    enabled: bool,
    unsafe_key: bool,
    base: Option<([i64; 4], [i64; 4])>,
    delta: [i64; 4],
}

impl RepeatedRollupBatch {
    fn new(device: bool, enabled: bool) -> Self {
        let (table, dimension, source_sql, pending_sql) = if device {
            (
                "traffic_device_minute",
                "device_id",
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_device_minute WHERE timestamp=?1 AND gateway_id=?2 AND device_id=?3",
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_device_hour_pending WHERE timestamp=?1 AND gateway_id=?2 AND device_id=?3",
            )
        } else {
            (
                "traffic_destination_minute",
                "remote_ip",
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_destination_minute WHERE timestamp=?1 AND gateway_id=?2 AND remote_ip=?3",
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_destination_hour_pending WHERE timestamp=?1 AND gateway_id=?2 AND remote_ip=?3",
            )
        };
        Self {
            table,
            dimension,
            source_sql,
            pending_sql,
            key: None,
            consecutive: 0,
            enabled,
            unsafe_key: false,
            base: None,
            delta: [0; 4],
        }
    }

    fn read_counters(
        tx: &Transaction<'_>,
        sql: &str,
        key: &[Value],
    ) -> rusqlite::Result<Option<[i64; 4]>> {
        let values: Option<[Value; 4]> = tx
            .prepare_cached(sql)?
            .query_row(rusqlite::params_from_iter(key), |row| {
                Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?])
            })
            .optional()?;
        let Some(values) = values else {
            return Ok(Some([0; 4]));
        };
        let mut counters = [0; 4];
        for (index, value) in values.into_iter().enumerate() {
            match value {
                Value::Integer(n) if n >= 0 => counters[index] = n,
                _ => return Ok(None),
            }
        }
        Ok(Some(counters))
    }

    fn add(
        &mut self,
        tx: &Transaction<'_>,
        key: &[Value],
        upload: i64,
        download: i64,
        packets: i64,
    ) -> rusqlite::Result<()> {
        if !self.enabled {
            return upsert_rollup(
                tx,
                self.table,
                Some(self.dimension),
                key,
                upload,
                download,
                packets,
            );
        }
        if self.key.as_deref() != Some(key) {
            self.flush(tx)?;
            self.key = Some(key.to_vec());
            self.consecutive = 0;
            self.unsafe_key = false;
        }
        if upload < 0 || download < 0 || packets < 0 {
            self.flush(tx)?;
            self.unsafe_key = true;
        }
        // Short runs stay on the normal path so isolated keys and pairs do
        // not pay two extra reads before the key changes.
        if self.consecutive < 3 || self.unsafe_key {
            self.consecutive = self.consecutive.saturating_add(1);
            return upsert_rollup(
                tx,
                self.table,
                Some(self.dimension),
                key,
                upload,
                download,
                packets,
            );
        }
        if self.base.is_none() {
            let old = Self::read_counters(tx, self.source_sql, key)?;
            let mut pending_key = key.to_vec();
            let Value::Integer(timestamp) = pending_key[0] else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            pending_key[0] = (timestamp / HOUR_MS * HOUR_MS).into();
            let pending = Self::read_counters(tx, self.pending_sql, &pending_key)?;
            self.base = old.zip(pending);
            if self.base.is_none() {
                self.unsafe_key = true;
            }
        }
        if let Some((old, pending)) = self.base {
            let values = [upload, download, packets, 1];
            let mut next = [0; 4];
            // Stored counters and incoming deltas are nonnegative here. The
            // original trigger's pending-old intermediate is therefore in
            // range; checking both endpoints keeps every subsequent integer
            // addition exact and avoids SQLite's overflow-to-REAL behavior.
            let safe = (0..4).all(|index| {
                let Some(sum) = self.delta[index].checked_add(values[index]) else {
                    return false;
                };
                next[index] = sum;
                old[index].checked_add(sum).is_some() && pending[index].checked_add(sum).is_some()
            });
            if safe {
                self.delta = next;
                if self.delta[3] == ROLLUP_MAX_DELTAS {
                    self.flush(tx)?;
                }
                return Ok(());
            }
            self.flush(tx)?;
            self.unsafe_key = true;
        }
        upsert_rollup(
            tx,
            self.table,
            Some(self.dimension),
            key,
            upload,
            download,
            packets,
        )
    }

    fn flush(&mut self, tx: &Transaction<'_>) -> rusqlite::Result<()> {
        if self.delta[3] != 0 {
            let key = self.key.as_deref().expect("buffered rollup has a key");
            adjust_rollup(
                tx,
                self.table,
                Some(self.dimension),
                key,
                self.delta[0],
                self.delta[1],
                self.delta[2],
                self.delta[3],
            )?;
        }
        self.base = None;
        self.delta = [0; 4];
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static LAST_TOTAL_ROLLUP_COUNTS: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

#[derive(Default)]
struct TotalRollupBatch {
    base: Option<([i64; 4], [i64; 4])>,
    delta: [i64; 4],
    disabled: bool,
    statements: u64,
    original: u64,
}

impl TotalRollupBatch {
    fn read_counters(
        tx: &Transaction<'_>,
        sql: &str,
        timestamp: i64,
        gateway: &str,
    ) -> rusqlite::Result<Option<[i64; 4]>> {
        let values: Option<[Value; 4]> = tx
            .query_row(sql, params![timestamp, gateway], |r| {
                Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?])
            })
            .optional()?;
        let Some(values) = values else {
            return Ok(Some([0; 4]));
        };
        let mut counters = [0; 4];
        for (i, value) in values.into_iter().enumerate() {
            match value {
                Value::Integer(n) if n >= 0 => counters[i] = n,
                _ => return Ok(None),
            }
        }
        Ok(Some(counters))
    }

    fn add(
        &mut self,
        tx: &Transaction<'_>,
        batch: &TelemetryBatch,
        flow: &FlowDelta,
    ) -> rusqlite::Result<()> {
        let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
        #[cfg(test)]
        if benchmark_sql_profile_enabled() {
            benchmark_sql_profile(
                "raw:traffic_total_minute",
                None,
                Some(&[timestamp.into(), batch.gateway_id.clone().into()]),
            );
        }
        let values = [
            to_i64(flow.upload_bytes),
            to_i64(flow.download_bytes),
            to_i64(flow.packets),
            1,
        ];
        self.original += 1;
        if !self.disabled && self.base.is_none() {
            let old = Self::read_counters(
                tx,
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_total_minute WHERE timestamp=?1 AND gateway_id=?2",
                timestamp,
                &batch.gateway_id,
            )?;
            let pending = Self::read_counters(
                tx,
                "SELECT upload_bytes,download_bytes,packets,flow_count FROM traffic_total_hour_pending WHERE timestamp=?1 AND gateway_id=?2",
                timestamp / HOUR_MS * HOUR_MS,
                &batch.gateway_id,
            )?;
            self.base = old.zip(pending);
            if self.base.is_none() {
                self.disabled = true;
            }
        }
        if let Some((old, pending)) = self.base {
            let mut next = [0; 4];
            // The standard minute trigger computes pending - old + new on
            // every update. Nonnegative integer old/pending and deltas make
            // -old and pending-old representable; checking both endpoints
            // below also keeps every intermediate pending+delta and new value
            // in i64. Thus SQLite never switches to REAL in either ordering.
            let safe = (0..4).all(|i| {
                let Some(sum) = self.delta[i].checked_add(values[i]) else {
                    return false;
                };
                next[i] = sum;
                old[i].checked_add(sum).is_some() && pending[i].checked_add(sum).is_some()
            });
            if safe {
                self.delta = next;
                if self.delta[3] == ROLLUP_MAX_DELTAS {
                    self.flush(tx, batch)?;
                }
                return Ok(());
            }
            self.flush(tx, batch)?;
            self.disabled = true;
        }
        self.statements += 1;
        upsert_rollup(
            tx,
            "traffic_total_minute",
            None,
            &[timestamp.into(), batch.gateway_id.clone().into()],
            values[0],
            values[1],
            values[2],
        )
    }

    fn flush(&mut self, tx: &Transaction<'_>, batch: &TelemetryBatch) -> rusqlite::Result<()> {
        if self.delta[3] != 0 {
            let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
            adjust_rollup(
                tx,
                "traffic_total_minute",
                None,
                &[timestamp.into(), batch.gateway_id.clone().into()],
                self.delta[0],
                self.delta[1],
                self.delta[2],
                self.delta[3],
            )?;
            self.statements += 1;
        }
        self.base = None;
        self.delta = [0; 4];
        Ok(())
    }
}

fn upsert_rollup(
    tx: &Transaction<'_>,
    table: &str,
    dimension: Option<&str>,
    keys: &[Value],
    upload: i64,
    download: i64,
    packets: i64,
) -> rusqlite::Result<()> {
    #[cfg(test)]
    if table != "traffic_total_minute" && benchmark_sql_profile_enabled() {
        benchmark_sql_profile(&format!("raw:{table}"), None, Some(keys));
    }
    adjust_rollup(tx, table, dimension, keys, upload, download, packets, 1)
}

#[allow(clippy::too_many_arguments)]
fn adjust_rollup(
    tx: &Transaction<'_>,
    table: &str,
    dimension: Option<&str>,
    keys: &[Value],
    upload: i64,
    download: i64,
    packets: i64,
    flow_count: i64,
) -> rusqlite::Result<()> {
    let columns = dimension.map_or_else(
        || "timestamp, gateway_id".to_owned(),
        |dimension| format!("timestamp, gateway_id, {dimension}"),
    );
    let placeholders = (1..=keys.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let metric_offset = keys.len() + 1;
    let sql = format!(
        "INSERT INTO {table}({columns}, upload_bytes, download_bytes, packets, flow_count)
         VALUES ({placeholders}, ?{metric_offset}, ?{}, ?{}, ?{})
         ON CONFLICT({columns}) DO UPDATE SET
           upload_bytes = upload_bytes + excluded.upload_bytes,
           download_bytes = download_bytes + excluded.download_bytes,
           packets = packets + excluded.packets,
           flow_count = flow_count + excluded.flow_count",
        metric_offset + 1,
        metric_offset + 2,
        metric_offset + 3,
    );
    let mut values = keys.to_vec();
    values.extend([
        upload.into(),
        download.into(),
        packets.into(),
        flow_count.into(),
    ]);
    #[cfg(test)]
    let started = benchmark_sql_profile_enabled().then(std::time::Instant::now);
    tx.prepare_cached(&sql)?
        .execute(rusqlite::params_from_iter(values))?;
    #[cfg(test)]
    if let Some(started) = started {
        benchmark_sql_profile(&format!("upsert:{table}"), Some(started.elapsed()), None);
    }
    Ok(())
}

fn update_active_flows(
    tx: &Transaction<'_>,
    active: &mut HashMap<FlowKey, ActiveFlow>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
    received_at: i64,
    batch_total: bool,
) -> rusqlite::Result<i64> {
    let unknown = FlowAttribution::default();
    let mut device_ids = HashMap::new();
    let mut totals = TotalRollupBatch {
        disabled: !batch_total,
        ..TotalRollupBatch::default()
    };
    let mut device_batch = RepeatedRollupBatch::new(true, batch_total);
    let mut destination_batch = RepeatedRollupBatch::new(false, batch_total);
    let mut active_count_delta = 0_i64;
    for (index, flow) in batch.flows.iter().enumerate() {
        let attribution = attributions.get(index).unwrap_or(&unknown);
        let key = FlowKey::from_batch(&batch.gateway_id, flow);
        let ended = flow.lifecycle == FlowLifecycle::Ended as i32;
        let mut was_active = true;
        {
            let current = match active.entry(key.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let mut restored =
                        ActiveFlow::new(&key, flow, FlowAttribution::default(), received_at);
                    was_active = attribution::restore(tx, &key, &mut restored)?;
                    entry.insert(restored)
                }
            };
            if current.add(flow, attribution, received_at) {
                totals.flush(tx, batch)?;
                attribution::reassign(
                    tx,
                    current.session_id(&key).as_ref(),
                    &current.attribution,
                    received_at,
                )?;
            }
            // Rollups and the contribution ledger must use the merged identity,
            // including for batches with weaker or missing classifier evidence.
            let device_id = match device_ids.entry(current.client_mac.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    *entry.insert(device_id_for_mac(tx, &key.gateway_id, &current.client_mac)?)
                }
            };
            current.device_id = device_id.or(current.device_id);
            totals.add(tx, batch, flow)?;
            persist_minute_rollups(
                tx,
                batch,
                flow,
                &current.attribution,
                current.device_id,
                &mut device_batch,
                &mut destination_batch,
            )?;
            #[cfg(test)]
            let ledger_started = benchmark_sql_profile_enabled().then(std::time::Instant::now);
            attribution::record(tx, &key, current, batch, flow, received_at)?;
            #[cfg(test)]
            if let Some(started) = ledger_started {
                benchmark_sql_profile("attribution_record", Some(started.elapsed()), None);
            }
            let checkpoint =
                received_at.saturating_sub(current.checkpointed_at) >= FLOW_CHECKPOINT_MS;
            let ended_at = ended.then(|| flow_lifecycle_end_at(flow, received_at));
            if (ended || checkpoint) && current.last_seen_at > 0 {
                #[cfg(test)]
                let session_started = benchmark_sql_profile_enabled().then(std::time::Instant::now);
                write_flow_session(tx, &key, current, ended_at, received_at)?;
                #[cfg(test)]
                if let Some(started) = session_started {
                    benchmark_sql_profile("flow_session", Some(started.elapsed()), None);
                }
            }
            if ended || checkpoint {
                current.checkpointed_at = received_at;
            }
        }
        if ended {
            active.remove(&key);
            if was_active {
                active_count_delta -= 1;
            }
        } else if !was_active {
            active_count_delta += 1;
        }
    }
    totals.flush(tx, batch)?;
    device_batch.flush(tx)?;
    destination_batch.flush(tx)?;
    #[cfg(test)]
    LAST_TOTAL_ROLLUP_COUNTS.set((totals.original, totals.statements));
    tracing::debug!(
        flows = batch.flows.len(),
        total_rollup_original = totals.original,
        total_rollup_upserts = totals.statements,
        "minute total rollup batching"
    );
    Ok(active_count_delta)
}

fn write_flow_session(
    tx: &Transaction<'_>,
    key: &FlowKey,
    flow: &ActiveFlow,
    ended_at: Option<i64>,
    checkpointed_at: i64,
) -> rusqlite::Result<()> {
    let device_id = match flow.device_id {
        Some(id) => Some(id),
        None => device_id_for_mac(tx, &key.gateway_id, &flow.client_mac)?,
    };
    tx.prepare_cached(
        "INSERT INTO flow_sessions(
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, upload_bytes, download_bytes, packets,
            started_at, last_seen_at, ended_at, checkpointed_at, domain, organization_id,
            application_id, category_id, traffic_role, protocol_id, organization_confidence,
            application_confidence, protocol_confidence, classification_confidence,
            classification_reason, classification_evidence_json, scope, path_type, nat,
            source_segment, destination_segment
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29,
                   ?30, ?31, ?32, ?33, ?34)
         ON CONFLICT(id) DO UPDATE SET
            device_id = COALESCE(excluded.device_id, flow_sessions.device_id),
            upload_bytes = excluded.upload_bytes, download_bytes = excluded.download_bytes,
            packets = excluded.packets, last_seen_at = excluded.last_seen_at,
            ended_at = CASE WHEN excluded.last_seen_at > flow_sessions.ended_at
                THEN excluded.ended_at ELSE COALESCE(excluded.ended_at, flow_sessions.ended_at) END,
            checkpointed_at = excluded.checkpointed_at,
            domain = excluded.domain, organization_id = excluded.organization_id,
            application_id = excluded.application_id, category_id = excluded.category_id,
            traffic_role = excluded.traffic_role, protocol_id = excluded.protocol_id,
            organization_confidence = excluded.organization_confidence,
            application_confidence = excluded.application_confidence,
            protocol_confidence = excluded.protocol_confidence,
            classification_confidence = excluded.classification_confidence,
            classification_reason = excluded.classification_reason,
            classification_evidence_json = excluded.classification_evidence_json,
            scope = excluded.scope, path_type = excluded.path_type, nat = excluded.nat,
            source_segment = excluded.source_segment,
            destination_segment = excluded.destination_segment",
    )?
    .execute(params![
        flow.session_id(key).as_ref(),
        key.gateway_id,
        device_id,
        key.ip_version,
        key.protocol,
        key.client_ip,
        key.client_port,
        key.remote_ip,
        key.remote_port,
        key.direction,
        flow.upload_bytes,
        flow.download_bytes,
        flow.packets,
        flow.started_at,
        flow.last_seen_at,
        ended_at,
        checkpointed_at,
        flow.attribution.domain,
        flow.attribution.organization_id,
        flow.attribution.application_id,
        flow.attribution.category_id,
        flow.attribution.traffic_role,
        flow.attribution.protocol_id,
        flow.attribution.organization_confidence,
        flow.attribution.application_confidence,
        flow.attribution.protocol_confidence,
        flow.attribution.confidence,
        flow.attribution.reason,
        flow.attribution.evidence_json,
        flow.scope,
        flow.path_type,
        flow.nat,
        flow.source_segment,
        flow.destination_segment,
    ])?;
    Ok(())
}

fn device_id_for_mac(
    tx: &Transaction<'_>,
    gateway_id: &str,
    mac: &[u8],
) -> rusqlite::Result<Option<i64>> {
    if mac.len() != 6 {
        return Ok(None);
    }
    tx.prepare_cached("SELECT id FROM devices WHERE gateway_id = ?1 AND mac = ?2")?
        .query_row(params![gateway_id, mac], |row| row.get(0))
        .optional()
}

fn dimension_columns(dimension: &str) -> &'static str {
    match dimension {
        "total" => "gateway_id",
        "device" => "gateway_id, device_id",
        "application" => "gateway_id, application_id, category_id",
        "domain" => "gateway_id, domain",
        "destination" => "gateway_id, remote_ip",
        _ => unreachable!(),
    }
}

fn aggregate_bounded(
    tx: &Transaction<'_>,
    dimension: &str,
    target: &str,
    cutoff: i64,
    limit: usize,
) -> rusqlite::Result<usize> {
    let keys = format!("timestamp, {}", dimension_columns(dimension));
    let qualified_keys = keys
        .split(',')
        .map(|column| format!("p.{}", column.trim()))
        .collect::<Vec<_>>()
        .join(",");
    let target_table = format!("traffic_{dimension}_{target}");
    let pending = format!("{target_table}_pending");
    tx.prepare_cached(&format!(
        "WITH selected AS (
             SELECT {keys} FROM {pending} WHERE timestamp<?1 ORDER BY {keys} LIMIT ?2
         )
         INSERT INTO {target_table}({keys},upload_bytes,download_bytes,packets,flow_count)
         SELECT {qualified_keys},p.upload_bytes,p.download_bytes,p.packets,p.flow_count
         FROM {pending} p JOIN selected s USING({keys}) WHERE 1
         ON CONFLICT({keys}) DO UPDATE SET
         upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,
         packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count"
    ))?
    .execute(params![cutoff, i64::try_from(limit).unwrap_or(i64::MAX)])?;
    tx.prepare_cached(&format!(
        "DELETE FROM {target_table} WHERE ({keys}) IN (
             SELECT {keys} FROM {pending} WHERE timestamp<?1 ORDER BY {keys} LIMIT ?2
         )
         AND upload_bytes=0 AND download_bytes=0 AND packets=0 AND flow_count=0"
    ))?
    .execute(params![cutoff, i64::try_from(limit).unwrap_or(i64::MAX)])?;
    tx.prepare_cached(&format!(
        "DELETE FROM {pending} WHERE ({keys}) IN (
             SELECT {keys} FROM {pending} WHERE timestamp<?1 ORDER BY {keys} LIMIT ?2
         )"
    ))?
    .execute(params![cutoff, i64::try_from(limit).unwrap_or(i64::MAX)])
}

fn rollup_pending(tx: &Transaction<'_>, tasks: &[(&str, &str, i64)]) -> rusqlite::Result<bool> {
    for (dimension, target, cutoff) in tasks {
        let table = format!("traffic_{dimension}_{target}_pending");
        let pending: bool = tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE timestamp<?1)"),
            [cutoff],
            |row| row.get(0),
        )?;
        if pending {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ip_version(ip: &[u8]) -> Option<i64> {
    match ip.len() {
        4 => Some(4),
        16 => Some(6),
        _ => None,
    }
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct FlowKey {
    gateway_id: String,
    ip_version: i64,
    protocol: i64,
    client_ip: Vec<u8>,
    client_port: i64,
    remote_ip: Vec<u8>,
    remote_port: i64,
    direction: i64,
}

impl FlowKey {
    fn sample_keys(gateway: &str, flow: &FlowDelta) -> [Self; 3] {
        // Samples have no direction; telemetry validates the three wire values.
        [
            Direction::Unspecified,
            Direction::Upload,
            Direction::Download,
        ]
        .map(|direction| Self {
            direction: i64::from(direction as i32),
            ..Self::from_batch(gateway, flow)
        })
    }

    fn from_batch(gateway_id: &str, flow: &FlowDelta) -> Self {
        Self {
            gateway_id: gateway_id.to_owned(),
            ip_version: i64::from(flow.ip_version),
            protocol: i64::from(flow.protocol),
            client_ip: flow.client_ip.clone(),
            client_port: i64::from(flow.client_port),
            remote_ip: flow.remote_ip.clone(),
            remote_port: i64::from(flow.remote_port),
            direction: i64::from(flow.direction),
        }
    }

    fn id(&self) -> String {
        format!(
            "{}:{}:{}:{:x?}:{}:{:x?}:{}:{}",
            self.gateway_id,
            self.ip_version,
            self.protocol,
            self.client_ip,
            self.client_port,
            self.remote_ip,
            self.remote_port,
            self.direction
        )
    }

    fn session_id(&self, started_at: i64) -> String {
        format!("{}:{started_at}", self.id())
    }
}

#[derive(Clone, Debug)]
struct ActiveFlow {
    // Most IDs are derivable from the flow key and start time; retain an
    // override only for historical rows that used a non-canonical ID.
    session_id_override: Option<Box<str>>,
    client_mac: Vec<u8>,
    device_id: Option<i64>,
    upload_bytes: i64,
    download_bytes: i64,
    packets: i64,
    started_at: i64,
    last_seen_at: i64,
    checkpointed_at: i64,
    last_received_at: i64,
    // Unknown classifications are common. Share the canonical default across
    // cache entries and detach only when attribution receives new evidence.
    attribution: Arc<FlowAttribution>,
    scope: i64,
    path_type: i64,
    nat: i64,
    source_segment: String,
    destination_segment: String,
}

impl ActiveFlow {
    fn attribution_mut(&mut self) -> &mut FlowAttribution {
        Arc::make_mut(&mut self.attribution)
    }

    fn merge_attribution(&mut self, incoming: &FlowAttribution) -> bool {
        if Arc::ptr_eq(&self.attribution, default_active_attribution()) && incoming.is_default() {
            false
        } else {
            attribution::merge(self.attribution_mut(), incoming)
        }
    }

    fn session_id<'a>(&'a self, key: &'a FlowKey) -> Cow<'a, str> {
        self.session_id_override.as_deref().map_or_else(
            || Cow::Owned(key.session_id(self.started_at)),
            Cow::Borrowed,
        )
    }

    fn new(
        _key: &FlowKey,
        flow: &FlowDelta,
        attribution: FlowAttribution,
        received_at: i64,
    ) -> Self {
        let observed_started_at = to_i64(flow.first_seen_unix_ms);
        let started_at = if observed_started_at == 0 {
            received_at
        } else {
            observed_started_at
        };
        let last_seen_at = if flow_has_traffic(flow) {
            to_i64(flow.last_seen_unix_ms).max(started_at)
        } else {
            0
        };
        Self {
            session_id_override: None,
            client_mac: flow.client_mac.clone(),
            device_id: None,
            upload_bytes: 0,
            download_bytes: 0,
            packets: 0,
            started_at,
            last_seen_at,
            checkpointed_at: started_at,
            last_received_at: received_at,
            attribution: shared_active_attribution(attribution),
            scope: i64::from(flow.scope),
            path_type: i64::from(flow.path_type),
            nat: i64::from(flow.nat),
            source_segment: flow.source_segment.clone(),
            destination_segment: flow.destination_segment.clone(),
        }
    }

    fn add(&mut self, flow: &FlowDelta, attribution: &FlowAttribution, received_at: i64) -> bool {
        self.last_received_at = self.last_received_at.max(received_at);
        if self.client_mac.is_empty() && !flow.client_mac.is_empty() {
            self.client_mac.clone_from(&flow.client_mac);
        }
        self.upload_bytes = self.upload_bytes.saturating_add(to_i64(flow.upload_bytes));
        self.download_bytes = self
            .download_bytes
            .saturating_add(to_i64(flow.download_bytes));
        self.packets = self.packets.saturating_add(to_i64(flow.packets));
        if flow_has_traffic(flow) {
            self.last_seen_at = self.last_seen_at.max(to_i64(flow.last_seen_unix_ms));
        }
        self.scope = i64::from(flow.scope);
        self.path_type = i64::from(flow.path_type);
        self.nat = i64::from(flow.nat);
        self.source_segment.clone_from(&flow.source_segment);
        self.destination_segment
            .clone_from(&flow.destination_segment);
        self.merge_attribution(attribution)
    }
}

pub(crate) fn flow_has_traffic(flow: &FlowDelta) -> bool {
    flow.upload_bytes > 0 || flow.download_bytes > 0 || flow.packets > 0
}

pub(crate) fn flow_lifecycle_end_at(flow: &FlowDelta, received_at: i64) -> i64 {
    let observed_at = to_i64(flow.last_seen_unix_ms);
    if observed_at > 0 {
        observed_at
    } else {
        received_at
    }
}

#[cfg(test)]
mod tests;

fn sample_matches(key: &FlowKey, current: &ActiveFlow, gateway: &str, flow: &FlowDelta) -> bool {
    key.gateway_id == gateway
        && key.ip_version == i64::from(flow.ip_version)
        && key.protocol == i64::from(flow.protocol)
        && key.client_ip == flow.client_ip
        && key.client_port == i64::from(flow.client_port)
        && key.remote_ip == flow.remote_ip
        && key.remote_port == i64::from(flow.remote_port)
        && current.started_at <= to_i64(flow.last_seen_unix_ms.saturating_add(1))
        && current.last_seen_at >= to_i64(flow.first_seen_unix_ms.saturating_sub(1))
}

// Late DPI must not erase the independently established DNS/application identity.
fn apply_late_protocol(current: &mut FlowAttribution, incoming: &FlowAttribution) {
    // Legacy ClickHouse protocol rewrite. SQLite uses the transactional,
    // dimension-aware path in attribution::reclassify_sqlite instead.
    current.protocol_id.clone_from(&incoming.protocol_id);
    current.protocol_confidence = incoming.protocol_confidence;
    if incoming.application_id != "unknown"
        && incoming.application_confidence >= current.application_confidence
    {
        current
            .organization_id
            .clone_from(&incoming.organization_id);
        current.organization_confidence = incoming.organization_confidence;
        current.application_id.clone_from(&incoming.application_id);
        current.application_confidence = incoming.application_confidence;
    }
    if incoming.category_id != "unknown" {
        current.category_id.clone_from(&incoming.category_id);
    }
    if incoming.traffic_role != "unknown" {
        current.traffic_role.clone_from(&incoming.traffic_role);
    }
    if incoming.domain.is_some() {
        current.domain.clone_from(&incoming.domain);
    }
    current.confidence = current.confidence.max(incoming.confidence);
    current.reason.clone_from(&incoming.reason);
    current.evidence_json.clone_from(&incoming.evidence_json);
}
