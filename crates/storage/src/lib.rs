//! SQLite-backed persistence and aggregation for netqmon.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::analytics::{AnalyticsBatch, AnalyticsFlow, TrafficDelta};
use crate::metadata::{DeviceAddressRecord, DeviceRecord, GatewayDetails};
use netqmon_protocol::v1::{FlowDelta, FlowLifecycle, TelemetryBatch};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/sqlite/0001_initial.sql");
const MIGRATIONS: [(i64, &str); 1] = [(1, INITIAL_MIGRATION)];
const MINUTE_MS: i64 = 60 * 1_000;
const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
const FLOW_CHECKPOINT_MS: i64 = 5 * MINUTE_MS;

/// Default database location for the single-container deployment.
pub const DEFAULT_DATABASE_PATH: &str = "/data/netqmon.db";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRecord {
    pub id: String,
    pub agent_token_hash: [u8; 32],
    pub last_seen_ms: u64,
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

#[derive(Clone, Debug, PartialEq)]
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

pub mod analytics;
pub mod clickhouse;
pub mod metadata;
pub mod storage;
pub use clickhouse::{ClickHouseClient, ClickHouseConfig, from_hex, to_hex};
pub use metadata::{MetadataStore, SqliteMetadataStore};
pub use storage::{AnalyticsBackend, Storage};

/// Unified storage error covering SQLite and `ClickHouse` operations.
#[derive(Debug)]
pub enum StorageError {
    MetadataSqlite(rusqlite::Error),
    DuckDb(String),
    ClickHouse(String),
    Connection(String),
    Serialization(String),
    InvalidData(String),
    Other(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetadataSqlite(err) => write!(f, "sqlite metadata error: {err}"),
            Self::DuckDb(err) => write!(f, "duckdb error: {err}"),
            Self::ClickHouse(err) => write!(f, "clickhouse error: {err}"),
            Self::Connection(err) => write!(f, "storage connection error: {err}"),
            Self::Serialization(err) => write!(f, "storage serialization error: {err}"),
            Self::InvalidData(err) => write!(f, "invalid storage data: {err}"),
            Self::Other(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MetadataSqlite(err) => Some(err),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::MetadataSqlite(err)
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

/// The single SQLite writer owned by the Collector.
#[derive(Debug)]
pub struct SqliteStorage {
    connection: Connection,
    active_flows: HashMap<FlowKey, ActiveFlow>,
}

impl SqliteStorage {
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
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        migrate(&connection)?;
        let active_flows = load_active_flows(&connection)?;
        Ok(Self {
            connection,
            active_flows,
        })
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
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
        let mut staged_active_flows = self.active_flows.clone();
        let flow_versions = update_active_flows(
            &transaction,
            &mut staged_active_flows,
            batch,
            attributions,
            received_at,
        )?;
        let flow_versions = deduplicate_flow_versions(flow_versions);
        let analytics_batch = build_analytics_batch(
            &transaction,
            batch,
            attributions,
            flow_versions,
            received_at_ms,
        )?;
        let payload = analytics_batch.encode().map_err(|error| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error)))
        })?;
        transaction.execute(
            "INSERT INTO analytics_outbox(gateway_id, boot_id, sequence, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                batch.gateway_id,
                batch.boot_id,
                to_i64(batch.sequence),
                payload,
                received_at,
            ],
        )?;
        transaction.commit()?;
        self.active_flows = staged_active_flows;
        Ok(PersistDisposition::Accepted)
    }

    /// Stores a late classification update and appends a new analytics flow
    /// version without repeating the packet counters or traffic contribution.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot update the flow or append its outbox event.
    pub fn append_reclassification(
        &mut self,
        gateway_id: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
    ) -> rusqlite::Result<bool> {
        self.append_reclassification_with_latest(gateway_id, flow, attribution, now_ms, None)
    }

    /// Stores a late classification update using the latest analytics version
    /// when the ended flow has already left SQLite recovery state.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot append the reclassification outbox event.
    pub fn append_reclassification_with_latest(
        &mut self,
        gateway_id: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
        latest: Option<&AnalyticsFlow>,
    ) -> rusqlite::Result<bool> {
        // FlowSampleKey intentionally contains only the network tuple and
        // timestamps. It does not carry the collector's upload/download
        // direction, so resolve the persisted identity from that tuple first.
        let cached_key = self
            .active_flows
            .iter()
            .find(|(candidate, current)| sample_matches(candidate, current, gateway_id, flow))
            .map(|(candidate, _)| candidate.clone());
        let cached = cached_key
            .as_ref()
            .and_then(|candidate| self.active_flows.get(candidate))
            .cloned();
        let key = cached_key.unwrap_or_else(|| FlowKey::from_batch(gateway_id, flow));
        let mut staged_active = cached.clone();
        if let Some(current) = &mut staged_active {
            apply_late_classification(&mut current.attribution, attribution);
        }

        let now = to_i64(now_ms);
        let transaction = self.connection.transaction()?;
        let analytics_flow = if let Some(current) = &staged_active {
            write_flow_session(&transaction, &key, current, false, now)?;
            analytics_flow_from_current(&transaction, &key, current, false, now)?
        } else if let Some(latest) = latest {
            let mut updated = latest.clone();
            apply_late_classification_to_analytics_flow(&mut updated, attribution, now_ms);
            updated
        } else {
            let Some(analytics_flow) = update_persisted_reclassification(
                &transaction,
                gateway_id,
                &key,
                flow,
                attribution,
            )?
            else {
                transaction.rollback()?;
                return Ok(false);
            };
            analytics_flow
        };

        let sequence: i64 = transaction.query_row(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'analytics_outbox'), 0) + 1",
            [],
            |row| row.get(0),
        )?;
        let batch = AnalyticsBatch {
            gateway_id: gateway_id.to_owned(),
            boot_id: "late-dpi".to_owned(),
            sequence: u64::try_from(sequence).unwrap_or(1),
            received_at: now_ms,
            flows: vec![analytics_flow],
            traffic: Vec::new(),
        };
        let payload = batch.encode().map_err(|error| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error)))
        })?;
        transaction.execute(
            "INSERT INTO analytics_outbox(gateway_id, boot_id, sequence, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![gateway_id, batch.boot_id, sequence, payload, now],
        )?;
        transaction.commit()?;
        if let Some(current) = staged_active {
            self.active_flows.insert(key, current);
        }
        Ok(true)
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
        self.connection
            .query_row(
                "SELECT domain FROM dns_observations
                 WHERE gateway_id = ?1 AND client_ip = ?2 AND answer_ip = ?3
                   AND observed_at <= ?4 AND expires_at > ?4
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![gateway_id, client_ip, answer_ip, to_i64(at_ms)],
                |row| row.get(0),
            )
            .optional()
    }

    /// Deletes data older than its retention window and expired DNS answers.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention transaction cannot be committed.
    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> rusqlite::Result<()> {
        let now = to_i64(now_ms);
        let transaction = self.connection.transaction()?;
        if policy.dns_days == 0 {
            transaction.execute("DELETE FROM dns_observations WHERE expires_at < ?1", [now])?;
        } else {
            let cutoff = now.saturating_sub(i64::from(policy.dns_days) * DAY_MS);
            transaction.execute(
                "DELETE FROM dns_observations WHERE expires_at < ?1 OR observed_at < ?2",
                params![now, cutoff],
            )?;
        }
        delete_older_than(
            &transaction,
            "ingest_batches",
            "received_at",
            now,
            policy.minute_days,
        )?;
        if policy.flow_sessions_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.flow_sessions_days) * DAY_MS);
            transaction.execute(
                "DELETE FROM active_flow_sessions WHERE ended_at IS NOT NULL AND last_seen_at < ?1",
                [cutoff],
            )?;
        }
        transaction.commit()
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

    /// Returns the number of currently active (non-ended) flow sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute the query.
    pub fn active_flow_count(&self) -> rusqlite::Result<i64> {
        self.connection.query_row(
            "SELECT COUNT(*) FROM active_flow_sessions WHERE ended_at IS NULL",
            [],
            |row| row.get(0),
        )
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

    /// Loads committed analytics batches in insertion order.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot read the outbox.
    pub fn outbox_batch(&self, limit: u32) -> rusqlite::Result<Vec<crate::metadata::OutboxRecord>> {
        let mut statement = self
            .connection
            .prepare("SELECT id, payload FROM analytics_outbox ORDER BY id LIMIT ?1")?;
        statement
            .query_map([limit], |row| {
                Ok(crate::metadata::OutboxRecord {
                    id: row.get(0)?,
                    payload: row.get(1)?,
                })
            })?
            .collect()
    }

    /// Acknowledges one analytics batch after it has been applied.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot delete the outbox record.
    pub fn acknowledge_outbox(&mut self, id: i64) -> StorageResult<()> {
        self.acknowledge_outbox_with_completed_flows(id, &[])
    }

    /// Acknowledges a batch and removes confirmed ended flow checkpoints atomically.
    ///
    /// Newer checkpoints are retained so an older outbox row cannot erase newer
    /// recovery state.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot acknowledge the batch and clean up flows.
    pub fn acknowledge_outbox_with_completed_flows(
        &mut self,
        id: i64,
        completed_flows: &[crate::metadata::CompletedFlowCheckpoint],
    ) -> StorageResult<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM analytics_outbox WHERE id = ?1", [id])?;
        let mut removed_flow_ids = Vec::new();
        for flow in completed_flows {
            let latest: Option<AnalyticsFlow> = transaction
                .query_row(
                    "SELECT id, gateway_id, COALESCE(device_id, 0), ip_version, protocol,
                            client_ip, client_port, remote_ip, remote_port, direction,
                            COALESCE(domain, ''), COALESCE(organization_id, 'unknown'),
                            COALESCE(application_id, 'unknown'), COALESCE(category_id, 'unknown'),
                            COALESCE(traffic_role, 'unknown'), COALESCE(protocol_id, 'unknown'),
                            COALESCE(organization_confidence, 0), COALESCE(application_confidence, 0),
                            COALESCE(protocol_confidence, 0), COALESCE(classification_confidence, 0),
                            COALESCE(classification_reason, ''), classification_evidence_json,
                            upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                            checkpointed_at, scope, path_type, nat, source_segment, destination_segment
                     FROM active_flow_sessions WHERE gateway_id = ?1 AND id = ?2",
                    params![flow.flow.gateway_id, flow.flow.flow_id],
                    analytics_flow_from_row,
                )
                .optional()?;
            if latest.as_ref() == Some(&flow.flow) {
                let deleted = transaction.execute(
                    "DELETE FROM active_flow_sessions
                     WHERE id = ?1 AND gateway_id = ?2 AND ended_at IS NOT NULL",
                    params![flow.flow.flow_id, flow.flow.gateway_id],
                )?;
                if deleted > 0 {
                    removed_flow_ids
                        .push((flow.flow.gateway_id.clone(), flow.flow.flow_id.clone()));
                }
            }
        }
        transaction.commit()?;
        self.active_flows.retain(|key, _| {
            !removed_flow_ids
                .iter()
                .any(|(gateway_id, flow_id)| key.gateway_id == *gateway_id && key.id() == *flow_id)
        });
        Ok(())
    }

    /// Returns the number of pending analytics batches.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot count the outbox rows.
    pub fn outbox_depth(&self) -> rusqlite::Result<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM analytics_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| u64::try_from(count).unwrap_or(0))
    }

    /// Returns the age in milliseconds of the oldest pending analytics batch.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot read the oldest outbox timestamp.
    pub fn outbox_oldest_age_ms(&self, now_ms: u64) -> rusqlite::Result<u64> {
        let created_at: Option<i64> = self.connection.query_row(
            "SELECT MIN(created_at) FROM analytics_outbox",
            [],
            |row| row.get(0),
        )?;
        Ok(created_at.map_or(0, |created_at| {
            now_ms.saturating_sub(u64::try_from(created_at).unwrap_or(0))
        }))
    }
}

fn update_persisted_reclassification(
    transaction: &rusqlite::Transaction<'_>,
    gateway_id: &str,
    key: &FlowKey,
    flow: &FlowDelta,
    attribution: &FlowAttribution,
) -> rusqlite::Result<Option<AnalyticsFlow>> {
    let matched_id: Option<String> = transaction
        .query_row(
            "SELECT id FROM active_flow_sessions
             WHERE gateway_id = ?1 AND ip_version = ?2 AND protocol = ?3
               AND client_ip = ?4 AND client_port = ?5
               AND remote_ip = ?6 AND remote_port = ?7
               AND started_at <= ?8 AND last_seen_at >= ?9
             ORDER BY checkpointed_at DESC
             LIMIT 1",
            params![
                gateway_id,
                key.ip_version,
                key.protocol,
                key.client_ip,
                key.client_port,
                key.remote_ip,
                key.remote_port,
                to_i64(flow.last_seen_unix_ms.saturating_add(1)),
                to_i64(flow.first_seen_unix_ms.saturating_sub(1)),
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(matched_id) = matched_id else {
        return Ok(None);
    };
    let changed = transaction.execute(
        "UPDATE active_flow_sessions SET
            organization_id = CASE
                WHEN organization_id = 'unknown' AND ?2 NOT IN ('', 'unknown') THEN ?2
                ELSE organization_id END,
            organization_confidence = CASE
                WHEN organization_id = 'unknown' AND ?2 NOT IN ('', 'unknown') THEN ?3
                ELSE organization_confidence END,
            application_id = CASE
                WHEN application_id = 'unknown' AND ?4 NOT IN ('', 'unknown') THEN ?4
                ELSE application_id END,
            application_confidence = CASE
                WHEN application_id = 'unknown' AND ?4 NOT IN ('', 'unknown') THEN ?5
                ELSE application_confidence END,
            protocol_id = CASE WHEN ?6 <> 'unknown' AND ?6 <> '' THEN ?6 ELSE protocol_id END,
            protocol_confidence = CASE WHEN ?6 <> 'unknown' AND ?6 <> '' THEN ?7 ELSE protocol_confidence END,
            category_id = CASE WHEN ?8 <> 'unknown' AND ?8 <> '' THEN ?8 ELSE category_id END,
            traffic_role = CASE WHEN ?9 <> 'unknown' AND ?9 <> '' THEN ?9 ELSE traffic_role END,
            classification_confidence = MAX(COALESCE(classification_confidence, 0), ?10),
            classification_reason = ?11,
            classification_evidence_json = ?12
         WHERE id = ?1 AND gateway_id = ?13",
        params![
            matched_id,
            attribution.organization_id,
            attribution.organization_confidence,
            attribution.application_id,
            attribution.application_confidence,
            attribution.protocol_id,
            attribution.protocol_confidence,
            attribution.category_id,
            attribution.traffic_role,
            attribution.confidence,
            attribution.reason,
            attribution.evidence_json,
            gateway_id,
        ],
    )?;
    debug_assert_eq!(changed, 1);
    let mut statement = transaction.prepare(
        "SELECT id, gateway_id, COALESCE(device_id, 0), ip_version, protocol,
                client_ip, client_port, remote_ip, remote_port, direction,
                COALESCE(domain, ''), COALESCE(organization_id, 'unknown'),
                COALESCE(application_id, 'unknown'), COALESCE(category_id, 'unknown'),
                COALESCE(traffic_role, 'unknown'), COALESCE(protocol_id, 'unknown'),
                COALESCE(organization_confidence, 0), COALESCE(application_confidence, 0),
                COALESCE(protocol_confidence, 0), COALESCE(classification_confidence, 0),
                COALESCE(classification_reason, ''), classification_evidence_json,
                upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                checkpointed_at, scope, path_type, nat, source_segment, destination_segment
         FROM active_flow_sessions WHERE id = ?1 AND gateway_id = ?2",
    )?;
    let flow = statement.query_row(params![matched_id, gateway_id], analytics_flow_from_row)?;
    Ok(Some(flow))
}

impl crate::metadata::MetadataStore for SqliteStorage {
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        SqliteStorage::gateway(self).map_err(Into::into)
    }

    fn gateway_details(&self) -> StorageResult<Option<GatewayDetails>> {
        self.connection
            .query_row(
                "SELECT id, name, agent_version, arch, kernel_version, openwrt_version, last_seen
                 FROM gateways ORDER BY created_at LIMIT 1",
                [],
                |row| {
                    Ok(GatewayDetails {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        arch: row.get(3)?,
                        kernel_version: row.get(4)?,
                        openwrt_version: row.get(5)?,
                        last_seen: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        SqliteStorage::save_gateway(
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
        SqliteStorage::replace_stale_gateway(
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
        SqliteStorage::admin_exists(self).map_err(Into::into)
    }

    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        SqliteStorage::create_admin(self, id, username, password_hash, now_ms).map_err(Into::into)
    }

    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        SqliteStorage::user_by_username(self, username).map_err(Into::into)
    }

    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        SqliteStorage::create_session(self, user_id, token_hash, now_ms, expires_at)
            .map_err(Into::into)
    }

    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        SqliteStorage::session(self, token_hash, now_ms).map_err(Into::into)
    }

    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        SqliteStorage::delete_session(self, token_hash).map_err(Into::into)
    }

    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        SqliteStorage::persist_classified_batch(
            self,
            batch,
            attributions,
            device_identities,
            received_at_ms,
        )
        .map_err(Into::into)
    }

    fn append_reclassification(
        &mut self,
        gateway_id: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
    ) -> StorageResult<bool> {
        SqliteStorage::append_reclassification(self, gateway_id, flow, attribution, now_ms)
            .map_err(Into::into)
    }

    fn append_reclassification_with_latest(
        &mut self,
        gateway_id: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
        latest: Option<&AnalyticsFlow>,
    ) -> StorageResult<bool> {
        SqliteStorage::append_reclassification_with_latest(
            self,
            gateway_id,
            flow,
            attribution,
            now_ms,
            latest,
        )
        .map_err(Into::into)
    }

    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        SqliteStorage::device_evidence(self, gateway_id, mac).map_err(Into::into)
    }

    fn devices(&self, limit: u32, offset: u64) -> StorageResult<(Vec<DeviceRecord>, u64)> {
        let total = self
            .connection
            .query_row("SELECT COUNT(*) FROM devices", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let mut statement = self.connection.prepare(
            "SELECT id, gateway_id, mac, hostname, display_name, vendor, device_type, os_family,
                    model, identity_confidence, identity_evidence_json, vendor_confidence,
                    device_type_confidence, os_confidence, model_confidence, private_mac,
                    first_seen, last_seen
             FROM devices ORDER BY COALESCE(display_name, hostname, ''), id LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(params![limit, to_i64(offset)], read_device_record)?;
        let devices = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((devices, u64::try_from(total).unwrap_or(0)))
    }

    fn device(&self, id: i64) -> StorageResult<Option<DeviceRecord>> {
        self.connection
            .query_row(
                "SELECT id, gateway_id, mac, hostname, display_name, vendor, device_type, os_family,
                        model, identity_confidence, identity_evidence_json, vendor_confidence,
                        device_type_confidence, os_confidence, model_confidence, private_mac,
                        first_seen, last_seen
                 FROM devices WHERE id = ?1",
                [id],
                read_device_record,
            )
            .optional()
            .map_err(Into::into)
    }

    fn device_addresses(&self, id: i64) -> StorageResult<Vec<DeviceAddressRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT a.ip, a.ip_version, a.first_seen, a.last_seen, a.application_id,
                    a.application_confidence, a.application_source, a.application_last_seen,
                    (SELECT e.source FROM self_host_endpoint_evidence e
                     WHERE e.gateway_id = d.gateway_id AND e.ip = a.ip
                       AND e.expires_at > CAST(unixepoch('subsec') * 1000 AS INTEGER)
                     ORDER BY e.confidence DESC, e.last_seen DESC LIMIT 1),
                    (SELECT e.last_seen FROM self_host_endpoint_evidence e
                     WHERE e.gateway_id = d.gateway_id AND e.ip = a.ip
                       AND e.expires_at > CAST(unixepoch('subsec') * 1000 AS INTEGER)
                     ORDER BY e.confidence DESC, e.last_seen DESC LIMIT 1)
             FROM device_addresses a JOIN devices d ON d.id = a.device_id
             WHERE a.device_id = ?1 ORDER BY a.last_seen DESC, a.ip",
        )?;
        let rows = statement.query_map([id], |row| {
            Ok(DeviceAddressRecord {
                ip: row.get(0)?,
                ip_version: row.get(1)?,
                first_seen: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                last_seen: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                application_id: row.get(4)?,
                application_confidence: row.get(5)?,
                application_source: row.get(6)?,
                application_last_seen: row
                    .get::<_, Option<i64>>(7)?
                    .and_then(|value| u64::try_from(value).ok()),
                self_host_source: row.get(8)?,
                self_host_last_seen: row
                    .get::<_, Option<i64>>(9)?
                    .and_then(|value| u64::try_from(value).ok()),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn device_count(&self) -> StorageResult<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM devices", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|value| u64::try_from(value).unwrap_or(0))
            .map_err(Into::into)
    }

    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        SqliteStorage::resolve_domain(self, gateway_id, client_ip, answer_ip, at_ms)
            .map_err(Into::into)
    }

    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        SqliteStorage::load_retention_policy(self).map_err(Into::into)
    }

    fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        SqliteStorage::save_retention_policy(self, policy, now_ms).map_err(Into::into)
    }

    fn active_flow_count(&self) -> StorageResult<i64> {
        SqliteStorage::active_flow_count(self).map_err(Into::into)
    }

    fn run_metadata_retention(
        &mut self,
        now_ms: u64,
        policy: RetentionPolicy,
    ) -> StorageResult<()> {
        SqliteStorage::run_retention(self, now_ms, policy).map_err(Into::into)
    }

    fn outbox_batch(&self, limit: u32) -> StorageResult<Vec<crate::metadata::OutboxRecord>> {
        SqliteStorage::outbox_batch(self, limit).map_err(Into::into)
    }

    fn acknowledge_outbox(&mut self, id: i64) -> StorageResult<()> {
        SqliteStorage::acknowledge_outbox(self, id)
    }

    fn acknowledge_outbox_with_completed_flows(
        &mut self,
        id: i64,
        completed_flows: &[crate::metadata::CompletedFlowCheckpoint],
    ) -> StorageResult<()> {
        SqliteStorage::acknowledge_outbox_with_completed_flows(self, id, completed_flows)
    }

    fn outbox_depth(&self) -> StorageResult<u64> {
        SqliteStorage::outbox_depth(self).map_err(Into::into)
    }

    fn outbox_oldest_age_ms(&self, now_ms: u64) -> StorageResult<u64> {
        SqliteStorage::outbox_oldest_age_ms(self, now_ms).map_err(Into::into)
    }

    fn metadata_database_size_bytes(&self) -> StorageResult<u64> {
        SqliteStorage::database_size_bytes(self)
            .map(|size| u64::try_from(size).unwrap_or(0))
            .map_err(Into::into)
    }
}

fn read_device_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        id: row.get(0)?,
        gateway_id: row.get(1)?,
        mac: row.get(2)?,
        hostname: row.get(3)?,
        display_name: row.get(4)?,
        vendor: row.get(5)?,
        device_type: row.get(6)?,
        os_family: row.get(7)?,
        model: row.get(8)?,
        identity_confidence: row.get(9)?,
        identity_evidence_json: row.get(10)?,
        vendor_confidence: row.get(11)?,
        device_type_confidence: row.get(12)?,
        os_confidence: row.get(13)?,
        model_confidence: row.get(14)?,
        private_mac: row.get(15)?,
        first_seen: u64::try_from(row.get::<_, i64>(16)?).unwrap_or(0),
        last_seen: u64::try_from(row.get::<_, i64>(17)?).unwrap_or(0),
    })
}

fn migrate(connection: &Connection) -> rusqlite::Result<()> {
    let had_migrations = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let has_v2_metadata = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'active_flow_sessions')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if had_migrations && !has_v2_metadata {
        return Err(rusqlite::Error::InvalidQuery);
    }
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

fn load_active_flows(connection: &Connection) -> rusqlite::Result<HashMap<FlowKey, ActiveFlow>> {
    let mut statement = connection.prepare(
        "SELECT gateway_id, ip_version, protocol, client_ip, client_port, remote_ip,
                remote_port, direction, upload_bytes, download_bytes, packets,
                started_at, last_seen_at, checkpointed_at, domain, organization_id,
                application_id, category_id, traffic_role, protocol_id, organization_confidence,
                application_confidence, protocol_confidence, classification_confidence,
                classification_reason, classification_evidence_json, scope, path_type, nat,
                source_segment, destination_segment
         FROM active_flow_sessions WHERE ended_at IS NULL",
    )?;
    statement
        .query_map([], |row| {
            Ok((
                FlowKey {
                    gateway_id: row.get(0)?,
                    ip_version: row.get(1)?,
                    protocol: row.get(2)?,
                    client_ip: row.get(3)?,
                    client_port: row.get(4)?,
                    remote_ip: row.get(5)?,
                    remote_port: row.get(6)?,
                    direction: row.get(7)?,
                },
                ActiveFlow {
                    client_mac: Vec::new(),
                    upload_bytes: row.get(8)?,
                    download_bytes: row.get(9)?,
                    packets: row.get(10)?,
                    started_at: row.get(11)?,
                    last_seen_at: row.get(12)?,
                    checkpointed_at: row.get(13)?,
                    scope: row.get(26)?,
                    path_type: row.get(27)?,
                    nat: row.get(28)?,
                    source_segment: row.get(29)?,
                    destination_segment: row.get(30)?,
                    attribution: FlowAttribution {
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
                    },
                },
            ))
        })?
        .collect()
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
    for device in &batch.device_observations {
        let seen = to_i64(device.last_seen_unix_ms);
        let identity = identities
            .iter()
            .find(|identity| identity.mac == device.mac);
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
    let mut affected = Vec::<Vec<u8>>::new();
    for (index, flow) in batch.flows.iter().enumerate() {
        let Some(attribution) = attributions.get(index) else {
            continue;
        };
        if attribution_evidence_type(attribution, "self_host_shared_ip") {
            tx.execute(
                "DELETE FROM self_host_endpoint_evidence WHERE gateway_id=?1 AND ip=?2",
                params![batch.gateway_id, flow.remote_ip],
            )?;
            if !affected.contains(&flow.remote_ip) {
                affected.push(flow.remote_ip.clone());
            }
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
        if !affected.contains(&flow.remote_ip) {
            affected.push(flow.remote_ip.clone());
        }
    }
    refresh_self_host_addresses(tx, &batch.gateway_id, newest, affected)
}

fn refresh_self_host_addresses(
    tx: &Transaction<'_>,
    gateway_id: &str,
    newest: i64,
    affected: Vec<Vec<u8>>,
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
    for observation in &batch.dns_observations {
        let observed_at = to_i64(observation.observed_at_unix_ms);
        let ttl_ms = i64::from(observation.ttl_seconds).saturating_mul(1_000);
        tx.execute(
            "INSERT INTO dns_observations(
                gateway_id, client_ip, domain, answer_ip, record_type, ttl,
                observed_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                batch.gateway_id,
                observation.client_ip,
                observation.domain,
                observation.answer_ip,
                observation.record_type,
                observation.ttl_seconds,
                observed_at,
                observed_at.saturating_add(ttl_ms),
            ],
        )?;
    }
    Ok(())
}

fn update_active_flows(
    tx: &Transaction<'_>,
    active: &mut HashMap<FlowKey, ActiveFlow>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
    received_at: i64,
) -> rusqlite::Result<Vec<AnalyticsFlow>> {
    let unknown = FlowAttribution::default();
    let mut versions = Vec::new();
    for (index, flow) in batch.flows.iter().enumerate() {
        let attribution = attributions.get(index).unwrap_or(&unknown);
        let key = FlowKey::from_batch(&batch.gateway_id, flow);
        let ended = flow.lifecycle == FlowLifecycle::Ended as i32;
        {
            let current = active
                .entry(key.clone())
                .or_insert_with(|| ActiveFlow::new(flow, attribution.clone(), received_at));
            current.add(flow, attribution);
            let checkpoint =
                received_at.saturating_sub(current.checkpointed_at) >= FLOW_CHECKPOINT_MS;
            if ended || checkpoint {
                write_flow_session(tx, &key, current, ended, received_at)?;
                versions.push(analytics_flow_from_current(
                    tx,
                    &key,
                    current,
                    ended,
                    received_at,
                )?);
                current.checkpointed_at = received_at;
            }
        }
        if ended {
            active.remove(&key);
        }
    }
    Ok(versions)
}

fn analytics_flow_from_current(
    tx: &Transaction<'_>,
    key: &FlowKey,
    flow: &ActiveFlow,
    ended: bool,
    checkpointed_at: i64,
) -> rusqlite::Result<AnalyticsFlow> {
    let device_id = device_id_for_mac(tx, &key.gateway_id, &flow.client_mac)?
        .and_then(|id| u64::try_from(id).ok())
        .unwrap_or(0);
    Ok(AnalyticsFlow {
        flow_id: key.id(),
        gateway_id: key.gateway_id.clone(),
        device_id,
        ip_version: u8::try_from(key.ip_version).unwrap_or(0),
        protocol: u8::try_from(key.protocol).unwrap_or(0),
        client_ip: key.client_ip.clone(),
        client_port: u16::try_from(key.client_port).unwrap_or(0),
        remote_ip: key.remote_ip.clone(),
        remote_port: u16::try_from(key.remote_port).unwrap_or(0),
        direction: u8::try_from(key.direction).unwrap_or(0),
        domain: flow.attribution.domain.clone().unwrap_or_default(),
        organization_id: normalized_id(&flow.attribution.organization_id),
        application_id: normalized_id(&flow.attribution.application_id),
        category_id: normalized_id(&flow.attribution.category_id),
        traffic_role: normalized_id(&flow.attribution.traffic_role),
        protocol_id: normalized_id(&flow.attribution.protocol_id),
        organization_confidence: flow.attribution.organization_confidence,
        application_confidence: flow.attribution.application_confidence,
        protocol_confidence: flow.attribution.protocol_confidence,
        classification_confidence: flow.attribution.confidence,
        classification_reason: flow.attribution.reason.clone(),
        classification_evidence_json: flow.attribution.evidence_json.clone(),
        upload_bytes: u64::try_from(flow.upload_bytes).unwrap_or(0),
        download_bytes: u64::try_from(flow.download_bytes).unwrap_or(0),
        packets: u64::try_from(flow.packets).unwrap_or(0),
        started_at: u64::try_from(flow.started_at).unwrap_or(0),
        last_seen_at: u64::try_from(flow.last_seen_at).unwrap_or(0),
        ended_at: ended.then(|| u64::try_from(flow.last_seen_at).unwrap_or(0)),
        checkpointed_at: u64::try_from(checkpointed_at).unwrap_or(0),
        scope: u8::try_from(flow.scope).unwrap_or(0),
        path_type: u8::try_from(flow.path_type).unwrap_or(0),
        nat: u8::try_from(flow.nat).unwrap_or(0),
        source_segment: flow.source_segment.clone(),
        destination_segment: flow.destination_segment.clone(),
    })
}

fn analytics_flow_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnalyticsFlow> {
    let ended_at: Option<i64> = row.get(27)?;
    Ok(AnalyticsFlow {
        flow_id: row.get(0)?,
        gateway_id: row.get(1)?,
        device_id: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
        ip_version: u8::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
        protocol: u8::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        client_ip: row.get(5)?,
        client_port: u16::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        remote_ip: row.get(7)?,
        remote_port: u16::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
        direction: u8::try_from(row.get::<_, i64>(9)?).unwrap_or(0),
        domain: row.get(10)?,
        organization_id: row.get(11)?,
        application_id: row.get(12)?,
        category_id: row.get(13)?,
        traffic_role: row.get(14)?,
        protocol_id: row.get(15)?,
        organization_confidence: row.get(16)?,
        application_confidence: row.get(17)?,
        protocol_confidence: row.get(18)?,
        classification_confidence: row.get(19)?,
        classification_reason: row.get(20)?,
        classification_evidence_json: row.get(21)?,
        upload_bytes: u64::try_from(row.get::<_, i64>(22)?).unwrap_or(0),
        download_bytes: u64::try_from(row.get::<_, i64>(23)?).unwrap_or(0),
        packets: u64::try_from(row.get::<_, i64>(24)?).unwrap_or(0),
        started_at: u64::try_from(row.get::<_, i64>(25)?).unwrap_or(0),
        last_seen_at: u64::try_from(row.get::<_, i64>(26)?).unwrap_or(0),
        ended_at: ended_at.map(|value| u64::try_from(value).unwrap_or(0)),
        checkpointed_at: u64::try_from(row.get::<_, i64>(28)?).unwrap_or(0),
        scope: u8::try_from(row.get::<_, i64>(29)?).unwrap_or(0),
        path_type: u8::try_from(row.get::<_, i64>(30)?).unwrap_or(0),
        nat: u8::try_from(row.get::<_, i64>(31)?).unwrap_or(0),
        source_segment: row.get(32)?,
        destination_segment: row.get(33)?,
    })
}

fn build_analytics_batch(
    tx: &Transaction<'_>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
    flows: Vec<AnalyticsFlow>,
    received_at: u64,
) -> rusqlite::Result<AnalyticsBatch> {
    let unknown = FlowAttribution::default();
    let mut traffic = Vec::with_capacity(batch.flows.len());
    for (index, flow) in batch.flows.iter().enumerate() {
        let attribution = attributions.get(index).unwrap_or(&unknown);
        let device_id = device_id_for_flow(tx, &batch.gateway_id, flow)?
            .and_then(|id| u64::try_from(id).ok())
            .unwrap_or(0);
        let timestamp = if flow.last_seen_unix_ms == 0 {
            received_at
        } else {
            flow.last_seen_unix_ms
        };
        traffic.push(TrafficDelta {
            timestamp,
            gateway_id: batch.gateway_id.clone(),
            scope: u8::try_from(flow.scope).unwrap_or(0),
            direction: u8::try_from(flow.direction).unwrap_or(0),
            transport_protocol: u8::try_from(flow.protocol).unwrap_or(0),
            path_type: u8::try_from(flow.path_type).unwrap_or(0),
            nat: u8::try_from(flow.nat).unwrap_or(0),
            device_id,
            organization_id: normalized_id(&attribution.organization_id),
            application_id: normalized_id(&attribution.application_id),
            category_id: normalized_id(&attribution.category_id),
            protocol_id: normalized_id(&attribution.protocol_id),
            domain: attribution.domain.clone().unwrap_or_default(),
            remote_ip: flow.remote_ip.clone(),
            upload_bytes: flow.upload_bytes,
            download_bytes: flow.download_bytes,
            packets: flow.packets,
            flow_count: 1,
        });
    }
    Ok(AnalyticsBatch {
        gateway_id: batch.gateway_id.clone(),
        boot_id: batch.boot_id.clone(),
        sequence: batch.sequence,
        received_at,
        flows,
        traffic,
    })
}

/// Each analytics batch can contain multiple lifecycle snapshots of one flow.
/// Analytics stores version rows once per gateway/boot/batch, so keep the
/// final snapshot for each flow while preserving the original row order.
fn deduplicate_flow_versions(flows: Vec<AnalyticsFlow>) -> Vec<AnalyticsFlow> {
    let mut last_index = HashMap::with_capacity(flows.len());
    for (index, flow) in flows.iter().enumerate() {
        last_index.insert(flow.flow_id.clone(), index);
    }
    flows
        .into_iter()
        .enumerate()
        .filter_map(|(index, flow)| (last_index.get(&flow.flow_id) == Some(&index)).then_some(flow))
        .collect()
}

fn normalized_id(value: &str) -> String {
    if value.is_empty() {
        "unknown".to_owned()
    } else {
        value.to_owned()
    }
}

fn write_flow_session(
    tx: &Transaction<'_>,
    key: &FlowKey,
    flow: &ActiveFlow,
    ended: bool,
    checkpointed_at: i64,
) -> rusqlite::Result<()> {
    let device_id = device_id_for_mac(tx, &key.gateway_id, &flow.client_mac)?;
    tx.execute(
        "INSERT INTO active_flow_sessions(
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
            device_id = COALESCE(excluded.device_id, active_flow_sessions.device_id),
            upload_bytes = excluded.upload_bytes, download_bytes = excluded.download_bytes,
            packets = excluded.packets, last_seen_at = excluded.last_seen_at,
            ended_at = excluded.ended_at, checkpointed_at = excluded.checkpointed_at,
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
        params![
            key.id(),
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
            ended.then_some(flow.last_seen_at),
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
        ],
    )?;
    Ok(())
}

fn device_id_for_flow(
    tx: &Transaction<'_>,
    gateway_id: &str,
    flow: &FlowDelta,
) -> rusqlite::Result<Option<i64>> {
    device_id_for_mac(tx, gateway_id, &flow.client_mac)
}

fn device_id_for_mac(
    tx: &Transaction<'_>,
    gateway_id: &str,
    mac: &[u8],
) -> rusqlite::Result<Option<i64>> {
    if mac.len() != 6 {
        return Ok(None);
    }
    tx.query_row(
        "SELECT id FROM devices WHERE gateway_id = ?1 AND mac = ?2",
        params![gateway_id, mac],
        |row| row.get(0),
    )
    .optional()
}

fn delete_older_than(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    now: i64,
    days: u32,
) -> rusqlite::Result<()> {
    if days == 0 {
        return Ok(());
    }
    let cutoff = now.saturating_sub(i64::from(days) * DAY_MS);
    tx.execute(
        &format!("DELETE FROM {table} WHERE {column} < ?1"),
        [cutoff],
    )?;
    Ok(())
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
}

#[derive(Clone, Debug)]
struct ActiveFlow {
    client_mac: Vec<u8>,
    upload_bytes: i64,
    download_bytes: i64,
    packets: i64,
    started_at: i64,
    last_seen_at: i64,
    checkpointed_at: i64,
    attribution: FlowAttribution,
    scope: i64,
    path_type: i64,
    nat: i64,
    source_segment: String,
    destination_segment: String,
}

impl ActiveFlow {
    fn new(flow: &FlowDelta, attribution: FlowAttribution, received_at: i64) -> Self {
        let observed_started_at = to_i64(flow.first_seen_unix_ms);
        let started_at = if observed_started_at == 0 {
            received_at
        } else {
            observed_started_at
        };
        Self {
            client_mac: flow.client_mac.clone(),
            upload_bytes: 0,
            download_bytes: 0,
            packets: 0,
            started_at,
            last_seen_at: started_at,
            checkpointed_at: started_at,
            attribution,
            scope: i64::from(flow.scope),
            path_type: i64::from(flow.path_type),
            nat: i64::from(flow.nat),
            source_segment: flow.source_segment.clone(),
            destination_segment: flow.destination_segment.clone(),
        }
    }

    fn add(&mut self, flow: &FlowDelta, attribution: &FlowAttribution) {
        if self.client_mac.is_empty() && !flow.client_mac.is_empty() {
            self.client_mac.clone_from(&flow.client_mac);
        }
        self.upload_bytes = self.upload_bytes.saturating_add(to_i64(flow.upload_bytes));
        self.download_bytes = self
            .download_bytes
            .saturating_add(to_i64(flow.download_bytes));
        self.packets = self.packets.saturating_add(to_i64(flow.packets));
        self.last_seen_at = self.last_seen_at.max(to_i64(flow.last_seen_unix_ms));
        self.scope = i64::from(flow.scope);
        self.path_type = i64::from(flow.path_type);
        self.nat = i64::from(flow.nat);
        self.source_segment.clone_from(&flow.source_segment);
        self.destination_segment
            .clone_from(&flow.destination_segment);
        let confidence_order = attribution
            .confidence
            .total_cmp(&self.attribution.confidence);
        if confidence_order == Ordering::Greater
            || (confidence_order == Ordering::Equal
                && self.attribution.domain.is_none()
                && attribution.domain.is_some())
        {
            self.attribution.clone_from(attribution);
        }
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

// Late DPI can fill missing identity fields, but must not replace an
// independently established DNS/application identity.
fn apply_late_classification(current: &mut FlowAttribution, incoming: &FlowAttribution) {
    if current.organization_id == "unknown"
        && !incoming.organization_id.is_empty()
        && incoming.organization_id != "unknown"
    {
        current
            .organization_id
            .clone_from(&incoming.organization_id);
        current.organization_confidence = incoming.organization_confidence;
    }
    if current.application_id == "unknown"
        && !incoming.application_id.is_empty()
        && incoming.application_id != "unknown"
    {
        current.application_id.clone_from(&incoming.application_id);
        current.application_confidence = incoming.application_confidence;
    }
    current.protocol_id.clone_from(&incoming.protocol_id);
    current.protocol_confidence = incoming.protocol_confidence;
    if incoming.category_id != "unknown" {
        current.category_id.clone_from(&incoming.category_id);
    }
    if incoming.traffic_role != "unknown" {
        current.traffic_role.clone_from(&incoming.traffic_role);
    }
    current.confidence = current.confidence.max(incoming.confidence);
    current.reason.clone_from(&incoming.reason);
    current.evidence_json.clone_from(&incoming.evidence_json);
}

fn apply_late_classification_to_analytics_flow(
    flow: &mut AnalyticsFlow,
    attribution: &FlowAttribution,
    now_ms: u64,
) {
    if flow.organization_id == "unknown"
        && !attribution.organization_id.is_empty()
        && attribution.organization_id != "unknown"
    {
        flow.organization_id
            .clone_from(&attribution.organization_id);
        flow.organization_confidence = attribution.organization_confidence;
    }
    if flow.application_id == "unknown"
        && !attribution.application_id.is_empty()
        && attribution.application_id != "unknown"
    {
        flow.application_id.clone_from(&attribution.application_id);
        flow.application_confidence = attribution.application_confidence;
    }
    flow.protocol_id.clone_from(&attribution.protocol_id);
    flow.protocol_confidence = attribution.protocol_confidence;
    if attribution.category_id != "unknown" {
        flow.category_id.clone_from(&attribution.category_id);
    }
    if attribution.traffic_role != "unknown" {
        flow.traffic_role.clone_from(&attribution.traffic_role);
    }
    flow.classification_confidence = flow.classification_confidence.max(attribution.confidence);
    flow.classification_reason.clone_from(&attribution.reason);
    flow.classification_evidence_json
        .clone_from(&attribution.evidence_json);
    flow.checkpointed_at = now_ms.max(flow.checkpointed_at.saturating_add(1));
}
