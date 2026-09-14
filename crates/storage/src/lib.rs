//! SQLite-backed persistence and aggregation for netqmon.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use netqmon_protocol::v1::{FlowDelta, FlowLifecycle, TelemetryBatch};
use rusqlite::types::{Type, Value};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/sqlite/0001_initial.sql");
const MIGRATIONS: [(i64, &str); 1] = [(1, INITIAL_MIGRATION)];
const MINUTE_MS: i64 = 60 * 1_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const FLOW_CHECKPOINT_MS: i64 = 5 * MINUTE_MS;
const DIMENSIONS: [&str; 5] = ["total", "device", "application", "domain", "destination"];

/// Default database location for the single-container deployment.
pub const DEFAULT_DATABASE_PATH: &str = "/data/netqmon.db";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRecord {
    pub id: String,
    pub agent_token_hash: [u8; 32],
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

    /// Loads the single enrolled Gateway.
    ///
    /// # Errors
    ///
    /// Returns an error when SQLite cannot execute or decode the query.
    pub fn gateway(&self) -> rusqlite::Result<Option<GatewayRecord>> {
        self.connection
            .query_row(
                "SELECT id, agent_token_hash FROM gateways ORDER BY created_at LIMIT 1",
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
                    Ok(GatewayRecord {
                        id: row.get(0)?,
                        agent_token_hash,
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
        persist_minute_rollups(&transaction, batch, attributions)?;
        let mut staged_active_flows = self.active_flows.clone();
        update_active_flows(
            &transaction,
            &mut staged_active_flows,
            batch,
            attributions,
            received_at,
        )?;
        transaction.commit()?;
        self.active_flows = staged_active_flows;
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

    /// Aggregates complete minute buckets into hour and day tables.
    ///
    /// # Errors
    ///
    /// Returns an error when the aggregation transaction cannot be committed.
    pub fn roll_up_hour_and_day(&mut self, now_ms: u64) -> rusqlite::Result<()> {
        let now = to_i64(now_ms);
        let transaction = self.connection.transaction()?;
        for dimension in DIMENSIONS {
            aggregate(&transaction, dimension, "minute", "hour", HOUR_MS, now)?;
            aggregate(&transaction, dimension, "hour", "day", DAY_MS, now)?;
        }
        transaction.commit()
    }

    /// Deletes data older than its retention window and expired DNS answers.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention transaction cannot be committed.
    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> rusqlite::Result<()> {
        let now = to_i64(now_ms);
        let transaction = self.connection.transaction()?;
        delete_older_than(
            &transaction,
            "flow_sessions",
            "last_seen_at",
            now,
            policy.flow_sessions_days,
        )?;
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
        for dimension in DIMENSIONS {
            delete_older_than(
                &transaction,
                &format!("traffic_{dimension}_minute"),
                "timestamp",
                now,
                policy.minute_days,
            )?;
            delete_older_than(
                &transaction,
                &format!("traffic_{dimension}_hour"),
                "timestamp",
                now,
                policy.hour_days,
            )?;
            delete_older_than(
                &transaction,
                &format!("traffic_{dimension}_day"),
                "timestamp",
                now,
                policy.day_days,
            )?;
        }
        transaction.commit()
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
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
            "SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NULL",
            [],
            |row| row.get(0),
        )
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
        match self {
            Self::ClickHouse(storage) => storage.reclassify_flow(gateway, flow, attribution),
            Self::Sqlite(storage) => {
                for (key, current) in &mut storage.active_flows {
                    if sample_matches(key, current, gateway, flow)
                        && attribution.protocol_confidence
                            >= current.attribution.protocol_confidence
                    {
                        apply_late_protocol(&mut current.attribution, attribution);
                    }
                }
                storage.connection.execute(
                    "UPDATE flow_sessions SET protocol_id=?1,protocol_confidence=?2,category_id=CASE WHEN ?3='unknown' THEN category_id ELSE ?3 END,traffic_role=CASE WHEN ?4='unknown' THEN traffic_role ELSE ?4 END,
                        classification_confidence=MAX(classification_confidence,?5),classification_reason=?6,classification_evidence_json=?7
                     WHERE gateway_id=?8 AND ip_version=?9 AND protocol=?10 AND client_ip=?11 AND client_port=?12
                        AND remote_ip=?13 AND remote_port=?14 AND started_at<=?15 AND last_seen_at>=?16
                        AND protocol_confidence<=?2",
                    params![attribution.protocol_id,attribution.protocol_confidence,attribution.category_id,attribution.traffic_role,
                        attribution.confidence,attribution.reason,attribution.evidence_json,gateway,flow.ip_version,flow.protocol,
                        flow.client_ip,flow.client_port,flow.remote_ip,flow.remote_port,to_i64(flow.last_seen_unix_ms.saturating_add(1)),to_i64(flow.first_seen_unix_ms.saturating_sub(1))],
                )?;
                Ok(())
            }
        }
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

    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        StorageBackend::run_retention(self, now_ms, policy)
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

fn load_active_flows(connection: &Connection) -> rusqlite::Result<HashMap<FlowKey, ActiveFlow>> {
    let mut statement = connection.prepare(
        "SELECT gateway_id, ip_version, protocol, client_ip, client_port, remote_ip,
                remote_port, direction, upload_bytes, download_bytes, packets,
                started_at, last_seen_at, checkpointed_at, domain, organization_id,
                application_id, category_id, traffic_role, protocol_id, organization_confidence,
                application_confidence, protocol_confidence, classification_confidence,
                classification_reason, classification_evidence_json, scope, path_type, nat,
                source_segment, destination_segment
         FROM flow_sessions WHERE ended_at IS NULL",
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

#[allow(clippy::too_many_lines)]
fn persist_minute_rollups(
    tx: &Transaction<'_>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
) -> rusqlite::Result<()> {
    let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
    let unknown = FlowAttribution::default();
    for (index, flow) in batch.flows.iter().enumerate() {
        let attribution = attributions.get(index).unwrap_or(&unknown);
        let upload = to_i64(flow.upload_bytes);
        let download = to_i64(flow.download_bytes);
        let packets = to_i64(flow.packets);
        upsert_rollup(
            tx,
            "traffic_total_minute",
            None,
            &[timestamp.into(), batch.gateway_id.clone().into()],
            upload,
            download,
            packets,
        )?;
        if let Some(device_id) = device_id_for_flow(tx, &batch.gateway_id, flow)? {
            upsert_rollup(
                tx,
                "traffic_device_minute",
                Some("device_id"),
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
                attribution.application_id.clone().into(),
                attribution.category_id.clone().into(),
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
        upsert_rollup(
            tx,
            "traffic_destination_minute",
            Some("remote_ip"),
            &[
                timestamp.into(),
                batch.gateway_id.clone().into(),
                flow.remote_ip.clone().into(),
            ],
            upload,
            download,
            packets,
        )?;
        let device_id = device_id_for_flow(tx, &batch.gateway_id, flow)?.unwrap_or(0);
        upsert_rollup(
            tx,
            "traffic_scope_minute",
            Some("scope, direction, device_id, application_id, category_id, domain, remote_ip"),
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
            ],
            upload,
            download,
            packets,
        )?;
    }
    Ok(())
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
         VALUES ({placeholders}, ?{metric_offset}, ?{}, ?{}, 1)
         ON CONFLICT({columns}) DO UPDATE SET
           upload_bytes = upload_bytes + excluded.upload_bytes,
           download_bytes = download_bytes + excluded.download_bytes,
           packets = packets + excluded.packets,
           flow_count = flow_count + 1",
        metric_offset + 1,
        metric_offset + 2,
    );
    let mut values = keys.to_vec();
    values.extend([upload.into(), download.into(), packets.into()]);
    tx.execute(&sql, rusqlite::params_from_iter(values))?;
    Ok(())
}

fn update_active_flows(
    tx: &Transaction<'_>,
    active: &mut HashMap<FlowKey, ActiveFlow>,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
    received_at: i64,
) -> rusqlite::Result<()> {
    let unknown = FlowAttribution::default();
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
                current.checkpointed_at = received_at;
            }
        }
        if ended {
            active.remove(&key);
        }
    }
    Ok(())
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

fn aggregate(
    tx: &Transaction<'_>,
    dimension: &str,
    source: &str,
    target: &str,
    bucket_ms: i64,
    now: i64,
) -> rusqlite::Result<()> {
    let columns = dimension_columns(dimension);
    let source_table = format!("traffic_{dimension}_{source}");
    let target_table = format!("traffic_{dimension}_{target}");
    let sql = format!(
        "INSERT OR REPLACE INTO {target_table}(
            timestamp, {columns}, upload_bytes, download_bytes, packets, flow_count
         ) SELECT (timestamp / ?1) * ?1, {columns}, SUM(upload_bytes),
                  SUM(download_bytes), SUM(packets), SUM(flow_count)
           FROM {source_table} WHERE timestamp < ?2
           GROUP BY (timestamp / ?1), {columns}"
    );
    tx.execute(&sql, params![bucket_ms, now / bucket_ms * bucket_ms])?;
    Ok(())
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

// Late DPI must not erase the independently established DNS/application identity.
fn apply_late_protocol(current: &mut FlowAttribution, incoming: &FlowAttribution) {
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
