//! ClickHouse storage backend implementation for netqmon.

#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::format_push_string,
    clippy::unreadable_literal
)]

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netqmon_protocol::v1::{FlowLifecycle, TelemetryBatch};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ActiveFlow, DeviceEvidenceRecord, DeviceIdentityUpdate, FlowAttribution, FlowKey,
    GatewayRecord, PersistDisposition, RetentionPolicy, SessionRecord, StorageBackend,
    StorageError, StorageResult, TrafficTotal, UserRecord, flow_lifecycle_end_at,
};

fn flow_scope_name(value: i32) -> &'static str {
    match netqmon_protocol::v1::FlowScope::try_from(value) {
        Ok(netqmon_protocol::v1::FlowScope::Internet) => "internet",
        Ok(netqmon_protocol::v1::FlowScope::Internal) => "internal",
        Ok(netqmon_protocol::v1::FlowScope::Tunnel) => "tunnel",
        _ => "unknown",
    }
}

fn flow_path_name(value: i32) -> &'static str {
    match netqmon_protocol::v1::PathType::try_from(value) {
        Ok(netqmon_protocol::v1::PathType::Forwarded) => "forwarded",
        Ok(netqmon_protocol::v1::PathType::Internal) => "internal",
        Ok(netqmon_protocol::v1::PathType::Tunnel) => "tunnel",
        _ => "unknown",
    }
}

fn flow_nat_name(value: i32) -> &'static str {
    match netqmon_protocol::v1::NatType::try_from(value) {
        Ok(netqmon_protocol::v1::NatType::None) => "none",
        Ok(netqmon_protocol::v1::NatType::Snat) => "snat",
        Ok(netqmon_protocol::v1::NatType::Dnat) => "dnat",
        Ok(netqmon_protocol::v1::NatType::Both) => "both",
        _ => "unknown",
    }
}

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/clickhouse/0001_initial.sql");
const PROTOCOL_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0002_traffic_scope_protocol.sql");
const BATCH_DEDUPLICATION_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0003_batch_deduplication.sql");
const INCREMENTAL_ROLLUPS_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0004_incremental_rollups.sql");
const QUERY_AND_ACTIVITY_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0005_query_and_activity_indexes.sql");
const PROTOCOL_ONLY_APPLICATION_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0006_protocol_only_app_rollup.sql");
const PROTOCOL_APPLICATION_ROLLUP_MIGRATION: &str =
    include_str!("../../../migrations/clickhouse/0007_protocol_application_rollup.sql");
const MIGRATIONS: [(u32, &str); 7] = [
    (1, INITIAL_MIGRATION),
    (2, PROTOCOL_MIGRATION),
    (3, BATCH_DEDUPLICATION_MIGRATION),
    (4, INCREMENTAL_ROLLUPS_MIGRATION),
    (5, QUERY_AND_ACTIVITY_MIGRATION),
    (6, PROTOCOL_ONLY_APPLICATION_MIGRATION),
    (7, PROTOCOL_APPLICATION_ROLLUP_MIGRATION),
];
const MINUTE_MS: i64 = 60 * 1_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const FLOW_CHECKPOINT_MS: i64 = 5 * MINUTE_MS;
const MAX_DNS_CACHE_KEYS: usize = 16_384;
const PROTOCOL_APPLICATION_PREFIX: &str = "protocol:";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsLookupKey {
    gateway_id: String,
    client_ip: String,
    answer_ip: String,
}

#[derive(Clone, Debug)]
struct CachedDnsObservation {
    id: i64,
    domain: String,
    observed_at: i64,
    expires_at: i64,
}

/// ClickHouse client configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub timeout_ms: u64,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8123".to_owned(),
            database: "default".to_owned(),
            user: None,
            password: None,
            timeout_ms: 5_000,
        }
    }
}

/// Lightweight ClickHouse HTTP/1.1 client over standard TCP stream.
#[derive(Clone, Debug)]
pub struct ClickHouseClient {
    config: ClickHouseConfig,
}

impl ClickHouseClient {
    #[must_use]
    pub fn new(config: ClickHouseConfig) -> Self {
        Self { config }
    }

    /// Checks connectivity to the ClickHouse server.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on network or HTTP error.
    pub fn ping(&self) -> StorageResult<()> {
        let _ = self.execute("SELECT 1")?;
        Ok(())
    }

    /// Executes arbitrary SQL without expecting a structured result.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on execution failure.
    pub fn execute(&self, sql: &str) -> StorageResult<String> {
        let path = format!("/?database={}", url_encode(&self.config.database));
        self.post(&path, sql.as_bytes(), "text/plain; charset=utf-8")
    }

    /// Executes a SQL query and parses the response as JSON.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query failure or JSON parse error.
    pub fn query_json(&self, sql: &str) -> StorageResult<Value> {
        let formatted = if sql.to_uppercase().contains("FORMAT ") {
            sql.to_owned()
        } else {
            format!("{sql} FORMAT JSON")
        };
        let response = self.execute(&formatted)?;
        if response.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&response).map_err(|err| {
            StorageError::Serialization(format!("failed to parse ClickHouse JSON response: {err}"))
        })
    }

    /// Inserts a slice of JSON objects into the specified table using `FORMAT JSONEachRow`.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on insert failure.
    pub fn insert_json_each_row(&self, table: &str, rows: &[Value]) -> StorageResult<()> {
        self.insert_json_each_row_with_token(table, rows, None)
    }

    fn insert_json_each_row_with_token(
        &self,
        table: &str,
        rows: &[Value],
        token: Option<&str>,
    ) -> StorageResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut body = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut body, row).map_err(|err| {
                StorageError::Serialization(format!("failed to serialize row to JSON: {err}"))
            })?;
            body.push(b'\n');
        }
        let query = token.map_or_else(
            || format!("INSERT INTO {table} FORMAT JSONEachRow"),
            |token| {
                format!(
                    "INSERT INTO {table} SETTINGS insert_deduplicate = 1, insert_deduplication_token = '{token}' FORMAT JSONEachRow"
                )
            },
        );
        let path = format!(
            "/?database={}&query={}",
            url_encode(&self.config.database),
            url_encode(&query)
        );
        let _ = self.post(&path, &body, "application/x-ndjson")?;
        Ok(())
    }

    fn post(&self, path_and_query: &str, body: &[u8], content_type: &str) -> StorageResult<String> {
        let (host, port) = parse_host_port(&self.config.url)?;
        let addr = format!("{host}:{port}");
        let socket_addrs = addr
            .to_socket_addrs()
            .map_err(|err| StorageError::Connection(format!("cannot resolve {addr}: {err}")))?
            .next()
            .ok_or_else(|| StorageError::Connection(format!("no address resolved for {addr}")))?;

        let timeout = Duration::from_millis(self.config.timeout_ms.max(1_000));
        let mut stream = TcpStream::connect_timeout(&socket_addrs, timeout).map_err(|err| {
            StorageError::Connection(format!("failed to connect to {addr}: {err}"))
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| StorageError::Connection(format!("set read timeout failed: {err}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| StorageError::Connection(format!("set write timeout failed: {err}")))?;

        let mut request = format!(
            "POST {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: netqmon-storage\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(user) = &self.config.user {
            request.push_str(&format!("X-ClickHouse-User: {user}\r\n"));
        }
        if let Some(password) = &self.config.password {
            request.push_str(&format!("X-ClickHouse-Key: {password}\r\n"));
        }
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .map_err(|err| StorageError::Connection(format!("write request failed: {err}")))?;
        stream
            .write_all(body)
            .map_err(|err| StorageError::Connection(format!("write body failed: {err}")))?;
        stream
            .flush()
            .map_err(|err| StorageError::Connection(format!("flush failed: {err}")))?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|err| StorageError::Connection(format!("read status line failed: {err}")))?;

        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(StorageError::Connection(format!(
                "invalid HTTP status line: {status_line}"
            )));
        }
        let status_code: u16 = parts[1].parse().map_err(|_| {
            StorageError::Connection(format!("invalid HTTP status code: {}", parts[1]))
        })?;

        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|err| StorageError::Connection(format!("read header failed: {err}")))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            let lower = trimmed.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                if let Ok(len) = rest.trim().parse::<usize>() {
                    content_length = Some(len);
                }
            } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                is_chunked = true;
            }
        }

        let mut body_bytes = Vec::new();
        if is_chunked {
            loop {
                let mut size_str = String::new();
                reader.read_line(&mut size_str).map_err(|err| {
                    StorageError::Connection(format!("read chunk size failed: {err}"))
                })?;
                let size_str = size_str.trim();
                let chunk_size = usize::from_str_radix(size_str, 16).map_err(|_| {
                    StorageError::Connection(format!("invalid chunk size: {size_str}"))
                })?;
                if chunk_size == 0 {
                    let mut trailer = String::new();
                    let _ = reader.read_line(&mut trailer);
                    break;
                }
                let mut chunk = vec![0u8; chunk_size];
                reader
                    .read_exact(&mut chunk)
                    .map_err(|err| StorageError::Connection(format!("read chunk failed: {err}")))?;
                body_bytes.extend_from_slice(&chunk);
                let mut crlf = [0u8; 2];
                let _ = reader.read_exact(&mut crlf);
            }
        } else if let Some(len) = content_length {
            body_bytes.resize(len, 0);
            reader.read_exact(&mut body_bytes).map_err(|err| {
                StorageError::Connection(format!("read body exact failed: {err}"))
            })?;
        } else {
            let _ = reader.read_to_end(&mut body_bytes);
        }

        let body_str = String::from_utf8_lossy(&body_bytes).to_string();
        if status_code != 200 {
            return Err(StorageError::ClickHouse(format!(
                "HTTP {status_code}: {}",
                body_str.trim()
            )));
        }
        Ok(body_str)
    }
}

/// ClickHouse-backed implementation of the netqmon storage contract.
#[derive(Clone, Debug)]
pub struct ClickHouseStorage {
    client: ClickHouseClient,
    active_flows: HashMap<FlowKey, ActiveFlow>,
    dns_cache: Arc<Mutex<HashMap<DnsLookupKey, Vec<CachedDnsObservation>>>>,
}

impl ClickHouseStorage {
    pub(crate) fn reclassify_flow(
        &mut self,
        gateway: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
    ) -> StorageResult<()> {
        let mut matched_active_flow = false;
        let mut attribution_changed = false;
        for (key, current) in &mut self.active_flows {
            if !crate::sample_matches(key, current, gateway, flow) {
                continue;
            }
            matched_active_flow = true;
            if attribution.protocol_confidence >= current.attribution.protocol_confidence {
                let previous = current.attribution.clone();
                crate::apply_late_protocol(&mut current.attribution, attribution);
                attribution_changed |= current.attribution != previous;
            }
        }
        // Late DPI can emit the same attribution more than once for an active
        // sample. ClickHouse persists this as an INSERT ... SELECT rewrite, so
        // avoid reading and rewriting the row when the in-memory latest value
        // already matches the incoming result.
        if matched_active_flow && !attribution_changed {
            return Ok(());
        }
        // DPI samples identify the bidirectional 5-tuple but do not carry the
        // telemetry direction. Match every direction and the sample's time
        // range; session IDs also include the lifetime start time now.
        let sql=format!("INSERT INTO flow_sessions SELECT * REPLACE ('{protocol_id}' AS protocol_id,{protocol_confidence} AS protocol_confidence,
            if('{category}'='unknown',category_id,'{category}') AS category_id,if('{role}'='unknown',traffic_role,'{role}') AS traffic_role,greatest(classification_confidence,{confidence}) AS classification_confidence,
            '{reason}' AS classification_reason,'{evidence}' AS classification_evidence_json,
            greatest(checkpointed_at+1,toUnixTimestamp64Milli(now64(3))) AS checkpointed_at)
            FROM flow_sessions FINAL WHERE gateway_id='{gateway}' AND ip_version={ip_version} AND protocol={protocol}
            AND client_ip='{client_ip}' AND client_port={client_port} AND remote_ip='{remote_ip}' AND remote_port={remote_port}
            AND started_at<={last} AND last_seen_at>={first} AND protocol_confidence<={protocol_confidence}",
            protocol_id=escape_sql(&attribution.protocol_id),protocol_confidence=attribution.protocol_confidence,
            category=escape_sql(&attribution.category_id),role=escape_sql(&attribution.traffic_role),confidence=attribution.confidence,
            reason=escape_sql(&attribution.reason),evidence=escape_sql(&attribution.evidence_json),gateway=escape_sql(gateway),
            ip_version=flow.ip_version,protocol=flow.protocol,client_ip=to_hex(&flow.client_ip),client_port=flow.client_port,
            remote_ip=to_hex(&flow.remote_ip),remote_port=flow.remote_port,last=flow.last_seen_unix_ms.saturating_add(1),first=flow.first_seen_unix_ms.saturating_sub(1));
        self.client.execute(&sql)?;
        Ok(())
    }

    /// Connects to ClickHouse, verifies the connection, and executes pending migrations.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on connection or migration failure.
    pub fn open(config: ClickHouseConfig) -> StorageResult<Self> {
        let client = ClickHouseClient::new(config);
        let mut storage = Self {
            client,
            active_flows: HashMap::new(),
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
        };
        storage.migrate()?;
        storage.active_flows = storage.load_active_flows()?;
        Ok(storage)
    }

    fn load_active_flows(&self) -> StorageResult<HashMap<FlowKey, ActiveFlow>> {
        let sql = "SELECT gateway_id, ip_version, protocol, client_ip, client_port,
                          remote_ip, remote_port, direction, upload_bytes, download_bytes,
                          packets, started_at, last_seen_at, checkpointed_at, domain,
                          organization_id, application_id, category_id, traffic_role,
                          protocol_id, organization_confidence, application_confidence,
                          protocol_confidence, classification_confidence, classification_reason,
                          classification_evidence_json, scope, path_type, nat,
                          source_segment, destination_segment, device_id, id
                   FROM flow_sessions FINAL WHERE ended_at IS NULL FORMAT JSON";
        let result = self.client.query_json(sql)?;
        let mut active = HashMap::new();
        if let Some(rows) = result["data"].as_array() {
            for row in rows {
                let key = FlowKey {
                    gateway_id: row["gateway_id"].as_str().unwrap_or_default().to_owned(),
                    ip_version: json_i64(&row["ip_version"]),
                    protocol: json_i64(&row["protocol"]),
                    client_ip: from_hex(row["client_ip"].as_str().unwrap_or_default())?,
                    client_port: json_i64(&row["client_port"]),
                    remote_ip: from_hex(row["remote_ip"].as_str().unwrap_or_default())?,
                    remote_port: json_i64(&row["remote_port"]),
                    direction: json_i64(&row["direction"]),
                };
                let optional_string = |field: &str| {
                    row.get(field)
                        .filter(|value| !value.is_null())
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                };
                active.insert(
                    key,
                    ActiveFlow {
                        session_id: row["id"].as_str().unwrap_or_default().to_owned(),
                        client_mac: Vec::new(),
                        device_id: row
                            .get("device_id")
                            .filter(|value| !value.is_null())
                            .map(json_i64),
                        upload_bytes: json_i64(&row["upload_bytes"]),
                        download_bytes: json_i64(&row["download_bytes"]),
                        packets: json_i64(&row["packets"]),
                        started_at: json_i64(&row["started_at"]),
                        last_seen_at: json_i64(&row["last_seen_at"]),
                        checkpointed_at: json_i64(&row["checkpointed_at"]),
                        attribution: FlowAttribution {
                            domain: optional_string("domain"),
                            organization_id: optional_string("organization_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            application_id: optional_string("application_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            category_id: optional_string("category_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            traffic_role: optional_string("traffic_role")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            protocol_id: optional_string("protocol_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            organization_confidence: json_f64(&row["organization_confidence"]),
                            application_confidence: json_f64(&row["application_confidence"]),
                            protocol_confidence: json_f64(&row["protocol_confidence"]),
                            confidence: json_f64(&row["classification_confidence"]),
                            reason: optional_string("classification_reason")
                                .unwrap_or_else(|| "no matching rule".to_owned()),
                            evidence_json: row["classification_evidence_json"]
                                .as_str()
                                .unwrap_or("[]")
                                .to_owned(),
                        },
                        scope: json_i64(&row["scope"]),
                        path_type: json_i64(&row["path_type"]),
                        nat: json_i64(&row["nat"]),
                        source_segment: row["source_segment"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        destination_segment: row["destination_segment"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    },
                );
            }
        }
        Ok(active)
    }

    #[must_use]
    pub fn client(&self) -> &ClickHouseClient {
        &self.client
    }

    /// Applies schema migrations to ClickHouse.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on migration execution failure.
    pub fn migrate(&self) -> StorageResult<()> {
        let create_migrations = "CREATE TABLE IF NOT EXISTS schema_migrations (version UInt32, applied_at Int64) ENGINE = MergeTree() ORDER BY version";
        self.client.execute(create_migrations)?;

        let rows = self
            .client
            .query_json("SELECT version FROM schema_migrations ORDER BY version")?;
        let applied_versions: Vec<u32> = rows["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|row| row["version"].as_u64().map(|v| v as u32))
                    .collect()
            })
            .unwrap_or_default();

        for (version, script) in MIGRATIONS {
            if applied_versions.contains(&version) {
                continue;
            }
            self.apply_sql_script(script)?;
            let now = to_i64(unix_now_ms());
            let record = json!({ "version": version, "applied_at": now });
            self.client
                .insert_json_each_row("schema_migrations", &[record])?;
        }
        Ok(())
    }

    fn apply_sql_script(&self, script: &str) -> StorageResult<()> {
        let statements = split_sql_statements(script);
        for statement in statements {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                self.client.execute(trimmed)?;
            }
        }
        Ok(())
    }

    /// Resolves client-scoped DNS answer valid at timestamp.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query execution or decoding error.
    pub fn resolve_domain_ch(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        let key = DnsLookupKey {
            gateway_id: gateway_id.to_owned(),
            client_ip: to_hex(client_ip),
            answer_ip: to_hex(answer_ip),
        };
        let at = to_i64(at_ms);
        {
            let cache = self
                .dns_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(observations) = cache.get(&key) {
                return Ok(resolve_cached_dns(observations, at));
            }
        }

        let sql = format!(
            "SELECT id, domain, observed_at, expires_at FROM dns_observations
             WHERE gateway_id = '{}' AND client_ip = '{}' AND answer_ip = '{}'
             FORMAT JSON",
            escape_sql(&key.gateway_id),
            key.client_ip,
            key.answer_ip,
        );
        let result = self.client.query_json(&sql)?;
        let observations = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| {
                Some(CachedDnsObservation {
                    id: json_i64(&row["id"]),
                    domain: row["domain"].as_str()?.to_owned(),
                    observed_at: json_i64(&row["observed_at"]),
                    expires_at: json_i64(&row["expires_at"]),
                })
            })
            .collect::<Vec<_>>();
        let mut cache = self
            .dns_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= MAX_DNS_CACHE_KEYS
            && !cache.contains_key(&key)
            && let Some(evicted) = cache.keys().next().cloned()
        {
            cache.remove(&evicted);
        }
        let cached = cache.entry(key).or_insert(observations);
        Ok(resolve_cached_dns(cached, at))
    }

    fn invalidate_dns_cache(&self, batch: &TelemetryBatch) {
        if batch.dns_observations.is_empty() {
            return;
        }
        let mut cache = self
            .dns_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for observation in &batch.dns_observations {
            cache.remove(&DnsLookupKey {
                gateway_id: batch.gateway_id.clone(),
                client_ip: to_hex(&observation.client_ip),
                answer_ip: to_hex(&observation.answer_ip),
            });
        }
    }

    pub fn device_evidence_ch(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        let mac_hex = to_hex(mac);
        let sql = format!(
            "SELECT gateway_id, mac, source, field, value, confidence,
                    first_seen, last_seen, hit_count, metadata_json
             FROM device_evidence FINAL
             WHERE gateway_id = '{gateway}' AND mac = '{mac_hex}'
             ORDER BY field, source, value FORMAT JSON",
            gateway = escape_sql(gateway_id),
        );
        let result = self.client.query_json(&sql)?;
        let mut evidence = Vec::new();
        if let Some(rows) = result["data"].as_array() {
            for row in rows {
                evidence.push(DeviceEvidenceRecord {
                    gateway_id: row["gateway_id"].as_str().unwrap_or("").to_owned(),
                    mac: from_hex(row["mac"].as_str().unwrap_or(""))?,
                    source: row["source"].as_str().unwrap_or("").to_owned(),
                    field: row["field"].as_str().unwrap_or("").to_owned(),
                    value: row["value"].as_str().unwrap_or("").to_owned(),
                    confidence: row["confidence"]
                        .as_f64()
                        .or_else(|| {
                            row["confidence"]
                                .as_str()
                                .and_then(|value| value.parse().ok())
                        })
                        .unwrap_or(0.0),
                    first_seen: json_u64(&row["first_seen"]),
                    last_seen: json_u64(&row["last_seen"]),
                    hit_count: json_u64(&row["hit_count"]),
                    metadata_json: row["metadata_json"].as_str().unwrap_or("{}").to_owned(),
                });
            }
        }
        Ok(evidence)
    }

    fn device_identity_evidence_json(
        &self,
        gateway_id: &str,
        mac_hex: &str,
    ) -> StorageResult<Value> {
        let mac = from_hex(mac_hex)?;
        let evidence = self
            .device_evidence_ch(gateway_id, &mac)?
            .into_iter()
            .map(|item| {
                json!({
                    "source": item.source,
                    "field": item.field,
                    "value": item.value,
                    "confidence": item.confidence,
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "hit_count": item.hit_count,
                    "metadata_json": item.metadata_json,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!(evidence))
    }

    fn device_identity_evidence_by_keys(
        &self,
        device_keys: &HashSet<(String, String)>,
    ) -> StorageResult<HashMap<(String, String), Vec<Value>>> {
        if device_keys.is_empty() {
            return Ok(HashMap::new());
        }
        let key_list = device_keys
            .iter()
            .map(|(gateway, mac)| format!("('{}', '{}')", escape_sql(gateway), escape_sql(mac)))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT gateway_id, mac, source, field, value, confidence, first_seen,
                    last_seen, hit_count, metadata_json
             FROM device_evidence FINAL
             WHERE (gateway_id, mac) IN ({key_list})
             ORDER BY gateway_id, mac, field, source, value FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let mut evidence_by_device = HashMap::<(String, String), Vec<Value>>::new();
        if let Some(rows) = result["data"].as_array() {
            for evidence in rows {
                let key = (
                    evidence["gateway_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    evidence["mac"].as_str().unwrap_or_default().to_owned(),
                );
                evidence_by_device.entry(key).or_default().push(json!({
                    "source": evidence["source"].as_str().unwrap_or_default(),
                    "field": evidence["field"].as_str().unwrap_or_default(),
                    "value": evidence["value"].as_str().unwrap_or_default(),
                    "confidence": json_f64(&evidence["confidence"]),
                    "first_seen": json_u64(&evidence["first_seen"]),
                    "last_seen": json_u64(&evidence["last_seen"]),
                    "hit_count": json_u64(&evidence["hit_count"]),
                    "metadata_json": evidence["metadata_json"].as_str().unwrap_or("{}"),
                }));
            }
        }
        Ok(evidence_by_device)
    }

    /// Queries total traffic over a half-open time range.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_total_traffic_ch(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> StorageResult<Vec<TrafficTotal>> {
        let from = to_i64(from_ms);
        let to = to_i64(to_ms);
        let sql = format!(
            "SELECT timestamp, sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes, sum(packets) AS packets, sum(flow_count) AS flow_count FROM traffic_total_minute WHERE timestamp >= {from} AND timestamp < {to} GROUP BY timestamp ORDER BY timestamp ASC FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let mut totals = Vec::new();
        if let Some(rows) = result["data"].as_array() {
            for row in rows {
                totals.push(TrafficTotal {
                    timestamp: row["timestamp"]
                        .as_i64()
                        .or_else(|| row["timestamp"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0),
                    upload_bytes: row["upload_bytes"]
                        .as_i64()
                        .or_else(|| row["upload_bytes"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0),
                    download_bytes: row["download_bytes"]
                        .as_i64()
                        .or_else(|| row["download_bytes"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0),
                    packets: row["packets"]
                        .as_i64()
                        .or_else(|| row["packets"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0),
                    flow_count: row["flow_count"]
                        .as_i64()
                        .or_else(|| row["flow_count"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0),
                });
            }
        }
        Ok(totals)
    }

    /// Queries overview metrics.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_overview(
        &self,
        now: u64,
        offline_after_ms: u64,
        gw_warning: Option<String>,
    ) -> StorageResult<Value> {
        let now_i64 = to_i64(now);
        let day_ago = now_i64.saturating_sub(DAY_MS);
        let dev_count_sql = "SELECT count() AS c FROM devices FINAL FORMAT JSON";
        let dev_res = self.client.query_json(dev_count_sql)?;
        let devices = dev_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_i64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let app_count_sql = "SELECT count() AS c FROM (
                 SELECT DISTINCT application_id FROM traffic_application_minute
             ) FORMAT JSON";
        let app_res = self.client.query_json(&app_count_sql)?;
        let applications = app_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_i64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let hist_sql = format!(
            "SELECT coalesce(sum(upload_bytes), 0) AS up, coalesce(sum(download_bytes), 0) AS down FROM traffic_total_minute WHERE timestamp >= {day_ago} FORMAT JSON"
        );
        let hist_res = self.client.query_json(&hist_sql)?;
        let hist_first = hist_res["data"].as_array().and_then(|a| a.first());
        let up = hist_first
            .and_then(|r| {
                r["up"]
                    .as_i64()
                    .or_else(|| r["up"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);
        let down = hist_first
            .and_then(|r| {
                r["down"]
                    .as_i64()
                    .or_else(|| r["down"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let gw_sql = "SELECT id, name, agent_version, kernel_version, openwrt_version, last_seen FROM gateways FINAL ORDER BY created_at LIMIT 1 FORMAT JSON";
        let gw_res = self.client.query_json(gw_sql)?;
        let gw_row = gw_res["data"].as_array().and_then(|a| a.first());

        let (gateway_status, gateway_json) = if let Some(gw) = gw_row {
            let last_seen = gw["last_seen"]
                .as_i64()
                .or_else(|| gw["last_seen"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0);
            let status = if now.saturating_sub(last_seen as u64) <= offline_after_ms {
                "online"
            } else {
                "offline"
            };
            (
                status,
                Some(json!({
                    "id": gw["id"].as_str().unwrap_or(""),
                    "name": gw["name"].as_str().unwrap_or(""),
                    "agent_version": gw["agent_version"].as_str().unwrap_or(""),
                    "kernel_version": gw["kernel_version"].as_str().unwrap_or(""),
                    "openwrt_version": gw["openwrt_version"].as_str().unwrap_or(""),
                    "status": status,
                    "last_seen": last_seen,
                })),
            )
        } else {
            ("unenrolled", None)
        };

        let capture_warning = if gateway_status == "offline" {
            Some("No gateway telemetry has arrived within the offline threshold".to_owned())
        } else {
            gw_warning
        };

        Ok(json!({
            "devices": devices,
            "active_devices": 0,
            "active_flows": self.active_flows.len(),
            "applications": applications,
            "traffic_rate_upload_bps": 0,
            "traffic_rate_download_bps": 0,
            "traffic_total_upload_bytes_24h": up,
            "traffic_total_download_bytes_24h": down,
            "gateway": gateway_json,
            "gateway_status": gateway_status,
            "capture_warning": capture_warning,
        }))
    }

    /// Queries aggregated traffic series.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_traffic(
        &self,
        from_ms: u64,
        to_ms: u64,
        resolution: &str,
    ) -> StorageResult<Vec<Value>> {
        let table = match resolution {
            "hour" => "traffic_total_hour",
            "day" => "traffic_total_day",
            _ => "traffic_total_minute",
        };
        let from = to_i64(from_ms);
        let to = to_i64(to_ms);
        let sql = format!(
            "SELECT timestamp, sum(upload_bytes) AS up, sum(download_bytes) AS down, sum(packets) AS pkts, sum(flow_count) AS flows FROM {table} WHERE timestamp >= {from} AND timestamp < {to} GROUP BY timestamp ORDER BY timestamp ASC FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                items.push(json!({
                    "timestamp": r["timestamp"].as_i64().or_else(|| r["timestamp"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "upload_bytes": r["up"].as_i64().or_else(|| r["up"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["down"].as_i64().or_else(|| r["down"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "packets": r["pkts"].as_i64().or_else(|| r["pkts"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "flow_count": r["flows"].as_i64().or_else(|| r["flows"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                }));
            }
        }
        Ok(items)
    }

    /// Queries the dashboard traffic series and grouped breakdown in one response.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when either ClickHouse query fails.
    pub fn query_traffic_breakdown(
        &self,
        from_ms: u64,
        to_ms: u64,
        group_by: &str,
        limit: u32,
        offset: u64,
        scope: Option<i64>,
        direction: Option<i64>,
        bucket_ms: u64,
    ) -> StorageResult<Value> {
        let from = to_i64(from_ms);
        let to = to_i64(to_ms);
        let bucket = to_i64(bucket_ms.max(1));
        let scope_clause = scope.map_or_else(String::new, |value| format!(" AND scope = {value}"));
        let direction_clause =
            direction.map_or_else(String::new, |value| format!(" AND direction = {value}"));
        let points_sql = format!(
            "SELECT intDiv(timestamp, {bucket}) * {bucket} AS timestamp,
                    sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                    sum(packets) AS packets, sum(flow_count) AS flow_count
             FROM traffic_scope_minute
             WHERE timestamp >= {from} AND timestamp < {to}{scope_clause}{direction_clause}
             GROUP BY timestamp ORDER BY timestamp FORMAT JSON"
        );
        let points_result = self.client.query_json(&points_sql)?;
        let points = points_result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                json!({
                    "timestamp": json_i64(&row["timestamp"]),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                })
            })
            .collect::<Vec<_>>();

        let (select, from_sql, group_sql, order_sql, paginated) = match group_by {
            "client" => (
                "toString(t.device_id) AS id, any(coalesce(d.display_name, d.hostname, '')) AS name,
                 any(d.mac) AS mac, sum(t.upload_bytes) AS upload_bytes,
                 sum(t.download_bytes) AS download_bytes, sum(t.packets) AS packets,
                 sum(t.flow_count) AS flow_count, max(t.timestamp) AS last_seen",
                "traffic_scope_minute AS t LEFT JOIN devices AS d FINAL ON d.id = t.device_id",
                "t.device_id",
                "upload_bytes + download_bytes DESC, id ASC",
                true,
            ),
            "application" => (
                "t.application_id AS id, t.application_id AS name, '' AS mac,
                 sum(t.upload_bytes) AS upload_bytes, sum(t.download_bytes) AS download_bytes,
                 sum(t.packets) AS packets, sum(t.flow_count) AS flow_count,
                 max(t.timestamp) AS last_seen",
                "traffic_scope_minute AS t",
                "t.application_id",
                "upload_bytes + download_bytes DESC, id ASC",
                true,
            ),
            "category" => (
                "t.category_id AS id, t.category_id AS name, '' AS mac,
                 sum(t.upload_bytes) AS upload_bytes, sum(t.download_bytes) AS download_bytes,
                 sum(t.packets) AS packets, sum(t.flow_count) AS flow_count,
                 max(t.timestamp) AS last_seen",
                "traffic_scope_minute AS t",
                "t.category_id",
                "upload_bytes + download_bytes DESC, id ASC",
                true,
            ),
            "protocol_l4" => (
                "multiIf(t.protocol = 6, 'tcp', t.protocol = 17, 'udp',
                        t.protocol = 1, 'icmp', t.protocol = 58, 'icmpv6',
                        toString(t.protocol)) AS id,
                 multiIf(t.protocol = 6, 'TCP', t.protocol = 17, 'UDP', t.protocol = 1, 'ICMP',
                         t.protocol = 58, 'ICMPv6', concat('IP ', toString(t.protocol))) AS name,
                 '' AS mac, sum(t.upload_bytes) AS upload_bytes,
                 sum(t.download_bytes) AS download_bytes, sum(t.packets) AS packets,
                 sum(t.flow_count) AS flow_count, max(t.timestamp) AS last_seen",
                "traffic_scope_minute AS t",
                "t.protocol",
                "upload_bytes + download_bytes DESC, id ASC",
                true,
            ),
            "protocol_l7" | "protocol" => (
                "t.protocol_id AS id, t.protocol_id AS name, '' AS mac,
                 sum(t.upload_bytes) AS upload_bytes, sum(t.download_bytes) AS download_bytes,
                 sum(t.packets) AS packets, sum(t.flow_count) AS flow_count,
                 max(t.timestamp) AS last_seen",
                "traffic_scope_minute AS t",
                "t.protocol_id",
                "upload_bytes + download_bytes DESC, id ASC",
                true,
            ),
            _ => (
                "'total' AS id, 'All traffic' AS name, '' AS mac,
                 sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                 sum(packets) AS packets, sum(flow_count) AS flow_count,
                 max(timestamp) AS last_seen",
                "traffic_scope_minute",
                "",
                "id ASC",
                false,
            ),
        };
        let group_clause = if group_sql.is_empty() {
            String::new()
        } else {
            format!(" GROUP BY {group_sql}")
        };
        let page_clause = if paginated {
            format!(" LIMIT {limit} OFFSET {offset}")
        } else {
            String::new()
        };
        let prefix = if group_by == "client" { "t." } else { "" };
        let client_filter = if group_by == "client" {
            " AND t.device_id != 0"
        } else {
            ""
        };
        let breakdown_sql = format!(
            "SELECT {select} FROM {from_sql} WHERE {prefix}timestamp >= {from} AND {prefix}timestamp < {to}{scope_clause}{direction_clause}{client_filter}{group_clause} ORDER BY {order_sql}{page_clause} FORMAT JSON"
        );
        let breakdown_result = self.client.query_json(&breakdown_sql)?;
        let breakdown = breakdown_result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let mac_hex = row["mac"].as_str().unwrap_or_default();
                let mac = from_hex(mac_hex)
                    .ok()
                    .filter(|bytes| !bytes.is_empty())
                    .map(|bytes| format_mac_bytes(&bytes));
                json!({
                    "id": row["id"].as_str().unwrap_or_default(),
                    "name": row["name"].as_str().unwrap_or_default(),
                    "mac": mac,
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                    "last_seen": row.get("last_seen").filter(|value| !value.is_null()).map(json_i64),
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "from": from_ms,
            "to": to_ms,
            "bucket_ms": bucket_ms,
            "group_by": group_by,
            "scope": scope.map_or("all", |value| match value {
                1 => "internet",
                2 => "internal",
                3 => "tunnel",
                _ => "all",
            }),
            "direction": direction.map_or("both", |value| match value {
                1 => "upload",
                2 => "download",
                _ => "both",
            }),
            "points": points,
            "breakdown": breakdown,
        }))
    }

    /// Queries paginated devices/clients.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_clients(&self, limit: u32, offset: u64) -> StorageResult<(Vec<Value>, u64)> {
        self.query_clients_with_window(limit, offset, None)
    }

    /// Queries clients ranked by traffic in a half-open timestamp range.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_clients_in_range(
        &self,
        limit: u32,
        offset: u64,
        from_ms: i64,
        to_ms: i64,
    ) -> StorageResult<(Vec<Value>, u64)> {
        self.query_clients_with_window(limit, offset, Some((from_ms, to_ms)))
    }

    fn query_clients_with_window(
        &self,
        limit: u32,
        offset: u64,
        window: Option<(i64, i64)>,
    ) -> StorageResult<(Vec<Value>, u64)> {
        let count_sql = "SELECT count() AS c FROM devices FINAL FORMAT JSON";
        let count_res = self.client.query_json(count_sql)?;
        let total = count_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_u64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let traffic_table = window.map_or_else(
            || {
                "(SELECT gateway_id, device_id, sum(upload_bytes) AS upload_bytes,
                         sum(download_bytes) AS download_bytes, sum(flow_count) AS flow_count
                  FROM traffic_device_minute GROUP BY gateway_id, device_id) AS t"
                    .to_owned()
            },
            |(from_ms, to_ms)| {
                format!(
                    "(SELECT gateway_id, device_id, sum(upload_bytes) AS upload_bytes,
                            sum(download_bytes) AS download_bytes, sum(flow_count) AS flow_count
                     FROM traffic_device_minute
                     WHERE timestamp >= {from_ms} AND timestamp < {to_ms}
                     GROUP BY gateway_id, device_id) AS t"
                )
            },
        );
        let order_by = "sum(t.upload_bytes + t.download_bytes) DESC, d.id";
        let activity_join = window.map_or_else(
            || {
                "(SELECT gateway_id, device_id, max(last_traffic_seen) AS last_traffic_seen
                  FROM device_traffic_activity GROUP BY gateway_id, device_id) AS f
                    ON d.gateway_id = f.gateway_id AND d.id = f.device_id"
                    .to_owned()
            },
            |(from_ms, to_ms)| {
                format!(
                    "(SELECT gateway_id, device_id, max(last_seen_at) AS last_traffic_seen
                     FROM flow_sessions FINAL
                     WHERE (upload_bytes > 0 OR download_bytes > 0 OR packets > 0)
                       AND last_seen_at >= {from_ms} AND last_seen_at < {to_ms}
                     GROUP BY gateway_id, device_id) AS f
                       ON d.gateway_id = f.gateway_id AND d.id = f.device_id"
                )
            },
        );
        let sql = format!(
            "SELECT d.id AS id, d.gateway_id AS gateway_id, d.mac AS mac,
                    d.hostname AS hostname, d.display_name AS display_name, d.vendor AS vendor,
                    d.device_type AS device_type, d.os_family AS os_family, d.model AS model,
                    d.identity_confidence AS identity_confidence,
                    d.identity_evidence_json AS identity_evidence_json,
                    d.vendor_confidence AS vendor_confidence,
                    d.device_type_confidence AS device_type_confidence,
                    d.os_confidence AS os_confidence, d.model_confidence AS model_confidence,
                    d.private_mac AS private_mac,
                    d.first_seen AS first_seen, d.last_seen AS last_seen,
                    f.last_traffic_seen AS last_traffic_seen,
                    coalesce(sum(t.upload_bytes), 0) AS up,
                    coalesce(sum(t.download_bytes), 0) AS down,
                    coalesce(sum(t.flow_count), 0) AS flow_count
             FROM devices AS d FINAL
             LEFT JOIN {traffic_table} ON d.gateway_id = t.gateway_id AND d.id = t.device_id
             LEFT JOIN {activity_join}
             GROUP BY d.id, d.gateway_id, d.mac, d.hostname, d.display_name, d.vendor,
                      d.device_type, d.os_family, d.model, d.identity_confidence,
                      d.identity_evidence_json, d.vendor_confidence, d.device_type_confidence,
                      d.os_confidence, d.model_confidence, d.private_mac, d.first_seen,
                      d.last_seen, f.last_traffic_seen
             ORDER BY {order_by} LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        let rows = res["data"].as_array().cloned().unwrap_or_default();
        let device_keys = rows
            .iter()
            .map(|row| {
                (
                    row["gateway_id"].as_str().unwrap_or_default().to_owned(),
                    row["mac"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect::<HashSet<_>>();
        let evidence_by_device = self.device_identity_evidence_by_keys(&device_keys)?;
        let device_ids = rows
            .iter()
            .map(|row| json_i64(&row["id"]))
            .collect::<HashSet<_>>();
        let mut addresses_by_device = HashMap::<i64, Vec<Value>>::new();
        if !device_ids.is_empty() {
            let id_list = device_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let addresses_sql = format!(
                "SELECT device_id, ip, ip_version, application_id, application_confidence,
                        application_source
                 FROM device_addresses FINAL WHERE device_id IN ({id_list})
                 ORDER BY device_id, last_seen DESC, ip_version FORMAT JSON"
            );
            let addresses_result = self.client.query_json(&addresses_sql)?;
            if let Some(address_rows) = addresses_result["data"].as_array() {
                for address in address_rows {
                    addresses_by_device
                        .entry(json_i64(&address["device_id"]))
                        .or_default()
                        .push(address.clone());
                }
            }
        }
        for r in &rows {
            let id = r["id"]
                .as_i64()
                .or_else(|| r["id"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0);
            let mac_hex = r["mac"].as_str().unwrap_or("");
            let mac_bytes = from_hex(mac_hex).unwrap_or_default();
            let mac_str = format_mac_bytes(&mac_bytes);
            let evidence = evidence_by_device
                .get(&(
                    r["gateway_id"].as_str().unwrap_or_default().to_owned(),
                    mac_hex.to_owned(),
                ))
                .cloned()
                .unwrap_or_default();
            let address_rows = addresses_by_device.get(&id).cloned().unwrap_or_default();
            let ips = address_rows
                .iter()
                .filter_map(|address| address["ip"].as_str())
                .filter_map(|ip_hex| from_hex(ip_hex).ok())
                .map(|ip| format_ip_bytes(&ip))
                .collect::<Vec<_>>();
            let self_host_application = address_rows
                .first()
                .filter(|_| address_rows.len() == 1)
                .and_then(|address| {
                    address["application_id"]
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(|application_id| {
                            json!({
                                "application_id": application_id,
                                "confidence": json_f64(&address["application_confidence"]),
                                "source": address["application_source"]
                                    .as_str()
                                    .filter(|value| !value.is_empty()),
                                "role": "server",
                            })
                        })
                });
            items.push(json!({
                    "id": id,
                    "mac": mac_str,
                    "ip": ips.first().cloned(),
                    "name": r["display_name"].as_str().or_else(|| r["hostname"].as_str()).unwrap_or_default(),
                    "hostname": r["hostname"].as_str(),
                    "vendor": r["vendor"].as_str(),
                    "identity": {
                        "vendor": r["vendor"].as_str(),
                        "device_type": r["device_type"].as_str(),
                        "os_family": r["os_family"].as_str(),
                        "model": r["model"].as_str(),
                        "confidence": r["identity_confidence"].as_str().unwrap_or("unknown"),
                        "vendor_confidence": json_f64(&r["vendor_confidence"]),
                        "device_type_confidence": json_f64(&r["device_type_confidence"]),
                        "os_confidence": json_f64(&r["os_confidence"]),
                        "model_confidence": json_f64(&r["model_confidence"]),
                        "private_mac": json_u64(&r["private_mac"]) != 0,
                        "evidence": evidence,
                    },
                    "last_seen": json_i64(&r["last_seen"]),
                    "last_traffic_seen": r["last_traffic_seen"].as_i64().or_else(|| r["last_traffic_seen"].as_str().and_then(|s| s.parse().ok())),
                    "upload_bytes": json_i64(&r["up"]),
                    "download_bytes": json_i64(&r["down"]),
                    "flow_count": json_i64(&r["flow_count"]),
                    "self_host_application": self_host_application,
                }));
        }
        Ok((items, total))
    }

    /// Queries client detail by device id.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_client_detail(&self, id: i64) -> StorageResult<Option<Value>> {
        let sql = format!(
            "SELECT id, gateway_id, mac, hostname, display_name, vendor, device_type,
                    os_family, model, identity_confidence, identity_evidence_json,
                    vendor_confidence, device_type_confidence, os_confidence, model_confidence,
                    private_mac, first_seen, last_seen
             FROM devices FINAL WHERE id = {id} LIMIT 1 FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        if let Some(row) = res["data"].as_array().and_then(|a| a.first()) {
            let traffic_sql = format!(
                "SELECT maxOrNull(last_traffic_seen) AS last_traffic_seen
                 FROM device_traffic_activity
                 WHERE gateway_id = '{}' AND device_id = {id} FORMAT JSON",
                escape_sql(row["gateway_id"].as_str().unwrap_or_default())
            );
            let traffic_res = self.client.query_json(&traffic_sql)?;
            let last_traffic_seen = traffic_res["data"]
                .as_array()
                .and_then(|rows| rows.first())
                .and_then(|traffic| {
                    traffic["last_traffic_seen"].as_i64().or_else(|| {
                        traffic["last_traffic_seen"]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                    })
                });
            let stats_sql = format!(
                "SELECT sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                        sum(flow_count) AS flow_count
                 FROM traffic_device_minute WHERE device_id = {id} FORMAT JSON"
            );
            let stats_res = self.client.query_json(&stats_sql)?;
            let stats = stats_res["data"].as_array().and_then(|rows| rows.first());
            let mac_hex = row["mac"].as_str().unwrap_or("");
            let mac_bytes = from_hex(mac_hex).unwrap_or_default();
            let mac_str = format_mac_bytes(&mac_bytes);

            let ip_sql = format!(
                "SELECT ip, ip_version, first_seen, last_seen, application_id,
                        application_confidence, application_source, application_last_seen
                 FROM device_addresses FINAL WHERE device_id = {id}
                 ORDER BY last_seen DESC, ip FORMAT JSON"
            );
            let mut addrs = Vec::new();
            let ip_res = self.client.query_json(&ip_sql)?;
            if let Some(rows) = ip_res["data"].as_array() {
                for r in rows {
                    if let Some(ip_hex) = r["ip"].as_str() {
                        if let Ok(ip_b) = from_hex(ip_hex) {
                            let application_id = r["application_id"]
                                .as_str()
                                .filter(|value| !value.is_empty());
                            let self_host_application = if let Some(application_id) = application_id
                            {
                                Some(json!({
                                    "application_id": application_id,
                                    "confidence": r["application_confidence"].as_f64().or_else(|| r["application_confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                                    "source": r["application_source"]
                                        .as_str()
                                        .filter(|value| !value.is_empty()),
                                    "last_seen": r["application_last_seen"].as_i64().or_else(|| r["application_last_seen"].as_str().and_then(|value| value.parse().ok())).filter(|value| *value != 0),
                                    "role": "server",
                                }))
                            } else {
                                None
                            };
                            addrs.push(json!({
                                    "ip": format_ip_bytes(&ip_b),
                                    "ip_version": r["ip_version"].as_u64().or_else(|| r["ip_version"].as_str().and_then(|s| s.parse().ok())).unwrap_or(4),
                                    "first_seen": r["first_seen"].as_i64().or_else(|| r["first_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                                    "last_seen": r["last_seen"].as_i64().or_else(|| r["last_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                                    "self_host_application": self_host_application,
                                }));
                        }
                    }
                }
            }

            let self_host_application = if addrs.len() == 1 {
                addrs[0].get("self_host_application").cloned()
            } else {
                None
            };
            let evidence = self.device_identity_evidence_json(
                row["gateway_id"].as_str().unwrap_or_default(),
                row["mac"].as_str().unwrap_or_default(),
            )?;
            let client = json!({
                "id": id,
                "mac": mac_str,
                "name": row["display_name"].as_str().or_else(|| row["hostname"].as_str()).unwrap_or_default(),
                "vendor": row["vendor"].as_str(),
                "identity": {
                    "vendor": row["vendor"].as_str(),
                    "device_type": row["device_type"].as_str(),
                    "os_family": row["os_family"].as_str(),
                    "model": row["model"].as_str(),
                    "confidence": row["identity_confidence"].as_str().unwrap_or("unknown"),
                    "vendor_confidence": row["vendor_confidence"].as_f64().or_else(|| row["vendor_confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                    "device_type_confidence": row["device_type_confidence"].as_f64().or_else(|| row["device_type_confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                    "os_confidence": row["os_confidence"].as_f64().or_else(|| row["os_confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                    "model_confidence": row["model_confidence"].as_f64().or_else(|| row["model_confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                    "private_mac": json_u64(&row["private_mac"]) != 0,
                    "evidence": evidence,
                },
                "first_seen": json_i64(&row["first_seen"]),
                "last_seen": json_i64(&row["last_seen"]),
                "last_traffic_seen": last_traffic_seen,
                "upload_bytes": stats.map_or(0, |value| json_i64(&value["upload_bytes"])),
                "download_bytes": stats.map_or(0, |value| json_i64(&value["download_bytes"])),
                "flow_count": stats.map_or(0, |value| json_i64(&value["flow_count"])),
            });
            let client = if let Some(application) = self_host_application {
                let mut client = client;
                client["self_host_application"] = application;
                client
            } else {
                client
            };
            Ok(Some(json!({ "client": client, "addresses": addrs })))
        } else {
            Ok(None)
        }
    }

    /// Queries one of the client detail relations exposed by the collector API.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when a ClickHouse query fails or a stored address is malformed.
    pub fn query_client_related(
        &self,
        id: i64,
        relation: &str,
        from_ms: u64,
        to_ms: u64,
        scope: Option<i64>,
        limit: u32,
        offset: u64,
    ) -> StorageResult<Value> {
        let from = to_i64(from_ms);
        let to = to_i64(to_ms);
        let scope_clause = scope.map_or_else(String::new, |value| format!(" AND scope = {value}"));
        if relation == "traffic" {
            let duration = to_ms.saturating_sub(from_ms);
            let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
            let bucket = to_i64(bucket_ms);
            let sql = format!(
                "SELECT intDiv(timestamp, {bucket}) * {bucket} AS timestamp,
                        sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                        sum(packets) AS packets, sum(flow_count) AS flow_count
                 FROM traffic_scope_minute
                 WHERE device_id = {id} AND timestamp >= {from} AND timestamp < {to}{scope_clause}
                 GROUP BY timestamp ORDER BY timestamp FORMAT JSON"
            );
            let result = self.client.query_json(&sql)?;
            let points = result["data"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| {
                    json!({
                        "timestamp": json_i64(&row["timestamp"]),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "flow_count": json_i64(&row["flow_count"]),
                    })
                })
                .collect::<Vec<_>>();
            return Ok(json!({ "bucket_ms": bucket_ms, "points": points }));
        }

        let page = format!(" LIMIT {limit} OFFSET {offset}");
        let sql = match relation {
            "applications" => format!(
                "SELECT coalesce(application_id, 'unknown') AS application_id,
                        coalesce(category_id, 'unknown') AS category_id,
                        sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                        sum(packets) AS packets, count() AS flow_count,
                        max(last_seen_at) AS last_seen,
                        avg(classification_confidence) AS confidence
                 FROM flow_sessions FINAL
                 WHERE device_id = {id} AND last_seen_at >= {from} AND last_seen_at < {to}{scope_clause}
                 GROUP BY application_id, category_id
                 ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "domains" => format!(
                "SELECT domain, sum(upload_bytes) AS upload_bytes,
                        sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                        count() AS flow_count, max(last_seen_at) AS last_seen
                 FROM flow_sessions FINAL
                 WHERE device_id = {id} AND domain IS NOT NULL
                   AND last_seen_at >= {from} AND last_seen_at < {to}{scope_clause}
                 GROUP BY domain ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "destinations" => format!(
                "SELECT remote_ip, max(domain) AS domain, sum(upload_bytes) AS upload_bytes,
                        sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                        count() AS flow_count, max(last_seen_at) AS last_seen
                 FROM flow_sessions FINAL
                 WHERE device_id = {id} AND last_seen_at >= {from} AND last_seen_at < {to}{scope_clause}
                 GROUP BY remote_ip ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "flows" => format!(
                "SELECT id, client_ip, client_port, remote_ip, remote_port, protocol, direction,
                        domain, coalesce(application_id, 'unknown') AS application_id,
                        coalesce(category_id, 'unknown') AS category_id,
                        classification_confidence, coalesce(classification_reason, 'no matching rule') AS classification_reason,
                        upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                        scope, path_type, nat, source_segment, destination_segment
                 FROM flow_sessions FINAL
                 WHERE device_id = {id} AND last_seen_at >= {from} AND last_seen_at < {to}{scope_clause}
                 ORDER BY last_seen_at DESC{page} FORMAT JSON"
            ),
            _ => return Err(StorageError::Other("unknown client relation".to_owned())),
        };
        let result = self.client.query_json(&sql)?;
        let items = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| match relation {
                "applications" => json!({
                    "application_id": row["application_id"].as_str().unwrap_or("unknown"),
                    "category_id": row["category_id"].as_str().unwrap_or("unknown"),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                    "last_seen": json_i64(&row["last_seen"]),
                    "confidence": row["confidence"].as_f64().or_else(|| row["confidence"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0.0),
                    "client_count": 1,
                }),
                "domains" => json!({
                    "domain": row["domain"].as_str().unwrap_or_default(),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                    "last_seen": json_i64(&row["last_seen"]),
                }),
                "destinations" => {
                    let bytes = from_hex(row["remote_ip"].as_str().unwrap_or_default())
                        .unwrap_or_default();
                    json!({
                        "remote_ip": format_ip_bytes(&bytes),
                        "domain": row["domain"].as_str(),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "flow_count": json_i64(&row["flow_count"]),
                        "last_seen": json_i64(&row["last_seen"]),
                    })
                }
                "flows" => {
                    let client_ip = from_hex(row["client_ip"].as_str().unwrap_or_default())
                        .unwrap_or_default();
                    let remote_ip = from_hex(row["remote_ip"].as_str().unwrap_or_default())
                        .unwrap_or_default();
                    json!({
                        "id": row["id"].as_str().unwrap_or_default(),
                        "client_ip": format_ip_bytes(&client_ip),
                        "client_port": json_i64(&row["client_port"]),
                        "remote_ip": format_ip_bytes(&remote_ip),
                        "remote_port": json_i64(&row["remote_port"]),
                        "protocol": json_i64(&row["protocol"]),
                        "direction": json_i64(&row["direction"]),
                        "domain": row["domain"].as_str(),
                        "application": row["application_id"].as_str().unwrap_or("unknown"),
                        "category": row["category_id"].as_str().unwrap_or("unknown"),
                        "confidence": row["classification_confidence"].as_f64().or_else(|| row["classification_confidence"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0.0),
                        "reason": row["classification_reason"].as_str().unwrap_or("no matching rule"),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "started_at": json_i64(&row["started_at"]),
                        "last_seen": json_i64(&row["last_seen_at"]),
                        "ended_at": row.get("ended_at").filter(|v| !v.is_null()).map(json_i64),
                        "scope": flow_scope_name(json_i64(&row["scope"]) as i32),
                        "path_type": flow_path_name(json_i64(&row["path_type"]) as i32),
                        "nat": flow_nat_name(json_i64(&row["nat"]) as i32),
                        "source_segment": row["source_segment"].as_str().unwrap_or_default(),
                        "destination_segment": row["destination_segment"].as_str().unwrap_or_default(),
                    })
                }
                _ => Value::Null,
            })
            .collect::<Vec<_>>();
        Ok(json!(items))
    }

    /// Queries the paginated application index with an optional time window.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute the query.
    pub fn query_applications_for_window(
        &self,
        limit: u32,
        offset: u64,
        window: Option<(i64, i64)>,
    ) -> StorageResult<(Vec<Value>, u64)> {
        let time_filter = window.map_or_else(String::new, |(from, to)| {
            format!(" AND timestamp >= {from} AND timestamp < {to}")
        });
        let count_sql = format!(
            "SELECT count() AS c FROM (
                 SELECT application_id, category_id FROM traffic_application_minute
                 WHERE 1 = 1{time_filter}
                 GROUP BY application_id, category_id
             ) FORMAT JSON"
        );
        let count_result = self.client.query_json(&count_sql)?;
        let total = count_result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| json_u64(&row["c"]))
            .unwrap_or(0);

        let client_filter = window.map_or_else(
            || "device_id IS NOT NULL".to_owned(),
            |(from, to)| {
                format!("device_id IS NOT NULL AND last_seen_at >= {from} AND last_seen_at < {to}")
            },
        );
        let flow_application = application_group_expression("application_id", "protocol_id");
        let sql = format!(
            "WITH app_totals AS (
                 SELECT application_id, category_id, sum(upload_bytes) AS upload_bytes,
                        sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                        sum(flow_count) AS flow_count, max(timestamp) AS last_seen
                 FROM traffic_application_minute
                 WHERE 1 = 1{time_filter}
                 GROUP BY application_id, category_id
             ), client_counts AS (
                 SELECT application_id,
                        uniqExactIf(device_id, {client_filter}) AS client_count,
                        anyIf(organization_id, organization_id IS NOT NULL AND organization_id != 'unknown') AS organization_id
                 FROM (
                     SELECT {flow_application} AS application_id, device_id, organization_id, last_seen_at
                     FROM flow_sessions FINAL
                 ) AS classified_flows
                 GROUP BY application_id
             )
             SELECT a.application_id, a.category_id, a.upload_bytes, a.download_bytes,
                    a.packets, a.flow_count, a.last_seen, coalesce(c.client_count, 0) AS client_count,
                    if(a.application_id IN ('unknown', 'protocol-only') OR startsWith(a.application_id, '{PROTOCOL_APPLICATION_PREFIX}'), '', ifNull(nullIf(c.organization_id, ''), '')) AS organization_id
             FROM app_totals AS a
             LEFT JOIN client_counts AS c ON c.application_id = a.application_id
             ORDER BY a.upload_bytes + a.download_bytes DESC, a.application_id, a.category_id
             LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let items = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                json!({
                    "application_id": row["application_id"].as_str().unwrap_or("unknown"),
                    "category_id": row["category_id"].as_str().unwrap_or("unknown"),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                    "last_seen": json_i64(&row["last_seen"]),
                    "client_count": json_u64(&row["client_count"]),
                    "organization_id": row["organization_id"]
                        .as_str()
                        .filter(|value| !value.is_empty()),
                })
            })
            .collect();
        Ok((items, total))
    }

    /// Queries organization or detected-protocol rankings from persisted flows.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute the query.
    pub fn query_flow_groups(
        &self,
        field: &str,
        limit: u32,
        offset: u64,
    ) -> StorageResult<(Vec<Value>, u64)> {
        let field = match field {
            "organization_id" | "protocol_id" => field,
            _ => return Err(StorageError::Other("unsupported flow grouping".to_owned())),
        };
        let group = format!("coalesce({field}, 'unknown')");
        let count_sql = format!(
            "SELECT count() AS c FROM (SELECT {group} AS id FROM flow_sessions FINAL GROUP BY id) FORMAT JSON"
        );
        let count_result = self.client.query_json(&count_sql)?;
        let total = count_result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| json_u64(&row["c"]))
            .unwrap_or(0);
        let sql = format!(
            "SELECT {group} AS id, sum(upload_bytes) AS upload_bytes,
                    sum(download_bytes) AS download_bytes, count() AS flows,
                    max(last_seen_at) AS last_seen,
                    {clients_select}
             FROM flow_sessions FINAL GROUP BY id
             ORDER BY upload_bytes + download_bytes DESC, id ASC
             LIMIT {limit} OFFSET {offset} FORMAT JSON",
            clients_select = if field == "organization_id" {
                "uniqExactIf(device_id, device_id IS NOT NULL) AS clients"
            } else {
                "toUInt64(0) AS clients"
            }
        );
        let result = self.client.query_json(&sql)?;
        let items = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let id = row["id"].as_str().unwrap_or("unknown");
                let mut item = json!({
                    "id": id,
                    "name": id,
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "flows": json_u64(&row["flows"]),
                    "last_seen": json_i64(&row["last_seen"]),
                });
                if field == "organization_id" {
                    item["clients"] = json_u64(&row["clients"]).into();
                }
                item
            })
            .collect();
        Ok((items, total))
    }

    /// Queries one application's traffic and flow-derived detail fields.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute a query.
    pub fn query_application_detail(
        &self,
        application_id: &str,
        category: Option<&str>,
        window: Option<(i64, i64)>,
    ) -> StorageResult<Option<Value>> {
        let app = escape_sql(application_id);
        let time_filter = window.map_or_else(String::new, |(from, to)| {
            format!(" AND timestamp >= {from} AND timestamp < {to}")
        });
        let flow_time_filter = window.map_or_else(String::new, |(from, to)| {
            format!(" AND last_seen_at >= {from} AND last_seen_at < {to}")
        });
        let category_predicate = category.map_or_else(String::new, |value| {
            format!(" AND category_id = '{}'", escape_sql(value))
        });
        let category_value = category.map(|value| escape_sql(value));
        let category_select = category_value.map_or_else(
            || "any(category_id)".to_owned(),
            |value| format!("'{value}'"),
        );
        let summary_sql = format!(
            "SELECT application_id, {category_select} AS category_id,
                    sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                    sum(packets) AS packets, sum(flow_count) AS flow_count,
                    max(timestamp) AS last_seen
             FROM traffic_application_minute
             WHERE application_id = '{app}'{category_predicate}{time_filter}
             GROUP BY application_id FORMAT JSON"
        );
        let summary_result = self.client.query_json(&summary_sql)?;
        let Some(summary) = summary_result["data"]
            .as_array()
            .and_then(|rows| rows.first())
        else {
            return Ok(window.map(|_| {
                json!({
                    "application_id": application_id,
                    "category_id": category.unwrap_or("unknown"),
                    "upload_bytes": 0,
                    "download_bytes": 0,
                    "packets": 0,
                    "flow_count": 0,
                    "last_seen": 0,
                    "client_count": 0,
                    "domain_count": 0,
                    "destination_count": 0,
                    "confidence": 0.0,
                    "classifier_reason": "no matching rule",
                    "organization_id": "unknown",
                    "observed_protocols": [],
                })
            }));
        };
        let flow_filter = format!(
            "{}{}{}",
            application_flow_filter(application_id, ""),
            category
                .filter(|_| !is_protocol_application_id(application_id))
                .map_or_else(String::new, |value| format!(
                    " AND coalesce(category_id, 'unknown') = '{}'",
                    escape_sql(value)
                )),
            flow_time_filter
        );
        let stats_sql = format!(
            "SELECT uniqExact(device_id) AS clients, uniqExact(domain) AS domains,
                    uniqExact(remote_ip) AS destinations, avg(classification_confidence) AS confidence,
                    coalesce(any(classification_reason), 'no matching rule') AS reason,
                    anyIf(coalesce(organization_id, 'unknown'), organization_id IS NOT NULL AND organization_id != 'unknown') AS organization_id
             FROM flow_sessions FINAL WHERE {flow_filter} FORMAT JSON"
        );
        let stats_result = self.client.query_json(&stats_sql)?;
        let stats = stats_result["data"]
            .as_array()
            .and_then(|rows| rows.first());
        let protocols_sql = format!(
            "SELECT coalesce(protocol_id, 'unknown') AS id, count() AS flows
             FROM flow_sessions FINAL WHERE {flow_filter}
             GROUP BY id ORDER BY flows DESC, id ASC FORMAT JSON"
        );
        let protocols_result = self.client.query_json(&protocols_sql)?;
        let protocols = protocols_result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| json!({ "id": row["id"].as_str().unwrap_or("unknown"), "flows": json_u64(&row["flows"]) }))
            .collect::<Vec<_>>();
        let stats = stats.unwrap_or(&Value::Null);
        let organization =
            if application_id == "unknown" || is_protocol_application_id(application_id) {
                "unknown"
            } else {
                stats["organization_id"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .unwrap_or("unknown")
            };
        Ok(Some(json!({
            "application_id": summary["application_id"].as_str().unwrap_or(application_id),
            "category_id": summary["category_id"].as_str().unwrap_or("unknown"),
            "upload_bytes": json_i64(&summary["upload_bytes"]),
            "download_bytes": json_i64(&summary["download_bytes"]),
            "packets": json_i64(&summary["packets"]),
            "flow_count": json_i64(&summary["flow_count"]),
            "last_seen": json_i64(&summary["last_seen"]),
            "client_count": json_u64(&stats["clients"]),
            "domain_count": json_u64(&stats["domains"]),
            "destination_count": json_u64(&stats["destinations"]),
            "confidence": stats["confidence"].as_f64().or_else(|| stats["confidence"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0.0),
            "classifier_reason": stats["reason"].as_str().unwrap_or("no matching rule"),
            "organization_id": organization,
            "observed_protocols": protocols,
        })))
    }

    /// Queries an application's traffic, clients, domains, destinations, or flows.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute the query.
    pub fn query_application_related(
        &self,
        application_id: &str,
        category: Option<&str>,
        relation: &str,
        from_ms: u64,
        to_ms: u64,
        limit: u32,
        offset: u64,
        include_all: bool,
    ) -> StorageResult<Value> {
        let app = escape_sql(application_id);
        let from = to_i64(from_ms);
        let to = to_i64(to_ms);
        let traffic_category_filter = category.map_or_else(String::new, |value| {
            format!(
                " AND coalesce(category_id, 'unknown') = '{}'",
                escape_sql(value)
            )
        });
        let category_filter = category
            .filter(|_| !is_protocol_application_id(application_id))
            .map_or_else(String::new, |value| {
                format!(
                    " AND coalesce(category_id, 'unknown') = '{}'",
                    escape_sql(value)
                )
            });
        let page = if include_all && matches!(relation, "domains" | "destinations") {
            String::new()
        } else {
            format!(" LIMIT {limit} OFFSET {offset}")
        };
        if relation == "traffic" {
            let duration = to_ms.saturating_sub(from_ms);
            let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
            let bucket = to_i64(bucket_ms);
            let sql = format!(
                "SELECT intDiv(timestamp, {bucket}) * {bucket} AS timestamp,
                        sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                        sum(packets) AS packets, sum(flow_count) AS flow_count
                 FROM traffic_application_minute
                 WHERE application_id = '{app}'{traffic_category_filter}
                   AND timestamp >= {from} AND timestamp < {to}
                 GROUP BY timestamp ORDER BY timestamp FORMAT JSON"
            );
            let result = self.client.query_json(&sql)?;
            let points = result["data"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| {
                    json!({
                        "timestamp": json_i64(&row["timestamp"]),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "flow_count": json_i64(&row["flow_count"]),
                    })
                })
                .collect::<Vec<_>>();
            return Ok(json!({ "bucket_ms": bucket_ms, "points": points }));
        }

        let application_filter = application_flow_filter(application_id, "");
        let flow_application_filter = application_flow_filter(application_id, "f.");
        let scope_application_filter = application_flow_filter(application_id, "t.");
        let flow_category_filter = category
            .filter(|_| !is_protocol_application_id(application_id))
            .map_or_else(String::new, |value| {
                format!(
                    " AND coalesce(f.category_id, 'unknown') = '{}'",
                    escape_sql(value)
                )
            });
        let scope_category_filter = category
            .filter(|_| !is_protocol_application_id(application_id))
            .map_or_else(String::new, |value| {
                format!(
                    " AND coalesce(t.category_id, 'unknown') = '{}'",
                    escape_sql(value)
                )
            });

        let sql = match relation {
            "clients" => format!(
                "SELECT d.id, d.mac, coalesce(d.display_name, d.hostname, '') AS name,
                        d.gateway_id, d.vendor, d.device_type, d.os_family, d.model,
                        d.identity_confidence, d.vendor_confidence,
                        d.device_type_confidence, d.os_confidence, d.model_confidence,
                        d.private_mac, d.last_seen, sum(f.upload_bytes) AS upload_bytes,
                        sum(f.download_bytes) AS download_bytes, count() AS flow_count
                 FROM flow_sessions AS f FINAL INNER JOIN devices AS d FINAL ON d.id = f.device_id
                 WHERE {flow_application_filter}{flow_category_filter}
                   AND f.last_seen_at >= {from} AND f.last_seen_at < {to}
                 GROUP BY d.id, d.mac, name, d.gateway_id, d.vendor, d.device_type,
                          d.os_family, d.model, d.identity_confidence, d.vendor_confidence,
                          d.device_type_confidence, d.os_confidence, d.model_confidence,
                          d.private_mac, d.last_seen
                 ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "domains" => format!(
                "SELECT t.domain, sum(t.upload_bytes) AS upload_bytes,
                        sum(t.download_bytes) AS download_bytes, sum(t.packets) AS packets,
                        sum(t.flow_count) AS flow_count, max(t.timestamp) AS last_seen
                 FROM traffic_scope_minute AS t
                 WHERE {scope_application_filter}{scope_category_filter}
                   AND t.domain != '' AND t.domain != 'unknown'
                   AND t.timestamp >= {from} AND t.timestamp < {to}
                 GROUP BY t.domain ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "destinations" => format!(
                "SELECT t.remote_ip, nullIf(max(t.domain), 'unknown') AS domain,
                        sum(t.upload_bytes) AS upload_bytes,
                        sum(t.download_bytes) AS download_bytes, sum(t.packets) AS packets,
                        sum(t.flow_count) AS flow_count, max(t.timestamp) AS last_seen
                 FROM traffic_scope_minute AS t
                 WHERE {scope_application_filter}{scope_category_filter}
                   AND t.timestamp >= {from} AND t.timestamp < {to}
                 GROUP BY t.remote_ip
                 ORDER BY upload_bytes + download_bytes DESC{page} FORMAT JSON"
            ),
            "flows" => format!(
                "SELECT id, client_ip, client_port, remote_ip, remote_port, protocol, direction,
                        domain, coalesce(category_id, 'unknown') AS category_id,
                        classification_confidence, coalesce(classification_reason, 'no matching rule') AS classification_reason,
                        upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                        scope, path_type, nat, source_segment, destination_segment
                 FROM flow_sessions FINAL
                 WHERE {application_filter}{category_filter}
                   AND last_seen_at >= {from} AND last_seen_at < {to}
                 ORDER BY last_seen_at DESC{page} FORMAT JSON"
            ),
            _ => return Err(StorageError::Other("unknown application relation".to_owned())),
        };
        let result = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        let rows = result["data"].as_array().cloned().unwrap_or_default();
        let device_keys = if relation == "clients" {
            rows.iter()
                .map(|row| {
                    (
                        row["gateway_id"].as_str().unwrap_or_default().to_owned(),
                        row["mac"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        let evidence_by_device = self.device_identity_evidence_by_keys(&device_keys)?;
        for row in &rows {
            let item = match relation {
                "clients" => {
                    let mac_hex = row["mac"].as_str().unwrap_or_default();
                    let mac_bytes = from_hex(mac_hex).unwrap_or_default();
                    let confidence = |field: &str| {
                        row[field]
                            .as_f64()
                            .or_else(|| row[field].as_str().and_then(|value| value.parse().ok()))
                            .unwrap_or(0.0)
                    };
                    let private_mac = json_u64(&row["private_mac"]) != 0;
                    let evidence = evidence_by_device
                        .get(&(
                            row["gateway_id"].as_str().unwrap_or_default().to_owned(),
                            mac_hex.to_owned(),
                        ))
                        .cloned()
                        .unwrap_or_default();
                    json!({
                        "id": json_i64(&row["id"]),
                        "mac": format_mac_bytes(&mac_bytes),
                        "name": row["name"].as_str().unwrap_or_default(),
                        "vendor": row["vendor"].as_str(),
                        "identity": {
                            "vendor": row["vendor"].as_str(),
                            "device_type": row["device_type"].as_str(),
                            "os_family": row["os_family"].as_str(),
                            "model": row["model"].as_str(),
                            "confidence": row["identity_confidence"].as_str().unwrap_or("unknown"),
                            "vendor_confidence": confidence("vendor_confidence"),
                            "device_type_confidence": confidence("device_type_confidence"),
                            "os_confidence": confidence("os_confidence"),
                            "model_confidence": confidence("model_confidence"),
                            "private_mac": private_mac,
                            "evidence": evidence,
                        },
                        "last_seen": json_i64(&row["last_seen"]),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "flow_count": json_u64(&row["flow_count"]),
                    })
                }
                "domains" => json!({
                    "domain": row["domain"].as_str().unwrap_or_default(),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_u64(&row["flow_count"]),
                    "last_seen": json_i64(&row["last_seen"]),
                }),
                "destinations" => {
                    let bytes =
                        from_hex(row["remote_ip"].as_str().unwrap_or_default()).unwrap_or_default();
                    json!({
                        "remote_ip": format_ip_bytes(&bytes),
                        "domain": row["domain"].as_str(),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "flow_count": json_u64(&row["flow_count"]),
                        "last_seen": json_i64(&row["last_seen"]),
                    })
                }
                "flows" => {
                    let client_ip =
                        from_hex(row["client_ip"].as_str().unwrap_or_default()).unwrap_or_default();
                    let remote_ip =
                        from_hex(row["remote_ip"].as_str().unwrap_or_default()).unwrap_or_default();
                    json!({
                        "id": row["id"].as_str().unwrap_or_default(),
                        "client_ip": format_ip_bytes(&client_ip),
                        "client_port": json_i64(&row["client_port"]),
                        "remote_ip": format_ip_bytes(&remote_ip),
                        "remote_port": json_i64(&row["remote_port"]),
                        "protocol": json_i64(&row["protocol"]),
                        "direction": json_i64(&row["direction"]),
                        "domain": row["domain"].as_str(),
                        "application": application_id,
                        "category": row["category_id"].as_str().unwrap_or("unknown"),
                        "confidence": row["classification_confidence"].as_f64().or_else(|| row["classification_confidence"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0.0),
                        "reason": row["classification_reason"].as_str().unwrap_or("no matching rule"),
                        "upload_bytes": json_i64(&row["upload_bytes"]),
                        "download_bytes": json_i64(&row["download_bytes"]),
                        "packets": json_i64(&row["packets"]),
                        "started_at": json_i64(&row["started_at"]),
                        "last_seen": json_i64(&row["last_seen_at"]),
                        "ended_at": row.get("ended_at").filter(|v| !v.is_null()).map(json_i64),
                        "scope": flow_scope_name(json_i64(&row["scope"]) as i32),
                        "path_type": flow_path_name(json_i64(&row["path_type"]) as i32),
                        "nat": flow_nat_name(json_i64(&row["nat"]) as i32),
                        "source_segment": row["source_segment"].as_str().unwrap_or_default(),
                        "destination_segment": row["destination_segment"].as_str().unwrap_or_default(),
                    })
                }
                _ => Value::Null,
            };
            items.push(item);
        }
        Ok(json!(items))
    }

    fn refresh_self_host_address_ch(
        &self,
        gateway_id: &str,
        ip: &str,
        newest_seen: i64,
    ) -> StorageResult<()> {
        let gateway = escape_sql(gateway_id);
        let ip = escape_sql(ip);
        let sql = format!(
            "SELECT uniqExact(application_id) AS application_count,
                    any(application_id) AS selected_application_id, max(confidence) AS confidence,
                    min(source) AS source, max(last_seen) AS last_seen
             FROM self_host_endpoint_evidence FINAL
             WHERE gateway_id = '{gateway}' AND ip = '{ip}'
               AND application_id != '__shared__' AND expires_at > {newest_seen}
             FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let row = result["data"].as_array().and_then(|rows| rows.first());
        let has_one_application = row.is_some_and(|row| json_u64(&row["application_count"]) == 1);
        let (application_id, confidence, source, last_seen) =
            if let Some(row) = row.filter(|_| has_one_application) {
                (
                    row["selected_application_id"].as_str().unwrap_or_default(),
                    json_f64(&row["confidence"]),
                    row["source"].as_str().unwrap_or_default(),
                    json_i64(&row["last_seen"]),
                )
            } else {
                ("", 0.0, "", 0)
            };
        self.execute_mutation(&format!(
            "ALTER TABLE device_addresses UPDATE
                application_id = '{}', application_confidence = {confidence},
                application_source = '{}', application_last_seen = {last_seen}
             WHERE ip = '{ip}'
               AND device_id IN (SELECT id FROM devices FINAL WHERE gateway_id = '{gateway}')",
            escape_sql(application_id),
            escape_sql(source),
        ))
    }

    /// Queries applications summary.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_applications(&self, limit: u32, offset: u64) -> StorageResult<(Vec<Value>, u64)> {
        let count_sql = "SELECT count(distinct application_id) AS c FROM traffic_application_minute FORMAT JSON";
        let count_res = self.client.query_json(count_sql)?;
        let total = count_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_u64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let sql = format!(
            "SELECT application_id, any(category_id) AS category_id, sum(upload_bytes) AS up, sum(download_bytes) AS down, sum(packets) AS pkts, sum(flow_count) AS flows FROM traffic_application_minute GROUP BY application_id ORDER BY down DESC LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                items.push(json!({
                    "id": r["application_id"].as_str().unwrap_or(""),
                    "name": r["application_id"].as_str().unwrap_or(""),
                    "category_id": r["category_id"].as_str().unwrap_or("unknown"),
                    "upload_bytes": r["up"].as_i64().or_else(|| r["up"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["down"].as_i64().or_else(|| r["down"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "packets": r["pkts"].as_i64().or_else(|| r["pkts"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "flow_count": r["flows"].as_i64().or_else(|| r["flows"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "client_count": 0,
                }));
            }
        }
        Ok((items, total))
    }

    /// Queries domains summary.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_domains(&self, limit: u32, offset: u64) -> StorageResult<(Vec<Value>, u64)> {
        let count_sql = "SELECT count(distinct domain) AS c FROM traffic_domain_minute FORMAT JSON";
        let count_res = self.client.query_json(count_sql)?;
        let total = count_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_u64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let sql = format!(
            "SELECT domain, sum(upload_bytes) AS up, sum(download_bytes) AS down,
                    sum(packets) AS pkts, sum(flow_count) AS flows, max(timestamp) AS last_seen
             FROM traffic_domain_minute GROUP BY domain
             ORDER BY up + down DESC, domain ASC LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                items.push(json!({
                    "domain": r["domain"].as_str().unwrap_or(""),
                    "upload_bytes": r["up"].as_i64().or_else(|| r["up"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["down"].as_i64().or_else(|| r["down"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "packets": r["pkts"].as_i64().or_else(|| r["pkts"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "flow_count": r["flows"].as_i64().or_else(|| r["flows"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "last_seen": json_i64(&r["last_seen"]),
                }));
            }
        }
        Ok((items, total))
    }

    /// Queries destinations summary.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_destinations(&self, limit: u32, offset: u64) -> StorageResult<(Vec<Value>, u64)> {
        let count_sql =
            "SELECT count(distinct remote_ip) AS c FROM traffic_destination_minute FORMAT JSON";
        let count_res = self.client.query_json(count_sql)?;
        let total = count_res["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| {
                r["c"]
                    .as_u64()
                    .or_else(|| r["c"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);

        let sql = format!(
            "SELECT remote_ip, sum(upload_bytes) AS up, sum(download_bytes) AS down, sum(packets) AS pkts, sum(flow_count) AS flows FROM traffic_destination_minute GROUP BY remote_ip ORDER BY down DESC LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                let ip_hex = r["remote_ip"].as_str().unwrap_or("");
                let ip_bytes = from_hex(ip_hex).unwrap_or_default();
                let ip_str = format_ip_bytes(&ip_bytes);
                items.push(json!({
                    "remote_ip": ip_str,
                    "upload_bytes": r["up"].as_i64().or_else(|| r["up"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["down"].as_i64().or_else(|| r["down"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "packets": r["pkts"].as_i64().or_else(|| r["pkts"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "flow_count": r["flows"].as_i64().or_else(|| r["flows"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "client_count": 0,
                }));
            }
        }
        Ok((items, total))
    }

    /// Queries internet destinations with the fields consumed by the collector API.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute the query.
    pub fn query_destination_details(
        &self,
        limit: u32,
        offset: u64,
        window: Option<(i64, i64)>,
    ) -> StorageResult<(Vec<Value>, u64)> {
        let time_filter = window.map_or_else(String::new, |(from, to)| {
            format!(" AND timestamp >= {from} AND timestamp < {to}")
        });
        let count_sql = format!(
            "SELECT uniqExact(remote_ip) AS c FROM traffic_scope_minute
             WHERE scope = 1{time_filter} FORMAT JSON"
        );
        let count_result = self.client.query_json(&count_sql)?;
        let total = count_result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| json_u64(&row["c"]))
            .unwrap_or(0);
        let sql = format!(
            "SELECT p.remote_ip, p.upload_bytes, p.download_bytes, p.packets,
                    p.flow_count, p.last_seen, coalesce(f.domain, '') AS domain,
                    coalesce(f.client_count, 0) AS client_count,
                    coalesce(f.application_id, '') AS application_id
             FROM (
                 SELECT remote_ip, sum(upload_bytes) AS upload_bytes,
                        sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                        sum(flow_count) AS flow_count, max(timestamp) AS last_seen
                 FROM traffic_scope_minute WHERE scope = 1{time_filter}
                 GROUP BY remote_ip
                 ORDER BY upload_bytes + download_bytes DESC, remote_ip ASC
                 LIMIT {limit} OFFSET {offset}
             ) AS p
             LEFT JOIN (
                 SELECT remote_ip,
                        argMaxIf(domain, last_seen_at, domain IS NOT NULL) AS domain,
                        uniqExactIf(device_id, device_id IS NOT NULL) AS client_count,
                        argMaxIf(application_id, last_seen_at,
                                 application_id IS NOT NULL AND application_id != 'unknown') AS application_id
                 FROM flow_sessions FINAL GROUP BY remote_ip
             ) AS f ON f.remote_ip = p.remote_ip
             ORDER BY p.upload_bytes + p.download_bytes DESC, p.remote_ip ASC FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let items = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let ip_hex = row["remote_ip"].as_str().unwrap_or_default();
                let ip_bytes = from_hex(ip_hex).unwrap_or_default();
                json!({
                    "remote_ip": format_ip_bytes(&ip_bytes),
                    "upload_bytes": json_i64(&row["upload_bytes"]),
                    "download_bytes": json_i64(&row["download_bytes"]),
                    "packets": json_i64(&row["packets"]),
                    "flow_count": json_i64(&row["flow_count"]),
                    "last_seen": json_i64(&row["last_seen"]),
                    "domain": row["domain"].as_str().filter(|value| !value.is_empty()),
                    "client_count": json_u64(&row["client_count"]),
                    "application_id": row["application_id"].as_str().filter(|value| !value.is_empty()),
                })
            })
            .collect();
        Ok((items, total))
    }

    /// Queries destination traffic pairs for Geo aggregation.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_geo_destinations(&self) -> StorageResult<Vec<(Vec<u8>, i64, i64)>> {
        let sql = "SELECT remote_ip, sum(upload_bytes) AS up, sum(download_bytes) AS down FROM traffic_destination_minute GROUP BY remote_ip FORMAT JSON";
        let res = self.client.query_json(sql)?;
        let mut out = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                let ip_hex = r["remote_ip"].as_str().unwrap_or("");
                if let Ok(ip_bytes) = from_hex(ip_hex) {
                    let up = r["up"]
                        .as_i64()
                        .or_else(|| r["up"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0);
                    let down = r["down"]
                        .as_i64()
                        .or_else(|| r["down"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap_or(0);
                    out.push((ip_bytes, up, down));
                }
            }
        }
        Ok(out)
    }

    /// Queries per-destination byte totals for the Geo summary API.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` when ClickHouse cannot execute the query.
    pub fn query_geo_traffic(
        &self,
        from_ms: Option<u64>,
        to_ms: Option<u64>,
    ) -> StorageResult<Vec<(Vec<u8>, i64)>> {
        let time_filter = match (from_ms, to_ms) {
            (Some(from), Some(to)) => format!(
                " AND timestamp >= {} AND timestamp < {}",
                to_i64(from),
                to_i64(to)
            ),
            _ => String::new(),
        };
        let sql = format!(
            "SELECT remote_ip, sum(upload_bytes + download_bytes) AS bytes
             FROM traffic_scope_minute WHERE scope = 1{time_filter}
             GROUP BY remote_ip FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let mut rows = Vec::new();
        if let Some(items) = result["data"].as_array() {
            for row in items {
                let address = from_hex(row["remote_ip"].as_str().unwrap_or_default())?;
                rows.push((address, json_i64(&row["bytes"])));
            }
        }
        Ok(rows)
    }

    /// Queries paginated flows.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_flows(
        &self,
        limit: u32,
        offset: u64,
    ) -> StorageResult<(Vec<Value>, Option<String>)> {
        let sql = format!(
            "SELECT id, ip_version, protocol, client_ip, client_port, remote_ip, remote_port, direction, domain, organization_id, application_id, category_id, traffic_role, protocol_id, organization_confidence, application_confidence, protocol_confidence, classification_confidence, classification_reason, classification_evidence_json, upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at, device_id, scope, path_type, nat, source_segment, destination_segment FROM flow_sessions FINAL ORDER BY last_seen_at DESC LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                let client_ip = from_hex(r["client_ip"].as_str().unwrap_or("")).unwrap_or_default();
                let remote_ip = from_hex(r["remote_ip"].as_str().unwrap_or("")).unwrap_or_default();
                items.push(json!({
                    "id": r["id"].as_str().unwrap_or(""),
                    "client_ip": format_ip_bytes(&client_ip),
                    "client_port": r["client_port"].as_i64().or_else(|| r["client_port"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "remote_ip": format_ip_bytes(&remote_ip),
                    "remote_port": r["remote_port"].as_i64().or_else(|| r["remote_port"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "protocol": r["protocol"].as_i64().or_else(|| r["protocol"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "ip_version": r["ip_version"].as_i64().or_else(|| r["ip_version"].as_str().and_then(|s| s.parse().ok())).unwrap_or(4),
                    "direction": r["direction"].as_i64().or_else(|| r["direction"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "domain": r["domain"].as_str(),
                    "organization_id": r["organization_id"].as_str(),
                    "application_id": r["application_id"].as_str(),
                    "category_id": r["category_id"].as_str(),
                    "traffic_role": r["traffic_role"].as_str(),
                    "protocol_id": r["protocol_id"].as_str(),
                    "organization_confidence": r["organization_confidence"].as_f64().or_else(|| r["organization_confidence"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0),
                    "application_confidence": r["application_confidence"].as_f64().or_else(|| r["application_confidence"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0),
                    "protocol_confidence": r["protocol_confidence"].as_f64().or_else(|| r["protocol_confidence"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0),
                    "classification_confidence": r["classification_confidence"].as_f64().or_else(|| r["classification_confidence"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0),
                    "classification_reason": r["classification_reason"].as_str(),
                    "classification_evidence_json": r["classification_evidence_json"].as_str(),
                    "scope": flow_scope_name(r["scope"].as_i64().unwrap_or(4) as i32),
                    "path_type": flow_path_name(r["path_type"].as_i64().unwrap_or(4) as i32),
                    "nat": flow_nat_name(r["nat"].as_i64().unwrap_or(5) as i32),
                    "source_segment": r["source_segment"].as_str().unwrap_or(""),
                    "destination_segment": r["destination_segment"].as_str().unwrap_or(""),
                    "upload_bytes": r["upload_bytes"].as_i64().or_else(|| r["upload_bytes"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["download_bytes"].as_i64().or_else(|| r["download_bytes"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "packets": r["packets"].as_i64().or_else(|| r["packets"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "started_at": r["started_at"].as_i64().or_else(|| r["started_at"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "last_seen_at": r["last_seen_at"].as_i64().or_else(|| r["last_seen_at"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "ended_at": r["ended_at"].as_i64().or_else(|| r["ended_at"].as_str().and_then(|s| s.parse().ok())),
                    "device_id": r["device_id"].as_i64().or_else(|| r["device_id"].as_str().and_then(|s| s.parse().ok())),
                }));
            }
        }
        Ok((items, None))
    }
}

impl ClickHouseStorage {
    fn roll_up_dimension(
        &self,
        dimension: &str,
        source_period: &str,
        target_period: &str,
        bucket_ms: i64,
        complete_before_ms: i64,
    ) -> StorageResult<()> {
        let source = format!("traffic_{dimension}_{source_period}");
        let target = format!("traffic_{dimension}_{target_period}");
        let dimension_columns = match dimension {
            "total" => "",
            "device" => "device_id",
            "application" => "application_id, category_id",
            "domain" => "domain",
            "destination" => "remote_ip",
            _ => return Err(StorageError::Other("unknown traffic dimension".to_owned())),
        };
        let dimension_select = if dimension_columns.is_empty() {
            String::new()
        } else {
            format!(", {dimension_columns}")
        };
        let dimension_group = if dimension_columns.is_empty() {
            String::new()
        } else {
            format!(", {dimension_columns}")
        };
        let dimension = escape_sql(dimension);
        let source_period = escape_sql(source_period);
        let target_period = escape_sql(target_period);
        let gateways_sql = format!(
            "SELECT DISTINCT gateway_id FROM traffic_rollup_dirty FINAL
             WHERE dimension = '{dimension}' AND period = '{source_period}'
             ORDER BY gateway_id FORMAT JSON"
        );
        let gateways_result = self.client.query_json(&gateways_sql)?;
        let gateways = gateways_result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["gateway_id"].as_str())
            .map(str::to_owned)
            .collect::<Vec<_>>();

        for gateway_id in gateways {
            let gateway = escape_sql(&gateway_id);
            let dirty_sql = format!(
                "SELECT timestamp, version FROM traffic_rollup_dirty FINAL
                 WHERE gateway_id = '{gateway}' AND dimension = '{dimension}'
                   AND period = '{source_period}' FORMAT JSON"
            );
            let dirty_result = self.client.query_json(&dirty_sql)?;
            let progress_sql = format!(
                "SELECT timestamp, max(processed_version) AS processed_version
                 FROM traffic_rollup_progress
                 WHERE gateway_id = '{gateway}' AND dimension = '{dimension}'
                   AND period = '{source_period}' GROUP BY timestamp FORMAT JSON"
            );
            let progress_result = self.client.query_json(&progress_sql)?;
            let processed_versions = progress_result["data"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| {
                    (
                        json_i64(&row["timestamp"]),
                        json_i64(&row["processed_version"]),
                    )
                })
                .collect::<HashMap<_, _>>();
            let mut processed_source_buckets = Vec::<(i64, i64)>::new();
            let mut target_buckets = HashMap::<i64, i64>::new();
            if let Some(rows) = dirty_result["data"].as_array() {
                for row in rows {
                    let timestamp = json_i64(&row["timestamp"]);
                    let version = json_i64(&row["version"]);
                    if timestamp >= complete_before_ms
                        || version <= processed_versions.get(&timestamp).copied().unwrap_or(0)
                    {
                        continue;
                    }
                    processed_source_buckets.push((timestamp, version));
                    let target_bucket = timestamp.div_euclid(bucket_ms) * bucket_ms;
                    target_buckets
                        .entry(target_bucket)
                        .and_modify(|current| *current = (*current).max(version))
                        .or_insert(version);
                }
            }
            if target_buckets.is_empty() {
                continue;
            }
            let bucket_list = target_buckets
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");

            // Rebuild only complete buckets whose source period was touched by
            // a new batch. This includes arbitrarily late data without scanning
            // the entire retained history on every maintenance tick.
            self.execute_mutation(&format!(
                "ALTER TABLE {target} DELETE WHERE gateway_id = '{gateway}'
                 AND timestamp IN ({bucket_list})"
            ))?;
            let sql = format!(
                "INSERT INTO {target} (timestamp, gateway_id{dimension_select},
                        upload_bytes, download_bytes, packets, flow_count)
                 SELECT intDiv(timestamp, {bucket_ms}) * {bucket_ms} AS bucket,
                        gateway_id{dimension_select}, sum(upload_bytes), sum(download_bytes),
                        sum(packets), sum(flow_count)
                 FROM {source}
                 WHERE gateway_id = '{gateway}' AND timestamp < {complete_before_ms}
                   AND intDiv(timestamp, {bucket_ms}) * {bucket_ms} IN ({bucket_list})
                 GROUP BY bucket, gateway_id{dimension_group}"
            );
            self.client.execute(&sql)?;

            let derived_markers = target_buckets
                .iter()
                .map(|(timestamp, version)| {
                    json!({
                        "gateway_id": gateway_id,
                        "dimension": dimension,
                        "period": target_period,
                        "timestamp": timestamp,
                        "version": version,
                    })
                })
                .collect::<Vec<_>>();
            self.client
                .insert_json_each_row("traffic_rollup_dirty", &derived_markers)?;

            let processed_rows = processed_source_buckets
                .into_iter()
                .map(|(timestamp, processed_version)| {
                    json!({
                        "gateway_id": gateway_id,
                        "dimension": dimension,
                        "period": source_period,
                        "timestamp": timestamp,
                        "processed_version": processed_version,
                    })
                })
                .collect::<Vec<_>>();
            self.client
                .insert_json_each_row("traffic_rollup_progress", &processed_rows)?;
        }
        Ok(())
    }

    fn execute_mutation(&self, sql: &str) -> StorageResult<()> {
        self.client
            .execute(&format!("{sql} SETTINGS mutations_sync = 1"))?;
        Ok(())
    }

    fn insert_batch_rows(
        &self,
        batch: &TelemetryBatch,
        table: &str,
        rows: &[Value],
    ) -> StorageResult<()> {
        let token = format!(
            "netqmon-{}-{}-{}-{table}",
            to_hex(batch.gateway_id.as_bytes()),
            to_hex(batch.boot_id.as_bytes()),
            batch.sequence,
        );
        self.client
            .insert_json_each_row_with_token(table, rows, Some(&token))
    }
}

impl StorageBackend for ClickHouseStorage {
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        let sql = "SELECT id, agent_token_hash, last_seen FROM gateways FINAL ORDER BY created_at LIMIT 1 FORMAT JSON";
        let result = self.client.query_json(sql)?;
        let first = result["data"].as_array().and_then(|rows| rows.first());
        if let Some(row) = first {
            let id = row["id"].as_str().unwrap_or("").to_owned();
            let hash_hex = row["agent_token_hash"].as_str().unwrap_or("");
            let hash_bytes = from_hex(hash_hex)?;
            let agent_token_hash = hash_bytes.try_into().map_err(|_| {
                StorageError::Serialization("agent token hash must contain 32 bytes".to_owned())
            })?;
            Ok(Some(GatewayRecord {
                id,
                agent_token_hash,
                last_seen_ms: json_u64(&row["last_seen"]),
            }))
        } else {
            Ok(None)
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
        let count_sql = "SELECT count() AS count FROM gateways FORMAT JSON";
        let result = self.client.query_json(count_sql)?;
        let count = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| {
                row["count"]
                    .as_u64()
                    .or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);
        if count != 0 {
            return Ok(false);
        }

        let now = to_i64(now_ms);
        let record = json!({
            "id": gateway_id,
            "site_id": "default",
            "name": name,
            "agent_token_hash": to_hex(agent_token_hash),
            "agent_version": agent_version,
            "arch": "",
            "kernel_version": "",
            "openwrt_version": "",
            "status": "online",
            "last_seen": now,
            "created_at": now
        });
        self.client.insert_json_each_row("gateways", &[record])?;
        Ok(true)
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
        // ReplacingMergeTree has no row-level UPDATE transaction. An
        // INSERT ... SELECT keeps the stale predicate in the same ClickHouse
        // statement and preserves all metadata that is not part of enrollment.
        let sql = format!(
            "INSERT INTO gateways (
                id, site_id, name, agent_token_hash, agent_version, arch,
                kernel_version, openwrt_version, status, last_seen, created_at
             )
             SELECT id, site_id, '{}', '{}', '{}', arch, kernel_version,
                    openwrt_version, 'online', {}, created_at
             FROM gateways FINAL
             WHERE id = '{}' AND last_seen <= {} LIMIT 1",
            escape_sql(name),
            escape_sql(&to_hex(agent_token_hash)),
            escape_sql(agent_version),
            to_i64(now_ms),
            escape_sql(gateway_id),
            to_i64(stale_before_ms),
        );
        self.client.execute(&sql)?;

        let replaced = self.gateway()?.is_some_and(|gateway| {
            gateway.id == gateway_id
                && gateway.agent_token_hash.as_slice() == agent_token_hash
                && gateway.last_seen_ms == now_ms
        });
        Ok(replaced)
    }

    fn admin_exists(&self) -> StorageResult<bool> {
        let sql = "SELECT count() AS count FROM users FINAL FORMAT JSON";
        let result = self.client.query_json(sql)?;
        let count = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| {
                row["count"]
                    .as_u64()
                    .or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);
        Ok(count > 0)
    }

    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        if self.admin_exists()? {
            return Ok(false);
        }
        let now = to_i64(now_ms);
        let record = json!({
            "id": id,
            "username": username,
            "password_hash": password_hash,
            "created_at": now
        });
        self.client.insert_json_each_row("users", &[record])?;
        Ok(true)
    }

    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        let sql = format!(
            "SELECT id, username, password_hash FROM users FINAL WHERE username = '{}' LIMIT 1 FORMAT JSON",
            escape_sql(username)
        );
        let result = self.client.query_json(&sql)?;
        let user = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| UserRecord {
                id: row["id"].as_str().unwrap_or("").to_owned(),
                username: row["username"].as_str().unwrap_or("").to_owned(),
                password_hash: row["password_hash"].as_str().unwrap_or("").to_owned(),
            });
        Ok(user)
    }

    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        let record = json!({
            "token_hash": to_hex(token_hash),
            "user_id": user_id,
            "created_at": to_i64(now_ms),
            "expires_at": to_i64(expires_at)
        });
        self.client
            .insert_json_each_row("auth_sessions", &[record])?;
        self.execute_mutation(&format!(
            "ALTER TABLE auth_sessions DELETE WHERE expires_at <= {}",
            to_i64(now_ms)
        ))
    }

    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        let hex = to_hex(token_hash);
        let now = to_i64(now_ms);
        let sql = format!(
            "SELECT s.user_id AS user_id, u.username AS username, s.expires_at AS expires_at FROM auth_sessions AS s FINAL LEFT JOIN users AS u FINAL ON s.user_id = u.id WHERE s.token_hash = '{hex}' AND s.expires_at > {now} LIMIT 1 FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        let session = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| SessionRecord {
                user_id: row["user_id"].as_str().unwrap_or("").to_owned(),
                username: row["username"].as_str().unwrap_or("").to_owned(),
                expires_at: row["expires_at"]
                    .as_u64()
                    .or_else(|| row["expires_at"].as_str().and_then(|s| s.parse().ok()))
                    .unwrap_or(0),
            });
        Ok(session)
    }

    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        let hex = to_hex(token_hash);
        let count_sql = format!(
            "SELECT count() AS count FROM auth_sessions FINAL WHERE token_hash = '{hex}' FORMAT JSON"
        );
        let result = self.client.query_json(&count_sql)?;
        let exists = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .is_some_and(|row| json_u64(&row["count"]) > 0);
        if !exists {
            return Ok(false);
        }
        self.execute_mutation(&format!(
            "ALTER TABLE auth_sessions DELETE WHERE token_hash = '{hex}'"
        ))?;
        Ok(true)
    }

    fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        self.persist_classified_batch(batch, &[], &[], received_at_ms)
    }

    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        let received_at = to_i64(received_at_ms);

        // Check if duplicate batch exists.
        let dup_check = format!(
            "SELECT count() AS count FROM ingest_batches WHERE gateway_id = '{}' AND boot_id = '{}' AND sequence = {} FORMAT JSON",
            escape_sql(&batch.gateway_id),
            escape_sql(&batch.boot_id),
            to_i64(batch.sequence)
        );
        let dup_res = self.client.query_json(&dup_check)?;
        let count = dup_res["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| {
                row["count"]
                    .as_u64()
                    .or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);
        if count > 0 {
            return Ok(PersistDisposition::Duplicate);
        }

        let ingest_record = json!({
            "gateway_id": batch.gateway_id,
            "boot_id": batch.boot_id,
            "sequence": to_i64(batch.sequence),
            "received_at": received_at,
        });

        // 1. Gateway record update
        let health = batch.health.as_ref();
        let agent_token_hash = self
            .gateway()?
            .filter(|gateway| gateway.id == batch.gateway_id)
            .map(|gateway| to_hex(&gateway.agent_token_hash))
            .ok_or_else(|| {
                StorageError::Other(format!(
                    "cannot update unknown gateway {} without credentials",
                    batch.gateway_id
                ))
            })?;
        let gateway_sql = format!(
            "SELECT site_id, name, arch, created_at FROM gateways FINAL
             WHERE id = '{}' LIMIT 1 FORMAT JSON",
            escape_sql(&batch.gateway_id)
        );
        let gateway_result = self.client.query_json(&gateway_sql)?;
        let existing_gateway = gateway_result["data"]
            .as_array()
            .and_then(|rows| rows.first());
        let gw_update = json!({
            "id": batch.gateway_id,
            "site_id": existing_gateway
                .and_then(|row| row["site_id"].as_str())
                .unwrap_or("default"),
            "name": existing_gateway
                .and_then(|row| row["name"].as_str())
                .unwrap_or(&batch.gateway_id),
            "agent_token_hash": agent_token_hash,
            "agent_version": batch.agent_version,
            "arch": existing_gateway
                .and_then(|row| row["arch"].as_str())
                .unwrap_or(""),
            "kernel_version": health.map_or("", |h| h.kernel_version.as_str()),
            "openwrt_version": health.map_or("", |h| h.openwrt_version.as_str()),
            "status": "online",
            "last_seen": received_at,
            "created_at": existing_gateway
                .map_or(received_at, |row| json_i64(&row["created_at"])),
        });
        self.insert_batch_rows(batch, "gateways", &[gw_update])?;

        // 3. Batch insert into devices & device_addresses
        let mut device_rows = Vec::new();
        let mut address_rows = Vec::new();
        let mac_values = batch
            .device_observations
            .iter()
            .map(|device| format!("'{}'", to_hex(&device.mac)))
            .collect::<HashSet<_>>();
        let mut existing_devices = HashMap::<String, Value>::new();
        if !mac_values.is_empty() {
            let mac_list = mac_values.into_iter().collect::<Vec<_>>().join(", ");
            let sql = format!(
                "SELECT mac, hostname, display_name, vendor, device_type, os_family, model,
                        identity_confidence, vendor_confidence, device_type_confidence,
                        os_confidence, model_confidence, private_mac, identity_evidence_json,
                        first_seen, last_seen
                 FROM devices FINAL WHERE gateway_id = '{}' AND mac IN ({mac_list}) FORMAT JSON",
                escape_sql(&batch.gateway_id)
            );
            let result = self.client.query_json(&sql)?;
            if let Some(rows) = result["data"].as_array() {
                for row in rows {
                    if let Some(mac) = row["mac"].as_str() {
                        existing_devices.insert(mac.to_owned(), row.clone());
                    }
                }
            }
        }
        let device_ids = batch
            .device_observations
            .iter()
            .map(|device| device_id_from_mac(&device.mac).to_string())
            .collect::<HashSet<_>>();
        let mut existing_addresses = HashMap::<String, Value>::new();
        if !device_ids.is_empty() {
            let id_list = device_ids.into_iter().collect::<Vec<_>>().join(", ");
            let sql = format!(
                "SELECT device_id, ip, ip_version, first_seen, last_seen,
                        application_id, application_confidence, application_source,
                        application_last_seen
                 FROM device_addresses FINAL WHERE device_id IN ({id_list}) FORMAT JSON"
            );
            let result = self.client.query_json(&sql)?;
            if let Some(rows) = result["data"].as_array() {
                for row in rows {
                    let key = format!(
                        "{}:{}",
                        json_i64(&row["device_id"]),
                        row["ip"].as_str().unwrap_or_default()
                    );
                    existing_addresses.insert(key, row.clone());
                }
            }
        }
        for dev in &batch.device_observations {
            let seen = to_i64(dev.last_seen_unix_ms);
            let dev_id = device_id_from_mac(&dev.mac);
            let identity = device_identities
                .iter()
                .find(|identity| identity.mac == dev.mac);
            let mac_hex = to_hex(&dev.mac);
            let existing = existing_devices.get(&mac_hex);
            let existing_string = |field: &str| {
                existing
                    .and_then(|row| row.get(field))
                    .filter(|value| !value.is_null())
                    .and_then(Value::as_str)
            };
            let hostname = if dev.hostname.is_empty() {
                existing_string("hostname")
                    .map_or(Value::Null, |value| Value::String(value.to_owned()))
            } else {
                Value::String(dev.hostname.clone())
            };
            let preserve_identity = |field: &str, incoming: Option<&str>| {
                incoming
                    .or_else(|| existing_string(field))
                    .map_or(Value::Null, |value| Value::String(value.to_owned()))
            };
            let identity_confidence = identity
                .and_then(|value| value.confidence.as_deref())
                .unwrap_or("unknown");
            let first_seen = existing.map_or(seen, |row| json_i64(&row["first_seen"]));
            let last_seen = existing.map_or(seen, |row| json_i64(&row["last_seen"]).max(seen));
            device_rows.push(json!({
                "id": dev_id,
                "gateway_id": batch.gateway_id,
                "mac": mac_hex,
                "hostname": hostname,
                "display_name": existing
                    .and_then(|row| row.get("display_name"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "vendor": preserve_identity("vendor", identity.and_then(|value| value.vendor.as_deref())),
                "device_type": preserve_identity("device_type", identity.and_then(|value| value.device_type.as_deref())),
                "os_family": preserve_identity("os_family", identity.and_then(|value| value.os_family.as_deref())),
                "model": preserve_identity("model", identity.and_then(|value| value.model.as_deref())),
                "identity_confidence": identity_confidence,
                "vendor_confidence": identity.map_or(0.0, |value| value.vendor_confidence),
                "device_type_confidence": identity.map_or(0.0, |value| value.device_type_confidence),
                "os_confidence": identity.map_or(0.0, |value| value.os_confidence),
                "model_confidence": identity.map_or(0.0, |value| value.model_confidence),
                "private_mac": u8::from(identity.is_some_and(|value| value.private_mac)),
                "identity_evidence_json": identity.map_or("[]", |value| value.evidence_json.as_str()),
                "first_seen": first_seen,
                "last_seen": last_seen,
            }));
            if let Some(ver) = ip_version(&dev.ip) {
                let ip_hex = to_hex(&dev.ip);
                let address_key = format!("{dev_id}:{ip_hex}");
                let existing_address = existing_addresses.get(&address_key);
                address_rows.push(json!({
                    "device_id": dev_id,
                    "ip": ip_hex,
                    "ip_version": ver,
                    "first_seen": existing_address
                        .map_or(seen, |row| json_i64(&row["first_seen"])),
                    "last_seen": existing_address
                        .map_or(seen, |row| json_i64(&row["last_seen"]).max(seen)),
                    "application_id": existing_address
                        .and_then(|row| row["application_id"].as_str())
                        .unwrap_or(""),
                    "application_confidence": existing_address
                        .map_or(0.0, |row| json_f64(&row["application_confidence"])),
                    "application_source": existing_address
                        .and_then(|row| row["application_source"].as_str())
                        .unwrap_or(""),
                    "application_last_seen": existing_address
                        .map_or(0, |row| json_i64(&row["application_last_seen"])),
                }));
            }
        }
        self.insert_batch_rows(batch, "devices", &device_rows)?;
        self.insert_batch_rows(batch, "device_addresses", &address_rows)?;

        let newest_endpoint_seen = batch
            .flows
            .iter()
            .map(|flow| to_i64(flow.last_seen_unix_ms))
            .max()
            .unwrap_or_else(|| to_i64(batch.sent_at));
        let gateway = escape_sql(&batch.gateway_id);
        let assigned_ips_sql = format!(
            "SELECT DISTINCT ip FROM device_addresses FINAL
             WHERE application_id != ''
               AND device_id IN (SELECT id FROM devices FINAL WHERE gateway_id = '{gateway}')
             FORMAT JSON"
        );
        let assigned_ips_result = self.client.query_json(&assigned_ips_sql)?;
        let mut affected_ips = HashSet::new();
        if let Some(rows) = assigned_ips_result["data"].as_array() {
            affected_ips.extend(
                rows.iter()
                    .filter_map(|row| row["ip"].as_str().map(ToOwned::to_owned)),
            );
        }

        let mut endpoint_candidates =
            HashMap::<(String, u32, u32, String), (f64, String, i64, i64)>::new();
        let mut shared_ips = HashSet::new();
        for (index, flow) in batch.flows.iter().enumerate() {
            let Some(attribution) = attributions.get(index) else {
                continue;
            };
            let ip = to_hex(&flow.remote_ip);
            let last_seen = to_i64(flow.last_seen_unix_ms.max(batch.sent_at));
            if super::attribution_evidence_type(attribution, "self_host_shared_ip") {
                shared_ips.insert(ip.clone());
                endpoint_candidates.retain(|(candidate_ip, _, _, _), _| candidate_ip != &ip);
                affected_ips.insert(ip);
                continue;
            }
            if attribution.application_id == "unknown"
                || attribution.application_confidence < 0.9
                || matches!(flow.remote_port, 80 | 443)
                || !super::attribution_evidence_type(attribution, "self_host_application")
            {
                continue;
            }
            affected_ips.insert(ip.clone());
            let key = (
                ip,
                flow.protocol,
                flow.remote_port,
                attribution.application_id.clone(),
            );
            let source = if super::attribution_evidence_type(attribution, "service_binding") {
                "service_binding"
            } else {
                "classifier"
            }
            .to_owned();
            let expires_at = last_seen.saturating_add(24 * 60 * 60 * 1_000);
            endpoint_candidates
                .entry(key)
                .and_modify(|existing| {
                    existing.0 = existing.0.max(attribution.application_confidence);
                    existing.1.clone_from(&source);
                    existing.2 = existing.2.max(last_seen);
                    existing.3 = existing.3.max(expires_at);
                })
                .or_insert((
                    attribution.application_confidence,
                    source,
                    last_seen,
                    expires_at,
                ));
        }
        if !shared_ips.is_empty() {
            let ips = shared_ips
                .iter()
                .map(|ip| format!("'{}'", escape_sql(ip)))
                .collect::<Vec<_>>()
                .join(", ");
            self.execute_mutation(&format!(
                "ALTER TABLE self_host_endpoint_evidence DELETE
                 WHERE gateway_id = '{gateway}' AND ip IN ({ips})"
            ))?;
        }
        let candidate_ips = endpoint_candidates
            .keys()
            .map(|(ip, _, _, _)| ip.clone())
            .collect::<HashSet<_>>();
        let mut existing_endpoint_evidence = HashMap::new();
        if !candidate_ips.is_empty() {
            let ips = candidate_ips
                .iter()
                .map(|ip| format!("'{}'", escape_sql(ip)))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT ip, protocol, port, application_id, confidence, source, last_seen, expires_at
                 FROM self_host_endpoint_evidence FINAL
                 WHERE gateway_id = '{gateway}' AND ip IN ({ips}) FORMAT JSON"
            );
            let result = self.client.query_json(&sql)?;
            if let Some(rows) = result["data"].as_array() {
                for row in rows {
                    let key = (
                        row["ip"].as_str().unwrap_or_default().to_owned(),
                        json_i64(&row["protocol"]) as u32,
                        json_i64(&row["port"]) as u32,
                        row["application_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    );
                    if json_i64(&row["expires_at"]) > newest_endpoint_seen {
                        existing_endpoint_evidence.insert(key, row.clone());
                    }
                }
            }
        }
        let endpoint_rows = endpoint_candidates
            .into_iter()
            .map(|(key, (confidence, source, last_seen, expires_at))| {
                let existing = (!shared_ips.contains(&key.0))
                    .then(|| existing_endpoint_evidence.get(&key))
                    .flatten();
                json!({
                    "gateway_id": batch.gateway_id,
                    "ip": key.0,
                    "protocol": key.1,
                    "port": key.2,
                    "application_id": key.3,
                    "confidence": existing.map_or(confidence, |row| confidence.max(json_f64(&row["confidence"]))),
                    "source": source,
                    "last_seen": existing.map_or(last_seen, |row| last_seen.max(json_i64(&row["last_seen"]))),
                    "expires_at": existing.map_or(expires_at, |row| expires_at.max(json_i64(&row["expires_at"]))),
                })
            })
            .collect::<Vec<_>>();
        self.insert_batch_rows(batch, "self_host_endpoint_evidence", &endpoint_rows)?;

        let mut affected_ips = affected_ips.into_iter().collect::<Vec<_>>();
        affected_ips.sort_unstable();
        for ip in affected_ips {
            self.refresh_self_host_address_ch(&batch.gateway_id, &ip, newest_endpoint_seen)?;
        }

        let mut evidence_rows = Vec::new();
        for identity in device_identities {
            if identity.evidence.is_empty() {
                continue;
            }
            let mut accumulated = self
                .device_evidence_ch(&batch.gateway_id, &identity.mac)?
                .into_iter()
                .map(|item| {
                    (
                        (item.source.clone(), item.field.clone(), item.value.clone()),
                        item,
                    )
                })
                .collect::<HashMap<_, _>>();
            let mut changed = HashSet::new();
            for item in &identity.evidence {
                let key = (item.source.clone(), item.field.clone(), item.value.clone());
                let record =
                    accumulated
                        .entry(key.clone())
                        .or_insert_with(|| DeviceEvidenceRecord {
                            gateway_id: batch.gateway_id.clone(),
                            mac: identity.mac.clone(),
                            source: item.source.clone(),
                            field: item.field.clone(),
                            value: item.value.clone(),
                            confidence: 0.0,
                            first_seen: item.observed_at,
                            last_seen: item.observed_at,
                            hit_count: 0,
                            metadata_json: "{}".to_owned(),
                        });
                record.confidence = record.confidence.max(item.confidence.clamp(0.0, 1.0));
                record.first_seen = record.first_seen.min(item.observed_at);
                record.last_seen = record.last_seen.max(item.observed_at);
                record.hit_count = record.hit_count.saturating_add(1);
                if item.metadata_json != "{}" {
                    record.metadata_json.clone_from(&item.metadata_json);
                }
                changed.insert(key);
            }
            evidence_rows.extend(changed.into_iter().filter_map(|key| {
                accumulated.remove(&key).map(|record| {
                    json!({
                        "gateway_id": record.gateway_id,
                        "mac": to_hex(&record.mac),
                        "source": record.source,
                        "field": record.field,
                        "value": record.value,
                        "confidence": record.confidence,
                        "first_seen": to_i64(record.first_seen),
                        "last_seen": to_i64(record.last_seen),
                        "hit_count": record.hit_count,
                        "metadata_json": record.metadata_json,
                    })
                })
            }));
        }
        self.insert_batch_rows(batch, "device_evidence", &evidence_rows)?;

        // 4. Batch insert into dns_observations
        let mut dns_rows = Vec::new();
        for (i, obs) in batch.dns_observations.iter().enumerate() {
            let observed_at = to_i64(obs.observed_at_unix_ms);
            let ttl_ms = i64::from(obs.ttl_seconds).saturating_mul(1_000);
            dns_rows.push(json!({
                "id": observed_at.saturating_add(i as i64),
                "gateway_id": batch.gateway_id,
                "client_ip": to_hex(&obs.client_ip),
                "domain": obs.domain,
                "answer_ip": to_hex(&obs.answer_ip),
                "record_type": obs.record_type,
                "ttl": obs.ttl_seconds,
                "observed_at": observed_at,
                "expires_at": observed_at.saturating_add(ttl_ms),
            }));
        }
        self.insert_batch_rows(batch, "dns_observations", &dns_rows)?;
        self.invalidate_dns_cache(batch);

        // 5. Batch insert into traffic rollup minute tables
        let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
        let unknown = FlowAttribution::default();
        let mut total_rows = Vec::new();
        let mut dev_rows = Vec::new();
        let mut app_rows = Vec::new();
        let mut dom_rows = Vec::new();
        let mut dst_rows = Vec::new();
        let mut scope_rows = Vec::new();

        let mut flow_macs = batch
            .flows
            .iter()
            .filter(|flow| flow.client_mac.len() == 6)
            .map(|flow| to_hex(&flow.client_mac))
            .collect::<HashSet<_>>();
        for flow in &batch.flows {
            let key = FlowKey::from_batch(&batch.gateway_id, flow);
            if let Some(mac) = self
                .active_flows
                .get(&key)
                .map(|active| active.client_mac.as_slice())
                .filter(|mac| mac.len() == 6)
            {
                flow_macs.insert(to_hex(mac));
            }
        }
        let mut resolved_device_ids = HashMap::<String, i64>::new();
        if !flow_macs.is_empty() {
            let mac_list = flow_macs
                .iter()
                .map(|mac| format!("'{}'", escape_sql(mac)))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT mac, id FROM devices FINAL
                 WHERE gateway_id = '{}' AND mac IN ({mac_list}) FORMAT JSON",
                escape_sql(&batch.gateway_id)
            );
            let result = self.client.query_json(&sql)?;
            if let Some(rows) = result["data"].as_array() {
                for row in rows {
                    if let Some(mac) = row["mac"].as_str() {
                        resolved_device_ids.insert(mac.to_owned(), json_i64(&row["id"]));
                    }
                }
            }
        }

        for (index, flow) in batch.flows.iter().enumerate() {
            let attr = attributions.get(index).unwrap_or(&unknown);
            let upload = to_i64(flow.upload_bytes);
            let download = to_i64(flow.download_bytes);
            let packets = to_i64(flow.packets);
            let protocol_application_id = (attr.application_id == "unknown"
                && !attr.protocol_id.is_empty()
                && attr.protocol_id != "unknown")
                .then(|| format!("{PROTOCOL_APPLICATION_PREFIX}{}", attr.protocol_id));
            let (application_id, category_id) = protocol_application_id.as_deref().map_or_else(
                || (attr.application_id.as_str(), attr.category_id.as_str()),
                |id| (id, "unknown"),
            );

            total_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));

            let flow_mac = (flow.client_mac.len() == 6).then(|| to_hex(&flow.client_mac));
            let dev_id = flow_mac
                .as_ref()
                .and_then(|mac| resolved_device_ids.get(mac))
                .copied();
            if let Some(dev_id) = dev_id {
                dev_rows.push(json!({
                    "timestamp": timestamp,
                    "gateway_id": batch.gateway_id,
                    "device_id": dev_id,
                    "upload_bytes": upload,
                    "download_bytes": download,
                    "packets": packets,
                    "flow_count": 1
                }));
            }

            app_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "application_id": application_id,
                "category_id": category_id,
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));

            dom_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "domain": attr.domain.as_deref().unwrap_or("unknown"),
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));

            dst_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "remote_ip": to_hex(&flow.remote_ip),
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));
            scope_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "scope": flow.scope,
                "direction": flow.direction,
                "device_id": dev_id.unwrap_or(0),
                "application_id": attr.application_id,
                "category_id": attr.category_id,
                "domain": attr.domain.as_deref().unwrap_or("unknown"),
                "remote_ip": to_hex(&flow.remote_ip),
                "protocol": flow.protocol,
                "protocol_id": attr.protocol_id,
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));
        }

        self.insert_batch_rows(batch, "traffic_total_minute", &total_rows)?;
        self.insert_batch_rows(batch, "traffic_device_minute", &dev_rows)?;
        self.insert_batch_rows(batch, "traffic_application_minute", &app_rows)?;
        self.insert_batch_rows(batch, "traffic_domain_minute", &dom_rows)?;
        self.insert_batch_rows(batch, "traffic_destination_minute", &dst_rows)?;
        self.insert_batch_rows(batch, "traffic_scope_minute", &scope_rows)?;
        if !batch.flows.is_empty() {
            let version = rollup_marker_version(batch, received_at);
            let dirty_rows = ["total", "device", "application", "domain", "destination"]
                .into_iter()
                .map(|dimension| {
                    json!({
                        "gateway_id": batch.gateway_id,
                        "dimension": dimension,
                        "period": "minute",
                        "timestamp": timestamp,
                        "version": version,
                    })
                })
                .collect::<Vec<_>>();
            self.insert_batch_rows(batch, "traffic_rollup_dirty", &dirty_rows)?;
        }

        // 6. BATCH insert flow_sessions (Task 18.3: No single-row synchronous insert!)
        let mut session_rows = Vec::new();
        let mut staged_active_flows = self.active_flows.clone();
        for (index, flow) in batch.flows.iter().enumerate() {
            let attr = attributions.get(index).unwrap_or(&unknown);
            let key = FlowKey::from_batch(&batch.gateway_id, flow);
            let ended = flow.lifecycle == FlowLifecycle::Ended as i32;

            let current = staged_active_flows
                .entry(key.clone())
                .or_insert_with(|| ActiveFlow::new(&key, flow, attr.clone(), received_at));
            current.add(flow, attr);
            current.device_id = current
                .client_mac
                .get(..6)
                .filter(|_| current.client_mac.len() == 6)
                .and_then(|mac| resolved_device_ids.get(&to_hex(mac)))
                .copied()
                .or(current.device_id);

            let checkpoint =
                received_at.saturating_sub(current.checkpointed_at) >= FLOW_CHECKPOINT_MS;
            let ended_at = ended.then(|| flow_lifecycle_end_at(flow, received_at));
            if (ended || checkpoint) && current.last_seen_at > 0 {
                let dev_id = current.device_id;
                let current_attribution = &current.attribution;
                session_rows.push(json!({
                    "id": current.session_id,
                    "gateway_id": key.gateway_id,
                    "device_id": dev_id,
                    "ip_version": key.ip_version,
                    "protocol": key.protocol,
                    "client_ip": to_hex(&key.client_ip),
                    "client_port": key.client_port,
                    "remote_ip": to_hex(&key.remote_ip),
                    "remote_port": key.remote_port,
                    "direction": key.direction,
                    "domain": current_attribution.domain,
                    "organization_id": current_attribution.organization_id,
                    "application_id": current_attribution.application_id,
                    "category_id": current_attribution.category_id,
                    "traffic_role": current_attribution.traffic_role,
                    "protocol_id": current_attribution.protocol_id,
                    "organization_confidence": current_attribution.organization_confidence,
                    "application_confidence": current_attribution.application_confidence,
                    "protocol_confidence": current_attribution.protocol_confidence,
                    "classification_confidence": current_attribution.confidence,
                    "classification_reason": current_attribution.reason,
                    "classification_evidence_json": current_attribution.evidence_json,
                    "scope": current.scope,
                    "path_type": current.path_type,
                    "nat": current.nat,
                    "source_segment": current.source_segment,
                    "destination_segment": current.destination_segment,
                    "upload_bytes": current.upload_bytes,
                    "download_bytes": current.download_bytes,
                    "packets": current.packets,
                    "started_at": current.started_at,
                    "last_seen_at": current.last_seen_at,
                    "ended_at": ended_at,
                    "checkpointed_at": received_at,
                }));
            }
            if ended || checkpoint {
                current.checkpointed_at = received_at;
            }

            if ended {
                staged_active_flows.remove(&key);
            }
        }

        if !session_rows.is_empty() {
            let mut latest_by_id = HashMap::new();
            for row in session_rows {
                if let Some(id) = row["id"].as_str() {
                    latest_by_id.insert(id.to_owned(), row);
                }
            }
            let mut session_rows = latest_by_id.into_values().collect::<Vec<_>>();
            session_rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            self.insert_batch_rows(batch, "flow_sessions", &session_rows)?;
        }

        let mut active_device_ids = HashSet::new();
        for flow in &batch.flows {
            if flow.upload_bytes == 0 && flow.download_bytes == 0 && flow.packets == 0 {
                continue;
            }
            let Some(mac) = flow
                .client_mac
                .get(..6)
                .filter(|_| flow.client_mac.len() == 6)
            else {
                continue;
            };
            let mac_hex = to_hex(mac);
            active_device_ids.insert(
                resolved_device_ids
                    .get(&mac_hex)
                    .copied()
                    .unwrap_or_else(|| device_id_from_mac(mac)),
            );
        }
        if !active_device_ids.is_empty() {
            let mut active_device_ids = active_device_ids.into_iter().collect::<Vec<_>>();
            active_device_ids.sort_unstable();
            let activity_rows = active_device_ids
                .into_iter()
                .map(|device_id| {
                    json!({
                        "gateway_id": batch.gateway_id,
                        "device_id": device_id,
                        "last_traffic_seen": received_at,
                    })
                })
                .collect::<Vec<_>>();
            self.insert_batch_rows(batch, "device_traffic_activity", &activity_rows)?;
        }

        // Record acceptance last so a failed write can be replayed. Per-table
        // insert tokens make those replays idempotent while their dedup windows
        // retain the token.
        self.insert_batch_rows(batch, "ingest_batches", &[ingest_record])?;
        self.active_flows = staged_active_flows;

        Ok(PersistDisposition::Accepted)
    }

    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        self.resolve_domain_ch(gateway_id, client_ip, answer_ip, at_ms)
    }

    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        self.device_evidence_ch(gateway_id, mac)
    }

    fn query_total_traffic(&self, from_ms: u64, to_ms: u64) -> StorageResult<Vec<TrafficTotal>> {
        self.query_total_traffic_ch(from_ms, to_ms)
    }

    fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<()> {
        let now = to_i64(now_ms);
        let complete_hour = now.div_euclid(HOUR_MS) * HOUR_MS;
        let complete_day = now.div_euclid(DAY_MS) * DAY_MS;
        for dimension in ["total", "device", "application", "domain", "destination"] {
            self.roll_up_dimension(dimension, "minute", "hour", HOUR_MS, complete_hour)?;
            self.roll_up_dimension(dimension, "hour", "day", DAY_MS, complete_day)?;
        }
        Ok(())
    }

    fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        let now = to_i64(now_ms);
        self.execute_mutation(&format!(
            "ALTER TABLE self_host_endpoint_evidence DELETE WHERE expires_at <= {now}"
        ))?;
        if policy.flow_sessions_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.flow_sessions_days) * DAY_MS);
            self.execute_mutation(&format!(
                "ALTER TABLE flow_sessions DELETE WHERE last_seen_at < {cutoff}"
            ))?;
        }
        if policy.dns_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.dns_days) * DAY_MS);
            self.execute_mutation(&format!(
                "ALTER TABLE dns_observations DELETE WHERE expires_at < {now} OR observed_at < {cutoff}"
            ))?;
        } else {
            self.execute_mutation(&format!(
                "ALTER TABLE dns_observations DELETE WHERE expires_at < {now}"
            ))?;
        }
        self.dns_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        if policy.minute_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.minute_days) * DAY_MS);
            self.execute_mutation(&format!(
                "ALTER TABLE ingest_batches DELETE WHERE received_at < {cutoff}"
            ))?;
            for dimension in ["total", "device", "application", "domain", "destination"] {
                self.execute_mutation(&format!(
                    "ALTER TABLE traffic_{dimension}_minute DELETE WHERE timestamp < {cutoff}"
                ))?;
            }
            for table in ["traffic_rollup_dirty", "traffic_rollup_progress"] {
                self.execute_mutation(&format!(
                    "ALTER TABLE {table} DELETE WHERE period = 'minute' AND timestamp < {cutoff}"
                ))?;
            }
        }
        if policy.hour_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.hour_days) * DAY_MS);
            for dimension in ["total", "device", "application", "domain", "destination"] {
                self.execute_mutation(&format!(
                    "ALTER TABLE traffic_{dimension}_hour DELETE WHERE timestamp < {cutoff}"
                ))?;
            }
            for table in ["traffic_rollup_dirty", "traffic_rollup_progress"] {
                self.execute_mutation(&format!(
                    "ALTER TABLE {table} DELETE WHERE period = 'hour' AND timestamp < {cutoff}"
                ))?;
            }
        }
        if policy.day_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.day_days) * DAY_MS);
            for dimension in ["total", "device", "application", "domain", "destination"] {
                self.execute_mutation(&format!(
                    "ALTER TABLE traffic_{dimension}_day DELETE WHERE timestamp < {cutoff}"
                ))?;
            }
        }
        Ok(())
    }

    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        let sql = "SELECT value FROM settings FINAL WHERE key = 'retention' LIMIT 1 FORMAT JSON";
        let result = self.client.query_json(sql)?;
        if let Some(row) = result["data"].as_array().and_then(|rows| rows.first()) {
            if let Some(val_str) = row["value"].as_str() {
                if let Ok(policy) = serde_json::from_str::<RetentionPolicy>(val_str) {
                    return Ok(policy);
                }
            }
        }
        Ok(RetentionPolicy::default())
    }

    fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        let val_str = serde_json::to_string(policy).map_err(|err| {
            StorageError::Serialization(format!("failed to serialize retention policy: {err}"))
        })?;
        let record = json!({
            "key": "retention",
            "value": val_str,
            "updated_at": to_i64(now_ms),
        });
        self.client.insert_json_each_row("settings", &[record])
    }

    fn active_flow_count(&self) -> StorageResult<i64> {
        let result = self.client.query_json(
            "SELECT count() AS count FROM flow_sessions FINAL WHERE ended_at IS NULL FORMAT JSON",
        )?;
        Ok(result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| json_i64(&row["count"]))
            .unwrap_or(0))
    }

    fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        let since = to_i64(since_ms);
        let sql = format!(
            "SELECT count() AS total,
                    countIf(application_id = 'unknown') AS unknown
             FROM flow_sessions FINAL WHERE last_seen_at >= {since} FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        if let Some(row) = result["data"].as_array().and_then(|rows| rows.first()) {
            let total = json_i64(&row["total"]);
            let unknown = json_i64(&row["unknown"]);
            if total > 0 {
                return Ok(unknown as f64 / total as f64);
            }
        }
        Ok(0.0)
    }

    fn database_size_bytes(&self) -> StorageResult<i64> {
        let database = escape_sql(&self.client.config.database);
        let sql = format!(
            "SELECT sum(bytes_on_disk) AS size FROM system.parts
             WHERE active AND database = '{database}' FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        Ok(result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(|row| json_i64(&row["size"]))
            .unwrap_or(0))
    }

    fn backend_name(&self) -> &'static str {
        "clickhouse"
    }
}

fn parse_host_port(url: &str) -> StorageResult<(String, u16)> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some((h, p)) = host_port.split_once(':') {
        let port: u16 = p.parse().map_err(|_| {
            StorageError::Connection(format!("invalid port in ClickHouse URL: {p}"))
        })?;
        Ok((h.to_owned(), port))
    } else {
        Ok((host_port.to_owned(), 8123))
    }
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

fn application_group_expression(application_column: &str, protocol_column: &str) -> String {
    format!(
        "if(coalesce({application_column}, 'unknown') = 'unknown' AND coalesce(nullIf({protocol_column}, ''), 'unknown') != 'unknown', concat('{PROTOCOL_APPLICATION_PREFIX}', coalesce(nullIf({protocol_column}, ''), 'unknown')), coalesce({application_column}, 'unknown'))"
    )
}

fn is_protocol_application_id(application_id: &str) -> bool {
    application_id.starts_with(PROTOCOL_APPLICATION_PREFIX)
}

fn application_flow_filter(application_id: &str, prefix: &str) -> String {
    let application = format!("{prefix}application_id");
    let protocol = format!("coalesce(nullIf({prefix}protocol_id, ''), 'unknown')");
    if application_id == "unknown" {
        format!(
            "coalesce({application}, 'unknown') = 'unknown' AND coalesce({protocol}, 'unknown') = 'unknown'"
        )
    } else if let Some(protocol_id) = application_id.strip_prefix(PROTOCOL_APPLICATION_PREFIX) {
        format!(
            "coalesce({application}, 'unknown') = 'unknown' AND {protocol} = '{}'",
            escape_sql(protocol_id)
        )
    } else {
        format!("{application} = '{}'", escape_sql(application_id))
    }
}

fn escape_sql(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
}

fn resolve_cached_dns(observations: &[CachedDnsObservation], at: i64) -> Option<String> {
    observations
        .iter()
        .filter(|observation| observation.observed_at <= at && observation.expires_at > at)
        .max_by_key(|observation| (observation.observed_at, observation.id))
        .map(|observation| observation.domain.clone())
}

fn split_sql_statements(script: &str) -> Vec<&str> {
    script.split(';').collect()
}

#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> StorageResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(StorageError::Serialization(
            "hex string has odd length".to_owned(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| StorageError::Serialization(e.to_string()))
        })
        .collect()
}

fn device_id_from_mac(mac: &[u8]) -> i64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in mac {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash & 0x7fff_ffff_ffff_ffff) as i64
}

fn ip_version(ip: &[u8]) -> Option<u8> {
    match ip.len() {
        4 => Some(4),
        16 => Some(6),
        _ => None,
    }
}

fn to_i64<T: TryInto<i64>>(value: T) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

fn rollup_marker_version(batch: &TelemetryBatch, received_at: i64) -> i64 {
    received_at
        .saturating_mul(1_000_000)
        .saturating_add(to_i64(batch.sequence).rem_euclid(1_000_000))
        .max(2)
}

fn json_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
        .unwrap_or(0)
}

fn json_i64(value: &Value) -> i64 {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
        .unwrap_or(0)
}

fn json_f64(value: &Value) -> f64 {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
        .unwrap_or(0.0)
}

fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
                std::net::Ipv6Addr::from(octets).to_string()
            } else {
                to_hex(bytes)
            }
        }
        _ => to_hex(bytes),
    }
}

fn format_mac_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::{CachedDnsObservation, resolve_cached_dns};

    #[test]
    fn cached_dns_resolution_respects_expiry_and_newest_valid_observation() {
        let observations = vec![
            CachedDnsObservation {
                id: 1,
                domain: "old.example".to_owned(),
                observed_at: 100,
                expires_at: 400,
            },
            CachedDnsObservation {
                id: 2,
                domain: "new.example".to_owned(),
                observed_at: 200,
                expires_at: 250,
            },
        ];

        assert_eq!(
            resolve_cached_dns(&observations, 225).as_deref(),
            Some("new.example")
        );
        assert_eq!(
            resolve_cached_dns(&observations, 300).as_deref(),
            Some("old.example")
        );
        assert_eq!(resolve_cached_dns(&observations, 400), None);
    }
}
