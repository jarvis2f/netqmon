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
use std::time::Duration;

use netqmon_protocol::v1::{FlowLifecycle, TelemetryBatch};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ActiveFlow, DeviceEvidenceRecord, DeviceIdentityUpdate, FlowAttribution, FlowKey,
    GatewayRecord, PersistDisposition, RetentionPolicy, SessionRecord, StorageBackend,
    StorageError, StorageResult, TrafficTotal, UserRecord,
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
const MIGRATIONS: [(u32, &str); 2] = [(1, INITIAL_MIGRATION), (2, PROTOCOL_MIGRATION)];
const MINUTE_MS: i64 = 60 * 1_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const FLOW_CHECKPOINT_MS: i64 = 5 * MINUTE_MS;

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
        let query = format!("INSERT INTO {table} FORMAT JSONEachRow");
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
}

impl ClickHouseStorage {
    pub(crate) fn reclassify_flow(
        &mut self,
        gateway: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
    ) -> StorageResult<()> {
        for (key, current) in &mut self.active_flows {
            if crate::sample_matches(key, current, gateway, flow)
                && attribution.protocol_confidence >= current.attribution.protocol_confidence
            {
                crate::apply_late_protocol(&mut current.attribution, attribution);
            }
        }
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
        let storage = Self {
            client,
            active_flows: HashMap::new(),
        };
        storage.migrate()?;
        Ok(storage)
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
        let client_ip_hex = to_hex(client_ip);
        let answer_ip_hex = to_hex(answer_ip);
        let at = to_i64(at_ms);
        let sql = format!(
            "SELECT domain FROM dns_observations WHERE gateway_id = '{gateway}' AND client_ip = '{client_ip_hex}' AND answer_ip = '{answer_ip_hex}' AND observed_at <= {at} AND expires_at > {at} ORDER BY observed_at DESC, id DESC LIMIT 1 FORMAT JSON",
            gateway = escape_sql(gateway_id),
        );
        let result = self.client.query_json(&sql)?;
        let domain = result["data"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row["domain"].as_str())
            .map(ToOwned::to_owned);
        Ok(domain)
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
        let dev_count_sql = "SELECT count() AS c FROM devices FORMAT JSON";
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

        let app_count_sql = "SELECT count(distinct application_id) AS c FROM traffic_application_minute FORMAT JSON";
        let app_res = self.client.query_json(app_count_sql)?;
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

    /// Queries paginated devices/clients.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query error.
    pub fn query_clients(&self, limit: u32, offset: u64) -> StorageResult<(Vec<Value>, u64)> {
        let count_sql = "SELECT count() AS c FROM devices FORMAT JSON";
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
            "SELECT d.id AS id, d.gateway_id AS gateway_id, d.mac AS mac, d.hostname AS hostname, d.display_name AS display_name, d.vendor AS vendor, d.first_seen AS first_seen, d.last_seen AS last_seen, coalesce(sum(t.upload_bytes), 0) AS up, coalesce(sum(t.download_bytes), 0) AS down FROM devices AS d FINAL LEFT JOIN traffic_device_minute AS t ON d.id = t.device_id GROUP BY d.id, d.gateway_id, d.mac, d.hostname, d.display_name, d.vendor, d.first_seen, d.last_seen ORDER BY last_seen DESC LIMIT {limit} OFFSET {offset} FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        let mut items = Vec::new();
        if let Some(rows) = res["data"].as_array() {
            for r in rows {
                let id = r["id"]
                    .as_i64()
                    .or_else(|| r["id"].as_str().and_then(|s| s.parse().ok()))
                    .unwrap_or(0);
                let mac_hex = r["mac"].as_str().unwrap_or("");
                let mac_bytes = from_hex(mac_hex).unwrap_or_default();
                let mac_str = format_mac_bytes(&mac_bytes);

                let ip_sql = format!(
                    "SELECT ip FROM device_addresses FINAL WHERE device_id = {id} FORMAT JSON"
                );
                let mut ips = Vec::new();
                let mut ip_hexes = Vec::new();
                if let Ok(ip_res) = self.client.query_json(&ip_sql) {
                    if let Some(ip_rows) = ip_res["data"].as_array() {
                        for ir in ip_rows {
                            if let Some(ip_hex) = ir["ip"].as_str() {
                                if let Ok(ip_b) = from_hex(ip_hex) {
                                    ips.push(format_ip_bytes(&ip_b));
                                    ip_hexes.push(ip_hex.to_owned());
                                }
                            }
                        }
                    }
                }

                let self_host_application = if ip_hexes.len() == 1 {
                    self.self_host_application_ch(
                        r["gateway_id"].as_str().unwrap_or_default(),
                        &ip_hexes[0],
                    )?
                } else {
                    None
                };
                items.push(json!({
                    "id": id,
                    "mac": mac_str,
                    "ip": ips.first().cloned(),
                    "hostname": r["hostname"].as_str(),
                    "display_name": r["display_name"].as_str(),
                    "vendor": r["vendor"].as_str(),
                    "first_seen": r["first_seen"].as_i64().or_else(|| r["first_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "last_seen": r["last_seen"].as_i64().or_else(|| r["last_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "active_flows": 0,
                    "upload_bytes": r["up"].as_i64().or_else(|| r["up"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "download_bytes": r["down"].as_i64().or_else(|| r["down"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                    "self_host_application": self_host_application,
                }));
            }
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
            "SELECT id, gateway_id, mac, hostname, display_name, vendor, first_seen, last_seen FROM devices FINAL WHERE id = {id} LIMIT 1 FORMAT JSON"
        );
        let res = self.client.query_json(&sql)?;
        if let Some(row) = res["data"].as_array().and_then(|a| a.first()) {
            let mac_hex = row["mac"].as_str().unwrap_or("");
            let mac_bytes = from_hex(mac_hex).unwrap_or_default();
            let mac_str = format_mac_bytes(&mac_bytes);

            let ip_sql = format!(
                "SELECT ip, ip_version, first_seen, last_seen FROM device_addresses FINAL WHERE device_id = {id} FORMAT JSON"
            );
            let mut addrs = Vec::new();
            if let Ok(ip_res) = self.client.query_json(&ip_sql) {
                if let Some(rows) = ip_res["data"].as_array() {
                    for r in rows {
                        if let Some(ip_hex) = r["ip"].as_str() {
                            if let Ok(ip_b) = from_hex(ip_hex) {
                                addrs.push(json!({
                                    "ip": format_ip_bytes(&ip_b),
                                    "ip_version": r["ip_version"].as_u64().or_else(|| r["ip_version"].as_str().and_then(|s| s.parse().ok())).unwrap_or(4),
                                    "first_seen": r["first_seen"].as_i64().or_else(|| r["first_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                                    "last_seen": r["last_seen"].as_i64().or_else(|| r["last_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                                    "self_host_application": self.self_host_application_ch(
                                        row["gateway_id"].as_str().unwrap_or_default(),
                                        ip_hex,
                                    )?,
                                }));
                            }
                        }
                    }
                }
            }

            let self_host_application = if addrs.len() == 1 {
                addrs[0].get("self_host_application").cloned()
            } else {
                None
            };
            Ok(Some(json!({
                "id": id,
                "mac": mac_str,
                "hostname": row["hostname"].as_str(),
                "display_name": row["display_name"].as_str(),
                "vendor": row["vendor"].as_str(),
                "first_seen": row["first_seen"].as_i64().or_else(|| row["first_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                "last_seen": row["last_seen"].as_i64().or_else(|| row["last_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
                "addresses": addrs,
                "active_flows": 0,
                "self_host_application": self_host_application,
            })))
        } else {
            Ok(None)
        }
    }

    fn self_host_application_ch(&self, gateway_id: &str, ip: &str) -> StorageResult<Option<Value>> {
        let sql = format!(
            "SELECT application_id, max(confidence) AS confidence, argMax(source, last_seen) AS source, max(last_seen) AS endpoint_last_seen FROM self_host_endpoint_evidence FINAL WHERE gateway_id = '{}' AND ip = '{}' AND expires_at > toUnixTimestamp64Milli(now64(3)) GROUP BY application_id FORMAT JSON",
            escape_sql(gateway_id),
            escape_sql(ip)
        );
        let result = self.client.query_json(&sql)?;
        let rows = result["data"].as_array().cloned().unwrap_or_default();
        if rows.len() != 1 || rows[0]["application_id"].as_str() == Some("__shared__") {
            return Ok(None);
        }
        let row = &rows[0];
        Ok(row["application_id"].as_str().map(|application_id| {
            json!({
                "application_id": application_id,
                "confidence": row["confidence"].as_f64().or_else(|| row["confidence"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0.0),
                "source": row["source"].as_str(),
                "last_seen": row["endpoint_last_seen"].as_i64().or_else(|| row["endpoint_last_seen"].as_str().and_then(|value| value.parse().ok())).unwrap_or(0),
                "role": "server",
            })
        }))
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
            "SELECT domain, sum(upload_bytes) AS up, sum(download_bytes) AS down, sum(packets) AS pkts, sum(flow_count) AS flows FROM traffic_domain_minute GROUP BY domain ORDER BY down DESC LIMIT {limit} OFFSET {offset} FORMAT JSON"
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
                    "client_count": 0,
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
        let sql = "SELECT count() AS count FROM users FORMAT JSON";
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
        self.client.insert_json_each_row("auth_sessions", &[record])
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
        let sql = format!("ALTER TABLE auth_sessions DELETE WHERE token_hash = '{hex}'");
        self.client.execute(&sql)?;
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
            batch.sequence
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

        // 1. Batch insert into ingest_batches
        let ingest_record = json!({
            "gateway_id": batch.gateway_id,
            "boot_id": batch.boot_id,
            "sequence": batch.sequence as i64,
            "received_at": received_at,
        });
        self.client
            .insert_json_each_row("ingest_batches", &[ingest_record])?;

        // 2. Gateway record update
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
        let gw_update = json!({
            "id": batch.gateway_id,
            "site_id": "default",
            "name": batch.gateway_id,
            "agent_token_hash": agent_token_hash,
            "agent_version": batch.agent_version,
            "arch": "",
            "kernel_version": health.map_or("", |h| h.kernel_version.as_str()),
            "openwrt_version": health.map_or("", |h| h.openwrt_version.as_str()),
            "status": "online",
            "last_seen": received_at,
            "created_at": received_at,
        });
        self.client.insert_json_each_row("gateways", &[gw_update])?;

        // 3. Batch insert into devices & device_addresses
        let mut device_rows = Vec::new();
        let mut address_rows = Vec::new();
        for dev in &batch.device_observations {
            let seen = to_i64(dev.last_seen_unix_ms);
            let dev_id = device_id_from_mac(&dev.mac);
            let identity = device_identities
                .iter()
                .find(|identity| identity.mac == dev.mac);
            device_rows.push(json!({
                "id": dev_id,
                "gateway_id": batch.gateway_id,
                "mac": to_hex(&dev.mac),
                "hostname": if dev.hostname.is_empty() { Value::Null } else { Value::String(dev.hostname.clone()) },
                "display_name": Value::Null,
                "vendor": identity.and_then(|value| value.vendor.as_ref()).map_or(Value::Null, |value| Value::String(value.clone())),
                "device_type": identity.and_then(|value| value.device_type.as_ref()).map_or(Value::Null, |value| Value::String(value.clone())),
                "os_family": identity.and_then(|value| value.os_family.as_ref()).map_or(Value::Null, |value| Value::String(value.clone())),
                "model": identity.and_then(|value| value.model.as_ref()).map_or(Value::Null, |value| Value::String(value.clone())),
                "identity_confidence": identity.and_then(|value| value.confidence.as_deref()).unwrap_or("unknown"),
                "vendor_confidence": identity.map_or(0.0, |value| value.vendor_confidence),
                "device_type_confidence": identity.map_or(0.0, |value| value.device_type_confidence),
                "os_confidence": identity.map_or(0.0, |value| value.os_confidence),
                "model_confidence": identity.map_or(0.0, |value| value.model_confidence),
                "private_mac": u8::from(identity.is_some_and(|value| value.private_mac)),
                "identity_evidence_json": identity.map_or("[]", |value| value.evidence_json.as_str()),
                "first_seen": seen,
                "last_seen": seen,
            }));
            if let Some(ver) = ip_version(&dev.ip) {
                address_rows.push(json!({
                    "device_id": dev_id,
                    "ip": to_hex(&dev.ip),
                    "ip_version": ver,
                    "first_seen": seen,
                    "last_seen": seen,
                }));
            }
        }
        self.client.insert_json_each_row("devices", &device_rows)?;
        self.client
            .insert_json_each_row("device_addresses", &address_rows)?;

        let mut endpoint_rows = Vec::new();
        for (index, flow) in batch.flows.iter().enumerate() {
            let Some(attribution) = attributions.get(index) else {
                continue;
            };
            let last_seen = to_i64(flow.last_seen_unix_ms.max(batch.sent_at));
            if super::attribution_evidence_type(attribution, "self_host_shared_ip") {
                endpoint_rows.push(json!({
                    "gateway_id": batch.gateway_id,
                    "ip": to_hex(&flow.remote_ip),
                    "protocol": flow.protocol,
                    "port": flow.remote_port,
                    "application_id": "__shared__",
                    "confidence": 1.0,
                    "source": "endpoint_consensus",
                    "last_seen": last_seen,
                    "expires_at": last_seen.saturating_add(24 * 60 * 60 * 1_000),
                }));
                continue;
            }
            if attribution.application_id == "unknown"
                || attribution.application_confidence < 0.9
                || matches!(flow.remote_port, 80 | 443)
                || !super::attribution_evidence_type(attribution, "self_host_application")
            {
                continue;
            }
            endpoint_rows.push(json!({
                "gateway_id": batch.gateway_id,
                "ip": to_hex(&flow.remote_ip),
                "protocol": flow.protocol,
                "port": flow.remote_port,
                "application_id": attribution.application_id,
                "confidence": attribution.application_confidence,
                "source": if super::attribution_evidence_type(attribution, "service_binding") { "service_binding" } else { "classifier" },
                "last_seen": last_seen,
                "expires_at": last_seen.saturating_add(24 * 60 * 60 * 1_000),
            }));
        }
        self.client
            .insert_json_each_row("self_host_endpoint_evidence", &endpoint_rows)?;

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
        self.client
            .insert_json_each_row("device_evidence", &evidence_rows)?;

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
        self.client
            .insert_json_each_row("dns_observations", &dns_rows)?;

        // 5. Batch insert into traffic rollup minute tables
        let timestamp = to_i64(batch.sent_at) / MINUTE_MS * MINUTE_MS;
        let unknown = FlowAttribution::default();
        let mut total_rows = Vec::new();
        let mut dev_rows = Vec::new();
        let mut app_rows = Vec::new();
        let mut dom_rows = Vec::new();
        let mut dst_rows = Vec::new();
        let mut scope_rows = Vec::new();

        for (index, flow) in batch.flows.iter().enumerate() {
            let attr = attributions.get(index).unwrap_or(&unknown);
            let upload = to_i64(flow.upload_bytes);
            let download = to_i64(flow.download_bytes);
            let packets = to_i64(flow.packets);

            total_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));

            let dev_id = device_id_from_mac(&flow.client_mac);
            dev_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "device_id": dev_id,
                "upload_bytes": upload,
                "download_bytes": download,
                "packets": packets,
                "flow_count": 1
            }));

            app_rows.push(json!({
                "timestamp": timestamp,
                "gateway_id": batch.gateway_id,
                "application_id": attr.application_id,
                "category_id": attr.category_id,
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
                "device_id": device_id_from_mac(&flow.client_mac),
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

        self.client
            .insert_json_each_row("traffic_total_minute", &total_rows)?;
        self.client
            .insert_json_each_row("traffic_device_minute", &dev_rows)?;
        self.client
            .insert_json_each_row("traffic_application_minute", &app_rows)?;
        self.client
            .insert_json_each_row("traffic_domain_minute", &dom_rows)?;
        self.client
            .insert_json_each_row("traffic_destination_minute", &dst_rows)?;
        self.client
            .insert_json_each_row("traffic_scope_minute", &scope_rows)?;

        // 6. BATCH insert flow_sessions (Task 18.3: No single-row synchronous insert!)
        let mut session_rows = Vec::new();
        for (index, flow) in batch.flows.iter().enumerate() {
            let attr = attributions.get(index).unwrap_or(&unknown);
            let key = FlowKey::from_batch(&batch.gateway_id, flow);
            let ended = flow.lifecycle == FlowLifecycle::Ended as i32;

            let current = self
                .active_flows
                .entry(key.clone())
                .or_insert_with(|| ActiveFlow::new(flow, attr.clone(), received_at));
            current.add(flow, attr);

            let checkpoint =
                received_at.saturating_sub(current.checkpointed_at) >= FLOW_CHECKPOINT_MS;
            if ended || checkpoint {
                let dev_id = device_id_from_mac(&current.client_mac);
                session_rows.push(json!({
                    "id": key.id(),
                    "gateway_id": key.gateway_id,
                    "device_id": dev_id,
                    "ip_version": key.ip_version,
                    "protocol": key.protocol,
                    "client_ip": to_hex(&key.client_ip),
                    "client_port": key.client_port,
                    "remote_ip": to_hex(&key.remote_ip),
                    "remote_port": key.remote_port,
                    "direction": key.direction,
                    "domain": attr.domain,
                    "organization_id": attr.organization_id,
                    "application_id": attr.application_id,
                    "category_id": attr.category_id,
                    "traffic_role": attr.traffic_role,
                    "protocol_id": attr.protocol_id,
                    "organization_confidence": attr.organization_confidence,
                    "application_confidence": attr.application_confidence,
                    "protocol_confidence": attr.protocol_confidence,
                    "classification_confidence": attr.confidence,
                    "classification_reason": attr.reason,
                    "classification_evidence_json": attr.evidence_json,
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
                    "ended_at": if ended { Value::from(received_at) } else { Value::Null },
                    "checkpointed_at": received_at,
                }));
                current.checkpointed_at = received_at;
            }

            if ended {
                self.active_flows.remove(&key);
            }
        }

        if !session_rows.is_empty() {
            self.client
                .insert_json_each_row("flow_sessions", &session_rows)?;
        }

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

    fn roll_up_hour_and_day(&mut self, _now_ms: u64) -> StorageResult<()> {
        // Roll up minute to hour
        let sql_hour = "INSERT INTO traffic_total_hour SELECT toStartOfHour(toDateTime(timestamp / 1000)) * 1000 AS timestamp, gateway_id, sum(upload_bytes), sum(download_bytes), sum(packets), sum(flow_count) FROM traffic_total_minute GROUP BY timestamp, gateway_id";
        let _ = self.client.execute(sql_hour);
        // Roll up hour to day
        let sql_day = "INSERT INTO traffic_total_day SELECT toStartOfDay(toDateTime(timestamp / 1000)) * 1000 AS timestamp, gateway_id, sum(upload_bytes), sum(download_bytes), sum(packets), sum(flow_count) FROM traffic_total_hour GROUP BY timestamp, gateway_id";
        let _ = self.client.execute(sql_day);
        Ok(())
    }

    fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        let now = to_i64(now_ms);
        if policy.flow_sessions_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.flow_sessions_days) * DAY_MS);
            let sql = format!("ALTER TABLE flow_sessions DELETE WHERE last_seen_at < {cutoff}");
            let _ = self.client.execute(&sql);
        }
        if policy.dns_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.dns_days) * DAY_MS);
            let sql = format!("ALTER TABLE dns_observations DELETE WHERE observed_at < {cutoff}");
            let _ = self.client.execute(&sql);
        }
        if policy.minute_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.minute_days) * DAY_MS);
            let sql = format!("ALTER TABLE traffic_total_minute DELETE WHERE timestamp < {cutoff}");
            let _ = self.client.execute(&sql);
        }
        if policy.hour_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.hour_days) * DAY_MS);
            let sql = format!("ALTER TABLE traffic_total_hour DELETE WHERE timestamp < {cutoff}");
            let _ = self.client.execute(&sql);
        }
        if policy.day_days > 0 {
            let cutoff = now.saturating_sub(i64::from(policy.day_days) * DAY_MS);
            let sql = format!("ALTER TABLE traffic_total_day DELETE WHERE timestamp < {cutoff}");
            let _ = self.client.execute(&sql);
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
        Ok(self.active_flows.len() as i64)
    }

    fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        let since = to_i64(since_ms);
        let sql = format!(
            "SELECT sum(upload_bytes + download_bytes) AS total, sum(if(application_id = 'unknown' OR application_id = '', upload_bytes + download_bytes, 0)) AS unknown FROM traffic_application_minute WHERE timestamp >= {since} FORMAT JSON"
        );
        let result = self.client.query_json(&sql)?;
        if let Some(row) = result["data"].as_array().and_then(|rows| rows.first()) {
            let total = row["total"]
                .as_f64()
                .or_else(|| row["total"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0.0);
            let unknown = row["unknown"]
                .as_f64()
                .or_else(|| row["unknown"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0.0);
            if total > 0.0 {
                return Ok(unknown / total);
            }
        }
        Ok(0.0)
    }

    fn database_size_bytes(&self) -> StorageResult<i64> {
        let sql = "SELECT sum(bytes_on_disk) AS size FROM system.parts WHERE active FORMAT JSON";
        if let Ok(result) = self.client.query_json(sql) {
            if let Some(row) = result["data"].as_array().and_then(|rows| rows.first()) {
                if let Some(size) = row["size"]
                    .as_i64()
                    .or_else(|| row["size"].as_str().and_then(|s| s.parse().ok()))
                {
                    return Ok(size);
                }
            }
        }
        Ok(1024 * 1024)
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

fn escape_sql(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
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

fn json_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
        .unwrap_or(0)
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
