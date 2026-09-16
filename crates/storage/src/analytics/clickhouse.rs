use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsResolution, AnalyticsStore, AnalyticsSummary,
    ApplyBatchResult, FlowPage, FlowQuery, GeoTraffic, SummaryQuery, TrafficBreakdown,
    TrafficBreakdownQuery, TrafficDelta, TrafficDimension, TrafficPoint, TrafficQuery,
};
use crate::{ClickHouseClient, ClickHouseConfig, RetentionPolicy, StorageResult};

const INITIAL_MIGRATION: &str =
    include_str!("../../../../migrations/clickhouse/analytics/0001_initial.sql");
const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;
const FACT_DIMENSIONS: &str = "gateway_id, scope, direction, transport_protocol, path_type, nat, device_id, organization_id, application_id, category_id, protocol_id, domain, remote_ip";

/// `ClickHouse` implementation of the analytics-only contract.
#[derive(Clone, Debug)]
pub struct ClickHouseAnalyticsStore {
    client: ClickHouseClient,
}

impl ClickHouseAnalyticsStore {
    /// Connects to `ClickHouse` and applies the analytics schema.
    ///
    /// # Errors
    /// Returns an error if the server is unreachable or the schema cannot be applied.
    pub fn open(config: ClickHouseConfig) -> StorageResult<Self> {
        let store = Self {
            client: ClickHouseClient::new(config),
        };
        store.client.ping()?;
        for statement in INITIAL_MIGRATION
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            store.client.execute(statement)?;
        }
        let applied = store
            .client
            .query_json("SELECT count() AS count FROM schema_migrations FINAL WHERE version = 1")?;
        if value_u64(&applied["data"][0]["count"]) == 0 {
            store.client.execute(&format!(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, {})",
                now_ms()
            ))?;
        }
        Ok(store)
    }

    fn table(resolution: AnalyticsResolution) -> &'static str {
        match resolution {
            AnalyticsResolution::Minute => "traffic_minute",
            AnalyticsResolution::Hour => "traffic_hour",
            AnalyticsResolution::Day => "traffic_day",
        }
    }

    fn summary(
        &self,
        query: &SummaryQuery,
        dimension: &'static str,
    ) -> StorageResult<Vec<AnalyticsSummary>> {
        let where_clause = summary_where(query);
        let device_id = if dimension == "device_id" {
            "device_id"
        } else {
            "toUInt64(0)"
        };
        let sql = format!(
            "SELECT toString({dimension}) AS key, {device_id} AS device_id,
                    sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes,
                    sum(packets) AS packets, sum(flow_count) AS flow_count,
                    max(timestamp) AS last_seen_at, uniqExact(device_id) AS distinct_devices,
                    argMax(domain, timestamp) AS last_domain,
                    argMax(application_id, timestamp) AS latest_application_id
             FROM {} FINAL WHERE {where_clause}
             GROUP BY {dimension}
             ORDER BY upload_bytes + download_bytes DESC, key
             LIMIT {} OFFSET {}",
            Self::table(query.resolution),
            query.limit,
            query.offset,
        );
        let response = self.client.query_json(&sql)?;
        Ok(json_rows(&response)
            .iter()
            .map(|row| AnalyticsSummary {
                key: value_string(&row["key"]),
                device_id: value_u64(&row["device_id"]),
                upload_bytes: value_u64(&row["upload_bytes"]),
                download_bytes: value_u64(&row["download_bytes"]),
                packets: value_u64(&row["packets"]),
                flow_count: value_u64(&row["flow_count"]),
                last_seen_at: value_u64(&row["last_seen_at"]),
                distinct_devices: value_u64(&row["distinct_devices"]),
                last_domain: optional_string(&row["last_domain"]),
                application_id: optional_string(&row["latest_application_id"]),
            })
            .collect())
    }
}

impl AnalyticsStore for ClickHouseAnalyticsStore {
    fn overview(&self, from: u64, to: u64) -> StorageResult<super::AnalyticsOverview> {
        let response = self.client.query_json(&format!(
            "SELECT uniqExactIf(application_id, application_id != 'unknown') AS application_count,
                    sum(upload_bytes) AS upload_bytes, sum(download_bytes) AS download_bytes
             FROM traffic_minute FINAL WHERE timestamp >= {from} AND timestamp < {to}"
        ))?;
        let row = &response["data"][0];
        Ok(super::AnalyticsOverview {
            application_count: value_u64(&row["application_count"]),
            upload_bytes: value_u64(&row["upload_bytes"]),
            download_bytes: value_u64(&row["download_bytes"]),
        })
    }

    fn apply_batch(&mut self, batch: &AnalyticsBatch) -> StorageResult<ApplyBatchResult> {
        let query = format!(
            "SELECT count() AS count FROM processed_batches FINAL
             WHERE gateway_id = {} AND boot_id = {} AND sequence = {}",
            sql_string(&batch.gateway_id),
            sql_string(&batch.boot_id),
            batch.sequence,
        );
        let response = self.client.query_json(&query)?;
        if value_u64(&response["data"][0]["count"]) > 0 {
            return Ok(ApplyBatchResult::Duplicate);
        }

        let flow_rows = batch
            .flows
            .iter()
            .map(|flow| flow_json_version(flow, batch))
            .collect::<Vec<_>>();
        self.client
            .insert_json_each_row("flow_session_versions", &flow_rows)?;

        let mut aggregates = BTreeMap::<TrafficKey, TrafficDelta>::new();
        for row in &batch.traffic {
            let mut row = row.clone();
            row.timestamp = row.timestamp / MINUTE_MS * MINUTE_MS;
            let key = TrafficKey::from(&row);
            if let Some(current) = aggregates.get_mut(&key) {
                current.upload_bytes = current.upload_bytes.saturating_add(row.upload_bytes);
                current.download_bytes = current.download_bytes.saturating_add(row.download_bytes);
                current.packets = current.packets.saturating_add(row.packets);
                current.flow_count = current.flow_count.saturating_add(row.flow_count);
            } else {
                aggregates.insert(key, row);
            }
        }
        let traffic_rows = aggregates
            .values()
            .map(|delta| {
                json!({
                    "timestamp": delta.timestamp,
                    "gateway_id": delta.gateway_id,
                    "scope": delta.scope,
                    "direction": delta.direction,
                    "transport_protocol": delta.transport_protocol,
                    "path_type": delta.path_type,
                    "nat": delta.nat,
                    "device_id": delta.device_id,
                    "organization_id": delta.organization_id,
                    "application_id": delta.application_id,
                    "category_id": delta.category_id,
                    "protocol_id": delta.protocol_id,
                    "domain": delta.domain,
                    "remote_ip": crate::to_hex(&delta.remote_ip),
                    "upload_bytes": delta.upload_bytes,
                    "download_bytes": delta.download_bytes,
                    "packets": delta.packets,
                    "flow_count": delta.flow_count,
                    "boot_id": batch.boot_id,
                    "batch_sequence": batch.sequence,
                })
            })
            .collect::<Vec<_>>();
        self.client
            .insert_json_each_row("traffic_minute", &traffic_rows)?;

        // Write the marker last. If any earlier request failed, replaying the
        // same row identities is safe because the fact tables use ReplacingMergeTree.
        self.client.execute(&format!(
            "INSERT INTO processed_batches(gateway_id, boot_id, sequence, applied_at)
             VALUES ({}, {}, {}, {})",
            sql_string(&batch.gateway_id),
            sql_string(&batch.boot_id),
            batch.sequence,
            batch.received_at,
        ))?;
        Ok(ApplyBatchResult::Applied)
    }

    fn traffic_series(&self, query: &TrafficQuery) -> StorageResult<Vec<TrafficPoint>> {
        let sql = format!(
            "SELECT timestamp, sum(upload_bytes) AS upload_bytes,
                    sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                    sum(flow_count) AS flow_count
             FROM {} FINAL WHERE {}
             GROUP BY timestamp ORDER BY timestamp",
            Self::table(query.resolution),
            traffic_where(query),
        );
        let response = self.client.query_json(&sql)?;
        Ok(json_rows(&response)
            .iter()
            .map(|row| TrafficPoint {
                timestamp: value_u64(&row["timestamp"]),
                upload_bytes: value_u64(&row["upload_bytes"]),
                download_bytes: value_u64(&row["download_bytes"]),
                packets: value_u64(&row["packets"]),
                flow_count: value_u64(&row["flow_count"]),
            })
            .collect())
    }

    fn traffic_breakdown(
        &self,
        query: &TrafficBreakdownQuery,
    ) -> StorageResult<Vec<TrafficBreakdown>> {
        let dimension = match query.dimension {
            TrafficDimension::Device => "device_id",
            TrafficDimension::Organization => "organization_id",
            TrafficDimension::Application => "application_id",
            TrafficDimension::Category => "category_id",
            TrafficDimension::Protocol => "protocol_id",
            TrafficDimension::Domain => "domain",
            TrafficDimension::Destination => "remote_ip",
            TrafficDimension::TransportProtocol => "transport_protocol",
        };
        let sql = format!(
            "SELECT toString({dimension}) AS key, sum(upload_bytes) AS upload_bytes,
                    sum(download_bytes) AS download_bytes, sum(packets) AS packets,
                    sum(flow_count) AS flow_count, max(timestamp) AS last_seen_at
             FROM {} FINAL WHERE {}
             GROUP BY {dimension}
             ORDER BY upload_bytes + download_bytes DESC, key
             LIMIT {} OFFSET {}",
            Self::table(query.traffic.resolution),
            traffic_where(&query.traffic),
            query.limit,
            query.offset,
        );
        let response = self.client.query_json(&sql)?;
        Ok(json_rows(&response)
            .iter()
            .map(|row| TrafficBreakdown {
                key: value_string(&row["key"]),
                upload_bytes: value_u64(&row["upload_bytes"]),
                download_bytes: value_u64(&row["download_bytes"]),
                packets: value_u64(&row["packets"]),
                flow_count: value_u64(&row["flow_count"]),
                last_seen_at: value_u64(&row["last_seen_at"]),
            })
            .collect())
    }

    fn flows(&self, query: &FlowQuery) -> StorageResult<FlowPage> {
        let filter = flow_where(query);
        let (sort, order) = flow_order(query);
        let response = self.client.query_json(&format!(
            "SELECT * FROM flow_sessions_latest WHERE {filter}
             ORDER BY {sort} {order}, flow_id LIMIT {} OFFSET {}",
            query.limit, query.offset
        ))?;
        let rows = json_rows(&response)
            .iter()
            .map(read_flow)
            .collect::<StorageResult<Vec<_>>>()?;
        let count = self.client.query_json(&format!(
            "SELECT count() AS count FROM flow_sessions_latest WHERE {filter}"
        ))?;
        Ok(FlowPage {
            rows,
            total: value_u64(&count["data"][0]["count"]),
        })
    }

    fn flow_by_id(&self, gateway_id: &str, flow_id: &str) -> StorageResult<Option<AnalyticsFlow>> {
        let response = self.client.query_json(&format!(
            "SELECT * FROM flow_sessions_latest
             WHERE gateway_id = {} AND flow_id = {} LIMIT 1",
            sql_string(gateway_id),
            sql_string(flow_id),
        ))?;
        json_rows(&response).first().map(read_flow).transpose()
    }

    fn flow_by_tuple(
        &self,
        identity: &super::AnalyticsFlowIdentity,
    ) -> StorageResult<Option<AnalyticsFlow>> {
        let response = self.client.query_json(&format!(
            "SELECT * FROM flow_sessions_latest
             WHERE gateway_id = {} AND ip_version = {} AND protocol = {}
               AND client_ip = {} AND client_port = {} AND remote_ip = {}
               AND remote_port = {} AND started_at = {}
             ORDER BY checkpointed_at DESC LIMIT 1",
            sql_string(&identity.gateway_id),
            identity.ip_version,
            identity.protocol,
            sql_string(&crate::to_hex(&identity.client_ip)),
            identity.client_port,
            sql_string(&crate::to_hex(&identity.remote_ip)),
            identity.remote_port,
            identity.started_at,
        ))?;
        json_rows(&response).first().map(read_flow).transpose()
    }

    fn application_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "application_id")
    }

    fn organization_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "organization_id")
    }

    fn protocol_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "protocol_id")
    }

    fn transport_protocol_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "transport_protocol")
    }

    fn category_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "category_id")
    }

    fn domain_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "domain")
    }

    fn destination_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "remote_ip")
    }

    fn client_traffic(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>> {
        self.summary(query, "device_id")
    }

    fn geo_traffic(&self, query: &SummaryQuery) -> StorageResult<Vec<GeoTraffic>> {
        let sql = format!(
            "SELECT remote_ip, sum(upload_bytes) AS upload_bytes,
                    sum(download_bytes) AS download_bytes
             FROM {} FINAL WHERE {}
             GROUP BY remote_ip ORDER BY upload_bytes + download_bytes DESC",
            Self::table(query.resolution),
            summary_where(query),
        );
        let response = self.client.query_json(&sql)?;
        json_rows(&response)
            .iter()
            .map(|row| {
                Ok(GeoTraffic {
                    remote_ip: crate::from_hex(&value_string(&row["remote_ip"]))?,
                    upload_bytes: value_u64(&row["upload_bytes"]),
                    download_bytes: value_u64(&row["download_bytes"]),
                })
            })
            .collect()
    }

    fn unknown_ratio(&self, since: u64) -> StorageResult<f64> {
        let response = self.client.query_json(&format!(
            "SELECT if(sum(upload_bytes + download_bytes) = 0, 0.0,
                       sumIf(upload_bytes + download_bytes, application_id = 'unknown')
                       / sum(upload_bytes + download_bytes)) AS ratio
             FROM traffic_minute FINAL WHERE timestamp >= {since}"
        ))?;
        Ok(value_f64(&response["data"][0]["ratio"]))
    }

    fn rollup(&mut self, now: u64) -> StorageResult<()> {
        let hour_end = now / HOUR_MS * HOUR_MS;
        let hour_start = hour_end.saturating_sub(HOUR_MS);
        self.insert_rollup("traffic_hour", "traffic_minute", hour_start, hour_end, now)?;
        let day_end = now / DAY_MS * DAY_MS;
        let day_start = day_end.saturating_sub(DAY_MS);
        self.insert_rollup("traffic_day", "traffic_hour", day_start, day_end, now)
    }

    fn run_retention(&mut self, now: u64, policy: RetentionPolicy) -> StorageResult<()> {
        let mut statements = Vec::new();
        if policy.flow_sessions_days != 0 {
            let cutoff = now.saturating_sub(u64::from(policy.flow_sessions_days) * DAY_MS);
            statements.push(format!(
                "ALTER TABLE flow_session_versions DELETE WHERE last_seen_at < {cutoff} SETTINGS mutations_sync = 1"
            ));
        }
        for (table, days) in [
            ("traffic_minute", policy.minute_days),
            ("traffic_hour", policy.hour_days),
            ("traffic_day", policy.day_days),
        ] {
            if days != 0 {
                let cutoff = now.saturating_sub(u64::from(days) * DAY_MS);
                statements.push(format!(
                    "ALTER TABLE {table} DELETE WHERE timestamp < {cutoff} SETTINGS mutations_sync = 1"
                ));
            }
        }
        for statement in statements {
            self.client.execute(&statement)?;
        }
        Ok(())
    }

    fn database_size_bytes(&self) -> StorageResult<u64> {
        let response = self.client.query_json(
            "SELECT sum(bytes_on_disk) AS bytes FROM system.parts
             WHERE active AND database = currentDatabase()
               AND table IN ('processed_batches', 'flow_session_versions', 'traffic_minute', 'traffic_hour', 'traffic_day')",
        )?;
        Ok(value_u64(&response["data"][0]["bytes"]))
    }

    fn backend_name(&self) -> &'static str {
        "clickhouse"
    }
}

impl ClickHouseAnalyticsStore {
    fn insert_rollup(
        &self,
        target: &'static str,
        source: &'static str,
        start: u64,
        end: u64,
        version: u64,
    ) -> StorageResult<()> {
        self.client.execute(&format!(
            "INSERT INTO {target}({FACT_DIMENSIONS}, timestamp, upload_bytes, download_bytes, packets, flow_count, rollup_version)
             SELECT gateway_id, scope, direction, transport_protocol, path_type, nat, device_id, organization_id,
                    application_id, category_id, protocol_id, domain, remote_ip, {start},
                    sum(upload_bytes), sum(download_bytes), sum(packets), sum(flow_count), {version}
             FROM {source} FINAL WHERE timestamp >= {start} AND timestamp < {end}
             GROUP BY {FACT_DIMENSIONS}"
        ))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TrafficKey {
    timestamp: u64,
    gateway_id: String,
    scope: u8,
    direction: u8,
    transport_protocol: u8,
    path_type: u8,
    nat: u8,
    device_id: u64,
    organization_id: String,
    application_id: String,
    category_id: String,
    protocol_id: String,
    domain: String,
    remote_ip: Vec<u8>,
}

impl From<&TrafficDelta> for TrafficKey {
    fn from(row: &TrafficDelta) -> Self {
        Self {
            timestamp: row.timestamp,
            gateway_id: row.gateway_id.clone(),
            scope: row.scope,
            direction: row.direction,
            transport_protocol: row.transport_protocol,
            path_type: row.path_type,
            nat: row.nat,
            device_id: row.device_id,
            organization_id: row.organization_id.clone(),
            application_id: row.application_id.clone(),
            category_id: row.category_id.clone(),
            protocol_id: row.protocol_id.clone(),
            domain: row.domain.clone(),
            remote_ip: row.remote_ip.clone(),
        }
    }
}

fn flow_json(flow: &AnalyticsFlow) -> Value {
    json!({
        "gateway_id": flow.gateway_id,
        "flow_id": flow.flow_id,
        "boot_id": "",
        "batch_sequence": 0,
        "device_id": flow.device_id,
        "ip_version": flow.ip_version,
        "protocol": flow.protocol,
        "client_ip": crate::to_hex(&flow.client_ip),
        "client_port": flow.client_port,
        "remote_ip": crate::to_hex(&flow.remote_ip),
        "remote_port": flow.remote_port,
        "direction": flow.direction,
        "domain": flow.domain,
        "organization_id": flow.organization_id,
        "application_id": flow.application_id,
        "category_id": flow.category_id,
        "traffic_role": flow.traffic_role,
        "protocol_id": flow.protocol_id,
        "organization_confidence": flow.organization_confidence,
        "application_confidence": flow.application_confidence,
        "protocol_confidence": flow.protocol_confidence,
        "classification_confidence": flow.classification_confidence,
        "classification_reason": flow.classification_reason,
        "classification_evidence_json": flow.classification_evidence_json,
        "upload_bytes": flow.upload_bytes,
        "download_bytes": flow.download_bytes,
        "packets": flow.packets,
        "started_at": flow.started_at,
        "last_seen_at": flow.last_seen_at,
        "ended_at": flow.ended_at,
        "checkpointed_at": flow.checkpointed_at,
        "scope": flow.scope,
        "path_type": flow.path_type,
        "nat": flow.nat,
        "source_segment": flow.source_segment,
        "destination_segment": flow.destination_segment,
    })
}

fn read_flow(row: &Value) -> StorageResult<AnalyticsFlow> {
    Ok(AnalyticsFlow {
        flow_id: value_string(&row["flow_id"]),
        gateway_id: value_string(&row["gateway_id"]),
        device_id: value_u64(&row["device_id"]),
        ip_version: u8::try_from(value_u64(&row["ip_version"])).unwrap_or_default(),
        protocol: u8::try_from(value_u64(&row["protocol"])).unwrap_or_default(),
        client_ip: crate::from_hex(&value_string(&row["client_ip"]))?,
        client_port: u16::try_from(value_u64(&row["client_port"])).unwrap_or_default(),
        remote_ip: crate::from_hex(&value_string(&row["remote_ip"]))?,
        remote_port: u16::try_from(value_u64(&row["remote_port"])).unwrap_or_default(),
        direction: u8::try_from(value_u64(&row["direction"])).unwrap_or_default(),
        domain: value_string(&row["domain"]),
        organization_id: value_string(&row["organization_id"]),
        application_id: value_string(&row["application_id"]),
        category_id: value_string(&row["category_id"]),
        traffic_role: value_string(&row["traffic_role"]),
        protocol_id: value_string(&row["protocol_id"]),
        organization_confidence: value_f64(&row["organization_confidence"]),
        application_confidence: value_f64(&row["application_confidence"]),
        protocol_confidence: value_f64(&row["protocol_confidence"]),
        classification_confidence: value_f64(&row["classification_confidence"]),
        classification_reason: value_string(&row["classification_reason"]),
        classification_evidence_json: value_string(&row["classification_evidence_json"]),
        upload_bytes: value_u64(&row["upload_bytes"]),
        download_bytes: value_u64(&row["download_bytes"]),
        packets: value_u64(&row["packets"]),
        started_at: value_u64(&row["started_at"]),
        last_seen_at: value_u64(&row["last_seen_at"]),
        ended_at: (!row["ended_at"].is_null()).then(|| value_u64(&row["ended_at"])),
        checkpointed_at: value_u64(&row["checkpointed_at"]),
        scope: u8::try_from(value_u64(&row["scope"])).unwrap_or_default(),
        path_type: u8::try_from(value_u64(&row["path_type"])).unwrap_or_default(),
        nat: u8::try_from(value_u64(&row["nat"])).unwrap_or_default(),
        source_segment: value_string(&row["source_segment"]),
        destination_segment: value_string(&row["destination_segment"]),
    })
}

fn traffic_where(query: &TrafficQuery) -> String {
    let mut filters = vec![format!(
        "timestamp >= {} AND timestamp < {}",
        query.from, query.to
    )];
    push_string_filter(&mut filters, "gateway_id", query.gateway_id.as_deref());
    push_number_filter(&mut filters, "scope", query.scope.map(u64::from));
    push_number_filter(&mut filters, "direction", query.direction.map(u64::from));
    push_number_filter(&mut filters, "device_id", query.device_id);
    push_string_filter(
        &mut filters,
        "organization_id",
        query.organization_id.as_deref(),
    );
    push_string_filter(
        &mut filters,
        "application_id",
        query.application_id.as_deref(),
    );
    push_string_filter(&mut filters, "category_id", query.category_id.as_deref());
    push_string_filter(&mut filters, "protocol_id", query.protocol_id.as_deref());
    push_string_filter(&mut filters, "domain", query.domain.as_deref());
    if let Some(remote_ip) = &query.remote_ip {
        filters.push(format!(
            "remote_ip = {}",
            sql_string(&crate::to_hex(remote_ip))
        ));
    }
    filters.join(" AND ")
}

fn summary_where(query: &SummaryQuery) -> String {
    let mut filters = vec![format!(
        "timestamp >= {} AND timestamp < {}",
        query.from, query.to
    )];
    push_string_filter(&mut filters, "gateway_id", query.gateway_id.as_deref());
    push_number_filter(&mut filters, "device_id", query.device_id);
    push_number_filter(&mut filters, "scope", query.scope.map(u64::from));
    push_number_filter(&mut filters, "direction", query.direction.map(u64::from));
    push_string_filter(
        &mut filters,
        "organization_id",
        query.organization_id.as_deref(),
    );
    push_string_filter(
        &mut filters,
        "application_id",
        query.application_id.as_deref(),
    );
    push_string_filter(&mut filters, "category_id", query.category_id.as_deref());
    push_string_filter(&mut filters, "protocol_id", query.protocol_id.as_deref());
    push_string_filter(&mut filters, "domain", query.domain.as_deref());
    if let Some(remote_ip) = &query.remote_ip {
        filters.push(format!(
            "remote_ip = {}",
            sql_string(&crate::to_hex(remote_ip))
        ));
    }
    filters.join(" AND ")
}

fn flow_where(query: &FlowQuery) -> String {
    let mut filters = vec![format!(
        "last_seen_at >= {} AND last_seen_at < {}",
        query.from, query.to
    )];
    push_string_filter(&mut filters, "gateway_id", query.gateway_id.as_deref());
    push_number_filter(&mut filters, "device_id", query.device_id);
    push_string_filter(
        &mut filters,
        "application_id",
        query.application_id.as_deref(),
    );
    push_string_filter(
        &mut filters,
        "organization_id",
        query.organization_id.as_deref(),
    );
    push_string_filter(&mut filters, "protocol_id", query.protocol_id.as_deref());
    push_string_filter(&mut filters, "domain", query.domain.as_deref());
    if let Some(value) = &query.client_ip {
        filters.push(format!("client_ip = {}", sql_string(&crate::to_hex(value))));
    }
    if let Some(value) = &query.remote_ip {
        filters.push(format!("remote_ip = {}", sql_string(&crate::to_hex(value))));
    }
    if let Some(value) = &query.any_ip {
        let address = sql_string(&crate::to_hex(value));
        filters.push(format!("(client_ip = {address} OR remote_ip = {address})"));
    }
    push_number_filter(
        &mut filters,
        "protocol",
        query.transport_protocol.map(u64::from),
    );
    push_number_filter(&mut filters, "direction", query.direction.map(u64::from));
    push_number_filter(&mut filters, "scope", query.scope.map(u64::from));
    push_number_filter(&mut filters, "path_type", query.path_type.map(u64::from));
    push_number_filter(&mut filters, "nat", query.nat.map(u64::from));
    if let Some(port) = query.port {
        filters.push(format!("(client_port = {port} OR remote_port = {port})"));
    }
    if let Some(search) = query.search.as_deref().filter(|value| !value.is_empty()) {
        let escaped = search
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = sql_string(&format!("%{escaped}%"));
        filters.push(format!("(positionCaseInsensitive(domain, {pattern}) > 0 OR positionCaseInsensitive(application_id, {pattern}) > 0 OR positionCaseInsensitive(organization_id, {pattern}) > 0 OR positionCaseInsensitive(protocol_id, {pattern}) > 0)"));
    }
    if let Some(sort_value) = query.after_sort_value {
        let column = flow_sort_column(query);
        let cmp = if query.descending { "<" } else { ">" };
        let id_cmp = if query.descending { ">" } else { "<" };
        let flow_id = sql_string(query.after_flow_id.as_deref().unwrap_or(""));
        filters.push(format!(
            "({column} {cmp} {sort_value} OR ({column} = {sort_value} AND flow_id {id_cmp} {flow_id}))"
        ));
    }
    filters.join(" AND ")
}

fn flow_sort_column(query: &FlowQuery) -> &'static str {
    match query.sort_by {
        super::FlowSort::LastSeen => "last_seen_at",
        super::FlowSort::Started => "started_at",
        super::FlowSort::UploadBytes => "upload_bytes",
        super::FlowSort::DownloadBytes => "download_bytes",
        super::FlowSort::TotalBytes => "upload_bytes + download_bytes",
        super::FlowSort::Duration => "if(isNull(ended_at), last_seen_at, ended_at) - started_at",
    }
}

fn flow_order(query: &FlowQuery) -> (&'static str, &'static str) {
    let column = match query.sort_by {
        super::FlowSort::LastSeen => "last_seen_at",
        super::FlowSort::Started => "started_at",
        super::FlowSort::UploadBytes => "upload_bytes",
        super::FlowSort::DownloadBytes => "download_bytes",
        super::FlowSort::TotalBytes => "upload_bytes + download_bytes",
        super::FlowSort::Duration => "if(isNull(ended_at), last_seen_at, ended_at) - started_at",
    };
    (column, if query.descending { "DESC" } else { "ASC" })
}

fn push_string_filter(filters: &mut Vec<String>, column: &str, value: Option<&str>) {
    if let Some(value) = value {
        filters.push(format!("{column} = {}", sql_string(value)));
    }
}

fn push_number_filter(filters: &mut Vec<String>, column: &str, value: Option<u64>) {
    if let Some(value) = value {
        filters.push(format!("{column} = {value}"));
    }
}

fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn json_rows(value: &Value) -> &[Value] {
    value["data"].as_array().map_or(&[], Vec::as_slice)
}

fn value_string(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn value_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|raw| raw.parse().ok()))
        .unwrap_or(0)
}

fn value_f64(value: &Value) -> f64 {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|raw| raw.parse().ok()))
        .unwrap_or(0.0)
}

fn optional_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn flow_json_version(flow: &AnalyticsFlow, batch: &AnalyticsBatch) -> Value {
    let mut value = flow_json(flow);
    value["boot_id"] = json!(batch.boot_id);
    value["batch_sequence"] = json!(batch.sequence);
    value
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}
