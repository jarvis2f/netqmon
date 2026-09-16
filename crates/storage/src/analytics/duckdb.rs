use std::collections::BTreeMap;
use std::path::Path;

use duckdb::{Connection, params};

use super::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsResolution, AnalyticsStore, AnalyticsSummary,
    ApplyBatchResult, FlowPage, FlowQuery, GeoTraffic, SummaryQuery, TrafficBreakdown,
    TrafficBreakdownQuery, TrafficDelta, TrafficDimension, TrafficPoint, TrafficQuery,
};
use crate::{RetentionPolicy, StorageError, StorageResult};

const INITIAL_MIGRATION: &str = include_str!("../../../../migrations/duckdb/0001_initial.sql");
const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

/// `DuckDB` implementation of the historical analytics contract.
#[derive(Debug)]
pub struct DuckDbAnalyticsStore {
    connection: Connection,
}

impl DuckDbAnalyticsStore {
    /// Opens or creates a persistent `DuckDB` analytics database.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let connection = Connection::open(path).map_err(|error| duckdb_error(&error))?;
        Self::from_connection(connection)
    }

    /// Opens an in-memory `DuckDB` analytics database.
    ///
    /// # Errors
    /// Returns an error if the database cannot be initialized.
    pub fn open_in_memory() -> StorageResult<Self> {
        let connection = Connection::open_in_memory().map_err(|error| duckdb_error(&error))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> StorageResult<Self> {
        connection
            .execute_batch(INITIAL_MIGRATION)
            .map_err(|error| duckdb_error(&error))?;
        connection
            .execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
                [now_ms()],
            )
            .map_err(|error| duckdb_error(&error))?;
        Ok(Self { connection })
    }

    fn resolution_table(resolution: AnalyticsResolution) -> &'static str {
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
        let table = Self::resolution_table(query.resolution);
        let group = match dimension {
            "application_id" => "application_id",
            "organization_id" => "organization_id",
            "protocol_id" => "protocol_id",
            "category_id" => "category_id",
            "transport_protocol" => "transport_protocol",
            "domain" => "domain",
            "remote_ip" => "remote_ip",
            "device_id" => "device_id",
            _ => unreachable!("summary dimension is a fixed internal identifier"),
        };
        let key_expression = if group == "remote_ip" {
            "hex(remote_ip)".to_owned()
        } else {
            format!("CAST({group} AS VARCHAR)")
        };
        let device_expression = if group == "device_id" {
            "device_id"
        } else {
            "CAST(0 AS UBIGINT)"
        };
        let sql = format!(
            "SELECT {key_expression}, {device_expression},
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count), MAX(timestamp),
                    COUNT(DISTINCT device_id), arg_max(domain, timestamp),
                    arg_max(application_id, timestamp)
             FROM {table}
             WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR gateway_id = ?3)
               AND (?4 IS NULL OR device_id = ?4)
               AND (?5 IS NULL OR scope = ?5)
               AND (?6 IS NULL OR direction = ?6)
               AND (?7 IS NULL OR organization_id = ?7)
               AND (?8 IS NULL OR application_id = ?8)
               AND (?9 IS NULL OR category_id = ?9)
               AND (?10 IS NULL OR protocol_id = ?10)
               AND (?11 IS NULL OR domain = ?11)
               AND (?12 IS NULL OR remote_ip = ?12)
             GROUP BY {group}
             ORDER BY SUM(upload_bytes) + SUM(download_bytes) DESC, {group}
             LIMIT ?13 OFFSET ?14"
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| duckdb_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    query.from,
                    query.to,
                    query.gateway_id,
                    query.device_id,
                    query.scope,
                    query.direction,
                    query.organization_id,
                    query.application_id,
                    query.category_id,
                    query.protocol_id,
                    query.domain,
                    query.remote_ip,
                    query.limit,
                    query.offset,
                ],
                |row| {
                    Ok(AnalyticsSummary {
                        key: row.get(0)?,
                        device_id: row.get(1)?,
                        upload_bytes: row.get(2)?,
                        download_bytes: row.get(3)?,
                        packets: row.get(4)?,
                        flow_count: row.get(5)?,
                        last_seen_at: row.get(6)?,
                        distinct_devices: row.get(7)?,
                        last_domain: row.get(8)?,
                        application_id: row.get(9)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .map_err(|error| duckdb_error(&error))
    }

    fn insert_rollup_bucket(
        &mut self,
        target: &'static str,
        source: &'static str,
        bucket_start: u64,
        bucket_end: u64,
    ) -> StorageResult<()> {
        self.connection
            .execute(
                &format!(
                    "INSERT INTO {target}(
                        timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                        organization_id, application_id, category_id, protocol_id, domain, remote_ip,
                        upload_bytes, download_bytes, packets, flow_count
                     )
                     SELECT ?1, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                            organization_id, application_id, category_id, protocol_id, domain, remote_ip,
                            SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
                     FROM {source}
                     WHERE timestamp >= ?2 AND timestamp < ?3
                     GROUP BY gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                              organization_id, application_id, category_id, protocol_id, domain, remote_ip
                     ON CONFLICT DO UPDATE SET
                        upload_bytes = excluded.upload_bytes,
                        download_bytes = excluded.download_bytes,
                        packets = excluded.packets,
                        flow_count = excluded.flow_count"
                ),
                params![bucket_start, bucket_start, bucket_end],
            )
            .map_err(|error| duckdb_error(&error))?;
        Ok(())
    }
}

impl AnalyticsStore for DuckDbAnalyticsStore {
    fn overview(&self, from: u64, to: u64) -> StorageResult<super::AnalyticsOverview> {
        self.connection
            .query_row(
                "SELECT COUNT(DISTINCT CASE WHEN application_id != 'unknown' THEN application_id END),
                        COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
                 FROM traffic_minute WHERE timestamp >= ?1 AND timestamp < ?2",
                params![from, to],
                |row| {
                    Ok(super::AnalyticsOverview {
                        application_count: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))
    }

    fn apply_batch(&mut self, batch: &AnalyticsBatch) -> StorageResult<ApplyBatchResult> {
        let tx = self
            .connection
            .transaction()
            .map_err(|error| duckdb_error(&error))?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO processed_batches(gateway_id, boot_id, sequence, applied_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    batch.gateway_id,
                    batch.boot_id,
                    batch.sequence,
                    batch.received_at
                ],
            )
            .map_err(|error| duckdb_error(&error))?;
        if inserted == 0 {
            tx.rollback().map_err(|error| duckdb_error(&error))?;
            return Ok(ApplyBatchResult::Duplicate);
        }

        for flow in &batch.flows {
            insert_flow_version(&tx, flow, &batch.boot_id, batch.sequence)?;
        }
        let mut aggregated = BTreeMap::<TrafficKey, TrafficDelta>::new();
        for delta in &batch.traffic {
            let mut delta = delta.clone();
            delta.timestamp = delta.timestamp / MINUTE_MS * MINUTE_MS;
            let key = TrafficKey::from(&delta);
            if let Some(current) = aggregated.get_mut(&key) {
                current.upload_bytes = current.upload_bytes.saturating_add(delta.upload_bytes);
                current.download_bytes =
                    current.download_bytes.saturating_add(delta.download_bytes);
                current.packets = current.packets.saturating_add(delta.packets);
                current.flow_count = current.flow_count.saturating_add(delta.flow_count);
            } else {
                aggregated.insert(key, delta);
            }
        }
        for delta in aggregated.values() {
            tx.execute(
                "INSERT INTO traffic_minute(
                    timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                    organization_id, application_id, category_id, protocol_id, domain, remote_ip,
                    upload_bytes, download_bytes, packets, flow_count
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
                 )
                 ON CONFLICT DO UPDATE SET
                    upload_bytes = traffic_minute.upload_bytes + excluded.upload_bytes,
                    download_bytes = traffic_minute.download_bytes + excluded.download_bytes,
                    packets = traffic_minute.packets + excluded.packets,
                    flow_count = traffic_minute.flow_count + excluded.flow_count",
                params![
                    delta.timestamp,
                    delta.gateway_id,
                    delta.scope,
                    delta.direction,
                    delta.transport_protocol,
                    delta.path_type,
                    delta.nat,
                    delta.device_id,
                    delta.organization_id,
                    delta.application_id,
                    delta.category_id,
                    delta.protocol_id,
                    delta.domain,
                    delta.remote_ip,
                    delta.upload_bytes,
                    delta.download_bytes,
                    delta.packets,
                    delta.flow_count,
                ],
            )
            .map_err(|error| duckdb_error(&error))?;
        }
        tx.commit().map_err(|error| duckdb_error(&error))?;
        Ok(ApplyBatchResult::Applied)
    }

    fn traffic_series(&self, query: &TrafficQuery) -> StorageResult<Vec<TrafficPoint>> {
        let table = Self::resolution_table(query.resolution);
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT timestamp, SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
                 FROM {table}
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND (?3 IS NULL OR gateway_id = ?3)
                   AND (?4 IS NULL OR scope = ?4)
                   AND (?5 IS NULL OR direction = ?5)
                   AND (?6 IS NULL OR device_id = ?6)
                   AND (?7 IS NULL OR organization_id = ?7)
                   AND (?8 IS NULL OR application_id = ?8)
                   AND (?9 IS NULL OR category_id = ?9)
                   AND (?10 IS NULL OR protocol_id = ?10)
                   AND (?11 IS NULL OR domain = ?11)
                   AND (?12 IS NULL OR remote_ip = ?12)
                 GROUP BY timestamp ORDER BY timestamp"
            ))
            .map_err(|error| duckdb_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    query.from,
                    query.to,
                    query.gateway_id,
                    query.scope,
                    query.direction,
                    query.device_id,
                    query.organization_id,
                    query.application_id,
                    query.category_id,
                    query.protocol_id,
                    query.domain,
                    query.remote_ip,
                ],
                |row| {
                    Ok(TrafficPoint {
                        timestamp: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                        packets: row.get(3)?,
                        flow_count: row.get(4)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .map_err(|error| duckdb_error(&error))
    }

    fn traffic_breakdown(
        &self,
        query: &TrafficBreakdownQuery,
    ) -> StorageResult<Vec<TrafficBreakdown>> {
        let table = Self::resolution_table(query.traffic.resolution);
        let dimension = match query.dimension {
            TrafficDimension::Device => "device_id",
            TrafficDimension::Organization => "organization_id",
            TrafficDimension::Application => "application_id",
            TrafficDimension::Category => "category_id",
            TrafficDimension::Protocol => "protocol_id",
            TrafficDimension::Domain => "domain",
            TrafficDimension::Destination => "hex(remote_ip)",
            TrafficDimension::TransportProtocol => "transport_protocol",
        };
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT CAST({dimension} AS VARCHAR), SUM(upload_bytes), SUM(download_bytes),
                        SUM(packets), SUM(flow_count), MAX(timestamp)
                 FROM {table}
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND (?3 IS NULL OR gateway_id = ?3)
                   AND (?4 IS NULL OR scope = ?4)
                   AND (?5 IS NULL OR direction = ?5)
                   AND (?6 IS NULL OR device_id = ?6)
                   AND (?7 IS NULL OR organization_id = ?7)
                   AND (?8 IS NULL OR application_id = ?8)
                   AND (?9 IS NULL OR category_id = ?9)
                   AND (?10 IS NULL OR protocol_id = ?10)
                   AND (?11 IS NULL OR domain = ?11)
                   AND (?12 IS NULL OR remote_ip = ?12)
                 GROUP BY {dimension}
                 ORDER BY SUM(upload_bytes) + SUM(download_bytes) DESC, {dimension}
                 LIMIT ?13 OFFSET ?14"
            ))
            .map_err(|error| duckdb_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    query.traffic.from,
                    query.traffic.to,
                    query.traffic.gateway_id,
                    query.traffic.scope,
                    query.traffic.direction,
                    query.traffic.device_id,
                    query.traffic.organization_id,
                    query.traffic.application_id,
                    query.traffic.category_id,
                    query.traffic.protocol_id,
                    query.traffic.domain,
                    query.traffic.remote_ip,
                    query.limit,
                    query.offset,
                ],
                |row| {
                    Ok(TrafficBreakdown {
                        key: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                        packets: row.get(3)?,
                        flow_count: row.get(4)?,
                        last_seen_at: row.get(5)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .map_err(|error| duckdb_error(&error))
    }

    fn flows(&self, query: &FlowQuery) -> StorageResult<FlowPage> {
        let sort_column = flow_sort_column(query);
        let sort_operator = if query.descending { "<" } else { ">" };
        let order = if query.descending { "DESC" } else { "ASC" };
        let rows = flow_rows(&self.connection, query, sort_column, sort_operator, order)?;
        let total = flow_count(&self.connection, query, sort_column, sort_operator)?;
        Ok(FlowPage { rows, total })
    }

    fn flow_by_id(&self, gateway_id: &str, flow_id: &str) -> StorageResult<Option<AnalyticsFlow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT flow_id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                        remote_ip, remote_port, direction, domain, organization_id, application_id,
                        category_id, traffic_role, protocol_id, organization_confidence,
                        application_confidence, protocol_confidence, classification_confidence,
                        classification_reason, classification_evidence_json, upload_bytes, download_bytes,
                        packets, started_at, last_seen_at, ended_at, checkpointed_at, scope, path_type, nat,
                        source_segment, destination_segment
                 FROM flow_sessions_latest WHERE gateway_id = ?1 AND flow_id = ?2",
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut rows = statement
            .query(params![gateway_id, flow_id])
            .map_err(|error| duckdb_error(&error))?;
        rows.next()
            .map_err(|error| duckdb_error(&error))?
            .map(read_flow)
            .transpose()
            .map_err(|error| duckdb_error(&error))
    }

    fn flow_by_tuple(
        &self,
        identity: &super::AnalyticsFlowIdentity,
    ) -> StorageResult<Option<AnalyticsFlow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT flow_id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                        remote_ip, remote_port, direction, domain, organization_id, application_id,
                        category_id, traffic_role, protocol_id, organization_confidence,
                        application_confidence, protocol_confidence, classification_confidence,
                        classification_reason, classification_evidence_json, upload_bytes, download_bytes,
                        packets, started_at, last_seen_at, ended_at, checkpointed_at, scope, path_type, nat,
                        source_segment, destination_segment
                 FROM flow_sessions_latest
                 WHERE gateway_id = ?1 AND ip_version = ?2 AND protocol = ?3
                   AND client_ip = ?4 AND client_port = ?5 AND remote_ip = ?6
                   AND remote_port = ?7 AND started_at = ?8
                 ORDER BY checkpointed_at DESC LIMIT 1",
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut rows = statement
            .query(params![
                identity.gateway_id,
                identity.ip_version,
                identity.protocol,
                identity.client_ip,
                identity.client_port,
                identity.remote_ip,
                identity.remote_port,
                identity.started_at,
            ])
            .map_err(|error| duckdb_error(&error))?;
        rows.next()
            .map_err(|error| duckdb_error(&error))?
            .map(read_flow)
            .transpose()
            .map_err(|error| duckdb_error(&error))
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
        let table = Self::resolution_table(query.resolution);
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes)
                 FROM {table}
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND (?3 IS NULL OR gateway_id = ?3)
                   AND (?4 IS NULL OR device_id = ?4)
                 GROUP BY remote_ip ORDER BY SUM(upload_bytes) + SUM(download_bytes) DESC"
            ))
            .map_err(|error| duckdb_error(&error))?;
        let rows = statement
            .query_map(
                params![query.from, query.to, query.gateway_id, query.device_id],
                |row| {
                    Ok(GeoTraffic {
                        remote_ip: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .map_err(|error| duckdb_error(&error))
    }

    fn unknown_ratio(&self, since: u64) -> StorageResult<f64> {
        self.connection
            .query_row(
                "SELECT CASE WHEN COALESCE(SUM(upload_bytes + download_bytes), 0) = 0 THEN 0.0
                        ELSE CAST(SUM(CASE WHEN application_id = 'unknown'
                                           THEN upload_bytes + download_bytes ELSE 0 END) AS DOUBLE)
                             / SUM(upload_bytes + download_bytes)
                        END
                 FROM traffic_minute WHERE timestamp >= ?1",
                [since],
                |row| row.get(0),
            )
            .map_err(|error| duckdb_error(&error))
    }

    fn rollup(&mut self, now: u64) -> StorageResult<()> {
        let hour_end = now / HOUR_MS * HOUR_MS;
        let hour_start = hour_end.saturating_sub(HOUR_MS);
        self.insert_rollup_bucket("traffic_hour", "traffic_minute", hour_start, hour_end)?;
        let day_end = now / DAY_MS * DAY_MS;
        let day_start = day_end.saturating_sub(DAY_MS);
        self.insert_rollup_bucket("traffic_day", "traffic_hour", day_start, day_end)?;
        Ok(())
    }

    fn run_retention(&mut self, now: u64, policy: RetentionPolicy) -> StorageResult<()> {
        let tx = self
            .connection
            .transaction()
            .map_err(|error| duckdb_error(&error))?;
        if policy.flow_sessions_days != 0 {
            let cutoff = now.saturating_sub(u64::from(policy.flow_sessions_days) * DAY_MS);
            tx.execute(
                "DELETE FROM flow_session_versions WHERE last_seen_at < ?1",
                [cutoff],
            )
            .map_err(|error| duckdb_error(&error))?;
        }
        for (table, days) in [
            ("traffic_minute", policy.minute_days),
            ("traffic_hour", policy.hour_days),
            ("traffic_day", policy.day_days),
        ] {
            if days != 0 {
                let cutoff = now.saturating_sub(u64::from(days) * DAY_MS);
                tx.execute(
                    &format!("DELETE FROM {table} WHERE timestamp < ?1"),
                    [cutoff],
                )
                .map_err(|error| duckdb_error(&error))?;
            }
        }
        tx.commit().map_err(|error| duckdb_error(&error))
    }

    fn database_size_bytes(&self) -> StorageResult<u64> {
        self.connection
            .query_row(
                "SELECT CAST(block_size AS UBIGINT) * CAST(total_blocks AS UBIGINT)
                 FROM pragma_database_size()",
                [],
                |row| row.get(0),
            )
            .map_err(|error| duckdb_error(&error))
    }

    fn backend_name(&self) -> &'static str {
        "duckdb"
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
    fn from(value: &TrafficDelta) -> Self {
        Self {
            timestamp: value.timestamp,
            gateway_id: value.gateway_id.clone(),
            scope: value.scope,
            direction: value.direction,
            transport_protocol: value.transport_protocol,
            path_type: value.path_type,
            nat: value.nat,
            device_id: value.device_id,
            organization_id: value.organization_id.clone(),
            application_id: value.application_id.clone(),
            category_id: value.category_id.clone(),
            protocol_id: value.protocol_id.clone(),
            domain: value.domain.clone(),
            remote_ip: value.remote_ip.clone(),
        }
    }
}

fn insert_flow_version(
    tx: &duckdb::Transaction<'_>,
    flow: &AnalyticsFlow,
    boot_id: &str,
    sequence: u64,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO flow_session_versions VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
            ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36
         )",
        params![
            flow.gateway_id,
            flow.flow_id,
            boot_id,
            sequence,
            flow.device_id,
            flow.ip_version,
            flow.protocol,
            flow.client_ip,
            flow.client_port,
            flow.remote_ip,
            flow.remote_port,
            flow.direction,
            flow.domain,
            flow.organization_id,
            flow.application_id,
            flow.category_id,
            flow.traffic_role,
            flow.protocol_id,
            flow.organization_confidence,
            flow.application_confidence,
            flow.protocol_confidence,
            flow.classification_confidence,
            flow.classification_reason,
            flow.classification_evidence_json,
            flow.upload_bytes,
            flow.download_bytes,
            flow.packets,
            flow.started_at,
            flow.last_seen_at,
            flow.ended_at,
            flow.checkpointed_at,
            flow.scope,
            flow.path_type,
            flow.nat,
            flow.source_segment,
            flow.destination_segment,
        ],
    )
    .map_err(|error| duckdb_error(&error))?;
    Ok(())
}

fn read_flow(row: &duckdb::Row<'_>) -> duckdb::Result<AnalyticsFlow> {
    Ok(AnalyticsFlow {
        flow_id: row.get(0)?,
        gateway_id: row.get(1)?,
        device_id: row.get(2)?,
        ip_version: row.get(3)?,
        protocol: row.get(4)?,
        client_ip: row.get(5)?,
        client_port: row.get(6)?,
        remote_ip: row.get(7)?,
        remote_port: row.get(8)?,
        direction: row.get(9)?,
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
        upload_bytes: row.get(22)?,
        download_bytes: row.get(23)?,
        packets: row.get(24)?,
        started_at: row.get(25)?,
        last_seen_at: row.get(26)?,
        ended_at: row.get(27)?,
        checkpointed_at: row.get(28)?,
        scope: row.get(29)?,
        path_type: row.get(30)?,
        nat: row.get(31)?,
        source_segment: row.get(32)?,
        destination_segment: row.get(33)?,
    })
}

fn flow_sort_column(query: &FlowQuery) -> &'static str {
    match query.sort_by {
        super::FlowSort::LastSeen => "last_seen_at",
        super::FlowSort::Started => "started_at",
        super::FlowSort::UploadBytes => "upload_bytes",
        super::FlowSort::DownloadBytes => "download_bytes",
        super::FlowSort::TotalBytes => "upload_bytes + download_bytes",
        super::FlowSort::Duration => "COALESCE(ended_at, last_seen_at) - started_at",
    }
}

fn flow_filters(sort_column: &str, sort_operator: &str) -> String {
    format!(
        "WHERE last_seen_at >= ?1 AND last_seen_at < ?2
           AND (?3 IS NULL OR gateway_id = ?3)
           AND (?4 IS NULL OR device_id = ?4)
           AND (?5 IS NULL OR application_id = ?5)
           AND (?6 IS NULL OR organization_id = ?6)
           AND (?7 IS NULL OR protocol_id = ?7)
           AND (?8 IS NULL OR domain = ?8)
           AND (?9 IS NULL OR client_ip = ?9)
           AND (?10 IS NULL OR remote_ip = ?10)
           AND (?11 IS NULL OR protocol = ?11)
           AND (?12 IS NULL OR remote_port = ?12 OR client_port = ?12)
           AND (?13 IS NULL OR direction = ?13)
           AND (?14 IS NULL OR scope = ?14)
           AND (?15 IS NULL OR path_type = ?15)
           AND (?16 IS NULL OR nat = ?16)
           AND (?17 IS NULL OR lower(domain || ' ' || application_id || ' ' || organization_id || ' ' || protocol_id) LIKE '%' || lower(?17) || '%')
           AND (?18 IS NULL OR client_ip = ?18 OR remote_ip = ?18)
           AND (?19 IS NULL OR {sort_column} {sort_operator} ?19 OR ({sort_column} = ?19 AND flow_id > ?20))"
    )
}

fn flow_rows(
    connection: &Connection,
    query: &FlowQuery,
    sort_column: &str,
    sort_operator: &str,
    order: &str,
) -> StorageResult<Vec<AnalyticsFlow>> {
    let sql = format!(
        "SELECT flow_id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                remote_ip, remote_port, direction, domain, organization_id, application_id,
                category_id, traffic_role, protocol_id, organization_confidence,
                application_confidence, protocol_confidence, classification_confidence,
                classification_reason, classification_evidence_json, upload_bytes, download_bytes,
                packets, started_at, last_seen_at, ended_at, checkpointed_at, scope, path_type, nat,
                source_segment, destination_segment
         FROM flow_sessions_latest {} ORDER BY {sort_column} {order}, flow_id ASC
         LIMIT ?21 OFFSET ?22",
        flow_filters(sort_column, sort_operator)
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| duckdb_error(&error))?;
    let rows = statement
        .query_map(
            params![
                query.from,
                query.to,
                query.gateway_id,
                query.device_id,
                query.application_id,
                query.organization_id,
                query.protocol_id,
                query.domain,
                query.client_ip,
                query.remote_ip,
                query.transport_protocol,
                query.port,
                query.direction,
                query.scope,
                query.path_type,
                query.nat,
                query.search,
                query.any_ip,
                query.after_sort_value,
                query.after_flow_id,
                query.limit,
                query.offset,
            ],
            read_flow,
        )
        .map_err(|error| duckdb_error(&error))?;
    rows.collect::<duckdb::Result<Vec<_>>>()
        .map_err(|error| duckdb_error(&error))
}

fn flow_count(
    connection: &Connection,
    query: &FlowQuery,
    sort_column: &str,
    sort_operator: &str,
) -> StorageResult<u64> {
    let sql = format!(
        "SELECT COUNT(*) FROM flow_sessions_latest {}",
        flow_filters(sort_column, sort_operator)
    );
    connection
        .query_row(
            &sql,
            params![
                query.from,
                query.to,
                query.gateway_id,
                query.device_id,
                query.application_id,
                query.organization_id,
                query.protocol_id,
                query.domain,
                query.client_ip,
                query.remote_ip,
                query.transport_protocol,
                query.port,
                query.direction,
                query.scope,
                query.path_type,
                query.nat,
                query.search,
                query.any_ip,
                query.after_sort_value,
                query.after_flow_id,
            ],
            |row| row.get(0),
        )
        .map_err(|error| duckdb_error(&error))
}

fn duckdb_error(error: &duckdb::Error) -> StorageError {
    StorageError::DuckDb(error.to_string())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_batch(sequence: u64, protocol_id: &str, checkpointed_at: u64) -> AnalyticsBatch {
        let flow = AnalyticsFlow {
            flow_id: "flow-1".to_owned(),
            gateway_id: "gateway-1".to_owned(),
            device_id: 7,
            ip_version: 4,
            protocol: 6,
            client_ip: vec![10, 0, 0, 2],
            client_port: 45_000,
            remote_ip: vec![1, 1, 1, 1],
            remote_port: 443,
            direction: 1,
            domain: "example.test".to_owned(),
            organization_id: "unknown".to_owned(),
            application_id: "unknown".to_owned(),
            category_id: "unknown".to_owned(),
            traffic_role: "unknown".to_owned(),
            protocol_id: protocol_id.to_owned(),
            organization_confidence: 0.0,
            application_confidence: 0.0,
            protocol_confidence: 0.8,
            classification_confidence: 0.8,
            classification_reason: "test".to_owned(),
            classification_evidence_json: "[]".to_owned(),
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
            started_at: 60_000,
            last_seen_at: checkpointed_at,
            ended_at: None,
            checkpointed_at,
            scope: 1,
            path_type: 2,
            nat: 3,
            source_segment: String::new(),
            destination_segment: String::new(),
        };
        AnalyticsBatch {
            gateway_id: "gateway-1".to_owned(),
            boot_id: "boot-1".to_owned(),
            sequence,
            received_at: checkpointed_at,
            flows: vec![flow],
            traffic: vec![TrafficDelta {
                timestamp: 60_001,
                gateway_id: "gateway-1".to_owned(),
                scope: 1,
                direction: 1,
                transport_protocol: 6,
                path_type: 2,
                nat: 3,
                device_id: 7,
                organization_id: "unknown".to_owned(),
                application_id: "unknown".to_owned(),
                category_id: "unknown".to_owned(),
                protocol_id: protocol_id.to_owned(),
                domain: "example.test".to_owned(),
                remote_ip: vec![1, 1, 1, 1],
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                flow_count: 1,
            }],
        }
    }

    #[test]
    fn applying_the_same_batch_twice_does_not_double_traffic() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let batch = test_batch(1, "unknown", 120_000);
        assert_eq!(
            store.apply_batch(&batch).unwrap(),
            ApplyBatchResult::Applied
        );
        assert_eq!(
            store.apply_batch(&batch).unwrap(),
            ApplyBatchResult::Duplicate
        );
        let rows = store
            .traffic_series(&TrafficQuery {
                from: 0,
                to: 180_000,
                resolution: AnalyticsResolution::Minute,
                gateway_id: Some("gateway-1".to_owned()),
                scope: None,
                direction: None,
                device_id: None,
                organization_id: None,
                application_id: None,
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].upload_bytes, 100);
        assert_eq!(rows[0].download_bytes, 200);
        assert_eq!(rows[0].flow_count, 1);
    }

    #[test]
    fn latest_flow_version_reflects_late_reclassification() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        store
            .apply_batch(&test_batch(1, "unknown", 120_000))
            .unwrap();
        store.apply_batch(&test_batch(2, "quic", 180_000)).unwrap();
        let page = store
            .flows(&FlowQuery {
                from: 0,
                to: 1_000_000,
                gateway_id: Some("gateway-1".to_owned()),
                device_id: None,
                application_id: None,
                organization_id: None,
                protocol_id: None,
                domain: None,
                limit: 10,
                offset: 0,
                ..FlowQuery::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.rows[0].protocol_id, "quic");
    }
}
