use std::collections::{BTreeMap, HashMap};
use std::env;
use std::path::Path;

use duckdb::{Connection, params};

use super::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsQueryPlan, AnalyticsResolution, AnalyticsStore,
    AnalyticsSummary, ApplyBatchResult, FlowPage, FlowQuery, GeoTraffic, SummaryQuery,
    TrafficBreakdown, TrafficBreakdownQuery, TrafficDelta, TrafficDimension, TrafficPoint,
    TrafficQuery,
};
use crate::{RetentionPolicy, StorageError, StorageResult};

const INITIAL_MIGRATION: &str = include_str!("../../../../migrations/duckdb/0001_initial.sql");
const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

#[derive(Clone, Copy)]
enum TrafficFact {
    Core,
    Endpoint,
}

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
        let threads = env::var("NETQMON_DUCKDB_THREADS")
            .ok()
            .map_or(Ok(1_u8), |value| {
                value.parse::<u8>().map_err(|_| {
                    StorageError::InvalidData(
                        "NETQMON_DUCKDB_THREADS must be an integer from 1 to 8".to_owned(),
                    )
                })
            })?;
        if !(1..=8).contains(&threads) {
            return Err(StorageError::InvalidData(
                "NETQMON_DUCKDB_THREADS must be an integer from 1 to 8".to_owned(),
            ));
        }
        connection
            .execute_batch(&format!("SET threads = {threads}"))
            .map_err(|error| duckdb_error(&error))?;
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

    fn resolution_table(resolution: AnalyticsResolution, fact: TrafficFact) -> &'static str {
        match (fact, resolution) {
            (TrafficFact::Core, AnalyticsResolution::Minute) => "traffic_core_minute",
            (TrafficFact::Core, AnalyticsResolution::Hour) => "traffic_core_hour",
            (TrafficFact::Core, AnalyticsResolution::Day) => "traffic_core_day",
            (TrafficFact::Endpoint, AnalyticsResolution::Minute) => "traffic_endpoint_minute",
            (TrafficFact::Endpoint, AnalyticsResolution::Hour) => "traffic_endpoint_hour",
            (TrafficFact::Endpoint, AnalyticsResolution::Day) => "traffic_endpoint_day",
        }
    }

    fn planned_source(from: u64, to: u64, fact: TrafficFact) -> String {
        let plan = AnalyticsQueryPlan::for_range(from, to);
        if plan.segments.is_empty() {
            return format!(
                "SELECT * FROM {} WHERE 1 = 0",
                Self::resolution_table(AnalyticsResolution::Minute, fact)
            );
        }
        plan.segments
            .iter()
            .map(|segment| {
                let table = Self::resolution_table(segment.table, fact);
                format!(
                    "SELECT * FROM {table} WHERE timestamp >= {} AND timestamp < {}",
                    segment.from, segment.to
                )
            })
            .collect::<Vec<_>>()
            .join(" UNION ALL ")
    }

    fn fact_for_query(query: &TrafficQuery) -> TrafficFact {
        if query.domain.is_some() || query.remote_ip.is_some() {
            TrafficFact::Endpoint
        } else {
            TrafficFact::Core
        }
    }

    fn fact_for_summary(query: &SummaryQuery, dimension: &str) -> TrafficFact {
        if matches!(dimension, "domain" | "remote_ip")
            || query.domain.is_some()
            || query.remote_ip.is_some()
        {
            TrafficFact::Endpoint
        } else {
            TrafficFact::Core
        }
    }

    fn summary(
        &self,
        query: &SummaryQuery,
        dimension: &'static str,
    ) -> StorageResult<Vec<AnalyticsSummary>> {
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
        let fact = Self::fact_for_summary(query, dimension);
        let endpoint = matches!(fact, TrafficFact::Endpoint);
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
        let last_domain_expression = if endpoint {
            "arg_max(domain, timestamp)"
        } else {
            "CAST(NULL AS VARCHAR)"
        };
        let domain_filter = if endpoint {
            "domain = ?11"
        } else {
            "?11 IS NULL"
        };
        let remote_filter = if endpoint {
            "remote_ip = ?12"
        } else {
            "?12 IS NULL"
        };
        let source = Self::planned_source(query.from, query.to, fact);
        let sql = format!(
            "SELECT {key_expression}, {device_expression},
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count), MAX(timestamp),
                    COUNT(DISTINCT device_id), {last_domain_expression},
                    arg_max(application_id, timestamp),
                    arg_max(category_id, timestamp),
                    arg_max(organization_id, timestamp)
             FROM ({source}) AS traffic
             WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR gateway_id = ?3)
               AND (?4 IS NULL OR device_id = ?4)
               AND (?5 IS NULL OR scope = ?5)
               AND (?6 IS NULL OR direction = ?6)
               AND (?7 IS NULL OR organization_id = ?7)
               AND (?8 IS NULL OR application_id = ?8)
               AND (?9 IS NULL OR category_id = ?9)
               AND (?10 IS NULL OR protocol_id = ?10)
               AND (?11 IS NULL OR {domain_filter})
               AND (?12 IS NULL OR {remote_filter})
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
                        category_id: row.get(10)?,
                        organization_id: row.get(11)?,
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
        endpoint: bool,
    ) -> StorageResult<u64> {
        let (columns, group_columns) = if endpoint {
            (
                "timestamp, gateway_id, scope, direction, device_id,
                 organization_id, application_id, category_id, protocol_id, domain, remote_ip,
                 upload_bytes, download_bytes, packets, flow_count",
                "gateway_id, scope, direction, device_id, organization_id, application_id,
                 category_id, protocol_id, domain, remote_ip",
            )
        } else {
            (
                "timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                 organization_id, application_id, category_id, protocol_id,
                 upload_bytes, download_bytes, packets, flow_count",
                "gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                 organization_id, application_id, category_id, protocol_id",
            )
        };
        let select_dimensions = if endpoint {
            "gateway_id, scope, direction, device_id, organization_id, application_id,
             category_id, protocol_id, domain, remote_ip"
        } else {
            "gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
             organization_id, application_id, category_id, protocol_id"
        };
        let rows = self
            .connection
            .execute(
                &format!(
                    "INSERT INTO {target}({columns})
                     SELECT ?1, {select_dimensions},
                            SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
                     FROM {source}
                     WHERE timestamp >= ?2 AND timestamp < ?3
                     GROUP BY {group_columns}
                     ON CONFLICT DO UPDATE SET
                        upload_bytes = excluded.upload_bytes,
                        download_bytes = excluded.download_bytes,
                        packets = excluded.packets,
                        flow_count = excluded.flow_count"
                ),
                params![bucket_start, bucket_start, bucket_end],
            )
            .map_err(|error| duckdb_error(&error))?;
        Ok(u64::try_from(rows).unwrap_or(u64::MAX))
    }

    fn rollup_watermark(&self, name: &str) -> StorageResult<u64> {
        self.connection
            .query_row(
                "SELECT completed_until FROM analytics_rollup_state WHERE rollup_name = ?1",
                [name],
                |row| row.get(0),
            )
            .map_err(|error| duckdb_error(&error))
    }

    fn set_rollup_watermark(&self, name: &str, completed_until: u64) -> StorageResult<()> {
        self.connection
            .execute(
                "INSERT INTO analytics_rollup_state(rollup_name, completed_until)
                 VALUES (?1, ?2)
                 ON CONFLICT (rollup_name) DO UPDATE SET completed_until = excluded.completed_until",
                params![name, completed_until],
            )
            .map_err(|error| duckdb_error(&error))?;
        Ok(())
    }

    fn advance_rollup(
        &mut self,
        name: &str,
        target: &'static str,
        source: &'static str,
        last_complete_bucket: u64,
        bucket_ms: u64,
        endpoint: bool,
    ) -> StorageResult<u64> {
        let mut watermark = self.rollup_watermark(name)?;
        if watermark == 0 {
            let first: Option<u64> = self
                .connection
                .query_row(&format!("SELECT MIN(timestamp) FROM {source}"), [], |row| {
                    row.get(0)
                })
                .map_err(|error| duckdb_error(&error))?;
            watermark = first.map_or(last_complete_bucket, |timestamp| {
                timestamp / bucket_ms * bucket_ms
            });
        }
        let mut rows_written = 0_u64;
        while watermark < last_complete_bucket {
            let bucket_end = watermark.saturating_add(bucket_ms);
            rows_written = rows_written.saturating_add(
                self.insert_rollup_bucket(target, source, watermark, bucket_end, endpoint)?,
            );
            watermark = bucket_end;
            self.set_rollup_watermark(name, watermark)?;
        }
        if watermark == 0 && last_complete_bucket != 0 {
            self.set_rollup_watermark(name, last_complete_bucket)?;
        }
        Ok(rows_written)
    }
}

impl AnalyticsStore for DuckDbAnalyticsStore {
    fn overview(&self, from: u64, to: u64) -> StorageResult<super::AnalyticsOverview> {
        let source = Self::planned_source(from, to, TrafficFact::Core);
        self.connection
            .query_row(
                &format!("SELECT COUNT(DISTINCT CASE WHEN application_id != 'unknown' THEN application_id END),
                        COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
                 FROM ({source}) AS traffic WHERE timestamp >= ?1 AND timestamp < ?2"),
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
        self.apply_batches(std::slice::from_ref(batch))
            .map(|results| {
                results
                    .into_iter()
                    .next()
                    .unwrap_or(ApplyBatchResult::Duplicate)
            })
    }

    #[allow(clippy::too_many_lines)]
    fn apply_batches(
        &mut self,
        batches: &[AnalyticsBatch],
    ) -> StorageResult<Vec<ApplyBatchResult>> {
        let tx = self
            .connection
            .transaction()
            .map_err(|error| duckdb_error(&error))?;
        let attribution_table_empty: bool = tx
            .query_row(
                "SELECT NOT EXISTS (SELECT 1 FROM flow_traffic_attribution LIMIT 1)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut attribution_cache =
            HashMap::<(String, String, u64), Option<StoredFlowAttribution>>::new();
        let mut core_aggregated = BTreeMap::<CoreTrafficKey, TrafficDelta>::new();
        let mut endpoint_aggregated = BTreeMap::<EndpointTrafficKey, TrafficDelta>::new();
        let mut results = Vec::with_capacity(batches.len());
        let mut processed_statement = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO processed_batches(gateway_id, boot_id, sequence, applied_at)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut version_statement = tx
            .prepare_cached(
                "INSERT INTO flow_session_versions VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                 ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36
              ) ON CONFLICT (gateway_id, flow_id, boot_id, batch_sequence) DO UPDATE SET
                 device_id = excluded.device_id,
                 ip_version = excluded.ip_version,
                 protocol = excluded.protocol,
                 client_ip = excluded.client_ip,
                 client_port = excluded.client_port,
                 remote_ip = excluded.remote_ip,
                 remote_port = excluded.remote_port,
                 direction = excluded.direction,
                 domain = excluded.domain,
                 organization_id = excluded.organization_id,
                 application_id = excluded.application_id,
                 category_id = excluded.category_id,
                 traffic_role = excluded.traffic_role,
                 protocol_id = excluded.protocol_id,
                 organization_confidence = excluded.organization_confidence,
                 application_confidence = excluded.application_confidence,
                 protocol_confidence = excluded.protocol_confidence,
                 classification_confidence = excluded.classification_confidence,
                 classification_reason = excluded.classification_reason,
                 classification_evidence_json = excluded.classification_evidence_json,
                 upload_bytes = excluded.upload_bytes,
                 download_bytes = excluded.download_bytes,
                 packets = excluded.packets,
                 started_at = excluded.started_at,
                 last_seen_at = excluded.last_seen_at,
                 ended_at = excluded.ended_at,
                 checkpointed_at = excluded.checkpointed_at,
                 scope = excluded.scope,
                 path_type = excluded.path_type,
                 nat = excluded.nat,
                 source_segment = excluded.source_segment,
                 destination_segment = excluded.destination_segment",
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut load_attr_statement = tx
            .prepare_cached(
                "SELECT timestamp, scope, direction, transport_protocol, path_type, nat,
                        device_id, organization_id, application_id, category_id, protocol_id, domain,
                        remote_ip, upload_bytes, download_bytes, packets, flow_count
                 FROM flow_traffic_attribution
                 WHERE gateway_id = ?1 AND flow_id = ?2 AND started_at = ?3",
            )
            .map_err(|error| duckdb_error(&error))?;
        let mut store_attr_statement = tx
            .prepare_cached(
                "INSERT INTO flow_traffic_attribution(
                    gateway_id, flow_id, started_at, timestamp, scope, direction, transport_protocol,
                    path_type, nat, device_id, organization_id, application_id, category_id, protocol_id,
                    domain, remote_ip, upload_bytes, download_bytes, packets, flow_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                 ON CONFLICT (gateway_id, flow_id, started_at) DO UPDATE SET
                    timestamp = excluded.timestamp, scope = excluded.scope, direction = excluded.direction,
                    transport_protocol = excluded.transport_protocol, path_type = excluded.path_type,
                    nat = excluded.nat, device_id = excluded.device_id, organization_id = excluded.organization_id,
                    application_id = excluded.application_id, category_id = excluded.category_id,
                    protocol_id = excluded.protocol_id, domain = excluded.domain, remote_ip = excluded.remote_ip,
                    upload_bytes = excluded.upload_bytes, download_bytes = excluded.download_bytes,
                    packets = excluded.packets, flow_count = excluded.flow_count",
            )
            .map_err(|error| duckdb_error(&error))?;
        for batch in batches {
            let inserted = processed_statement
                .execute(params![
                    batch.gateway_id,
                    batch.boot_id,
                    batch.sequence,
                    batch.received_at
                ])
                .map_err(|error| duckdb_error(&error))?;
            if inserted == 0 {
                results.push(ApplyBatchResult::Duplicate);
                continue;
            }
            results.push(ApplyBatchResult::Applied);

            let flows = latest_flows_in_batch(batch);
            for flow in flows {
                insert_flow_version(&mut version_statement, flow, &batch.boot_id, batch.sequence)?;
                apply_flow_reclassification(
                    &tx,
                    &mut load_attr_statement,
                    &mut store_attr_statement,
                    &mut attribution_cache,
                    attribution_table_empty,
                    flow,
                    &mut core_aggregated,
                    &mut endpoint_aggregated,
                )?;
            }
            for delta in &batch.traffic {
                let mut delta = delta.clone();
                delta.timestamp = delta.timestamp / MINUTE_MS * MINUTE_MS;
                aggregate_delta(&mut core_aggregated, CoreTrafficKey::from(&delta), &delta);
                aggregate_delta(
                    &mut endpoint_aggregated,
                    EndpointTrafficKey::from(&delta),
                    &delta,
                );
            }
        }
        {
            let mut statement = tx
                .prepare_cached(
                "INSERT INTO traffic_core_minute(
                    timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
                    organization_id, application_id, category_id, protocol_id,
                    upload_bytes, download_bytes, packets, flow_count
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
                 )
                 ON CONFLICT DO UPDATE SET
                    upload_bytes = traffic_core_minute.upload_bytes + excluded.upload_bytes,
                    download_bytes = traffic_core_minute.download_bytes + excluded.download_bytes,
                    packets = traffic_core_minute.packets + excluded.packets,
                    flow_count = traffic_core_minute.flow_count + excluded.flow_count",
                )
                .map_err(|error| duckdb_error(&error))?;
            for delta in core_aggregated.values() {
                statement
                    .execute(params![
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
                        delta.upload_bytes,
                        delta.download_bytes,
                        delta.packets,
                        delta.flow_count,
                    ])
                    .map_err(|error| duckdb_error(&error))?;
            }
        }
        {
            let mut statement = tx
                .prepare_cached(
                "INSERT INTO traffic_endpoint_minute(
                    timestamp, gateway_id, scope, direction, device_id,
                    organization_id, application_id, category_id, protocol_id, domain, remote_ip,
                    upload_bytes, download_bytes, packets, flow_count
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
                 )
                 ON CONFLICT DO UPDATE SET
                    upload_bytes = traffic_endpoint_minute.upload_bytes + excluded.upload_bytes,
                    download_bytes = traffic_endpoint_minute.download_bytes + excluded.download_bytes,
                    packets = traffic_endpoint_minute.packets + excluded.packets,
                    flow_count = traffic_endpoint_minute.flow_count + excluded.flow_count",
                )
                .map_err(|error| duckdb_error(&error))?;
            for delta in endpoint_aggregated.values() {
                statement
                    .execute(params![
                        delta.timestamp,
                        delta.gateway_id,
                        delta.scope,
                        delta.direction,
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
                    ])
                    .map_err(|error| duckdb_error(&error))?;
            }
        }
        drop(processed_statement);
        drop(version_statement);
        drop(load_attr_statement);
        drop(store_attr_statement);
        tx.commit().map_err(|error| duckdb_error(&error))?;
        Ok(results)
    }

    fn traffic_series(&self, query: &TrafficQuery) -> StorageResult<Vec<TrafficPoint>> {
        let endpoint = matches!(Self::fact_for_query(query), TrafficFact::Endpoint);
        let domain_filter = if endpoint {
            "domain = ?11"
        } else {
            "?11 IS NULL"
        };
        let remote_filter = if endpoint {
            "remote_ip = ?12"
        } else {
            "?12 IS NULL"
        };
        let source = Self::planned_source(query.from, query.to, Self::fact_for_query(query));
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT timestamp, SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
                 FROM ({source}) AS traffic
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND (?3 IS NULL OR gateway_id = ?3)
                   AND (?4 IS NULL OR scope = ?4)
                   AND (?5 IS NULL OR direction = ?5)
                   AND (?6 IS NULL OR device_id = ?6)
                   AND (?7 IS NULL OR organization_id = ?7)
                   AND (?8 IS NULL OR application_id = ?8)
                   AND (?9 IS NULL OR category_id = ?9)
                   AND (?10 IS NULL OR protocol_id = ?10)
                   AND (?11 IS NULL OR {domain_filter})
                   AND (?12 IS NULL OR {remote_filter})
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
        let fact = match query.dimension {
            TrafficDimension::Domain | TrafficDimension::Destination => TrafficFact::Endpoint,
            _ => Self::fact_for_query(&query.traffic),
        };
        let endpoint = matches!(fact, TrafficFact::Endpoint);
        let domain_filter = if endpoint {
            "domain = ?11"
        } else {
            "?11 IS NULL"
        };
        let remote_filter = if endpoint {
            "remote_ip = ?12"
        } else {
            "?12 IS NULL"
        };
        let source = Self::planned_source(query.traffic.from, query.traffic.to, fact);
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
                 FROM ({source}) AS traffic
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND (?3 IS NULL OR gateway_id = ?3)
                   AND (?4 IS NULL OR scope = ?4)
                   AND (?5 IS NULL OR direction = ?5)
                   AND (?6 IS NULL OR device_id = ?6)
                   AND (?7 IS NULL OR organization_id = ?7)
                   AND (?8 IS NULL OR application_id = ?8)
                   AND (?9 IS NULL OR category_id = ?9)
                   AND (?10 IS NULL OR protocol_id = ?10)
                   AND (?11 IS NULL OR {domain_filter})
                   AND (?12 IS NULL OR {remote_filter})
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
        // Traffic rows are the authoritative byte totals, while the latest
        // flow view is the authoritative catalog for late classifications.
        // Merge applications that have not reached a corrected traffic row so
        // the UI never hides a newly recognized application.
        let mut catalog_query = query.clone();
        catalog_query.limit = u32::MAX;
        catalog_query.offset = 0;
        let mut rows = self.summary(&catalog_query, "application_id")?;
        rows.retain(|row| {
            row.upload_bytes > 0 || row.download_bytes > 0 || row.packets > 0 || row.flow_count > 0
        });
        let mut statement = self
            .connection
            .prepare(
                "SELECT application_id, COALESCE(SUM(upload_bytes), 0),
                        COALESCE(SUM(download_bytes), 0), COALESCE(SUM(packets), 0),
                        COUNT(*), MAX(last_seen_at), COUNT(DISTINCT device_id),
                        arg_max(domain, last_seen_at),
                        arg_max(category_id, last_seen_at),
                        arg_max(organization_id, last_seen_at)
                 FROM flow_sessions_latest
                 WHERE last_seen_at >= ?1 AND last_seen_at < ?2
                   AND application_id IS NOT NULL AND application_id != ''
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
                 GROUP BY application_id",
            )
            .map_err(|error| duckdb_error(&error))?;
        let flow_rows = statement
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
                ],
                |row| {
                    Ok(AnalyticsSummary {
                        key: row.get(0)?,
                        device_id: 0,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                        packets: row.get(3)?,
                        flow_count: row.get(4)?,
                        last_seen_at: row.get(5)?,
                        distinct_devices: row.get(6)?,
                        last_domain: row.get(7)?,
                        application_id: row.get(0)?,
                        category_id: row.get(8)?,
                        organization_id: row.get(9)?,
                    })
                },
            )
            .map_err(|error| duckdb_error(&error))?
            .collect::<duckdb::Result<Vec<_>>>()
            .map_err(|error| duckdb_error(&error))?;
        for flow_row in flow_rows {
            if let Some(existing) = rows.iter_mut().find(|row| row.key == flow_row.key) {
                existing.last_seen_at = existing.last_seen_at.max(flow_row.last_seen_at);
                if existing.last_domain.is_none() {
                    existing.last_domain = flow_row.last_domain;
                }
                if existing.category_id.is_none()
                    || existing.category_id.as_deref() == Some("unknown")
                {
                    existing.category_id = flow_row.category_id;
                }
                if existing.organization_id.is_none()
                    || existing.organization_id.as_deref() == Some("unknown")
                {
                    existing.organization_id = flow_row.organization_id;
                }
                existing.distinct_devices =
                    existing.distinct_devices.max(flow_row.distinct_devices);
            } else {
                rows.push(flow_row);
            }
        }
        rows.sort_by(|left, right| {
            let left_total = left.upload_bytes.saturating_add(left.download_bytes);
            let right_total = right.upload_bytes.saturating_add(right.download_bytes);
            right_total
                .cmp(&left_total)
                .then_with(|| left.key.cmp(&right.key))
        });
        let start = usize::try_from(query.offset).unwrap_or(usize::MAX);
        Ok(rows
            .into_iter()
            .skip(start)
            .take(query.limit as usize)
            .collect())
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
        let source = Self::planned_source(query.from, query.to, TrafficFact::Endpoint);
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes)
                 FROM ({source}) AS traffic
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
        let source = Self::planned_source(since, now_ms(), TrafficFact::Core);
        self.connection
            .query_row(
                &format!(
                    "SELECT CASE WHEN COALESCE(SUM(upload_bytes + download_bytes), 0) = 0 THEN 0.0
                        ELSE CAST(SUM(CASE WHEN application_id = 'unknown'
                                           THEN upload_bytes + download_bytes ELSE 0 END) AS DOUBLE)
                             / SUM(upload_bytes + download_bytes)
                        END
                 FROM ({source}) AS traffic WHERE timestamp >= ?1"
                ),
                [since],
                |row| row.get(0),
            )
            .map_err(|error| duckdb_error(&error))
    }

    fn rollup(&mut self, now: u64) -> StorageResult<u64> {
        let hour_end = now / HOUR_MS * HOUR_MS;
        let mut rows_written = self.advance_rollup(
            "core_hour",
            "traffic_core_hour",
            "traffic_core_minute",
            hour_end,
            HOUR_MS,
            false,
        )?;
        rows_written = rows_written.saturating_add(self.advance_rollup(
            "endpoint_hour",
            "traffic_endpoint_hour",
            "traffic_endpoint_minute",
            hour_end,
            HOUR_MS,
            true,
        )?);
        let day_end = now / DAY_MS * DAY_MS;
        rows_written = rows_written.saturating_add(self.advance_rollup(
            "core_day",
            "traffic_core_day",
            "traffic_core_hour",
            day_end,
            DAY_MS,
            false,
        )?);
        rows_written = rows_written.saturating_add(self.advance_rollup(
            "endpoint_day",
            "traffic_endpoint_day",
            "traffic_endpoint_hour",
            day_end,
            DAY_MS,
            true,
        )?);
        Ok(rows_written)
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
            tx.execute(
                "DELETE FROM flow_traffic_attribution WHERE timestamp < ?1",
                [cutoff],
            )
            .map_err(|error| duckdb_error(&error))?;
        }
        for (table, days) in [
            ("traffic_core_minute", policy.minute_days),
            ("traffic_core_hour", policy.hour_days),
            ("traffic_core_day", policy.day_days),
            ("traffic_endpoint_minute", policy.minute_days),
            ("traffic_endpoint_hour", policy.hour_days),
            ("traffic_endpoint_day", policy.day_days),
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
struct CoreTrafficKey {
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
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EndpointTrafficKey {
    timestamp: u64,
    gateway_id: String,
    scope: u8,
    direction: u8,
    device_id: u64,
    organization_id: String,
    application_id: String,
    category_id: String,
    protocol_id: String,
    domain: String,
    remote_ip: Vec<u8>,
}

impl From<&TrafficDelta> for CoreTrafficKey {
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
        }
    }
}

impl From<&TrafficDelta> for EndpointTrafficKey {
    fn from(value: &TrafficDelta) -> Self {
        Self {
            timestamp: value.timestamp,
            gateway_id: value.gateway_id.clone(),
            scope: value.scope,
            direction: value.direction,
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

fn aggregate_delta<K>(rows: &mut BTreeMap<K, TrafficDelta>, key: K, delta: &TrafficDelta)
where
    K: Ord,
{
    if let Some(current) = rows.get_mut(&key) {
        current.upload_bytes = current.upload_bytes.saturating_add(delta.upload_bytes);
        current.download_bytes = current.download_bytes.saturating_add(delta.download_bytes);
        current.packets = current.packets.saturating_add(delta.packets);
        current.flow_count = current.flow_count.saturating_add(delta.flow_count);
    } else {
        rows.insert(key, delta.clone());
    }
}

fn latest_flows_in_batch(batch: &AnalyticsBatch) -> Vec<&AnalyticsFlow> {
    let mut latest = BTreeMap::<(&str, &str), &AnalyticsFlow>::new();
    for flow in &batch.flows {
        let key = (flow.gateway_id.as_str(), flow.flow_id.as_str());
        match latest.get(&key) {
            Some(previous) if previous.checkpointed_at >= flow.checkpointed_at => {}
            _ => {
                latest.insert(key, flow);
            }
        }
    }
    latest.into_values().collect()
}

#[derive(Clone, Debug)]
struct StoredFlowAttribution {
    gateway_id: String,
    timestamp: u64,
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
    upload_bytes: u64,
    download_bytes: u64,
    packets: u64,
    flow_count: u64,
}

impl StoredFlowAttribution {
    fn from_flow(flow: &AnalyticsFlow) -> Self {
        Self {
            gateway_id: flow.gateway_id.clone(),
            timestamp: flow.started_at / MINUTE_MS * MINUTE_MS,
            scope: flow.scope,
            direction: flow.direction,
            transport_protocol: flow.protocol,
            path_type: flow.path_type,
            nat: flow.nat,
            device_id: flow.device_id,
            organization_id: flow.organization_id.clone(),
            application_id: flow.application_id.clone(),
            category_id: flow.category_id.clone(),
            protocol_id: flow.protocol_id.clone(),
            domain: flow.domain.clone(),
            remote_ip: flow.remote_ip.clone(),
            upload_bytes: flow.upload_bytes,
            download_bytes: flow.download_bytes,
            packets: flow.packets,
            flow_count: 1,
        }
    }

    fn same_dimensions(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
            && self.scope == other.scope
            && self.direction == other.direction
            && self.transport_protocol == other.transport_protocol
            && self.path_type == other.path_type
            && self.nat == other.nat
            && self.device_id == other.device_id
            && self.organization_id == other.organization_id
            && self.application_id == other.application_id
            && self.category_id == other.category_id
            && self.protocol_id == other.protocol_id
            && self.domain == other.domain
            && self.remote_ip == other.remote_ip
    }
}

fn load_flow_attribution(
    statement: &mut duckdb::Statement<'_>,
    flow: &AnalyticsFlow,
) -> StorageResult<Option<StoredFlowAttribution>> {
    let mut rows = statement
        .query(params![flow.gateway_id, flow.flow_id, flow.started_at])
        .map_err(|error| duckdb_error(&error))?;
    rows.next()
        .map_err(|error| duckdb_error(&error))?
        .map(|row| {
            Ok(StoredFlowAttribution {
                gateway_id: flow.gateway_id.clone(),
                timestamp: row.get(0)?,
                scope: row.get(1)?,
                direction: row.get(2)?,
                transport_protocol: row.get(3)?,
                path_type: row.get(4)?,
                nat: row.get(5)?,
                device_id: row.get(6)?,
                organization_id: row.get(7)?,
                application_id: row.get(8)?,
                category_id: row.get(9)?,
                protocol_id: row.get(10)?,
                domain: row.get(11)?,
                remote_ip: row.get(12)?,
                upload_bytes: row.get(13)?,
                download_bytes: row.get(14)?,
                packets: row.get(15)?,
                flow_count: row.get(16)?,
            })
        })
        .transpose()
        .map_err(|error: duckdb::Error| duckdb_error(&error))
}

fn store_flow_attribution(
    statement: &mut duckdb::Statement<'_>,
    flow: &AnalyticsFlow,
    attribution: &StoredFlowAttribution,
) -> StorageResult<()> {
    statement
        .execute(params![
            flow.gateway_id,
            flow.flow_id,
            flow.started_at,
            attribution.timestamp,
            attribution.scope,
            attribution.direction,
            attribution.transport_protocol,
            attribution.path_type,
            attribution.nat,
            attribution.device_id,
            attribution.organization_id,
            attribution.application_id,
            attribution.category_id,
            attribution.protocol_id,
            attribution.domain,
            attribution.remote_ip,
            attribution.upload_bytes,
            attribution.download_bytes,
            attribution.packets,
            attribution.flow_count,
        ])
        .map_err(|error| duckdb_error(&error))?;
    Ok(())
}

fn subtract_fact(
    tx: &duckdb::Transaction<'_>,
    table: &str,
    old: &StoredFlowAttribution,
    endpoint: bool,
) -> StorageResult<u64> {
    let predicate = if endpoint {
        "timestamp = ?1 AND gateway_id = ?2 AND scope = ?3 AND direction = ?4 AND device_id = ?5
         AND organization_id = ?6 AND application_id = ?7 AND category_id = ?8 AND protocol_id = ?9
         AND domain = ?10 AND remote_ip = ?11"
    } else {
        "timestamp = ?1 AND gateway_id = ?2 AND scope = ?3 AND direction = ?4
         AND transport_protocol = ?5 AND path_type = ?6 AND nat = ?7 AND device_id = ?8
         AND organization_id = ?9 AND application_id = ?10 AND category_id = ?11 AND protocol_id = ?12"
    };
    let (upload_param, download_param, packets_param, flow_count_param) = if endpoint {
        ("?12", "?13", "?14", "?15")
    } else {
        ("?13", "?14", "?15", "?16")
    };
    let sql = format!(
        "UPDATE {table}
         SET upload_bytes = CASE WHEN upload_bytes >= {upload_param} THEN upload_bytes - {upload_param} ELSE 0 END,
             download_bytes = CASE WHEN download_bytes >= {download_param} THEN download_bytes - {download_param} ELSE 0 END,
             packets = CASE WHEN packets >= {packets_param} THEN packets - {packets_param} ELSE 0 END,
             flow_count = CASE WHEN flow_count >= {flow_count_param} THEN flow_count - {flow_count_param} ELSE 0 END
          WHERE {predicate}"
    );
    let mut statement = tx
        .prepare_cached(&sql)
        .map_err(|error| duckdb_error(&error))?;
    let params = if endpoint {
        params![
            old.timestamp,
            old.gateway_id,
            old.scope,
            old.direction,
            old.device_id,
            old.organization_id,
            old.application_id,
            old.category_id,
            old.protocol_id,
            old.domain,
            old.remote_ip,
            old.upload_bytes,
            old.download_bytes,
            old.packets,
            old.flow_count,
        ]
    } else {
        params![
            old.timestamp,
            old.gateway_id,
            old.scope,
            old.direction,
            old.transport_protocol,
            old.path_type,
            old.nat,
            old.device_id,
            old.organization_id,
            old.application_id,
            old.category_id,
            old.protocol_id,
            old.upload_bytes,
            old.download_bytes,
            old.packets,
            old.flow_count,
        ]
    };
    let changed = statement
        .execute(params)
        .map_err(|error| duckdb_error(&error))?;
    Ok(u64::try_from(changed).unwrap_or(u64::MAX))
}

fn add_fact(
    tx: &duckdb::Transaction<'_>,
    table: &str,
    current: &StoredFlowAttribution,
    endpoint: bool,
) -> StorageResult<()> {
    let (columns, values) = if endpoint {
        (
            "timestamp, gateway_id, scope, direction, device_id, organization_id,
             application_id, category_id, protocol_id, domain, remote_ip,
             upload_bytes, download_bytes, packets, flow_count",
            "?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15",
        )
    } else {
        (
            "timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
             organization_id, application_id, category_id, protocol_id,
             upload_bytes, download_bytes, packets, flow_count",
            "?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16",
        )
    };
    let sql = format!(
        "INSERT INTO {table}({columns}) VALUES ({values})
         ON CONFLICT DO UPDATE SET
           upload_bytes = {table}.upload_bytes + excluded.upload_bytes,
           download_bytes = {table}.download_bytes + excluded.download_bytes,
           packets = {table}.packets + excluded.packets,
           flow_count = {table}.flow_count + excluded.flow_count"
    );
    let mut statement = tx
        .prepare_cached(&sql)
        .map_err(|error| duckdb_error(&error))?;
    let params = if endpoint {
        params![
            current.timestamp,
            current.gateway_id,
            current.scope,
            current.direction,
            current.device_id,
            current.organization_id,
            current.application_id,
            current.category_id,
            current.protocol_id,
            current.domain,
            current.remote_ip,
            current.upload_bytes,
            current.download_bytes,
            current.packets,
            current.flow_count,
        ]
    } else {
        params![
            current.timestamp,
            current.gateway_id,
            current.scope,
            current.direction,
            current.transport_protocol,
            current.path_type,
            current.nat,
            current.device_id,
            current.organization_id,
            current.application_id,
            current.category_id,
            current.protocol_id,
            current.upload_bytes,
            current.download_bytes,
            current.packets,
            current.flow_count,
        ]
    };
    statement
        .execute(params)
        .map_err(|error| duckdb_error(&error))?;
    Ok(())
}

fn attribution_delta(flow: &AnalyticsFlow, attribution: &StoredFlowAttribution) -> TrafficDelta {
    TrafficDelta {
        timestamp: attribution.timestamp,
        gateway_id: flow.gateway_id.clone(),
        scope: attribution.scope,
        direction: attribution.direction,
        transport_protocol: attribution.transport_protocol,
        path_type: attribution.path_type,
        nat: attribution.nat,
        device_id: attribution.device_id,
        organization_id: attribution.organization_id.clone(),
        application_id: attribution.application_id.clone(),
        category_id: attribution.category_id.clone(),
        protocol_id: attribution.protocol_id.clone(),
        domain: attribution.domain.clone(),
        remote_ip: attribution.remote_ip.clone(),
        upload_bytes: attribution.upload_bytes,
        download_bytes: attribution.download_bytes,
        packets: attribution.packets,
        flow_count: attribution.flow_count,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_flow_reclassification(
    tx: &duckdb::Transaction<'_>,
    load_attr_statement: &mut duckdb::Statement<'_>,
    store_attr_statement: &mut duckdb::Statement<'_>,
    attribution_cache: &mut HashMap<(String, String, u64), Option<StoredFlowAttribution>>,
    attribution_table_empty: bool,
    flow: &AnalyticsFlow,
    core: &mut BTreeMap<CoreTrafficKey, TrafficDelta>,
    endpoint: &mut BTreeMap<EndpointTrafficKey, TrafficDelta>,
) -> StorageResult<()> {
    let key = (
        flow.gateway_id.clone(),
        flow.flow_id.clone(),
        flow.started_at,
    );
    let previous = match attribution_cache.get(&key) {
        Some(cached) => cached.clone(),
        None => {
            if attribution_table_empty {
                None
            } else {
                let loaded = load_flow_attribution(load_attr_statement, flow)?;
                attribution_cache.insert(key.clone(), loaded.clone());
                loaded
            }
        }
    };
    let current = StoredFlowAttribution::from_flow(flow);
    if let Some(previous) = previous {
        if !previous.same_dimensions(&current) {
            subtract_fact(tx, "traffic_core_minute", &previous, false)?;
            subtract_fact(tx, "traffic_endpoint_minute", &previous, true)?;
            for (table, bucket_ms, endpoint) in [
                ("traffic_core_hour", HOUR_MS, false),
                ("traffic_core_day", DAY_MS, false),
                ("traffic_endpoint_hour", HOUR_MS, true),
                ("traffic_endpoint_day", DAY_MS, true),
            ] {
                let mut old_bucket = previous.clone();
                old_bucket.timestamp = previous.timestamp / bucket_ms * bucket_ms;
                if subtract_fact(tx, table, &old_bucket, endpoint)? > 0 {
                    let mut new_bucket = current.clone();
                    new_bucket.timestamp = current.timestamp / bucket_ms * bucket_ms;
                    add_fact(tx, table, &new_bucket, endpoint)?;
                }
            }
            let delta = attribution_delta(flow, &current);
            aggregate_delta(core, CoreTrafficKey::from(&delta), &delta);
            aggregate_delta(endpoint, EndpointTrafficKey::from(&delta), &delta);
        }
    }
    store_flow_attribution(store_attr_statement, flow, &current)?;
    attribution_cache.insert(key, Some(current));
    Ok(())
}

fn insert_flow_version(
    statement: &mut duckdb::Statement<'_>,
    flow: &AnalyticsFlow,
    boot_id: &str,
    sequence: u64,
) -> StorageResult<()> {
    statement
        .execute(params![
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
        ])
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

    #[test]
    fn late_reclassification_moves_minute_traffic_to_the_new_application() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut first = test_batch(1, "unknown", 120_000);
        first.flows[0].application_id = "unknown".to_owned();
        store.apply_batch(&first).unwrap();

        let mut correction = test_batch(2, "unknown", 180_000);
        correction.flows[0].application_id = "example-app".to_owned();
        correction.traffic.clear();
        store.apply_batch(&correction).unwrap();

        let unknown = store
            .application_summary(&SummaryQuery {
                from: 0,
                to: 1_000_000,
                resolution: AnalyticsResolution::Minute,
                gateway_id: None,
                device_id: None,
                scope: None,
                direction: None,
                organization_id: None,
                application_id: Some("unknown".to_owned()),
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        let corrected = store
            .application_summary(&SummaryQuery {
                from: 0,
                to: 1_000_000,
                resolution: AnalyticsResolution::Minute,
                gateway_id: None,
                device_id: None,
                scope: None,
                direction: None,
                organization_id: None,
                application_id: Some("example-app".to_owned()),
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        assert!(unknown.is_empty());
        assert_eq!(corrected.first().map(|row| row.upload_bytes), Some(100));
    }

    #[test]
    fn late_reclassification_updates_materialized_hour_and_day_traffic() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut first = test_batch(1, "unknown", 120_000);
        first.traffic[0].timestamp = 30 * MINUTE_MS;
        store.apply_batch(&first).unwrap();
        assert!(store.rollup(2 * DAY_MS).unwrap() > 0);

        let mut correction = test_batch(2, "unknown", 180_000);
        correction.traffic.clear();
        correction.flows[0].application_id = "example-app".to_owned();
        store.apply_batch(&correction).unwrap();

        let rows = store
            .application_summary(&SummaryQuery {
                from: 0,
                to: 2 * DAY_MS,
                resolution: AnalyticsResolution::Day,
                gateway_id: None,
                device_id: None,
                scope: None,
                direction: None,
                organization_id: None,
                application_id: Some("example-app".to_owned()),
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        assert_eq!(rows.first().map(|row| row.upload_bytes), Some(100));
        assert_eq!(rows.first().map(|row| row.download_bytes), Some(200));

        let unknown = store
            .application_summary(&SummaryQuery {
                application_id: Some("unknown".to_owned()),
                ..SummaryQuery {
                    from: 0,
                    to: 2 * DAY_MS,
                    resolution: AnalyticsResolution::Day,
                    gateway_id: None,
                    device_id: None,
                    scope: None,
                    direction: None,
                    organization_id: None,
                    application_id: None,
                    category_id: None,
                    protocol_id: None,
                    domain: None,
                    remote_ip: None,
                    limit: 20,
                    offset: 0,
                }
            })
            .unwrap();
        assert!(unknown.is_empty());
    }

    #[test]
    fn current_minute_tail_is_visible_before_rollup() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        store.apply_batch(&test_batch(1, "tcp", 120_000)).unwrap();
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
        assert_eq!(rows.iter().map(|row| row.upload_bytes).sum::<u64>(), 100);
    }

    #[test]
    fn mixed_resolution_query_does_not_double_count_rollups() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut first = test_batch(1, "tcp", 60 * DAY_MS + HOUR_MS);
        first.traffic[0].timestamp = 60 * DAY_MS + 30 * MINUTE_MS;
        store.apply_batch(&first).unwrap();
        let mut second = test_batch(2, "tcp", 61 * DAY_MS + HOUR_MS);
        second.traffic[0].timestamp = 61 * DAY_MS + 30 * MINUTE_MS;
        store.apply_batch(&second).unwrap();
        store.rollup(62 * DAY_MS).unwrap();
        let rows = store
            .traffic_series(&TrafficQuery {
                from: 60 * DAY_MS,
                to: 62 * DAY_MS,
                resolution: AnalyticsResolution::Day,
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
        assert_eq!(rows.iter().map(|row| row.upload_bytes).sum::<u64>(), 200);
    }

    #[test]
    fn application_catalog_includes_late_classification_without_traffic_rewrite() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut batch = test_batch(1, "unknown", 120_000);
        batch.flows[0].application_id = "example-app".to_owned();
        batch.flows[0].organization_id = "example-org".to_owned();
        store.apply_batch(&batch).unwrap();
        let rows = store
            .application_summary(&SummaryQuery {
                from: 0,
                to: 1_000_000,
                resolution: AnalyticsResolution::Day,
                gateway_id: None,
                device_id: None,
                scope: None,
                direction: None,
                organization_id: None,
                application_id: None,
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        assert!(rows.iter().any(|row| row.key == "example-app"));
    }

    #[test]
    fn query_plan_uses_disjoint_day_hour_and_minute_segments() {
        let plan = AnalyticsQueryPlan::for_range(90 * 60_000, 2 * DAY_MS + 30 * 60_000);
        assert_eq!(plan.segments.len(), 4);
        assert_eq!(plan.segments[0].table, AnalyticsResolution::Minute);
        assert_eq!(plan.segments[1].table, AnalyticsResolution::Hour);
        assert!(
            plan.segments
                .iter()
                .any(|segment| segment.table == AnalyticsResolution::Day)
        );
        for pair in plan.segments.windows(2) {
            assert!(pair[0].to <= pair[1].from);
        }
    }

    #[test]
    fn rollup_watermark_backfills_each_missing_bucket_once() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut first = test_batch(1, "unknown", 3_600_000);
        first.traffic[0].timestamp = 60_000;
        let mut second = test_batch(2, "unknown", 7_200_000);
        second.traffic[0].timestamp = 3_660_000;
        store.apply_batch(&first).unwrap();
        store.apply_batch(&second).unwrap();
        assert!(store.rollup(4 * HOUR_MS).unwrap() > 0);
        let buckets: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM traffic_core_hour", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(buckets, 2);
        let watermark: u64 = store
            .connection
            .query_row(
                "SELECT completed_until FROM analytics_rollup_state WHERE rollup_name = 'core_hour'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark, 4 * HOUR_MS);
        assert_eq!(store.rollup(4 * HOUR_MS).unwrap(), 0);
        let repeated: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM traffic_core_hour", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(repeated, buckets);
    }

    #[test]
    fn rollup_same_hour_twice_does_not_change_data() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut batch = test_batch(1, "tcp", HOUR_MS);
        batch.traffic[0].timestamp = 30 * MINUTE_MS;
        store.apply_batch(&batch).unwrap();
        store.rollup(2 * HOUR_MS).unwrap();
        let first: (u64, u64) = store
            .connection
            .query_row(
                "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
                 FROM traffic_core_hour",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        store.rollup(2 * HOUR_MS).unwrap();
        let second: (u64, u64) = store
            .connection
            .query_row(
                "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
                 FROM traffic_core_hour",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(second, first);
    }

    #[test]
    fn rollup_advances_day_watermark_after_backfill() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut batch = test_batch(1, "tcp", DAY_MS + HOUR_MS);
        batch.traffic[0].timestamp = DAY_MS + MINUTE_MS;
        store.apply_batch(&batch).unwrap();
        store.rollup(2 * DAY_MS).unwrap();
        let watermark: u64 = store
            .connection
            .query_row(
                "SELECT completed_until FROM analytics_rollup_state WHERE rollup_name = 'core_day'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark, 2 * DAY_MS);
        let days: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM traffic_core_day", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(days, 1);
    }

    #[test]
    fn restart_preserves_rollup_watermark() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("analytics.duckdb");
        {
            let mut store = DuckDbAnalyticsStore::open(&path).unwrap();
            let mut batch = test_batch(1, "tcp", HOUR_MS);
            batch.traffic[0].timestamp = 30 * MINUTE_MS;
            store.apply_batch(&batch).unwrap();
            store.rollup(2 * HOUR_MS).unwrap();
        }
        let mut reopened = DuckDbAnalyticsStore::open(&path).unwrap();
        let watermark: u64 = reopened
            .connection
            .query_row(
                "SELECT completed_until FROM analytics_rollup_state WHERE rollup_name = 'core_hour'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark, 2 * HOUR_MS);
        reopened.rollup(2 * HOUR_MS).unwrap();
        let rows: u64 = reopened
            .connection
            .query_row("SELECT COUNT(*) FROM traffic_core_hour", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn duplicate_flow_versions_in_one_batch_keep_the_last_snapshot() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut batch = test_batch(1, "tls", 120_000);
        let mut latest = batch.flows[0].clone();
        latest.application_id = "example-app".to_owned();
        latest.application_confidence = 0.9;
        latest.checkpointed_at += 1;
        batch.flows.push(latest);

        assert_eq!(
            store.apply_batch(&batch).unwrap(),
            ApplyBatchResult::Applied
        );
        let page = store
            .flows(&FlowQuery {
                from: 0,
                to: 1_000_000,
                gateway_id: Some("gateway-1".to_owned()),
                limit: 10,
                ..FlowQuery::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.rows[0].application_id, "example-app");
    }

    #[test]
    fn duplicate_flow_versions_in_one_batch_do_not_double_correct_traffic() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let mut initial = test_batch(1, "tls", 120_000);
        initial.flows[0].application_id = "unknown".to_owned();
        store.apply_batch(&initial).unwrap();

        let mut batch = test_batch(2, "tls", 180_000);
        batch.traffic.clear();
        batch.flows[0].application_id = "first-app".to_owned();
        let mut latest = batch.flows[0].clone();
        latest.application_id = "example-app".to_owned();
        latest.checkpointed_at += 1;
        batch.flows.push(latest);
        store.apply_batch(&batch).unwrap();

        let corrected = store
            .application_summary(&SummaryQuery {
                from: 0,
                to: 1_000_000,
                resolution: AnalyticsResolution::Minute,
                gateway_id: None,
                device_id: None,
                scope: None,
                direction: None,
                organization_id: None,
                application_id: Some("example-app".to_owned()),
                category_id: None,
                protocol_id: None,
                domain: None,
                remote_ip: None,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        assert_eq!(corrected.first().map(|row| row.upload_bytes), Some(100));
        assert_eq!(corrected.first().map(|row| row.download_bytes), Some(200));
        let stale = store
            .application_summary(&SummaryQuery {
                application_id: Some("first-app".to_owned()),
                ..SummaryQuery {
                    from: 0,
                    to: 1_000_000,
                    resolution: AnalyticsResolution::Minute,
                    gateway_id: None,
                    device_id: None,
                    scope: None,
                    direction: None,
                    organization_id: None,
                    application_id: None,
                    category_id: None,
                    protocol_id: None,
                    domain: None,
                    remote_ip: None,
                    limit: 20,
                    offset: 0,
                }
            })
            .unwrap();
        assert!(stale.is_empty());
    }

    #[test]
    #[ignore = "manual performance benchmark; run with --ignored"]
    fn apply_batches_performance_smoke() {
        let mut store = DuckDbAnalyticsStore::open_in_memory().unwrap();
        let started = std::time::Instant::now();
        let mut batches = Vec::with_capacity(100);
        for sequence in 1..=100 {
            let mut batch = test_batch(sequence, "tcp", sequence * 60_000);
            let flow_template = batch.flows[0].clone();
            let traffic_template = batch.traffic[0].clone();
            batch.flows.clear();
            batch.traffic.clear();
            for index in 0..100 {
                let mut flow = flow_template.clone();
                flow.flow_id = format!("flow-{sequence}-{index}");
                batch.flows.push(flow);
                let mut traffic = traffic_template.clone();
                traffic.timestamp = sequence * 60_000;
                batch.traffic.push(traffic);
            }
            batches.push(batch);
        }
        store.apply_batches(&batches).unwrap();
        eprintln!(
            "apply_batches_performance_smoke batches=100 flows=10000 elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
}
