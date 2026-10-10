use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use netqmon_geo::GeoProvider;

use crate::CollectorState;
use crate::geo_updater;
use crate::realtime::format_ip;

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_PAGE_SIZE: u32 = 50;
const MAX_PAGE_SIZE: u32 = 200;
const MAX_OFFSET: u64 = 1_000_000;
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const DEFAULT_GATEWAY_OFFLINE_AFTER_MS: u64 = 30_000;
const DEFAULT_INSIGHT_WINDOW_MS: u64 = DAY_MS;
const MAX_INSIGHT_WINDOW_MS: u64 = 30 * DAY_MS;
const PROTOCOL_APPLICATION_PREFIX: &str = "protocol:";

pub(crate) fn router() -> Router<CollectorState> {
    Router::new()
        .route("/internal/overview", get(overview))
        .route("/internal/traffic", get(traffic))
        .route("/internal/clients", get(clients))
        .route("/internal/clients/{id}", get(client_detail))
        .route("/internal/clients/{id}/{relation}", get(client_related))
        .route("/internal/applications", get(applications))
        .route("/internal/organizations", get(organizations))
        .route("/internal/protocols", get(protocols))
        .route("/internal/applications/{id}", get(application_detail))
        .route(
            "/internal/applications/{id}/{relation}",
            get(application_related),
        )
        .route("/internal/domains", get(domains))
        .route("/internal/destinations", get(destinations))
        .route("/internal/geo", get(geo_summary))
        .route("/internal/insights", get(insights))
        .route("/internal/flows", get(flows))
        .route(
            "/internal/settings/retention",
            get(get_retention).put(put_retention),
        )
        .route("/internal/settings/retention/run", post(run_retention))
        .route("/internal/settings/rules/reload", post(reload_rules))
        .route("/internal/settings/diagnostics", get(diagnostics))
        .route("/internal/settings/geo", get(get_geo_settings))
        .route("/internal/settings/geo/update", post(post_geo_update))
        .route("/internal/settings/license", get(get_license))
        .route(
            "/internal/settings/license/activate",
            post(activate_license),
        )
        .route("/internal/settings/license/check", post(check_license))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateLicenseRequest {
    license_key: String,
}

async fn get_license(State(state): State<CollectorState>) -> Response {
    match state.license.status() {
        Ok(status) => Json(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            data: status,
            pagination: None,
        })
        .into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "license_state_error",
            &error,
        ),
    }
}

async fn activate_license(
    State(state): State<CollectorState>,
    Json(request): Json<ActivateLicenseRequest>,
) -> Response {
    if request.license_key.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_license_key",
            "license_key must not be empty",
        );
    }
    match state.license.activate(request.license_key.trim()).await {
        Ok(status) => Json(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            data: status,
            pagination: None,
        })
        .into_response(),
        Err(error) => api_error(StatusCode::BAD_GATEWAY, "license_activation_failed", &error),
    }
}

async fn check_license(State(state): State<CollectorState>) -> Response {
    match state.license.check().await {
        Ok(status) => Json(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            data: status,
            pagination: None,
        })
        .into_response(),
        Err(error) => api_error(StatusCode::BAD_GATEWAY, "license_check_failed", &error),
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    offset: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowPageQuery {
    limit: Option<u32>,
    offset: Option<u64>,
    from: Option<u64>,
    to: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationDetailQuery {
    limit: Option<u32>,
    offset: Option<u64>,
    category: Option<String>,
    from: Option<u64>,
    to: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationQuery {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
    offset: Option<u64>,
    lang: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeoQuery {
    from: Option<u64>,
    to: Option<u64>,
    lang: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct Page {
    limit: u32,
    offset: u64,
}

#[derive(Serialize)]
struct SuccessEnvelope<T> {
    schema_version: u8,
    data: T,
    pagination: Option<Pagination>,
}

#[derive(Serialize)]
struct Pagination {
    limit: u32,
    offset: u64,
    total: u64,
}

impl Page {
    fn parse(query: Result<Query<PageQuery>, QueryRejection>) -> Result<Self, Box<Response>> {
        let Query(query) = query.map_err(|error| {
            Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                &error.body_text(),
            ))
        })?;
        Self::from_query(query)
    }

    fn from_query(query: PageQuery) -> Result<Self, Box<Response>> {
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        let offset = query.offset.unwrap_or(0);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_pagination",
                "limit must be between 1 and 200",
            )));
        }
        if offset > MAX_OFFSET {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_pagination",
                "offset must not exceed 1000000",
            )));
        }
        Ok(Self { limit, offset })
    }
}

fn query_window(from: Option<u64>, to: Option<u64>) -> Result<Option<(i64, i64)>, &'static str> {
    match (from, to) {
        (None, None) => Ok(None),
        (Some(from), Some(to)) if from < to && i64::try_from(to).is_ok() => {
            Ok(Some((to_i64(from), to_i64(to))))
        }
        _ => Err("from and to must be supplied together as a valid timestamp range"),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficQuery {
    from: Option<u64>,
    to: Option<u64>,
    group_by: Option<String>,
    limit: Option<u32>,
    offset: Option<u64>,
    scope: Option<String>,
    direction: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InsightQuery {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
}

pub(crate) use crate::insights::InsightWindow;

fn parse_insight_window(
    query: Result<Query<InsightQuery>, QueryRejection>,
) -> Result<InsightWindow, Box<Response>> {
    let Query(query) = query.map_err(|error| {
        Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            &error.body_text(),
        ))
    })?;
    let to = query.to.unwrap_or_else(now_ms);
    let from = query
        .from
        .unwrap_or_else(|| to.saturating_sub(DEFAULT_INSIGHT_WINDOW_MS));
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if from >= to || to.saturating_sub(from) > MAX_INSIGHT_WINDOW_MS {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "insight range must be ordered and no longer than 30 days",
        )));
    }
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 200",
        )));
    }
    Ok(InsightWindow { from, to, limit })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    search: Option<String>,
    client: Option<String>,
    application: Option<String>,
    organization: Option<String>,
    detected_protocol: Option<String>,
    domain: Option<String>,
    ip: Option<String>,
    protocol: Option<String>,
    port: Option<u16>,
    direction: Option<String>,
    scope: Option<String>,
    path_type: Option<String>,
    nat: Option<String>,
    from: Option<u64>,
    to: Option<u64>,
    sort: Option<String>,
    order: Option<String>,
}

#[derive(Clone, Debug)]
struct FlowCursor {
    sort_value: i64,
    id: String,
}

struct FlowPageOptions {
    limit: u32,
    sort_column: &'static str,
    sort_name: &'static str,
    descending: bool,
    cursor: Option<FlowCursor>,
}

#[allow(clippy::too_many_lines)]
async fn overview(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(response) = Page::parse(query) {
        return *response;
    }
    let snapshot = state.realtime_snapshot();
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        let now = now_ms();
        let offline_after_ms = gateway_offline_after_ms();
        return clickhouse
            .query_overview(now, offline_after_ms, None)
            .map(|mut value| {
                let gateway_status = value["gateway_status"]
                    .as_str()
                    .unwrap_or("unenrolled")
                    .to_owned();
                let warning = capture_warning(&gateway_status, &snapshot);
                if let Some(gateway) = value["gateway"].as_object_mut() {
                    let health = snapshot.gateway_health.as_ref();
                    if let Some(health) = health {
                        gateway.insert("agent_version".to_owned(), json!(health.agent_version));
                        gateway.insert("kernel_version".to_owned(), json!(health.kernel_version));
                        gateway.insert("openwrt_version".to_owned(), json!(health.openwrt_version));
                    }
                    gateway.insert(
                        "offloading_status".to_owned(),
                        json!(
                            health.map_or("unknown", |value| value.hardware_flow_offload.as_str())
                        ),
                    );
                    gateway.insert(
                        "capture_interface".to_owned(),
                        json!(health.map_or("", |value| value.capture_interface.as_str())),
                    );
                    gateway.insert(
                        "capture_interfaces".to_owned(),
                        json!(
                            health.map_or_else(Vec::new, |value| value.capture_interfaces.clone())
                        ),
                    );
                    gateway.insert(
                        "interface_counter_sanity".to_owned(),
                        json!(
                            health
                                .map_or("unknown", |value| value.interface_counter_sanity.as_str())
                        ),
                    );
                    gateway.insert(
                        "interface_delta_bytes".to_owned(),
                        json!(health.map_or(0, |value| value.interface_delta_bytes)),
                    );
                    gateway.insert(
                        "flow_delta_bytes".to_owned(),
                        json!(health.map_or(0, |value| value.flow_delta_bytes)),
                    );
                    gateway.insert("capture_warning".to_owned(), json!(warning));
                    gateway.insert("offline_after_ms".to_owned(), json!(offline_after_ms));
                }
                json!({
                    "gateway_status": gateway_status,
                    "gateway": value["gateway"].clone(),
                    "realtime": snapshot,
                    "last_24_hours": {
                        "upload_bytes": value["traffic_total_upload_bytes_24h"].clone(),
                        "download_bytes": value["traffic_total_download_bytes_24h"].clone(),
                    },
                    "device_count": value["devices"].clone(),
                    "application_count": value["applications"].clone(),
                })
            })
            .map_or_else(storage_error, api_ok);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<Value> {
        let now = now_ms();
        let offline_after_ms = gateway_offline_after_ms();
        let devices: i64 = scalar(connection, "SELECT COUNT(*) FROM devices", [])?;
        let applications: i64 = scalar(
            connection,
            "SELECT COUNT(DISTINCT application_id) FROM traffic_application_minute",
            [],
        )?;
        let historical: (i64, i64) = connection.query_row(
            "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
             FROM traffic_total_minute WHERE timestamp >= ?1",
            [to_i64(now.saturating_sub(DAY_MS))],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let gateway = connection
            .query_row(
                "SELECT id, name, agent_version, kernel_version, openwrt_version, last_seen
                 FROM gateways ORDER BY created_at LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let gateway_status = gateway.as_ref().map_or("unenrolled", |gateway| {
            if now.saturating_sub(to_u64(gateway.5)) <= offline_after_ms {
                "online"
            } else {
                "offline"
            }
        });
        let capture_warning = capture_warning(gateway_status, &snapshot);
        let gateway = gateway.map(|gateway| {
            let health = snapshot.gateway_health.as_ref();
            json!({
                "id": gateway.0,
                "name": gateway.1,
                "status": gateway_status,
                "last_seen": gateway.5,
                "agent_version": health.map_or(gateway.2.as_str(), |value| value.agent_version.as_str()),
                "kernel_version": health.map_or(gateway.3.as_str(), |value| value.kernel_version.as_str()),
                "openwrt_version": health.map_or(gateway.4.as_str(), |value| value.openwrt_version.as_str()),
                "offloading_status": health.map_or("unknown", |value| value.hardware_flow_offload.as_str()),
                "capture_interface": health.map_or("", |value| value.capture_interface.as_str()),
                "capture_interfaces": health.map_or_else(Vec::new, |value| value.capture_interfaces.clone()),
                "interface_counter_sanity": health.map_or("unknown", |value| value.interface_counter_sanity.as_str()),
                "interface_delta_bytes": health.map_or(0, |value| value.interface_delta_bytes),
                "flow_delta_bytes": health.map_or(0, |value| value.flow_delta_bytes),
                "capture_warning": capture_warning,
                "offline_after_ms": offline_after_ms,
            })
        });
        Ok(json!({
            "gateway_status": gateway_status,
            "gateway": gateway,
            "realtime": snapshot,
            "last_24_hours": {
                "upload_bytes": historical.0,
                "download_bytes": historical.1,
            },
            "device_count": devices,
            "application_count": applications,
        }))
    })();
    result.map_or_else(storage_error, api_ok)
}

fn capture_warning(
    gateway_status: &str,
    snapshot: &crate::realtime::RealtimeSnapshot,
) -> Option<String> {
    if gateway_status == "offline" {
        return Some("No gateway telemetry has arrived within the offline threshold".to_owned());
    }
    let Some(health) = snapshot.gateway_health.as_ref() else {
        return Some("Capture health telemetry has not been reported".to_owned());
    };
    let mut reasons = Vec::new();
    if health.hardware_flow_offload == "enabled" {
        reasons.push("hardware flow offloading is enabled".to_owned());
    }
    if health.dropped_batches > 0 {
        reasons.push(format!(
            "{} dropped telemetry batches",
            health.dropped_batches
        ));
    }
    if health.dns_dropped_events > 0 {
        reasons.push(format!("{} dropped DNS events", health.dns_dropped_events));
    }
    if health.protocol_probe_dropped_events > 0 {
        reasons.push(format!(
            "{} dropped protocol probe events",
            health.protocol_probe_dropped_events
        ));
    }
    if health.interface_counter_sanity == "degraded" {
        reasons.push(format!(
            "interface counters exceeded captured flow deltas ({}B interface, {}B flows)",
            health.interface_delta_bytes, health.flow_delta_bytes
        ));
    }
    (!reasons.is_empty()).then(|| format!("Capture degraded: {}", reasons.join("; ")))
}

async fn traffic(
    State(state): State<CollectorState>,
    query: Result<Query<TrafficQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::parse(Ok(Query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }))) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let to = query.to.unwrap_or_else(now_ms);
    let from = query.from.unwrap_or_else(|| to.saturating_sub(DAY_MS));
    if from >= to || to > i64::MAX as u64 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "from must be less than to and both timestamps must fit signed 64-bit milliseconds",
        );
    }
    let group_by = query.group_by.as_deref().unwrap_or("none");
    if !matches!(
        group_by,
        "none" | "client" | "application" | "category" | "protocol_l7" | "protocol_l4" | "protocol"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group_by",
            "group_by must be one of none, client, application, category, protocol_l7, or protocol_l4",
        );
    }
    let normalized_group_by = if group_by == "protocol" {
        "protocol_l7"
    } else {
        group_by
    };
    let scope = match traffic_scope(query.scope.as_deref().unwrap_or("internet")) {
        Ok(value) => value,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_scope", message),
    };
    let direction = match traffic_direction(query.direction.as_deref().unwrap_or("both")) {
        Ok(value) => value,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_direction", message),
    };
    traffic_breakdown(
        &state,
        from,
        to,
        normalized_group_by,
        page,
        scope,
        direction,
    )
}

fn traffic_breakdown(
    state: &CollectorState,
    from: u64,
    to: u64,
    group_by: &str,
    page: Page,
    scope: Option<i64>,
    direction: Option<i64>,
) -> Response {
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        let duration = to.saturating_sub(from);
        let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
        return clickhouse
            .query_traffic_breakdown(
                from,
                to,
                group_by,
                page.limit,
                page.offset,
                scope,
                direction,
                bucket_ms,
            )
            .map(|mut data| {
                if group_by == "application" {
                    if let Some(items) = data["breakdown"].as_array_mut() {
                        for item in items {
                            let id = item["id"].as_str().unwrap_or("unknown");
                            let metadata = inner.classifier.application_metadata(id);
                            if let Some(object) = item.as_object_mut() {
                                object.insert(
                                    "name".to_owned(),
                                    json!(metadata.as_ref().map(|value| value.name.clone())),
                                );
                                object.insert("icon".to_owned(), icon_json(metadata));
                            }
                        }
                    }
                }
                data
            })
            .map_or_else(storage_error, api_ok);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<Value> {
        // Keep historical charts bounded while retaining the exact requested window.
        let duration = to.saturating_sub(from);
        let raw_bucket = duration.div_ceil(180);
        let bucket_ms = raw_bucket.max(60_000).div_ceil(60_000) * 60_000;
        let mut points_statement = connection.prepare(
            "SELECT (timestamp / ?1) * ?1 AS bucket, SUM(upload_bytes),
                    SUM(download_bytes), SUM(packets), SUM(flow_count)
             FROM traffic_scope_minute WHERE timestamp >= ?2 AND timestamp < ?3
               AND (?4 IS NULL OR scope = ?4) AND (?5 IS NULL OR direction = ?5)
             GROUP BY bucket ORDER BY bucket",
        )?;
        let points = points_statement
            .query_map(
                params![
                    to_i64(bucket_ms),
                    to_i64(from),
                    to_i64(to),
                    scope,
                    direction
                ],
                |row| {
                    Ok(json!({
                        "timestamp": row.get::<_, i64>(0)?,
                        "upload_bytes": row.get::<_, i64>(1)?,
                        "download_bytes": row.get::<_, i64>(2)?,
                        "packets": row.get::<_, i64>(3)?,
                        "flow_count": row.get::<_, i64>(4)?,
                    }))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let (breakdown_sql, has_limit) = traffic_breakdown_query(group_by);
        let mut breakdown_statement = connection.prepare(breakdown_sql)?;
        let map_row = |row: &rusqlite::Row<'_>| {
            let mac = row
                .get::<_, Option<Vec<u8>>>(2)?
                .map(|value| format_mac(&value));
            let id = row.get::<_, String>(0)?;
            let mut value = json!({
                "id": id,
                "name": row.get::<_, String>(1)?,
                "mac": mac,
                "upload_bytes": row.get::<_, i64>(3)?,
                "download_bytes": row.get::<_, i64>(4)?,
                "packets": row.get::<_, i64>(5)?,
                "flow_count": row.get::<_, i64>(6)?,
                "last_seen": row.get::<_, Option<i64>>(7)?,
            });
            if group_by == "application" {
                if let Some(object) = value.as_object_mut() {
                    let application_id = object
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let metadata = inner.classifier.application_metadata(application_id);
                    object.insert(
                        "name".to_owned(),
                        json!(metadata.as_ref().map(|metadata| metadata.name.clone())),
                    );
                    object.insert("icon".to_owned(), icon_json(metadata));
                }
            }
            Ok(value)
        };
        let breakdown = if has_limit {
            breakdown_statement
                .query_map(
                    params![
                        to_i64(from),
                        to_i64(to),
                        scope,
                        direction,
                        i64::from(page.limit),
                        to_i64(page.offset)
                    ],
                    map_row,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            breakdown_statement
                .query_map(params![to_i64(from), to_i64(to), scope, direction], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(json!({
            "from": from,
            "to": to,
            "bucket_ms": bucket_ms,
            "group_by": group_by,
            "scope": query_scope_name(scope),
            "direction": query_direction_name(direction),
            "points": points,
            "breakdown": breakdown,
        }))
    })();
    result.map_or_else(storage_error, api_ok)
}

fn traffic_breakdown_query(group_by: &str) -> (&'static str, bool) {
    match group_by {
        "client" => (
            "SELECT CAST(d.id AS TEXT), COALESCE(d.display_name, d.hostname, ''), d.mac,
                    SUM(t.upload_bytes), SUM(t.download_bytes), SUM(t.packets), SUM(t.flow_count),
                    MAX(t.timestamp)
             FROM traffic_scope_minute t JOIN devices d ON d.id = t.device_id
             WHERE t.timestamp >= ?1 AND t.timestamp < ?2
               AND (?3 IS NULL OR t.scope = ?3) AND (?4 IS NULL OR t.direction = ?4)
             GROUP BY d.id ORDER BY SUM(t.upload_bytes + t.download_bytes) DESC
             LIMIT ?5 OFFSET ?6",
            true,
        ),
        "application" => (
            "SELECT t.application_id, t.application_id, NULL,
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count),
                    MAX(timestamp)
             FROM traffic_scope_minute t WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR t.scope = ?3) AND (?4 IS NULL OR t.direction = ?4)
             GROUP BY t.application_id ORDER BY SUM(upload_bytes + download_bytes) DESC
             LIMIT ?5 OFFSET ?6",
            true,
        ),
        "category" => (
            "SELECT t.category_id, t.category_id, NULL,
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count),
                    MAX(timestamp)
             FROM traffic_scope_minute t WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR t.scope = ?3) AND (?4 IS NULL OR t.direction = ?4)
             GROUP BY t.category_id ORDER BY SUM(upload_bytes + download_bytes) DESC
             LIMIT ?5 OFFSET ?6",
            true,
        ),
        "protocol_l7" | "protocol" => (
            "SELECT COALESCE(t.protocol_id, 'unknown'), COALESCE(t.protocol_id, 'unknown'), NULL,
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count),
                    MAX(timestamp)
             FROM traffic_scope_minute t WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR t.scope = ?3) AND (?4 IS NULL OR t.direction = ?4)
             GROUP BY COALESCE(t.protocol_id, 'unknown') ORDER BY SUM(upload_bytes + download_bytes) DESC
             LIMIT ?5 OFFSET ?6",
            true,
        ),
        "protocol_l4" => (
            "SELECT CASE t.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' WHEN 1 THEN 'icmp' WHEN 58 THEN 'icmpv6' ELSE CAST(t.protocol AS TEXT) END,
                    CASE t.protocol WHEN 6 THEN 'TCP' WHEN 17 THEN 'UDP' WHEN 1 THEN 'ICMP' WHEN 58 THEN 'ICMPv6' ELSE 'IP ' || CAST(t.protocol AS TEXT) END,
                    NULL,
                    SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count),
                    MAX(timestamp)
             FROM traffic_scope_minute t WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR t.scope = ?3) AND (?4 IS NULL OR t.direction = ?4)
             GROUP BY t.protocol ORDER BY SUM(upload_bytes + download_bytes) DESC
             LIMIT ?5 OFFSET ?6",
            true,
        ),
        _ => (
            "SELECT 'total', 'All traffic', NULL,
                    COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0),
                    COALESCE(SUM(packets), 0), COALESCE(SUM(flow_count), 0), MAX(timestamp)
             FROM traffic_scope_minute WHERE timestamp >= ?1 AND timestamp < ?2
               AND (?3 IS NULL OR scope = ?3) AND (?4 IS NULL OR direction = ?4)",
            false,
        ),
    }
}

fn traffic_scope(value: &str) -> Result<Option<i64>, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "internet" => Ok(Some(netqmon_protocol::v1::FlowScope::Internet as i64)),
        "internal" => Ok(Some(netqmon_protocol::v1::FlowScope::Internal as i64)),
        "tunnel" => Ok(Some(netqmon_protocol::v1::FlowScope::Tunnel as i64)),
        _ => Err("scope must be one of internet, internal, tunnel, or all"),
    }
}

fn traffic_direction(value: &str) -> Result<Option<i64>, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "both" => Ok(None),
        "upload" => Ok(Some(netqmon_protocol::v1::Direction::Upload as i64)),
        "download" => Ok(Some(netqmon_protocol::v1::Direction::Download as i64)),
        _ => Err("direction must be one of both, upload, or download"),
    }
}

fn query_scope_name(value: Option<i64>) -> &'static str {
    match value {
        Some(value) if value == netqmon_protocol::v1::FlowScope::Internet as i64 => "internet",
        Some(value) if value == netqmon_protocol::v1::FlowScope::Internal as i64 => "internal",
        Some(value) if value == netqmon_protocol::v1::FlowScope::Tunnel as i64 => "tunnel",
        _ => "all",
    }
}

fn query_direction_name(value: Option<i64>) -> &'static str {
    match value {
        Some(value) if value == netqmon_protocol::v1::Direction::Upload as i64 => "upload",
        Some(value) if value == netqmon_protocol::v1::Direction::Download as i64 => "download",
        _ => "both",
    }
}

async fn clients(
    State(state): State<CollectorState>,
    query: Result<Query<WindowPageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::from_query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let window = match query_window(query.from, query.to) {
        Ok(window) => window,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_time_range", message),
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        let query = match window {
            Some((from, to)) => {
                clickhouse.query_clients_in_range(page.limit, page.offset, from, to)
            }
            None => clickhouse.query_clients(page.limit, page.offset),
        };
        return query.map_or_else(storage_error, |(items, total)| page_ok(items, page, total));
    }
    query_clients(inner.storage.connection(), page, window)
        .map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

async fn client_detail(
    State(state): State<CollectorState>,
    Path(id): Path<String>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(response) = Page::parse(query) {
        return *response;
    }
    let Ok(id) = id.parse::<i64>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_id",
            "client id must be an integer",
        );
    };
    if id <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_id",
            "client id must be positive",
        );
    }
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return match clickhouse.query_client_detail(id) {
            Ok(Some(value)) => api_ok(value),
            Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "client was not found"),
            Err(error) => storage_error(error),
        };
    }
    match query_client_detail(inner.storage.connection(), id) {
        Ok(Some(value)) => api_ok(value),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "client was not found"),
        Err(error) => storage_error(error),
    }
}

async fn client_related(
    State(state): State<CollectorState>,
    Path((id, relation)): Path<(String, String)>,
    query: Result<Query<RelatedQuery>, QueryRejection>,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_id",
            "client id must be an integer",
        );
    };
    if id <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_id",
            "client id must be positive",
        );
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::parse(Ok(Query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }))) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let to = query.to.unwrap_or_else(now_ms);
    let from = query.from.unwrap_or_else(|| to.saturating_sub(DAY_MS));
    if from >= to {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "from must be less than to",
        );
    }
    let scope = match traffic_scope(query.scope.as_deref().unwrap_or("internet")) {
        Ok(value) => value,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_scope", message),
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        if !matches!(
            relation.as_str(),
            "traffic" | "applications" | "domains" | "destinations" | "flows"
        ) {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "client relation was not found",
            );
        }
        return clickhouse
            .query_client_related(id, &relation, from, to, scope, page.limit, page.offset)
            .map(|mut value| {
                if let Some(items) = value.as_array_mut() {
                    if matches!(relation.as_str(), "applications" | "flows") {
                        for item in items {
                            let app = item["application_id"]
                                .as_str()
                                .or_else(|| item["application"].as_str())
                                .unwrap_or("unknown");
                            let metadata = inner.classifier.application_metadata(app);
                            if relation == "applications" {
                                if let Some(object) = item.as_object_mut() {
                                    object.insert(
                                        "name".to_owned(),
                                        json!(metadata.as_ref().map(|value| value.name.clone())),
                                    );
                                    object.insert("icon".to_owned(), icon_json(metadata));
                                }
                            } else if let Some(object) = item.as_object_mut() {
                                object.insert(
                                    "application_name".to_owned(),
                                    json!(metadata.as_ref().map(|value| value.name.clone())),
                                );
                                object.insert("icon".to_owned(), icon_json(metadata));
                            }
                        }
                    }
                }
                value
            })
            .map_or_else(storage_error, api_ok);
    }
    let connection = inner.storage.connection();
    let result = match relation.as_str() {
        "traffic" => query_client_traffic(connection, id, from, to, scope),
        "applications" => {
            query_client_applications(connection, &inner.classifier, id, page, from, to, scope)
        }
        "domains" => query_client_domains(connection, id, page, from, to, scope),
        "destinations" => query_client_destinations(connection, id, page, from, to, scope),
        "flows" => query_client_flows(connection, &inner.classifier, id, page, from, to, scope),
        _ => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "client relation was not found",
            );
        }
    };
    result.map_or_else(storage_error, api_ok)
}

fn query_client_traffic(
    connection: &Connection,
    id: i64,
    from: u64,
    to: u64,
    scope: Option<i64>,
) -> rusqlite::Result<Value> {
    let duration = to.saturating_sub(from);
    let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
    let mut statement = connection.prepare(
        "SELECT (timestamp / ?1) * ?1 AS bucket, SUM(upload_bytes), SUM(download_bytes),
                SUM(packets), SUM(flow_count)
         FROM traffic_scope_minute WHERE device_id = ?2 AND timestamp >= ?3 AND timestamp < ?4
           AND (?5 IS NULL OR scope = ?5)
         GROUP BY bucket ORDER BY bucket",
    )?;
    let points = statement
        .query_map(
            params![to_i64(bucket_ms), id, to_i64(from), to_i64(to), scope],
            |row| {
                Ok(json!({
                    "timestamp": row.get::<_, i64>(0)?, "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?, "packets": row.get::<_, i64>(3)?,
                    "flow_count": row.get::<_, i64>(4)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({ "bucket_ms": bucket_ms, "points": points }))
}

fn query_client_applications(
    connection: &Connection,
    classifier: &crate::classifier::ClassifierHandle,
    id: i64,
    page: Page,
    from: u64,
    to: u64,
    scope: Option<i64>,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(
        "SELECT COALESCE(application_id, 'unknown'), COALESCE(category_id, 'unknown'),
                SUM(upload_bytes), SUM(download_bytes), SUM(packets), COUNT(*), MAX(last_seen_at),
                AVG(COALESCE(classification_confidence, 0))
         FROM flow_sessions WHERE device_id = ?1 AND last_seen_at >= ?2 AND last_seen_at < ?3
           AND (?4 IS NULL OR scope = ?4)
         GROUP BY application_id, category_id ORDER BY SUM(upload_bytes + download_bytes) DESC
         LIMIT ?5 OFFSET ?6",
    )?;
    let items = statement
        .query_map(
            params![
                id,
                to_i64(from),
                to_i64(to),
                scope,
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                let application_id = row.get::<_, String>(0)?;
                let metadata = classifier.application_metadata(&application_id);
                Ok(json!({
                    "application_id": application_id,
                    "name": metadata.as_ref().map(|metadata| metadata.name.clone()),
                    "category_id": row.get::<_, String>(1)?,
                    "upload_bytes": row.get::<_, i64>(2)?, "download_bytes": row.get::<_, i64>(3)?,
                    "packets": row.get::<_, i64>(4)?, "flow_count": row.get::<_, i64>(5)?,
                    "last_seen": row.get::<_, i64>(6)?, "confidence": row.get::<_, f64>(7)?,
                    "client_count": 1,
                    "icon": icon_json(metadata),
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_client_domains(
    connection: &Connection,
    id: i64,
    page: Page,
    from: u64,
    to: u64,
    scope: Option<i64>,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(
        "SELECT domain, SUM(upload_bytes), SUM(download_bytes), SUM(packets), COUNT(*), MAX(last_seen_at)
         FROM flow_sessions WHERE device_id = ?1 AND domain IS NOT NULL
           AND last_seen_at >= ?2 AND last_seen_at < ?3
           AND (?4 IS NULL OR scope = ?4)
         GROUP BY domain ORDER BY SUM(upload_bytes + download_bytes) DESC LIMIT ?5 OFFSET ?6",
    )?;
    let items = statement
        .query_map(
            params![
                id,
                to_i64(from),
                to_i64(to),
                scope,
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                Ok(json!({
                    "domain": row.get::<_, String>(0)?, "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?, "packets": row.get::<_, i64>(3)?,
                    "flow_count": row.get::<_, i64>(4)?, "last_seen": row.get::<_, i64>(5)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_client_destinations(
    connection: &Connection,
    id: i64,
    page: Page,
    from: u64,
    to: u64,
    scope: Option<i64>,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(
        "SELECT remote_ip, MAX(domain), SUM(upload_bytes), SUM(download_bytes), SUM(packets), COUNT(*), MAX(last_seen_at)
         FROM flow_sessions WHERE device_id = ?1 AND last_seen_at >= ?2 AND last_seen_at < ?3
           AND (?4 IS NULL OR scope = ?4)
         GROUP BY remote_ip ORDER BY SUM(upload_bytes + download_bytes) DESC LIMIT ?5 OFFSET ?6",
    )?;
    let items = statement
        .query_map(
            params![
                id,
                to_i64(from),
                to_i64(to),
                scope,
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                let ip: Vec<u8> = row.get(0)?;
                Ok(json!({
                    "remote_ip": format_ip(&ip), "domain": row.get::<_, Option<String>>(1)?,
                    "upload_bytes": row.get::<_, i64>(2)?, "download_bytes": row.get::<_, i64>(3)?,
                    "packets": row.get::<_, i64>(4)?, "flow_count": row.get::<_, i64>(5)?,
                    "last_seen": row.get::<_, i64>(6)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_client_flows(
    connection: &Connection,
    classifier: &crate::classifier::ClassifierHandle,
    id: i64,
    page: Page,
    from: u64,
    to: u64,
    scope: Option<i64>,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(
        "SELECT id, client_ip, client_port, remote_ip, remote_port, protocol, direction, domain,
                COALESCE(application_id, 'unknown'), COALESCE(category_id, 'unknown'),
                COALESCE(classification_confidence, 0), COALESCE(classification_reason, 'no matching rule'),
                upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                scope, path_type, nat, source_segment, destination_segment
         FROM flow_sessions WHERE device_id = ?1 AND last_seen_at >= ?2 AND last_seen_at < ?3
           AND (?4 IS NULL OR scope = ?4)
         ORDER BY last_seen_at DESC LIMIT ?5 OFFSET ?6",
    )?;
    let items = statement.query_map(
        params![id, to_i64(from), to_i64(to), scope, i64::from(page.limit), to_i64(page.offset)],
        |row| {
            let client_ip: Vec<u8> = row.get(1)?;
            let remote_ip: Vec<u8> = row.get(3)?;
            let application = row.get::<_, String>(8)?;
            let application_metadata = classifier.application_metadata(&application);
            let application_name = application_metadata
                .as_ref()
                .map(|metadata| metadata.name.clone());
            let icon = icon_json(application_metadata);
            Ok(json!({
            "id": row.get::<_, String>(0)?, "client_ip": format_ip(&client_ip), "client_port": row.get::<_, i64>(2)?,
            "remote_ip": format_ip(&remote_ip), "remote_port": row.get::<_, i64>(4)?, "protocol": row.get::<_, i64>(5)?,
            "direction": row.get::<_, i64>(6)?, "domain": row.get::<_, Option<String>>(7)?,
            "application": application, "application_name": application_name, "icon": icon, "category": row.get::<_, String>(9)?,
            "confidence": row.get::<_, f64>(10)?, "reason": row.get::<_, String>(11)?,
            "upload_bytes": row.get::<_, i64>(12)?, "download_bytes": row.get::<_, i64>(13)?,
            "packets": row.get::<_, i64>(14)?, "started_at": row.get::<_, i64>(15)?,
            "last_seen": row.get::<_, i64>(16)?, "ended_at": row.get::<_, Option<i64>>(17)?,
            "scope": flow_scope_name(row.get::<_, i32>(18)?),
            "path_type": flow_path_name(row.get::<_, i32>(19)?),
            "nat": flow_nat_name(row.get::<_, i32>(20)?),
            "source_segment": row.get::<_, String>(21)?,
            "destination_segment": row.get::<_, String>(22)?,
        }))
        },
    )?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

async fn applications(
    State(state): State<CollectorState>,
    query: Result<Query<WindowPageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::from_query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let window = match query_window(query.from, query.to) {
        Ok(window) => window,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_time_range", message),
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return clickhouse
            .query_applications_for_window(page.limit, page.offset, window)
            .map(|(mut items, total)| {
                for item in &mut items {
                    let application_id = item["application_id"].as_str().unwrap_or("unknown");
                    let application = inner.classifier.application_metadata(application_id);
                    let organization_id = item["organization_id"].as_str().unwrap_or("unknown");
                    let organization = (organization_id != "unknown")
                        .then(|| inner.classifier.organization_metadata(organization_id))
                        .flatten();
                    if let Some(object) = item.as_object_mut() {
                        object.insert(
                            "name".to_owned(),
                            json!(application.as_ref().map(|value| value.name.clone())),
                        );
                        object.insert("icon".to_owned(), icon_json(application));
                        object.insert(
                            "organization_name".to_owned(),
                            json!(organization.as_ref().map(|value| value.name.clone())),
                        );
                    }
                }
                page_ok(items, page, total)
            })
            .unwrap_or_else(storage_error);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let total = if let Some((from, to)) = window {
            scalar(
                connection,
                "SELECT COUNT(*) FROM (
                    SELECT application_id, category_id FROM traffic_application_minute
                    WHERE timestamp >= ?1 AND timestamp < ?2
                    GROUP BY application_id, category_id
                 )",
                params![from, to],
            )?
        } else {
            scalar(
                connection,
                "SELECT COUNT(*) FROM (
                    SELECT application_id, category_id FROM traffic_application_minute
                    GROUP BY application_id, category_id
                 )",
                [],
            )?
        };
        let query_sql = if window.is_some() {
            "WITH app_totals AS (
                 SELECT application_id, category_id, SUM(upload_bytes) AS upload_bytes,
                        SUM(download_bytes) AS download_bytes, SUM(packets) AS packets,
                        SUM(flow_count) AS flow_count, MAX(timestamp) AS last_seen
                 FROM traffic_application_minute
                 WHERE timestamp >= ?1 AND timestamp < ?2
                 GROUP BY application_id, category_id
             ), client_counts AS (
                 SELECT CASE WHEN COALESCE(application_id, 'unknown') = 'unknown' AND COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
                             THEN 'protocol:' || COALESCE(NULLIF(protocol_id, ''), 'unknown') ELSE COALESCE(application_id, 'unknown') END AS application_id,
                        COUNT(DISTINCT device_id) AS client_count
                 FROM flow_sessions
                 WHERE device_id IS NOT NULL AND last_seen_at >= ?1 AND last_seen_at < ?2
                 GROUP BY CASE WHEN COALESCE(application_id, 'unknown') = 'unknown' AND COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
                               THEN 'protocol:' || COALESCE(NULLIF(protocol_id, ''), 'unknown') ELSE COALESCE(application_id, 'unknown') END
             )
             SELECT t.application_id, t.category_id, t.upload_bytes, t.download_bytes,
                    t.packets, t.flow_count, t.last_seen, COALESCE(c.client_count, 0),
                    CASE
                            WHEN t.application_id IN ('unknown', 'protocol-only') OR t.application_id LIKE 'protocol:%' THEN NULL
                        ELSE (SELECT f.organization_id FROM flow_sessions f
                              WHERE f.application_id = t.application_id
                                AND f.organization_id IS NOT NULL AND f.organization_id != 'unknown'
                              LIMIT 1)
                    END
             FROM app_totals t LEFT JOIN client_counts c ON c.application_id = t.application_id
             ORDER BY t.upload_bytes + t.download_bytes DESC, t.application_id
             LIMIT ?3 OFFSET ?4"
        } else {
            "WITH app_totals AS (
                 SELECT application_id, category_id, SUM(upload_bytes) AS upload_bytes,
                        SUM(download_bytes) AS download_bytes, SUM(packets) AS packets,
                        SUM(flow_count) AS flow_count, MAX(timestamp) AS last_seen
                 FROM traffic_application_minute
                 GROUP BY application_id, category_id
             ), client_counts AS (
                 SELECT CASE WHEN COALESCE(application_id, 'unknown') = 'unknown' AND COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
                             THEN 'protocol:' || COALESCE(NULLIF(protocol_id, ''), 'unknown') ELSE COALESCE(application_id, 'unknown') END AS application_id,
                        COUNT(DISTINCT device_id) AS client_count
                 FROM flow_sessions WHERE device_id IS NOT NULL
                 GROUP BY CASE WHEN COALESCE(application_id, 'unknown') = 'unknown' AND COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
                               THEN 'protocol:' || COALESCE(NULLIF(protocol_id, ''), 'unknown') ELSE COALESCE(application_id, 'unknown') END
             )
             SELECT t.application_id, t.category_id, t.upload_bytes, t.download_bytes,
                    t.packets, t.flow_count, t.last_seen, COALESCE(c.client_count, 0),
                    CASE
                            WHEN t.application_id IN ('unknown', 'protocol-only') OR t.application_id LIKE 'protocol:%' THEN NULL
                        ELSE (SELECT f.organization_id FROM flow_sessions f
                              WHERE f.application_id = t.application_id
                                AND f.organization_id IS NOT NULL AND f.organization_id != 'unknown'
                              LIMIT 1)
                    END
             FROM app_totals t LEFT JOIN client_counts c ON c.application_id = t.application_id
             ORDER BY t.upload_bytes + t.download_bytes DESC, t.application_id
             LIMIT ?1 OFFSET ?2"
        };
        let mut statement = connection.prepare(query_sql)?;
        let map_row = |row: &Row<'_>| map_application_row(row, &inner);
        let items = match window {
            Some((from, to)) => statement
                .query_map(
                    params![from, to, i64::from(page.limit), to_i64(page.offset)],
                    map_row,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => statement
                .query_map(params![i64::from(page.limit), to_i64(page.offset)], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        Ok((items, to_u64(total)))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

fn map_application_row(row: &Row<'_>, inner: &crate::CollectorInner) -> rusqlite::Result<Value> {
    let application_id = row.get::<_, String>(0)?;
    let application_metadata = inner.classifier.application_metadata(&application_id);
    let organization_id = if matches!(application_id.as_str(), "unknown" | "protocol-only") {
        None
    } else if application_id.starts_with(PROTOCOL_APPLICATION_PREFIX) {
        None
    } else {
        row.get::<_, Option<String>>(8)?
    };
    let organization_metadata = organization_id
        .as_deref()
        .filter(|id| !id.is_empty() && *id != "unknown")
        .and_then(|id| inner.classifier.organization_metadata(id));
    Ok(json!({
        "application_id": application_id,
        "name": application_metadata
            .as_ref()
            .map(|metadata| metadata.name.clone()),
        "category_id": row.get::<_, String>(1)?,
        "upload_bytes": row.get::<_, i64>(2)?,
        "download_bytes": row.get::<_, i64>(3)?,
        "packets": row.get::<_, i64>(4)?,
        "flow_count": row.get::<_, i64>(5)?,
        "last_seen": row.get::<_, i64>(6)?,
        "client_count": row.get::<_, i64>(7)?,
        "organization_id": organization_id,
        "organization_name": organization_metadata.as_ref().map(|metadata| metadata.name.clone()),
        "icon": icon_json(application_metadata),
    }))
}

fn sqlite_application_flow_filter(id_parameter: &str, prefix: &str) -> String {
    let application = format!("COALESCE({prefix}application_id, 'unknown')");
    let protocol = format!("COALESCE(NULLIF({prefix}protocol_id, ''), 'unknown')");
    format!(
        "(({id_parameter} LIKE '{PROTOCOL_APPLICATION_PREFIX}%' AND {application} = 'unknown' AND {protocol} = substr({id_parameter}, 10)) \
         OR ({id_parameter} = 'unknown' AND {application} = 'unknown' AND {protocol} = 'unknown') \
         OR ({id_parameter} NOT IN ('unknown', 'protocol-only') AND {id_parameter} NOT LIKE '{PROTOCOL_APPLICATION_PREFIX}%' AND {application} = {id_parameter}))"
    )
}

async fn organizations(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return clickhouse
            .query_flow_groups("organization_id", page.limit, page.offset)
            .map(|(mut items, total)| {
                for item in &mut items {
                    let id = item["id"].as_str().unwrap_or("unknown").to_owned();
                    let metadata = inner.classifier.organization_metadata(&id);
                    if let Some(object) = item.as_object_mut() {
                        object.insert(
                            "name".to_owned(),
                            json!(metadata_name(metadata.as_ref(), &id)),
                        );
                        object.insert("icon".to_owned(), icon_json(metadata));
                    }
                }
                page_ok(items, page, total)
            })
            .unwrap_or_else(storage_error);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let total: i64 = scalar(
            connection,
            "SELECT COUNT(DISTINCT COALESCE(organization_id, 'unknown')) FROM flow_sessions",
            [],
        )?;
        let mut statement = connection.prepare(
            "SELECT COALESCE(organization_id, 'unknown'), SUM(upload_bytes), SUM(download_bytes), COUNT(*), MAX(last_seen_at), COUNT(DISTINCT device_id)
             FROM flow_sessions GROUP BY COALESCE(organization_id, 'unknown')
             ORDER BY SUM(upload_bytes + download_bytes) DESC LIMIT ?1 OFFSET ?2",
        )?;
        let items = statement
            .query_map(params![i64::from(page.limit), to_i64(page.offset)], |row| {
                let id: String = row.get(0)?;
                let metadata = inner.classifier.organization_metadata(&id);
                Ok(json!({
                    "id": id.clone(),
                    "name": metadata_name(metadata.as_ref(), &id),
                    "icon": icon_json(metadata),
                    "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?,
                    "flows": row.get::<_, i64>(3)?,
                    "last_seen": row.get::<_, i64>(4)?,
                    "clients": row.get::<_, i64>(5)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, to_u64(total)))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

async fn protocols(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return clickhouse
            .query_flow_groups("protocol_id", page.limit, page.offset)
            .map(|(items, total)| page_ok(items, page, total))
            .unwrap_or_else(storage_error);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let total: i64 = scalar(
            connection,
            "SELECT COUNT(DISTINCT COALESCE(protocol_id, 'unknown')) FROM flow_sessions",
            [],
        )?;
        let mut statement = connection.prepare(
            "SELECT COALESCE(protocol_id, 'unknown'), SUM(upload_bytes), SUM(download_bytes), COUNT(*), MAX(last_seen_at)
             FROM flow_sessions GROUP BY COALESCE(protocol_id, 'unknown')
             ORDER BY SUM(upload_bytes + download_bytes) DESC LIMIT ?1 OFFSET ?2",
        )?;
        let items = statement
            .query_map(params![i64::from(page.limit), to_i64(page.offset)], |row| {
                let id: String = row.get(0)?;
                Ok(json!({
                    "id": id.clone(),
                    "name": id,
                    "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?,
                    "flows": row.get::<_, i64>(3)?,
                    "last_seen": row.get::<_, i64>(4)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, to_u64(total)))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

async fn application_detail(
    State(state): State<CollectorState>,
    Path(id): Path<String>,
    query: Result<Query<ApplicationDetailQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    if let Err(response) = Page::parse(Ok(Query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }))) {
        return *response;
    }
    let window = match query_window(query.from, query.to) {
        Ok(window) => window,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_time_range", message),
    };
    if !valid_application_identifier(&id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_application_id",
            "application id contains unsupported characters",
        );
    }
    if query
        .category
        .as_deref()
        .is_some_and(|value| !valid_identifier(value))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_category_id",
            "category id contains unsupported characters",
        );
    }
    let category = query.category.as_deref();
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return match clickhouse.query_application_detail(&id, category, window) {
            Ok(Some(mut value)) => {
                let organization_id = value["organization_id"].as_str().unwrap_or("unknown");
                let organization = (organization_id != "unknown")
                    .then(|| inner.classifier.organization_metadata(organization_id))
                    .flatten();
                let application = inner.classifier.application_metadata(&id);
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "name".to_owned(),
                        json!(application.as_ref().map(|metadata| metadata.name.clone())),
                    );
                    object.insert(
                        "organization_name".to_owned(),
                        json!(organization.as_ref().map(|metadata| metadata.name.clone())),
                    );
                    object.insert("icon".to_owned(), icon_json(application));
                }
                api_ok(value)
            }
            Ok(None) => api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "application was not found",
            ),
            Err(error) => storage_error(error),
        };
    }
    let summary_sql = "SELECT application_id, category_id, SUM(upload_bytes), SUM(download_bytes),
                              SUM(packets), SUM(flow_count), MAX(timestamp)
                       FROM traffic_application_minute
                       WHERE application_id = ?1 AND (?2 IS NULL OR category_id = ?2)
                         AND (?3 IS NULL OR timestamp >= ?3) AND (?4 IS NULL OR timestamp < ?4)
                       GROUP BY application_id, category_id";
    let result = inner
        .storage
        .connection()
        .query_row(
            summary_sql,
            params![
                id,
                category,
                window.map(|(from, _)| from),
                window.map(|(_, to)| to)
            ],
            |row| summary_row(row, &["application_id", "category_id"]),
        )
        .optional();
    match result {
        Ok(Some(mut value)) => {
            let connection = inner.storage.connection();
            let classifier = connection.query_row(
                &format!("SELECT COUNT(DISTINCT device_id), COUNT(DISTINCT domain),
                        COUNT(DISTINCT hex(remote_ip)), AVG(COALESCE(classification_confidence, 0)),
                        COALESCE(MAX(classification_reason), 'no matching rule'),
                        COALESCE(MAX(CASE
                            WHEN ?1 NOT IN ('unknown', 'protocol-only') AND ?1 NOT LIKE '{PROTOCOL_APPLICATION_PREFIX}%'
                             AND organization_id IS NOT NULL AND organization_id != 'unknown'
                            THEN organization_id
                        END), 'unknown')
                 FROM flow_sessions
                 WHERE {flow_filter}
                   AND (?3 IS NULL OR last_seen_at >= ?3) AND (?4 IS NULL OR last_seen_at < ?4)
                   AND (?1 LIKE '{PROTOCOL_APPLICATION_PREFIX}%' OR ?2 IS NULL OR COALESCE(category_id, 'unknown') = ?2)",
                    flow_filter = sqlite_application_flow_filter("?1", "")
                ),
                params![
                    id,
                    category,
                    window.map(|(from, _)| from),
                    window.map(|(_, to)| to)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<f64>>(3)?.unwrap_or(0.0),
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            );
            match classifier {
                Ok((clients, domains, destinations, confidence, reason, organization)) => {
                    let organization = if id == "unknown" {
                        "unknown".to_owned()
                    } else {
                        organization
                    };
                    let observed_protocols = query_application_protocols(
                        connection,
                        &id,
                        category,
                        window.map(|(from, _)| from),
                        window.map(|(_, to)| to),
                    )
                    .unwrap_or_else(|_| Vec::new());
                    let application_metadata = inner.classifier.application_metadata(&id);
                    let organization_metadata = (organization != "unknown")
                        .then(|| inner.classifier.organization_metadata(&organization))
                        .flatten();
                    if let Some(object) = value.as_object_mut() {
                        object.insert(
                            "name".to_owned(),
                            json!(
                                application_metadata
                                    .as_ref()
                                    .map(|metadata| metadata.name.clone())
                            ),
                        );
                        object.insert("client_count".to_owned(), json!(clients));
                        object.insert("domain_count".to_owned(), json!(domains));
                        object.insert("destination_count".to_owned(), json!(destinations));
                        object.insert("confidence".to_owned(), json!(confidence));
                        object.insert("classifier_reason".to_owned(), json!(reason));
                        object.insert("organization_id".to_owned(), json!(organization));
                        object.insert(
                            "organization_name".to_owned(),
                            json!(
                                organization_metadata
                                    .as_ref()
                                    .map(|metadata| metadata.name.clone())
                            ),
                        );
                        object.insert("observed_protocols".to_owned(), json!(observed_protocols));
                        object.insert("icon".to_owned(), icon_json(application_metadata));
                    }
                    api_ok(value)
                }
                Err(error) => storage_error(error),
            }
        }
        Ok(None) if window.is_some() => api_ok(json!({
            "application_id": id,
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
        })),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "application was not found",
        ),
        Err(error) => storage_error(error),
    }
}

fn query_application_protocols(
    connection: &Connection,
    id: &str,
    category: Option<&str>,
    from: Option<i64>,
    to: Option<i64>,
) -> rusqlite::Result<Vec<Value>> {
    let mut statement = connection.prepare(&format!(
        "SELECT COALESCE(protocol_id, 'unknown'), COUNT(*)
         FROM flow_sessions
         WHERE {flow_filter}
           AND (?3 IS NULL OR last_seen_at >= ?3) AND (?4 IS NULL OR last_seen_at < ?4)
           AND (?1 LIKE '{PROTOCOL_APPLICATION_PREFIX}%' OR ?2 IS NULL OR COALESCE(category_id, 'unknown') = ?2)
         GROUP BY COALESCE(protocol_id, 'unknown')
         ORDER BY COUNT(*) DESC, COALESCE(protocol_id, 'unknown')",
        flow_filter = sqlite_application_flow_filter("?1", "")
    ))?;
    statement
        .query_map(params![id, category, from, to], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "flows": row.get::<_, i64>(1)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelatedQuery {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
    offset: Option<u64>,
    all: Option<bool>,
    scope: Option<String>,
    category: Option<String>,
}

async fn application_related(
    State(state): State<CollectorState>,
    Path((id, relation)): Path<(String, String)>,
    query: Result<Query<RelatedQuery>, QueryRejection>,
) -> Response {
    if !valid_application_identifier(&id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_application_id",
            "application id contains unsupported characters",
        );
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    if query
        .category
        .as_deref()
        .is_some_and(|value| !valid_identifier(value))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_category_id",
            "category id contains unsupported characters",
        );
    }
    let page = match Page::parse(Ok(Query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }))) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let to = query.to.unwrap_or_else(now_ms);
    let from = query.from.unwrap_or_else(|| to.saturating_sub(DAY_MS));
    if from >= to {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "from must be less than to",
        );
    }
    let inner = state.lock();
    let category = query.category.as_deref();
    let include_all =
        query.all.unwrap_or(false) && matches!(relation.as_str(), "domains" | "destinations");
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        if !matches!(
            relation.as_str(),
            "traffic" | "clients" | "domains" | "destinations" | "flows"
        ) {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "application relation was not found",
            );
        }
        return clickhouse
            .query_application_related(
                &id,
                category,
                &relation,
                from,
                to,
                page.limit,
                page.offset,
                include_all,
            )
            .map(|mut value| {
                if relation == "flows" {
                    if let Some(items) = value.as_array_mut() {
                        let metadata = inner.classifier.application_metadata(&id);
                        for item in items {
                            if let Some(object) = item.as_object_mut() {
                                object.insert(
                                    "application_name".to_owned(),
                                    json!(metadata.as_ref().map(|value| value.name.clone())),
                                );
                                object.insert("icon".to_owned(), icon_json(metadata.clone()));
                            }
                        }
                    }
                }
                value
            })
            .map_or_else(storage_error, api_ok);
    }
    let connection = inner.storage.connection();
    let result = match relation.as_str() {
        "traffic" => query_application_traffic(connection, &id, category, from, to),
        "clients" => query_application_clients(connection, &id, category, page, from, to),
        "domains" => {
            query_application_domains(connection, &id, category, page, from, to, include_all)
        }
        "destinations" => {
            query_application_destinations(connection, &id, category, page, from, to, include_all)
        }
        "flows" => {
            query_application_flows(connection, &inner.classifier, &id, category, page, from, to)
        }
        _ => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "application relation was not found",
            );
        }
    };
    result.map_or_else(storage_error, api_ok)
}

fn query_application_traffic(
    connection: &Connection,
    id: &str,
    category: Option<&str>,
    from: u64,
    to: u64,
) -> rusqlite::Result<Value> {
    let duration = to.saturating_sub(from);
    let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
    let table = "traffic_application_minute";
    let mut statement = connection.prepare(&format!(
        "SELECT (timestamp / ?1) * ?1 AS bucket, SUM(upload_bytes), SUM(download_bytes),
                SUM(packets), SUM(flow_count)
         FROM {table}
         WHERE application_id = ?2 AND (?3 IS NULL OR category_id = ?3)
           AND timestamp >= ?4 AND timestamp < ?5
         GROUP BY bucket ORDER BY bucket"
    ))?;
    let points = statement
        .query_map(
            params![to_i64(bucket_ms), id, category, to_i64(from), to_i64(to)],
            |row| {
                Ok(json!({
                    "timestamp": row.get::<_, i64>(0)?,
                    "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?,
                    "packets": row.get::<_, i64>(3)?,
                    "flow_count": row.get::<_, i64>(4)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({ "bucket_ms": bucket_ms, "points": points }))
}

fn query_application_clients(
    connection: &Connection,
    id: &str,
    category: Option<&str>,
    page: Page,
    from: u64,
    to: u64,
) -> rusqlite::Result<Value> {
    let category_filter = if id.starts_with(PROTOCOL_APPLICATION_PREFIX) {
        "?1 LIKE 'protocol:%' OR ?2 IS NULL OR COALESCE(f.category_id, 'unknown') = ?2"
    } else {
        "?2 IS NULL OR COALESCE(f.category_id, 'unknown') = ?2"
    };
    let mut statement = connection.prepare(&format!(
        "SELECT d.id, d.mac, COALESCE(d.display_name, d.hostname, ''), d.vendor,
                d.device_type, d.os_family, d.model, d.identity_confidence,
                COALESCE((SELECT json_group_array(json_object(
                    'source', e.source, 'field', e.field, 'value', e.value,
                    'confidence', e.confidence, 'first_seen', e.first_seen,
                    'last_seen', e.last_seen, 'hit_count', e.hit_count,
                    'metadata_json', e.metadata_json))
                  FROM device_evidence e WHERE e.gateway_id = d.gateway_id AND e.mac = d.mac), '[]'),
                d.vendor_confidence, d.device_type_confidence, d.os_confidence,
                d.model_confidence, d.private_mac, d.last_seen,
                SUM(f.upload_bytes), SUM(f.download_bytes), COUNT(*)
         FROM flow_sessions f JOIN devices d ON d.id = f.device_id
         WHERE {application_filter}
           AND ({category_filter})
           AND f.last_seen_at >= ?3 AND f.last_seen_at < ?4
         GROUP BY d.id ORDER BY SUM(f.upload_bytes + f.download_bytes) DESC
         LIMIT ?5 OFFSET ?6",
        application_filter = sqlite_application_flow_filter("?1", "f.")
    ))?;
    let items = statement
        .query_map(
            params![
                id,
                category,
                to_i64(from),
                to_i64(to),
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                let mac: Vec<u8> = row.get(1)?;
                Ok(json!({
                    "id": row.get::<_, i64>(0)?, "mac": format_mac(&mac),
                    "name": row.get::<_, String>(2)?, "vendor": row.get::<_, Option<String>>(3)?,
                    "identity": device_identity_json(row, 3)?,
                    "last_seen": row.get::<_, i64>(14)?, "upload_bytes": row.get::<_, i64>(15)?,
                    "download_bytes": row.get::<_, i64>(16)?, "flow_count": row.get::<_, i64>(17)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_application_domains(
    connection: &Connection,
    id: &str,
    category: Option<&str>,
    page: Page,
    from: u64,
    to: u64,
    include_all: bool,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(&format!(
        "SELECT domain, SUM(upload_bytes), SUM(download_bytes), SUM(packets),
                SUM(flow_count), MAX(timestamp)
         FROM traffic_scope_minute WHERE {application_filter}
           AND (?2 IS NULL OR ?1 LIKE 'protocol:%' OR COALESCE(category_id, 'unknown') = ?2)
           AND domain != '' AND domain != 'unknown'
           AND timestamp >= ?3 AND timestamp < ?4
         GROUP BY domain ORDER BY SUM(upload_bytes + download_bytes) DESC
         LIMIT CASE WHEN ?5 THEN -1 ELSE ?6 END OFFSET ?7",
        application_filter = sqlite_application_flow_filter("?1", "")
    ))?;
    let items = statement
        .query_map(
            params![
                id,
                category,
                to_i64(from),
                to_i64(to),
                include_all,
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                Ok(json!({
                    "domain": row.get::<_, String>(0)?, "upload_bytes": row.get::<_, i64>(1)?,
                    "download_bytes": row.get::<_, i64>(2)?, "packets": row.get::<_, i64>(3)?,
                    "flow_count": row.get::<_, i64>(4)?, "last_seen": row.get::<_, i64>(5)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_application_destinations(
    connection: &Connection,
    id: &str,
    category: Option<&str>,
    page: Page,
    from: u64,
    to: u64,
    include_all: bool,
) -> rusqlite::Result<Value> {
    let mut statement = connection.prepare(&format!(
        "SELECT remote_ip, NULLIF(MAX(domain), 'unknown'), SUM(upload_bytes),
                SUM(download_bytes), SUM(packets), SUM(flow_count), MAX(timestamp)
         FROM traffic_scope_minute WHERE {application_filter}
           AND (?2 IS NULL OR ?1 LIKE 'protocol:%' OR COALESCE(category_id, 'unknown') = ?2)
           AND timestamp >= ?3 AND timestamp < ?4
         GROUP BY remote_ip ORDER BY SUM(upload_bytes + download_bytes) DESC
         LIMIT CASE WHEN ?5 THEN -1 ELSE ?6 END OFFSET ?7",
        application_filter = sqlite_application_flow_filter("?1", "")
    ))?;
    let items = statement
        .query_map(
            params![
                id,
                category,
                to_i64(from),
                to_i64(to),
                include_all,
                i64::from(page.limit),
                to_i64(page.offset)
            ],
            |row| {
                let ip: Vec<u8> = row.get(0)?;
                Ok(json!({
                    "remote_ip": format_ip(&ip), "domain": row.get::<_, Option<String>>(1)?,
                    "upload_bytes": row.get::<_, i64>(2)?, "download_bytes": row.get::<_, i64>(3)?,
                    "packets": row.get::<_, i64>(4)?, "flow_count": row.get::<_, i64>(5)?,
                    "last_seen": row.get::<_, i64>(6)?,
                }))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

fn query_application_flows(
    connection: &Connection,
    classifier: &crate::classifier::ClassifierHandle,
    id: &str,
    category: Option<&str>,
    page: Page,
    from: u64,
    to: u64,
) -> rusqlite::Result<Value> {
    let application_name = classifier
        .application_metadata(id)
        .as_ref()
        .map(|metadata| metadata.name.clone());
    let category_filter = if id.starts_with(PROTOCOL_APPLICATION_PREFIX) {
        "?1 LIKE 'protocol:%' OR ?2 IS NULL OR COALESCE(category_id, 'unknown') = ?2"
    } else {
        "?2 IS NULL OR COALESCE(category_id, 'unknown') = ?2"
    };
    let mut statement = connection.prepare(&format!(
        "SELECT id, client_ip, client_port, remote_ip, remote_port, protocol, direction,
                domain, category_id, classification_confidence, classification_reason,
                upload_bytes, download_bytes, packets, started_at, last_seen_at, ended_at,
                scope, path_type, nat, source_segment, destination_segment
         FROM flow_sessions WHERE {application_filter}
           AND ({category_filter})
           AND last_seen_at >= ?3 AND last_seen_at < ?4
         ORDER BY last_seen_at DESC LIMIT ?5 OFFSET ?6",
        application_filter = sqlite_application_flow_filter("?1", "")
    ))?;
    let items = statement.query_map(
        params![id, category, to_i64(from), to_i64(to), i64::from(page.limit), to_i64(page.offset)],
        |row| {
            let client_ip: Vec<u8> = row.get(1)?;
            let remote_ip: Vec<u8> = row.get(3)?;
            Ok(json!({
                "id": row.get::<_, String>(0)?, "client_ip": format_ip(&client_ip),
                "client_port": row.get::<_, i64>(2)?, "remote_ip": format_ip(&remote_ip),
                "remote_port": row.get::<_, i64>(4)?, "protocol": row.get::<_, i64>(5)?,
                "direction": row.get::<_, i64>(6)?, "domain": row.get::<_, Option<String>>(7)?,
                "application": id, "application_name": application_name,
                "category": row.get::<_, Option<String>>(8)?.unwrap_or_else(|| "unknown".to_owned()),
                "confidence": row.get::<_, Option<f64>>(9)?.unwrap_or(0.0),
                "reason": row.get::<_, Option<String>>(10)?.unwrap_or_else(|| "no matching rule".to_owned()),
                "upload_bytes": row.get::<_, i64>(11)?, "download_bytes": row.get::<_, i64>(12)?,
                "packets": row.get::<_, i64>(13)?, "started_at": row.get::<_, i64>(14)?,
                "last_seen": row.get::<_, i64>(15)?, "ended_at": row.get::<_, Option<i64>>(16)?,
                "scope": flow_scope_name(row.get::<_, i32>(17)?),
                "path_type": flow_path_name(row.get::<_, i32>(18)?),
                "nat": flow_nat_name(row.get::<_, i32>(19)?),
                "source_segment": row.get::<_, String>(20)?,
                "destination_segment": row.get::<_, String>(21)?,
            }))
        },
    )?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(items))
}

async fn domains(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    summary_page(
        &state,
        query,
        "traffic_domain_minute",
        "domain",
        &["domain"],
    )
}

async fn destinations(
    State(state): State<CollectorState>,
    query: Result<Query<DestinationQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::parse(Ok(Query(PageQuery {
        limit: query.limit,
        offset: query.offset,
    }))) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    if let (Some(from), Some(to)) = (query.from, query.to) {
        if from >= to {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_time_range",
                "from must be less than to",
            );
        }
    }
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        let window = match (query.from, query.to) {
            (Some(from), Some(to)) => Some((to_i64(from), to_i64(to))),
            _ => None,
        };
        return clickhouse
            .query_destination_details(page.limit, page.offset, window)
            .map(|(mut items, total)| {
                for item in &mut items {
                    let remote_ip = item["remote_ip"].as_str().unwrap_or_default();
                    let geo = remote_ip
                        .parse::<IpAddr>()
                        .ok()
                        .and_then(|ip| {
                            match inner
                                .geo_provider
                                .lookup_with_lang(ip, query.lang.as_deref())
                            {
                                Ok(record) => record,
                                Err(error) => {
                                    tracing::warn!(%ip, %error, "Geo lookup failed");
                                    None
                                }
                            }
                        })
                        .unwrap_or_default();
                    let application_id = item["application_id"].as_str().map(ToOwned::to_owned);
                    let metadata = application_id
                        .as_deref()
                        .filter(|id| !id.is_empty() && *id != "unknown")
                        .and_then(|id| inner.classifier.application_metadata(id));
                    if let Some(object) = item.as_object_mut() {
                        object.remove("application_id");
                        object.insert("application".to_owned(), json!(application_id));
                        object.insert(
                            "application_name".to_owned(),
                            json!(metadata.as_ref().map(|value| value.name.clone())),
                        );
                        object.insert("country_code".to_owned(), json!(geo.country_code));
                        object.insert("country_name".to_owned(), json!(geo.country_name));
                        object.insert("region".to_owned(), json!(geo.region));
                        object.insert("city".to_owned(), json!(geo.city));
                        object.insert("latitude".to_owned(), json!(geo.latitude));
                        object.insert("longitude".to_owned(), json!(geo.longitude));
                        object.insert("asn".to_owned(), json!(geo.asn));
                        object.insert("organization".to_owned(), json!(geo.organization));
                    }
                }
                page_ok(items, page, total)
            })
            .unwrap_or_else(storage_error);
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let (total, items) = match (query.from, query.to) {
            (Some(from), Some(to)) => {
                let from_i = to_i64(from);
                let to_i = to_i64(to);
                let total: i64 = scalar(
                    connection,
                    "SELECT COUNT(DISTINCT hex(remote_ip)) FROM traffic_scope_minute
                     WHERE scope = ?1 AND timestamp >= ?2 AND timestamp < ?3",
                    params![
                        netqmon_protocol::v1::FlowScope::Internet as i32,
                        from_i,
                        to_i
                    ],
                )?;
                let mut statement = connection.prepare(
                    "WITH page AS (
                        SELECT t.remote_ip, SUM(t.upload_bytes) AS upload_bytes,
                               SUM(t.download_bytes) AS download_bytes, SUM(t.packets) AS packets,
                               SUM(t.flow_count) AS flow_count, MAX(t.timestamp) AS last_seen
                        FROM traffic_scope_minute t
                        WHERE t.scope = ?1 AND t.timestamp >= ?2 AND t.timestamp < ?3
                        GROUP BY t.remote_ip
                        ORDER BY SUM(t.upload_bytes + t.download_bytes) DESC, hex(t.remote_ip)
                        LIMIT ?4 OFFSET ?5
                     )
                     SELECT page.remote_ip, page.upload_bytes, page.download_bytes, page.packets,
                            page.flow_count, page.last_seen,
                            (SELECT f.domain FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.domain IS NOT NULL
                             ORDER BY f.last_seen_at DESC LIMIT 1),
                            (SELECT COUNT(DISTINCT f.device_id) FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.device_id IS NOT NULL),
                            (SELECT f.application_id FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.application_id IS NOT NULL AND f.application_id != 'unknown'
                             ORDER BY f.last_seen_at DESC LIMIT 1)
                     FROM page",
                )?;
                let rows = statement
                    .query_map(
                        params![
                            netqmon_protocol::v1::FlowScope::Internet as i32,
                            from_i,
                            to_i,
                            i64::from(page.limit),
                            to_i64(page.offset)
                        ],
                        |row| map_destination_row(row, &inner, query.lang.as_deref()),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                (total, rows)
            }
            _ => {
                let total: i64 = scalar(
                    connection,
                    "SELECT COUNT(DISTINCT hex(remote_ip)) FROM traffic_scope_minute WHERE scope = ?1",
                    [netqmon_protocol::v1::FlowScope::Internet as i32],
                )?;
                let mut statement = connection.prepare(
                    "WITH page AS (
                        SELECT t.remote_ip, SUM(t.upload_bytes) AS upload_bytes,
                               SUM(t.download_bytes) AS download_bytes, SUM(t.packets) AS packets,
                               SUM(t.flow_count) AS flow_count, MAX(t.timestamp) AS last_seen
                        FROM traffic_scope_minute t WHERE t.scope = ?1 GROUP BY t.remote_ip
                        ORDER BY SUM(t.upload_bytes + t.download_bytes) DESC, hex(t.remote_ip)
                        LIMIT ?2 OFFSET ?3
                     )
                     SELECT page.remote_ip, page.upload_bytes, page.download_bytes, page.packets,
                            page.flow_count, page.last_seen,
                            (SELECT f.domain FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.domain IS NOT NULL
                             ORDER BY f.last_seen_at DESC LIMIT 1),
                            (SELECT COUNT(DISTINCT f.device_id) FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.device_id IS NOT NULL),
                            (SELECT f.application_id FROM flow_sessions f
                             WHERE f.remote_ip = page.remote_ip AND f.application_id IS NOT NULL AND f.application_id != 'unknown'
                             ORDER BY f.last_seen_at DESC LIMIT 1)
                     FROM page",
                )?;
                let rows = statement
                    .query_map(
                        params![
                            netqmon_protocol::v1::FlowScope::Internet as i32,
                            i64::from(page.limit),
                            to_i64(page.offset)
                        ],
                        |row| map_destination_row(row, &inner, query.lang.as_deref()),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                (total, rows)
            }
        };
        Ok((items, to_u64(total)))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

fn map_destination_row(
    row: &Row<'_>,
    inner: &crate::CollectorInner,
    lang: Option<&str>,
) -> rusqlite::Result<Value> {
    let address: Vec<u8> = row.get(0)?;
    let remote_ip = format_ip(&address);
    let geo = remote_ip
        .parse::<IpAddr>()
        .ok()
        .and_then(|ip| match inner.geo_provider.lookup_with_lang(ip, lang) {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(%ip, %error, "Geo lookup failed");
                None
            }
        })
        .unwrap_or_default();
    let application_id = row.get::<_, Option<String>>(8)?;
    let application_metadata = application_id
        .as_deref()
        .filter(|id| !id.is_empty() && *id != "unknown")
        .and_then(|id| inner.classifier.application_metadata(id));
    Ok(json!({
        "remote_ip": remote_ip,
        "upload_bytes": row.get::<_, i64>(1)?,
        "download_bytes": row.get::<_, i64>(2)?,
        "packets": row.get::<_, i64>(3)?,
        "flow_count": row.get::<_, i64>(4)?,
        "last_seen": row.get::<_, i64>(5)?,
        "domain": row.get::<_, Option<String>>(6)?,
        "client_count": row.get::<_, i64>(7)?,
        "application": application_id,
        "application_name": application_metadata
            .as_ref()
            .map(|metadata| metadata.name.clone()),
        "country_code": geo.country_code,
        "country_name": geo.country_name,
        "region": geo.region,
        "city": geo.city,
        "latitude": geo.latitude,
        "longitude": geo.longitude,
        "asn": geo.asn,
        "organization": geo.organization,
    }))
}

async fn geo_summary(
    State(state): State<CollectorState>,
    query: Result<Query<GeoQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    if let (Some(from), Some(to)) = (query.from, query.to) {
        if from >= to {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_time_range",
                "from must be less than to",
            );
        }
    }
    let inner = state.lock();
    if !inner.geo_provider.is_enabled() {
        return api_ok(json!({
            "enabled": false,
            "top_countries": [],
            "top_asns": [],
            "country_distribution": [],
        }));
    }
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return clickhouse
            .query_geo_traffic(query.from, query.to)
            .map(|rows| aggregate_geo_values(&inner, rows, query.lang.as_deref()))
            .map_or_else(storage_error, api_ok);
    }
    aggregate_geo_traffic(&inner, query.from, query.to, query.lang.as_deref())
        .map_or_else(storage_error, api_ok)
}

async fn insights(
    State(state): State<CollectorState>,
    query: Result<Query<InsightQuery>, QueryRejection>,
) -> Response {
    let window = match parse_insight_window(query) {
        Ok(window) => window,
        Err(response) => return *response,
    };
    let snapshot = state.realtime_snapshot();
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        return crate::insights::detect_clickhouse(
            clickhouse.client(),
            &snapshot,
            window,
            crate::insights::collector_lag_threshold_ms(),
            crate::insights::high_upload_threshold_bytes(),
        )
        .map(|items| serde_json::to_value(items).unwrap_or(Value::Array(Vec::new())))
        .map_or_else(storage_error, api_ok);
    }
    let result = (|| -> rusqlite::Result<Value> {
        let connection = inner.storage.connection();
        let items = crate::insights::detect(
            connection,
            &snapshot,
            window,
            crate::insights::collector_lag_threshold_ms(),
            crate::insights::high_upload_threshold_bytes(),
        )?;
        Ok(serde_json::to_value(items).unwrap_or(Value::Array(Vec::new())))
    })();
    result.map_or_else(storage_error, api_ok)
}

fn aggregate_geo_traffic(
    inner: &crate::CollectorInner,
    from: Option<u64>,
    to: Option<u64>,
    lang: Option<&str>,
) -> rusqlite::Result<Value> {
    let (sql, params_vec): (&str, Vec<SqlValue>) = match (from, to) {
        (Some(from), Some(to)) => (
            "SELECT remote_ip, SUM(upload_bytes + download_bytes)
             FROM traffic_scope_minute
             WHERE scope = ?1 AND timestamp >= ?2 AND timestamp < ?3
             GROUP BY remote_ip",
            vec![
                SqlValue::Integer(netqmon_protocol::v1::FlowScope::Internet as i64),
                SqlValue::Integer(to_i64(from)),
                SqlValue::Integer(to_i64(to)),
            ],
        ),
        _ => (
            "SELECT remote_ip, SUM(upload_bytes + download_bytes)
             FROM traffic_scope_minute WHERE scope = ?1 GROUP BY remote_ip",
            vec![SqlValue::Integer(
                netqmon_protocol::v1::FlowScope::Internet as i64,
            )],
        ),
    };
    let mut statement = inner.storage.connection().prepare(sql)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(params_vec), |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(aggregate_geo_values(inner, rows, lang))
}

fn aggregate_geo_values(
    inner: &crate::CollectorInner,
    rows: impl IntoIterator<Item = (Vec<u8>, i64)>,
    lang: Option<&str>,
) -> Value {
    let mut countries: HashMap<(String, String), u64> = HashMap::new();
    let mut asns: HashMap<(u32, String), u64> = HashMap::new();
    let mut unknown_bytes = 0_u64;
    for (address, bytes) in rows {
        let bytes = to_u64(bytes);
        let record = format_ip(&address).parse::<IpAddr>().ok().and_then(|ip| {
            match inner.geo_provider.lookup_with_lang(ip, lang) {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(%ip, %error, "Geo lookup failed");
                    None
                }
            }
        });
        let Some(record) = record else {
            unknown_bytes = unknown_bytes.saturating_add(bytes);
            continue;
        };
        if let Some(code) = record.country_code {
            let name = record.country_name.unwrap_or_else(|| code.clone());
            let total = countries.entry((code, name)).or_default();
            *total = total.saturating_add(bytes);
        } else {
            unknown_bytes = unknown_bytes.saturating_add(bytes);
        }
        if let Some(asn) = record.asn {
            let organization = record
                .organization
                .unwrap_or_else(|| "Unknown organization".to_owned());
            let total = asns.entry((asn, organization)).or_default();
            *total = total.saturating_add(bytes);
        }
    }
    geo_summary_value(countries, asns, unknown_bytes)
}

fn geo_summary_value(
    countries: HashMap<(String, String), u64>,
    asns: HashMap<(u32, String), u64>,
    unknown_bytes: u64,
) -> Value {
    let mut country_items = countries
        .into_iter()
        .map(|((country_code, country_name), bytes)| {
            json!({
                "country_code": country_code,
                "country_name": country_name,
                "bytes": bytes,
            })
        })
        .collect::<Vec<_>>();
    country_items.sort_by(|left, right| {
        right["bytes"]
            .as_u64()
            .cmp(&left["bytes"].as_u64())
            .then_with(|| {
                left["country_code"]
                    .as_str()
                    .cmp(&right["country_code"].as_str())
            })
    });
    let top_countries = country_items.iter().take(5).cloned().collect::<Vec<_>>();
    let visible_country_count = if unknown_bytes > 0 { 4 } else { 5 };
    let mut distribution = country_items
        .iter()
        .take(visible_country_count)
        .cloned()
        .collect::<Vec<_>>();
    if country_items.len() > visible_country_count {
        let other_bytes = country_items[visible_country_count..]
            .iter()
            .filter_map(|item| item["bytes"].as_u64())
            .fold(0_u64, u64::saturating_add);
        distribution.push(json!({
            "country_code": "other",
            "country_name": "Other",
            "bytes": other_bytes,
        }));
    }
    if unknown_bytes > 0 {
        distribution.push(json!({
            "country_code": "unknown",
            "country_name": "Unknown",
            "bytes": unknown_bytes,
        }));
    }
    distribution.sort_by(|left, right| right["bytes"].as_u64().cmp(&left["bytes"].as_u64()));
    let mut asn_items = asns
        .into_iter()
        .map(|((asn, organization), bytes)| {
            json!({
                "asn": asn,
                "organization": organization,
                "bytes": bytes,
            })
        })
        .collect::<Vec<_>>();
    asn_items.sort_by(|left, right| {
        right["bytes"]
            .as_u64()
            .cmp(&left["bytes"].as_u64())
            .then_with(|| left["asn"].as_u64().cmp(&right["asn"].as_u64()))
    });
    json!({
        "enabled": true,
        "top_countries": top_countries,
        "top_asns": asn_items.into_iter().take(5).collect::<Vec<_>>(),
        "country_distribution": distribution,
    })
}

async fn flows(
    State(state): State<CollectorState>,
    query: Result<Query<FlowQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let options = match parse_flow_page_options(&query) {
        Ok(options) => options,
        Err(response) => return *response,
    };
    let inner = state.lock();
    if let Some(clickhouse) = inner.storage.clickhouse_storage() {
        if let Err(rusqlite::Error::InvalidParameterName(name)) = flow_filters(&query) {
            return flow_query_error(&name);
        }
        return query_flow_page_clickhouse(clickhouse, &inner.classifier, &query, &options)
            .map(|(items, next_cursor)| {
                Json(json!({
                    "schema_version": SCHEMA_VERSION,
                    "data": items,
                    "pagination": {
                        "limit": options.limit,
                        "next_cursor": next_cursor,
                        "sort": options.sort_name,
                        "order": if options.descending { "desc" } else { "asc" },
                    }
                }))
                .into_response()
            })
            .unwrap_or_else(storage_error);
    }
    let result = query_flow_page(
        inner.storage.connection(),
        &inner.classifier,
        &query,
        &options,
    );
    match result {
        Ok((items, next_cursor)) => Json(json!({
            "schema_version": SCHEMA_VERSION,
            "data": items,
            "pagination": {
                "limit": options.limit,
                "next_cursor": next_cursor,
                "sort": options.sort_name,
                "order": if options.descending { "desc" } else { "asc" },
            }
        }))
        .into_response(),
        Err(rusqlite::Error::InvalidParameterName(name)) => flow_query_error(&name),
        Err(error) => storage_error(error),
    }
}

fn parse_flow_page_options(query: &FlowQuery) -> Result<FlowPageOptions, Box<Response>> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 200",
        )));
    }
    let (sort_column, sort_name) = match query.sort.as_deref().unwrap_or("last_seen") {
        "last_seen" => ("f.last_seen_at", "last_seen"),
        "started" => ("f.started_at", "started"),
        "download" => ("f.download_bytes", "download"),
        "upload" => ("f.upload_bytes", "upload"),
        "duration" => (
            "(COALESCE(f.ended_at, f.last_seen_at) - f.started_at)",
            "duration",
        ),
        _ => {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_sort",
                "sort must be one of last_seen, started, download, upload, or duration",
            )));
        }
    };
    let descending = match query.order.as_deref().unwrap_or("desc") {
        "desc" => true,
        "asc" => false,
        _ => {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_sort",
                "order must be asc or desc",
            )));
        }
    };
    let cursor = query
        .cursor
        .as_deref()
        .map(parse_flow_cursor)
        .transpose()
        .map_err(|message| {
            Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                message,
            ))
        })?;
    Ok(FlowPageOptions {
        limit,
        sort_column,
        sort_name,
        descending,
        cursor,
    })
}

fn query_flow_page(
    connection: &Connection,
    classifier: &crate::classifier::ClassifierHandle,
    query: &FlowQuery,
    options: &FlowPageOptions,
) -> rusqlite::Result<(Vec<Value>, Option<String>)> {
    let (mut clauses, mut values) = flow_filters(query)?;
    if let Some(cursor) = options.cursor.as_ref() {
        let comparison = if options.descending { '<' } else { '>' };
        clauses.push(format!(
            "({} {comparison} ? OR ({} = ? AND f.id > ?))",
            options.sort_column, options.sort_column
        ));
        values.extend([
            SqlValue::Integer(cursor.sort_value),
            SqlValue::Integer(cursor.sort_value),
            SqlValue::Text(cursor.id.clone()),
        ]);
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let order = if options.descending { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT f.id, f.client_ip, f.client_port, f.remote_ip, f.remote_port, f.protocol,
                f.direction, f.domain, f.organization_id, f.application_id, f.category_id,
                f.traffic_role, f.protocol_id, f.organization_confidence, f.application_confidence,
                f.protocol_confidence, f.classification_confidence,
                f.classification_reason, f.classification_evidence_json, f.upload_bytes,
                f.download_bytes, f.packets, f.started_at, f.last_seen_at, f.ended_at,
                f.device_id, COALESCE(d.display_name, d.hostname, ''), d.mac,
                d.device_type, d.model, d.vendor, d.os_family,
                f.scope, f.path_type, f.nat, f.source_segment, f.destination_segment, {}
         FROM flow_sessions f LEFT JOIN devices d ON d.id = f.device_id{where_clause}
         ORDER BY {} {order}, f.id ASC LIMIT ?",
        options.sort_column, options.sort_column
    );
    values.push(SqlValue::Integer(i64::from(options.limit) + 1));
    let mut statement = connection.prepare(&sql)?;
    let mut items = statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            flow_row_json(row, classifier)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = items.len() > options.limit as usize;
    items.truncate(options.limit as usize);
    let next_cursor = has_more
        .then(|| flow_cursor_for(items.last().expect("extra row implies a non-empty page")));
    for item in &mut items {
        item.as_object_mut()
            .expect("Flow item is an object")
            .remove("cursor_value");
    }
    Ok((items, next_cursor))
}

fn query_flow_page_clickhouse(
    clickhouse: &netqmon_storage::ClickHouseStorage,
    classifier: &crate::classifier::ClassifierHandle,
    query: &FlowQuery,
    options: &FlowPageOptions,
) -> netqmon_storage::StorageResult<(Vec<Value>, Option<String>)> {
    let mut clauses = Vec::new();
    if let Some(search) = non_empty(query.search.as_deref()) {
        if let Ok(ip) = search.parse::<IpAddr>() {
            let ip_hex = netqmon_storage::to_hex(&ip_bytes(ip));
            let ip_hex = clickhouse_quote(&ip_hex);
            clauses.push(format!(
                "(f.client_ip = '{ip_hex}' OR f.remote_ip = '{ip_hex}')"
            ));
        } else {
            let pattern = clickhouse_quote(&format!("%{}%", search.to_lowercase()));
            clauses.push(format!(
                "(lower(coalesce(f.domain, '')) LIKE '{pattern}' OR lower(coalesce(f.application_id, '')) LIKE '{pattern}' OR lower(coalesce(d.display_name, d.hostname, '')) LIKE '{pattern}' OR lower(coalesce(d.mac, '')) LIKE '{pattern}')"
            ));
        }
    }
    if let Some(client) = non_empty(query.client.as_deref()) {
        if let Ok(id) = client.parse::<i64>() {
            clauses.push(format!("f.device_id = {id}"));
        } else if let Ok(ip) = client.parse::<IpAddr>() {
            let ip_hex = clickhouse_quote(&netqmon_storage::to_hex(&ip_bytes(ip)));
            clauses.push(format!("f.client_ip = '{ip_hex}'"));
        } else {
            let pattern = clickhouse_quote(&format!(
                "%{}%",
                client.to_lowercase().replace([':', '-'], "")
            ));
            clauses.push(format!(
                "(lower(coalesce(d.display_name, d.hostname, '')) LIKE '{pattern}' OR lower(coalesce(d.mac, '')) LIKE '{pattern}')"
            ));
        }
    }
    for (value, column) in [
        (query.application.as_deref(), "f.application_id"),
        (query.organization.as_deref(), "f.organization_id"),
        (query.detected_protocol.as_deref(), "f.protocol_id"),
    ] {
        if let Some(value) = non_empty(value) {
            clauses.push(format!(
                "lower(coalesce({column}, 'unknown')) = '{}'",
                clickhouse_quote(&value.to_lowercase())
            ));
        }
    }
    if let Some(domain) = non_empty(query.domain.as_deref()) {
        clauses.push(format!(
            "lower(coalesce(f.domain, '')) LIKE '{}'",
            clickhouse_quote(&format!("%{}%", domain.to_lowercase()))
        ));
    }
    if let Some(ip) = non_empty(query.ip.as_deref()) {
        let ip = ip
            .parse::<IpAddr>()
            .expect("flow_filters validates IP filters");
        let ip_hex = clickhouse_quote(&netqmon_storage::to_hex(&ip_bytes(ip)));
        clauses.push(format!("f.remote_ip = '{ip_hex}'"));
    }
    if let Some(protocol) = non_empty(query.protocol.as_deref()) {
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            value => value
                .parse::<u8>()
                .expect("flow_filters validates protocols"),
        };
        clauses.push(format!("f.protocol = {protocol}"));
    }
    if let Some(port) = query.port {
        clauses.push(format!(
            "(f.client_port = {port} OR f.remote_port = {port})"
        ));
    }
    if let Some(direction) = non_empty(query.direction.as_deref()) {
        let direction = match direction.to_ascii_lowercase().as_str() {
            "unknown" => 0,
            "upload" => 1,
            "download" => 2,
            _ => unreachable!("flow_filters validates directions"),
        };
        clauses.push(format!("f.direction = {direction}"));
    }
    if let Some(scope) = non_empty(query.scope.as_deref()) {
        let scope = match scope.to_ascii_lowercase().as_str() {
            "internet" => netqmon_protocol::v1::FlowScope::Internet as i64,
            "internal" => netqmon_protocol::v1::FlowScope::Internal as i64,
            "tunnel" => netqmon_protocol::v1::FlowScope::Tunnel as i64,
            "unknown" => netqmon_protocol::v1::FlowScope::Unknown as i64,
            _ => unreachable!("flow_filters validates scopes"),
        };
        clauses.push(format!("f.scope = {scope}"));
    }
    if let Some(path_type) = non_empty(query.path_type.as_deref()) {
        let path_type = match path_type.to_ascii_lowercase().as_str() {
            "forwarded" => netqmon_protocol::v1::PathType::Forwarded as i64,
            "internal" => netqmon_protocol::v1::PathType::Internal as i64,
            "tunnel" => netqmon_protocol::v1::PathType::Tunnel as i64,
            "unknown" => netqmon_protocol::v1::PathType::Unknown as i64,
            _ => unreachable!("flow_filters validates path types"),
        };
        clauses.push(format!("f.path_type = {path_type}"));
    }
    if let Some(nat) = non_empty(query.nat.as_deref()) {
        let nat = match nat.to_ascii_lowercase().as_str() {
            "none" => netqmon_protocol::v1::NatType::None as i64,
            "snat" => netqmon_protocol::v1::NatType::Snat as i64,
            "dnat" => netqmon_protocol::v1::NatType::Dnat as i64,
            "both" => netqmon_protocol::v1::NatType::Both as i64,
            "unknown" => netqmon_protocol::v1::NatType::Unknown as i64,
            _ => unreachable!("flow_filters validates NAT types"),
        };
        clauses.push(format!("f.nat = {nat}"));
    }
    if query.from.is_some() || query.to.is_some() {
        let from = to_i64(query.from.unwrap_or(0));
        let to = to_i64(query.to.unwrap_or_else(now_ms));
        clauses.push(format!(
            "f.last_seen_at >= {from} AND f.last_seen_at < {to}"
        ));
    }
    if let Some(cursor) = options.cursor.as_ref() {
        let comparison = if options.descending { "<" } else { ">" };
        clauses.push(format!(
            "({column} {comparison} {value} OR ({column} = {value} AND f.id > '{id}'))",
            column = options.sort_column,
            value = cursor.sort_value,
            id = clickhouse_quote(&cursor.id),
        ));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let order = if options.descending { "DESC" } else { "ASC" };
    let limit = u64::from(options.limit) + 1;
    let sql = format!(
        "SELECT f.id, f.client_ip, f.client_port, f.remote_ip, f.remote_port, f.protocol,
                f.direction, f.domain, f.organization_id, f.application_id, f.category_id,
                f.traffic_role, f.protocol_id, f.organization_confidence, f.application_confidence,
                f.protocol_confidence, f.classification_confidence,
                f.classification_reason, f.classification_evidence_json, f.upload_bytes,
                f.download_bytes, f.packets, f.started_at, f.last_seen_at, f.ended_at,
                f.device_id, coalesce(d.display_name, d.hostname, '') AS client_name, d.mac,
                d.device_type, d.model, d.vendor, d.os_family,
                f.scope, f.path_type, f.nat, f.source_segment, f.destination_segment,
                {sort_column} AS cursor_value
         FROM flow_sessions AS f FINAL LEFT JOIN devices AS d FINAL ON d.id = f.device_id{where_clause}
         ORDER BY {sort_column} {order}, f.id ASC LIMIT {limit} FORMAT JSON",
        sort_column = options.sort_column,
    );
    let result = clickhouse.client().query_json(&sql)?;
    let mut items = result["data"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            let client_ip =
                netqmon_storage::from_hex(row["client_ip"].as_str().unwrap_or_default())
                    .unwrap_or_default();
            let remote_ip =
                netqmon_storage::from_hex(row["remote_ip"].as_str().unwrap_or_default())
                    .unwrap_or_default();
            let application = row["application_id"].as_str().unwrap_or("unknown");
            let organization = row["organization_id"].as_str().unwrap_or("unknown");
            let category = row["category_id"].as_str().unwrap_or("unknown");
            let traffic_role = row["traffic_role"].as_str().unwrap_or("unknown");
            let protocol_id = row["protocol_id"].as_str().unwrap_or("unknown");
            let application_metadata = classifier.application_metadata(application);
            let organization_metadata = classifier.organization_metadata(organization);
            let client_mac = netqmon_storage::from_hex(row["mac"].as_str().unwrap_or_default())
                .ok()
                .filter(|value| !value.is_empty())
                .map(|value| format_mac(&value));
            let number = |name: &str| {
                row[name]
                    .as_i64()
                    .or_else(|| row[name].as_str().and_then(|value| value.parse().ok()))
                    .unwrap_or(0)
            };
            let optional_number = |name: &str| {
                row.get(name).filter(|value| !value.is_null()).map(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
                        .unwrap_or(0)
                })
            };
            let decimal = |name: &str| {
                row[name]
                    .as_f64()
                    .or_else(|| row[name].as_str().and_then(|value| value.parse().ok()))
                    .unwrap_or(0.0)
            };
            json!({
                "id": row["id"].as_str().unwrap_or_default(),
                "client_ip": format_ip(&client_ip),
                "client_port": number("client_port"),
                "remote_ip": format_ip(&remote_ip),
                "remote_port": number("remote_port"),
                "protocol": number("protocol"),
                "direction": number("direction"),
                "domain": row["domain"].as_str(),
                "organization": organization,
                "organization_name": organization_metadata.as_ref().map(|value| value.name.clone()),
                "application": application,
                "application_name": application_metadata.as_ref().map(|value| value.name.clone()),
                "icon": icon_json(application_metadata),
                "category": category,
                "traffic_role": traffic_role,
                "protocol_id": protocol_id,
                "organization_confidence": decimal("organization_confidence"),
                "application_confidence": decimal("application_confidence"),
                "protocol_confidence": decimal("protocol_confidence"),
                "confidence": decimal("classification_confidence"),
                "reason": row["classification_reason"].as_str().unwrap_or("no matching rule"),
                "evidence": row["classification_evidence_json"].as_str().unwrap_or("[]"),
                "upload_bytes": number("upload_bytes"),
                "download_bytes": number("download_bytes"),
                "packets": number("packets"),
                "started_at": number("started_at"),
                "last_seen": number("last_seen_at"),
                "ended_at": optional_number("ended_at"),
                "client_id": optional_number("device_id"),
                "client_name": row["client_name"].as_str().unwrap_or_default(),
                "client_mac": client_mac,
                "client_identity": {
                    "device_type": row["device_type"].as_str(),
                    "model": row["model"].as_str(),
                    "vendor": row["vendor"].as_str(),
                    "os_family": row["os_family"].as_str(),
                },
                "scope": flow_scope_name(number("scope") as i32),
                "path_type": flow_path_name(number("path_type") as i32),
                "nat": flow_nat_name(number("nat") as i32),
                "source_segment": row["source_segment"].as_str().unwrap_or_default(),
                "destination_segment": row["destination_segment"].as_str().unwrap_or_default(),
                "cursor_value": number("cursor_value"),
            })
        })
        .collect::<Vec<_>>();
    let has_more = items.len() > options.limit as usize;
    items.truncate(options.limit as usize);
    let next_cursor = has_more
        .then(|| flow_cursor_for(items.last().expect("extra row implies a non-empty page")));
    for item in &mut items {
        item.as_object_mut()
            .expect("flow result is an object")
            .remove("cursor_value");
    }
    Ok((items, next_cursor))
}

fn clickhouse_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn flow_filters(query: &FlowQuery) -> rusqlite::Result<(Vec<String>, Vec<SqlValue>)> {
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    add_flow_identity_filters(query, &mut clauses, &mut values)?;
    add_flow_transport_filters(query, &mut clauses, &mut values)?;
    Ok((clauses, values))
}

fn add_flow_identity_filters(
    query: &FlowQuery,
    clauses: &mut Vec<String>,
    values: &mut Vec<SqlValue>,
) -> rusqlite::Result<()> {
    if let Some(search) = non_empty(query.search.as_deref()) {
        if let Ok(ip) = search.parse::<IpAddr>() {
            clauses.push("(f.client_ip = ? OR f.remote_ip = ?)".to_owned());
            let bytes = ip_bytes(ip);
            values.extend([SqlValue::Blob(bytes.clone()), SqlValue::Blob(bytes)]);
        } else {
            clauses.push("(LOWER(COALESCE(f.domain, '')) LIKE ? OR LOWER(COALESCE(f.application_id, '')) LIKE ? OR LOWER(COALESCE(d.display_name, d.hostname, '')) LIKE ? OR LOWER(HEX(COALESCE(d.mac, X''))) LIKE ?)".to_owned());
            let pattern = format!("%{}%", search.to_lowercase());
            values.extend((0..4).map(|_| SqlValue::Text(pattern.clone())));
        }
    }
    if let Some(client) = non_empty(query.client.as_deref()) {
        if let Ok(id) = client.parse::<i64>() {
            clauses.push("f.device_id = ?".to_owned());
            values.push(SqlValue::Integer(id));
        } else if let Ok(ip) = client.parse::<IpAddr>() {
            clauses.push("f.client_ip = ?".to_owned());
            values.push(SqlValue::Blob(ip_bytes(ip)));
        } else {
            clauses.push("(LOWER(COALESCE(d.display_name, d.hostname, '')) LIKE ? OR LOWER(HEX(COALESCE(d.mac, X''))) LIKE ?)".to_owned());
            let pattern = format!("%{}%", client.to_lowercase().replace([':', '-'], ""));
            values.extend([SqlValue::Text(pattern.clone()), SqlValue::Text(pattern)]);
        }
    }
    if let Some(application) = non_empty(query.application.as_deref()) {
        clauses.push("LOWER(COALESCE(f.application_id, 'unknown')) = ?".to_owned());
        values.push(SqlValue::Text(application.to_lowercase()));
    }
    if let Some(organization) = non_empty(query.organization.as_deref()) {
        clauses.push("LOWER(COALESCE(f.organization_id, 'unknown')) = ?".to_owned());
        values.push(SqlValue::Text(organization.to_lowercase()));
    }
    if let Some(detected_protocol) = non_empty(query.detected_protocol.as_deref()) {
        clauses.push("LOWER(COALESCE(f.protocol_id, 'unknown')) = ?".to_owned());
        values.push(SqlValue::Text(detected_protocol.to_lowercase()));
    }
    if let Some(domain) = non_empty(query.domain.as_deref()) {
        clauses.push("LOWER(COALESCE(f.domain, '')) LIKE ?".to_owned());
        values.push(SqlValue::Text(format!("%{}%", domain.to_lowercase())));
    }
    if let Some(ip) = non_empty(query.ip.as_deref()) {
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|_| rusqlite::Error::InvalidParameterName("invalid_ip".to_owned()))?;
        clauses.push("f.remote_ip = ?".to_owned());
        values.push(SqlValue::Blob(ip_bytes(ip)));
    }
    Ok(())
}

fn add_flow_transport_filters(
    query: &FlowQuery,
    clauses: &mut Vec<String>,
    values: &mut Vec<SqlValue>,
) -> rusqlite::Result<()> {
    if let Some(protocol) = non_empty(query.protocol.as_deref()) {
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            value => value.parse::<u8>().map(i64::from).map_err(|_| {
                rusqlite::Error::InvalidParameterName("invalid_protocol".to_owned())
            })?,
        };
        clauses.push("f.protocol = ?".to_owned());
        values.push(SqlValue::Integer(protocol));
    }
    if let Some(port) = query.port {
        clauses.push("(f.client_port = ? OR f.remote_port = ?)".to_owned());
        values.extend([
            SqlValue::Integer(i64::from(port)),
            SqlValue::Integer(i64::from(port)),
        ]);
    }
    if let Some(direction) = non_empty(query.direction.as_deref()) {
        let direction = match direction.to_ascii_lowercase().as_str() {
            "unknown" => 0,
            "upload" => 1,
            "download" => 2,
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid_direction".to_owned(),
                ));
            }
        };
        clauses.push("f.direction = ?".to_owned());
        values.push(SqlValue::Integer(direction));
    }
    if let Some(scope) = non_empty(query.scope.as_deref()) {
        let scope = match scope.to_ascii_lowercase().as_str() {
            "internet" => netqmon_protocol::v1::FlowScope::Internet as i64,
            "internal" => netqmon_protocol::v1::FlowScope::Internal as i64,
            "tunnel" => netqmon_protocol::v1::FlowScope::Tunnel as i64,
            "unknown" => netqmon_protocol::v1::FlowScope::Unknown as i64,
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid_scope".to_owned(),
                ));
            }
        };
        clauses.push("f.scope = ?".to_owned());
        values.push(SqlValue::Integer(scope));
    }
    if let Some(path_type) = non_empty(query.path_type.as_deref()) {
        let path_type = match path_type.to_ascii_lowercase().as_str() {
            "forwarded" => netqmon_protocol::v1::PathType::Forwarded as i64,
            "internal" => netqmon_protocol::v1::PathType::Internal as i64,
            "tunnel" => netqmon_protocol::v1::PathType::Tunnel as i64,
            "unknown" => netqmon_protocol::v1::PathType::Unknown as i64,
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid_path_type".to_owned(),
                ));
            }
        };
        clauses.push("f.path_type = ?".to_owned());
        values.push(SqlValue::Integer(path_type));
    }
    if let Some(nat) = non_empty(query.nat.as_deref()) {
        let nat = match nat.to_ascii_lowercase().as_str() {
            "none" => netqmon_protocol::v1::NatType::None as i64,
            "snat" => netqmon_protocol::v1::NatType::Snat as i64,
            "dnat" => netqmon_protocol::v1::NatType::Dnat as i64,
            "both" => netqmon_protocol::v1::NatType::Both as i64,
            "unknown" => netqmon_protocol::v1::NatType::Unknown as i64,
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid_nat".to_owned(),
                ));
            }
        };
        clauses.push("f.nat = ?".to_owned());
        values.push(SqlValue::Integer(nat));
    }
    if query.from.is_some() || query.to.is_some() {
        let from = query.from.unwrap_or(0);
        let to = query.to.unwrap_or_else(now_ms);
        if from >= to || to > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "invalid_time_range".to_owned(),
            ));
        }
        clauses.push("f.last_seen_at >= ? AND f.last_seen_at < ?".to_owned());
        values.extend([
            SqlValue::Integer(to_i64(from)),
            SqlValue::Integer(to_i64(to)),
        ]);
    }
    Ok(())
}

fn flow_row_json(
    row: &rusqlite::Row<'_>,
    classifier: &crate::classifier::ClassifierHandle,
) -> rusqlite::Result<Value> {
    let client_ip: Vec<u8> = row.get(1)?;
    let remote_ip: Vec<u8> = row.get(3)?;
    let application = row
        .get::<_, Option<String>>(9)?
        .unwrap_or_else(|| "unknown".to_owned());
    let application_metadata = classifier.application_metadata(&application);
    let application_name = application_metadata
        .as_ref()
        .map(|metadata| metadata.name.clone());
    let icon = icon_json(application_metadata);
    Ok(json!({
        "id": row.get::<_, String>(0)?, "client_ip": format_ip(&client_ip),
        "client_port": row.get::<_, i64>(2)?, "remote_ip": format_ip(&remote_ip),
        "remote_port": row.get::<_, i64>(4)?, "protocol": row.get::<_, i64>(5)?,
        "direction": row.get::<_, i64>(6)?, "domain": row.get::<_, Option<String>>(7)?,
        "organization": row.get::<_, Option<String>>(8)?.unwrap_or_else(|| "unknown".to_owned()),
        "application": application,
        "application_name": application_name,
        "icon": icon,
        "category": row.get::<_, Option<String>>(10)?.unwrap_or_else(|| "unknown".to_owned()),
        "traffic_role": row.get::<_, Option<String>>(11)?.unwrap_or_else(|| "unknown".to_owned()),
        "protocol_id": row.get::<_, Option<String>>(12)?.unwrap_or_else(|| "unknown".to_owned()),
        "organization_confidence": row.get::<_, Option<f64>>(13)?.unwrap_or(0.0),
        "application_confidence": row.get::<_, Option<f64>>(14)?.unwrap_or(0.0),
        "protocol_confidence": row.get::<_, Option<f64>>(15)?.unwrap_or(0.0),
        "confidence": row.get::<_, Option<f64>>(16)?.unwrap_or(0.0),
        "reason": row.get::<_, Option<String>>(17)?.unwrap_or_else(|| "no matching rule".to_owned()),
        "evidence": row.get::<_, Option<String>>(18)?.unwrap_or_else(|| "[]".to_owned()),
        "upload_bytes": row.get::<_, i64>(19)?, "download_bytes": row.get::<_, i64>(20)?,
        "packets": row.get::<_, i64>(21)?, "started_at": row.get::<_, i64>(22)?,
        "last_seen": row.get::<_, i64>(23)?, "ended_at": row.get::<_, Option<i64>>(24)?,
        "client_id": row.get::<_, Option<i64>>(25)?, "client_name": row.get::<_, String>(26)?,
        "client_mac": row.get::<_, Option<Vec<u8>>>(27)?.map(|mac| format_mac(&mac)),
        "client_identity": {
            "device_type": row.get::<_, Option<String>>(28)?,
            "model": row.get::<_, Option<String>>(29)?,
            "vendor": row.get::<_, Option<String>>(30)?,
            "os_family": row.get::<_, Option<String>>(31)?,
        },
        "scope": flow_scope_name(row.get::<_, i32>(32)?),
        "path_type": flow_path_name(row.get::<_, i32>(33)?),
        "nat": flow_nat_name(row.get::<_, i32>(34)?),
        "source_segment": row.get::<_, String>(35)?,
        "destination_segment": row.get::<_, String>(36)?,
        "cursor_value": row.get::<_, i64>(37)?,
    }))
}

fn flow_cursor_for(item: &Value) -> String {
    format!(
        "{}|{}",
        item["cursor_value"].as_i64().unwrap_or_default(),
        item["id"].as_str().unwrap_or_default()
    )
}

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

fn flow_query_error(name: &str) -> Response {
    let (code, message) = match name {
        "invalid_ip" => ("invalid_ip", "ip must be a valid IPv4 or IPv6 address"),
        "invalid_protocol" => (
            "invalid_protocol",
            "protocol must be tcp, udp, or an IP protocol number",
        ),
        "invalid_direction" => (
            "invalid_direction",
            "direction must be upload, download, or unknown",
        ),
        "invalid_scope" => (
            "invalid_scope",
            "scope must be internet, internal, tunnel, or unknown",
        ),
        "invalid_path_type" => (
            "invalid_path_type",
            "path_type must be forwarded, internal, tunnel, or unknown",
        ),
        "invalid_nat" => (
            "invalid_nat",
            "nat must be none, snat, dnat, both, or unknown",
        ),
        "invalid_time_range" => ("invalid_time_range", "from must be less than to"),
        _ => ("invalid_query", "Flow query is invalid"),
    };
    api_error(StatusCode::BAD_REQUEST, code, message)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn parse_flow_cursor(value: &str) -> Result<FlowCursor, &'static str> {
    let Some((sort_value, id)) = value.split_once('|') else {
        return Err("cursor is malformed");
    };
    let sort_value = sort_value
        .parse::<i64>()
        .map_err(|_| "cursor is malformed")?;
    if id.is_empty() {
        return Err("cursor is malformed");
    }
    Ok(FlowCursor {
        sort_value,
        id: id.to_owned(),
    })
}

fn summary_page(
    state: &CollectorState,
    query: Result<Query<PageQuery>, QueryRejection>,
    table: &str,
    group: &str,
    names: &[&str],
) -> Response {
    let page = match Page::parse(query) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let inner = state.lock();
    if table == "traffic_domain_minute" {
        if let Some(clickhouse) = inner.storage.clickhouse_storage() {
            return clickhouse
                .query_domains(page.limit, page.offset)
                .map(|(items, total)| page_ok(items, page, total))
                .unwrap_or_else(storage_error);
        }
    }
    let connection = inner.storage.connection();
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let count_sql = format!("SELECT COUNT(*) FROM (SELECT 1 FROM {table} GROUP BY {group})");
        let total: i64 = scalar(connection, &count_sql, [])?;
        let sql = format!(
            "SELECT {group}, SUM(upload_bytes), SUM(download_bytes), SUM(packets),
                    SUM(flow_count), MAX(timestamp)
             FROM {table} GROUP BY {group}
             ORDER BY SUM(upload_bytes + download_bytes) DESC, {group}
             LIMIT ?1 OFFSET ?2"
        );
        let mut statement = connection.prepare(&sql)?;
        let items = statement
            .query_map(params![i64::from(page.limit), to_i64(page.offset)], |row| {
                summary_row(row, names)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, to_u64(total)))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}

fn summary_row(row: &rusqlite::Row<'_>, names: &[&str]) -> rusqlite::Result<Value> {
    let mut object = serde_json::Map::new();
    for (index, name) in names.iter().enumerate() {
        object.insert((*name).to_owned(), json!(row.get::<_, String>(index)?));
    }
    let metric = names.len();
    object.insert("upload_bytes".to_owned(), json!(row.get::<_, i64>(metric)?));
    object.insert(
        "download_bytes".to_owned(),
        json!(row.get::<_, i64>(metric + 1)?),
    );
    object.insert("packets".to_owned(), json!(row.get::<_, i64>(metric + 2)?));
    object.insert(
        "flow_count".to_owned(),
        json!(row.get::<_, i64>(metric + 3)?),
    );
    object.insert(
        "last_seen".to_owned(),
        json!(row.get::<_, i64>(metric + 4)?),
    );
    Ok(Value::Object(object))
}

fn query_clients(
    connection: &Connection,
    page: Page,
    window: Option<(i64, i64)>,
) -> rusqlite::Result<(Vec<Value>, u64)> {
    let total: i64 = scalar(connection, "SELECT COUNT(*) FROM devices", [])?;
    let traffic_join = if window.is_some() {
        "(SELECT device_id, SUM(upload_bytes) AS upload_bytes,
                SUM(download_bytes) AS download_bytes, SUM(flow_count) AS flow_count,
                MAX(timestamp) AS timestamp
         FROM traffic_device_minute WHERE timestamp >= ?1 AND timestamp < ?2
         GROUP BY device_id)"
    } else {
        "traffic_device_minute"
    };
    let session_window = if window.is_some() {
        "AND flow_sessions.last_seen_at >= ?1 AND flow_sessions.last_seen_at < ?2"
    } else {
        ""
    };
    let page_window = if window.is_some() {
        "?3 OFFSET ?4"
    } else {
        "?1 OFFSET ?2"
    };
    let sql = format!(
        "SELECT d.id, d.mac, COALESCE(d.display_name, d.hostname, ''), d.vendor,
                d.device_type, d.os_family, d.model, d.identity_confidence,
                COALESCE((SELECT json_group_array(json_object(
                    'source', e.source, 'field', e.field, 'value', e.value,
                    'confidence', e.confidence, 'first_seen', e.first_seen,
                    'last_seen', e.last_seen, 'hit_count', e.hit_count,
                    'metadata_json', e.metadata_json))
                  FROM device_evidence e WHERE e.gateway_id = d.gateway_id AND e.mac = d.mac), '[]'),
                d.vendor_confidence, d.device_type_confidence, d.os_confidence,
                d.model_confidence, d.private_mac, d.last_seen,
                (SELECT MAX(flow_sessions.last_seen_at) FROM flow_sessions
                 WHERE flow_sessions.device_id = d.id
                   AND (flow_sessions.upload_bytes > 0 OR flow_sessions.download_bytes > 0
                        OR flow_sessions.packets > 0) {session_window}),
                COALESCE(SUM(t.upload_bytes), 0), COALESCE(SUM(t.download_bytes), 0),
                COALESCE(SUM(t.flow_count), 0),
                (SELECT ip FROM device_addresses a WHERE a.device_id = d.id
                 ORDER BY a.last_seen DESC, a.ip_version LIMIT 1),
                CASE WHEN (SELECT COUNT(*) FROM device_addresses a WHERE a.device_id=d.id)=1
                     THEN (SELECT application_id FROM device_addresses a WHERE a.device_id=d.id LIMIT 1)
                END,
                CASE WHEN (SELECT COUNT(*) FROM device_addresses a WHERE a.device_id=d.id)=1
                     THEN (SELECT application_confidence FROM device_addresses a WHERE a.device_id=d.id LIMIT 1)
                     ELSE 0 END,
                CASE WHEN (SELECT COUNT(*) FROM device_addresses a WHERE a.device_id=d.id)=1
                     THEN (SELECT application_source FROM device_addresses a WHERE a.device_id=d.id LIMIT 1)
                END
         FROM devices d LEFT JOIN {traffic_join} t ON t.device_id = d.id
         GROUP BY d.id ORDER BY SUM(COALESCE(t.upload_bytes, 0) + COALESCE(t.download_bytes, 0)) DESC,
                  d.id LIMIT {page_window}"
    );
    let mut statement = connection.prepare(&sql)?;
    let map_row = |row: &Row<'_>| {
        let mac: Vec<u8> = row.get(1)?;
        let ip = row
            .get::<_, Option<Vec<u8>>>(19)?
            .map(|value| format_ip(&value));
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "mac": format_mac(&mac),
            "name": row.get::<_, String>(2)?,
            "vendor": row.get::<_, Option<String>>(3)?,
            "identity": device_identity_json(row, 3)?,
            "last_seen": row.get::<_, i64>(14)?,
            "last_traffic_seen": row.get::<_, Option<i64>>(15)?,
            "upload_bytes": row.get::<_, i64>(16)?,
            "download_bytes": row.get::<_, i64>(17)?,
            "flow_count": row.get::<_, i64>(18)?,
            "ip": ip,
            "self_host_application": row.get::<_, Option<String>>(20)?.map(|application_id| json!({
                "application_id": application_id,
                "confidence": row.get::<_, f64>(21).unwrap_or(0.0),
                "source": row.get::<_, Option<String>>(22).ok().flatten(),
                "role": "server",
            })),
        }))
    };
    let items = match window {
        Some((from, to)) => statement
            .query_map(
                params![from, to, i64::from(page.limit), to_i64(page.offset)],
                map_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => statement
            .query_map(params![i64::from(page.limit), to_i64(page.offset)], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok((items, to_u64(total)))
}

fn query_client_detail(connection: &Connection, id: i64) -> rusqlite::Result<Option<Value>> {
    let client = connection
        .query_row(
            "SELECT d.id, d.mac, COALESCE(d.display_name, d.hostname, ''), d.vendor,
                    d.device_type, d.os_family, d.model, d.identity_confidence,
                    COALESCE((SELECT json_group_array(json_object(
                        'source', e.source, 'field', e.field, 'value', e.value,
                        'confidence', e.confidence, 'first_seen', e.first_seen,
                        'last_seen', e.last_seen, 'hit_count', e.hit_count,
                        'metadata_json', e.metadata_json))
                      FROM device_evidence e WHERE e.gateway_id = d.gateway_id AND e.mac = d.mac), '[]'),
                    d.vendor_confidence, d.device_type_confidence, d.os_confidence,
                    d.model_confidence, d.private_mac, d.first_seen, d.last_seen,
                    (SELECT MAX(flow_sessions.last_seen_at) FROM flow_sessions
                     WHERE flow_sessions.device_id = d.id
                       AND (flow_sessions.upload_bytes > 0 OR flow_sessions.download_bytes > 0
                            OR flow_sessions.packets > 0)),
                    COALESCE(SUM(t.upload_bytes), 0),
                    COALESCE(SUM(t.download_bytes), 0), COALESCE(SUM(t.flow_count), 0)
             FROM devices d LEFT JOIN traffic_device_minute t ON t.device_id = d.id
             WHERE d.id = ?1 GROUP BY d.id",
            [id],
            |row| {
                let mac: Vec<u8> = row.get(1)?;
                Ok(json!({
                    "id": row.get::<_, i64>(0)?,
                    "mac": format_mac(&mac),
                    "name": row.get::<_, String>(2)?,
                    "vendor": row.get::<_, Option<String>>(3)?,
                    "identity": device_identity_json(row, 3)?,
                    "first_seen": row.get::<_, i64>(14)?,
                    "last_seen": row.get::<_, i64>(15)?,
                    "last_traffic_seen": row.get::<_, Option<i64>>(16)?,
                    "upload_bytes": row.get::<_, i64>(17)?,
                    "download_bytes": row.get::<_, i64>(18)?,
                    "flow_count": row.get::<_, i64>(19)?,
                }))
            },
        )
        .optional()?;
    let Some(mut client) = client else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT ip, ip_version, first_seen, last_seen, application_id,
                application_confidence, application_source, application_last_seen
         FROM device_addresses
         WHERE device_id = ?1 ORDER BY last_seen DESC, hex(ip)",
    )?;
    let addresses = statement
        .query_map([id], |row| {
            let address: Vec<u8> = row.get(0)?;
            Ok(json!({
                "ip": format_ip(&address),
                "ip_version": row.get::<_, i64>(1)?,
                "first_seen": row.get::<_, i64>(2)?,
                "last_seen": row.get::<_, i64>(3)?,
                "self_host_application": row.get::<_, Option<String>>(4)?.map(|application_id| json!({
                    "application_id": application_id,
                    "confidence": row.get::<_, f64>(5).unwrap_or(0.0),
                    "source": row.get::<_, Option<String>>(6).ok().flatten(),
                    "last_seen": row.get::<_, Option<i64>>(7).ok().flatten(),
                    "role": "server",
                })),
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if addresses.len() == 1 {
        if let Some(application) = addresses[0].get("self_host_application") {
            if !application.is_null() {
                client["self_host_application"] = application.clone();
            }
        }
    }
    Ok(Some(json!({ "client": client, "addresses": addresses })))
}

async fn get_retention(State(state): State<CollectorState>) -> Response {
    let inner = state.lock();
    let result = inner.storage.load_retention_policy();
    match result {
        Ok(policy) => api_ok(json!({
            "flow_sessions_days": policy.flow_sessions_days,
            "dns_days": policy.dns_days,
            "minute_days": policy.minute_days,
            "hour_days": policy.hour_days,
            "day_days": policy.day_days,
        })),
        Err(error) => storage_error(error),
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct RetentionUpdate {
    flow_sessions_days: u32,
    dns_days: u32,
    minute_days: u32,
    hour_days: u32,
    day_days: u32,
}

async fn put_retention(State(state): State<CollectorState>, body: Bytes) -> Response {
    let update: RetentionUpdate = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body must be valid JSON with flow_sessions_days, dns_days, minute_days, hour_days, day_days",
            );
        }
    };
    if update.minute_days == 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_retention",
            "minute_days must be at least 1",
        );
    }
    if update.hour_days != 0 && update.hour_days < update.minute_days {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_retention",
            "hour_days must be 0 (forever) or >= minute_days",
        );
    }
    if update.day_days != 0 && update.hour_days != 0 && update.day_days < update.hour_days {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_retention",
            "day_days must be 0 (forever) or >= hour_days",
        );
    }
    let policy = netqmon_storage::RetentionPolicy {
        flow_sessions_days: update.flow_sessions_days,
        dns_days: update.dns_days,
        minute_days: update.minute_days,
        hour_days: update.hour_days,
        day_days: update.day_days,
    };
    let mut inner = state.lock();
    match inner.storage.save_retention_policy(&policy, now_ms()) {
        Ok(()) => api_ok(json!({
            "flow_sessions_days": policy.flow_sessions_days,
            "dns_days": policy.dns_days,
            "minute_days": policy.minute_days,
            "hour_days": policy.hour_days,
            "day_days": policy.day_days,
        })),
        Err(error) => storage_error(error),
    }
}

async fn run_retention(State(state): State<CollectorState>) -> Response {
    let result = {
        let mut inner = state.lock();
        let policy = match inner.storage.load_retention_policy() {
            Ok(policy) => policy,
            Err(error) => return storage_error(error),
        };
        inner.storage.run_retention(now_ms(), policy)
    };
    match result {
        Ok(()) => api_ok(json!({ "status": "completed" })),
        Err(error) => storage_error(error),
    }
}

async fn reload_rules(State(state): State<CollectorState>) -> Response {
    let inner = state.lock();
    match inner.classifier.reload_rules() {
        Ok(stats) => {
            let mut payload =
                serde_json::to_value(&stats).expect("rule statistics serialize as JSON object");
            payload["reloaded_at"] = json!(now_ms());
            api_ok(payload)
        }
        Err(error) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "classifier_unavailable",
            &error,
        ),
    }
}

async fn diagnostics(State(state): State<CollectorState>) -> Response {
    let topology = state
        .realtime_snapshot()
        .gateway_health
        .and_then(|health| health.topology);
    let inner = state.lock();
    let result = (|| -> Result<Value, String> {
        let now = now_ms();
        let db_size = inner
            .storage
            .database_size_bytes()
            .map_err(|e| e.to_string())?;
        let active_flows = inner
            .storage
            .active_flow_count()
            .map_err(|e| e.to_string())?;
        let unknown_ratio = inner
            .storage
            .unknown_ratio(now.saturating_sub(DAY_MS))
            .map_err(|e| e.to_string())?;
        let retention = inner
            .storage
            .load_retention_policy()
            .map_err(|e| e.to_string())?;

        let gateway = if let Some(ch) = inner.storage.clickhouse_storage() {
            let gw_sql = "SELECT id, name, agent_version, kernel_version, openwrt_version, last_seen FROM gateways FINAL ORDER BY created_at LIMIT 1 FORMAT JSON";
            let res = ch.client().query_json(gw_sql).map_err(|e| e.to_string())?;
            res["data"].as_array().and_then(|a| a.first()).map(|r| json!({
                "id": r["id"].as_str().unwrap_or(""),
                "name": r["name"].as_str().unwrap_or(""),
                "agent_version": r["agent_version"].as_str().unwrap_or(""),
                "kernel_version": r["kernel_version"].as_str().unwrap_or(""),
                "openwrt_version": r["openwrt_version"].as_str().unwrap_or(""),
                "last_seen": r["last_seen"].as_i64().or_else(|| r["last_seen"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
            }))
        } else {
            let connection = inner.storage.connection();
            connection
                .query_row(
                    "SELECT id, name, agent_version, kernel_version, openwrt_version, last_seen
                     FROM gateways ORDER BY created_at LIMIT 1",
                    [],
                    |row| {
                        Ok(json!({
                            "id": row.get::<_, String>(0)?,
                            "name": row.get::<_, String>(1)?,
                            "agent_version": row.get::<_, String>(2)?,
                            "kernel_version": row.get::<_, String>(3)?,
                            "openwrt_version": row.get::<_, String>(4)?,
                            "last_seen": row.get::<_, i64>(5)?,
                        }))
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?
        };

        Ok(json!({
            "collector_version": env!("CARGO_PKG_VERSION"),
            "db_backend": inner.storage.backend_name(),
            "db_size_bytes": db_size,
            "gateway": gateway,
            "active_flows": active_flows,
            "unknown_ratio": unknown_ratio,
            "retention": {
                "flow_sessions_days": retention.flow_sessions_days,
                "dns_days": retention.dns_days,
                "minute_days": retention.minute_days,
                "hour_days": retention.hour_days,
                "day_days": retention.day_days,
            },
            "geo_enabled": inner.geo_provider.is_enabled(),
            "classification": inner.classifier.diagnostics(),
            "classifier_manager": classifier_manager_status(),
            "sampling": state.sampling.diagnostics(),
            "recognition": crate::recognition_diagnostics::diagnostics(&inner, now.saturating_sub(DAY_MS))?,
            "topology": topology,
        }))
    })();
    result.map_or_else(storage_error, api_ok)
}

pub(crate) fn classifier_manager_status_from_path(path: &std::path::Path) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<Value>(&content).ok())
}

fn classifier_manager_status() -> Option<Value> {
    classifier_manager_status_from_path(std::path::Path::new(
        "/run/netqmon/classifier-manager-status.json",
    ))
}

fn api_ok(data: Value) -> Response {
    (
        StatusCode::OK,
        Json(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            data,
            pagination: None,
        }),
    )
        .into_response()
}

fn page_ok(items: Vec<Value>, page: Page, total: u64) -> Response {
    (
        StatusCode::OK,
        Json(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            data: items,
            pagination: Some(Pagination {
                limit: page.limit,
                offset: page.offset,
                total,
            }),
        }),
    )
        .into_response()
}

fn icon_json(metadata: Option<crate::classifier::EntityMetadata>) -> Value {
    metadata.map_or(Value::Null, |metadata| json!(metadata.icon))
}

fn metadata_name(metadata: Option<&crate::classifier::EntityMetadata>, fallback: &str) -> String {
    metadata.map_or_else(|| fallback.to_owned(), |metadata| metadata.name.clone())
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "schema_version": SCHEMA_VERSION,
            "error": {
                "code": code,
                "message": message,
            },
            "pagination": null,
        })),
    )
        .into_response()
}

fn storage_error<E: std::fmt::Display>(_error: E) -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage_error",
        "query could not be completed",
    )
}

fn scalar<P>(connection: &Connection, sql: &str, parameters: P) -> rusqlite::Result<i64>
where
    P: rusqlite::Params,
{
    connection.query_row(sql, parameters, |row| row.get(0))
}

fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        return "unknown".to_owned();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn device_identity_json(row: &Row<'_>, vendor_index: usize) -> rusqlite::Result<Value> {
    let evidence_text: String = row
        .get::<_, Option<String>>(vendor_index + 5)?
        .unwrap_or_else(|| "[]".to_owned());
    let evidence = serde_json::from_str::<Value>(&evidence_text).unwrap_or_else(|_| json!([]));
    Ok(json!({
        "vendor": row.get::<_, Option<String>>(vendor_index)?,
        "device_type": row.get::<_, Option<String>>(vendor_index + 1)?,
        "os_family": row.get::<_, Option<String>>(vendor_index + 2)?,
        "model": row.get::<_, Option<String>>(vendor_index + 3)?,
        "confidence": row
            .get::<_, Option<String>>(vendor_index + 4)?
            .unwrap_or_else(|| "unknown".to_owned()),
        "vendor_confidence": row.get::<_, f64>(vendor_index + 6)?,
        "device_type_confidence": row.get::<_, f64>(vendor_index + 7)?,
        "os_confidence": row.get::<_, f64>(vendor_index + 8)?,
        "model_confidence": row.get::<_, f64>(vendor_index + 9)?,
        "private_mac": row.get::<_, bool>(vendor_index + 10)?,
        "evidence": evidence,
    }))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_application_identifier(value: &str) -> bool {
    value
        .strip_prefix(PROTOCOL_APPLICATION_PREFIX)
        .is_some_and(valid_identifier)
        || valid_identifier(value)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn gateway_offline_after_ms() -> u64 {
    std::env::var("NETQMON_GATEWAY_OFFLINE_AFTER_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GATEWAY_OFFLINE_AFTER_MS)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

async fn get_geo_settings(State(state): State<CollectorState>) -> Response {
    let (geo_directory, enabled) = {
        let inner = state.lock();
        (inner.geo_directory.clone(), inner.geo_provider.is_enabled())
    };
    let status = geo_updater::get_geo_status(&geo_directory, enabled);
    api_ok(json!(status))
}

#[derive(Clone, Debug, Default, Deserialize)]
struct GeoUpdateRequest {
    city_url: Option<String>,
    country_url: Option<String>,
    asn_url: Option<String>,
}

async fn post_geo_update(
    State(state): State<CollectorState>,
    body: Option<Json<GeoUpdateRequest>>,
) -> Response {
    let geo_directory = {
        let inner = state.lock();
        inner.geo_directory.clone()
    };
    let payload = body.map(|b| b.0).unwrap_or_default();

    let update_res = tokio::task::spawn_blocking(move || {
        let city = payload
            .city_url
            .or(payload.country_url)
            .unwrap_or_else(|| geo_updater::DEFAULT_CITY_SOURCE.to_owned());
        let asn = payload
            .asn_url
            .unwrap_or_else(|| geo_updater::DEFAULT_ASN_SOURCE.to_owned());
        geo_updater::update_geo_databases_with_urls(&geo_directory, &city, &asn)
    })
    .await;

    let (actual_directory, updated_files) = match update_res {
        Ok(Ok((dir, files))) => (dir, files),
        Ok(Err(error)) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "geo_update_error",
                &error,
            );
        }
        Err(join_err) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "geo_update_error",
                &join_err.to_string(),
            );
        }
    };

    let (geo_directory, enabled) = {
        let mut inner = state.lock();
        inner.geo_directory = actual_directory;
        let load = netqmon_geo::LocalDbProvider::load(&inner.geo_directory);
        for warning in &load.warnings {
            tracing::warn!(warning, "geo reload warning");
        }
        let enabled = load.provider.is_enabled();
        inner.geo_provider = Arc::new(load.provider);
        tracing::info!(
            enabled,
            directory = %inner.geo_directory.display(),
            "geo provider reloaded successfully"
        );
        (inner.geo_directory.clone(), enabled)
    };

    let status = geo_updater::get_geo_status(&geo_directory, enabled);
    api_ok(json!({
        "success": true,
        "message": "Geo databases updated and reloaded successfully",
        "updated_files": updated_files,
        "status": status,
    }))
}
