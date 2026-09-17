use std::collections::{BTreeMap, HashMap};
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
use netqmon_geo::GeoProvider;
use netqmon_storage::analytics::{
    AnalyticsFlow, AnalyticsSummary, FlowQuery as AnalyticsFlowQuery, FlowSort, SummaryQuery,
    TrafficBreakdownQuery, TrafficDimension, TrafficQuery as AnalyticsTrafficQuery,
    resolution_for_range,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
    offset: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimePageQuery {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
    offset: Option<u64>,
    category: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficParams {
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
struct DestinationParams {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
    offset: Option<u64>,
    lang: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeoParams {
    from: Option<u64>,
    to: Option<u64>,
    lang: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InsightParams {
    from: Option<u64>,
    to: Option<u64>,
    limit: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowParams {
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
        Self::from_values(query.limit, query.offset)
    }

    fn from_values(limit: Option<u32>, offset: Option<u64>) -> Result<Self, Box<Response>> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE);
        let offset = offset.unwrap_or(0);
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

fn parse_time_range(from: Option<u64>, to: Option<u64>) -> Result<(u64, u64), Box<Response>> {
    let to = to.unwrap_or_else(now_ms);
    let from = from.unwrap_or_else(|| to.saturating_sub(DAY_MS));
    if from >= to || to > u64::try_from(i64::MAX).expect("i64::MAX is nonnegative") {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "from must be less than to and both timestamps must fit signed 64-bit milliseconds",
        )));
    }
    Ok((from, to))
}

fn summary_query(from: u64, to: u64, page: Page) -> SummaryQuery {
    SummaryQuery {
        from,
        to,
        resolution: resolution_for_range(from, to),
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
        limit: page.limit,
        offset: page.offset,
    }
}

fn traffic_query(from: u64, to: u64) -> AnalyticsTrafficQuery {
    AnalyticsTrafficQuery {
        from,
        to,
        resolution: resolution_for_range(from, to),
        gateway_id: None,
        scope: None,
        direction: None,
        device_id: None,
        organization_id: None,
        application_id: None,
        category_id: None,
        protocol_id: None,
        domain: None,
        remote_ip: None,
    }
}

async fn overview(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(response) = Page::parse(query) {
        return *response;
    }
    let snapshot = state.realtime_snapshot();
    let inner = state.lock();
    let now = now_ms();
    let offline_after_ms = gateway_offline_after_ms();
    let gateway = match inner.storage.gateway_details() {
        Ok(gateway) => gateway,
        Err(error) => return storage_error(error),
    };
    let device_count = match inner.storage.device_count() {
        Ok(count) => count,
        Err(error) => return storage_error(error),
    };
    let analytics = match inner
        .storage
        .analytics()
        .overview(now.saturating_sub(DAY_MS), now)
    {
        Ok(analytics) => analytics,
        Err(error) => return storage_error(error),
    };
    let gateway_status = gateway.as_ref().map_or("unenrolled", |record| {
        if now.saturating_sub(record.last_seen) <= offline_after_ms {
            "online"
        } else {
            "offline"
        }
    });
    let capture_warning = capture_warning(gateway_status, snapshot.gateway_health.as_ref());
    let gateway = gateway.map(|gateway| {
        let health = snapshot.gateway_health.as_ref();
        json!({
            "id": gateway.id,
            "name": gateway.name,
            "status": gateway_status,
            "last_seen": gateway.last_seen,
            "agent_version": health.map_or(gateway.agent_version.as_str(), |v| v.agent_version.as_str()),
            "kernel_version": health.map_or(gateway.kernel_version.as_str(), |v| v.kernel_version.as_str()),
            "openwrt_version": health.map_or(gateway.openwrt_version.as_str(), |v| v.openwrt_version.as_str()),
            "offloading_status": health.map_or("unknown", |v| v.hardware_flow_offload.as_str()),
            "capture_interface": health.map_or("", |v| v.capture_interface.as_str()),
            "capture_interfaces": health.map_or_else(Vec::new, |v| v.capture_interfaces.clone()),
            "interface_counter_sanity": health.map_or("unknown", |v| v.interface_counter_sanity.as_str()),
            "interface_delta_bytes": health.map_or(0, |v| v.interface_delta_bytes),
            "flow_delta_bytes": health.map_or(0, |v| v.flow_delta_bytes),
            "capture_warning": capture_warning,
            "offline_after_ms": offline_after_ms,
        })
    });
    api_ok(json!({
        "gateway_status": gateway_status,
        "gateway": gateway,
        "realtime": snapshot,
        "last_24_hours": {"upload_bytes": analytics.upload_bytes, "download_bytes": analytics.download_bytes},
        "device_count": device_count,
        "application_count": analytics.application_count,
    }))
}

fn capture_warning(
    gateway_status: &str,
    health: Option<&crate::realtime::GatewayHealthSnapshot>,
) -> Option<String> {
    if gateway_status == "offline" {
        return Some("No gateway telemetry has arrived within the offline threshold".to_owned());
    }
    let Some(health) = health else {
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
    query: Result<Query<TrafficParams>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(page) => page,
        Err(response) => return *response,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(range) => range,
        Err(error) => return *error,
    };
    let group = query.group_by.as_deref().unwrap_or("none");
    let group = if group == "protocol" {
        "protocol_l7"
    } else {
        group
    };
    if !matches!(
        group,
        "none" | "client" | "application" | "category" | "protocol_l7" | "protocol_l4"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group_by",
            "group_by must be one of none, client, application, category, protocol_l7, or protocol_l4",
        );
    }
    let scope = match parse_scope(query.scope.as_deref().unwrap_or("internet")) {
        Ok(value) => value,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_scope", message),
    };
    let direction = match parse_direction(query.direction.as_deref().unwrap_or("both")) {
        Ok(value) => value,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_direction", message),
    };
    let inner = state.lock();
    let mut analytics_query = traffic_query(from, to);
    analytics_query.scope = scope;
    analytics_query.direction = direction;
    let points = match inner.storage.analytics().traffic_series(&analytics_query) {
        Ok(points) => points,
        Err(error) => return storage_error(error),
    };
    let duration = to.saturating_sub(from);
    let bucket_ms = duration.div_ceil(180).max(60_000).div_ceil(60_000) * 60_000;
    let mut buckets = BTreeMap::<u64, [u64; 4]>::new();
    for point in points {
        let bucket = point.timestamp / bucket_ms * bucket_ms;
        let totals = buckets.entry(bucket).or_default();
        totals[0] = totals[0].saturating_add(point.upload_bytes);
        totals[1] = totals[1].saturating_add(point.download_bytes);
        totals[2] = totals[2].saturating_add(point.packets);
        totals[3] = totals[3].saturating_add(point.flow_count);
    }
    let points = buckets.into_iter().map(|(timestamp, v)| json!({
        "timestamp": timestamp, "upload_bytes": v[0], "download_bytes": v[1], "packets": v[2], "flow_count": v[3]
    })).collect::<Vec<_>>();
    let breakdown = match traffic_breakdown(&inner, group, page, analytics_query, &points) {
        Ok(breakdown) => breakdown,
        Err(error) => return *error,
    };
    api_ok(json!({
        "from":from,"to":to,"bucket_ms":bucket_ms,"group_by":group,
        "scope":scope_name(scope),"direction":direction_name(direction),"points":points,"breakdown":breakdown
    }))
}

fn traffic_breakdown(
    inner: &crate::CollectorInner,
    group: &str,
    page: Page,
    analytics_query: AnalyticsTrafficQuery,
    points: &[Value],
) -> Result<Vec<Value>, Box<Response>> {
    if group == "none" {
        let totals = points.iter().fold([0_u64; 4], |mut acc, point| {
            for (index, key) in ["upload_bytes", "download_bytes", "packets", "flow_count"]
                .iter()
                .enumerate()
            {
                acc[index] = acc[index].saturating_add(point[*key].as_u64().unwrap_or(0));
            }
            acc
        });
        return Ok(vec![
            json!({"id":"total","name":"All traffic","upload_bytes":totals[0],"download_bytes":totals[1],"packets":totals[2],"flow_count":totals[3],"last_seen":null}),
        ]);
    }
    let dimension = match group {
        "client" => TrafficDimension::Device,
        "application" => TrafficDimension::Application,
        "category" => TrafficDimension::Category,
        "protocol_l4" => TrafficDimension::TransportProtocol,
        _ => TrafficDimension::Protocol,
    };
    let rows = inner
        .storage
        .analytics()
        .traffic_breakdown(&TrafficBreakdownQuery {
            traffic: analytics_query,
            dimension,
            limit: page.limit,
            offset: page.offset,
        })
        .map_err(|error| Box::new(storage_error(error)))?;
    Ok(rows
        .iter()
        .map(|row| traffic_breakdown_item(inner, group, row))
        .collect())
}

fn traffic_breakdown_item(
    inner: &crate::CollectorInner,
    group: &str,
    row: &netqmon_storage::analytics::TrafficBreakdown,
) -> Value {
    let mut item = json!({"id":row.key,"name":row.key,"upload_bytes":row.upload_bytes,"download_bytes":row.download_bytes,"packets":row.packets,"flow_count":row.flow_count,"last_seen":row.last_seen_at});
    if group == "client" {
        if let Ok(id) = row.key.parse::<i64>() {
            if let Ok(Some(device)) = inner.storage.device(id) {
                item["id"] = json!(device.id.to_string());
                item["name"] = json!(display_name(&device));
                item["mac"] = json!(format_mac(&device.mac));
            }
        }
    } else if group == "application" {
        let metadata = inner.classifier.application_metadata(&row.key);
        item["name"] = json!(metadata.as_ref().map(|m| m.name.clone()));
        item["icon"] = icon_json(metadata);
    } else if group == "protocol_l4" {
        let (id, name) = transport_protocol_name(&row.key);
        item["id"] = json!(id);
        item["name"] = json!(name);
    }
    item
}

fn parse_scope(value: &str) -> Result<Option<u8>, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "internet" => Ok(Some(netqmon_protocol::v1::FlowScope::Internet as u8)),
        "internal" => Ok(Some(netqmon_protocol::v1::FlowScope::Internal as u8)),
        "tunnel" => Ok(Some(netqmon_protocol::v1::FlowScope::Tunnel as u8)),
        _ => Err("scope must be one of internet, internal, tunnel, or all"),
    }
}

fn parse_direction(value: &str) -> Result<Option<u8>, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "both" => Ok(None),
        "upload" => Ok(Some(netqmon_protocol::v1::Direction::Upload as u8)),
        "download" => Ok(Some(netqmon_protocol::v1::Direction::Download as u8)),
        _ => Err("direction must be one of both, upload, or download"),
    }
}

fn scope_name(value: Option<u8>) -> &'static str {
    match value.and_then(|v| netqmon_protocol::v1::FlowScope::try_from(i32::from(v)).ok()) {
        Some(netqmon_protocol::v1::FlowScope::Internet) => "internet",
        Some(netqmon_protocol::v1::FlowScope::Internal) => "internal",
        Some(netqmon_protocol::v1::FlowScope::Tunnel) => "tunnel",
        _ => "all",
    }
}

fn direction_name(value: Option<u8>) -> &'static str {
    match value.and_then(|v| netqmon_protocol::v1::Direction::try_from(i32::from(v)).ok()) {
        Some(netqmon_protocol::v1::Direction::Upload) => "upload",
        Some(netqmon_protocol::v1::Direction::Download) => "download",
        _ => "both",
    }
}

fn transport_protocol_name(value: &str) -> (String, String) {
    let n = value.parse::<u8>().unwrap_or(0);
    match n {
        6 => ("tcp".to_owned(), "TCP".to_owned()),
        17 => ("udp".to_owned(), "UDP".to_owned()),
        1 => ("icmp".to_owned(), "ICMP".to_owned()),
        58 => ("icmpv6".to_owned(), "ICMPv6".to_owned()),
        other => (other.to_string(), format!("IP {other}")),
    }
}

async fn clients(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    let (rows, total) = match inner.storage.devices(u32::MAX, 0) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let analytics = summary_query(
        0,
        now_ms(),
        Page {
            limit: u32::MAX,
            offset: 0,
        },
    );
    let traffic_map: HashMap<u64, AnalyticsSummary> = inner
        .storage
        .analytics()
        .client_traffic(&analytics)
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.device_id, s))
        .collect();

    let mut device_entries = rows
        .into_iter()
        .map(|device| {
            let dev_id = positive_id_as_u64(device.id);
            let traffic = traffic_map.get(&dev_id).cloned();
            (device, traffic)
        })
        .collect::<Vec<_>>();

    device_entries.sort_by(|(a_dev, a_traf), (b_dev, b_traf)| {
        let a_bytes = a_traf
            .as_ref()
            .map_or(0, |t| t.upload_bytes.saturating_add(t.download_bytes));
        let b_bytes = b_traf
            .as_ref()
            .map_or(0, |t| t.upload_bytes.saturating_add(t.download_bytes));
        b_bytes
            .cmp(&a_bytes)
            .then_with(|| b_dev.last_seen.cmp(&a_dev.last_seen))
            .then_with(|| a_dev.id.cmp(&b_dev.id))
    });

    let offset = usize::try_from(page.offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(page.limit).unwrap_or(usize::MAX);
    let paged = device_entries.into_iter().skip(offset).take(limit);

    let mut items = Vec::new();
    for (device, traffic) in paged {
        let evidence = match inner
            .storage
            .device_evidence(&device.gateway_id, &device.mac)
        {
            Ok(rows) => rows,
            Err(error) => return storage_error(error),
        };
        let addresses = match inner.storage.device_addresses(device.id) {
            Ok(rows) => rows,
            Err(error) => return storage_error(error),
        };
        items.push(device_json(
            &device,
            traffic.as_ref(),
            &evidence,
            &addresses,
        ));
    }
    page_ok(items, page, total)
}

async fn client_detail(
    State(state): State<CollectorState>,
    Path(id): Path<String>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(response) = Page::parse(query) {
        return *response;
    }
    let id = match parse_positive_id(&id, "invalid_client_id") {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let inner = state.lock();
    let device = match inner.storage.device(id) {
        Ok(Some(value)) => value,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "not_found", "client was not found"),
        Err(e) => return storage_error(e),
    };
    let evidence = match inner
        .storage
        .device_evidence(&device.gateway_id, &device.mac)
    {
        Ok(rows) => rows,
        Err(error) => return storage_error(error),
    };
    let addresses = match inner.storage.device_addresses(id) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let mut q = summary_query(
        0,
        now_ms(),
        Page {
            limit: 200,
            offset: 0,
        },
    );
    q.device_id = Some(positive_id_as_u64(id));
    let apps = inner
        .storage
        .analytics()
        .application_summary(&q)
        .unwrap_or_default();
    let domains = inner
        .storage
        .analytics()
        .domain_summary(&q)
        .unwrap_or_default();
    let destinations = inner
        .storage
        .analytics()
        .destination_summary(&q)
        .unwrap_or_default();
    let traffic = inner
        .storage
        .analytics()
        .client_traffic(&q)
        .ok()
        .and_then(|mut rows| rows.pop());
    let address_rows = addresses
        .iter()
        .map(device_address_json)
        .collect::<Vec<_>>();
    let mut client = device_json(&device, traffic.as_ref(), &evidence, &addresses);
    client["applications"] = json!(
        apps.into_iter()
            .map(|row| summary_item(&row, "application", &inner.classifier))
            .collect::<Vec<_>>()
    );
    client["domains"] = json!(
        domains
            .into_iter()
            .map(|row| summary_item(&row, "domain", &inner.classifier))
            .collect::<Vec<_>>()
    );
    client["destinations"] = json!(
        destinations
            .into_iter()
            .map(|row| summary_item(&row, "destination", &inner.classifier))
            .collect::<Vec<_>>()
    );
    api_ok(json!({"client":client,"addresses":address_rows}))
}

async fn client_related(
    State(state): State<CollectorState>,
    Path((id, relation)): Path<(String, String)>,
    query: Result<Query<TimePageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let id = match parse_positive_id(&id, "invalid_client_id") {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    match relation.as_str() {
        "traffic" => {
            let mut q = traffic_query(from, to);
            q.device_id = Some(positive_id_as_u64(id));
            q.scope = Some(netqmon_protocol::v1::FlowScope::Internet as u8);
            match inner.storage.analytics().traffic_series(&q) {
                Ok(rows) => api_ok(
                    json!({"bucket_ms":60_000,"points":rows.into_iter().map(|r|json!({"timestamp":r.timestamp,"upload_bytes":r.upload_bytes,"download_bytes":r.download_bytes,"packets":r.packets,"flow_count":r.flow_count})).collect::<Vec<_>>()}),
                ),
                Err(e) => storage_error(e),
            }
        }
        "applications" | "domains" | "destinations" => {
            let mut q = summary_query(from, to, page);
            q.device_id = Some(positive_id_as_u64(id));
            q.scope = Some(netqmon_protocol::v1::FlowScope::Internet as u8);
            q.category_id.clone_from(&query.category);
            let result = match relation.as_str() {
                "applications" => inner.storage.analytics().application_summary(&q),
                "domains" => inner.storage.analytics().domain_summary(&q),
                _ => inner.storage.analytics().destination_summary(&q),
            };
            match result {
                Ok(rows) => page_ok(
                    rows.iter()
                        .map(|r| summary_item(r, relation.trim_end_matches('s'), &inner.classifier))
                        .collect(),
                    page,
                    rows.len() as u64,
                ),
                Err(e) => storage_error(e),
            }
        }
        "flows" => {
            let q = AnalyticsFlowQuery {
                from,
                to,
                device_id: Some(positive_id_as_u64(id)),
                limit: page.limit,
                offset: page.offset,
                ..AnalyticsFlowQuery::default()
            };
            match inner.storage.analytics().flows(&q) {
                Ok(rows) => page_ok(
                    rows.rows
                        .iter()
                        .map(|flow| flow_json(flow, &inner))
                        .collect(),
                    page,
                    rows.total,
                ),
                Err(e) => storage_error(e),
            }
        }
        _ => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "client relation was not found",
        ),
    }
}

async fn applications(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_query", &error.body_text());
        }
    };
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    let q = summary_query(from, to, page);
    match inner.storage.analytics().application_summary(&q) {
        Ok(rows) => page_ok(
            rows.iter()
                .map(|r| summary_item(r, "application", &inner.classifier))
                .collect(),
            page,
            rows.len() as u64,
        ),
        Err(e) => storage_error(e),
    }
}

async fn organizations(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    match inner
        .storage
        .analytics()
        .organization_summary(&summary_query(0, now_ms(), page))
    {
        Ok(rows) => page_ok(
            rows.iter()
                .map(|r| summary_item(r, "organization", &inner.classifier))
                .collect(),
            page,
            rows.len() as u64,
        ),
        Err(e) => storage_error(e),
    }
}

async fn protocols(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    match inner
        .storage
        .analytics()
        .protocol_summary(&summary_query(0, now_ms(), page))
    {
        Ok(rows) => page_ok(
            rows.iter()
                .map(|r| summary_item(r, "protocol", &inner.classifier))
                .collect(),
            page,
            rows.len() as u64,
        ),
        Err(e) => storage_error(e),
    }
}

async fn application_detail(
    State(state): State<CollectorState>,
    Path(id): Path<String>,
    query: Result<Query<TimePageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    if !valid_entity_id(&id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_application_id",
            "application id contains unsupported characters",
        );
    }
    let normalized_category = match query.category.as_deref() {
        Some("undefined") | Some("null") | Some("") => None,
        other => other,
    };
    if normalized_category.is_some_and(|value| !valid_entity_id(value)) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_category_id",
            "category id contains unsupported characters",
        );
    }
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    let mut q = summary_query(from, to, page);
    q.application_id = Some(id.clone());
    q.category_id = normalized_category.map(str::to_owned);
    let summary = match inner.storage.analytics().application_summary(&q) {
        Ok(mut rows) => rows.pop(),
        Err(e) => return storage_error(e),
    };
    let summary = summary.unwrap_or_else(|| AnalyticsSummary {
        key: id.clone(),
        application_id: Some(id.clone()),
        category_id: normalized_category.map(str::to_owned),
        ..AnalyticsSummary::default()
    });
    let mut protocol_query = q.clone();
    protocol_query.limit = 200;
    protocol_query.offset = 0;
    let protocol_count = inner
        .storage
        .analytics()
        .protocol_summary(&protocol_query)
        .map_or(0, |v| v.len());
    let client_count = summary.distinct_devices;
    let domain_count = inner
        .storage
        .analytics()
        .domain_summary(&protocol_query)
        .map_or(0, |v| v.len());
    let category_id_display = summary
        .category_id
        .or_else(|| normalized_category.map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    api_ok(
        json!({"application_id":id,"category_id":category_id_display,"upload_bytes":summary.upload_bytes,"download_bytes":summary.download_bytes,"packets":summary.packets,"flow_count":summary.flow_count,"last_seen":summary.last_seen_at,"protocol_count":protocol_count,"client_count":client_count,"domain_count":domain_count}),
    )
}

async fn application_related(
    State(state): State<CollectorState>,
    Path((id, relation)): Path<(String, String)>,
    query: Result<Query<TimePageQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let normalized_category = match query.category.as_deref() {
        Some("undefined") | Some("null") | Some("") => None,
        other => other.map(str::to_owned),
    };
    let inner = state.lock();
    let mut q = summary_query(from, to, page);
    q.application_id = Some(id.clone());
    q.category_id = normalized_category.clone();
    q.scope = Some(netqmon_protocol::v1::FlowScope::Internet as u8);
    match relation.as_str() {
        "traffic" => {
            let mut t = traffic_query(from, to);
            t.application_id = Some(id);
            t.category_id = normalized_category;
            t.scope = q.scope;
            match inner.storage.analytics().traffic_series(&t) {
                Ok(rows) => api_ok(
                    json!({"bucket_ms":60_000,"points":rows.into_iter().map(|r|json!({"timestamp":r.timestamp,"upload_bytes":r.upload_bytes,"download_bytes":r.download_bytes,"packets":r.packets,"flow_count":r.flow_count})).collect::<Vec<_>>()}),
                ),
                Err(e) => storage_error(e),
            }
        }
        "clients" | "domains" | "destinations" => {
            let result = match relation.as_str() {
                "clients" => inner.storage.analytics().client_traffic(&q),
                "domains" => inner.storage.analytics().domain_summary(&q),
                _ => inner.storage.analytics().destination_summary(&q),
            };
            match result {
                Ok(rows) => page_ok(
                    rows.iter()
                        .map(|r| summary_item(r, relation.trim_end_matches('s'), &inner.classifier))
                        .collect(),
                    page,
                    rows.len() as u64,
                ),
                Err(e) => storage_error(e),
            }
        }
        "flows" => {
            let fq = AnalyticsFlowQuery {
                from,
                to,
                application_id: Some(id),
                ..AnalyticsFlowQuery::default()
            };
            match inner.storage.analytics().flows(&fq) {
                Ok(rows) => page_ok(
                    rows.rows
                        .iter()
                        .map(|flow| flow_json(flow, &inner))
                        .collect(),
                    page,
                    rows.total,
                ),
                Err(e) => storage_error(e),
            }
        }
        _ => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "application relation was not found",
        ),
    }
}

async fn domains(
    State(state): State<CollectorState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let page = match Page::parse(query) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    match inner
        .storage
        .analytics()
        .domain_summary(&summary_query(0, now_ms(), page))
    {
        Ok(rows) => page_ok(
            rows.iter()
                .map(|r| summary_item(r, "domain", &inner.classifier))
                .collect(),
            page,
            rows.len() as u64,
        ),
        Err(e) => storage_error(e),
    }
}

async fn destinations(
    State(state): State<CollectorState>,
    query: Result<Query<DestinationParams>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let page = match Page::from_values(query.limit, query.offset) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    let mut q = summary_query(from, to, page);
    q.scope = Some(netqmon_protocol::v1::FlowScope::Internet as u8);
    let rows = match inner.storage.analytics().destination_summary(&q) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let items = rows
        .iter()
        .map(|row| {
            destination_json(
                row,
                &inner.geo_provider,
                &inner.classifier,
                query.lang.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    page_ok(items, page, rows.len() as u64)
}

fn destination_json(
    row: &AnalyticsSummary,
    geo: &Arc<dyn GeoProvider>,
    classifier: &crate::classifier::ClassifierHandle,
    lang: Option<&str>,
) -> Value {
    let ip = netqmon_storage::from_hex(&row.key).unwrap_or_default();
    let address = format_ip(&ip);
    let record = address
        .parse::<IpAddr>()
        .ok()
        .and_then(|ip| geo.lookup_with_lang(ip, lang).ok().flatten())
        .unwrap_or_default();
    let app = row
        .application_id
        .as_deref()
        .filter(|id| *id != "unknown")
        .and_then(|id| classifier.application_metadata(id));
    json!({"remote_ip":address,"upload_bytes":row.upload_bytes,"download_bytes":row.download_bytes,"packets":row.packets,"flow_count":row.flow_count,"last_seen":row.last_seen_at,"domain":row.last_domain,"client_count":row.distinct_devices,"application":row.application_id,"application_name":app.as_ref().map(|v|v.name.clone()),"country_code":record.country_code,"country_name":record.country_name,"region":record.region,"city":record.city,"latitude":record.latitude,"longitude":record.longitude,"asn":record.asn,"organization":record.organization})
}

async fn geo_summary(
    State(state): State<CollectorState>,
    query: Result<Query<GeoParams>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let (from, to) = match parse_time_range(query.from, query.to) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let inner = state.lock();
    if !inner.geo_provider.is_enabled() {
        return api_ok(
            json!({"enabled":false,"top_countries":[],"top_asns":[],"country_distribution":[]}),
        );
    }
    let mut q = summary_query(
        from,
        to,
        Page {
            limit: u32::MAX,
            offset: 0,
        },
    );
    let traffic = match inner.storage.analytics().geo_traffic(&q) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let mut countries = BTreeMap::<String, (String, u64)>::new();
    let mut asns = BTreeMap::<String, (String, u64)>::new();
    let mut total = 0_u64;
    for row in traffic {
        let ip = format_ip(&row.remote_ip);
        let Some(record) = ip.parse::<IpAddr>().ok().and_then(|ip| {
            inner
                .geo_provider
                .lookup_with_lang(ip, query.lang.as_deref())
                .ok()
                .flatten()
        }) else {
            continue;
        };
        let bytes = row.upload_bytes.saturating_add(row.download_bytes);
        total = total.saturating_add(bytes);
        if let (Some(code), Some(name)) = (record.country_code, record.country_name) {
            let entry = countries.entry(code).or_insert((name, 0));
            entry.1 = entry.1.saturating_add(bytes);
        }
        if let (Some(asn), Some(org)) = (record.asn, record.organization) {
            let entry = asns.entry(asn.to_string()).or_insert((org, 0));
            entry.1 = entry.1.saturating_add(bytes);
        }
    }
    let mut country_rows = countries.into_iter().collect::<Vec<_>>();
    country_rows.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
    let top_countries = country_rows
        .iter()
        .map(|(code, (name, bytes))| json!({"country_code":code,"country_name":name,"bytes":bytes}))
        .collect::<Vec<_>>();
    let mut asn_rows = asns.into_iter().collect::<Vec<_>>();
    asn_rows.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
    let top_asns = asn_rows
        .iter()
        .map(|(asn, (org, bytes))| {
            json!({"asn":asn.parse::<u64>().unwrap_or(0),"organization":org,"bytes":bytes})
        })
        .collect::<Vec<_>>();
    let mut distribution = top_countries.clone();
    distribution.sort_by(|a, b| b["bytes"].as_u64().cmp(&a["bytes"].as_u64()));
    let _ = &mut q;
    api_ok(
        json!({"enabled":true,"top_countries":top_countries,"top_asns":top_asns,"country_distribution":distribution,"total_bytes":total}),
    )
}

async fn insights(
    State(state): State<CollectorState>,
    query: Result<Query<InsightParams>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let to = query.to.unwrap_or_else(now_ms);
    let from = query
        .from
        .unwrap_or_else(|| to.saturating_sub(DEFAULT_INSIGHT_WINDOW_MS));
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if from >= to || to.saturating_sub(from) > MAX_INSIGHT_WINDOW_MS {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "insight range must be ordered and no longer than 30 days",
        );
    }
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 200",
        );
    }
    let snapshot = state.realtime_snapshot();
    let inner = state.lock();
    let analytics = inner.storage.analytics();
    match crate::insights::detect_from_analytics(
        &*analytics,
        inner.storage.metadata(),
        &snapshot,
        crate::insights::InsightWindow { from, to, limit },
        crate::insights::collector_lag_threshold_ms(),
        crate::insights::high_upload_threshold_bytes(),
    ) {
        Ok(items) => api_ok(json!(items)),
        Err(e) => storage_error(e),
    }
}

async fn flows(
    State(state): State<CollectorState>,
    query: Result<Query<FlowParams>, QueryRejection>,
) -> Response {
    let Query(params) = match query {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let (q, limit, sort) = match build_flow_query(&params, &state.lock()) {
        Ok(values) => values,
        Err(error) => return *error,
    };
    let inner = state.lock();
    let result = match inner.storage.analytics().flows(&q) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let has_more = result.rows.len() > usize::try_from(limit).unwrap_or(usize::MAX)
        || result.total > u64::from(limit);
    let rows = result
        .rows
        .into_iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| {
            rows.last()
                .map(|row| format!("{}|{}", flow_sort_value(row, sort), row.flow_id))
        })
        .flatten();
    let items = rows
        .iter()
        .map(|row| flow_json(row, &inner))
        .collect::<Vec<_>>();
    Json(json!({"schema_version":SCHEMA_VERSION,"data":items,"pagination":{"limit":limit,"next_cursor":next_cursor}})).into_response()
}

struct FlowRequest {
    from: u64,
    to: u64,
    limit: u32,
    sort: FlowSort,
    descending: bool,
    cursor: Option<(i64, String)>,
}

struct FlowDeviceFilters {
    device_ids: Vec<u64>,
    search_ip: Option<Vec<u8>>,
}

fn build_flow_query(
    params: &FlowParams,
    inner: &crate::CollectorInner,
) -> Result<(AnalyticsFlowQuery, u32, FlowSort), Box<Response>> {
    let request = parse_flow_request(params)?;
    let FlowDeviceFilters {
        device_ids,
        search_ip,
    } = resolve_flow_device_filters(params, inner)?;
    let client_ip = params
        .client
        .as_deref()
        .and_then(|v| v.parse::<IpAddr>().ok())
        .map(ip_bytes);
    let remote_ip = params
        .ip
        .as_deref()
        .map(|raw| raw.parse::<IpAddr>().map(ip_bytes))
        .transpose()
        .map_err(|_| {
            Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_ip",
                "ip must be a valid IPv4 or IPv6 address",
            ))
        })?;
    let transport = parse_flow_filter(
        params.protocol.as_deref(),
        parse_transport_protocol,
        "invalid_protocol",
        "protocol must be tcp, udp, or an IP protocol number",
    )?;
    let direction = parse_flow_filter(
        params.direction.as_deref(),
        parse_flow_direction,
        "invalid_direction",
        "direction must be upload, download, or unknown",
    )?;
    let scope = parse_flow_filter(
        params.scope.as_deref(),
        parse_flow_scope,
        "invalid_scope",
        "scope must be internet, internal, tunnel, or unknown",
    )?;
    let path_type = parse_flow_filter(
        params.path_type.as_deref(),
        parse_path_type,
        "invalid_path_type",
        "path_type must be forwarded, internal, tunnel, or unknown",
    )?;
    let nat = parse_flow_filter(
        params.nat.as_deref(),
        parse_nat,
        "invalid_nat",
        "nat must be none, snat, dnat, both, or unknown",
    )?;
    let search_resolved = search_ip.is_some() || !device_ids.is_empty();
    Ok((
        AnalyticsFlowQuery {
            from: request.from,
            to: request.to,
            gateway_id: None,
            device_id: if device_ids.len() == 1 {
                Some(device_ids[0])
            } else {
                None
            },
            application_id: params.application.clone(),
            organization_id: params.organization.clone(),
            protocol_id: params.detected_protocol.clone(),
            domain: params.domain.clone(),
            client_ip,
            remote_ip,
            any_ip: search_ip,
            transport_protocol: transport,
            port: params.port,
            direction,
            scope,
            path_type,
            nat,
            search: (!search_resolved).then(|| params.search.clone()).flatten(),
            sort_by: request.sort,
            descending: request.descending,
            after_sort_value: request.cursor.as_ref().map(|cursor| cursor.0),
            after_flow_id: request.cursor.as_ref().map(|cursor| cursor.1.clone()),
            limit: request.limit.saturating_add(1),
            offset: 0,
        },
        request.limit,
        request.sort,
    ))
}

fn parse_flow_request(params: &FlowParams) -> Result<FlowRequest, Box<Response>> {
    let limit = params.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 200",
        )));
    }
    let to = params.to.unwrap_or_else(now_ms);
    let from = params.from.unwrap_or_else(|| to.saturating_sub(DAY_MS));
    if from >= to || to > u64::try_from(i64::MAX).expect("i64::MAX is nonnegative") {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_time_range",
            "from must be less than to",
        )));
    }
    let sort = match params.sort.as_deref().unwrap_or("last_seen") {
        "last_seen" => FlowSort::LastSeen,
        "started" => FlowSort::Started,
        "download" => FlowSort::DownloadBytes,
        "upload" => FlowSort::UploadBytes,
        "duration" => FlowSort::Duration,
        _ => {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_sort",
                "sort must be one of last_seen, started, download, upload, or duration",
            )));
        }
    };
    let descending = match params.order.as_deref().unwrap_or("desc") {
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
    let cursor = match params.cursor.as_deref().map(parse_flow_cursor).transpose() {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                e,
            )));
        }
    };
    Ok(FlowRequest {
        from,
        to,
        limit,
        sort,
        descending,
        cursor,
    })
}

fn resolve_flow_device_filters(
    params: &FlowParams,
    inner: &crate::CollectorInner,
) -> Result<FlowDeviceFilters, Box<Response>> {
    let mut device_ids = Vec::new();
    if let Some(client) = non_empty_trimmed(params.client.as_deref()) {
        if let Ok(id) = client.parse::<u64>() {
            device_ids.push(id);
        } else if client.parse::<IpAddr>().is_err() {
            device_ids = find_device_ids(inner, client)?;
        }
    }
    let search_ip = non_empty_trimmed(params.search.as_deref())
        .and_then(|search| search.parse::<IpAddr>().ok().map(ip_bytes));
    if search_ip.is_none() && device_ids.is_empty() {
        if let Some(search) = non_empty_trimmed(params.search.as_deref()) {
            device_ids = find_device_ids(inner, search)?;
        }
    }
    Ok(FlowDeviceFilters {
        device_ids,
        search_ip,
    })
}

fn find_device_ids(inner: &crate::CollectorInner, search: &str) -> Result<Vec<u64>, Box<Response>> {
    let devices = inner
        .storage
        .devices(10_000, 0)
        .map_err(|error| Box::new(storage_error(error)))?
        .0;
    let search_lower = search.to_lowercase();
    let mac_search = search_lower.replace([':', '-'], "");
    Ok(devices
        .iter()
        .filter(|device| {
            display_name(device).to_lowercase().contains(&search_lower)
                || format_mac(&device.mac).to_lowercase().contains(&mac_search)
        })
        .filter_map(|device| u64::try_from(device.id).ok())
        .collect())
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn parse_flow_filter(
    value: Option<&str>,
    parser: fn(&str) -> Result<u8, ()>,
    code: &str,
    message: &str,
) -> Result<Option<u8>, Box<Response>> {
    value
        .map(parser)
        .transpose()
        .map_err(|()| Box::new(api_error(StatusCode::BAD_REQUEST, code, message)))
}

fn parse_flow_cursor(value: &str) -> Result<(i64, String), &'static str> {
    let Some((sort, id)) = value.split_once('|') else {
        return Err("cursor is malformed");
    };
    let sort = sort.parse().map_err(|_| "cursor is malformed")?;
    if id.is_empty() {
        return Err("cursor is malformed");
    }
    Ok((sort, id.to_owned()))
}
fn flow_sort_value(flow: &AnalyticsFlow, sort: FlowSort) -> i64 {
    let value = match sort {
        FlowSort::LastSeen => flow.last_seen_at,
        FlowSort::Started => flow.started_at,
        FlowSort::UploadBytes => flow.upload_bytes,
        FlowSort::DownloadBytes => flow.download_bytes,
        FlowSort::TotalBytes => flow.upload_bytes.saturating_add(flow.download_bytes),
        FlowSort::Duration => flow
            .ended_at
            .unwrap_or(flow.last_seen_at)
            .saturating_sub(flow.started_at),
    };
    i64::try_from(value).unwrap_or(i64::MAX)
}
fn parse_transport_protocol(value: &str) -> Result<u8, ()> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        value => value.parse().map_err(|_| ()),
    }
}
fn parse_flow_direction(value: &str) -> Result<u8, ()> {
    match value.to_ascii_lowercase().as_str() {
        "unknown" => Ok(0),
        "upload" => Ok(1),
        "download" => Ok(2),
        _ => Err(()),
    }
}
fn parse_flow_scope(value: &str) -> Result<u8, ()> {
    match value.to_ascii_lowercase().as_str() {
        "internet" => Ok(1),
        "internal" => Ok(2),
        "tunnel" => Ok(3),
        "unknown" => Ok(0),
        _ => Err(()),
    }
}
fn parse_path_type(value: &str) -> Result<u8, ()> {
    match value.to_ascii_lowercase().as_str() {
        "forwarded" => Ok(1),
        "internal" => Ok(2),
        "tunnel" => Ok(3),
        "unknown" => Ok(0),
        _ => Err(()),
    }
}
fn parse_nat(value: &str) -> Result<u8, ()> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(1),
        "snat" => Ok(2),
        "dnat" => Ok(3),
        "both" => Ok(4),
        "unknown" => Ok(0),
        _ => Err(()),
    }
}

fn flow_json(flow: &AnalyticsFlow, inner: &crate::CollectorInner) -> Value {
    let device = i64::try_from(flow.device_id)
        .ok()
        .and_then(|id| inner.storage.device(id).ok().flatten());
    let app = inner.classifier.application_metadata(&flow.application_id);
    json!({"id":flow.flow_id,"client_ip":format_ip(&flow.client_ip),"client_port":flow.client_port,"remote_ip":format_ip(&flow.remote_ip),"remote_port":flow.remote_port,"protocol":flow.protocol,"direction":flow_direction_name(flow.direction),"domain":non_empty(&flow.domain),"organization":flow.organization_id,"application":flow.application_id,"application_name":app.as_ref().map(|m|m.name.clone()),"category":flow.category_id,"traffic_role":flow.traffic_role,"protocol_id":flow.protocol_id,"organization_confidence":flow.organization_confidence,"application_confidence":flow.application_confidence,"protocol_confidence":flow.protocol_confidence,"confidence":flow.classification_confidence,"reason":flow.classification_reason,"evidence":flow.classification_evidence_json,"upload_bytes":flow.upload_bytes,"download_bytes":flow.download_bytes,"packets":flow.packets,"started_at":flow.started_at,"last_seen":flow.last_seen_at,"ended_at":flow.ended_at,"client_id":(flow.device_id>0).then_some(flow.device_id),"client_name":device.as_ref().map(display_name).unwrap_or_default(),"client_mac":device.as_ref().map(|d|format_mac(&d.mac)),"scope":scope_numeric_name(flow.scope),"path_type":path_numeric_name(flow.path_type),"nat":nat_numeric_name(flow.nat),"source_segment":flow.source_segment,"destination_segment":flow.destination_segment})
}
fn flow_direction_name(value: u8) -> &'static str {
    match value {
        1 => "upload",
        2 => "download",
        _ => "unknown",
    }
}
fn scope_numeric_name(value: u8) -> &'static str {
    match value {
        1 => "internet",
        2 => "internal",
        3 => "tunnel",
        _ => "unknown",
    }
}
fn path_numeric_name(value: u8) -> &'static str {
    match value {
        1 => "forwarded",
        2 => "internal",
        3 => "tunnel",
        _ => "unknown",
    }
}
fn nat_numeric_name(value: u8) -> &'static str {
    match value {
        1 => "none",
        2 => "snat",
        3 => "dnat",
        4 => "both",
        _ => "unknown",
    }
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
        Err(e) => api_error(StatusCode::BAD_GATEWAY, "license_activation_failed", &e),
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
        Err(e) => api_error(StatusCode::BAD_GATEWAY, "license_check_failed", &e),
    }
}

async fn get_retention(State(state): State<CollectorState>) -> Response {
    let inner = state.lock();
    match inner.storage.load_retention_policy() {
        Ok(p) => api_ok(retention_json(p)),
        Err(e) => storage_error(e),
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
        Ok(v) => v,
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
    let p = netqmon_storage::RetentionPolicy {
        flow_sessions_days: update.flow_sessions_days,
        dns_days: update.dns_days,
        minute_days: update.minute_days,
        hour_days: update.hour_days,
        day_days: update.day_days,
    };
    let mut inner = state.lock();
    match inner.storage.save_retention_policy(&p, now_ms()) {
        Ok(()) => api_ok(retention_json(p)),
        Err(e) => storage_error(e),
    }
}
fn retention_json(p: netqmon_storage::RetentionPolicy) -> Value {
    json!({"flow_sessions_days":p.flow_sessions_days,"dns_days":p.dns_days,"minute_days":p.minute_days,"hour_days":p.hour_days,"day_days":p.day_days})
}
async fn run_retention(State(state): State<CollectorState>) -> Response {
    let mut inner = state.lock();
    let p = match inner.storage.load_retention_policy() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    match inner.storage.run_retention(now_ms(), p) {
        Ok(()) => api_ok(json!({"status":"completed"})),
        Err(e) => storage_error(e),
    }
}
async fn reload_rules(State(state): State<CollectorState>) -> Response {
    let inner = state.lock();
    match inner.classifier.reload_rules() {
        Ok(reload_stats) => {
            let mut value = serde_json::to_value(&reload_stats).expect("stats serialize");
            value["reloaded_at"] = json!(now_ms());
            api_ok(value)
        }
        Err(e) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "classifier_unavailable",
            &e,
        ),
    }
}

async fn diagnostics(State(state): State<CollectorState>) -> Response {
    let topology = state
        .realtime_snapshot()
        .gateway_health
        .and_then(|health| health.topology);
    let inner = state.lock();
    let now = now_ms();
    let metadata_size = match inner.storage.metadata_database_size_bytes() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let analytics_size = match inner.storage.analytics_database_size_bytes() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let active = match inner.storage.active_flow_count() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let unknown = match inner.storage.unknown_ratio(now.saturating_sub(DAY_MS)) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let policy = match inner.storage.load_retention_policy() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let depth = match inner.storage.outbox_depth() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let age = match inner.storage.outbox_oldest_age_ms(now) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let gateway = match inner.storage.gateway_details() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    api_ok(
        json!({"collector_version":env!("CARGO_PKG_VERSION"),"analytics_backend":inner.storage.analytics_backend(),"metadata_database_size_bytes":metadata_size,"analytics_database_size_bytes":analytics_size,"analytics_outbox_depth":depth,"analytics_outbox_oldest_age_ms":age,"analytics_last_success_at":inner.analytics_last_success_at_ms,"analytics_last_error":inner.analytics_last_error,"analytics_batches_processed_total":inner.analytics_batches_processed_total,"analytics_rows_written_total":inner.analytics_rows_written_total,"analytics_last_write_duration_ms":inner.analytics_last_write_duration_ms,"analytics_last_rollup_duration_ms":inner.analytics_last_rollup_duration_ms,"analytics_last_rollup_rows":inner.analytics_last_rollup_rows,"analytics_worker_idle":inner.analytics_worker_idle,"duckdb_threads":std::env::var("NETQMON_DUCKDB_THREADS").ok().and_then(|value| value.parse::<u8>().ok()).unwrap_or(1),"active_flow_count":active,"unknown_ratio":unknown,"gateway":gateway,"retention":retention_json(policy),"geo_enabled":inner.geo_provider.is_enabled(),"classification":inner.classifier.diagnostics(),"classifier_manager":classifier_manager_status(),"sampling":state.sampling.diagnostics(),"recognition":crate::recognition_diagnostics::diagnostics(&inner,now.saturating_sub(DAY_MS)),"topology":topology}),
    )
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
fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status,Json(json!({"schema_version":SCHEMA_VERSION,"error":{"code":code,"message":message},"pagination":null}))).into_response()
}
fn storage_error<E: std::fmt::Display>(_error: E) -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage_error",
        "query could not be completed",
    )
}
fn icon_json(metadata: Option<crate::classifier::EntityMetadata>) -> Value {
    metadata.map_or(Value::Null, |m| json!(m.icon))
}
fn parse_positive_id(value: &str, code: &str) -> Result<i64, Box<Response>> {
    let Ok(id) = value.parse::<i64>() else {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            code,
            "client id must be an integer",
        )));
    };
    if id <= 0 {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            code,
            "client id must be positive",
        )));
    }
    Ok(id)
}
fn positive_id_as_u64(id: i64) -> u64 {
    u64::try_from(id).expect("device IDs are positive")
}
fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        return "unknown".to_owned();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn display_name(d: &netqmon_storage::metadata::DeviceRecord) -> String {
    d.display_name
        .clone()
        .or_else(|| d.hostname.clone())
        .unwrap_or_default()
}
fn device_json(
    d: &netqmon_storage::metadata::DeviceRecord,
    traffic: Option<&AnalyticsSummary>,
    evidence_rows: &[netqmon_storage::DeviceEvidenceRecord],
    addresses: &[netqmon_storage::metadata::DeviceAddressRecord],
) -> Value {
    let evidence = if evidence_rows.is_empty() {
        serde_json::from_str::<Value>(&d.identity_evidence_json).unwrap_or_else(|_| json!([]))
    } else {
        json!(evidence_rows.iter().map(|row| json!({
            "source":row.source,"field":row.field,"value":row.value,"confidence":row.confidence,
            "first_seen":row.first_seen,"last_seen":row.last_seen,"hit_count":row.hit_count,
            "metadata_json":row.metadata_json
        })).collect::<Vec<_>>())
    };
    let identity = json!({"vendor":d.vendor,"device_type":d.device_type,"os_family":d.os_family,"model":d.model,"confidence":d.identity_confidence,"vendor_confidence":d.vendor_confidence,"device_type_confidence":d.device_type_confidence,"os_confidence":d.os_confidence,"model_confidence":d.model_confidence,"private_mac":d.private_mac,"evidence":evidence});
    let latest_address = addresses.iter().max_by_key(|address| address.last_seen);
    let self_host_application = (addresses.len() == 1)
        .then(|| addresses.first())
        .flatten()
        .and_then(|address| {
            address.application_id.as_ref().map(|application_id| {
                json!({
                    "application_id":application_id,"confidence":address.application_confidence,
                    "source":address.application_source,"role":"server"
                })
            })
        });
    json!({"id":d.id,"mac":format_mac(&d.mac),"name":display_name(d),"hostname":d.hostname,"display_name":d.display_name,"vendor":d.vendor,"identity":identity,"first_seen":d.first_seen,"last_seen":d.last_seen,"upload_bytes":traffic.map_or(0,|t|t.upload_bytes),"download_bytes":traffic.map_or(0,|t|t.download_bytes),"flow_count":traffic.map_or(0,|t|t.flow_count),"ip":latest_address.map(|address|format_ip(&address.ip)),"address_count":addresses.len(),"self_host_application":self_host_application})
}
fn device_address_json(a: &netqmon_storage::metadata::DeviceAddressRecord) -> Value {
    json!({"ip":format_ip(&a.ip),"ip_version":a.ip_version,"first_seen":a.first_seen,"last_seen":a.last_seen,"application_id":a.application_id,"application_confidence":a.application_confidence,"application_source":a.application_source,"application_last_seen":a.application_last_seen,"self_host_source":a.self_host_source,"self_host_last_seen":a.self_host_last_seen,"role":if a.self_host_source.is_some(){"server"}else{"client"}})
}
fn summary_item(
    row: &AnalyticsSummary,
    kind: &str,
    classifier: &crate::classifier::ClassifierHandle,
) -> Value {
    let key = if kind == "destination" {
        netqmon_storage::from_hex(&row.key)
            .map_or_else(|_| row.key.clone(), |bytes| format_ip(&bytes))
    } else {
        row.key.clone()
    };
    let mut item = json!({"id":key,"name":key,"upload_bytes":row.upload_bytes,"download_bytes":row.download_bytes,"packets":row.packets,"flow_count":row.flow_count,"last_seen":row.last_seen_at,"client_count":row.distinct_devices,"device_id":row.device_id});
    if kind == "application" {
        item["application_id"] = json!(key);
        let metadata = classifier.application_metadata(&row.key);
        item["name"] = json!(
            metadata
                .as_ref()
                .map_or_else(|| row.key.clone(), |m| m.name.clone())
        );
        item["icon"] = icon_json(metadata);
        let category = row.category_id.as_deref().unwrap_or("unknown");
        item["category_id"] = json!(category);
        item["traffic_class"] = json!(category);
        let org_id = row.organization_id.as_deref().unwrap_or("unknown");
        item["organization_id"] = json!(org_id);
        if org_id != "unknown" {
            let org_meta = classifier.organization_metadata(org_id);
            item["organization_name"] = json!(org_meta.as_ref().map(|m| m.name.clone()));
        } else {
            item["organization_name"] = json!(null);
        }
    }
    if kind == "organization" {
        let org_id = if row.key.is_empty() {
            "unknown"
        } else {
            &row.key
        };
        item["organization_id"] = json!(org_id);
        if org_id != "unknown" {
            let org_meta = classifier.organization_metadata(org_id);
            item["name"] = json!(
                org_meta
                    .as_ref()
                    .map_or_else(|| org_id.to_owned(), |m| m.name.clone())
            );
        } else {
            item["name"] = json!("unknown");
        }
    } else if kind == "protocol" || kind == "domain" {
        item["name"] = json!(if row.key.is_empty() {
            "unknown"
        } else {
            &row.key
        });
    }
    item
}
fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}
fn valid_entity_id(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
fn gateway_offline_after_ms() -> u64 {
    std::env::var("NETQMON_GATEWAY_OFFLINE_AFTER_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_GATEWAY_OFFLINE_AFTER_MS)
}

async fn get_geo_settings(State(state): State<CollectorState>) -> Response {
    let (directory, enabled) = {
        let inner = state.lock();
        (inner.geo_directory.clone(), inner.geo_provider.is_enabled())
    };
    api_ok(json!(geo_updater::get_geo_status(&directory, enabled)))
}
#[derive(Clone, Debug, Default, Deserialize)]
struct GeoUpdateRequest {
    #[serde(rename = "city_url")]
    city: Option<String>,
    #[serde(rename = "country_url")]
    country: Option<String>,
    #[serde(rename = "asn_url")]
    asn: Option<String>,
}
async fn post_geo_update(
    State(state): State<CollectorState>,
    body: Option<Json<GeoUpdateRequest>>,
) -> Response {
    let directory = { state.lock().geo_directory.clone() };
    let payload = body.map(|b| b.0).unwrap_or_default();
    let update = tokio::task::spawn_blocking(move || {
        let city = payload
            .city
            .or(payload.country)
            .unwrap_or_else(|| geo_updater::DEFAULT_CITY_SOURCE.to_owned());
        let asn = payload
            .asn
            .unwrap_or_else(|| geo_updater::DEFAULT_ASN_SOURCE.to_owned());
        geo_updater::update_geo_databases_with_urls(&directory, &city, &asn)
    })
    .await;
    let (actual, files) = match update {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "geo_update_error", &e),
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "geo_update_error",
                &e.to_string(),
            );
        }
    };
    let (directory, enabled) = {
        let mut inner = state.lock();
        inner.geo_directory = actual;
        let load = netqmon_geo::LocalDbProvider::load(&inner.geo_directory);
        for warning in &load.warnings {
            tracing::warn!(warning, "geo reload warning");
        }
        inner.geo_provider = Arc::new(load.provider);
        (inner.geo_directory.clone(), inner.geo_provider.is_enabled())
    };
    api_ok(
        json!({"success":true,"message":"Geo databases updated and reloaded successfully","updated_files":files,"status":geo_updater::get_geo_status(&directory,enabled)}),
    )
}
