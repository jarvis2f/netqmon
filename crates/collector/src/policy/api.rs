use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use netqmon_storage::{ClickHouseStorage, Storage};
use rusqlite::params;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::CollectorState;

use super::evaluator::{PolicyPreviewRequest, evaluate_preview};
use super::model::{MAX_REQUEST_BYTES, PolicySpecV1};
use super::service::{MutationResult, PolicyFailure};
use super::validation::{KnownSelectors, ValidationIssue, normalize_and_validate};

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;

pub(crate) fn router() -> Router<CollectorState> {
    Router::new()
        .route("/internal/policies", get(list).post(create))
        .route(
            "/internal/policies/republish",
            axum::routing::post(republish),
        )
        .route("/internal/policies/options", get(options))
        .route("/internal/policies/preview", axum::routing::post(preview))
        .route("/internal/policies/validate", axum::routing::post(validate))
        .route("/internal/policies/deployment", get(deployment))
        .route(
            "/internal/policies/{id}",
            get(detail).put(update).delete(delete),
        )
        .route(
            "/internal/policies/{id}/enabled",
            axum::routing::patch(set_enabled),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
}

async fn preview(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    let mut request: PolicyPreviewRequest = match parse_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    request.gateway_id = request.gateway_id.trim().to_owned();
    let Some(client_mac) = super::validation::normalize_mac(&request.client_mac) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_preview",
            "client_mac must be a canonical six-byte MAC address",
            None,
        );
    };
    request.client_mac = client_mac;
    if request.gateway_id.is_empty()
        || request.gateway_id.len() > 128
        || request.application_id.is_empty()
        || request.application_id.len() > 128
        || request.category_id.is_empty()
        || request.category_id.len() > 128
        || request.application_id.chars().any(char::is_control)
        || request.category_id.chars().any(char::is_control)
        || !request.application_confidence.is_finite()
        || !(0.0..=1.0).contains(&request.application_confidence)
        || request.at_ms < 0
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_preview",
            "preview identity, confidence, or timestamp is invalid",
            None,
        );
    }
    match registered_gateway(&state, &request.gateway_id) {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "gateway was not found",
                None,
            );
        }
        Err(_) => return store_unavailable(),
    }
    let (_, policies) = match state.policy_service.snapshot(&request.gateway_id) {
        Ok(snapshot) => snapshot,
        Err(error) => return failure(error),
    };
    let deployment = match state.policy_service.deployment(&request.gateway_id) {
        Ok(deployment) => deployment,
        Err(error) => return failure(error),
    };
    let result = evaluate_preview(
        &request,
        &policies,
        matches!(
            deployment.capabilities.application_block.as_str(),
            "supported" | "degraded"
        ),
        deployment.capabilities.application_limit == "supported",
    );
    success(StatusCode::OK, result)
}

async fn list(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    query: Result<Query<PolicyListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                error.body_text(),
                None,
            );
        }
    };
    let Some(gateway_id) = query.gateway_id.filter(|value| !value.trim().is_empty()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "gateway_id is required",
            None,
        );
    };
    match registered_gateway(&state, &gateway_id) {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "gateway was not found",
                None,
            );
        }
        Err(_) => return store_unavailable(),
    }
    let (page, page_size) = match parse_page(query.page, query.page_size) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state.policy_service.list(&gateway_id, page, page_size) {
        Ok(data) => success(StatusCode::OK, data),
        Err(error) => failure(error),
    }
}

async fn detail(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    match state.policy_service.detail(&id) {
        Ok(data) => success(StatusCode::OK, data),
        Err(error) => failure(error),
    }
}

async fn create(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let expected_revision = match parse_if_match(&headers) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    let spec: PolicySpecV1 = match parse_body(body) {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    let Ok((spec, errors, warnings)) = validate_spec(&state, spec) else {
        return store_unavailable();
    };
    if !errors.is_empty() {
        return validation_failure(&errors);
    }
    let result = state
        .policy_service
        .create(&spec, &session.user_id, expected_revision);
    mutation_response(&state, result, StatusCode::CREATED, &warnings)
}

async fn update(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let expected_revision = match parse_if_match(&headers) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    let expected_version = match parse_policy_version(&headers) {
        Ok(version) => version,
        Err(response) => return response,
    };
    let spec: PolicySpecV1 = match parse_body(body) {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    let Ok((spec, errors, warnings)) = validate_spec(&state, spec) else {
        return store_unavailable();
    };
    if !errors.is_empty() {
        return validation_failure(&errors);
    }
    let result = state.policy_service.update(
        &id,
        &spec,
        &session.user_id,
        expected_revision,
        expected_version,
    );
    mutation_response(&state, result, StatusCode::OK, &warnings)
}

async fn delete(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let expected_revision = match parse_if_match(&headers) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    match state
        .policy_service
        .delete(&id, &session.user_id, expected_revision)
    {
        Ok(result) => {
            publish_mutation(&state, &result);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => failure(error),
    }
}

async fn republish(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    query: Result<Query<GatewayQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                error.body_text(),
                None,
            );
        }
    };
    match registered_gateway(&state, &query.gateway_id) {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "gateway was not found",
                None,
            );
        }
        Err(_) => return store_unavailable(),
    }
    match state
        .policy_service
        .republish(&query.gateway_id, &session.user_id)
    {
        Ok(revision) => {
            crate::policy::push::schedule_refresh(
                std::sync::Arc::clone(&state.policy_service),
                state.policy_hub.clone(),
                query.gateway_id,
            );
            success(
                StatusCode::OK,
                json!({ "desired_revision": revision, "changed": true }),
            )
        }
        Err(error) => failure(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnabledRequest {
    enabled: bool,
}

async fn set_enabled(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let expected_revision = match parse_if_match(&headers) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    let expected_version = match parse_policy_version(&headers) {
        Ok(version) => version,
        Err(response) => return response,
    };
    let request: EnabledRequest = match parse_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = state.policy_service.set_enabled(
        &id,
        request.enabled,
        &session.user_id,
        expected_revision,
        expected_version,
    );
    mutation_response(&state, result, StatusCode::OK, &[])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateRequest {
    spec: PolicySpecV1,
}

async fn validate(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    let request: ValidateRequest = match parse_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok((spec, errors, warnings)) = validate_spec(&state, request.spec) else {
        return store_unavailable();
    };
    let valid = errors.is_empty();
    let normalized_spec = valid.then_some(spec);
    success(
        StatusCode::OK,
        json!({
            "normalized_spec": normalized_spec,
            "errors": errors,
            "warnings": warnings,
            "valid": valid,
        }),
    )
}

async fn deployment(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    query: Result<Query<GatewayQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                error.body_text(),
                None,
            );
        }
    };
    match registered_gateway(&state, &query.gateway_id) {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "gateway was not found",
                None,
            );
        }
        Err(_) => return store_unavailable(),
    }
    match state.policy_service.deployment(&query.gateway_id) {
        Ok(data) => success(StatusCode::OK, data),
        Err(error) => failure(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyListQuery {
    gateway_id: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayQuery {
    gateway_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsQuery {
    gateway_id: Option<String>,
    kind: Option<String>,
    q: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

async fn options(
    State(state): State<CollectorState>,
    headers: HeaderMap,
    query: Result<Query<OptionsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(response) = require_session(&state, &headers) {
        return response;
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                error.body_text(),
                None,
            );
        }
    };
    let kind = query.kind.as_deref().unwrap_or("gateways");
    if !matches!(kind, "gateways" | "clients" | "applications" | "categories") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "kind must be gateways, clients, applications, or categories",
            None,
        );
    }
    let (page, page_size) = match parse_page(query.page, query.page_size) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let search = query.q.as_deref().unwrap_or_default().trim();
    if search.chars().count() > 128 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "q must not exceed 128 characters",
            None,
        );
    }
    if kind != "gateways" {
        let Some(gateway_id) = query.gateway_id.as_deref() else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "gateway_id is required for this option kind",
                None,
            );
        };
        match registered_gateway(&state, gateway_id) {
            Ok(true) => {}
            Ok(false) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "gateway was not found",
                    None,
                );
            }
            Err(_) => return store_unavailable(),
        }
    }
    match policy_options(
        &state,
        query.gateway_id.as_deref(),
        kind,
        search,
        page,
        page_size,
    ) {
        Ok(value) => success(StatusCode::OK, value),
        Err(error) => {
            tracing::error!(%error, "policy options lookup failed");
            store_unavailable()
        }
    }
}

fn policy_options(
    state: &CollectorState,
    requested_gateway: Option<&str>,
    kind: &str,
    search: &str,
    page: u32,
    page_size: u32,
) -> Result<Value, String> {
    let inner = state.lock();
    let gateway = inner.storage.gateway().map_err(|error| error.to_string())?;
    let Some(gateway) = gateway else {
        if kind == "gateways" {
            return Ok(json!({ "items": [], "total": 0, "page": page, "page_size": page_size }));
        }
        return Err("no gateway is registered".to_owned());
    };
    if requested_gateway.is_some_and(|requested| requested != gateway.id) {
        return Err("gateway was not found".to_owned());
    }
    let gateway_id = gateway.id.clone();
    let offset = i64::from(page.saturating_sub(1)) * i64::from(page_size);
    if kind == "gateways" {
        if !search.is_empty()
            && !gateway_id
                .to_ascii_lowercase()
                .contains(&search.to_ascii_lowercase())
        {
            return Ok(json!({ "items": [], "total": 0, "page": page, "page_size": page_size }));
        }
        return Ok(json!({
            "items": [{ "id": gateway_id, "name": gateway_id.clone() }],
            "total": 1,
            "page": page,
            "page_size": page_size,
        }));
    }

    let classifier = inner.classifier.clone();
    if let Some(clickhouse) = inner.storage.clickhouse_storage().cloned() {
        drop(inner);
        let storage = Storage::clickhouse(clickhouse);
        return options_result(&PolicyOptionsQuery {
            storage: &storage,
            classifier: &classifier,
            gateway_id: &gateway_id,
            kind,
            search,
            page,
            page_size,
            offset,
        });
    }
    options_result(&PolicyOptionsQuery {
        storage: &inner.storage,
        classifier: &classifier,
        gateway_id: &gateway_id,
        kind,
        search,
        page,
        page_size,
        offset,
    })
}

struct PolicyOptionsQuery<'a> {
    storage: &'a Storage,
    classifier: &'a crate::classifier::ClassifierHandle,
    gateway_id: &'a str,
    kind: &'a str,
    search: &'a str,
    page: u32,
    page_size: u32,
    offset: i64,
}

fn options_result(query: &PolicyOptionsQuery<'_>) -> Result<Value, String> {
    let items = match query.kind {
        "clients" => option_clients(
            query.storage,
            query.gateway_id,
            query.search,
            query.page_size,
            query.offset,
        )?,
        "applications" => option_applications(
            query.storage,
            query.classifier,
            query.gateway_id,
            query.search,
            query.page_size,
            query.offset,
        )?,
        "categories" => option_categories(
            query.storage,
            query.gateway_id,
            query.search,
            query.page_size,
            query.offset,
        )?,
        _ => return Err("unsupported option kind".to_owned()),
    };
    Ok(json!({
        "items": items,
        "page": query.page,
        "page_size": query.page_size,
        "total": items_total(query.storage, query.gateway_id, query.kind, query.search)?,
    }))
}

fn option_clients(
    storage: &Storage,
    gateway_id: &str,
    search: &str,
    page_size: u32,
    offset: i64,
) -> Result<Vec<Value>, String> {
    if let Some(connection) = storage.sqlite_connection() {
        let mut statement = connection
            .prepare(
                "SELECT mac, COALESCE(NULLIF(display_name, ''), NULLIF(hostname, ''), '')
                 FROM devices WHERE gateway_id = ?1
                   AND (?2 = '' OR instr(lower(hex(mac)), lower(replace(?2, ':', ''))) > 0
                        OR instr(lower(display_name), lower(?2)) > 0 OR instr(lower(hostname), lower(?2)) > 0)
                 ORDER BY COALESCE(NULLIF(display_name, ''), NULLIF(hostname, ''), hex(mac)), mac
                 LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| error.to_string())?;
        return statement
            .query_map(
                params![gateway_id, search, i64::from(page_size), offset],
                |row| {
                    let mac_bytes: Vec<u8> = row.get(0)?;
                    let mac = crate::query_api::format_mac(&mac_bytes).to_ascii_uppercase();
                    let name: String = row.get(1)?;
                    let name = if name.is_empty() { mac.clone() } else { name };
                    Ok(json!({ "id": mac, "mac": mac, "name": name, "gateway_id": gateway_id }))
                },
            )
            .map_err(|error| error.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| error.to_string());
    }
    let clickhouse = storage
        .clickhouse_storage()
        .ok_or_else(|| "storage backend unavailable".to_owned())?;
    let filter = clickhouse_search(
        "concat(mac, ' ', ifNull(display_name, ''), ' ', ifNull(hostname, ''))",
        search,
    );
    let rows = clickhouse_rows(
        clickhouse,
        &format!(
            "SELECT mac, coalesce(nullIf(display_name, ''), nullIf(hostname, ''), mac) AS name
             FROM devices FINAL WHERE gateway_id = {} AND {} ORDER BY name, mac LIMIT {} OFFSET {}",
            clickhouse_literal(gateway_id),
            filter,
            page_size,
            offset
        ),
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let mac = row["mac"].as_str().unwrap_or_default();
            let name = row["name"].as_str().unwrap_or(mac);
            json!({ "id": mac, "mac": mac, "name": name, "gateway_id": gateway_id })
        })
        .collect())
}

fn option_applications(
    storage: &Storage,
    classifier: &crate::classifier::ClassifierHandle,
    gateway_id: &str,
    search: &str,
    page_size: u32,
    offset: i64,
) -> Result<Vec<Value>, String> {
    let ids = if let Some(connection) = storage.sqlite_connection() {
        let mut statement = connection
            .prepare(
                "SELECT application_id FROM (
                    SELECT application_id FROM flow_sessions WHERE gateway_id = ?1 AND application_id NOT IN ('unknown', '')
                    UNION SELECT application_id FROM traffic_application_minute WHERE gateway_id = ?1 AND application_id NOT IN ('unknown', '')
                 ) WHERE (?2 = '' OR instr(lower(application_id), lower(?2)) > 0)
                 ORDER BY application_id LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map(
                params![gateway_id, search, i64::from(page_size), offset],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| error.to_string())?
    } else {
        let clickhouse = storage
            .clickhouse_storage()
            .ok_or_else(|| "storage backend unavailable".to_owned())?;
        let filter = clickhouse_search("application_id", search);
        clickhouse_rows(clickhouse, &format!(
            "SELECT application_id FROM (
                SELECT application_id FROM flow_sessions FINAL WHERE gateway_id = {} AND application_id NOT IN ('unknown', '')
                UNION DISTINCT SELECT application_id FROM traffic_application_minute FINAL WHERE gateway_id = {} AND application_id NOT IN ('unknown', '')
             ) WHERE {}
             ORDER BY application_id LIMIT {} OFFSET {}",
            clickhouse_literal(gateway_id), clickhouse_literal(gateway_id), filter, page_size, offset
        ))?
        .into_iter()
        .filter_map(|row| row["application_id"].as_str().map(str::to_owned))
        .collect()
    };
    Ok(ids
        .into_iter()
        .map(|id| {
            let name = classifier
                .application_metadata(&id)
                .map_or_else(|| id.clone(), |metadata| metadata.name.clone());
            json!({ "id": id, "name": name })
        })
        .collect())
}

fn option_categories(
    storage: &Storage,
    gateway_id: &str,
    search: &str,
    page_size: u32,
    offset: i64,
) -> Result<Vec<Value>, String> {
    let ids = if let Some(connection) = storage.sqlite_connection() {
        let mut statement = connection
            .prepare(
                "SELECT category_id FROM (
                    SELECT category_id FROM flow_sessions WHERE gateway_id = ?1 AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                    UNION SELECT category_id FROM traffic_application_minute WHERE gateway_id = ?1 AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                 ) WHERE (?2 = '' OR instr(lower(category_id), lower(?2)) > 0)
                 ORDER BY category_id LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map(
                params![gateway_id, search, i64::from(page_size), offset],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| error.to_string())?
    } else {
        let clickhouse = storage
            .clickhouse_storage()
            .ok_or_else(|| "storage backend unavailable".to_owned())?;
        let filter = clickhouse_search("category_id", search);
        clickhouse_rows(clickhouse, &format!(
            "SELECT category_id FROM (
                SELECT category_id FROM flow_sessions FINAL WHERE gateway_id = {} AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                UNION DISTINCT SELECT category_id FROM traffic_application_minute FINAL WHERE gateway_id = {} AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
             ) WHERE {} ORDER BY category_id LIMIT {} OFFSET {}",
            clickhouse_literal(gateway_id), clickhouse_literal(gateway_id), filter, page_size, offset
        ))?
        .into_iter()
        .filter_map(|row| row["category_id"].as_str().map(str::to_owned))
        .collect()
    };
    Ok(ids
        .into_iter()
        .map(|id| json!({ "id": id, "name": id }))
        .collect())
}

fn items_total(
    storage: &Storage,
    gateway_id: &str,
    kind: &str,
    search: &str,
) -> Result<u64, String> {
    if let Some(connection) = storage.sqlite_connection() {
        let count: i64 = match kind {
            "clients" => connection.query_row(
                "SELECT COUNT(*) FROM devices WHERE gateway_id = ?1
                 AND (?2 = '' OR instr(lower(mac), lower(?2)) > 0 OR instr(lower(display_name), lower(?2)) > 0 OR instr(lower(hostname), lower(?2)) > 0)",
                params![gateway_id, search], |row| row.get(0),
            ),
            "applications" => connection.query_row(
                "SELECT COUNT(*) FROM (
                    SELECT application_id FROM flow_sessions WHERE gateway_id = ?1 AND application_id NOT IN ('unknown', '')
                    UNION SELECT application_id FROM traffic_application_minute WHERE gateway_id = ?1 AND application_id NOT IN ('unknown', '')
                 ) WHERE (?2 = '' OR instr(lower(application_id), lower(?2)) > 0)",
                params![gateway_id, search], |row| row.get(0),
            ),
            "categories" => connection.query_row(
                "SELECT COUNT(*) FROM (
                    SELECT category_id FROM flow_sessions WHERE gateway_id = ?1 AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                    UNION SELECT category_id FROM traffic_application_minute WHERE gateway_id = ?1 AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                 ) WHERE (?2 = '' OR instr(lower(category_id), lower(?2)) > 0)",
                params![gateway_id, search], |row| row.get(0),
            ),
            _ => return Err("unsupported option kind".to_owned()),
        }
        .map_err(|error| error.to_string())?;
        return Ok(u64::try_from(count).unwrap_or(0));
    }
    let clickhouse = storage
        .clickhouse_storage()
        .ok_or_else(|| "storage backend unavailable".to_owned())?;
    let query = match kind {
        "clients" => {
            let filter = clickhouse_search(
                "concat(mac, ' ', ifNull(display_name, ''), ' ', ifNull(hostname, ''))",
                search,
            );
            format!(
                "SELECT count() AS total FROM devices FINAL WHERE gateway_id = {} AND {filter}",
                clickhouse_literal(gateway_id)
            )
        }
        "applications" => {
            let filter = clickhouse_search("application_id", search);
            format!("SELECT count() AS total FROM (
                SELECT application_id FROM flow_sessions FINAL WHERE gateway_id = {} AND application_id NOT IN ('unknown', '')
                UNION DISTINCT SELECT application_id FROM traffic_application_minute FINAL WHERE gateway_id = {} AND application_id NOT IN ('unknown', '')
             ) WHERE {filter}", clickhouse_literal(gateway_id), clickhouse_literal(gateway_id))
        }
        "categories" => {
            let filter = clickhouse_search("category_id", search);
            format!("SELECT count() AS total FROM (
                SELECT category_id FROM flow_sessions FINAL WHERE gateway_id = {} AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
                UNION DISTINCT SELECT category_id FROM traffic_application_minute FINAL WHERE gateway_id = {} AND category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown'
             ) WHERE {filter}", clickhouse_literal(gateway_id), clickhouse_literal(gateway_id))
        }
        _ => return Err("unsupported option kind".to_owned()),
    };
    let data = clickhouse
        .client()
        .query_json(&query)
        .map_err(|error| error.to_string())?;
    Ok(data["data"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| {
            item["total"]
                .as_u64()
                .or_else(|| item["total"].as_str()?.parse().ok())
        })
        .unwrap_or(0))
}

fn policy_catalog(state: &CollectorState, spec: &PolicySpecV1) -> Result<KnownSelectors, String> {
    let inner = state.lock();
    let registered = inner.storage.gateway().map_err(|error| error.to_string())?;
    let gateway_exists = registered
        .as_ref()
        .is_some_and(|gateway| gateway.id == spec.gateway_id);
    let mut known = KnownSelectors {
        gateway_exists,
        ..KnownSelectors::default()
    };
    if !gateway_exists {
        return Ok(known);
    }
    let classifier = inner.classifier.clone();
    if let Some(connection) = inner.storage.sqlite_connection() {
        known = sqlite_selector_catalog(connection, spec)?;
        drop(inner);
        add_application_metadata(&mut known, &classifier, spec);
        return Ok(known);
    }

    let clickhouse = inner
        .storage
        .clickhouse_storage()
        .cloned()
        .ok_or_else(|| "storage backend unavailable".to_owned())?;
    drop(inner);
    known = clickhouse_selector_catalog(&clickhouse, spec)?;
    add_application_metadata(&mut known, &classifier, spec);
    Ok(known)
}

fn sqlite_selector_catalog(
    connection: &rusqlite::Connection,
    spec: &PolicySpecV1,
) -> Result<KnownSelectors, String> {
    let mut known = KnownSelectors {
        gateway_exists: true,
        ..KnownSelectors::default()
    };
    let mut clauses = Vec::new();
    let mut values = vec![rusqlite::types::Value::Text(spec.gateway_id.clone())];
    for (kind, selectors) in [
        ("client", &spec.selectors.clients),
        ("application", &spec.selectors.applications),
        ("category", &spec.selectors.categories),
    ] {
        for selector in selectors {
            let parameter = values.len() + 1;
            clauses.push(match kind {
                "client" => format!(
                    "SELECT 'client' AS kind, ?{parameter} AS selector_id
                     WHERE EXISTS(SELECT 1 FROM devices WHERE gateway_id = ?1
                                  AND upper(hex(mac)) = upper(replace(?{parameter}, ':', '')))"
                ),
                "application" => format!(
                    "SELECT 'application' AS kind, ?{parameter} AS selector_id
                     WHERE EXISTS(SELECT 1 FROM flow_sessions WHERE gateway_id = ?1 AND application_id = ?{parameter})
                        OR EXISTS(SELECT 1 FROM traffic_application_minute WHERE gateway_id = ?1 AND application_id = ?{parameter})"
                ),
                _ => format!(
                    "SELECT 'category' AS kind, ?{parameter} AS selector_id
                     WHERE EXISTS(SELECT 1 FROM flow_sessions WHERE gateway_id = ?1 AND category_id = ?{parameter})
                        OR EXISTS(SELECT 1 FROM traffic_application_minute WHERE gateway_id = ?1 AND category_id = ?{parameter})"
                ),
            });
            values.push(rusqlite::types::Value::Text(selector.clone()));
        }
    }
    if !clauses.is_empty() {
        let mut statement = connection
            .prepare(&clauses.join(" UNION ALL "))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(values.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| error.to_string())?;
        for (kind, selector) in rows {
            insert_known_selector(&mut known, &kind, selector);
        }
    }
    Ok(known)
}

fn clickhouse_selector_catalog(
    clickhouse: &ClickHouseStorage,
    spec: &PolicySpecV1,
) -> Result<KnownSelectors, String> {
    let mut known = KnownSelectors {
        gateway_exists: true,
        ..KnownSelectors::default()
    };
    let gateway = clickhouse_literal(&spec.gateway_id);
    let clients = selector_literals(&spec.selectors.clients);
    let applications = selector_literals(&spec.selectors.applications);
    let categories = selector_literals(&spec.selectors.categories);
    let mut selects = Vec::new();
    if !clients.is_empty() {
        selects.push(format!(
            "SELECT 'client' AS kind, upper(mac) AS selector_id FROM devices FINAL WHERE gateway_id = {gateway} AND upper(mac) IN ({clients})"
        ));
    }
    if !applications.is_empty() {
        selects.push(format!(
            "SELECT 'application' AS kind, application_id AS selector_id FROM flow_sessions FINAL WHERE gateway_id = {gateway} AND application_id IN ({applications})"
        ));
        selects.push(format!(
            "SELECT 'application' AS kind, application_id AS selector_id FROM traffic_application_minute FINAL WHERE gateway_id = {gateway} AND application_id IN ({applications})"
        ));
    }
    if !categories.is_empty() {
        selects.push(format!(
            "SELECT 'category' AS kind, category_id AS selector_id FROM flow_sessions FINAL WHERE gateway_id = {gateway} AND category_id IN ({categories})"
        ));
        selects.push(format!(
            "SELECT 'category' AS kind, category_id AS selector_id FROM traffic_application_minute FINAL WHERE gateway_id = {gateway} AND category_id IN ({categories})"
        ));
    }
    if !selects.is_empty() {
        for row in clickhouse_rows(clickhouse, &selects.join(" UNION ALL "))? {
            let selector = row["selector_id"].as_str().unwrap_or_default().to_owned();
            insert_known_selector(
                &mut known,
                row["kind"].as_str().unwrap_or_default(),
                selector,
            );
        }
    }
    Ok(known)
}

fn insert_known_selector(known: &mut KnownSelectors, kind: &str, selector: String) {
    match kind {
        "client" => {
            known.clients.insert(selector);
        }
        "application" => {
            known.applications.insert(selector);
        }
        "category" => {
            known.categories.insert(selector);
        }
        _ => {}
    }
}

fn add_application_metadata(
    known: &mut KnownSelectors,
    classifier: &crate::classifier::ClassifierHandle,
    spec: &PolicySpecV1,
) {
    for application in &spec.selectors.applications {
        if classifier.application_metadata(application).is_some() {
            known.applications.insert(application.clone());
        }
    }
}

fn selector_literals(selectors: &[String]) -> String {
    selectors
        .iter()
        .map(|selector| clickhouse_literal(selector))
        .collect::<Vec<_>>()
        .join(", ")
}

fn clickhouse_rows(storage: &ClickHouseStorage, query: &str) -> Result<Vec<Value>, String> {
    let result = storage
        .client()
        .query_json(query)
        .map_err(|error| error.to_string())?;
    Ok(result["data"].as_array().cloned().unwrap_or_default())
}

fn clickhouse_search(column: &str, search: &str) -> String {
    if search.is_empty() {
        "1".to_owned()
    } else {
        format!(
            "positionCaseInsensitiveUTF8(toString({column}), {}) > 0",
            clickhouse_literal(search)
        )
    }
}

fn clickhouse_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn registered_gateway(state: &CollectorState, gateway_id: &str) -> Result<bool, String> {
    state
        .lock()
        .storage
        .gateway()
        .map(|gateway| gateway.is_some_and(|gateway| gateway.id == gateway_id))
        .map_err(|error| error.to_string())
}

fn validate_spec(
    state: &CollectorState,
    mut spec: PolicySpecV1,
) -> Result<(PolicySpecV1, Vec<ValidationIssue>, Vec<String>), String> {
    let structural_errors = normalize_and_validate(&mut spec, None);
    if spec.selectors.clients.len() > 32
        || spec.selectors.applications.len() > 32
        || spec.selectors.categories.len() > 16
        || spec.selectors.clients.iter().any(|value| value.len() > 32)
        || spec
            .selectors
            .applications
            .iter()
            .any(|value| value.len() > 128)
        || spec
            .selectors
            .categories
            .iter()
            .any(|value| value.len() > 128)
        || spec.gateway_id.is_empty()
    {
        return Ok((spec, structural_errors, Vec::new()));
    }
    let known = policy_catalog(state, &spec)?;
    let errors = normalize_and_validate(&mut spec, Some(&known));
    let mut warnings = Vec::new();
    if spec.action.kind == super::model::ActionKind::Allow {
        warnings.push(
            "Allow only skips NetQmon blocks; it does not bypass the upstream firewall or limits."
                .to_owned(),
        );
    }
    if !spec.selectors.clients.is_empty()
        && spec.selectors.applications.is_empty()
        && spec.selectors.categories.is_empty()
        && spec.selectors.min_application_confidence.to_bits() != 0.8_f64.to_bits()
    {
        warnings
            .push("min_application_confidence is ignored for client-only selectors.".to_owned());
    }
    Ok((spec, errors, warnings))
}

#[allow(clippy::result_large_err)]
fn require_session(
    state: &CollectorState,
    headers: &HeaderMap,
) -> Result<netqmon_storage::SessionRecord, Response> {
    let Some(token) = crate::bearer_token(headers) else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid admin session is required",
            None,
        ));
    };
    let result = state
        .lock()
        .storage
        .session(&crate::hash_token(token), crate::unix_time_ms());
    match result {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(api_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid admin session is required",
            None,
        )),
        Err(error) => {
            tracing::error!(%error, "policy session verification failed");
            Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_store_unavailable",
                "session verification is temporarily unavailable",
                None,
            ))
        }
    }
}

#[allow(clippy::result_large_err)]
fn parse_body<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, Response> {
    let body = body.map_err(|error| {
        let status = error.status();
        let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
            "policy_too_large"
        } else {
            "invalid_spec"
        };
        api_error(status, code, "request body could not be read", None)
    })?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "policy_too_large",
            "request body exceeds 64 KiB",
            None,
        ));
    }
    serde_json::from_slice(&body).map_err(|error| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_spec",
            format!("request body must be valid JSON: {error}"),
            None,
        )
    })
}

#[allow(clippy::result_large_err)]
fn parse_if_match(headers: &HeaderMap) -> Result<u64, Response> {
    let Some(value) = headers.get("if-match") else {
        return Err(api_error(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "If-Match must contain the current gateway revision",
            None,
        ));
    };
    let value = value.to_str().unwrap_or_default();
    let Some(value) = value
        .strip_prefix("\"rev:")
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_if_match",
            "If-Match must use the format \"rev:<revision>\"",
            None,
        ));
    };
    value.parse().map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_if_match",
            "If-Match revision must be a non-negative integer",
            None,
        )
    })
}

#[allow(clippy::result_large_err)]
fn parse_policy_version(headers: &HeaderMap) -> Result<u64, Response> {
    let Some(value) = headers.get("x-expected-policy-version") else {
        return Err(api_error(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "X-Expected-Policy-Version is required",
            None,
        ));
    };
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "invalid_policy_version",
                "X-Expected-Policy-Version must be a positive integer",
                None,
            )
        })
}

#[allow(clippy::result_large_err)]
fn parse_page(page: Option<u32>, page_size: Option<u32>) -> Result<(u32, u32), Response> {
    let page = page.unwrap_or(1);
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if page == 0 || page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "page must be positive and page_size must be between 1 and 100",
            None,
        ));
    }
    Ok((page, page_size))
}

fn mutation_response(
    state: &CollectorState,
    result: Result<MutationResult, PolicyFailure>,
    status: StatusCode,
    warnings: &[String],
) -> Response {
    match result {
        Ok(result) => {
            publish_mutation(state, &result);
            success(
                status,
                json!({
                    "policy": result.policy,
                    "desired_revision": result.revision,
                    "changed": result.changed,
                    "warnings": warnings,
                }),
            )
        }
        Err(error) => failure(error),
    }
}

fn publish_mutation(state: &CollectorState, result: &MutationResult) {
    if result.changed {
        crate::policy::push::schedule_refresh(
            std::sync::Arc::clone(&state.policy_service),
            state.policy_hub.clone(),
            result.gateway_id.clone(),
        );
    }
}

fn validation_failure(errors: &[ValidationIssue]) -> Response {
    let first_code = errors
        .iter()
        .find(|error| error.code != "invalid_spec")
        .map_or("invalid_spec", |error| error.code.as_str());
    let status = match first_code {
        "not_found" => StatusCode::NOT_FOUND,
        "unsupported_selector" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::BAD_REQUEST,
    };
    api_error(
        status,
        first_code,
        "policy specification is invalid",
        Some(json!({ "errors": errors })),
    )
}

fn failure(error: PolicyFailure) -> Response {
    match error {
        PolicyFailure::NotFound => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "policy was not found",
            None,
        ),
        PolicyFailure::RevisionConflict { current_revision } => api_error(
            StatusCode::CONFLICT,
            "revision_conflict",
            "gateway policy revision has changed",
            Some(json!({ "current_revision": current_revision })),
        ),
        PolicyFailure::VersionConflict {
            current_revision,
            current_version,
        } => api_error(
            StatusCode::CONFLICT,
            "revision_conflict",
            "policy was changed by another editor",
            Some(
                json!({ "current_revision": current_revision, "current_policy_version": current_version }),
            ),
        ),
        PolicyFailure::LimitOverlapUnsupported => api_error(
            StatusCode::CONFLICT,
            "limit_overlap_unsupported",
            "application-level limits must not overlap for the same client",
            None,
        ),
        PolicyFailure::PolicyLimitExceeded => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "policy_limit_exceeded",
            "gateway has reached its 256 policy limit",
            None,
        ),
        PolicyFailure::PolicyTooLarge => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "policy_too_large",
            "normalized policy exceeds 8 KiB",
            None,
        ),
        PolicyFailure::PolicyBundleTooLarge => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "policy_bundle_too_large",
            "gateway policy bundle exceeds the 768 KiB limit",
            None,
        ),
        PolicyFailure::ScheduleComplexityExceeded => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schedule_complexity_exceeded",
            "gateway schedule projection is too complex",
            None,
        ),
        PolicyFailure::Invalid { code, message } => {
            api_error(StatusCode::BAD_REQUEST, code, message, None)
        }
        PolicyFailure::Store(error) => {
            tracing::error!(%error, "policy database operation failed");
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_store_unavailable",
                "policy storage is temporarily unavailable",
                None,
            )
        }
    }
}

fn success<T: serde::Serialize>(status: StatusCode, data: T) -> Response {
    (
        status,
        Json(json!({ "schema_version": SCHEMA_VERSION, "data": data })),
    )
        .into_response()
}

fn api_error(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    details: Option<Value>,
) -> Response {
    let mut error = json!({ "code": code, "message": message.into() });
    if let Some(details) = details {
        error["details"] = details;
    }
    (
        status,
        Json(json!({ "schema_version": SCHEMA_VERSION, "error": error })),
    )
        .into_response()
}

fn store_unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "policy_store_unavailable",
        "policy storage is temporarily unavailable",
        None,
    )
}
