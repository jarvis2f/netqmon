mod cache;
mod favicon_im;
mod provider;
mod resolver;
#[cfg(test)]
mod tests;

pub(crate) use cache::{IconCacheConfig, IconCacheStats};

use std::sync::Arc;

use crate::classifier::ClassifierHandle;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::CollectorState;
use cache::IconCache;
use favicon_im::FaviconImProvider;
use provider::RemoteIconProvider;
use resolver::{application_candidates, organization_candidates};

#[derive(Clone)]
pub(crate) struct IconService {
    cache: IconCache,
    provider: Arc<dyn RemoteIconProvider>,
}

impl IconService {
    pub(crate) fn new(config: IconCacheConfig) -> Self {
        Self {
            cache: IconCache::new(config),
            provider: Arc::new(FaviconImProvider::new(config.fetch_timeout)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_provider(
        config: IconCacheConfig,
        provider: Arc<dyn RemoteIconProvider>,
    ) -> Self {
        Self {
            cache: IconCache::new(config),
            provider,
        }
    }

    pub(crate) async fn fetch_first(&self, candidates: Vec<String>) -> Option<CachedRemoteIcon> {
        for hostname in candidates {
            match self
                .cache
                .get_or_fetch("favicon-im", &hostname, self.provider.clone())
                .await
            {
                CachedIcon::Hit {
                    bytes,
                    content_type,
                } => {
                    return Some(CachedRemoteIcon {
                        bytes,
                        content_type,
                        hostname,
                    });
                }
                CachedIcon::Miss => {}
            }
        }
        None
    }

    pub(crate) async fn stats(&self) -> IconCacheStats {
        self.cache.stats().await
    }

    pub(crate) async fn clear(&self) -> IconCacheStats {
        self.cache.clear().await
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CachedRemoteIcon {
    pub(crate) bytes: Bytes,
    pub(crate) content_type: String,
    pub(crate) hostname: String,
}

#[derive(Clone, Debug)]
pub(crate) enum CachedIcon {
    Hit { bytes: Bytes, content_type: String },
    Miss,
}

pub(crate) fn router() -> Router<CollectorState> {
    Router::new()
        .route("/internal/icons/application/{id}", get(application_icon))
        .route("/internal/icons/organization/{id}", get(organization_icon))
        .route("/internal/icons/domain/{hostname}", get(domain_icon))
        .route("/internal/settings/icon-cache", get(icon_cache_stats))
        .route(
            "/internal/settings/icon-cache/clear",
            post(clear_icon_cache),
        )
}

async fn application_icon(State(state): State<CollectorState>, Path(id): Path<String>) -> Response {
    let (application, organization) = state.icon_application_context(&id);
    let Some(application) = application else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let candidates = application_candidates(&application, organization.as_ref());
    icon_response(state.icon_service(), candidates).await
}

async fn organization_icon(
    State(state): State<CollectorState>,
    Path(id): Path<String>,
) -> Response {
    let Some(organization) = state.icon_organization_context(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    icon_response(state.icon_service(), organization_candidates(&organization)).await
}

async fn domain_icon(
    State(state): State<CollectorState>,
    Path(hostname): Path<String>,
) -> Response {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if !ClassifierHandle::valid_icon_hostname_for_metadata(&normalized) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    icon_response(state.icon_service(), vec![normalized]).await
}

async fn icon_response(service: Arc<IconService>, candidates: Vec<String>) -> Response {
    let Some(icon) = service.fetch_first(candidates).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&icon.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert("x-netqmon-icon-cache", HeaderValue::from_static("hit"));
    headers.insert(
        "x-netqmon-icon-source",
        HeaderValue::from_static("favicon.im"),
    );
    if let Ok(value) = HeaderValue::from_str(&icon.hostname) {
        headers.insert("x-netqmon-icon-domain", value);
    }
    (headers, icon.bytes).into_response()
}

async fn icon_cache_stats(State(state): State<CollectorState>) -> Response {
    axum::Json(state.icon_service().stats().await).into_response()
}

async fn clear_icon_cache(State(state): State<CollectorState>) -> Response {
    axum::Json(state.icon_service().clear().await).into_response()
}
