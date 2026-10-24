//! Keep synchronous SQLite/ClickHouse reads off Tokio's request workers.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use moka::future::Cache;
use tokio::sync::Semaphore;

use crate::CollectorState;

#[derive(Clone)]
struct CachedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl IntoResponse for CachedResponse {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

pub(super) fn wrap(router: Router<CollectorState>) -> Router<CollectorState> {
    let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
    let permits = Arc::new(Semaphore::new(parallelism.saturating_sub(1).clamp(1, 4)));
    let insights = Cache::<String, CachedResponse>::builder()
        .max_capacity(32)
        .time_to_live(Duration::from_secs(10))
        .build();
    router.route_layer(from_fn(move |request: Request, next: Next| {
        let permits = Arc::clone(&permits);
        let insights = insights.clone();
        async move {
            if request.method() != Method::GET
                || request.uri().path() == "/internal/overview/status"
            {
                return next.run(request).await;
            }
            if request.uri().path() != "/internal/insights" {
                return read(permits, request, next).await;
            }
            // Exact URIs preserve explicit time bounds and pagination. Moka
            // coalesces concurrent misses, and failed reads are never cached.
            let key = request.uri().to_string();
            let result = insights
                .try_get_with(key, async move {
                    let response = read(permits, request, next).await;
                    let (parts, body) = response.into_parts();
                    let body = to_bytes(body, 2 * 1024 * 1024).await.map_err(|error| {
                        tracing::error!(%error, "could not buffer insights response");
                        CachedResponse {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            headers: HeaderMap::new(),
                            body: Bytes::from_static(b"insights response unavailable"),
                        }
                    })?;
                    let response = CachedResponse {
                        status: parts.status,
                        headers: parts.headers,
                        body,
                    };
                    if response.status.is_success() {
                        Ok(response)
                    } else {
                        Err(response)
                    }
                })
                .await;
            match result {
                Ok(response) => response.into_response(),
                Err(response) => response.as_ref().clone().into_response(),
            }
        }
    }))
}

async fn read(permits: Arc<Semaphore>, request: Request, next: Next) -> Response {
    let Ok(permit) = permits.acquire_owned().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let runtime = tokio::runtime::Handle::current();
    match tokio::task::spawn_blocking(move || {
        // Retain the slot even if the client disconnects while SQLite is busy.
        let _permit = permit;
        runtime.block_on(next.run(request))
    })
    .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "query worker failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    fn request(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn concurrent_insights_are_coalesced_and_time_bounds_are_part_of_the_key() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let router = wrap(Router::new().route(
            "/internal/insights",
            get(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(20));
                    axum::Json(serde_json::json!({ "data": [1] }))
                }
            }),
        ))
        .with_state(CollectorState::new("test"));
        let (first, second) = tokio::join!(
            router
                .clone()
                .oneshot(request("/internal/insights?from=1&to=2")),
            router
                .clone()
                .oneshot(request("/internal/insights?from=1&to=2")),
        );
        assert_eq!(first.unwrap().status(), StatusCode::OK);
        assert_eq!(second.unwrap().status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        router
            .oneshot(request("/internal/insights?from=2&to=3"))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_insights_are_not_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let router = wrap(Router::new().route(
            "/internal/insights",
            get(move || {
                let count = Arc::clone(&count);
                async move {
                    if count.fetch_add(1, Ordering::SeqCst) == 0 {
                        StatusCode::BAD_GATEWAY
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        ))
        .with_state(CollectorState::new("test"));
        assert_eq!(
            router
                .clone()
                .oneshot(request("/internal/insights"))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            router
                .clone()
                .oneshot(request("/internal/insights"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            router
                .oneshot(request("/internal/insights"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_queries_do_not_block_the_async_runtime() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&entered);
        let (resume, wait) = std::sync::mpsc::channel();
        let wait = Arc::new(std::sync::Mutex::new(wait));
        let router = wrap(Router::new().route(
            "/internal/traffic",
            get(move || {
                let notify = Arc::clone(&notify);
                let wait = Arc::clone(&wait);
                async move {
                    notify.notify_one();
                    wait.lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap();
                    StatusCode::OK
                }
            }),
        ))
        .with_state(CollectorState::new("test"));
        let heavy = tokio::spawn(router.oneshot(request("/internal/traffic")));
        entered.notified().await;
        // A timer must still run on this runtime's only async worker.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!heavy.is_finished());
        resume.send(()).unwrap();
        assert_eq!(heavy.await.unwrap().unwrap().status(), StatusCode::OK);
    }
}
