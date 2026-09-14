use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::Url;

use super::provider::{RemoteIcon, RemoteIconProvider};

#[derive(Clone)]
pub(crate) struct FaviconImProvider {
    client: reqwest::Client,
}

impl FaviconImProvider {
    pub(crate) fn new(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent(concat!("netqmon-collector/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("favicon HTTP client configuration must be valid");
        Self { client }
    }
}

impl RemoteIconProvider for FaviconImProvider {
    fn fetch<'a>(
        &'a self,
        hostname: &'a str,
        max_object_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Option<RemoteIcon>> + Send + 'a>> {
        Box::pin(async move {
            let url = Url::parse(&format!("https://favicon.im/{hostname}")).ok()?;
            let response = match self.client.get(url).send().await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(domain = %hostname, error = %error, "remote icon fetch failed");
                    return None;
                }
            };
            if !response.status().is_success() {
                tracing::debug!(
                    domain = %hostname,
                    status = response.status().as_u16(),
                    "remote icon returned non-success"
                );
                return None;
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !content_type.starts_with("image/") {
                tracing::debug!(domain = %hostname, content_type, "remote icon invalid content type");
                return None;
            }
            let bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::debug!(domain = %hostname, error = %error, "remote icon body read failed");
                    return None;
                }
            };
            if bytes.is_empty() || bytes.len() > max_object_bytes {
                tracing::debug!(
                    domain = %hostname,
                    bytes = bytes.len(),
                    max_object_bytes,
                    "remote icon invalid size"
                );
                return None;
            }
            Some(RemoteIcon {
                bytes,
                content_type,
            })
        })
    }
}
