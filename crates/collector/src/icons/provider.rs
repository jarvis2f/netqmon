use std::future::Future;
use std::pin::Pin;

use axum::body::Bytes;

#[derive(Clone, Debug)]
pub(crate) struct RemoteIcon {
    pub(crate) bytes: Bytes,
    pub(crate) content_type: String,
}

pub(crate) trait RemoteIconProvider: Send + Sync {
    fn fetch<'a>(
        &'a self,
        hostname: &'a str,
        max_object_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Option<RemoteIcon>> + Send + 'a>>;
}
