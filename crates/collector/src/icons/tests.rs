use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::classifier::ClassifierHandle;
use axum::body::Bytes;

use super::cache::IconCache;
use super::provider::{RemoteIcon, RemoteIconProvider};
use super::resolver::application_candidates;
use super::{CachedIcon, IconCacheConfig, IconService};

#[derive(Default)]
struct MockProvider {
    counts: Mutex<HashMap<String, usize>>,
    responses: Mutex<HashMap<String, Option<RemoteIcon>>>,
    delay: Duration,
}

impl MockProvider {
    fn hit(&self, hostname: &str, bytes: &'static [u8]) {
        self.responses.lock().unwrap().insert(
            hostname.to_owned(),
            Some(RemoteIcon {
                bytes: Bytes::from_static(bytes),
                content_type: "image/png".to_owned(),
            }),
        );
    }

    fn miss(&self, hostname: &str) {
        self.responses
            .lock()
            .unwrap()
            .insert(hostname.to_owned(), None);
    }

    fn count(&self, hostname: &str) -> usize {
        *self.counts.lock().unwrap().get(hostname).unwrap_or(&0)
    }
}

impl RemoteIconProvider for MockProvider {
    fn fetch<'a>(
        &'a self,
        hostname: &'a str,
        _max_object_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = Option<RemoteIcon>> + Send + 'a>> {
        Box::pin(async move {
            {
                let mut counts = self.counts.lock().unwrap();
                *counts.entry(hostname.to_owned()).or_default() += 1;
            }
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.responses
                .lock()
                .unwrap()
                .get(hostname)
                .cloned()
                .unwrap_or(None)
        })
    }
}

#[tokio::test]
async fn first_request_fetches_and_second_request_uses_cache() {
    let provider = Arc::new(MockProvider::default());
    provider.hit("discord.com", b"icon");
    let cache = IconCache::new(IconCacheConfig::default());

    let first = cache
        .get_or_fetch("favicon-im", "discord.com", provider.clone())
        .await;
    assert!(matches!(first, CachedIcon::Hit { .. }));
    let second = cache
        .get_or_fetch("favicon-im", "discord.com", provider.clone())
        .await;
    assert!(matches!(second, CachedIcon::Hit { .. }));
    assert_eq!(provider.count("discord.com"), 1);
    assert_eq!(cache.stats().await.entry_count, 1);
}

#[tokio::test]
async fn fallback_chain_negative_caches_failed_domains() {
    let provider = Arc::new(MockProvider::default());
    provider.miss("a.example");
    provider.hit("b.example", b"icon");
    let service = IconService::with_provider(IconCacheConfig::default(), provider.clone());

    let icon = service
        .fetch_first(vec!["a.example".to_owned(), "b.example".to_owned()])
        .await
        .expect("fallback icon returned");
    assert_eq!(icon.hostname, "b.example");
    assert_eq!(provider.count("a.example"), 1);
    assert_eq!(provider.count("b.example"), 1);

    let icon = service
        .fetch_first(vec!["a.example".to_owned(), "b.example".to_owned()])
        .await
        .expect("fallback icon returned from cache");
    assert_eq!(icon.hostname, "b.example");
    assert_eq!(provider.count("a.example"), 1);
    assert_eq!(provider.count("b.example"), 1);
}

#[tokio::test]
async fn concurrent_requests_are_deduplicated() {
    let provider = Arc::new(MockProvider {
        delay: Duration::from_millis(25),
        ..MockProvider::default()
    });
    provider.hit("discord.com", b"icon");
    let cache = Arc::new(IconCache::new(IconCacheConfig::default()));
    let tasks = (0..20)
        .map(|_| {
            let cache = cache.clone();
            let provider = provider.clone();
            tokio::spawn(async move {
                cache
                    .get_or_fetch("favicon-im", "discord.com", provider)
                    .await
            })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        assert!(matches!(task.await.unwrap(), CachedIcon::Hit { .. }));
    }
    assert_eq!(provider.count("discord.com"), 1);
}

#[tokio::test]
async fn clear_cache_invalidates_entries() {
    let provider = Arc::new(MockProvider::default());
    provider.hit("a.example", b"a");
    provider.hit("b.example", b"b");
    provider.hit("c.example", b"c");
    let cache = IconCache::new(IconCacheConfig::default());
    for hostname in ["a.example", "b.example", "c.example"] {
        cache
            .get_or_fetch("favicon-im", hostname, provider.clone())
            .await;
    }
    assert_eq!(cache.stats().await.entry_count, 3);
    assert_eq!(cache.clear().await.entry_count, 0);
    cache
        .get_or_fetch("favicon-im", "a.example", provider.clone())
        .await;
    assert_eq!(provider.count("a.example"), 2);
}

#[tokio::test]
async fn weighted_lru_evicts_least_recently_used_entry() {
    let provider = Arc::new(MockProvider::default());
    provider.hit("a.example", b"aaaa");
    provider.hit("b.example", b"bbbb");
    provider.hit("c.example", b"cccc");
    let cache = IconCache::new(IconCacheConfig {
        max_bytes: 8,
        ..IconCacheConfig::default()
    });

    cache
        .get_or_fetch("favicon-im", "a.example", provider.clone())
        .await;
    cache
        .get_or_fetch("favicon-im", "b.example", provider.clone())
        .await;
    cache.stats().await;
    cache
        .get_or_fetch("favicon-im", "a.example", provider.clone())
        .await;
    cache.touch("favicon-im:a.example").await;
    cache
        .get_or_fetch("favicon-im", "c.example", provider.clone())
        .await;
    cache.stats().await;

    assert!(cache.contains_key("favicon-im:a.example").await);
    assert!(!cache.contains_key("favicon-im:b.example").await);
    assert!(cache.contains_key("favicon-im:c.example").await);
}

#[test]
fn repository_xiaohongshu_icon_metadata_keeps_remote_candidate() {
    let application = ClassifierHandle::test_default()
        .application_metadata("xiaohongshu")
        .expect("xiaohongshu application metadata");
    let organization = ClassifierHandle::test_default()
        .organization_metadata("xingyin")
        .expect("xingyin organization metadata");

    assert_eq!(
        application.icon.local_fallback.as_deref(),
        Some("xiaohongshu")
    );
    assert_eq!(
        application_candidates(&application, Some(&organization)),
        vec!["xiaohongshu.com".to_owned()]
    );
}
