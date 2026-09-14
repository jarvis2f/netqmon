use std::time::{Duration, Instant};

use moka::Expiry;
use moka::future::Cache;
use moka::policy::EvictionPolicy;
use serde::Serialize;

use super::CachedIcon;
use super::provider::RemoteIconProvider;

const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;
const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MAX_OBJECT_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct IconCacheConfig {
    pub(crate) max_bytes: u64,
    pub(crate) positive_ttl: Duration,
    pub(crate) negative_ttl: Duration,
    pub(crate) fetch_timeout: Duration,
    pub(crate) max_object_bytes: usize,
}

impl IconCacheConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            max_bytes: env_u64("NETQMON_ICON_CACHE_MAX_BYTES").unwrap_or(DEFAULT_MAX_BYTES),
            positive_ttl: Duration::from_secs(
                env_u64("NETQMON_ICON_CACHE_TTL_SECONDS").unwrap_or(DEFAULT_POSITIVE_TTL.as_secs()),
            ),
            negative_ttl: Duration::from_secs(
                env_u64("NETQMON_ICON_NEGATIVE_TTL_SECONDS")
                    .unwrap_or(DEFAULT_NEGATIVE_TTL.as_secs()),
            ),
            fetch_timeout: Duration::from_millis(
                env_u64("NETQMON_ICON_FETCH_TIMEOUT_MS")
                    .unwrap_or(u64::try_from(DEFAULT_FETCH_TIMEOUT.as_millis()).unwrap_or(3_000)),
            ),
            max_object_bytes: env_u64("NETQMON_ICON_MAX_OBJECT_BYTES")
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(DEFAULT_MAX_OBJECT_BYTES),
        }
    }
}

impl Default for IconCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            positive_ttl: DEFAULT_POSITIVE_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }
}

#[derive(Clone)]
pub(crate) struct IconCache {
    cache: Cache<String, CachedIcon>,
    config: IconCacheConfig,
}

#[cfg(test)]
impl IconCache {
    pub(crate) async fn contains_key(&self, key: &str) -> bool {
        self.cache.run_pending_tasks().await;
        self.cache.contains_key(key)
    }

    pub(crate) async fn touch(&self, key: &str) {
        let _ = self.cache.get(key).await;
        self.cache.run_pending_tasks().await;
    }
}

impl IconCache {
    pub(crate) fn new(config: IconCacheConfig) -> Self {
        let expiry = IconExpiry {
            positive_ttl: config.positive_ttl,
            negative_ttl: config.negative_ttl,
        };
        let cache = Cache::builder()
            .name("netqmon-icon-cache")
            .eviction_policy(EvictionPolicy::lru())
            .weigher(|_key, value: &CachedIcon| -> u32 {
                match value {
                    CachedIcon::Hit { bytes, .. } => bytes.len().try_into().unwrap_or(u32::MAX),
                    CachedIcon::Miss => 1,
                }
            })
            .max_capacity(config.max_bytes)
            .expire_after(expiry)
            .build();
        Self { cache, config }
    }

    pub(crate) async fn get_or_fetch(
        &self,
        provider_name: &'static str,
        hostname: &str,
        provider: std::sync::Arc<dyn RemoteIconProvider>,
    ) -> CachedIcon {
        let key = format!("{provider_name}:{hostname}");
        let hostname = hostname.to_owned();
        let max_object_bytes = self.config.max_object_bytes;
        self.cache
            .get_with(key, async move {
                tracing::debug!(provider = provider_name, domain = %hostname, "icon cache miss");
                if let Some(icon) = provider.fetch(&hostname, max_object_bytes).await {
                    tracing::debug!(
                        provider = provider_name,
                        domain = %hostname,
                        bytes = icon.bytes.len(),
                        "remote icon fetched"
                    );
                    CachedIcon::Hit {
                        bytes: icon.bytes,
                        content_type: icon.content_type,
                    }
                } else {
                    tracing::debug!(provider = provider_name, domain = %hostname, "remote icon not found");
                    CachedIcon::Miss
                }
            })
            .await
    }

    pub(crate) async fn stats(&self) -> IconCacheStats {
        self.cache.run_pending_tasks().await;
        IconCacheStats {
            entry_count: self.cache.entry_count(),
            weighted_size_bytes: self.cache.weighted_size(),
            capacity_bytes: self.config.max_bytes,
            positive_ttl_seconds: self.config.positive_ttl.as_secs(),
            negative_ttl_seconds: self.config.negative_ttl.as_secs(),
        }
    }

    pub(crate) async fn clear(&self) -> IconCacheStats {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
        self.stats().await
    }
}

#[derive(Clone, Copy, Debug)]
struct IconExpiry {
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl Expiry<String, CachedIcon> for IconExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedIcon,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(match value {
            CachedIcon::Hit { .. } => self.positive_ttl,
            CachedIcon::Miss => self.negative_ttl,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct IconCacheStats {
    pub(crate) entry_count: u64,
    pub(crate) weighted_size_bytes: u64,
    pub(crate) capacity_bytes: u64,
    pub(crate) positive_ttl_seconds: u64,
    pub(crate) negative_ttl_seconds: u64,
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
}
