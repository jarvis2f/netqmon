//! Small, generation-invalidated cache for expensive grouped summary pages.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::sync::Cache;
use serde_json::Value;

#[derive(Clone)]
pub(crate) struct SummaryPageCache {
    pages: Cache<(&'static str, u32, u64, u64, Option<(i64, i64)>), Arc<(Vec<Value>, u64)>>,
    generation: Arc<AtomicU64>,
}

impl SummaryPageCache {
    pub(crate) fn new() -> Self {
        Self {
            pages: Cache::builder()
                .max_capacity(10_000)
                .weigher(
                    |_: &(&'static str, u32, u64, u64, Option<(i64, i64)>),
                     page: &Arc<(Vec<Value>, u64)>| {
                        u32::try_from(page.0.len().max(1)).unwrap_or(u32::MAX)
                    },
                )
                .time_to_live(Duration::from_secs(2))
                .build(),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn get(
        &self,
        kind: &'static str,
        limit: u32,
        offset: u64,
        generation: u64,
    ) -> Option<(Vec<Value>, u64)> {
        self.get_window(kind, limit, offset, generation, None)
    }

    pub(crate) fn get_window(
        &self,
        kind: &'static str,
        limit: u32,
        offset: u64,
        generation: u64,
        window: Option<(i64, i64)>,
    ) -> Option<(Vec<Value>, u64)> {
        if self.generation() != generation {
            return None;
        }
        let page = self.pages.get(&(kind, limit, offset, generation, window))?;
        (self.generation() == generation).then(|| page.as_ref().clone())
    }

    pub(crate) fn insert(
        &self,
        kind: &'static str,
        limit: u32,
        offset: u64,
        generation: u64,
        page: Vec<Value>,
        total: u64,
    ) {
        self.insert_window(kind, limit, offset, generation, None, page, total);
    }

    pub(crate) fn insert_window(
        &self,
        kind: &'static str,
        limit: u32,
        offset: u64,
        generation: u64,
        window: Option<(i64, i64)>,
        page: Vec<Value>,
        total: u64,
    ) {
        self.pages.insert(
            (kind, limit, offset, generation, window),
            Arc::new((page, total)),
        );
    }

    pub(crate) fn invalidate(&self) {
        // Generation keys make old pages unreachable immediately. Let the
        // bounded two-second cache reclaim them without doing cache-wide work
        // on the ingestion path.
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_kind_is_part_of_the_page_key() {
        let cache = SummaryPageCache::new();
        let generation = cache.generation();
        let domains = vec![serde_json::json!({"kind": "domains"})];
        cache.insert("domains", 50, 0, generation, domains.clone(), 1);

        assert_eq!(cache.get("domains", 50, 0, generation), Some((domains, 1)));
        assert_eq!(cache.get("organizations", 50, 0, generation), None);
    }

    #[test]
    fn invalidation_makes_old_pages_unreachable() {
        let cache = SummaryPageCache::new();
        let generation = cache.generation();
        let page = vec![serde_json::json!({"domain": "before.example"})];
        cache.insert("domains", 50, 0, generation, page.clone(), 1);
        assert_eq!(cache.get("domains", 50, 0, generation), Some((page, 1)));

        cache.invalidate();
        assert_eq!(cache.generation(), generation + 1);
        assert_eq!(cache.get("domains", 50, 0, generation), None);
        assert_eq!(cache.get("domains", 50, 0, cache.generation()), None);
    }

    #[test]
    fn time_window_is_part_of_the_page_key() {
        let cache = SummaryPageCache::new();
        let generation = cache.generation();
        let first_window = Some((1_000, 2_000));
        let second_window = Some((2_000, 3_000));
        let first_page = vec![serde_json::json!({"window": 1})];
        let second_page = vec![serde_json::json!({"window": 2})];

        cache.insert_window(
            "applications",
            50,
            0,
            generation,
            first_window,
            first_page.clone(),
            1,
        );
        cache.insert_window(
            "applications",
            50,
            0,
            generation,
            second_window,
            second_page.clone(),
            1,
        );

        assert_eq!(
            cache.get_window("applications", 50, 0, generation, first_window),
            Some((first_page, 1))
        );
        assert_eq!(
            cache.get_window("applications", 50, 0, generation, second_window),
            Some((second_page, 1))
        );
        assert_eq!(cache.get("applications", 50, 0, generation), None);
    }
}
