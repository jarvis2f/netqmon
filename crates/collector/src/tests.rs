use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use netqmon_protocol::policy::FlowVerdict;
use netqmon_protocol::v1::probe_result::Outcome as ProbeOutcome;
use netqmon_protocol::v1::{
    AgentHealth, CounterSanityStatus, DeviceDiscoveryObservation, Direction, DnsObservation,
    DnsRecordType, EnrollRequest, EnrollResponse, FaviconProbeResult, FlowDelta, FlowLifecycle,
    FlowScope, NatType, OffloadStatus, PathType, ProbeResult, TelemetryBatch, TopologySummary,
};
use netqmon_protocol::{PROTOCOL_VERSION, encode_telemetry_batch};
use prost::Message;
use tempfile::tempdir;
use tower::ServiceExt;

use super::*;

const ENROLLMENT_TOKEN: &str = "test-enrollment-token";

#[test]
fn rollup_maintenance_retries_only_transient_sqlite_lock_errors() {
    let busy = StorageError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        None,
    ));
    let locked = StorageError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_LOCKED),
        None,
    ));
    let io = StorageError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
        None,
    ));

    assert!(super::should_retry_maintenance_after_error(false, &busy));
    assert!(super::should_retry_maintenance_after_error(false, &locked));
    assert!(!super::should_retry_maintenance_after_error(false, &io));
    assert!(super::should_retry_maintenance_after_error(true, &io));
}

#[allow(unsafe_code)]
fn sqlite_memory_used_bytes() -> u64 {
    // sqlite3_memory_used takes no pointers and only reads SQLite's global byte counter.
    unsafe { rusqlite::ffi::sqlite3_memory_used() }.max(0) as u64
}

#[cfg(feature = "rust-heap-meter")]
#[allow(unsafe_code)]
mod rust_heap_meter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
    static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

    struct TrackingAllocator;

    fn record_allocation(size: usize) {
        if size == 0 {
            return;
        }
        let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
        PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    }

    fn record_deallocation(size: usize) {
        if size != 0 {
            LIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
        }
    }

    // SAFETY: Each method delegates allocation to `System` and updates only
    // atomic accounting. The original pointer and layout are passed unchanged.
    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                record_allocation(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                record_allocation(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
            record_deallocation(layout.size());
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let resized = unsafe { System.realloc(pointer, layout, new_size) };
            if !resized.is_null() {
                if new_size >= layout.size() {
                    record_allocation(new_size - layout.size());
                } else {
                    record_deallocation(layout.size() - new_size);
                }
            }
            resized
        }
    }

    #[global_allocator]
    static ALLOCATOR: TrackingAllocator = TrackingAllocator;

    pub(crate) fn begin() -> usize {
        let current = LIVE_BYTES.load(Ordering::Relaxed);
        PEAK_BYTES.store(current, Ordering::Relaxed);
        current
    }

    pub(crate) fn current() -> usize {
        LIVE_BYTES.load(Ordering::Relaxed)
    }

    pub(crate) fn peak_growth_since(baseline: usize) -> usize {
        PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline)
    }
}

mod clickhouse_compat;
mod client_pagination;
mod concurrency;
mod file_ingest_benchmark;
mod geo_bounded;

// Original expiration behavior, used as a differential oracle.
fn legacy_dns_observe(cache: &mut DnsDomainCache, batch: &TelemetryBatch) {
    for observation in &batch.dns_observations {
        if observation.domain.is_empty() || observation.answer_ip.is_empty() {
            continue;
        }
        let key = DnsDomainKey {
            gateway_id: Arc::from(batch.gateway_id.as_str()),
            client_ip: observation.client_ip.clone(),
            answer_ip: observation.answer_ip.clone(),
        };
        let observed_at = observation.observed_at_unix_ms;
        match cache.entries.get_mut(&key) {
            Some(value) if value.observed_at <= observed_at => {
                value.domain.clone_from(&observation.domain);
                value.observed_at = observed_at;
            }
            Some(_) => {}
            None => {
                cache.entries.insert(
                    key,
                    DnsDomainValue {
                        domain: observation.domain.clone(),
                        observed_at,
                    },
                );
            }
        }
    }
    let oldest = batch.sent_at.saturating_sub(cache.ttl_ms);
    cache.entries.retain(|_, value| value.observed_at >= oldest);
}

#[test]
fn dns_cache_expiration_matches_full_scan_with_out_of_order_batches() {
    let mut optimized = DnsDomainCache {
        ttl_ms: 100,
        ..Default::default()
    };
    let mut original = DnsDomainCache {
        ttl_ms: 100,
        ..Default::default()
    };
    let mut seed = 7123_u64;
    for step in 0..3000_u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let sent_at = (step / 3).saturating_sub((seed >> 20) % 50);
        let observation = DnsObservation {
            client_ip: vec![192, 0, 2, (seed % 5) as u8],
            answer_ip: if seed % 41 == 0 {
                vec![]
            } else {
                vec![198, 51, 100, (seed >> 8) as u8]
            },
            domain: if seed % 43 == 0 {
                String::new()
            } else {
                format!("{}.example", seed % 100)
            },
            observed_at_unix_ms: sent_at.saturating_sub((seed >> 16) % 130) + (seed >> 24) % 10,
            ..Default::default()
        };
        let batch = TelemetryBatch {
            gateway_id: format!("gw-{}", seed % 3),
            sent_at,
            dns_observations: vec![observation],
            ..Default::default()
        };
        optimized.observe(&batch);
        legacy_dns_observe(&mut original, &batch);
        assert_eq!(optimized.entries, original.entries, "step {step}");
        assert!(optimized.entries.values().all(|value| {
            optimized
                .oldest_observed_at
                .is_some_and(|oldest| oldest <= value.observed_at)
        }));
    }
    let flush = TelemetryBatch {
        sent_at: 10_000,
        ..Default::default()
    };
    optimized.observe(&flush);
    assert!(optimized.entries.is_empty());
    assert!(optimized.oldest_observed_at.is_none());
}

#[test]
fn dns_cache_refresh_of_oldest_preserves_inclusive_ttl_boundary() {
    let mut cache = DnsDomainCache {
        ttl_ms: 100,
        ..Default::default()
    };
    let batch = |sent_at, observed_at| TelemetryBatch {
        gateway_id: "gw".into(),
        sent_at,
        dns_observations: vec![DnsObservation {
            client_ip: vec![1],
            answer_ip: vec![2],
            domain: "example.org".into(),
            observed_at_unix_ms: observed_at,
            ..Default::default()
        }],
        ..Default::default()
    };
    cache.observe(&batch(100, 100));
    cache.observe(&batch(200, 200));
    cache.observe(&TelemetryBatch {
        sent_at: 250,
        ..Default::default()
    });
    assert_eq!(cache.oldest_observed_at, Some(200));
    cache.observe(&TelemetryBatch {
        sent_at: 300,
        ..Default::default()
    });
    assert_eq!(cache.resolve("gw", &[1], &[2], 300), Some("example.org"));
    cache.observe(&TelemetryBatch {
        sent_at: 301,
        ..Default::default()
    });
    assert!(cache.entries.is_empty());
    assert_eq!(cache.oldest_observed_at, None);
}

#[test]
fn dns_cache_capacity_bounds_entries_and_expires_fallback_window() {
    let mut cache = DnsDomainCache {
        ttl_ms: 100,
        max_entries: 1,
        ..Default::default()
    };
    let observation = |client, answer, sent_at| TelemetryBatch {
        gateway_id: "gw".into(),
        sent_at,
        dns_observations: vec![DnsObservation {
            client_ip: vec![client],
            answer_ip: vec![answer],
            domain: format!("{answer}.example"),
            observed_at_unix_ms: sent_at,
            ..Default::default()
        }],
        ..Default::default()
    };
    cache.observe(&observation(1, 2, 1_000));
    cache.observe(&observation(3, 4, 1_010));
    assert_eq!(cache.entries.len(), 1);
    assert!(cache.has_live_evicted_history());
    cache.observe(&TelemetryBatch {
        sent_at: 1_101,
        ..Default::default()
    });
    assert!(!cache.has_live_evicted_history());
}

#[test]
#[ignore = "manual DNS cache scan benchmark"]
fn dns_cache_idle_scan_benchmark() {
    use std::time::Instant;
    let count: u32 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let mut optimized = DnsDomainCache {
        max_entries: usize::try_from(count).unwrap().saturating_add(1),
        ..Default::default()
    };
    let mut original = DnsDomainCache::default();
    let batch = TelemetryBatch {
        gateway_id: "benchmark".into(),
        sent_at: 1_000,
        dns_observations: (0..count)
            .map(|n| DnsObservation {
                client_ip: vec![192, 0, 2, 1],
                answer_ip: n.to_be_bytes().to_vec(),
                domain: format!("host-{n}.example"),
                observed_at_unix_ms: 1_000,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    #[cfg(feature = "rust-heap-meter")]
    let cache_heap_before = rust_heap_meter::begin();
    optimized.observe(&batch);
    #[cfg(feature = "rust-heap-meter")]
    let cache_heap_bytes = rust_heap_meter::current().saturating_sub(cache_heap_before);
    legacy_dns_observe(&mut original, &batch);
    #[cfg(not(feature = "rust-heap-meter"))]
    let cache_heap_bytes: Option<usize> = None;
    #[cfg(feature = "rust-heap-meter")]
    let cache_heap_bytes = Some(cache_heap_bytes);
    let idle = TelemetryBatch {
        sent_at: 2_000,
        ..Default::default()
    };
    let mut times = [Vec::new(), Vec::new()];
    for iteration in 0..200 {
        for pass in 0..2 {
            let current = (iteration + pass) % 2;
            let start = Instant::now();
            if current == 0 {
                legacy_dns_observe(&mut original, &idle);
            } else {
                optimized.observe(&idle);
            }
            times[current].push(start.elapsed().as_nanos());
        }
    }
    assert_eq!(original.entries, optimized.entries);
    for (name, values) in ["before", "after"].into_iter().zip(&mut times) {
        values.sort_unstable();
        eprintln!(
            "dns_cache_rows={count} cache_heap_bytes={cache_heap_bytes:?} {name} p50_ns={} p95_ns={} p99_ns={}",
            values[100], values[190], values[198]
        );
    }
    // Also measure an actual expiration sweep. Clone outside the timed region
    // and alternate order; half the entries survive the cutoff.
    for (key, value) in &mut original.entries {
        if key.answer_ip[3] % 2 == 0 {
            value.observed_at = 2_000;
        }
    }
    let expiration = TelemetryBatch {
        sent_at: original.ttl_ms + 1_500,
        ..Default::default()
    };
    let mut sweeps = [Vec::new(), Vec::new()];
    for iteration in 0..10 {
        let mut before = DnsDomainCache {
            entries: original.entries.clone(),
            ..Default::default()
        };
        let mut after = DnsDomainCache {
            entries: original.entries.clone(),
            oldest_observed_at: Some(1_000),
            ..Default::default()
        };
        for pass in 0..2 {
            let current = (iteration + pass) % 2;
            let start = Instant::now();
            if current == 0 {
                legacy_dns_observe(&mut before, &expiration);
            } else {
                after.observe(&expiration);
            }
            sweeps[current].push(start.elapsed().as_micros());
        }
        assert_eq!(before.entries, after.entries);
    }
    for (name, values) in ["before", "after"].into_iter().zip(&mut sweeps) {
        values.sort_unstable();
        eprintln!(
            "dns_cache_expiration_rows={count} {name} p50_us={} max_us={}",
            values[5], values[9]
        );
    }
}

#[test]
#[ignore = "manual file-backed DNS cache fallback benchmark"]
fn file_dns_history_fallback_benchmark() {
    use std::time::Instant;
    let count: u32 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);
    assert!((1..=MAX_FLOWS_PER_BATCH as u32).contains(&count));
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("dns-fallback.db")).unwrap();
    sqlite
        .save_gateway(
            "dns-fallback-benchmark",
            "benchmark",
            "test",
            &[42; 32],
            1_700_000_000_000,
        )
        .unwrap();
    let base = 1_700_000_000_000_u64;
    let dns_batch = TelemetryBatch {
        gateway_id: "dns-fallback-benchmark".to_owned(),
        boot_id: "dns-fallback-benchmark".to_owned(),
        sequence: 1,
        sent_at: base + 1_000,
        dns_observations: (0..count)
            .map(|id| DnsObservation {
                client_ip: (0x0a00_0001_u32 + id).to_be_bytes().to_vec(),
                answer_ip: (0xc633_6400_u32 + id).to_be_bytes().to_vec(),
                domain: format!("host-{id}.example"),
                observed_at_unix_ms: base,
                ttl_seconds: 1,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    sqlite.persist_batch(&dns_batch, base + 1_000).unwrap();
    sqlite
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let mut evicted_cache = DnsDomainCache {
        max_entries: 1,
        ..Default::default()
    };
    evicted_cache.observe(&dns_batch);
    assert!(evicted_cache.has_live_evicted_history());
    let cached_domain_cache = DnsDomainCache {
        max_entries: count as usize + 1,
        ..Default::default()
    };
    let mut cached_domain_cache = cached_domain_cache;
    cached_domain_cache.observe(&dns_batch);

    let flow_batch = TelemetryBatch {
        gateway_id: dns_batch.gateway_id.clone(),
        sent_at: base + 20_000,
        flows: (0..count)
            .map(|id| FlowDelta {
                client_ip: (0x0a00_0001_u32 + id).to_be_bytes().to_vec(),
                remote_ip: (0xc633_6400_u32 + id).to_be_bytes().to_vec(),
                protocol: 17,
                remote_port: 443,
                last_seen_unix_ms: base + 20_000,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let analyses = vec![
        Some(dpi::SampleAnalysis {
            dpi: Some(dpi::engine::DpiResult {
                protocol: "quic".to_owned(),
                source: "benchmark".to_owned(),
                confidence: 1.0,
                metadata: std::collections::BTreeMap::new(),
            }),
            signatures: Vec::new(),
        });
        count as usize
    ];
    let storage = Storage::sqlite(sqlite);
    let no_domains = vec![None; count as usize];
    let mut cached_times = Vec::new();
    let mut fallback_times = Vec::new();
    for iteration in 0..5 {
        for pass in 0..2 {
            let cached_first = (iteration + pass) % 2 == 0;
            let started = Instant::now();
            let domains = resolve_batch_domains(&storage, &flow_batch).unwrap();
            assert!(domains.iter().all(Option::is_none));
            if cached_first {
                let cached = flow_batch
                    .flows
                    .iter()
                    .map(|flow| {
                        cached_domain_cache
                            .resolve(
                                &flow_batch.gateway_id,
                                &flow.client_ip,
                                &flow.remote_ip,
                                flow.last_seen_unix_ms,
                            )
                            .map(str::to_owned)
                    })
                    .collect::<Vec<_>>();
                assert!(cached.iter().all(Option::is_some));
                cached_times.push(started.elapsed().as_micros());
            } else {
                let fallback = resolve_evicted_dns_domains(
                    &storage,
                    &evicted_cache,
                    &flow_batch,
                    &analyses,
                    &no_domains,
                )
                .unwrap();
                for (index, flow) in flow_batch.flows.iter().enumerate() {
                    let actual = evicted_cache
                        .resolve(
                            &flow_batch.gateway_id,
                            &flow.client_ip,
                            &flow.remote_ip,
                            flow.last_seen_unix_ms,
                        )
                        .map(str::to_owned)
                        .or_else(|| fallback[index].clone());
                    assert_eq!(actual, Some(format!("host-{index}.example")));
                }
                fallback_times.push(started.elapsed().as_micros());
            }
        }
    }
    cached_times.sort_unstable();
    fallback_times.sort_unstable();
    eprintln!(
        "dns_fallback_file rows={count} db_bytes={} wal_bytes={} cache_path_p50_us={} fallback_path_p50_us={} cache_entries={} fallback_entries={}",
        std::fs::metadata(directory.path().join("dns-fallback.db"))
            .unwrap()
            .len(),
        std::fs::metadata(directory.path().join("dns-fallback.db-wal"))
            .map(|metadata| metadata.len())
            .unwrap_or(0),
        cached_times[2],
        fallback_times[2],
        cached_domain_cache.entries.len(),
        evicted_cache.entries.len()
    );
}

#[test]
#[ignore = "manual file-backed DNS cache capacity and memory benchmark"]
fn file_dns_cache_capacity_memory_benchmark() {
    let rows: u64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let batch_size = 10_000_u64;
    assert!(rows > 0 && rows <= 10_000_000);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dns-capacity.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway(
            "dns-capacity-benchmark",
            "benchmark",
            "test",
            &[42; 32],
            1_700_000_000_000,
        )
        .unwrap();
    let sqlite_before = sqlite_memory_used_bytes();
    #[cfg(feature = "rust-heap-meter")]
    let heap_before = rust_heap_meter::begin();
    let mut cache = DnsDomainCache::default();
    for sequence in 0..rows.div_ceil(batch_size) {
        let first = sequence * batch_size;
        let count = (rows - first).min(batch_size);
        let sent_at = 1_700_000_000_000_u64 + sequence * 1_000;
        let batch = TelemetryBatch {
            gateway_id: "dns-capacity-benchmark".to_owned(),
            boot_id: "dns-capacity-benchmark".to_owned(),
            sequence: sequence + 1,
            sent_at,
            dns_observations: (first..first + count)
                .map(|id| DnsObservation {
                    client_ip: (0x0a00_0001_u32 + (id % 65_536) as u32)
                        .to_be_bytes()
                        .to_vec(),
                    answer_ip: (0xc633_6400_u32 + id as u32).to_be_bytes().to_vec(),
                    domain: format!("host-{id}.example"),
                    observed_at_unix_ms: sent_at,
                    ttl_seconds: 3_600,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        cache.observe(&batch);
        sqlite.persist_batch(&batch, sent_at).unwrap();
    }
    assert_eq!(
        cache.entries.len(),
        usize::try_from(rows)
            .unwrap()
            .min(DNS_DOMAIN_CACHE_MAX_ENTRIES)
    );
    assert_eq!(
        cache.has_live_evicted_history(),
        rows > DNS_DOMAIN_CACHE_MAX_ENTRIES as u64
    );
    let persisted: i64 = sqlite
        .connection()
        .query_row("SELECT COUNT(*) FROM dns_observations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(persisted, rows as i64);
    sqlite
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let sqlite_after = sqlite_memory_used_bytes();
    #[cfg(feature = "rust-heap-meter")]
    let heap_live = rust_heap_meter::current().saturating_sub(heap_before);
    #[cfg(not(feature = "rust-heap-meter"))]
    let heap_live: Option<usize> = None;
    #[cfg(feature = "rust-heap-meter")]
    let heap_live = Some(heap_live);
    #[cfg(feature = "rust-heap-meter")]
    let heap_peak = Some(rust_heap_meter::peak_growth_since(heap_before));
    #[cfg(not(feature = "rust-heap-meter"))]
    let heap_peak: Option<usize> = None;
    eprintln!(
        "dns_cache_capacity_file rows={rows} batches={} cache_entries={} evicted_history={} db_bytes={} wal_bytes={} cache_heap_live_bytes={heap_live:?} heap_peak_growth_bytes={heap_peak:?} sqlite_allocator_before={sqlite_before} sqlite_allocator_after={sqlite_after}",
        rows.div_ceil(batch_size),
        cache.entries.len(),
        cache.has_live_evicted_history(),
        std::fs::metadata(&path).unwrap().len(),
        std::fs::metadata(format!("{}-wal", path.display()))
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    );
}

#[test]
fn dns_history_is_scoped_by_client_and_answer_ip() {
    let batch = TelemetryBatch {
        gateway_id: "gw-test".to_owned(),
        sent_at: 20_000,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 168, 2, 88],
            answer_ip: vec![101, 70, 9, 104],
            domain: "api-play.amemv.com".to_owned(),
            observed_at_unix_ms: 1_000,
            ttl_seconds: 10,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut cache = DnsDomainCache::default();
    cache.observe(&batch);
    assert_eq!(
        cache.resolve("gw-test", &[192, 168, 2, 88], &[101, 70, 9, 104], 20_000),
        Some("api-play.amemv.com")
    );
    assert_eq!(
        cache.resolve("gw-test", &[192, 168, 2, 89], &[101, 70, 9, 104], 20_000),
        None
    );
}

#[test]
fn expired_dns_history_classifies_quic_without_sni() {
    let state = test_state_with_repository_rules();
    let inner = state.lock();
    let mut dns_domains = DnsDomainCache::default();
    dns_domains.observe(&TelemetryBatch {
        gateway_id: "gw-test".to_owned(),
        sent_at: 1_000,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 168, 2, 88],
            answer_ip: vec![198, 51, 100, 1],
            domain: "www.youtube.com".to_owned(),
            observed_at_unix_ms: 1_000,
            ttl_seconds: 10,
            ..Default::default()
        }],
        ..Default::default()
    });
    let batch = TelemetryBatch {
        gateway_id: "gw-test".to_owned(),
        sent_at: 20_000,
        flows: vec![FlowDelta {
            client_ip: vec![192, 168, 2, 88],
            remote_ip: vec![198, 51, 100, 1],
            protocol: 17,
            remote_port: 443,
            last_seen_unix_ms: 20_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let dpi = dpi::engine::DpiResult {
        protocol: "quic".into(),
        source: "ndpi".into(),
        confidence: 1.0,
        metadata: std::collections::BTreeMap::new(),
    };
    let result = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut ServiceBindingCache::default(),
        &dns_domains,
        &FaviconEndpointCache::default(),
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: Some(dpi),
            signatures: Vec::new(),
        })],
        false,
    )
    .unwrap();
    assert_eq!(result[0].application_id, "youtube");
}

#[test]
fn evicted_dns_cache_history_is_recovered_from_file_database() {
    let directory = tempfile::tempdir().unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open(directory.path().join("dns-history-fallback.db")).unwrap(),
        repository_rule_engine(),
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "dns-history-fallback".to_owned(),
            gateway_name: "dns-history-fallback".to_owned(),
        })
        .unwrap();
    let base = 1_700_000_000_000_u64;
    let mut dns_domains = DnsDomainCache {
        max_entries: 1,
        ..Default::default()
    };
    for (sequence, client_ip, answer_ip, domain) in [
        (
            1,
            vec![192, 0, 2, 88],
            vec![198, 51, 100, 1],
            "www.youtube.com",
        ),
        (
            2,
            vec![192, 0, 2, 89],
            vec![198, 51, 100, 2],
            "other.example",
        ),
    ] {
        let batch = TelemetryBatch {
            gateway_id: enrollment.gateway_id.clone(),
            boot_id: "dns-history-fallback".to_owned(),
            sequence,
            sent_at: base + sequence * 1_000,
            dns_observations: vec![DnsObservation {
                client_ip,
                answer_ip,
                domain: domain.to_owned(),
                observed_at_unix_ms: base,
                ttl_seconds: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        dns_domains.observe(&batch);
        state
            .lock()
            .storage
            .persist_batch(&batch, batch.sent_at)
            .unwrap();
    }
    assert_eq!(dns_domains.entries.len(), 1);
    assert!(dns_domains.has_live_evicted_history());

    let batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        sent_at: base + 20_000,
        flows: vec![FlowDelta {
            client_mac: vec![2, 0, 0, 0, 0, 1],
            client_ip: vec![192, 0, 2, 88],
            remote_ip: vec![198, 51, 100, 1],
            ip_version: 4,
            protocol: 17,
            remote_port: 443,
            client_port: 50_000,
            direction: Direction::Upload as i32,
            first_seen_unix_ms: base + 20_000,
            last_seen_unix_ms: base + 20_000,
            lifecycle: FlowLifecycle::Ended as i32,
            ..Default::default()
        }],
        ..Default::default()
    };
    dns_domains.observe(&batch);
    let query_reader = state
        .query_storage
        .as_ref()
        .unwrap()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .query_reader()
        .unwrap()
        .unwrap();
    let domains = resolve_batch_domains(&query_reader, &batch).unwrap();
    assert_eq!(domains, vec![None]);
    let analyses = vec![Some(dpi::SampleAnalysis {
        dpi: Some(dpi::engine::DpiResult {
            protocol: "quic".to_owned(),
            source: "ndpi".to_owned(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::new(),
        }),
        signatures: Vec::new(),
    })];
    let recovered =
        resolve_evicted_dns_domains(&query_reader, &dns_domains, &batch, &analyses, &domains)
            .unwrap();
    assert_eq!(recovered, vec![Some("www.youtube.com".to_owned())]);
    let inner = state.lock();
    let attribution = classify_resolved_batch(
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut ServiceBindingCache::default(),
        &dns_domains,
        &FaviconEndpointCache::default(),
        &batch,
        &analyses,
        false,
        &domains,
        &recovered,
    )
    .unwrap();
    assert_eq!(attribution[0].application_id, "youtube");
}

#[test]
fn batch_dns_history_overrides_an_older_persisted_observation_after_eviction() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("dns-batch-history.db")).unwrap();
    let gateway_id = "dns-batch-history";
    sqlite
        .save_gateway(gateway_id, "router", "test", &[17; 32], 1_700_000_000_000)
        .unwrap();
    let base = 1_700_000_000_000_u64;
    let old_dns_batch = TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        boot_id: "dns-batch-history".to_owned(),
        sequence: 1,
        sent_at: base + 1_000,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 88],
            answer_ip: vec![198, 51, 100, 88],
            domain: "old.example".to_owned(),
            observed_at_unix_ms: base,
            ttl_seconds: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    sqlite
        .persist_batch(&old_dns_batch, old_dns_batch.sent_at)
        .unwrap();

    let mut dns_domains = DnsDomainCache {
        max_entries: 1,
        ..Default::default()
    };
    dns_domains.observe(&TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        sent_at: base + 5_000,
        dns_observations: vec![
            DnsObservation {
                client_ip: vec![192, 0, 2, 90],
                answer_ip: vec![198, 51, 100, 90],
                domain: "unrelated-a.example".to_owned(),
                observed_at_unix_ms: base + 4_000,
                ttl_seconds: 60,
                ..Default::default()
            },
            DnsObservation {
                client_ip: vec![192, 0, 2, 91],
                answer_ip: vec![198, 51, 100, 91],
                domain: "unrelated-b.example".to_owned(),
                observed_at_unix_ms: base + 4_000,
                ttl_seconds: 60,
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    assert!(dns_domains.has_live_evicted_history());

    let batch = TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        sent_at: base + 20_000,
        flows: vec![FlowDelta {
            client_ip: vec![192, 0, 2, 88],
            remote_ip: vec![198, 51, 100, 88],
            protocol: 17,
            remote_port: 443,
            last_seen_unix_ms: base + 20_000,
            ..Default::default()
        }],
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 88],
            answer_ip: vec![198, 51, 100, 88],
            domain: "new.example".to_owned(),
            observed_at_unix_ms: base + 15_000,
            ttl_seconds: 60,
            ..Default::default()
        }],
        ..Default::default()
    };
    let analyses = vec![Some(dpi::SampleAnalysis {
        dpi: Some(dpi::engine::DpiResult {
            protocol: "quic".to_owned(),
            source: "test".to_owned(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::new(),
        }),
        signatures: Vec::new(),
    })];
    let storage = Storage::sqlite(sqlite);
    let recovered =
        resolve_evicted_dns_domains(&storage, &dns_domains, &batch, &analyses, &[None]).unwrap();
    assert_eq!(recovered, vec![Some("new.example".to_owned())]);
}

#[test]
fn ambiguous_high_confidence_application_signatures_fall_back_to_default() {
    use crate::dpi::SignatureApplicationMatch;

    let signatures = vec![
        SignatureApplicationMatch {
            application_id: "netqmon_qos_test".to_owned(),
            confidence: 0.99,
            signature_hits: 1,
        },
        SignatureApplicationMatch {
            application_id: "netqmon_qos_ambiguous".to_owned(),
            confidence: 0.99,
            signature_hits: 1,
        },
    ];
    assert_eq!(
        ambiguous_signature_application_ids(&signatures),
        ["netqmon_qos_ambiguous", "netqmon_qos_test"]
    );

    let same_application = vec![
        SignatureApplicationMatch {
            application_id: "netqmon_qos_test".to_owned(),
            confidence: 0.99,
            signature_hits: 1,
        },
        SignatureApplicationMatch {
            application_id: "netqmon_qos_test".to_owned(),
            confidence: 0.95,
            signature_hits: 1,
        },
    ];
    assert!(ambiguous_signature_application_ids(&same_application).is_empty());

    let low_confidence_collision = vec![
        SignatureApplicationMatch {
            application_id: "netqmon_qos_test".to_owned(),
            confidence: 0.99,
            signature_hits: 1,
        },
        SignatureApplicationMatch {
            application_id: "weak_candidate".to_owned(),
            confidence: 0.79,
            signature_hits: 1,
        },
    ];
    assert!(ambiguous_signature_application_ids(&low_confidence_collision).is_empty());
}

#[test]
fn lifecycle_without_new_evidence_keeps_a_flow_verdict_but_end_revokes_it() {
    let service = policy::PolicyService::open_in_memory().unwrap();
    let hub = PolicyHub::new();
    let bundle = hub.refresh_gateway(&service, "gw-test", false).unwrap();
    let epoch = bundle.frame.snapshot_identity().unwrap().1.to_owned();
    let session = hub.register("gw-test").unwrap();
    let now = policy::push::now_ms();
    let flow_id = "00000000000000000000000000000001";
    hub.queue_flow_command(PolicyWireFrame::FlowCommand {
        wire_version: POLICY_WIRE_VERSION,
        gateway_id: "gw-test".to_owned(),
        boot_id: "boot-test".to_owned(),
        controller_epoch: epoch,
        config_revision: 0,
        command_id: uuid::Uuid::new_v4().to_string(),
        policy_flow_id: flow_id.to_owned(),
        operation: FlowCommandOperation::Upsert,
        verdict: Some(FlowVerdict::Block),
        policy_ids: vec!["00000000-0000-4000-8000-000000000001".to_owned()],
        issued_at_ms: now,
        expires_at_ms: now + 120_000,
    })
    .unwrap();
    assert!(
        hub.take_flow_command(&session, 0, Some("boot-test"))
            .is_some()
    );
    let mut batch = TelemetryBatch {
        gateway_id: "gw-test".to_owned(),
        boot_id: "boot-test".to_owned(),
        flows: vec![FlowDelta {
            policy_flow_id: flow_id.to_owned(),
            lifecycle: FlowLifecycle::Idle as i32,
            scope: FlowScope::Internet as i32,
            client_mac: vec![2, 0, 0, 0, 1, 35],
            protocol: 6,
            ..Default::default()
        }],
        ..Default::default()
    };
    for lifecycle in [FlowLifecycle::Active, FlowLifecycle::Idle] {
        batch.flows[0].lifecycle = lifecycle as i32;
        queue_policy_flow_decisions(&hub, &batch, &[FlowAttribution::default()]);
        assert!(
            hub.take_flow_command(&session, 0, Some("boot-test"))
                .is_none()
        );
    }
    batch.flows[0].lifecycle = FlowLifecycle::Ended as i32;
    queue_policy_flow_decisions(&hub, &batch, &[FlowAttribution::default()]);
    assert!(matches!(
        hub.take_flow_command(&session, 0, Some("boot-test")),
        Some(PolicyWireFrame::FlowCommand {
            operation: FlowCommandOperation::Revoke,
            ..
        })
    ));
}

#[test]
fn late_dpi_recovers_exact_client_context_and_queues_block() {
    let state = test_state_with_repository_rules();
    let gateway = "gw-late";
    let mac = vec![2, 0, 0, 0, 1, 35];
    let spec = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "gateway_id": gateway, "name": "Block YouTube", "description": "", "enabled": true, "priority": 500,
        "selectors": {"clients": ["02:00:00:00:01:23"], "applications": ["youtube"], "categories": [], "min_application_confidence": 0.85},
        "network": {"scope": "internet", "direction": "both"},
        "action": {"type": "block", "download_bps": null, "upload_bps": null}, "schedule": null
    })).unwrap();
    state.policy_service.create(&spec, "admin", 0).unwrap();
    let bundle = state
        .policy_hub
        .refresh_gateway(&state.policy_service, gateway, false)
        .unwrap();
    let session = state.policy_hub.register(gateway).unwrap();
    state.policy_hub.record_flow_capabilities(
        &session,
        bundle.frame.snapshot_identity().unwrap().2,
        &netqmon_protocol::policy::PolicyCapabilities {
            application_block: netqmon_protocol::policy::PolicyCapability::Degraded,
            ..netqmon_protocol::policy::PolicyCapabilities::unsupported()
        },
    );
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50_000,
        remote_ip: vec![198, 51, 100, 1],
        remote_port: 443,
        client_mac: mac,
        scope: FlowScope::Internet as i32,
        lifecycle: FlowLifecycle::Active as i32,
        direction: Direction::Upload as i32,
        packets: 3,
        upload_bytes: 500,
        first_seen_unix_ms: 1_000,
        last_seen_unix_ms: 1_100,
        policy_flow_id: "00000000000000000000000000000001".into(),
        ..Default::default()
    };
    let batch = TelemetryBatch {
        gateway_id: gateway.into(),
        boot_id: "boot-late".into(),
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state
        .lock()
        .policy_flow_contexts
        .observe(&batch, std::time::Instant::now());
    let mut sample = dpi::CachedResult::for_test(
        gateway.into(),
        batch.boot_id.clone(),
        netqmon_protocol::v1::FlowSampleKey {
            ip_version: 4,
            protocol: 6,
            client_ip: flow.client_ip.clone(),
            client_port: flow.client_port,
            remote_ip: flow.remote_ip.clone(),
            remote_port: flow.remote_port,
            first_seen_unix_ms: 1_000,
        },
        1_100,
        Some(dpi::engine::DpiResult {
            protocol: "tls".into(),
            confidence: 1.0,
            source: "ndpi".into(),
            metadata: std::collections::BTreeMap::from([(
                "hostname".into(),
                "www.youtube.com".into(),
            )]),
        }),
    );
    sample.policy_flow_ids.push(flow.policy_flow_id.clone());
    let decisions = apply_sample_result(&mut state.lock(), &sample).unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].1.application_id, "youtube");
    queue_policy_flow_decisions(
        &state.policy_hub,
        &decisions[0].0,
        std::slice::from_ref(&decisions[0].1),
    );
    assert!(
        matches!(state.policy_hub.take_flow_command(&session, 1, Some("boot-late")), Some(PolicyWireFrame::FlowCommand {
        operation: FlowCommandOperation::Upsert, verdict: Some(FlowVerdict::Block), policy_flow_id, ..
    }) if policy_flow_id == flow.policy_flow_id)
    );
    sample.boot = "another-boot".into();
    assert!(
        apply_sample_result(&mut state.lock(), &sample)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn policy_revision_re_evaluates_active_flow_with_allow_and_keeps_matching_limit() {
    use netqmon_protocol::policy::{PolicyCapabilities, PolicyCapability};

    let service = policy::PolicyService::open_in_memory().unwrap();
    let gateway = "gw-flow-revision";
    let mac = "02:00:00:00:01:23";
    let block = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "gateway_id": gateway,
        "name": "Block target app",
        "description": "",
        "enabled": true,
        "priority": 20,
        "selectors": {"clients": [mac], "applications": ["netqmon_qos_test"],
            "categories": [], "min_application_confidence": 0.95},
        "network": {"scope": "internet", "direction": "both"},
        "action": {"type": "block", "download_bps": null, "upload_bps": null},
        "schedule": null
    }))
    .unwrap();
    let block = service.create(&block, "test", 0).unwrap();
    let limit = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "gateway_id": gateway,
        "name": "Limit target app",
        "description": "",
        "enabled": true,
        "priority": 50,
        "selectors": {"clients": [mac], "applications": ["netqmon_qos_test"],
            "categories": [], "min_application_confidence": 0.95},
        "network": {"scope": "internet", "direction": "both"},
        "action": {"type": "limit", "download_bps": 4_000_000, "upload_bps": 2_000_000},
        "schedule": null
    }))
    .unwrap();
    let limit_mutation = service.create(&limit, "test", block.revision).unwrap();
    let limit_revision = limit_mutation.revision;
    let limit = limit_mutation.policy.unwrap();

    let hub = PolicyHub::new();
    let bundle = hub.refresh_gateway(&service, gateway, false).unwrap();
    let revision = bundle.frame.snapshot_identity().unwrap().2;
    let session = hub.register(gateway).unwrap();
    let capabilities = PolicyCapabilities {
        application_block: PolicyCapability::Supported,
        application_limit: PolicyCapability::Supported,
        ..PolicyCapabilities::unsupported()
    };
    hub.record_flow_capabilities(&session, revision, &capabilities);

    let flow_id = "000000000000000000000000000000af";
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50_000,
        remote_ip: vec![198, 51, 100, 1],
        remote_port: 443,
        client_mac: vec![2, 0, 0, 0, 1, 35],
        scope: FlowScope::Internet as i32,
        lifecycle: FlowLifecycle::Active as i32,
        direction: Direction::Upload as i32,
        packets: 3,
        upload_bytes: 500,
        first_seen_unix_ms: 1_000,
        last_seen_unix_ms: 1_100,
        policy_flow_id: flow_id.to_owned(),
        ..Default::default()
    };
    let batch = TelemetryBatch {
        gateway_id: gateway.to_owned(),
        boot_id: "boot-flow-revision".to_owned(),
        flows: vec![flow],
        ..Default::default()
    };
    queue_policy_flow_decisions(
        &hub,
        &batch,
        &[strong_self_host_attribution("netqmon_qos_test")],
    );
    assert!(matches!(
        hub.take_flow_command(&session, revision, Some("boot-flow-revision")),
        Some(PolicyWireFrame::FlowCommand {
            policy_flow_id,
            verdict: Some(FlowVerdict::Block),
            ..
        }) if policy_flow_id == flow_id
    ));

    let allow = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "gateway_id": gateway,
        "name": "Allow target app",
        "description": "",
        "enabled": true,
        "priority": 10,
        "selectors": {"clients": [mac], "applications": ["netqmon_qos_test"],
            "categories": [], "min_application_confidence": 0.95},
        "network": {"scope": "internet", "direction": "both"},
        "action": {"type": "allow", "download_bps": null, "upload_bps": null},
        "schedule": null
    }))
    .unwrap();
    let allow = service
        .create(&allow, "test", limit_revision)
        .unwrap()
        .policy
        .unwrap();
    let bundle = hub.refresh_gateway(&service, gateway, false).unwrap();
    let next_revision = bundle.frame.snapshot_identity().unwrap().2;
    hub.record_flow_capabilities(&session, next_revision, &capabilities);
    let re_evaluated = hub
        .take_flow_command(&session, next_revision, Some("boot-flow-revision"))
        .unwrap();
    assert!(matches!(
        re_evaluated,
        PolicyWireFrame::FlowCommand {
            operation: FlowCommandOperation::Upsert,
            policy_flow_id,
            verdict: Some(FlowVerdict::Shape),
            ref policy_ids,
            config_revision,
            ..
        } if policy_flow_id == flow_id && policy_ids == &[limit.id.clone()] && config_revision == next_revision
    ));

    let PolicyWireFrame::PolicySnapshot { policies, .. } = &bundle.frame else {
        unreachable!();
    };
    let preview = policy::evaluate_preview(
        &policy::PolicyPreviewRequest {
            gateway_id: gateway.to_owned(),
            client_mac: mac.to_owned(),
            application_id: "netqmon_qos_test".to_owned(),
            category_id: "streaming".to_owned(),
            application_confidence: 0.99,
            scope: "internet".to_owned(),
            at_ms: policy::push::now_ms(),
        },
        policies,
        true,
        true,
    );
    assert_eq!(preview.selected_block_verdict, "allow");
    assert!(
        preview
            .matched_policies
            .iter()
            .any(|row| row.policy_id == allow.id && row.selected)
    );
    assert!(
        preview
            .active_limits
            .iter()
            .any(|row| row.policy_id == limit.id && row.status == "supported")
    );
}

fn strong_self_host_attribution(application_id: &str) -> FlowAttribution {
    FlowAttribution {
        organization_id: "self_host_org".to_owned(),
        application_id: application_id.to_owned(),
        category_id: "streaming".to_owned(),
        application_confidence: 0.99,
        confidence: 0.99,
        reason: format!("domain_exact:{application_id}.home.arpa"),
        evidence_json: format!(
            r#"[{{"type":"self_host_application","value":"{application_id}","source":"rule","weight":0.99}}]"#
        ),
        ..FlowAttribution::default()
    }
}

#[test]
fn initial_allow_and_limit_evaluation_sends_shape_for_the_active_limit() {
    use netqmon_protocol::policy::{PolicyCapabilities, PolicyCapability};

    let service = policy::PolicyService::open_in_memory().unwrap();
    let gateway = "gw-allow-limit-initial";
    let mac = "02:00:00:00:01:23";
    let create = |name: &str, priority: u16, action: serde_json::Value| {
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"gateway_id":gateway,"name":name,"description":"",
            "enabled":true,"priority":priority,
            "selectors":{"clients":[mac],"applications":["netqmon_qos_test"],
                "categories":[],"min_application_confidence":0.95},
            "network":{"scope":"internet","direction":"both"},
            "action":action,"schedule":null
        }))
        .unwrap()
    };
    let block = service
        .create(
            &create(
                "Block app",
                20,
                serde_json::json!({
            "type":"block","download_bps":null,"upload_bps":null}),
            ),
            "test",
            0,
        )
        .unwrap()
        .policy
        .unwrap();
    let limit = service
        .create(
            &create(
                "Limit app",
                50,
                serde_json::json!({
            "type":"limit","download_bps":4_000_000,"upload_bps":2_000_000}),
            ),
            "test",
            1,
        )
        .unwrap()
        .policy
        .unwrap();
    let allow = service
        .create(
            &create(
                "Allow app",
                10,
                serde_json::json!({
            "type":"allow","download_bps":null,"upload_bps":null}),
            ),
            "test",
            2,
        )
        .unwrap()
        .policy
        .unwrap();

    let hub = PolicyHub::new();
    let bundle = hub.refresh_gateway(&service, gateway, false).unwrap();
    let revision = bundle.frame.snapshot_identity().unwrap().2;
    let session = hub.register(gateway).unwrap();
    hub.record_flow_capabilities(
        &session,
        revision,
        &PolicyCapabilities {
            application_block: PolicyCapability::Supported,
            application_limit: PolicyCapability::Supported,
            ..PolicyCapabilities::unsupported()
        },
    );
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 2],
        client_port: 48_016,
        remote_ip: vec![203, 0, 113, 9],
        remote_port: 7_000,
        client_mac: vec![2, 0, 0, 0, 1, 35],
        scope: FlowScope::Internet as i32,
        lifecycle: FlowLifecycle::Active as i32,
        direction: Direction::Download as i32,
        packets: 3,
        download_bytes: 1_024,
        first_seen_unix_ms: 1_000,
        last_seen_unix_ms: 1_100,
        policy_flow_id: "000000000000000000000000000000af".to_owned(),
        ..Default::default()
    };
    let batch = TelemetryBatch {
        gateway_id: gateway.to_owned(),
        boot_id: "boot-allow-limit-initial".to_owned(),
        flows: vec![flow.clone()],
        ..Default::default()
    };

    queue_policy_flow_decisions(
        &hub,
        &batch,
        &[strong_self_host_attribution("netqmon_qos_test")],
    );

    assert!(matches!(
        hub.take_flow_command(&session, revision, Some("boot-allow-limit-initial")),
        Some(PolicyWireFrame::FlowCommand {
            operation:FlowCommandOperation::Upsert,
            policy_flow_id,
            verdict:Some(FlowVerdict::Shape),
            ref policy_ids,
            ..
        }) if policy_flow_id == flow.policy_flow_id && policy_ids == &[limit.id.clone()]
    ));
    let PolicyWireFrame::PolicySnapshot { policies, .. } = &bundle.frame else {
        unreachable!();
    };
    let preview = policy::evaluate_preview(
        &policy::PolicyPreviewRequest {
            gateway_id: gateway.to_owned(),
            client_mac: mac.to_owned(),
            application_id: "netqmon_qos_test".to_owned(),
            category_id: "streaming".to_owned(),
            application_confidence: 0.99,
            scope: "internet".to_owned(),
            at_ms: policy::push::now_ms(),
        },
        policies,
        true,
        true,
    );
    assert_eq!(preview.selected_block_verdict, "allow");
    assert!(
        preview
            .matched_policies
            .iter()
            .any(|row| row.policy_id == allow.id && row.selected)
    );
    assert!(
        preview
            .matched_policies
            .iter()
            .any(|row| row.policy_id == block.id)
    );
    assert!(
        preview
            .active_limits
            .iter()
            .any(|row| row.policy_id == limit.id && row.status == "supported")
    );
}

#[test]
fn service_binding_reuses_full_endpoint_but_never_reverse_proxy_socket() {
    let mut cache = ServiceBindingCache {
        entries: HashMap::new(),
        ttl_ms: 60_000,
        max_entries: 16,
    };
    let endpoint = ServiceBindingKey {
        ip: "192.0.2.31".parse().unwrap(),
        protocol: 6,
        port: 8096,
    };
    let mut strong = strong_self_host_attribution("jellyfin");
    cache.apply(endpoint.clone(), None, 1_000, &mut strong);
    let mut unknown = FlowAttribution::default();
    cache.apply(endpoint, None, 2_000, &mut unknown);
    assert_eq!(unknown.application_id, "jellyfin");
    assert!(attribution_has_evidence(&unknown, "service_binding"));

    let proxy = ServiceBindingKey {
        ip: "192.0.2.20".parse().unwrap(),
        protocol: 6,
        port: 443,
    };
    let mut proxy_strong = strong_self_host_attribution("jellyfin");
    cache.apply(proxy.clone(), None, 3_000, &mut proxy_strong);
    let mut proxy_unknown = FlowAttribution::default();
    cache.apply(proxy, None, 4_000, &mut proxy_unknown);
    assert_eq!(proxy_unknown.application_id, "unknown");
}

#[test]
fn collector_schedules_and_accepts_favicon_probe_identity() {
    let mut cache = FaviconEndpointCache::default();
    let flow = FlowDelta {
        protocol: 6,
        remote_ip: vec![192, 168, 2, 31],
        remote_port: 8096,
        ..Default::default()
    };
    let batch = TelemetryBatch {
        sequence: 7,
        flows: vec![flow],
        ..Default::default()
    };
    let requests = cache.schedule(&batch, &[FlowAttribution::default()], 1_000);
    assert_eq!(requests.len(), 1);
    let digest = "2d01a6171b7ef8ffb8d1f6f9c24a9b9dc8c0186c6fbd653760ff7a34b626f8e8";
    let sha256 = digest
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    cache.observe_results(
        &repository_rule_engine(),
        &TelemetryBatch {
            sent_at: 2_000,
            probe_results: vec![ProbeResult {
                request_id: requests[0].request_id.clone(),
                observed_at_unix_ms: 2_000,
                outcome: Some(ProbeOutcome::Favicon(FaviconProbeResult {
                    target_ip: vec![192, 168, 2, 31],
                    port: 8096,
                    sha256: vec![sha256],
                })),
                status: "ok".to_owned(),
            }],
            ..Default::default()
        },
    );
    let identity = cache
        .identity(
            &ServiceBindingKey {
                ip: "192.168.2.31".parse().unwrap(),
                protocol: 6,
                port: 8096,
            },
            2_000,
        )
        .unwrap();
    assert_eq!(identity.application_id, "selfhost_jellyfin");
}

fn test_state() -> CollectorState {
    CollectorState::new(ENROLLMENT_TOKEN)
}

#[test]
fn configured_wal_checkpoint_uses_independent_connection_and_preserves_data() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("collector-wal-checkpoint.db");
    let sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .connection()
        .execute_batch(
            "PRAGMA wal_autocheckpoint=0;
             CREATE TABLE checkpoint_fixture(payload BLOB NOT NULL);
             WITH RECURSIVE n(i) AS (
                 VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 1024
             )
             INSERT INTO checkpoint_fixture(payload)
             SELECT randomblob(4096) FROM n;",
        )
        .unwrap();
    let mut wal_path = path.as_os_str().to_os_string();
    wal_path.push("-wal");
    assert!(std::fs::metadata(&wal_path).unwrap().len() >= 32 * 1024);

    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    state.checkpoint_sqlite_wal_if_larger_than(32 * 1024);
    drop(state);
    assert_eq!(
        std::fs::metadata(&wal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0),
        0
    );

    let reopened = SqliteStorage::open(&path).unwrap();
    let count: i64 = reopened
        .connection()
        .query_row("SELECT COUNT(*) FROM checkpoint_fixture", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1024);
}

fn repository_rule_engine() -> crate::classifier::ClassifierHandle {
    crate::classifier::ClassifierHandle::test_default()
}

fn test_state_with_repository_rules() -> CollectorState {
    CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        repository_rule_engine(),
    )
    .unwrap()
}

fn unavailable_classifier_state() -> CollectorState {
    CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        crate::classifier::ClassifierHandle::connect(PathBuf::from(
            "/missing/netqmon-classifierd.sock",
        ))
        .unwrap(),
    )
    .unwrap()
}

fn enrollment_request(token: &str) -> Request<Body> {
    let request = EnrollRequest {
        enrollment_token: token.to_owned(),
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "test-gateway".to_owned(),
    };
    Request::builder()
        .method("POST")
        .uri("/v1/ingest/enroll")
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(request.encode_to_vec()))
        .unwrap()
}

async fn enroll_agent(router: &Router) -> EnrollResponse {
    let response = router
        .clone()
        .oneshot(enrollment_request(ENROLLMENT_TOKEN))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    EnrollResponse::decode(body).unwrap()
}

fn query_state() -> CollectorState {
    let state = test_state_with_repository_rules();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "boot-query".to_owned(),
            gateway_name: "query-router".to_owned(),
        })
        .unwrap();
    let timestamp = 1_700_000_000_000;
    let batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        device_observations: vec![netqmon_protocol::v1::DeviceObservation {
            mac: vec![2, 0, 0, 0, 0, 1],
            ip: vec![192, 0, 2, 10],
            hostname: "laptop".to_owned(),
            last_seen_unix_ms: timestamp,
            dhcp: None,
        }],
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            direction: Direction::Upload as i32,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            scope: FlowScope::Internet as i32,
            path_type: PathType::Forwarded as i32,
            nat: NatType::Snat as i32,
            source_segment: "192.0.2.0/24".to_owned(),
            destination_segment: "internet".to_owned(),
            ..FlowDelta::default()
        }],
        health: Some(AgentHealth {
            observed_at_unix_ms: timestamp,
            uptime_seconds: 3_600,
            dropped_batches: 2,
            dns_dropped_events: 1,
            tracked_flows: 1,
            kernel_version: "6.6.73".to_owned(),
            openwrt_version: "24.10.0".to_owned(),
            hardware_flow_offload: OffloadStatus::Enabled as i32,
            capture_interface: "br-lan".to_owned(),
            interface_counter_sanity: CounterSanityStatus::Ok as i32,
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    state
}

#[tokio::test]
#[ignore = "manual file-backed application API benchmark"]
async fn file_application_api_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("applications.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    let base: i64 = 1_700_000_000_000;
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], base as u64)
        .unwrap();
    let connection = sqlite.connection();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) SELECT i,'benchmark',CAST(printf('%012x',i) AS BLOB),?1,?1 FROM n", [base]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,category_id,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at,ended_at) SELECT printf('flow-%d',i),'benchmark',i%1000+1,4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,CASE WHEN i%10=0 THEN 'unknown' ELSE printf('app-%d',i%200) END,printf('category-%d',(i/200)%10),'tcp',printf('org-%d',i%100),i%1000,i%500,1,?2,?2+(i/2000)*60000,?2,?2 FROM n", rusqlite::params![rows,base]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_application_minute(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2+(i/2000)*60000,'benchmark',CASE WHEN i%10=0 THEN 'protocol:tcp' ELSE printf('app-%d',i%200) END,printf('category-%d',(i/200)%10),SUM(i%1000),SUM(i%500),COUNT(*),COUNT(*) FROM n GROUP BY 1,2,3,4", rusqlite::params![rows,base]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    eprintln!(
        "app_api_rows={rows} db_bytes={}",
        std::fs::metadata(&path).unwrap().len()
    );
    for (name, sql) in [(
        "app_groups",
        "SELECT application_id,category_id,SUM(upload_bytes),SUM(download_bytes) FROM traffic_application_minute GROUP BY application_id,category_id",
    )] {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        for line in statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
        {
            eprintln!("app_plan={name} {}", line.unwrap());
        }
    }
    for windowed in [false, true] {
        let sql = crate::query_api::sqlite_applications_query_sql(windowed);
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let plan = if windowed {
            statement
                .query_map(
                    rusqlite::params![base, base + (rows / 2000 + 1) * 60_000, 50_i64, 0_i64],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        } else {
            statement
                .query_map([50_i64, 0_i64], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        for line in plan {
            eprintln!("app_plan=app_list_window_{windowed} {line}");
        }
    }
    if std::env::var("NETQMON_BENCH_COMPACT_APP_CLIENTS").as_deref() == Ok("1") {
        fn query_rows(
            connection: &rusqlite::Connection,
            sql: &str,
            windowed: bool,
            from: i64,
            to: i64,
        ) -> rusqlite::Result<Vec<serde_json::Value>> {
            let mut statement = connection.prepare(sql)?;
            let map_row = |row: &rusqlite::Row<'_>| {
                Ok(serde_json::json!([
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                ]))
            };
            if windowed {
                statement
                    .query_map(rusqlite::params![from, to, 50_i64, 0_i64], map_row)?
                    .collect()
            } else {
                statement.query_map([50_i64, 0_i64], map_row)?.collect()
            }
        }

        fn compact_client_union(sql: &str, windowed: bool) -> String {
            let (app_join, app_predicate, protocol_join, protocol_predicate, flow_window) =
                if windowed {
                    (
                        "CROSS JOIN flow_sessions f",
                        "f.application_id = p.application_id AND",
                        "CROSS JOIN flow_sessions f",
                        "f.protocol_id = p.protocol_id AND",
                        "AND f.last_seen_at >= ?1 AND f.last_seen_at < ?2",
                    )
                } else {
                    (
                        "JOIN flow_sessions f ON f.application_id = p.application_id",
                        "",
                        "JOIN flow_sessions f ON f.protocol_id = p.protocol_id",
                        "",
                        "",
                    )
                };
            let cte_start = sql.find("client_flows AS (").unwrap();
            let cte_end = sql[cte_start..]
                .find("), client_counts AS (")
                .map(|offset| cte_start + offset + 1)
                .unwrap();
            let replacement = format!(
                "client_flows AS (
                    SELECT f.application_id, f.device_id
                    FROM page_apps p {app_join}
                    WHERE {app_predicate} f.device_id IS NOT NULL
                      AND f.application_id != 'unknown' {flow_window}
                    UNION ALL
                    SELECT 'protocol:' || f.protocol_id, f.device_id
                    FROM page_protocols p {protocol_join}
                    WHERE {protocol_predicate} f.device_id IS NOT NULL
                      AND (f.application_id = 'unknown' OR f.application_id IS NULL)
                      AND f.protocol_id != '' AND f.protocol_id != 'unknown' {flow_window}
                    UNION ALL
                    SELECT 'unknown', f.device_id
                    FROM page_apps p JOIN flow_sessions f
                      ON (f.application_id = 'unknown' OR f.application_id IS NULL)
                    WHERE p.application_id = 'unknown' AND f.device_id IS NOT NULL
                      AND COALESCE(NULLIF(f.protocol_id, ''), 'unknown') = 'unknown' {flow_window}
                )"
            );
            format!("{}{}{}", &sql[..cte_start], replacement, &sql[cte_end..])
        }

        let window = (
            base + (rows / 4000) * 60_000,
            base + (rows / 2000 + 1) * 60_000,
        );
        for windowed in [false, true] {
            let original_sql = crate::query_api::sqlite_applications_query_sql(windowed);
            let compact_sql = compact_client_union(&original_sql, windowed);
            let (from, to) = if windowed { window } else { (0, 0) };
            let mut original_times = Vec::new();
            let mut compact_times = Vec::new();
            let mut expected = None;
            for sample in 0..20 {
                let run = |sql: &str| {
                    let started = Instant::now();
                    let result = query_rows(connection, sql, windowed, from, to).unwrap();
                    (started.elapsed().as_micros(), result)
                };
                let (original, compact) = if sample % 2 == 0 {
                    let original = run(&original_sql);
                    let compact = run(&compact_sql);
                    (original, compact)
                } else {
                    let compact = run(&compact_sql);
                    let original = run(&original_sql);
                    (original, compact)
                };
                assert_eq!(original.1, compact.1, "windowed={windowed}");
                if let Some(previous) = &expected {
                    assert_eq!(previous, &original.1, "fixture changed between runs");
                } else {
                    expected = Some(original.1.clone());
                }
                original_times.push(original.0);
                compact_times.push(compact.0);
            }
            original_times.sort_unstable();
            compact_times.sort_unstable();
            let mut plan = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {compact_sql}"))
                .unwrap();
            let plan = if windowed {
                plan.query_map(rusqlite::params![from, to, 50_i64, 0_i64], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            } else {
                plan.query_map([50_i64, 0_i64], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            };
            eprintln!(
                "app_client_union_benchmark rows={rows} windowed={windowed} original_us={}/{}/{} compact_us={}/{}/{}",
                original_times[10],
                original_times[18],
                original_times[19],
                compact_times[10],
                compact_times[18],
                compact_times[19]
            );
            for line in plan {
                eprintln!("app_client_union_plan windowed={windowed} {line}");
            }
        }
    }
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());
    if std::env::var("NETQMON_BENCH_APPS_ONLY").as_deref() != Ok("1") {
        let mut detail_durations = Vec::new();
        for _ in 0..20 {
            let start = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/applications/app-1?category=category-1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = parse_json(response).await;
            assert_eq!(result["data"]["application_id"], "app-1");
            assert!(result["data"]["observed_protocols"].is_array());
            detail_durations.push(start.elapsed().as_micros());
        }
        detail_durations.sort_unstable();
        eprintln!(
            "app_detail_api_rows={rows} p50_us={} p95_us={} p99_us={}",
            detail_durations[10], detail_durations[18], detail_durations[19]
        );
    }
    if std::env::var("NETQMON_BENCH_DETAIL_ONLY").as_deref() != Ok("1") {
        let windows = if std::env::var("NETQMON_BENCH_ALL_TIME_ONLY").as_deref() == Ok("1") {
            vec![false]
        } else {
            vec![false, true]
        };
        for window in windows {
            let mut durations = Vec::new();
            for _ in 0..20 {
                let uri = if window {
                    format!(
                        "/internal/applications?limit=50&from={}&to={}",
                        base + (rows / 4000) * 60000,
                        base + (rows / 2000 + 1) * 60000
                    )
                } else {
                    "/internal/applications?limit=50".to_owned()
                };
                let start = Instant::now();
                let response = router
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let result = parse_json(response).await;
                durations.push(start.elapsed().as_micros());
                assert_eq!(result["data"].as_array().unwrap().len(), 50);
                assert!(result["pagination"]["total"].as_u64().unwrap() >= 50);
            }
            durations.sort_unstable();
            eprintln!(
                "app_api_rows={rows} window={window} p50_us={} p95_us={} p99_us={}",
                durations[10], durations[18], durations[19]
            );
        }
    }
    if std::env::var("NETQMON_BENCH_APPLICATION_COVERING_INDEX").as_deref() == Ok("1") {
        state
            .lock()
            .storage
            .connection()
            .execute_batch(
                "DROP INDEX flow_sessions_application_last_seen;
                 CREATE INDEX flow_sessions_application_last_seen
                     ON flow_sessions(application_id,last_seen_at);
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        let before_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications?limit=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let before_data = parse_json(before_response).await;
        let mut old_durations = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/applications?limit=50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = parse_json(response).await;
            assert_eq!(result["data"], before_data["data"]);
            old_durations.push(started.elapsed().as_micros());
        }
        old_durations.sort_unstable();
        let mut old_detail_durations = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/applications/app-1?category=category-1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = parse_json(response).await;
            assert_eq!(result["data"]["application_id"], "app-1");
            old_detail_durations.push(started.elapsed().as_micros());
        }
        old_detail_durations.sort_unstable();
        let (old_index_bytes, old_update_us) = {
            let inner = state.lock();
            let connection = inner.storage.connection();
            let bytes = connection.query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_application_last_seen'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            ).unwrap().unwrap_or(0);
            let mut updates = Vec::new();
            for _ in 0..5 {
                connection
                    .execute_batch("SAVEPOINT application_index_bench")
                    .unwrap();
                let started = Instant::now();
                connection
                    .execute(
                        "UPDATE flow_sessions SET last_seen_at=last_seen_at+1
                     WHERE rowid IN (SELECT rowid FROM flow_sessions ORDER BY rowid LIMIT 1000)",
                        [],
                    )
                    .unwrap();
                updates.push(started.elapsed().as_micros());
                connection
                    .execute_batch(
                        "ROLLBACK TO application_index_bench; RELEASE application_index_bench",
                    )
                    .unwrap();
            }
            updates.sort_unstable();
            (bytes, updates[2])
        };
        state
            .lock()
            .storage
            .connection()
            .execute_batch(
                "DROP INDEX flow_sessions_application_last_seen;
             CREATE INDEX flow_sessions_application_last_seen
                 ON flow_sessions(application_id,last_seen_at,protocol_id,device_id);
             PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        let inner = state.lock();
        let connection = inner.storage.connection();
        let index_bytes: i64 = connection
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_application_last_seen'",
                [],
                |row| row.get::<_, Option<i64>>(0).map(|value| value.unwrap_or(0)),
            )
            .unwrap();
        let app_sql = crate::query_api::sqlite_applications_query_sql(false);
        let plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {app_sql}"))
            .unwrap()
            .query_map([50_i64, 0_i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut updates = Vec::new();
        for _ in 0..5 {
            connection
                .execute_batch("SAVEPOINT application_index_bench")
                .unwrap();
            let started = Instant::now();
            connection
                .execute(
                    "UPDATE flow_sessions SET last_seen_at=last_seen_at+1
                 WHERE rowid IN (SELECT rowid FROM flow_sessions ORDER BY rowid LIMIT 1000)",
                    [],
                )
                .unwrap();
            updates.push(started.elapsed().as_micros());
            connection
                .execute_batch(
                    "ROLLBACK TO application_index_bench; RELEASE application_index_bench",
                )
                .unwrap();
        }
        updates.sort_unstable();
        drop(inner);
        let mut durations = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/applications?limit=50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = parse_json(response).await;
            assert_eq!(result["data"], before_data["data"]);
            assert_eq!(result["pagination"], before_data["pagination"]);
            durations.push(started.elapsed().as_micros());
        }
        durations.sort_unstable();
        let mut detail_durations = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/applications/app-1?category=category-1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = parse_json(response).await;
            assert_eq!(result["data"]["application_id"], "app-1");
            detail_durations.push(started.elapsed().as_micros());
        }
        detail_durations.sort_unstable();
        eprintln!(
            "app_covering_index rows={rows} old_index_bytes={old_index_bytes} new_index_bytes={index_bytes} update_1000_us_old={old_update_us} update_1000_us_new={} old_api_p50_p95_p99_us={:?} new_api_p50_p95_p99_us={:?} old_detail_api_p50_p95_p99_us={:?} new_detail_api_p50_p95_p99_us={:?} plan={plan:?} file_bytes={}",
            updates[2],
            [old_durations[10], old_durations[18], old_durations[19]],
            [durations[10], durations[18], durations[19]],
            [
                old_detail_durations[10],
                old_detail_durations[18],
                old_detail_durations[19]
            ],
            [
                detail_durations[10],
                detail_durations[18],
                detail_durations[19]
            ],
            std::fs::metadata(&path).unwrap().len(),
        );
    }
}

#[tokio::test]
#[ignore = "manual file-backed full flow API index benchmark"]
async fn file_flow_api_order_index_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let timestamp_group_size: i64 = std::env::var("NETQMON_BENCH_TIMESTAMP_GROUP_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    let index_order =
        if std::env::var("NETQMON_BENCH_FLOW_INDEX_ORDER").as_deref() == Ok("new-first") {
            "new-first"
        } else {
            "old-first"
        };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    // Recreate the pre-migration schema so the benchmark remains an
    // old-index/new-index comparison after migration 16 lands in the binary.
    sqlite
        .connection()
        .execute_batch(
            "DROP INDEX flow_sessions_last_seen_at;
             CREATE INDEX flow_sessions_last_seen_at ON flow_sessions(last_seen_at);
             DELETE FROM schema_migrations WHERE version=16;",
        )
        .unwrap();
    let base = 1_700_000_000_000_i64;
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], base as u64)
        .unwrap();
    sqlite
        .connection()
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
             INSERT INTO flow_sessions(
                 id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,
                 remote_port,direction,domain,application_id,category_id,protocol_id,
                    organization_id,upload_bytes,download_bytes,packets,started_at,
                 last_seen_at,checkpointed_at,ended_at
             )
             SELECT printf('flow-%d',i),'benchmark',4,6,
                    CAST(printf('%08x',i%1000) AS BLOB),i%60000,
                    CAST(printf('%08x',i%50000) AS BLOB),443,1,
                    printf('domain-%d.example',i%10000),printf('app-%d',i%100),
                    printf('category-%d',i%10),'tcp',printf('org-%d',i%500),
                    i%1000,i%500,1,?2,?2+(i/?3),?2,?2
             FROM n",
            rusqlite::params![rows, base, timestamp_group_size],
        )
        .unwrap();
    sqlite
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let measure_last_seen_updates = |connection: &rusqlite::Connection| {
        let ids = (1..=1_000_i64)
            .map(|id| (format!("flow-{id}"), base + id / timestamp_group_size))
            .collect::<Vec<_>>();
        let mut samples = Vec::new();
        for _ in 0..5 {
            connection.execute_batch("BEGIN IMMEDIATE").unwrap();
            let started = Instant::now();
            {
                let mut statement = connection
                    .prepare_cached("UPDATE flow_sessions SET last_seen_at=?2 WHERE id=?1")
                    .unwrap();
                for (id, timestamp) in &ids {
                    statement
                        .execute(rusqlite::params![id, timestamp + 1])
                        .unwrap();
                }
            }
            samples.push(started.elapsed().as_micros());
            {
                let mut statement = connection
                    .prepare_cached("UPDATE flow_sessions SET last_seen_at=?2 WHERE id=?1")
                    .unwrap();
                for (id, timestamp) in &ids {
                    statement.execute(rusqlite::params![id, timestamp]).unwrap();
                }
            }
            connection.execute_batch("COMMIT").unwrap();
        }
        samples.sort_unstable();
        (samples[2], samples[4])
    };
    eprintln!(
        "flow_api_index rows={rows} timestamp_group_size={timestamp_group_size} file_bytes_before={} ",
        std::fs::metadata(&path).unwrap().len()
    );
    let old_index_bytes: i64 = sqlite
        .connection()
        .query_row(
            "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_last_seen_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());
    let migrate_index = |state: &CollectorState, ddl: &str| {
        let started = Instant::now();
        state
            .lock()
            .storage
            .connection()
            .execute_batch(ddl)
            .unwrap();
        let elapsed_us = started.elapsed().as_micros();
        let wal_path = std::path::PathBuf::from(format!("{}-wal", path.display()));
        let wal_bytes = std::fs::metadata(&wal_path).map_or(0, |metadata| metadata.len());
        (elapsed_us, wal_bytes)
    };
    let new_index_ddl = "BEGIN IMMEDIATE;
             DROP INDEX flow_sessions_last_seen_at;
             CREATE INDEX flow_sessions_last_seen_at
                 ON flow_sessions(last_seen_at DESC,id ASC);
             COMMIT;";
    let old_index_ddl = "BEGIN IMMEDIATE;
             DROP INDEX flow_sessions_last_seen_at;
             CREATE INDEX flow_sessions_last_seen_at ON flow_sessions(last_seen_at);
             COMMIT;";
    let mut new_index_bytes = 0_i64;
    let mut migration = None;
    if index_order == "new-first" {
        migration = Some(migrate_index(&state, new_index_ddl));
        new_index_bytes = state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_last_seen_at'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    }
    let writes_before = measure_last_seen_updates(state.lock().storage.connection());
    let measure = |router: axum::Router| async move {
        let mut samples = Vec::new();
        let mut response_data: Option<serde_json::Value> = None;
        let mut next_cursor = None;
        for _ in 0..20 {
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/flows?limit=50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            samples.push(started.elapsed().as_micros());
            assert_eq!(result["data"].as_array().unwrap().len(), 50);
            if let Some(expected) = response_data.as_ref() {
                assert_eq!(expected, &result["data"]);
                assert_eq!(
                    next_cursor.as_deref(),
                    result["pagination"]["next_cursor"].as_str()
                );
            } else {
                next_cursor = result["pagination"]["next_cursor"]
                    .as_str()
                    .map(str::to_owned);
                response_data = Some(result["data"].clone());
            }
        }
        samples.sort_unstable();
        (samples[10], samples[18], samples[19])
    };
    let measure_with_concurrent_ingest = |router: axum::Router, state: CollectorState| async move {
        let writing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let writer_samples = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let active_queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let overlapping_writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_state = state.clone();
        let writer_flag = writing.clone();
        let writer_timings = writer_samples.clone();
        let queries_in_flight = active_queries.clone();
        let overlap_count = overlapping_writes.clone();
        let flow_templates = (0..64_u32)
            .map(|index| FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![10, 0, (index >> 8) as u8, index as u8],
                client_port: 10_000 + index,
                remote_ip: vec![198, 51, 100, (index % 250) as u8],
                remote_port: 443,
                client_mac: vec![2, 0, 0, 0, (index >> 8) as u8, index as u8],
                direction: Direction::Upload as i32,
                upload_bytes: 64,
                packets: 1,
                first_seen_unix_ms: base as u64,
                last_seen_unix_ms: base as u64,
                lifecycle: FlowLifecycle::Ended as i32,
                scope: FlowScope::Internet as i32,
                path_type: PathType::Forwarded as i32,
                nat: NatType::Snat as i32,
                ..FlowDelta::default()
            })
            .collect::<Vec<_>>();
        let writer = std::thread::spawn(move || {
            let mut sequence = 1_u64;
            while writer_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let observed_at = base as u64 + sequence;
                let mut batch = TelemetryBatch {
                    gateway_id: "benchmark".to_owned(),
                    boot_id: "flow-index-concurrent-ingest".to_owned(),
                    sequence,
                    sent_at: observed_at,
                    agent_version: "benchmark".to_owned(),
                    protocol_version: PROTOCOL_VERSION,
                    ..TelemetryBatch::default()
                };
                batch.flows = flow_templates
                    .iter()
                    .cloned()
                    .map(|mut flow| {
                        flow.last_seen_unix_ms = observed_at;
                        flow
                    })
                    .collect();
                let started = Instant::now();
                if queries_in_flight.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                    overlap_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                writer_state.accept_batch(&batch).unwrap();
                writer_timings
                    .lock()
                    .unwrap()
                    .push(started.elapsed().as_micros());
                sequence += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut query_samples = Vec::new();
        let mut query_rows = 0;
        for _ in 0..100 {
            let started = Instant::now();
            active_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/internal/flows?limit=50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            active_queries.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            query_samples.push(started.elapsed().as_micros());
            query_rows += result["data"].as_array().unwrap().len();
        }
        writing.store(false, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();

        query_samples.sort_unstable();
        let mut writer_samples = writer_samples.lock().unwrap().clone();
        writer_samples.sort_unstable();
        assert!(query_rows >= 5_000);
        assert!(!writer_samples.is_empty(), "concurrent ingest did not run");
        assert!(
            overlapping_writes.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "no Collector write overlapped an API request"
        );
        (
            (query_samples[50], query_samples[94], query_samples[99]),
            writer_samples.len(),
            overlapping_writes.load(std::sync::atomic::Ordering::Relaxed),
            (
                writer_samples[writer_samples.len() / 2],
                writer_samples[writer_samples.len() * 95 / 100],
                writer_samples[writer_samples.len() * 99 / 100],
            ),
        )
    };
    let before = measure(router.clone()).await;
    let before_concurrent = measure_with_concurrent_ingest(router.clone(), state.clone()).await;
    if index_order == "old-first" {
        migration = Some(migrate_index(&state, new_index_ddl));
        new_index_bytes = state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_last_seen_at'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    } else {
        migrate_index(&state, old_index_ddl);
    }
    let (migration_elapsed_us, migration_wal_bytes) = migration.unwrap();
    let after = measure(router.clone()).await;
    let after_concurrent = measure_with_concurrent_ingest(router.clone(), state.clone()).await;
    let writes_after = measure_last_seen_updates(state.lock().storage.connection());
    eprintln!(
        "flow_api_index rows={rows} timestamp_group_size={timestamp_group_size} index_order={index_order} before_p50_p95_p99_us={before:?} after_p50_p95_p99_us={after:?} concurrent_before_query_p50_p95_p99_us_writer_batches_writer_p50_p95_p99_us={before_concurrent:?} concurrent_after_query_p50_p95_p99_us_writer_batches_writer_p50_p95_p99_us={after_concurrent:?} last_seen_1000_updates_before_p50_max_us={writes_before:?} last_seen_1000_updates_after_p50_max_us={writes_after:?} old_index_bytes={old_index_bytes} replacement_index_bytes={new_index_bytes} net_index_bytes={} migration_elapsed_us={migration_elapsed_us} migration_wal_bytes={migration_wal_bytes} file_bytes_after={}",
        new_index_bytes - old_index_bytes,
        std::fs::metadata(&path).unwrap().len()
    );
}

#[tokio::test]
#[ignore = "manual file-backed organization and protocol API index benchmark"]
async fn file_flow_group_api_expression_index_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flow-groups.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    let base = 1_700_000_000_000_i64;
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], base as u64)
        .unwrap();
    sqlite
        .connection()
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000)
         INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen)
         SELECT i,'benchmark',CAST(printf('%012x',i) AS BLOB),?1,?1 FROM n",
            [base],
        )
        .unwrap();
    sqlite
        .connection()
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
             INSERT INTO flow_sessions(
                 id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,
                 remote_ip,remote_port,direction,application_id,category_id,protocol_id,
                 organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,
                 checkpointed_at,ended_at
             )
             SELECT printf('flow-%d',i),'benchmark',i%1000+1,4,6,
                    CAST(printf('%08x',i%1000) AS BLOB),i%60000,
                    CAST(printf('%08x',i%50000) AS BLOB),443,1,'app', 'category',
                    printf('protocol-%02d',i%20),printf('org-%03d',i%100),
                    (i%1000)+(i%100)*17,(i%500)+(i%20)*13,1,?2,?2+i,?2,?2
             FROM n",
            rusqlite::params![rows, base],
        )
        .unwrap();
    sqlite
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());

    async fn measure(
        router: &axum::Router,
        route: &str,
        cache: &query_api::summary_cache::SummaryPageCache,
        cold: bool,
    ) -> ([u128; 3], serde_json::Value) {
        let mut samples = Vec::new();
        let mut expected = None;
        for _ in 0..20 {
            if cold {
                cache.invalidate();
            }
            let started = Instant::now();
            let response = router
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            samples.push(started.elapsed().as_micros());
            if let Some(expected) = expected.as_ref() {
                assert_eq!(expected, &result);
            } else {
                expected = Some(result);
            }
        }
        samples.sort_unstable();
        (
            [samples[10], samples[18], samples[19]],
            expected.expect("at least one sample"),
        )
    }

    // Compare SQLite's per-connection page-cache limit on the same file-backed
    // flow distribution. Negative cache_size values are kibibytes, not pages.
    for cache_kib in [512_i64, 2_000, 8_192] {
        {
            let inner = state.lock();
            let connection = inner.storage.connection();
            connection
                .pragma_update(None, "cache_size", -cache_kib)
                .unwrap();
            connection.execute_batch("PRAGMA shrink_memory").unwrap();
        }
        let (organization, organization_response) = measure(
            &router,
            "/internal/organizations?limit=50",
            &state.summary_pages,
            true,
        )
        .await;
        let (protocol, protocol_response) = measure(
            &router,
            "/internal/protocols?limit=50",
            &state.summary_pages,
            true,
        )
        .await;
        assert_eq!(organization_response["pagination"]["total"], 100);
        assert_eq!(protocol_response["pagination"]["total"], 20);
        let effective_cache_kib = {
            let inner = state.lock();
            inner
                .storage
                .connection()
                .pragma_query_value(None, "cache_size", |row| row.get::<_, i64>(0))
                .unwrap()
        };
        let sqlite_bytes = sqlite_memory_used_bytes();
        eprintln!(
            "flow_group_cache_size rows={rows} configured_cache_kib={cache_kib} effective_cache_size={effective_cache_kib} organization_p50_p95_p99_us={organization:?} protocol_p50_p95_p99_us={protocol:?} sqlite_memory_bytes={sqlite_bytes}"
        );
    }
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        connection
            .pragma_update(None, "cache_size", -2_000_i64)
            .unwrap();
        connection.execute_batch("PRAGMA shrink_memory").unwrap();
    }

    fn measure_counter_updates(connection: &rusqlite::Connection) -> [u128; 3] {
        let mut samples = Vec::new();
        for _ in 0..7 {
            let started = Instant::now();
            connection
                .execute_batch(
                    "SAVEPOINT flow_group_index_update_bench;
                     UPDATE flow_sessions SET upload_bytes=upload_bytes+1,
                         download_bytes=download_bytes+1,last_seen_at=last_seen_at+1
                     WHERE id IN (SELECT id FROM flow_sessions ORDER BY id LIMIT 1000);
                     ROLLBACK TO flow_group_index_update_bench;
                     RELEASE flow_group_index_update_bench;",
                )
                .unwrap();
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        [samples[3], samples[5], samples[6]]
    }

    for (kind, route, index_name, candidate_sql) in [
        (
            "organization",
            "/internal/organizations?limit=50",
            "flow_sessions_organization_last_seen",
            "CREATE INDEX flow_sessions_organization_last_seen
             ON flow_sessions(COALESCE(organization_id,'unknown'), device_id)",
        ),
        (
            "protocol",
            "/internal/protocols?limit=50",
            "flow_sessions_protocol_last_seen",
            "CREATE INDEX flow_sessions_protocol_last_seen
             ON flow_sessions(COALESCE(protocol_id,'unknown'))",
        ),
    ] {
        let (before, before_response) = measure(&router, route, &state.summary_pages, true).await;
        let (before_warm, before_warm_response) =
            measure(&router, route, &state.summary_pages, false).await;
        assert_eq!(
            before_response, before_warm_response,
            "{kind} warm response changed"
        );
        let old_index_bytes = {
            let guard = state.lock();
            guard
                .storage
                .connection()
                .query_row(
                    "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name=?1",
                    [index_name],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };
        state
            .lock()
            .storage
            .connection()
            .execute_batch(&format!("DROP INDEX {index_name}; {candidate_sql}"))
            .unwrap();
        let (after, after_response) = measure(&router, route, &state.summary_pages, true).await;
        let (after_warm, after_warm_response) =
            measure(&router, route, &state.summary_pages, false).await;
        assert_eq!(before_response, after_response, "{kind} response changed");
        assert_eq!(
            after_response, after_warm_response,
            "{kind} candidate warm response changed"
        );
        let (plan, index_bytes) = {
            let guard = state.lock();
            let connection = guard.storage.connection();
            let plan_sql = if kind == "organization" {
                "EXPLAIN QUERY PLAN SELECT COALESCE(organization_id,'unknown'), SUM(upload_bytes), SUM(download_bytes), COUNT(*), MAX(last_seen_at), COUNT(DISTINCT device_id), COUNT(*) OVER () FROM flow_sessions GROUP BY COALESCE(organization_id,'unknown') ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50 OFFSET 0"
            } else {
                "EXPLAIN QUERY PLAN SELECT COALESCE(protocol_id,'unknown'), SUM(upload_bytes), SUM(download_bytes), COUNT(*), MAX(last_seen_at), COUNT(*) OVER () FROM flow_sessions GROUP BY COALESCE(protocol_id,'unknown') ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50 OFFSET 0"
            };
            let plan = connection
                .prepare(plan_sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let index_bytes: i64 = connection
                .query_row(
                    "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name=?1",
                    [index_name],
                    |row| row.get(0),
                )
                .unwrap();
            (plan, index_bytes)
        };
        let candidate_updates = {
            let guard = state.lock();
            measure_counter_updates(guard.storage.connection())
        };
        state
            .lock()
            .storage
            .connection()
            .execute_batch(&format!(
                "DROP INDEX {index_name};
                 CREATE INDEX {index_name} ON flow_sessions({}, last_seen_at)",
                if kind == "organization" {
                    "organization_id"
                } else {
                    "protocol_id"
                }
            ))
            .unwrap();
        let old_updates = {
            let guard = state.lock();
            measure_counter_updates(guard.storage.connection())
        };
        eprintln!(
            "flow_group_index kind={kind} rows={rows} old_cold_p50_p95_p99_us={before:?} old_warm_p50_p95_p99_us={before_warm:?} candidate_cold_p50_p95_p99_us={after:?} candidate_warm_p50_p95_p99_us={after_warm:?} old_update_1000_p50_p95_p99_us={old_updates:?} candidate_update_1000_p50_p95_p99_us={candidate_updates:?} old_index_bytes={old_index_bytes} candidate_index_bytes={index_bytes} db_bytes={} plan={plan:?}",
            std::fs::metadata(&path).unwrap().len(),
        );
    }
}

#[test]
#[ignore = "manual file-backed domain day-rollup query benchmark"]
fn file_domain_day_rollup_query_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let domains: i64 = std::env::var("NETQMON_BENCH_DOMAINS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    let directory = tempdir().unwrap();
    let path = directory.path().join("domain-day-rollup.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    {
        let connection = sqlite.connection();
        connection
            .execute(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
             INSERT INTO traffic_domain_minute(
                 timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count
             )
             SELECT 1700000000000+((i-1)/200)*480000,'benchmark',
                    printf('domain-%05d.example',(i-1)%?2),
                    i%997,i%313,1,1 FROM n",
                rusqlite::params![rows, domains],
            )
            .unwrap();
    }
    let rollup_now = 1_700_000_000_000_i64 + ((rows + 199) / 200) * 480_000 + 86_400_000;
    sqlite.roll_up_hour_and_day(rollup_now as u64).unwrap();
    let connection = sqlite.connection();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();

    let minute_sql = "SELECT domain,SUM(upload_bytes),SUM(download_bytes),SUM(packets),
                             SUM(flow_count),MAX(timestamp),COUNT(*) OVER ()
                      FROM traffic_domain_minute GROUP BY domain
                      ORDER BY SUM(upload_bytes+download_bytes) DESC,domain LIMIT ?1 OFFSET ?2";
    let day_sql = "WITH totals AS (
                       SELECT domain,SUM(upload_bytes) upload_bytes,
                              SUM(download_bytes) download_bytes,SUM(packets) packets,
                              SUM(flow_count) flow_count
                       FROM traffic_domain_day GROUP BY domain
                   ), latest AS (
                       SELECT domain,MAX(timestamp) last_seen
                       FROM traffic_domain_minute GROUP BY domain
                   )
                   SELECT totals.domain,totals.upload_bytes,totals.download_bytes,
                          totals.packets,totals.flow_count,latest.last_seen,COUNT(*) OVER ()
                   FROM totals JOIN latest USING(domain)
                   ORDER BY totals.upload_bytes+totals.download_bytes DESC,totals.domain
                   LIMIT ?1 OFFSET ?2";
    let pending_day_sql = "WITH bounds AS MATERIALIZED (
                       SELECT MIN(timestamp) AS min_ts,MAX(timestamp) AS max_ts
                       FROM traffic_domain_minute
                   ), minute_totals AS (
                       SELECT m.domain,
                              SUM(CASE WHEN m.timestamp < (b.min_ts/86400000+1)*86400000
                                             OR m.timestamp >= b.max_ts/86400000*86400000
                                       THEN m.upload_bytes ELSE 0 END) AS upload_bytes,
                              SUM(CASE WHEN m.timestamp < (b.min_ts/86400000+1)*86400000
                                             OR m.timestamp >= b.max_ts/86400000*86400000
                                       THEN m.download_bytes ELSE 0 END) AS download_bytes,
                              SUM(CASE WHEN m.timestamp < (b.min_ts/86400000+1)*86400000
                                             OR m.timestamp >= b.max_ts/86400000*86400000
                                       THEN m.packets ELSE 0 END) AS packets,
                              SUM(CASE WHEN m.timestamp < (b.min_ts/86400000+1)*86400000
                                             OR m.timestamp >= b.max_ts/86400000*86400000
                                       THEN m.flow_count ELSE 0 END) AS flow_count,
                              MAX(m.timestamp) AS last_seen
                       FROM traffic_domain_minute m CROSS JOIN bounds b
                       GROUP BY m.domain
                   ), coarse_rows AS (
                       SELECT d.domain,d.upload_bytes,d.download_bytes,d.packets,d.flow_count
                       FROM traffic_domain_day d CROSS JOIN bounds b
                       WHERE d.timestamp >= (b.min_ts/86400000+1)*86400000
                         AND d.timestamp < b.max_ts/86400000*86400000
                       UNION ALL
                       SELECT p.domain,p.upload_bytes,p.download_bytes,p.packets,p.flow_count
                       FROM traffic_domain_day_pending p CROSS JOIN bounds b
                       WHERE p.timestamp >= (b.min_ts/86400000+1)*86400000
                         AND p.timestamp < b.max_ts/86400000*86400000
                       UNION ALL
                       SELECT p.domain,p.upload_bytes,p.download_bytes,p.packets,p.flow_count
                       FROM traffic_domain_hour_pending p CROSS JOIN bounds b
                       WHERE p.timestamp >= (b.min_ts/86400000+1)*86400000
                         AND p.timestamp < b.max_ts/86400000*86400000
                   ), coarse_totals AS (
                       SELECT domain,SUM(upload_bytes) upload_bytes,
                              SUM(download_bytes) download_bytes,SUM(packets) packets,
                              SUM(flow_count) flow_count
                       FROM coarse_rows GROUP BY domain
                   )
                   SELECT m.domain,m.upload_bytes+COALESCE(c.upload_bytes,0),
                          m.download_bytes+COALESCE(c.download_bytes,0),
                          m.packets+COALESCE(c.packets,0),
                          m.flow_count+COALESCE(c.flow_count,0),m.last_seen,COUNT(*) OVER ()
                   FROM minute_totals m LEFT JOIN coarse_totals c USING(domain)
                   ORDER BY (m.upload_bytes+COALESCE(c.upload_bytes,0))+
                            (m.download_bytes+COALESCE(c.download_bytes,0)) DESC,m.domain
                   LIMIT ?1 OFFSET ?2";

    fn page(connection: &rusqlite::Connection, sql: &str) -> Vec<serde_json::Value> {
        connection
            .prepare(sql)
            .unwrap()
            .query_map([50_i64, 0_i64], |row| {
                Ok(json!([
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?
                ]))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
    fn measure(
        connection: &rusqlite::Connection,
        sql: &str,
    ) -> ([u128; 3], Vec<serde_json::Value>) {
        let mut samples = Vec::new();
        let mut expected = None;
        for _ in 0..20 {
            let started = Instant::now();
            let result = page(connection, sql);
            samples.push(started.elapsed().as_micros());
            if let Some(expected) = expected.as_ref() {
                assert_eq!(expected, &result);
            } else {
                expected = Some(result);
            }
        }
        samples.sort_unstable();
        (
            [samples[10], samples[18], samples[19]],
            expected.expect("twenty query samples"),
        )
    }

    let (minute, minute_page) = measure(connection, minute_sql);
    let (day, day_page) = measure(connection, day_sql);
    let (pending_day, pending_day_page) = measure(connection, pending_day_sql);
    assert_eq!(minute_page, day_page, "daily rollup changed API page data");
    assert_eq!(
        minute_page, pending_day_page,
        "pending-aware day query changed API page data"
    );
    for (name, sql) in [
        ("minute", minute_sql),
        ("day", day_sql),
        ("pending-day", pending_day_sql),
    ] {
        let plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map([50_i64, 0_i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        eprintln!("domain_day_plan kind={name} {plan:?}");
    }
    let minute_bytes: i64 = connection
        .query_row(
            "SELECT SUM(pgsize) FROM dbstat WHERE name='traffic_domain_minute' OR name='sqlite_autoindex_traffic_domain_minute_1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let day_bytes: i64 = connection
        .query_row(
            "SELECT SUM(pgsize) FROM dbstat WHERE name='traffic_domain_day' OR name='sqlite_autoindex_traffic_domain_day_1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    eprintln!(
        "domain_day_query rows={rows} domains={domains} minute_p50_p95_p99_us={minute:?} day_plus_exact_latest_p50_p95_p99_us={day:?} pending_aware_day_query_p50_p95_p99_us={pending_day:?} minute_table_and_pk_bytes={minute_bytes} day_table_and_pk_bytes={day_bytes} file_bytes={}",
        std::fs::metadata(&path).unwrap().len(),
    );
}

#[tokio::test]
#[ignore = "manual file-backed domain API benchmark"]
async fn file_domain_api_benchmark() {
    use std::time::Instant;

    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let groups: i64 = std::env::var("NETQMON_BENCH_GROUPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000)
        .max(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("domains.db");
    let mut storage = SqliteStorage::open(&path).unwrap();
    storage
        .save_gateway("benchmark", "router", "test", &[7; 32], 1_700_000_000_000)
        .unwrap();
    let insert_sql = if groups < 2_000 {
        "WITH RECURSIVE n(i) AS (
             VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < ?1
         )
         INSERT INTO traffic_domain_minute(
             timestamp, gateway_id, domain, upload_bytes, download_bytes, packets, flow_count
         )
         SELECT 1700000000000 + (i / 2000) * 60000, 'benchmark',
                printf('domain-%05d.example', i % ?2), SUM(i % 1000), SUM(i % 300),
                COUNT(*), COUNT(*)
         FROM n GROUP BY i / 2000, i % ?2"
    } else {
        "WITH RECURSIVE n(i) AS (
             VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < ?1
         )
         INSERT INTO traffic_domain_minute(
             timestamp, gateway_id, domain, upload_bytes, download_bytes, packets, flow_count
         )
         SELECT 1700000000000 + (i / 2000) * 60000, 'benchmark',
                printf('domain-%05d.example', i % ?2), i % 1000, i % 300, 1, 1
         FROM n"
    };
    storage
        .connection()
        .execute(insert_sql, rusqlite::params![rows, groups])
        .unwrap();
    storage
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let connection = storage.connection();
    let mut plan = connection
        .prepare("EXPLAIN QUERY PLAN SELECT domain, SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count), MAX(timestamp), COUNT(*) OVER () FROM traffic_domain_minute GROUP BY domain ORDER BY SUM(upload_bytes + download_bytes) DESC, domain LIMIT ?1 OFFSET ?2")
        .unwrap();
    for detail in plan
        .query_map([50_i64, 0_i64], |row| row.get::<_, String>(3))
        .unwrap()
    {
        eprintln!("domain_api_plan={}", detail.unwrap());
    }
    drop(plan);
    eprintln!(
        "domain_api_fixture rows={rows} groups={groups} db_bytes={}",
        std::fs::metadata(&path).unwrap().len()
    );
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, storage, repository_rule_engine()).unwrap();
    let router = internal_router(state);
    let mut samples = Vec::with_capacity(20);
    let mut first_sample = None;
    let total_groups = rows.min(groups) as usize;
    let page_count = (total_groups / 50).max(1);
    for iteration in 0..20 {
        let (limit, offset) = if page_count >= 20 {
            (50, (iteration % page_count) * 50)
        } else {
            (iteration + 1, 0)
        };
        let started = Instant::now();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/internal/domains?limit={limit}&offset={offset}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_json(response).await;
        assert_eq!(body["pagination"]["total"], rows.min(groups) as u64);
        assert_eq!(
            body["data"].as_array().unwrap().len(),
            (limit as usize).min(total_groups)
        );
        let elapsed = started.elapsed().as_micros();
        first_sample.get_or_insert(elapsed);
        samples.push(elapsed);
    }
    samples.sort_unstable();
    eprintln!(
        "domain_api rows={rows} groups={groups} db_bytes={} samples={} first_us={} p50_us={} p95_us={} p99_us={}",
        std::fs::metadata(&path).unwrap().len(),
        samples.len(),
        first_sample.unwrap_or_default(),
        samples[10],
        samples[18],
        samples[19],
    );
}

#[test]
#[ignore = "manual file-backed application summary pagination benchmark"]
fn file_application_summary_pagination_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempfile::tempdir().unwrap();
    let sqlite = SqliteStorage::open(directory.path().join("summary.db")).unwrap();
    let db = sqlite.connection();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_application_minute(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) SELECT i,'benchmark',printf('app-%d',i%50000),printf('category-%d',i%5),i%1000,i%300,1,1 FROM n", [rows]).unwrap();
    let sql = "SELECT application_id,category_id,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count),MAX(timestamp) FROM traffic_application_minute GROUP BY application_id,category_id ORDER BY SUM(upload_bytes)+SUM(download_bytes) DESC,application_id";
    let paged = format!(
        "SELECT application_id,category_id,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count),MAX(timestamp),COUNT(*) OVER () FROM traffic_application_minute GROUP BY application_id,category_id ORDER BY SUM(upload_bytes)+SUM(download_bytes) DESC,application_id LIMIT 50 OFFSET 50"
    );
    let mut times = [Vec::new(), Vec::new()];
    for iteration in 0..10 {
        for pass in 0..2 {
            let current = (iteration + pass) % 2;
            let start = Instant::now();
            if current == 0 {
                let mut stmt = db.prepare(sql).unwrap();
                let all = stmt
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, i64>(3)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(all.len(), usize::try_from(rows.min(50_000)).unwrap());
                std::hint::black_box(&all[50..100]);
            } else {
                let mut stmt = db.prepare(&paged).unwrap();
                let page = stmt
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, i64>(7)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(page.len(), 50);
                assert_eq!(page[0].4, rows.min(50_000));
                std::hint::black_box(page);
            }
            times[current].push(start.elapsed().as_micros());
        }
    }
    for (name, values) in ["before", "after"].into_iter().zip(&mut times) {
        values.sort_unstable();
        eprintln!(
            "summary_rows={rows} {name} p50_us={} p95_us={} p99_us={} materialized={}",
            values[5],
            values[9],
            values[9],
            if name == "before" {
                rows.min(50_000)
            } else {
                50
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual file-backed client API benchmark"]
async fn file_client_api_benchmark() {
    use std::time::Instant;
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let clients: i64 = std::env::var("NETQMON_BENCH_CLIENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    assert!(clients >= 50 && clients <= 999_999 && rows >= clients);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("clients.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .connection()
        .execute_batch("DROP INDEX traffic_device_minute_device")
        .unwrap();
    let base: i64 = 1_700_000_000_000;
    sqlite
        .save_gateway(
            "benchmark",
            "router",
            "test",
            &[7; 32],
            u64::try_from(base).unwrap(),
        )
        .unwrap();
    let connection = sqlite.connection();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO devices(id,gateway_id,mac,hostname,first_seen,last_seen) SELECT i,'benchmark',CAST(printf('%06d',i) AS BLOB),printf('client-%d',i),?2,?2 FROM n", rusqlite::params![clients,base]).unwrap();
    connection.execute("INSERT INTO device_addresses(device_id,ip,ip_version,first_seen,last_seen,application_id,application_confidence,application_source) SELECT id,CAST(printf('%08x',id) AS BLOB),4,?1,?1,CASE WHEN id%2=0 THEN 'self-host' ELSE NULL END,0.9,'test' FROM devices", [base]).unwrap();
    connection.execute("INSERT INTO device_evidence(gateway_id,mac,source,field,value,confidence,first_seen,last_seen) SELECT gateway_id,mac,'test','model','test-model',0.8,?1,?1 FROM devices",[base]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at,ended_at) SELECT printf('flow-%d',i),'benchmark',i%?2+1,4,6,CAST(printf('%08x',i%?2) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,printf('app-%d',i%100),'tcp',i%1000,i%500,1,?3,?3+(i/?2)*60000,?3,?3 FROM n",rusqlite::params![rows,clients,base]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_device_minute(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?3+(i/?2)*60000,'benchmark',i%?2+1,i%1000,i%500,1,1 FROM n",rusqlite::params![rows,clients,base]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let plan_sql = "SELECT d.id,(SELECT MAX(f.last_seen_at) FROM flow_sessions f WHERE f.device_id=d.id AND (f.upload_bytes>0 OR f.download_bytes>0 OR f.packets>0)),COALESCE(SUM(t.upload_bytes),0),COALESCE(SUM(t.download_bytes),0),(SELECT ip FROM device_addresses a WHERE a.device_id=d.id ORDER BY a.last_seen DESC,a.ip_version LIMIT 1) FROM devices d LEFT JOIN traffic_device_minute t ON t.device_id=d.id GROUP BY d.id ORDER BY SUM(COALESCE(t.upload_bytes,0)+COALESCE(t.download_bytes,0)) DESC,d.id LIMIT 50";
    let mut plan = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {plan_sql}"))
        .unwrap();
    for line in plan.query_map([], |r| r.get::<_, String>(3)).unwrap() {
        eprintln!("client_plan={}", line.unwrap());
    }
    drop(plan);
    let paged_plan_sql = "WITH client_page AS (SELECT d.id AS device_id,COALESCE(SUM(t.upload_bytes),0) AS upload_bytes,COALESCE(SUM(t.download_bytes),0) AS download_bytes,COALESCE(SUM(t.flow_count),0) AS flow_count,SUM(COALESCE(t.upload_bytes,0)+COALESCE(t.download_bytes,0)) AS sort_bytes FROM devices d LEFT JOIN traffic_device_minute t ON t.device_id=d.id GROUP BY d.id ORDER BY sort_bytes DESC,d.id LIMIT 50) SELECT d.id,(SELECT MAX(f.last_seen_at) FROM flow_sessions f WHERE f.device_id=d.id AND (f.upload_bytes>0 OR f.download_bytes>0 OR f.packets>0)),p.upload_bytes,p.download_bytes,(SELECT ip FROM device_addresses a WHERE a.device_id=d.id ORDER BY a.last_seen DESC,a.ip_version LIMIT 1) FROM client_page p JOIN devices d ON d.id=p.device_id ORDER BY p.sort_bytes DESC,d.id";
    let mut plan = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {paged_plan_sql}"))
        .unwrap();
    for line in plan.query_map([], |r| r.get::<_, String>(3)).unwrap() {
        eprintln!("client_paged_plan={}", line.unwrap());
    }
    drop(plan);
    eprintln!(
        "client_api_rows={rows} clients={clients} db_bytes={}",
        std::fs::metadata(&path).unwrap().len()
    );
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());
    let mut baseline_pages = Vec::new();
    for window in [false, true] {
        let mut samples = Vec::new();
        let mut page = None;
        for _ in 0..20 {
            let uri = if window {
                format!(
                    "/internal/clients?limit=50&from={}&to={}",
                    base + (rows / clients / 2) * 60000,
                    base + (rows / clients + 1) * 60000
                )
            } else {
                "/internal/clients?limit=50".to_owned()
            };
            let start = Instant::now();
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let result: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                    .unwrap();
            samples.push(start.elapsed().as_micros());
            assert_eq!(result["data"].as_array().unwrap().len(), 50);
            assert_eq!(result["pagination"]["total"], clients);
            if let Some(expected) = &page {
                assert_eq!(&result, expected);
            } else {
                page = Some(result);
            }
        }
        baseline_pages.push(page.expect("twenty requests produce a page"));
        samples.sort_unstable();
        eprintln!(
            "client_api_rows={rows} clients={clients} indexed=false window={window} p50_us={} p95_us={} p99_us={}",
            samples[10], samples[18], samples[19]
        );
    }

    let measure_insert_batch = |connection: &rusqlite::Connection| {
        let mut samples = Vec::new();
        for _ in 0..5 {
            connection.execute_batch("BEGIN IMMEDIATE").unwrap();
            let start = Instant::now();
            connection
                .execute(
                    "WITH RECURSIVE n(i) AS (
                     VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<?1
                 )
                 INSERT INTO traffic_device_minute(
                     timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count
                 )
                 SELECT ?2,'benchmark',i,1,1,1,1 FROM n WHERE i>0",
                    rusqlite::params![clients.min(5_000) + 1, base + 86_400_000],
                )
                .unwrap();
            samples.push(start.elapsed().as_micros());
            connection.execute_batch("ROLLBACK").unwrap();
        }
        samples.sort_unstable();
        samples[2]
    };
    {
        let state_guard = state.lock();
        let connection = state_guard.storage.connection();
        let insert_p50 = measure_insert_batch(connection);
        eprintln!("client_api_rows={rows} indexed=false insert_5000_p50_us={insert_p50}");
        let index_build_started = Instant::now();
        connection
            .execute_batch(
                "CREATE INDEX traffic_device_minute_device
                 ON traffic_device_minute(device_id);",
            )
            .unwrap();
        let index_build_elapsed_ms = index_build_started.elapsed().as_millis();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let index_bytes: i64 = connection
            .query_row(
                "SELECT COALESCE(SUM(pgsize),0) FROM dbstat
                 WHERE name='traffic_device_minute_device'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        eprintln!(
            "client_api_rows={rows} indexed=true index_build_elapsed_ms={index_build_elapsed_ms} db_bytes={} index_bytes={index_bytes}",
            std::fs::metadata(&path).unwrap().len()
        );
        let mut plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {paged_plan_sql}"))
            .unwrap();
        for line in plan.query_map([], |row| row.get::<_, String>(3)).unwrap() {
            eprintln!("client_indexed_paged_plan={}", line.unwrap());
        }
        drop(plan);
        let insert_p50 = measure_insert_batch(connection);
        eprintln!("client_api_rows={rows} indexed=true insert_5000_p50_us={insert_p50}");
    }
    for (window_index, window) in [false, true].into_iter().enumerate() {
        let mut samples = Vec::new();
        for _ in 0..20 {
            let uri = if window {
                format!(
                    "/internal/clients?limit=50&from={}&to={}",
                    base + (rows / clients / 2) * 60000,
                    base + (rows / clients + 1) * 60000
                )
            } else {
                "/internal/clients?limit=50".to_owned()
            };
            let start = Instant::now();
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let result: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                    .unwrap();
            samples.push(start.elapsed().as_micros());
            assert_eq!(result["data"].as_array().unwrap().len(), 50);
            assert_eq!(result["pagination"]["total"], clients);
            assert_eq!(result, baseline_pages[window_index]);
        }
        samples.sort_unstable();
        eprintln!(
            "client_api_rows={rows} clients={clients} indexed=true window={window} p50_us={} p95_us={} p99_us={}",
            samples[10], samples[18], samples[19]
        );
    }

    // Reopen after removing the experimental index so the concurrency sample
    // covers the current production schema and fresh per-connection caches.
    {
        let state_guard = state.lock();
        state_guard
            .storage
            .connection()
            .execute_batch(
                "DROP INDEX traffic_device_minute_device;
                 DELETE FROM schema_migrations WHERE version=15;",
            )
            .unwrap();
    }
    drop(router);
    drop(state);
    let sqlite = SqliteStorage::open(&path).unwrap();
    let index_present: bool = sqlite
        .connection()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='traffic_device_minute_device')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(index_present);
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());

    let proc_rss_kib = |field: &str| {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    };
    let rss_kib = move || {
        proc_rss_kib("VmRSS").or_else(|| {
            let output = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .ok()?;
            String::from_utf8(output.stdout)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        })
    };
    let rss_before = rss_kib();
    let high_water_before = proc_rss_kib("VmHWM");
    let sqlite_before = sqlite_memory_used_bytes();
    let sampling = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sample_flag = std::sync::Arc::clone(&sampling);
    let sampler = std::thread::spawn(move || {
        let mut max_rss = 0;
        let mut max_sqlite_bytes = 0;
        while sample_flag.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(value) = rss_kib() {
                max_rss = max_rss.max(value);
            }
            max_sqlite_bytes = max_sqlite_bytes.max(sqlite_memory_used_bytes());
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        (max_rss, max_sqlite_bytes)
    });

    let concurrent_started = Instant::now();
    let mut requests = Vec::new();
    let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..8 {
        let concurrent_router = router.clone();
        let request_in_flight = std::sync::Arc::clone(&in_flight);
        let request_max_in_flight = std::sync::Arc::clone(&max_in_flight);
        requests.push(tokio::spawn(async move {
            for _ in 0..16 {
                let current =
                    request_in_flight.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                request_max_in_flight.fetch_max(current, std::sync::atomic::Ordering::Relaxed);
                let response = concurrent_router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/internal/clients?limit=50")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let result: serde_json::Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
                )
                .unwrap();
                assert_eq!(result["data"].as_array().unwrap().len(), 50);
                assert_eq!(result["pagination"]["total"], clients);
                request_in_flight.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    let writer_state = state.clone();
    let writer = tokio::task::spawn_blocking(move || {
        let inner = writer_state.lock();
        let connection = inner.storage.connection();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        for _ in 0..500 {
            connection
                .execute(
                    "UPDATE traffic_device_minute SET upload_bytes=upload_bytes+1
                     WHERE device_id=1
                       AND timestamp=(SELECT MIN(timestamp) FROM traffic_device_minute WHERE device_id=1)",
                    [],
                )
                .unwrap();
        }
        connection.execute_batch("COMMIT").unwrap();
    });
    let mut request_failed = false;
    for request in requests {
        request_failed |= request.await.is_err();
    }
    let writer_result = writer.await;
    let concurrent_elapsed = concurrent_started.elapsed();
    sampling.store(false, std::sync::atomic::Ordering::Relaxed);
    let (peak_rss, peak_sqlite_bytes) = sampler.join().unwrap();
    let rss_after = rss_kib();
    let high_water_rss = proc_rss_kib("VmHWM");
    let sqlite_after = sqlite_memory_used_bytes();
    let max_concurrent_requests = max_in_flight.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "client_api_concurrent rows={rows} clients={clients} requests=128 max_concurrent_requests={max_concurrent_requests} concurrent_writer_updates=500 elapsed_ms={} rss_kib_before={rss_before:?} rss_kib_high_water_before={high_water_before:?} rss_kib_sampled_peak={peak_rss} rss_kib_high_water_after={high_water_rss:?} rss_kib_after={rss_after:?} sqlite_bytes_before={sqlite_before} sqlite_bytes_peak={peak_sqlite_bytes} sqlite_bytes_after={sqlite_after}",
        concurrent_elapsed.as_millis()
    );
    assert!(!request_failed, "a concurrent client request failed");
    assert!(max_concurrent_requests > 1, "requests did not overlap");
    writer_result.unwrap();
}

fn sample_batch(gateway_id: &str, sequence: u64) -> TelemetryBatch {
    TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        boot_id: "boot-1".to_owned(),
        sequence,
        sent_at: 1_700_000_000_000 + sequence,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            upload_bytes: 100,
            download_bytes: 50,
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    }
}

#[tokio::test]
async fn discovery_only_device_accumulates_evidence_and_field_confidence() {
    let state = test_state_with_repository_rules();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "discovery-boot".to_owned(),
            gateway_name: "router".to_owned(),
        })
        .unwrap();
    for sequence in 1..=2 {
        let observed_at = 1_700_000_000_000 + sequence;
        let batch = TelemetryBatch {
            gateway_id: enrollment.gateway_id.clone(),
            boot_id: "discovery-boot".to_owned(),
            sequence,
            sent_at: observed_at,
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            device_discovery_observations: vec![DeviceDiscoveryObservation {
                mac: vec![0, 1, 2, 3, 4, 5],
                ip: vec![192, 0, 2, 50],
                protocol: "mdns".to_owned(),
                service: "_ipp._tcp.local".to_owned(),
                instance: "Office Printer._ipp._tcp.local".to_owned(),
                hostname: "printer.local".to_owned(),
                port: 631,
                attributes: [("md".to_owned(), "LaserJet".to_owned())].into(),
                observed_at_unix_ms: observed_at,
            }],
            ..TelemetryBatch::default()
        };
        assert_eq!(
            state.accept_batch(&batch).unwrap(),
            BatchDisposition::Accepted
        );
    }

    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/clients?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"][0]["last_traffic_seen"].is_null());
    let identity = &json["data"][0]["identity"];
    assert_eq!(identity["device_type"], "printer");
    assert!(identity["device_type_confidence"].as_f64().unwrap() > 0.9);
    assert!(
        identity["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["hit_count"] == 2)
    );
}

fn telemetry_request(batch: &TelemetryBatch, token: &str) -> Request<Body> {
    let encoded = encode_telemetry_batch(batch, 1).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/ingest/telemetry")
        .header(CONTENT_TYPE, "application/x-protobuf")
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(encoding) = encoded.encoding.http_value() {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    builder.body(Body::from(encoded.body)).unwrap()
}

#[tokio::test]
async fn public_and_internal_health_routes_are_available() {
    let state = test_state();
    for uri in ["/health", "/v1/ingest/health"] {
        let response = public_router(state.clone())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unavailable_classifier_defers_ingestion_and_strict_apis_return_503() {
    let state = unavailable_classifier_state();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "missing-classifier".to_owned(),
            gateway_name: "test-gateway".to_owned(),
        })
        .unwrap();
    let batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "missing-classifier".to_owned(),
        sequence: 1,
        sent_at: 1_700_000_000_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            remote_ip: vec![203, 0, 113, 10],
            remote_port: 443,
            last_seen_unix_ms: 1_700_000_000_000,
            ..Default::default()
        }],
        ..Default::default()
    };

    assert!(matches!(
        state.accept_batch(&batch),
        Err(TelemetryIngestError::ClassifierUnavailable(_))
    ));
    assert_eq!(state.lock().accepted_batches, 0);

    let health = public_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let router = internal_router(state);
    let strict = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/rules/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(strict.status(), StatusCode::SERVICE_UNAVAILABLE);

    let diagnostics = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(
        json["data"]["classification"]["availability"],
        "unavailable"
    );
}

#[tokio::test]
async fn late_start_classifier_recovers_and_switches_to_ready() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("classifier.sock");

    // 1. Collector connects to socket before classifier exists
    let classifier = crate::classifier::ClassifierHandle::connect(socket_path.clone()).unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        classifier.clone(),
    )
    .unwrap();
    // 2. Health fails and diagnostics shows unavailable
    assert!(classifier.health().is_err());
    let router = internal_router(state);
    let diagnostics = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(
        json["data"]["classification"]["availability"],
        "unavailable"
    );

    // 3. Late start: Classifier UnixListener binds socket
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let server_handle = std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            while let Ok(n) = std::io::BufRead::read_line(&mut reader, &mut line) {
                if n == 0 {
                    break;
                }
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let req_id = req
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("test")
                    .to_owned();
                let resp = match req.get("type").and_then(|v| v.as_str()) {
                    Some("rule_stats") => netqmon_classifier_client::ServerResponse::RuleStats {
                        request_id: req_id,
                        stats: netqmon_classifier_client::RuleStats {
                            rule_version: "inline-test".to_owned(),
                            ..Default::default()
                        },
                    },
                    Some("version") => netqmon_classifier_client::ServerResponse::Version {
                        request_id: req_id,
                        version: netqmon_classifier_client::ClassifierVersion {
                            version: "inline-test".to_owned(),
                            build: None,
                        },
                    },
                    _ => netqmon_classifier_client::ServerResponse::Health {
                        request_id: req_id,
                        health: netqmon_classifier_client::ClassifierHealth {
                            ready: true,
                            detail: None,
                        },
                    },
                };
                use std::io::Write as _;
                writeln!(writer, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
                writer.flush().unwrap();
                line.clear();
            }
        }
    });

    // Wait until probe backoff passes (initial delay is 1s)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // 4. Probing classifier now succeeds and transitions to ready
    assert!(classifier.health().is_ok());

    let diagnostics = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(json["data"]["classification"]["availability"], "ready");

    drop(server_handle);
}

#[tokio::test]
async fn realtime_sse_sends_initial_snapshot_after_every_reconnect() {
    let router = internal_router(query_state());
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/realtime/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/event-stream"
        );
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&first);
        assert!(text.contains("event: snapshot"));
        assert!(text.contains("\"generated_at\""));
        assert!(text.contains("\"active_flows\""));
        assert!(text.contains("\"history\""));
    }
}

#[tokio::test]
async fn overview_summary_uses_counts_and_sse_reconnects_restore_history() {
    let state = query_state();
    let router = internal_router(state.clone());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/overview?summary=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    assert!(value["data"]["realtime"].get("active_flows").is_none());
    assert_eq!(
        value["data"]["realtime"]["active_client_count"],
        state.realtime_snapshot().clients.len()
    );
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/realtime/stream?summary=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&first);
        let data = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(data).unwrap();
        assert!(snapshot.get("active_flows").is_none());
        assert_eq!(snapshot["history_complete"], true);
        assert_eq!(
            snapshot["history"].as_array().unwrap().len(),
            state.realtime_snapshot().history.len()
        );
        state.lock().realtime.update(
            &sample_batch("test-gateway", 99),
            &[],
            1700000100000,
            1700000100000,
        );
        let next = stream.next().await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&next);
        // Updates may first announce gateway/device events. Find the snapshot.
        let mut text = text.into_owned();
        while !text.contains("event: snapshot") {
            text = String::from_utf8_lossy(&stream.next().await.unwrap().unwrap()).into_owned();
        }
        let data = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let update: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(update["history_complete"], false);
        assert_eq!(update["history"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn realtime_sse_status_only_omits_traffic_and_preserves_gateway_events() {
    let state = query_state();
    let router = internal_router(state.clone());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/realtime/stream?status_only=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let first = stream.next().await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&first);
    assert!(text.contains("event: snapshot"));
    let data = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(data).unwrap();
    assert_eq!(snapshot.as_object().unwrap().len(), 2);
    assert!(snapshot.get("generated_at").is_some());
    assert!(snapshot.get("gateway_health").is_some());
    assert!(snapshot.get("active_flows").is_none());
    assert!(snapshot.get("history").is_none());
    assert!(snapshot.get("clients").is_none());

    state
        .lock()
        .realtime
        .gateway_status("test-gateway", "offline", 1234);
    let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&next);
    assert!(text.contains("event: gateway_status"));
    assert!(text.contains("\"status\":\"offline\""));
    assert!(text.contains("\"observed_at\":1234"));
}

#[tokio::test]
async fn internal_query_api_covers_all_core_resources_with_stable_schema() {
    let router = internal_router(query_state());
    for uri in [
        "/internal/overview?limit=10&offset=0",
        "/internal/traffic?from=1699999999000&to=1700000061000&limit=10&offset=0",
        "/internal/traffic?from=1699999999000&to=1700000061000&group_by=client&limit=10",
        "/internal/clients?limit=10&offset=0",
        "/internal/clients/1?limit=10&offset=0",
        "/internal/clients/1/traffic?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/applications?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/domains?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/destinations?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/flows?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications?limit=10&offset=0",
        "/internal/applications/unknown?limit=10&offset=0",
        "/internal/applications/unknown/traffic?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/clients?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/domains?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/destinations?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/flows?from=1699999999000&to=1700000061000&limit=10",
        "/internal/domains?limit=10&offset=0",
        "/internal/destinations?limit=10&offset=0",
        "/internal/insights?from=1699999980000&to=1700000061000&limit=10",
        "/internal/flows?limit=10",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], 1, "{uri}");
        assert!(value.get("data").is_some(), "{uri}");
        assert!(value.get("pagination").is_some(), "{uri}");
    }
}

#[tokio::test]
async fn client_queries_expose_last_traffic_seen_separately_from_discovery() {
    let router = internal_router(query_state());

    let list = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/clients?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(list.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        list_json["data"][0]["last_traffic_seen"],
        serde_json::json!(1_700_000_000_000_i64)
    );

    let detail = router
        .oneshot(
            Request::builder()
                .uri("/internal/clients/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let detail_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(detail.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        detail_json["data"]["client"]["last_traffic_seen"],
        serde_json::json!(1_700_000_000_000_i64)
    );
}

#[tokio::test]
async fn update_client_info_modifies_display_name_and_device_type() {
    let router = internal_router(query_state());

    // 1. Update client 1 name and device_type
    let update_req = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/clients/1")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "My Custom Laptop",
                        "device_type": "laptop"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_req.status(), StatusCode::OK);
    let update_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(update_req.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(update_json["data"]["client"]["name"], "My Custom Laptop");
    assert_eq!(
        update_json["data"]["client"]["identity"]["device_type"],
        "laptop"
    );

    // 2. Verify GET /internal/clients/1 reflects the changes
    let get_req = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/clients/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_req.status(), StatusCode::OK);
    let get_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(get_req.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(get_json["data"]["client"]["name"], "My Custom Laptop");
    assert_eq!(
        get_json["data"]["client"]["identity"]["device_type"],
        "laptop"
    );

    // 3. Clear display_name with null or empty string, fallback to hostname
    let clear_name_req = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/clients/1")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": ""
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clear_name_req.status(), StatusCode::OK);
    let clear_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(clear_name_req.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(clear_json["data"]["client"]["name"], "laptop");

    // 4. Non-existent client returns 404
    let not_found_req = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/clients/999999")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "Ghost"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_found_req.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn client_device_type_override_is_used_by_queries_and_null_restores_auto() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE devices SET device_type='laptop', device_type_confidence=0.8 WHERE id=1",
            [],
        )
        .unwrap();
    let router = internal_router(state.clone());
    for (payload, expected_type, expected_override) in [
        (
            serde_json::json!({"device_type":"printer", "name":"Office"}),
            "printer",
            Some("printer"),
        ),
        (serde_json::json!({"name":null}), "printer", Some("printer")),
        (serde_json::json!({}), "printer", Some("printer")),
        (serde_json::json!({"device_type":null}), "desktop", None),
        (
            serde_json::json!({"device_type":"camera"}),
            "camera",
            Some("camera"),
        ),
        (serde_json::json!({"device_type":""}), "desktop", None),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/internal/clients/1")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let client = &value["data"]["client"];
        assert_eq!(client["identity"]["device_type"], expected_type);
        assert_eq!(
            client["identity"]["device_type_override"],
            serde_json::json!(expected_override)
        );
        if payload.get("name").is_some_and(serde_json::Value::is_null) {
            assert_eq!(client["name"], "laptop");
        }

        // A later automatic result is retained underneath the manual selection.
        state
            .lock()
            .storage
            .connection()
            .execute("UPDATE devices SET device_type='desktop' WHERE id=1", [])
            .unwrap();
        for uri in ["/internal/clients/1", "/internal/clients?limit=10"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                    .unwrap();
            let client = if uri.contains('?') {
                &value["data"][0]
            } else {
                &value["data"]["client"]
            };
            assert_eq!(client["identity"]["device_type"], expected_type, "{uri}");
            assert_eq!(
                client["identity"]["device_type_override"],
                serde_json::json!(expected_override)
            );
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/flows?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(
            value["data"][0]["client_identity"]["device_type"],
            expected_type
        );
    }
}

#[tokio::test]
async fn flow_group_empty_pages_count_null_and_unknown_once_on_file_database() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("group-counts.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1000)
        .unwrap();
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());
    for values in [
        vec![],
        vec![None],
        vec![Some("unknown")],
        vec![None, Some("unknown"), Some("unknown")],
        vec![
            None,
            Some("unknown"),
            Some(""),
            Some("Unknown"),
            Some("中文"),
        ],
        vec![Some(""), Some("org-a"), Some("org-a")],
    ] {
        {
            let inner = state.lock();
            let db = inner.storage.connection();
            db.execute("DELETE FROM flow_sessions", []).unwrap();
            for (index, value) in values.iter().enumerate() {
                db.execute("INSERT INTO flow_sessions(id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,organization_id,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES (?1,'gateway-1',4,6,X'C0000201',1,X'C6336401',443,1,?2,?2,1,1,1,1000,1000,1000)",rusqlite::params![format!("flow-{index}"),value]).unwrap();
            }
        }
        // This fixture mutates SQLite directly, outside the collector's normal
        // accepted-ingest invalidation path.
        state.summary_pages.invalidate();
        let expected = values
            .iter()
            .map(|value| value.unwrap_or("unknown"))
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;
        for resource in ["organizations", "protocols"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/{resource}?limit=1&offset=100"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = parse_json(response).await;
            assert_eq!(
                body["pagination"]["total"], expected,
                "{resource} {values:?}"
            );
            assert_eq!(body["data"], json!([]));
        }
    }
}

#[tokio::test]
async fn application_pages_keep_category_totals_and_window_client_counts_on_file_database() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("application-pages.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute_batch(
        "INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) VALUES
          (1,'gateway-1',X'020000000001',1000,1000),
          (2,'gateway-1',X'020000000002',1000,1000);
         INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,category_id,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES
          ('a','gateway-1',1,4,6,X'C0000201',1,X'C6336401',443,1,'app-a','cat-x','tcp','org-a',100,20,2,1000,1000,1000),
          ('b','gateway-1',2,4,6,X'C0000202',2,X'C6336402',443,1,'app-a','cat-y','tcp','org-a',200,30,3,1000,2000,2000),
          ('d','gateway-1',1,4,6,X'C0000201',4,X'C6336404',443,1,'app-a','cat-y','udp','org-a',50,10,1,1000,2000,2000),
          ('c','gateway-1',1,4,6,X'C0000201',3,X'C6336403',443,1,'unknown','unknown','tcp','unknown',10,5,1,1000,1000,1000);
         INSERT INTO traffic_application_minute VALUES
          (1000,'gateway-1','app-a','cat-x',100,20,2,1),
          (2000,'gateway-1','app-a','cat-x',50,10,1,1),
          (2000,'gateway-1','app-a','cat-y',200,30,3,1),
          (1000,'gateway-1','protocol:tcp','unknown',10,5,1,1)"
    ).unwrap();
    let sql = crate::query_api::sqlite_applications_query_sql(false);
    let plan = sqlite
        .connection()
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map([1_i64, 0_i64], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("COVERING INDEX flow_sessions_application_last_seen")),
        "{plan:?}"
    );
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state.clone());
    for (query, total, expected_id, expected_category, clients) in [
        ("limit=1", 3, Some("app-a"), Some("cat-y"), Some(2)),
        ("limit=1&offset=1", 3, Some("app-a"), Some("cat-x"), Some(2)),
        ("limit=1&offset=100", 3, None, None, None),
        (
            "limit=1&from=1000&to=2000",
            2,
            Some("app-a"),
            Some("cat-x"),
            Some(1),
        ),
        ("limit=1&from=3000&to=4000", 0, None, None, None),
    ] {
        let value = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let window = match query {
            "limit=1&from=1000&to=2000" => Some((1000, 2000)),
            "limit=1&from=3000&to=4000" => Some((3000, 4000)),
            _ => None,
        };
        let offset = query
            .split('&')
            .find_map(|part| part.strip_prefix("offset="))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let generation = state.summary_pages.generation();
        assert!(
            state
                .summary_pages
                .get_window("applications", 1, offset, generation, window)
                .is_some()
        );
        assert!(value["data"].as_array().unwrap().iter().all(|item| {
            item.as_object()
                .is_some_and(|object| !object.contains_key("_persisted_organization_id"))
        }));
        let repeated = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(repeated, value, "cached application page: {query}");
        let summary = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{query}&summary=true"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(summary["pagination"], value["pagination"], "{query}");
        assert_eq!(
            summary["data"].as_array().unwrap().len(),
            value["data"].as_array().unwrap().len(),
            "{query}"
        );
        for (full, compact) in value["data"]
            .as_array()
            .unwrap()
            .iter()
            .zip(summary["data"].as_array().unwrap())
        {
            for field in [
                "application_id",
                "category_id",
                "upload_bytes",
                "download_bytes",
                "packets",
                "flow_count",
                "last_seen",
            ] {
                assert_eq!(compact[field], full[field], "{query}: {field}");
            }
        }
        assert_eq!(value["pagination"]["total"], total, "{query}");
        if let Some(id) = expected_id {
            assert_eq!(value["data"][0]["application_id"], id, "{query}");
            assert_eq!(
                value["data"][0]["category_id"],
                expected_category.unwrap(),
                "{query}"
            );
            assert_eq!(
                value["data"][0]["client_count"],
                clients.unwrap(),
                "{query}"
            );
        } else {
            assert_eq!(value["data"], json!([]), "{query}");
        }
    }

    let category_detail = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/app-a?category=cat-y")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(category_detail["data"]["client_count"], 2);
    assert_eq!(category_detail["data"]["destination_count"], 2);
    assert_eq!(
        category_detail["data"]["observed_protocols"],
        json!([
            {"id": "tcp", "flows": 1},
            {"id": "udp", "flows": 1},
        ])
    );

    let generation = state.summary_pages.generation();
    assert_eq!(
        state.accept_batch(&sample_batch("gateway-1", 1)).unwrap(),
        BatchDisposition::Accepted
    );
    assert_eq!(state.summary_pages.generation(), generation + 1);
    let refreshed = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications?limit=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let upload_total: i64 = refreshed["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["upload_bytes"].as_i64().unwrap())
        .sum();
    assert_eq!(upload_total, 460);
}

#[tokio::test]
async fn application_page_client_counts_match_application_and_protocol_aliases() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite =
        SqliteStorage::open(directory.path().join("application-client-counts.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite
        .connection()
        .execute_batch(
            "INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) VALUES
                (1,'gateway-1',X'020000000001',1000,3000),
                (2,'gateway-1',X'020000000002',1000,3000),
                (3,'gateway-1',X'020000000003',1000,3000);
             INSERT INTO flow_sessions
                (id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,
                 remote_port,direction,application_id,category_id,protocol_id,organization_id,
                 upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at)
             VALUES
                ('pseudo-tcp','gateway-1',1,4,6,X'C0000201',1,X'C6336401',443,1,'unknown','unknown','tcp','unknown',1,1,1,1000,1000,1000),
                ('real-prefix','gateway-1',2,4,6,X'C0000202',2,X'C6336402',443,1,'protocol:tcp','unknown','udp','unknown',1,1,1,1000,2000,2000),
                ('unknown','gateway-1',3,4,6,X'C0000203',3,X'C6336403',443,1,'unknown','unknown','unknown','unknown',1,1,1,1000,1000,1000),
                ('null-app','gateway-1',1,4,6,X'C0000201',4,X'C6336404',443,1,NULL,'unknown',NULL,'unknown',1,1,1,1000,2000,2000),
                ('pseudo-quic','gateway-1',2,4,6,X'C0000202',5,X'C6336405',443,1,'unknown','unknown','quic','unknown',1,1,1,1000,3000,3000),
                ('normal','gateway-1',3,4,6,X'C0000203',6,X'C6336406',443,1,'app-a','web','tcp','unknown',1,1,1,1000,1000,1000);
             INSERT INTO traffic_application_minute
                (timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count)
             VALUES
                (1000,'gateway-1','app-a','web',1,1,1,1),
                (1000,'gateway-1','protocol:tcp','unknown',1,1,1,1),
                (1000,'gateway-1','unknown','unknown',1,1,1,1),
                (3000,'gateway-1','protocol:quic','unknown',1,1,1,1);",
        )
        .unwrap();
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state);

    for (query, expected) in [
        (
            "limit=50",
            json!({
                "app-a": 1,
                "protocol:tcp": 2,
                "protocol:quic": 1,
                "unknown": 2,
            }),
        ),
        (
            "limit=50&from=1000&to=2001",
            json!({
                "app-a": 1,
                "protocol:tcp": 2,
                "unknown": 2,
            }),
        ),
    ] {
        let response = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let actual = response["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["application_id"].as_str().unwrap().to_owned(),
                    item["client_count"].as_u64().unwrap(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let expected = expected.as_object().unwrap();
        assert_eq!(actual.len(), expected.len(), "{query}");
        for (application_id, count) in expected {
            assert_eq!(
                actual.get(application_id).copied(),
                count.as_u64(),
                "{query}"
            );
        }
    }
}

#[tokio::test]
async fn application_rankings_match_detail_totals_and_pagination_without_flow_statistics() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection.execute(
            "INSERT INTO traffic_application_minute
                (timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count)
             VALUES (1700000000000,?1,'youtube','streaming',1000,5000,20,2),
                    (1700000060000,?1,'youtube','streaming',2000,6000,30,3),
                    (1700000000000,?1,'protocol:quic','unknown',300,700,10,1),
                    (1700000000000,?1,'unknown','custom',100,500,5,1)",
            [gateway],
        ).unwrap();
    }
    let router = internal_router(state);
    for params in [
        "limit=2",
        "limit=2&offset=1",
        "limit=2&offset=1000",
        "limit=10&from=1700000000000&to=1700000060000",
        "limit=10&from=1700000060000&to=1700000120000",
        "limit=10&from=1&to=2",
    ] {
        let full = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{params}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let summary = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/applications?{params}&summary=true"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(full["pagination"], summary["pagination"], "{params}");
        let expected = full["data"].as_array().unwrap();
        let actual = summary["data"].as_array().unwrap();
        assert_eq!(expected.len(), actual.len());
        for (full, summary) in expected.iter().zip(actual) {
            for field in [
                "application_id",
                "category_id",
                "name",
                "icon",
                "upload_bytes",
                "download_bytes",
                "packets",
                "flow_count",
                "last_seen",
            ] {
                assert_eq!(full[field], summary[field], "{params}: {field}");
            }
            assert!(summary.get("client_count").is_none());
            assert!(summary.get("organization_id").is_none());
        }
    }
}

#[tokio::test]
async fn application_detail_filters_duplicate_unknown_rows_by_category() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_application_minute
                 (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
                 VALUES (1700000000000, ?1, 'unknown', 'communication', 900, 1100, 20, 2)",
                [&gateway_id],
            )
            .unwrap();
    }

    let router = internal_router(state);
    let detail = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown?category=communication")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(detail["data"]["application_id"], "unknown");
    assert_eq!(detail["data"]["category_id"], "communication");
    assert_eq!(detail["data"]["upload_bytes"], 900);
    assert_eq!(detail["data"]["download_bytes"], 1100);

    let traffic = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown/traffic?category=communication&from=1699999999000&to=1700000001000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(traffic["data"]["points"].as_array().unwrap().len(), 1);
    assert_eq!(traffic["data"]["points"][0]["upload_bytes"], 900);
    assert_eq!(traffic["data"]["points"][0]["download_bytes"], 1100);
}

#[tokio::test]
async fn unknown_application_does_not_associate_organization_from_flow_sessions() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_application_minute
                 (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
                 VALUES (1700000000000, ?1, 'unknown', 'web', 500, 500, 10, 1)",
                [&gateway_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO flow_sessions
                 (id, gateway_id, ip_version, protocol, client_ip, client_port, remote_ip, remote_port,
                  direction, application_id, category_id, organization_id, upload_bytes, download_bytes,
                  packets, started_at, last_seen_at, checkpointed_at)
                 VALUES ('flow-apple-unknown', ?1, 4, 6, X'C000020A', 50001, X'C6336401', 443,
                         1, 'unknown', 'web', 'apple', 500, 500, 10, 1700000000000, 1700000000000, 1700000000000)",
                [&gateway_id],
            )
            .unwrap();
    }

    let router = internal_router(state);
    let list_response = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications?limit=50&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let items = list_response["data"].as_array().unwrap();
    let unknown_app = items
        .iter()
        .find(|item| item["application_id"] == "unknown")
        .expect("unknown application item");
    assert!(
        unknown_app["organization_id"].is_null(),
        "unknown application should have null organization_id, got {:?}",
        unknown_app["organization_id"]
    );
    assert!(
        unknown_app["organization_name"].is_null(),
        "unknown application should have null organization_name, got {:?}",
        unknown_app["organization_name"]
    );

    let detail_response = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown?category=web")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(detail_response["data"]["application_id"], "unknown");
    assert_eq!(detail_response["data"]["organization_id"], "unknown");
    assert!(detail_response["data"]["organization_name"].is_null());
}

#[tokio::test]
async fn application_aggregate_falls_back_to_classifier_organization_metadata() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        // Only the 30-day minute aggregate retains this application; its
        // flow_sessions rows are gone, so the SQL organization lookup is empty.
        connection
            .execute(
                "INSERT INTO traffic_application_minute
                 (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
                 VALUES (1700000000000, ?1, 'xiaohongshu', 'social', 700, 300, 12, 2)",
                [&gateway_id],
            )
            .unwrap();
        let retained_flows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM flow_sessions WHERE application_id = 'xiaohongshu'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_flows, 0, "fixture must not keep matching flows");
    }

    let router = internal_router(state);
    let list_response = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications?limit=50&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let items = list_response["data"].as_array().unwrap();
    let application = items
        .iter()
        .find(|item| item["application_id"] == "xiaohongshu")
        .expect("xiaohongshu application item");
    assert_eq!(application["name"], "Xiaohongshu");
    assert_eq!(
        application["organization_id"], "xingyin",
        "metadata fallback should supply the organization id"
    );
    assert_eq!(application["organization_name"], "Xingyin");
}

#[tokio::test]
async fn traffic_scope_and_direction_filter_metrics_chart_and_breakdown_together() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_scope_minute(
                timestamp, gateway_id, scope, direction, device_id, application_id,
                category_id, domain, remote_ip, protocol, protocol_id, upload_bytes, download_bytes, packets, flow_count
             ) VALUES (?1, ?2, ?3, ?4, 1, 'internal-test', 'network', 'unknown',
                       X'C0000214', 17, 'wireguard', 0, 800, 7, 1)",
                rusqlite::params![
                    1_700_000_000_000_i64,
                    gateway_id,
                    FlowScope::Internal as i32,
                    Direction::Download as i32
                ],
            )
            .unwrap();
    }
    let router = internal_router(state);
    let internet = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=none")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(internet["data"]["scope"], "internet");
    assert_eq!(internet["data"]["points"][0]["upload_bytes"], 100);

    let internal_download = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=application&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_download["data"]["direction"], "download");
    assert_eq!(
        internal_download["data"]["points"][0]["download_bytes"],
        800
    );
    assert_eq!(
        internal_download["data"]["breakdown"][0]["id"],
        "internal-test"
    );
    assert_eq!(internal_download["data"]["breakdown"][0]["upload_bytes"], 0);

    let internal_l7 = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol_l7&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_l7["data"]["group_by"], "protocol_l7");
    assert_eq!(internal_l7["data"]["breakdown"][0]["id"], "wireguard");
    assert_eq!(internal_l7["data"]["breakdown"][0]["download_bytes"], 800);

    let internal_l4 = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol_l4&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_l4["data"]["group_by"], "protocol_l4");
    assert_eq!(internal_l4["data"]["breakdown"][0]["id"], "udp");
    assert_eq!(internal_l4["data"]["breakdown"][0]["name"], "UDP");
    assert_eq!(internal_l4["data"]["breakdown"][0]["download_bytes"], 800);

    let internal_alias = parse_json(router.oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_alias["data"]["group_by"], "protocol_l7");
    assert_eq!(internal_alias["data"]["breakdown"][0]["id"], "wireguard");
}

#[tokio::test]
async fn insights_report_new_devices_with_explainable_evidence() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = parse_json(response).await;
    let item = &value["data"][0];
    assert_eq!(item["category"], "device");
    assert_eq!(item["code"], "device.new_device");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "device-discovery");
    assert_eq!(item["time"], 1_700_000_000_000_i64);
    assert_eq!(item["affected_client"]["name"], "laptop");
    assert_eq!(item["evidence"]["mac"], "02:00:00:00:00:01");
}

#[tokio::test]
async fn insights_expose_the_unknown_application_ratio_and_rule_basis() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "classification.unknown_ratio_high")
        .unwrap();
    assert_eq!(item["category"], "classification");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier");
    assert_eq!(item["evidence"]["unknown_bytes"], 150);
    assert_eq!(item["evidence"]["total_bytes"], 150);
    assert_eq!(item["evidence"]["rule"], "application_id = unknown");
}

#[tokio::test]
async fn insights_infer_encrypted_dns_without_claiming_a_domain() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_001_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_001,
            remote_ip: vec![1, 1, 1, 1],
            remote_port: 443,
            direction: 1,
            upload_bytes: 200,
            packets: 2,
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "dns.encrypted_dns_detected")
        .unwrap();
    assert_eq!(item["category"], "dns");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "flow-rules");
    assert_eq!(item["evidence"]["rule"], "known_doh_provider");
    assert_eq!(item["evidence"]["provider"], "Cloudflare");
    assert!(item["evidence"]["domain"].is_null());
    assert_eq!(
        item["evidence"]["domain_limit"],
        "Encrypted DNS contents are not visible"
    );
}

#[tokio::test]
async fn insights_correlate_private_tracker_and_bittorrent_peer_activity() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_002_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: timestamp,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation")
        .unwrap();
    assert_eq!(item["category"], "protocol");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier-correlation");
    assert_eq!(item["affected_client"]["name"], "laptop");
    assert_eq!(item["evidence"]["tracker_role"], "tracker_service");
    assert_eq!(item["evidence"]["peer_protocol"], "bittorrent");
    assert_eq!(item["evidence"]["action"], "observation_only");
}

#[tokio::test]
async fn pt_correlation_within_30_minutes_succeeds() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let tracker_time = 1_700_000_002_000;
    let peer_time = tracker_time + 20 * 60 * 1000; // 20 minutes later
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: peer_time,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: tracker_time,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: tracker_time,
                last_seen_unix_ms: tracker_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: peer_time,
                last_seen_unix_ms: peer_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/internal/insights?from=1699999980000&to={}&limit=20",
                    peer_time + 60000
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation");
    assert!(item.is_some());
}

#[tokio::test]
async fn pt_correlation_beyond_30_minutes_fails() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let tracker_time = 1_700_000_002_000;
    let peer_time = tracker_time + 120 * 60 * 1000; // 2 hours later
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: peer_time,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: tracker_time,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: tracker_time,
                last_seen_unix_ms: tracker_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: peer_time,
                last_seen_unix_ms: peer_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/internal/insights?from=1699999980000&to={}&limit=20",
                    peer_time + 60000
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation");
    assert!(item.is_none());
}

#[tokio::test]
async fn l2tp_ipsec_correlation_reports_l2tp_and_ipsec_evidence() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_002_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 17,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_020,
                remote_ip: vec![203, 0, 113, 20],
                remote_port: 1701,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 50,
                client_ip: vec![192, 0, 2, 10],
                client_port: 0,
                remote_ip: vec![203, 0, 113, 20],
                remote_port: 0,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: timestamp + 1_000,
                last_seen_unix_ms: timestamp + 1_000,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.l2tp_ipsec_detected")
        .unwrap();
    assert_eq!(item["category"], "protocol");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier-correlation");
    assert_eq!(item["evidence"]["remote_ip"], "203.0.113.20");
    assert_eq!(item["evidence"]["l2tp_flows"], 1);
    assert_eq!(item["evidence"]["esp_flows"], 1);
}

#[tokio::test]
async fn l2tp_ipsec_correlation_ignores_l2tp_without_ipsec_evidence() {
    let timestamp = 1_700_000_002_000;
    let l2tp_only = query_state();
    let gateway_id = l2tp_only
        .lock()
        .gateway
        .as_ref()
        .unwrap()
        .gateway_id
        .clone();
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_020,
            remote_ip: vec![203, 0, 113, 21],
            remote_port: 1701,
            direction: 1,
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        l2tp_only.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(l2tp_only)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    assert!(
        value["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["code"] != "protocol.l2tp_ipsec_detected")
    );
}

#[tokio::test]
async fn organization_and_protocol_apis_coalesce_historical_nulls_to_unknown() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE flow_sessions SET organization_id = NULL, protocol_id = NULL",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    for uri in [
        "/internal/organizations?limit=10",
        "/internal/protocols?limit=10",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let value = parse_json(response).await;
        assert_eq!(value["data"][0]["id"], "unknown", "{uri}");
        assert_eq!(value["data"][0]["name"], "unknown", "{uri}");
    }
}

#[test]
fn insights_flag_high_upload_from_recent_history_without_blocking() {
    let state = query_state();
    let inner = state.lock();
    let items = crate::insights::traffic::query_high_upload_insights(
        inner.storage.connection(),
        crate::insights::InsightWindow {
            from: 1_699_999_980_000,
            to: 1_700_000_061_000,
            limit: 10,
        },
        100,
    )
    .unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item.code, "traffic.high_upload");
    assert_eq!(item.category, "traffic");
    assert_eq!(item.source, "traffic-history");
    assert_eq!(item.evidence["upload_bytes"], 100);
    assert_eq!(item.evidence["threshold_bytes"], 100);
    assert_eq!(item.evidence["action"], "observation_only");
}

#[tokio::test]
async fn organization_protocol_pages_preserve_nulls_counts_and_empty_offsets_on_file_database() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("flow-groups.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1_000)
        .unwrap();
    sqlite.connection().execute_batch(
        "INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) VALUES
          (1,'gateway-1',X'020000000001',1000,1000),
          (2,'gateway-1',X'020000000002',1000,1000);
         INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,organization_id,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES
          ('a','gateway-1',1,4,6,X'C0000201',1,X'C6336401',443,1,NULL,NULL,100,20,2,1000,1000,1000),
          ('b','gateway-1',2,4,6,X'C0000202',2,X'C6336402',443,1,'unknown','unknown',200,30,3,1000,2000,2000),
          ('c','gateway-1',1,4,6,X'C0000201',3,X'C6336403',443,1,'known-org','known-protocol',10,5,1,1000,3000,3000)"
    ).unwrap();
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state);
    for resource in ["organizations", "protocols"] {
        for offset in [0, 1, 100] {
            let value = parse_json(
                router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/internal/{resource}?limit=1&offset={offset}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(value["pagination"]["total"], 2);
            match offset {
                0 => {
                    let item = &value["data"][0];
                    assert_eq!(item["id"], "unknown");
                    assert_eq!(item["upload_bytes"], 300);
                    assert_eq!(item["download_bytes"], 50);
                    assert_eq!(item["flows"], 2);
                    assert_eq!(item["last_seen"], 2000);
                    if resource == "organizations" {
                        assert_eq!(item["clients"], 2);
                    }
                }
                1 => assert_eq!(
                    value["data"][0]["id"],
                    if resource == "organizations" {
                        "known-org"
                    } else {
                        "known-protocol"
                    }
                ),
                _ => assert_eq!(value["data"], json!([])),
            }
        }
    }
}

#[tokio::test]
async fn insights_explain_each_capture_quality_warning() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let items = value["data"].as_array().unwrap();
    let codes = items
        .iter()
        .map(|item| item["code"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert!(codes.contains("capture.hardware_flow_offload"));
    assert!(codes.contains("capture.dns_event_drops"));
    assert!(codes.contains("capture.telemetry_queue_drops"));
    assert!(codes.contains("capture.collector_lag"));
    let collector_lag = items
        .iter()
        .find(|item| item["code"] == "capture.collector_lag")
        .unwrap();
    assert_eq!(
        collector_lag["evidence"]["agent_batch_time"],
        1_700_000_000_000_u64
    );
    assert!(
        collector_lag["params"]["lag_ms"].as_u64().unwrap()
            >= crate::insights::collector_lag_threshold_ms()
    );
    for item in items {
        assert!(item.get("title").is_none());
        assert!(item.get("reason").is_none());
        assert!(item.get("time").is_some());
        assert!(item.get("source").is_some());
        assert!(item.get("category").is_some());
        assert!(item.get("code").is_some());
        assert!(item.get("params").is_some());
        assert!(item.get("evidence").is_some());
        if item["code"].as_str().unwrap().starts_with("capture.") {
            assert_eq!(item["category"], "capture");
        }
    }
}

#[tokio::test]
async fn topology_health_is_exposed_in_diagnostics_and_insights() {
    let state = query_state();
    let gateway_id = state.lock().storage.gateway().unwrap().unwrap().id;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: 1_700_000_001_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        health: Some(AgentHealth {
            observed_at_unix_ms: 1_700_000_001_000,
            capture_interface: "br-lan".to_owned(),
            topology: Some(TopologySummary {
                topology_mode: "one-arm-router".to_owned(),
                agent_addresses: vec!["192.0.2.8".to_owned()],
                upstream_gateway: "192.0.2.1".to_owned(),
                ipv4_coverage: "full".to_owned(),
                ipv6_coverage: "partial".to_owned(),
                icmp_redirect: "enabled".to_owned(),
                software_flow_offload: OffloadStatus::Enabled as i32,
                hardware_flow_offload: OffloadStatus::Disabled as i32,
                confidence: 60,
                topology_warnings: vec!["Asymmetric routing suspected".to_owned()],
                ..TopologySummary::default()
            }),
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let router = internal_router(state);
    let diagnostics = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/settings/diagnostics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        diagnostics["data"]["topology"]["topology_mode"],
        "one-arm-router"
    );
    assert_eq!(
        diagnostics["data"]["topology"]["capture_interface"],
        "br-lan"
    );

    let status = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/overview/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        status["data"]["topology"]["topology_mode"],
        "one-arm-router"
    );
    assert!(status["data"].get("recognition").is_none());

    let insights = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let codes = insights["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["code"].as_str())
        .collect::<std::collections::HashSet<_>>();
    assert!(codes.contains("capture.icmp_redirect_enabled"));
    assert!(codes.contains("capture.ipv6_coverage"));
    assert!(codes.contains("capture.software_flow_offload"));
    assert!(codes.contains("capture.topology_confidence"));
    assert!(codes.contains("capture.asymmetric_routing"));
}

#[tokio::test]
async fn domain_pages_keep_group_totals_and_empty_offset_on_file_database() {
    let directory = tempfile::tempdir().unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open(directory.path().join("domains.db")).unwrap(),
        repository_rule_engine(),
    )
    .unwrap();
    let empty = parse_json(
        internal_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/internal/domains?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(empty["pagination"]["total"], 0);
    assert_eq!(empty["data"], json!([]));
    state
        .lock()
        .storage
        .connection()
        .execute_batch(
            "INSERT INTO traffic_domain_minute VALUES
         (1000,'gateway','a.example',100,50,3,1),
         (2000,'gateway','a.example',200,50,4,2),
         (1000,'gateway','b.example',300,100,5,3),
         (1000,'gateway','c.example',1,2,1,1)",
        )
        .unwrap();
    state.summary_pages.invalidate();
    let router = internal_router(state);
    for (offset, expected, total) in [
        (0, Some("a.example"), 3),
        (1, Some("b.example"), 3),
        (100, None, 3),
    ] {
        let result = parse_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/internal/domains?limit=1&offset={offset}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(result["pagination"]["total"], total);
        match expected {
            Some(domain) => assert_eq!(result["data"][0]["domain"], domain),
            None => assert_eq!(result["data"], json!([])),
        }
    }
}

#[tokio::test]
async fn summary_page_cache_is_invalidated_after_accepted_file_ingest() {
    let directory = tempfile::tempdir().unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open(directory.path().join("domain-cache-ingest.db")).unwrap(),
        repository_rule_engine(),
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "domain-cache-boot".to_owned(),
            gateway_name: "domain-cache-router".to_owned(),
        })
        .unwrap();
    let router = internal_router(state.clone());
    let request = || {
        Request::builder()
            .uri("/internal/domains?limit=50")
            .body(Body::empty())
            .unwrap()
    };
    let empty = parse_json(router.clone().oneshot(request()).await.unwrap()).await;
    assert_eq!(empty["pagination"]["total"], 0);
    for uri in [
        "/internal/organizations?limit=50",
        "/internal/protocols?limit=50",
    ] {
        let page = parse_json(
            router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(page["pagination"]["total"], 0);
    }

    let timestamp = 1_700_000_000_000;
    assert_eq!(
        state
            .accept_batch(&TelemetryBatch {
                gateway_id: enrollment.gateway_id,
                boot_id: "domain-cache-boot".to_owned(),
                sequence: 1,
                sent_at: timestamp,
                agent_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                flows: vec![FlowDelta {
                    ip_version: 4,
                    protocol: 6,
                    client_ip: vec![192, 0, 2, 10],
                    client_port: 50_000,
                    remote_ip: vec![198, 51, 100, 20],
                    remote_port: 443,
                    direction: Direction::Upload as i32,
                    upload_bytes: 100,
                    download_bytes: 25,
                    packets: 2,
                    first_seen_unix_ms: timestamp,
                    last_seen_unix_ms: timestamp,
                    lifecycle: FlowLifecycle::Ended as i32,
                    scope: FlowScope::Internet as i32,
                    ..FlowDelta::default()
                }],
                ..TelemetryBatch::default()
            })
            .unwrap(),
        BatchDisposition::Accepted
    );
    let populated = parse_json(router.clone().oneshot(request()).await.unwrap()).await;
    assert_eq!(populated["pagination"]["total"], 1);
    assert_eq!(populated["data"].as_array().unwrap().len(), 1);
    for uri in [
        "/internal/organizations?limit=50",
        "/internal/protocols?limit=50",
    ] {
        let page = parse_json(
            router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(page["pagination"]["total"], 1);
    }

    let retention_now = timestamp + 31 * 24 * 60 * 60 * 1_000;
    assert!(state.run_maintenance_at(true, retention_now).unwrap());
    let router = internal_router(state);
    let retained = parse_json(router.clone().oneshot(request()).await.unwrap()).await;
    assert_eq!(retained["pagination"]["total"], 0);
    assert_eq!(retained["data"], json!([]));
    for uri in [
        "/internal/organizations?limit=50",
        "/internal/protocols?limit=50",
    ] {
        let page = parse_json(
            router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(page["pagination"]["total"], 0);
    }
}

#[tokio::test]
async fn late_dpi_domain_reclassification_invalidates_cached_summary_pages() {
    let state = query_state();
    let router = internal_router(state.clone());
    let request = || {
        Request::builder()
            .uri("/internal/domains?limit=50")
            .body(Body::empty())
            .unwrap()
    };
    let before = parse_json(router.clone().oneshot(request()).await.unwrap()).await;
    let previous_domain = before["data"][0]["domain"].as_str().unwrap();
    assert_ne!(previous_domain, "www.youtube.com");
    let generation = state.summary_pages.generation();
    let gateway_id: String = state
        .lock()
        .storage
        .connection()
        .query_row("SELECT gateway_id FROM flow_sessions LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let sample = dpi::CachedResult::for_test(
        gateway_id,
        "boot-query".to_owned(),
        netqmon_protocol::v1::FlowSampleKey {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            first_seen_unix_ms: 1_700_000_000_000,
        },
        1_700_000_000_000,
        Some(dpi::engine::DpiResult {
            protocol: "tls".to_owned(),
            confidence: 1.0,
            source: "ndpi".to_owned(),
            metadata: std::collections::BTreeMap::from([(
                "hostname".to_owned(),
                "www.youtube.com".to_owned(),
            )]),
        }),
    );
    let processing = state.processing.lock().unwrap();
    process_sample(&state.inner, &sample, &processing, &state.summary_pages).unwrap();
    drop(processing);
    assert_eq!(state.summary_pages.generation(), generation + 1);

    let after = parse_json(router.oneshot(request()).await.unwrap()).await;
    assert_eq!(after["pagination"]["total"], 1);
    assert_eq!(after["data"][0]["domain"], "www.youtube.com");
}

#[tokio::test]
async fn destinations_include_identity_traffic_clients_and_geo_placeholders() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let destination = &value["data"][0];
    assert_eq!(destination["remote_ip"], "198.51.100.1");
    assert_eq!(destination["client_count"], 1);
    assert_eq!(destination["flow_count"], 1);
    assert_eq!(destination["upload_bytes"], 100);
    assert_eq!(destination["download_bytes"], 50);
    assert!(destination.get("domain").is_some());
    assert!(destination.get("country_code").is_some());
    assert!(destination.get("asn").is_some());
    assert!(destination.get("organization").is_some());
}

#[tokio::test]
async fn destinations_cached_totals_preserve_empty_pages_and_refresh_metadata() {
    let state = query_state();
    let router = internal_router(state.clone());
    let first = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/destinations?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let total = first["pagination"]["total"].as_u64().unwrap();
    assert!(total > 0);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE flow_sessions SET domain = 'fresh.example' WHERE remote_ip = X'C6336401'",
            [],
        )
        .unwrap();
    let refreshed = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/destinations?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refreshed["data"][0]["domain"], "fresh.example");
    assert_eq!(refreshed["pagination"]["total"], total);
    let empty = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/destinations?limit=1&offset=1000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(empty["data"], json!([]));
    assert_eq!(empty["pagination"]["total"], total);
}

#[tokio::test]
async fn traffic_totals_reuse_chart_scan_without_losing_last_seen_or_empty_results() {
    let state = query_state();
    let expected_last_seen: i64 = state
        .query()
        .storage
        .connection()
        .query_row(
            "SELECT MAX(timestamp) FROM traffic_scope_minute",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let router = internal_router(state);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/traffic?from=1699913600000&to=1700000061000&scope=all")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    assert_eq!(
        value["data"]["breakdown"][0]["last_seen"],
        expected_last_seen
    );
    let points = value["data"]["points"].as_array().unwrap();
    for metric in ["upload_bytes", "download_bytes", "packets", "flow_count"] {
        let total: i64 = points
            .iter()
            .map(|point| point[metric].as_i64().unwrap())
            .sum();
        assert_eq!(value["data"]["breakdown"][0][metric], total);
    }
    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/traffic?from=0&to=1&scope=all")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    assert!(value["data"]["points"].as_array().unwrap().is_empty());
    assert_eq!(value["data"]["breakdown"][0]["upload_bytes"], 0);
    assert!(value["data"]["breakdown"][0]["last_seen"].is_null());
}

#[derive(Debug)]
struct TestGeoProvider;

impl GeoProvider for TestGeoProvider {
    fn lookup(&self, ip: IpAddr) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        self.lookup_with_lang(ip, None)
    }

    fn lookup_with_lang(
        &self,
        ip: IpAddr,
        lang: Option<&str>,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        let country_name = if let Some(l) = lang {
            if l.starts_with("zh") {
                "美国"
            } else {
                "United States"
            }
        } else {
            "United States"
        };
        Ok(
            (ip == "198.51.100.1".parse::<IpAddr>().unwrap()).then(|| netqmon_geo::GeoRecord {
                country_code: Some("US".to_owned()),
                country_name: Some(country_name.to_owned()),
                region: Some("California".to_owned()),
                city: Some("Los Angeles".to_owned()),
                latitude: Some(34.0522),
                longitude: Some(-118.2437),
                asn: Some(64_496),
                organization: Some("Example Network".to_owned()),
            }),
        )
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct CountingAsnGeoProvider {
    asns: HashMap<IpAddr, u32>,
    failures: std::collections::HashSet<IpAddr>,
    calls: std::sync::Mutex<HashMap<IpAddr, usize>>,
}

impl CountingAsnGeoProvider {
    fn new(
        asns: impl IntoIterator<Item = (IpAddr, u32)>,
        failures: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            asns: asns.into_iter().collect(),
            failures: failures.into_iter().collect(),
            calls: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn call_count(&self, ip: IpAddr) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}

impl GeoProvider for CountingAsnGeoProvider {
    fn lookup(&self, ip: IpAddr) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        *self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(ip)
            .or_default() += 1;
        if self.failures.contains(&ip) {
            return Err(netqmon_geo::GeoError::new("test lookup failure"));
        }
        Ok(self
            .asns
            .get(&ip)
            .copied()
            .map(|asn| netqmon_geo::GeoRecord {
                asn: Some(asn),
                ..Default::default()
            }))
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct AsnClassifierRequest {
    domain: Option<String>,
    remote_ip: Option<String>,
    remote_asn: Option<u32>,
    has_dpi: bool,
}

fn spawn_asn_classifier_server(
    socket_path: PathBuf,
    expected_requests: usize,
) -> std::thread::JoinHandle<Vec<AsnClassifierRequest>> {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::os::unix::net::UnixListener::bind(socket_path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        let mut observed = Vec::new();
        let mut classification_requests = 0;

        while classification_requests < expected_requests {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            let request: netqmon_classifier_client::ClientRequest =
                serde_json::from_str(&line).unwrap();
            let response = match request {
                netqmon_classifier_client::ClientRequest::Health { request_id } => {
                    netqmon_classifier_client::ServerResponse::Health {
                        request_id,
                        health: netqmon_classifier_client::ClassifierHealth {
                            ready: true,
                            detail: None,
                        },
                    }
                }
                netqmon_classifier_client::ClientRequest::ClassifyBatch {
                    request_id,
                    request,
                } => {
                    classification_requests += 1;
                    let entries = request
                        .entries
                        .into_iter()
                        .map(|entry| {
                            observed.push(AsnClassifierRequest {
                                domain: entry.domain.clone(),
                                remote_ip: entry.remote_ip.clone(),
                                remote_asn: entry.remote_asn,
                                has_dpi: entry.dpi_evidence.is_some(),
                            });
                            let asn = entry.remote_asn;
                            let suffix = asn.unwrap_or_default();
                            netqmon_classifier_client::ClassificationResult {
                                entry_id: entry.entry_id,
                                organization: asn.map(|_| {
                                    netqmon_classifier_client::ClassifiedEntity {
                                        id: format!("asn-org-{suffix}"),
                                        confidence: 0.91,
                                    }
                                }),
                                application: asn.map(|_| {
                                    netqmon_classifier_client::ClassifiedEntity {
                                        id: format!("asn-app-{suffix}"),
                                        confidence: 0.92,
                                    }
                                }),
                                traffic_class: asn.map(|_| {
                                    netqmon_classifier_client::ClassifiedEntity {
                                        id: "test-asn".to_owned(),
                                        confidence: 0.9,
                                    }
                                }),
                                traffic_role: None,
                                protocol: entry.dpi_evidence.as_ref().map(|_| {
                                    netqmon_classifier_client::ClassifiedEntity {
                                        id: "late-dpi".to_owned(),
                                        confidence: 0.95,
                                    }
                                }),
                                evidence: asn
                                    .map(|value| {
                                        vec![netqmon_classifier_client::ClassificationEvidence {
                                            evidence_type: "remote_asn".to_owned(),
                                            value: value.to_string(),
                                            source: "test-geo".to_owned(),
                                            weight: 0.92,
                                        }]
                                    })
                                    .unwrap_or_default(),
                                device_evidence: Vec::new(),
                                error: None,
                            }
                        })
                        .collect();
                    netqmon_classifier_client::ServerResponse::ClassificationBatch {
                        request_id,
                        result: netqmon_classifier_client::ClassificationBatchResult { entries },
                    }
                }
                other => panic!("unexpected classifier request: {other:?}"),
            };
            writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        observed
    })
}

fn asn_test_flow(remote_ip: Vec<u8>, client_port: u32, timestamp: u64) -> FlowDelta {
    FlowDelta {
        ip_version: u32::try_from(if remote_ip.len() == 4 { 4 } else { 6 }).unwrap(),
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port,
        remote_ip,
        remote_port: 443,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        packets: 1,
        lifecycle: FlowLifecycle::Ended as i32,
        ..Default::default()
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn collector_forwards_batch_local_geo_asns_to_classifier_and_late_dpi() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("asn-classifier.sock");
    let server = spawn_asn_classifier_server(socket_path.clone(), 13);
    let classifier = crate::classifier::ClassifierHandle::connect(socket_path).unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        classifier,
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "test".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "asn-test".to_owned(),
            gateway_name: "asn-test".to_owned(),
        })
        .unwrap();
    let v4: IpAddr = "203.0.113.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    let missed: IpAddr = "198.51.100.10".parse().unwrap();
    let failed: IpAddr = "2001:db8::bad".parse().unwrap();
    let v4_bytes = vec![203, 0, 113, 10];
    let v6_bytes = "2001:db8::10"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    let failed_bytes = "2001:db8::bad"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    let primary_geo = Arc::new(CountingAsnGeoProvider::new(
        [(v4, 64_512), (v6, 64_513)],
        [failed],
    ));
    state.lock().geo_provider = primary_geo.clone();

    let timestamp = 1_700_000_000_000;
    let initial = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 1],
            domain: "generic.cdn.test".to_owned(),
            answer_ip: v6_bytes.clone(),
            record_type: DnsRecordType::Aaaa as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: timestamp,
        }],
        flows: vec![
            asn_test_flow(v4_bytes.clone(), 50_001, timestamp),
            asn_test_flow(v4_bytes.clone(), 50_002, timestamp),
            asn_test_flow(v6_bytes.clone(), 50_003, timestamp),
            asn_test_flow(vec![198, 51, 100, 10], 50_004, timestamp),
            asn_test_flow(vec![198, 51, 100, 10], 50_005, timestamp),
            asn_test_flow(failed_bytes.clone(), 50_006, timestamp),
            asn_test_flow(failed_bytes.clone(), 50_007, timestamp),
        ],
        ..Default::default()
    };
    assert_eq!(
        state.accept_batch(&initial).unwrap(),
        BatchDisposition::Accepted
    );
    assert_eq!(primary_geo.call_count(v4), 1);
    assert_eq!(primary_geo.call_count(v6), 1);
    assert_eq!(primary_geo.call_count(missed), 1);
    assert_eq!(primary_geo.call_count(failed), 1);

    let (organization, application, evidence): (String, String, String) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT organization_id, application_id, classification_evidence_json FROM flow_sessions WHERE client_port=50001",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(organization, "asn-org-64512");
    assert_eq!(application, "asn-app-64512");
    assert!(evidence.contains("remote_asn"));
    assert!(evidence.contains("64512"));

    let second = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 2,
        sent_at: timestamp + 1,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![asn_test_flow(v4_bytes.clone(), 50_008, timestamp + 1)],
        ..Default::default()
    };
    state.accept_batch(&second).unwrap();
    assert_eq!(primary_geo.call_count(v4), 2, "ASN cache is batch-local");

    let replacement_geo = Arc::new(CountingAsnGeoProvider::new(
        [(v4, 64_514), (v6, 64_515)],
        [],
    ));
    state.lock().geo_provider = replacement_geo.clone();
    let replacement = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 3,
        sent_at: timestamp + 2,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![asn_test_flow(v4_bytes, 50_009, timestamp + 2)],
        ..Default::default()
    };
    state.accept_batch(&replacement).unwrap();
    assert_eq!(replacement_geo.call_count(v4), 1);
    let replacement_application: String = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT application_id FROM flow_sessions WHERE client_port=50009",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(replacement_application, "asn-app-64514");

    let late = dpi::CachedResult::for_test(
        enrollment.gateway_id,
        "asn-test".to_owned(),
        netqmon_protocol::v1::FlowSampleKey {
            ip_version: 6,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_003,
            remote_ip: v6_bytes,
            remote_port: 443,
            first_seen_unix_ms: timestamp,
        },
        timestamp + 3,
        Some(dpi::engine::DpiResult {
            protocol: "tls".to_owned(),
            confidence: 0.9,
            metadata: std::collections::BTreeMap::from([(
                "hostname".to_owned(),
                "sni.example.test".to_owned(),
            )]),
            source: "ndpi".to_owned(),
        }),
    );
    apply_sample_result(&mut state.lock(), &late).unwrap();
    let (protocol, late_evidence): (String, String) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT protocol_id, classification_evidence_json FROM flow_sessions WHERE client_port=50003",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(protocol, "late-dpi");
    assert!(late_evidence.contains("64515"));

    let requests = server.join().unwrap();
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("203.0.113.10") && request.remote_asn == Some(64_512)
    }));
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("2001:db8::10")
            && request.remote_asn == Some(64_515)
            && request.has_dpi
    }));
    assert!(requests.iter().any(|request| {
        request.domain.as_deref() == Some("sni.example.test")
            && request.remote_asn == Some(64_515)
            && request.has_dpi
    }));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.remote_ip.as_deref() == Some("198.51.100.10"))
            .filter(|request| request.remote_asn.is_none())
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.remote_ip.as_deref() == Some("2001:db8::bad"))
            .filter(|request| request.remote_asn.is_none())
            .count(),
        2
    );
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("203.0.113.10") && request.remote_asn == Some(64_514)
    }));
}

#[tokio::test]
async fn destinations_are_enriched_by_the_configured_geo_provider() {
    let state = query_state();
    state.lock().geo_provider = Arc::new(TestGeoProvider);

    // Test default language
    let response = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let destination = &value["data"][0];
    assert_eq!(destination["country_code"], "US");
    assert_eq!(destination["country_name"], "United States");
    assert_eq!(destination["region"], "California");
    assert_eq!(destination["city"], "Los Angeles");
    assert_eq!(destination["latitude"], 34.0522);
    assert_eq!(destination["longitude"], -118.2437);
    assert_eq!(destination["asn"], 64_496);
    assert_eq!(destination["organization"], "Example Network");

    // Test with ?lang=zh-CN
    let response_zh = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10&lang=zh-CN")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_zh.status(), StatusCode::OK);
    let body_zh = to_bytes(response_zh.into_body(), 16 * 1024).await.unwrap();
    let value_zh: serde_json::Value = serde_json::from_slice(&body_zh).unwrap();
    assert_eq!(value_zh["data"][0]["country_name"], "美国");
}

#[tokio::test]
async fn geo_summary_aggregates_country_and_asn_traffic() {
    let state = query_state();
    state.lock().geo_provider = Arc::new(TestGeoProvider);
    let response = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], true);
    assert_eq!(value["data"]["top_countries"][0]["country_code"], "US");
    assert_eq!(
        value["data"]["top_countries"][0]["country_name"],
        "United States"
    );
    assert_eq!(value["data"]["top_countries"][0]["bytes"], 150);
    assert_eq!(value["data"]["top_asns"][0]["asn"], 64_496);
    assert_eq!(value["data"]["country_distribution"][0]["bytes"], 150);

    // Test with ?lang=zh-CN
    let response_zh = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/geo?lang=zh-CN")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_zh.status(), StatusCode::OK);
    let body_zh = to_bytes(response_zh.into_body(), 16 * 1024).await.unwrap();
    let value_zh: serde_json::Value = serde_json::from_slice(&body_zh).unwrap();
    assert_eq!(value_zh["data"]["top_countries"][0]["country_name"], "美国");
}

#[tokio::test]
async fn flows_apply_composable_server_side_filters() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE flow_sessions SET domain = 'example.com', application_id = 'example'",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    for uri in [
        "/internal/flows?search=laptop",
        "/internal/flows?client=laptop&application=example",
        "/internal/flows?domain=example.com&ip=198.51.100.1",
        "/internal/flows?protocol=tcp&port=443&direction=upload",
        "/internal/flows?from=1699999999000&to=1700000001000",
        "/internal/flows?sort=download&order=asc",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"].as_array().unwrap().len(), 1, "{uri}");
        assert_eq!(value["data"][0]["client_name"], "laptop", "{uri}");
        assert!(value["data"][0]["organization"].is_string(), "{uri}");
        assert!(value["data"][0]["traffic_role"].is_string(), "{uri}");
        assert!(value["data"][0]["protocol_id"].is_string(), "{uri}");
        assert!(value["data"][0]["evidence"].is_string(), "{uri}");
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/flows?protocol=udp&direction=download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn flows_use_a_stable_cursor_without_counting_all_records() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "INSERT INTO flow_sessions(
                 id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                 remote_ip, remote_port, direction, upload_bytes, download_bytes, packets,
                 started_at, last_seen_at, ended_at, checkpointed_at, domain, application_id,
                 category_id, classification_confidence, classification_reason
             ) SELECT 'zz-cursor-second', gateway_id, device_id, ip_version, protocol, client_ip,
                    client_port, remote_ip, remote_port, direction, upload_bytes, download_bytes,
                    packets, started_at, last_seen_at, ended_at, checkpointed_at, domain,
                    application_id, category_id, classification_confidence, classification_reason
             FROM flow_sessions LIMIT 1",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/flows?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(first.into_body(), 16 * 1024).await.unwrap();
    let first_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(first_value["data"].as_array().unwrap().len(), 1);
    assert!(first_value["pagination"].get("total").is_none());
    let cursor = first_value["pagination"]["next_cursor"].as_str().unwrap();
    let encoded_cursor = cursor.bytes().fold(String::new(), |mut output, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(output, "%{byte:02X}").unwrap();
        }
        output
    });
    let second = router
        .oneshot(
            Request::builder()
                .uri(format!("/internal/flows?limit=1&cursor={encoded_cursor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(second.into_body(), 16 * 1024).await.unwrap();
    let second_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(second_value["data"][0]["id"], "zz-cursor-second");
    assert!(second_value["pagination"]["next_cursor"].is_null());
}

#[tokio::test]
async fn overview_status_is_small_and_matches_overview() {
    for online in [false, true] {
        let state = query_state();
        let last_seen = if online {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        } else {
            1_700_000_000_000
        };
        state
            .lock()
            .storage
            .connection()
            .execute("UPDATE gateways SET last_seen = ?1", [last_seen])
            .unwrap();
        let router = internal_router(state);
        let mut responses = Vec::new();
        for path in ["/internal/overview/status", "/internal/overview"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            if path.ends_with("/status") {
                assert!(body.len() < 1024);
            }
            responses.push(serde_json::from_slice::<serde_json::Value>(&body).unwrap());
        }
        let status = &responses[0]["data"];
        let full = &responses[1]["data"];
        assert_eq!(status.as_object().unwrap().len(), 4);
        assert_eq!(status["controller_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            status["gateway_status"],
            if online { "online" } else { "offline" }
        );
        assert_eq!(status["gateway_status"], full["gateway_status"]);
        assert_eq!(status["gateway"].as_object().unwrap().len(), 5);
        for field in [
            "id",
            "name",
            "last_seen",
            "offline_after_ms",
            "agent_version",
        ] {
            assert_eq!(status["gateway"][field], full["gateway"][field]);
        }
    }
}

#[tokio::test]
async fn overview_status_handles_unenrolled_gateway() {
    let response = internal_router(test_state_with_repository_rules())
        .oneshot(
            Request::builder()
                .uri("/internal/overview/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["data"],
        serde_json::json!({
            "gateway_status": "unenrolled", "gateway": null,
            "controller_version": env!("CARGO_PKG_VERSION"),
            "topology": null,
        })
    );
}

#[tokio::test]
async fn overview_reports_stale_gateway_and_capture_health_honestly() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute("UPDATE gateways SET last_seen = 1700000000000", [])
        .unwrap();
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["gateway_status"], "offline");
    assert_eq!(value["data"]["gateway"]["name"], "query-router");
    assert_eq!(value["data"]["gateway"]["openwrt_version"], "24.10.0");
    assert_eq!(value["data"]["gateway"]["kernel_version"], "6.6.73");
    assert_eq!(value["data"]["gateway"]["agent_version"], "0.1.0");
    assert_eq!(value["data"]["gateway"]["offloading_status"], "enabled");
    assert_eq!(value["data"]["gateway"]["interface_counter_sanity"], "ok");
    assert!(
        value["data"]["gateway"]["capture_warning"]
            .as_str()
            .unwrap()
            .contains("offline threshold")
    );
}

#[tokio::test]
async fn overview_reports_interface_counter_sanity_warning() {
    let state = query_state();
    let gateway_id = {
        let inner = state.lock();
        inner.gateway.as_ref().unwrap().gateway_id.clone()
    };
    {
        let mut inner = state.lock();
        inner.realtime.update(
            &TelemetryBatch {
                gateway_id,
                boot_id: "boot-query".to_owned(),
                sequence: 2,
                sent_at: 1_700_000_001_000,
                agent_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                health: Some(AgentHealth {
                    observed_at_unix_ms: 1_700_000_001_000,
                    capture_interface: "br-lan".to_owned(),
                    hardware_flow_offload: OffloadStatus::Disabled as i32,
                    interface_counter_sanity: CounterSanityStatus::Degraded as i32,
                    interface_delta_bytes: 524_288,
                    interface_delta_packets: 300,
                    flow_delta_bytes: 65_536,
                    flow_delta_packets: 30,
                    ..AgentHealth::default()
                }),
                ..TelemetryBatch::default()
            },
            &[],
            1_700_000_001_000,
            1_700_000_001_000,
        );
    }
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["data"]["gateway"]["interface_counter_sanity"],
        "degraded"
    );
    assert!(
        value["data"]["gateway"]["capture_warning"]
            .as_str()
            .unwrap()
            .contains("interface counters exceeded")
    );
}

#[tokio::test]
async fn internal_query_api_validates_pagination_ranges_and_unknown_fields() {
    let router = internal_router(query_state());
    for (uri, code) in [
        ("/internal/clients?limit=0", "invalid_pagination"),
        ("/internal/domains?limit=201", "invalid_pagination"),
        ("/internal/clients?offset=1000001", "invalid_pagination"),
        ("/internal/flows?unexpected=true", "invalid_query"),
        ("/internal/flows?ip=not-an-ip", "invalid_ip"),
        ("/internal/flows?protocol=quic", "invalid_protocol"),
        ("/internal/flows?direction=sideways", "invalid_direction"),
        ("/internal/flows?cursor=broken", "invalid_cursor"),
        ("/internal/clients/-1?limit=10", "invalid_client_id"),
        (
            "/internal/applications/INVALID!?limit=10",
            "invalid_application_id",
        ),
        (
            "/internal/applications/unknown?category=INVALID!",
            "invalid_category_id",
        ),
        ("/internal/traffic?from=20&to=10", "invalid_time_range"),
        (
            "/internal/traffic?group_by=unsupported_group",
            "invalid_group_by",
        ),
        ("/internal/insights?unexpected=true", "invalid_query"),
        (
            "/internal/insights?from=0&to=2678400000",
            "invalid_time_range",
        ),
        ("/internal/insights?limit=201", "invalid_pagination"),
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], 1, "{uri}");
        assert_eq!(value["error"]["code"], code, "{uri}");
        assert!(value.get("pagination").is_some(), "{uri}");
    }
}

#[tokio::test]
async fn request_timeout_returns_http_408() {
    let response = public_router(test_state())
        .oneshot(
            Request::builder()
                .uri("/test/slow")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn both_listeners_bind_and_internal_listener_is_loopback() {
    let config = CollectorConfig {
        public_addr: "127.0.0.1:0".parse().unwrap(),
        internal_addr: "127.0.0.1:0".parse().unwrap(),
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        database_path: PathBuf::from(":memory:"),
        storage_backend: "sqlite".to_owned(),
        clickhouse_config: ClickHouseConfig::default(),
        classifier_socket: PathBuf::from("/tmp/classifierd.sock"),
        geo_directory: PathBuf::from(DEFAULT_GEO_DIRECTORY),
        mac_dataset_path: default_mac_dataset_path(&PathBuf::from(":memory:")),
        mac_dataset_source_url: DEFAULT_MAC_DATASET_SOURCE_URL.to_owned(),
        icon_cache_config: IconCacheConfig::default(),
    };
    let (public, internal) = match bind_listeners(&config).await {
        Ok(listeners) => listeners,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("listener binding failed: {error}"),
    };
    assert_ne!(public.local_addr().unwrap().port(), 0);
    assert!(internal.local_addr().unwrap().ip().is_loopback());
    assert_ne!(internal.local_addr().unwrap().port(), 0);
}

#[test]
fn default_mac_dataset_path_uses_database_directory() {
    assert_eq!(
        default_mac_dataset_path(Path::new("/var/lib/netqmon/netqmon.db")),
        PathBuf::from("/var/lib/netqmon/mac-prefixes.json")
    );
    assert_eq!(
        default_mac_dataset_path(Path::new("netqmon.db")),
        PathBuf::from("mac-prefixes.json")
    );
}

#[test]
fn default_geo_directory_uses_database_directory() {
    let actual = default_geo_directory(Path::new("/var/lib/netqmon/netqmon.db"));
    if Path::new(DEFAULT_GEO_DIRECTORY).is_dir() || Path::new("/data").is_dir() {
        assert_eq!(actual, PathBuf::from(DEFAULT_GEO_DIRECTORY));
    } else {
        assert_eq!(actual, PathBuf::from("/var/lib/netqmon/geo"));
    }
}

#[tokio::test]
async fn enrollment_requires_token_and_allows_only_one_active_gateway() {
    let state = test_state();
    let router = public_router(state.clone());
    let missing = router
        .clone()
        .oneshot(enrollment_request(""))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let enrolled = enroll_agent(&router).await;
    assert!(!enrolled.gateway_id.is_empty());
    assert_eq!(enrolled.agent_token.len(), 64);

    let repeated = router
        .clone()
        .oneshot(enrollment_request(ENROLLMENT_TOKEN))
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::CONFLICT);
    let message = to_bytes(repeated.into_body(), 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&message).contains("already enrolled"));

    let repeated_invalid = router.oneshot(enrollment_request("wrong")).await.unwrap();
    assert_eq!(repeated_invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stale_gateway_enrollment_rotates_token_and_preserves_history() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrolled = enroll_agent(&router).await;
    let batch = sample_batch(&enrolled.gateway_id, 1);
    let response = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrolled.agent_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();

    let replacement = enroll_agent(&router).await;
    assert_eq!(replacement.gateway_id, enrolled.gateway_id);
    assert_ne!(replacement.agent_token, enrolled.agent_token);

    let old_token_response = router
        .clone()
        .oneshot(telemetry_request(
            &sample_batch(&replacement.gateway_id, 2),
            &enrolled.agent_token,
        ))
        .await
        .unwrap();
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = router
        .clone()
        .oneshot(telemetry_request(
            &sample_batch(&replacement.gateway_id, 2),
            &replacement.agent_token,
        ))
        .await
        .unwrap();
    assert_eq!(new_token_response.status(), StatusCode::NO_CONTENT);

    let history_count: i64 = state
        .lock()
        .storage
        .connection()
        .query_row("SELECT COUNT(*) FROM ingest_batches", [], |row| row.get(0))
        .unwrap();
    assert_eq!(history_count, 2);
}

#[tokio::test]
async fn collector_ingestion_remains_available_during_bounded_sqlite_retention() {
    use std::time::Instant;

    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("retention-ingest.db");
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open(&database_path).unwrap(),
        repository_rule_engine(),
    )
    .unwrap();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let now = unix_time_ms();
    {
        let inner = state.lock();
        inner
            .storage
            .connection()
            .execute(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<50000)
                 INSERT INTO traffic_scope_minute(
                   timestamp,gateway_id,scope,direction,device_id,application_id,category_id,
                   domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count)
                 SELECT ?1,?2,1,1,1,'app','cat','example',CAST(printf('%016x',i) AS BLOB),
                   6,'tcp',1,1,1,1 FROM n",
                rusqlite::params![
                    i64::try_from(now.saturating_sub(31 * 86_400_000_u64)).unwrap(),
                    enrollment.gateway_id
                ],
            )
            .unwrap();
    }

    let maintenance_state = state.clone();
    let retention = tokio::task::spawn_blocking(move || -> Result<std::time::Duration, String> {
        let started = Instant::now();
        for _ in 0..100 {
            match maintenance_state.run_maintenance(true) {
                Ok(true) => return Ok(started.elapsed()),
                Ok(false) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Err("retention did not finish within 100 maintenance slices".into())
    });

    let mut timings = Vec::new();
    let mut accepted = 0;
    const REQUESTS: u64 = 500;
    for sequence in 1..=REQUESTS {
        let started = Instant::now();
        let response = router
            .clone()
            .oneshot(telemetry_request(
                &sample_batch(&enrollment.gateway_id, sequence),
                &enrollment.agent_token,
            ))
            .await
            .unwrap();
        timings.push(started.elapsed());
        accepted += usize::from(response.status() == StatusCode::NO_CONTENT);
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    let cleanup_elapsed = retention.await.unwrap().unwrap();
    timings.sort();
    let percentile = |p: usize| {
        timings
            .get(
                timings
                    .len()
                    .saturating_mul(p)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .copied()
            .unwrap_or_default()
    };
    eprintln!(
        "collector_retention_ingest accepted={accepted}/{REQUESTS} cleanup_ms={} p50_us={} p95_us={} p99_us={} max_us={}",
        cleanup_elapsed.as_millis(),
        percentile(50).as_micros(),
        percentile(95).as_micros(),
        percentile(99).as_micros(),
        timings.last().unwrap().as_micros(),
    );
}

#[tokio::test]
async fn concurrent_stale_enrollment_rotates_gateway_only_once() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrolled = enroll_agent(&router).await;
    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();

    let first = router.clone().oneshot(enrollment_request(ENROLLMENT_TOKEN));
    let second = router.clone().oneshot(enrollment_request(ENROLLMENT_TOKEN));
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );

    let gateway = state.lock().storage.gateway().unwrap().unwrap();
    assert_eq!(gateway.id, enrolled.gateway_id);
    assert_ne!(gateway.agent_token_hash, hash_token(&enrolled.agent_token));
}

#[tokio::test]
async fn invalid_agent_token_is_rejected_before_payload_processing() {
    let state = test_state();
    let router = public_router(state.clone());
    let _enrollment = enroll_agent(&router).await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/telemetry")
                .header(AUTHORIZATION, "Bearer wrong")
                .body(Body::from("not protobuf"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.stats().accepted_batches, 0);
}

#[tokio::test]
async fn duplicate_batch_counts_traffic_only_once() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let batch = sample_batch(&enrollment.gateway_id, 1);

    let first = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    let duplicate = router
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    assert_eq!(
        state.stats(),
        IngestStats {
            accepted_batches: 1,
            dedupe_hits: 1,
            traffic_bytes: 150,
        }
    );
    let realtime = state.realtime_snapshot();
    assert_eq!(realtime.history.len(), 1);
    assert_eq!(realtime.total.upload_bytes_per_second, 100);
}

#[tokio::test]
async fn rejects_too_many_flows_and_oversized_wire_body() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let mut batch = sample_batch(&enrollment.gateway_id, 1);
    batch.flows = vec![FlowDelta::default(); MAX_FLOWS_PER_BATCH + 1];
    let response = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/telemetry")
                .header(AUTHORIZATION, format!("Bearer {}", enrollment.agent_token))
                .body(Body::from(vec![0; MAX_BODY_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(state.stats().accepted_batches, 0);
}

#[tokio::test]
async fn synthetic_agent_sustains_one_second_batches() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;

    for sequence in 1..=10 {
        let batch = sample_batch(&enrollment.gateway_id, sequence);
        let response = router
            .clone()
            .oneshot(telemetry_request(&batch, &enrollment.agent_token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        state.stats(),
        IngestStats {
            accepted_batches: 10,
            dedupe_hits: 0,
            traffic_bytes: 1_500,
        }
    );
}

#[test]
fn gateway_auth_and_traffic_survive_collector_restart() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("netqmon.db");
    let request = EnrollRequest {
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "router".to_owned(),
    };
    let state = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    let enrollment = state.enroll(&request).unwrap();
    let batch = sample_batch(&enrollment.gateway_id, 1);
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    drop(state);

    let restarted = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    assert_eq!(
        restarted.authenticate(&enrollment.agent_token),
        Some(enrollment.gateway_id)
    );
    let inner = restarted.lock();
    let traffic: i64 = inner
        .storage
        .connection()
        .query_row(
            "SELECT upload_bytes + download_bytes FROM traffic_total_minute",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(traffic, 150);
}

#[test]
fn rotated_gateway_credentials_survive_collector_restart() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("netqmon.db");
    let request = EnrollRequest {
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        agent_version: "0.1.0-beta.4".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "router".to_owned(),
    };
    let state = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    let initial = state.enroll(&request).unwrap();
    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();
    let replacement = state.enroll(&request).unwrap();
    assert_eq!(replacement.gateway_id, initial.gateway_id);
    assert_ne!(replacement.agent_token, initial.agent_token);
    drop(state);

    let restarted = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    assert_eq!(
        restarted.authenticate(&replacement.agent_token),
        Some(replacement.gateway_id)
    );
    assert_eq!(restarted.authenticate(&initial.agent_token), None);
}

#[test]
fn dns_attribution_classifies_each_client_without_cross_talk() {
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        crate::classifier::ClassifierHandle::test_default(),
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "boot-1".to_owned(),
            gateway_name: "router".to_owned(),
        })
        .unwrap();
    let observed_at = 1_700_000_000_000;
    let shared_address = vec![203, 0, 113, 9];
    let clients = [vec![192, 0, 2, 10], vec![192, 0, 2, 11]];
    let domains = ["www.youtube.com", "api.openai.com"];
    let mut batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "boot-1".to_owned(),
        sequence: 1,
        sent_at: observed_at,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        ..TelemetryBatch::default()
    };
    for (index, client) in clients.iter().enumerate() {
        batch.dns_observations.push(DnsObservation {
            client_ip: client.clone(),
            domain: domains[index].to_owned(),
            answer_ip: shared_address.clone(),
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: observed_at,
        });
        batch.flows.push(FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: client.clone(),
            client_port: 50_000 + u32::try_from(index).unwrap(),
            remote_ip: shared_address.clone(),
            remote_port: 443,
            direction: 1,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            first_seen_unix_ms: observed_at,
            last_seen_unix_ms: observed_at,
            lifecycle: FlowLifecycle::Ended as i32,
            ..FlowDelta::default()
        });
    }
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );

    let inner = state.lock();
    let mut statement = inner
        .storage
        .connection()
        .prepare("SELECT domain, application_id, category_id FROM flow_sessions ORDER BY client_ip")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "www.youtube.com".to_owned(),
                "youtube".to_owned(),
                "streaming".to_owned(),
            ),
            (
                "api.openai.com".to_owned(),
                "openai".to_owned(),
                "ai".to_owned(),
            ),
        ]
    );
}

// ---------- Phase 10 auth integration tests ----------

fn auth_status_request() -> Request<Body> {
    Request::builder()
        .uri("/internal/auth/status")
        .body(Body::empty())
        .unwrap()
}

fn auth_setup_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/setup")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap()
}

fn auth_login_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap()
}

fn auth_verify_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/verify")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn auth_logout_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn parse_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn auth_status_reports_setup_required_initially() {
    let router = internal_router(test_state());
    let response = router.oneshot(auth_status_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["setup_required"], true);
}

#[tokio::test]
async fn setup_creates_admin_and_blocks_duplicate() {
    let state = test_state();
    let router = internal_router(state);

    // Initial setup succeeds.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "strongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(!json["data"]["session_token"].as_str().unwrap().is_empty());
    assert!(!json["data"]["user"]["id"].as_str().unwrap().is_empty());
    assert_eq!(json["data"]["user"]["username"], "admin");
    assert!(json["data"]["expires_at"].as_u64().unwrap() > 0);

    // Status now reports setup complete.
    let response = router.clone().oneshot(auth_status_request()).await.unwrap();
    let json = parse_json(response).await;
    assert_eq!(json["data"]["setup_required"], false);

    // Duplicate setup is rejected with 409.
    let response = router
        .oneshot(auth_setup_request("admin2", "anotherpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "setup_complete");
}

#[tokio::test]
async fn setup_validates_credential_requirements() {
    let router = internal_router(test_state());

    // Username too short.
    let response = router
        .clone()
        .oneshot(auth_setup_request("ab", "strongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "invalid_credentials");

    // Password too short.
    let response = router
        .oneshot(auth_setup_request("admin", "short"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_with_valid_credentials_issues_session() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin first.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Login with valid credentials.
    let response = router
        .clone()
        .oneshot(auth_login_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(!json["data"]["session_token"].as_str().unwrap().is_empty());
    assert_eq!(json["data"]["user"]["username"], "admin");
}

#[tokio::test]
async fn login_with_invalid_credentials_returns_unauthorized() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin first.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Wrong password.
    let response = router
        .clone()
        .oneshot(auth_login_request("admin", "wrongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "invalid_login");

    // Non-existent user.
    let response = router
        .oneshot(auth_login_request("nonexistent", "somepassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_with_valid_session_returns_user_info() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin and extract token.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    let json = parse_json(response).await;
    let token = json["data"]["session_token"].as_str().unwrap().to_owned();

    // Verify returns user info.
    let response = router
        .clone()
        .oneshot(auth_verify_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["user"]["username"], "admin");
    assert!(json["data"]["expires_at"].as_u64().unwrap() > 0);

    // Verify with invalid token returns 401.
    let response = router
        .oneshot(auth_verify_request("invalid-token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_invalidates_session() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin and extract token.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    let json = parse_json(response).await;
    let token = json["data"]["session_token"].as_str().unwrap().to_owned();

    // Session is initially valid.
    let response = router
        .clone()
        .oneshot(auth_verify_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Logout.
    let response = router
        .clone()
        .oneshot(auth_logout_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Session is now invalid.
    let response = router.oneshot(auth_verify_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn retention_maintenance_checkpoints_expired_flows_from_the_owning_cache() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("retention-owner-cache.db");
    let now = unix_time_ms();
    let last_received = now.saturating_sub(31 * 60 * 1_000);
    let gateway_id = "gateway-owner-cache";
    let mut storage = SqliteStorage::open(&database_path).unwrap();
    storage
        .save_gateway(gateway_id, "router", "test", &[7; 32], last_received)
        .unwrap();
    let mut batch = sample_batch(gateway_id, 1);
    batch.sent_at = last_received;
    batch.flows[0].lifecycle = FlowLifecycle::Active as i32;
    batch.flows[0].last_seen_unix_ms = last_received;
    storage.persist_batch(&batch, last_received).unwrap();
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT COUNT(*) FROM flow_sessions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "the active flow has not reached its regular checkpoint yet"
    );

    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, storage, repository_rule_engine()).unwrap();
    assert!(state.run_maintenance(true).unwrap());

    let inner = state.lock();
    let (rows, upload, download, ended_at): (i64, i64, i64, Option<i64>) = inner
        .storage
        .connection()
        .query_row(
            "SELECT COUNT(*),SUM(upload_bytes),SUM(download_bytes),MAX(ended_at) FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!((rows, upload, download), (1, 100, 50));
    assert!(ended_at.is_some());
    assert_eq!(inner.storage.active_flow_count().unwrap(), 0);
}

#[test]
fn file_maintenance_resumes_bounded_rollup_with_owner_progress() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("bounded-rollup-maintenance.db");
    let flow_time = 1_700_000_000_000_u64;
    let gateway_id = "gateway-bounded-rollup";
    let mut storage = SqliteStorage::open(&database_path).unwrap();
    storage
        .save_gateway(gateway_id, "router", "test", &[7; 32], flow_time)
        .unwrap();

    let mut batch = sample_batch(gateway_id, 1);
    batch.sent_at = flow_time;
    batch.flows = (0..620)
        .map(|index| FlowDelta {
            client_ip: vec![192, 0, 2, (index % 250 + 1) as u8],
            client_port: index as u32,
            remote_ip: vec![198, 51, 100, (index % 250 + 1) as u8],
            remote_port: 10_000 + index as u32,
            first_seen_unix_ms: flow_time + index as u64,
            last_seen_unix_ms: flow_time + index as u64,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 1,
            ..FlowDelta::default()
        })
        .collect();
    storage.persist_batch(&batch, flow_time).unwrap();

    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, storage, repository_rule_engine()).unwrap();
    let maintenance_time = flow_time + 2 * 24 * 60 * 60 * 1_000;
    let mut completed = false;
    for _ in 0..20 {
        if state.run_maintenance_at(false, maintenance_time).unwrap() {
            completed = true;
            break;
        }
    }
    assert!(completed, "bounded maintenance should eventually finish");

    let inner = state.lock();
    let (minute_upload, hour_upload, day_upload): (i64, i64, i64) = inner
        .storage
        .connection()
        .query_row(
            "SELECT
                (SELECT COALESCE(SUM(upload_bytes),0) FROM traffic_total_minute),
                (SELECT COALESCE(SUM(upload_bytes),0) FROM traffic_total_hour),
                (SELECT COALESCE(SUM(upload_bytes),0) FROM traffic_total_day)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (minute_upload, hour_upload, day_upload),
        (62_000, 62_000, 62_000)
    );
}

#[tokio::test]
async fn settings_retention_endpoints_and_manual_run() {
    let state = test_state();
    let router = internal_router(state);

    // 1. GET returns default retention
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/retention")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["flow_sessions_days"], 7);
    assert_eq!(json["data"]["dns_days"], 7);
    assert_eq!(json["data"]["minute_days"], 30);
    assert_eq!(json["data"]["hour_days"], 365);
    assert_eq!(json["data"]["day_days"], 0);

    // 2. PUT with invalid minute_days: 0 returns 400
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/settings/retention")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"flow_sessions_days":7,"dns_days":7,"minute_days":0,"hour_days":30,"day_days":0}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 3. PUT with valid policy updates and returns new policy
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/settings/retention")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"flow_sessions_days":14,"dns_days":3,"minute_days":60,"hour_days":180,"day_days":730}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["flow_sessions_days"], 14);
    assert_eq!(json["data"]["dns_days"], 3);
    assert_eq!(json["data"]["minute_days"], 60);
    assert_eq!(json["data"]["hour_days"], 180);
    assert_eq!(json["data"]["day_days"], 730);

    // 4. GET verifies persisted update
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/retention")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["flow_sessions_days"], 14);

    // 5. POST manual retention run returns completed
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/retention/run")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["status"], "completed");
}

#[tokio::test]
async fn settings_icon_cache_endpoints_report_and_clear_stats() {
    let router = internal_router(test_state());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/icon-cache")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["entry_count"], 0);
    assert_eq!(json["weighted_size_bytes"], 0);
    assert_eq!(json["capacity_bytes"], 32 * 1024 * 1024);
    assert_eq!(json["positive_ttl_seconds"], 24 * 60 * 60);
    assert_eq!(json["negative_ttl_seconds"], 60 * 60);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/icon-cache/clear")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["entry_count"], 0);
    assert_eq!(json["weighted_size_bytes"], 0);
}

#[tokio::test]
async fn settings_rules_reload_endpoint() {
    let state = test_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/rules/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["application_count"], 3);
    assert_eq!(json["data"]["selfhost_application_count"], 1);
    assert_eq!(json["data"]["client_count"], 1);
    assert_eq!(json["data"]["protocol_count"], 2);
    assert_eq!(json["data"]["rule_version"], "test-rule-version");
    assert!(json["data"]["updated_at_unix_ms"].as_u64().unwrap() > 0);
    assert!(json["data"]["reloaded_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn settings_diagnostics_endpoint() {
    let state = query_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["db_backend"], "sqlite");
    assert!(json["data"]["db_size_bytes"].as_i64().unwrap() > 0);
    assert!(json["data"]["sqlite"]["page_size_bytes"].as_i64().unwrap() > 0);
    assert!(json["data"]["sqlite"]["freelist_pages"].as_i64().unwrap() >= 0);
    assert!(json["data"]["sqlite"]["wal_file_bytes"].is_null());
    assert!(json["data"]["gateway"].is_object());
    assert!(json["data"]["retention"].is_object());
    assert_eq!(json["data"]["collector_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["data"]["classification"]["availability"], "ready");
    assert_eq!(json["data"]["classification"]["classifier_version"], "test");
    assert_eq!(
        json["data"]["classification"]["stats"]["application_count"],
        3
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["selfhost_application_count"],
        1
    );
    assert_eq!(json["data"]["classification"]["stats"]["client_count"], 1);
    assert_eq!(json["data"]["classification"]["stats"]["protocol_count"], 2);
    assert_eq!(
        json["data"]["classification"]["stats"]["sample_match_requests"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["signature_match_count"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["signature_match_application_count"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["rule_version"],
        "test-rule-version"
    );
    assert!(
        json["data"]["classification"]["stats"]["updated_at_unix_ms"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json["data"].get("rule_sources").is_none());
}

#[tokio::test]
async fn sqlite_diagnostics_reports_database_and_wal_file_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("diagnostics.db");
    let storage = SqliteStorage::open(&db).unwrap();
    storage
        .connection()
        .execute("CREATE TABLE diagnostic_probe (value INTEGER)", [])
        .unwrap();
    let wal = dir.path().join("diagnostics.db-wal");
    let wal_before = std::fs::metadata(&wal).unwrap().len();
    assert!(wal_before > 0);
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, storage, repository_rule_engine()).unwrap();
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(
        json["data"]["sqlite"]["wal_file_bytes"].as_u64(),
        Some(wal_before)
    );
    assert!(
        json["data"]["sqlite"]["database_file_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[tokio::test]
async fn settings_diagnostics_includes_classifier_manager_field() {
    let state = test_state();
    let router = internal_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert!(json["data"].get("classifier_manager").is_some());
}

#[test]
fn classifier_manager_status_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let status_file = temp.path().join("status.json");
    let status_json = serde_json::json!({
        "state": "running",
        "current_version": "0.1.0",
        "candidate_version": null,
        "last_checked_at": 1726000000,
        "last_error": null
    });
    std::fs::write(&status_file, serde_json::to_vec(&status_json).unwrap()).unwrap();

    let parsed = crate::query_api::classifier_manager_status_from_path(&status_file);
    assert!(parsed.is_some());
    let val = parsed.unwrap();
    assert_eq!(val["state"], "running");
    assert_eq!(val["current_version"], "0.1.0");
    assert_eq!(val["last_checked_at"], 1726000000);

    let nonexistent = temp.path().join("nonexistent.json");
    assert!(crate::query_api::classifier_manager_status_from_path(&nonexistent).is_none());
}

#[tokio::test]
async fn settings_geo_endpoints() {
    let state = test_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(json["data"]["directory"].is_string());
    assert!(
        json["data"]["attribution"]
            .as_str()
            .unwrap()
            .contains("GeoLite2")
    );
    assert!(json["data"]["databases"].is_array());
    let databases = json["data"]["databases"].as_array().unwrap();
    assert!(
        databases
            .iter()
            .any(|d| d["filename"] == "GeoLite2-City.mmdb")
    );
    assert!(
        databases
            .iter()
            .any(|d| d["filename"] == "GeoLite2-ASN.mmdb")
    );
}

#[tokio::test]
async fn settings_geo_update_endpoint_handles_error() {
    let state = test_state();
    let router = internal_router(state);

    let body = serde_json::json!({
        "city_url": "ftp://example.invalid/invalid-city.mmdb",
        "asn_url": "ftp://example.invalid/invalid-asn.mmdb",
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/geo/update")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "geo_update_error");
}

#[tokio::test]
async fn settings_license_endpoints() {
    let state = test_state();
    let router = internal_router(state);

    // 1. GET /internal/settings/license initially returns valid status
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/license")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["activated"], false);
    assert_eq!(json["data"]["edition"], "community");

    // 2. POST with empty key returns BAD_REQUEST
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/license/activate")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "license_key": "   " }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 3. POST /internal/settings/license/check without activation returns bad gateway
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/license/check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn sample_endpoint_enforces_auth_gateway_and_limits() {
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};
    let state = test_state();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-test".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let mut batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-test".into(),
        sequence: 1,
        sent_at: 1000,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            policy_flow_id: String::new(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 17,
                client_ip: vec![192, 0, 2, 1],
                client_port: 50000,
                remote_ip: vec![198, 51, 100, 1],
                remote_port: 443,
                first_seen_unix_ms: 1000,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: 1000,
                original_length: 64,
                captured_length: 64,
                payload: vec![0x45; 64],
            }],
            total_captured_bytes: 64,
        }],
    };
    let request = |batch: &FlowSampleBatch, token: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/ingest/samples")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(batch.encode_to_vec()))
            .unwrap()
    };
    let router = public_router(state.clone());
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, "wrong-token"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    batch.gateway_id = "other".into();
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    batch.gateway_id = enrolled.gateway_id;
    batch.samples[0].total_captured_bytes = 1;
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    batch.samples[0].total_captured_bytes = 64;
    assert_eq!(
        router
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(state.lock().accepted_batches, 0);
}

#[cfg(ndpi_available)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_sample_ingestion_updates_ended_flow_without_persisting_payload() {
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};
    let mut state = test_state_with_repository_rules();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-test".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let inner = Arc::downgrade(&state.inner);
    let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
        state.lock().classifier.clone(),
    ));
    state.sampling = Arc::new(dpi::SamplingService::new(
        true,
        dpi::default_engine(),
        signature_matcher,
        move |result| {
            if let Some(inner) = inner.upgrade() {
                apply_sample_result(&mut inner.lock().unwrap(), &result).unwrap();
            }
        },
    ));
    let timestamp = 1_700_000_000_000;
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        direction: 1,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        upload_bytes: 108,
        packets: 1,
        lifecycle: FlowLifecycle::Ended.into(),
        protocol_hint: "bittorrent_handshake".into(),
        ..Default::default()
    };
    let telemetry = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-test".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&telemetry).unwrap();
    let read = || {
        state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT protocol_id,upload_bytes,classification_evidence_json FROM flow_sessions",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(read().0, "unknown", "legacy Agent hint must be ignored");
    let mut payload = vec![0; 108];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&108u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&flow.client_ip);
    payload[16..20].copy_from_slice(&flow.remote_ip);
    payload[20..22].copy_from_slice(&50000u16.to_be_bytes());
    payload[22..24].copy_from_slice(&443u16.to_be_bytes());
    payload[32] = 0x50;
    payload[33] = 0x18;
    payload[40] = 19;
    payload[41..60].copy_from_slice(b"BitTorrent protocol");
    let batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id,
        boot_id: "sample-test".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            policy_flow_id: String::new(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: timestamp,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: timestamp,
                original_length: 108,
                captured_length: 108,
                payload,
            }],
            total_captured_bytes: 108,
        }],
    };
    let encoded = netqmon_protocol::encode_flow_sample_batch(&batch, 0).unwrap();
    let response = public_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/samples")
                .header(AUTHORIZATION, format!("Bearer {}", enrolled.agent_token))
                .header(CONTENT_ENCODING, "zstd")
                .body(Body::from(encoded.body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for _ in 0..100 {
        if read().0 == "bittorrent" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (protocol, bytes, evidence) = read();
    assert_eq!(protocol, "bittorrent");
    assert_eq!(bytes, 108);
    assert!(evidence.contains("ndpi"));
    assert!(!evidence.contains("BitTorrent protocol"));
    let diagnostics = state.sampling.diagnostics().to_string();
    assert!(!diagnostics.contains("payload"));
    assert!(!diagnostics.contains("BitTorrent protocol"));
    assert_eq!(state.lock().accepted_batches, 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn signature_sample_match_reclassifies_flow_without_dpi() {
    use crate::dpi::engine::{DpiEngine, DpiFlow, DpiResult};
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};

    struct NoDpiEngine;
    struct NoDpiFlow;
    impl DpiEngine for NoDpiEngine {
        fn name(&self) -> &'static str {
            "fixture"
        }
        fn start(&self, _: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
            Ok(Box::new(NoDpiFlow))
        }
    }
    impl DpiFlow for NoDpiFlow {
        fn classify(&mut self, _: &[SamplePacket]) -> Option<DpiResult> {
            None
        }
        fn finish(&mut self) -> Option<DpiResult> {
            None
        }
    }

    let mut state = test_state_with_repository_rules();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-signature".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let inner = Arc::downgrade(&state.inner);
    let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
        state.lock().classifier.clone(),
    ));
    state.sampling = Arc::new(dpi::SamplingService::new(
        true,
        Arc::new(NoDpiEngine),
        signature_matcher,
        move |result| {
            if let Some(inner) = inner.upgrade() {
                apply_sample_result(&mut inner.lock().unwrap(), &result).unwrap();
            }
        },
    ));
    let timestamp = 1_700_000_000_000;
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        direction: 1,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        upload_bytes: 108,
        packets: 1,
        lifecycle: FlowLifecycle::Ended.into(),
        ..Default::default()
    };
    let telemetry = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&telemetry).unwrap();
    let read = || {
        state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT application_id,organization_id,classification_evidence_json FROM flow_sessions",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(read().0, "unknown");

    let mut payload = vec![0u8; 48];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&48u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&flow.client_ip);
    payload[16..20].copy_from_slice(&flow.remote_ip);
    payload[20..22].copy_from_slice(&50000u16.to_be_bytes());
    payload[22..24].copy_from_slice(&443u16.to_be_bytes());
    payload[32] = 0x50;
    payload[33] = 0x10;
    payload[40..44].copy_from_slice(&[0x33, 0x66, 0x00, 0x0b]);
    payload[44] = 0x0c;
    let batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            policy_flow_id: String::new(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: timestamp,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: timestamp,
                original_length: u32::try_from(payload.len()).unwrap(),
                captured_length: u32::try_from(payload.len()).unwrap(),
                payload,
            }],
            total_captured_bytes: 48,
        }],
    };
    let encoded = netqmon_protocol::encode_flow_sample_batch(&batch, 0).unwrap();
    let response = public_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/samples")
                .header(AUTHORIZATION, format!("Bearer {}", enrolled.agent_token))
                .header(CONTENT_ENCODING, "zstd")
                .body(Body::from(encoded.body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    for _ in 0..200 {
        let (_, _, evidence) = read();
        if evidence.contains("payload_signature") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_, _, evidence) = read();
    assert!(
        evidence.contains("payload_signature"),
        "the ended flow records the signature evidence: {evidence}"
    );
    assert!(
        !evidence.contains("3366000b"),
        "raw payload bytes must never be persisted"
    );

    // The next telemetry batch for the same flow attributes through the cache.
    let followup = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&followup).unwrap();
    let (application, organization, category, evidence) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT application_id,organization_id,category_id,classification_evidence_json
             FROM flow_sessions",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(application, "honor_of_kings");
    assert_eq!(organization, "tencent");
    assert_eq!(category, "gaming");
    assert!(evidence.contains("payload_signature"));
    assert_eq!(state.lock().accepted_batches, 2);
}

#[test]
fn missing_classifierd_never_blocks_signature_matching_or_sampling() {
    use crate::dpi::SignatureMatcher;
    use netqmon_protocol::v1::FlowSampleKey;

    let handle =
        classifier::ClassifierHandle::connect(PathBuf::from("/missing/netqmon-classifierd.sock"))
            .unwrap();
    let matcher = classifier::ClassifierdSignatureMatcher::new(handle);
    let key = FlowSampleKey {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        first_seen_unix_ms: 1,
    };
    let packets = vec![netqmon_protocol::v1::SamplePacket {
        direction: 1,
        timestamp_unix_ms: 1,
        original_length: 48,
        captured_length: 48,
        payload: vec![0x45; 48],
    }];
    let started = std::time::Instant::now();
    let observed = matcher.match_sample(&key, &packets);
    assert!(observed.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a missing classifierd must fail fast, not stall the DPI worker"
    );
}

#[test]
fn hostname_domain_rules_fill_unknown_dns_without_overriding_dns_applications() {
    let state = test_state_with_repository_rules();
    let inner = state.lock();
    for (dns, hostname, native, expected, expected_domain) in [
        (
            "cdn.unmatched.test",
            "www.youtube.com",
            "Netflix",
            "youtube",
            "www.youtube.com",
        ),
        (
            "netflix.com",
            "www.youtube.com",
            "YouTube",
            "netflix",
            "netflix.com",
        ),
        (
            "cdn.unmatched.test",
            "",
            "YouTube",
            "youtube",
            "cdn.unmatched.test",
        ),
    ] {
        let batch = TelemetryBatch {
            sent_at: 1000,
            flows: vec![FlowDelta {
                client_ip: vec![192, 0, 2, 1],
                remote_ip: vec![198, 51, 100, 1],
                protocol: 6,
                remote_port: 443,
                last_seen_unix_ms: 1000,
                ..Default::default()
            }],
            dns_observations: vec![DnsObservation {
                client_ip: vec![192, 0, 2, 1],
                answer_ip: vec![198, 51, 100, 1],
                domain: dns.into(),
                observed_at_unix_ms: 1000,
                ttl_seconds: 60,
                ..Default::default()
            }],
            ..Default::default()
        };
        let dpi = dpi::engine::DpiResult {
            protocol: "tls".into(),
            source: "ndpi".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::from([
                ("hostname".into(), hostname.into()),
                ("application_protocol".into(), native.into()),
            ]),
        };
        let result = classify_batch(
            &inner.storage,
            &inner.classifier,
            inner.geo_provider.as_ref(),
            &mut ServiceBindingCache::default(),
            &DnsDomainCache::default(),
            &FaviconEndpointCache::default(),
            &batch,
            &[Some(dpi::SampleAnalysis {
                dpi: Some(dpi),
                signatures: Vec::new(),
            })],
            false,
        )
        .unwrap();
        assert_eq!(result[0].application_id, expected);
        assert_eq!(result[0].domain.as_deref(), Some(expected_domain));
        assert_eq!(result[0].category_id, "streaming");
        assert_eq!(result[0].protocol_id, "tls");
    }
}

#[test]
fn local_hostname_does_not_identify_selfhost_or_bind_reverse_proxy_port() {
    let state = test_state_with_repository_rules();
    let inner = state.lock();
    let batch = TelemetryBatch {
        sent_at: 1_000,
        flows: vec![FlowDelta {
            client_ip: vec![192, 168, 2, 10],
            remote_ip: vec![192, 168, 2, 20],
            protocol: 6,
            remote_port: 443,
            last_seen_unix_ms: 1_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let dpi = dpi::engine::DpiResult {
        protocol: "tls".into(),
        source: "ndpi".into(),
        confidence: 1.0,
        metadata: std::collections::BTreeMap::from([(
            "hostname".into(),
            "jellyfin.home.arpa".into(),
        )]),
    };
    let mut bindings = ServiceBindingCache::default();
    let identified = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut bindings,
        &DnsDomainCache::default(),
        &FaviconEndpointCache::default(),
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: Some(dpi),
            signatures: Vec::new(),
        })],
        false,
    )
    .unwrap();
    assert_eq!(identified[0].application_id, "unknown");

    let without_hostname = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut bindings,
        &DnsDomainCache::default(),
        &FaviconEndpointCache::default(),
        &batch,
        &[None],
        false,
    )
    .unwrap();
    assert_eq!(without_hostname[0].application_id, "unknown");
    assert!(!attribution_has_evidence(
        &without_hostname[0],
        "service_binding"
    ));
}

#[tokio::test]
async fn insights_detect_first_batch_of_low_cost_enhancements() {
    let state = query_state();
    let inner = state.lock();
    let conn = inner.storage.connection();
    let gateway_id: String = conn
        .query_row("SELECT id FROM gateways LIMIT 1", [], |r| r.get(0))
        .unwrap();

    // 1. Client spike & Application spike
    // Seed baseline in [1000, 2000) and current spike in [2000, 3000)
    conn.execute(
        "INSERT INTO traffic_device_minute (timestamp, gateway_id, device_id, upload_bytes, download_bytes, packets, flow_count)
         VALUES (1500, ?1, 1, 1000000, 1000000, 100, 10),
                (2500, ?1, 1, 15000000, 15000000, 1000, 50)",
        [&gateway_id],
    ).unwrap();

    conn.execute(
        "INSERT INTO traffic_application_minute (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
         VALUES (1500, ?1, 'youtube', 'streaming', 1000000, 1000000, 100, 10),
                (2500, ?1, 'youtube', 'streaming', 15000000, 15000000, 1000, 50)",
        [&gateway_id],
    ).unwrap();

    let client_spikes = crate::insights::traffic::query_client_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(client_spikes.len(), 1);
    assert_eq!(client_spikes[0].code, "traffic.client_spike");
    assert_eq!(client_spikes[0].category, "traffic");
    assert_eq!(client_spikes[0].params["client"], "laptop");

    let app_spikes = crate::insights::traffic::query_application_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(app_spikes.len(), 1);
    assert_eq!(app_spikes[0].code, "traffic.application_spike");
    assert_eq!(app_spikes[0].category, "traffic");
    assert_eq!(app_spikes[0].params["application"], "youtube");

    // 2. New protocol
    conn.execute(
        "INSERT INTO flow_sessions (
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
            upload_bytes, download_bytes, packets, protocol_id
         ) VALUES (
            'flow-new-proto', ?1, 1, 4, 6, X'C000020A', 50000,
            X'C6336401', 443, 1, 2500, 2500, 2500, 1000, 1000, 10, 'quic'
         )",
        [&gateway_id],
    )
    .unwrap();

    let new_protos = crate::insights::protocol::query_new_protocol_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert!(
        new_protos
            .iter()
            .any(|i| i.code == "protocol.new_protocol" && i.params["protocol"] == "quic")
    );

    // 3. Client unknown ratio high
    conn.execute(
        "INSERT INTO flow_sessions (
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
            upload_bytes, download_bytes, packets, application_id
         ) VALUES (
            'flow-unknown-heavy', ?1, 1, 4, 6, X'C000020A', 50001,
            X'C6336402', 443, 1, 2500, 2500, 2500, 2000000, 2000000, 100, 'unknown'
         )",
        [&gateway_id],
    )
    .unwrap();

    let client_unknowns = crate::insights::classification::query_client_unknown_ratio_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert!(
        client_unknowns
            .iter()
            .any(|i| i.code == "classification.client_unknown_ratio_high")
    );

    // 4. Fanout spike: add 55 distinct remote IPs
    for i in 1..=55 {
        conn.execute(
            "INSERT INTO flow_sessions (
                id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
                upload_bytes, download_bytes, packets
             ) VALUES (
                ?1, ?2, 1, 4, 6, X'C000020A', ?3,
                ?4, 80, 1, 2500, 2500, 2500, 100, 100, 1
             )",
            rusqlite::params![
                format!("fanout-flow-{i}"),
                gateway_id,
                50000 + i,
                vec![10, 0, (i / 256) as u8, (i % 256) as u8]
            ],
        )
        .unwrap();
    }

    let fanouts = crate::insights::destination::query_fanout_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(fanouts.len(), 1);
    assert_eq!(fanouts[0].code, "destination.fanout_spike");
    assert_eq!(fanouts[0].category, "destination");
    assert!(fanouts[0].params["count"].as_i64().unwrap() >= 55);
}

#[test]
fn same_batch_dns_links_dual_stack_addresses_without_cross_device_leakage() {
    let mac = vec![2, 0, 0, 0, 0, 1];
    let ipv4 = vec![192, 0, 2, 1];
    let ipv6 = vec![0x20; 16];
    let mut batch = TelemetryBatch {
        device_observations: vec![
            netqmon_protocol::v1::DeviceObservation {
                mac: mac.clone(),
                ip: ipv4.clone(),
                last_seen_unix_ms: 1_000,
                ..Default::default()
            },
            netqmon_protocol::v1::DeviceObservation {
                mac: mac.clone(),
                ip: ipv6.clone(),
                last_seen_unix_ms: 1_000,
                ..Default::default()
            },
        ],
        dns_observations: vec![DnsObservation {
            client_ip: ipv6,
            answer_ip: vec![198, 51, 100, 1],
            domain: "video.example.test".into(),
            ttl_seconds: 60,
            observed_at_unix_ms: 1_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        resolve_batch_domain(&batch, &ipv4, &[198, 51, 100, 1], 1_001),
        Some("video.example.test")
    );
    assert_eq!(
        resolve_batch_domain(&batch, &ipv4, &[198, 51, 100, 1], 61_000),
        None
    );
    assert_eq!(
        resolve_batch_domain(&batch, &[192, 0, 2, 2], &[198, 51, 100, 1], 1_001),
        None
    );
    batch
        .device_observations
        .push(netqmon_protocol::v1::DeviceObservation {
            mac: vec![2, 0, 0, 0, 0, 2],
            ip: ipv4.clone(),
            last_seen_unix_ms: 1_000,
            ..Default::default()
        });
    assert_eq!(
        resolve_batch_domain(&batch, &ipv4, &[198, 51, 100, 1], 1_001),
        None
    );
}
