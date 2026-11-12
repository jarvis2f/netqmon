use super::*;
use std::time::Instant;

fn expiry_progress_counts(
    connection: &rusqlite::Connection,
    simulated_now: u64,
) -> rusqlite::Result<(i64, i64, i64, i64, i64)> {
    let now = i64::try_from(simulated_now).unwrap_or(i64::MAX);
    connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NULL),
           (SELECT COUNT(*) FROM flow_rollup_sessions),
           (SELECT COUNT(*) FROM flow_rollup_contributions),
           (SELECT COUNT(*) FROM flow_rollup_contributions WHERE expires_at<=?1),
           EXISTS(SELECT 1 FROM traffic_total_hour_pending WHERE timestamp<?2) +
           EXISTS(SELECT 1 FROM traffic_device_hour_pending WHERE timestamp<?2) +
           EXISTS(SELECT 1 FROM traffic_application_hour_pending WHERE timestamp<?2) +
           EXISTS(SELECT 1 FROM traffic_domain_hour_pending WHERE timestamp<?2) +
           EXISTS(SELECT 1 FROM traffic_destination_hour_pending WHERE timestamp<?2) +
           EXISTS(SELECT 1 FROM traffic_total_day_pending WHERE timestamp<?3) +
           EXISTS(SELECT 1 FROM traffic_device_day_pending WHERE timestamp<?3) +
           EXISTS(SELECT 1 FROM traffic_application_day_pending WHERE timestamp<?3) +
           EXISTS(SELECT 1 FROM traffic_domain_day_pending WHERE timestamp<?3) +
           EXISTS(SELECT 1 FROM traffic_destination_day_pending WHERE timestamp<?3)",
        rusqlite::params![
            now,
            now / 3_600_000 * 3_600_000,
            now / 86_400_000 * 86_400_000
        ],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )
}

#[test]
fn expiry_progress_reports_only_eligible_pending_rollup_tasks() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("expiry-progress.db");
    let storage = SqliteStorage::open(path).unwrap();
    let connection = storage.connection();
    let now = 3 * 86_400_000 + 2 * 3_600_000;
    connection
        .execute(
            "INSERT INTO traffic_domain_hour_pending
             VALUES (0,'gateway','hour.example',0,0,0,0)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO traffic_destination_day_pending
             VALUES (0,'gateway',X'01020304',0,0,0,0)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO traffic_total_hour_pending
             VALUES (?1,'gateway',0,0,0,0)",
            [i64::try_from(now).unwrap()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO traffic_total_day_pending
             VALUES (?1,'gateway',0,0,0,0)",
            [i64::try_from(now).unwrap()],
        )
        .unwrap();

    assert_eq!(
        expiry_progress_counts(connection, now).unwrap(),
        (0, 0, 0, 0, 2)
    );
}

fn proc_status_kib(field: &str) -> Option<u64> {
    if let Some(value) = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{field}:")))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
    {
        return Some(value);
    }
    if field == "VmHWM" {
        return process_high_water_rss_kib();
    }
    if field != "VmRSS" {
        return None;
    }
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

#[allow(unsafe_code)]
fn process_high_water_rss_kib() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // getrusage only writes the initialized, stack-owned rusage record.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return None;
        }
        let high_water = u64::try_from(usage.ru_maxrss).ok()?;
        #[cfg(target_os = "macos")]
        return Some(high_water / 1024);
        #[cfg(target_os = "linux")]
        return Some(high_water);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

fn proc_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let user = fields.get(11)?.parse::<u64>().ok()?;
    let system = fields.get(12)?.parse::<u64>().ok()?;
    Some(user.saturating_add(system))
}

fn report_sqlite_schema_diagnostics(connection: &rusqlite::Connection) {
    let page_count: i64 = connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    let freelist_count: i64 = connection
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .unwrap();
    let cache_size: i64 = connection
        .pragma_query_value(None, "cache_size", |row| row.get(0))
        .unwrap();
    let page_size: i64 = connection
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap();
    eprintln!(
        "collector_sqlite_pragma page_count={page_count} page_size={page_size} freelist_count={freelist_count} cache_size={cache_size}"
    );
    let mut statement = connection
        .prepare(
            "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY SUM(pgsize) DESC LIMIT 30",
        )
        .unwrap();
    for row in statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .unwrap()
    {
        eprintln!("collector_sqlite_dbstat {:?}", row.unwrap());
    }
    let recovery_payload: (i64, f64, i64, f64, i64) = connection
        .query_row(
            "SELECT COUNT(*),AVG(length(metadata_json)),MAX(length(metadata_json)),
                    AVG(length(attribution_json)),MAX(length(attribution_json))
             FROM flow_rollup_sessions",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    let contribution_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM flow_rollup_contributions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    eprintln!(
        "collector_sqlite_recovery_rows sessions={} metadata_avg_bytes={} metadata_max_bytes={} attribution_avg_bytes={} attribution_max_bytes={} contributions={contribution_rows}",
        recovery_payload.0,
        recovery_payload.1,
        recovery_payload.2,
        recovery_payload.3,
        recovery_payload.4,
    );
    for (name, sql) in [
        (
            "recovery_sessions",
            "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at<=1794000000000 LIMIT 500",
        ),
        (
            "recovery_expired_contributions",
            "DELETE FROM flow_rollup_contributions WHERE (session_ref,timestamp,scope,direction,device_id,remote_ip,protocol) IN (SELECT session_ref,timestamp,scope,direction,device_id,remote_ip,protocol FROM flow_rollup_contributions WHERE expires_at<=1794000000000 LIMIT 500)",
        ),
        (
            "recovery_expired_sessions",
            "DELETE FROM flow_rollup_sessions WHERE id IN (SELECT s.id FROM flow_rollup_sessions s WHERE ((s.ended_at IS NOT NULL AND s.ended_at<=1794000000000) OR s.updated_at<=1792200000000) AND NOT EXISTS (SELECT 1 FROM flow_rollup_contributions c WHERE c.session_ref=s.id) LIMIT 500)",
        ),
        (
            "recovery_stale_flow_sessions",
            "UPDATE flow_sessions SET ended_at=last_seen_at WHERE rowid IN (SELECT f.rowid FROM flow_sessions f WHERE f.ended_at IS NULL AND f.checkpointed_at<=1790400000000 AND NOT EXISTS (SELECT 1 FROM flow_rollup_sessions r WHERE r.session_id=f.id AND r.ended_at IS NULL AND r.updated_at>1790400000000) LIMIT 500)",
        ),
        (
            "rollup_mark_hour",
            "UPDATE flow_rollup_contributions SET hour_upload=upload_bytes,hour_download=download_bytes,hour_packets=packets,hour_flows=flow_count WHERE timestamp<1794000000000 AND (hour_upload!=upload_bytes OR hour_download!=download_bytes OR hour_packets!=packets OR hour_flows!=flow_count)",
        ),
        (
            "rollup_mark_day",
            "UPDATE flow_rollup_contributions SET day_upload=hour_upload,day_download=hour_download,day_packets=hour_packets,day_flows=hour_flows WHERE timestamp<1793404800000 AND (day_upload!=hour_upload OR day_download!=hour_download OR day_packets!=hour_packets OR day_flows!=hour_flows)",
        ),
        (
            "rollup_application_hour_pending",
            "INSERT INTO traffic_application_hour(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) SELECT timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count FROM traffic_application_hour_pending WHERE timestamp<1794000000000 ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count",
        ),
    ] {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        for row in statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
        {
            eprintln!("collector_sqlite_plan {name}: {}", row.unwrap());
        }
    }
}

fn mac_for(client: usize) -> Vec<u8> {
    let id = u32::try_from(client).expect("benchmark client id fits u32");
    [
        2,
        0,
        (id >> 24) as u8,
        (id >> 16) as u8,
        (id >> 8) as u8,
        id as u8,
    ]
    .to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual file-backed end-to-end Collector ingestion benchmark"]
async fn file_collector_ingest_benchmark() {
    // This manual stress test can fail only after a long-running write. Keep
    // storage warnings visible so SQLite's underlying error code is not lost
    // behind the telemetry endpoint's intentionally generic HTTP response.
    let log_level = if std::env::var("NETQMON_BENCH_TRACE_STORAGE").is_ok_and(|value| value == "1")
    {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .try_init();
    let rows: u64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let clients: usize = std::env::var("NETQMON_BENCH_CLIENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_000);
    let destinations: u64 = std::env::var("NETQMON_BENCH_DESTINATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(rows);
    let batch_flows: usize = std::env::var("NETQMON_BENCH_BATCH_FLOWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(MAX_FLOWS_PER_BATCH);
    // Set this to `active` to model telemetry streams that never deliver End.
    let active_flows = std::env::var("NETQMON_BENCH_LIFECYCLE")
        .is_ok_and(|value| value.eq_ignore_ascii_case("active"));
    let expire_active = active_flows
        && std::env::var("NETQMON_BENCH_EXPIRE_ACTIVE").is_ok_and(|value| value == "1");
    let concurrent_reads =
        std::env::var("NETQMON_BENCH_CONCURRENT_READS").is_ok_and(|value| value == "1");
    let concurrent_maintenance =
        std::env::var("NETQMON_BENCH_CONCURRENT_MAINTENANCE").is_ok_and(|value| value == "1");
    let maintenance_interval_ms = std::env::var("NETQMON_BENCH_MAINTENANCE_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(50);
    let batch_interval_ms = std::env::var("NETQMON_BENCH_BATCH_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000);
    let wal_truncate_threshold = std::env::var("NETQMON_BENCH_WAL_TRUNCATE_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let wal_checkpoint_mode = std::env::var("NETQMON_BENCH_WAL_CHECKPOINT_MODE")
        .unwrap_or_else(|_| "TRUNCATE".to_owned())
        .to_ascii_uppercase();
    assert!(matches!(
        wal_checkpoint_mode.as_str(),
        "PASSIVE" | "RESTART" | "TRUNCATE"
    ));
    let lifecycle = if active_flows {
        FlowLifecycle::Active
    } else {
        FlowLifecycle::Ended
    };
    assert!(rows > 0 && clients > 0 && clients <= 65_536);
    assert!(destinations > 0 && destinations <= u64::from(u32::MAX));
    assert!(batch_flows > 0 && batch_flows <= MAX_FLOWS_PER_BATCH);

    let directory = if let Some(path) = std::env::var_os("NETQMON_BENCH_DIR") {
        tempfile::tempdir_in(path).unwrap()
    } else {
        tempdir().unwrap()
    };
    let path = directory.path().join("collector-ingest.db");
    let storage = SqliteStorage::open(&path).unwrap();
    let client_device_index =
        std::env::var("NETQMON_BENCH_CLIENT_DEVICE_INDEX").is_ok_and(|value| value == "1");
    if client_device_index {
        storage
            .connection()
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS traffic_device_minute_device
                 ON traffic_device_minute(device_id)",
            )
            .unwrap();
    } else {
        storage
            .connection()
            .execute_batch("DROP INDEX IF EXISTS traffic_device_minute_device")
            .unwrap();
    }
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, storage, repository_rule_engine()).unwrap();
    let wal_frame_diagnostics = std::env::var("NETQMON_BENCH_WAL_FRAMES")
        .is_ok_and(|value| value == "1")
        .then(|| rusqlite::Connection::open(&path).unwrap());
    let router = public_router(state.clone());
    let internal = internal_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let batches = rows.div_ceil(batch_flows as u64);
    let base = if std::env::var("NETQMON_BENCH_CURRENT_TIMESTAMP").is_ok_and(|value| value == "1") {
        unix_time_ms().saturating_sub(60_000)
    } else {
        1_700_000_000_000_u64
    };
    let stop_background = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let query_task = concurrent_reads.then(|| {
        let router = internal.clone();
        let stop = std::sync::Arc::clone(&stop_background);
        tokio::spawn(async move {
            let paths = [
                "/internal/clients?limit=50",
                "/internal/applications?limit=50",
                "/internal/flows?limit=50",
            ];
            let mut samples = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                for path in paths {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let started = Instant::now();
                    let response = router
                        .clone()
                        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK, "query {path}");
                    let body = to_bytes(response.into_body(), 16 * 1024 * 1024)
                        .await
                        .unwrap();
                    assert!(!body.is_empty(), "query {path} returned an empty body");
                    samples.push((path, started.elapsed().as_micros()));
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            samples
        })
    });
    let maintenance_results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let wal_truncate_results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let maintenance_thread = concurrent_maintenance.then(|| {
        let state = state.clone();
        let stop = std::sync::Arc::clone(&stop_background);
        let results = std::sync::Arc::clone(&maintenance_results);
        let truncate_results = std::sync::Arc::clone(&wal_truncate_results);
        let database_path = path.clone();
        let checkpoint_mode = wal_checkpoint_mode.clone();
        std::thread::spawn(move || {
            let checkpoint_connection = (wal_truncate_threshold > 0)
                .then(|| rusqlite::Connection::open(&database_path).unwrap());
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let started = Instant::now();
                let result = state.run_maintenance(false);
                let retry = match &result {
                    Ok(complete) => !complete,
                    Err(error) => should_retry_maintenance_after_error(false, error),
                };
                let outcome = match result {
                    Ok(_) => 0_u8,
                    Err(StorageError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                        if matches!(
                            code.code,
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        ) =>
                    {
                        1
                    }
                    Err(error) => {
                        eprintln!("collector_benchmark_maintenance_error={error}");
                        2
                    }
                };
                results
                    .lock()
                    .unwrap()
                    .push((started.elapsed().as_micros(), outcome));
                // WAL checkpointing is independent of rollup completion. A
                // sustained ingest workload may keep bounded rollup work
                // permanently behind; gating a configured checkpoint on
                // `complete` would make this benchmark control ineffective.
                if let Some(connection) = checkpoint_connection.as_ref() {
                    let wal_path =
                        std::path::PathBuf::from(format!("{}-wal", database_path.display()));
                    let before_bytes = std::fs::metadata(&wal_path)
                        .map(|metadata| metadata.len())
                        .unwrap_or(0);
                    if before_bytes >= wal_truncate_threshold {
                        let checkpoint_started = Instant::now();
                        let checkpoint_sql = match checkpoint_mode.as_str() {
                            "PASSIVE" => "PRAGMA wal_checkpoint(PASSIVE)",
                            "RESTART" => "PRAGMA wal_checkpoint(RESTART)",
                            _ => "PRAGMA wal_checkpoint(TRUNCATE)",
                        };
                        let status = connection.query_row(checkpoint_sql, [], |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, i64>(1)?,
                                    row.get::<_, i64>(2)?,
                                ))
                            });
                        let after_bytes = std::fs::metadata(&wal_path)
                            .map(|metadata| metadata.len())
                            .unwrap_or(0);
                        let succeeded = status.as_ref().is_ok_and(|(busy, _, _)| *busy == 0);
                        if !succeeded {
                            eprintln!(
                                "collector_benchmark_wal_checkpoint_failed mode={checkpoint_mode} elapsed_us={} before_bytes={before_bytes} after_bytes={after_bytes} status={status:?}",
                                checkpoint_started.elapsed().as_micros(),
                            );
                        }
                        truncate_results.lock().unwrap().push((
                            checkpoint_started.elapsed().as_micros(),
                            succeeded,
                            before_bytes,
                            after_bytes,
                        ));
                    }
                }
                // Match production scheduling: use the configured cadence
                // after a completed pass, but continue bounded work after
                // 250 ms when a pass reports remaining rows or a transient
                // SQLite lock. Sleeping a full minute between incomplete
                // rollup slices can create an artificial, unbounded backlog.
                let delay = if retry {
                    std::time::Duration::from_millis(250)
                } else {
                    std::time::Duration::from_millis(maintenance_interval_ms)
                };
                std::thread::sleep(delay);
            }
        })
    });
    let cpu_before = proc_cpu_ticks();
    let rss_before = proc_status_kib("VmRSS");
    let high_water_before = proc_status_kib("VmHWM");
    let sqlite_before = sqlite_memory_used_bytes();
    let rss_sample_interval = if std::path::Path::new("/proc/self/status").exists() {
        std::time::Duration::from_millis(5)
    } else {
        // On macOS, `ps` starts a short-lived process for each sample.
        std::time::Duration::from_millis(100)
    };
    #[cfg(feature = "rust-heap-meter")]
    let rust_heap_before = Some(super::rust_heap_meter::begin());
    #[cfg(not(feature = "rust-heap-meter"))]
    let rust_heap_before: Option<usize> = None;
    let sample_active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sample_flag = std::sync::Arc::clone(&sample_active);
    let sampler = std::thread::spawn(move || {
        let mut peak_rss = 0;
        let mut peak_sqlite = sqlite_memory_used_bytes();
        while sample_flag.load(std::sync::atomic::Ordering::Relaxed) {
            peak_rss = peak_rss.max(
                proc_status_kib("VmRSS")
                    .or_else(process_high_water_rss_kib)
                    .unwrap_or(0),
            );
            peak_sqlite = peak_sqlite.max(sqlite_memory_used_bytes());
            std::thread::sleep(rss_sample_interval);
        }
        (peak_rss, peak_sqlite)
    });

    let started = Instant::now();
    let mut request_times = Vec::with_capacity(usize::try_from(batches).unwrap_or(0));
    let progress_every = std::env::var("NETQMON_BENCH_PROGRESS_BATCHES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| (batches / 20).max(1));
    let mut expected_upload = 0_u128;
    let mut expected_download = 0_u128;
    let wal_path = std::path::PathBuf::from(format!("{}-wal", path.display()));
    let mut wal_peak_bytes = 0_u64;
    for sequence in 0..batches {
        let first = sequence * batch_flows as u64;
        let count = (rows - first).min(batch_flows as u64);
        let sent_at = base + sequence * batch_interval_ms;
        let device_observations = if sequence == 0 {
            (0..clients)
                .map(|client| netqmon_protocol::v1::DeviceObservation {
                    mac: mac_for(client),
                    ip: (0x0a00_0001_u32 + client as u32).to_be_bytes().to_vec(),
                    hostname: format!("client-{client}"),
                    last_seen_unix_ms: sent_at,
                    dhcp: None,
                })
                .collect()
        } else {
            Vec::new()
        };
        let flows = (first..first + count)
            .map(|flow_id| {
                let client = usize::try_from(flow_id % clients as u64).unwrap();
                let upload = flow_id % 1_000 + 1;
                let download = flow_id % 500 + 1;
                expected_upload += u128::from(upload);
                expected_download += u128::from(download);
                FlowDelta {
                    ip_version: 4,
                    protocol: 6,
                    client_ip: (0x0a00_0001_u32 + client as u32).to_be_bytes().to_vec(),
                    client_port: u32::try_from(flow_id % 60_000 + 1_000).unwrap(),
                    remote_ip: (0xc633_6400_u32 + u32::try_from(flow_id % destinations).unwrap())
                        .to_be_bytes()
                        .to_vec(),
                    remote_port: 443,
                    direction: Direction::Upload as i32,
                    upload_bytes: upload,
                    download_bytes: download,
                    packets: 1,
                    first_seen_unix_ms: sent_at,
                    last_seen_unix_ms: sent_at,
                    lifecycle: lifecycle as i32,
                    client_mac: mac_for(client),
                    scope: FlowScope::Internet as i32,
                    ..Default::default()
                }
            })
            .collect();
        let batch = TelemetryBatch {
            gateway_id: enrollment.gateway_id.clone(),
            boot_id: "collector-ingest-benchmark".to_owned(),
            sequence: sequence + 1,
            sent_at,
            agent_version: "benchmark".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            flows,
            device_observations,
            ..Default::default()
        };
        let request_started = Instant::now();
        let response = router
            .clone()
            .oneshot(telemetry_request(&batch, &enrollment.agent_token))
            .await
            .unwrap();
        let status = response.status();
        let response_body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_default();
        if status != StatusCode::NO_CONTENT && status != StatusCode::OK {
            let file_bytes = std::fs::metadata(&path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let wal_bytes = std::fs::metadata(&wal_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let sqlite_snapshot = rusqlite::Connection::open(&path)
                .ok()
                .and_then(|connection| {
                    connection
                        .query_row(
                            "SELECT (SELECT page_count FROM pragma_page_count),
                                (SELECT freelist_count FROM pragma_freelist_count),
                                (SELECT cache_size FROM pragma_cache_size),
                                (SELECT wal_autocheckpoint FROM pragma_wal_autocheckpoint)",
                            [],
                            |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, i64>(1)?,
                                    row.get::<_, i64>(2)?,
                                    row.get::<_, i64>(3)?,
                                ))
                            },
                        )
                        .ok()
                });
            let wal_frame_status = wal_frame_diagnostics.as_ref().and_then(|connection| {
                connection
                    .query_row("PRAGMA wal_checkpoint(NOOP)", [], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .ok()
            });
            let maintenance_snapshot = maintenance_results
                .lock()
                .unwrap()
                .iter()
                .rev()
                .take(8)
                .copied()
                .collect::<Vec<_>>();
            let truncate_snapshot = wal_truncate_results
                .lock()
                .unwrap()
                .iter()
                .rev()
                .take(8)
                .copied()
                .collect::<Vec<_>>();
            let maintenance_phase_snapshot = state
                .take_maintenance_phase_times()
                .into_iter()
                .rev()
                .take(8)
                .collect::<Vec<_>>();
            eprintln!(
                "collector_ingest_failure sequence={sequence} rows_written={} file_bytes={file_bytes} wal_bytes={wal_bytes} sqlite_snapshot={sqlite_snapshot:?} wal_frame_status={wal_frame_status:?} maintenance_recent={maintenance_snapshot:?} maintenance_phases_recent={maintenance_phase_snapshot:?} wal_checkpoint_mode={wal_checkpoint_mode} wal_checkpoint_recent={truncate_snapshot:?} sqlite_memory_bytes={} database_dir={:?}",
                first + count,
                sqlite_memory_used_bytes(),
                directory.path(),
            );
        }
        assert!(
            status == StatusCode::NO_CONTENT || status == StatusCode::OK,
            "batch {sequence} returned {status}: {}",
            String::from_utf8_lossy(&response_body)
        );
        request_times.push(request_started.elapsed().as_micros());
        wal_peak_bytes = wal_peak_bytes.max(
            std::fs::metadata(&wal_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
        );
        if (sequence + 1) % progress_every == 0 || sequence + 1 == batches {
            let elapsed = started.elapsed().as_secs_f64();
            let file_bytes = std::fs::metadata(&path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let wal_bytes = std::fs::metadata(&wal_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let wal_frame_status = wal_frame_diagnostics.as_ref().and_then(|connection| {
                connection
                    .query_row("PRAGMA wal_checkpoint(NOOP)", [], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .ok()
            });
            eprintln!(
                "collector_ingest_progress rows={} clients={clients} completed={} total_batches={batches} elapsed_s={elapsed:.1} file_bytes={file_bytes} wal_bytes={wal_bytes} wal_checkpoint_noop_busy_log_checkpointed={wal_frame_status:?} database_dir={:?}",
                first + count,
                sequence + 1,
                directory.path(),
            );
        }
    }

    stop_background.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut query_samples = if let Some(task) = query_task {
        task.await.unwrap()
    } else {
        Vec::new()
    };
    if let Some(thread) = maintenance_thread {
        thread.join().unwrap();
    }
    let maintenance_samples = maintenance_results.lock().unwrap();
    let maintenance_failures = maintenance_samples
        .iter()
        .filter(|(_, outcome)| *outcome == 2)
        .count();
    assert_eq!(maintenance_failures, 0);
    if concurrent_maintenance {
        assert!(maintenance_samples.iter().any(|(_, outcome)| *outcome == 0));
    }
    query_samples.sort_unstable_by_key(|(path, _)| *path);
    let query_summary = [
        "/internal/clients?limit=50",
        "/internal/applications?limit=50",
        "/internal/flows?limit=50",
    ]
    .map(|path| {
        let mut times = query_samples
            .iter()
            .filter_map(|(sample_path, elapsed)| (*sample_path == path).then_some(*elapsed))
            .collect::<Vec<_>>();
        times.sort_unstable();
        let quantile = |percent: usize| {
            times
                .get(((times.len().saturating_sub(1)) * percent) / 100)
                .copied()
                .unwrap_or(0)
        };
        (path, times.len(), quantile(50), quantile(95), quantile(99))
    });
    if concurrent_reads {
        assert!(query_summary.iter().all(|(_, samples, ..)| *samples > 0));
    }
    let maintenance_summary = (
        maintenance_samples.len(),
        maintenance_samples
            .iter()
            .map(|(elapsed, _)| *elapsed)
            .max()
            .unwrap_or(0),
        maintenance_samples
            .iter()
            .filter(|(_, outcome)| *outcome == 1)
            .count(),
    );
    let wal_truncate_samples = wal_truncate_results.lock().unwrap();
    let wal_truncate_summary = (
        wal_truncate_samples.len(),
        wal_truncate_samples
            .iter()
            .filter(|(_, succeeded, _, _)| *succeeded)
            .count(),
        wal_truncate_samples
            .iter()
            .map(|(elapsed, _, _, _)| *elapsed)
            .max()
            .unwrap_or(0),
        wal_truncate_samples
            .iter()
            .map(|(_, _, before, _)| *before)
            .max()
            .unwrap_or(0),
        wal_truncate_samples
            .iter()
            .map(|(_, _, _, after)| *after)
            .max()
            .unwrap_or(0),
    );
    drop(wal_truncate_samples);
    drop(maintenance_samples);
    let accept_batch_phase_samples = state.take_accept_batch_phase_times();
    let phase_samples = state.take_maintenance_phase_times();
    let phase_summary = |mut times: Vec<u128>| {
        times.sort_unstable();
        let quantile = |percent: usize| {
            times
                .get(((times.len().saturating_sub(1)) * percent) / 100)
                .copied()
                .unwrap_or(0)
        };
        (
            times.len(),
            quantile(50),
            quantile(95),
            quantile(99),
            times.last().copied().unwrap_or(0),
        )
    };
    let maintenance_phase_summary = (
        phase_summary(
            phase_samples
                .iter()
                .map(|sample| sample.state_lock_wait_us)
                .collect(),
        ),
        phase_summary(
            phase_samples
                .iter()
                .map(|sample| sample.owner_cache_us)
                .collect(),
        ),
        phase_summary(
            phase_samples
                .iter()
                .map(|sample| sample.recovery_gc_us)
                .collect(),
        ),
        phase_summary(
            phase_samples
                .iter()
                .map(|sample| sample.rollup_us)
                .collect(),
        ),
    );
    let accept_batch_phase_summary = (
        phase_summary(
            accept_batch_phase_samples
                .iter()
                .map(|sample| sample.state_lock_wait_us)
                .collect(),
        ),
        phase_summary(
            accept_batch_phase_samples
                .iter()
                .map(|sample| sample.storage_persist_us)
                .collect(),
        ),
        phase_summary(
            accept_batch_phase_samples
                .iter()
                .map(|sample| sample.in_memory_update_us)
                .collect(),
        ),
        phase_summary(
            accept_batch_phase_samples
                .iter()
                .map(|sample| sample.state_lock_hold_us)
                .collect(),
        ),
    );

    let mut expiry_passes = 0_u32;
    let mut expiry_elapsed_ms = 0_u128;
    if expire_active {
        // A recovery slice may shrink below the configured maximum when its
        // transaction hits the progress deadline. Keep enough bounded passes
        // for both contribution and session cleanup, including test overrides.
        let max_expiry_passes = rows.div_ceil(500).saturating_mul(16).saturating_add(100);
        let expiry_started = Instant::now();
        loop {
            expiry_passes += 1;
            let simulated_now = unix_time_ms().saturating_add(31 * 60 * 1_000);
            if state.run_maintenance_at(false, simulated_now).unwrap() {
                break;
            }
            if expiry_passes % 1_000 == 0 {
                let inner = state.lock();
                let cleanup_counts =
                    expiry_progress_counts(inner.storage.connection(), simulated_now).unwrap();
                drop(inner);
                eprintln!(
                    "collector_expiry_progress passes={expiry_passes} elapsed_s={:.1} open_flow_sessions={} recovery_sessions={} contributions={} expired_contributions={} pending_rollup_tasks={}",
                    expiry_started.elapsed().as_secs_f64(),
                    cleanup_counts.0,
                    cleanup_counts.1,
                    cleanup_counts.2,
                    cleanup_counts.3,
                    cleanup_counts.4,
                );
            }
            assert!(
                u64::from(expiry_passes) < max_expiry_passes,
                "active flow expiry exceeded {max_expiry_passes} passes for {rows} rows"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        expiry_elapsed_ms = expiry_started.elapsed().as_millis();
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let expiry_phase_samples = state.take_maintenance_phase_times();
    let expiry_phase_summary = (
        phase_summary(
            expiry_phase_samples
                .iter()
                .map(|sample| sample.state_lock_wait_us)
                .collect(),
        ),
        phase_summary(
            expiry_phase_samples
                .iter()
                .map(|sample| sample.owner_cache_us)
                .collect(),
        ),
        phase_summary(
            expiry_phase_samples
                .iter()
                .map(|sample| sample.recovery_gc_us)
                .collect(),
        ),
        phase_summary(
            expiry_phase_samples
                .iter()
                .map(|sample| sample.rollup_us)
                .collect(),
        ),
    );
    eprintln!(
        "collector_expiry_phases passes={expiry_passes} state_lock_wait_n_p50_p95_p99_max={:?} owner_cache_n_p50_p95_p99_max={:?} recovery_gc_n_p50_p95_p99_max={:?} rollup_n_p50_p95_p99_max={:?}",
        expiry_phase_summary.0,
        expiry_phase_summary.1,
        expiry_phase_summary.2,
        expiry_phase_summary.3,
    );
    let rss_after_expiry = proc_status_kib("VmRSS");
    sample_active.store(false, std::sync::atomic::Ordering::Relaxed);
    let (rss_peak, sqlite_peak) = sampler.join().unwrap();
    let request_first_us = request_times.first().copied().unwrap_or(0);
    request_times.sort_unstable();
    let percentile = |percent: usize| request_times[((request_times.len() - 1) * percent) / 100];
    let request_max_us = request_times.last().copied().unwrap_or(0);
    let total_elapsed = started.elapsed();
    let stats = state.stats();
    assert_eq!(stats.accepted_batches, batches);
    assert_eq!(stats.dedupe_hits, 0);
    assert_eq!(
        u128::from(stats.traffic_bytes),
        expected_upload.saturating_add(expected_download)
    );
    // Active sessions are checkpointed in `flow_sessions` periodically, while
    // `flow_rollup_sessions` holds the latest durable counters between those
    // checkpoints. Treat the recovery row as authoritative when present, and
    // include legacy/raw sessions that have no recovery row.
    let persisted: (i64, i64, i64, i64) = {
        let guard = state.lock();
        guard
            .storage
            .connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        guard
            .storage
            .connection()
            .query_row(
                "WITH durable_sessions AS (
                    SELECT r.session_id AS id, r.upload_bytes, r.download_bytes, r.ended_at
                    FROM flow_rollup_sessions r
                    UNION ALL
                    SELECT f.id, f.upload_bytes, f.download_bytes, f.ended_at
                    FROM flow_sessions f
                    WHERE NOT EXISTS (
                        SELECT 1 FROM flow_rollup_sessions r WHERE r.session_id = f.id
                    )
                 )
                 SELECT COUNT(*), SUM(upload_bytes), SUM(download_bytes),
                        SUM(CASE WHEN ended_at IS NULL THEN 1 ELSE 0 END)
                 FROM durable_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    };
    assert_eq!(persisted.0, i64::try_from(rows).unwrap());
    assert_eq!(u128::try_from(persisted.1).unwrap(), expected_upload);
    assert_eq!(u128::try_from(persisted.2).unwrap(), expected_download);
    if expire_active || !active_flows {
        assert_eq!(persisted.3, 0);
    } else {
        // A long-running benchmark can outlive ACTIVE_FLOW_TTL_MS. Maintenance
        // is expected to close flows that have gone idle even when this
        // fixture never sends End; only the explicit end-of-run expiry mode
        // requires every remaining session to be closed here.
        assert!((0..=i64::try_from(rows).unwrap()).contains(&persisted.3));
    }
    if std::env::var("NETQMON_BENCH_SCHEMA_DIAGNOSTICS").is_ok_and(|value| value == "1") {
        let inner = state.lock();
        report_sqlite_schema_diagnostics(inner.storage.connection());
    }
    let file_bytes = std::fs::metadata(&path).unwrap().len();
    #[cfg(feature = "rust-heap-meter")]
    let (rust_heap_peak_growth, rust_heap_after) =
        rust_heap_before.map_or((None, None), |before| {
            (
                Some(super::rust_heap_meter::peak_growth_since(before)),
                Some(super::rust_heap_meter::current()),
            )
        });
    #[cfg(not(feature = "rust-heap-meter"))]
    let (rust_heap_peak_growth, rust_heap_after): (Option<usize>, Option<usize>) = (None, None);
    let wal_bytes = std::fs::metadata(format!("{}-wal", path.display()))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    eprintln!(
        "collector_ingest rows={rows} clients={clients} destinations={destinations} base_timestamp={base} lifecycle={lifecycle:?} batch_interval_ms={batch_interval_ms} client_device_index={client_device_index} expire_active={expire_active} concurrent_reads={concurrent_reads} concurrent_maintenance={concurrent_maintenance} maintenance_interval_ms={maintenance_interval_ms} wal_checkpoint_threshold_bytes={wal_truncate_threshold} wal_checkpoint_mode={wal_checkpoint_mode} wal_checkpoint_attempts_success_max_us_max_before_max_after={wal_truncate_summary:?} query_summary={query_summary:?} maintenance_calls={} maintenance_max_us={} maintenance_busy_retries={} maintenance_phase_state_lock_n_p50_p95_p99_max={:?} maintenance_phase_owner_cache_n_p50_p95_p99_max={:?} maintenance_phase_recovery_gc_n_p50_p95_p99_max={:?} maintenance_phase_rollup_n_p50_p95_p99_max={:?} accept_batch_phase_state_lock_wait_n_p50_p95_p99_max={:?} accept_batch_phase_storage_persist_n_p50_p95_p99_max={:?} accept_batch_phase_in_memory_update_n_p50_p95_p99_max={:?} accept_batch_phase_state_lock_hold_n_p50_p95_p99_max={:?} expiry_passes={expiry_passes} expiry_elapsed_ms={expiry_elapsed_ms} rss_kib_after_expiry={rss_after_expiry:?} batch_flows={batch_flows} batches={batches} elapsed_ms={} flows_per_s={} request_first_us={request_first_us} request_p50_us={} request_p95_us={} request_p99_us={} request_max_us={request_max_us} file_bytes={file_bytes} wal_peak_bytes_sampled_after_batch={wal_peak_bytes} wal_bytes_after_checkpoint={wal_bytes} rss_kib_before={rss_before:?} rss_kib_sampled_peak={rss_peak} rss_kib_high_water_before={high_water_before:?} rss_kib_high_water_after={:?} rust_heap_live_before_bytes={rust_heap_before:?} rust_heap_peak_growth_bytes={rust_heap_peak_growth:?} rust_heap_live_after_bytes={rust_heap_after:?} sqlite_bytes_before={sqlite_before} sqlite_bytes_peak={sqlite_peak} sqlite_bytes_after={} cpu_ticks_before={cpu_before:?} cpu_ticks_after={:?} stats={stats:?}",
        maintenance_summary.0,
        maintenance_summary.1,
        maintenance_summary.2,
        maintenance_phase_summary.0,
        maintenance_phase_summary.1,
        maintenance_phase_summary.2,
        maintenance_phase_summary.3,
        accept_batch_phase_summary.0,
        accept_batch_phase_summary.1,
        accept_batch_phase_summary.2,
        accept_batch_phase_summary.3,
        total_elapsed.as_millis(),
        u128::from(rows).saturating_mul(1_000_000) / u128::from(total_elapsed.as_micros().max(1)),
        percentile(50),
        percentile(95),
        percentile(99),
        proc_status_kib("VmHWM"),
        sqlite_memory_used_bytes(),
        proc_cpu_ticks(),
    );
}
