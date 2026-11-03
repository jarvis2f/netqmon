use super::*;
use std::time::Instant;

fn legacy_delete_older_than(tx: &Transaction<'_>, table: &str, column: &str, now: i64, days: u32) {
    if days != 0 {
        let cutoff = now.saturating_sub(i64::from(days) * DAY_MS);
        tx.execute(
            &format!("DELETE FROM {table} WHERE {column} < ?1"),
            [cutoff],
        )
        .unwrap();
    }
}

fn legacy_full_retention(storage: &mut SqliteStorage, now_ms: u64, policy: RetentionPolicy) {
    let now = to_i64(now_ms);
    let transaction = storage.connection.transaction().unwrap();
    prune_flow_state(&transaction, &storage.active_flows, now).unwrap();
    legacy_delete_older_than(
        &transaction,
        "flow_sessions",
        "last_seen_at",
        now,
        policy.flow_sessions_days,
    );
    if policy.dns_days == 0 {
        transaction
            .execute("DELETE FROM dns_observations WHERE expires_at < ?1", [now])
            .unwrap();
    } else {
        let cutoff = now.saturating_sub(i64::from(policy.dns_days) * DAY_MS);
        transaction
            .execute(
                "DELETE FROM dns_observations WHERE expires_at < ?1 OR observed_at < ?2",
                params![now, cutoff],
            )
            .unwrap();
    }
    legacy_delete_older_than(
        &transaction,
        "ingest_batches",
        "received_at",
        now,
        policy.minute_days,
    );
    legacy_delete_older_than(
        &transaction,
        "traffic_scope_minute",
        "timestamp",
        now,
        policy.minute_days,
    );
    for dimension in DIMENSIONS {
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_minute"),
            "timestamp",
            now,
            policy.minute_days,
        );
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_hour"),
            "timestamp",
            now,
            policy.hour_days,
        );
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_day"),
            "timestamp",
            now,
            policy.day_days,
        );
        for (tier, days) in [("hour", policy.hour_days), ("day", policy.day_days)] {
            legacy_delete_older_than(
                &transaction,
                &format!("traffic_{dimension}_{tier}_pending"),
                "timestamp",
                now,
                days,
            );
        }
    }
    transaction.commit().unwrap();
}

fn process_write_bytes() -> Option<u64> {
    std::fs::read_to_string("/proc/self/io")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("write_bytes:")?.trim().parse().ok())
}

fn process_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
}

// Run separately for each mode using NETQMON_RETENTION_BASELINE=true/false.
#[test]
#[ignore = "manual SQLite retention benchmark"]
fn file_retention_benchmark() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };
    let baseline = std::env::var("NETQMON_RETENTION_BASELINE").as_deref() == Ok("true");
    let rows: u32 = std::env::var("NETQMON_RETENTION_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("retention-bench.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .connection()
        .execute_batch("CREATE TABLE writer_probe (value INTEGER)")
        .unwrap();
    storage.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2,'gateway-1',1,1,1,'app','cat','example',CAST(printf('%016x',i) AS BLOB),6,'tcp',1,1,1,1 FROM n", params![rows, to_i64(NOW)]).unwrap();
    storage
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let autocheckpoint_pages = std::env::var("NETQMON_RETENTION_AUTOCHECKPOINT_PAGES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    storage
        .connection()
        .pragma_update(None, "wal_autocheckpoint", autocheckpoint_pages)
        .unwrap();
    let mut bounded_writer = if baseline {
        None
    } else {
        let writer = storage.independent_connection(false).unwrap().unwrap();
        writer
            .connection()
            .pragma_update(None, "wal_autocheckpoint", autocheckpoint_pages)
            .unwrap();
        Some(writer)
    };
    let wal = dir.path().join("retention-bench.db-wal");
    let running = Arc::new(AtomicBool::new(true));
    let ready = Arc::new(Barrier::new(2));
    let writer = if std::env::var_os("NETQMON_RETENTION_WRITER").is_some() {
        let (worker_running, worker_ready, path) = (running.clone(), ready.clone(), path.clone());
        let worker = std::thread::spawn(move || {
            let connection = Connection::open(path).unwrap();
            connection.busy_timeout(Duration::from_millis(500)).unwrap();
            let mut observations = Vec::new();
            worker_ready.wait();
            while worker_running.load(Ordering::Relaxed) {
                let start = Instant::now();
                let result = connection.execute("INSERT INTO writer_probe VALUES(1)", []);
                observations.push((start.elapsed(), result.is_ok()));
                std::thread::sleep(Duration::from_millis(5));
            }
            observations
        });
        ready.wait();
        Some(worker)
    } else {
        None
    };
    let before = process_write_bytes();
    let cpu_before = process_cpu_ticks();
    RETENTION_TRANSACTION_TIMES.with(|v| v.borrow_mut().clear());
    RETENTION_PHASE_TIMES.with(|v| v.borrow_mut().clear());
    let started = Instant::now();
    let mut cycles = 0;
    if baseline {
        legacy_full_retention(
            &mut storage,
            NOW + 31 * DAY_MS as u64,
            RetentionPolicy::default(),
        );
    } else {
        loop {
            cycles += 1;
            if bounded_writer
                .as_mut()
                .unwrap()
                .run_retention_bounded(
                    NOW + 31 * DAY_MS as u64,
                    RetentionPolicy::default(),
                    RetentionBudget {
                        max_rows_per_batch: std::env::var("NETQMON_RETENTION_BATCH_ROWS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(500),
                        transaction_target: Duration::from_millis(
                            std::env::var("NETQMON_RETENTION_TRANSACTION_MS")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(100),
                        ),
                        ..RetentionBudget::default()
                    },
                )
                .unwrap()
            {
                break;
            }
        }
    }
    let elapsed = started.elapsed();
    running.store(false, Ordering::Relaxed);
    if let Some(writer) = writer {
        let observations = writer.join().unwrap();
        let mut latency: Vec<_> = observations.iter().map(|(duration, _)| *duration).collect();
        latency.sort();
        let p50 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(50)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        let p95 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(95)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        let p99 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(99)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        eprintln!(
            "writer_baseline={baseline} attempts={} success={} errors={} p50_us={p50:?} p95_us={p95:?} p99_us={p99:?} max_us={:?}",
            observations.len(),
            observations.iter().filter(|(_, ok)| *ok).count(),
            observations.iter().filter(|(_, ok)| !*ok).count(),
            latency.last().map(Duration::as_micros)
        );
    }
    let cpu_ticks = cpu_before
        .zip(process_cpu_ticks())
        .and_then(|(a, b)| b.checked_sub(a));
    let mut tx_times = RETENTION_TRANSACTION_TIMES.with(|v| v.borrow().clone());
    if baseline {
        tx_times.push(elapsed);
    }
    tx_times.sort();
    let tx_p95 = tx_times
        .get(
            tx_times
                .len()
                .saturating_mul(95)
                .div_ceil(100)
                .saturating_sub(1),
        )
        .map(Duration::as_micros);
    let tx_max = tx_times.last().map(Duration::as_micros);
    let p99_index = tx_times
        .len()
        .saturating_mul(99)
        .div_ceil(100)
        .saturating_sub(1);
    let tx_p99 = tx_times.get(p99_index).map(Duration::as_micros);
    let phases = RETENTION_PHASE_TIMES.with(|v| v.borrow().clone());
    let phase_percentile = |idx: usize, percentile: usize| {
        let mut values: Vec<_> = phases
            .iter()
            .map(|phase| match idx {
                0 => phase.0,
                1 => phase.1,
                _ => phase.2,
            })
            .collect();
        values.sort();
        values
            .get(
                values
                    .len()
                    .saturating_mul(percentile)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros)
    };
    let phase_p95 = (
        phase_percentile(0, 95),
        phase_percentile(1, 95),
        phase_percentile(2, 95),
    );
    let io = before
        .zip(process_write_bytes())
        .and_then(|(a, b)| b.checked_sub(a));
    let peak = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .map(str::to_owned)
        });
    eprintln!(
        "retention_baseline={baseline} rows={rows} batch_rows={} autocheckpoint_pages={autocheckpoint_pages} elapsed_ms={} cycles={cycles} wal_bytes={} process_write_bytes={io:?} peak_rss={peak:?} cpu_ticks={cpu_ticks:?} tx_count={} tx_p95_us={tx_p95:?} tx_p99_us={tx_p99:?} tx_max_us={tx_max:?} begin_delete_commit_p95_us={phase_p95:?}",
        std::env::var("NETQMON_RETENTION_BATCH_ROWS").unwrap_or_else(|_| "500".into()),
        elapsed.as_millis(),
        std::fs::metadata(wal).unwrap().len(),
        tx_times.len()
    );
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

// Run with: cargo test -p netqmon-storage --release file_total_rollup_benchmark -- --ignored --nocapture
#[test]
#[ignore = "manual SQLite file benchmark"]
fn file_total_rollup_benchmark() {
    for scenario in ["repeated", "distinct", "mixed"] {
        if std::env::var("NETQMON_BENCH_SCENARIO").is_ok_and(|v| v != scenario) {
            continue;
        }
        for batched in [false, true] {
            if std::env::var("NETQMON_BENCH_BATCHED").is_ok_and(|v| v != batched.to_string()) {
                continue;
            }
            let dir = tempdir().unwrap();
            let path = dir.path().join("bench.db");
            let mut storage = open_at(&path, NOW).unwrap();
            storage
                .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
                .unwrap();
            storage
                .connection()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0;")
                .unwrap();
            let wal = dir.path().join("bench.db-wal");
            let before_wal = std::fs::metadata(&wal).unwrap().len();
            let before_db = std::fs::metadata(&path).unwrap().len();
            let mut input = batch(1, FlowLifecycle::Active);
            let mut flow = input.flows[0].clone();
            if std::env::var_os("NETQMON_PROFILE_ENDED").is_some() {
                flow.lifecycle = FlowLifecycle::Ended as i32;
            }
            input.flows = (0..4096)
                .map(|i| {
                    let mut f = flow.clone();
                    if scenario == "distinct" || (scenario == "mixed" && i % 2 == 0) {
                        f.remote_ip = (i as u32).to_be_bytes().to_vec();
                    }
                    f
                })
                .collect();
            let attrs: Vec<_> = (0..input.flows.len())
                .map(|i| {
                    if scenario == "mixed" && i % 128 == 0 {
                        service_attribution()
                    } else {
                        FlowAttribution::default()
                    }
                })
                .collect();
            if std::env::var_os("NETQMON_PROFILE_SQL").is_some() {
                BENCH_SQL_PROFILE.with(|profile| *profile.borrow_mut() = Some(HashMap::new()));
            }
            let write_before = process_write_bytes();
            let cpu_before = process_cpu_ticks();
            let start = Instant::now();
            storage
                .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, batched)
                .unwrap();
            let elapsed = start.elapsed();
            let cpu_ticks = cpu_before
                .zip(process_cpu_ticks())
                .and_then(|(a, b)| b.checked_sub(a));
            let counts = LAST_TOTAL_ROLLUP_COUNTS.get();
            let wal_bytes = std::fs::metadata(&wal).unwrap().len() - before_wal;
            let db_growth = std::fs::metadata(&path).unwrap().len() - before_db;
            let io_written = write_before
                .zip(process_write_bytes())
                .and_then(|(before, after)| after.checked_sub(before));
            let peak_rss = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find(|line| line.starts_with("VmHWM:"))
                        .map(str::to_owned)
                });
            eprintln!(
                "scenario={scenario} batched={batched} flows={} total_original={} total_upserts={} elapsed_us={} wal_file_growth={} db_file_growth={} cache_bytes={} peak_rss={peak_rss:?} process_write_bytes={io_written:?} cpu_ticks={cpu_ticks:?}",
                input.flows.len(),
                counts.0,
                counts.1,
                elapsed.as_micros(),
                wal_bytes,
                db_growth,
                std::mem::size_of::<TotalRollupBatch>()
            );
            BENCH_SQL_PROFILE.with(|profile| {
                if let Some(entries) = profile.borrow_mut().take() {
                    let mut entries: Vec<_> = entries.into_iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    for (name, entry) in entries {
                        eprintln!("sql_profile scenario={scenario} batched={batched} path={name} calls={} elapsed_us={} unique_keys={}", entry.calls, entry.nanos / 1_000, entry.keys.len());
                    }
                }
            });
            assert_eq!(counts.0, 4096);
            assert_eq!(
                metrics(storage.connection(), "traffic_total_minute", "1=1").3,
                4096
            );
        }
    }
}

#[test]
#[ignore = "manual historical rollup benchmark"]
fn historical_rollup_benchmark() {
    let mut storage = setup();
    storage.connection().execute(
        "WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99999)
         INSERT INTO traffic_total_minute(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count)
         SELECT ?1+i*60000,'gateway-1',1,1,1,1 FROM n", [to_i64(NOW)]
    ).unwrap();
    let later = NOW + 100_000 * 60_000 + 2 * DAY_MS as u64;
    storage.roll_up_hour_and_day(later).unwrap();
    let start = Instant::now();
    for _ in 0..100 {
        storage.roll_up_hour_and_day(later).unwrap();
    }
    eprintln!(
        "historical_minutes=100000 idle_maintenance_100={:?}",
        start.elapsed()
    );
    assert_eq!(
        metrics(storage.connection(), "traffic_total_day", "1=1"),
        (100000, 100000, 100000, 100000)
    );
}

// Run with: cargo test -p netqmon-storage --release hot_paths_with_large_active_cache -- --ignored --nocapture
#[test]
#[ignore = "manual hot-path scaling benchmark"]
fn hot_paths_with_large_active_cache() {
    for size in [100_u32, 10_000, 30_000] {
        let mut storage = setup();
        let input = batch(1, FlowLifecycle::Active);
        storage
            .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
            .unwrap();
        for index in 0..size {
            let mut flow = input.flows[0].clone();
            flow.remote_ip = index.to_be_bytes().to_vec();
            let key = FlowKey::from_batch("gateway-1", &flow);
            let current = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW));
            storage.active_flows.insert(key, current);
        }
        let mut unified = Storage::sqlite(storage);
        let start = Instant::now();
        for index in 0..100 {
            unified
                .reclassify_flow_at(
                    "gateway-1",
                    &input.flows[0],
                    &service_attribution(),
                    NOW + index,
                )
                .unwrap();
        }
        let dpi = start.elapsed();
        let Storage::Sqlite(mut storage) = unified else {
            unreachable!()
        };
        let start = Instant::now();
        for sequence in 2..102 {
            storage
                .persist_classified_batch(
                    &batch(sequence, FlowLifecycle::Active),
                    &[transport_attribution()],
                    &[],
                    NOW + sequence,
                )
                .unwrap();
        }
        eprintln!(
            "active_cache={size} dpi_100={dpi:?} ingest_100={:?}",
            start.elapsed()
        );
        assert_eq!(
            metrics(storage.connection(), "traffic_total_minute", "1=1"),
            (10100, 5050, 303, 101)
        );
    }
}
