use super::*;

#[test]
fn bounded_retention_allows_another_sqlite_writer_to_make_progress() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let dir = tempdir().unwrap();
    let path = dir.path().join("retention-concurrency.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .connection()
        .execute_batch("CREATE TABLE writer_probe (value INTEGER)")
        .unwrap();
    storage.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<10000) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?1,'gateway-1',1,1,1,'app','cat','test',CAST(printf('%016x',i) AS BLOB),6,'tcp',1,1,1,1 FROM n", [to_i64(NOW)]).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let count = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(Barrier::new(2));
    let worker = {
        let (running, count, ready, path) =
            (running.clone(), count.clone(), ready.clone(), path.clone());
        std::thread::spawn(move || {
            let connection = Connection::open(path).unwrap();
            connection.busy_timeout(Duration::from_secs(5)).unwrap();
            ready.wait();
            while running.load(Ordering::Relaxed) {
                if connection
                    .execute("INSERT INTO writer_probe VALUES(1)", [])
                    .is_ok()
                {
                    count.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    ready.wait();
    let before = count.load(Ordering::Relaxed);
    let result = storage.run_retention_bounded(
        NOW + 31 * DAY_MS as u64,
        RetentionPolicy::default(),
        RetentionBudget::default(),
    );
    running.store(false, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(result.unwrap());
    assert!(
        count.load(Ordering::Relaxed) > before,
        "concurrent writer made no progress"
    );
}

#[test]
fn bounded_retention_resumes_after_failure_and_restart_with_scope_totals_consistent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bounded-retention.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Ended);
    let original = input.flows[0].clone();
    input.flows = (1..=8)
        .map(|i| {
            let mut f = original.clone();
            f.remote_ip = vec![198, 51, 100, i];
            f
        })
        .collect();
    storage
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    let later = NOW + 31 * DAY_MS as u64;
    let budget = RetentionBudget {
        max_rows_per_batch: 1,
        transaction_target: Duration::from_millis(100),
        total_budget: Duration::from_secs(5),
    };
    assert!(
        !storage
            .run_retention_bounded(
                later,
                RetentionPolicy::default(),
                RetentionBudget {
                    total_budget: Duration::ZERO,
                    ..budget
                }
            )
            .unwrap()
    );
    storage.connection().execute_batch("CREATE TRIGGER fail_scope_expiry BEFORE DELETE ON traffic_scope_minute BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let mut injected_failure_seen = false;
    for _ in 0..100 {
        match storage.run_retention_bounded(later, RetentionPolicy::default(), budget) {
            Err(_) => {
                injected_failure_seen = true;
                break;
            }
            Ok(true) => break,
            Ok(false) => {}
        }
    }
    assert!(injected_failure_seen);
    let source: i64 = storage
        .connection()
        .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| {
            r.get(0)
        })
        .unwrap();
    let total: i64 = storage
        .connection()
        .query_row(
            "SELECT sum(source_rows) FROM traffic_scope_total_minute",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!((source, total), (8, 8));
    storage
        .connection()
        .execute_batch("DROP TRIGGER fail_scope_expiry")
        .unwrap();
    drop(storage);
    let mut storage = open_at(&path, later).unwrap();
    let mut completed = false;
    for _ in 0..100 {
        if storage
            .run_retention_bounded(later, RetentionPolicy::default(), budget)
            .unwrap()
        {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_total_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn retention_progress_interrupt_rolls_back_current_batch_and_can_resume() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("interrupt-retention.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Ended);
    let original = input.flows[0].clone();
    input.flows = (1..=32)
        .map(|i| {
            let mut flow = original.clone();
            flow.remote_ip = vec![203, 0, 113, i];
            flow
        })
        .collect();
    storage
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    let later = NOW + 31 * DAY_MS as u64;
    let interrupted = storage
        .run_retention_bounded(
            later,
            RetentionPolicy::default(),
            RetentionBudget {
                max_rows_per_batch: 32,
                transaction_target: Duration::ZERO,
                total_budget: Duration::from_secs(1),
            },
        )
        .unwrap();
    assert!(!interrupted);
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        32
    );
    drop(storage);
    let mut storage = open_at(&path, later).unwrap();
    let mut complete = false;
    for _ in 0..100 {
        if storage
            .run_retention_bounded(
                later,
                RetentionPolicy::default(),
                RetentionBudget {
                    max_rows_per_batch: 8,
                    ..RetentionBudget::default()
                },
            )
            .unwrap()
        {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn v8_upgrade_bootstraps_only_unmaterialized_history() {
    let mut storage = setup();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    let later = NOW + 2 * DAY_MS as u64;
    storage.roll_up_hour_and_day(later).unwrap();
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Ended), &[], &[], NOW + 1)
        .unwrap();
    for dimension in DIMENSIONS {
        for (source, target) in [("minute", "hour"), ("hour", "day")] {
            storage
                .connection()
                .execute_batch(&format!(
                    "DROP TRIGGER traffic_{dimension}_{source}_pending_insert;
                 DROP TRIGGER traffic_{dimension}_{source}_pending_update;
                 DROP TABLE traffic_{dimension}_{target}_pending;"
                ))
                .unwrap();
        }
    }
    storage
        .connection()
        .execute("DELETE FROM schema_migrations WHERE version=9", [])
        .unwrap();
    let mut upgraded = SqliteStorage::from_connection_at(storage.connection, NOW + 2).unwrap();
    upgraded.roll_up_hour_and_day(later).unwrap();
    for tier in ["minute", "hour", "day"] {
        assert_eq!(
            metrics(
                upgraded.connection(),
                &format!("traffic_total_{tier}"),
                "1=1"
            ),
            (200, 100, 6, 2)
        );
    }
}

#[test]
fn repeated_maintenance_does_not_rewrite_history() {
    let mut storage = setup();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    let later = NOW + 2 * DAY_MS as u64;
    storage.roll_up_hour_and_day(later).unwrap();
    let changes = storage.connection().total_changes();
    storage.roll_up_hour_and_day(later).unwrap();
    assert_eq!(storage.connection().total_changes(), changes);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_day", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn bounded_rollup_resumes_across_restart_without_double_counting() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bounded-rollup.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Ended);
    let original = input.flows[0].clone();
    input.flows = (1..=20)
        .map(|i| {
            let mut flow = original.clone();
            flow.remote_ip = vec![198, 51, 100, i];
            flow.client_port += u32::from(i);
            flow
        })
        .collect();
    storage
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    let later = NOW + 2 * DAY_MS as u64;
    let budget = RetentionBudget {
        max_rows_per_batch: 3,
        transaction_target: Duration::from_millis(100),
        total_budget: Duration::from_secs(1),
    };
    assert!(!storage.roll_up_hour_and_day_bounded(later, budget).unwrap());
    drop(storage);

    let mut storage = open_at(&path, NOW + 1_000).unwrap();
    let mut complete = false;
    for _ in 0..100 {
        if storage.roll_up_hour_and_day_bounded(later, budget).unwrap() {
            complete = true;
            break;
        }
    }
    assert!(complete, "bounded rollup did not drain its pending rows");
    for tier in ["minute", "hour", "day"] {
        assert_eq!(
            metrics(
                storage.connection(),
                &format!("traffic_total_{tier}"),
                "1=1"
            ),
            (2_000, 1_000, 60, 20),
            "incorrect {tier} totals"
        );
        assert_eq!(
            metrics(
                storage.connection(),
                &format!("traffic_destination_{tier}"),
                "1=1"
            ),
            (2_000, 1_000, 60, 20),
            "incorrect {tier} destination totals"
        );
    }
    let changes = storage.connection().total_changes();
    assert!(storage.roll_up_hour_and_day_bounded(later, budget).unwrap());
    assert_eq!(storage.connection().total_changes(), changes);
}

#[test]
fn bounded_rollup_yields_to_another_file_database_writer() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    let dir = tempdir().unwrap();
    let path = dir.path().join("bounded-rollup-concurrency.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<10000) INSERT INTO traffic_destination_minute(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) SELECT ?1,'gateway-1',CAST(printf('%08x',i) AS BLOB),1,1,1,1 FROM n", [to_i64(NOW - DAY_MS as u64)]).unwrap();
    storage
        .connection()
        .execute_batch("CREATE TABLE writer_probe(value INTEGER)")
        .unwrap();

    let running = Arc::new(AtomicBool::new(true));
    let writes = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(Barrier::new(2));
    let worker = {
        let (running, writes, ready, worker_path) =
            (running.clone(), writes.clone(), ready.clone(), path.clone());
        std::thread::spawn(move || {
            let connection = Connection::open(worker_path).unwrap();
            connection.busy_timeout(Duration::from_secs(5)).unwrap();
            ready.wait();
            while running.load(Ordering::Relaxed) {
                if connection
                    .execute("INSERT INTO writer_probe VALUES(1)", [])
                    .is_ok()
                {
                    writes.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    ready.wait();
    while writes.load(Ordering::Relaxed) == 0 {
        std::thread::yield_now();
    }
    let before = writes.load(Ordering::Relaxed);
    let result = storage.roll_up_hour_and_day_bounded(
        NOW + 2 * DAY_MS as u64,
        RetentionBudget {
            max_rows_per_batch: 50,
            transaction_target: Duration::from_millis(100),
            total_budget: Duration::from_secs(1),
        },
    );
    running.store(false, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(!result.unwrap());
    assert!(writes.load(Ordering::Relaxed) > before);
}

#[test]
fn rollup_marker_pages_seek_the_contribution_primary_key_without_sorting() {
    let storage = setup();
    let plan = storage
        .connection()
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT session_ref,timestamp,scope,direction,device_id,remote_ip,protocol
             FROM flow_rollup_contributions
             WHERE (session_ref,timestamp,scope,direction,device_id,remote_ip,protocol)
                   >(0,0,0,0,0,X'',0)
             ORDER BY session_ref,timestamp,scope,direction,device_id,remote_ip,protocol
             LIMIT 500",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join(" | ");
    assert!(
        plan.contains("PRIMARY KEY"),
        "unexpected marker page plan: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE"),
        "marker page should preserve primary-key order: {plan}"
    );
}

#[test]
fn late_classification_is_not_applied_twice_by_incremental_maintenance() {
    let mut storage = setup();
    let input = batch(1, FlowLifecycle::Ended);
    storage
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    let later = NOW + 2 * DAY_MS as u64;
    storage.roll_up_hour_and_day(later).unwrap();
    attribution::reclassify_sqlite(
        &mut storage,
        "gateway-1",
        &input.flows[0],
        &service_attribution(),
        to_i64(NOW + 2_000),
    )
    .unwrap();
    for _ in 0..3 {
        storage.roll_up_hour_and_day(later).unwrap();
        for tier in ["minute", "hour", "day"] {
            assert_eq!(
                metrics(
                    storage.connection(),
                    &format!("traffic_application_{tier}"),
                    "application_id='video-app'"
                ),
                (100, 50, 3, 1)
            );
            assert_eq!(
                metrics(
                    storage.connection(),
                    &format!("traffic_application_{tier}"),
                    "application_id!='video-app'"
                ),
                (0, 0, 0, 0)
            );
        }
    }
}

#[test]
fn late_old_bucket_survives_source_retention_without_replacing_preserved_history() {
    let mut storage = setup();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    let later = NOW + 10 * DAY_MS as u64;
    storage
        .run_retention(
            later,
            RetentionPolicy {
                minute_days: 1,
                flow_sessions_days: 365,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (0, 0, 0, 0)
    );
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Ended), &[], &[], later + 1)
        .unwrap();
    storage.roll_up_hour_and_day(later + 2).unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
    for dim in DIMENSIONS {
        for tier in ["hour", "day"] {
            let expected = (200, 100, 6, 2);
            assert_eq!(
                metrics(
                    storage.connection(),
                    &format!("traffic_{dim}_{tier}"),
                    "1=1"
                ),
                expected
            );
        }
    }
}

#[test]
fn pending_deltas_survive_restart_and_failed_maintenance() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pending.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    drop(storage);
    let mut storage = open_at(&path, NOW + 2_000).unwrap();
    storage.connection().execute_batch("CREATE TRIGGER reject_rollup BEFORE INSERT ON traffic_total_hour BEGIN SELECT RAISE(ABORT,'rollback'); END;").unwrap();
    let later = NOW + 2 * DAY_MS as u64;
    assert!(storage.roll_up_hour_and_day(later).is_err());
    assert_eq!(
        metrics(storage.connection(), "traffic_total_hour", "1=1"),
        (0, 0, 0, 0)
    );
    storage
        .connection()
        .execute_batch("DROP TRIGGER reject_rollup")
        .unwrap();
    storage.roll_up_hour_and_day(later).unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_day", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn retention_also_expires_unmaterialized_work() {
    let mut storage = setup();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    let later = NOW + 400 * DAY_MS as u64;
    storage
        .run_retention(later, RetentionPolicy::default())
        .unwrap();
    storage.roll_up_hour_and_day(later).unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_hour", "1=1"),
        (0, 0, 0, 0)
    );
}

#[test]
fn wal_reader_is_consistent_while_the_writer_commits() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wal.db");
    let mut storage = Storage::sqlite(open_at(&path, NOW).unwrap());
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Ended), &[], &[], NOW)
        .unwrap();
    let reader = storage.query_reader().unwrap().unwrap();
    assert_eq!(
        metrics(reader.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Ended), &[], &[], NOW + 1)
        .unwrap();
    assert_eq!(
        metrics(reader.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
    assert!(
        reader
            .connection()
            .execute("DELETE FROM flow_sessions", [])
            .is_err()
    );
    let next = storage.query_reader().unwrap().unwrap();
    assert_eq!(
        metrics(next.connection(), "traffic_total_minute", "1=1"),
        (200, 100, 6, 2)
    );
}

#[test]
fn late_dpi_waits_for_a_maintenance_writer_before_reading() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("writers.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let input = batch(1, FlowLifecycle::Ended);
    storage
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    let maintenance = storage.independent_connection(false).unwrap().unwrap();
    maintenance
        .connection
        .execute_batch("BEGIN IMMEDIATE; UPDATE gateways SET name='maintenance';")
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = attribution::reclassify_sqlite(
            &mut storage,
            "gateway-1",
            &input.flows[0],
            &service_attribution(),
            to_i64(NOW + 2_000),
        );
        done_tx.send((result, storage)).unwrap();
    });
    started_rx.recv().unwrap();
    let early = done_rx.recv_timeout(Duration::from_millis(200));
    let waited = matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout));
    maintenance.connection.execute_batch("COMMIT").unwrap();
    let (result, storage) = early.unwrap_or_else(|_| done_rx.recv().unwrap());
    worker.join().unwrap();
    assert!(
        waited,
        "DPI must wait for the writer instead of upgrading a stale read snapshot"
    );
    result.unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (100, 50, 3, 1)
    );
}
