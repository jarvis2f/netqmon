use super::*;

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
