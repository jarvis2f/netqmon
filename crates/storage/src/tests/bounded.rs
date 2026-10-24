use super::*;
use crate::attribution::{CORRECTION_WINDOW_MS, ENDED_GRACE_MS};

fn count(storage: &SqliteStorage, table: &str) -> i64 {
    storage
        .connection()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn session_json_is_stored_once_across_minutes() {
    let mut storage = setup();
    for seq in 1..=6 {
        let mut input = batch(seq, FlowLifecycle::Active);
        input.sent_at = NOW + seq * 60_000;
        storage
            .persist_classified_batch(&input, &[transport_attribution()], &[], NOW + seq * 60_000)
            .unwrap();
    }
    assert_eq!(count(&storage, "flow_rollup_sessions"), 1);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 6);
    let columns = storage
        .connection()
        .prepare("PRAGMA table_info(flow_rollup_contributions)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for forbidden in [
        "metadata_json",
        "attribution_json",
        "session_upload",
        "session_id",
    ] {
        assert!(!columns.iter().any(|name| name == forbidden));
    }
}

#[test]
fn only_recent_contributions_move_even_before_gc_and_restart_preserves_full_counts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("window.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    let later = NOW + CORRECTION_WINDOW_MS as u64 + 60_000;
    let mut second = batch(2, FlowLifecycle::Active);
    second.sent_at = later;
    second.flows[0].last_seen_unix_ms = later;
    storage
        .persist_classified_batch(&second, &[transport_attribution()], &[], later)
        .unwrap();
    let mut unified = Storage::sqlite(storage);
    unified
        .reclassify_flow_at(
            "gateway-1",
            &second.flows[0],
            &service_attribution(),
            later + 1_000,
        )
        .unwrap();
    assert_eq!(
        metrics(
            unified.connection(),
            "traffic_application_minute",
            "application_id='protocol:tls'"
        ),
        (100, 50, 3, 1)
    );
    assert_eq!(
        metrics(
            unified.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (100, 50, 3, 1)
    );
    let Storage::Sqlite(mut storage) = unified else {
        unreachable!()
    };
    storage.prune_reclassification(later + 2_000).unwrap();
    assert_eq!(count(&storage, "flow_rollup_contributions"), 1);
    drop(storage);
    let mut storage = open_at(&path, NOW).unwrap();
    let mut third = batch(3, FlowLifecycle::Ended);
    third.sent_at = later + 3_000;
    third.flows[0].last_seen_unix_ms = later + 3_000;
    storage
        .persist_classified_batch(&third, &[transport_attribution()], &[], later + 3_000)
        .unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (300, 150, 9, 3)
    );
    let session: (i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets FROM flow_sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(session, (300, 150, 9));
}

#[test]
fn closed_grace_boundary_freezes_history_but_keeps_latest_session_identity() {
    let mut storage = setup();
    let input = batch(1, FlowLifecycle::Ended);
    storage
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    let mut storage = Storage::sqlite(storage);
    storage
        .reclassify_flow_at(
            "gateway-1",
            &input.flows[0],
            &service_attribution(),
            NOW + ENDED_GRACE_MS as u64 - 1,
        )
        .unwrap();
    let stronger = FlowAttribution {
        application_id: "better-app".into(),
        application_confidence: 0.99,
        ..service_attribution()
    };
    storage
        .reclassify_flow_at(
            "gateway-1",
            &input.flows[0],
            &stronger,
            NOW + ENDED_GRACE_MS as u64,
        )
        .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (100, 50, 3, 1)
    );
    let app: String = storage
        .connection()
        .query_row("SELECT application_id FROM flow_sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(app, "better-app");
    storage
        .prune_reclassification(NOW + ENDED_GRACE_MS as u64)
        .unwrap();
    let Storage::Sqlite(storage) = storage else {
        unreachable!()
    };
    assert_eq!(count(&storage, "flow_rollup_sessions"), 0);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn gc_checkpoints_unwritten_recovery_state_and_does_not_restore_stale_classification() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("orphan.db");
    let input = batch(1, FlowLifecycle::Active);
    {
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        storage
            .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
            .unwrap();
        assert_eq!(count(&storage, "flow_sessions"), 0);
    }
    let mut unified = Storage::sqlite(open_at(&path, NOW).unwrap());
    // Reopen before any new telemetry: the pending state must restore the tuple
    // and counters, so late DPI can still find this not-yet-checkpointed flow.
    let expired = NOW + CORRECTION_WINDOW_MS as u64;
    unified
        .reclassify_flow_at(
            "gateway-1",
            &input.flows[0],
            &service_attribution(),
            expired,
        )
        .unwrap();
    assert_eq!(
        metrics(
            unified.connection(),
            "traffic_application_minute",
            "application_id='protocol:tls'"
        ),
        (100, 50, 3, 1)
    );
    unified.prune_reclassification(expired).unwrap();
    let Storage::Sqlite(storage) = unified else {
        unreachable!()
    };
    assert_eq!(count(&storage, "flow_rollup_sessions"), 0);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    let identity: (String, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT application_id,upload_bytes,download_bytes FROM flow_sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(identity, ("video-app".into(), 100, 50));
    drop(storage);
    let mut storage = open_at(&path, NOW).unwrap();
    let mut next = batch(2, FlowLifecycle::Ended);
    next.sent_at = expired + 1_000;
    next.flows[0].last_seen_unix_ms = expired + 1_000;
    storage
        .persist_classified_batch(&next, &[transport_attribution()], &[], expired + 1_000)
        .unwrap();
    let totals: (i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes FROM flow_sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(totals, (200, 100));
}

#[test]
fn expired_row_in_same_bucket_is_not_resurrected_by_new_traffic() {
    let mut storage = setup();
    let first = batch(1, FlowLifecycle::Active);
    storage
        .persist_classified_batch(&first, &[transport_attribution()], &[], NOW)
        .unwrap();
    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    let later = NOW + CORRECTION_WINDOW_MS as u64 + 1;
    // Delayed telemetry can retain the old sent_at bucket while arriving later.
    let second = batch(2, FlowLifecycle::Active);
    storage
        .persist_classified_batch(&second, &[service_attribution()], &[], later)
        .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='protocol:tls'"
        ),
        (100, 50, 3, 1)
    );
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (100, 50, 3, 1)
    );
    let row: (i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes FROM flow_rollup_contributions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, (100, 50));
    let mut storage = Storage::sqlite(storage);
    let stronger = FlowAttribution {
        application_id: "better-app".into(),
        application_confidence: 0.99,
        ..service_attribution()
    };
    storage
        .reclassify_flow_at("gateway-1", &second.flows[0], &stronger, later + 1)
        .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='protocol:tls'"
        ),
        (100, 50, 3, 1)
    );
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='better-app'"
        ),
        (100, 50, 3, 1)
    );
    for tier in ["hour", "day"] {
        assert_eq!(
            metrics(
                storage.connection(),
                &format!("traffic_application_{tier}"),
                "application_id='protocol:tls'"
            ),
            (100, 50, 3, 1)
        );
        assert_eq!(
            metrics(
                storage.connection(),
                &format!("traffic_application_{tier}"),
                "application_id='better-app'"
            ),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn receipt_time_bounds_work_even_for_old_packet_timestamps() {
    let mut storage = setup();
    let input = batch(1, FlowLifecycle::Ended);
    let received = NOW + DAY_MS as u64;
    storage
        .persist_classified_batch(&input, &[transport_attribution()], &[], received)
        .unwrap();
    let mut storage = Storage::sqlite(storage);
    storage
        .reclassify_flow_at(
            "gateway-1",
            &input.flows[0],
            &service_attribution(),
            received + 1_000,
        )
        .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (100, 50, 3, 1)
    );
}

#[test]
fn gc_failure_rolls_back_checkpoint_and_deletion() {
    let mut storage = setup();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    storage.connection().execute_batch("CREATE TRIGGER reject_pending_gc BEFORE DELETE ON flow_rollup_sessions BEGIN SELECT RAISE(ABORT,'test gc rollback'); END;").unwrap();
    assert!(
        storage
            .prune_reclassification(NOW + CORRECTION_WINDOW_MS as u64)
            .is_err()
    );
    assert_eq!(count(&storage, "flow_sessions"), 0);
    assert_eq!(count(&storage, "flow_rollup_sessions"), 1);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 1);
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn v5_upgrade_preserves_history_and_enables_correction_for_new_traffic() {
    let mut storage = setup();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Ended),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    // Schema 5 has durable sessions and rollups, but no correction work tables.
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
        .execute_batch(
            "DROP TABLE flow_rollup_contributions;
         DROP TABLE flow_rollup_sessions;
         DROP INDEX dns_observations_answer_lookup;
         DROP INDEX flow_sessions_sample_lookup;
         DROP INDEX flow_sessions_open_checkpoint;
         DROP TRIGGER traffic_scope_total_insert;
         DROP TRIGGER traffic_scope_total_counters;
         DROP TRIGGER traffic_scope_total_move;
         DROP TRIGGER traffic_scope_total_delete;
         DROP TABLE traffic_scope_total_minute;
         DELETE FROM schema_migrations WHERE version>=6;",
        )
        .unwrap();
    let storage = SqliteStorage::from_connection_at(storage.connection, NOW).unwrap();
    assert_eq!(
        count(&storage, "schema_migrations"),
        i64::try_from(MIGRATIONS.len()).unwrap()
    );
    assert_eq!(count(&storage, "flow_rollup_sessions"), 0);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    let session: (i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets FROM flow_sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(session, (100, 50, 3));
    for tier in ["minute", "hour", "day"] {
        for dimension in ["total", "application"] {
            assert_eq!(
                metrics(
                    storage.connection(),
                    &format!("traffic_{dimension}_{tier}"),
                    "1=1"
                ),
                (100, 50, 3, 1)
            );
        }
    }

    // Opening again must not recreate tables or change the preserved aggregates.
    let mut storage = SqliteStorage::from_connection(storage.connection).unwrap();
    let mut next = batch(2, FlowLifecycle::Ended);
    next.sent_at += 60_000;
    next.flows[0].client_port += 1;
    storage
        .persist_classified_batch(&next, &[transport_attribution()], &[], NOW + 2_000)
        .unwrap();
    assert_eq!(count(&storage, "flow_rollup_sessions"), 1);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 1);
    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    let mut storage = Storage::sqlite(storage);
    storage
        .reclassify_flow_at(
            "gateway-1",
            &next.flows[0],
            &service_attribution(),
            NOW + 3_000,
        )
        .unwrap();
    for tier in ["minute", "hour", "day"] {
        for app in ["protocol:tls", "video-app"] {
            assert_eq!(
                metrics(
                    storage.connection(),
                    &format!("traffic_application_{tier}"),
                    &format!("application_id='{app}'")
                ),
                (100, 50, 3, 1)
            );
        }
        assert_eq!(
            metrics(
                storage.connection(),
                &format!("traffic_total_{tier}"),
                "1=1"
            ),
            (200, 100, 6, 2)
        );
    }
}

#[test]
fn long_running_flow_keeps_a_bounded_window_independent_of_history_retention() {
    let mut storage = setup();
    let mut last = batch(1, FlowLifecycle::Active);
    for i in 0..100 {
        let now = NOW + i * 60_000;
        last = batch(i + 1, FlowLifecycle::Active);
        last.sent_at = now;
        last.flows[0].last_seen_unix_ms = now;
        storage
            .persist_classified_batch(&last, &[transport_attribution()], &[], now)
            .unwrap();
        storage.prune_reclassification(now).unwrap();
        assert!(count(&storage, "flow_rollup_contributions") <= 30);
        assert_eq!(count(&storage, "flow_rollup_sessions"), 1);
    }
    let latest = NOW + 99 * 60_000;
    let mut storage = Storage::sqlite(storage);
    storage
        .reclassify_flow_at(
            "gateway-1",
            &last.flows[0],
            &service_attribution(),
            latest + 1,
        )
        .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (3000, 1500, 90, 30)
    );
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='protocol:tls'"
        ),
        (7000, 3500, 210, 70)
    );
    let Storage::Sqlite(mut storage) = storage else {
        unreachable!()
    };
    storage
        .run_retention(
            latest + CORRECTION_WINDOW_MS as u64,
            RetentionPolicy {
                minute_days: 0,
                ..RetentionPolicy::default()
            },
        )
        .unwrap();
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    assert_eq!(count(&storage, "flow_rollup_sessions"), 0);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (10000, 5000, 300, 100)
    );
}
