use super::*;
use crate::attribution::{CORRECTION_WINDOW_MS, ENDED_GRACE_MS};

fn count(storage: &SqliteStorage, table: &str) -> i64 {
    storage
        .connection()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn owned_cache_checkpoint_is_batched_and_failed_checkpoint_keeps_entries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("owned-cache-batches.db");
    let mut sqlite = open_at(&path, NOW).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Active);
    for port in 50_001..50_006 {
        let mut flow = input.flows[0].clone();
        flow.client_port = port;
        input.flows.push(flow);
    }
    sqlite
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    sqlite.connection().execute_batch("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON flow_sessions BEGIN SELECT RAISE(ABORT, 'checkpoint failure'); END").unwrap();
    let mut storage = Storage::sqlite(sqlite);
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64 + 1;
    let budget = RetentionBudget {
        max_rows_per_batch: 2,
        transaction_target: Duration::from_secs(2),
        ..RetentionBudget::default()
    };
    assert!(storage.prune_owned_flow_cache(expired, budget).is_err());
    assert_eq!(storage.active_flow_count().unwrap(), 6);
    storage
        .connection()
        .execute_batch("DROP TRIGGER reject_checkpoint")
        .unwrap();
    let mut previous = 6;
    for _ in 0..20 {
        let done = storage.prune_owned_flow_cache(expired, budget).unwrap();
        let remaining = storage.active_flow_count().unwrap();
        assert!(previous - remaining <= 2);
        previous = remaining;
        if done {
            break;
        }
    }
    assert_eq!(previous, 0);
    drop(storage);
    let reopened = open_at(&path, expired + 1).unwrap();
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1"),
        (600, 300, 18, 6)
    );
    let (ended, bytes): (i64, i64) = reopened
        .connection()
        .query_row(
            "SELECT COUNT(*), SUM(upload_bytes) FROM flow_sessions WHERE ended_at IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((ended, bytes), (6, 600));
}

#[test]
fn concurrent_owner_pruning_and_ingest_preserve_counters_after_restart() {
    use std::sync::{Arc, Barrier, Mutex};
    let dir = tempdir().unwrap();
    let path = dir.path().join("owner-concurrent.db");
    let mut sqlite = open_at(&path, NOW).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    sqlite
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[service_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    let shared = Arc::new(Mutex::new(Storage::sqlite(sqlite)));
    let barrier = Arc::new(Barrier::new(2));
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    let worker_storage = Arc::clone(&shared);
    let worker_barrier = Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        for sequence in 2..=101 {
            worker_storage
                .lock()
                .unwrap()
                .persist_classified_batch(
                    &batch(sequence, FlowLifecycle::Active),
                    &[service_attribution()],
                    &[],
                    expired + sequence,
                )
                .unwrap();
            std::thread::yield_now();
        }
    });
    barrier.wait();
    for _ in 0..100 {
        shared
            .lock()
            .unwrap()
            .prune_owned_flow_cache(expired, RetentionBudget::default())
            .unwrap();
        std::thread::yield_now();
    }
    worker.join().unwrap();
    let storage = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (10_100, 5_050, 303, 101)
    );
    drop(storage);
    let reopened = open_at(&path, expired + 102).unwrap();
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1"),
        (10_100, 5_050, 303, 101)
    );
    assert_eq!(reopened.active_flows.len(), 1);
    assert_eq!(reopened.active_flows.expiry.len(), 1);
    let active = reopened.active_flows.values().next().unwrap();
    assert_eq!(
        (active.upload_bytes, active.download_bytes),
        (10_100, 5_050)
    );
    assert_eq!(active.attribution.application_id, "video-app");
}

#[test]
fn interrupted_owner_checkpoint_reduces_next_batch_without_evicting() {
    let dir = tempdir().unwrap();
    let mut sqlite = open_at(&dir.path().join("interrupted-owner.db"), NOW).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Active);
    for port in 50_001..50_020 {
        let mut flow = input.flows[0].clone();
        flow.client_port = port;
        input.flows.push(flow);
    }
    sqlite
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    let mut storage = Storage::sqlite(sqlite);
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    let mut budget = RetentionBudget {
        max_rows_per_batch: 20,
        transaction_target: Duration::from_nanos(1),
        ..RetentionBudget::default()
    };
    assert!(!storage.prune_owned_flow_cache(expired, budget).unwrap());
    let Storage::Sqlite(sqlite) = &storage else {
        unreachable!()
    };
    assert_eq!(sqlite.active_flows.len(), 20);
    assert_eq!(sqlite.owner_prune_rows, Some(10));
    budget.transaction_target = Duration::from_secs(2);
    for _ in 0..10 {
        if storage.prune_owned_flow_cache(expired, budget).unwrap() {
            break;
        }
    }
    assert_eq!(storage.active_flow_count().unwrap(), 0);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (2_000, 1_000, 60, 20)
    );
}

#[test]
fn startup_recovery_gc_retries_after_progress_handler_interruptions() {
    let mut storage = setup();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();

    // A deliberately tiny initial budget forces SQLite's progress handler to
    // interrupt the first slices. Startup recovery must relax its budget and
    // finish instead of retrying an identical, doomed slice forever.
    storage
        .prune_reclassification_at_startup_with_budget(
            NOW + ACTIVE_FLOW_TTL_MS as u64 + 1,
            500,
            Some(Duration::from_nanos(1)),
            Duration::from_secs(5),
        )
        .unwrap();

    assert_eq!(count(&storage, "flow_rollup_sessions"), 0);
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn maintenance_writer_retries_interrupted_recovery_with_smaller_file_db_batches() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("maintenance-recovery-adaptive.db");
    let mut sqlite = open_at(&path, NOW).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Active);
    let base = input.flows[0].clone();
    input.flows.clear();
    for port in 50_000..50_100 {
        let mut flow = base.clone();
        flow.client_port = port;
        input.flows.push(flow);
    }
    sqlite
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64 + 1;
    let mut owner = Storage::sqlite(sqlite);
    let tiny_budget = RetentionBudget {
        max_rows_per_batch: 100,
        transaction_target: Duration::from_nanos(1),
        ..RetentionBudget::default()
    };

    let mut writer = owner.maintenance_writer().unwrap().unwrap();
    assert!(
        !writer
            .prune_reclassification_for_maintenance_bounded(expired, tiny_budget)
            .unwrap()
    );
    owner.sync_maintenance_state_from(&writer);
    let Storage::Sqlite(owner_sqlite) = &owner else {
        unreachable!();
    };
    assert_eq!(owner_sqlite.recovery_prune_rows, Some(50));

    let mut writer = owner.maintenance_writer().unwrap().unwrap();
    assert!(
        !writer
            .prune_reclassification_for_maintenance_bounded(
                expired,
                RetentionBudget {
                    transaction_target: Duration::from_secs(1),
                    ..tiny_budget
                },
            )
            .unwrap()
    );
    owner.sync_maintenance_state_from(&writer);
    let Storage::Sqlite(owner_sqlite) = &owner else {
        unreachable!();
    };
    assert_eq!(owner_sqlite.recovery_prune_rows, Some(100));

    let mut complete = false;
    for _ in 0..10 {
        let mut writer = owner.maintenance_writer().unwrap().unwrap();
        complete = writer
            .prune_reclassification_for_maintenance_bounded(
                expired,
                RetentionBudget {
                    transaction_target: Duration::from_secs(1),
                    ..tiny_budget
                },
            )
            .unwrap();
        owner.sync_maintenance_state_from(&writer);
        if complete {
            break;
        }
    }
    assert!(complete);
    let Storage::Sqlite(owner_sqlite) = &mut owner else {
        unreachable!();
    };
    assert_eq!(owner_sqlite.recovery_prune_rows, None);
    assert_eq!(count(owner_sqlite, "flow_rollup_sessions"), 0);

    // Expire and checkpoint the owner cache after the independent recovery
    // pass; persisted traffic totals must survive closing and reopening.
    assert!(
        owner
            .prune_owned_flow_cache(expired, RetentionBudget::default())
            .unwrap()
    );
    drop(owner);
    let reopened = open_at(&path, expired + 1).unwrap();
    assert_eq!(count(&reopened, "flow_rollup_sessions"), 0);
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1"),
        (10_000, 5_000, 300, 100)
    );
}

#[test]
fn startup_recovery_gc_yields_and_background_maintenance_resumes() {
    let mut storage = setup();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64 + 60_000;

    storage
        .prune_reclassification_at_startup_with_budget(
            expired,
            1,
            Some(Duration::from_millis(100)),
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(count(&storage, "flow_rollup_contributions"), 1);
    assert!(
        load_active_flows(storage.connection(), expired)
            .unwrap()
            .is_empty()
    );

    assert!(
        storage
            .prune_reclassification_bounded(expired, 1, Duration::from_secs(1))
            .unwrap()
    );
    assert_eq!(count(&storage, "flow_rollup_contributions"), 0);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
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
         DROP INDEX traffic_device_minute_device;
         ALTER TABLE devices DROP COLUMN device_type_override;
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
