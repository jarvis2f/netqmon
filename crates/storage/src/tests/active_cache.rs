use super::*;

#[test]
fn missing_end_is_reclaimed_without_losing_counters_or_rollups() {
    let mut storage = setup();
    let input = batch(1, FlowLifecycle::Active);
    storage
        .persist_classified_batch(&input, &[service_attribution()], &[], NOW)
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    storage.prune_reclassification(expired - 1).unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    storage.prune_reclassification(expired).unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 0);
    let checkpoint: (i64, i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets,ended_at FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        checkpoint,
        (100, 50, 3, to_i64(input.flows[0].last_seen_unix_ms))
    );

    // The same lifetime's delayed End still includes an additional delta.
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Ended), &[], &[], expired + 1)
        .unwrap();
    let counters: (i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counters, (200, 100, 6));
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (200, 100, 6, 2)
    );
}

#[test]
fn resumed_lifetime_after_gc_survives_another_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("resumed.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Active), &[], &[], NOW)
        .unwrap();
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    storage.prune_reclassification(expired).unwrap();
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Active), &[], &[], expired + 1)
        .unwrap();
    drop(storage);
    let mut storage = open_at(&path, expired + 2).unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let current = storage.active_flows.values().next().unwrap();
    assert_eq!((current.upload_bytes, current.download_bytes), (200, 100));
    storage
        .persist_classified_batch(&batch(3, FlowLifecycle::Ended), &[], &[], expired + 3)
        .unwrap();
    let counters: (i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counters, (300, 150, 9));
}

#[test]
fn one_batch_can_end_and_replace_the_same_tuple() {
    let mut storage = setup();
    storage
        .persist_classified_batch(&batch(1, FlowLifecycle::Active), &[], &[], NOW)
        .unwrap();
    let mut input = batch(2, FlowLifecycle::Ended);
    input.flows[0].upload_bytes = 0;
    input.flows[0].download_bytes = 0;
    input.flows[0].packets = 0;
    let mut replacement = batch(3, FlowLifecycle::Active).flows.remove(0);
    replacement.first_seen_unix_ms = NOW + 3_000;
    input.flows.push(replacement);
    storage
        .persist_classified_batch(&input, &[], &[], NOW + 3_000)
        .unwrap();
    assert_eq!(storage.active_flows.len(), 1);
    let current = storage.active_flows.values().next().unwrap();
    assert_eq!(current.started_at, to_i64(NOW + 3_000));
    assert_eq!(current.upload_bytes, 100);
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (200, 100, 6, 3)
    );
}

#[test]
fn fresh_receipt_and_idle_updates_protect_old_packet_timestamps() {
    let mut storage = setup();
    let input = batch(1, FlowLifecycle::Active);
    let received = NOW + DAY_MS as u64;
    storage
        .persist_classified_batch(&input, &[], &[], received)
        .unwrap();
    storage
        .prune_reclassification(received + ACTIVE_FLOW_TTL_MS as u64 - 1)
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let mut idle = batch(2, FlowLifecycle::Idle);
    idle.flows[0].upload_bytes = 0;
    idle.flows[0].download_bytes = 0;
    idle.flows[0].packets = 0;
    let idle_at = received + ACTIVE_FLOW_TTL_MS as u64 - 1;
    storage
        .persist_classified_batch(&idle, &[], &[], idle_at)
        .unwrap();
    storage
        .prune_reclassification(idle_at + ACTIVE_FLOW_TTL_MS as u64 - 1)
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let current = storage.active_flows.values().next().unwrap();
    assert_eq!(
        current.last_seen_at,
        to_i64(input.flows[0].last_seen_unix_ms)
    );
    storage
        .prune_reclassification(idle_at + ACTIVE_FLOW_TTL_MS as u64)
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 0);
}

#[test]
fn startup_closes_stale_checkpoints_but_keeps_fresh_recovery_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("active.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut old = batch(1, FlowLifecycle::Active);
    // Persist an open checkpoint as left by an older collector release.
    storage
        .persist_classified_batch(&old, &[], &[], NOW + FLOW_CHECKPOINT_MS as u64)
        .unwrap();
    storage
        .connection()
        .execute("DELETE FROM flow_rollup_sessions", [])
        .unwrap();
    old.sequence = 2;
    old.flows[0].client_port += 1;
    let later = NOW + ACTIVE_FLOW_TTL_MS as u64 + FLOW_CHECKPOINT_MS as u64 + 60_000;
    storage
        .persist_classified_batch(&old, &[], &[], later)
        .unwrap();
    // Its traffic is old, but Collector receipt time is recent.
    drop(storage);
    let mut storage = open_at(&path, later + 1).unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    assert_eq!(
        storage
            .active_flows
            .values()
            .next()
            .unwrap()
            .last_received_at,
        to_i64(later)
    );
    let closed: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(closed, 1);
    storage
        .prune_reclassification(later + ACTIVE_FLOW_TTL_MS as u64)
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 0);
    drop(storage);
    assert_eq!(
        open_at(&path, later + ACTIVE_FLOW_TTL_MS as u64 + 1)
            .unwrap()
            .active_flow_count()
            .unwrap(),
        0
    );
}

#[test]
fn failed_batch_leaves_untouched_flows_and_retry_counts_intact() {
    let mut storage = setup();
    let initial = batch(1, FlowLifecycle::Active);
    storage
        .persist_classified_batch(&initial, &[], &[], NOW)
        .unwrap();
    storage
        .connection()
        .execute_batch(
            "CREATE TRIGGER reject_new_session BEFORE INSERT ON flow_rollup_sessions
         WHEN NEW.metadata_json LIKE '%50001%'
         BEGIN SELECT RAISE(ABORT,'reject second flow'); END;",
        )
        .unwrap();
    let mut input = batch(2, FlowLifecycle::Active);
    let mut other = input.flows[0].clone();
    other.client_port = 50_001;
    input.flows.push(other);
    assert!(
        storage
            .persist_classified_batch(&input, &[], &[], NOW + 2_000)
            .is_err()
    );
    assert_eq!(storage.active_flows.len(), 1);
    assert_eq!(
        storage.active_flows.values().next().unwrap().upload_bytes,
        100
    );
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
    storage
        .connection()
        .execute_batch("DROP TRIGGER reject_new_session")
        .unwrap();
    storage
        .persist_classified_batch(&input, &[], &[], NOW + 2_000)
        .unwrap();
    assert_eq!(storage.active_flows.len(), 2);
    let ended = batch(3, FlowLifecycle::Ended);
    storage
        .persist_classified_batch(&ended, &[], &[], NOW + 3_000)
        .unwrap();
    assert_eq!(storage.active_flows.len(), 1);
    assert_eq!(
        storage.active_flows.values().next().unwrap().upload_bytes,
        100
    );
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (400, 200, 12, 4)
    );
}

#[test]
fn late_dpi_updates_both_active_directions_and_preserves_unrelated_flows() {
    let mut storage = setup();
    let mut input = batch(1, FlowLifecycle::Active);
    let mut download = input.flows[0].clone();
    download.direction = Direction::Download as i32;
    let mut unrelated = input.flows[0].clone();
    unrelated.remote_port = 8443;
    input.flows.extend([download, unrelated]);
    storage
        .persist_classified_batch(&input, &[], &[], NOW)
        .unwrap();
    attribution::reclassify_sqlite(
        &mut storage,
        "gateway-1",
        &input.flows[0],
        &service_attribution(),
        to_i64(NOW + 1),
    )
    .unwrap();
    assert_eq!(storage.active_flows.len(), 3);
    for (key, current) in &storage.active_flows {
        assert_eq!(
            current.attribution.application_id,
            if key.remote_port == 443 {
                "video-app"
            } else {
                "unknown"
            }
        );
    }
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (200, 100, 6, 2)
    );
    let mut outside_window = input.flows[0].clone();
    outside_window.first_seen_unix_ms = NOW + 60_000;
    outside_window.last_seen_unix_ms = NOW + 61_000;
    let stronger = FlowAttribution {
        application_id: "other-app".into(),
        application_confidence: 1.0,
        ..service_attribution()
    };
    attribution::reclassify_sqlite(
        &mut storage,
        "gateway-1",
        &outside_window,
        &stronger,
        to_i64(NOW + 2),
    )
    .unwrap();
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='other-app'"
        ),
        (0, 0, 0, 0)
    );
}

#[test]
fn sample_lookup_uses_the_tuple_index() {
    let storage = setup();
    let plan: Vec<String> = storage.connection().prepare(
        "EXPLAIN QUERY PLAN SELECT id FROM flow_sessions
         WHERE gateway_id=?1 AND ip_version=?2 AND protocol=?3 AND client_ip=?4
           AND client_port=?5 AND remote_ip=?6 AND remote_port=?7 AND started_at<=?8 AND last_seen_at>=?9",
    ).unwrap().query_map(params!["gateway-1",4,6,vec![192_u8,0,2,10],50000,vec![198_u8,51,100,1],443,to_i64(NOW),to_i64(NOW)], |row| row.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("flow_sessions_sample_lookup")),
        "{plan:?}"
    );
}
