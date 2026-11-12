use super::*;

fn wait_for_empty_cache_reclaim(cache: &mut ActiveFlowCache) {
    for _ in 0..1000 {
        if cache.flows.capacity() == 0 {
            return;
        }
        cache.release_large_empty_allocation();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(cache.flows.capacity(), 0);
}

#[test]
fn interrupted_recovery_prune_shrinks_and_syncs_batch_limit() {
    assert_eq!(next_recovery_prune_rows(1000, 1000, false), Some(500));
    assert_eq!(next_recovery_prune_rows(1, 1000, false), Some(1));
    assert_eq!(next_recovery_prune_rows(500, 1000, true), None);
    assert_eq!(
        recovery_prune_rows_after_progress(
            50,
            500,
            Duration::from_millis(10),
            Duration::from_millis(100)
        ),
        100
    );
    assert_eq!(
        recovery_prune_rows_after_progress(
            50,
            500,
            Duration::from_millis(60),
            Duration::from_millis(100)
        ),
        50
    );
    assert_eq!(
        recovery_prune_rows_after_progress(
            400,
            500,
            Duration::from_millis(10),
            Duration::from_millis(100)
        ),
        500
    );

    let directory = tempdir().unwrap();
    let path = directory.path().join("recovery-prune-sizing.db");
    let mut owner = Storage::Sqlite(open_at(&path, NOW).unwrap());
    let mut maintenance = owner.maintenance_writer().unwrap().unwrap();
    let Storage::Sqlite(writer) = &mut maintenance else {
        unreachable!();
    };
    writer.recovery_prune_rows = next_recovery_prune_rows(1000, 1000, false);

    owner.sync_maintenance_state_from(&maintenance);
    let Storage::Sqlite(owner) = owner else {
        unreachable!();
    };
    assert_eq!(owner.recovery_prune_rows, Some(500));
}

#[test]
fn active_flows_share_default_attribution_and_detach_on_classification() {
    let mut input = batch(1, FlowLifecycle::Active);
    let mut second_flow = input.flows[0].clone();
    second_flow.remote_ip = vec![203, 0, 113, 2];
    input.flows[0].remote_ip = vec![203, 0, 113, 1];
    let first_key = FlowKey::from_batch("gateway-1", &input.flows[0]);
    let second_key = FlowKey::from_batch("gateway-1", &second_flow);
    let mut first = ActiveFlow::new(
        &first_key,
        &input.flows[0],
        FlowAttribution::default(),
        to_i64(NOW),
    );
    let second = ActiveFlow::new(
        &second_key,
        &second_flow,
        FlowAttribution::default(),
        to_i64(NOW),
    );

    assert!(Arc::ptr_eq(&first.attribution, &second.attribution));
    assert!(!first.merge_attribution(&FlowAttribution::default()));
    assert!(Arc::ptr_eq(&first.attribution, &second.attribution));

    let classified = FlowAttribution {
        application_id: "video-app".to_owned(),
        application_confidence: 0.9,
        confidence: 0.9,
        reason: "classifier".to_owned(),
        evidence_json: r#"[{"type":"signature"}]"#.to_owned(),
        ..FlowAttribution::default()
    };
    assert!(first.merge_attribution(&classified));
    assert!(!Arc::ptr_eq(&first.attribution, &second.attribution));
    assert_eq!(first.attribution.application_id, "video-app");
    assert_eq!(second.attribution.application_id, "unknown");
}

#[test]
fn full_reclaimer_queue_keeps_empty_allocation_for_later_retry() {
    let (sender, receiver) = mpsc::sync_channel(1);
    sender.try_send(HashMap::new()).unwrap();
    let mut cache = ActiveFlowCache::default();
    cache.flows.reserve(100_000);
    let capacity = cache.flows.capacity();
    cache.try_send_empty_allocation(&sender);
    assert_eq!(cache.flows.capacity(), capacity);
    receiver.try_recv().unwrap();
    cache.try_send_empty_allocation(&sender);
    assert_eq!(cache.flows.capacity(), 0);
    assert!(receiver.try_recv().unwrap().capacity() >= 65_536);
    cache.flows.reserve(100_000);
    let capacity = cache.flows.capacity();
    drop(receiver);
    cache.try_send_empty_allocation(&sender);
    assert_eq!(cache.flows.capacity(), capacity);
}

#[test]
fn file_expiry_releases_large_empty_cache_after_checkpoint() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("cache-capacity.db");
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
    storage.active_flows.flows.reserve(100_000);
    assert!(storage.active_flows.flows.capacity() >= 65_536);
    storage
        .prune_reclassification_bounded(NOW + ACTIVE_FLOW_TTL_MS as u64, 1, Duration::from_secs(2))
        .unwrap();
    assert!(storage.active_flows.is_empty());
    wait_for_empty_cache_reclaim(&mut storage.active_flows);
    let bytes: i64 = storage
        .connection()
        .query_row("SELECT upload_bytes FROM flow_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(bytes, 100);
    drop(storage);
    let reopened = open_at(&path, NOW + ACTIVE_FLOW_TTL_MS as u64 + 1).unwrap();
    assert!(reopened.active_flows.is_empty());
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1").0,
        100
    );
}

#[test]
fn restored_noncanonical_session_id_is_preserved_without_canonical_heap_copy() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy-session-id.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[service_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(2, FlowLifecycle::Active),
            &[service_attribution()],
            &[],
            NOW + FLOW_CHECKPOINT_MS as u64,
        )
        .unwrap();
    storage
        .connection()
        .execute("UPDATE flow_sessions SET id='legacy-session-id'", [])
        .unwrap();
    storage
        .connection()
        .execute(
            "UPDATE flow_rollup_sessions SET session_id='legacy-session-id'",
            [],
        )
        .unwrap();
    drop(storage);

    let mut reopened = open_at(&path, NOW + FLOW_CHECKPOINT_MS as u64 + 1).unwrap();
    let (key, flow) = reopened.active_flows.flows.iter().next().unwrap();
    assert_eq!(
        flow.session_id_override.as_deref(),
        Some("legacy-session-id")
    );
    assert_eq!(flow.session_id(key).as_ref(), "legacy-session-id");
    reopened
        .persist_classified_batch(
            &batch(3, FlowLifecycle::Active),
            &[service_attribution()],
            &[],
            NOW + 2 * FLOW_CHECKPOINT_MS as u64,
        )
        .unwrap();
    let sessions: (i64, i64) = reopened
        .connection()
        .query_row(
            "SELECT COUNT(*), MAX(upload_bytes) FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(sessions, (1, 300));
    let recovery_rows: i64 = reopened
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_rollup_sessions WHERE session_id='legacy-session-id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(recovery_rows, 1);
}

#[test]
fn file_recovery_attribution_sequence_reopens_and_reads_legacy_object() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("compact-recovery-attribution.db");
    let expected = service_attribution();
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[expected.clone()],
            &[],
            NOW,
        )
        .unwrap();
    let encoded: String = storage
        .connection()
        .query_row(
            "SELECT attribution_json FROM flow_rollup_sessions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(encoded.starts_with('['));
    assert_eq!(
        serde_json::from_str::<FlowAttribution>(&encoded).unwrap(),
        expected
    );
    drop(storage);

    let reopened = open_at(&path, NOW + 1).unwrap();
    assert_eq!(
        reopened
            .active_flows
            .values()
            .next()
            .unwrap()
            .attribution
            .as_ref(),
        &expected
    );

    // Existing databases contain object-form JSON. Keep that representation
    // readable after new writes begin using the compact sequence form.
    let legacy = serde_json::to_string(&expected).unwrap();
    reopened
        .connection()
        .execute(
            "UPDATE flow_rollup_sessions SET attribution_json=?1",
            [&legacy],
        )
        .unwrap();
    drop(reopened);

    let reopened = open_at(&path, NOW + 2).unwrap();
    assert_eq!(
        reopened
            .active_flows
            .values()
            .next()
            .unwrap()
            .attribution
            .as_ref(),
        &expected
    );
}

#[test]
fn small_empty_active_cache_keeps_allocation_for_reuse() {
    let mut cache = ActiveFlowCache::default();
    let input = batch(1, FlowLifecycle::Active);
    let key = FlowKey::from_batch("gateway-1", &input.flows[0]);
    cache.insert(
        key.clone(),
        ActiveFlow::new(&key, &input.flows[0], transport_attribution(), to_i64(NOW)),
    );
    let capacity = cache.flows.capacity();
    cache.remove(&key);
    cache.release_large_empty_allocation();
    assert_eq!(cache.flows.capacity(), capacity);
}

#[test]
fn active_flow_cache_evicts_oldest_to_a_hard_capacity() {
    let mut cache = ActiveFlowCache::default();
    let input = batch(1, FlowLifecycle::Active);
    let mut keys = Vec::new();
    for index in 0..3_i64 {
        let mut flow = input.flows[0].clone();
        flow.remote_port += u32::try_from(index).unwrap();
        let key = FlowKey::from_batch("gateway-1", &flow);
        let mut state = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW) + index);
        state.last_received_at += index;
        keys.push(key.clone());
        cache.insert(key, state);
    }

    cache.trim_to_capacity(2);

    assert_eq!(cache.len(), 2);
    assert!(cache.get(&keys[0]).is_none());
    assert!(cache.get(&keys[1]).is_some());
    assert!(cache.get(&keys[2]).is_some());
    assert_eq!(cache.expiry.len(), 2);
}

#[test]
fn active_flow_cache_extend_enforces_the_production_capacity() {
    let input = batch(1, FlowLifecycle::Active);
    let mut cache = ActiveFlowCache::default();
    let flows = (0..=ACTIVE_FLOW_CACHE_CAPACITY).map(|index| {
        let mut flow = input.flows[0].clone();
        flow.remote_port += u32::try_from(index).unwrap();
        let key = FlowKey::from_batch("gateway-1", &flow);
        let mut state = ActiveFlow::new(
            &key,
            &flow,
            FlowAttribution::default(),
            to_i64(NOW) + i64::try_from(index).unwrap(),
        );
        state.last_received_at += i64::try_from(index).unwrap();
        (key, state)
    });

    cache.extend(flows);

    assert_eq!(cache.len(), ACTIVE_FLOW_CACHE_CAPACITY);
    assert_eq!(cache.expiry.len(), ACTIVE_FLOW_CACHE_CAPACITY);
    assert!(cache.flows.capacity() <= ACTIVE_FLOW_CACHE_CAPACITY * 2);
}

#[test]
fn active_flow_startup_limit_uses_the_existing_checkpoint_index() {
    let directory = tempdir().unwrap();
    let storage = open_at(&directory.path().join("active-flow-plan.db"), NOW).unwrap();
    let mut statement = storage
        .connection()
        .prepare(
            "EXPLAIN QUERY PLAN SELECT id FROM flow_sessions
             WHERE ended_at IS NULL AND checkpointed_at>?1
             ORDER BY checkpointed_at DESC LIMIT ?2",
        )
        .unwrap();
    let plan = statement
        .query_map(
            params![
                to_i64(NOW),
                i64::try_from(ACTIVE_FLOW_CACHE_CAPACITY).unwrap()
            ],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert!(
        plan.iter()
            .any(|line| line.contains("flow_sessions_open_checkpoint")),
        "{plan:?}"
    );
    assert!(
        !plan.iter().any(|line| line.contains("TEMP B-TREE")),
        "{plan:?}"
    );
}

#[test]
fn active_flow_count_restores_from_file_database_on_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("active-flow-count-restart.db");
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
    storage
        .persist_classified_batch(
            &batch(2, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW + FLOW_CHECKPOINT_MS as u64,
        )
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    drop(storage);

    let reopened = open_at(&path, NOW + FLOW_CHECKPOINT_MS as u64 + 1).unwrap();
    assert_eq!(reopened.active_flow_count().unwrap(), 1);
    let rows: i64 = reopened
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn file_evicted_active_flow_restores_counters_attribution_and_active_count() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("evicted-active-flow.db");
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
    let flow = batch(1, FlowLifecycle::Active).flows[0].clone();
    let key = FlowKey::from_batch("gateway-1", &flow);
    assert_eq!(storage.active_flow_count().unwrap(), 1);

    storage.active_flows.remove(&key);
    storage
        .persist_classified_batch(&batch(2, FlowLifecycle::Active), &[], &[], NOW + 2_000)
        .unwrap();
    assert_eq!(storage.active_flows.len(), 1);
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let restored = storage.active_flows.get(&key).unwrap();
    assert_eq!(
        (
            restored.upload_bytes,
            restored.download_bytes,
            restored.packets
        ),
        (200, 100, 6)
    );
    assert_eq!(restored.attribution.protocol_id, "tls");

    drop(storage);
    let mut reopened = open_at(&path, NOW + 2_001).unwrap();
    assert_eq!(reopened.active_flow_count().unwrap(), 1);
    reopened
        .persist_classified_batch(&batch(3, FlowLifecycle::Ended), &[], &[], NOW + 3_000)
        .unwrap();
    assert_eq!(reopened.active_flow_count().unwrap(), 0);
    let counters: (i64, i64, i64, Option<i64>) = reopened
        .connection()
        .query_row(
            "SELECT upload_bytes,download_bytes,packets,ended_at FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(counters, (300, 150, 9, Some(to_i64(NOW + 3_000))));
}

#[test]
fn owner_maintenance_releases_large_cache_emptied_by_end_event() {
    let directory = tempdir().unwrap();
    let mut storage = open_at(&directory.path().join("end-cache.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
        .unwrap();
    storage.active_flows.flows.reserve(100_000);
    storage
        .persist_batch(&batch(2, FlowLifecycle::Ended), NOW + 1)
        .unwrap();
    assert!(storage.active_flows.is_empty());
    assert!(storage.active_flows.flows.capacity() >= 65_536);
    let mut owned = Storage::sqlite(storage);
    assert!(
        owned
            .prune_owned_flow_cache(NOW + 2, RetentionBudget::default())
            .unwrap()
    );
    let Storage::Sqlite(mut storage) = owned else {
        unreachable!()
    };
    wait_for_empty_cache_reclaim(&mut storage.active_flows);
}

#[test]
fn restart_uses_newer_recovery_receipt_in_expiry_index() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("recovery-expiry.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let checkpoint_at = NOW + FLOW_CHECKPOINT_MS as u64;
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            checkpoint_at,
        )
        .unwrap();
    let recovered_at = checkpoint_at + 30_000;
    storage
        .persist_classified_batch(
            &batch(2, FlowLifecycle::Active),
            &[service_attribution()],
            &[],
            recovered_at,
        )
        .unwrap();
    drop(storage);
    let mut reopened = open_at(&path, recovered_at + 1).unwrap();
    assert_eq!(reopened.active_flows.len(), 1);
    assert_eq!(
        reopened.active_flows.expiry.first().unwrap().0,
        to_i64(recovered_at)
    );
    let flow = reopened.active_flows.values().next().unwrap();
    assert_eq!(
        (flow.upload_bytes, flow.download_bytes, flow.packets),
        (200, 100, 6)
    );
    assert_eq!(flow.attribution.application_id, "video-app");
    reopened
        .prune_reclassification_bounded(
            checkpoint_at + ACTIVE_FLOW_TTL_MS as u64,
            1,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(reopened.active_flows.len(), 1);
    reopened
        .prune_reclassification_bounded(
            recovered_at + ACTIVE_FLOW_TTL_MS as u64,
            1,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(reopened.active_flows.len(), 0);
}

#[test]
fn expiry_index_tracks_updates_ends_and_zero_traffic_flows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("expiry-index.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    for sequence in 1..=50 {
        storage
            .persist_classified_batch(
                &batch(sequence, FlowLifecycle::Active),
                &[service_attribution()],
                &[],
                NOW + sequence,
            )
            .unwrap();
        assert_eq!(
            storage.active_flows.expiry.len(),
            storage.active_flows.len()
        );
    }
    let mut idle = batch(51, FlowLifecycle::Active);
    idle.flows[0].client_port += 1;
    idle.flows[0].upload_bytes = 0;
    idle.flows[0].download_bytes = 0;
    idle.flows[0].packets = 0;
    storage
        .persist_classified_batch(&idle, &[], &[], NOW + 51)
        .unwrap();
    assert_eq!(storage.active_flows.len(), 2);
    assert_eq!(storage.active_flows.expiry.len(), 2);
    let mut unified = Storage::sqlite(storage);
    let expired = NOW + 50 + ACTIVE_FLOW_TTL_MS as u64;
    let budget = RetentionBudget {
        max_rows_per_batch: 1,
        transaction_target: Duration::from_secs(2),
        ..RetentionBudget::default()
    };
    assert!(unified.prune_owned_flow_cache(expired, budget).unwrap());
    assert_eq!(unified.active_flow_count().unwrap(), 1);
    assert!(unified.prune_owned_flow_cache(expired + 1, budget).unwrap());
    assert_eq!(unified.active_flow_count().unwrap(), 0);
    let (flows, bytes): (i64, i64) = unified
        .connection()
        .query_row(
            "SELECT COUNT(*), SUM(upload_bytes) FROM flow_sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((flows, bytes), (1, 5000));
    drop(unified);
    let reopened = open_at(&path, expired + 2).unwrap();
    assert_eq!(reopened.active_flows.len(), 0);
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1").0,
        5000
    );
}

#[test]
fn file_maintenance_checkpoints_the_owning_cache() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("owned-cache.db");
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
    let mut storage = Storage::Sqlite(sqlite);
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    let mut writer = storage.maintenance_writer().unwrap().unwrap();
    writer
        .prune_reclassification_for_maintenance_bounded(expired, RetentionBudget::default())
        .unwrap();
    assert_eq!(writer.active_flow_count().unwrap(), 0);
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    for _ in 0..10 {
        if storage
            .prune_owned_flow_cache(expired, RetentionBudget::default())
            .unwrap()
        {
            break;
        }
    }
    assert_eq!(storage.active_flow_count().unwrap(), 0);
    drop(writer);
    drop(storage);
    let reopened = open_at(&path, expired + 1).unwrap();
    let values: (i64, i64, i64, Option<i64>) = reopened
        .connection()
        .query_row(
            "SELECT upload_bytes, download_bytes, packets, ended_at FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        values,
        (
            100,
            50,
            3,
            Some(to_i64(
                batch(1, FlowLifecycle::Active).flows[0].last_seen_unix_ms
            ))
        )
    );
}

#[test]
fn total_batch_matches_original_across_barriers_and_capacity() {
    let mut baseline = setup();
    let mut optimized = setup();
    let mut input = batch(1, FlowLifecycle::Active);
    let flow = input.flows[0].clone();
    input.flows = (0..1300)
        .map(|i: u32| {
            let mut f = flow.clone();
            f.remote_ip = i.to_be_bytes().to_vec();
            f
        })
        .collect();
    input.flows.push(input.flows[20].clone());
    let mut attrs = vec![FlowAttribution::default(); input.flows.len()];
    *attrs.last_mut().unwrap() = service_attribution();
    baseline
        .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, false)
        .unwrap();
    optimized
        .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, true)
        .unwrap();
    let (original, written) = LAST_TOTAL_ROLLUP_COUNTS.get();
    assert_eq!(original, 1301);
    assert!(written < original);
    for table in [
        "traffic_total_minute",
        "traffic_total_hour_pending",
        "traffic_device_minute",
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_destination_minute",
        "traffic_scope_minute",
        "traffic_scope_total_minute",
    ] {
        let dump = |s: &SqliteStorage| -> Vec<String> {
            let mut stmt = s
                .connection()
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let mut rows = stmt
                .query_map([], |r| {
                    Ok(format!(
                        "{:?}",
                        (0..r.as_ref().column_count())
                            .map(|i| r.get::<_, Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()?
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            rows
        };
        assert_eq!(dump(&baseline), dump(&optimized), "{table}");
    }
}

fn dump_rollups(storage: &SqliteStorage, table: &str) -> Vec<String> {
    let mut statement = storage
        .connection()
        .prepare(&format!("SELECT * FROM {table}"))
        .unwrap();
    let mut rows = statement
        .query_map([], |row| {
            let values = (0..row.as_ref().column_count())
                .map(|i| row.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(format!("{values:?}"))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows.sort();
    rows
}

#[test]
#[ignore = "child process for interrupted ingestion test"]
fn repeated_rollup_interrupted_child() {
    let path = std::env::var_os("NETQMON_CRASH_TEST_DB").expect("child database path");
    let marker = std::env::var_os("NETQMON_CRASH_TEST_MARKER").expect("child marker path");
    let mut storage = open_at(std::path::Path::new(&path), NOW + 1).unwrap();
    let mut callbacks = 0_u64;
    storage
        .connection()
        .progress_handler(
            100,
            Some(move || {
                callbacks += 1;
                if callbacks == 2_000 {
                    std::fs::write(&marker, b"transaction active").unwrap();
                    loop {
                        std::thread::park();
                    }
                }
                false
            }),
        )
        .unwrap();
    let mut input = batch(2, FlowLifecycle::Active);
    input.flows = vec![input.flows[0].clone(); 512];
    storage.persist_batch(&input, NOW + 2).unwrap();
    panic!("child did not reach the interruption point");
}

#[test]
fn file_repeated_rollup_batch_recovers_from_process_kill() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("crash.db");
    let reference_path = directory.path().join("reference.db");
    for db_path in [&path, &reference_path] {
        let mut storage = open_at(db_path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        storage
            .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
            .unwrap();
    }
    let marker = directory.path().join("started");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::active_cache::repeated_rollup_interrupted_child",
            "--ignored",
        ])
        .env("NETQMON_CRASH_TEST_DB", &path)
        .env("NETQMON_CRASH_TEST_MARKER", &marker)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !marker.exists() && std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let reached = marker.exists();
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let _ = child.wait().unwrap();
    assert!(
        reached,
        "child did not reach an active ingestion transaction"
    );
    let mut recovered = open_at(&path, NOW + 3).unwrap();
    let mut reference = open_at(&reference_path, NOW + 3).unwrap();
    for table in [
        "traffic_device_minute",
        "traffic_device_hour_pending",
        "traffic_destination_minute",
        "traffic_destination_hour_pending",
        "flow_rollup_sessions",
        "flow_rollup_contributions",
        "ingest_batches",
    ] {
        assert_eq!(
            dump_rollups(&recovered, table),
            dump_rollups(&reference, table),
            "after kill: {table}"
        );
    }
    let mut retry = batch(2, FlowLifecycle::Active);
    retry.flows = vec![retry.flows[0].clone(); 512];
    recovered.persist_batch(&retry, NOW + 2).unwrap();
    reference.persist_batch(&retry, NOW + 2).unwrap();
    for table in [
        "traffic_device_minute",
        "traffic_device_hour_pending",
        "traffic_destination_minute",
        "traffic_destination_hour_pending",
        "flow_rollup_sessions",
        "flow_rollup_contributions",
        "ingest_batches",
    ] {
        assert_eq!(
            dump_rollups(&recovered, table),
            dump_rollups(&reference, table),
            "after retry: {table}"
        );
    }
}

#[test]
fn file_repeated_rollup_batches_remain_atomic_during_concurrent_reads_and_writes() {
    use std::sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    let directory = tempdir().unwrap();
    let path = directory.path().join("concurrent-rollups.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let shared = Arc::new(Mutex::new(storage));
    let barrier = Arc::new(Barrier::new(3));
    let done = Arc::new(AtomicUsize::new(0));
    let workers = (0..2_u64)
        .map(|worker| {
            let storage = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                barrier.wait();
                for index in 0..20_u64 {
                    let sequence = index * 2 + worker + 1;
                    let mut input = batch(sequence, FlowLifecycle::Active);
                    input.flows = vec![input.flows[0].clone(); 32];
                    storage
                        .lock()
                        .unwrap()
                        .persist_batch(&input, NOW + sequence)
                        .unwrap();
                }
                done.fetch_add(1, Ordering::Release);
            })
        })
        .collect::<Vec<_>>();
    let reader = Connection::open(&path).unwrap();
    reader.busy_timeout(Duration::from_secs(10)).unwrap();
    barrier.wait();
    let mut observations = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while done.load(Ordering::Acquire) < 2 || observations < 10 {
        assert!(
            std::time::Instant::now() < deadline,
            "concurrent ingestion did not complete"
        );
        let transaction = reader.unchecked_transaction().unwrap();
        let device: (i64, i64) = transaction.query_row("SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(flow_count),0) FROM traffic_device_minute", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        let destination: (i64, i64) = transaction.query_row("SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(flow_count),0) FROM traffic_destination_minute", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(device, destination);
        transaction.commit().unwrap();
        observations += 1;
        std::thread::yield_now();
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let total: (i64, i64) = reader
        .query_row(
            "SELECT SUM(upload_bytes),SUM(flow_count) FROM traffic_device_minute",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(total, (128_000, 1_280));
}

#[test]
fn file_repeated_rollup_batch_matches_original_across_restart_and_rollups() {
    let dir = tempdir().unwrap();
    let baseline_path = dir.path().join("original.db");
    let optimized_path = dir.path().join("batched.db");
    let mut baseline = open_at(&baseline_path, NOW).unwrap();
    let mut optimized = open_at(&optimized_path, NOW).unwrap();
    for storage in [&mut baseline, &mut optimized] {
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
    }
    let mut input = batch(1, FlowLifecycle::Active);
    let mut second_device = input.device_observations[0].clone();
    second_device.mac = vec![2, 0, 0, 0, 0, 2];
    second_device.ip = vec![192, 0, 2, 11];
    input.device_observations.push(second_device);
    let first = input.flows[0].clone();
    input.flows = (0..1500)
        .map(|index| {
            let mut flow = first.clone();
            if (1100..1300).contains(&index) {
                flow.remote_ip = vec![203, 0, 113, 7];
                flow.client_ip = vec![192, 0, 2, 11];
                flow.client_port = 50_001;
                flow.client_mac = vec![2, 0, 0, 0, 0, 2];
            }
            flow
        })
        .collect();
    let mut attrs = vec![FlowAttribution::default(); input.flows.len()];
    attrs[1300] = service_attribution();
    for (storage, enabled) in [(&mut baseline, false), (&mut optimized, true)] {
        storage
            .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, enabled)
            .unwrap();
        assert_eq!(
            storage
                .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, enabled)
                .unwrap(),
            PersistDisposition::Duplicate
        );
    }
    let tables = [
        "traffic_device_minute",
        "traffic_device_hour_pending",
        "traffic_destination_minute",
        "traffic_destination_hour_pending",
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_scope_minute",
        "flow_sessions",
        "flow_rollup_sessions",
        "flow_rollup_contributions",
    ];
    for table in tables {
        assert_eq!(
            dump_rollups(&baseline, table),
            dump_rollups(&optimized, table),
            "{table}"
        );
    }
    drop(baseline);
    drop(optimized);
    let mut baseline = open_at(&baseline_path, NOW + 1).unwrap();
    let mut optimized = open_at(&optimized_path, NOW + 1).unwrap();
    for storage in [&mut baseline, &mut optimized] {
        attribution::reclassify_sqlite(
            storage,
            "gateway-1",
            &input.flows[1100],
            &service_attribution(),
            to_i64(NOW + 2),
        )
        .unwrap();
        assert_eq!(
            metrics(
                storage.connection(),
                "traffic_application_minute",
                "application_id='video-app'"
            )
            .0,
            150_000
        );
    }
    for table in [
        "traffic_device_minute",
        "traffic_destination_minute",
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_scope_minute",
        "flow_rollup_sessions",
        "flow_rollup_contributions",
    ] {
        assert_eq!(
            dump_rollups(&baseline, table),
            dump_rollups(&optimized, table),
            "after reclassification: {table}"
        );
    }
    let later = NOW + 2 * DAY_MS as u64;
    baseline.roll_up_hour_and_day(later).unwrap();
    optimized.roll_up_hour_and_day(later).unwrap();
    for table in [
        "traffic_device_minute",
        "traffic_device_hour",
        "traffic_device_day",
        "traffic_device_hour_pending",
        "traffic_device_day_pending",
        "traffic_destination_minute",
        "traffic_destination_hour",
        "traffic_destination_day",
        "traffic_destination_hour_pending",
        "traffic_destination_day_pending",
    ] {
        assert_eq!(
            dump_rollups(&baseline, table),
            dump_rollups(&optimized, table),
            "{table}"
        );
    }
    let retention_time = NOW + 31 * DAY_MS as u64;
    for storage in [&mut baseline, &mut optimized] {
        assert!(
            storage
                .run_retention_bounded(
                    retention_time,
                    RetentionPolicy::default(),
                    RetentionBudget::default()
                )
                .unwrap()
        );
    }
    for table in [
        "traffic_device_minute",
        "traffic_device_hour",
        "traffic_device_day",
        "traffic_device_hour_pending",
        "traffic_device_day_pending",
        "traffic_destination_minute",
        "traffic_destination_hour",
        "traffic_destination_day",
        "traffic_destination_hour_pending",
        "traffic_destination_day_pending",
    ] {
        assert_eq!(
            dump_rollups(&baseline, table),
            dump_rollups(&optimized, table),
            "after retention: {table}"
        );
    }
}

#[test]
fn file_repeated_rollup_batch_preserves_numeric_fallback_and_rollback() {
    for (metric, initial) in ["upload_bytes", "download_bytes", "packets", "flow_count"]
        .into_iter()
        .flat_map(|metric| {
            [
                Value::Integer(0),
                Value::Integer(-10),
                Value::Integer(i64::MAX - 50),
                Value::Real(9.223_372_036_854_776e18),
            ]
            .into_iter()
            .map(move |value| (metric, value))
        })
    {
        let dir = tempdir().unwrap();
        let mut original = open_at(&dir.path().join("original.db"), NOW).unwrap();
        let mut batched = open_at(&dir.path().join("batched.db"), NOW).unwrap();
        for storage in [&mut original, &mut batched] {
            storage
                .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
                .unwrap();
            storage
                .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
                .unwrap();
            for table in [
                "traffic_device_minute",
                "traffic_destination_minute",
                "traffic_device_hour_pending",
                "traffic_destination_hour_pending",
            ] {
                storage
                    .connection()
                    .execute(
                        &format!("UPDATE {table} SET {metric}=?1"),
                        [initial.clone()],
                    )
                    .unwrap();
            }
        }
        let mut input = batch(2, FlowLifecycle::Active);
        input.flows.extend([
            input.flows[0].clone(),
            input.flows[0].clone(),
            input.flows[0].clone(),
        ]);
        for (storage, enabled) in [(&mut original, false), (&mut batched, true)] {
            storage
                .persist_classified_batch_with_total_batching(&input, &[], &[], NOW + 1, enabled)
                .unwrap();
        }
        for table in [
            "traffic_device_minute",
            "traffic_device_hour_pending",
            "traffic_destination_minute",
            "traffic_destination_hour_pending",
        ] {
            assert_eq!(
                dump_rollups(&original, table),
                dump_rollups(&batched, table),
                "{table} metric={metric} initial={initial:?}"
            );
        }
        if metric != "upload_bytes" {
            continue;
        }
        let before = dump_rollups(&batched, "traffic_destination_minute");
        batched.connection().execute_batch("CREATE TRIGGER reject_batch BEFORE UPDATE ON traffic_destination_minute WHEN NEW.flow_count >= 9 BEGIN SELECT RAISE(ABORT,'injected failure'); END").unwrap();
        let mut failing = batch(3, FlowLifecycle::Active);
        failing.flows.extend([
            failing.flows[0].clone(),
            failing.flows[0].clone(),
            failing.flows[0].clone(),
            failing.flows[0].clone(),
            failing.flows[0].clone(),
        ]);
        assert!(batched.persist_batch(&failing, NOW + 2).is_err());
        assert_eq!(before, dump_rollups(&batched, "traffic_destination_minute"));
        let exists: bool = batched
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ingest_batches WHERE sequence=3)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!exists);
    }
}

#[test]
fn file_repeated_rollup_batch_preserves_zero_byte_flow_counts() {
    let directory = tempdir().unwrap();
    let mut storage = open_at(&directory.path().join("zero-flows.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let mut input = batch(1, FlowLifecycle::Active);
    input.flows[0].upload_bytes = 0;
    input.flows[0].download_bytes = 0;
    input.flows[0].packets = 0;
    input.flows = vec![input.flows[0].clone(); 16];
    storage.persist_batch(&input, NOW).unwrap();
    for table in [
        "traffic_device_minute",
        "traffic_device_hour_pending",
        "traffic_destination_minute",
        "traffic_destination_hour_pending",
    ] {
        assert_eq!(
            metrics(storage.connection(), table, "1=1"),
            (0, 0, 0, 16),
            "{table}"
        );
    }
}

#[test]
fn file_repeated_rollup_batch_flushes_before_negative_delta() {
    let directory = tempdir().unwrap();
    let mut original = open_at(&directory.path().join("original-negative.db"), NOW).unwrap();
    let mut batched = open_at(&directory.path().join("batched-negative.db"), NOW).unwrap();
    for storage in [&mut original, &mut batched] {
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
    }
    for (storage, enabled) in [(&mut original, false), (&mut batched, true)] {
        let tx = storage.connection.transaction().unwrap();
        let mut accumulator = RepeatedRollupBatch::new(false, enabled);
        let key = [
            to_i64(NOW).into(),
            "gateway-1".to_owned().into(),
            vec![1, 2, 3, 4].into(),
        ];
        for delta in [10, 10, 10, 10, 10, -7, 3] {
            accumulator.add(&tx, &key, delta, 0, 0).unwrap();
        }
        accumulator.flush(&tx).unwrap();
        tx.commit().unwrap();
    }
    for table in [
        "traffic_destination_minute",
        "traffic_destination_hour_pending",
    ] {
        assert_eq!(
            dump_rollups(&original, table),
            dump_rollups(&batched, table),
            "{table}"
        );
    }
}

#[test]
fn batched_total_matches_original_for_numeric_boundaries_and_rollback() {
    for initial in [
        Value::Integer(0),
        Value::Integer(i64::MAX - 50),
        Value::Real(9.223372036854776e18),
        Value::Integer(-10),
    ] {
        let mut baseline = setup();
        let mut optimized = setup();
        for s in [&mut baseline, &mut optimized] {
            let t = to_i64(NOW + 1_000) / MINUTE_MS * MINUTE_MS;
            s.connection().execute("INSERT INTO traffic_total_minute(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES(?1,'gateway-1',0,0,0,0)", [t]).unwrap();
            s.connection()
                .execute(
                    "UPDATE traffic_total_minute SET upload_bytes=?1 WHERE timestamp=?2",
                    params![initial, t],
                )
                .unwrap();
            s.connection()
                .execute(
                    "UPDATE traffic_total_hour_pending SET upload_bytes=?1",
                    [initial.clone()],
                )
                .unwrap();
        }
        let mut input = batch(1, FlowLifecycle::Active);
        input.flows.push(input.flows[0].clone());
        for (s, enabled) in [(&mut baseline, false), (&mut optimized, true)] {
            s.persist_classified_batch_with_total_batching(&input, &[], &[], NOW, enabled)
                .unwrap();
            assert_eq!(
                s.persist_classified_batch_with_total_batching(&input, &[], &[], NOW, enabled)
                    .unwrap(),
                PersistDisposition::Duplicate
            );
        }
        assert_eq!(
            LAST_TOTAL_ROLLUP_COUNTS.get(),
            (2, if initial == Value::Integer(0) { 1 } else { 2 })
        );
        for table in [
            "traffic_total_minute",
            "traffic_total_hour_pending",
            "traffic_scope_minute",
            "traffic_scope_total_minute",
        ] {
            let rows = |s: &SqliteStorage| -> Vec<String> {
                let mut stmt = s
                    .connection()
                    .prepare(&format!("SELECT * FROM {table}"))
                    .unwrap();
                let mut rows = stmt
                    .query_map([], |r| {
                        Ok(format!(
                            "{:?}",
                            (0..r.as_ref().column_count())
                                .map(|i| r.get::<_, Value>(i))
                                .collect::<rusqlite::Result<Vec<_>>>()?
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                rows.sort();
                rows
            };
            assert_eq!(
                rows(&baseline),
                rows(&optimized),
                "{table} initial={initial:?}"
            );
        }
        optimized.connection().execute_batch("CREATE TRIGGER fail_batch BEFORE INSERT ON traffic_domain_minute BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        let before: Value = optimized
            .connection()
            .query_row("SELECT upload_bytes FROM traffic_total_minute", [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut failing = batch(2, FlowLifecycle::Active);
        failing.flows[0].remote_ip = vec![203, 0, 113, 2];
        assert!(
            optimized
                .persist_classified_batch(&failing, &[], &[], NOW)
                .is_err()
        );
        let after: Value = optimized
            .connection()
            .query_row("SELECT upload_bytes FROM traffic_total_minute", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            optimized
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM ingest_batches WHERE sequence=2",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn same_batch_attribution_promotion_matches_sequential_writes() {
    let mut combined = setup();
    let mut sequential = setup();
    let mut first = batch(1, FlowLifecycle::Active);
    let mut second = first.clone();
    second.sequence = 2;
    first.flows[0].upload_bytes = 31;
    second.flows[0].upload_bytes = 73;
    let mut together = first.clone();
    together.flows.push(second.flows[0].clone());

    combined
        .persist_classified_batch(
            &together,
            &[FlowAttribution::default(), service_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    sequential
        .persist_classified_batch(&first, &[FlowAttribution::default()], &[], NOW)
        .unwrap();
    sequential
        .persist_classified_batch(&second, &[service_attribution()], &[], NOW)
        .unwrap();

    for table in [
        "traffic_total_minute",
        "traffic_device_minute",
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_destination_minute",
        "traffic_scope_minute",
        "traffic_scope_total_minute",
    ] {
        assert_eq!(
            metrics(combined.connection(), table, "1=1"),
            metrics(sequential.connection(), table, "1=1"),
            "{table}"
        );
    }
    for table in [
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_scope_minute",
    ] {
        let rows = |s: &SqliteStorage| -> Vec<String> {
            let mut statement = s
                .connection()
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let mut result = statement
                .query_map([], |row| {
                    let values = (0..row.as_ref().column_count())
                        .map(|i| row.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            result.sort();
            result
        };
        assert_eq!(rows(&combined), rows(&sequential), "{table}");
    }
    assert_eq!(
        combined
            .persist_classified_batch(&together, &[], &[], NOW)
            .unwrap(),
        PersistDisposition::Duplicate
    );
}

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
fn concurrent_active_update_survives_bounded_expiry_and_restart() {
    use std::sync::{Arc, Barrier, Mutex, mpsc};

    const FLOW_COUNT: u32 = 2_500;
    const UPDATE_COUNT: u64 = 20;
    let directory = tempdir().unwrap();
    let path = directory.path().join("active-expiry-concurrent.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();

    let mut initial = batch(1, FlowLifecycle::Active);
    let prototype = initial.flows[0].clone();
    initial.flows = (0..FLOW_COUNT)
        .map(|index| {
            let mut flow = prototype.clone();
            flow.remote_ip = (index + 1).to_be_bytes().to_vec();
            flow
        })
        .collect();
    let target_flow = initial.flows[0].clone();
    storage
        .persist_classified_batch(
            &initial,
            &vec![transport_attribution(); FLOW_COUNT as usize],
            &[],
            NOW,
        )
        .unwrap();
    assert_eq!(storage.active_flow_count().unwrap(), i64::from(FLOW_COUNT));

    let shared = Arc::new(Mutex::new(Storage::sqlite(storage)));
    let start = Arc::new(Barrier::new(2));
    let (first_slice_tx, first_slice_rx) = mpsc::channel();
    let worker_storage = Arc::clone(&shared);
    let worker_start = Arc::clone(&start);
    let expired_at = NOW + ACTIVE_FLOW_TTL_MS as u64;
    let maintenance = std::thread::spawn(move || {
        worker_start.wait();
        let mut slices = 0;
        loop {
            let complete = worker_storage
                .lock()
                .unwrap()
                .prune_owned_flow_cache(expired_at, RetentionBudget::default())
                .unwrap();
            slices += 1;
            if slices == 1 {
                first_slice_tx.send(()).unwrap();
            }
            if complete {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        slices
    });

    start.wait();
    first_slice_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("maintenance did not finish its first bounded slice");
    for sequence in 2..(UPDATE_COUNT + 2) {
        let mut update = batch(sequence, FlowLifecycle::Active);
        let updated_at = expired_at + sequence * FLOW_CHECKPOINT_MS as u64;
        let mut flow = target_flow.clone();
        flow.last_seen_unix_ms = updated_at;
        update.flows = vec![flow];
        shared
            .lock()
            .unwrap()
            .persist_classified_batch(&update, &[transport_attribution()], &[], updated_at)
            .unwrap();
    }
    let slices = maintenance.join().unwrap();
    assert!(slices > 1, "expected multiple bounded expiry transactions");

    let storage = shared.lock().unwrap();
    let connection = storage.sqlite_connection().unwrap();
    let persisted: (i64, i64, i64, i64, i64) = storage
        .sqlite_connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*), SUM(upload_bytes), SUM(download_bytes), SUM(packets),
                    SUM(CASE WHEN ended_at IS NULL THEN 1 ELSE 0 END)
             FROM flow_sessions",
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
    assert_eq!(
        persisted,
        (
            i64::from(FLOW_COUNT),
            i64::from(FLOW_COUNT) * 100 + UPDATE_COUNT as i64 * 100,
            i64::from(FLOW_COUNT) * 50 + UPDATE_COUNT as i64 * 50,
            i64::from(FLOW_COUNT) * 3 + UPDATE_COUNT as i64 * 3,
            1,
        )
    );
    assert_eq!(storage.active_flow_count().unwrap(), 1);
    let target_state: (String, i64, i64, i64) = connection
        .query_row(
            "SELECT protocol_id, upload_bytes, download_bytes, packets
             FROM flow_sessions WHERE remote_ip=?1 AND client_port=?2 AND ended_at IS NULL",
            rusqlite::params![target_flow.remote_ip, target_flow.client_port],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        target_state,
        (
            "tls".to_owned(),
            (UPDATE_COUNT as i64 + 1) * 100,
            (UPDATE_COUNT as i64 + 1) * 50,
            (UPDATE_COUNT as i64 + 1) * 3,
        )
    );
    assert_eq!(
        metrics(connection, "traffic_total_minute", "1=1").0,
        i64::from(FLOW_COUNT) * 100 + UPDATE_COUNT as i64 * 100
    );
    drop(storage);
    drop(shared);

    let reopened = open_at(&path, expired_at + UPDATE_COUNT * FLOW_CHECKPOINT_MS as u64).unwrap();
    assert_eq!(reopened.active_flow_count().unwrap(), 1);
    assert_eq!(reopened.active_flows.len(), 1);
    assert_eq!(
        reopened
            .active_flows
            .values()
            .next()
            .unwrap()
            .attribution
            .protocol_id,
        "tls"
    );
    assert_eq!(
        metrics(reopened.connection(), "traffic_total_minute", "1=1").0,
        i64::from(FLOW_COUNT) * 100 + UPDATE_COUNT as i64 * 100
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
    assert_eq!(storage.active_flows.expiry.len(), 1);
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
        "EXPLAIN QUERY PLAN SELECT id FROM flow_sessions INDEXED BY flow_sessions_sample_lookup
         WHERE gateway_id=?1 AND ip_version=?2 AND protocol=?3 AND client_ip=?4
           AND client_port=?5 AND remote_ip=?6 AND remote_port=?7 AND started_at<=?8 AND last_seen_at>=?9",
    ).unwrap().query_map(params!["gateway-1",4,6,vec![192_u8,0,2,10],50000,vec![198_u8,51,100,1],443,to_i64(NOW),to_i64(NOW)], |row| row.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("flow_sessions_sample_lookup")),
        "{plan:?}"
    );
    let columns: Vec<String> = storage
        .connection()
        .prepare("PRAGMA index_info(flow_sessions_sample_lookup)")
        .unwrap()
        .query_map([], |row| row.get(2))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        columns,
        [
            "gateway_id",
            "ip_version",
            "protocol",
            "client_ip",
            "client_port",
            "remote_ip",
            "remote_port"
        ]
    );
}

#[test]
fn sample_lookup_index_migration_preserves_rows_and_rolls_back() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("sample-lookup-migration.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Ended),
            &[transport_attribution()],
            &[],
            NOW + 1_000,
        )
        .unwrap();
    let before: (i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(before.0, 1);

    // Recreate the version-16 layout, then let the real migration runner
    // upgrade it. This exercises the transactional drop/rebuild on an existing
    // file rather than only checking a fresh database.
    storage
        .connection()
        .execute_batch(
            "BEGIN IMMEDIATE;
             DROP INDEX flow_sessions_sample_lookup;
             CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
                gateway_id,ip_version,protocol,client_ip,client_port,
                remote_ip,remote_port,last_seen_at
             );
             DELETE FROM schema_migrations WHERE version=17;
             COMMIT;",
        )
        .unwrap();
    drop(storage);
    let upgraded = open_at(&path, NOW + 1_000).unwrap();
    let new_columns: Vec<String> = upgraded
        .connection()
        .prepare("PRAGMA index_info(flow_sessions_sample_lookup)")
        .unwrap()
        .query_map([], |row| row.get(2))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(new_columns.len(), 7);
    assert_eq!(new_columns.last().map(String::as_str), Some("remote_port"));

    // Rollback procedure for the migration: restore the old index and remove
    // the migration marker before starting a binary that only knows v16.
    upgraded
        .connection()
        .execute_batch(
            "BEGIN IMMEDIATE;
             DROP INDEX flow_sessions_sample_lookup;
             CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
                gateway_id,ip_version,protocol,client_ip,client_port,
                remote_ip,remote_port,last_seen_at
             );
             DELETE FROM schema_migrations WHERE version=17;
             COMMIT;",
        )
        .unwrap();
    let old_columns: Vec<String> = upgraded
        .connection()
        .prepare("PRAGMA index_info(flow_sessions_sample_lookup)")
        .unwrap()
        .query_map([], |row| row.get(2))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(old_columns.len(), 8);
    assert_eq!(old_columns.last().map(String::as_str), Some("last_seen_at"));
    let after: (i64, i64, i64) = upgraded
        .connection()
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after, before);
    let integrity: String = upgraded
        .connection()
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}
