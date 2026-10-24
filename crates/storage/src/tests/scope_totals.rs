use super::*;

fn assert_matches_source(connection: &Connection) {
    let rows = |sql: &str| {
        connection
            .prepare(sql)
            .unwrap()
            .query_map([], |row| {
                (0..9)
                    .map(|column| row.get::<_, Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let expected = rows(
        "SELECT timestamp,gateway_id,scope,direction,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count),COUNT(*) FROM traffic_scope_minute GROUP BY scope,timestamp,direction,gateway_id ORDER BY scope,timestamp,direction,gateway_id",
    );
    let actual = rows(
        "SELECT timestamp,gateway_id,scope,direction,upload_bytes,download_bytes,packets,flow_count,source_rows FROM traffic_scope_total_minute ORDER BY scope,timestamp,direction,gateway_id",
    );
    assert_eq!(actual, expected);
}

#[test]
fn scope_totals_follow_ingestion_late_classification_and_retention() {
    let mut storage = Storage::sqlite(setup());
    for sequence in 1..=2 {
        storage
            .persist_classified_batch(
                &batch(sequence, FlowLifecycle::Active),
                &[transport_attribution()],
                &[],
                NOW + sequence * 1000,
            )
            .unwrap();
        assert_matches_source(storage.connection());
    }
    for _ in 0..2 {
        storage
            .reclassify_flow_at(
                "gateway-1",
                &batch(2, FlowLifecycle::Active).flows[0],
                &service_attribution(),
                NOW + 3000,
            )
            .unwrap();
        assert_matches_source(storage.connection());
    }
    let input = batch(3, FlowLifecycle::Ended);
    storage
        .persist_classified_batch(&input, &[service_attribution()], &[], NOW + 4000)
        .unwrap();
    assert_matches_source(storage.connection());
    storage
        .run_retention(NOW + 400 * DAY_MS as u64, RetentionPolicy::default())
        .unwrap();
    assert_matches_source(storage.connection());
    assert_eq!(
        storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM traffic_scope_total_minute",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn scope_totals_preserve_zero_observations_moves_and_transaction_rollback() {
    let mut storage = setup();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Ended), NOW)
        .unwrap();
    let c = storage.connection();
    c.execute_batch(
        "INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count)
         SELECT timestamp+30000,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,0,0,0,0 FROM traffic_scope_minute LIMIT 1;"
    ).unwrap();
    assert_matches_source(c);
    assert_eq!(c.query_row("SELECT COUNT(*) FROM traffic_scope_total_minute WHERE upload_bytes=0 AND download_bytes=0 AND source_rows=1", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    c.execute(
        "UPDATE traffic_scope_minute SET application_id='classified', domain='classified.example'",
        [],
    )
    .unwrap();
    assert_matches_source(c);
    c.execute_batch("BEGIN; UPDATE traffic_scope_minute SET upload_bytes=upload_bytes+100;")
        .unwrap();
    assert_matches_source(c);
    c.execute_batch("ROLLBACK").unwrap();
    assert_matches_source(c);
    c.execute("UPDATE traffic_scope_minute SET timestamp=timestamp+600000, scope=2, direction=2, gateway_id='gateway-2'", []).unwrap();
    assert_matches_source(c);
    c.execute(
        "DELETE FROM traffic_scope_minute WHERE upload_bytes > 0",
        [],
    )
    .unwrap();
    assert_matches_source(c);
    c.execute("DELETE FROM traffic_scope_minute", []).unwrap();
    assert_matches_source(c);
}

#[test]
fn scope_totals_upgrade_backfills_existing_rows_once() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v10.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .connection()
        .execute_batch(
            "DROP TRIGGER traffic_scope_total_insert;
         DROP TRIGGER traffic_scope_total_counters;
         DROP TRIGGER traffic_scope_total_move;
         DROP TRIGGER traffic_scope_total_delete;
         DROP TABLE traffic_scope_total_minute;
         DELETE FROM schema_migrations WHERE version=11;",
        )
        .unwrap();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Ended), NOW)
        .unwrap();
    drop(storage);
    let upgraded = open_at(&path, NOW + 1000).unwrap();
    assert_matches_source(upgraded.connection());
    assert_eq!(
        metrics(upgraded.connection(), "traffic_scope_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
    drop(upgraded);
    let reopened = open_at(&path, NOW + 2000).unwrap();
    assert_matches_source(reopened.connection());
    assert_eq!(
        metrics(reopened.connection(), "traffic_scope_total_minute", "1=1"),
        (100, 50, 3, 1)
    );
}

#[test]
fn scope_totals_retention_preserves_the_cutoff_and_forever_policy() {
    let mut storage = setup();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Ended), NOW)
        .unwrap();
    let original_timestamp: i64 = storage
        .connection()
        .query_row(
            "SELECT MIN(timestamp) FROM traffic_scope_minute",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let later = u64::try_from(original_timestamp).unwrap() + 30 * DAY_MS as u64;
    storage
        .run_retention(
            later,
            RetentionPolicy {
                minute_days: 0,
                ..RetentionPolicy::default()
            },
        )
        .unwrap();
    assert_matches_source(storage.connection());
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    storage
        .run_retention(
            later,
            RetentionPolicy {
                minute_days: 30,
                ..RetentionPolicy::default()
            },
        )
        .unwrap();
    assert_matches_source(storage.connection());
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    storage
        .run_retention(
            later + 1,
            RetentionPolicy {
                minute_days: 30,
                ..RetentionPolicy::default()
            },
        )
        .unwrap();
    assert_matches_source(storage.connection());
    assert_eq!(
        storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM traffic_scope_total_minute",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn scope_totals_stay_exact_when_late_classification_merges_existing_rows() {
    let mut storage = Storage::sqlite(setup());
    let mut input = batch(1, FlowLifecycle::Ended);
    let mut peer = input.flows[0].clone();
    peer.client_port += 1;
    input.flows.push(peer);
    let classified = FlowAttribution {
        protocol_id: "tls".into(),
        ..service_attribution()
    };
    storage
        .persist_classified_batch(
            &input,
            &[transport_attribution(), classified.clone()],
            &[],
            NOW,
        )
        .unwrap();
    assert_matches_source(storage.connection());
    storage
        .reclassify_flow_at("gateway-1", &input.flows[0], &classified, NOW + 1000)
        .unwrap();
    assert_matches_source(storage.connection());
    assert_eq!(
        metrics(storage.connection(), "traffic_scope_total_minute", "1=1"),
        (200, 100, 6, 2)
    );
}
