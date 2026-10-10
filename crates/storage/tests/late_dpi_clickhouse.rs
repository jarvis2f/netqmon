use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::v1::{DeviceObservation, FlowDelta, TelemetryBatch};
use netqmon_storage::{
    ClickHouseConfig, ClickHouseStorage, FlowAttribution, RetentionPolicy, Storage,
};

static CLICKHOUSE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn disposable_clickhouse() -> ClickHouseStorage {
    ClickHouseStorage::open(ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL").expect("disposable server URL"),
        database: std::env::var("NETQMON_TEST_CLICKHOUSE_DATABASE")
            .expect("disposable database name"),
        user: std::env::var("NETQMON_TEST_CLICKHOUSE_USER").ok(),
        password: std::env::var("NETQMON_TEST_CLICKHOUSE_PASSWORD").ok(),
        ..Default::default()
    })
    .unwrap()
}

#[test]
#[ignore = "requires a disposable ClickHouse database"]
fn late_dpi_updates_only_matching_sessions_without_changing_counters() {
    let _guard = CLICKHOUSE_TEST_LOCK.lock().unwrap();
    let backend = disposable_clickhouse();
    let one_flow_id = format!(
        "one:4:6:{:x?}:50000:{:x?}:443:2",
        [192, 0, 2, 2],
        [198, 51, 100, 1]
    );
    let two_flow_id = format!(
        "two:4:6:{:x?}:50000:{:x?}:443:0",
        [192, 0, 2, 2],
        [198, 51, 100, 1]
    );
    backend
        .client()
        .execute(&format!(
            "INSERT INTO flow_sessions
        (id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,
         application_id,category_id,traffic_role,protocol_id,upload_bytes,download_bytes,
         packets,started_at,last_seen_at,ended_at,checkpointed_at,classification_evidence_json)
        VALUES ('{one_flow_id}','one',4,6,'c0000202',50000,'c6336401',443,2,
          'tracker','p2p','tracker_service','unknown',123,456,8,1000,2000,2000,2000,'[]'),
        ('{two_flow_id}','two',4,6,'c0000202',50000,'c6336401',443,0,
          'tracker','p2p','tracker_service','unknown',123,456,8,1000,2000,2000,2000,'[]')",
        ))
        .unwrap();
    let mut storage = Storage::clickhouse(backend);
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 2],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 1],
        remote_port: 443,
        first_seen_unix_ms: 1000,
        last_seen_unix_ms: 1500,
        ..Default::default()
    };
    let attribution = FlowAttribution {
        protocol_id: "tls".into(),
        protocol_confidence: 1.0,
        evidence_json: r#"[{"type":"dpi","source":"ndpi","value":"tls"}]"#.into(),
        ..Default::default()
    };
    storage.reclassify_flow("one", &flow, &attribution).unwrap();
    let rows = storage.clickhouse_storage().unwrap().client().query_json(
        &format!("SELECT gateway_id,protocol_id,application_id,category_id,traffic_role,upload_bytes,download_bytes,packets
         FROM flow_sessions FINAL WHERE id IN ('{one_flow_id}', '{two_flow_id}') ORDER BY gateway_id")).unwrap();
    let rows = rows["data"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["protocol_id"], "tls");
    assert_eq!(rows[1]["protocol_id"], "unknown");
    assert_eq!(rows[0]["application_id"], "tracker");
    assert_eq!(rows[0]["category_id"], "p2p");
    assert_eq!(rows[0]["traffic_role"], "tracker_service");
    assert_eq!(rows[0]["upload_bytes"], "123");
    assert_eq!(rows[0]["download_bytes"], "456");
    assert_eq!(rows[0]["packets"], "8");
}

#[test]
#[ignore = "requires a disposable ClickHouse database"]
fn self_host_client_identity_is_single_application_per_ip() {
    let _guard = CLICKHOUSE_TEST_LOCK.lock().unwrap();
    let backend = disposable_clickhouse();
    let mut storage = Storage::clickhouse(backend);
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let gateway_id = format!("self-host-{}-{now}", std::process::id());
    let server_ip = vec![192, 0, 2, 31];
    let mac = vec![2, 0, 0, 0, 0, 31];
    assert!(
        storage
            .save_gateway(&gateway_id, "self-host-test", "test", &[42; 32], now)
            .unwrap()
    );
    let mut batch = TelemetryBatch {
        gateway_id,
        boot_id: "self-host-test".into(),
        sequence: 1,
        sent_at: now,
        device_observations: vec![DeviceObservation {
            mac,
            ip: server_ip.clone(),
            hostname: "server".into(),
            last_seen_unix_ms: now,
            dhcp: None,
        }],
        flows: vec![FlowDelta {
            remote_ip: server_ip,
            remote_port: 8096,
            protocol: 6,
            last_seen_unix_ms: now,
            ..Default::default()
        }],
        ..Default::default()
    };
    let attribution = |application_id: &str| FlowAttribution {
        application_id: application_id.into(),
        application_confidence: 0.99,
        confidence: 0.99,
        evidence_json: r#"[{"type":"self_host_application","source":"rule","weight":0.99}]"#.into(),
        ..Default::default()
    };
    storage
        .persist_classified_batch(&batch, &[attribution("jellyfin")], &[], now)
        .unwrap();
    let clients = storage
        .clickhouse_storage()
        .unwrap()
        .query_clients(200, 0)
        .unwrap()
        .0;
    let client = clients
        .iter()
        .find(|client| client["hostname"] == "server")
        .unwrap();
    assert_eq!(
        client["self_host_application"]["application_id"],
        "jellyfin"
    );

    batch.sequence = 2;
    batch.sent_at += 1;
    batch.flows[0].remote_port = 8123;
    batch.flows[0].last_seen_unix_ms += 1;
    storage
        .persist_classified_batch(&batch, &[attribution("home_assistant")], &[], now + 1)
        .unwrap();
    let clients = storage
        .clickhouse_storage()
        .unwrap()
        .query_clients(200, 0)
        .unwrap()
        .0;
    let client = clients
        .iter()
        .find(|client| client["hostname"] == "server")
        .unwrap();
    assert!(client["self_host_application"].is_null());
}

#[test]
#[ignore = "requires a disposable ClickHouse database"]
fn retention_removes_expired_incremental_rollup_metadata() {
    let _guard = CLICKHOUSE_TEST_LOCK.lock().unwrap();
    let backend = disposable_clickhouse();
    let mut storage = Storage::clickhouse(backend);
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let gateway_id = format!("rollup-retention-{}-{now}", std::process::id());
    let day_ms = 24 * 60 * 60 * 1_000_i64;
    let markers = [
        ("minute", i64::try_from(now).unwrap() - 10 * day_ms),
        ("minute", i64::try_from(now).unwrap() - day_ms),
        ("hour", i64::try_from(now).unwrap() - 40 * day_ms),
        ("hour", i64::try_from(now).unwrap() - 10 * day_ms),
    ];
    let dirty_rows = markers
        .iter()
        .map(|(period, timestamp)| {
            serde_json::json!({
                "gateway_id": gateway_id,
                "dimension": "total",
                "period": period,
                "timestamp": timestamp,
                "version": 1,
            })
        })
        .collect::<Vec<_>>();
    let progress_rows = markers
        .iter()
        .map(|(period, timestamp)| {
            serde_json::json!({
                "gateway_id": gateway_id,
                "dimension": "total",
                "period": period,
                "timestamp": timestamp,
                "processed_version": 1,
            })
        })
        .collect::<Vec<_>>();
    let client = storage.clickhouse_storage().unwrap().client();
    client
        .insert_json_each_row("traffic_rollup_dirty", &dirty_rows)
        .unwrap();
    client
        .insert_json_each_row("traffic_rollup_progress", &progress_rows)
        .unwrap();

    storage
        .run_retention(
            now,
            RetentionPolicy {
                flow_sessions_days: 0,
                dns_days: 0,
                minute_days: 7,
                hour_days: 30,
                day_days: 0,
            },
        )
        .unwrap();

    let minute_cutoff = i64::try_from(now).unwrap() - 7 * day_ms;
    let hour_cutoff = i64::try_from(now).unwrap() - 30 * day_ms;
    for table in ["traffic_rollup_dirty", "traffic_rollup_progress"] {
        let result = storage
            .clickhouse_storage()
            .unwrap()
            .client()
            .query_json(&format!(
                "SELECT countIf(period = 'minute' AND timestamp < {minute_cutoff}) AS expired_minutes,
                        countIf(period = 'hour' AND timestamp < {hour_cutoff}) AS expired_hours,
                        count() AS retained
                 FROM {table} WHERE gateway_id = '{gateway_id}' FORMAT JSON"
            ))
            .unwrap();
        let row = &result["data"][0];
        let count = |field: &str| {
            row[field]
                .as_u64()
                .or_else(|| row[field].as_str().and_then(|value| value.parse().ok()))
                .unwrap_or_default()
        };
        assert_eq!(count("expired_minutes"), 0, "{table}");
        assert_eq!(count("expired_hours"), 0, "{table}");
        assert_eq!(count("retained"), 2, "{table}");
    }
}
