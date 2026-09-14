use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::v1::{DeviceObservation, FlowDelta, TelemetryBatch};
use netqmon_storage::{ClickHouseConfig, ClickHouseStorage, FlowAttribution, Storage};

#[test]
#[ignore = "requires a disposable ClickHouse server"]
fn late_dpi_updates_only_matching_sessions_without_changing_counters() {
    let backend = ClickHouseStorage::open(ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL").expect("disposable server URL"),
        ..Default::default()
    })
    .unwrap();
    backend
        .client()
        .execute(
            "INSERT INTO flow_sessions
        (id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,
         application_id,category_id,traffic_role,protocol_id,upload_bytes,download_bytes,
         packets,started_at,last_seen_at,ended_at,checkpointed_at,classification_evidence_json)
        VALUES ('dpi-test','one',4,6,'c0000202',50000,'c6336401',443,
          'tracker','p2p','tracker_service','unknown',123,456,8,1000,2000,2000,2000,'[]'),
        ('dpi-test','two',4,6,'c0000202',50000,'c6336401',443,
          'tracker','p2p','tracker_service','unknown',123,456,8,1000,2000,2000,2000,'[]')",
        )
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
        "SELECT gateway_id,protocol_id,application_id,category_id,traffic_role,upload_bytes,download_bytes,packets
         FROM flow_sessions FINAL WHERE id='dpi-test' ORDER BY gateway_id").unwrap();
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
#[ignore = "requires a disposable ClickHouse server"]
fn self_host_client_identity_is_single_application_per_ip() {
    let backend = ClickHouseStorage::open(ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL").expect("disposable server URL"),
        ..Default::default()
    })
    .unwrap();
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
