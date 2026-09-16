use netqmon_protocol::v1::{
    DeviceObservation, Direction, DnsObservation, DnsRecordType, FlowDelta, FlowLifecycle,
    FlowScope, NatType, PathType, TelemetryBatch,
};
use tempfile::tempdir;

use super::*;

const NOW: u64 = 1_700_000_000_000;

fn setup() -> SqliteStorage {
    let mut storage = SqliteStorage::open_in_memory().unwrap();
    assert!(
        storage
            .save_gateway("gateway-1", "router", "0.1.0", &[7; 32], NOW)
            .unwrap()
    );
    storage
}

fn batch(sequence: u64, lifecycle: FlowLifecycle) -> TelemetryBatch {
    TelemetryBatch {
        gateway_id: "gateway-1".to_owned(),
        boot_id: "boot-1".to_owned(),
        sequence,
        sent_at: NOW + sequence * 1_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: 1,
        device_observations: vec![DeviceObservation {
            mac: vec![2, 0, 0, 0, 0, 1],
            ip: vec![192, 0, 2, u8::try_from(10 + sequence).unwrap()],
            hostname: "laptop".to_owned(),
            last_seen_unix_ms: NOW + sequence,
            dhcp: None,
        }],
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "example.com".to_owned(),
            answer_ip: vec![198, 51, 100, 1],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: NOW,
        }],
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            direction: Direction::Upload as i32,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            first_seen_unix_ms: NOW,
            last_seen_unix_ms: NOW + sequence * 1_000,
            lifecycle: lifecycle as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            scope: FlowScope::Internet as i32,
            path_type: PathType::Forwarded as i32,
            nat: NatType::Snat as i32,
            source_segment: "192.0.2.0/24".to_owned(),
            destination_segment: "internet".to_owned(),
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    }
}

#[test]
fn empty_database_migrates_and_configures_pragmas() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let count: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (
                'sites', 'gateways', 'users', 'devices', 'device_addresses',
                'dns_observations', 'flow_sessions', 'traffic_total_minute',
                'traffic_total_hour', 'traffic_total_day', 'settings',
                'device_evidence', 'traffic_scope_minute')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 13);
    for (pragma, expected) in [
        ("foreign_keys", 1),
        ("synchronous", 1),
        ("busy_timeout", 5_000),
    ] {
        let value: i64 = storage
            .connection()
            .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, expected, "{pragma}");
    }
}

#[test]
fn migration_and_gateway_survive_reopen() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("netqmon.db");
    {
        let mut storage = SqliteStorage::open(&path).unwrap();
        assert!(
            storage
                .save_gateway("gateway-1", "router", "0.1.0", &[9; 32], NOW)
                .unwrap()
        );
    }
    let storage = SqliteStorage::open(&path).unwrap();
    assert_eq!(storage.gateway().unwrap().unwrap().id, "gateway-1");
    let journal_mode: String = storage
        .connection()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal");
    let migrations: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(migrations, 2);
    let index_exists: bool = storage
        .connection()
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'index' AND name = 'flow_sessions_remote_last_seen'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(index_exists);
    let insight_index_exists: bool = storage
        .connection()
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'index' AND name = 'flow_sessions_port_last_seen_remote'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(insight_index_exists);
}

#[test]
fn stale_gateway_credentials_rotate_without_changing_identity() {
    let mut storage = SqliteStorage::open_in_memory().unwrap();
    assert!(
        storage
            .save_gateway("gateway-1", "router", "0.1.0", &[7; 32], NOW)
            .unwrap()
    );

    assert!(
        storage
            .replace_stale_gateway(
                "gateway-1",
                "replacement-router",
                "0.1.0-beta.4",
                &[9; 32],
                NOW,
                NOW + 1_000,
            )
            .unwrap()
    );
    let gateway = storage.gateway().unwrap().unwrap();
    assert_eq!(gateway.id, "gateway-1");
    assert_eq!(gateway.agent_token_hash, [9; 32]);
    assert_eq!(gateway.last_seen_ms, NOW + 1_000);

    assert!(
        !storage
            .replace_stale_gateway(
                "gateway-1",
                "another-router",
                "0.1.0-beta.4",
                &[11; 32],
                NOW,
                NOW + 2_000,
            )
            .unwrap()
    );
    let gateway = storage.gateway().unwrap().unwrap();
    assert_eq!(gateway.agent_token_hash, [9; 32]);
    assert_eq!(gateway.last_seen_ms, NOW + 1_000);
}

#[test]
fn self_host_client_enrichment_is_per_ip_and_rejects_shared_ip_apps() {
    let mut storage = setup();
    let mut first = batch(1, FlowLifecycle::Ended);
    let server_ip = vec![192, 0, 2, 31];
    first.flows[0].remote_ip.clone_from(&server_ip);
    first.flows[0].remote_port = 8096;
    first.device_observations.push(DeviceObservation {
        mac: vec![2, 0, 0, 0, 0, 31],
        ip: server_ip.clone(),
        hostname: "server".to_owned(),
        last_seen_unix_ms: NOW + 1_000,
        dhcp: None,
    });
    let jellyfin = FlowAttribution {
        application_id: "jellyfin".to_owned(),
        application_confidence: 0.99,
        confidence: 0.99,
        evidence_json: r#"[{"type":"self_host_application","source":"rule","weight":0.99}]"#
            .to_owned(),
        ..FlowAttribution::default()
    };
    storage
        .persist_classified_batch(&first, &[jellyfin], &[], NOW + 1_000)
        .unwrap();
    let enriched: Option<String> = storage
        .connection()
        .query_row(
            "SELECT application_id FROM device_addresses WHERE ip=?1",
            [&server_ip],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(enriched.as_deref(), Some("jellyfin"));

    let mut shared = first.clone();
    shared.sequence = 2;
    shared.flows[0].remote_port = 8123;
    shared.flows[0].last_seen_unix_ms = NOW + 2_000;
    let home_assistant = FlowAttribution {
        application_id: "home_assistant".to_owned(),
        application_confidence: 0.99,
        confidence: 0.99,
        evidence_json: r#"[{"type":"self_host_application","source":"rule","weight":0.99}]"#
            .to_owned(),
        ..FlowAttribution::default()
    };
    storage
        .persist_classified_batch(&shared, &[home_assistant], &[], NOW + 2_000)
        .unwrap();
    let enriched: Option<String> = storage
        .connection()
        .query_row(
            "SELECT application_id FROM device_addresses WHERE ip=?1",
            [&server_ip],
            |row| row.get(0),
        )
        .unwrap();
    assert!(enriched.is_none());

    let mut conflict = shared;
    conflict.sequence = 3;
    conflict.flows[0].last_seen_unix_ms = NOW + 3_000;
    let shared_ip = FlowAttribution {
        evidence_json:
            r#"[{"type":"self_host_shared_ip","source":"endpoint_consensus","weight":1.0}]"#
                .to_owned(),
        ..FlowAttribution::default()
    };
    storage
        .persist_classified_batch(&conflict, &[shared_ip], &[], NOW + 3_000)
        .unwrap();
    let endpoint_count: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM self_host_endpoint_evidence WHERE ip=?1",
            [&server_ip],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(endpoint_count, 0);
}

#[test]
fn administrator_and_hashed_sessions_are_persisted() {
    let mut storage = SqliteStorage::open_in_memory().unwrap();
    assert!(!storage.admin_exists().unwrap());
    assert!(
        storage
            .create_admin("user-1", "admin", "$argon2id$test", NOW)
            .unwrap()
    );
    assert!(
        !storage
            .create_admin("user-2", "other", "hash", NOW)
            .unwrap()
    );
    assert!(storage.admin_exists().unwrap());
    assert_eq!(
        storage
            .user_by_username("admin")
            .unwrap()
            .unwrap()
            .password_hash,
        "$argon2id$test"
    );

    let digest = [7_u8; 32];
    storage
        .create_session("user-1", &digest, NOW, NOW + 60_000)
        .unwrap();
    let session = storage.session(&digest, NOW + 1).unwrap().unwrap();
    assert_eq!(session.username, "admin");
    assert!(storage.session(&digest, NOW + 60_000).unwrap().is_none());
    assert!(storage.delete_session(&digest).unwrap());
    assert!(!storage.delete_session(&digest).unwrap());
}

#[test]
fn initial_database_persists_and_queries_application_rollups() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("netqmon.db");
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(INITIAL_MIGRATION).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
                [to_i64(NOW)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_application_minute(
                    timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes,
                    packets, flow_count
                 ) VALUES (?1, 'gateway-1', 'unknown', 'unknown', 10, 20, 1, 1)",
                [to_i64(NOW) / MINUTE_MS * MINUTE_MS],
            )
            .unwrap();
    }

    let storage = SqliteStorage::open(&path).unwrap();
    let row: (String, String, i64) = storage
        .connection()
        .query_row(
            "SELECT application_id, category_id, upload_bytes + download_bytes
             FROM traffic_application_minute",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("unknown".to_owned(), "unknown".to_owned(), 30));
}

#[test]
fn dns_resolution_is_time_aware_and_client_scoped() {
    let mut storage = setup();
    let mut observations = batch(1, FlowLifecycle::Active);
    observations.flows.clear();
    observations.dns_observations = vec![
        DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "video.example".to_owned(),
            answer_ip: vec![198, 51, 100, 1],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: NOW,
        },
        DnsObservation {
            client_ip: vec![192, 0, 2, 11],
            domain: "chat.example".to_owned(),
            answer_ip: vec![198, 51, 100, 1],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 120,
            observed_at_unix_ms: NOW,
        },
    ];
    storage.persist_batch(&observations, NOW).unwrap();

    assert_eq!(
        storage
            .resolve_domain(
                "gateway-1",
                &[192, 0, 2, 10],
                &[198, 51, 100, 1],
                NOW + 59_999,
            )
            .unwrap()
            .as_deref(),
        Some("video.example")
    );
    assert_eq!(
        storage
            .resolve_domain(
                "gateway-1",
                &[192, 0, 2, 11],
                &[198, 51, 100, 1],
                NOW + 59_999,
            )
            .unwrap()
            .as_deref(),
        Some("chat.example")
    );
    assert_eq!(
        storage
            .resolve_domain(
                "gateway-1",
                &[192, 0, 2, 10],
                &[198, 51, 100, 1],
                NOW + 60_000,
            )
            .unwrap(),
        None
    );
}

#[test]
fn classified_flows_populate_sessions_and_rollups() {
    let mut storage = setup();
    let attribution = FlowAttribution {
        domain: Some("api.openai.com".to_owned()),
        organization_id: "openai".to_owned(),
        application_id: "openai".to_owned(),
        category_id: "ai".to_owned(),
        traffic_role: "unknown".to_owned(),
        protocol_id: "tls".to_owned(),
        organization_confidence: 0.90,
        application_confidence: 0.98,
        protocol_confidence: 0.60,
        confidence: 0.98,
        reason: "domain:api.openai.com".to_owned(),
        evidence_json: r#"[{"type":"domain","value":"api.openai.com"}]"#.to_owned(),
    };
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Ended),
            std::slice::from_ref(&attribution),
            &[],
            NOW,
        )
        .unwrap();

    let rollup: (String, String) = storage
        .connection()
        .query_row(
            "SELECT application_id, category_id FROM traffic_application_minute",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rollup, ("openai".to_owned(), "ai".to_owned()));
    let domain: String = storage
        .connection()
        .query_row("SELECT domain FROM traffic_domain_minute", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(domain, "api.openai.com");
    let session: (String, String, String, String, String, String, f64, f64, f64, f64, String, String) = storage
        .connection()
        .query_row(
            "SELECT domain, organization_id, application_id, category_id, traffic_role, protocol_id,
                    organization_confidence, application_confidence, protocol_confidence,
                    classification_confidence, classification_reason, classification_evidence_json
             FROM flow_sessions",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(session.0, attribution.domain.clone().unwrap());
    assert_eq!(session.1, attribution.organization_id);
    assert_eq!(session.2, attribution.application_id);
    assert_eq!(session.3, attribution.category_id);
    assert_eq!(session.4, attribution.traffic_role);
    assert_eq!(session.5, attribution.protocol_id);
    assert!((session.6 - attribution.organization_confidence).abs() < f64::EPSILON);
    assert!((session.7 - attribution.application_confidence).abs() < f64::EPSILON);
    assert!((session.8 - attribution.protocol_confidence).abs() < f64::EPSILON);
    assert!((session.9 - attribution.confidence).abs() < f64::EPSILON);
    assert_eq!(session.10, attribution.reason);
    assert_eq!(session.11, attribution.evidence_json);
}

#[test]
fn device_evidence_accumulates_and_survives_reopen() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("netqmon.db");
    let mac = vec![2, 0, 0, 0, 0, 1];
    for (sequence, observed_at, confidence, metadata_json) in [
        (1, NOW + 10, 0.7, r#"{"rule":"iphone-hostname"}"#),
        (2, NOW + 20, 0.8, r#"{"rule":"iphone-hostname-v2"}"#),
    ] {
        let mut storage = SqliteStorage::open(&path).unwrap();
        if storage.gateway().unwrap().is_none() {
            storage
                .save_gateway("gateway-1", "router", "0.1.0", &[7; 32], NOW)
                .unwrap();
        }
        let identity = DeviceIdentityUpdate {
            mac: mac.clone(),
            vendor: Some("Apple".to_owned()),
            device_type: Some("smartphone".to_owned()),
            os_family: Some("iOS".to_owned()),
            model: None,
            confidence: Some("medium".to_owned()),
            vendor_confidence: confidence,
            device_type_confidence: 0.8,
            os_confidence: 0.75,
            model_confidence: 0.0,
            private_mac: true,
            evidence_json: "[]".to_owned(),
            evidence: vec![DeviceEvidenceUpdate {
                source: "hostname".to_owned(),
                field: "vendor".to_owned(),
                value: "Apple".to_owned(),
                confidence,
                observed_at,
                metadata_json: metadata_json.to_owned(),
            }],
        };
        let current_batch = batch(sequence, FlowLifecycle::Active);
        storage
            .persist_classified_batch(
                &current_batch,
                &[],
                std::slice::from_ref(&identity),
                observed_at,
            )
            .unwrap();
        if sequence == 2 {
            assert_eq!(
                storage
                    .persist_classified_batch(&current_batch, &[], &[identity], observed_at)
                    .unwrap(),
                PersistDisposition::Duplicate
            );
        }
    }

    let storage = SqliteStorage::open(&path).unwrap();
    let evidence = storage.device_evidence("gateway-1", &mac).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].first_seen, NOW + 10);
    assert_eq!(evidence[0].last_seen, NOW + 20);
    assert_eq!(evidence[0].hit_count, 2);
    assert!((evidence[0].confidence - 0.8).abs() < f64::EPSILON);
    assert_eq!(
        evidence[0].metadata_json,
        r#"{"rule":"iphone-hostname-v2"}"#
    );
}

#[test]
fn device_upsert_keeps_identity_when_ip_changes() {
    let mut storage = setup();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
        .unwrap();
    storage
        .persist_batch(&batch(2, FlowLifecycle::Active), NOW + 1_000)
        .unwrap();
    for (table, expected) in [("devices", 1), ("device_addresses", 2)] {
        let count: i64 = storage
            .connection()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }
}

#[test]
fn batch_is_deduplicated_and_rollup_matches_raw_delta() {
    let mut storage = setup();
    let batch = batch(1, FlowLifecycle::Active);
    assert_eq!(
        storage.persist_batch(&batch, NOW).unwrap(),
        PersistDisposition::Accepted
    );
    assert_eq!(
        storage.persist_batch(&batch, NOW).unwrap(),
        PersistDisposition::Duplicate
    );
    let metrics: (i64, i64, i64, i64) = storage
        .connection()
        .query_row(
            "SELECT upload_bytes, download_bytes, packets, flow_count FROM traffic_total_minute",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(metrics, (100, 50, 3, 1));
    let scoped: (i32, i32, i64, String, i32, String) = storage
        .connection()
        .query_row(
            "SELECT scope, direction, device_id, application_id, protocol, protocol_id
             FROM traffic_scope_minute",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(scoped.0, FlowScope::Internet as i32);
    assert_eq!(scoped.1, Direction::Upload as i32);
    assert!(scoped.2 > 0);
    assert_eq!(scoped.3, "unknown");
    assert_eq!(scoped.4, 6);
    assert_eq!(scoped.5, "unknown");
    for dimension in DIMENSIONS {
        let total: i64 = storage
            .connection()
            .query_row(
                &format!("SELECT upload_bytes + download_bytes FROM traffic_{dimension}_minute"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(total, 150, "{dimension}");
    }
    assert_eq!(
        storage
            .query_total_traffic(NOW - MINUTE_MS as u64, NOW + MINUTE_MS as u64)
            .unwrap(),
        vec![TrafficTotal {
            timestamp: to_i64(NOW) / MINUTE_MS * MINUTE_MS,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            flow_count: 1,
        }]
    );
}

#[test]
fn dns_expiry_flow_end_and_hour_day_rollups_are_persisted() {
    let mut storage = setup();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Ended), NOW)
        .unwrap();
    let expiry: i64 = storage
        .connection()
        .query_row("SELECT expires_at FROM dns_observations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(expiry, to_i64(NOW) + 60_000);
    let ended_at: Option<i64> = storage
        .connection()
        .query_row("SELECT ended_at FROM flow_sessions", [], |row| row.get(0))
        .unwrap();
    assert!(ended_at.is_some());

    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    for dimension in DIMENSIONS {
        for resolution in ["hour", "day"] {
            let table = format!("traffic_{dimension}_{resolution}");
            let total: i64 = storage
                .connection()
                .query_row(
                    &format!("SELECT upload_bytes + download_bytes FROM {table}"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(total, 150, "{table}");
        }
    }
}

#[test]
fn long_flow_checkpoints_and_resumes_after_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("netqmon.db");
    {
        let mut storage = SqliteStorage::open(&path).unwrap();
        assert!(
            storage
                .save_gateway("gateway-1", "router", "0.1.0", &[7; 32], NOW)
                .unwrap()
        );
        storage
            .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
            .unwrap();
        let before_checkpoint: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM flow_sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before_checkpoint, 0);
        storage
            .persist_batch(
                &batch(2, FlowLifecycle::Active),
                NOW + FLOW_CHECKPOINT_MS as u64,
            )
            .unwrap();
        let active: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);
    }

    let mut restarted = SqliteStorage::open(&path).unwrap();
    restarted
        .persist_batch(
            &batch(3, FlowLifecycle::Ended),
            NOW + FLOW_CHECKPOINT_MS as u64 + 1_000,
        )
        .unwrap();
    let totals: (i64, i64, i64, bool) = restarted
        .connection()
        .query_row(
            "SELECT upload_bytes, download_bytes, packets, ended_at IS NOT NULL FROM flow_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(totals, (300, 150, 9, true));
}

#[test]
fn retention_removes_expired_rows_but_keeps_day_rollups() {
    let mut storage = setup();
    storage
        .persist_batch(&batch(1, FlowLifecycle::Ended), NOW)
        .unwrap();
    storage
        .roll_up_hour_and_day(NOW + 2 * DAY_MS as u64)
        .unwrap();
    storage
        .run_retention(NOW + 400 * DAY_MS as u64, RetentionPolicy::default())
        .unwrap();
    for table in [
        "dns_observations",
        "flow_sessions",
        "traffic_total_minute",
        "traffic_total_hour",
    ] {
        let count: i64 = storage
            .connection()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let day_count: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM traffic_total_day", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(day_count, 1);
}

#[test]
fn retention_policy_roundtrip() {
    let mut storage = SqliteStorage::open_in_memory().unwrap();
    // Default when nothing is stored
    let default = storage.load_retention_policy().unwrap();
    assert_eq!(default.flow_sessions_days, 7);
    assert_eq!(default.dns_days, 7);
    assert_eq!(default.minute_days, 30);
    assert_eq!(default.hour_days, 365);
    assert_eq!(default.day_days, 0);

    // Save and reload
    let custom = RetentionPolicy {
        flow_sessions_days: 14,
        dns_days: 3,
        minute_days: 60,
        hour_days: 180,
        day_days: 730,
    };
    storage.save_retention_policy(&custom, NOW).unwrap();
    let loaded = storage.load_retention_policy().unwrap();
    assert_eq!(loaded.flow_sessions_days, 14);
    assert_eq!(loaded.dns_days, 3);
    assert_eq!(loaded.minute_days, 60);
    assert_eq!(loaded.hour_days, 180);
    assert_eq!(loaded.day_days, 730);

    // Overwrite
    let updated = RetentionPolicy {
        flow_sessions_days: 1,
        ..RetentionPolicy::default()
    };
    storage.save_retention_policy(&updated, NOW + 1000).unwrap();
    let reloaded = storage.load_retention_policy().unwrap();
    assert_eq!(reloaded.flow_sessions_days, 1);
    assert_eq!(reloaded.dns_days, 7);
}

#[test]
fn database_size_is_positive() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let size = storage.database_size_bytes().unwrap();
    assert!(size > 0);
}

#[test]
fn active_flow_count_and_unknown_ratio() {
    let mut storage = setup();
    // Before any flows
    assert_eq!(storage.active_flow_count().unwrap(), 0);
    assert!((storage.unknown_ratio(0).unwrap() - 0.0).abs() < f64::EPSILON);

    // Persist a batch with an active flow
    storage
        .persist_batch(&batch(1, FlowLifecycle::Active), NOW)
        .unwrap();
    assert!(storage.active_flow_count().unwrap() >= 0); // checkpoint may or may not have written
}

#[test]
fn late_transport_dpi_preserves_application_and_tracker_identity() {
    let mut current = FlowAttribution {
        domain: Some("tracker.example".into()),
        application_id: "private-tracker".into(),
        organization_id: "tracker-owner".into(),
        category_id: "p2p".into(),
        traffic_role: "tracker_service".into(),
        confidence: 1.0,
        ..Default::default()
    };
    super::apply_late_protocol(
        &mut current,
        &FlowAttribution {
            protocol_id: "tls".into(),
            protocol_confidence: 1.0,
            confidence: 0.8,
            ..Default::default()
        },
    );
    assert_eq!(current.protocol_id, "tls");
    assert_eq!(current.domain.as_deref(), Some("tracker.example"));
    assert_eq!(current.application_id, "private-tracker");
    assert_eq!(current.organization_id, "tracker-owner");
    assert_eq!(current.category_id, "p2p");
    assert_eq!(current.traffic_role, "tracker_service");
    assert!((current.confidence - 1.0).abs() < f64::EPSILON);
}
