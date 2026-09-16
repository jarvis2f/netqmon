#![cfg(feature = "analytics-duckdb")]

use netqmon_protocol::v1::{Direction, FlowDelta, FlowLifecycle, TelemetryBatch};
use netqmon_storage::analytics::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsResolution, ApplyBatchResult, FlowQuery, TrafficDelta,
    TrafficQuery,
};
use netqmon_storage::{FlowAttribution, PersistDisposition, Storage};

const NOW: u64 = 1_700_000_000_000;

fn flow(gateway_id: &str, flow_id: &str) -> AnalyticsFlow {
    AnalyticsFlow {
        flow_id: flow_id.to_owned(),
        gateway_id: gateway_id.to_owned(),
        device_id: 7,
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 7],
        client_port: 50_000,
        remote_ip: vec![198, 51, 100, 7],
        remote_port: 443,
        direction: Direction::Upload as u8,
        domain: "tracker.example".to_owned(),
        organization_id: "tracker-owner".to_owned(),
        application_id: "private-tracker".to_owned(),
        category_id: "p2p".to_owned(),
        traffic_role: "tracker_service".to_owned(),
        protocol_id: "unknown".to_owned(),
        organization_confidence: 0.9,
        application_confidence: 0.9,
        protocol_confidence: 0.0,
        classification_confidence: 0.9,
        classification_reason: "domain".to_owned(),
        classification_evidence_json: "[]".to_owned(),
        upload_bytes: 123,
        download_bytes: 456,
        packets: 8,
        started_at: NOW,
        last_seen_at: NOW + 1_000,
        ended_at: Some(NOW + 1_000),
        checkpointed_at: NOW + 1_000,
        scope: 1,
        path_type: 1,
        nat: 1,
        source_segment: "lan".to_owned(),
        destination_segment: "internet".to_owned(),
    }
}

fn traffic(gateway_id: &str) -> TrafficDelta {
    TrafficDelta {
        timestamp: NOW,
        gateway_id: gateway_id.to_owned(),
        scope: 1,
        direction: 1,
        transport_protocol: 6,
        path_type: 1,
        nat: 1,
        device_id: 7,
        organization_id: "tracker-owner".to_owned(),
        application_id: "private-tracker".to_owned(),
        category_id: "p2p".to_owned(),
        protocol_id: "unknown".to_owned(),
        domain: "tracker.example".to_owned(),
        remote_ip: vec![198, 51, 100, 7],
        upload_bytes: 123,
        download_bytes: 456,
        packets: 8,
        flow_count: 1,
    }
}

#[test]
fn analytics_batches_are_idempotent_and_flow_versions_are_append_only() {
    let mut analytics = Storage::open_in_memory().unwrap();
    let batch = AnalyticsBatch {
        gateway_id: "gateway-analytics".to_owned(),
        boot_id: "boot-1".to_owned(),
        sequence: 1,
        received_at: NOW,
        flows: vec![flow("gateway-analytics", "flow-1")],
        traffic: vec![traffic("gateway-analytics")],
    };
    assert_eq!(
        analytics.analytics_mut().apply_batch(&batch).unwrap(),
        ApplyBatchResult::Applied
    );
    assert_eq!(
        analytics.analytics_mut().apply_batch(&batch).unwrap(),
        ApplyBatchResult::Duplicate
    );

    let changed = AnalyticsBatch {
        boot_id: "late-dpi".to_owned(),
        sequence: 1,
        received_at: NOW + 2_000,
        flows: vec![AnalyticsFlow {
            protocol_id: "tls".to_owned(),
            protocol_confidence: 1.0,
            checkpointed_at: NOW + 2_000,
            last_seen_at: NOW + 2_000,
            ..batch.flows[0].clone()
        }],
        traffic: Vec::new(),
        ..batch.clone()
    };
    assert_eq!(
        analytics.analytics_mut().apply_batch(&changed).unwrap(),
        ApplyBatchResult::Applied
    );
    let latest = analytics
        .analytics()
        .flows(&FlowQuery {
            from: NOW,
            to: NOW + 10_000,
            gateway_id: Some("gateway-analytics".to_owned()),
            limit: 10,
            ..FlowQuery::default()
        })
        .unwrap();
    assert_eq!(latest.total, 1);
    assert_eq!(latest.rows[0].protocol_id, "tls");
    assert_eq!(latest.rows[0].application_id, "private-tracker");
    assert_eq!(latest.rows[0].upload_bytes, 123);

    let totals = analytics
        .analytics()
        .traffic_series(&TrafficQuery {
            from: NOW / 60_000 * 60_000,
            to: NOW / 60_000 * 60_000 + 60_000,
            resolution: AnalyticsResolution::Minute,
            gateway_id: Some("gateway-analytics".to_owned()),
            scope: None,
            direction: None,
            device_id: None,
            organization_id: None,
            application_id: None,
            category_id: None,
            protocol_id: None,
            domain: None,
            remote_ip: None,
        })
        .unwrap();
    assert_eq!(totals.iter().map(|row| row.upload_bytes).sum::<u64>(), 123);
    assert_eq!(
        totals.iter().map(|row| row.download_bytes).sum::<u64>(),
        456
    );
}

#[test]
fn sqlite_metadata_commits_classified_batches_to_the_outbox() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage
        .save_gateway("gateway-outbox", "router", "test", &[7; 32], NOW)
        .unwrap();
    let batch = TelemetryBatch {
        gateway_id: "gateway-outbox".to_owned(),
        boot_id: "boot-outbox".to_owned(),
        sequence: 1,
        sent_at: NOW,
        agent_version: "test".to_owned(),
        protocol_version: 1,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 8],
            client_port: 50_001,
            remote_ip: vec![198, 51, 100, 8],
            remote_port: 443,
            direction: Direction::Upload as i32,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            first_seen_unix_ms: NOW,
            last_seen_unix_ms: NOW + 1_000,
            lifecycle: FlowLifecycle::Ended as i32,
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        storage
            .persist_classified_batch(&batch, &[FlowAttribution::default()], &[], NOW)
            .unwrap(),
        PersistDisposition::Accepted
    );
    assert_eq!(storage.outbox_depth().unwrap(), 1);

    // Simulate a process exit after analytics commits but before SQLite acks.
    let record = storage.metadata().outbox_batch(1).unwrap().remove(0);
    let analytics_batch = AnalyticsBatch::decode(&record.payload).unwrap();
    assert_eq!(
        storage
            .analytics_mut()
            .apply_batch(&analytics_batch)
            .unwrap(),
        ApplyBatchResult::Applied
    );
    assert_eq!(storage.outbox_depth().unwrap(), 1);
    assert_eq!(storage.process_outbox(10).unwrap(), 1);
    assert_eq!(storage.outbox_depth().unwrap(), 0);
    assert_eq!(storage.process_outbox(10).unwrap(), 0);

    let late = FlowAttribution {
        protocol_id: "tls".to_owned(),
        protocol_confidence: 1.0,
        confidence: 1.0,
        reason: "late-dpi".to_owned(),
        ..FlowAttribution::default()
    };
    assert!(
        storage
            .reclassify_flow("gateway-outbox", &batch.flows[0], &late)
            .is_ok()
    );
    assert_eq!(storage.process_outbox(10).unwrap(), 1);
    let latest = storage
        .analytics()
        .flows(&FlowQuery {
            from: NOW,
            to: NOW + 10_000,
            gateway_id: Some("gateway-outbox".to_owned()),
            limit: 10,
            ..FlowQuery::default()
        })
        .unwrap();
    assert_eq!(latest.total, 1);
    assert_eq!(latest.rows[0].protocol_id, "tls");
}
