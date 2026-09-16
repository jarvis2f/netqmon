#![cfg(feature = "analytics-clickhouse")]

use netqmon_protocol::v1::Direction;
use netqmon_storage::ClickHouseConfig;
use netqmon_storage::analytics::clickhouse::ClickHouseAnalyticsStore;
use netqmon_storage::analytics::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsResolution, AnalyticsStore, ApplyBatchResult,
    FlowQuery, SummaryQuery, TrafficBreakdownQuery, TrafficDelta, TrafficDimension, TrafficQuery,
};

const NOW: u64 = 1_700_000_000_000;

fn flow(gateway_id: &str) -> AnalyticsFlow {
    AnalyticsFlow {
        flow_id: "contract-flow".to_owned(),
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

fn traffic_query(gateway_id: &str) -> TrafficQuery {
    let bucket = NOW / 60_000 * 60_000;
    TrafficQuery {
        from: bucket,
        to: bucket + 60_000,
        resolution: AnalyticsResolution::Minute,
        gateway_id: Some(gateway_id.to_owned()),
        scope: None,
        direction: None,
        device_id: None,
        organization_id: None,
        application_id: None,
        category_id: None,
        protocol_id: None,
        domain: None,
        remote_ip: None,
    }
}

#[test]
#[ignore = "requires NETQMON_TEST_CLICKHOUSE_URL"]
fn clickhouse_analytics_contract_is_idempotent_and_keeps_latest_flow_version() {
    let config = ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL")
            .expect("CI configures a ClickHouse test URL"),
        ..ClickHouseConfig::default()
    };
    let mut store = ClickHouseAnalyticsStore::open(config).unwrap();
    let gateway_id = format!("contract-{}", std::process::id());
    let batch = AnalyticsBatch {
        gateway_id: gateway_id.clone(),
        boot_id: "boot-contract".to_owned(),
        sequence: 1,
        received_at: NOW,
        flows: vec![flow(&gateway_id)],
        traffic: vec![traffic(&gateway_id)],
    };

    assert_eq!(
        store.apply_batch(&batch).unwrap(),
        ApplyBatchResult::Applied
    );
    assert_eq!(
        store.apply_batch(&batch).unwrap(),
        ApplyBatchResult::Duplicate
    );

    let traffic = store.traffic_series(&traffic_query(&gateway_id)).unwrap();
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].upload_bytes, 123);
    assert_eq!(traffic[0].download_bytes, 456);
    assert_eq!(traffic[0].packets, 8);
    assert_eq!(traffic[0].flow_count, 1);

    let breakdown = store
        .traffic_breakdown(&TrafficBreakdownQuery {
            traffic: traffic_query(&gateway_id),
            dimension: TrafficDimension::Application,
            limit: 10,
            offset: 0,
        })
        .unwrap();
    assert_eq!(breakdown.len(), 1);
    assert_eq!(breakdown[0].key, "private-tracker");
    assert_eq!(breakdown[0].upload_bytes, 123);

    let late = AnalyticsBatch {
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
    assert_eq!(store.apply_batch(&late).unwrap(), ApplyBatchResult::Applied);
    let page = store
        .flows(&FlowQuery {
            from: NOW,
            to: NOW + 10_000,
            gateway_id: Some(gateway_id.clone()),
            limit: 10,
            ..FlowQuery::default()
        })
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.rows[0].protocol_id, "tls");
    assert_eq!(page.rows[0].upload_bytes, 123);

    let summary = store
        .application_summary(&SummaryQuery {
            from: NOW / 60_000 * 60_000,
            to: NOW / 60_000 * 60_000 + 60_000,
            resolution: AnalyticsResolution::Minute,
            gateway_id: Some(gateway_id),
            device_id: None,
            scope: None,
            direction: None,
            organization_id: None,
            application_id: None,
            category_id: None,
            protocol_id: None,
            domain: None,
            remote_ip: None,
            limit: 10,
            offset: 0,
        })
        .unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].key, "private-tracker");
    assert_eq!(summary[0].upload_bytes, 123);
}
