use netqmon_protocol::v1::{AgentHealth, DeviceObservation, FlowDelta};

use super::*;

fn batch(sequence: u64, lifecycle: FlowLifecycle) -> TelemetryBatch {
    TelemetryBatch {
        gateway_id: "gateway-1".to_owned(),
        sequence,
        sent_at: 1_000 + sequence * 1_000,
        flows: vec![FlowDelta {
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 2],
            remote_port: 443,
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            last_seen_unix_ms: 1_000 + sequence * 1_000,
            lifecycle: lifecycle as i32,
            scope: WireFlowScope::Internet as i32,
            path_type: WirePathType::Forwarded as i32,
            nat: NatType::Snat as i32,
            source_segment: "192.0.2.0/24".to_owned(),
            destination_segment: "internet".to_owned(),
            ..FlowDelta::default()
        }],
        device_observations: vec![DeviceObservation {
            mac: vec![2, 0, 0, 0, 0, 1],
            ip: vec![192, 0, 2, 10],
            hostname: "laptop".to_owned(),
            last_seen_unix_ms: 1_000 + sequence * 1_000,
            dhcp: None,
        }],
        health: Some(AgentHealth {
            observed_at_unix_ms: 1_000 + sequence * 1_000,
            uptime_seconds: sequence,
            kernel_version: "6.6.73".to_owned(),
            openwrt_version: "24.10.0".to_owned(),
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    }
}

fn attribution() -> FlowAttribution {
    FlowAttribution {
        domain: Some("api.openai.com".to_owned()),
        application_id: "openai".to_owned(),
        category_id: "ai".to_owned(),
        confidence: 0.98,
        reason: "domain:api.openai.com".to_owned(),
        ..FlowAttribution::default()
    }
}

#[test]
fn tracks_one_second_rates_and_active_flow_lifecycle() {
    let mut engine = RealtimeEngine::default();
    engine.update(&batch(1, FlowLifecycle::Active), &[attribution()], 2_000);
    let first = engine.snapshot();
    assert_eq!(first.total.upload_bytes_per_second, 100);
    assert_eq!(first.total.download_bytes_per_second, 200);
    assert_eq!(first.internet.download_bytes_per_second, 200);
    assert_eq!(first.internal.download_bytes_per_second, 0);
    assert_eq!(
        first.clients["02:00:00:00:00:01"].upload_bytes_per_second,
        100
    );
    assert_eq!(first.applications["openai"].download_bytes_per_second, 200);
    assert_eq!(
        first.client_scopes["02:00:00:00:00:01"]
            .internet
            .download_bytes_per_second,
        200
    );
    assert_eq!(first.active_flows.len(), 1);
    assert_eq!(first.active_flows[0].scope, "internet");
    assert_eq!(first.active_flows[0].nat, "snat");
    let health = first.gateway_health.as_ref().unwrap();
    assert_eq!(health.kernel_version, "6.6.73");
    assert_eq!(health.openwrt_version, "24.10.0");

    engine.update(&batch(2, FlowLifecycle::Active), &[attribution()], 3_000);
    assert_eq!(engine.snapshot().active_flows[0].upload_bytes, 200);

    engine.update(&batch(3, FlowLifecycle::Ended), &[attribution()], 4_000);
    let ended = engine.snapshot();
    assert!(ended.active_flows.is_empty());
    assert_eq!(ended.history.len(), 3);
}

#[test]
fn partitions_total_throughput_by_scope() {
    let mut scoped = batch(1, FlowLifecycle::Active);
    let mut internal = scoped.flows[0].clone();
    internal.scope = WireFlowScope::Internal as i32;
    internal.path_type = WirePathType::Internal as i32;
    internal.upload_bytes = 40;
    internal.download_bytes = 60;
    internal.remote_ip = vec![192, 0, 2, 20];
    scoped.flows.push(internal);
    engine_update_assertions(scoped);
}

fn engine_update_assertions(batch: TelemetryBatch) {
    let mut engine = RealtimeEngine::default();
    engine.update(&batch, &[attribution(), attribution()], 2_000);
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.total.upload_bytes_per_second, 140);
    assert_eq!(snapshot.internet.upload_bytes_per_second, 100);
    assert_eq!(snapshot.internal.upload_bytes_per_second, 40);
    assert_eq!(snapshot.tunnel.upload_bytes_per_second, 0);
    assert_eq!(snapshot.unknown.upload_bytes_per_second, 0);
    assert_eq!(snapshot.history[0].upload_bytes_per_second, 100);
}

#[tokio::test]
async fn publishes_all_realtime_event_types() {
    let mut engine = RealtimeEngine::default();
    let mut receiver = engine.subscribe();
    engine.update(
        &batch(1, FlowLifecycle::Active),
        &[FlowAttribution::default()],
        2_000,
    );
    let mut names = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        names.push(event.name());
    }
    assert_eq!(
        names,
        vec!["gateway_status", "device_seen", "warning", "snapshot"]
    );
}

#[test]
fn history_is_bounded_to_fifteen_minutes() {
    let mut engine = RealtimeEngine::default();
    for sequence in 1..=905 {
        engine.update(
            &batch(sequence, FlowLifecycle::Active),
            &[attribution()],
            sequence * 1_000,
        );
    }
    assert_eq!(engine.snapshot().history.len(), MAX_HISTORY_POINTS);
}
