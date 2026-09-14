use netqmon_protocol::v1::{
    AgentHealth, DeviceDiscoveryObservation, DeviceObservation, FlowDelta, TelemetryBatch,
};
use netqmon_protocol::{
    ContentEncoding, PROTOCOL_VERSION, decode_telemetry_batch, encode_telemetry_batch,
    validate_batch_metadata,
};

fn sample_batch() -> TelemetryBatch {
    TelemetryBatch {
        gateway_id: "gateway-01".to_owned(),
        boot_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
        sequence: 42,
        sent_at: 1_700_000_000_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 20],
            client_port: 19_090,
            remote_ip: vec![198, 51, 100, 53],
            remote_port: 53,
            direction: 1,
            download_bytes: 4_096,
            packets: 8,
            client_mac: vec![0x02, 0, 0, 0, 0, 0x20],
            ..FlowDelta::default()
        }],
        device_observations: vec![DeviceObservation {
            mac: vec![0x02, 0, 0, 0, 0, 0x20],
            ip: vec![192, 0, 2, 20],
            hostname: "laptop".to_owned(),
            last_seen_unix_ms: 1_700_000_000_000,
            dhcp: None,
        }],
        device_discovery_observations: vec![DeviceDiscoveryObservation {
            mac: vec![0x02, 0, 0, 0, 0, 0x20],
            ip: vec![192, 0, 2, 20],
            protocol: "mdns".to_owned(),
            service: "_ipp._tcp.local".to_owned(),
            instance: "Office Printer._ipp._tcp.local".to_owned(),
            hostname: "printer.local".to_owned(),
            port: 631,
            attributes: [("md".to_owned(), "LaserJet".to_owned())].into(),
            observed_at_unix_ms: 1_700_000_000_000,
        }],
        health: Some(AgentHealth {
            observed_at_unix_ms: 1_700_000_000_000,
            uptime_seconds: 3600,
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    }
}

#[test]
fn collector_round_trips_zstd_batch_from_shared_generated_types() {
    let batch = sample_batch();
    validate_batch_metadata(&batch).unwrap();

    let encoded = encode_telemetry_batch(&batch, 1).unwrap();
    assert_eq!(encoded.encoding, ContentEncoding::Zstd);
    assert_eq!(encoded.encoding.http_value(), Some("zstd"));

    let decoded = decode_telemetry_batch(&encoded.body, encoded.encoding).unwrap();
    assert_eq!(decoded, batch);
}

#[test]
fn small_batch_may_use_identity_encoding() {
    let batch = sample_batch();
    let encoded = encode_telemetry_batch(&batch, usize::MAX).unwrap();
    assert_eq!(encoded.encoding, ContentEncoding::Identity);
    assert_eq!(encoded.encoding.http_value(), None);
    assert_eq!(
        decode_telemetry_batch(&encoded.body, encoded.encoding).unwrap(),
        batch
    );
}

#[test]
fn rejects_unknown_http_content_encoding() {
    assert!(ContentEncoding::from_http_value(Some("gzip")).is_err());
}
