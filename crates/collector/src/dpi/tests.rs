use super::*;
use netqmon_protocol::v1::{FlowDelta, FlowSample, SamplePacket};
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Default)]
struct FixtureMatcher {
    calls: Arc<AtomicUsize>,
}
impl SignatureMatcher for FixtureMatcher {
    fn match_sample(
        &self,
        _key: &FlowSampleKey,
        packets: &[SamplePacket],
    ) -> Vec<SignatureApplicationMatch> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let hit = packets.iter().any(|packet| {
            fixture_l4_payload(&packet.payload).starts_with(&[0x33, 0x66, 0x00, 0x0b])
        });
        if hit {
            vec![SignatureApplicationMatch {
                application_id: "honor_of_kings".into(),
                confidence: 0.95,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Minimal raw-packet payload extraction mirroring classifierd's parser.
fn fixture_l4_payload(raw: &[u8]) -> &[u8] {
    let Some(&first) = raw.first() else {
        return &[];
    };
    let (header_len, transport) = match first >> 4 {
        4 if raw.len() >= 20 => (usize::from(raw[0] & 0x0f) * 4, raw[9]),
        6 if raw.len() >= 40 => (40, raw[6]),
        _ => return &[],
    };
    if header_len > raw.len() || header_len + 20 > raw.len() {
        return &[];
    }
    match transport {
        6 => {
            let offset = usize::from(raw[header_len + 12] >> 4) * 4;
            if header_len + offset <= raw.len() {
                &raw[header_len + offset..]
            } else {
                &[]
            }
        }
        17 if header_len + 8 <= raw.len() => &raw[header_len + 8..],
        _ => &[],
    }
}

struct SilentEngine;
struct SilentFlow;
impl DpiEngine for SilentEngine {
    fn name(&self) -> &'static str {
        "fixture"
    }
    fn start(&self, _: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
        Ok(Box::new(SilentFlow))
    }
}
impl DpiFlow for SilentFlow {
    fn classify(&mut self, _: &[SamplePacket]) -> Option<DpiResult> {
        None
    }
    fn finish(&mut self) -> Option<DpiResult> {
        None
    }
}

struct TestEngine(Arc<AtomicUsize>);
struct TestFlow(Arc<AtomicUsize>, usize);
impl DpiEngine for TestEngine {
    fn name(&self) -> &'static str {
        "fixture"
    }
    fn start(&self, _: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
        Ok(Box::new(TestFlow(self.0.clone(), 0)))
    }
}
impl DpiFlow for TestFlow {
    fn classify(&mut self, packets: &[SamplePacket]) -> Option<DpiResult> {
        self.0.fetch_add(1, Ordering::SeqCst);
        self.1 += packets.len();
        (self.1 >= 2).then(|| DpiResult {
            protocol: "bittorrent".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::new(),
            source: "fixture".into(),
        })
    }
}
fn batch(sequence: u64) -> FlowSampleBatch {
    FlowSampleBatch {
        gateway_id: "a".into(),
        boot_id: "boot".into(),
        sequence,
        sent_at: 1000,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 17,
                client_ip: vec![192, 0, 2, 1],
                client_port: 50000,
                remote_ip: vec![198, 51, 100, 1],
                remote_port: 443,
                first_seen_unix_ms: 1000,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: 1000,
                captured_length: 64,
                original_length: 64,
                payload: vec![0x45; 64],
            }],
            total_captured_bytes: 64,
        }],
    }
}
fn wire_flow() -> FlowDelta {
    let key = batch(1).samples.remove(0).key.unwrap();
    FlowDelta {
        ip_version: key.ip_version,
        protocol: key.protocol,
        client_ip: key.client_ip,
        client_port: key.client_port,
        remote_ip: key.remote_ip,
        remote_port: key.remote_port,
        first_seen_unix_ms: 1000,
        last_seen_unix_ms: 1000,
        ..Default::default()
    }
}
#[test]
fn incremental_dpi_and_cached_result_are_gateway_and_boot_scoped() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(TestEngine(calls.clone())),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );
    assert!(service.submit(batch(1)));
    assert!(service.submit(batch(2)));
    let result = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        result.result.as_ref().expect("dpi result").protocol,
        "bittorrent"
    );
    assert!(service.lookup("a", "boot", &wire_flow()).is_some());
    assert!(service.lookup("b", "boot", &wire_flow()).is_none());
    assert!(service.lookup("a", "other-boot", &wire_flow()).is_none());
    assert!(service.submit(batch(3)));
    let _ = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let json = service.diagnostics().to_string();
    assert!(!json.contains("payload"));
    assert!(!json.contains("69,69"));
}
#[test]
fn disabled_service_drops_samples_without_starting_dpi() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = SamplingService::new(
        false,
        Arc::new(TestEngine(calls.clone())),
        Arc::new(FixtureMatcher::default()),
        |_| {},
    );
    assert!(!service.submit(batch(1)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(service.diagnostics()["impact"], Value::Null);
}
#[test]
fn actual_bandwidth_not_configured_budget_drives_impact() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = SamplingService::new(
        false,
        Arc::new(TestEngine(calls)),
        Arc::new(FixtureMatcher::default()),
        |_| {},
    );
    {
        let mut stats = service.stats.lock().unwrap();
        stats.started = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .unwrap();
        let b = stats.bucket();
        b.bytes = 1000;
        b.network_bytes = 1_000_000;
        b.samples = 10;
        b.attempted = 2;
        b.identified = 1;
        b.sizes.insert(100, 10);
    }
    let d = service.diagnostics();
    assert_eq!(d["impact"], "Low");
    assert_eq!(d["dpi_success_rate"], 0.5);
    assert_eq!(d["p95_sample_bytes"], 100);
    assert_eq!(d["traffic_ratio"], 0.001);
    assert!((d["bandwidth_kbps"].as_f64().unwrap() - 0.08).abs() < 0.001);
}

#[test]
fn gateway_budgets_and_agent_drop_deltas_are_counted_once() {
    let service = SamplingService::new(
        false,
        Arc::new(TestEngine(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FixtureMatcher::default()),
        |_| {},
    );
    let mut telemetry = TelemetryBatch {
        gateway_id: "one".into(),
        boot_id: "boot".into(),
        flows: vec![FlowDelta {
            packets: 1,
            ..wire_flow()
        }],
        health: Some(netqmon_protocol::v1::AgentHealth {
            sample_config: Some(SampleConfig {
                enabled: true,
                max_bytes_per_flow: 4096,
                ..Default::default()
            }),
            dropped_samples: 3,
            dropped_sample_bytes: 120,
            ..Default::default()
        }),
        ..Default::default()
    };
    service.observe_telemetry(&telemetry);
    service.observe_telemetry(&telemetry);
    telemetry.gateway_id = "two".into();
    telemetry
        .health
        .as_mut()
        .unwrap()
        .sample_config
        .as_mut()
        .unwrap()
        .enabled = false;
    telemetry.health.as_mut().unwrap().dropped_samples = 0;
    telemetry.health.as_mut().unwrap().dropped_sample_bytes = 0;
    service.observe_telemetry(&telemetry);
    let stats = service.stats.lock().unwrap();
    let bucket = &stats.buckets.back().unwrap().1;
    assert_eq!(bucket.new_flows, 2);
    assert_eq!(bucket.theoretical_bytes, 4096);
    assert_eq!(bucket.drops, 3);
    assert_eq!(bucket.drop_bytes, 120);
}

#[test]
fn cumulative_direction_limit_and_duplicate_batches_do_not_repeat_dpi() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(TestEngine(calls.clone())),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            tx.send(result).unwrap();
        },
    );
    let mut full = batch(1);
    let packet = full.samples[0].packets[0].clone();
    full.samples[0].packets = vec![packet.clone(); 32];
    full.samples[0].total_captured_bytes = 64 * 32;
    assert!(service.submit(full.clone()));
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(service.submit(full)); // Duplicate sequence is ignored.
    assert!(service.submit(batch(2))); // Direction budget was exhausted in batch 1.
    let mut marker = batch(3);
    marker.samples[0].flow_id = "marker".into();
    marker.samples[0].key.as_mut().unwrap().client_port = 60000;
    marker.samples[0].packets.push(packet);
    marker.samples[0].total_captured_bytes = 128;
    assert!(service.submit(marker));
    let completed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(completed.key.client_port, 60000);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let diagnostics = service.diagnostics();
    assert_eq!(diagnostics["sample_drops"], 1);
    assert!((diagnostics["sample_drop_rate"].as_f64().unwrap() - 1.0 / 35.0).abs() < 1e-9);
}

struct ProgressiveEngine;
struct ProgressiveFlow(usize);
impl DpiEngine for ProgressiveEngine {
    fn name(&self) -> &'static str {
        "ndpi"
    }
    fn start(&self, _: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
        Ok(Box::new(ProgressiveFlow(0)))
    }
}
impl DpiFlow for ProgressiveFlow {
    fn classify(&mut self, packets: &[SamplePacket]) -> Option<DpiResult> {
        self.0 += packets.len();
        Some(DpiResult {
            protocol: "quic".into(),
            source: "ndpi".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::from([(
                "application_protocol".into(),
                if self.0 > 1 { "YouTube" } else { "QUIC" }.into(),
            )]),
        })
    }
    fn finish(&mut self) -> Option<DpiResult> {
        let mut result = self.classify(&[]).unwrap();
        result.metadata.insert("finalized".into(), "true".into());
        Some(result)
    }
}
#[test]
fn generic_protocol_keeps_engine_and_flow_end_finalizes() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(ProgressiveEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );
    service.submit(batch(1));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .metadata["application_protocol"],
        "QUIC"
    );
    service.submit(batch(2));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .metadata["application_protocol"],
        "YouTube"
    );
    let mut flow = wire_flow();
    flow.lifecycle = netqmon_protocol::v1::FlowLifecycle::Ended as i32;
    service.observe_telemetry(&TelemetryBatch {
        gateway_id: "a".into(),
        boot_id: "boot".into(),
        flows: vec![flow],
        ..Default::default()
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(4))
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .metadata["finalized"],
        "true"
    );
}
#[test]
fn configured_sample_budget_runs_final_detection() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(ProgressiveEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );
    service.observe_telemetry(&TelemetryBatch {
        gateway_id: "a".into(),
        health: Some(netqmon_protocol::v1::AgentHealth {
            sample_config: Some(SampleConfig {
                enabled: true,
                max_bytes_per_flow: 64,
                max_packets_per_direction: 4,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    service.submit(batch(1));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .metadata["finalized"],
        "true"
    );
}

#[test]
fn signature_matches_complete_without_a_dpi_result() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(SilentEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );
    let mut signature_batch = batch(1);
    for packet in &mut signature_batch.samples[0].packets {
        payload_with_signature(packet);
    }
    assert!(service.submit(signature_batch));

    let completed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(completed.result.is_none());
    assert_eq!(completed.signatures.len(), 1);
    assert_eq!(completed.signatures[0].application_id, "honor_of_kings");
    assert!((completed.signatures[0].confidence - 0.95).abs() < f64::EPSILON);

    let analysis = service
        .lookup("a", "boot", &wire_flow())
        .expect("analysis cached");
    assert!(analysis.dpi.is_none());
    assert_eq!(analysis.signatures.len(), 1);

    // A miss must complete with no analysis at all.
    assert!(service.submit(batch(2)));
    let analysis = service.lookup("a", "boot", &wire_flow()).unwrap();
    assert!(analysis.signatures.is_empty() || analysis.dpi.is_none());
    assert!(service.diagnostics().to_string().contains("fixture"));
}

fn payload_with_signature(packet: &mut SamplePacket) {
    let mut raw = vec![0x45, 0x00];
    let total = 20 + 20 + 8;
    raw.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 6, 0x00, 0x00]);
    raw.extend_from_slice(&[192, 0, 2, 1]);
    raw.extend_from_slice(&[198, 51, 100, 1]);
    raw.extend_from_slice(&51_000u16.to_be_bytes());
    raw.extend_from_slice(&443u16.to_be_bytes());
    raw.extend_from_slice(&[0; 8]);
    raw.push(0x50);
    raw.push(0x10);
    raw.extend_from_slice(&[0; 6]);
    raw.extend_from_slice(&[0x33, 0x66, 0x00, 0x0b, 0xff, 0xee, 0xdd, 0xcc]);
    let captured = u32::try_from(raw.len()).unwrap();
    packet.captured_length = captured;
    packet.original_length = captured;
    packet.payload = raw;
}
