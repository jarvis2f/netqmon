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

struct FinishEngine;
struct FinishFlow(u64);

impl DpiEngine for FinishEngine {
    fn name(&self) -> &'static str {
        "finish-fixture"
    }

    fn start(&self, key: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
        Ok(Box::new(FinishFlow(key.first_seen_unix_ms)))
    }
}

impl DpiFlow for FinishFlow {
    fn classify(&mut self, _: &[SamplePacket]) -> Option<DpiResult> {
        Some(DpiResult {
            protocol: "tls".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::new(),
            source: "ndpi".into(),
        })
    }

    fn finish(&mut self) -> Option<DpiResult> {
        Some(DpiResult {
            protocol: "fixture".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::from([(
                "first_seen_unix_ms".into(),
                self.0.to_string(),
            )]),
            source: "finalized".into(),
        })
    }
}

fn batch_for_window(
    sequence: u64,
    flow_id: &str,
    first_seen_unix_ms: u64,
    last_packet_ms: u64,
) -> FlowSampleBatch {
    let mut batch = batch(sequence);
    let sample = &mut batch.samples[0];
    sample.flow_id = flow_id.into();
    sample.key.as_mut().unwrap().first_seen_unix_ms = first_seen_unix_ms;
    sample.packets[0].timestamp_unix_ms = last_packet_ms;
    batch
}

fn ending_batch(
    gateway: &str,
    boot: &str,
    ip_version: u32,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
) -> TelemetryBatch {
    let mut flow = wire_flow();
    flow.ip_version = ip_version;
    flow.first_seen_unix_ms = first_seen_unix_ms;
    flow.last_seen_unix_ms = last_seen_unix_ms;
    flow.lifecycle = netqmon_protocol::v1::FlowLifecycle::Ended as i32;
    TelemetryBatch {
        gateway_id: gateway.into(),
        boot_id: boot.into(),
        flows: vec![flow],
        ..Default::default()
    }
}

fn ending_with_key_mutation(
    gateway: &str,
    boot: &str,
    mutate: impl FnOnce(&mut FlowDelta),
) -> TelemetryBatch {
    let mut batch = ending_batch(gateway, boot, 4, 1_000, 5_000);
    mutate(&mut batch.flows[0]);
    batch
}

fn cached_result(
    gateway: &str,
    boot: &str,
    first_seen_unix_ms: u64,
    last_packet_ms: u64,
    expires: Instant,
) -> CachedResult {
    let mut key = batch(1).samples.remove(0).key.unwrap();
    key.first_seen_unix_ms = first_seen_unix_ms;
    CachedResult {
        gateway: gateway.into(),
        boot: boot.into(),
        key,
        last_packet_ms,
        result: Some(DpiResult {
            protocol: "fixture".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::from([(
                "first_seen_unix_ms".into(),
                first_seen_unix_ms.to_string(),
            )]),
            source: "fixture".into(),
        }),
        signatures: Vec::new(),
        expires,
    }
}

#[test]
fn ending_index_scopes_identity_and_preserves_overlapping_time_windows() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(FinishEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );

    assert!(service.submit(batch_for_window(1, "old", 1_000, 4_000)));
    assert!(service.submit(batch_for_window(2, "reused", 3_000, 5_000)));
    for _ in 0..2 {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .unwrap()
                .result
                .unwrap()
                .source,
            "ndpi"
        );
    }

    // Markers with a different identity or outside both sample windows must
    // not finalize either reused five-tuple flow.
    service.observe_telemetry(&ending_batch("other-gateway", "boot", 4, 1_000, 5_000));
    service.observe_telemetry(&ending_batch("a", "other-boot", 4, 1_000, 5_000));
    service.observe_telemetry(&ending_batch("a", "boot", 6, 1_000, 5_000));
    service.observe_telemetry(&ending_with_key_mutation("a", "boot", |flow| {
        flow.protocol = 6;
    }));
    service.observe_telemetry(&ending_with_key_mutation("a", "boot", |flow| {
        flow.client_port += 1;
    }));
    service.observe_telemetry(&ending_with_key_mutation("a", "boot", |flow| {
        flow.remote_port += 1;
    }));
    service.observe_telemetry(&ending_with_key_mutation("a", "boot", |flow| {
        flow.client_ip[3] += 1;
    }));
    service.observe_telemetry(&ending_with_key_mutation("a", "boot", |flow| {
        flow.remote_ip[3] += 1;
    }));
    service.observe_telemetry(&ending_batch("a", "boot", 4, 6_000, 7_000));
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(1_300)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    // This interval overlaps both reused flow windows, so both finalize.
    service.observe_telemetry(&ending_batch("a", "boot", 4, 3_500, 4_500));
    let mut finalized = (0..2)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(3))
                .unwrap()
                .key
                .first_seen_unix_ms
        })
        .collect::<Vec<_>>();
    finalized.sort_unstable();
    assert_eq!(finalized, vec![1_000, 3_000]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn reused_five_tuple_only_finalizes_the_matching_time_window() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(FinishEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );

    assert!(service.submit(batch_for_window(1, "first", 1_000, 2_000)));
    assert!(service.submit(batch_for_window(2, "reused", 3_000, 4_000)));
    for _ in 0..2 {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .unwrap()
                .result
                .unwrap()
                .source,
            "ndpi"
        );
    }

    service.observe_telemetry(&ending_batch("a", "boot", 4, 1_000, 1_500));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3))
            .unwrap()
            .key
            .first_seen_unix_ms,
        1_000
    );
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(1_200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
}

#[test]
fn ending_received_before_sample_still_finalizes_after_grace_period() {
    let (tx, rx) = mpsc::channel();
    let service = SamplingService::new(
        true,
        Arc::new(FinishEngine),
        Arc::new(FixtureMatcher::default()),
        move |result| {
            let _ = tx.send(result);
        },
    );

    let ending_received = Instant::now();
    service.observe_telemetry(&ending_batch("a", "boot", 4, 1_000, 2_000));
    std::thread::sleep(ENDING_DELAY + Duration::from_millis(100));
    assert!(service.submit(batch_for_window(1, "late-sample", 1_000, 2_000)));

    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .result
            .unwrap()
            .source,
        "ndpi"
    );
    let finalized = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(finalized.result.unwrap().source, "finalized");
    assert!(ending_received.elapsed() >= ENDING_DELAY);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn ending_interval_index_preserves_one_millisecond_boundary_semantics() {
    let index = EndingIntervalIndex::new(vec![(2_001, 3_000), (500, 999)]).unwrap();
    assert!(index.overlaps(1_000, 2_000)); // Adjacent by 1ms at either edge.
    assert!(!index.overlaps(1_001, 1_999));
    assert!(index.overlaps(2_500, 2_500));

    let disjoint = EndingIntervalIndex::new(vec![(2_002, 3_000), (500, 998)]).unwrap();
    assert!(!disjoint.overlaps(1_000, 2_000));
}

#[test]
fn lookup_index_keeps_multiple_time_windows_for_one_flow_identity() {
    let service = SamplingService::new(
        false,
        Arc::new(SilentEngine),
        Arc::new(FixtureMatcher::default()),
        |_| {},
    );
    let now = Instant::now();
    {
        let mut stats = service.stats.lock().unwrap();
        assert!(stats.insert_result(
            ("a".into(), "boot".into(), "old-window".into()),
            cached_result("a", "boot", 1_000, 2_000, now + CACHE_TTL),
            now,
        ));
        assert!(stats.insert_result(
            ("a".into(), "boot".into(), "new-window".into()),
            cached_result("a", "boot", 3_000, 5_000, now + CACHE_TTL),
            now,
        ));
    }

    let mut overlapping = wire_flow();
    overlapping.first_seen_unix_ms = 1_500;
    overlapping.last_seen_unix_ms = 4_000;
    assert_eq!(
        service
            .lookup("a", "boot", &overlapping)
            .unwrap()
            .dpi
            .unwrap()
            .metadata
            .get("first_seen_unix_ms")
            .map(String::as_str),
        Some("3000")
    );
    assert!(
        service
            .lookup("other-gateway", "boot", &overlapping)
            .is_none()
    );

    let mut disjoint = wire_flow();
    disjoint.first_seen_unix_ms = 2_500;
    disjoint.last_seen_unix_ms = 2_998;
    assert!(service.lookup("a", "boot", &disjoint).is_none());
}

#[test]
fn bounded_ending_and_result_indexes_preserve_capacity_and_ttl_cleanup() {
    let now = Instant::now();
    let mut stats = Stats::default();
    for _ in 0..CACHE_CAPACITY {
        let identity = FlowIdentity {
            gateway: "gateway-shared".into(),
            boot: "boot".into(),
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
        };
        assert!(stats.insert_ending(identity, 1_000, 2_000, now));
    }
    assert_eq!(stats.ending_count, CACHE_CAPACITY);
    assert!(!stats.insert_ending(
        FlowIdentity {
            gateway: "extra".into(),
            boot: "boot".into(),
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
        },
        1_000,
        2_000,
        now,
    ));

    for index in 0..CACHE_CAPACITY {
        let gateway = format!("gateway-{index}");
        assert!(stats.insert_result(
            (gateway.clone(), "boot".into(), format!("flow-{index}")),
            cached_result(&gateway, "boot", 1_000, 2_000, now + CACHE_TTL),
            now,
        ));
    }
    assert_eq!(stats.results.len(), CACHE_CAPACITY);
    assert_eq!(stats.result_expirations.len(), CACHE_CAPACITY);
    assert!(!stats.insert_result(
        ("extra".into(), "boot".into(), "extra-flow".into()),
        cached_result("extra", "boot", 1_000, 2_000, now + CACHE_TTL),
        now,
    ));

    let expired_at = now + CACHE_TTL + Duration::from_millis(1);
    stats.next_cleanup = expired_at;
    stats.cleanup_if_due(expired_at);
    assert_eq!(stats.ending_count, 0);
    assert!(stats.endings.is_empty());
    assert!(stats.results.is_empty());
    assert!(stats.results_by_identity.is_empty());
    assert!(stats.result_expirations.is_empty());
    assert!(stats.ending_index_dirty);
    let (_, refreshed, rebuild_all) = stats.take_ending_updates();
    assert!(refreshed.is_empty());
    assert!(rebuild_all);
    assert!(stats.insert_ending(
        FlowIdentity {
            gateway: "after-ttl".into(),
            boot: "boot".into(),
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
        },
        1_000,
        2_000,
        expired_at,
    ));
}

#[test]
fn seen_flow_expiry_is_periodic_exact_and_capacity_bounded() {
    let now = Instant::now();
    let mut stats = Stats::default();
    for index in 0..SEEN_FLOWS_CAPACITY {
        assert!(stats.record_seen_flow(format!("flow-{index}"), now));
    }
    assert_eq!(stats.seen_flows.len(), SEEN_FLOWS_CAPACITY);
    assert_eq!(stats.seen_flow_expirations.len(), SEEN_FLOWS_CAPACITY);
    assert!(!stats.record_seen_flow("overflow".into(), now));

    // A live observation refreshes its TTL without counting a new flow.
    assert!(!stats.record_seen_flow("flow-0".into(), now + Duration::from_secs(1)));
    assert_eq!(stats.seen_flow_expirations.len(), SEEN_FLOWS_CAPACITY);

    // An expired identity is counted as new immediately, even while the cache
    // is full and the periodic sweep is not due yet.
    let expired_at = now + CACHE_TTL + Duration::from_secs(2);
    assert!(stats.record_seen_flow("flow-1".into(), expired_at));
    assert_eq!(stats.seen_flows.len(), SEEN_FLOWS_CAPACITY);

    // Capacity pressure drains expired entries before admitting another ID.
    assert!(stats.record_seen_flow("overflow".into(), expired_at));
    assert_eq!(stats.seen_flows.len(), 2);
    assert!(stats.seen_flows.contains_key("flow-1"));
    assert!(stats.seen_flows.contains_key("overflow"));
    assert_eq!(stats.seen_flow_expirations.len(), 2);

    // Periodic maintenance runs at 30 seconds; a not-yet-due call is a no-op.
    let cleanup_at = expired_at + Duration::from_secs(60);
    let short_id: Arc<str> = Arc::from("short-lived");
    let short_expiry = cleanup_at.checked_sub(Duration::from_nanos(1)).unwrap();
    stats.seen_flows.insert(Arc::clone(&short_id), short_expiry);
    stats.seen_flow_expirations.insert((short_expiry, short_id));
    stats.next_seen_flows_cleanup = cleanup_at;
    stats.cleanup_seen_flows_if_due(cleanup_at.checked_sub(Duration::from_nanos(1)).unwrap());
    assert!(stats.seen_flows.contains_key("short-lived"));
    stats.cleanup_seen_flows_if_due(cleanup_at);
    assert!(!stats.seen_flows.contains_key("short-lived"));
    assert_eq!(
        stats.next_seen_flows_cleanup,
        cleanup_at + SEEN_FLOWS_CLEANUP_INTERVAL
    );
}

#[test]
fn flow_and_sequence_ttl_cleanup_removes_expired_index_entries() {
    let now = Instant::now();
    let key = batch(1).samples.remove(0).key.unwrap();
    let identity = FlowIdentity::from_sample("a", "boot", &key);
    let expired_id = ("a".into(), "boot".into(), "expired".into());
    let live_id = ("a".into(), "boot".into(), "live".into());
    let mut flows = HashMap::new();
    let mut flow_index = FlowIndex::new();
    for (id, expires) in [
        (
            expired_id.clone(),
            now.checked_sub(Duration::from_millis(1)).unwrap(),
        ),
        (live_id.clone(), now + CACHE_TTL),
    ] {
        flows.insert(
            id.clone(),
            FlowState {
                key: key.clone(),
                bytes: 0,
                packets: [0, 0],
                last_packet_ms: 1_000,
                expires,
                engine: None,
                result: None,
                signatures: Vec::new(),
            },
        );
        flow_index.entry(identity.clone()).or_default().insert(id);
    }
    let expired = expired_flow_ids(&flows, now);
    assert_eq!(expired, vec![expired_id.clone()]);
    remove_flows(&expired, &mut flows, &mut flow_index);
    assert!(!flows.contains_key(&expired_id));
    assert!(flows.contains_key(&live_id));
    assert_eq!(flow_index[&identity].len(), 1);
    assert!(flow_index[&identity].contains(&live_id));

    let mut sequences = HashMap::from([
        (
            ("a".into(), "old".into()),
            (1, now.checked_sub(Duration::from_millis(1)).unwrap()),
        ),
        (("a".into(), "live".into()), (2, now + CACHE_TTL)),
    ]);
    expire_sequences(&mut sequences, now);
    assert_eq!(sequences.len(), 1);
    assert!(sequences.contains_key(&("a".into(), "live".into())));
}

#[test]
fn worker_flow_cache_stays_at_capacity_and_drops_the_next_flow() {
    let matcher_calls = Arc::new(AtomicUsize::new(0));
    let service = SamplingService::new(
        true,
        Arc::new(SilentEngine),
        Arc::new(FixtureMatcher {
            calls: matcher_calls.clone(),
        }),
        |_| {},
    );
    let mut high_capacity = batch(1);
    let template = high_capacity.samples[0].clone();
    high_capacity.samples = (0..=CACHE_CAPACITY)
        .map(|index| {
            let mut sample = template.clone();
            sample.flow_id = format!("flow-{index}");
            sample
        })
        .collect();
    assert!(service.submit(high_capacity));

    let deadline = Instant::now() + Duration::from_secs(10);
    let diagnostics = loop {
        let diagnostics = service.diagnostics();
        if diagnostics["sample_drops"].as_u64() == Some(1) {
            break diagnostics;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not process full batch"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        diagnostics["sampled_flows"].as_u64(),
        Some(CACHE_CAPACITY as u64)
    );
    assert_eq!(matcher_calls.load(Ordering::SeqCst), CACHE_CAPACITY);
}

#[test]
#[ignore = "high-capacity CPU comparison; run explicitly with --ignored --nocapture"]
#[allow(clippy::cast_precision_loss)]
fn high_capacity_indexed_matching_benchmark() {
    const COUNT: usize = CACHE_CAPACITY;
    let identity = FlowIdentity {
        gateway: "gateway-shared".into(),
        boot: "boot".into(),
        ip_version: 4,
        protocol: 17,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50_000,
        remote_ip: vec![198, 51, 100, 1],
        remote_port: 443,
    };
    let flows: Vec<(FlowIdentity, u64, u64)> = (0..COUNT)
        .map(|_| (identity.clone(), 100_000, 100_000))
        .collect();
    let mut endings: Vec<(FlowIdentity, u64, u64)> = (0..COUNT - 1)
        .map(|index| {
            let first_seen = 200_000 + u64::try_from(index).unwrap() * 4;
            (identity.clone(), first_seen, first_seen)
        })
        .collect();
    endings.push((identity.clone(), 100_000, 100_000));

    let old_started = Instant::now();
    let mut old_checks = 0_u64;
    let mut old_matches = 0;
    for (flow_identity, flow_first, flow_last) in &flows {
        for (ending_identity, ending_first, ending_last) in &endings {
            old_checks += 1;
            if flow_identity == ending_identity
                && *flow_first <= (*ending_last).saturating_add(1)
                && (*flow_last).saturating_add(1) >= *ending_first
            {
                old_matches += 1;
            }
        }
    }
    let old_elapsed = old_started.elapsed();

    let build_started = Instant::now();
    let mut ending_windows = HashMap::<FlowIdentity, Vec<(u64, u64)>>::new();
    for (identity, first, last) in endings {
        ending_windows
            .entry(identity)
            .or_default()
            .push((first, last));
    }
    let ending_indexes = ending_windows
        .into_iter()
        .filter_map(|(identity, windows)| {
            EndingIntervalIndex::new(windows).map(|index| (identity, index))
        })
        .collect::<HashMap<_, _>>();
    let index_build_elapsed = build_started.elapsed();

    let indexed_started = Instant::now();
    let mut identity_lookups = 0_u64;
    let mut indexed_matches = 0;
    let mut interval_comparisons = 0_u64;
    for (identity, first, last) in &flows {
        identity_lookups += 1;
        let Some(index) = ending_indexes.get(identity) else {
            continue;
        };
        if index.overlaps(*first, *last) {
            indexed_matches += 1;
        }
    }
    let indexed_elapsed = indexed_started.elapsed();
    let indexed_total_elapsed = index_build_elapsed + indexed_elapsed;

    for (_, first, last) in &flows {
        let index = &ending_indexes[&identity];
        let target = last.saturating_add(1);
        let mut low = 0;
        let mut high = index.starts.len();
        while low < high {
            let middle = low + (high - low) / 2;
            interval_comparisons += 1;
            if index.starts[middle] <= target {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        assert!(low > 0 && index.prefix_max_ends[low - 1].saturating_add(1) >= *first);
    }

    assert_eq!(old_matches, indexed_matches);
    assert_eq!(old_matches, COUNT);
    assert_eq!(old_checks, (COUNT * COUNT) as u64);
    assert_eq!(identity_lookups, COUNT as u64);
    eprintln!(
        "legacy: {:?}, {old_checks} pair checks, {:.0} flow queries/s; indexed: build {:?}, query {:?}, total {:?}, {identity_lookups} identity lookups + {interval_comparisons} interval comparisons, {:.0} end-to-end flow queries/s ({:.0} query-only flow queries/s)",
        old_elapsed,
        COUNT as f64 / old_elapsed.as_secs_f64(),
        index_build_elapsed,
        indexed_elapsed,
        indexed_total_elapsed,
        COUNT as f64 / indexed_total_elapsed.as_secs_f64(),
        COUNT as f64 / indexed_elapsed.as_secs_f64(),
    );
}
