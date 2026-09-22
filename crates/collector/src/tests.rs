use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use netqmon_protocol::v1::probe_result::Outcome as ProbeOutcome;
use netqmon_protocol::v1::{
    AgentHealth, CounterSanityStatus, DeviceDiscoveryObservation, Direction, DnsObservation,
    DnsRecordType, EnrollRequest, EnrollResponse, FaviconProbeResult, FlowDelta, FlowLifecycle,
    FlowScope, NatType, OffloadStatus, PathType, ProbeResult, TelemetryBatch, TopologySummary,
};
use netqmon_protocol::{PROTOCOL_VERSION, encode_telemetry_batch};
use prost::Message;
use tempfile::tempdir;
use tower::ServiceExt;

use super::*;

const ENROLLMENT_TOKEN: &str = "test-enrollment-token";

fn strong_self_host_attribution(application_id: &str) -> FlowAttribution {
    FlowAttribution {
        organization_id: "self_host_org".to_owned(),
        application_id: application_id.to_owned(),
        category_id: "streaming".to_owned(),
        application_confidence: 0.99,
        confidence: 0.99,
        reason: format!("domain_exact:{application_id}.home.arpa"),
        evidence_json: format!(
            r#"[{{"type":"self_host_application","value":"{application_id}","source":"rule","weight":0.99}}]"#
        ),
        ..FlowAttribution::default()
    }
}

#[test]
fn service_binding_reuses_full_endpoint_but_never_reverse_proxy_socket() {
    let mut cache = ServiceBindingCache {
        entries: HashMap::new(),
        ttl_ms: 60_000,
        max_entries: 16,
    };
    let endpoint = ServiceBindingKey {
        ip: "192.0.2.31".parse().unwrap(),
        protocol: 6,
        port: 8096,
    };
    let mut strong = strong_self_host_attribution("jellyfin");
    cache.apply(endpoint.clone(), None, 1_000, &mut strong);
    let mut unknown = FlowAttribution::default();
    cache.apply(endpoint, None, 2_000, &mut unknown);
    assert_eq!(unknown.application_id, "jellyfin");
    assert!(attribution_has_evidence(&unknown, "service_binding"));

    let proxy = ServiceBindingKey {
        ip: "192.0.2.20".parse().unwrap(),
        protocol: 6,
        port: 443,
    };
    let mut proxy_strong = strong_self_host_attribution("jellyfin");
    cache.apply(proxy.clone(), None, 3_000, &mut proxy_strong);
    let mut proxy_unknown = FlowAttribution::default();
    cache.apply(proxy, None, 4_000, &mut proxy_unknown);
    assert_eq!(proxy_unknown.application_id, "unknown");
}

#[test]
fn collector_schedules_and_accepts_favicon_probe_identity() {
    let mut cache = FaviconEndpointCache::default();
    let flow = FlowDelta {
        protocol: 6,
        remote_ip: vec![192, 168, 2, 31],
        remote_port: 8096,
        ..Default::default()
    };
    let batch = TelemetryBatch {
        sequence: 7,
        flows: vec![flow],
        ..Default::default()
    };
    let requests = cache.schedule(&batch, &[FlowAttribution::default()], 1_000);
    assert_eq!(requests.len(), 1);
    let digest = "2d01a6171b7ef8ffb8d1f6f9c24a9b9dc8c0186c6fbd653760ff7a34b626f8e8";
    let sha256 = digest
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    cache.observe_results(
        &repository_rule_engine(),
        &TelemetryBatch {
            sent_at: 2_000,
            probe_results: vec![ProbeResult {
                request_id: requests[0].request_id.clone(),
                observed_at_unix_ms: 2_000,
                outcome: Some(ProbeOutcome::Favicon(FaviconProbeResult {
                    target_ip: vec![192, 168, 2, 31],
                    port: 8096,
                    sha256: vec![sha256],
                })),
                status: "ok".to_owned(),
            }],
            ..Default::default()
        },
    );
    let identity = cache
        .identity(
            &ServiceBindingKey {
                ip: "192.168.2.31".parse().unwrap(),
                protocol: 6,
                port: 8096,
            },
            2_000,
        )
        .unwrap();
    assert_eq!(identity.application_id, "selfhost_jellyfin");
}

fn test_state() -> CollectorState {
    CollectorState::new(ENROLLMENT_TOKEN)
}

fn repository_rule_engine() -> crate::classifier::ClassifierHandle {
    crate::classifier::ClassifierHandle::test_default()
}

fn test_state_with_repository_rules() -> CollectorState {
    CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        repository_rule_engine(),
    )
    .unwrap()
}

fn unavailable_classifier_state() -> CollectorState {
    CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        crate::classifier::ClassifierHandle::connect(PathBuf::from(
            "/missing/netqmon-classifierd.sock",
        ))
        .unwrap(),
    )
    .unwrap()
}

fn enrollment_request(token: &str) -> Request<Body> {
    let request = EnrollRequest {
        enrollment_token: token.to_owned(),
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "test-gateway".to_owned(),
    };
    Request::builder()
        .method("POST")
        .uri("/v1/ingest/enroll")
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(request.encode_to_vec()))
        .unwrap()
}

async fn enroll_agent(router: &Router) -> EnrollResponse {
    let response = router
        .clone()
        .oneshot(enrollment_request(ENROLLMENT_TOKEN))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    EnrollResponse::decode(body).unwrap()
}

fn query_state() -> CollectorState {
    let state = test_state_with_repository_rules();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "boot-query".to_owned(),
            gateway_name: "query-router".to_owned(),
        })
        .unwrap();
    let timestamp = 1_700_000_000_000;
    let batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        device_observations: vec![netqmon_protocol::v1::DeviceObservation {
            mac: vec![2, 0, 0, 0, 0, 1],
            ip: vec![192, 0, 2, 10],
            hostname: "laptop".to_owned(),
            last_seen_unix_ms: timestamp,
            dhcp: None,
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
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            scope: FlowScope::Internet as i32,
            path_type: PathType::Forwarded as i32,
            nat: NatType::Snat as i32,
            source_segment: "192.0.2.0/24".to_owned(),
            destination_segment: "internet".to_owned(),
            ..FlowDelta::default()
        }],
        health: Some(AgentHealth {
            observed_at_unix_ms: timestamp,
            uptime_seconds: 3_600,
            dropped_batches: 2,
            dns_dropped_events: 1,
            tracked_flows: 1,
            kernel_version: "6.6.73".to_owned(),
            openwrt_version: "24.10.0".to_owned(),
            hardware_flow_offload: OffloadStatus::Enabled as i32,
            capture_interface: "br-lan".to_owned(),
            interface_counter_sanity: CounterSanityStatus::Ok as i32,
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    state
}

fn sample_batch(gateway_id: &str, sequence: u64) -> TelemetryBatch {
    TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        boot_id: "boot-1".to_owned(),
        sequence,
        sent_at: 1_700_000_000_000 + sequence,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            upload_bytes: 100,
            download_bytes: 50,
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    }
}

#[tokio::test]
async fn discovery_only_device_accumulates_evidence_and_field_confidence() {
    let state = test_state_with_repository_rules();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "discovery-boot".to_owned(),
            gateway_name: "router".to_owned(),
        })
        .unwrap();
    for sequence in 1..=2 {
        let observed_at = 1_700_000_000_000 + sequence;
        let batch = TelemetryBatch {
            gateway_id: enrollment.gateway_id.clone(),
            boot_id: "discovery-boot".to_owned(),
            sequence,
            sent_at: observed_at,
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            device_discovery_observations: vec![DeviceDiscoveryObservation {
                mac: vec![0, 1, 2, 3, 4, 5],
                ip: vec![192, 0, 2, 50],
                protocol: "mdns".to_owned(),
                service: "_ipp._tcp.local".to_owned(),
                instance: "Office Printer._ipp._tcp.local".to_owned(),
                hostname: "printer.local".to_owned(),
                port: 631,
                attributes: [("md".to_owned(), "LaserJet".to_owned())].into(),
                observed_at_unix_ms: observed_at,
            }],
            ..TelemetryBatch::default()
        };
        assert_eq!(
            state.accept_batch(&batch).unwrap(),
            BatchDisposition::Accepted
        );
    }

    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/clients?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"][0]["last_traffic_seen"].is_null());
    let identity = &json["data"][0]["identity"];
    assert_eq!(identity["device_type"], "printer");
    assert!(identity["device_type_confidence"].as_f64().unwrap() > 0.9);
    assert!(
        identity["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["hit_count"] == 2)
    );
}

fn telemetry_request(batch: &TelemetryBatch, token: &str) -> Request<Body> {
    let encoded = encode_telemetry_batch(batch, 1).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/ingest/telemetry")
        .header(CONTENT_TYPE, "application/x-protobuf")
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(encoding) = encoded.encoding.http_value() {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    builder.body(Body::from(encoded.body)).unwrap()
}

#[tokio::test]
async fn public_and_internal_health_routes_are_available() {
    let state = test_state();
    for uri in ["/health", "/v1/ingest/health"] {
        let response = public_router(state.clone())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unavailable_classifier_keeps_ingestion_healthy_and_strict_apis_return_503() {
    let state = unavailable_classifier_state();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "missing-classifier".to_owned(),
            gateway_name: "test-gateway".to_owned(),
        })
        .unwrap();
    let batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "missing-classifier".to_owned(),
        sequence: 1,
        sent_at: 1_700_000_000_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            remote_ip: vec![203, 0, 113, 10],
            remote_port: 443,
            last_seen_unix_ms: 1_700_000_000_000,
            ..Default::default()
        }],
        ..Default::default()
    };

    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );

    let health = public_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let router = internal_router(state);
    let strict = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/rules/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(strict.status(), StatusCode::SERVICE_UNAVAILABLE);

    let diagnostics = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(
        json["data"]["classification"]["availability"],
        "unavailable"
    );
}

#[tokio::test]
async fn late_start_classifier_recovers_and_switches_to_ready() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("classifier.sock");

    // 1. Collector connects to socket before classifier exists
    let classifier = crate::classifier::ClassifierHandle::connect(socket_path.clone()).unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        classifier.clone(),
    )
    .unwrap();

    // 2. Health fails and diagnostics shows unavailable
    assert!(classifier.health().is_err());
    let router = internal_router(state);
    let diagnostics = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(
        json["data"]["classification"]["availability"],
        "unavailable"
    );

    // 3. Late start: Classifier UnixListener binds socket
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let server_handle = std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            while let Ok(n) = std::io::BufRead::read_line(&mut reader, &mut line) {
                if n == 0 {
                    break;
                }
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let req_id = req
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("test")
                    .to_owned();
                let resp = match req.get("type").and_then(|v| v.as_str()) {
                    Some("rule_stats") => netqmon_classifier_client::ServerResponse::RuleStats {
                        request_id: req_id,
                        stats: netqmon_classifier_client::RuleStats {
                            rule_version: "inline-test".to_owned(),
                            ..Default::default()
                        },
                    },
                    Some("version") => netqmon_classifier_client::ServerResponse::Version {
                        request_id: req_id,
                        version: netqmon_classifier_client::ClassifierVersion {
                            version: "inline-test".to_owned(),
                            build: None,
                        },
                    },
                    _ => netqmon_classifier_client::ServerResponse::Health {
                        request_id: req_id,
                        health: netqmon_classifier_client::ClassifierHealth {
                            ready: true,
                            detail: None,
                        },
                    },
                };
                use std::io::Write as _;
                writeln!(writer, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
                writer.flush().unwrap();
                line.clear();
            }
        }
    });

    // Wait until probe backoff passes (initial delay is 1s)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // 4. Probing classifier now succeeds and transitions to ready
    assert!(classifier.health().is_ok());

    let diagnostics = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = parse_json(diagnostics).await;
    assert_eq!(json["data"]["classification"]["availability"], "ready");

    drop(server_handle);
}

#[tokio::test]
async fn realtime_sse_sends_initial_snapshot_after_every_reconnect() {
    let router = internal_router(query_state());
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/realtime/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/event-stream"
        );
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&first);
        assert!(text.contains("event: snapshot"));
        assert!(text.contains("\"generated_at\""));
    }
}

#[tokio::test]
async fn internal_query_api_covers_all_core_resources_with_stable_schema() {
    let router = internal_router(query_state());
    for uri in [
        "/internal/overview?limit=10&offset=0",
        "/internal/traffic?from=1699999999000&to=1700000061000&limit=10&offset=0",
        "/internal/traffic?from=1699999999000&to=1700000061000&group_by=client&limit=10",
        "/internal/clients?limit=10&offset=0",
        "/internal/clients/1?limit=10&offset=0",
        "/internal/clients/1/traffic?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/applications?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/domains?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/destinations?from=1699999999000&to=1700000061000&limit=10",
        "/internal/clients/1/flows?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications?limit=10&offset=0",
        "/internal/applications/unknown?limit=10&offset=0",
        "/internal/applications/unknown/traffic?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/clients?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/domains?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/destinations?from=1699999999000&to=1700000061000&limit=10",
        "/internal/applications/unknown/flows?from=1699999999000&to=1700000061000&limit=10",
        "/internal/domains?limit=10&offset=0",
        "/internal/destinations?limit=10&offset=0",
        "/internal/insights?from=1699999980000&to=1700000061000&limit=10",
        "/internal/flows?limit=10",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], 1, "{uri}");
        assert!(value.get("data").is_some(), "{uri}");
        assert!(value.get("pagination").is_some(), "{uri}");
    }
}

#[tokio::test]
async fn client_queries_expose_last_traffic_seen_separately_from_discovery() {
    let router = internal_router(query_state());

    let list = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/clients?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(list.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        list_json["data"][0]["last_traffic_seen"],
        serde_json::json!(1_700_000_000_000_i64)
    );

    let detail = router
        .oneshot(
            Request::builder()
                .uri("/internal/clients/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let detail_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(detail.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        detail_json["data"]["client"]["last_traffic_seen"],
        serde_json::json!(1_700_000_000_000_i64)
    );
}

#[tokio::test]
async fn application_detail_filters_duplicate_unknown_rows_by_category() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_application_minute
                 (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
                 VALUES (1700000000000, ?1, 'unknown', 'communication', 900, 1100, 20, 2)",
                [&gateway_id],
            )
            .unwrap();
    }

    let router = internal_router(state);
    let detail = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown?category=communication")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(detail["data"]["application_id"], "unknown");
    assert_eq!(detail["data"]["category_id"], "communication");
    assert_eq!(detail["data"]["upload_bytes"], 900);
    assert_eq!(detail["data"]["download_bytes"], 1100);

    let traffic = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown/traffic?category=communication&from=1699999999000&to=1700000001000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(traffic["data"]["points"].as_array().unwrap().len(), 1);
    assert_eq!(traffic["data"]["points"][0]["upload_bytes"], 900);
    assert_eq!(traffic["data"]["points"][0]["download_bytes"], 1100);
}

#[tokio::test]
async fn unknown_application_does_not_associate_organization_from_flow_sessions() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_application_minute
                 (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
                 VALUES (1700000000000, ?1, 'unknown', 'web', 500, 500, 10, 1)",
                [&gateway_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO flow_sessions
                 (id, gateway_id, ip_version, protocol, client_ip, client_port, remote_ip, remote_port,
                  direction, application_id, category_id, organization_id, upload_bytes, download_bytes,
                  packets, started_at, last_seen_at, checkpointed_at)
                 VALUES ('flow-apple-unknown', ?1, 4, 6, X'C000020A', 50001, X'C6336401', 443,
                         1, 'unknown', 'web', 'apple', 500, 500, 10, 1700000000000, 1700000000000, 1700000000000)",
                [&gateway_id],
            )
            .unwrap();
    }

    let router = internal_router(state);
    let list_response = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/applications?limit=50&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let items = list_response["data"].as_array().unwrap();
    let unknown_app = items
        .iter()
        .find(|item| item["application_id"] == "unknown")
        .expect("unknown application item");
    assert!(
        unknown_app["organization_id"].is_null(),
        "unknown application should have null organization_id, got {:?}",
        unknown_app["organization_id"]
    );
    assert!(
        unknown_app["organization_name"].is_null(),
        "unknown application should have null organization_name, got {:?}",
        unknown_app["organization_name"]
    );

    let detail_response = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/applications/unknown?category=web")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(detail_response["data"]["application_id"], "unknown");
    assert_eq!(detail_response["data"]["organization_id"], "unknown");
    assert!(detail_response["data"]["organization_name"].is_null());
}

#[tokio::test]
async fn traffic_scope_and_direction_filter_metrics_chart_and_breakdown_together() {
    let state = query_state();
    {
        let inner = state.lock();
        let connection = inner.storage.connection();
        let gateway_id: String = connection
            .query_row("SELECT id FROM gateways LIMIT 1", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_scope_minute(
                timestamp, gateway_id, scope, direction, device_id, application_id,
                category_id, domain, remote_ip, protocol, protocol_id, upload_bytes, download_bytes, packets, flow_count
             ) VALUES (?1, ?2, ?3, ?4, 1, 'internal-test', 'network', 'unknown',
                       X'C0000214', 17, 'wireguard', 0, 800, 7, 1)",
                rusqlite::params![
                    1_700_000_000_000_i64,
                    gateway_id,
                    FlowScope::Internal as i32,
                    Direction::Download as i32
                ],
            )
            .unwrap();
    }
    let router = internal_router(state);
    let internet = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=none")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(internet["data"]["scope"], "internet");
    assert_eq!(internet["data"]["points"][0]["upload_bytes"], 100);

    let internal_download = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=application&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_download["data"]["direction"], "download");
    assert_eq!(
        internal_download["data"]["points"][0]["download_bytes"],
        800
    );
    assert_eq!(
        internal_download["data"]["breakdown"][0]["id"],
        "internal-test"
    );
    assert_eq!(internal_download["data"]["breakdown"][0]["upload_bytes"], 0);

    let internal_l7 = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol_l7&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_l7["data"]["group_by"], "protocol_l7");
    assert_eq!(internal_l7["data"]["breakdown"][0]["id"], "wireguard");
    assert_eq!(internal_l7["data"]["breakdown"][0]["download_bytes"], 800);

    let internal_l4 = parse_json(router.clone().oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol_l4&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_l4["data"]["group_by"], "protocol_l4");
    assert_eq!(internal_l4["data"]["breakdown"][0]["id"], "udp");
    assert_eq!(internal_l4["data"]["breakdown"][0]["name"], "UDP");
    assert_eq!(internal_l4["data"]["breakdown"][0]["download_bytes"], 800);

    let internal_alias = parse_json(router.oneshot(Request::builder()
        .uri("/internal/traffic?from=1699999980000&to=1700000061000&group_by=protocol&scope=internal&direction=download")
        .body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!(internal_alias["data"]["group_by"], "protocol_l7");
    assert_eq!(internal_alias["data"]["breakdown"][0]["id"], "wireguard");
}

#[tokio::test]
async fn insights_report_new_devices_with_explainable_evidence() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = parse_json(response).await;
    let item = &value["data"][0];
    assert_eq!(item["category"], "device");
    assert_eq!(item["code"], "device.new_device");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "device-discovery");
    assert_eq!(item["time"], 1_700_000_000_000_i64);
    assert_eq!(item["affected_client"]["name"], "laptop");
    assert_eq!(item["evidence"]["mac"], "02:00:00:00:00:01");
}

#[tokio::test]
async fn insights_expose_the_unknown_application_ratio_and_rule_basis() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "classification.unknown_ratio_high")
        .unwrap();
    assert_eq!(item["category"], "classification");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier");
    assert_eq!(item["evidence"]["unknown_bytes"], 150);
    assert_eq!(item["evidence"]["total_bytes"], 150);
    assert_eq!(item["evidence"]["rule"], "application_id = unknown");
}

#[tokio::test]
async fn insights_infer_encrypted_dns_without_claiming_a_domain() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_001_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_001,
            remote_ip: vec![1, 1, 1, 1],
            remote_port: 443,
            direction: 1,
            upload_bytes: 200,
            packets: 2,
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "dns.encrypted_dns_detected")
        .unwrap();
    assert_eq!(item["category"], "dns");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "flow-rules");
    assert_eq!(item["evidence"]["rule"], "known_doh_provider");
    assert_eq!(item["evidence"]["provider"], "Cloudflare");
    assert!(item["evidence"]["domain"].is_null());
    assert_eq!(
        item["evidence"]["domain_limit"],
        "Encrypted DNS contents are not visible"
    );
}

#[tokio::test]
async fn insights_correlate_private_tracker_and_bittorrent_peer_activity() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_002_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: timestamp,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation")
        .unwrap();
    assert_eq!(item["category"], "protocol");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier-correlation");
    assert_eq!(item["affected_client"]["name"], "laptop");
    assert_eq!(item["evidence"]["tracker_role"], "tracker_service");
    assert_eq!(item["evidence"]["peer_protocol"], "bittorrent");
    assert_eq!(item["evidence"]["action"], "observation_only");
}

#[tokio::test]
async fn pt_correlation_within_30_minutes_succeeds() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let tracker_time = 1_700_000_002_000;
    let peer_time = tracker_time + 20 * 60 * 1000; // 20 minutes later
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: peer_time,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: tracker_time,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: tracker_time,
                last_seen_unix_ms: tracker_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: peer_time,
                last_seen_unix_ms: peer_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/internal/insights?from=1699999980000&to={}&limit=20",
                    peer_time + 60000
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation");
    assert!(item.is_some());
}

#[tokio::test]
async fn pt_correlation_beyond_30_minutes_fails() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let tracker_time = 1_700_000_002_000;
    let peer_time = tracker_time + 120 * 60 * 1000; // 2 hours later
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: peer_time,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 10],
            domain: "tracker.hdtime.org".to_owned(),
            answer_ip: vec![203, 0, 113, 10],
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: tracker_time,
        }],
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_010,
                remote_ip: vec![203, 0, 113, 10],
                remote_port: 443,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: tracker_time,
                last_seen_unix_ms: tracker_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_011,
                remote_ip: vec![203, 0, 113, 11],
                remote_port: 51_413,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: peer_time,
                last_seen_unix_ms: peer_time,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    state
        .sampling
        .seed_for_test(&batch, &batch.flows[1], "bittorrent");
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/internal/insights?from=1699999980000&to={}&limit=20",
                    peer_time + 60000
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.p2p_tracker_correlation");
    assert!(item.is_none());
}

#[tokio::test]
async fn l2tp_ipsec_correlation_reports_l2tp_and_ipsec_evidence() {
    let state = query_state();
    let gateway_id = state.lock().gateway.as_ref().unwrap().gateway_id.clone();
    let timestamp = 1_700_000_002_000;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![
            FlowDelta {
                ip_version: 4,
                protocol: 17,
                client_ip: vec![192, 0, 2, 10],
                client_port: 50_020,
                remote_ip: vec![203, 0, 113, 20],
                remote_port: 1701,
                direction: 1,
                upload_bytes: 100,
                download_bytes: 200,
                packets: 3,
                first_seen_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
            FlowDelta {
                ip_version: 4,
                protocol: 50,
                client_ip: vec![192, 0, 2, 10],
                client_port: 0,
                remote_ip: vec![203, 0, 113, 20],
                remote_port: 0,
                direction: 1,
                upload_bytes: 300,
                download_bytes: 400,
                packets: 4,
                first_seen_unix_ms: timestamp + 1_000,
                last_seen_unix_ms: timestamp + 1_000,
                lifecycle: FlowLifecycle::Ended as i32,
                client_mac: vec![2, 0, 0, 0, 0, 1],
                ..FlowDelta::default()
            },
        ],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let item = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "protocol.l2tp_ipsec_detected")
        .unwrap();
    assert_eq!(item["category"], "protocol");
    assert!(item.get("title").is_none());
    assert!(item.get("reason").is_none());
    assert_eq!(item["source"], "classifier-correlation");
    assert_eq!(item["evidence"]["remote_ip"], "203.0.113.20");
    assert_eq!(item["evidence"]["l2tp_flows"], 1);
    assert_eq!(item["evidence"]["esp_flows"], 1);
}

#[tokio::test]
async fn l2tp_ipsec_correlation_ignores_l2tp_without_ipsec_evidence() {
    let timestamp = 1_700_000_002_000;
    let l2tp_only = query_state();
    let gateway_id = l2tp_only
        .lock()
        .gateway
        .as_ref()
        .unwrap()
        .gateway_id
        .clone();
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 17,
            client_ip: vec![192, 0, 2, 10],
            client_port: 50_020,
            remote_ip: vec![203, 0, 113, 21],
            remote_port: 1701,
            direction: 1,
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
            first_seen_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            ..FlowDelta::default()
        }],
        ..TelemetryBatch::default()
    };
    assert_eq!(
        l2tp_only.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let response = internal_router(l2tp_only)
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    assert!(
        value["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["code"] != "protocol.l2tp_ipsec_detected")
    );
}

#[tokio::test]
async fn organization_and_protocol_apis_coalesce_historical_nulls_to_unknown() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE flow_sessions SET organization_id = NULL, protocol_id = NULL",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    for uri in [
        "/internal/organizations?limit=10",
        "/internal/protocols?limit=10",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let value = parse_json(response).await;
        assert_eq!(value["data"][0]["id"], "unknown", "{uri}");
        assert_eq!(value["data"][0]["name"], "unknown", "{uri}");
    }
}

#[test]
fn insights_flag_high_upload_from_recent_history_without_blocking() {
    let state = query_state();
    let inner = state.lock();
    let items = crate::insights::traffic::query_high_upload_insights(
        inner.storage.connection(),
        crate::insights::InsightWindow {
            from: 1_699_999_980_000,
            to: 1_700_000_061_000,
            limit: 10,
        },
        100,
    )
    .unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item.code, "traffic.high_upload");
    assert_eq!(item.category, "traffic");
    assert_eq!(item.source, "traffic-history");
    assert_eq!(item.evidence["upload_bytes"], 100);
    assert_eq!(item.evidence["threshold_bytes"], 100);
    assert_eq!(item.evidence["action"], "observation_only");
}

#[tokio::test]
async fn insights_explain_each_capture_quality_warning() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=20")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value = parse_json(response).await;
    let items = value["data"].as_array().unwrap();
    let codes = items
        .iter()
        .map(|item| item["code"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert!(codes.contains("capture.hardware_flow_offload"));
    assert!(codes.contains("capture.dns_event_drops"));
    assert!(codes.contains("capture.telemetry_queue_drops"));
    assert!(codes.contains("capture.collector_lag"));
    for item in items {
        assert!(item.get("title").is_none());
        assert!(item.get("reason").is_none());
        assert!(item.get("time").is_some());
        assert!(item.get("source").is_some());
        assert!(item.get("category").is_some());
        assert!(item.get("code").is_some());
        assert!(item.get("params").is_some());
        assert!(item.get("evidence").is_some());
        if item["code"].as_str().unwrap().starts_with("capture.") {
            assert_eq!(item["category"], "capture");
        }
    }
}

#[tokio::test]
async fn topology_health_is_exposed_in_diagnostics_and_insights() {
    let state = query_state();
    let gateway_id = state.lock().storage.gateway().unwrap().unwrap().id;
    let batch = TelemetryBatch {
        gateway_id,
        boot_id: "boot-query".to_owned(),
        sequence: 2,
        sent_at: 1_700_000_001_000,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        health: Some(AgentHealth {
            observed_at_unix_ms: 1_700_000_001_000,
            capture_interface: "br-lan".to_owned(),
            topology: Some(TopologySummary {
                topology_mode: "one-arm-router".to_owned(),
                agent_addresses: vec!["192.0.2.8".to_owned()],
                upstream_gateway: "192.0.2.1".to_owned(),
                ipv4_coverage: "full".to_owned(),
                ipv6_coverage: "partial".to_owned(),
                icmp_redirect: "enabled".to_owned(),
                software_flow_offload: OffloadStatus::Enabled as i32,
                hardware_flow_offload: OffloadStatus::Disabled as i32,
                confidence: 60,
                topology_warnings: vec!["Asymmetric routing suspected".to_owned()],
                ..TopologySummary::default()
            }),
            ..AgentHealth::default()
        }),
        ..TelemetryBatch::default()
    };
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    let router = internal_router(state);
    let diagnostics = parse_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/settings/diagnostics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        diagnostics["data"]["topology"]["topology_mode"],
        "one-arm-router"
    );
    assert_eq!(
        diagnostics["data"]["topology"]["capture_interface"],
        "br-lan"
    );

    let insights = parse_json(
        router
            .oneshot(
                Request::builder()
                    .uri("/internal/insights?from=1699999980000&to=1700000061000&limit=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let codes = insights["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["code"].as_str())
        .collect::<std::collections::HashSet<_>>();
    assert!(codes.contains("capture.icmp_redirect_enabled"));
    assert!(codes.contains("capture.ipv6_coverage"));
    assert!(codes.contains("capture.software_flow_offload"));
    assert!(codes.contains("capture.topology_confidence"));
    assert!(codes.contains("capture.asymmetric_routing"));
}

#[tokio::test]
async fn destinations_include_identity_traffic_clients_and_geo_placeholders() {
    let response = internal_router(query_state())
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let destination = &value["data"][0];
    assert_eq!(destination["remote_ip"], "198.51.100.1");
    assert_eq!(destination["client_count"], 1);
    assert_eq!(destination["flow_count"], 1);
    assert_eq!(destination["upload_bytes"], 100);
    assert_eq!(destination["download_bytes"], 50);
    assert!(destination.get("domain").is_some());
    assert!(destination.get("country_code").is_some());
    assert!(destination.get("asn").is_some());
    assert!(destination.get("organization").is_some());
}

#[derive(Debug)]
struct TestGeoProvider;

impl GeoProvider for TestGeoProvider {
    fn lookup(&self, ip: IpAddr) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        self.lookup_with_lang(ip, None)
    }

    fn lookup_with_lang(
        &self,
        ip: IpAddr,
        lang: Option<&str>,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        let country_name = if let Some(l) = lang {
            if l.starts_with("zh") {
                "美国"
            } else {
                "United States"
            }
        } else {
            "United States"
        };
        Ok(
            (ip == "198.51.100.1".parse::<IpAddr>().unwrap()).then(|| netqmon_geo::GeoRecord {
                country_code: Some("US".to_owned()),
                country_name: Some(country_name.to_owned()),
                region: Some("California".to_owned()),
                city: Some("Los Angeles".to_owned()),
                latitude: Some(34.0522),
                longitude: Some(-118.2437),
                asn: Some(64_496),
                organization: Some("Example Network".to_owned()),
            }),
        )
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct CountingAsnGeoProvider {
    asns: HashMap<IpAddr, u32>,
    failures: std::collections::HashSet<IpAddr>,
    calls: std::sync::Mutex<HashMap<IpAddr, usize>>,
}

impl CountingAsnGeoProvider {
    fn new(
        asns: impl IntoIterator<Item = (IpAddr, u32)>,
        failures: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            asns: asns.into_iter().collect(),
            failures: failures.into_iter().collect(),
            calls: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn call_count(&self, ip: IpAddr) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}

impl GeoProvider for CountingAsnGeoProvider {
    fn lookup(&self, ip: IpAddr) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        *self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(ip)
            .or_default() += 1;
        if self.failures.contains(&ip) {
            return Err(netqmon_geo::GeoError::new("test lookup failure"));
        }
        Ok(self
            .asns
            .get(&ip)
            .copied()
            .map(|asn| netqmon_geo::GeoRecord {
                asn: Some(asn),
                ..Default::default()
            }))
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct AsnClassifierRequest {
    domain: Option<String>,
    remote_ip: Option<String>,
    remote_asn: Option<u32>,
    has_dpi: bool,
}

fn spawn_asn_classifier_server(
    socket_path: PathBuf,
    expected_requests: usize,
) -> std::thread::JoinHandle<Vec<AsnClassifierRequest>> {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::os::unix::net::UnixListener::bind(socket_path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        let mut observed = Vec::new();

        for _ in 0..expected_requests {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            let netqmon_classifier_client::ClientRequest::ClassifyBatch {
                request_id,
                request,
            } = serde_json::from_str(&line).unwrap()
            else {
                panic!("collector must use classify_batch IPC");
            };
            let entries = request
                .entries
                .into_iter()
                .map(|entry| {
                    observed.push(AsnClassifierRequest {
                        domain: entry.domain.clone(),
                        remote_ip: entry.remote_ip.clone(),
                        remote_asn: entry.remote_asn,
                        has_dpi: entry.dpi_evidence.is_some(),
                    });
                    let asn = entry.remote_asn;
                    let suffix = asn.unwrap_or_default();
                    netqmon_classifier_client::ClassificationResult {
                        entry_id: entry.entry_id,
                        organization: asn.map(|_| netqmon_classifier_client::ClassifiedEntity {
                            id: format!("asn-org-{suffix}"),
                            confidence: 0.91,
                        }),
                        application: asn.map(|_| netqmon_classifier_client::ClassifiedEntity {
                            id: format!("asn-app-{suffix}"),
                            confidence: 0.92,
                        }),
                        traffic_class: asn.map(|_| netqmon_classifier_client::ClassifiedEntity {
                            id: "test-asn".to_owned(),
                            confidence: 0.9,
                        }),
                        traffic_role: None,
                        protocol: entry.dpi_evidence.as_ref().map(|_| {
                            netqmon_classifier_client::ClassifiedEntity {
                                id: "late-dpi".to_owned(),
                                confidence: 0.95,
                            }
                        }),
                        evidence: asn
                            .map(|value| {
                                vec![netqmon_classifier_client::ClassificationEvidence {
                                    evidence_type: "remote_asn".to_owned(),
                                    value: value.to_string(),
                                    source: "test-geo".to_owned(),
                                    weight: 0.92,
                                }]
                            })
                            .unwrap_or_default(),
                        device_evidence: Vec::new(),
                        error: None,
                    }
                })
                .collect();
            let response = netqmon_classifier_client::ServerResponse::ClassificationBatch {
                request_id,
                result: netqmon_classifier_client::ClassificationBatchResult { entries },
            };
            writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        observed
    })
}

fn asn_test_flow(remote_ip: Vec<u8>, client_port: u32, timestamp: u64) -> FlowDelta {
    FlowDelta {
        ip_version: u32::try_from(if remote_ip.len() == 4 { 4 } else { 6 }).unwrap(),
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port,
        remote_ip,
        remote_port: 443,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        ..Default::default()
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn collector_forwards_batch_local_geo_asns_to_classifier_and_late_dpi() {
    let temp = tempfile::tempdir().unwrap();
    let socket_path = temp.path().join("asn-classifier.sock");
    let server = spawn_asn_classifier_server(socket_path.clone(), 11);
    let classifier = crate::classifier::ClassifierHandle::connect(socket_path).unwrap();
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        classifier,
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "test".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "asn-test".to_owned(),
            gateway_name: "asn-test".to_owned(),
        })
        .unwrap();
    let v4: IpAddr = "203.0.113.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    let missed: IpAddr = "198.51.100.10".parse().unwrap();
    let failed: IpAddr = "2001:db8::bad".parse().unwrap();
    let v4_bytes = vec![203, 0, 113, 10];
    let v6_bytes = "2001:db8::10"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    let failed_bytes = "2001:db8::bad"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    let primary_geo = Arc::new(CountingAsnGeoProvider::new(
        [(v4, 64_512), (v6, 64_513)],
        [failed],
    ));
    state.lock().geo_provider = primary_geo.clone();

    let timestamp = 1_700_000_000_000;
    let initial = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 0, 2, 1],
            domain: "generic.cdn.test".to_owned(),
            answer_ip: v6_bytes.clone(),
            record_type: DnsRecordType::Aaaa as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: timestamp,
        }],
        flows: vec![
            asn_test_flow(v4_bytes.clone(), 50_001, timestamp),
            asn_test_flow(v4_bytes.clone(), 50_002, timestamp),
            asn_test_flow(v6_bytes.clone(), 50_003, timestamp),
            asn_test_flow(vec![198, 51, 100, 10], 50_004, timestamp),
            asn_test_flow(vec![198, 51, 100, 10], 50_005, timestamp),
            asn_test_flow(failed_bytes.clone(), 50_006, timestamp),
            asn_test_flow(failed_bytes.clone(), 50_007, timestamp),
        ],
        ..Default::default()
    };
    assert_eq!(
        state.accept_batch(&initial).unwrap(),
        BatchDisposition::Accepted
    );
    assert_eq!(primary_geo.call_count(v4), 1);
    assert_eq!(primary_geo.call_count(v6), 1);
    assert_eq!(primary_geo.call_count(missed), 1);
    assert_eq!(primary_geo.call_count(failed), 1);

    let (organization, application, evidence): (String, String, String) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT organization_id, application_id, classification_evidence_json FROM flow_sessions WHERE client_port=50001",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(organization, "asn-org-64512");
    assert_eq!(application, "asn-app-64512");
    assert!(evidence.contains("remote_asn"));
    assert!(evidence.contains("64512"));

    let second = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 2,
        sent_at: timestamp + 1,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![asn_test_flow(v4_bytes.clone(), 50_008, timestamp + 1)],
        ..Default::default()
    };
    state.accept_batch(&second).unwrap();
    assert_eq!(primary_geo.call_count(v4), 2, "ASN cache is batch-local");

    let replacement_geo = Arc::new(CountingAsnGeoProvider::new(
        [(v4, 64_514), (v6, 64_515)],
        [],
    ));
    state.lock().geo_provider = replacement_geo.clone();
    let replacement = TelemetryBatch {
        gateway_id: enrollment.gateway_id.clone(),
        boot_id: "asn-test".to_owned(),
        sequence: 3,
        sent_at: timestamp + 2,
        agent_version: "test".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows: vec![asn_test_flow(v4_bytes, 50_009, timestamp + 2)],
        ..Default::default()
    };
    state.accept_batch(&replacement).unwrap();
    assert_eq!(replacement_geo.call_count(v4), 1);
    let replacement_application: String = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT application_id FROM flow_sessions WHERE client_port=50009",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(replacement_application, "asn-app-64514");

    let late = dpi::CachedResult::for_test(
        enrollment.gateway_id,
        "asn-test".to_owned(),
        netqmon_protocol::v1::FlowSampleKey {
            ip_version: 6,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_003,
            remote_ip: v6_bytes,
            remote_port: 443,
            first_seen_unix_ms: timestamp,
        },
        timestamp + 3,
        Some(dpi::engine::DpiResult {
            protocol: "tls".to_owned(),
            confidence: 0.9,
            metadata: std::collections::BTreeMap::from([(
                "hostname".to_owned(),
                "sni.example.test".to_owned(),
            )]),
            source: "ndpi".to_owned(),
        }),
    );
    apply_sample_result(&mut state.lock(), &late).unwrap();
    let (protocol, late_evidence): (String, String) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT protocol_id, classification_evidence_json FROM flow_sessions WHERE client_port=50003",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(protocol, "late-dpi");
    assert!(late_evidence.contains("64515"));

    let requests = server.join().unwrap();
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("203.0.113.10") && request.remote_asn == Some(64_512)
    }));
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("2001:db8::10")
            && request.remote_asn == Some(64_515)
            && request.has_dpi
    }));
    assert!(requests.iter().any(|request| {
        request.domain.as_deref() == Some("sni.example.test")
            && request.remote_asn == Some(64_515)
            && request.has_dpi
    }));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.remote_ip.as_deref() == Some("198.51.100.10"))
            .filter(|request| request.remote_asn.is_none())
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.remote_ip.as_deref() == Some("2001:db8::bad"))
            .filter(|request| request.remote_asn.is_none())
            .count(),
        2
    );
    assert!(requests.iter().any(|request| {
        request.remote_ip.as_deref() == Some("203.0.113.10") && request.remote_asn == Some(64_514)
    }));
}

#[tokio::test]
async fn destinations_are_enriched_by_the_configured_geo_provider() {
    let state = query_state();
    state.lock().geo_provider = Arc::new(TestGeoProvider);

    // Test default language
    let response = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let destination = &value["data"][0];
    assert_eq!(destination["country_code"], "US");
    assert_eq!(destination["country_name"], "United States");
    assert_eq!(destination["region"], "California");
    assert_eq!(destination["city"], "Los Angeles");
    assert_eq!(destination["latitude"], 34.0522);
    assert_eq!(destination["longitude"], -118.2437);
    assert_eq!(destination["asn"], 64_496);
    assert_eq!(destination["organization"], "Example Network");

    // Test with ?lang=zh-CN
    let response_zh = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/destinations?limit=10&lang=zh-CN")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_zh.status(), StatusCode::OK);
    let body_zh = to_bytes(response_zh.into_body(), 16 * 1024).await.unwrap();
    let value_zh: serde_json::Value = serde_json::from_slice(&body_zh).unwrap();
    assert_eq!(value_zh["data"][0]["country_name"], "美国");
}

#[tokio::test]
async fn geo_summary_aggregates_country_and_asn_traffic() {
    let state = query_state();
    state.lock().geo_provider = Arc::new(TestGeoProvider);
    let response = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], true);
    assert_eq!(value["data"]["top_countries"][0]["country_code"], "US");
    assert_eq!(
        value["data"]["top_countries"][0]["country_name"],
        "United States"
    );
    assert_eq!(value["data"]["top_countries"][0]["bytes"], 150);
    assert_eq!(value["data"]["top_asns"][0]["asn"], 64_496);
    assert_eq!(value["data"]["country_distribution"][0]["bytes"], 150);

    // Test with ?lang=zh-CN
    let response_zh = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/geo?lang=zh-CN")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_zh.status(), StatusCode::OK);
    let body_zh = to_bytes(response_zh.into_body(), 16 * 1024).await.unwrap();
    let value_zh: serde_json::Value = serde_json::from_slice(&body_zh).unwrap();
    assert_eq!(value_zh["data"]["top_countries"][0]["country_name"], "美国");
}

#[tokio::test]
async fn flows_apply_composable_server_side_filters() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE flow_sessions SET domain = 'example.com', application_id = 'example'",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    for uri in [
        "/internal/flows?search=laptop",
        "/internal/flows?client=laptop&application=example",
        "/internal/flows?domain=example.com&ip=198.51.100.1",
        "/internal/flows?protocol=tcp&port=443&direction=upload",
        "/internal/flows?from=1699999999000&to=1700000001000",
        "/internal/flows?sort=download&order=asc",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"].as_array().unwrap().len(), 1, "{uri}");
        assert_eq!(value["data"][0]["client_name"], "laptop", "{uri}");
        assert!(value["data"][0]["organization"].is_string(), "{uri}");
        assert!(value["data"][0]["traffic_role"].is_string(), "{uri}");
        assert!(value["data"][0]["protocol_id"].is_string(), "{uri}");
        assert!(value["data"][0]["evidence"].is_string(), "{uri}");
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/flows?protocol=udp&direction=download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn flows_use_a_stable_cursor_without_counting_all_records() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute(
            "INSERT INTO flow_sessions(
                 id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                 remote_ip, remote_port, direction, upload_bytes, download_bytes, packets,
                 started_at, last_seen_at, ended_at, checkpointed_at, domain, application_id,
                 category_id, classification_confidence, classification_reason
             ) SELECT 'zz-cursor-second', gateway_id, device_id, ip_version, protocol, client_ip,
                    client_port, remote_ip, remote_port, direction, upload_bytes, download_bytes,
                    packets, started_at, last_seen_at, ended_at, checkpointed_at, domain,
                    application_id, category_id, classification_confidence, classification_reason
             FROM flow_sessions LIMIT 1",
            [],
        )
        .unwrap();
    let router = internal_router(state);
    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/flows?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(first.into_body(), 16 * 1024).await.unwrap();
    let first_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(first_value["data"].as_array().unwrap().len(), 1);
    assert!(first_value["pagination"].get("total").is_none());
    let cursor = first_value["pagination"]["next_cursor"].as_str().unwrap();
    let encoded_cursor = cursor.bytes().fold(String::new(), |mut output, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(output, "%{byte:02X}").unwrap();
        }
        output
    });
    let second = router
        .oneshot(
            Request::builder()
                .uri(format!("/internal/flows?limit=1&cursor={encoded_cursor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(second.into_body(), 16 * 1024).await.unwrap();
    let second_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(second_value["data"][0]["id"], "zz-cursor-second");
    assert!(second_value["pagination"]["next_cursor"].is_null());
}

#[tokio::test]
async fn overview_reports_stale_gateway_and_capture_health_honestly() {
    let state = query_state();
    state
        .lock()
        .storage
        .connection()
        .execute("UPDATE gateways SET last_seen = 1700000000000", [])
        .unwrap();
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["gateway_status"], "offline");
    assert_eq!(value["data"]["gateway"]["name"], "query-router");
    assert_eq!(value["data"]["gateway"]["openwrt_version"], "24.10.0");
    assert_eq!(value["data"]["gateway"]["kernel_version"], "6.6.73");
    assert_eq!(value["data"]["gateway"]["agent_version"], "0.1.0");
    assert_eq!(value["data"]["gateway"]["offloading_status"], "enabled");
    assert_eq!(value["data"]["gateway"]["interface_counter_sanity"], "ok");
    assert!(
        value["data"]["gateway"]["capture_warning"]
            .as_str()
            .unwrap()
            .contains("offline threshold")
    );
}

#[tokio::test]
async fn overview_reports_interface_counter_sanity_warning() {
    let state = query_state();
    let gateway_id = {
        let inner = state.lock();
        inner.gateway.as_ref().unwrap().gateway_id.clone()
    };
    {
        let mut inner = state.lock();
        inner.realtime.update(
            &TelemetryBatch {
                gateway_id,
                boot_id: "boot-query".to_owned(),
                sequence: 2,
                sent_at: 1_700_000_001_000,
                agent_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                health: Some(AgentHealth {
                    observed_at_unix_ms: 1_700_000_001_000,
                    capture_interface: "br-lan".to_owned(),
                    hardware_flow_offload: OffloadStatus::Disabled as i32,
                    interface_counter_sanity: CounterSanityStatus::Degraded as i32,
                    interface_delta_bytes: 524_288,
                    interface_delta_packets: 300,
                    flow_delta_bytes: 65_536,
                    flow_delta_packets: 30,
                    ..AgentHealth::default()
                }),
                ..TelemetryBatch::default()
            },
            &[],
            1_700_000_001_000,
        );
    }
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["data"]["gateway"]["interface_counter_sanity"],
        "degraded"
    );
    assert!(
        value["data"]["gateway"]["capture_warning"]
            .as_str()
            .unwrap()
            .contains("interface counters exceeded")
    );
}

#[tokio::test]
async fn internal_query_api_validates_pagination_ranges_and_unknown_fields() {
    let router = internal_router(query_state());
    for (uri, code) in [
        ("/internal/clients?limit=0", "invalid_pagination"),
        ("/internal/domains?limit=201", "invalid_pagination"),
        ("/internal/clients?offset=1000001", "invalid_pagination"),
        ("/internal/flows?unexpected=true", "invalid_query"),
        ("/internal/flows?ip=not-an-ip", "invalid_ip"),
        ("/internal/flows?protocol=quic", "invalid_protocol"),
        ("/internal/flows?direction=sideways", "invalid_direction"),
        ("/internal/flows?cursor=broken", "invalid_cursor"),
        ("/internal/clients/-1?limit=10", "invalid_client_id"),
        (
            "/internal/applications/INVALID!?limit=10",
            "invalid_application_id",
        ),
        (
            "/internal/applications/unknown?category=INVALID!",
            "invalid_category_id",
        ),
        ("/internal/traffic?from=20&to=10", "invalid_time_range"),
        (
            "/internal/traffic?group_by=unsupported_group",
            "invalid_group_by",
        ),
        ("/internal/insights?unexpected=true", "invalid_query"),
        (
            "/internal/insights?from=0&to=2678400000",
            "invalid_time_range",
        ),
        ("/internal/insights?limit=201", "invalid_pagination"),
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], 1, "{uri}");
        assert_eq!(value["error"]["code"], code, "{uri}");
        assert!(value.get("pagination").is_some(), "{uri}");
    }
}

#[tokio::test]
async fn request_timeout_returns_http_408() {
    let response = public_router(test_state())
        .oneshot(
            Request::builder()
                .uri("/test/slow")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn both_listeners_bind_and_internal_listener_is_loopback() {
    let config = CollectorConfig {
        public_addr: "127.0.0.1:0".parse().unwrap(),
        internal_addr: "127.0.0.1:0".parse().unwrap(),
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        database_path: PathBuf::from(":memory:"),
        storage_backend: "sqlite".to_owned(),
        clickhouse_config: ClickHouseConfig::default(),
        classifier_socket: PathBuf::from("/tmp/classifierd.sock"),
        geo_directory: PathBuf::from(DEFAULT_GEO_DIRECTORY),
        mac_dataset_path: default_mac_dataset_path(&PathBuf::from(":memory:")),
        mac_dataset_source_url: DEFAULT_MAC_DATASET_SOURCE_URL.to_owned(),
        icon_cache_config: IconCacheConfig::default(),
    };
    let (public, internal) = match bind_listeners(&config).await {
        Ok(listeners) => listeners,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("listener binding failed: {error}"),
    };
    assert_ne!(public.local_addr().unwrap().port(), 0);
    assert!(internal.local_addr().unwrap().ip().is_loopback());
    assert_ne!(internal.local_addr().unwrap().port(), 0);
}

#[test]
fn default_mac_dataset_path_uses_database_directory() {
    assert_eq!(
        default_mac_dataset_path(Path::new("/var/lib/netqmon/netqmon.db")),
        PathBuf::from("/var/lib/netqmon/mac-prefixes.json")
    );
    assert_eq!(
        default_mac_dataset_path(Path::new("netqmon.db")),
        PathBuf::from("mac-prefixes.json")
    );
}

#[test]
fn default_geo_directory_uses_database_directory() {
    assert_eq!(
        default_geo_directory(Path::new("/var/lib/netqmon/netqmon.db")),
        PathBuf::from("/var/lib/netqmon/geo")
    );
}

#[tokio::test]
async fn enrollment_requires_token_and_allows_only_one_active_gateway() {
    let state = test_state();
    let router = public_router(state.clone());
    let missing = router
        .clone()
        .oneshot(enrollment_request(""))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let enrolled = enroll_agent(&router).await;
    assert!(!enrolled.gateway_id.is_empty());
    assert_eq!(enrolled.agent_token.len(), 64);

    let repeated = router
        .clone()
        .oneshot(enrollment_request(ENROLLMENT_TOKEN))
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::CONFLICT);
    let message = to_bytes(repeated.into_body(), 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&message).contains("already enrolled"));

    let repeated_invalid = router.oneshot(enrollment_request("wrong")).await.unwrap();
    assert_eq!(repeated_invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stale_gateway_enrollment_rotates_token_and_preserves_history() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrolled = enroll_agent(&router).await;
    let batch = sample_batch(&enrolled.gateway_id, 1);
    let response = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrolled.agent_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();

    let replacement = enroll_agent(&router).await;
    assert_eq!(replacement.gateway_id, enrolled.gateway_id);
    assert_ne!(replacement.agent_token, enrolled.agent_token);

    let old_token_response = router
        .clone()
        .oneshot(telemetry_request(
            &sample_batch(&replacement.gateway_id, 2),
            &enrolled.agent_token,
        ))
        .await
        .unwrap();
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = router
        .clone()
        .oneshot(telemetry_request(
            &sample_batch(&replacement.gateway_id, 2),
            &replacement.agent_token,
        ))
        .await
        .unwrap();
    assert_eq!(new_token_response.status(), StatusCode::NO_CONTENT);

    let history_count: i64 = state
        .lock()
        .storage
        .connection()
        .query_row("SELECT COUNT(*) FROM ingest_batches", [], |row| row.get(0))
        .unwrap();
    assert_eq!(history_count, 2);
}

#[tokio::test]
async fn concurrent_stale_enrollment_rotates_gateway_only_once() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrolled = enroll_agent(&router).await;
    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();

    let first = router.clone().oneshot(enrollment_request(ENROLLMENT_TOKEN));
    let second = router.clone().oneshot(enrollment_request(ENROLLMENT_TOKEN));
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );

    let gateway = state.lock().storage.gateway().unwrap().unwrap();
    assert_eq!(gateway.id, enrolled.gateway_id);
    assert_ne!(gateway.agent_token_hash, hash_token(&enrolled.agent_token));
}

#[tokio::test]
async fn invalid_agent_token_is_rejected_before_payload_processing() {
    let state = test_state();
    let router = public_router(state.clone());
    let _enrollment = enroll_agent(&router).await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/telemetry")
                .header(AUTHORIZATION, "Bearer wrong")
                .body(Body::from("not protobuf"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.stats().accepted_batches, 0);
}

#[tokio::test]
async fn duplicate_batch_counts_traffic_only_once() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let batch = sample_batch(&enrollment.gateway_id, 1);

    let first = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    let duplicate = router
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    assert_eq!(
        state.stats(),
        IngestStats {
            accepted_batches: 1,
            dedupe_hits: 1,
            traffic_bytes: 150,
        }
    );
    let realtime = state.realtime_snapshot();
    assert_eq!(realtime.history.len(), 1);
    assert_eq!(realtime.total.upload_bytes_per_second, 100);
}

#[tokio::test]
async fn rejects_too_many_flows_and_oversized_wire_body() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;
    let mut batch = sample_batch(&enrollment.gateway_id, 1);
    batch.flows = vec![FlowDelta::default(); MAX_FLOWS_PER_BATCH + 1];
    let response = router
        .clone()
        .oneshot(telemetry_request(&batch, &enrollment.agent_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/telemetry")
                .header(AUTHORIZATION, format!("Bearer {}", enrollment.agent_token))
                .body(Body::from(vec![0; MAX_BODY_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(state.stats().accepted_batches, 0);
}

#[tokio::test]
async fn synthetic_agent_sustains_one_second_batches() {
    let state = test_state();
    let router = public_router(state.clone());
    let enrollment = enroll_agent(&router).await;

    for sequence in 1..=10 {
        let batch = sample_batch(&enrollment.gateway_id, sequence);
        let response = router
            .clone()
            .oneshot(telemetry_request(&batch, &enrollment.agent_token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        state.stats(),
        IngestStats {
            accepted_batches: 10,
            dedupe_hits: 0,
            traffic_bytes: 1_500,
        }
    );
}

#[test]
fn gateway_auth_and_traffic_survive_collector_restart() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("netqmon.db");
    let request = EnrollRequest {
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "router".to_owned(),
    };
    let state = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    let enrollment = state.enroll(&request).unwrap();
    let batch = sample_batch(&enrollment.gateway_id, 1);
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );
    drop(state);

    let restarted = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    assert_eq!(
        restarted.authenticate(&enrollment.agent_token),
        Some(enrollment.gateway_id)
    );
    let inner = restarted.lock();
    let traffic: i64 = inner
        .storage
        .connection()
        .query_row(
            "SELECT upload_bytes + download_bytes FROM traffic_total_minute",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(traffic, 150);
}

#[test]
fn rotated_gateway_credentials_survive_collector_restart() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("netqmon.db");
    let request = EnrollRequest {
        enrollment_token: ENROLLMENT_TOKEN.to_owned(),
        agent_version: "0.1.0-beta.4".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "boot-1".to_owned(),
        gateway_name: "router".to_owned(),
    };
    let state = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    let initial = state.enroll(&request).unwrap();
    let stale_at = unix_time_ms().saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS + 1);
    state
        .lock()
        .storage
        .connection()
        .execute(
            "UPDATE gateways SET last_seen = ?1",
            [i64::try_from(stale_at).unwrap()],
        )
        .unwrap();
    let replacement = state.enroll(&request).unwrap();
    assert_eq!(replacement.gateway_id, initial.gateway_id);
    assert_ne!(replacement.agent_token, initial.agent_token);
    drop(state);

    let restarted = CollectorState::open(ENROLLMENT_TOKEN, &database_path).unwrap();
    assert_eq!(
        restarted.authenticate(&replacement.agent_token),
        Some(replacement.gateway_id)
    );
    assert_eq!(restarted.authenticate(&initial.agent_token), None);
}

#[test]
fn dns_attribution_classifies_each_client_without_cross_talk() {
    let state = CollectorState::with_storage(
        ENROLLMENT_TOKEN,
        SqliteStorage::open_in_memory().unwrap(),
        crate::classifier::ClassifierHandle::test_default(),
    )
    .unwrap();
    let enrollment = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "boot-1".to_owned(),
            gateway_name: "router".to_owned(),
        })
        .unwrap();
    let observed_at = 1_700_000_000_000;
    let shared_address = vec![203, 0, 113, 9];
    let clients = [vec![192, 0, 2, 10], vec![192, 0, 2, 11]];
    let domains = ["www.youtube.com", "api.openai.com"];
    let mut batch = TelemetryBatch {
        gateway_id: enrollment.gateway_id,
        boot_id: "boot-1".to_owned(),
        sequence: 1,
        sent_at: observed_at,
        agent_version: "0.1.0".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        ..TelemetryBatch::default()
    };
    for (index, client) in clients.iter().enumerate() {
        batch.dns_observations.push(DnsObservation {
            client_ip: client.clone(),
            domain: domains[index].to_owned(),
            answer_ip: shared_address.clone(),
            record_type: DnsRecordType::A as i32,
            ttl_seconds: 60,
            observed_at_unix_ms: observed_at,
        });
        batch.flows.push(FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: client.clone(),
            client_port: 50_000 + u32::try_from(index).unwrap(),
            remote_ip: shared_address.clone(),
            remote_port: 443,
            direction: 1,
            upload_bytes: 100,
            download_bytes: 50,
            packets: 3,
            first_seen_unix_ms: observed_at,
            last_seen_unix_ms: observed_at,
            lifecycle: FlowLifecycle::Ended as i32,
            ..FlowDelta::default()
        });
    }
    assert_eq!(
        state.accept_batch(&batch).unwrap(),
        BatchDisposition::Accepted
    );

    let inner = state.lock();
    let mut statement = inner
        .storage
        .connection()
        .prepare("SELECT domain, application_id, category_id FROM flow_sessions ORDER BY client_ip")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "www.youtube.com".to_owned(),
                "youtube".to_owned(),
                "streaming".to_owned(),
            ),
            (
                "api.openai.com".to_owned(),
                "openai".to_owned(),
                "ai".to_owned(),
            ),
        ]
    );
}

// ---------- Phase 10 auth integration tests ----------

fn auth_status_request() -> Request<Body> {
    Request::builder()
        .uri("/internal/auth/status")
        .body(Body::empty())
        .unwrap()
}

fn auth_setup_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/setup")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap()
}

fn auth_login_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap()
}

fn auth_verify_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/verify")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn auth_logout_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn parse_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn auth_status_reports_setup_required_initially() {
    let router = internal_router(test_state());
    let response = router.oneshot(auth_status_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["setup_required"], true);
}

#[tokio::test]
async fn setup_creates_admin_and_blocks_duplicate() {
    let state = test_state();
    let router = internal_router(state);

    // Initial setup succeeds.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "strongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(!json["data"]["session_token"].as_str().unwrap().is_empty());
    assert!(!json["data"]["user"]["id"].as_str().unwrap().is_empty());
    assert_eq!(json["data"]["user"]["username"], "admin");
    assert!(json["data"]["expires_at"].as_u64().unwrap() > 0);

    // Status now reports setup complete.
    let response = router.clone().oneshot(auth_status_request()).await.unwrap();
    let json = parse_json(response).await;
    assert_eq!(json["data"]["setup_required"], false);

    // Duplicate setup is rejected with 409.
    let response = router
        .oneshot(auth_setup_request("admin2", "anotherpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "setup_complete");
}

#[tokio::test]
async fn setup_validates_credential_requirements() {
    let router = internal_router(test_state());

    // Username too short.
    let response = router
        .clone()
        .oneshot(auth_setup_request("ab", "strongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "invalid_credentials");

    // Password too short.
    let response = router
        .oneshot(auth_setup_request("admin", "short"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_with_valid_credentials_issues_session() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin first.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Login with valid credentials.
    let response = router
        .clone()
        .oneshot(auth_login_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(!json["data"]["session_token"].as_str().unwrap().is_empty());
    assert_eq!(json["data"]["user"]["username"], "admin");
}

#[tokio::test]
async fn login_with_invalid_credentials_returns_unauthorized() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin first.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Wrong password.
    let response = router
        .clone()
        .oneshot(auth_login_request("admin", "wrongpassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "invalid_login");

    // Non-existent user.
    let response = router
        .oneshot(auth_login_request("nonexistent", "somepassword12"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_with_valid_session_returns_user_info() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin and extract token.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    let json = parse_json(response).await;
    let token = json["data"]["session_token"].as_str().unwrap().to_owned();

    // Verify returns user info.
    let response = router
        .clone()
        .oneshot(auth_verify_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["user"]["username"], "admin");
    assert!(json["data"]["expires_at"].as_u64().unwrap() > 0);

    // Verify with invalid token returns 401.
    let response = router
        .oneshot(auth_verify_request("invalid-token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_invalidates_session() {
    let state = test_state();
    let router = internal_router(state);

    // Setup admin and extract token.
    let response = router
        .clone()
        .oneshot(auth_setup_request("admin", "correcthorsebattery"))
        .await
        .unwrap();
    let json = parse_json(response).await;
    let token = json["data"]["session_token"].as_str().unwrap().to_owned();

    // Session is initially valid.
    let response = router
        .clone()
        .oneshot(auth_verify_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Logout.
    let response = router
        .clone()
        .oneshot(auth_logout_request(&token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Session is now invalid.
    let response = router.oneshot(auth_verify_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_retention_endpoints_and_manual_run() {
    let state = test_state();
    let router = internal_router(state);

    // 1. GET returns default retention
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/retention")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["flow_sessions_days"], 7);
    assert_eq!(json["data"]["dns_days"], 7);
    assert_eq!(json["data"]["minute_days"], 30);
    assert_eq!(json["data"]["hour_days"], 365);
    assert_eq!(json["data"]["day_days"], 0);

    // 2. PUT with invalid minute_days: 0 returns 400
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/settings/retention")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"flow_sessions_days":7,"dns_days":7,"minute_days":0,"hour_days":30,"day_days":0}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 3. PUT with valid policy updates and returns new policy
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/internal/settings/retention")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"flow_sessions_days":14,"dns_days":3,"minute_days":60,"hour_days":180,"day_days":730}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["flow_sessions_days"], 14);
    assert_eq!(json["data"]["dns_days"], 3);
    assert_eq!(json["data"]["minute_days"], 60);
    assert_eq!(json["data"]["hour_days"], 180);
    assert_eq!(json["data"]["day_days"], 730);

    // 4. GET verifies persisted update
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/retention")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["flow_sessions_days"], 14);

    // 5. POST manual retention run returns completed
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/retention/run")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["data"]["status"], "completed");
}

#[tokio::test]
async fn settings_icon_cache_endpoints_report_and_clear_stats() {
    let router = internal_router(test_state());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/icon-cache")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["entry_count"], 0);
    assert_eq!(json["weighted_size_bytes"], 0);
    assert_eq!(json["capacity_bytes"], 32 * 1024 * 1024);
    assert_eq!(json["positive_ttl_seconds"], 24 * 60 * 60);
    assert_eq!(json["negative_ttl_seconds"], 60 * 60);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/icon-cache/clear")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["entry_count"], 0);
    assert_eq!(json["weighted_size_bytes"], 0);
}

#[tokio::test]
async fn settings_rules_reload_endpoint() {
    let state = test_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/rules/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["application_count"], 3);
    assert_eq!(json["data"]["selfhost_application_count"], 1);
    assert_eq!(json["data"]["client_count"], 1);
    assert_eq!(json["data"]["protocol_count"], 2);
    assert_eq!(json["data"]["rule_version"], "test-rule-version");
    assert!(json["data"]["updated_at_unix_ms"].as_u64().unwrap() > 0);
    assert!(json["data"]["reloaded_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn settings_diagnostics_endpoint() {
    let state = query_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["db_backend"], "sqlite");
    assert!(json["data"]["db_size_bytes"].as_i64().unwrap() > 0);
    assert!(json["data"]["gateway"].is_object());
    assert!(json["data"]["retention"].is_object());
    assert_eq!(json["data"]["collector_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["data"]["classification"]["availability"], "ready");
    assert_eq!(json["data"]["classification"]["classifier_version"], "test");
    assert_eq!(
        json["data"]["classification"]["stats"]["application_count"],
        3
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["selfhost_application_count"],
        1
    );
    assert_eq!(json["data"]["classification"]["stats"]["client_count"], 1);
    assert_eq!(json["data"]["classification"]["stats"]["protocol_count"], 2);
    assert_eq!(
        json["data"]["classification"]["stats"]["sample_match_requests"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["signature_match_count"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["signature_match_application_count"],
        0
    );
    assert_eq!(
        json["data"]["classification"]["stats"]["rule_version"],
        "test-rule-version"
    );
    assert!(
        json["data"]["classification"]["stats"]["updated_at_unix_ms"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json["data"].get("rule_sources").is_none());
}

#[tokio::test]
async fn settings_diagnostics_includes_classifier_manager_field() {
    let state = test_state();
    let router = internal_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/diagnostics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert!(json["data"].get("classifier_manager").is_some());
}

#[test]
fn classifier_manager_status_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let status_file = temp.path().join("status.json");
    let status_json = serde_json::json!({
        "state": "running",
        "current_version": "0.1.0",
        "candidate_version": null,
        "last_checked_at": 1726000000,
        "last_error": null
    });
    std::fs::write(&status_file, serde_json::to_vec(&status_json).unwrap()).unwrap();

    let parsed = crate::query_api::classifier_manager_status_from_path(&status_file);
    assert!(parsed.is_some());
    let val = parsed.unwrap();
    assert_eq!(val["state"], "running");
    assert_eq!(val["current_version"], "0.1.0");
    assert_eq!(val["last_checked_at"], 1726000000);

    let nonexistent = temp.path().join("nonexistent.json");
    assert!(crate::query_api::classifier_manager_status_from_path(&nonexistent).is_none());
}

#[tokio::test]
async fn settings_geo_endpoints() {
    let state = test_state();
    let router = internal_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/internal/settings/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert!(json["data"]["directory"].is_string());
    assert!(
        json["data"]["attribution"]
            .as_str()
            .unwrap()
            .contains("GeoLite2")
    );
    assert!(json["data"]["databases"].is_array());
    let databases = json["data"]["databases"].as_array().unwrap();
    assert!(
        databases
            .iter()
            .any(|d| d["filename"] == "GeoLite2-City.mmdb")
    );
    assert!(
        databases
            .iter()
            .any(|d| d["filename"] == "GeoLite2-ASN.mmdb")
    );
}

#[tokio::test]
async fn settings_geo_update_endpoint_handles_error() {
    let state = test_state();
    let router = internal_router(state);

    let body = serde_json::json!({
        "city_url": "ftp://example.invalid/invalid-city.mmdb",
        "asn_url": "ftp://example.invalid/invalid-asn.mmdb",
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/geo/update")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = parse_json(response).await;
    assert_eq!(json["error"]["code"], "geo_update_error");
}

#[tokio::test]
async fn settings_license_endpoints() {
    let state = test_state();
    let router = internal_router(state);

    // 1. GET /internal/settings/license initially returns valid status
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal/settings/license")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = parse_json(response).await;
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["activated"], false);
    assert_eq!(json["data"]["edition"], "community");

    // 2. POST with empty key returns BAD_REQUEST
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/license/activate")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "license_key": "   " }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 3. POST /internal/settings/license/check without activation returns bad gateway
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/settings/license/check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn sample_endpoint_enforces_auth_gateway_and_limits() {
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};
    let state = test_state();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-test".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let mut batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-test".into(),
        sequence: 1,
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
                original_length: 64,
                captured_length: 64,
                payload: vec![0x45; 64],
            }],
            total_captured_bytes: 64,
        }],
    };
    let request = |batch: &FlowSampleBatch, token: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/ingest/samples")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(batch.encode_to_vec()))
            .unwrap()
    };
    let router = public_router(state.clone());
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, "wrong-token"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    batch.gateway_id = "other".into();
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    batch.gateway_id = enrolled.gateway_id;
    batch.samples[0].total_captured_bytes = 1;
    assert_eq!(
        router
            .clone()
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    batch.samples[0].total_captured_bytes = 64;
    assert_eq!(
        router
            .oneshot(request(&batch, &enrolled.agent_token))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(state.lock().accepted_batches, 0);
}

#[cfg(ndpi_available)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_sample_ingestion_updates_ended_flow_without_persisting_payload() {
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};
    let mut state = test_state_with_repository_rules();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-test".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let inner = Arc::downgrade(&state.inner);
    let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
        state.lock().classifier.clone(),
    ));
    state.sampling = Arc::new(dpi::SamplingService::new(
        true,
        dpi::default_engine(),
        signature_matcher,
        move |result| {
            if let Some(inner) = inner.upgrade() {
                apply_sample_result(&mut inner.lock().unwrap(), &result).unwrap();
            }
        },
    ));
    let timestamp = 1_700_000_000_000;
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        direction: 1,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        upload_bytes: 108,
        packets: 1,
        lifecycle: FlowLifecycle::Ended.into(),
        protocol_hint: "bittorrent_handshake".into(),
        ..Default::default()
    };
    let telemetry = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-test".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&telemetry).unwrap();
    let read = || {
        state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT protocol_id,upload_bytes,classification_evidence_json FROM flow_sessions",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(read().0, "unknown", "legacy Agent hint must be ignored");
    let mut payload = vec![0; 108];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&108u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&flow.client_ip);
    payload[16..20].copy_from_slice(&flow.remote_ip);
    payload[20..22].copy_from_slice(&50000u16.to_be_bytes());
    payload[22..24].copy_from_slice(&443u16.to_be_bytes());
    payload[32] = 0x50;
    payload[33] = 0x18;
    payload[40] = 19;
    payload[41..60].copy_from_slice(b"BitTorrent protocol");
    let batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id,
        boot_id: "sample-test".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: timestamp,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: timestamp,
                original_length: 108,
                captured_length: 108,
                payload,
            }],
            total_captured_bytes: 108,
        }],
    };
    let encoded = netqmon_protocol::encode_flow_sample_batch(&batch, 0).unwrap();
    let response = public_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/samples")
                .header(AUTHORIZATION, format!("Bearer {}", enrolled.agent_token))
                .header(CONTENT_ENCODING, "zstd")
                .body(Body::from(encoded.body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for _ in 0..100 {
        if read().0 == "bittorrent" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (protocol, bytes, evidence) = read();
    assert_eq!(protocol, "bittorrent");
    assert_eq!(bytes, 108);
    assert!(evidence.contains("ndpi"));
    assert!(!evidence.contains("BitTorrent protocol"));
    let diagnostics = state.sampling.diagnostics().to_string();
    assert!(!diagnostics.contains("payload"));
    assert!(!diagnostics.contains("BitTorrent protocol"));
    assert_eq!(state.lock().accepted_batches, 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn signature_sample_match_reclassifies_flow_without_dpi() {
    use crate::dpi::engine::{DpiEngine, DpiFlow, DpiResult};
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};

    struct NoDpiEngine;
    struct NoDpiFlow;
    impl DpiEngine for NoDpiEngine {
        fn name(&self) -> &'static str {
            "fixture"
        }
        fn start(&self, _: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
            Ok(Box::new(NoDpiFlow))
        }
    }
    impl DpiFlow for NoDpiFlow {
        fn classify(&mut self, _: &[SamplePacket]) -> Option<DpiResult> {
            None
        }
        fn finish(&mut self) -> Option<DpiResult> {
            None
        }
    }

    let mut state = test_state_with_repository_rules();
    let enrolled = state
        .enroll(&EnrollRequest {
            boot_id: "sample-signature".into(),
            agent_version: "test".into(),
            protocol_version: 1,
            gateway_name: "test".into(),
            enrollment_token: ENROLLMENT_TOKEN.into(),
        })
        .unwrap();
    let inner = Arc::downgrade(&state.inner);
    let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
        state.lock().classifier.clone(),
    ));
    state.sampling = Arc::new(dpi::SamplingService::new(
        true,
        Arc::new(NoDpiEngine),
        signature_matcher,
        move |result| {
            if let Some(inner) = inner.upgrade() {
                apply_sample_result(&mut inner.lock().unwrap(), &result).unwrap();
            }
        },
    ));
    let timestamp = 1_700_000_000_000;
    let flow = FlowDelta {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        direction: 1,
        first_seen_unix_ms: timestamp,
        last_seen_unix_ms: timestamp,
        upload_bytes: 108,
        packets: 1,
        lifecycle: FlowLifecycle::Ended.into(),
        ..Default::default()
    };
    let telemetry = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&telemetry).unwrap();
    let read = || {
        state
            .lock()
            .storage
            .connection()
            .query_row(
                "SELECT application_id,organization_id,classification_evidence_json FROM flow_sessions",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(read().0, "unknown");

    let mut payload = vec![0u8; 48];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&48u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&flow.client_ip);
    payload[16..20].copy_from_slice(&flow.remote_ip);
    payload[20..22].copy_from_slice(&50000u16.to_be_bytes());
    payload[22..24].copy_from_slice(&443u16.to_be_bytes());
    payload[32] = 0x50;
    payload[33] = 0x10;
    payload[40..44].copy_from_slice(&[0x33, 0x66, 0x00, 0x0b]);
    payload[44] = 0x0c;
    let batch = FlowSampleBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 1,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        samples: vec![FlowSample {
            flow_id: "flow".into(),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: timestamp,
            }),
            packets: vec![SamplePacket {
                direction: 1,
                timestamp_unix_ms: timestamp,
                original_length: u32::try_from(payload.len()).unwrap(),
                captured_length: u32::try_from(payload.len()).unwrap(),
                payload,
            }],
            total_captured_bytes: 48,
        }],
    };
    let encoded = netqmon_protocol::encode_flow_sample_batch(&batch, 0).unwrap();
    let response = public_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/samples")
                .header(AUTHORIZATION, format!("Bearer {}", enrolled.agent_token))
                .header(CONTENT_ENCODING, "zstd")
                .body(Body::from(encoded.body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    for _ in 0..200 {
        let (_, _, evidence) = read();
        if evidence.contains("payload_signature") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_, _, evidence) = read();
    assert!(
        evidence.contains("payload_signature"),
        "the ended flow records the signature evidence: {evidence}"
    );
    assert!(
        !evidence.contains("3366000b"),
        "raw payload bytes must never be persisted"
    );

    // The next telemetry batch for the same flow attributes through the cache.
    let followup = TelemetryBatch {
        gateway_id: enrolled.gateway_id.clone(),
        boot_id: "sample-signature".into(),
        sequence: 2,
        sent_at: timestamp,
        agent_version: "test".into(),
        protocol_version: 1,
        flows: vec![flow.clone()],
        ..Default::default()
    };
    state.accept_batch(&followup).unwrap();
    let (application, organization, category, evidence) = state
        .lock()
        .storage
        .connection()
        .query_row(
            "SELECT application_id,organization_id,category_id,classification_evidence_json
             FROM flow_sessions",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(application, "honor_of_kings");
    assert_eq!(organization, "tencent");
    assert_eq!(category, "gaming");
    assert!(evidence.contains("payload_signature"));
    assert_eq!(state.lock().accepted_batches, 2);
}

#[test]
fn missing_classifierd_never_blocks_signature_matching_or_sampling() {
    use crate::dpi::SignatureMatcher;
    use netqmon_protocol::v1::FlowSampleKey;

    let handle =
        classifier::ClassifierHandle::connect(PathBuf::from("/missing/netqmon-classifierd.sock"))
            .unwrap();
    let matcher = classifier::ClassifierdSignatureMatcher::new(handle);
    let key = FlowSampleKey {
        ip_version: 4,
        protocol: 6,
        client_ip: vec![192, 0, 2, 1],
        client_port: 50000,
        remote_ip: vec![198, 51, 100, 2],
        remote_port: 443,
        first_seen_unix_ms: 1,
    };
    let packets = vec![netqmon_protocol::v1::SamplePacket {
        direction: 1,
        timestamp_unix_ms: 1,
        original_length: 48,
        captured_length: 48,
        payload: vec![0x45; 48],
    }];
    let started = std::time::Instant::now();
    let observed = matcher.match_sample(&key, &packets);
    assert!(observed.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a missing classifierd must fail fast, not stall the DPI worker"
    );
}

#[test]
fn hostname_domain_rules_fill_unknown_dns_without_overriding_dns_applications() {
    let state = test_state_with_repository_rules();
    let inner = state.lock();
    for (dns, hostname, native, expected, expected_domain) in [
        (
            "cdn.unmatched.test",
            "www.youtube.com",
            "Netflix",
            "youtube",
            "www.youtube.com",
        ),
        (
            "netflix.com",
            "www.youtube.com",
            "YouTube",
            "netflix",
            "netflix.com",
        ),
        (
            "cdn.unmatched.test",
            "",
            "YouTube",
            "youtube",
            "cdn.unmatched.test",
        ),
    ] {
        let batch = TelemetryBatch {
            sent_at: 1000,
            flows: vec![FlowDelta {
                client_ip: vec![192, 0, 2, 1],
                remote_ip: vec![198, 51, 100, 1],
                protocol: 6,
                remote_port: 443,
                last_seen_unix_ms: 1000,
                ..Default::default()
            }],
            dns_observations: vec![DnsObservation {
                client_ip: vec![192, 0, 2, 1],
                answer_ip: vec![198, 51, 100, 1],
                domain: dns.into(),
                observed_at_unix_ms: 1000,
                ttl_seconds: 60,
                ..Default::default()
            }],
            ..Default::default()
        };
        let dpi = dpi::engine::DpiResult {
            protocol: "tls".into(),
            source: "ndpi".into(),
            confidence: 1.0,
            metadata: std::collections::BTreeMap::from([
                ("hostname".into(), hostname.into()),
                ("application_protocol".into(), native.into()),
            ]),
        };
        let result = classify_batch(
            &inner.storage,
            &inner.classifier,
            inner.geo_provider.as_ref(),
            &mut ServiceBindingCache::default(),
            &FaviconEndpointCache::default(),
            &batch,
            &[Some(dpi::SampleAnalysis {
                dpi: Some(dpi),
                signatures: Vec::new(),
            })],
        )
        .unwrap();
        assert_eq!(result[0].application_id, expected);
        assert_eq!(result[0].domain.as_deref(), Some(expected_domain));
        assert_eq!(result[0].category_id, "streaming");
        assert_eq!(result[0].protocol_id, "tls");
    }
}

#[test]
fn local_hostname_does_not_identify_selfhost_or_bind_reverse_proxy_port() {
    let state = test_state_with_repository_rules();
    let inner = state.lock();
    let batch = TelemetryBatch {
        sent_at: 1_000,
        flows: vec![FlowDelta {
            client_ip: vec![192, 168, 2, 10],
            remote_ip: vec![192, 168, 2, 20],
            protocol: 6,
            remote_port: 443,
            last_seen_unix_ms: 1_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let dpi = dpi::engine::DpiResult {
        protocol: "tls".into(),
        source: "ndpi".into(),
        confidence: 1.0,
        metadata: std::collections::BTreeMap::from([(
            "hostname".into(),
            "jellyfin.home.arpa".into(),
        )]),
    };
    let mut bindings = ServiceBindingCache::default();
    let identified = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut bindings,
        &FaviconEndpointCache::default(),
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: Some(dpi),
            signatures: Vec::new(),
        })],
    )
    .unwrap();
    assert_eq!(identified[0].application_id, "unknown");

    let without_hostname = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut bindings,
        &FaviconEndpointCache::default(),
        &batch,
        &[None],
    )
    .unwrap();
    assert_eq!(without_hostname[0].application_id, "unknown");
    assert!(!attribution_has_evidence(
        &without_hostname[0],
        "service_binding"
    ));
}

#[tokio::test]
async fn insights_detect_first_batch_of_low_cost_enhancements() {
    let state = query_state();
    let inner = state.lock();
    let conn = inner.storage.connection();
    let gateway_id: String = conn
        .query_row("SELECT id FROM gateways LIMIT 1", [], |r| r.get(0))
        .unwrap();

    // 1. Client spike & Application spike
    // Seed baseline in [1000, 2000) and current spike in [2000, 3000)
    conn.execute(
        "INSERT INTO traffic_device_minute (timestamp, gateway_id, device_id, upload_bytes, download_bytes, packets, flow_count)
         VALUES (1500, ?1, 1, 1000000, 1000000, 100, 10),
                (2500, ?1, 1, 15000000, 15000000, 1000, 50)",
        [&gateway_id],
    ).unwrap();

    conn.execute(
        "INSERT INTO traffic_application_minute (timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
         VALUES (1500, ?1, 'youtube', 'streaming', 1000000, 1000000, 100, 10),
                (2500, ?1, 'youtube', 'streaming', 15000000, 15000000, 1000, 50)",
        [&gateway_id],
    ).unwrap();

    let client_spikes = crate::insights::traffic::query_client_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(client_spikes.len(), 1);
    assert_eq!(client_spikes[0].code, "traffic.client_spike");
    assert_eq!(client_spikes[0].category, "traffic");
    assert_eq!(client_spikes[0].params["client"], "laptop");

    let app_spikes = crate::insights::traffic::query_application_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(app_spikes.len(), 1);
    assert_eq!(app_spikes[0].code, "traffic.application_spike");
    assert_eq!(app_spikes[0].category, "traffic");
    assert_eq!(app_spikes[0].params["application"], "youtube");

    // 2. New protocol
    conn.execute(
        "INSERT INTO flow_sessions (
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
            upload_bytes, download_bytes, packets, protocol_id
         ) VALUES (
            'flow-new-proto', ?1, 1, 4, 6, X'C000020A', 50000,
            X'C6336401', 443, 1, 2500, 2500, 2500, 1000, 1000, 10, 'quic'
         )",
        [&gateway_id],
    )
    .unwrap();

    let new_protos = crate::insights::protocol::query_new_protocol_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert!(
        new_protos
            .iter()
            .any(|i| i.code == "protocol.new_protocol" && i.params["protocol"] == "quic")
    );

    // 3. Client unknown ratio high
    conn.execute(
        "INSERT INTO flow_sessions (
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
            upload_bytes, download_bytes, packets, application_id
         ) VALUES (
            'flow-unknown-heavy', ?1, 1, 4, 6, X'C000020A', 50001,
            X'C6336402', 443, 1, 2500, 2500, 2500, 2000000, 2000000, 100, 'unknown'
         )",
        [&gateway_id],
    )
    .unwrap();

    let client_unknowns = crate::insights::classification::query_client_unknown_ratio_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert!(
        client_unknowns
            .iter()
            .any(|i| i.code == "classification.client_unknown_ratio_high")
    );

    // 4. Fanout spike: add 55 distinct remote IPs
    for i in 1..=55 {
        conn.execute(
            "INSERT INTO flow_sessions (
                id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
                remote_ip, remote_port, direction, started_at, last_seen_at, checkpointed_at,
                upload_bytes, download_bytes, packets
             ) VALUES (
                ?1, ?2, 1, 4, 6, X'C000020A', ?3,
                ?4, 80, 1, 2500, 2500, 2500, 100, 100, 1
             )",
            rusqlite::params![
                format!("fanout-flow-{i}"),
                gateway_id,
                50000 + i,
                vec![10, 0, (i / 256) as u8, (i % 256) as u8]
            ],
        )
        .unwrap();
    }

    let fanouts = crate::insights::destination::query_fanout_spike_insights(
        conn,
        crate::insights::InsightWindow {
            from: 2000,
            to: 3000,
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(fanouts.len(), 1);
    assert_eq!(fanouts[0].code, "destination.fanout_spike");
    assert_eq!(fanouts[0].category, "destination");
    assert!(fanouts[0].params["count"].as_i64().unwrap() >= 55);
}
