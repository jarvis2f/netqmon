use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use futures_util::{SinkExt as _, StreamExt as _};
use netqmon_protocol::policy::{
    PolicyAckStatus, PolicyCapabilities, PolicyCapability, PolicyResult, PolicyResultStatus,
    PolicyWireFrame,
};
use netqmon_storage::{ClickHouseConfig, ClickHouseStorage, Storage};
use tower::ServiceExt;

use crate::{CollectorState, hash_token, internal_router, policy::PolicyService, unix_time_ms};

fn state_with_gateway() -> CollectorState {
    let state = CollectorState::new("enrollment-token");
    let now = unix_time_ms();
    let mut inner = state.lock();
    inner
        .storage
        .create_admin("admin-1", "admin", "test-password-hash", now)
        .unwrap();
    inner
        .storage
        .save_gateway("gw-1", "Test gateway", "test", &[7; 32], now)
        .unwrap();
    let now_ms = i64::try_from(now).unwrap();
    inner
        .storage
        .sqlite_connection()
        .expect("test storage uses SQLite")
        .execute(
            "INSERT INTO devices(gateway_id, mac, display_name, hostname, first_seen, last_seen)
             VALUES ('gw-1', ?1, 'Office Laptop', 'office-laptop', ?2, ?2)",
            rusqlite::params![&[0xAA_u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF][..], now_ms],
        )
        .unwrap();
    inner
        .storage
        .create_session("admin-1", &hash_token("valid-session"), now, now + 60_000)
        .unwrap();
    drop(inner);
    state
}

fn state_with_agent_token() -> CollectorState {
    let state = state_with_gateway();
    let mut inner = state.lock();
    inner.gateway = Some(crate::GatewayCredential {
        gateway_id: "gw-1".to_owned(),
        agent_token_hash: hash_token("agent-secret"),
    });
    drop(inner);
    state
}

fn policy_spec(scope: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "gateway_id": "gw-1",
        "name": "Test policy",
        "description": "",
        "enabled": false,
        "priority": 500,
        "selectors": {
            "clients": [],
            "applications": [],
            "categories": [],
            "min_application_confidence": 0.85
        },
        "network": { "scope": scope, "direction": "both" },
        "action": { "type": "block", "download_bps": null, "upload_bps": null },
        "schedule": null
    })
}

fn request(uri: &str, method: &str, token: Option<&str>, body: Body) -> Request<Body> {
    let mut builder = Request::builder().uri(uri).method(method);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(body).unwrap()
}

#[tokio::test]
async fn policy_routes_require_a_live_admin_session() {
    let state = state_with_gateway();
    let app = internal_router(state.clone());

    let missing = app
        .clone()
        .oneshot(request(
            "/internal/policies?gateway_id=gw-1",
            "GET",
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let invalid = app
        .oneshot(request(
            "/internal/policies?gateway_id=gw-1",
            "GET",
            Some("expired-or-forged"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn policy_stream_authenticates_and_pushes_an_empty_initial_snapshot() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let state = state_with_agent_token();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::public_router(server_state))
            .await
            .unwrap();
    });
    let url = format!("ws://{address}/v1/agent/policies/stream");

    let missing = tokio_tungstenite::connect_async(&url).await.unwrap_err();
    assert!(
        matches!(missing, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == StatusCode::UNAUTHORIZED)
    );

    let mut invalid_request = url.as_str().into_client_request().unwrap();
    invalid_request.headers_mut().insert(
        "authorization",
        "Bearer invalid-agent-token".parse().unwrap(),
    );
    let invalid = tokio_tungstenite::connect_async(invalid_request)
        .await
        .unwrap_err();
    assert!(
        matches!(invalid, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == StatusCode::UNAUTHORIZED)
    );

    let mut request = url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer agent-secret".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = message.into_text().unwrap();
    let frame = PolicyWireFrame::decode(text.as_bytes()).unwrap();
    assert!(
        matches!(frame, PolicyWireFrame::PolicySnapshot { config_revision: 0, ref policies, .. } if policies.is_empty())
    );

    server.abort();
}

#[tokio::test]
async fn policy_stream_rejects_post_auth_metrics_for_another_gateway() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let state = state_with_agent_token();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::public_router(server_state))
            .await
            .unwrap();
    });
    let mut request = format!("ws://{address}/v1/agent/policies/stream")
        .as_str()
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer agent-secret".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let initial = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    assert!(matches!(
        PolicyWireFrame::decode(initial.as_bytes()).unwrap(),
        PolicyWireFrame::PolicySnapshot {
            config_revision: 0,
            ..
        }
    ));

    let health = PolicyWireFrame::PolicyHealth {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: "gw-1".to_owned(),
        boot_id: "boot-test".to_owned(),
        last_applied_revision: 0,
        controller_epoch: None,
        bundle_generation: None,
        checksum: None,
        capabilities: PolicyCapabilities::unsupported(),
        reported_at_ms: unix_time_ms() as i64,
        emergency_disabled: false,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(health.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    let forged = PolicyWireFrame::PolicyMetrics {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: "gw-other".to_owned(),
        boot_id: "boot-test".to_owned(),
        sampled_at_ms: unix_time_ms() as i64,
        metrics: vec![netqmon_protocol::policy::PolicyClientMetrics {
            policy_id: "policy-other".to_owned(),
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            upload: Some(netqmon_protocol::policy::PolicyDirectionMetrics {
                interface: "policy-block".to_owned(),
                bytes: Some(60),
                packets: Some(1),
                drops: Some(1),
                overlimits: None,
            }),
            download: None,
        }],
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(forged.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    let close = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        close,
        tokio_tungstenite::tungstenite::Message::Close(Some(frame))
            if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !state
                .policy_service
                .deployment("gw-1")
                .unwrap()
                .agent_connected
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn failed_policy_upgrade_does_not_register_a_session() {
    let state = state_with_agent_token();
    let response = crate::public_router(state.clone())
        .oneshot(request(
            "/v1/agent/policies/stream",
            "GET",
            Some("agent-secret"),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert!(!response.status().is_success());
    assert!(state.policy_hub.connected_gateway_ids().is_empty());
    assert!(
        !state
            .policy_service
            .deployment("gw-1")
            .unwrap()
            .agent_connected
    );
}

#[tokio::test]
async fn policy_mutation_pushes_the_latest_snapshot_and_ack_updates_deployment() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let state = state_with_agent_token();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::public_router(server_state))
            .await
            .unwrap();
    });
    let mut request = format!("ws://{address}/v1/agent/policies/stream")
        .as_str()
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer agent-secret".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let initial = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let initial = PolicyWireFrame::decode(initial.as_bytes()).unwrap();
    assert!(matches!(
        initial,
        PolicyWireFrame::PolicySnapshot {
            config_revision: 0,
            ..
        }
    ));

    let health = PolicyWireFrame::PolicyHealth {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: "gw-1".to_owned(),
        boot_id: "boot-test".to_owned(),
        last_applied_revision: 0,
        controller_epoch: None,
        bundle_generation: None,
        checksum: None,
        capabilities: PolicyCapabilities::unsupported(),
        reported_at_ms: unix_time_ms() as i64,
        emergency_disabled: false,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(health.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    let mut spec = policy_spec("internet");
    spec["enabled"] = serde_json::json!(true);
    spec["selectors"]["clients"] = serde_json::json!(["AA:BB:CC:DD:EE:FF"]);
    let mutation = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/policies")
                .method("POST")
                .header("authorization", "Bearer valid-session")
                .header("if-match", "\"rev:0\"")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mutation.status(), StatusCode::CREATED);

    let pushed = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let pushed = PolicyWireFrame::decode(pushed.as_bytes()).unwrap();
    let (gateway_id, controller_epoch, revision, generation, checksum) =
        pushed.snapshot_identity().unwrap();
    assert_eq!(revision, 1);
    let policy_id = match &pushed {
        PolicyWireFrame::PolicySnapshot { policies, .. } => policies[0].id.clone(),
        _ => unreachable!(),
    };
    let ack = PolicyWireFrame::PolicyAck {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "boot-test".to_owned(),
        controller_epoch: controller_epoch.to_owned(),
        config_revision: revision,
        bundle_generation: generation,
        checksum: checksum.to_owned(),
        status: PolicyAckStatus::Applied,
        capabilities: PolicyCapabilities {
            client_block: PolicyCapability::Supported,
            client_limit: PolicyCapability::Unsupported,
            application_block: PolicyCapability::Unsupported,
            application_limit: PolicyCapability::Unsupported,
        },
        results: vec![PolicyResult {
            policy_id: policy_id.clone(),
            status: PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }],
        reported_at_ms: unix_time_ms() as i64,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(ack.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.policy_service.deployment("gw-1").unwrap().status == "applied" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        state
            .policy_service
            .deployment("gw-1")
            .unwrap()
            .applied_revision,
        1
    );

    // Accept a valid policy drop metric on the authenticated WebSocket and
    // persist it in the deployment view.
    let metrics = PolicyWireFrame::PolicyMetrics {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "boot-test".to_owned(),
        sampled_at_ms: unix_time_ms() as i64,
        metrics: vec![netqmon_protocol::policy::PolicyClientMetrics {
            policy_id: policy_id.clone(),
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            upload: Some(netqmon_protocol::policy::PolicyDirectionMetrics {
                interface: "policy-block".to_owned(),
                bytes: Some(60),
                packets: Some(1),
                drops: Some(1),
                overlimits: None,
            }),
            download: None,
        }],
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(metrics.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let deployment = state.policy_service.deployment("gw-1").unwrap();
            if deployment.policies.iter().any(|policy| {
                policy.policy_id == policy_id
                    && policy.traffic_metrics.iter().any(|metric| {
                        metric.mac == "AA:BB:CC:DD:EE:FF"
                            && metric.upload.as_ref().is_some_and(|upload| {
                                upload.interface == "policy-block"
                                    && upload.bytes == Some(60)
                                    && upload.packets == Some(1)
                                    && upload.drops == Some(1)
                            })
                    })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let metrics = state
        .policy_service
        .deployment("gw-1")
        .unwrap()
        .policies
        .into_iter()
        .find(|policy| policy.policy_id == policy_id)
        .unwrap()
        .traffic_metrics;
    let blocked = metrics[0].upload.as_ref().unwrap();
    assert_eq!(blocked.interface, "policy-block");
    assert_eq!(blocked.bytes, Some(60));
    assert_eq!(blocked.packets, Some(1));
    assert_eq!(blocked.drops, Some(1));

    // A duplicate ACK for the currently sent snapshot is harmless.
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(ack.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    // Advance the desired revision, then replay the older ACK. The stream must
    // reject it without advancing the applied revision.
    let disable = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/internal/policies/{policy_id}/enabled"))
                .method("PATCH")
                .header("authorization", "Bearer valid-session")
                .header("if-match", "\"rev:1\"")
                .header("x-expected-policy-version", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disable.status(), StatusCode::OK);

    let latest = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let latest = PolicyWireFrame::decode(latest.as_bytes()).unwrap();
    assert!(matches!(
        &latest,
        PolicyWireFrame::PolicySnapshot {
            config_revision: 2,
            ..
        }
    ));

    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(ack.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();
    // A stale ACK must not close the stream; it may trigger a resend of the
    // current snapshot, which is also not a close.
    let resent = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resent = match resent {
        tokio_tungstenite::tungstenite::Message::Text(text) => {
            Some(PolicyWireFrame::decode(text.as_bytes()).unwrap())
        }
        tokio_tungstenite::tungstenite::Message::Close(frame) => {
            panic!("stale ack closed the policy stream: {frame:?}")
        }
        _ => None,
    };
    if let Some(resent) = resent {
        assert!(matches!(
            resent,
            PolicyWireFrame::PolicySnapshot {
                config_revision: 2,
                ..
            }
        ));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let deployment = state.policy_service.deployment("gw-1").unwrap();
    assert_eq!(deployment.desired_revision, 2);
    assert_eq!(deployment.applied_revision, 1);
    assert!(deployment.agent_connected);
    server.abort();
}

#[tokio::test]
async fn policy_stream_drops_old_boot_frames_without_closing() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let state = state_with_agent_token();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::public_router(server_state))
            .await
            .unwrap();
    });
    let mut request = format!("ws://{address}/v1/agent/policies/stream")
        .as_str()
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer agent-secret".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let initial = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let initial = PolicyWireFrame::decode(initial.as_bytes()).unwrap();
    let (gateway_id, epoch, _, _, _) = initial.snapshot_identity().unwrap();

    let health = PolicyWireFrame::PolicyHealth {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "current-agent-boot".to_owned(),
        last_applied_revision: 0,
        controller_epoch: None,
        bundle_generation: None,
        checksum: None,
        capabilities: PolicyCapabilities::unsupported(),
        reported_at_ms: unix_time_ms() as i64,
        emergency_disabled: false,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(health.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    let mut spec = policy_spec("internet");
    spec["enabled"] = serde_json::json!(true);
    spec["selectors"]["clients"] = serde_json::json!(["AA:BB:CC:DD:EE:FF"]);
    let mutation = internal_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/internal/policies")
                .method("POST")
                .header("authorization", "Bearer valid-session")
                .header("if-match", "\"rev:0\"")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mutation.status(), StatusCode::CREATED);

    let pushed = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let pushed = PolicyWireFrame::decode(pushed.as_bytes()).unwrap();
    let (gateway_id, controller_epoch, revision, generation, checksum) =
        pushed.snapshot_identity().unwrap();
    assert_eq!(revision, 1);
    assert_eq!(controller_epoch, epoch);
    let policy_id = match &pushed {
        PolicyWireFrame::PolicySnapshot { policies, .. } => policies[0].id.clone(),
        _ => unreachable!(),
    };
    let wrong_boot_ack = PolicyWireFrame::PolicyAck {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "previous-agent-boot".to_owned(),
        controller_epoch: controller_epoch.to_owned(),
        config_revision: revision,
        bundle_generation: generation,
        checksum: checksum.to_owned(),
        status: PolicyAckStatus::Applied,
        capabilities: PolicyCapabilities {
            client_block: PolicyCapability::Supported,
            client_limit: PolicyCapability::Unsupported,
            application_block: PolicyCapability::Unsupported,
            application_limit: PolicyCapability::Unsupported,
        },
        results: vec![PolicyResult {
            policy_id: policy_id.clone(),
            status: PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }],
        reported_at_ms: unix_time_ms() as i64,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(wrong_boot_ack.encode().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

    // A stale boot ACK must be dropped and answered only with the current
    // snapshot, never with a 1008 close.
    let resent = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        matches!(resent, tokio_tungstenite::tungstenite::Message::Text(_)),
        "unexpected message after stale boot ack: {resent:?}"
    );

    let old_boot_flow_ack = PolicyWireFrame::FlowAck {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "previous-agent-boot".to_owned(),
        controller_epoch: controller_epoch.to_owned(),
        config_revision: revision,
        command_id: "old-command".to_owned(),
        policy_flow_id: "00000000000000000000000000000001".to_owned(),
        status: netqmon_protocol::policy::FlowAckStatus::Applied,
        reason_code: None,
        alias_count: 0,
        reported_at_ms: unix_time_ms() as i64,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(old_boot_flow_ack.encode().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    let old_boot_metrics = PolicyWireFrame::PolicyMetrics {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "previous-agent-boot".to_owned(),
        sampled_at_ms: unix_time_ms() as i64,
        metrics: Vec::new(),
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(old_boot_metrics.encode().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

    let ack = PolicyWireFrame::PolicyAck {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: "current-agent-boot".to_owned(),
        controller_epoch: controller_epoch.to_owned(),
        config_revision: revision,
        bundle_generation: generation,
        checksum: checksum.to_owned(),
        status: PolicyAckStatus::Applied,
        capabilities: PolicyCapabilities {
            client_block: PolicyCapability::Supported,
            client_limit: PolicyCapability::Unsupported,
            application_block: PolicyCapability::Unsupported,
            application_limit: PolicyCapability::Unsupported,
        },
        results: vec![PolicyResult {
            policy_id,
            status: PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }],
        reported_at_ms: unix_time_ms() as i64,
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            String::from_utf8(ack.encode().unwrap()).unwrap().into(),
        ))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.policy_service.deployment("gw-1").unwrap().status == "applied" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let deployment = state.policy_service.deployment("gw-1").unwrap();
    assert_eq!(
        deployment.agent_boot_id.as_deref(),
        Some("current-agent-boot")
    );
    assert_eq!(deployment.applied_revision, 1);
    assert!(deployment.agent_connected);
    server.abort();
}

#[tokio::test]
async fn policy_api_checks_gateway_pagination_and_preconditions() {
    let state = state_with_gateway();
    let app = internal_router(state);

    let list = app
        .clone()
        .oneshot(request(
            "/internal/policies?gateway_id=gw-1&page=1&page_size=20",
            "GET",
            Some("valid-session"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 0);
    assert_eq!(value["data"]["desired_revision"], 0);

    let other_gateway = app
        .clone()
        .oneshot(request(
            "/internal/policies?gateway_id=other-gateway",
            "GET",
            Some("valid-session"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(other_gateway.status(), StatusCode::NOT_FOUND);

    let bad_page = app
        .clone()
        .oneshot(request(
            "/internal/policies?gateway_id=gw-1&page=0",
            "GET",
            Some("valid-session"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(bad_page.status(), StatusCode::BAD_REQUEST);

    let missing_revision = app
        .clone()
        .oneshot(request(
            "/internal/policies",
            "POST",
            Some("valid-session"),
            Body::from(serde_json::to_vec(&policy_spec("internet")).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(missing_revision.status(), StatusCode::PRECONDITION_REQUIRED);
}

#[tokio::test]
async fn sqlite_client_options_and_validation_use_canonical_mac_addresses() {
    let state = state_with_gateway();
    let app = internal_router(state);

    let options = app
        .clone()
        .oneshot(request(
            "/internal/policies/options?gateway_id=gw-1&kind=clients&q=aa%3Abb",
            "GET",
            Some("valid-session"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(options.status(), StatusCode::OK);
    let body = to_bytes(options.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"][0]["mac"], "AA:BB:CC:DD:EE:FF");
    assert_eq!(value["data"]["items"][0]["name"], "Office Laptop");

    let mut spec = policy_spec("internet");
    spec["selectors"]["clients"] = serde_json::json!(["aa:bb:cc:dd:ee:ff"]);
    let response = app
        .oneshot(request(
            "/internal/policies/validate",
            "POST",
            Some("valid-session"),
            Body::from(serde_json::to_vec(&serde_json::json!({ "spec": spec })).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["valid"], true);
    assert_eq!(
        value["data"]["normalized_spec"]["selectors"]["clients"][0],
        "AA:BB:CC:DD:EE:FF"
    );
}

#[test]
fn clickhouse_analytics_keeps_a_separate_sqlite_policy_database() {
    let (config, stop_server, server) = mock_clickhouse();
    let clickhouse = ClickHouseStorage::open(config).expect("mock ClickHouse should open");
    let analytics = Storage::clickhouse(clickhouse);
    assert!(analytics.sqlite_connection().is_none());

    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("netqmon-policies.db");
    let policy = PolicyService::open(&policy_path).unwrap();
    assert_eq!(policy.list("gw-1", 1, 20).unwrap().total, 0);
    assert!(policy_path.is_file());

    stop_server.store(true, Ordering::Relaxed);
    server.join().unwrap();
}

fn mock_clickhouse() -> (ClickHouseConfig, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let stop_server = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop_server);
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = serve_clickhouse_request(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
    });
    (
        ClickHouseConfig {
            url: format!("http://{address}"),
            database: "default".to_owned(),
            user: None,
            password: None,
            timeout_ms: 2_000,
        },
        stop_server,
        server,
    )
}

fn serve_clickhouse_request(mut stream: TcpStream) -> std::io::Result<()> {
    // Accepted sockets inherit the listener's nonblocking mode on macOS.
    stream.set_nonblocking(false)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().unwrap_or_default();
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    let response = br#"{"data":[]}"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )?;
    stream.write_all(response)
}

#[tokio::test]
async fn validate_reports_unsupported_scope_without_writing() {
    let state = state_with_gateway();
    let app = internal_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal/policies/validate")
                .method("POST")
                .header("authorization", "Bearer valid-session")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "spec": policy_spec("internal")
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["valid"], false);
    assert!(
        value["data"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| {
                issue["path"] == "network.scope" && issue["code"] == "unsupported_scope"
            })
    );
    assert_eq!(state.policy_service.list("gw-1", 1, 20).unwrap().total, 0);
}

#[tokio::test]
async fn policy_api_rejects_oversized_payloads() {
    let state = state_with_gateway();
    let app = internal_router(state);
    let response = app
        .oneshot(request(
            "/internal/policies/validate",
            "POST",
            Some("valid-session"),
            Body::from(vec![b' '; 64 * 1024 + 1]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
