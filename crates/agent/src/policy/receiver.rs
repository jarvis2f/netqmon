use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use futures_util::{SinkExt as _, StreamExt as _};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use netqmon_protocol::policy::{POLICY_MAX_FRAME_BYTES, PolicyWireFrame};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{WebSocketStream, connect_async_with_config};

use crate::config::AgentConfig;
use crate::transport::Credentials;

use super::executor;
use super::flow_alias::PolicyFlowAliasCache;
use super::flow_verdict::FlowVerdictWriter;
use super::shaper::ShapingState;

const MIN_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct PolicyReceiver {
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl PolicyReceiver {
    pub(crate) fn spawn(
        config: AgentConfig,
        boot_id: String,
        credentials: watch::Receiver<Option<Credentials>>,
        policy_flows_enabled: Arc<AtomicBool>,
        flow_commands_enabled: Arc<AtomicBool>,
        flow_alias_cache: Arc<Mutex<PolicyFlowAliasCache>>,
        flow_verdict_writer: FlowVerdictWriter,
        flow_bpf_ready: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::Builder::new()
            .name("netqmon-policy".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!("policy runtime could not start: {error}");
                        return;
                    }
                };
                runtime.block_on(run(
                    config,
                    boot_id,
                    credentials,
                    policy_flows_enabled,
                    flow_commands_enabled,
                    flow_alias_cache,
                    flow_verdict_writer,
                    flow_bpf_ready,
                    worker_shutdown,
                ));
            })
            .expect("policy receiver thread must start");
        Self {
            shutdown,
            worker: Some(worker),
        }
    }

    pub(crate) fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for PolicyReceiver {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

async fn run(
    config: AgentConfig,
    boot_id: String,
    mut credentials: watch::Receiver<Option<Credentials>>,
    policy_flows_enabled: Arc<AtomicBool>,
    flow_commands_enabled: Arc<AtomicBool>,
    flow_alias_cache: Arc<Mutex<PolicyFlowAliasCache>>,
    mut flow_verdict_writer: FlowVerdictWriter,
    flow_bpf_ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    tokio::spawn(reconcile_loop(
        config.clone(),
        boot_id.clone(),
        credentials.clone(),
        Arc::clone(&flow_bpf_ready),
        Arc::clone(&shutdown),
    ));

    let url = match config.effective_policy_ws_url() {
        Ok(Some(url)) => url,
        Ok(None) => {
            tracing::warn!(
                "policy WebSocket is disabled: configure WSS or opt into loopback/private-network ws://"
            );
            wait_for_shutdown(&shutdown).await;
            return;
        }
        Err(error) => {
            tracing::error!(%error, "policy WebSocket URL is invalid");
            wait_for_shutdown(&shutdown).await;
            return;
        }
    };
    let mut retry_delay = MIN_RETRY;
    let mut startup_restore_checked = false;
    let mut applied_flow_snapshot = None::<(String, u64)>;
    let emergency_disable_applied = AtomicBool::new(false);
    loop {
        if let Err(error) = synchronize_emergency_disable(
            &config,
            &flow_verdict_writer,
            &policy_flows_enabled,
            &flow_commands_enabled,
            &flow_alias_cache,
            &emergency_disable_applied,
        ) {
            tracing::warn!(%error, "could not clear application verdicts after emergency policy disable");
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let credential = credentials.borrow().clone();
        let Some(credential) = credential else {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(250)) => {},
                changed = credentials.changed() => if changed.is_err() { break; },
            }
            continue;
        };
        if !startup_restore_checked {
            if let Some((gateway_id, _)) = executor::restore_local(
                &config,
                &credential.gateway_id,
                &boot_id,
                flow_bpf_ready.load(Ordering::Acquire),
            ) {
                tracing::info!(gateway_id, "restored last persisted policy snapshot");
            }
            startup_restore_checked = true;
        }
        let session = connect_and_run(
            &url,
            &credential,
            &config,
            &boot_id,
            &mut credentials,
            &policy_flows_enabled,
            &flow_commands_enabled,
            &flow_alias_cache,
            &mut flow_verdict_writer,
            &flow_bpf_ready,
            &mut applied_flow_snapshot,
            &emergency_disable_applied,
            &shutdown,
        )
        .await;
        match session {
            Ok(()) => retry_delay = MIN_RETRY,
            Err(error) => {
                tracing::warn!(gateway_id = credential.gateway_id, %error, "policy WebSocket disconnected");
                let mut sleep_remaining = jitter(retry_delay);
                retry_delay = (retry_delay * 2).min(MAX_RETRY);
                'retry_wait: loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break 'retry_wait;
                    }
                    let sleep_for = sleep_remaining.min(Duration::from_secs(1));
                    tokio::select! {
                        _ = tokio::time::sleep(sleep_for) => {},
                        changed = credentials.changed() => {
                            if changed.is_err() { return; }
                            break 'retry_wait;
                        },
                    }
                    if let Err(error) = synchronize_emergency_disable(
                        &config,
                        &flow_verdict_writer,
                        &policy_flows_enabled,
                        &flow_commands_enabled,
                        &flow_alias_cache,
                        &emergency_disable_applied,
                    ) {
                        tracing::warn!(%error, "could not clear application verdicts after emergency policy disable");
                    }
                    if sleep_remaining <= sleep_for {
                        break 'retry_wait;
                    }
                    sleep_remaining -= sleep_for;
                }
            }
        }
    }
}

async fn connect_and_run(
    url: &str,
    credentials: &Credentials,
    config: &AgentConfig,
    boot_id: &str,
    credentials_changed: &mut watch::Receiver<Option<Credentials>>,
    policy_flows_enabled: &AtomicBool,
    flow_commands_enabled: &AtomicBool,
    flow_alias_cache: &Mutex<PolicyFlowAliasCache>,
    flow_verdict_writer: &mut FlowVerdictWriter,
    flow_bpf_ready: &AtomicBool,
    applied_flow_snapshot: &mut Option<(String, u64)>,
    emergency_disable_applied: &AtomicBool,
    shutdown: &AtomicBool,
) -> Result<()> {
    executor::invalidate_gateway_mismatch(config, &credentials.gateway_id)
        .map_err(anyhow::Error::msg)
        .context(
            "local policy state belongs to another gateway and could not be safely quarantined",
        )?;
    let mut request = url
        .into_client_request()
        .context("build policy WebSocket request")?;
    let authorization = format!("Bearer {}", credentials.agent_token);
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&authorization).context("invalid enrollment credential header")?,
    );
    let mut websocket_config = WebSocketConfig::default();
    websocket_config.max_message_size = Some(POLICY_MAX_FRAME_BYTES);
    websocket_config.max_frame_size = Some(POLICY_MAX_FRAME_BYTES);
    let (mut socket, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_async_with_config(request, Some(websocket_config), false),
    )
    .await
    .context("policy WebSocket connection timed out")??;
    send_frame(
        &mut socket,
        &executor::health_frame_with_flow_capability(
            config,
            &credentials.gateway_id,
            boot_id,
            flow_bpf_ready.load(Ordering::Acquire),
        ),
    )
    .await?;

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut policy_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + RECONCILE_INTERVAL,
        RECONCILE_INTERVAL,
    );
    policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut emergency_tick = tokio::time::interval(Duration::from_secs(1));
    emergency_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_reconcile_signature = None::<String>;
    loop {
        tokio::select! {
            changed = credentials_changed.changed() => {
                if changed.is_err() || credentials_changed.borrow().as_ref().is_none_or(|next| next.gateway_id != credentials.gateway_id || next.agent_token != credentials.agent_token) {
                    return Err(anyhow!("enrollment credentials changed"));
                }
            }
            _ = heartbeat.tick() => {
                send_frame(&mut socket, &executor::health_frame_with_flow_capability(config, &credentials.gateway_id, boot_id, flow_bpf_ready.load(Ordering::Acquire))).await?;
            }
            _ = policy_tick.tick() => {
                if let Some(acknowledgement) = executor::reconcile_saved_with_flow_capability(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    flow_bpf_ready.load(Ordering::Acquire),
                ) {
                    if let PolicyWireFrame::PolicyAck {
                        status,
                        capabilities,
                        controller_epoch,
                        config_revision,
                        ..
                    } = &acknowledgement
                    {
                        let has_flow_policy = super::state::load(
                            &config.policy_state_path,
                            &credentials.gateway_id,
                        )
                        .ok()
                        .flatten()
                        .is_some_and(|saved| {
                            snapshot_has_enabled_application_verdicts(&saved.snapshot)
                        });
                        let flow_capability_supported = application_verdict_capable(capabilities);
                        if !std::path::Path::new(&config.policy_disabled_path).exists()
                            && emergency_disable_applied.swap(false, Ordering::AcqRel) {
                            *applied_flow_snapshot = None;
                        }
                        let accepted = matches!(status,
                            netqmon_protocol::policy::PolicyAckStatus::Applied
                                | netqmon_protocol::policy::PolicyAckStatus::Partial);
                        if accepted && flow_bpf_ready.load(Ordering::Acquire)
                            && *applied_flow_snapshot != Some((controller_epoch.clone(), *config_revision)) {
                            match flow_verdict_writer.reset(*config_revision, has_flow_policy && flow_capability_supported) {
                                Ok(()) => *applied_flow_snapshot = Some((controller_epoch.clone(), *config_revision)),
                                Err(error) => {
                                    flow_commands_enabled.store(false, Ordering::Release);
                                    return Err(anyhow!("could not restore BPF policy state: {error}"));
                                }
                            }
                        }
                        let flow_ready = flow_bpf_ready.load(Ordering::Acquire)
                            && !std::path::Path::new(&config.policy_disabled_path).exists();
                        policy_flows_enabled.store(has_flow_policy && flow_ready, Ordering::Release);
                        flow_commands_enabled.store(
                            has_flow_policy
                                && flow_ready
                                && flow_capability_supported
                                && matches!(
                                    status,
                                    netqmon_protocol::policy::PolicyAckStatus::Applied
                                        | netqmon_protocol::policy::PolicyAckStatus::Partial
                                ),
                            Ordering::Release,
                        );
                    }
                    if let Some(signature) = acknowledgement_signature(&acknowledgement) {
                        if last_reconcile_signature.as_ref() != Some(&signature) {
                            send_frame(&mut socket, &acknowledgement).await?;
                            last_reconcile_signature = Some(signature);
                        }
                    }
                }
                for metrics in executor::traffic_metrics_frames(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    flow_verdict_writer,
                ) {
                    send_frame(&mut socket, &metrics).await?;
                }
            }
            _ = emergency_tick.tick() => {
                if let Err(error) = synchronize_emergency_disable(
                    config,
                    flow_verdict_writer,
                    policy_flows_enabled,
                    flow_commands_enabled,
                    flow_alias_cache,
                    emergency_disable_applied,
                ) {
                    tracing::warn!(%error, "could not clear application verdicts after emergency policy disable");
                }
            }
            message = socket.next() => {
                let Some(message) = message else { return Err(anyhow!("policy WebSocket closed")); };
                match message? {
                    Message::Text(text) => handle_frame(&mut socket, text.as_bytes(), credentials, config, boot_id, policy_flows_enabled, flow_commands_enabled, flow_alias_cache, flow_verdict_writer, flow_bpf_ready, applied_flow_snapshot, emergency_disable_applied).await?,
                    Message::Binary(bytes) => handle_frame(&mut socket, bytes.as_ref(), credentials, config, boot_id, policy_flows_enabled, flow_commands_enabled, flow_alias_cache, flow_verdict_writer, flow_bpf_ready, applied_flow_snapshot, emergency_disable_applied).await?,
                    Message::Ping(payload) => socket.send(Message::Pong(payload)).await.context("reply to policy ping")?,
                    Message::Pong(_) => {},
                    Message::Close(_) => return Err(anyhow!("Collector closed the policy WebSocket")),
                    _ => return Err(anyhow!("unsupported policy WebSocket frame")),
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if shutdown.load(Ordering::Relaxed) { return Ok(()); }
            }
        }
    }
}

fn synchronize_emergency_disable(
    config: &AgentConfig,
    flow_verdict_writer: &FlowVerdictWriter,
    policy_flows_enabled: &AtomicBool,
    flow_commands_enabled: &AtomicBool,
    flow_alias_cache: &Mutex<PolicyFlowAliasCache>,
    emergency_disable_applied: &AtomicBool,
) -> Result<(), String> {
    if !std::path::Path::new(&config.policy_disabled_path).exists() {
        return Ok(());
    }

    policy_flows_enabled.store(false, Ordering::Release);
    flow_commands_enabled.store(false, Ordering::Release);
    if emergency_disable_applied.load(Ordering::Acquire) {
        return Ok(());
    }

    if flow_verdict_writer.ready() {
        flow_verdict_writer.reset(0, false)?;
    }
    if let Ok(mut aliases) = flow_alias_cache.lock() {
        aliases.clear();
    }
    emergency_disable_applied.store(true, Ordering::Release);
    tracing::info!("cleared application flow verdicts after emergency policy disable");
    Ok(())
}

fn acknowledgement_signature(frame: &PolicyWireFrame) -> Option<String> {
    let PolicyWireFrame::PolicyAck {
        gateway_id,
        controller_epoch,
        config_revision,
        bundle_generation,
        checksum,
        status,
        capabilities,
        results,
        ..
    } = frame
    else {
        return None;
    };
    serde_json::to_string(&(
        gateway_id,
        controller_epoch,
        config_revision,
        bundle_generation,
        checksum,
        status,
        capabilities,
        results,
    ))
    .ok()
}

async fn handle_frame(
    socket: &mut WebSocketStream<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    bytes: &[u8],
    credentials: &Credentials,
    config: &AgentConfig,
    boot_id: &str,
    policy_flows_enabled: &AtomicBool,
    flow_commands_enabled: &AtomicBool,
    flow_alias_cache: &Mutex<PolicyFlowAliasCache>,
    flow_verdict_writer: &mut FlowVerdictWriter,
    flow_bpf_ready: &AtomicBool,
    applied_flow_snapshot: &mut Option<(String, u64)>,
    emergency_disable_applied: &AtomicBool,
) -> Result<()> {
    if std::path::Path::new(&config.policy_disabled_path).exists() {
        synchronize_emergency_disable(
            config,
            flow_verdict_writer,
            policy_flows_enabled,
            flow_commands_enabled,
            flow_alias_cache,
            emergency_disable_applied,
        )
        .map_err(anyhow::Error::msg)
        .context("could not clear application verdicts after emergency policy disable")?;
    } else if emergency_disable_applied.swap(false, Ordering::AcqRel) {
        *applied_flow_snapshot = None;
    }
    if bytes.len() > POLICY_MAX_FRAME_BYTES {
        return Err(anyhow!("Collector policy frame exceeds 1 MiB"));
    }
    let frame = PolicyWireFrame::decode(bytes)
        .map_err(anyhow::Error::msg)
        .context("Collector sent an invalid policy frame")?;
    match frame {
        snapshot @ PolicyWireFrame::PolicySnapshot { .. } => {
            let flow_bpf_ready = flow_bpf_ready.load(Ordering::Acquire);
            let (frame_gateway, _, _, _, _) = snapshot
                .snapshot_identity()
                .ok_or_else(|| anyhow!("Collector frame was not a snapshot"))?;
            if frame_gateway != credentials.gateway_id {
                return Err(anyhow!(
                    "Collector snapshot gateway binding does not match enrollment"
                ));
            }
            let mut acknowledgement = executor::process_snapshot_with_flow_capability(
                config,
                &credentials.gateway_id,
                boot_id,
                &snapshot,
                flow_bpf_ready,
            );
            let needs_flow_block = matches!(
                &snapshot,
                PolicyWireFrame::PolicySnapshot { policies, .. }
                    if policies.iter().any(|policy| {
                        policy.spec.enabled
                            && (!policy.spec.selectors.applications.is_empty()
                                || !policy.spec.selectors.categories.is_empty())
                            && matches!(
                                policy.spec.action.kind,
                                netqmon_protocol::policy::PolicyActionKind::Block
                                    | netqmon_protocol::policy::PolicyActionKind::Allow
                                    | netqmon_protocol::policy::PolicyActionKind::Limit
                            )
                    })
            );
            let accepted = matches!(
                &acknowledgement,
                PolicyWireFrame::PolicyAck {
                    status: netqmon_protocol::policy::PolicyAckStatus::Applied
                        | netqmon_protocol::policy::PolicyAckStatus::Partial,
                    ..
                }
            );
            if accepted {
                let identity = snapshot
                    .snapshot_identity()
                    .expect("snapshot was validated");
                let revision = identity.2;
                let new_identity = (identity.1.to_owned(), revision);
                let capability_supported = matches!(
                    &acknowledgement,
                    PolicyWireFrame::PolicyAck { capabilities, .. }
                        if application_verdict_capable(capabilities)
                );
                let enabled = needs_flow_block && capability_supported;
                let reset_result =
                    if flow_bpf_ready && *applied_flow_snapshot != Some(new_identity.clone()) {
                        flow_verdict_writer.reset(revision, enabled)
                    } else {
                        Ok(())
                    };
                if let Err(error) = &reset_result {
                    tracing::warn!(gateway_id = credentials.gateway_id, %error, "could not reset exact BPF flow verdict state");
                    mark_flow_capability_unsupported(&mut acknowledgement, &snapshot, error);
                }
                if reset_result.is_ok() && flow_bpf_ready {
                    *applied_flow_snapshot = Some(new_identity);
                } else if reset_result.is_err() {
                    *applied_flow_snapshot = None;
                }
                policy_flows_enabled.store(needs_flow_block, Ordering::Release);
                flow_commands_enabled.store(reset_result.is_ok() && enabled, Ordering::Release);
                if !needs_flow_block && let Ok(mut aliases) = flow_alias_cache.lock() {
                    aliases.clear();
                }
            }
            send_frame(socket, &acknowledgement).await?;
        }
        command @ PolicyWireFrame::FlowCommand { .. } => {
            let acknowledgement = apply_flow_command(
                command,
                &credentials.gateway_id,
                boot_id,
                config,
                flow_alias_cache,
                flow_commands_enabled,
                flow_verdict_writer,
                flow_bpf_ready.load(Ordering::Acquire),
            );
            send_frame(socket, &acknowledgement).await?;
        }
        _ => return Err(anyhow!("Collector may only send policy_snapshot frames")),
    }
    Ok(())
}

fn apply_flow_command(
    frame: PolicyWireFrame,
    gateway_id: &str,
    boot_id: &str,
    config: &AgentConfig,
    flow_alias_cache: &Mutex<PolicyFlowAliasCache>,
    flow_commands_enabled: &AtomicBool,
    flow_verdict_writer: &FlowVerdictWriter,
    flow_bpf_ready: bool,
) -> PolicyWireFrame {
    use netqmon_protocol::policy::{
        FlowAckStatus, FlowCommandOperation, FlowVerdict, POLICY_WIRE_VERSION, PolicyWireFrame,
    };

    let PolicyWireFrame::FlowCommand {
        gateway_id: command_gateway,
        boot_id: command_boot,
        controller_epoch,
        config_revision,
        command_id,
        policy_flow_id,
        operation,
        verdict,
        policy_ids,
        expires_at_ms,
        issued_at_ms,
        ..
    } = frame
    else {
        unreachable!("only flow commands are rejected here")
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(i64::MAX as u128) as i64
        });
    let saved = super::state::load(&config.policy_state_path, gateway_id)
        .ok()
        .flatten();
    let (aliases, client_mac, flow_ended, flow_partial) =
        flow_alias_cache
            .lock()
            .map_or((Vec::new(), None, false, false), |cache| {
                (
                    cache
                        .aliases(&policy_flow_id)
                        .map(<[_]>::to_vec)
                        .unwrap_or_default(),
                    cache.client_mac(&policy_flow_id).map(str::to_owned),
                    cache.is_ended(&policy_flow_id),
                    cache.is_partial(&policy_flow_id),
                )
            });
    let alias_count = u32::try_from(aliases.len()).unwrap_or(u32::MAX);
    let protocol = aliases.first().map(|key| key.protocol);
    let stale_command = flow_alias_cache.lock().map_or(true, |cache| {
        cache.command_is_stale(&policy_flow_id, issued_at_ms)
    });
    let (mut status, mut reason_code) = if command_gateway != gateway_id || command_boot != boot_id
    {
        (
            FlowAckStatus::Failed,
            Some("flow_identity_unresolved".to_owned()),
        )
    } else if expires_at_ms <= now_ms {
        (FlowAckStatus::Expired, Some("expired".to_owned()))
    } else if std::path::Path::new(&config.policy_disabled_path).exists() {
        (
            FlowAckStatus::Unsupported,
            Some("emergency_disabled".to_owned()),
        )
    } else if saved.as_ref().is_none_or(|state| {
        state.controller_epoch != controller_epoch || state.config_revision != config_revision
    }) {
        (
            FlowAckStatus::Unsupported,
            Some("revision_mismatch".to_owned()),
        )
    } else if operation == FlowCommandOperation::Upsert
        && !flow_commands_enabled.load(Ordering::Acquire)
    {
        (
            FlowAckStatus::Unsupported,
            Some("application_policy_disabled".to_owned()),
        )
    } else if operation == FlowCommandOperation::Upsert && !flow_bpf_ready {
        (
            FlowAckStatus::Unsupported,
            Some("application_enforcement_unavailable".to_owned()),
        )
    } else if operation == FlowCommandOperation::Upsert && flow_ended {
        (
            FlowAckStatus::Unsupported,
            Some("flow_identity_unresolved".to_owned()),
        )
    } else if stale_command && alias_count != 0 {
        (
            FlowAckStatus::Expired,
            Some("stale_flow_command".to_owned()),
        )
    } else if alias_count == 0 {
        let no_app_verdicts = saved
            .as_ref()
            .is_some_and(|state| !snapshot_has_enabled_application_verdicts(&state.snapshot));
        if operation == FlowCommandOperation::Revoke && no_app_verdicts {
            (FlowAckStatus::Applied, None)
        } else {
            (
                FlowAckStatus::Unsupported,
                Some("flow_identity_unresolved".to_owned()),
            )
        }
    } else if let Some(protocol) = protocol {
        let ttl_ms = expires_at_ms.saturating_sub(issued_at_ms);
        if (protocol == 17 && ttl_ms > 30_000)
            || (protocol == 6 && ttl_ms > 120_000)
            || !matches!(protocol, 6 | 17)
            || aliases.iter().any(|key| key.protocol != protocol)
        {
            (FlowAckStatus::Failed, Some("invalid_flow_ttl".to_owned()))
        } else if operation == FlowCommandOperation::Upsert
            && !flow_command_policy_references_valid(
                saved.as_ref(),
                &policy_ids,
                verdict,
                issued_at_ms,
                expires_at_ms,
            )
        {
            (
                FlowAckStatus::Failed,
                Some("invalid_policy_reference".to_owned()),
            )
        } else {
            match (operation, verdict) {
                (FlowCommandOperation::Upsert, Some(FlowVerdict::Block)) => {
                    let remaining_ms = expires_at_ms.saturating_sub(now_ms).max(0) as u64;
                    let deadline = crate::linux::monotonic_ns()
                        .saturating_add(remaining_ms.saturating_mul(1_000_000));
                    if let (Some(policy_id), Some(client_mac)) =
                        (policy_ids.first(), client_mac.as_deref())
                    {
                        match flow_verdict_writer.install_block(
                            &aliases,
                            &policy_flow_id,
                            policy_id,
                            client_mac,
                            config_revision,
                            deadline,
                        ) {
                            Ok(_) => {
                                if let Ok(mut cache) = flow_alias_cache.lock() {
                                    cache.record_command(&policy_flow_id, issued_at_ms);
                                }
                                (FlowAckStatus::Applied, None)
                            }
                            Err(_) => (
                                FlowAckStatus::Failed,
                                Some("bpf_map_write_failed".to_owned()),
                            ),
                        }
                    } else {
                        (
                            FlowAckStatus::Failed,
                            Some("flow_identity_unresolved".to_owned()),
                        )
                    }
                }
                (FlowCommandOperation::Upsert, Some(FlowVerdict::Allow)) => {
                    match flow_verdict_writer.clear_aliases(&aliases, Some(&policy_flow_id)) {
                        Ok(_) => {
                            if let Ok(mut cache) = flow_alias_cache.lock() {
                                cache.record_command(&policy_flow_id, issued_at_ms);
                            }
                            (FlowAckStatus::Applied, None)
                        }
                        Err(_) => (
                            FlowAckStatus::Failed,
                            Some("bpf_map_write_failed".to_owned()),
                        ),
                    }
                }
                (FlowCommandOperation::Upsert, Some(FlowVerdict::Shape)) => {
                    let tags = saved
                        .as_ref()
                        .and_then(|state| state.shaping_state.as_ref())
                        .and_then(|shaping| {
                            application_shape_tags(
                                shaping,
                                &aliases,
                                client_mac.as_deref()?,
                                &policy_ids,
                                &|alias| {
                                    flow_alias_cache
                                        .lock()
                                        .ok()
                                        .and_then(|cache| cache.direction(&policy_flow_id, alias))
                                },
                            )
                        });
                    if let Some(tags) = tags {
                        let remaining_ms = expires_at_ms.saturating_sub(now_ms).max(0) as u64;
                        let deadline = crate::linux::monotonic_ns()
                            .saturating_add(remaining_ms.saturating_mul(1_000_000));
                        match flow_verdict_writer.install_shape(
                            &tags,
                            &policy_flow_id,
                            config_revision,
                            deadline,
                        ) {
                            Ok(_) => {
                                if let Ok(mut cache) = flow_alias_cache.lock() {
                                    cache.record_command(&policy_flow_id, issued_at_ms);
                                }
                                (FlowAckStatus::Applied, None)
                            }
                            Err(_) => (
                                FlowAckStatus::Failed,
                                Some("bpf_map_write_failed".to_owned()),
                            ),
                        }
                    } else {
                        if config.log_level >= crate::config::LogLevel::Debug {
                            eprintln!(
                                "application class unresolved: flow={policy_flow_id} client={client_mac:?} policies={policy_ids:?} aliases={aliases:?} directions={:?} classes={:?}",
                                aliases
                                    .iter()
                                    .map(|alias| flow_alias_cache
                                        .lock()
                                        .ok()
                                        .and_then(|cache| cache.direction(&policy_flow_id, alias)))
                                    .collect::<Vec<_>>(),
                                saved
                                    .as_ref()
                                    .and_then(|state| state.shaping_state.as_ref())
                                    .map(|shaping| shaping
                                        .interfaces()
                                        .flat_map(|interface| &interface.application_classes)
                                        .collect::<Vec<_>>())
                            );
                        }
                        (
                            FlowAckStatus::Unsupported,
                            Some("application_class_unresolved".to_owned()),
                        )
                    }
                }
                (FlowCommandOperation::Revoke, None) => {
                    match flow_verdict_writer.clear_aliases(&aliases, Some(&policy_flow_id)) {
                        Ok(_) => {
                            if let Ok(mut cache) = flow_alias_cache.lock() {
                                cache.record_command(&policy_flow_id, issued_at_ms);
                            }
                            (FlowAckStatus::Applied, None)
                        }
                        Err(_) => (
                            FlowAckStatus::Failed,
                            Some("bpf_map_write_failed".to_owned()),
                        ),
                    }
                }
                _ => (
                    FlowAckStatus::Failed,
                    Some("invalid_flow_operation".to_owned()),
                ),
            }
        }
    } else {
        (
            FlowAckStatus::Unsupported,
            Some("flow_identity_unresolved".to_owned()),
        )
    };
    if flow_partial && status == FlowAckStatus::Applied {
        status = FlowAckStatus::Partial;
        reason_code = Some("partial_coverage".to_owned());
    }
    PolicyWireFrame::FlowAck {
        wire_version: POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: boot_id.to_owned(),
        controller_epoch,
        command_id,
        policy_flow_id,
        config_revision,
        status,
        reason_code,
        alias_count,
        reported_at_ms: now_ms,
    }
}

fn application_verdict_capable(
    capabilities: &netqmon_protocol::policy::PolicyCapabilities,
) -> bool {
    use netqmon_protocol::policy::PolicyCapability;
    capabilities.application_block != PolicyCapability::Unsupported
        || capabilities.application_limit == PolicyCapability::Supported
}

fn snapshot_has_enabled_application_verdicts(snapshot: &PolicyWireFrame) -> bool {
    let PolicyWireFrame::PolicySnapshot { policies, .. } = snapshot else {
        return false;
    };
    policies.iter().any(|policy| {
        policy.spec.enabled
            && (!policy.spec.selectors.applications.is_empty()
                || !policy.spec.selectors.categories.is_empty())
            && matches!(
                policy.spec.action.kind,
                netqmon_protocol::policy::PolicyActionKind::Block
                    | netqmon_protocol::policy::PolicyActionKind::Allow
                    | netqmon_protocol::policy::PolicyActionKind::Limit
            )
    })
}

fn application_shape_tags(
    shaping: &ShapingState,
    aliases: &[crate::flow::FlowKey],
    client_mac: &str,
    policy_ids: &[String],
    direction: &impl Fn(&crate::flow::FlowKey) -> Option<super::shaper::Direction>,
) -> Option<Vec<(crate::flow::FlowKey, u16)>> {
    let mut tags = Vec::new();
    for alias in aliases.iter().filter(|alias| alias.hook == 2) {
        let class = policy_ids.iter().find_map(|policy_id| {
            shaping
                .interfaces()
                .filter(|interface| interface.ifindex == alias.ifindex)
                .find_map(|interface| {
                    interface.application_classes.iter().find(|class| {
                        class.policy_id == *policy_id
                            && class.mac.eq_ignore_ascii_case(client_mac)
                            && class.ifindex == alias.ifindex
                            && (!interface.shared_egress
                                || direction(alias) == Some(class.direction))
                    })
                })
        });
        if let Some(class) = class {
            tags.push((alias.clone(), class.tag));
        }
    }
    (!tags.is_empty()).then_some(tags)
}

fn mark_flow_capability_unsupported(
    acknowledgement: &mut PolicyWireFrame,
    snapshot: &PolicyWireFrame,
    error: &str,
) {
    use netqmon_protocol::policy::{
        PolicyAckStatus, PolicyCapability, PolicyResultStatus, PolicyWireFrame,
    };

    let PolicyWireFrame::PolicyAck {
        status,
        capabilities,
        results,
        ..
    } = acknowledgement
    else {
        return;
    };
    capabilities.application_block = PolicyCapability::Unsupported;
    capabilities.application_limit = PolicyCapability::Unsupported;
    if *status == PolicyAckStatus::Applied {
        *status = PolicyAckStatus::Partial;
    }
    let app_policy_ids = match snapshot {
        PolicyWireFrame::PolicySnapshot { policies, .. } => policies
            .iter()
            .filter(|policy| {
                policy.spec.enabled
                    && (!policy.spec.selectors.applications.is_empty()
                        || !policy.spec.selectors.categories.is_empty())
                    && matches!(
                        policy.spec.action.kind,
                        netqmon_protocol::policy::PolicyActionKind::Block
                            | netqmon_protocol::policy::PolicyActionKind::Allow
                            | netqmon_protocol::policy::PolicyActionKind::Limit
                    )
            })
            .map(|policy| policy.id.as_str())
            .collect::<std::collections::HashSet<_>>(),
        _ => return,
    };
    for result in results
        .iter_mut()
        .filter(|result| app_policy_ids.contains(result.policy_id.as_str()))
    {
        result.status = PolicyResultStatus::Unsupported;
        result.reason_code = Some("unsupported_bpf_verifier".to_owned());
        result.message = Some(format!("exact BPF flow verdict setup failed: {error}"));
    }
}

fn flow_command_policy_references_valid(
    state: Option<&super::state::PolicyState>,
    policy_ids: &[String],
    verdict: Option<netqmon_protocol::policy::FlowVerdict>,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> bool {
    use netqmon_protocol::policy::{FlowVerdict, PolicyActionKind, PolicyWireFrame};

    let Some(state) = state else {
        return false;
    };
    let PolicyWireFrame::PolicySnapshot {
        policies,
        schedule_intervals,
        valid_until_ms,
        ..
    } = &state.snapshot
    else {
        return false;
    };
    if policy_ids.is_empty() || issued_at_ms >= expires_at_ms || expires_at_ms > *valid_until_ms {
        return false;
    }
    policy_ids.iter().all(|policy_id| {
        let Some(policy) = policies.iter().find(|policy| policy.id == *policy_id) else {
            return false;
        };
        let active_schedule = if policy.spec.schedule.is_some() {
            schedule_intervals
                .iter()
                .find(|intervals| intervals.policy_id == *policy_id)
                .and_then(|intervals| {
                    intervals.intervals.iter().find(|interval| {
                        interval.start_ms <= issued_at_ms && issued_at_ms < interval.end_ms
                    })
                })
                .is_some_and(|interval| expires_at_ms <= interval.end_ms)
        } else {
            true
        };
        active_schedule
            && policy.spec.enabled
            && (!policy.spec.selectors.applications.is_empty()
                || !policy.spec.selectors.categories.is_empty())
            && (match verdict {
                Some(FlowVerdict::Block) => policy.spec.action.kind == PolicyActionKind::Block,
                Some(FlowVerdict::Allow) => policy.spec.action.kind == PolicyActionKind::Allow,
                Some(FlowVerdict::Shape) => {
                    policy.spec.action.kind == PolicyActionKind::Limit
                        && !policy.spec.selectors.clients.is_empty()
                }
                None => false,
            })
    })
}

async fn send_frame(
    socket: &mut WebSocketStream<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    frame: &PolicyWireFrame,
) -> Result<()> {
    let bytes = frame
        .encode()
        .map_err(anyhow::Error::msg)
        .context("encode policy health or acknowledgement")?;
    socket
        .send(Message::Text(
            String::from_utf8_lossy(&bytes).into_owned().into(),
        ))
        .await
        .context("send policy frame")
}

async fn reconcile_loop(
    config: AgentConfig,
    boot_id: String,
    credentials: watch::Receiver<Option<Credentials>>,
    flow_bpf_ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if shutdown.load(Ordering::Relaxed) { return; }
                if std::path::Path::new(&config.policy_disabled_path).exists() { continue; }
                let Ok(Some(saved)) = super::state::load_any(&config.policy_state_path) else { continue; };
                let Some(credential) = credentials.borrow().clone() else { continue; };
                if credential.gateway_id != saved.gateway_id { continue; }
                if let Some(ack) = executor::reconcile_saved_with_flow_capability(&config, &saved.gateway_id, &boot_id, flow_bpf_ready.load(Ordering::Acquire)) {
                    if matches!(ack, PolicyWireFrame::PolicyAck { status: netqmon_protocol::policy::PolicyAckStatus::Failed, .. }) {
                        tracing::debug!(gateway_id = saved.gateway_id, "local policy schedule reconciliation reported failure");
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if shutdown.load(Ordering::Relaxed) { return; }
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn jitter(delay: Duration) -> Duration {
    let mut random = [0u8; 2];
    if getrandom::fill(&mut random).is_err() {
        return delay;
    }
    let basis_points = u16::from_be_bytes(random) % 4_001;
    let multiplier = 8_000_u128 + u128::from(basis_points);
    let millis = delay.as_millis().saturating_mul(multiplier) / 10_000;
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    #[test]
    fn degraded_application_block_enables_verdicts_but_degraded_shaping_does_not() {
        use netqmon_protocol::policy::{PolicyCapabilities, PolicyCapability};
        let mut capabilities = PolicyCapabilities::unsupported();
        assert!(!super::application_verdict_capable(&capabilities));
        capabilities.application_block = PolicyCapability::Degraded;
        assert!(super::application_verdict_capable(&capabilities));
        capabilities.application_block = PolicyCapability::Unsupported;
        capabilities.application_limit = PolicyCapability::Degraded;
        assert!(!super::application_verdict_capable(&capabilities));
        capabilities.application_limit = PolicyCapability::Supported;
        assert!(super::application_verdict_capable(&capabilities));
    }

    use super::*;
    use crate::flow::FlowKey;
    use crate::policy::shaper::{
        Direction, ManagedInterface, allocate_application_classes, allocate_classes,
    };

    fn flow_key(hook: u8, ifindex: u32) -> FlowKey {
        FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            hook,
            ifindex,
            source_address: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination_address: [198, 51, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 50_000,
            destination_port: 443,
        }
    }

    fn shaping_state() -> ShapingState {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let clients = allocate_classes(
            "gw-test",
            Direction::Upload,
            "eth0",
            2,
            &std::collections::BTreeMap::from([(mac.clone(), 8_000_000)]),
            &[],
        )
        .unwrap();
        let applications = allocate_application_classes(
            "gw-test",
            Direction::Upload,
            "eth0",
            2,
            &std::collections::BTreeMap::from([(("policy-a".to_owned(), mac), 4_000_000)]),
            &clients,
            &[],
        )
        .unwrap();
        ShapingState {
            shared_egress: None,
            schema_version: 1,
            upload_interface: Some(ManagedInterface {
                shared_egress: false,
                name: "eth0".to_owned(),
                ifindex: 2,
                capacity_bps: 100_000_000,
                original_root_kind: "noqueue".to_owned(),
                clients,
                application_classes: applications,
            }),
            download_interface: None,
        }
    }

    #[test]
    fn retry_jitter_stays_within_twenty_percent() {
        let base = Duration::from_secs(10);
        for _ in 0..100 {
            let result = jitter(base);
            assert!(result >= Duration::from_secs(8));
            assert!(result <= Duration::from_millis(12_000));
        }
    }

    #[test]
    fn shape_commands_tag_only_managed_egress_aliases_for_the_selected_client_and_policy() {
        let shaping = shaping_state();
        let aliases = [flow_key(1, 1), flow_key(2, 2)];
        let policy_ids = vec!["policy-a".to_owned()];
        let tags = application_shape_tags(
            &shaping,
            &aliases,
            "AA:BB:CC:DD:EE:FF",
            &policy_ids,
            &|_| None,
        )
        .unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].0, aliases[1]);
        assert_eq!(
            Some(tags[0].1),
            shaping
                .upload_interface
                .as_ref()
                .unwrap()
                .application_classes
                .first()
                .map(|class| class.tag)
        );
        assert!(
            application_shape_tags(
                &shaping,
                &aliases,
                "00:11:22:33:44:55",
                &policy_ids,
                &|_| None
            )
            .is_none()
        );
        assert!(
            application_shape_tags(
                &shaping,
                &aliases,
                "aa:bb:cc:dd:ee:ff",
                &["another-policy".to_owned()],
                &|_| None,
            )
            .is_none()
        );
    }

    #[test]
    fn shared_interface_aliases_select_application_classes_by_normalized_direction() {
        let mut shaping = shaping_state();
        let mut shared = shaping.upload_interface.take().unwrap();
        shared.shared_egress = true;
        let mut download = shared.application_classes[0].clone();
        download.direction = Direction::Download;
        download.tag = 2;
        shared.application_classes.push(download);
        let upload_tag = shared.application_classes[0].tag;
        shaping.shared_egress = Some(shared);
        let up = flow_key(2, 2);
        let mut down = up.clone();
        down.source_port += 1;
        let aliases = [up.clone(), down.clone()];
        let policy_ids = vec!["policy-a".to_owned()];
        let tags = application_shape_tags(
            &shaping,
            &aliases,
            "AA:BB:CC:DD:EE:FF",
            &policy_ids,
            &|key| {
                Some(if key == &up {
                    Direction::Upload
                } else {
                    Direction::Download
                })
            },
        )
        .unwrap();
        assert_eq!(tags, vec![(up, upload_tag), (down, 2)]);
        assert!(
            application_shape_tags(
                &shaping,
                &aliases,
                "AA:BB:CC:DD:EE:FF",
                &policy_ids,
                &|_| None
            )
            .is_none()
        );
    }
}
