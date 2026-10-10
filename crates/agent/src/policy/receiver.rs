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
use crate::conntrack::{ConntrackContext, ProxySocketContext, SharedConntrack};
#[cfg(feature = "qos-client-priority")]
use crate::linux::qos_priority_runtime::PriorityRuntime;
use crate::topology::TopologyContext;
use crate::transport::Credentials;

use super::executor;
#[cfg(feature = "qos-client-priority")]
use super::flow_alias::AliasDirection;
use super::flow_alias::{PolicyFlowAliasCache, proxy_return_aliases, proxy_socket_return_aliases};
use super::flow_verdict::FlowVerdictWriter;
use super::shape_tags::ShapeTagRejection;
#[cfg(feature = "qos-client-priority")]
use super::shape_tags::{ShapeTagGap, priority_application_shape_tags};
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

fn restore_local(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_bpf_ready: bool,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
) -> Option<(String, PolicyWireFrame)> {
    #[cfg(feature = "qos-client-priority")]
    if let Some(priority_runtime) = priority_runtime {
        let restored =
            priority_runtime
                .lock()
                .ok()?
                .restore_local(gateway_id, boot_id, flow_bpf_ready)?;
        return Some((gateway_id.to_owned(), restored));
    }
    executor::restore_local(config, gateway_id, boot_id, flow_bpf_ready)
}

fn reconcile_saved(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_bpf_ready: bool,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
) -> Option<PolicyWireFrame> {
    #[cfg(feature = "qos-client-priority")]
    if let Some(priority_runtime) = priority_runtime {
        return priority_runtime
            .lock()
            .ok()?
            .reconcile_saved(gateway_id, boot_id, flow_bpf_ready);
    }
    executor::reconcile_saved_with_flow_capability(config, gateway_id, boot_id, flow_bpf_ready)
}

fn has_enabled_application_flow_policy(
    config: &AgentConfig,
    gateway_id: &str,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
) -> bool {
    #[cfg(feature = "qos-client-priority")]
    if let Some(priority_runtime) = priority_runtime {
        return priority_runtime
            .lock()
            .is_ok_and(|runtime| runtime.has_enabled_application_flow_policy());
    }

    super::state::load(&config.policy_state_path, gateway_id)
        .ok()
        .flatten()
        .is_some_and(|saved| super::snapshot_has_enabled_application_verdicts(&saved.snapshot))
}

fn health_frame_for_runtime(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_bpf_ready: bool,
    priority_runtime_active: bool,
) -> PolicyWireFrame {
    let mut frame =
        executor::health_frame_with_flow_capability(config, gateway_id, boot_id, flow_bpf_ready);
    if priority_runtime_active
        && let PolicyWireFrame::PolicyHealth { capabilities, .. } = &mut frame
    {
        *capabilities =
            executor::priority_runtime_capabilities(flow_bpf_ready, capabilities.client_block);
    }
    frame
}

fn flow_identity_tracking_enabled(flow_bpf_ready: bool, emergency_disabled: bool) -> bool {
    flow_bpf_ready && !emergency_disabled
}

fn no_app_verdicts_for_empty_alias_revoke(
    saved_snapshot_has_app_verdicts: bool,
    priority_runtime_has_app_verdicts: Option<bool>,
) -> bool {
    !priority_runtime_has_app_verdicts.unwrap_or(saved_snapshot_has_app_verdicts)
}

impl PolicyReceiver {
    pub(crate) fn spawn(
        config: AgentConfig,
        boot_id: String,
        credentials: watch::Receiver<Option<Credentials>>,
        policy_flows_enabled: Arc<AtomicBool>,
        flow_commands_enabled: Arc<AtomicBool>,
        flow_alias_cache: Arc<Mutex<PolicyFlowAliasCache>>,
        conntrack: SharedConntrack,
        topology: Arc<TopologyContext>,
        flow_verdict_writer: FlowVerdictWriter,
        flow_bpf_ready: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
        #[cfg(feature = "qos-client-priority")] priority_runtime: Option<
            Arc<Mutex<PriorityRuntime>>,
        >,
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
                    conntrack,
                    topology,
                    flow_verdict_writer,
                    flow_bpf_ready,
                    worker_shutdown,
                    #[cfg(feature = "qos-client-priority")]
                    priority_runtime,
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
    conntrack: SharedConntrack,
    topology: Arc<TopologyContext>,
    mut flow_verdict_writer: FlowVerdictWriter,
    flow_bpf_ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<Arc<Mutex<PriorityRuntime>>>,
) {
    let stream_connected = Arc::new(AtomicBool::new(false));
    tokio::spawn(reconcile_loop(
        config.clone(),
        boot_id.clone(),
        credentials.clone(),
        Arc::clone(&flow_bpf_ready),
        Arc::clone(&stream_connected),
        Arc::clone(&shutdown),
        #[cfg(feature = "qos-client-priority")]
        priority_runtime.clone(),
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
    let mut applied_flow_snapshot = None::<(String, u64, u64, String)>;
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
        #[cfg(feature = "qos-client-priority")]
        if let Err(error) =
            synchronize_priority_emergency_disable(&config, priority_runtime.as_ref())
        {
            tracing::warn!(%error, "could not bypass client budgets after emergency policy disable");
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
            if let Some((gateway_id, _)) = restore_local(
                &config,
                &credential.gateway_id,
                &boot_id,
                flow_bpf_ready.load(Ordering::Acquire),
                #[cfg(feature = "qos-client-priority")]
                priority_runtime.as_ref(),
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
            &conntrack,
            &topology,
            &mut flow_verdict_writer,
            &flow_bpf_ready,
            &mut applied_flow_snapshot,
            &emergency_disable_applied,
            &stream_connected,
            &shutdown,
            #[cfg(feature = "qos-client-priority")]
            priority_runtime.clone(),
        )
        .await;
        stream_connected.store(false, Ordering::Release);
        match session {
            Ok(()) => retry_delay = MIN_RETRY,
            Err(error) => {
                tracing::warn!(gateway_id = credential.gateway_id, %error, "policy WebSocket disconnected");
                // Policy tracing has no subscriber in the Agent process; keep
                // the reconnect cause visible in the service log.
                eprintln!("policy WebSocket disconnected: {error:#}");
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
                    #[cfg(feature = "qos-client-priority")]
                    if let Err(error) =
                        synchronize_priority_emergency_disable(&config, priority_runtime.as_ref())
                    {
                        tracing::warn!(%error, "could not bypass client budgets after emergency policy disable");
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
    conntrack: &SharedConntrack,
    topology: &TopologyContext,
    flow_verdict_writer: &mut FlowVerdictWriter,
    flow_bpf_ready: &AtomicBool,
    applied_flow_snapshot: &mut Option<(String, u64, u64, String)>,
    emergency_disable_applied: &AtomicBool,
    stream_connected: &AtomicBool,
    shutdown: &AtomicBool,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<Arc<Mutex<PriorityRuntime>>>,
) -> Result<()> {
    #[cfg(feature = "qos-client-priority")]
    if priority_runtime.is_none() {
        executor::invalidate_gateway_mismatch(config, &credentials.gateway_id)
            .map_err(anyhow::Error::msg)
            .context(
                "local policy state belongs to another gateway and could not be safely quarantined",
            )?;
    }
    #[cfg(not(feature = "qos-client-priority"))]
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
    stream_connected.store(true, Ordering::Release);
    #[cfg(feature = "qos-client-priority")]
    let priority_runtime_active = priority_runtime.is_some();
    #[cfg(not(feature = "qos-client-priority"))]
    let priority_runtime_active = false;
    tracing::info!(
        policy_backend = if priority_runtime_active {
            "priority"
        } else {
            "legacy"
        },
        "policy execution backend selected"
    );
    send_frame(
        &mut socket,
        &health_frame_for_runtime(
            config,
            &credentials.gateway_id,
            boot_id,
            flow_bpf_ready.load(Ordering::Acquire),
            priority_runtime_active,
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
                send_frame(&mut socket, &health_frame_for_runtime(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    flow_bpf_ready.load(Ordering::Acquire),
                    priority_runtime_active,
                )).await?;
            }
            _ = policy_tick.tick() => {
                if let Some(acknowledgement) = reconcile_saved(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    flow_bpf_ready.load(Ordering::Acquire),
                    #[cfg(feature = "qos-client-priority")]
                    priority_runtime.as_ref(),
                ) {
                    if let PolicyWireFrame::PolicyAck {
                        status,
                        capabilities,
                        controller_epoch,
                        config_revision,
                        bundle_generation,
                        checksum,
                        ..
                    } = &acknowledgement
                    {
                        let has_flow_policy = has_enabled_application_flow_policy(
                            config,
                            &credentials.gateway_id,
                            #[cfg(feature = "qos-client-priority")]
                            priority_runtime.as_ref(),
                        );
                        let flow_capability_supported = application_verdict_capable(capabilities);
                        if !std::path::Path::new(&config.policy_disabled_path).exists()
                            && emergency_disable_applied.swap(false, Ordering::AcqRel) {
                            *applied_flow_snapshot = None;
                        }
                        let accepted = matches!(status,
                            netqmon_protocol::policy::PolicyAckStatus::Applied
                                | netqmon_protocol::policy::PolicyAckStatus::Partial);
                        if accepted && flow_bpf_ready.load(Ordering::Acquire)
                            && *applied_flow_snapshot != Some((controller_epoch.clone(), *config_revision, *bundle_generation, checksum.clone())) {
                            match flow_verdict_writer.reset(*config_revision, has_flow_policy && flow_capability_supported) {
                                Ok(()) => *applied_flow_snapshot = Some((controller_epoch.clone(), *config_revision, *bundle_generation, checksum.clone())),
                                Err(error) => {
                                    flow_commands_enabled.store(false, Ordering::Release);
                                    return Err(anyhow!("could not restore BPF policy state: {error}"));
                                }
                            }
                        }
                        let flow_ready = flow_identity_tracking_enabled(
                            flow_bpf_ready.load(Ordering::Acquire),
                            std::path::Path::new(&config.policy_disabled_path).exists(),
                        );
                        // Identity tracking must be live before an application policy exists:
                        // the Collector needs a Flow ID before it can return an exact-flow
                        // command. `flow_commands_enabled` remains gated by an accepted policy.
                        policy_flows_enabled.store(flow_ready, Ordering::Release);
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
                #[cfg(feature = "qos-client-priority")]
                let metric_frames = if let Some(runtime) = priority_runtime.as_ref() {
                    executor::traffic_metrics_frames_priority(
                        &credentials.gateway_id,
                        boot_id,
                        flow_verdict_writer,
                        runtime,
                    )
                } else {
                    executor::traffic_metrics_frames(
                        config,
                        &credentials.gateway_id,
                        boot_id,
                        flow_verdict_writer,
                    )
                };
                #[cfg(not(feature = "qos-client-priority"))]
                let metric_frames = executor::traffic_metrics_frames(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    flow_verdict_writer,
                );
                for metrics in metric_frames {
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
                #[cfg(feature = "qos-client-priority")]
                if let Err(error) = synchronize_priority_emergency_disable(
                    config,
                    priority_runtime.as_ref(),
                ) {
                    tracing::warn!(%error, "could not bypass client budgets after emergency policy disable");
                }
            }
            message = socket.next() => {
                let Some(message) = message else { return Err(anyhow!("policy WebSocket closed")); };
                match message? {
                    Message::Text(text) => handle_frame(&mut socket, text.as_bytes(), credentials, config, boot_id, policy_flows_enabled, flow_commands_enabled, flow_alias_cache, conntrack, topology, flow_verdict_writer, flow_bpf_ready, applied_flow_snapshot, &mut last_reconcile_signature, emergency_disable_applied, #[cfg(feature = "qos-client-priority")] priority_runtime.as_ref()).await?,
                    Message::Binary(bytes) => handle_frame(&mut socket, bytes.as_ref(), credentials, config, boot_id, policy_flows_enabled, flow_commands_enabled, flow_alias_cache, conntrack, topology, flow_verdict_writer, flow_bpf_ready, applied_flow_snapshot, &mut last_reconcile_signature, emergency_disable_applied, #[cfg(feature = "qos-client-priority")] priority_runtime.as_ref()).await?,
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

#[cfg(feature = "qos-client-priority")]
fn synchronize_priority_emergency_disable(
    config: &AgentConfig,
    priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
) -> Result<(), String> {
    if !std::path::Path::new(&config.policy_disabled_path).exists() {
        return Ok(());
    }
    let Some(priority_runtime) = priority_runtime else {
        return Ok(());
    };
    priority_runtime
        .lock()
        .map_err(|_| "priority runtime lock poisoned".to_owned())?
        .emergency_disable()
        .map_err(|error| format!("{error:#}"))
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
    conntrack: &SharedConntrack,
    topology: &TopologyContext,
    flow_verdict_writer: &mut FlowVerdictWriter,
    flow_bpf_ready: &AtomicBool,
    applied_flow_snapshot: &mut Option<(String, u64, u64, String)>,
    last_reconcile_signature: &mut Option<String>,
    emergency_disable_applied: &AtomicBool,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
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
        #[cfg(feature = "qos-client-priority")]
        if let Some(priority_runtime) = priority_runtime {
            priority_runtime
                .lock()
                .map_err(|_| anyhow!("priority runtime lock poisoned"))?
                .emergency_disable()
                .context("could not bypass client HTB assignments after emergency disable")?;
        }
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
            #[cfg(feature = "qos-client-priority")]
            let mut acknowledgement = if let Some(priority_runtime) = priority_runtime {
                let mut runtime = priority_runtime
                    .lock()
                    .map_err(|_| anyhow!("priority runtime lock poisoned"))?;
                runtime.apply_snapshot(&snapshot, &credentials.gateway_id, boot_id, flow_bpf_ready)
            } else {
                executor::process_snapshot_with_flow_capability(
                    config,
                    &credentials.gateway_id,
                    boot_id,
                    &snapshot,
                    flow_bpf_ready,
                )
            };
            #[cfg(not(feature = "qos-client-priority"))]
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
                let new_identity = (
                    identity.1.to_owned(),
                    revision,
                    identity.3,
                    identity.4.to_owned(),
                );
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
                    #[cfg(feature = "qos-client-priority")]
                    if let Some(priority_runtime) = priority_runtime {
                        let cleanup_result = priority_runtime
                            .lock()
                            .map_err(|_| anyhow!("priority runtime lock poisoned"))
                            .and_then(|runtime| runtime.prune_unused_classes_after_flow_reset());
                        if let Err(error) = cleanup_result {
                            tracing::warn!(
                                gateway_id = credentials.gateway_id,
                                revision,
                                %error,
                                "could not remove unused Agent-owned priority classes"
                            );
                            mark_priority_class_cleanup_degraded(
                                &mut acknowledgement,
                                &snapshot,
                                &format!("{error:#}"),
                            );
                        }
                    }
                } else if reset_result.is_err() {
                    *applied_flow_snapshot = None;
                }
                // Keep emitting exact identities before the Collector has an application
                // policy to request. Enforcement remains gated by `flow_commands_enabled`.
                policy_flows_enabled.store(
                    flow_identity_tracking_enabled(
                        flow_bpf_ready,
                        std::path::Path::new(&config.policy_disabled_path).exists(),
                    ),
                    Ordering::Release,
                );
                flow_commands_enabled.store(reset_result.is_ok() && enabled, Ordering::Release);
                if !needs_flow_block && let Ok(mut aliases) = flow_alias_cache.lock() {
                    aliases.clear();
                }
            }
            send_frame(socket, &acknowledgement).await?;
            *last_reconcile_signature = acknowledgement_signature(&acknowledgement);
        }
        command @ PolicyWireFrame::FlowCommand { .. } => {
            let acknowledgement = apply_flow_command(
                command,
                &credentials.gateway_id,
                boot_id,
                config,
                flow_alias_cache,
                &conntrack,
                &topology,
                flow_commands_enabled,
                flow_verdict_writer,
                flow_bpf_ready.load(Ordering::Acquire),
                #[cfg(feature = "qos-client-priority")]
                priority_runtime,
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
    conntrack: &SharedConntrack,
    topology: &TopologyContext,
    flow_commands_enabled: &AtomicBool,
    flow_verdict_writer: &FlowVerdictWriter,
    flow_bpf_ready: bool,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<&Arc<Mutex<PriorityRuntime>>>,
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
    let (mut base_aliases, cached_client_mac) = flow_alias_cache
        .lock()
        .ok()
        .map(|cache| {
            (
                cache
                    .aliases(&policy_flow_id)
                    .map(<[_]>::to_vec)
                    .unwrap_or_default(),
                cache.client_mac(&policy_flow_id).map(str::to_owned),
            )
        })
        .unwrap_or_default();
    let mut conntrack_snapshot = conntrack
        .read()
        .map(|snapshot| Arc::clone(&snapshot))
        .unwrap_or_default();
    if operation == FlowCommandOperation::Upsert
        && base_aliases
            .iter()
            .any(|alias| conntrack_snapshot.resolve(alias).is_none())
    {
        // The observer refreshes conntrack every five seconds. A newly
        // established flow can therefore reach its first FlowCommand before
        // that snapshot contains the entry. Refresh once at the command
        // boundary and publish the updated snapshot to SharedConntrack.
        let refreshed = Arc::new(ConntrackContext::discover());
        if let Ok(mut guard) = conntrack.write() {
            *guard = Arc::clone(&refreshed);
        }
        conntrack_snapshot = refreshed;
    }
    #[cfg(feature = "qos-client-priority")]
    let client_delivery_ifindex = cached_client_mac.as_deref().and_then(|mac| {
        priority_runtime
            .and_then(|runtime| runtime.lock().ok())
            .and_then(|runtime| runtime.client_delivery_ifindex(mac))
    });
    #[cfg(not(feature = "qos-client-priority"))]
    let client_delivery_ifindex: Option<u32> = None;
    if operation == FlowCommandOperation::Upsert
        && let Ok(mut cache) = flow_alias_cache.lock()
    {
        cache.reconcile_for_command(
            &policy_flow_id,
            client_delivery_ifindex,
            &conntrack_snapshot,
        );
        if let Some(updated) = cache.aliases(&policy_flow_id) {
            base_aliases = updated.to_vec();
        }
    }
    let mut proxy_resolution = proxy_return_aliases(&base_aliases, &conntrack_snapshot, topology);
    if !proxy_resolution.expected && proxy_resolution.aliases.is_empty() {
        // REDIRECT can terminate the connection in the local proxy without
        // exposing the translated reply tuple through conntrack. The exact
        // accepted proxy socket (client IP + client port) is independent
        // kernel evidence for the same connection.
        let sockets = ProxySocketContext::discover();
        let socket_resolution = proxy_socket_return_aliases(&base_aliases, &sockets, topology);
        if socket_resolution.expected {
            proxy_resolution = socket_resolution;
        }
    }
    if proxy_resolution.expected || !proxy_resolution.aliases.is_empty() {
        tracing::debug!(
            target: "netqmon_agent::policy::flow_trace",
            policy_flow_id,
            proxy_expected = proxy_resolution.expected,
            proxy_unresolved = proxy_resolution.unresolved,
            proxy_alias_count = proxy_resolution.aliases.len(),
            proxy_aliases = ?proxy_resolution.aliases,
            "resolved TCP REDIRECT proxy return aliases"
        );
    }
    let mut proxy_capacity_exceeded = false;
    if !proxy_resolution.aliases.is_empty()
        && let Ok(mut cache) = flow_alias_cache.lock()
    {
        for alias in &proxy_resolution.aliases {
            if cache
                .insert_proxy_return(&policy_flow_id, alias.clone())
                .is_err()
            {
                proxy_capacity_exceeded = true;
            }
        }
    }
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
    let proxy_unresolved = proxy_resolution.expected
        && (proxy_resolution.aliases.is_empty() || proxy_resolution.unresolved);
    let alias_count = u32::try_from(aliases.len()).unwrap_or(u32::MAX);
    let hooks = aliases.iter().map(|alias| alias.hook).collect::<Vec<_>>();
    let ifindices = aliases
        .iter()
        .map(|alias| alias.ifindex)
        .collect::<Vec<_>>();
    let protocol = aliases.first().map(|key| key.protocol);
    let stale_command = flow_alias_cache.lock().map_or(true, |cache| {
        cache.command_is_stale(&policy_flow_id, issued_at_ms)
    });
    let revision_matches = {
        #[cfg(feature = "qos-client-priority")]
        if let Some(priority_runtime) = priority_runtime {
            priority_runtime.lock().is_ok_and(|runtime| {
                runtime.flow_revision_matches(&controller_epoch, config_revision)
            })
        } else {
            saved.as_ref().is_some_and(|state| {
                state.controller_epoch == controller_epoch
                    && state.config_revision == config_revision
            })
        }
        #[cfg(not(feature = "qos-client-priority"))]
        saved.as_ref().is_some_and(|state| {
            state.controller_epoch == controller_epoch && state.config_revision == config_revision
        })
    };
    let policy_references_valid = {
        #[cfg(feature = "qos-client-priority")]
        if let Some(priority_runtime) = priority_runtime {
            let application_verdict = verdict.filter(|verdict| {
                matches!(
                    verdict,
                    FlowVerdict::Shape | FlowVerdict::Block | FlowVerdict::Allow
                )
            });
            application_verdict.is_some()
                && client_mac.as_deref().is_some_and(|client_mac| {
                    priority_runtime.lock().is_ok_and(|runtime| {
                        runtime.application_policy_references_valid(
                            &controller_epoch,
                            config_revision,
                            &policy_ids,
                            client_mac,
                            application_verdict.expect("application verdict checked above"),
                            issued_at_ms,
                            expires_at_ms,
                        )
                    })
                })
        } else {
            flow_command_policy_references_valid(
                saved.as_ref(),
                &policy_ids,
                verdict,
                issued_at_ms,
                expires_at_ms,
            )
        }
        #[cfg(not(feature = "qos-client-priority"))]
        flow_command_policy_references_valid(
            saved.as_ref(),
            &policy_ids,
            verdict,
            issued_at_ms,
            expires_at_ms,
        )
    };
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
    } else if !revision_matches {
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
        let saved_snapshot_has_app_verdicts = saved
            .as_ref()
            .is_some_and(|state| super::snapshot_has_enabled_application_verdicts(&state.snapshot));
        #[cfg(feature = "qos-client-priority")]
        let priority_runtime_has_app_verdicts = priority_runtime.map(|runtime| {
            runtime.lock().map_or(true, |runtime| {
                runtime.has_enabled_application_flow_policy()
            })
        });
        #[cfg(not(feature = "qos-client-priority"))]
        let priority_runtime_has_app_verdicts = None;
        let no_app_verdicts = no_app_verdicts_for_empty_alias_revoke(
            saved_snapshot_has_app_verdicts,
            priority_runtime_has_app_verdicts,
        );
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
        } else if operation == FlowCommandOperation::Upsert && !policy_references_valid {
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
                        // A FlowCommand may only contain the client-to-server
                        // alias. For a block, also install the exact reverse
                        // tuple so the response direction is covered even when
                        // the download-side alias was not observed.
                        let block_aliases = block_reverse_aliases(&aliases);
                        match flow_verdict_writer.install_block(
                            &block_aliases,
                            &command_id,
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
                                block_ack_status(
                                    proxy_capacity_exceeded,
                                    proxy_unresolved,
                                    flow_partial,
                                )
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
                    let installed_aliases = block_reverse_aliases(&aliases);
                    match flow_verdict_writer.clear_aliases(
                        &installed_aliases,
                        Some(&policy_flow_id),
                        &command_id,
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
                }
                (FlowCommandOperation::Upsert, Some(FlowVerdict::Shape)) => {
                    let direction = |alias: &crate::flow::FlowKey| {
                        flow_alias_cache
                            .lock()
                            .ok()
                            .and_then(|cache| cache.direction(&policy_flow_id, alias))
                    };
                    #[cfg(feature = "qos-client-priority")]
                    let shape_direction = |alias: &crate::flow::FlowKey| {
                        flow_alias_cache
                            .lock()
                            .ok()
                            .and_then(|cache| cache.shape_direction(&policy_flow_id, alias))
                    };
                    #[allow(unused_mut)]
                    let mut unresolved_direction = false;
                    #[allow(unused_mut)]
                    let mut unresolved_class = false;
                    // Aliases observed on an untranslated WAN hook without
                    // conntrack are deliberately kept out of the installable
                    // set. Report them precisely instead of guessing a tuple.
                    let tuple_unverified = flow_alias_cache
                        .lock()
                        .ok()
                        .is_some_and(|cache| cache.has_unverified_aliases(&policy_flow_id));
                    let tags: Option<Vec<(crate::flow::FlowKey, u32)>> = {
                        #[cfg(feature = "qos-client-priority")]
                        if let Some(priority_runtime) = priority_runtime {
                            let selection = client_mac.as_deref().and_then(|client_mac| {
                                priority_runtime.lock().ok().map(|runtime| {
                                    priority_application_shape_tags(
                                        &runtime,
                                        &aliases,
                                        client_mac,
                                        &policy_ids,
                                        &shape_direction,
                                    )
                                })
                            });
                            match selection {
                                Some(selection) => {
                                    unresolved_direction = selection
                                        .unresolved
                                        .contains(&ShapeTagGap::DirectionUnknown);
                                    unresolved_class = selection
                                        .unresolved
                                        .contains(&ShapeTagGap::ClassUnresolved);
                                    Some(selection.tags)
                                }
                                None => None,
                            }
                        } else {
                            saved
                                .as_ref()
                                .and_then(|state| state.shaping_state.as_ref())
                                .and_then(|shaping| {
                                    application_shape_tags(
                                        shaping,
                                        &aliases,
                                        client_mac.as_deref()?,
                                        &policy_ids,
                                        &direction,
                                    )
                                })
                        }
                        #[cfg(not(feature = "qos-client-priority"))]
                        saved
                            .as_ref()
                            .and_then(|state| state.shaping_state.as_ref())
                            .and_then(|shaping| {
                                application_shape_tags(
                                    shaping,
                                    &aliases,
                                    client_mac.as_deref()?,
                                    &policy_ids,
                                    &direction,
                                )
                            })
                    };
                    match tags {
                        Some(tags) if !tags.is_empty() => {
                            let remaining_ms = expires_at_ms.saturating_sub(now_ms).max(0) as u64;
                            let deadline = crate::linux::monotonic_ns()
                                .saturating_add(remaining_ms.saturating_mul(1_000_000));
                            match flow_verdict_writer.install_shape(
                                &tags,
                                &command_id,
                                &policy_flow_id,
                                config_revision,
                                deadline,
                            ) {
                                Ok(_) => {
                                    if let Ok(mut cache) = flow_alias_cache.lock() {
                                        cache.record_command(&policy_flow_id, issued_at_ms);
                                    }
                                    shape_coverage_status(
                                        unresolved_direction
                                            || unresolved_class
                                            || tuple_unverified
                                            || flow_partial,
                                    )
                                }
                                Err(_) => (
                                    FlowAckStatus::Failed,
                                    Some("bpf_map_write_failed".to_owned()),
                                ),
                            }
                        }
                        _ => {
                            let controlled_hook = {
                                #[cfg(feature = "qos-client-priority")]
                                if let Some(priority_runtime) = priority_runtime {
                                    priority_runtime.lock().is_ok_and(|runtime| {
                                        aliases.iter().any(|alias| {
                                            runtime.controls_flow_hook(alias.hook, alias.ifindex)
                                        })
                                    })
                                } else {
                                    aliases
                                        .iter()
                                        .any(|alias| alias.ifindex != 0 && alias.hook == 2)
                                }
                                #[cfg(not(feature = "qos-client-priority"))]
                                aliases
                                    .iter()
                                    .any(|alias| alias.ifindex != 0 && alias.hook == 2)
                            };
                            let flow_direction_known = {
                                #[cfg(feature = "qos-client-priority")]
                                {
                                    aliases.iter().any(|alias| {
                                        shape_direction(alias).is_some_and(|direction| {
                                            direction != AliasDirection::Unshaped
                                        })
                                    })
                                }
                                #[cfg(not(feature = "qos-client-priority"))]
                                {
                                    aliases.iter().any(|alias| direction(alias).is_some())
                                }
                            };
                            (
                                FlowAckStatus::Unsupported,
                                Some(
                                    ShapeTagRejection {
                                        controlled_hook,
                                        client_mac_present: client_mac.is_some(),
                                        flow_direction_known,
                                        direction_unknown: unresolved_direction,
                                        tuple_unverified,
                                    }
                                    .reason()
                                    .to_owned(),
                                ),
                            )
                        }
                    }
                }
                (FlowCommandOperation::Revoke, None) => {
                    let installed_aliases = block_reverse_aliases(&aliases);
                    match flow_verdict_writer.clear_aliases(
                        &installed_aliases,
                        Some(&policy_flow_id),
                        &command_id,
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
        reason_code = Some("partial_alias_coverage".to_owned());
    }
    let reported_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(now_ms, |duration| {
            duration.as_millis().min(i64::MAX as u128) as i64
        });
    let failure_class = match reason_code.as_deref() {
        Some("expired" | "stale_flow_command") => "classification_or_command_late",
        Some(
            "flow_identity_unresolved"
            | "flow_identity_partial"
            | "flow_identity_or_alias_mismatch",
        ) => "flow_identity_or_alias_mismatch",
        Some("bpf_map_write_failed") => "bpf_map_write_failure",
        Some("traffic_not_on_controlled_hook") => "traffic_not_on_controlled_hook",
        Some(_) => "flow_command_rejected",
        None => "none",
    };
    let command_processing_ms = reported_at_ms.saturating_sub(now_ms);
    let command_age_ms = reported_at_ms.saturating_sub(issued_at_ms);
    if matches!(status, FlowAckStatus::Applied | FlowAckStatus::Partial) {
        tracing::debug!(
            target: "netqmon_agent::policy::flow_trace",
            command_id,
            policy_flow_id,
            config_revision,
            ?operation,
            ?verdict,
            policy_ids = ?policy_ids,
            alias_count,
            hooks = ?hooks,
            ifindices = ?ifindices,
            client_identity_present = client_mac.is_some(),
            command_issued_at_ms = issued_at_ms,
            command_received_at_ms = now_ms,
            command_reported_at_ms = reported_at_ms,
            command_age_ms,
            command_processing_ms,
            ?status,
            "FlowCommand execution completed"
        );
    } else {
        tracing::warn!(
            target: "netqmon_agent::policy::flow_trace",
            command_id,
            policy_flow_id,
            config_revision,
            ?operation,
            ?verdict,
            policy_ids = ?policy_ids,
            alias_count,
            hooks = ?hooks,
            ifindices = ?ifindices,
            client_identity_present = client_mac.is_some(),
            command_issued_at_ms = issued_at_ms,
            command_received_at_ms = now_ms,
            command_reported_at_ms = reported_at_ms,
            command_age_ms,
            command_processing_ms,
            failure_class,
            reason_code = reason_code.as_deref().unwrap_or(""),
            ?status,
            "FlowCommand execution rejected"
        );
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
        reported_at_ms,
    }
}

fn block_ack_status(
    proxy_capacity_exceeded: bool,
    proxy_unresolved: bool,
    flow_partial: bool,
) -> (netqmon_protocol::policy::FlowAckStatus, Option<String>) {
    use netqmon_protocol::policy::FlowAckStatus;
    if proxy_capacity_exceeded {
        (
            FlowAckStatus::Partial,
            Some("proxy_alias_capacity_exceeded".to_owned()),
        )
    } else if proxy_unresolved {
        (
            FlowAckStatus::Partial,
            Some("proxy_return_path_unresolved".to_owned()),
        )
    } else if flow_partial {
        (
            FlowAckStatus::Partial,
            Some("partial_alias_coverage".to_owned()),
        )
    } else {
        (FlowAckStatus::Applied, None)
    }
}

fn block_reverse_aliases(aliases: &[crate::flow::FlowKey]) -> Vec<crate::flow::FlowKey> {
    // The same wire tuple can be observed at either TC hook depending on which
    // interface carries the client-facing side (LAN bridge port, WAN uplink,
    // or a tunnel). A block must therefore cover both the exact tuple and its
    // reverse on both hooks; reasoning that hook 1 is always upload and hook 2
    // is always download leaves traffic unblocked on the other topology.
    const MAX_BLOCK_ALIASES: usize = 8;
    let mut result = Vec::with_capacity(MAX_BLOCK_ALIASES);
    let mut push = |alias: crate::flow::FlowKey| {
        if result.len() < MAX_BLOCK_ALIASES && !result.contains(&alias) {
            result.push(alias);
        }
    };
    // Preserve every observed/verified tuple first, including a proxy-return
    // tuple. Variants must never evict the real path from the four/eight slots.
    for alias in aliases.iter().take(MAX_BLOCK_ALIASES) {
        push(alias.clone());
    }
    for alias in aliases.iter().take(MAX_BLOCK_ALIASES) {
        let mut reverse = alias.clone();
        std::mem::swap(
            &mut reverse.source_address,
            &mut reverse.destination_address,
        );
        std::mem::swap(&mut reverse.source_port, &mut reverse.destination_port);
        let mut reverse_ingress = reverse.clone();
        reverse_ingress.hook = 1;
        push(reverse_ingress);
        let mut reverse_egress = reverse;
        reverse_egress.hook = 2;
        push(reverse_egress);
        let mut other_hook = alias.clone();
        other_hook.hook = if alias.hook == 1 { 2 } else { 1 };
        push(other_hook);
    }
    result
}

fn application_verdict_capable(
    capabilities: &netqmon_protocol::policy::PolicyCapabilities,
) -> bool {
    use netqmon_protocol::policy::PolicyCapability;
    capabilities.application_block != PolicyCapability::Unsupported
        || capabilities.application_limit == PolicyCapability::Supported
}

/// A shape command is only `Applied` when every necessary controlled-direction
/// alias was verified and tagged. Any unresolved alias, missing class or alias
/// cap is reported as partial coverage instead of a false full success.
fn shape_coverage_status(
    incomplete: bool,
) -> (netqmon_protocol::policy::FlowAckStatus, Option<String>) {
    use netqmon_protocol::policy::FlowAckStatus;

    if incomplete {
        (
            FlowAckStatus::Partial,
            Some("partial_alias_coverage".to_owned()),
        )
    } else {
        (FlowAckStatus::Applied, None)
    }
}

fn application_shape_tags(
    shaping: &ShapingState,
    aliases: &[crate::flow::FlowKey],
    client_mac: &str,
    policy_ids: &[String],
    direction: &impl Fn(&crate::flow::FlowKey) -> Option<super::shaper::Direction>,
) -> Option<Vec<(crate::flow::FlowKey, u32)>> {
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
            tags.push((alias.clone(), u32::from(class.tag)));
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

#[cfg(feature = "qos-client-priority")]
fn mark_priority_class_cleanup_degraded(
    acknowledgement: &mut PolicyWireFrame,
    snapshot: &PolicyWireFrame,
    error: &str,
) {
    use netqmon_protocol::policy::{
        PolicyAckStatus, PolicyActionKind, PolicyResultStatus, PolicyWireFrame,
    };

    let PolicyWireFrame::PolicyAck {
        status, results, ..
    } = acknowledgement
    else {
        return;
    };
    let app_limit_policy_ids = match snapshot {
        PolicyWireFrame::PolicySnapshot { policies, .. } => policies
            .iter()
            .filter(|policy| {
                policy.spec.action.kind == PolicyActionKind::Limit
                    && (!policy.spec.selectors.applications.is_empty()
                        || !policy.spec.selectors.categories.is_empty())
            })
            .map(|policy| policy.id.as_str())
            .collect::<std::collections::HashSet<_>>(),
        _ => return,
    };
    if *status == PolicyAckStatus::Applied {
        *status = PolicyAckStatus::Partial;
    }
    for result in results
        .iter_mut()
        .filter(|result| app_limit_policy_ids.contains(result.policy_id.as_str()))
    {
        if matches!(
            result.status,
            PolicyResultStatus::Applied | PolicyResultStatus::Disabled
        ) {
            result.status = PolicyResultStatus::Degraded;
            result.reason_code = Some("priority_class_cleanup_failed".to_owned());
            result.message = Some(format!(
                "FlowVerdict state was reset, but an unused Agent-owned HTB class could not be removed: {error}"
            ));
        }
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
    stream_connected: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "qos-client-priority")] priority_runtime: Option<Arc<Mutex<PriorityRuntime>>>,
) {
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if shutdown.load(Ordering::Relaxed) { return; }
                if stream_connected.load(Ordering::Acquire) { continue; }
                if std::path::Path::new(&config.policy_disabled_path).exists() { continue; }
                let Some(credential) = credentials.borrow().clone() else { continue; };
                #[cfg(feature = "qos-client-priority")]
                let ack = if let Some(priority_runtime) = &priority_runtime {
                    let priority_ack = priority_runtime
                        .lock()
                        .ok()
                        .and_then(|mut runtime| runtime.reconcile_saved(
                            &credential.gateway_id,
                            &boot_id,
                            flow_bpf_ready.load(Ordering::Acquire),
                        ));
                    priority_ack
                } else {
                    let Ok(Some(saved)) = super::state::load_any(&config.policy_state_path) else { continue; };
                    if credential.gateway_id != saved.gateway_id { continue; }
                    executor::reconcile_saved_with_flow_capability(
                        &config,
                        &saved.gateway_id,
                        &boot_id,
                        flow_bpf_ready.load(Ordering::Acquire),
                    )
                };
                #[cfg(not(feature = "qos-client-priority"))]
                let ack = {
                    let Ok(Some(saved)) = super::state::load_any(&config.policy_state_path) else { continue; };
                    if credential.gateway_id != saved.gateway_id { continue; }
                    executor::reconcile_saved_with_flow_capability(&config, &saved.gateway_id, &boot_id, flow_bpf_ready.load(Ordering::Acquire))
                };
                if let Some(ack) = ack {
                    if matches!(ack, PolicyWireFrame::PolicyAck { status: netqmon_protocol::policy::PolicyAckStatus::Failed, .. }) {
                        tracing::debug!(gateway_id = credential.gateway_id, "local policy schedule reconciliation reported failure");
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
    fn empty_alias_revoke_uses_the_current_priority_snapshot() {
        assert!(super::no_app_verdicts_for_empty_alias_revoke(
            true,
            Some(false)
        ));
        assert!(!super::no_app_verdicts_for_empty_alias_revoke(
            false,
            Some(true)
        ));
        assert!(!super::no_app_verdicts_for_empty_alias_revoke(true, None));
        assert!(super::no_app_verdicts_for_empty_alias_revoke(false, None));
    }

    #[test]
    fn exact_flow_identity_tracking_does_not_require_an_active_app_policy() {
        // The exact-flow map can track identities while empty. The Collector needs those IDs
        // to identify an application and only then request a policy for it.
        assert!(super::flow_identity_tracking_enabled(true, false));
        assert!(!super::flow_identity_tracking_enabled(false, false));
        assert!(!super::flow_identity_tracking_enabled(true, true));
    }

    #[test]
    fn application_limit_snapshot_requires_application_flow_identity() {
        use netqmon_protocol::policy::{PolicySnapshotEntry, PolicyWireFrame};

        let spec = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "gateway_id": "gw-test",
            "name": "Application limit",
            "enabled": true,
            "selectors": {
                "clients": ["AA:BB:CC:DD:EE:FF"],
                "applications": ["netqmon_qos_test"],
                "categories": [],
                "min_application_confidence": 0.95
            },
            "network": { "scope": "internet", "direction": "both" },
            "action": { "type": "limit", "upload_bps": 2000000, "download_bps": 4000000 },
            "schedule": null
        }))
        .unwrap();
        let snapshot = PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000002".to_owned(),
            1,
            1,
            1,
            1_000_000,
            vec![PolicySnapshotEntry {
                id: "00000000-0000-4000-8000-000000000001".to_owned(),
                spec,
            }],
            Vec::new(),
        )
        .unwrap();

        assert!(crate::policy::snapshot_has_enabled_application_verdicts(
            &snapshot
        ));
    }

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

    #[cfg(feature = "qos-client-priority")]
    #[test]
    fn failed_priority_class_cleanup_is_reported_as_degraded_limit_ack() {
        use netqmon_protocol::policy::{
            PolicyAckStatus, PolicyCapabilities, PolicyCapability, PolicyResult,
            PolicyResultStatus, PolicySnapshotEntry, PolicyWireFrame,
        };

        let spec = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "gateway_id": "gw-test",
            "name": "Application limit",
            "enabled": false,
            "selectors": {
                "clients": ["AA:BB:CC:DD:EE:FF"],
                "applications": ["netflix"],
                "categories": [],
                "min_application_confidence": 0.95
            },
            "network": { "scope": "internet", "direction": "both" },
            "action": { "type": "limit", "upload_bps": 2000000, "download_bps": 4000000 },
            "schedule": null
        }))
        .unwrap();
        let policy_id = "00000000-0000-4000-8000-000000000001";
        let snapshot = PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000002".to_owned(),
            27,
            1,
            1,
            1_000_000,
            vec![PolicySnapshotEntry {
                id: policy_id.to_owned(),
                spec,
            }],
            Vec::new(),
        )
        .unwrap();
        let capabilities = PolicyCapabilities {
            client_block: PolicyCapability::Supported,
            client_limit: PolicyCapability::Supported,
            application_block: PolicyCapability::Supported,
            application_limit: PolicyCapability::Supported,
        };
        let mut acknowledgement = crate::policy::executor::priority_policy_ack(
            &snapshot,
            "boot-test",
            capabilities,
            PolicyAckStatus::Applied,
            vec![PolicyResult {
                policy_id: policy_id.to_owned(),
                status: PolicyResultStatus::Disabled,
                reason_code: None,
                message: None,
                details: None,
            }],
        );

        super::mark_priority_class_cleanup_degraded(
            &mut acknowledgement,
            &snapshot,
            "tc class del failed",
        );

        let PolicyWireFrame::PolicyAck {
            status, results, ..
        } = acknowledgement
        else {
            panic!("expected policy acknowledgement");
        };
        assert_eq!(status, PolicyAckStatus::Partial);
        assert_eq!(results[0].status, PolicyResultStatus::Degraded);
        assert_eq!(
            results[0].reason_code.as_deref(),
            Some("priority_class_cleanup_failed")
        );
        assert!(
            results[0]
                .message
                .as_deref()
                .is_some_and(|message| message.contains("tc class del failed"))
        );
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
                .map(|class| u32::from(class.tag))
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
        assert_eq!(tags, vec![(up, u32::from(upload_tag)), (down, 2)]);
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

    #[test]
    fn block_aliases_cover_both_hooks_and_directions() {
        let alias = flow_key(2, 2);
        let aliases = block_reverse_aliases(std::slice::from_ref(&alias));
        assert_eq!(aliases.len(), 4);
        assert!(aliases.contains(&alias));

        let mut same_tuple_ingress = alias.clone();
        same_tuple_ingress.hook = 1;
        assert!(aliases.contains(&same_tuple_ingress));

        let mut reverse_ingress = alias.clone();
        std::mem::swap(
            &mut reverse_ingress.source_address,
            &mut reverse_ingress.destination_address,
        );
        std::mem::swap(
            &mut reverse_ingress.source_port,
            &mut reverse_ingress.destination_port,
        );
        reverse_ingress.hook = 1;
        assert!(aliases.contains(&reverse_ingress));

        let mut reverse_egress = reverse_ingress;
        reverse_egress.hook = 2;
        assert!(aliases.contains(&reverse_egress));
    }

    #[test]
    fn missing_proxy_return_alias_is_partial_not_applied() {
        use netqmon_protocol::policy::FlowAckStatus;

        assert_eq!(
            block_ack_status(false, true, false),
            (
                FlowAckStatus::Partial,
                Some("proxy_return_path_unresolved".to_owned())
            )
        );
        assert_eq!(
            block_ack_status(true, false, false),
            (
                FlowAckStatus::Partial,
                Some("proxy_alias_capacity_exceeded".to_owned())
            )
        );
        assert_eq!(
            block_ack_status(false, false, false).0,
            FlowAckStatus::Applied
        );
    }

    #[test]
    fn block_aliases_keep_observed_upload_and_download_tuples() {
        let upload = flow_key(1, 2);
        let mut download = upload.clone();
        std::mem::swap(
            &mut download.source_address,
            &mut download.destination_address,
        );
        std::mem::swap(&mut download.source_port, &mut download.destination_port);
        download.hook = 2;
        let aliases = block_reverse_aliases(&[upload.clone(), download.clone()]);
        assert!(aliases.contains(&upload));
        assert!(aliases.contains(&download));
        assert_eq!(aliases.len(), 4);
    }

    #[cfg(feature = "qos-client-priority")]
    #[test]
    fn incomplete_shape_coverage_is_partial_not_applied() {
        use netqmon_protocol::policy::FlowAckStatus;

        let (status, reason) = shape_coverage_status(false);
        assert_eq!(status, FlowAckStatus::Applied);
        assert!(reason.is_none());

        let (status, reason) = shape_coverage_status(true);
        assert_eq!(status, FlowAckStatus::Partial);
        assert_eq!(reason.as_deref(), Some("partial_alias_coverage"));
    }
}
