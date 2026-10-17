use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::StreamExt as _;
use netqmon_protocol::policy::{
    FlowAckStatus, FlowCommandOperation, POLICY_MAX_FRAME_BYTES, PolicyWireFrame,
};
use tokio::sync::{Notify, watch};
use tokio::time::{Duration, Instant};

use super::compiler::compile_snapshot;
use super::service::PolicyService;
use super::{PolicyPreviewRequest, evaluate_preview, flow_verdict_expiry};

const PING_INTERVAL: Duration = Duration::from_secs(20);
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);
const FLOW_COMMAND_QUEUE_CAPACITY: usize = 64;
const FLOW_COMMAND_STATE_CAPACITY: usize = 16_384;
const FLOW_COMMAND_IN_FLIGHT_CAPACITY: usize = 64;
const FLOW_COMMAND_RETRY_AFTER: Duration = Duration::from_secs(5);
const FLOW_COMMAND_MAX_ATTEMPTS: u8 = 3;
const FLOW_EVALUATION_CONTEXT_TTL_MS: i64 = 300_000;

#[derive(Clone)]
pub(crate) struct PolicyHub {
    inner: Arc<PolicyHubInner>,
}

struct PolicyHubInner {
    controller_epoch: String,
    next_session_id: AtomicU64,
    next_flow_context_generation: AtomicU64,
    gateways: Mutex<HashMap<String, GatewayState>>,
}

struct GatewayState {
    generation: u64,
    bundle: Option<Arc<PublishedBundle>>,
    updates: watch::Sender<Option<Arc<PublishedBundle>>>,
    session: Option<ActiveSession>,
    flow_boot_id: Option<String>,
    flow_pending: HashMap<String, PolicyWireFrame>,
    flow_queue: VecDeque<String>,
    flow_queued: HashSet<String>,
    flow_states: HashMap<String, PolicyWireFrame>,
    flow_evaluation_contexts: HashMap<String, FlowEvaluationContext>,
    flow_in_flight: HashMap<String, InFlightFlowCommand>,
    flow_attempts: HashMap<String, u8>,
    flow_notify: Arc<Notify>,
    flow_capabilities: Option<(u64, bool, bool)>,
}

#[derive(Clone)]
struct FlowEvaluationContext {
    generation: u64,
    boot_id: String,
    policy_flow_id: String,
    protocol: u32,
    request: PolicyPreviewRequest,
    expires_at_ms: i64,
}

struct InFlightFlowCommand {
    key: String,
    frame: PolicyWireFrame,
    sent_at: Instant,
    attempts: u8,
}

struct ActiveSession {
    id: u64,
    cancelled: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) struct PublishedBundle {
    pub(crate) frame: PolicyWireFrame,
    bytes: Arc<Vec<u8>>,
}

pub(crate) struct AgentSession {
    pub(crate) gateway_id: String,
    pub(crate) id: u64,
    updates: watch::Receiver<Option<Arc<PublishedBundle>>>,
    cancelled: watch::Receiver<bool>,
    flow_notify: Arc<Notify>,
}

impl PublishedBundle {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl PolicyHub {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(PolicyHubInner {
                controller_epoch: uuid::Uuid::new_v4().to_string(),
                next_session_id: AtomicU64::new(1),
                next_flow_context_generation: AtomicU64::new(1),
                gateways: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn controller_epoch(&self) -> &str {
        &self.inner.controller_epoch
    }

    pub(crate) fn connected_gateway_ids(&self) -> Vec<String> {
        self.inner
            .gateways
            .lock()
            .map(|gateways| {
                gateways
                    .iter()
                    .filter(|(_, state)| state.session.is_some())
                    .map(|(gateway_id, _)| gateway_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn refresh_gateway(
        &self,
        service: &PolicyService,
        gateway_id: &str,
        force_new_generation: bool,
    ) -> Result<Arc<PublishedBundle>, String> {
        let now = now_ms();
        let (revision, policies) = service
            .snapshot(gateway_id)
            .map_err(|error| format!("read policy snapshot: {error:?}"))?;
        let mut gateways = self
            .inner
            .gateways
            .lock()
            .map_err(|_| "policy hub is unavailable".to_owned())?;
        let state = gateway_state(&mut gateways, gateway_id);
        if let Some(bundle) = &state.bundle {
            let current_revision = bundle.frame.snapshot_identity().map(|identity| identity.2);
            if current_revision.is_some_and(|current| current > revision) {
                return Ok(Arc::clone(bundle));
            }
        }
        if !force_new_generation {
            if let Some(bundle) = &state.bundle {
                let identity = bundle.frame.snapshot_identity();
                let current_revision = identity.map(|identity| identity.2);
                let valid_until = match &bundle.frame {
                    PolicyWireFrame::PolicySnapshot { valid_until_ms, .. } => *valid_until_ms,
                    _ => 0,
                };
                if current_revision == Some(revision) && now < valid_until {
                    return Ok(Arc::clone(bundle));
                }
            }
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "policy bundle generation exhausted".to_owned())?;
        let frame = compile_snapshot(
            gateway_id,
            &self.inner.controller_epoch,
            generation,
            now,
            revision,
            policies,
        )?;
        let bytes = Arc::new(frame.encode()?);
        let bundle = Arc::new(PublishedBundle { frame, bytes });
        if let Some((_, epoch, next_revision, _, _)) = bundle.frame.snapshot_identity() {
            let old_revision = state
                .bundle
                .as_ref()
                .and_then(|current| current.frame.snapshot_identity())
                .map(|identity| identity.2);
            if old_revision.is_some_and(|old| old != next_revision) {
                state.revoke_active_flow_states(epoch, next_revision, now);
                state.flow_capabilities = None;
            }
        }
        state.generation = generation;
        state.bundle = Some(Arc::clone(&bundle));
        state.updates.send_replace(Some(Arc::clone(&bundle)));
        Ok(bundle)
    }

    pub(crate) fn register(&self, gateway_id: &str) -> Result<AgentSession, String> {
        let id = self.inner.next_session_id.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err("policy connection id exhausted".to_owned());
        }
        let mut gateways = self
            .inner
            .gateways
            .lock()
            .map_err(|_| "policy hub is unavailable".to_owned())?;
        let state = gateway_state(&mut gateways, gateway_id);
        if let Some(old) = state.session.take() {
            old.cancelled.send_replace(true);
        }
        let (cancelled, cancel_receiver) = watch::channel(false);
        state.session = Some(ActiveSession { id, cancelled });
        state.requeue_flow_states(now_ms());
        Ok(AgentSession {
            gateway_id: gateway_id.to_owned(),
            id,
            updates: state.updates.subscribe(),
            cancelled: cancel_receiver,
            flow_notify: Arc::clone(&state.flow_notify),
        })
    }

    pub(crate) fn current_bundle(&self, gateway_id: &str) -> Option<Arc<PublishedBundle>> {
        self.inner
            .gateways
            .lock()
            .ok()
            .and_then(|gateways| gateways.get(gateway_id)?.bundle.clone())
    }

    pub(crate) fn record_flow_capabilities(
        &self,
        gateway_id: &str,
        revision: u64,
        capabilities: &netqmon_protocol::policy::PolicyCapabilities,
    ) {
        let now = now_ms();
        let (bundle, contexts, block_supported, limit_supported) = {
            let Ok(mut gateways) = self.inner.gateways.lock() else {
                return;
            };
            let state = gateway_state(&mut gateways, gateway_id);
            let block_supported = capabilities.application_block
                != netqmon_protocol::policy::PolicyCapability::Unsupported;
            let limit_supported = capabilities.application_limit
                == netqmon_protocol::policy::PolicyCapability::Supported;
            state
                .flow_evaluation_contexts
                .retain(|_, context| context.expires_at_ms > now);
            let Some(bundle) = state.bundle.clone().filter(|bundle| {
                bundle
                    .frame
                    .snapshot_identity()
                    .is_some_and(|identity| identity.2 == revision)
            }) else {
                return;
            };
            state.flow_capabilities = Some((revision, block_supported, limit_supported));
            (
                bundle,
                state
                    .flow_evaluation_contexts
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
                block_supported,
                limit_supported,
            )
        };

        for context in contexts {
            if let Some(command) =
                flow_command_for_context(&bundle, &context, block_supported, limit_supported, now)
            {
                if let PolicyWireFrame::FlowCommand {
                    config_revision,
                    command_id,
                    policy_flow_id,
                    verdict,
                    policy_ids,
                    issued_at_ms,
                    ..
                } = &command
                {
                    let verdict = match verdict {
                        Some(netqmon_protocol::policy::FlowVerdict::Block) => "Block",
                        Some(netqmon_protocol::policy::FlowVerdict::Allow) => "Allow",
                        Some(netqmon_protocol::policy::FlowVerdict::Shape) => "Shape",
                        None => "None",
                    };
                    tracing::debug!(
                        gateway_id,
                        boot_id = context.boot_id,
                        config_revision,
                        command_id,
                        policy_flow_id,
                        verdict,
                        policy_ids = ?policy_ids,
                        issued_at_ms,
                        "re-evaluated active flow after policy acknowledgement"
                    );
                }
                if let Err(error) = self.queue_flow_command_for_context(command, context.generation)
                {
                    tracing::warn!(gateway_id, policy_flow_id = context.policy_flow_id, %error,
                        "could not re-evaluate active flow after policy acknowledgement");
                }
            }
        }
    }

    pub(crate) fn remember_flow_context(
        &self,
        gateway_id: &str,
        boot_id: &str,
        policy_flow_id: &str,
        protocol: u32,
        request: PolicyPreviewRequest,
        now: i64,
    ) -> Option<u64> {
        let key = flow_command_key(boot_id, policy_flow_id);
        let mut generation = self
            .inner
            .next_flow_context_generation
            .load(Ordering::Relaxed);
        let generation = loop {
            let next = generation.checked_add(1)?;
            match self
                .inner
                .next_flow_context_generation
                .compare_exchange_weak(generation, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break generation,
                Err(current) => generation = current,
            }
        };
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return None;
        };
        let state = gateway_state(&mut gateways, gateway_id);
        if state
            .flow_boot_id
            .as_deref()
            .is_some_and(|current| current != boot_id)
        {
            state.clear_flow_commands();
        }
        state.flow_boot_id = Some(boot_id.to_owned());
        state
            .flow_evaluation_contexts
            .retain(|_, context| context.expires_at_ms > now);
        if !state.flow_evaluation_contexts.contains_key(&key)
            && state.flow_evaluation_contexts.len() >= FLOW_COMMAND_STATE_CAPACITY
        {
            return None;
        }
        state.flow_evaluation_contexts.insert(
            key,
            FlowEvaluationContext {
                generation,
                boot_id: boot_id.to_owned(),
                policy_flow_id: policy_flow_id.to_owned(),
                protocol,
                request,
                expires_at_ms: now.saturating_add(FLOW_EVALUATION_CONTEXT_TTL_MS),
            },
        );
        Some(generation)
    }

    pub(crate) fn forget_flow_context(
        &self,
        gateway_id: &str,
        boot_id: &str,
        policy_flow_id: &str,
    ) {
        let key = flow_command_key(boot_id, policy_flow_id);
        if let Ok(mut gateways) = self.inner.gateways.lock()
            && let Some(state) = gateways.get_mut(gateway_id)
        {
            state.flow_evaluation_contexts.remove(&key);
        }
    }

    pub(crate) fn flow_capabilities(&self, gateway_id: &str) -> (bool, bool) {
        let Ok(gateways) = self.inner.gateways.lock() else {
            return (false, false);
        };
        let Some(state) = gateways.get(gateway_id) else {
            return (false, false);
        };
        let revision = state
            .bundle
            .as_ref()
            .and_then(|bundle| bundle.frame.snapshot_identity())
            .map(|identity| identity.2);
        state
            .flow_capabilities
            .filter(|(capability_revision, _, _)| Some(*capability_revision) == revision)
            .map_or((false, false), |(_, block, limit)| (block, limit))
    }

    pub(crate) fn queue_flow_command(&self, mut frame: PolicyWireFrame) -> Result<(), String> {
        self.queue_flow_command_inner(&mut frame, None)
    }

    pub(crate) fn queue_flow_command_for_context(
        &self,
        mut frame: PolicyWireFrame,
        context_generation: u64,
    ) -> Result<(), String> {
        self.queue_flow_command_inner(&mut frame, Some(context_generation))
    }

    fn queue_flow_command_inner(
        &self,
        frame: &mut PolicyWireFrame,
        expected_context_generation: Option<u64>,
    ) -> Result<(), String> {
        frame.validate()?;
        let (
            gateway_id,
            boot_id,
            controller_epoch,
            config_revision,
            policy_flow_id,
            requested_issued_at,
            requested_expires_at,
        ) = match &*frame {
            PolicyWireFrame::FlowCommand {
                gateway_id,
                boot_id,
                controller_epoch,
                config_revision,
                policy_flow_id,
                issued_at_ms,
                expires_at_ms,
                ..
            } => (
                gateway_id.clone(),
                boot_id.clone(),
                controller_epoch.clone(),
                *config_revision,
                policy_flow_id.clone(),
                *issued_at_ms,
                *expires_at_ms,
            ),
            _ => return Err("expected a flow_command frame".to_owned()),
        };
        let key = flow_command_key(&boot_id, &policy_flow_id);
        let mut gateways = self
            .inner
            .gateways
            .lock()
            .map_err(|_| "policy hub is unavailable".to_owned())?;
        let state = gateway_state(&mut gateways, &gateway_id);
        if let Some(bundle) = &state.bundle {
            let Some((expected_gateway, expected_epoch, expected_revision, _, _)) =
                bundle.frame.snapshot_identity()
            else {
                return Err("current policy bundle has no snapshot identity".to_owned());
            };
            if expected_gateway != gateway_id.as_str()
                || expected_epoch != controller_epoch.as_str()
                || expected_revision != config_revision
            {
                return Err("stale_flow_command_snapshot".to_owned());
            }
        }
        if let Some(generation) = expected_context_generation {
            if state.flow_boot_id.as_deref() != Some(boot_id.as_str())
                || state
                    .flow_evaluation_contexts
                    .get(&key)
                    .map(|context| context.generation)
                    != Some(generation)
            {
                // A newer packet, agent boot, or snapshot has superseded this
                // asynchronous decision; it must not replace current flow state.
                return Ok(());
            }
        }
        if state
            .flow_boot_id
            .as_deref()
            .is_some_and(|current| current != boot_id)
        {
            state.clear_flow_commands();
        }
        state.flow_boot_id = Some(boot_id);
        if let Some(previous) = state.flow_states.get(&key)
            && same_flow_decision(previous, &frame)
            && flow_command_expires_at(previous).is_some_and(|expires| {
                let refresh_margin = flow_command_lifetime(previous).unwrap_or(30_000) / 2;
                expires > requested_issued_at.saturating_add(refresh_margin)
            })
        {
            return Ok(());
        }
        if let Some(previous_issued) = state.flow_states.get(&key).and_then(flow_command_issued_at)
        {
            let ttl = requested_expires_at.saturating_sub(requested_issued_at);
            if let PolicyWireFrame::FlowCommand {
                issued_at_ms,
                expires_at_ms,
                ..
            } = &mut *frame
            {
                *issued_at_ms = (*issued_at_ms).max(previous_issued.saturating_add(1));
                *expires_at_ms = issued_at_ms.saturating_add(ttl);
            }
        }
        if !state.flow_states.contains_key(&key)
            && state.flow_states.len() >= FLOW_COMMAND_STATE_CAPACITY
        {
            tracing::warn!(gateway_id, policy_flow_id, "flow command state is full");
            return Err("flow_command_backpressure".to_owned());
        }
        state.flow_states.insert(key.clone(), frame.clone());
        state.flow_pending.insert(key.clone(), frame.clone());
        state.fill_flow_queue();
        let notify = Arc::clone(&state.flow_notify);
        drop(gateways);
        notify.notify_one();
        Ok(())
    }

    pub(crate) fn revoke_flow_if_active(
        &self,
        gateway_id: &str,
        boot_id: &str,
        controller_epoch: &str,
        config_revision: u64,
        policy_flow_id: &str,
        now: i64,
    ) -> Result<bool, String> {
        let key = flow_command_key(boot_id, policy_flow_id);
        let is_active = self
            .inner
            .gateways
            .lock()
            .ok()
            .and_then(|gateways| {
                gateways
                    .get(gateway_id)?
                    .flow_states
                    .get(&key)
                    .map(|frame| {
                        matches!(
                            frame,
                            PolicyWireFrame::FlowCommand {
                                operation: FlowCommandOperation::Upsert,
                                ..
                            }
                        )
                    })
            })
            .unwrap_or(false);
        if !is_active {
            return Ok(false);
        }
        let command_id = uuid::Uuid::new_v4().to_string();
        tracing::debug!(
            target: "netqmon_collector::policy::flow_trace",
            gateway_id,
            boot_id,
            config_revision,
            command_id,
            policy_flow_id,
            verdict = "None",
            policy_ids = ?Vec::<String>::new(),
            issued_at_ms = now,
            operation = "Revoke",
            "re-evaluated active flow after policy acknowledgement"
        );
        self.queue_flow_command(PolicyWireFrame::FlowCommand {
            wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
            gateway_id: gateway_id.to_owned(),
            boot_id: boot_id.to_owned(),
            controller_epoch: controller_epoch.to_owned(),
            config_revision,
            command_id,
            policy_flow_id: policy_flow_id.to_owned(),
            operation: FlowCommandOperation::Revoke,
            verdict: None,
            policy_ids: Vec::new(),
            expires_at_ms: now.saturating_add(30_000),
            issued_at_ms: now,
        })?;
        Ok(true)
    }

    pub(crate) fn take_flow_command(
        &self,
        session: &AgentSession,
        current_revision: u64,
    ) -> Option<PolicyWireFrame> {
        let mut gateways = self.inner.gateways.lock().ok()?;
        let state = gateways.get_mut(&session.gateway_id)?;
        if !state
            .session
            .as_ref()
            .is_some_and(|active| active.id == session.id)
            || state.flow_in_flight.len() >= FLOW_COMMAND_IN_FLIGHT_CAPACITY
        {
            return None;
        }
        state.fill_flow_queue();
        let queue_len = state.flow_queue.len();
        for _ in 0..queue_len {
            let key = state.flow_queue.pop_front()?;
            state.flow_queued.remove(&key);
            let Some(frame) = state.flow_pending.remove(&key) else {
                continue;
            };
            if flow_command_revision(&frame) != Some(current_revision) {
                state.flow_pending.insert(key.clone(), frame);
                continue;
            }
            state.fill_flow_queue();
            if !state.flow_queue.is_empty() {
                session.flow_notify.notify_one();
            }
            return Some(frame);
        }
        None
    }

    pub(crate) fn mark_flow_command_sent(&self, session: &AgentSession, frame: PolicyWireFrame) {
        let PolicyWireFrame::FlowCommand {
            command_id,
            boot_id,
            policy_flow_id,
            ..
        } = &frame
        else {
            return;
        };
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return;
        };
        let Some(state) = gateways.get_mut(&session.gateway_id) else {
            return;
        };
        if !state
            .session
            .as_ref()
            .is_some_and(|active| active.id == session.id)
        {
            return;
        }
        let attempts = state
            .flow_attempts
            .entry(command_id.clone())
            .and_modify(|attempts| *attempts = attempts.saturating_add(1))
            .or_insert(1);
        state.flow_in_flight.insert(
            command_id.clone(),
            InFlightFlowCommand {
                key: flow_command_key(boot_id, policy_flow_id),
                frame,
                sent_at: Instant::now(),
                attempts: *attempts,
            },
        );
    }

    pub(crate) fn requeue_unsent_flow_command(
        &self,
        session: &AgentSession,
        frame: PolicyWireFrame,
    ) {
        let PolicyWireFrame::FlowCommand {
            boot_id,
            policy_flow_id,
            ..
        } = &frame
        else {
            return;
        };
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return;
        };
        let Some(state) = gateways.get_mut(&session.gateway_id) else {
            return;
        };
        if !state
            .session
            .as_ref()
            .is_some_and(|active| active.id == session.id)
        {
            return;
        }
        let key = flow_command_key(boot_id, policy_flow_id);
        if !state
            .flow_states
            .get(&key)
            .is_some_and(|current| flow_command_id(current) == flow_command_id(&frame))
        {
            return;
        }
        state.flow_pending.insert(key, frame);
        state.fill_flow_queue();
        session.flow_notify.notify_one();
    }

    pub(crate) fn retry_flow_commands(&self, session: &AgentSession) {
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return;
        };
        let Some(state) = gateways.get_mut(&session.gateway_id) else {
            return;
        };
        if !state
            .session
            .as_ref()
            .is_some_and(|active| active.id == session.id)
        {
            return;
        }
        let due = state
            .flow_in_flight
            .iter()
            .filter(|(_, pending)| {
                pending.sent_at.elapsed() >= FLOW_COMMAND_RETRY_AFTER
                    && pending.attempts < FLOW_COMMAND_MAX_ATTEMPTS
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in due {
            if let Some(pending) = state.flow_in_flight.remove(&id) {
                if state
                    .flow_states
                    .get(&pending.key)
                    .is_some_and(|current| flow_command_id(current) == Some(id.as_str()))
                {
                    state.flow_pending.insert(pending.key, pending.frame);
                } else {
                    state.flow_attempts.remove(&id);
                }
            }
        }
        let exhausted = state
            .flow_in_flight
            .iter()
            .filter(|(_, pending)| {
                pending.sent_at.elapsed() >= FLOW_COMMAND_RETRY_AFTER
                    && pending.attempts >= FLOW_COMMAND_MAX_ATTEMPTS
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in exhausted {
            state.flow_in_flight.remove(&id);
            state.flow_attempts.remove(&id);
        }
        state.fill_flow_queue();
        if !state.flow_queue.is_empty() {
            session.flow_notify.notify_one();
        }
    }

    pub(crate) fn acknowledge_flow_command(
        &self,
        session: &AgentSession,
        gateway_id: &str,
        boot_id: &str,
        controller_epoch: &str,
        command_id: &str,
        policy_flow_id: &str,
        config_revision: u64,
        status: FlowAckStatus,
    ) -> bool {
        if gateway_id != session.gateway_id || !self.is_active(session) {
            return false;
        }
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return false;
        };
        let Some(state) = gateways.get_mut(gateway_id) else {
            return false;
        };
        let Some(sent) = state.flow_in_flight.remove(command_id) else {
            return false;
        };
        let expected_key = flow_command_key(boot_id, policy_flow_id);
        let valid = sent.key == expected_key
            && matches!(
                sent.frame,
                PolicyWireFrame::FlowCommand {
                    controller_epoch: ref expected_epoch,
                    config_revision: expected_revision,
                    ..
                } if expected_epoch == controller_epoch && expected_revision == config_revision
            );
        if !valid {
            state.flow_in_flight.insert(command_id.to_owned(), sent);
            return false;
        }
        state.flow_attempts.remove(command_id);
        if matches!(
            sent.frame,
            PolicyWireFrame::FlowCommand {
                operation: FlowCommandOperation::Revoke,
                ..
            }
        ) && matches!(
            status,
            FlowAckStatus::Applied | FlowAckStatus::Partial | FlowAckStatus::Expired
        ) && state.flow_states.get(&expected_key).is_some_and(|current| {
            matches!(current, PolicyWireFrame::FlowCommand { command_id: current_id, .. } if current_id == command_id)
        }) {
            state.flow_states.remove(&expected_key);
        }
        state.fill_flow_queue();
        if !state.flow_queue.is_empty() {
            state.flow_notify.notify_one();
        }
        true
    }

    pub(crate) fn notify_flow_commands(&self, session: &AgentSession) {
        session.flow_notify.notify_one();
    }

    pub(crate) fn is_active(&self, session: &AgentSession) -> bool {
        self.inner
            .gateways
            .lock()
            .ok()
            .and_then(|gateways| {
                gateways
                    .get(&session.gateway_id)
                    .and_then(|state| state.session.as_ref())
                    .map(|active| active.id == session.id)
            })
            .unwrap_or(false)
    }

    pub(crate) fn unregister(&self, session: &AgentSession) -> bool {
        let Ok(mut gateways) = self.inner.gateways.lock() else {
            return false;
        };
        let Some(state) = gateways.get_mut(&session.gateway_id) else {
            return false;
        };
        if state
            .session
            .as_ref()
            .is_some_and(|active| active.id == session.id)
        {
            state.session = None;
            true
        } else {
            false
        }
    }
}

fn gateway_state<'a>(
    gateways: &'a mut HashMap<String, GatewayState>,
    gateway_id: &str,
) -> &'a mut GatewayState {
    gateways.entry(gateway_id.to_owned()).or_insert_with(|| {
        let (updates, _) = watch::channel(None);
        GatewayState {
            generation: 0,
            bundle: None,
            updates,
            session: None,
            flow_boot_id: None,
            flow_pending: HashMap::new(),
            flow_queue: VecDeque::new(),
            flow_queued: HashSet::new(),
            flow_states: HashMap::new(),
            flow_evaluation_contexts: HashMap::new(),
            flow_in_flight: HashMap::new(),
            flow_attempts: HashMap::new(),
            flow_notify: Arc::new(Notify::new()),
            flow_capabilities: None,
        }
    })
}

impl GatewayState {
    fn clear_flow_commands(&mut self) {
        self.flow_pending.clear();
        self.flow_queue.clear();
        self.flow_queued.clear();
        self.flow_states.clear();
        self.flow_evaluation_contexts.clear();
        self.flow_in_flight.clear();
        self.flow_attempts.clear();
    }

    fn fill_flow_queue(&mut self) {
        let now = now_ms();
        let revision = self
            .bundle
            .as_ref()
            .and_then(|bundle| bundle.frame.snapshot_identity())
            .map(|identity| identity.2);
        // A previous revision can never be sent after the new snapshot.
        // Keeping it in the bounded queue can indefinitely hide current flows.
        self.flow_pending.retain(|_, frame| {
            flow_command_expires_at(frame).is_some_and(|expires| expires > now)
                && revision.is_none_or(|current| {
                    flow_command_revision(frame).is_some_and(|value| value >= current)
                })
        });
        self.flow_states
            .retain(|_, frame| flow_command_expires_at(frame).is_some_and(|expires| expires > now));
        self.flow_queue.retain(|key| {
            self.flow_pending.get(key).is_some_and(|frame| {
                revision.is_none_or(|current| flow_command_revision(frame) == Some(current))
            })
        });
        self.flow_queued = self.flow_queue.iter().cloned().collect();
        if self.flow_queue.len() >= FLOW_COMMAND_QUEUE_CAPACITY {
            return;
        }
        let available = FLOW_COMMAND_QUEUE_CAPACITY - self.flow_queue.len();
        let keys = self
            .flow_pending
            .iter()
            .filter(|(key, frame)| {
                !self.flow_queued.contains(*key)
                    && revision.is_none_or(|current| flow_command_revision(frame) == Some(current))
            })
            .take(available)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.flow_queued.insert(key.clone());
            self.flow_queue.push_back(key);
        }
    }

    fn requeue_flow_states(&mut self, now: i64) {
        self.flow_in_flight.clear();
        for (key, frame) in &self.flow_states {
            if flow_command_expires_at(frame).is_some_and(|expires| expires > now) {
                self.flow_pending.insert(key.clone(), frame.clone());
            }
        }
        self.fill_flow_queue();
        if !self.flow_queue.is_empty() {
            self.flow_notify.notify_one();
        }
    }

    fn revoke_active_flow_states(&mut self, epoch: &str, revision: u64, now: i64) {
        let active = self
            .flow_states
            .iter()
            .filter_map(|(key, frame)| {
                let PolicyWireFrame::FlowCommand {
                    gateway_id,
                    boot_id,
                    policy_flow_id,
                    operation: FlowCommandOperation::Upsert,
                    ..
                } = frame
                else {
                    return None;
                };
                Some((
                    key.clone(),
                    gateway_id.clone(),
                    boot_id.clone(),
                    policy_flow_id.clone(),
                ))
            })
            .collect::<Vec<_>>();
        for (key, gateway_id, boot_id, policy_flow_id) in active {
            let command_id = uuid::Uuid::new_v4().to_string();
            tracing::debug!(
                target: "netqmon_collector::policy::flow_trace",
                gateway_id,
                boot_id,
                config_revision = revision,
                command_id,
                policy_flow_id,
                verdict = "None",
                policy_ids = ?Vec::<String>::new(),
                issued_at_ms = now,
                operation = "Revoke",
                "re-evaluated active flow after policy acknowledgement"
            );
            let frame = PolicyWireFrame::FlowCommand {
                wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
                gateway_id,
                boot_id,
                controller_epoch: epoch.to_owned(),
                config_revision: revision,
                command_id,
                policy_flow_id,
                operation: FlowCommandOperation::Revoke,
                verdict: None,
                policy_ids: Vec::new(),
                expires_at_ms: now.saturating_add(30_000),
                issued_at_ms: now,
            };
            self.flow_states.insert(key.clone(), frame.clone());
            self.flow_pending.insert(key, frame);
        }
        self.flow_queue.clear();
        self.flow_queued.clear();
        self.fill_flow_queue();
        if !self.flow_queue.is_empty() {
            self.flow_notify.notify_one();
        }
    }
}

fn flow_command_for_context(
    bundle: &PublishedBundle,
    context: &FlowEvaluationContext,
    application_block_supported: bool,
    application_limit_supported: bool,
    now: i64,
) -> Option<PolicyWireFrame> {
    let PolicyWireFrame::PolicySnapshot {
        controller_epoch,
        config_revision,
        policies,
        ..
    } = &bundle.frame
    else {
        return None;
    };
    if context.expires_at_ms <= now {
        return None;
    }
    let mut request = context.request.clone();
    request.at_ms = now;
    let evaluated = evaluate_preview(
        &request,
        policies,
        application_block_supported,
        application_limit_supported,
    );
    let (verdict, policy_ids) = super::evaluator::flow_command_decision(&evaluated);
    let verdict = verdict.filter(|_| !policy_ids.is_empty() && policy_ids.len() <= 16)?;
    let ttl_ms = match context.protocol {
        17 => 30_000,
        6 => 120_000,
        _ => return None,
    };
    let expires_at_ms = flow_verdict_expiry(&bundle.frame, &policy_ids, now, ttl_ms)?;
    Some(PolicyWireFrame::FlowCommand {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: request.gateway_id,
        boot_id: context.boot_id.clone(),
        controller_epoch: controller_epoch.clone(),
        config_revision: *config_revision,
        command_id: uuid::Uuid::new_v4().to_string(),
        policy_flow_id: context.policy_flow_id.clone(),
        operation: FlowCommandOperation::Upsert,
        verdict: Some(verdict),
        policy_ids,
        expires_at_ms,
        issued_at_ms: now,
    })
}

fn flow_command_key(boot_id: &str, policy_flow_id: &str) -> String {
    format!("{boot_id}\0{policy_flow_id}")
}

fn flow_command_id(frame: &PolicyWireFrame) -> Option<&str> {
    match frame {
        PolicyWireFrame::FlowCommand { command_id, .. } => Some(command_id),
        _ => None,
    }
}

fn flow_command_revision(frame: &PolicyWireFrame) -> Option<u64> {
    match frame {
        PolicyWireFrame::FlowCommand {
            config_revision, ..
        } => Some(*config_revision),
        _ => None,
    }
}

fn flow_command_expires_at(frame: &PolicyWireFrame) -> Option<i64> {
    match frame {
        PolicyWireFrame::FlowCommand { expires_at_ms, .. } => Some(*expires_at_ms),
        _ => None,
    }
}

fn flow_command_issued_at(frame: &PolicyWireFrame) -> Option<i64> {
    match frame {
        PolicyWireFrame::FlowCommand { issued_at_ms, .. } => Some(*issued_at_ms),
        _ => None,
    }
}

fn flow_command_lifetime(frame: &PolicyWireFrame) -> Option<i64> {
    match frame {
        PolicyWireFrame::FlowCommand {
            expires_at_ms,
            issued_at_ms,
            ..
        } => Some(expires_at_ms.saturating_sub(*issued_at_ms)),
        _ => None,
    }
}

fn same_flow_decision(left: &PolicyWireFrame, right: &PolicyWireFrame) -> bool {
    matches!(
        (left, right),
        (
            PolicyWireFrame::FlowCommand {
                gateway_id: left_gateway,
                boot_id: left_boot,
                controller_epoch: left_epoch,
                config_revision: left_revision,
                policy_flow_id: left_flow,
                operation: left_operation,
                verdict: left_verdict,
                policy_ids: left_ids,
                ..
            },
            PolicyWireFrame::FlowCommand {
                gateway_id: right_gateway,
                boot_id: right_boot,
                controller_epoch: right_epoch,
                config_revision: right_revision,
                policy_flow_id: right_flow,
                operation: right_operation,
                verdict: right_verdict,
                policy_ids: right_ids,
                ..
            }
        ) if left_gateway == right_gateway
            && left_boot == right_boot
            && left_epoch == right_epoch
            && left_revision == right_revision
            && left_flow == right_flow
            && left_operation == right_operation
            && left_verdict == right_verdict
            && left_ids == right_ids
    )
}

pub(crate) fn schedule_refresh(service: Arc<PolicyService>, hub: PolicyHub, gateway_id: String) {
    tokio::spawn(async move {
        if let Err(error) = hub.refresh_gateway(&service, &gateway_id, true) {
            tracing::error!(gateway_id, error, "could not publish policy snapshot");
        }
    });
}

pub(crate) fn spawn_schedule_refresh(service: Arc<PolicyService>, hub: PolicyHub) {
    tokio::spawn(async move {
        let mut refresh_at = Instant::now() + Duration::from_secs(24 * 60 * 60);
        loop {
            tokio::time::sleep_until(refresh_at).await;
            refresh_at += Duration::from_secs(24 * 60 * 60);
            for gateway_id in hub.connected_gateway_ids() {
                if let Err(error) = hub.refresh_gateway(&service, &gateway_id, true) {
                    tracing::error!(
                        gateway_id,
                        error,
                        "could not refresh policy schedule windows"
                    );
                }
            }
        }
    });
}

pub(crate) async fn run_socket(
    mut socket: WebSocket,
    service: Arc<PolicyService>,
    hub: PolicyHub,
    mut session: AgentSession,
) {
    if let Err(error) = service.mark_agent_connected(&session.gateway_id) {
        tracing::error!(
            gateway_id = session.gateway_id,
            ?error,
            "could not mark agent connected"
        );
        hub.unregister(&session);
        return;
    }
    let mut last_activity = Instant::now();
    let mut last_sent: Option<Arc<PublishedBundle>> = None;
    let mut agent_boot_id: Option<String> = None;
    let initial_bundle = { session.updates.borrow_and_update().clone() };
    if let Some(bundle) = initial_bundle {
        if socket
            .send(Message::Text(
                String::from_utf8_lossy(bundle.bytes()).into_owned().into(),
            ))
            .await
            .is_err()
        {
            disconnect_session(&service, &hub, &session);
            return;
        }
        record_bundle_delivery(&service, &hub, &session, &bundle);
        last_sent = Some(bundle);
    }
    hub.notify_flow_commands(&session);
    let mut ping_interval = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut flow_retry_interval = tokio::time::interval_at(
        Instant::now() + FLOW_COMMAND_RETRY_AFTER,
        FLOW_COMMAND_RETRY_AFTER,
    );
    flow_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if !hub.is_active(&session) {
            break;
        }
        tokio::select! {
            changed = session.cancelled.changed() => {
                if changed.is_err() || *session.cancelled.borrow_and_update() {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: 1001,
                        reason: "replaced by a newer authenticated agent connection".into(),
                    }))).await;
                    break;
                }
            }
            changed = session.updates.changed() => {
                if changed.is_err() {
                    break;
                }
                let next_bundle = { session.updates.borrow_and_update().clone() };
                if let Some(bundle) = next_bundle {
                    if socket.send(Message::Text(String::from_utf8_lossy(bundle.bytes()).into_owned().into())).await.is_err() {
                        break;
                    }
                    record_bundle_delivery(&service, &hub, &session, &bundle);
                    last_sent = Some(bundle);
                    hub.notify_flow_commands(&session);
                }
            }
            _ = session.flow_notify.notified() => {
                let current_revision = last_sent
                    .as_ref()
                    .and_then(|bundle| bundle.frame.snapshot_identity())
                    .map_or(0, |identity| identity.2);
                if let Some(frame) = hub.take_flow_command(&session, current_revision) {
                    match frame.encode() {
                        Ok(bytes) => {
                            if socket.send(Message::Text(String::from_utf8_lossy(&bytes).into_owned().into())).await.is_err() {
                                hub.requeue_unsent_flow_command(&session, frame);
                                break;
                            }
                            hub.mark_flow_command_sent(&session, frame);
                        }
                        Err(error) => tracing::warn!(gateway_id = session.gateway_id, %error, "could not encode flow command"),
                    }
                }
            }
            _ = flow_retry_interval.tick() => hub.retry_flow_commands(&session),
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(last_activity + ACTIVITY_TIMEOUT) => {
                tracing::warn!(gateway_id = session.gateway_id, "agent policy stream activity timed out");
                break;
            }
            message = socket.next() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                        last_activity = Instant::now();
                    }
                    Some(Ok(Message::Pong(_))) => last_activity = Instant::now(),
                    Some(Ok(Message::Text(text))) => {
                        if handle_agent_frame(
                            text.as_bytes(), &service, &hub, &session, &last_sent,
                            &mut agent_boot_id,
                        ) {
                            last_activity = Instant::now();
                        } else {
                            let _ = socket.send(Message::Close(Some(CloseFrame {
                                code: 1008,
                                reason: "invalid policy protocol frame".into(),
                            }))).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if handle_agent_frame(
                            bytes.as_ref(), &service, &hub, &session, &last_sent,
                            &mut agent_boot_id,
                        ) {
                            last_activity = Instant::now();
                        } else {
                            let _ = socket.send(Message::Close(Some(CloseFrame {
                                code: 1008,
                                reason: "invalid policy protocol frame".into(),
                            }))).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(error)) => {
                        tracing::debug!(gateway_id = session.gateway_id, %error, "policy stream closed");
                        break;
                    }
                }
            }
        }
    }

    disconnect_session(&service, &hub, &session);
}

fn record_bundle_delivery(
    service: &PolicyService,
    hub: &PolicyHub,
    session: &AgentSession,
    bundle: &PublishedBundle,
) {
    if !hub.is_active(session) {
        return;
    }
    let Some((gateway_id, _, revision, _, _)) = bundle.frame.snapshot_identity() else {
        return;
    };
    if let Err(error) = service.record_delivery(gateway_id, revision, now_ms()) {
        tracing::error!(
            gateway_id,
            revision,
            ?error,
            "could not record delivered policy snapshot"
        );
    }
}

fn disconnect_session(service: &PolicyService, hub: &PolicyHub, session: &AgentSession) {
    if hub.unregister(session)
        && let Err(error) = service.mark_agent_disconnected(&session.gateway_id)
    {
        tracing::error!(
            gateway_id = session.gateway_id,
            ?error,
            "could not mark agent offline"
        );
    }
}

fn handle_agent_frame(
    bytes: &[u8],
    service: &PolicyService,
    hub: &PolicyHub,
    session: &AgentSession,
    last_sent: &Option<Arc<PublishedBundle>>,
    agent_boot_id: &mut Option<String>,
) -> bool {
    if bytes.len() > POLICY_MAX_FRAME_BYTES || !hub.is_active(session) {
        return false;
    }
    let Ok(frame) = PolicyWireFrame::decode(bytes) else {
        return false;
    };
    match frame {
        PolicyWireFrame::PolicyHealth {
            gateway_id,
            boot_id,
            last_applied_revision,
            controller_epoch,
            bundle_generation,
            checksum,
            capabilities,
            emergency_disabled,
            reported_at_ms,
            ..
        } if gateway_id == session.gateway_id => {
            if agent_boot_id
                .as_ref()
                .is_some_and(|current| current != &boot_id)
            {
                return false;
            }
            if service
                .record_health(
                    &session.gateway_id,
                    &boot_id,
                    hub.controller_epoch(),
                    last_applied_revision,
                    &capabilities,
                    emergency_disabled,
                    reported_at_ms,
                )
                .is_ok()
            {
                if let Some(bundle) = hub.current_bundle(&session.gateway_id)
                    && let Some((
                        expected_gateway,
                        expected_epoch,
                        revision,
                        generation,
                        expected_checksum,
                    )) = bundle.frame.snapshot_identity()
                    && expected_gateway == session.gateway_id
                    && last_applied_revision == revision
                    && controller_epoch.as_deref() == Some(expected_epoch)
                    && bundle_generation == Some(generation)
                    && checksum.as_deref() == Some(expected_checksum)
                {
                    hub.record_flow_capabilities(&session.gateway_id, revision, &capabilities);
                }
                *agent_boot_id = Some(boot_id);
                true
            } else {
                false
            }
        }
        PolicyWireFrame::PolicyAck {
            gateway_id,
            boot_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            checksum,
            status,
            capabilities,
            results,
            reported_at_ms,
            ..
        } if gateway_id == session.gateway_id => {
            if agent_boot_id.as_deref() != Some(boot_id.as_str()) {
                return false;
            }
            let Some(bundle) = last_sent.as_ref() else {
                return false;
            };
            let Some((
                expected_gateway,
                expected_epoch,
                expected_revision,
                expected_generation,
                expected_checksum,
            )) = bundle.frame.snapshot_identity()
            else {
                return false;
            };
            if expected_gateway != gateway_id
                || expected_epoch != controller_epoch
                || expected_revision != config_revision
                || expected_generation != bundle_generation
                || expected_checksum != checksum
            {
                return false;
            }
            let result = service.record_ack(
                &session.gateway_id,
                &boot_id,
                &controller_epoch,
                config_revision,
                bundle_generation,
                &checksum,
                status,
                &capabilities,
                &results,
                reported_at_ms,
            );
            if matches!(result, Ok(true)) {
                hub.record_flow_capabilities(&session.gateway_id, config_revision, &capabilities);
                true
            } else {
                false
            }
        }
        PolicyWireFrame::PolicyMetrics {
            gateway_id,
            boot_id,
            sampled_at_ms,
            metrics,
            ..
        } if gateway_id == session.gateway_id => {
            if agent_boot_id.as_deref() != Some(boot_id.as_str()) {
                return false;
            }
            service
                .record_metrics(&gateway_id, &boot_id, sampled_at_ms, &metrics)
                .is_ok()
        }
        PolicyWireFrame::FlowAck {
            gateway_id,
            boot_id,
            controller_epoch,
            config_revision,
            command_id,
            policy_flow_id,
            status,
            reason_code,
            alias_count,
            reported_at_ms,
            ..
        } if gateway_id == session.gateway_id => {
            if agent_boot_id.as_deref() != Some(boot_id.as_str()) {
                return false;
            }
            if !hub.acknowledge_flow_command(
                session,
                &gateway_id,
                &boot_id,
                &controller_epoch,
                &command_id,
                &policy_flow_id,
                config_revision,
                status,
            ) {
                return false;
            }
            tracing::debug!(
                gateway_id,
                boot_id,
                command_id,
                policy_flow_id,
                config_revision,
                ?status,
                reason_code = reason_code.as_deref().unwrap_or(""),
                alias_count,
                reported_at_ms,
                "agent acknowledged an application flow command"
            );
            true
        }
        _ => false,
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| {
            i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyService;
    use netqmon_protocol::policy::POLICY_WIRE_VERSION;

    fn flow_command(hub: &PolicyHub, number: u64, revision: u64, revoke: bool) -> PolicyWireFrame {
        PolicyWireFrame::FlowCommand {
            wire_version: POLICY_WIRE_VERSION,
            gateway_id: "gw-test".to_owned(),
            boot_id: "boot-test".to_owned(),
            controller_epoch: hub.inner.controller_epoch.clone(),
            config_revision: revision,
            command_id: uuid::Uuid::new_v4().to_string(),
            policy_flow_id: format!("{number:032x}"),
            operation: if revoke {
                FlowCommandOperation::Revoke
            } else {
                FlowCommandOperation::Upsert
            },
            verdict: (!revoke).then_some(netqmon_protocol::policy::FlowVerdict::Shape),
            policy_ids: if revoke {
                Vec::new()
            } else {
                vec!["00000000-0000-4000-8000-000000000001".to_owned()]
            },
            issued_at_ms: now_ms(),
            expires_at_ms: now_ms() + 30_000,
        }
    }

    #[test]
    fn old_and_future_revisions_cannot_starve_current_flow_commands() {
        let hub = PolicyHub::new();
        let session = hub.register("gw-test").unwrap();
        for number in 0..128 {
            hub.queue_flow_command(flow_command(&hub, number, 0, true))
                .unwrap();
        }
        let frame = compile_snapshot(
            "gw-test",
            &hub.inner.controller_epoch,
            1,
            now_ms(),
            1,
            Vec::new(),
        )
        .unwrap();
        hub.inner
            .gateways
            .lock()
            .unwrap()
            .get_mut("gw-test")
            .unwrap()
            .bundle = Some(Arc::new(PublishedBundle {
            bytes: Arc::new(frame.encode().unwrap()),
            frame,
        }));
        for number in 128..256 {
            assert_eq!(
                hub.queue_flow_command(flow_command(&hub, number, 2, false)),
                Err("stale_flow_command_snapshot".to_owned())
            );
        }
        let current = flow_command(&hub, 256, 1, false);
        hub.queue_flow_command(current.clone()).unwrap();
        assert_eq!(hub.take_flow_command(&session, 1), Some(current));
        assert!(hub.take_flow_command(&session, 1).is_none());
    }

    #[test]
    fn stale_flow_context_cannot_replace_a_newer_same_revision_decision() {
        let service = PolicyService::open_in_memory().unwrap();
        let hub = PolicyHub::new();
        hub.refresh_gateway(&service, "gw-test", false).unwrap();
        let now = now_ms();
        let request = |application_id: &str| PolicyPreviewRequest {
            gateway_id: "gw-test".to_owned(),
            client_mac: "02:00:00:00:00:01".to_owned(),
            application_id: application_id.to_owned(),
            category_id: "streaming".to_owned(),
            application_confidence: 0.99,
            scope: "internet".to_owned(),
            at_ms: now,
        };
        let flow_id = "00000000000000000000000000000001";
        let old_generation = hub
            .remember_flow_context("gw-test", "boot-test", flow_id, 6, request("old-app"), now)
            .unwrap();
        let new_generation = hub
            .remember_flow_context(
                "gw-test",
                "boot-test",
                flow_id,
                6,
                request("new-app"),
                now + 1,
            )
            .unwrap();
        let session = hub.register("gw-test").unwrap();
        let old = flow_command(&hub, 1, 0, false);
        hub.queue_flow_command_for_context(old, old_generation)
            .unwrap();
        assert!(hub.take_flow_command(&session, 0).is_none());

        let current = flow_command(&hub, 1, 0, false);
        let current_id = flow_command_id(&current).unwrap().to_owned();
        hub.queue_flow_command_for_context(current, new_generation)
            .unwrap();
        let late_old = flow_command(&hub, 1, 0, true);
        hub.queue_flow_command_for_context(late_old, old_generation)
            .unwrap();
        let states = hub.inner.gateways.lock().unwrap();
        let saved = &states["gw-test"].flow_states[&flow_command_key("boot-test", flow_id)];
        assert_eq!(flow_command_id(saved), Some(current_id.as_str()));
    }

    #[test]
    fn flow_command_from_an_old_snapshot_is_rejected_before_queueing() {
        let hub = PolicyHub::new();
        hub.refresh_gateway(&PolicyService::open_in_memory().unwrap(), "gw-test", false)
            .unwrap();
        let next = compile_snapshot(
            "gw-test",
            &hub.inner.controller_epoch,
            2,
            now_ms(),
            1,
            Vec::new(),
        )
        .unwrap();
        hub.inner
            .gateways
            .lock()
            .unwrap()
            .get_mut("gw-test")
            .unwrap()
            .bundle = Some(Arc::new(PublishedBundle {
            bytes: Arc::new(next.encode().unwrap()),
            frame: next,
        }));

        assert_eq!(
            hub.queue_flow_command(flow_command(&hub, 1, 0, false)),
            Err("stale_flow_command_snapshot".to_owned())
        );
        assert!(
            hub.inner.gateways.lock().unwrap()["gw-test"]
                .flow_states
                .is_empty()
        );
    }

    #[test]
    fn retry_and_unsent_commands_cannot_overwrite_a_newer_decision() {
        let hub = PolicyHub::new();
        let session = hub.register("gw-test").unwrap();
        let old = flow_command(&hub, 1, 0, false);
        hub.queue_flow_command(old.clone()).unwrap();
        let old = hub.take_flow_command(&session, 0).unwrap();
        hub.mark_flow_command_sent(&session, old.clone());
        let newer = flow_command(&hub, 1, 0, true);
        hub.queue_flow_command(newer.clone()).unwrap();
        {
            let mut states = hub.inner.gateways.lock().unwrap();
            let state = states.get_mut("gw-test").unwrap();
            for pending in state.flow_in_flight.values_mut() {
                pending.sent_at = Instant::now() - FLOW_COMMAND_RETRY_AFTER;
            }
        }
        hub.retry_flow_commands(&session);
        hub.requeue_unsent_flow_command(&session, old);
        let delivered = hub.take_flow_command(&session, 0).unwrap();
        assert_eq!(flow_command_id(&delivered), flow_command_id(&newer));
        let states = hub.inner.gateways.lock().unwrap();
        assert!(states["gw-test"].flow_in_flight.is_empty());
        assert!(states["gw-test"].flow_attempts.is_empty());
    }

    #[test]
    fn acknowledgement_reopens_a_full_window_and_keeps_a_newer_decision() {
        use futures_util::FutureExt as _;
        let hub = PolicyHub::new();
        let session = hub.register("gw-test").unwrap();
        for number in 0..=FLOW_COMMAND_IN_FLIGHT_CAPACITY as u64 {
            hub.queue_flow_command(flow_command(&hub, number, 0, true))
                .unwrap();
        }
        let mut sent = Vec::new();
        for _ in 0..FLOW_COMMAND_IN_FLIGHT_CAPACITY {
            let frame = hub.take_flow_command(&session, 0).unwrap();
            hub.mark_flow_command_sent(&session, frame.clone());
            sent.push(frame);
        }
        assert!(hub.take_flow_command(&session, 0).is_none());
        let _ = session.flow_notify.notified().now_or_never();
        let PolicyWireFrame::FlowCommand {
            command_id,
            policy_flow_id,
            ..
        } = &sent[0]
        else {
            unreachable!()
        };
        let number = u64::from_str_radix(policy_flow_id, 16).unwrap();
        let newer = flow_command(&hub, number, 0, false);
        hub.queue_flow_command(newer.clone()).unwrap();
        let _ = session.flow_notify.notified().now_or_never();
        assert!(hub.acknowledge_flow_command(
            &session,
            "gw-test",
            "boot-test",
            &hub.inner.controller_epoch,
            command_id,
            policy_flow_id,
            0,
            FlowAckStatus::Applied
        ));
        assert!(session.flow_notify.notified().now_or_never().is_some());
        let states = hub.inner.gateways.lock().unwrap();
        let current =
            &states["gw-test"].flow_states[&flow_command_key("boot-test", policy_flow_id)];
        assert_eq!(flow_command_id(current), flow_command_id(&newer));
    }

    #[test]
    fn degraded_block_capability_allows_exact_commands_only_at_the_current_revision() {
        use netqmon_protocol::policy::{PolicyCapabilities, PolicyCapability};
        let service = PolicyService::open_in_memory().unwrap();
        let hub = PolicyHub::new();
        hub.refresh_gateway(&service, "gw-test", false).unwrap();
        let mut capabilities = PolicyCapabilities::unsupported();
        capabilities.application_block = PolicyCapability::Degraded;
        hub.record_flow_capabilities("gw-test", 0, &capabilities);
        assert_eq!(hub.flow_capabilities("gw-test"), (true, false));
        hub.record_flow_capabilities("gw-test", 1, &capabilities);
        assert_eq!(hub.flow_capabilities("gw-test"), (true, false));
        capabilities.application_block = PolicyCapability::Unsupported;
        hub.record_flow_capabilities("gw-test", 0, &capabilities);
        assert_eq!(hub.flow_capabilities("gw-test"), (false, false));
    }

    #[test]
    fn hub_replays_the_same_bundle_then_coalesces_to_the_latest_snapshot() {
        let service = PolicyService::open_in_memory().unwrap();
        let hub = PolicyHub::new();
        let first = hub.refresh_gateway(&service, "gw-test", false).unwrap();
        let same = hub.refresh_gateway(&service, "gw-test", false).unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(first.bytes(), same.bytes());
        let session = hub.register("gw-test").unwrap();
        assert_eq!(
            session.updates.borrow().as_ref().unwrap().bytes(),
            first.bytes()
        );
        assert!(hub.is_active(&session));
        assert!(hub.unregister(&session));
    }

    #[test]
    fn new_authenticated_session_invalidates_the_previous_connection() {
        let hub = PolicyHub::new();
        let old = hub.register("gw-test").unwrap();
        let current = hub.register("gw-test").unwrap();
        assert!(!hub.is_active(&old));
        assert!(hub.is_active(&current));
        assert!(*old.cancelled.borrow());
    }
}
