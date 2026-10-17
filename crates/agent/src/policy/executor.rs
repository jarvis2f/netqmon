use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::policy::{
    MAX_SAFE_JSON_INTEGER, POLICY_WIRE_VERSION, PolicyAckStatus, PolicyActionKind,
    PolicyCapabilities, PolicyCapability, PolicyClientMetrics, PolicyClientRate,
    PolicyDirectionMetrics, PolicyResult, PolicyResultDetails, PolicyResultStatus,
    PolicySnapshotEntry, PolicyWireFrame,
};
use sha2::{Digest as _, Sha256};

use crate::config::AgentConfig;

use super::capabilities::{self, PolicyTopology};
use super::flow_verdict::{self, FlowVerdictWriter};
use super::identity::{ClientAddresses, IdentityError};
use super::mark::{self, MarkRule};
use super::nft::{self, NftPlan};
use super::qdisc;
use super::schedule::{self, ScheduleState};
use super::shaper::{self, ClientRates, Direction, ManagedInterface, ShapingState};
use super::state::{self, PolicyState};

const POLICY_BLOCK_METRICS_INTERFACE: &str = "policy-block";

pub(crate) fn restore_local(
    config: &AgentConfig,
    gateway_id: &str,
    _boot_id: &str,
    flow_bpf_ready: bool,
) -> Option<(String, PolicyWireFrame)> {
    if Path::new(&config.policy_disabled_path).exists() {
        return None;
    }
    let saved = match state::load(&config.policy_state_path, gateway_id) {
        Ok(Some(saved)) => saved,
        Ok(None) => return None,
        Err(error) => {
            eprintln!("saved policy state was rejected: {error}");
            return None;
        }
    };
    let acknowledgement = process_snapshot_with_flow_capability(
        config,
        gateway_id,
        "startup-restore",
        &saved.snapshot,
        flow_bpf_ready,
    );
    match acknowledgement {
        PolicyWireFrame::PolicyAck {
            status: PolicyAckStatus::Applied | PolicyAckStatus::Partial,
            ..
        } => Some((saved.gateway_id, saved.snapshot)),
        PolicyWireFrame::PolicyAck { results, .. } => {
            let details = results
                .iter()
                .find_map(|result| result.message.as_deref())
                .unwrap_or("the local policy snapshot was not applied");
            eprintln!("saved policy state could not be restored: {details}");
            None
        }
        _ => None,
    }
}

pub(crate) fn invalidate_gateway_mismatch(
    config: &AgentConfig,
    gateway_id: &str,
) -> Result<(), String> {
    let Some(saved) = state::load_any(&config.policy_state_path)? else {
        return Ok(());
    };
    if saved.gateway_id == gateway_id {
        return Ok(());
    }
    nft::clear_owned()?;
    if let Some(shaping) = &saved.shaping_state {
        qdisc::write_journal(&config.policy_state_path, Some(shaping), None)?;
        qdisc::restore(shaping)?;
        let mut cleared = saved;
        cleared.shaping_state = None;
        cleared.shaping_marks.clear();
        state::persist(&config.policy_state_path, &cleared)?;
        qdisc::clear_journal(&config.policy_state_path)?;
        state::quarantine_gateway_mismatch(&config.policy_state_path)
    } else {
        state::quarantine_gateway_mismatch(&config.policy_state_path)
    }
}

pub(crate) fn process_snapshot(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    snapshot: &PolicyWireFrame,
) -> PolicyWireFrame {
    process_snapshot_with_flow_capability(config, gateway_id, boot_id, snapshot, false)
}

pub(crate) fn process_snapshot_with_flow_capability(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    snapshot: &PolicyWireFrame,
    flow_bpf_ready: bool,
) -> PolicyWireFrame {
    let topology = runtime_topology(config, flow_bpf_ready);
    process_snapshot_with(
        config,
        gateway_id,
        boot_id,
        snapshot,
        &topology,
        &mut SystemNftRunner,
        state::persist,
    )
}

fn runtime_topology(config: &AgentConfig, flow_bpf_ready: bool) -> PolicyTopology {
    let mut topology = capabilities::inspect(config);
    if flow_bpf_ready && topology.supported {
        topology.capabilities.application_block = if topology.is_one_arm_router() {
            PolicyCapability::Degraded
        } else {
            PolicyCapability::Supported
        };
        if topology.capabilities.client_limit != PolicyCapability::Unsupported
            && topology
                .lan_interfaces
                .iter()
                .chain(&topology.wan_interfaces)
                .all(|interface| config.interfaces.contains(interface))
            && qdisc::application_shaping_supported().is_ok()
        {
            topology.capabilities.application_limit = PolicyCapability::Supported;
        }
    }
    topology
}

pub(crate) fn priority_runtime_capabilities(
    flow_bpf_ready: bool,
    client_block: PolicyCapability,
) -> PolicyCapabilities {
    let application_capability = if flow_bpf_ready {
        PolicyCapability::Supported
    } else {
        PolicyCapability::Unsupported
    };
    PolicyCapabilities {
        client_block,
        client_limit: PolicyCapability::Supported,
        application_block: application_capability,
        application_limit: application_capability,
    }
}

trait NftRunner {
    fn clear_owned(&mut self) -> Result<(), String>;
    fn is_installed(&mut self) -> Result<bool, String>;
    fn replace(&mut self, topology: &PolicyTopology, plan: &NftPlan) -> Result<(), String>;
    fn inspect_mark_conflicts(
        &mut self,
        _topology: &PolicyTopology,
        _owned: Option<&ShapingState>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn prepare_shaping(
        &mut self,
        desired: &ShapingState,
        _previous: Option<&ShapingState>,
    ) -> Result<ShapingState, String> {
        Ok(desired.clone())
    }
    fn write_shaping_journal(
        &mut self,
        _state_path: &Path,
        _previous: Option<&ShapingState>,
        _next: Option<&ShapingState>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn apply_shaping(
        &mut self,
        _desired: &ShapingState,
        _previous: Option<&ShapingState>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn rollback_shaping(
        &mut self,
        _previous: Option<&ShapingState>,
        _current: Option<&ShapingState>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn clear_shaping_journal(&mut self, _state_path: &Path) -> Result<(), String> {
        Ok(())
    }
    fn recover_shaping_journal(
        &mut self,
        _state_path: &Path,
        _committed: Option<&ShapingState>,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

struct SystemNftRunner;

impl NftRunner for SystemNftRunner {
    fn clear_owned(&mut self) -> Result<(), String> {
        nft::clear_owned()
    }

    fn is_installed(&mut self) -> Result<bool, String> {
        nft::is_installed()
    }

    fn replace(&mut self, topology: &PolicyTopology, plan: &NftPlan) -> Result<(), String> {
        nft::replace(topology, plan)
    }

    fn inspect_mark_conflicts(
        &mut self,
        topology: &PolicyTopology,
        owned: Option<&ShapingState>,
    ) -> Result<(), String> {
        let interfaces = topology
            .lan_interfaces
            .iter()
            .chain(topology.wan_interfaces.iter())
            .cloned()
            .collect::<Vec<_>>();
        mark::inspect_conflicts(&interfaces, owned)
    }

    fn prepare_shaping(
        &mut self,
        desired: &ShapingState,
        previous: Option<&ShapingState>,
    ) -> Result<ShapingState, String> {
        qdisc::prepare_state(desired, previous)
    }

    fn write_shaping_journal(
        &mut self,
        state_path: &Path,
        previous: Option<&ShapingState>,
        next: Option<&ShapingState>,
    ) -> Result<(), String> {
        qdisc::write_journal(state_path, previous, next)
    }

    fn apply_shaping(
        &mut self,
        desired: &ShapingState,
        previous: Option<&ShapingState>,
    ) -> Result<(), String> {
        qdisc::apply(desired, previous)
    }

    fn rollback_shaping(
        &mut self,
        previous: Option<&ShapingState>,
        current: Option<&ShapingState>,
    ) -> Result<(), String> {
        match (previous, current) {
            (Some(previous), Some(current)) => qdisc::apply(previous, Some(current)),
            (Some(previous), None) => qdisc::apply(previous, None),
            (None, Some(current)) => qdisc::restore(current),
            (None, None) => Ok(()),
        }
    }

    fn clear_shaping_journal(&mut self, state_path: &Path) -> Result<(), String> {
        qdisc::clear_journal(state_path)
    }

    fn recover_shaping_journal(
        &mut self,
        state_path: &Path,
        committed: Option<&ShapingState>,
    ) -> Result<bool, String> {
        qdisc::recover_journal(state_path, committed)
    }
}

fn process_snapshot_with(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    snapshot: &PolicyWireFrame,
    topology: &PolicyTopology,
    nft_runner: &mut impl NftRunner,
    persist: impl Fn(&Path, &PolicyState) -> Result<(), String>,
) -> PolicyWireFrame {
    let Some((frame_gateway, epoch, revision, generation, checksum)) = snapshot.snapshot_identity()
    else {
        return health_frame(config, gateway_id, boot_id);
    };
    if frame_gateway != gateway_id || snapshot.validate().is_err() {
        return failure_ack(
            snapshot,
            boot_id,
            &topology.capabilities,
            "invalid_snapshot",
            "snapshot validation failed or the gateway binding does not match",
            PolicyAckStatus::Failed,
        );
    }
    if Path::new(&config.policy_disabled_path).exists() {
        return policy_ack(
            snapshot,
            boot_id,
            topology.capabilities.clone(),
            PolicyAckStatus::Failed,
            snapshot_results(
                snapshot,
                PolicyResultStatus::Failed,
                Some((
                    "emergency_disabled",
                    "local emergency disable marker is present",
                )),
            ),
        );
    }

    if matches!(snapshot, PolicyWireFrame::PolicySnapshot { policies, .. }
        if policies.iter().any(|policy| policy.spec.enabled
            && netqmon_protocol::policy::is_client_total_spec(&policy.spec)))
    {
        return failure_ack(
            snapshot,
            boot_id,
            &topology.capabilities,
            "priority_backend_required",
            "client totals require the verified priority backend; the previous policy remains active",
            PolicyAckStatus::Failed,
        );
    }

    let old = match state::load(&config.policy_state_path, gateway_id) {
        Ok(old) => old,
        Err(error) => {
            return failure_ack(
                snapshot,
                boot_id,
                &topology.capabilities,
                "local_state_invalid",
                &error,
                PolicyAckStatus::Failed,
            );
        }
    };
    if let Err(error) = nft_runner.recover_shaping_journal(
        &config.policy_state_path,
        old.as_ref().and_then(|saved| saved.shaping_state.as_ref()),
    ) {
        return failure_ack(
            snapshot,
            boot_id,
            &topology.capabilities,
            "manual_cleanup_required",
            &error,
            PolicyAckStatus::Failed,
        );
    }
    if let Some(previous) = &old {
        if revision < previous.config_revision {
            return failure_ack(
                snapshot,
                boot_id,
                &topology.capabilities,
                "revision_rollback_detected",
                "snapshot revision is lower than the last successfully persisted revision",
                PolicyAckStatus::Failed,
            );
        }
        if epoch == previous.controller_epoch
            && (revision < previous.config_revision
                || (revision == previous.config_revision
                    && generation < previous.bundle_generation))
        {
            return failure_ack(
                snapshot,
                boot_id,
                &topology.capabilities,
                "stale_snapshot",
                "snapshot revision or generation is older than the last applied snapshot",
                PolicyAckStatus::Failed,
            );
        }
        if epoch == previous.controller_epoch
            && revision == previous.config_revision
            && generation == previous.bundle_generation
            && checksum != previous.checksum
        {
            return failure_ack(
                snapshot,
                boot_id,
                &topology.capabilities,
                "snapshot_identity_conflict",
                "the same epoch, revision, and generation carried a different checksum",
                PolicyAckStatus::Failed,
            );
        }
    }

    let (policies, intervals, valid_until_ms) =
        snapshot_parts(snapshot).expect("snapshot checked above");
    let now = now_ms();
    if !topology.supported && policies.iter().any(is_supported_client_policy) {
        let results = unsupported_topology_results(policies, topology);
        return policy_ack(
            snapshot,
            boot_id,
            topology.capabilities.clone(),
            PolicyAckStatus::Unsupported,
            results,
        );
    }

    let mut runtime_topology = topology.clone();
    let previous_shape = old.as_ref().and_then(|saved| saved.shaping_state.as_ref());
    let mut plan = build_plan(policies, intervals, valid_until_ms, now, &runtime_topology);
    let mut preflight_error = None;
    let has_shaping_rates = !plan.client_rates.is_empty() || !plan.application_rates.is_empty();
    if has_shaping_rates {
        if let Err(error) = nft_runner.inspect_mark_conflicts(&runtime_topology, previous_shape) {
            preflight_error = Some(error);
        } else if let Err(error) =
            compile_shaping_plan(gateway_id, &runtime_topology, previous_shape, &mut plan)
        {
            preflight_error = Some(error);
        }
        if let Some(error) = &preflight_error {
            mark_limit_unsupported(&mut runtime_topology, error);
            return failure_ack(
                snapshot,
                boot_id,
                &runtime_topology.capabilities,
                error
                    .split_once(": ")
                    .map_or("unsupported_mark_conflict", |(code, _)| code),
                &format!("{error}; the previous policy snapshot remains active"),
                PolicyAckStatus::Failed,
            );
        }
    }

    let mut desired_shape = plan
        .shaping_state
        .clone()
        .unwrap_or_else(ShapingState::empty);
    let mut saved_shape = plan.shaping_state.clone();
    let mut shape_prepared = false;
    let mut shape_error = None;
    if plan.shaping_state.is_some() || previous_shape.is_some() {
        match nft_runner.prepare_shaping(&desired_shape, previous_shape) {
            Ok(prepared) => {
                desired_shape = prepared;
                saved_shape = (!desired_shape.is_empty()).then(|| desired_shape.clone());
                plan.shaping_state = saved_shape.clone();
                shape_prepared = true;
            }
            Err(error) if has_shaping_rates => {
                mark_limit_unsupported(&mut runtime_topology, &error);
                return failure_ack(
                    snapshot,
                    boot_id,
                    &runtime_topology.capabilities,
                    error
                        .split_once(": ")
                        .map_or("unsupported_existing_qdisc", |(code, _)| code),
                    &format!("{error}; the previous policy snapshot remains active"),
                    PolicyAckStatus::Failed,
                );
            }
            Err(error) => {
                shape_error = Some(error);
                saved_shape = previous_shape.cloned();
                plan.shaping_state = saved_shape.clone();
            }
        }
    }
    if let Some(error) = shape_error.as_deref() {
        mark_limit_results_degraded(&mut plan, policies, error);
    }
    let shape_changed = previous_shape != saved_shape.as_ref();
    if previous_shape.is_some() && shape_error.is_some() && !shape_prepared {
        let error = shape_error.as_deref().unwrap_or("manual_cleanup_required");
        let code = error
            .split_once(": ")
            .map_or("manual_cleanup_required", |(code, _)| code);
        return failure_ack(
            snapshot,
            boot_id,
            &runtime_topology.capabilities,
            code,
            error,
            PolicyAckStatus::Failed,
        );
    }

    let topology_fingerprint = topology_fingerprint(&runtime_topology);
    let nft_plan = NftPlan {
        blocked_v4: plan.blocked_v4.iter().copied().collect(),
        blocked_v6: plan.blocked_v6.iter().copied().collect(),
        mark_rules: plan.mark_rules.clone(),
    };
    let previous_mark_rules = old
        .as_ref()
        .map_or(&[][..], |saved| saved.shaping_marks.as_slice());
    let same_configuration = old.as_ref().is_some_and(|previous| {
        previous.checksum == checksum
            && previous.topology_fingerprint == topology_fingerprint
            && previous.blocked_clients_v4
                == nft_plan
                    .blocked_v4
                    .iter()
                    .copied()
                    .map(IpAddr::V4)
                    .collect::<Vec<_>>()
            && previous.blocked_clients_v6
                == nft_plan
                    .blocked_v6
                    .iter()
                    .copied()
                    .map(IpAddr::V6)
                    .collect::<Vec<_>>()
            && previous_mark_rules == nft_plan.mark_rules.as_slice()
            && previous.shaping_state == saved_shape
    });
    let mut journal_written = false;
    if shape_prepared && shape_changed {
        let previous_saved_shape = old.as_ref().and_then(|saved| saved.shaping_state.as_ref());
        let next_saved_shape = saved_shape.as_ref();
        if previous_saved_shape.is_some() || next_saved_shape.is_some() {
            if let Err(error) = nft_runner.write_shaping_journal(
                &config.policy_state_path,
                previous_saved_shape,
                next_saved_shape,
            ) {
                return failure_ack(
                    snapshot,
                    boot_id,
                    &runtime_topology.capabilities,
                    "state_prepare_failed",
                    &error,
                    PolicyAckStatus::Failed,
                );
            }
            journal_written = true;
        }
    }
    if !plan.has_supported_policy {
        if let Err(error) = nft_runner.clear_owned() {
            if journal_written {
                let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
            }
            return failure_ack(
                snapshot,
                boot_id,
                &runtime_topology.capabilities,
                "nft_apply_failed",
                &error,
                PolicyAckStatus::Failed,
            );
        }
    } else {
        let installed = if same_configuration {
            nft_runner.is_installed()
        } else {
            Ok(false)
        };
        match installed {
            Ok(true) => {}
            Ok(false) => {
                if let Err(error) = nft_runner.replace(&runtime_topology, &nft_plan) {
                    let rollback_error = rollback_runtime(
                        &runtime_topology,
                        old.as_ref(),
                        None,
                        false,
                        &config.policy_state_path,
                        nft_runner,
                    )
                    .err();
                    if journal_written {
                        let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
                    }
                    let message = rollback_error
                        .map(|rollback| format!("{error}; rollback failed: {rollback}"))
                        .unwrap_or(error);
                    return failure_ack(
                        snapshot,
                        boot_id,
                        &runtime_topology.capabilities,
                        "nft_apply_failed",
                        &message,
                        PolicyAckStatus::Failed,
                    );
                }
            }
            Err(error) => {
                if journal_written {
                    let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
                }
                return failure_ack(
                    snapshot,
                    boot_id,
                    &runtime_topology.capabilities,
                    "nft_inspection_failed",
                    &error,
                    PolicyAckStatus::Failed,
                );
            }
        }
    }

    if shape_prepared
        && shape_changed
        && let Err(error) = nft_runner.apply_shaping(&desired_shape, previous_shape)
    {
        let rollback = rollback_runtime(
            &runtime_topology,
            old.as_ref(),
            Some(&desired_shape),
            true,
            &config.policy_state_path,
            nft_runner,
        );
        if rollback.is_ok() && journal_written {
            let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
        }
        let message = rollback
            .err()
            .map(|rollback| format!("{error}; rollback failed: {rollback}"))
            .unwrap_or(error);
        return failure_ack(
            snapshot,
            boot_id,
            &runtime_topology.capabilities,
            "tc_apply_failed",
            &message,
            PolicyAckStatus::Failed,
        );
    }

    let state = match PolicyState::from_snapshot(
        snapshot.clone(),
        topology_fingerprint,
        plan.blocked_v4.iter().copied().map(IpAddr::V4).collect(),
        plan.blocked_v6.iter().copied().map(IpAddr::V6).collect(),
        saved_shape,
        plan.mark_rules.clone(),
    ) {
        Ok(state) => state,
        Err(error) => {
            let rollback = rollback_runtime(
                &runtime_topology,
                old.as_ref(),
                Some(&desired_shape),
                shape_prepared && shape_changed,
                &config.policy_state_path,
                nft_runner,
            );
            if rollback.is_ok() && journal_written {
                let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
            }
            let message = rollback
                .err()
                .map(|rollback| format!("{error}; rollback failed: {rollback}"))
                .unwrap_or(error);
            return failure_ack(
                snapshot,
                boot_id,
                &topology.capabilities,
                "state_prepare_failed",
                &message,
                PolicyAckStatus::Failed,
            );
        }
    };
    if old.as_ref() != Some(&state)
        && let Err(error) = persist(&config.policy_state_path, &state)
    {
        let rollback = rollback_runtime(
            &runtime_topology,
            old.as_ref(),
            Some(&desired_shape),
            shape_prepared && shape_changed,
            &config.policy_state_path,
            nft_runner,
        );
        if rollback.is_ok() && journal_written {
            let _ = nft_runner.clear_shaping_journal(&config.policy_state_path);
        }
        let message = rollback
            .err()
            .map(|rollback| format!("{error}; rollback failed: {rollback}"))
            .unwrap_or(error);
        return failure_ack(
            snapshot,
            boot_id,
            &topology.capabilities,
            "state_persist_failed",
            &message,
            PolicyAckStatus::Failed,
        );
    }
    if journal_written
        && let Err(error) = nft_runner.clear_shaping_journal(&config.policy_state_path)
    {
        eprintln!("policy shaping journal remains for startup reconciliation: {error}");
    }
    policy_ack(
        snapshot,
        boot_id,
        runtime_topology.capabilities.clone(),
        plan.ack_status,
        plan.results,
    )
}

pub(crate) fn reconcile_saved_with_flow_capability(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_bpf_ready: bool,
) -> Option<PolicyWireFrame> {
    let saved = state::load(&config.policy_state_path, gateway_id)
        .ok()
        .flatten()?;
    if Path::new(&config.policy_disabled_path).exists() {
        return Some(saved.snapshot);
    }
    Some(process_snapshot_with_flow_capability(
        config,
        gateway_id,
        boot_id,
        &saved.snapshot,
        flow_bpf_ready,
    ))
}

pub(crate) fn traffic_metrics_frames(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_verdict_writer: &FlowVerdictWriter,
) -> Vec<PolicyWireFrame> {
    let Ok(Some(saved)) = state::load(&config.policy_state_path, gateway_id) else {
        return Vec::new();
    };
    let Some((policies, intervals, valid_until_ms)) = snapshot_parts(&saved.snapshot) else {
        return Vec::new();
    };
    let Some(sampled_at_ms) = now_ms().filter(|value| *value >= 0) else {
        return Vec::new();
    };
    let mut metrics = BTreeMap::<(String, String), PolicyClientMetrics>::new();
    append_block_policy_metrics(
        &mut metrics,
        policies,
        intervals,
        valid_until_ms,
        sampled_at_ms,
        flow_verdict_writer,
    );
    let classes = saved
        .shaping_state
        .as_ref()
        .and_then(|shaping| qdisc::read_metrics(shaping).ok())
        .unwrap_or_default();
    append_shaping_policy_metrics(
        &mut metrics,
        policies,
        intervals,
        valid_until_ms,
        sampled_at_ms,
        &classes,
    );
    metrics
        .into_values()
        .collect::<Vec<_>>()
        .chunks(256)
        .map(|chunk| PolicyWireFrame::PolicyMetrics {
            wire_version: POLICY_WIRE_VERSION,
            gateway_id: gateway_id.to_owned(),
            boot_id: boot_id.to_owned(),
            sampled_at_ms,
            metrics: chunk.to_vec(),
        })
        .collect()
}

fn append_block_policy_metrics(
    metrics: &mut BTreeMap<(String, String), PolicyClientMetrics>,
    policies: &[PolicySnapshotEntry],
    intervals: &[netqmon_protocol::policy::PolicyScheduleIntervals],
    valid_until_ms: i64,
    sampled_at_ms: i64,
    flow_verdict_writer: &FlowVerdictWriter,
) {
    if !flow_verdict_writer.ready() {
        return;
    }
    let block_counters = match flow_verdict_writer.policy_drop_counters() {
        Ok(counters) => counters,
        Err(error) => {
            eprintln!("could not read BPF policy drop counters: {error}");
            return;
        }
    };
    let active_block_policies = policies
        .iter()
        .filter(|policy| {
            policy.spec.enabled
                && policy.spec.action.kind == PolicyActionKind::Block
                && is_application_policy(policy)
                && schedule::evaluate(policy, intervals, Some(sampled_at_ms), valid_until_ms)
                    == ScheduleState::Active
        })
        .map(|policy| {
            (
                flow_verdict::policy_identity_hash(&policy.id),
                policy.id.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for ((policy_hash, client_mac), (packets, bytes)) in block_counters {
        let Some(policy_id) = active_block_policies.get(&policy_hash) else {
            continue;
        };
        let mac = format_client_mac(client_mac);
        metrics.insert(
            ((*policy_id).to_owned(), mac.clone()),
            policy_block_metric(policy_id, mac, packets, bytes),
        );
    }
}

fn append_shaping_policy_metrics(
    metrics: &mut BTreeMap<(String, String), PolicyClientMetrics>,
    policies: &[PolicySnapshotEntry],
    intervals: &[netqmon_protocol::policy::PolicyScheduleIntervals],
    valid_until_ms: i64,
    sampled_at_ms: i64,
    classes: &[qdisc::ClassCounters],
) {
    for policy in policies.iter().filter(|policy| {
        policy.spec.enabled
            && policy.spec.action.kind == PolicyActionKind::Limit
            && (is_client_policy_shape(policy) || is_application_policy(policy))
            && schedule::evaluate(policy, intervals, Some(sampled_at_ms), valid_until_ms)
                == ScheduleState::Active
    }) {
        for class in classes.iter().filter(|class| {
            if is_application_policy(policy) {
                class
                    .application
                    .as_ref()
                    .is_some_and(|application| application.policy_id == policy.id)
            } else {
                class.application.is_none()
                    && class.client.has_total_budget
                    && policy
                        .spec
                        .selectors
                        .clients
                        .iter()
                        .any(|mac| mac.eq_ignore_ascii_case(&class.client.mac))
            }
        }) {
            let mac = class.client.mac.to_ascii_uppercase();
            let key = (policy.id.clone(), mac.clone());
            let item = metrics.entry(key).or_insert_with(|| PolicyClientMetrics {
                policy_id: policy.id.clone(),
                mac,
                upload: None,
                download: None,
            });
            let direction_metrics = PolicyDirectionMetrics {
                interface: class.interface.clone(),
                bytes: class.bytes,
                packets: class.packets,
                drops: class.drops,
                overlimits: class.overlimits,
            };
            let direction = class
                .application
                .as_ref()
                .map_or(class.client.direction, |application| application.direction);
            match direction {
                Direction::Upload => item.upload = Some(direction_metrics),
                Direction::Download => item.download = Some(direction_metrics),
            }
        }
    }
}

fn format_client_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn policy_block_metric(
    policy_id: &str,
    mac: String,
    packets: u64,
    bytes: u64,
) -> PolicyClientMetrics {
    let packets = (packets <= MAX_SAFE_JSON_INTEGER).then_some(packets);
    let bytes = (bytes <= MAX_SAFE_JSON_INTEGER).then_some(bytes);
    PolicyClientMetrics {
        policy_id: policy_id.to_owned(),
        mac,
        upload: Some(PolicyDirectionMetrics {
            interface: POLICY_BLOCK_METRICS_INTERFACE.to_owned(),
            bytes,
            packets,
            drops: packets,
            overlimits: None,
        }),
        download: None,
    }
}

pub(crate) fn health_frame(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
) -> PolicyWireFrame {
    health_frame_with_flow_capability(config, gateway_id, boot_id, false)
}

pub(crate) fn health_frame_with_flow_capability(
    config: &AgentConfig,
    gateway_id: &str,
    boot_id: &str,
    flow_bpf_ready: bool,
) -> PolicyWireFrame {
    let state = state::load(&config.policy_state_path, gateway_id)
        .ok()
        .flatten();
    let capability = runtime_topology(config, flow_bpf_ready);
    let (revision, epoch, generation, checksum) =
        state.as_ref().map_or((0, None, None, None), |state| {
            (
                state.config_revision,
                Some(state.controller_epoch.clone()),
                Some(state.bundle_generation),
                Some(state.checksum.clone()),
            )
        });
    PolicyWireFrame::PolicyHealth {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: boot_id.to_owned(),
        last_applied_revision: revision,
        controller_epoch: epoch,
        bundle_generation: generation,
        checksum,
        capabilities: capability.capabilities,
        reported_at_ms: now_ms().unwrap_or(0).max(0),
        emergency_disabled: Path::new(&config.policy_disabled_path).exists(),
    }
}

pub(crate) fn status_json(config: &AgentConfig) -> serde_json::Value {
    let state = state::load_any(&config.policy_state_path).ok().flatten();
    let topology = capabilities::inspect(config);
    serde_json::json!({
        "gateway_id": state.as_ref().map(|state| state.gateway_id.as_str()),
        "config_revision": state.as_ref().map_or(0, |state| state.config_revision),
        "bundle_generation": state.as_ref().map_or(0, |state| state.bundle_generation),
        "checksum": state.as_ref().map(|state| state.checksum.as_str()),
        "client_block": topology.capabilities.client_block,
        "client_limit": topology.capabilities.client_limit,
        "client_limit_reason_code": topology.client_limit_reason_code,
        "client_limit_reason": topology.client_limit_reason,
        "one_arm_return_path_verified": config.policy_one_arm_return_path_verified,
        "interface_capacities": topology.lan_interfaces.iter().chain(topology.wan_interfaces.iter()).collect::<std::collections::BTreeSet<_>>().into_iter().map(|interface| {
            let capacity = super::capacity::effective(interface, config.policy_interface_capacity_bps.get(interface).copied());
            let measured = capacity.as_ref().ok();
            serde_json::json!({"interface": interface, "capacity_bps": measured.map(|capacity| capacity.bps), "source": measured.map(|capacity| capacity.source), "link_interfaces": measured.map(|capacity| &capacity.link_interfaces), "reason": capacity.as_ref().err()})
        }).collect::<Vec<_>>(),
        "shaping_interfaces": state.as_ref().and_then(|state| state.shaping_state.as_ref()).map(|shaping| {
            shaping.interfaces()
                .map(|interface| interface.name.as_str())
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "shaping_client_classes": state.as_ref().and_then(|state| state.shaping_state.as_ref()).map(|shaping| {
            shaping.interfaces()
                .map(|interface| interface.clients.len())
                .sum::<usize>()
        }).unwrap_or_default(),
        "capability_reason_code": topology.reason_code,
        "capability_reason": topology.reason,
        "emergency_disabled": Path::new(&config.policy_disabled_path).exists(),
        "policy_state_valid": state.is_some(),
    })
}

pub(crate) fn restore_command(config: &AgentConfig) -> Result<(), String> {
    if !is_root() {
        return Err("policy resume must run as root".to_owned());
    }
    let saved = state::load_any(&config.policy_state_path)?
        .ok_or_else(|| "no valid local policy snapshot is available".to_owned())?;
    state::remove_disabled_marker(&config.policy_disabled_path)?;
    // The CLI has no handle to the running Agent's exact-flow BPF maps.
    // Re-enable application snapshots for its next reconciliation tick (or
    // startup), which checks the real map readiness and reinstalls the tree.
    // Processing them here as BPF-unavailable would erase their saved classes.
    if matches!(&saved.snapshot, PolicyWireFrame::PolicySnapshot { policies, .. }
        if policies.iter().any(|policy| policy.spec.enabled && is_application_policy(policy)))
    {
        return Ok(());
    }
    let acknowledgement =
        process_snapshot(config, &saved.gateway_id, "local-resume", &saved.snapshot);
    match acknowledgement {
        PolicyWireFrame::PolicyAck {
            status: PolicyAckStatus::Applied | PolicyAckStatus::Partial,
            ..
        } => Ok(()),
        PolicyWireFrame::PolicyAck { results, .. } => {
            let _ = state::write_disabled_marker(&config.policy_disabled_path);
            let details = results
                .iter()
                .find_map(|result| result.message.as_deref())
                .unwrap_or("the local policy snapshot was not applied");
            Err(format!(
                "could not resume local policy enforcement: {details}"
            ))
        }
        _ => Err("could not resume local policy enforcement".to_owned()),
    }
}

pub(crate) fn unlock_command(config: &AgentConfig) -> Result<(), String> {
    if !is_root() {
        return Err("policy unlock must run as root".to_owned());
    }
    state::write_disabled_marker(&config.policy_disabled_path)?;
    let Some(mut saved) = state::load_any(&config.policy_state_path)? else {
        nft::clear_owned()?;
        return Ok(());
    };
    if let Some(shaping) = &saved.shaping_state {
        qdisc::write_journal(&config.policy_state_path, Some(shaping), None)?;
    }
    nft::clear_owned()?;
    if let Some(shaping) = &saved.shaping_state {
        qdisc::restore(shaping)?;
        saved.shaping_state = None;
        saved.shaping_marks.clear();
        state::persist(&config.policy_state_path, &saved)?;
        qdisc::clear_journal(&config.policy_state_path)?;
    }
    Ok(())
}

fn rollback_runtime(
    topology: &PolicyTopology,
    previous: Option<&PolicyState>,
    current_shape: Option<&ShapingState>,
    rollback_shape: bool,
    state_path: &Path,
    nft_runner: &mut impl NftRunner,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if rollback_shape {
        let previous_shape = previous.and_then(|saved| saved.shaping_state.as_ref());
        match nft_runner.recover_shaping_journal(state_path, previous_shape) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(error) = nft_runner.rollback_shaping(previous_shape, current_shape) {
                    errors.push(format!("qdisc rollback failed: {error}"));
                }
            }
            Err(error) => errors.push(format!("qdisc recovery failed: {error}")),
        }
    }
    if let Some(previous) = previous {
        let plan = NftPlan {
            blocked_v4: previous
                .blocked_clients_v4
                .iter()
                .filter_map(|address| match address {
                    IpAddr::V4(address) => Some(*address),
                    IpAddr::V6(_) => None,
                })
                .collect(),
            blocked_v6: previous
                .blocked_clients_v6
                .iter()
                .filter_map(|address| match address {
                    IpAddr::V6(address) => Some(*address),
                    IpAddr::V4(_) => None,
                })
                .collect(),
            mark_rules: previous.shaping_marks.clone(),
        };
        let has_runtime_policy = !plan.blocked_v4.is_empty()
            || !plan.blocked_v6.is_empty()
            || !plan.mark_rules.is_empty()
            || previous.snapshot_has_enabled_client_policy();
        let result = if has_runtime_policy {
            nft_runner.replace(topology, &plan)
        } else {
            nft_runner.clear_owned()
        };
        if let Err(error) = result {
            errors.push(format!("nft rollback failed: {error}"));
        }
    } else if let Err(error) = nft_runner.clear_owned() {
        errors.push(format!("nft rollback failed: {error}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

impl PolicyState {
    fn snapshot_has_enabled_client_policy(&self) -> bool {
        snapshot_parts(&self.snapshot).is_some_and(|(policies, _, _)| {
            policies.iter().any(|policy| {
                is_supported_client_policy(policy)
                    || (policy.spec.enabled
                        && is_application_policy(policy)
                        && matches!(
                            policy.spec.action.kind,
                            PolicyActionKind::Block
                                | PolicyActionKind::Allow
                                | PolicyActionKind::Limit
                        ))
            })
        })
    }
}

fn mark_limit_unsupported(topology: &mut PolicyTopology, error: &str) {
    let (code, message) = error
        .split_once(": ")
        .filter(|(code, _)| !code.is_empty() && code.len() <= 128)
        .map_or_else(
            || ("unsupported_kernel_feature".to_owned(), error.to_owned()),
            |(code, message)| (code.to_owned(), message.to_owned()),
        );
    topology.capabilities.client_limit = PolicyCapability::Unsupported;
    topology.capabilities.application_limit = PolicyCapability::Unsupported;
    topology.client_limit_reason_code = Some(code);
    topology.client_limit_reason = Some(message);
}

fn mark_limit_results_degraded(
    plan: &mut BuiltPlan,
    policies: &[PolicySnapshotEntry],
    error: &str,
) {
    let code = error
        .split_once(": ")
        .map_or("degraded_ownership_conflict", |(code, _)| code);
    let message = error.split_once(": ").map_or(error, |(_, message)| message);
    for policy in policies
        .iter()
        .filter(|policy| policy.spec.enabled && policy.spec.action.kind == PolicyActionKind::Limit)
    {
        if let Some(result) = plan
            .results
            .iter_mut()
            .find(|result| result.policy_id == policy.id)
        {
            let details = result
                .details
                .get_or_insert_with(PolicyResultDetails::default);
            details.mark_conflict_code = Some(code.to_owned());
            if result.status == PolicyResultStatus::Applied {
                result.status = PolicyResultStatus::Unsupported;
                result.reason_code = Some(code.to_owned());
                result.message = Some(message.to_owned());
            }
        }
    }
    if plan.results.iter().any(|result| {
        matches!(
            result.status,
            PolicyResultStatus::Applied | PolicyResultStatus::Degraded
        )
    }) && plan.results.iter().any(|result| {
        matches!(
            result.status,
            PolicyResultStatus::Unsupported | PolicyResultStatus::Failed
        )
    }) {
        plan.ack_status = PolicyAckStatus::Partial;
    }
}

struct BuiltPlan {
    blocked_v4: BTreeSet<Ipv4Addr>,
    blocked_v6: BTreeSet<Ipv6Addr>,
    results: Vec<PolicyResult>,
    ack_status: PolicyAckStatus,
    has_supported_policy: bool,
    client_rates: BTreeMap<String, ClientRates>,
    application_rates: BTreeMap<(String, String), ClientRates>,
    client_addresses: Vec<(String, IpAddr)>,
    mark_rules: Vec<MarkRule>,
    shaping_state: Option<ShapingState>,
}

fn build_plan(
    policies: &[PolicySnapshotEntry],
    intervals: &[netqmon_protocol::policy::PolicyScheduleIntervals],
    valid_until_ms: i64,
    now: Option<i64>,
    topology: &PolicyTopology,
) -> BuiltPlan {
    let mut results = BTreeMap::<String, PolicyResult>::new();
    let mut candidates = policies
        .iter()
        .filter_map(|policy| {
            if !policy.spec.enabled {
                results.insert(
                    policy.id.clone(),
                    result(&policy.id, PolicyResultStatus::Disabled, None, None),
                );
                return None;
            }
            if !is_client_policy_shape(policy) {
                if is_application_policy(policy)
                    && policy.spec.action.kind == PolicyActionKind::Limit
                    && !policy.spec.selectors.clients.is_empty()
                    && policy.spec.network.scope == "internet"
                    && policy.spec.network.direction == "both"
                    && topology.capabilities.application_limit != PolicyCapability::Unsupported
                {
                    results.insert(
                        policy.id.clone(),
                        result(&policy.id, PolicyResultStatus::Applied, None, None),
                    );
                    return Some(policy);
                }
                if is_application_policy(policy)
                    && matches!(
                        policy.spec.action.kind,
                        PolicyActionKind::Block | PolicyActionKind::Allow
                    )
                    && topology.capabilities.application_block != PolicyCapability::Unsupported
                {
                    results.insert(
                        policy.id.clone(),
                        result(&policy.id, PolicyResultStatus::Applied, None, None),
                    );
                    return None;
                }
                let (code, message) = unsupported_reason(policy, topology);
                results.insert(
                    policy.id.clone(),
                    result(
                        &policy.id,
                        PolicyResultStatus::Unsupported,
                        Some(&code),
                        Some(&message),
                    ),
                );
                return None;
            }
            if policy.spec.action.kind == PolicyActionKind::Limit
                && topology.capabilities.client_limit == PolicyCapability::Unsupported
            {
                let (code, message) = unsupported_reason(policy, topology);
                results.insert(
                    policy.id.clone(),
                    result(
                        &policy.id,
                        PolicyResultStatus::Unsupported,
                        Some(&code),
                        Some(&message),
                    ),
                );
                return None;
            }
            if policy.spec.schedule.is_some()
                && intervals.iter().all(|entry| entry.policy_id != policy.id)
            {
                results.insert(
                    policy.id.clone(),
                    result(
                        &policy.id,
                        PolicyResultStatus::Failed,
                        Some("schedule_window_missing"),
                        Some("scheduled policy has no compiled UTC intervals"),
                    ),
                );
                return None;
            }
            match schedule::evaluate(policy, intervals, now, valid_until_ms) {
                ScheduleState::Expired => {
                    results.insert(
                        policy.id.clone(),
                        result(
                            &policy.id,
                            PolicyResultStatus::Failed,
                            Some("schedule_expired"),
                            Some("the Collector schedule window has expired"),
                        ),
                    );
                    None
                }
                ScheduleState::ClockInvalid => {
                    results.insert(
                        policy.id.clone(),
                        result(
                            &policy.id,
                            PolicyResultStatus::Failed,
                            Some("clock_invalid"),
                            Some("system time is not a plausible Unix epoch"),
                        ),
                    );
                    None
                }
                ScheduleState::Inactive => {
                    results.insert(
                        policy.id.clone(),
                        result(&policy.id, PolicyResultStatus::Applied, None, None),
                    );
                    None
                }
                ScheduleState::Active => {
                    results.insert(
                        policy.id.clone(),
                        result(&policy.id, PolicyResultStatus::Applied, None, None),
                    );
                    Some(policy)
                }
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.spec
            .priority
            .cmp(&right.spec.priority)
            .then_with(|| left.id.cmp(&right.id))
    });

    let identities = ClientAddresses::from_neighbors(topology.neighbor_bindings.clone());
    let mut blocked_v4 = BTreeSet::new();
    let mut blocked_v6 = BTreeSet::new();
    let mut client_rates = BTreeMap::<String, ClientRates>::new();
    let mut application_rates = BTreeMap::<(String, String), ClientRates>::new();
    let mut client_addresses = Vec::<(String, IpAddr)>::new();
    let mut policy_clients = BTreeMap::<String, BTreeSet<String>>::new();
    let mut decided_client_rules = BTreeSet::<String>::new();
    let mut resolved = BTreeMap::<String, Result<Vec<IpAddr>, IdentityError>>::new();
    for policy in &candidates {
        let mut resolved_any = false;
        let mut unresolved_any = false;
        for mac in &policy.spec.selectors.clients {
            let normalized = mac.to_ascii_lowercase();
            let addresses = resolved
                .entry(normalized.clone())
                .or_insert_with(|| identities.resolve(&normalized));
            match addresses {
                Ok(addresses) => {
                    resolved_any = true;
                    let apply_client_rule = match policy.spec.action.kind {
                        PolicyActionKind::Block | PolicyActionKind::Allow => {
                            decided_client_rules.insert(normalized.clone())
                        }
                        PolicyActionKind::Limit => true,
                    };
                    policy_clients
                        .entry(policy.id.clone())
                        .or_default()
                        .insert(normalized.clone());
                    for address in addresses {
                        client_addresses.push((normalized.clone(), *address));
                        if apply_client_rule && policy.spec.action.kind == PolicyActionKind::Block {
                            match address {
                                IpAddr::V4(address)
                                    if !address.is_unspecified()
                                        && !address.is_loopback()
                                        && !address.is_multicast()
                                        && !address.is_link_local() =>
                                {
                                    blocked_v4.insert(*address);
                                }
                                IpAddr::V6(address)
                                    if !address.is_unspecified()
                                        && !address.is_loopback()
                                        && !address.is_multicast()
                                        && !address.is_unicast_link_local() =>
                                {
                                    if topology.ipv6_coverage {
                                        blocked_v6.insert(*address);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if policy.spec.action.kind == PolicyActionKind::Limit {
                        let rates = if is_application_policy(policy) {
                            application_rates
                                .entry((policy.id.clone(), normalized))
                                .or_default()
                        } else {
                            client_rates.entry(normalized).or_default()
                        };
                        rates.add_limit(
                            policy.spec.action.upload_bps,
                            policy.spec.action.download_bps,
                        );
                    }
                }
                Err(error) => {
                    unresolved_any = true;
                    let current = results.entry(policy.id.clone()).or_insert_with(|| {
                        result(&policy.id, PolicyResultStatus::Failed, None, None)
                    });
                    current.status = if policy.spec.action.kind == PolicyActionKind::Limit {
                        PolicyResultStatus::Degraded
                    } else {
                        PolicyResultStatus::Failed
                    };
                    current.reason_code =
                        Some(if policy.spec.action.kind == PolicyActionKind::Limit {
                            "identity_partial".to_owned()
                        } else {
                            error.reason_code().to_owned()
                        });
                    current.message = Some(match error {
                        IdentityError::Unresolved => {
                            format!("no current LAN neighbor address was found for {normalized}")
                        }
                        IdentityError::Conflict => format!(
                            "current LAN neighbor data maps an address to multiple MACs for {normalized}"
                        ),
                    });
                }
            }
        }
        if policy.spec.action.kind == PolicyActionKind::Limit && unresolved_any && resolved_any {
            let current = results
                .get_mut(&policy.id)
                .expect("identity gap inserted result");
            current.status = PolicyResultStatus::Degraded;
            current.reason_code = Some("identity_partial".to_owned());
            current.message = Some(
                "some selected clients have no unambiguous current LAN identity; known clients remain shaped"
                    .to_owned(),
            );
        }
    }
    client_addresses.sort();
    client_addresses.dedup();
    for policy in policies
        .iter()
        .filter(|policy| policy.spec.action.kind == PolicyActionKind::Limit)
    {
        if let Some(entry) = results.get_mut(&policy.id) {
            if entry.status == PolicyResultStatus::Applied
                && topology.capabilities.client_limit == PolicyCapability::Degraded
            {
                entry.status = PolicyResultStatus::Degraded;
                entry.reason_code = topology
                    .client_limit_reason_code
                    .clone()
                    .or_else(|| Some("ipv6_unavailable".to_owned()));
                entry.message = topology.client_limit_reason.clone().or_else(|| {
                    Some("rate limiting has partial address-family coverage".to_owned())
                });
            }
        }
    }
    let mut results = policies
        .iter()
        .filter_map(|policy| results.remove(&policy.id))
        .collect::<Vec<_>>();
    if topology.capabilities.client_block == PolicyCapability::Degraded
        || topology.capabilities.application_block == PolicyCapability::Degraded
    {
        for policy in policies.iter().filter(|policy| {
            policy.spec.action.kind != PolicyActionKind::Limit
                && ((is_supported_client_policy(policy)
                    && topology.capabilities.client_block == PolicyCapability::Degraded)
                    || (is_application_policy(policy)
                        && topology.capabilities.application_block == PolicyCapability::Degraded))
        }) {
            if let Some(entry) = results
                .iter_mut()
                .find(|entry| entry.policy_id == policy.id)
            {
                if entry.status == PolicyResultStatus::Applied {
                    entry.status = PolicyResultStatus::Degraded;
                    entry.reason_code = topology.reason_code.clone();
                    entry.message = topology.reason.clone();
                }
            }
        }
    }
    for policy in policies
        .iter()
        .filter(|policy| policy.spec.action.kind == PolicyActionKind::Limit)
    {
        if let Some(entry) = results
            .iter_mut()
            .find(|entry| entry.policy_id == policy.id)
        {
            let selected = policy_clients.get(&policy.id).cloned().unwrap_or_default();
            let clients = selected
                .iter()
                .filter_map(|mac| {
                    if is_application_policy(policy) {
                        let rates = application_rates.get(&(policy.id.clone(), mac.clone()))?;
                        Some(PolicyClientRate {
                            mac: mac.clone(),
                            effective_upload_bps: rates.upload_bps.map(|rate| {
                                rate.min(
                                    client_rates
                                        .get(mac)
                                        .and_then(|parent| parent.upload_bps)
                                        .unwrap_or_else(|| {
                                            topology.wan_capacity_bps.unwrap_or(rate)
                                        }),
                                )
                            }),
                            effective_download_bps: rates.download_bps.map(|rate| {
                                rate.min(
                                    client_rates
                                        .get(mac)
                                        .and_then(|parent| parent.download_bps)
                                        .unwrap_or_else(|| {
                                            topology.lan_capacity_bps.unwrap_or(rate)
                                        }),
                                )
                            }),
                        })
                    } else {
                        let rates = client_rates.get(mac)?;
                        Some(PolicyClientRate {
                            mac: mac.clone(),
                            effective_upload_bps: rates.upload_bps,
                            effective_download_bps: rates.download_bps,
                        })
                    }
                })
                .collect::<Vec<_>>();
            let mut interfaces = BTreeSet::new();
            if clients
                .iter()
                .any(|client| client.effective_upload_bps.is_some())
                && let Some(interface) = topology.wan_interfaces.first()
            {
                interfaces.insert(interface.clone());
            }
            if clients
                .iter()
                .any(|client| client.effective_download_bps.is_some())
                && let Some(interface) = topology.lan_interfaces.first()
            {
                interfaces.insert(interface.clone());
            }
            entry.details = Some(PolicyResultDetails {
                clients,
                controlled_interfaces: interfaces.into_iter().collect(),
                qdisc: (!selected.is_empty()).then(|| "HTB + fq_codel".to_owned()),
                mark_conflict_code: None,
            });
        }
    }
    let any_applied = !blocked_v4.is_empty()
        || !blocked_v6.is_empty()
        || results.iter().any(|result| {
            matches!(
                result.status,
                PolicyResultStatus::Applied | PolicyResultStatus::Degraded
            )
        });
    let any_failed = results
        .iter()
        .any(|result| result.status == PolicyResultStatus::Failed);
    let any_unsupported = results
        .iter()
        .any(|result| result.status == PolicyResultStatus::Unsupported);
    let any_degraded = results
        .iter()
        .any(|result| result.status == PolicyResultStatus::Degraded);
    let ack_status = if any_unsupported {
        if any_applied || any_failed {
            PolicyAckStatus::Partial
        } else {
            PolicyAckStatus::Unsupported
        }
    } else if any_failed {
        if any_applied {
            PolicyAckStatus::Partial
        } else {
            PolicyAckStatus::Failed
        }
    } else if any_degraded {
        PolicyAckStatus::Partial
    } else {
        PolicyAckStatus::Applied
    };
    let has_supported_policy = results.iter().any(|entry| {
        matches!(
            entry.status,
            PolicyResultStatus::Applied | PolicyResultStatus::Degraded
        )
    });
    BuiltPlan {
        blocked_v4,
        blocked_v6,
        results,
        ack_status,
        has_supported_policy,
        client_rates,
        application_rates,
        client_addresses,
        mark_rules: Vec::new(),
        shaping_state: None,
    }
}

fn build_shaping_state(
    gateway_id: &str,
    topology: &PolicyTopology,
    client_rates: &BTreeMap<String, ClientRates>,
    application_rates: &BTreeMap<(String, String), ClientRates>,
    previous: Option<&ShapingState>,
) -> Result<ShapingState, String> {
    if client_rates.is_empty() && application_rates.is_empty() {
        return Ok(ShapingState::empty());
    }
    let (
        Some(lan),
        Some(wan),
        Some(lan_ifindex),
        Some(wan_ifindex),
        Some(lan_capacity),
        Some(wan_capacity),
    ) = (
        topology.lan_interfaces.first(),
        topology.wan_interfaces.first(),
        topology.lan_ifindex,
        topology.wan_ifindex,
        topology.lan_capacity_bps,
        topology.wan_capacity_bps,
    )
    else {
        return Err(
            "unsupported_multi_egress: verified LAN/WAN interface metadata is incomplete"
                .to_owned(),
        );
    };
    if topology.is_one_arm_router() {
        if lan_ifindex != wan_ifindex || lan_capacity != wan_capacity {
            return Err(
                "shared egress requires one consistent physical interface identity and capacity"
                    .to_owned(),
            );
        }
        let prior = previous.and_then(|state| state.shared_egress.as_ref());
        let mut clients = Vec::new();
        let mut applications = Vec::new();
        for direction in [Direction::Upload, Direction::Download] {
            let directional_rate = |rates: &ClientRates| match direction {
                Direction::Upload => rates.upload_bps,
                Direction::Download => rates.download_bps,
            };
            let mut rates = client_rates
                .iter()
                .filter_map(|(mac, rates)| {
                    let rate = match direction {
                        Direction::Upload => rates.upload_bps,
                        Direction::Download => rates.download_bps,
                    }?;
                    Some((mac.clone(), rate))
                })
                .collect::<BTreeMap<_, _>>();
            let mut app_rates = BTreeMap::new();
            for ((policy, mac), limits) in application_rates {
                if let Some(rate) = directional_rate(limits) {
                    let parent = *rates.entry(mac.clone()).or_insert(lan_capacity);
                    app_rates.insert((policy.clone(), mac.clone()), rate.min(parent));
                }
            }
            if rates.values().any(|rate| *rate > lan_capacity) {
                return Err(
                    "invalid_client_rate: shared client ceiling exceeds interface capacity"
                        .to_owned(),
                );
            }
            let mut directional_clients = shaper::allocate_shared_client_classes(
                gateway_id,
                direction,
                lan,
                lan_ifindex,
                &rates,
                prior.map_or(&[][..], |interface| interface.clients.as_slice()),
            )?;
            for client in &mut directional_clients {
                client.has_total_budget = client_rates
                    .get(&client.mac)
                    .and_then(directional_rate)
                    .is_some();
            }
            let mut reserved = applications
                .iter()
                .map(|app: &shaper::ApplicationClass| app.class_minor)
                .collect::<std::collections::BTreeSet<_>>();
            if let Some(prior) = prior {
                reserved.extend(
                    prior
                        .application_classes
                        .iter()
                        .filter(|app| {
                            app.direction != direction
                                && application_rates
                                    .get(&(app.policy_id.clone(), app.mac.clone()))
                                    .is_some_and(|limits| {
                                        match app.direction {
                                            Direction::Upload => limits.upload_bps,
                                            Direction::Download => limits.download_bps,
                                        }
                                        .is_some()
                                    })
                                && !applications
                                    .iter()
                                    .any(|allocated| allocated.class_minor == app.class_minor)
                        })
                        .map(|app| app.class_minor),
                );
            }
            applications.extend(shaper::allocate_application_classes_reserved(
                gateway_id,
                direction,
                lan,
                lan_ifindex,
                &app_rates,
                &directional_clients,
                prior.map_or(&[][..], |interface| {
                    interface.application_classes.as_slice()
                }),
                &reserved,
            )?);
            clients.extend(directional_clients);
        }
        let state = ShapingState {
            schema_version: 2,
            upload_interface: None,
            download_interface: None,
            shared_egress: Some(ManagedInterface {
                shared_egress: true,
                name: lan.clone(),
                ifindex: lan_ifindex,
                capacity_bps: lan_capacity,
                original_root_kind: String::new(),
                clients,
                application_classes: applications,
            }),
        };
        state.validate()?;
        return Ok(state);
    }
    let upload = build_managed_interface(
        gateway_id,
        Direction::Upload,
        wan,
        wan_ifindex,
        wan_capacity,
        client_rates,
        application_rates,
        previous.and_then(|state| state.upload_interface.as_ref()),
    )?;
    let download = build_managed_interface(
        gateway_id,
        Direction::Download,
        lan,
        lan_ifindex,
        lan_capacity,
        client_rates,
        application_rates,
        previous.and_then(|state| state.download_interface.as_ref()),
    )?;
    Ok(ShapingState {
        shared_egress: None,
        schema_version: 1,
        upload_interface: upload,
        download_interface: download,
    })
}

fn build_managed_interface(
    gateway_id: &str,
    direction: Direction,
    interface_name: &str,
    ifindex: u32,
    capacity_bps: u64,
    client_rates: &BTreeMap<String, ClientRates>,
    application_rates: &BTreeMap<(String, String), ClientRates>,
    previous: Option<&ManagedInterface>,
) -> Result<Option<ManagedInterface>, String> {
    let client_rate = |rates: &ClientRates| match direction {
        Direction::Upload => rates.upload_bps,
        Direction::Download => rates.download_bps,
    };
    let mut parent_rates = client_rates
        .iter()
        .filter_map(|(mac, rates)| client_rate(rates).map(|rate| (mac.clone(), rate)))
        .collect::<BTreeMap<_, _>>();
    let mut policy_rates = BTreeMap::<(String, String), u64>::new();
    for ((policy_id, mac), rates) in application_rates {
        if let Some(rate) = client_rate(rates) {
            parent_rates.entry(mac.clone()).or_insert(capacity_bps);
            policy_rates.insert((policy_id.clone(), mac.clone()), rate);
        }
    }
    if parent_rates.is_empty() {
        return Ok(None);
    }
    let mut clients = shaper::allocate_classes(
        gateway_id,
        direction,
        interface_name,
        ifindex,
        &parent_rates,
        previous.map_or(&[][..], |interface| interface.clients.as_slice()),
    )?;
    for client in &mut clients {
        client.has_total_budget = client_rates
            .get(&client.mac)
            .and_then(client_rate)
            .is_some();
    }
    for ((_, mac), rate) in &mut policy_rates {
        if let Some(parent) = clients.iter().find(|client| client.mac == *mac) {
            *rate = (*rate).min(parent.rate_bps);
        }
    }
    let application_classes = shaper::allocate_application_classes(
        gateway_id,
        direction,
        interface_name,
        ifindex,
        &policy_rates,
        &clients,
        previous.map_or(&[][..], |interface| {
            interface.application_classes.as_slice()
        }),
    )?;
    Ok(Some(ManagedInterface {
        shared_egress: false,
        name: interface_name.to_owned(),
        ifindex,
        capacity_bps,
        original_root_kind: String::new(),
        clients,
        application_classes,
    }))
}

fn compile_shaping_plan(
    gateway_id: &str,
    topology: &PolicyTopology,
    previous: Option<&ShapingState>,
    plan: &mut BuiltPlan,
) -> Result<(), String> {
    let state = build_shaping_state(
        gateway_id,
        topology,
        &plan.client_rates,
        &plan.application_rates,
        previous,
    )?;
    if state.is_empty() {
        return Ok(());
    }
    let upload = state
        .upload_interface
        .as_ref()
        .map_or(&[][..], |interface| interface.clients.as_slice());
    let download = state
        .download_interface
        .as_ref()
        .map_or(&[][..], |interface| interface.clients.as_slice());
    let Some(lan) = topology.lan_interfaces.first() else {
        return Err("unsupported_multi_egress: no verified LAN interface is available".to_owned());
    };
    let Some(wan) = topology.wan_interfaces.first() else {
        return Err("unsupported_multi_egress: no verified WAN interface is available".to_owned());
    };
    plan.mark_rules = mark::rules_for_clients(upload, download, &plan.client_addresses, lan, wan);
    if let Some(shared) = &state.shared_egress {
        let upload = shared
            .clients
            .iter()
            .filter(|client| client.direction == Direction::Upload)
            .cloned()
            .collect::<Vec<_>>();
        let download = shared
            .clients
            .iter()
            .filter(|client| client.direction == Direction::Download)
            .cloned()
            .collect::<Vec<_>>();
        plan.mark_rules =
            mark::rules_for_clients(&upload, &download, &plan.client_addresses, lan, wan);
    }
    plan.shaping_state = Some(state);
    Ok(())
}

fn unsupported_topology_results(
    policies: &[PolicySnapshotEntry],
    topology: &PolicyTopology,
) -> Vec<PolicyResult> {
    policies
        .iter()
        .map(|policy| {
            if !policy.spec.enabled {
                result(&policy.id, PolicyResultStatus::Disabled, None, None)
            } else if is_supported_client_policy(policy)
                || (is_application_policy(policy)
                    && policy.spec.action.kind == PolicyActionKind::Limit
                    && !policy.spec.selectors.clients.is_empty()
                    && topology.capabilities.application_limit != PolicyCapability::Unsupported)
            {
                let (code, message) = if policy.spec.action.kind == PolicyActionKind::Limit {
                    (
                        "unsupported_topology".to_owned(),
                        topology.client_limit_reason.clone().unwrap_or_else(|| {
                            "aggregate shaping topology is not verified".to_owned()
                        }),
                    )
                } else {
                    (
                        topology
                            .reason_code
                            .clone()
                            .unwrap_or_else(|| "unsupported_topology".to_owned()),
                        topology.reason.clone().unwrap_or_else(|| {
                            "client enforcement topology is not verified".to_owned()
                        }),
                    )
                };
                result(
                    &policy.id,
                    PolicyResultStatus::Unsupported,
                    Some(&code),
                    Some(&message),
                )
            } else {
                let (code, message) = unsupported_reason(policy, topology);
                result(
                    &policy.id,
                    PolicyResultStatus::Unsupported,
                    Some(&code),
                    Some(&message),
                )
            }
        })
        .collect()
}

fn is_supported_client_policy(policy: &PolicySnapshotEntry) -> bool {
    policy.spec.enabled && is_client_policy_shape(policy)
}

fn is_client_policy_shape(policy: &PolicySnapshotEntry) -> bool {
    !policy.spec.selectors.clients.is_empty()
        && policy.spec.selectors.applications.is_empty()
        && policy.spec.selectors.categories.is_empty()
        && matches!(
            policy.spec.action.kind,
            PolicyActionKind::Block | PolicyActionKind::Allow | PolicyActionKind::Limit
        )
        && policy.spec.network.scope == "internet"
        && policy.spec.network.direction == "both"
}

fn is_application_policy(policy: &PolicySnapshotEntry) -> bool {
    !policy.spec.selectors.applications.is_empty() || !policy.spec.selectors.categories.is_empty()
}

fn unsupported_reason(policy: &PolicySnapshotEntry, topology: &PolicyTopology) -> (String, String) {
    if is_application_policy(policy) && policy.spec.action.kind == PolicyActionKind::Limit {
        if policy.spec.selectors.clients.is_empty() {
            return (
                "unsupported_global_app_limit".to_owned(),
                "global application bandwidth pools are not supported".to_owned(),
            );
        }
        return (
            "unsupported_application_shaping".to_owned(),
            "aggregate application shaping requires verified child classes and egress marks"
                .to_owned(),
        );
    }
    if is_application_policy(policy)
        && topology.capabilities.application_block == PolicyCapability::Unsupported
    {
        return (
            topology
                .reason_code
                .clone()
                .unwrap_or_else(|| "unsupported_bpf_verifier".to_owned()),
            topology.reason.clone().unwrap_or_else(|| {
                "exact application flow verdicts require a verified BPF writer and TC hooks"
                    .to_owned()
            }),
        );
    }
    if policy.spec.action.kind == PolicyActionKind::Limit {
        (
            topology
                .client_limit_reason_code
                .clone()
                .unwrap_or_else(|| "unsupported_kernel_feature".to_owned()),
            topology.client_limit_reason.clone().unwrap_or_else(|| {
                "client aggregate shaping is unavailable on this topology".to_owned()
            }),
        )
    } else {
        (
            "unsupported_policy_shape".to_owned(),
            "policy does not match the supported client Internet block/allow/limit shape"
                .to_owned(),
        )
    }
}

fn snapshot_parts(
    snapshot: &PolicyWireFrame,
) -> Option<(
    &[PolicySnapshotEntry],
    &[netqmon_protocol::policy::PolicyScheduleIntervals],
    i64,
)> {
    match snapshot {
        PolicyWireFrame::PolicySnapshot {
            policies,
            schedule_intervals,
            valid_until_ms,
            ..
        } => Some((policies, schedule_intervals, *valid_until_ms)),
        _ => None,
    }
}

fn snapshot_results(
    snapshot: &PolicyWireFrame,
    status: PolicyResultStatus,
    error: Option<(&str, &str)>,
) -> Vec<PolicyResult> {
    snapshot_parts(snapshot).map_or_else(Vec::new, |(policies, _, _)| {
        policies
            .iter()
            .map(|policy| {
                if !policy.spec.enabled && error.is_none() {
                    result(&policy.id, PolicyResultStatus::Disabled, None, None)
                } else {
                    result(
                        &policy.id,
                        status,
                        error.map(|(code, _)| code),
                        error.map(|(_, message)| message),
                    )
                }
            })
            .collect()
    })
}

fn policy_ack(
    snapshot: &PolicyWireFrame,
    boot_id: &str,
    capabilities: PolicyCapabilities,
    status: PolicyAckStatus,
    results: Vec<PolicyResult>,
) -> PolicyWireFrame {
    let (gateway_id, controller_epoch, config_revision, bundle_generation, checksum) =
        snapshot.snapshot_identity().unwrap_or((
            "invalid",
            "00000000-0000-4000-8000-000000000000",
            0,
            0,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ));
    PolicyWireFrame::PolicyAck {
        wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
        gateway_id: gateway_id.to_owned(),
        boot_id: boot_id.to_owned(),
        controller_epoch: controller_epoch.to_owned(),
        config_revision,
        bundle_generation,
        checksum: checksum.to_owned(),
        status,
        capabilities,
        results,
        reported_at_ms: now_ms().unwrap_or(0).max(0),
    }
}

pub(crate) fn priority_policy_ack(
    snapshot: &PolicyWireFrame,
    boot_id: &str,
    capabilities: PolicyCapabilities,
    status: PolicyAckStatus,
    results: Vec<PolicyResult>,
) -> PolicyWireFrame {
    policy_ack(snapshot, boot_id, capabilities, status, results)
}

pub(crate) fn priority_failure_ack(
    snapshot: &PolicyWireFrame,
    boot_id: &str,
    message: &str,
) -> PolicyWireFrame {
    policy_ack(
        snapshot,
        boot_id,
        PolicyCapabilities {
            client_block: PolicyCapability::Unsupported,
            client_limit: PolicyCapability::Unsupported,
            application_block: PolicyCapability::Unsupported,
            application_limit: PolicyCapability::Unsupported,
        },
        PolicyAckStatus::Failed,
        snapshot_results(
            snapshot,
            PolicyResultStatus::Failed,
            Some((
                message
                    .split_once(": ")
                    .map_or("priority_backend_failed", |(code, _)| code),
                message,
            )),
        ),
    )
}

fn failure_ack(
    snapshot: &PolicyWireFrame,
    boot_id: &str,
    capabilities: &PolicyCapabilities,
    code: &str,
    message: &str,
    status: PolicyAckStatus,
) -> PolicyWireFrame {
    policy_ack(
        snapshot,
        boot_id,
        capabilities.clone(),
        status,
        snapshot_results(snapshot, PolicyResultStatus::Failed, Some((code, message))),
    )
}

fn result(
    policy_id: &str,
    status: PolicyResultStatus,
    reason_code: Option<&str>,
    message: Option<&str>,
) -> PolicyResult {
    PolicyResult {
        policy_id: policy_id.to_owned(),
        status,
        reason_code: reason_code
            .filter(|value| {
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned),
        message: message.map(sanitize_result_message),
        details: None,
    }
}

fn sanitize_result_message(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len().min(512));
    for character in message.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() > 512 {
            break;
        }
        sanitized.push(character);
    }
    sanitized.trim().to_owned()
}

fn now_ms() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

fn topology_fingerprint(topology: &PolicyTopology) -> String {
    let bytes = serde_json::to_vec(&(
        // Force reconciliation after upgrades that change the owned rules,
        // even when the saved snapshot and network topology are unchanged.
        super::nft::RULESET_VERSION,
        &topology.lan_interfaces,
        &topology.wan_interfaces,
        &topology.internal_networks,
        topology.ipv6_coverage,
    ))
    .expect("policy topology fields serialize");
    let digest = Sha256::digest(bytes);
    let mut fingerprint = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(fingerprint, "{byte:02x}");
    }
    fingerprint
}

fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use netqmon_protocol::policy::{
        PolicyAckStatus, PolicyCapabilities, PolicyCapability, PolicyWireFrame,
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn priority_runtime_uses_one_flow_readiness_source_for_ack_and_health() {
        let supported = priority_runtime_capabilities(true, PolicyCapability::Supported);
        let unsupported = priority_runtime_capabilities(false, PolicyCapability::Degraded);

        assert_eq!(supported.application_block, PolicyCapability::Supported);
        assert_eq!(supported.application_limit, PolicyCapability::Supported);
        assert_eq!(supported.client_limit, PolicyCapability::Supported);
        assert_eq!(unsupported.application_block, PolicyCapability::Unsupported);
        assert_eq!(unsupported.application_limit, PolicyCapability::Unsupported);
        assert_eq!(unsupported.client_block, PolicyCapability::Degraded);
    }

    #[test]
    fn application_block_metrics_reuse_per_client_policy_metrics() {
        let metric = policy_block_metric(
            "application-block-1",
            "AA:BB:CC:DD:EE:FF".to_owned(),
            12,
            4096,
        );
        assert_eq!(metric.policy_id, "application-block-1");
        assert_eq!(metric.mac, "AA:BB:CC:DD:EE:FF");
        let blocked = metric.upload.unwrap();
        assert_eq!(blocked.interface, "policy-block");
        assert_eq!(blocked.packets, Some(12));
        assert_eq!(blocked.bytes, Some(4096));
        assert_eq!(blocked.drops, Some(12));
        assert_eq!(blocked.overlimits, None);
        assert!(metric.download.is_none());

        let metric = policy_block_metric(
            "application-block-1",
            "AA:BB:CC:DD:EE:FF".to_owned(),
            u64::MAX,
            u64::MAX,
        );
        let blocked = metric.upload.unwrap();
        assert_eq!(blocked.packets, None);
        assert_eq!(blocked.bytes, None);
        assert_eq!(blocked.drops, None);
    }

    #[test]
    fn nft_failure_message_is_wire_safe_and_keeps_diagnostic_context() {
        let diagnostic = format!("nft -c failed: {}\n{}", "x".repeat(510), "y".repeat(80));
        let result = result(
            "policy-test",
            PolicyResultStatus::Failed,
            Some("nft_apply_failed"),
            Some(&diagnostic),
        );
        let frame = PolicyWireFrame::PolicyAck {
            wire_version: netqmon_protocol::policy::POLICY_WIRE_VERSION,
            gateway_id: "gateway-test".to_owned(),
            boot_id: "boot-test".to_owned(),
            controller_epoch: "00000000-0000-0000-0000-000000000000".to_owned(),
            config_revision: 1,
            bundle_generation: 1,
            checksum: format!("sha256:{}", "0".repeat(64)),
            status: PolicyAckStatus::Failed,
            capabilities: PolicyCapabilities::unsupported(),
            results: vec![result.clone()],
            reported_at_ms: 1,
        };

        assert!(frame.validate().is_ok());
        assert_eq!(result.reason_code.as_deref(), Some("nft_apply_failed"));
        assert!(!result.message.as_deref().unwrap().contains('\n'));
        assert!(result.message.as_deref().unwrap().len() <= 512);
    }

    #[test]
    fn failed_cleanup_reports_disabled_policies_as_failed() {
        let acknowledgement = failure_ack(
            &disabled_snapshot(1),
            "boot-test",
            &PolicyCapabilities::unsupported(),
            "nft_apply_failed",
            "injected nft clear failure",
            PolicyAckStatus::Failed,
        );
        match acknowledgement {
            PolicyWireFrame::PolicyAck {
                status, results, ..
            } => {
                assert_eq!(status, PolicyAckStatus::Failed);
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].status, PolicyResultStatus::Failed);
                assert_eq!(results[0].reason_code.as_deref(), Some("nft_apply_failed"));
            }
            _ => panic!("expected policy acknowledgement"),
        }
    }

    #[derive(Default)]
    struct FakeNftRunner {
        installed: Option<NftPlan>,
        replace_calls: usize,
        clear_calls: usize,
        fail_on_replace: Option<usize>,
        mark_conflict: Option<String>,
    }

    impl NftRunner for FakeNftRunner {
        fn clear_owned(&mut self) -> Result<(), String> {
            self.clear_calls += 1;
            self.installed = None;
            Ok(())
        }

        fn is_installed(&mut self) -> Result<bool, String> {
            Ok(self.installed.is_some())
        }

        fn replace(&mut self, _topology: &PolicyTopology, plan: &NftPlan) -> Result<(), String> {
            self.replace_calls += 1;
            if self.fail_on_replace == Some(self.replace_calls) {
                return Err("simulated nft apply failure".to_owned());
            }
            self.installed = Some(plan.clone());
            Ok(())
        }

        fn inspect_mark_conflicts(
            &mut self,
            _topology: &PolicyTopology,
            _owned: Option<&ShapingState>,
        ) -> Result<(), String> {
            self.mark_conflict.clone().map_or(Ok(()), Err)
        }
    }

    fn entry(id: &str, priority: u16, action: &str) -> PolicySnapshotEntry {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "spec": {
                "schema_version": 1,
                "gateway_id": "gw-test",
                "name": id,
                "enabled": true,
                "priority": priority,
                "selectors": {
                    "clients": ["aa:bb:cc:dd:ee:ff"],
                    "applications": [],
                    "categories": [],
                    "min_application_confidence": 0.85
                },
                "network": { "scope": "internet", "direction": "both" },
                "action": { "type": action },
                "schedule": null
            }
        }))
        .unwrap()
    }

    fn topology(neighbor_bindings: Vec<(String, IpAddr)>, ipv6_coverage: bool) -> PolicyTopology {
        PolicyTopology {
            supported: true,
            reason_code: (!ipv6_coverage).then(|| "ipv6_unavailable".to_owned()),
            reason: None,
            capabilities: PolicyCapabilities {
                client_block: if ipv6_coverage {
                    PolicyCapability::Supported
                } else {
                    PolicyCapability::Degraded
                },
                ..PolicyCapabilities::unsupported()
            },
            client_limit_reason_code: Some("unsupported_test_limit".to_owned()),
            client_limit_reason: Some("limit capability is disabled in this fixture".to_owned()),
            lan_interfaces: vec!["br-lan".to_owned()],
            wan_interfaces: vec!["eth0".to_owned()],
            lan_ifindex: Some(1),
            wan_ifindex: Some(2),
            lan_capacity_bps: Some(100_000_000),
            wan_capacity_bps: Some(100_000_000),
            internal_networks: vec!["192.168.1.0/24".to_owned(), "fd00::/64".to_owned()],
            neighbor_bindings,
            ipv6_coverage,
        }
    }

    #[test]
    fn multigig_application_only_plan_uses_detected_capacity_for_implicit_parents() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        for capacity in [2_500_000_000, 10_000_000_000] {
            for one_arm in [false, true] {
                let mut topology = topology(Vec::new(), true);
                topology.lan_capacity_bps = Some(capacity);
                topology.wan_capacity_bps = Some(capacity);
                if one_arm {
                    topology.wan_interfaces = topology.lan_interfaces.clone();
                    topology.wan_ifindex = topology.lan_ifindex;
                }
                let applications = BTreeMap::from([(
                    ("app".to_owned(), mac.clone()),
                    ClientRates {
                        upload_bps: Some(1_000_000),
                        download_bps: Some(1_000_000),
                    },
                )]);
                let state =
                    build_shaping_state("gw", &topology, &BTreeMap::new(), &applications, None)
                        .unwrap();
                state.validate().unwrap();
                for interface in state.interfaces() {
                    assert_eq!(interface.capacity_bps, capacity);
                    assert!(
                        interface
                            .clients
                            .iter()
                            .all(|client| client.rate_bps == capacity && !client.has_total_budget)
                    );
                    assert!(
                        interface
                            .application_classes
                            .iter()
                            .all(|application| application.rate_bps == 1_000_000)
                    );
                }
            }
        }
    }

    #[test]
    fn one_arm_client_plan_has_one_physical_root_and_independent_direction_budgets() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let mut topology = topology(vec![(mac.clone(), "192.168.1.42".parse().unwrap())], true);
        topology.wan_interfaces = topology.lan_interfaces.clone();
        topology.wan_ifindex = topology.lan_ifindex;
        let rates = BTreeMap::from([(
            mac,
            ClientRates {
                upload_bps: Some(5_000_000),
                download_bps: Some(8_000_000),
            },
        )]);
        let state = build_shaping_state("gw", &topology, &rates, &BTreeMap::new(), None).unwrap();
        assert!(state.upload_interface.is_none() && state.download_interface.is_none());
        assert_eq!(state.interfaces().count(), 1);
        assert_eq!(state.schema_version, 2);
        let shared = state.shared_egress.as_ref().unwrap();
        assert_eq!(shared.clients.len(), 2);
        assert_eq!(shared.clients[0].rate_bps, 5_000_000);
        assert_eq!(shared.clients[1].rate_bps, 8_000_000);
        assert_ne!(shared.clients[0].class_minor, shared.clients[1].class_minor);
        assert_ne!(shared.clients[0].tag, shared.clients[1].tag);
        let again =
            build_shaping_state("gw", &topology, &rates, &BTreeMap::new(), Some(&state)).unwrap();
        assert_eq!(again, state);
        assert_eq!(
            topology.capabilities.client_limit,
            PolicyCapability::Unsupported
        );
    }

    #[test]
    fn one_arm_application_block_is_partial_and_does_not_require_shaping() {
        let mut policy = entry("application-block", 10, "block");
        policy.spec.selectors.applications = vec!["app.example".to_owned()];
        let mut topology = topology(Vec::new(), true);
        topology.wan_interfaces = topology.lan_interfaces.clone();
        topology.capabilities.application_block = PolicyCapability::Degraded;
        topology.reason_code = Some("one_arm_return_path_unverified".to_owned());
        topology.reason = Some("only packets traversing the Agent are controlled".to_owned());
        let plan = build_plan(
            std::slice::from_ref(&policy),
            &[],
            1_800_086_400_000,
            Some(1_800_000_000_000),
            &topology,
        );
        assert_eq!(plan.ack_status, PolicyAckStatus::Partial);
        assert_eq!(plan.results[0].status, PolicyResultStatus::Degraded);
        assert_eq!(plan.results[0].reason_code, topology.reason_code);
        assert!(plan.has_supported_policy);
        assert!(plan.shaping_state.is_none());
        assert!(plan.blocked_v4.is_empty());
        assert!(plan.blocked_v6.is_empty());

        topology.capabilities.application_block = PolicyCapability::Unsupported;
        let rejected = build_plan(
            &[policy],
            &[],
            1_800_086_400_000,
            Some(1_800_000_000_000),
            &topology,
        );
        assert_eq!(rejected.ack_status, PolicyAckStatus::Unsupported);
        assert!(!rejected.has_supported_policy);
    }

    #[test]
    fn supported_limits_are_applied_despite_a_degraded_block_capability() {
        let mut policy = entry("client-limit", 10, "limit");
        policy.spec.action.download_bps = Some(5_000_000);
        policy.spec.action.upload_bps = Some(2_000_000);
        let mut topology = topology(
            vec![(
                "aa:bb:cc:dd:ee:ff".to_owned(),
                "192.168.1.42".parse().unwrap(),
            )],
            true,
        );
        topology.capabilities.client_block = PolicyCapability::Degraded;
        topology.capabilities.client_limit = PolicyCapability::Supported;
        let plan = build_plan(
            &[policy],
            &[],
            1_800_086_400_000,
            Some(1_800_000_000_000),
            &topology,
        );
        assert_eq!(plan.results[0].status, PolicyResultStatus::Applied);
        assert_eq!(plan.ack_status, PolicyAckStatus::Applied);
    }

    #[test]
    fn application_limit_compiles_to_a_child_class_with_a_capacity_parent() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let mut policy = entry("application-limit", 10, "limit");
        policy.spec.selectors.applications = vec!["app.example".to_owned()];
        policy.spec.action.upload_bps = Some(8_000_000);
        policy.spec.action.download_bps = Some(4_000_000);
        let mut topology = topology(vec![(mac.clone(), "192.168.1.42".parse().unwrap())], true);
        topology.capabilities.client_limit = PolicyCapability::Supported;
        topology.capabilities.application_limit = PolicyCapability::Supported;

        let mut plan = build_plan(
            &[policy],
            &[],
            1_800_086_400_000,
            Some(1_800_000_000_000),
            &topology,
        );
        assert_eq!(plan.results[0].status, PolicyResultStatus::Applied);
        assert!(plan.has_supported_policy);
        compile_shaping_plan("gw-test", &topology, None, &mut plan).unwrap();

        let shaping = plan.shaping_state.as_ref().unwrap();
        let upload = shaping.upload_interface.as_ref().unwrap();
        let parent = upload
            .clients
            .iter()
            .find(|client| client.mac == mac)
            .unwrap();
        assert!(!parent.has_total_budget);
        assert_eq!(parent.rate_bps, 100_000_000);
        let application = upload.application_classes.first().unwrap();
        assert_eq!(application.policy_id, "application-limit");
        assert_eq!(application.mac, mac);
        assert_eq!(application.rate_bps, 8_000_000);
        assert_eq!(application.parent_class_minor, parent.class_minor);
        assert_eq!(plan.mark_rules.len(), 2);
    }

    #[test]
    fn application_limit_is_clamped_by_the_client_aggregate_budget() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let client_rates = BTreeMap::from([(
            mac.clone(),
            ClientRates {
                upload_bps: Some(5_000_000),
                download_bps: None,
            },
        )]);
        let application_rates = BTreeMap::from([(
            ("application-limit".to_owned(), mac.clone()),
            ClientRates {
                upload_bps: Some(9_000_000),
                download_bps: None,
            },
        )]);
        let interface = build_managed_interface(
            "gw-test",
            Direction::Upload,
            "eth0",
            2,
            100_000_000,
            &client_rates,
            &application_rates,
            None,
        )
        .unwrap()
        .unwrap();
        assert!(interface.clients[0].has_total_budget);
        assert_eq!(interface.clients[0].rate_bps, 5_000_000);
        assert_eq!(interface.application_classes[0].rate_bps, 5_000_000);
    }

    fn executor_context() -> (tempfile::TempDir, AgentConfig, PolicyTopology) {
        let directory = tempdir().unwrap();
        let config = AgentConfig {
            policy_state_path: directory.path().join("policy-state.json"),
            policy_disabled_path: directory.path().join("policy-disabled"),
            ..AgentConfig::default()
        };
        let topology = topology(
            vec![(
                "aa:bb:cc:dd:ee:ff".to_owned(),
                "192.168.1.42".parse().unwrap(),
            )],
            true,
        );
        (directory, config, topology)
    }

    fn snapshot(generation: u64) -> PolicyWireFrame {
        let now = now_ms().unwrap();
        PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            12,
            generation,
            now,
            now + 86_400_000,
            vec![PolicySnapshotEntry {
                id: "00000000-0000-4000-8000-000000000010".to_owned(),
                spec: serde_json::from_value(serde_json::json!({
                    "schema_version": 1,
                    "gateway_id": "gw-test",
                    "name": "Block test client",
                    "description": "",
                    "enabled": true,
                    "priority": 10,
                    "selectors": {
                        "clients": ["AA:BB:CC:DD:EE:FF"],
                        "applications": [],
                        "categories": [],
                        "min_application_confidence": 0.85
                    },
                    "network": { "scope": "internet", "direction": "both" },
                    "action": { "type": "block" },
                    "schedule": null
                }))
                .unwrap(),
            }],
            Vec::new(),
        )
        .unwrap()
    }

    fn disabled_snapshot(generation: u64) -> PolicyWireFrame {
        let now = now_ms().unwrap();
        let mut disabled_policy = entry("00000000-0000-4000-8000-000000000010", 10, "block");
        disabled_policy.spec.selectors.clients = vec!["AA:BB:CC:DD:EE:FF".to_owned()];
        disabled_policy.spec.enabled = false;
        PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            12,
            generation,
            now,
            now + 86_400_000,
            vec![disabled_policy],
            Vec::new(),
        )
        .unwrap()
    }

    fn limit_snapshot(generation: u64) -> PolicyWireFrame {
        let now = now_ms().unwrap();
        PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            12,
            generation,
            now,
            now + 86_400_000,
            vec![PolicySnapshotEntry {
                id: "00000000-0000-4000-8000-000000000010".to_owned(),
                spec: serde_json::from_value(serde_json::json!({
                    "schema_version": 1,
                    "gateway_id": "gw-test",
                    "name": "Limit test client",
                    "description": "",
                    "enabled": true,
                    "priority": 10,
                    "selectors": {
                        "clients": ["AA:BB:CC:DD:EE:FF"],
                        "applications": [],
                        "categories": [],
                        "min_application_confidence": 0.85
                    },
                    "network": { "scope": "internet", "direction": "both" },
                    "action": { "type": "limit", "upload_bps": 5000000, "download_bps": 8000000 },
                    "schedule": null
                }))
                .unwrap(),
            }],
            Vec::new(),
        )
        .unwrap()
    }

    fn limit_snapshot_with_application(generation: u64) -> PolicyWireFrame {
        let PolicyWireFrame::PolicySnapshot {
            gateway_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            mut policies,
            schedule_intervals,
            ..
        } = limit_snapshot(generation)
        else {
            unreachable!()
        };
        policies.push(PolicySnapshotEntry {
            id: "00000000-0000-4000-8000-000000000011".to_owned(),
            spec: serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "gateway_id": "gw-test",
                "name": "Limit test application",
                "description": "",
                "enabled": true,
                "priority": 11,
                "selectors": {
                    "clients": ["AA:BB:CC:DD:EE:FF"],
                    "applications": ["youtube"],
                    "categories": [],
                    "min_application_confidence": 0.85
                },
                "network": { "scope": "internet", "direction": "both" },
                "action": { "type": "limit", "upload_bps": 2000000, "download_bps": 3000000 },
                "schedule": null
            }))
            .unwrap(),
        });
        PolicyWireFrame::snapshot(
            gateway_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            policies,
            schedule_intervals,
        )
        .unwrap()
    }

    fn process_with_fake(
        config: &AgentConfig,
        topology: &PolicyTopology,
        runner: &mut FakeNftRunner,
        frame: &PolicyWireFrame,
    ) -> PolicyWireFrame {
        process_snapshot_with(
            config,
            "gw-test",
            "boot-test",
            frame,
            topology,
            runner,
            state::persist,
        )
    }

    fn ack_status(frame: &PolicyWireFrame) -> PolicyAckStatus {
        match frame {
            PolicyWireFrame::PolicyAck { status, .. } => *status,
            _ => panic!("expected policy acknowledgement"),
        }
    }

    fn failure_code(frame: &PolicyWireFrame) -> Option<&str> {
        match frame {
            PolicyWireFrame::PolicyAck { results, .. } => results
                .iter()
                .find_map(|result| result.reason_code.as_deref()),
            _ => None,
        }
    }

    #[test]
    fn client_rules_follow_priority_and_allow_only_overrides_lower_priority() {
        let allow_first = vec![entry("allow", 10, "allow"), entry("block", 20, "block")];
        let plan = build_plan(
            &allow_first,
            &[],
            1_900_000_000_000,
            Some(1_800_000_000_000),
            &topology(
                vec![(
                    "aa:bb:cc:dd:ee:ff".to_owned(),
                    "192.168.1.42".parse().unwrap(),
                )],
                true,
            ),
        );
        assert!(plan.blocked_v4.is_empty());

        let block_first = vec![entry("block", 10, "block"), entry("allow", 20, "allow")];
        let plan = build_plan(
            &block_first,
            &[],
            1_900_000_000_000,
            Some(1_800_000_000_000),
            &topology(
                vec![(
                    "aa:bb:cc:dd:ee:ff".to_owned(),
                    "192.168.1.42".parse().unwrap(),
                )],
                true,
            ),
        );
        assert_eq!(plan.blocked_v4, ["192.168.1.42".parse().unwrap()].into());
    }

    #[test]
    fn address_reassignment_replaces_the_blocked_ip_and_ipv4_only_is_partial() {
        let policy = vec![entry("block", 10, "block")];
        let first = build_plan(
            &policy,
            &[],
            1_900_000_000_000,
            Some(1_800_000_000_000),
            &topology(
                vec![(
                    "aa:bb:cc:dd:ee:ff".to_owned(),
                    "192.168.1.42".parse().unwrap(),
                )],
                false,
            ),
        );
        let reassigned = build_plan(
            &policy,
            &[],
            1_900_000_000_000,
            Some(1_800_000_000_000),
            &topology(
                vec![(
                    "aa:bb:cc:dd:ee:ff".to_owned(),
                    "192.168.1.43".parse().unwrap(),
                )],
                false,
            ),
        );
        assert_eq!(first.blocked_v4, ["192.168.1.42".parse().unwrap()].into());
        assert_eq!(
            reassigned.blocked_v4,
            ["192.168.1.43".parse().unwrap()].into()
        );
        assert_eq!(reassigned.ack_status, PolicyAckStatus::Partial);
    }

    #[test]
    fn unknown_topology_marks_supported_shapes_unsupported() {
        let policies = vec![entry("block", 10, "block")];
        let topology =
            PolicyTopology::unsupported("unsupported_topology", "no verified forwarding path");
        let results = unsupported_topology_results(&policies, &topology);
        assert!(!topology.supported);
        assert_eq!(results[0].status, PolicyResultStatus::Unsupported);
        assert_eq!(
            results[0].reason_code.as_deref(),
            Some("unsupported_topology")
        );
    }

    #[test]
    fn successful_apply_persists_and_repeated_snapshot_is_idempotent() {
        let (_directory, config, topology) = executor_context();
        let frame = snapshot(1);
        let mut runner = FakeNftRunner::default();

        assert_eq!(
            ack_status(&process_with_fake(&config, &topology, &mut runner, &frame)),
            PolicyAckStatus::Applied
        );
        assert_eq!(runner.replace_calls, 1);
        assert_eq!(
            runner.installed.as_ref().unwrap().blocked_v4,
            vec!["192.168.1.42".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test")
                .unwrap()
                .unwrap()
                .config_revision,
            12
        );

        assert_eq!(
            ack_status(&process_with_fake(&config, &topology, &mut runner, &frame)),
            PolicyAckStatus::Applied
        );
        assert_eq!(
            runner.replace_calls, 1,
            "the installed snapshot should be reused"
        );
    }

    #[test]
    fn upgrade_replaces_legacy_forward_only_rules_for_the_same_snapshot() {
        let (_directory, config, topology) = executor_context();
        let frame = snapshot(1);
        let mut runner = FakeNftRunner::default();
        process_with_fake(&config, &topology, &mut runner, &frame);
        let mut saved = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        let legacy = serde_json::to_vec(&(
            &topology.lan_interfaces,
            &topology.wan_interfaces,
            &topology.internal_networks,
            topology.ipv6_coverage,
        ))
        .unwrap();
        saved.topology_fingerprint = Sha256::digest(legacy)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        state::persist(&config.policy_state_path, &saved).unwrap();

        assert_eq!(
            ack_status(&process_with_fake(&config, &topology, &mut runner, &frame)),
            PolicyAckStatus::Applied
        );
        assert_eq!(
            runner.replace_calls, 2,
            "an upgrade must replace the old forward-only table"
        );
        process_with_fake(&config, &topology, &mut runner, &frame);
        assert_eq!(
            runner.replace_calls, 2,
            "the upgraded table remains idempotent"
        );
    }

    #[test]
    fn failed_nft_apply_restores_the_previous_policy_and_state() {
        let (_directory, config, topology) = executor_context();
        let mut runner = FakeNftRunner::default();
        let previous = snapshot(1);
        assert_eq!(
            ack_status(&process_with_fake(
                &config,
                &topology,
                &mut runner,
                &previous
            )),
            PolicyAckStatus::Applied
        );
        let old_state = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        runner.fail_on_replace = Some(2);

        let acknowledgement = process_with_fake(&config, &topology, &mut runner, &snapshot(2));
        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&acknowledgement), Some("nft_apply_failed"));
        assert_eq!(
            runner.replace_calls, 3,
            "rollback reapplies the saved nft plan"
        );
        assert_eq!(
            runner.installed.unwrap().blocked_v4,
            vec!["192.168.1.42".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(old_state)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root in a private Linux network namespace"]
    fn live_nft_apply_and_clear_failures_preserve_previous_policy() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        if std::env::var_os("NETQMON_LIVE_NFT_ROLLBACK_CHILD").is_none() {
            let directory = tempdir().unwrap();
            let wrapper_dir = directory.path().join("bin");
            std::fs::create_dir_all(&wrapper_dir).unwrap();
            let fail_once = directory.path().join("nft-fail-once");
            let injected = directory.path().join("nft-failure-injected");
            let real_nft = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join("nft"))
                .find(|path| path.is_file())
                .expect("nft must be available before adding the failure shim");
            let wrapper = wrapper_dir.join("nft");
            std::fs::write(
                &wrapper,
                r#"#!/bin/sh
if [ -f "$NETQMON_NFT_FAIL_ONCE" ] \
  && [ "$1" = -f ] && [ "$2" = - ]; then
  rm -f "$NETQMON_NFT_FAIL_ONCE"
  : > "$NETQMON_NFT_FAIL_MARKER"
  echo 'injected nft transaction failure' >&2
  exit 42
fi
exec "$NETQMON_NFT_REAL" "$@"
"#,
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&wrapper).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&wrapper, permissions).unwrap();
            let path = std::env::join_paths(
                std::iter::once(wrapper_dir)
                    .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
            )
            .unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "policy::executor::tests::live_nft_apply_and_clear_failures_preserve_previous_policy",
                    "--ignored",
                    "--nocapture",
                ])
                .env("NETQMON_LIVE_NFT_ROLLBACK_CHILD", "1")
                .env("NETQMON_NFT_FAIL_ONCE", &fail_once)
                .env("NETQMON_NFT_FAIL_MARKER", &injected)
                .env("NETQMON_NFT_REAL", real_nft)
                .env("PATH", path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated nft rollback subprocess failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            println!("{}", String::from_utf8_lossy(&output.stdout));
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            return;
        }

        assert!(nix::unistd::geteuid().is_root(), "test requires root");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to mutate a process in the host network namespace"
        );
        let run = |binary: &str, arguments: &[&str]| {
            let output = Command::new(binary).args(arguments).output().unwrap();
            assert!(
                output.status.success(),
                "{binary} {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };
        run("ip", &["link", "add", "lan0", "type", "dummy"]);
        run("ip", &["link", "add", "wan0", "type", "dummy"]);
        run("ip", &["link", "set", "lan0", "up"]);
        run("ip", &["link", "set", "wan0", "up"]);

        let (_directory, config, mut topology) = executor_context();
        topology.lan_interfaces = vec!["lan0".to_owned()];
        topology.wan_interfaces = vec!["wan0".to_owned()];
        topology.lan_ifindex = Some(nix::net::if_::if_nametoindex("lan0").unwrap());
        topology.wan_ifindex = Some(nix::net::if_::if_nametoindex("wan0").unwrap());
        topology.capabilities.client_limit = PolicyCapability::Supported;
        topology.client_limit_reason_code = None;
        topology.client_limit_reason = None;

        let mut runner = SystemNftRunner;
        assert_eq!(
            ack_status(&process_snapshot_with(
                &config,
                "gw-test",
                "boot-test",
                &snapshot(1),
                &topology,
                &mut runner,
                state::persist,
            )),
            PolicyAckStatus::Applied
        );
        let saved_before = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        let table_before = run("nft", &["list", "table", "inet", "netqmon_policy"]);
        let table_before = String::from_utf8_lossy(&table_before.stdout).into_owned();
        assert!(table_before.contains("192.168.1.42"), "{table_before}");
        std::fs::write(
            std::env::var_os("NETQMON_NFT_FAIL_ONCE").unwrap(),
            b"fail the next nft transaction",
        )
        .unwrap();

        let acknowledgement = process_snapshot_with(
            &config,
            "gw-test",
            "boot-test",
            &limit_snapshot(2),
            &topology,
            &mut runner,
            state::persist,
        );
        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&acknowledgement), Some("nft_apply_failed"));
        assert!(
            std::path::Path::new(&std::env::var_os("NETQMON_NFT_FAIL_MARKER").unwrap()).exists()
        );
        assert!(
            !std::path::Path::new(&std::env::var_os("NETQMON_NFT_FAIL_ONCE").unwrap()).exists()
        );
        let message = match &acknowledgement {
            PolicyWireFrame::PolicyAck { results, .. } => results
                .iter()
                .find_map(|result| result.message.as_deref())
                .unwrap_or_default(),
            _ => unreachable!(),
        };
        assert!(
            message.contains("injected nft transaction failure"),
            "{message}"
        );
        assert!(!message.contains("rollback failed"), "{message}");
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(saved_before.clone())
        );
        let table_after = run("nft", &["list", "table", "inet", "netqmon_policy"]);
        let table_after = String::from_utf8_lossy(&table_after.stdout);
        assert_eq!(table_before, table_after);
        let qdiscs: serde_json::Value =
            serde_json::from_slice(&run("tc", &["-j", "qdisc", "show", "dev", "wan0"]).stdout)
                .unwrap();
        assert!(qdiscs.as_array().unwrap().iter().any(|qdisc| {
            qdisc.get("root").and_then(serde_json::Value::as_bool) == Some(true)
                && qdisc.get("kind").and_then(serde_json::Value::as_str) == Some("noqueue")
        }));
        assert!(
            run("tc", &["class", "show", "dev", "wan0"])
                .stdout
                .is_empty()
        );
        assert!(
            !config
                .policy_state_path
                .with_extension("shaping-journal.json")
                .exists()
        );

        std::fs::write(
            std::env::var_os("NETQMON_NFT_FAIL_ONCE").unwrap(),
            b"fail the nft clear transaction",
        )
        .unwrap();
        let clear_acknowledgement = process_snapshot_with(
            &config,
            "gw-test",
            "boot-test",
            &disabled_snapshot(3),
            &topology,
            &mut runner,
            state::persist,
        );
        assert_eq!(ack_status(&clear_acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(
            failure_code(&clear_acknowledgement),
            Some("nft_apply_failed")
        );
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(saved_before)
        );
        let table_after_clear_failure = run("nft", &["list", "table", "inet", "netqmon_policy"]);
        assert_eq!(
            table_before,
            String::from_utf8_lossy(&table_after_clear_failure.stdout).into_owned()
        );
        assert!(
            std::path::Path::new(&std::env::var_os("NETQMON_NFT_FAIL_MARKER").unwrap()).exists()
        );
        assert!(
            !std::path::Path::new(&std::env::var_os("NETQMON_NFT_FAIL_ONCE").unwrap()).exists()
        );

        nft::clear_owned().unwrap();
        run("ip", &["link", "del", "wan0"]);
        run("ip", &["link", "del", "lan0"]);
        println!(
            "PASS: injected nft apply and clear failures preserved prior nft policy and saved state; qdisc remained noqueue"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root in a private Linux network namespace"]
    fn live_tc_failure_rolls_back_nft_and_partially_applied_qdisc() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        if std::env::var_os("NETQMON_LIVE_TC_ROLLBACK_CHILD").is_none() {
            let real_tc = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join("tc"))
                .find(|path| path.is_file())
                .expect("tc must be available before adding the failure shim");
            for failure_point in [
                "root-qdisc",
                "root-class",
                "client-class",
                "default-class",
                "leaf-qdisc",
                "client-fw-filter",
                "application-class",
                "application-leaf-qdisc",
                "application-fw-filter",
            ] {
                let directory = tempdir().unwrap();
                let wrapper_dir = directory.path().join("bin");
                std::fs::create_dir_all(&wrapper_dir).unwrap();
                let fail_once = directory.path().join("tc-fail-once");
                let injected = directory.path().join("tc-failure-injected");
                std::fs::write(&fail_once, b"inject one tc failure").unwrap();
                let wrapper = wrapper_dir.join("tc");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
if [ -f "$NETQMON_TC_FAIL_ONCE" ]; then
  if [ "$NETQMON_TC_FAIL_POINT" = root-qdisc ] \
    && [ "$1" = qdisc ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = root ]; then
    rm -f "$NETQMON_TC_FAIL_ONCE"
    : > "$NETQMON_TC_FAIL_MARKER"
    echo 'injected failure while replacing the HTB root qdisc' >&2
    exit 42
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = root-class ] \
    && [ "$1" = class ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$6" = 51: ] \
    && [ "$7" = classid ] && [ "$8" = 51:1 ]; then
    rm -f "$NETQMON_TC_FAIL_ONCE"
    : > "$NETQMON_TC_FAIL_MARKER"
    echo 'injected failure after HTB root qdisc setup' >&2
    exit 42
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = client-class ] \
    && [ "$1" = class ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$6" = 51:1 ] \
    && [ "$7" = classid ] && [ "$8" != 51:1 ] && [ "$9" = htb ]; then
    rm -f "$NETQMON_TC_FAIL_ONCE"
    : > "$NETQMON_TC_FAIL_MARKER"
    echo 'injected failure after HTB root class setup' >&2
    exit 42
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = default-class ] \
    && [ "$1" = class ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$7" = classid ]; then
    case "$8" in
      51:[4-6][0-9][0-9])
        rm -f "$NETQMON_TC_FAIL_ONCE"
        : > "$NETQMON_TC_FAIL_MARKER"
        echo 'injected failure after application default class setup' >&2
        exit 42
        ;;
    esac
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = application-class ] \
    && [ "$1" = class ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$6" != 51: ] \
    && [ "$7" = classid ] && [ "$9" = htb ]; then
    case "$8" in
      51:[2-6][0-9][0-9][0-9])
        rm -f "$NETQMON_TC_FAIL_ONCE"
        : > "$NETQMON_TC_FAIL_MARKER"
        echo 'injected failure after client child classes and before application class setup' >&2
        exit 42
        ;;
    esac
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = application-leaf-qdisc ] \
    && [ "$1" = qdisc ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$7" = handle ] \
    && [ "$9" = fq_codel ]; then
    case "$6" in
      51:[2-6][0-9][0-9][0-9])
        rm -f "$NETQMON_TC_FAIL_ONCE"
        : > "$NETQMON_TC_FAIL_MARKER"
        echo 'injected failure after application class setup' >&2
        exit 42
        ;;
    esac
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = application-fw-filter ] \
    && [ "$1" = filter ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$7" = protocol ] \
    && [ "$9" = prio ] && [ "${10}" = 100 ] \
    && [ "${11}" = handle ] && [ "${13}" = fw ]; then
    case "${12}" in
      */0xfe000000)
        rm -f "$NETQMON_TC_FAIL_ONCE"
        : > "$NETQMON_TC_FAIL_MARKER"
        echo 'injected failure after application class and leaf qdisc setup' >&2
        exit 42
        ;;
    esac
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = leaf-qdisc ] \
    && [ "$1" = qdisc ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$7" = handle ] \
    && [ "$9" = fq_codel ]; then
    rm -f "$NETQMON_TC_FAIL_ONCE"
    : > "$NETQMON_TC_FAIL_MARKER"
    echo 'injected failure after HTB root/class setup' >&2
    exit 42
  fi
  if [ "$NETQMON_TC_FAIL_POINT" = client-fw-filter ] \
    && [ "$1" = filter ] && [ "$2" = replace ] \
    && [ "$3" = dev ] && [ "$4" = wan0 ] \
    && [ "$5" = parent ] && [ "$6" = 51: ] \
    && [ "$7" = protocol ] && [ "$8" = all ] \
    && [ "$9" = prio ] && [ "${10}" = 100 ] \
    && [ "${13}" = fw ]; then
    rm -f "$NETQMON_TC_FAIL_ONCE"
    : > "$NETQMON_TC_FAIL_MARKER"
    echo 'injected failure after client HTB class and leaf qdisc setup' >&2
    exit 42
  fi
fi
exec "$NETQMON_TC_REAL" "$@"
"#,
                )
                .unwrap();
                let mut permissions = std::fs::metadata(&wrapper).unwrap().permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(&wrapper, permissions).unwrap();
                let path = std::env::join_paths(
                    std::iter::once(wrapper_dir)
                        .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
                )
                .unwrap();
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "policy::executor::tests::live_tc_failure_rolls_back_nft_and_partially_applied_qdisc",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("NETQMON_LIVE_TC_ROLLBACK_CHILD", "1")
                    .env("NETQMON_TC_FAIL_POINT", failure_point)
                    .env("NETQMON_TC_FAIL_ONCE", &fail_once)
                    .env("NETQMON_TC_FAIL_MARKER", &injected)
                    .env("NETQMON_TC_REAL", &real_tc)
                    .env("PATH", path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "isolated rollback subprocess failed at {failure_point}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                println!("{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            }
            return;
        }

        assert!(nix::unistd::geteuid().is_root(), "test requires root");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to mutate a process in the host network namespace"
        );
        let run = |binary: &str, arguments: &[&str]| {
            let output = Command::new(binary).args(arguments).output().unwrap();
            assert!(
                output.status.success(),
                "{binary} {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };
        run("ip", &["link", "add", "lan0", "type", "dummy"]);
        run("ip", &["link", "add", "wan0", "type", "dummy"]);
        run("ip", &["link", "set", "lan0", "up"]);
        run("ip", &["link", "set", "wan0", "up"]);

        let (_directory, config, mut topology) = executor_context();
        assert!(matches!(
            std::env::var("NETQMON_TC_FAIL_POINT").as_deref(),
            Ok("root-qdisc"
                | "root-class"
                | "client-class"
                | "default-class"
                | "leaf-qdisc"
                | "client-fw-filter"
                | "application-class"
                | "application-leaf-qdisc"
                | "application-fw-filter")
        ));
        topology.lan_interfaces = vec!["lan0".to_owned()];
        topology.wan_interfaces = vec!["wan0".to_owned()];
        topology.lan_ifindex = Some(nix::net::if_::if_nametoindex("lan0").unwrap());
        topology.wan_ifindex = Some(nix::net::if_::if_nametoindex("wan0").unwrap());
        topology.capabilities.client_limit = PolicyCapability::Supported;
        topology.capabilities.application_limit = PolicyCapability::Supported;
        topology.client_limit_reason_code = None;
        topology.client_limit_reason = None;

        let mut runner = SystemNftRunner;
        let previous = snapshot(1);
        assert_eq!(
            ack_status(&process_snapshot_with(
                &config,
                "gw-test",
                "boot-test",
                &previous,
                &topology,
                &mut runner,
                state::persist,
            )),
            PolicyAckStatus::Applied
        );
        let saved_before = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        let table_before = run("nft", &["list", "table", "inet", "netqmon_policy"]);
        assert!(String::from_utf8_lossy(&table_before.stdout).contains("192.168.1.42"));
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test")
                .unwrap()
                .unwrap()
                .shaping_state,
            None
        );

        let acknowledgement = process_snapshot_with(
            &config,
            "gw-test",
            "boot-test",
            &limit_snapshot_with_application(2),
            &topology,
            &mut runner,
            state::persist,
        );
        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&acknowledgement), Some("tc_apply_failed"));
        assert!(
            std::path::Path::new(&std::env::var_os("NETQMON_TC_FAIL_MARKER").unwrap()).exists(),
            "injected {} failure did not match a tc command",
            std::env::var("NETQMON_TC_FAIL_POINT").unwrap()
        );
        assert!(!std::path::Path::new(&std::env::var_os("NETQMON_TC_FAIL_ONCE").unwrap()).exists());
        let message = match &acknowledgement {
            PolicyWireFrame::PolicyAck { results, .. } => results
                .iter()
                .find_map(|result| result.message.as_deref())
                .unwrap_or_default(),
            _ => unreachable!(),
        };
        assert!(!message.contains("rollback failed"), "{message}");
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(saved_before)
        );
        let table_after = run("nft", &["list", "table", "inet", "netqmon_policy"]);
        let table_after = String::from_utf8_lossy(&table_after.stdout);
        assert!(table_after.contains("192.168.1.42"), "{table_after}");
        assert!(!table_after.contains("meta mark"), "{table_after}");
        let qdiscs: serde_json::Value =
            serde_json::from_slice(&run("tc", &["-j", "qdisc", "show", "dev", "wan0"]).stdout)
                .unwrap();
        assert!(qdiscs.as_array().unwrap().iter().any(|qdisc| {
            qdisc.get("root").and_then(serde_json::Value::as_bool) == Some(true)
                && qdisc.get("kind").and_then(serde_json::Value::as_str) == Some("noqueue")
        }));
        assert!(
            run("tc", &["class", "show", "dev", "wan0"])
                .stdout
                .is_empty()
        );
        assert!(
            !config
                .policy_state_path
                .with_extension("shaping-journal.json")
                .exists()
        );

        nft::clear_owned().unwrap();
        run("ip", &["link", "del", "wan0"]);
        run("ip", &["link", "del", "lan0"]);
        println!(
            "PASS: injected live tc failure at {} restored the prior nft policy, noqueue root qdisc, persisted snapshot, and removed the shaping journal",
            std::env::var("NETQMON_TC_FAIL_POINT").unwrap()
        );
    }

    #[test]
    fn failed_persistence_restores_runtime_and_keeps_saved_policy() {
        let (_directory, config, topology) = executor_context();
        let mut runner = FakeNftRunner::default();
        let previous = snapshot(1);
        assert_eq!(
            ack_status(&process_with_fake(
                &config,
                &topology,
                &mut runner,
                &previous
            )),
            PolicyAckStatus::Applied
        );
        let old_state = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        let next = snapshot(2);
        let acknowledgement = process_snapshot_with(
            &config,
            "gw-test",
            "boot-test",
            &next,
            &topology,
            &mut runner,
            |_, _| Err("simulated state persistence failure".to_owned()),
        );

        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&acknowledgement), Some("state_persist_failed"));
        assert_eq!(
            runner.replace_calls, 3,
            "rollback reapplies the saved nft plan"
        );
        assert_eq!(
            runner.installed.unwrap().blocked_v4,
            vec!["192.168.1.42".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(old_state)
        );
    }

    #[test]
    fn client_total_scope_cannot_overwrite_legacy_state_or_remove_working_rules() {
        let (_directory, config, topology) = executor_context();
        let mut runner = FakeNftRunner::default();
        assert_eq!(
            ack_status(&process_with_fake(
                &config,
                &topology,
                &mut runner,
                &snapshot(1)
            )),
            PolicyAckStatus::Applied
        );
        let before = std::fs::read(&config.policy_state_path).unwrap();
        let installed = runner.installed.clone();
        let replace_calls = runner.replace_calls;
        let clear_calls = runner.clear_calls;
        let journal_path = config
            .policy_state_path
            .with_extension("shaping-journal.json");
        std::fs::write(&journal_path, b"untouched legacy recovery journal").unwrap();
        let PolicyWireFrame::PolicySnapshot {
            gateway_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            mut policies,
            schedule_intervals,
            ..
        } = limit_snapshot(2)
        else {
            unreachable!()
        };
        policies[0].spec.network.scope =
            netqmon_protocol::policy::POLICY_CLIENT_TOTAL_SCOPE.to_owned();
        let total = PolicyWireFrame::snapshot(
            gateway_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            policies,
            schedule_intervals,
        )
        .unwrap();
        let ack = process_with_fake(&config, &topology, &mut runner, &total);
        assert_eq!(ack_status(&ack), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&ack), Some("priority_backend_required"));
        assert_eq!(runner.replace_calls, replace_calls);
        assert_eq!(runner.clear_calls, clear_calls);
        assert_eq!(runner.installed, installed);
        assert_eq!(std::fs::read(&config.policy_state_path).unwrap(), before);
        assert_eq!(
            std::fs::read(journal_path).unwrap(),
            b"untouched legacy recovery journal"
        );
    }

    #[test]
    fn mark_preflight_conflict_keeps_the_previous_runtime_and_saved_snapshot() {
        let (_directory, config, mut topology) = executor_context();
        topology.capabilities.client_limit = PolicyCapability::Supported;
        let mut runner = FakeNftRunner::default();
        let previous = snapshot(1);
        assert_eq!(
            ack_status(&process_with_fake(
                &config,
                &topology,
                &mut runner,
                &previous
            )),
            PolicyAckStatus::Applied
        );
        let saved_before = state::load(&config.policy_state_path, "gw-test")
            .unwrap()
            .unwrap();
        let installed_before = runner.installed.clone();
        let replace_calls_before = runner.replace_calls;
        runner.mark_conflict = Some(
            "unsupported_mark_conflict: an existing firewall rule uses packet marks".to_owned(),
        );

        let acknowledgement =
            process_with_fake(&config, &topology, &mut runner, &limit_snapshot(2));

        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(
            failure_code(&acknowledgement),
            Some("unsupported_mark_conflict")
        );
        assert_eq!(runner.replace_calls, replace_calls_before);
        assert_eq!(runner.installed, installed_before);
        assert_eq!(
            state::load(&config.policy_state_path, "gw-test").unwrap(),
            Some(saved_before)
        );
    }

    #[test]
    fn emergency_marker_rejects_remote_snapshot_without_touching_runtime_or_state() {
        let (_directory, config, topology) = executor_context();
        std::fs::write(&config.policy_disabled_path, "emergency disable").unwrap();
        let mut runner = FakeNftRunner::default();

        let acknowledgement = process_with_fake(&config, &topology, &mut runner, &snapshot(1));
        assert_eq!(ack_status(&acknowledgement), PolicyAckStatus::Failed);
        assert_eq!(failure_code(&acknowledgement), Some("emergency_disabled"));
        assert_eq!(runner.replace_calls, 0);
        assert_eq!(runner.clear_calls, 0);
        assert!(runner.installed.is_none());
        assert!(
            state::load(&config.policy_state_path, "gw-test")
                .unwrap()
                .is_none()
        );
    }
}
