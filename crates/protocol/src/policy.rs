//! Policy push wire protocol shared by Collector and Agent.
//!
//! Policy frames are JSON on a dedicated WebSocket and do not change the
//! telemetry protobuf protocol version.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const POLICY_WIRE_VERSION: u32 = 1;
pub const POLICY_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const POLICY_MAX_METRICS_FRAME_BYTES: usize = 256 * 1024;
pub const POLICY_MAX_SNAPSHOT_BYTES: usize = 768 * 1024;
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpecV1 {
    pub schema_version: u32,
    pub gateway_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default)]
    pub selectors: PolicySelectors,
    pub network: PolicyNetworkSelector,
    pub action: PolicyAction,
    #[serde(default)]
    pub schedule: Option<PolicySchedule>,
}

fn default_priority() -> u16 {
    500
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelectors {
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_confidence")]
    pub min_application_confidence: f64,
}

fn default_confidence() -> f64 {
    0.85
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyNetworkSelector {
    pub scope: String,
    pub direction: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyActionKind {
    Block,
    Allow,
    Limit,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAction {
    #[serde(rename = "type")]
    pub kind: PolicyActionKind,
    #[serde(default)]
    pub download_bps: Option<u64>,
    #[serde(default)]
    pub upload_bps: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySchedule {
    pub timezone: String,
    pub windows: Vec<PolicyScheduleWindow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyWeekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl PolicyWeekday {
    #[must_use]
    pub const fn monday_index(self) -> u32 {
        match self {
            Self::Mon => 0,
            Self::Tue => 1,
            Self::Wed => 2,
            Self::Thu => 3,
            Self::Fri => 4,
            Self::Sat => 5,
            Self::Sun => 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScheduleWindow {
    pub days: Vec<PolicyWeekday>,
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotEntry {
    pub id: String,
    pub spec: PolicySpecV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScheduleInterval {
    pub start_ms: i64,
    pub end_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScheduleIntervals {
    pub policy_id: String,
    pub intervals: Vec<PolicyScheduleInterval>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyWireFrame {
    PolicySnapshot {
        wire_version: u32,
        gateway_id: String,
        controller_epoch: String,
        config_revision: u64,
        bundle_generation: u64,
        generated_at_ms: i64,
        valid_until_ms: i64,
        checksum: String,
        policies: Vec<PolicySnapshotEntry>,
        schedule_intervals: Vec<PolicyScheduleIntervals>,
    },
    PolicyAck {
        wire_version: u32,
        gateway_id: String,
        boot_id: String,
        controller_epoch: String,
        config_revision: u64,
        bundle_generation: u64,
        checksum: String,
        status: PolicyAckStatus,
        capabilities: PolicyCapabilities,
        results: Vec<PolicyResult>,
        reported_at_ms: i64,
    },
    PolicyHealth {
        wire_version: u32,
        gateway_id: String,
        boot_id: String,
        last_applied_revision: u64,
        controller_epoch: Option<String>,
        bundle_generation: Option<u64>,
        checksum: Option<String>,
        capabilities: PolicyCapabilities,
        reported_at_ms: i64,
        emergency_disabled: bool,
    },
    PolicyMetrics {
        wire_version: u32,
        gateway_id: String,
        boot_id: String,
        sampled_at_ms: i64,
        metrics: Vec<PolicyClientMetrics>,
    },
    FlowCommand {
        wire_version: u32,
        gateway_id: String,
        boot_id: String,
        controller_epoch: String,
        config_revision: u64,
        command_id: String,
        policy_flow_id: String,
        operation: FlowCommandOperation,
        verdict: Option<FlowVerdict>,
        policy_ids: Vec<String>,
        expires_at_ms: i64,
        issued_at_ms: i64,
    },
    FlowAck {
        wire_version: u32,
        gateway_id: String,
        boot_id: String,
        controller_epoch: String,
        command_id: String,
        policy_flow_id: String,
        config_revision: u64,
        status: FlowAckStatus,
        reason_code: Option<String>,
        alias_count: u32,
        reported_at_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowCommandOperation {
    Upsert,
    Revoke,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowVerdict {
    Block,
    Allow,
    Shape,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowAckStatus {
    Applied,
    Partial,
    Unsupported,
    Failed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyClientMetrics {
    pub policy_id: String,
    pub mac: String,
    pub upload: Option<PolicyDirectionMetrics>,
    pub download: Option<PolicyDirectionMetrics>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDirectionMetrics {
    pub interface: String,
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub drops: Option<u64>,
    pub overlimits: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAckStatus {
    Applied,
    Partial,
    Failed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyResultStatus {
    Applied,
    Degraded,
    Unsupported,
    Failed,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCapability {
    Supported,
    Unsupported,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCapabilities {
    pub client_block: PolicyCapability,
    pub client_limit: PolicyCapability,
    pub application_block: PolicyCapability,
    pub application_limit: PolicyCapability,
}

impl PolicyCapabilities {
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            client_block: PolicyCapability::Unsupported,
            client_limit: PolicyCapability::Unsupported,
            application_block: PolicyCapability::Unsupported,
            application_limit: PolicyCapability::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    pub policy_id: String,
    pub status: PolicyResultStatus,
    pub reason_code: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub details: Option<PolicyResultDetails>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResultDetails {
    #[serde(default)]
    pub clients: Vec<PolicyClientRate>,
    #[serde(default)]
    pub controlled_interfaces: Vec<String>,
    #[serde(default)]
    pub qdisc: Option<String>,
    #[serde(default)]
    pub mark_conflict_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyClientRate {
    pub mac: String,
    pub effective_upload_bps: Option<u64>,
    pub effective_download_bps: Option<u64>,
}

#[derive(Serialize)]
struct SnapshotChecksumPayload<'a> {
    gateway_id: &'a str,
    controller_epoch: &'a str,
    config_revision: u64,
    bundle_generation: u64,
    generated_at_ms: i64,
    valid_until_ms: i64,
    policies: &'a [PolicySnapshotEntry],
    schedule_intervals: &'a [PolicyScheduleIntervals],
}

impl PolicyWireFrame {
    /// Create a deterministically ordered and checksum protected snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the fields are invalid or the canonical payload exceeds its size limit.
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot(
        gateway_id: String,
        controller_epoch: String,
        config_revision: u64,
        bundle_generation: u64,
        generated_at_ms: i64,
        valid_until_ms: i64,
        mut policies: Vec<PolicySnapshotEntry>,
        mut schedule_intervals: Vec<PolicyScheduleIntervals>,
    ) -> Result<Self, String> {
        policies.sort_by(|left, right| left.id.cmp(&right.id));
        schedule_intervals.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        for schedule in &mut schedule_intervals {
            schedule
                .intervals
                .sort_by_key(|interval| (interval.start_ms, interval.end_ms));
        }
        let checksum = checksum_for(
            &gateway_id,
            &controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            &policies,
            &schedule_intervals,
        )?;
        let frame = Self::PolicySnapshot {
            wire_version: POLICY_WIRE_VERSION,
            gateway_id,
            controller_epoch,
            config_revision,
            bundle_generation,
            generated_at_ms,
            valid_until_ms,
            checksum,
            policies,
            schedule_intervals,
        };
        validate_snapshot(&frame)?;
        let encoded = serde_json::to_vec(&frame).map_err(|error| error.to_string())?;
        if encoded.len() > POLICY_MAX_SNAPSHOT_BYTES {
            return Err("policy snapshot exceeds 768 KiB".to_owned());
        }
        Ok(frame)
    }

    /// Validates the wire frame and its payload checksum.
    ///
    /// # Errors
    ///
    /// Returns an error when a field, identity, size, or checksum is invalid.
    // Keep the exhaustive protocol-frame validation in one match so adding a
    // wire variant cannot silently bypass a branch-specific validation path.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::PolicySnapshot { .. } => validate_snapshot(self),
            Self::PolicyAck {
                wire_version,
                gateway_id,
                boot_id,
                controller_epoch,
                config_revision,
                bundle_generation,
                checksum,
                results,
                reported_at_ms,
                ..
            } => {
                if *wire_version != POLICY_WIRE_VERSION {
                    return Err("unsupported policy wire version".to_owned());
                }
                validate_gateway(gateway_id)?;
                validate_nonempty_id(boot_id, "boot_id")?;
                validate_epoch(controller_epoch)?;
                validate_generations(*config_revision, *bundle_generation)?;
                validate_checksum(checksum)?;
                if *reported_at_ms < 0 {
                    return Err("reported_at_ms must be non-negative".to_owned());
                }
                validate_results(results)
            }
            Self::PolicyHealth {
                wire_version,
                gateway_id,
                boot_id,
                controller_epoch,
                bundle_generation,
                checksum,
                last_applied_revision,
                reported_at_ms,
                ..
            } => {
                if *wire_version != POLICY_WIRE_VERSION {
                    return Err("unsupported policy wire version".to_owned());
                }
                validate_gateway(gateway_id)?;
                validate_nonempty_id(boot_id, "boot_id")?;
                if *last_applied_revision > MAX_SAFE_JSON_INTEGER {
                    return Err(
                        "last applied revision is outside the JSON safe integer range".to_owned(),
                    );
                }
                match (controller_epoch, bundle_generation, checksum) {
                    (Some(epoch), Some(generation), Some(checksum)) => {
                        validate_epoch(epoch)?;
                        if *generation == 0 || *generation > MAX_SAFE_JSON_INTEGER {
                            return Err("bundle generation is outside the JSON safe integer range"
                                .to_owned());
                        }
                        validate_checksum(checksum)?;
                    }
                    (None, None, None) if *last_applied_revision == 0 => {}
                    _ => return Err("health snapshot identity fields are incomplete".to_owned()),
                }
                if *reported_at_ms < 0 {
                    return Err("reported_at_ms must be non-negative".to_owned());
                }
                Ok(())
            }
            Self::PolicyMetrics {
                wire_version,
                gateway_id,
                boot_id,
                sampled_at_ms,
                metrics,
            } => {
                if *wire_version != POLICY_WIRE_VERSION {
                    return Err("unsupported policy wire version".to_owned());
                }
                validate_gateway(gateway_id)?;
                validate_nonempty_id(boot_id, "boot_id")?;
                if *sampled_at_ms < 0 {
                    return Err("sampled_at_ms must be non-negative".to_owned());
                }
                validate_policy_metrics(metrics)?;
                let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
                if encoded.len() > POLICY_MAX_METRICS_FRAME_BYTES {
                    return Err("policy metrics frame exceeds 256 KiB".to_owned());
                }
                Ok(())
            }
            Self::FlowCommand {
                wire_version,
                gateway_id,
                boot_id,
                controller_epoch,
                config_revision,
                command_id,
                policy_flow_id,
                operation,
                verdict,
                policy_ids,
                expires_at_ms,
                issued_at_ms,
            } => {
                if *wire_version != POLICY_WIRE_VERSION {
                    return Err("unsupported policy wire version".to_owned());
                }
                validate_gateway(gateway_id)?;
                validate_nonempty_id(boot_id, "boot_id")?;
                validate_epoch(controller_epoch)?;
                if *config_revision > MAX_SAFE_JSON_INTEGER {
                    return Err("config_revision is outside the JSON safe integer range".to_owned());
                }
                validate_nonempty_id(command_id, "command_id")?;
                if policy_flow_id.is_empty()
                    || policy_flow_id.len() > 64
                    || policy_flow_id.chars().any(char::is_control)
                {
                    return Err(
                        "policy_flow_id must contain 1 through 64 non-control characters"
                            .to_owned(),
                    );
                }
                if *issued_at_ms < 0
                    || *expires_at_ms <= *issued_at_ms
                    || expires_at_ms.saturating_sub(*issued_at_ms) > 120_000
                {
                    return Err(
                        "flow command lifetime must be positive and no longer than 120 seconds"
                            .to_owned(),
                    );
                }
                match operation {
                    FlowCommandOperation::Upsert => {
                        if verdict.is_none() || policy_ids.is_empty() || policy_ids.len() > 16 {
                            return Err(
                                "upsert requires a verdict and 1 through 16 policy ids".to_owned()
                            );
                        }
                        for policy_id in policy_ids {
                            validate_nonempty_id(policy_id, "policy_id")?;
                        }
                    }
                    FlowCommandOperation::Revoke => {
                        if verdict.is_some() || !policy_ids.is_empty() {
                            return Err(
                                "revoke must not include a verdict or policy ids".to_owned()
                            );
                        }
                    }
                }
                Ok(())
            }
            Self::FlowAck {
                wire_version,
                gateway_id,
                boot_id,
                controller_epoch,
                command_id,
                policy_flow_id,
                config_revision,
                reason_code,
                reported_at_ms,
                ..
            } => {
                if *wire_version != POLICY_WIRE_VERSION {
                    return Err("unsupported policy wire version".to_owned());
                }
                validate_gateway(gateway_id)?;
                validate_nonempty_id(boot_id, "boot_id")?;
                validate_epoch(controller_epoch)?;
                validate_nonempty_id(command_id, "command_id")?;
                if policy_flow_id.is_empty()
                    || policy_flow_id.len() > 64
                    || policy_flow_id.chars().any(char::is_control)
                {
                    return Err(
                        "policy_flow_id must contain 1 through 64 non-control characters"
                            .to_owned(),
                    );
                }
                if *config_revision > MAX_SAFE_JSON_INTEGER || *reported_at_ms < 0 {
                    return Err("flow acknowledgement identity or timestamp is invalid".to_owned());
                }
                if reason_code.as_ref().is_some_and(|reason| {
                    reason.is_empty() || reason.len() > 128 || reason.chars().any(char::is_control)
                }) {
                    return Err("flow acknowledgement reason_code is invalid".to_owned());
                }
                Ok(())
            }
        }
    }

    /// Encodes this validated frame as bounded JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or the encoded frame exceeds its size limit.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > POLICY_MAX_FRAME_BYTES {
            return Err("policy frame exceeds 1 MiB".to_owned());
        }
        Ok(bytes)
    }

    /// Decodes a bounded JSON frame and validates its protocol fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is oversized, malformed, or invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > POLICY_MAX_FRAME_BYTES {
            return Err("policy frame exceeds 1 MiB".to_owned());
        }
        let frame: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        frame.validate()?;
        Ok(frame)
    }

    #[must_use]
    pub fn snapshot_identity(&self) -> Option<(&str, &str, u64, u64, &str)> {
        match self {
            Self::PolicySnapshot {
                gateway_id,
                controller_epoch,
                config_revision,
                bundle_generation,
                checksum,
                ..
            } => Some((
                gateway_id,
                controller_epoch,
                *config_revision,
                *bundle_generation,
                checksum,
            )),
            _ => None,
        }
    }
}

fn validate_policy_metrics(metrics: &[PolicyClientMetrics]) -> Result<(), String> {
    if metrics.len() > 256 {
        return Err("policy metrics frame contains more than 256 client summaries".to_owned());
    }
    if metrics
        .windows(2)
        .any(|pair| (&pair[0].policy_id, &pair[0].mac) >= (&pair[1].policy_id, &pair[1].mac))
    {
        return Err("policy metrics must be sorted by unique policy and client".to_owned());
    }
    for metric in metrics {
        validate_nonempty_id(&metric.policy_id, "metrics policy id")?;
        if !valid_mac(&metric.mac) {
            return Err("policy metrics contain an invalid client MAC".to_owned());
        }
        if metric.upload.is_none() && metric.download.is_none() {
            return Err("policy metrics must contain at least one traffic direction".to_owned());
        }
        for direction in [&metric.upload, &metric.download].into_iter().flatten() {
            if direction.interface.is_empty()
                || direction.interface.len() > 15
                || direction
                    .interface
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)))
                || [
                    direction.bytes,
                    direction.packets,
                    direction.drops,
                    direction.overlimits,
                ]
                .into_iter()
                .flatten()
                .any(|count| count > MAX_SAFE_JSON_INTEGER)
            {
                return Err("policy metrics contain invalid interface or counter data".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_snapshot(frame: &PolicyWireFrame) -> Result<(), String> {
    let PolicyWireFrame::PolicySnapshot {
        wire_version,
        gateway_id,
        controller_epoch,
        config_revision,
        bundle_generation,
        generated_at_ms,
        valid_until_ms,
        checksum,
        policies,
        schedule_intervals,
    } = frame
    else {
        return Err("expected policy_snapshot frame".to_owned());
    };
    if *wire_version != POLICY_WIRE_VERSION {
        return Err("unsupported policy wire version".to_owned());
    }
    validate_gateway(gateway_id)?;
    validate_epoch(controller_epoch)?;
    validate_generations(*config_revision, *bundle_generation)?;
    validate_checksum(checksum)?;
    if *generated_at_ms < 0 || *valid_until_ms <= *generated_at_ms {
        return Err("snapshot validity timestamps are invalid".to_owned());
    }
    if policies.len() > 256 {
        return Err("snapshot contains more than 256 policies".to_owned());
    }
    if policies.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err("snapshot policies must be sorted by unique policy id".to_owned());
    }
    for policy in policies {
        validate_nonempty_id(&policy.id, "policy id")?;
        validate_policy_spec(gateway_id, &policy.spec)?;
    }
    if schedule_intervals
        .windows(2)
        .any(|pair| pair[0].policy_id >= pair[1].policy_id)
    {
        return Err("schedule intervals must be sorted by unique policy id".to_owned());
    }
    for schedule in schedule_intervals {
        validate_nonempty_id(&schedule.policy_id, "schedule policy id")?;
        if policies
            .iter()
            .all(|policy| policy.id != schedule.policy_id)
        {
            return Err("schedule intervals reference an unknown policy".to_owned());
        }
        if schedule
            .intervals
            .windows(2)
            .any(|pair| (pair[0].start_ms, pair[0].end_ms) >= (pair[1].start_ms, pair[1].end_ms))
            || schedule
                .intervals
                .iter()
                .any(|interval| interval.start_ms >= interval.end_ms)
        {
            return Err("schedule intervals must be sorted, unique, and non-empty".to_owned());
        }
    }
    let expected = checksum_for(
        gateway_id,
        controller_epoch,
        *config_revision,
        *bundle_generation,
        *generated_at_ms,
        *valid_until_ms,
        policies,
        schedule_intervals,
    )?;
    if expected != *checksum {
        return Err("policy snapshot checksum mismatch".to_owned());
    }
    let encoded = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    if encoded.len() > POLICY_MAX_SNAPSHOT_BYTES {
        return Err("policy snapshot exceeds 768 KiB".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn checksum_for(
    gateway_id: &str,
    controller_epoch: &str,
    config_revision: u64,
    bundle_generation: u64,
    generated_at_ms: i64,
    valid_until_ms: i64,
    policies: &[PolicySnapshotEntry],
    schedule_intervals: &[PolicyScheduleIntervals],
) -> Result<String, String> {
    validate_generations(config_revision, bundle_generation)?;
    let payload = SnapshotChecksumPayload {
        gateway_id,
        controller_epoch,
        config_revision,
        bundle_generation,
        generated_at_ms,
        valid_until_ms,
        policies,
        schedule_intervals,
    };
    let canonical = serde_jcs::to_vec(&payload).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(canonical);
    let mut checksum = String::with_capacity(71);
    checksum.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(checksum, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(checksum)
}

fn validate_policy_spec(gateway_id: &str, spec: &PolicySpecV1) -> Result<(), String> {
    if spec.schema_version != 1 || spec.gateway_id != gateway_id {
        return Err("policy spec schema or gateway does not match snapshot".to_owned());
    }
    if spec.name.trim().is_empty() || spec.name.chars().count() > 100 {
        return Err("policy spec name is invalid".to_owned());
    }
    if spec.description.chars().count() > 500 || spec.priority > 1000 {
        return Err("policy spec description or priority is invalid".to_owned());
    }
    if spec.network.scope != "internet" || spec.network.direction != "both" {
        return Err("policy spec uses an unsupported network scope".to_owned());
    }
    if spec.selectors.clients.len() > 32
        || spec.selectors.applications.len() > 32
        || spec.selectors.categories.len() > 16
        || (spec.selectors.clients.is_empty()
            && spec.selectors.applications.is_empty()
            && spec.selectors.categories.is_empty())
    {
        return Err("policy spec selectors are invalid".to_owned());
    }
    if !spec.selectors.min_application_confidence.is_finite()
        || !(0.80..=1.0).contains(&spec.selectors.min_application_confidence)
    {
        return Err("policy application confidence is invalid".to_owned());
    }
    for client in &spec.selectors.clients {
        if !valid_mac(client) {
            return Err("policy contains a non-canonical client MAC".to_owned());
        }
    }
    for (name, values) in [
        ("application", &spec.selectors.applications),
        ("category", &spec.selectors.categories),
    ] {
        if values.iter().any(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) {
            return Err(format!("policy contains an invalid {name} selector"));
        }
    }
    match spec.action.kind {
        PolicyActionKind::Block | PolicyActionKind::Allow => {
            if spec.action.download_bps.is_some() || spec.action.upload_bps.is_some() {
                return Err("block/allow actions cannot contain rate limits".to_owned());
            }
        }
        PolicyActionKind::Limit => {
            if spec.selectors.clients.is_empty()
                || (spec.action.download_bps.is_none() && spec.action.upload_bps.is_none())
                || [spec.action.download_bps, spec.action.upload_bps]
                    .into_iter()
                    .flatten()
                    .any(|rate| !(64_000..=1_000_000_000).contains(&rate))
            {
                return Err("policy limit action is invalid".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_results(results: &[PolicyResult]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(results.len());
    for result in results {
        validate_nonempty_id(&result.policy_id, "result policy id")?;
        if !seen.insert(&result.policy_id) {
            return Err("policy result ids must be unique".to_owned());
        }
        if result.reason_code.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) || result
            .message
            .as_ref()
            .is_some_and(|value| value.len() > 512 || value.chars().any(char::is_control))
        {
            return Err("policy result reason/message is invalid".to_owned());
        }
        if let Some(details) = &result.details {
            if details.clients.len() > 32
                || details.controlled_interfaces.len() > 2
                || details.qdisc.as_ref().is_some_and(|value| {
                    value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
                })
                || details.mark_conflict_code.as_ref().is_some_and(|value| {
                    value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
                })
                || details.controlled_interfaces.iter().any(|value| {
                    value.is_empty() || value.len() > 15 || value.chars().any(char::is_control)
                })
                || details.clients.iter().any(|client| {
                    !valid_mac(&client.mac)
                        || [client.effective_upload_bps, client.effective_download_bps]
                            .into_iter()
                            .flatten()
                            .any(|rate| !(64_000..=1_000_000_000).contains(&rate))
                })
            {
                return Err("policy result details are invalid".to_owned());
            }
        }
    }
    if results.len() > 256 {
        return Err("policy ack contains more than 256 results".to_owned());
    }
    Ok(())
}

fn validate_generations(revision: u64, generation: u64) -> Result<(), String> {
    if revision > MAX_SAFE_JSON_INTEGER || generation == 0 || generation > MAX_SAFE_JSON_INTEGER {
        return Err("revision or generation is outside the JSON safe integer range".to_owned());
    }
    Ok(())
}

fn validate_gateway(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err("gateway_id is invalid".to_owned());
    }
    Ok(())
}

fn validate_nonempty_id(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(format!("{name} is invalid"));
    }
    Ok(())
}

fn validate_epoch(value: &str) -> Result<(), String> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte),
        })
    {
        return Err("controller_epoch must be a lowercase 128-bit UUID".to_owned());
    }
    Ok(())
}

fn validate_checksum(value: &str) -> Result<(), String> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("checksum must be sha256 followed by 64 lowercase hex digits".to_owned());
    }
    Ok(())
}

fn valid_mac(value: &str) -> bool {
    value.len() == 17
        && value.bytes().enumerate().all(|(index, byte)| {
            if index % 3 == 2 {
                byte == b':'
            } else {
                byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PolicySpecV1 {
        PolicySpecV1 {
            schema_version: 1,
            gateway_id: "gw-test".to_owned(),
            name: "Block laptop".to_owned(),
            description: String::new(),
            enabled: true,
            priority: 500,
            selectors: PolicySelectors {
                clients: vec!["AA:BB:CC:DD:EE:FF".to_owned()],
                applications: Vec::new(),
                categories: Vec::new(),
                min_application_confidence: 0.85,
            },
            network: PolicyNetworkSelector {
                scope: "internet".to_owned(),
                direction: "both".to_owned(),
            },
            action: PolicyAction {
                kind: PolicyActionKind::Block,
                download_bps: None,
                upload_bps: None,
            },
            schedule: None,
        }
    }

    fn snapshot(generation: u64, id: &str) -> PolicyWireFrame {
        PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            12,
            generation,
            1_791_600_000_000,
            1_794_192_000_000,
            vec![PolicySnapshotEntry {
                id: id.to_owned(),
                spec: spec(),
            }],
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn snapshot_checksum_has_a_stable_golden_value_and_round_trips() {
        let frame = snapshot(40, "00000000-0000-4000-8000-000000000002");
        let encoded = frame.encode().unwrap();
        let decoded = PolicyWireFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(
            frame.snapshot_identity().unwrap().4,
            "sha256:23d7078ccbf9f171d9e26659d6ad12e367b4d583e260c7d27ad39c62e463c3f7"
        );
    }

    #[test]
    fn snapshot_order_is_canonical_and_checksum_detects_field_mutation() {
        let mut first = match snapshot(40, "b") {
            PolicyWireFrame::PolicySnapshot { policies, .. } => policies,
            _ => unreachable!(),
        };
        first.push(PolicySnapshotEntry {
            id: "a".to_owned(),
            spec: spec(),
        });
        let frame = PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            12,
            40,
            1_791_600_000_000,
            1_794_192_000_000,
            first,
            Vec::new(),
        )
        .unwrap();
        let PolicyWireFrame::PolicySnapshot { policies, .. } = &frame else {
            unreachable!()
        };
        assert_eq!(policies[0].id, "a");
        let mut changed = frame;
        if let PolicyWireFrame::PolicySnapshot {
            generated_at_ms, ..
        } = &mut changed
        {
            *generated_at_ms += 1;
        }
        assert!(changed.validate().unwrap_err().contains("checksum"));
    }

    #[test]
    fn strict_decoder_rejects_unknown_fields_gateway_mismatch_and_bad_generation() {
        let encoded = snapshot(40, "p-1").encode().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(PolicyWireFrame::decode(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut wrong_gateway = match snapshot(40, "p-1") {
            PolicyWireFrame::PolicySnapshot { .. } => snapshot(40, "p-1"),
            _ => unreachable!(),
        };
        if let PolicyWireFrame::PolicySnapshot { policies, .. } = &mut wrong_gateway {
            policies[0].spec.gateway_id = "another".to_owned();
        }
        assert!(wrong_gateway.validate().is_err());

        assert!(
            PolicyWireFrame::snapshot(
                "gw-test".to_owned(),
                "00000000-0000-4000-8000-000000000001".to_owned(),
                12,
                MAX_SAFE_JSON_INTEGER + 1,
                1_791_600_000_000,
                1_794_192_000_000,
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn decoder_rejects_oversize_frames_and_wrong_wire_versions() {
        assert!(PolicyWireFrame::decode(&vec![b' '; POLICY_MAX_FRAME_BYTES + 1]).is_err());
        let encoded = snapshot(40, "p-1").encode().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["wire_version"] = serde_json::json!(2);
        assert!(PolicyWireFrame::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn flow_commands_are_bounded_idempotent_frames_and_revokes_carry_no_policy() {
        let make_command = |operation, verdict, policy_ids| PolicyWireFrame::FlowCommand {
            wire_version: POLICY_WIRE_VERSION,
            gateway_id: "gw-test".to_owned(),
            boot_id: "boot-1".to_owned(),
            controller_epoch: "00000000-0000-4000-8000-000000000001".to_owned(),
            config_revision: 12,
            command_id: "command-1".to_owned(),
            policy_flow_id: "0123456789abcdef0123456789abcdef".to_owned(),
            operation,
            verdict,
            policy_ids,
            expires_at_ms: 1_791_600_030_000,
            issued_at_ms: 1_791_600_000_000,
        };
        let command = make_command(
            FlowCommandOperation::Upsert,
            Some(FlowVerdict::Block),
            vec!["policy-1".to_owned()],
        );
        let encoded = command.encode().unwrap();
        assert_eq!(PolicyWireFrame::decode(&encoded).unwrap(), command);

        let revoke = make_command(FlowCommandOperation::Revoke, None, Vec::new());
        assert!(revoke.encode().is_ok());

        let invalid = make_command(FlowCommandOperation::Upsert, None, vec!["policy-1".into()]);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn metrics_frames_require_canonical_macs_and_safe_counters() {
        let frame = PolicyWireFrame::PolicyMetrics {
            wire_version: POLICY_WIRE_VERSION,
            gateway_id: "gw-test".to_owned(),
            boot_id: "boot-1".to_owned(),
            sampled_at_ms: 1_791_600_000_000,
            metrics: vec![PolicyClientMetrics {
                policy_id: "p-1".to_owned(),
                mac: "AA:BB:CC:DD:EE:FF".to_owned(),
                upload: Some(PolicyDirectionMetrics {
                    interface: "wan0".to_owned(),
                    bytes: Some(1024),
                    packets: Some(8),
                    drops: Some(0),
                    overlimits: Some(1),
                }),
                download: None,
            }],
        };
        assert!(frame.encode().is_ok());

        let mut policy_block_metric = frame.clone();
        if let PolicyWireFrame::PolicyMetrics { metrics, .. } = &mut policy_block_metric {
            let direction = metrics[0].upload.as_mut().unwrap();
            direction.interface = "policy-block".to_owned();
            direction.bytes = Some(222);
            direction.packets = Some(3);
            direction.drops = Some(3);
            direction.overlimits = None;
        }
        let encoded = policy_block_metric.encode().unwrap();
        assert_eq!(
            PolicyWireFrame::decode(&encoded).unwrap(),
            policy_block_metric
        );

        let mut lowercase_mac = frame.clone();
        if let PolicyWireFrame::PolicyMetrics { metrics, .. } = &mut lowercase_mac {
            metrics[0].mac.make_ascii_lowercase();
        }
        assert!(lowercase_mac.validate().is_err());

        let mut unsafe_counter = frame;
        if let PolicyWireFrame::PolicyMetrics { metrics, .. } = &mut unsafe_counter {
            metrics[0].upload.as_mut().unwrap().bytes = Some(MAX_SAFE_JSON_INTEGER + 1);
        }
        assert!(unsafe_counter.validate().is_err());
    }
}
