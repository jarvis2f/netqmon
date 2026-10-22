//! Opt-in, netlink-only client total budget runtime.
//!
//! Activation requires an explicit runtime config. Using real interfaces in
//! the initial network namespace additionally requires an explicit config
//! opt-in. It owns IFB 52:, LAN egress 51: roots, the client map publication,
//! and the independent priority state/journal.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, bail};
use libbpf_rs::{MapCore as _, MapFlags, ProgramHandle, ProgramMut};
use netqmon_protocol::policy::{
    PolicyAckStatus, PolicyCapability, PolicyResultStatus, PolicyWireFrame,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::{AgentConfig, AttachBackend},
    policy::{
        classid,
        priority_cleanup::{parse_classid_text, unused_priority_classes},
        priority_delivery::{self, DeliveryLayout, QueuePort},
        priority_plan::{ApplicationBudget, ClientBudget, PriorityPlan, QueueTree},
        priority_selection::PrioritySelection,
        priority_slots::{self, ClientSlotLease},
    },
};

use super::qos_priority_maps::{ClientMapEntry, PriorityMaps};

const STRUCTURAL_CAPACITY_BPS: u64 = 100_000_000_000;
const MATCHER_HANDLE: &str = "0x4e515006";
const IFB_OBSERVER_HANDLE: &str = "0x4e515007";
const MATCHER_HANDLE_ID: u32 = 0x4e51_5006;
const IFB_OBSERVER_HANDLE_ID: u32 = 0x4e51_5007;
const MATCHER_PROGRAM: &str = "netqmon_qos_priority_match";
const IFB_OBSERVER_PROGRAM: &str = "netqmon_qos_priority_ifb";
const PRIORITY_PIN_PREFIX: &str = "nqp-priority-";
const AGENT_COMM: &str = "netqmon-agent";
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    ifb: String,
    output: PathBuf,
    #[serde(default)]
    allow_initial_namespace: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorityState {
    schema_version: u32,
    gateway_id: String,
    controller_epoch: String,
    config_revision: u64,
    bundle_generation: u64,
    checksum: String,
    snapshot: PolicyWireFrame,
    leases: Vec<ClientSlotLease>,
    #[serde(default)]
    application_classes: Vec<ActiveApplicationClass>,
    generation: u32,
    expires_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveApplicationClass {
    policy_id: String,
    mac: String,
    slot: u16,
    minor: u32,
    upload_bps: Option<u64>,
    download_bps: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct PriorityClassMetrics {
    pub policy_id: String,
    pub mac: String,
    pub upload: bool,
    pub interface: String,
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub drops: Option<u64>,
    pub overlimits: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct ParsedPriorityClassMetrics {
    bytes: Option<u64>,
    packets: Option<u64>,
    drops: Option<u64>,
    overlimits: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct OriginalQueueRoot {
    kind: String,
    options: Value,
    mq_leaves: Vec<OriginalMqLeaf>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct OriginalMqLeaf {
    minor: String,
    kind: String,
    options: Value,
}

impl OriginalQueueRoot {
    fn noqueue() -> Self {
        Self {
            kind: "noqueue".to_owned(),
            options: Value::Null,
            mq_leaves: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct OwnedPort {
    port: QueuePort,
    original_root: OriginalQueueRoot,
}

pub(crate) struct PriorityRuntime {
    agent: AgentConfig,
    config: RuntimeConfig,
    maps: Arc<Mutex<PriorityMaps>>,
    layout: DeliveryLayout,
    ports: Vec<OwnedPort>,
    ifb_ifindex: u32,
    ifb_created: bool,
    ifb_original_root: Option<OriginalQueueRoot>,
    owned_roots: BTreeSet<(String, u32)>,
    output: PathBuf,
    state_path: PathBuf,
    journal_path: PathBuf,
    pin_dir: PathBuf,
    pin_dir_owned: bool,
    priority: u32,
    matcher_attached: Vec<QueuePort>,
    ifb_observer_attached: bool,
    clsact_created: BTreeSet<String>,
    active: Option<PriorityState>,
    active_plan: Option<PriorityPlan>,
    is_one_arm_router: bool,
    force_reapply: bool,
    emergency_disabled: bool,
    shutdown_done: bool,
}

fn run(binary: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(binary).args(args).output()?;
    if !output.status.success() {
        bail!(
            "{binary} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn ensure_no_hw_tc_offload(dev: &str, is_ifb: bool) -> Result<()> {
    match Command::new("ethtool").args(["-k", dev]).output() {
        Ok(output) => {
            if !output.status.success() {
                bail!(
                    "priority_offload_unknown: ethtool feature inspection is required: ethtool [\"-k\", {dev:?}]: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            let offload = String::from_utf8(output.stdout)?;
            if offload
                .lines()
                .any(|line| line.starts_with("hw-tc-offload:") && line.contains(": on"))
            {
                if is_ifb {
                    bail!("priority_offload_conflict: IFB hw-tc-offload is enabled");
                }
                bail!("priority_offload_conflict: hw-tc-offload is enabled on {dev}");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).context("priority_offload_unknown: ethtool feature inspection is required")
        }
    }
}

fn tc(args: &[&str]) -> Result<String> {
    run("tc", args)
}

fn ip(args: &[&str]) -> Result<String> {
    run("ip", args)
}

fn parse_json(text: &str, what: &str) -> Result<Value> {
    serde_json::from_str(text).with_context(|| format!("{what} returned invalid JSON"))
}

/// `tc -j class show` is not implemented by every iproute2 release (6.1 prints
/// the classic table). Accept both encodings and an empty dump, which means the
/// device has no classes.
fn parse_class_dump(text: &str, what: &str) -> Result<Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        return parse_json(trimmed, what);
    }
    let mut entries = Vec::new();
    let mut recognized = false;
    for line in trimmed.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"class") {
            recognized = true;
        }
        if fields.get(..2) != Some(&["class", "htb"]) {
            continue;
        }
        let Some(handle) = fields.get(2) else {
            continue;
        };
        let mut entry = serde_json::Map::new();
        entry.insert("class".to_owned(), Value::String("htb".to_owned()));
        entry.insert("handle".to_owned(), Value::String((*handle).to_owned()));
        match fields.get(3) {
            Some(&"root") => {
                entry.insert("root".to_owned(), Value::Bool(true));
            }
            Some(&"parent") => {
                if let Some(parent) = fields.get(4) {
                    entry.insert("parent".to_owned(), Value::String((*parent).to_owned()));
                }
            }
            _ => {}
        }
        entries.push(Value::Object(entry));
    }
    if !recognized {
        return parse_json(trimmed, what);
    }
    Ok(Value::Array(entries))
}

fn valid_test_name(name: &str) -> bool {
    name.starts_with("nqp-")
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_runtime_name(name: &str, allow_initial_namespace: bool) -> bool {
    if allow_initial_namespace {
        valid_interface_name(name)
    } else {
        valid_test_name(name)
    }
}

fn require_namespace_opt_in(initial_namespace: bool, allow_initial_namespace: bool) -> Result<()> {
    if initial_namespace && !allow_initial_namespace {
        bail!("priority_private_namespace_required: initial namespace opt-in is missing");
    }
    Ok(())
}

fn incompatible_nft(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(incompatible_nft),
        Value::Object(object) => {
            object.contains_key("flowtable")
                || object.contains_key("flow")
                || object
                    .get("mangle")
                    .is_some_and(|assignment| assignment["key"]["meta"]["key"] == "priority")
                || object.values().any(incompatible_nft)
        }
        _ => false,
    }
}

fn has_legacy_netqmon_mark_rule(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(has_legacy_netqmon_mark_rule),
        Value::Object(object) => {
            object
                .get("comment")
                .and_then(Value::as_str)
                .is_some_and(|comment| {
                    comment.starts_with("netqmon:traffic-limit:")
                        || comment.starts_with("netqmon:shared:")
                })
                || object.values().any(has_legacy_netqmon_mark_rule)
        }
        _ => false,
    }
}

fn capture_original_root(qdiscs: &Value) -> Result<OriginalQueueRoot> {
    let entries = qdiscs.as_array().context("qdisc dump is not an array")?;
    let roots = entries
        .iter()
        .filter(|entry| entry.get("root").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    if roots.len() > 1 {
        bail!("priority_qdisc_conflict: multiple root qdiscs");
    }
    let Some(root) = roots.first() else {
        return Ok(OriginalQueueRoot::noqueue());
    };
    let kind = root["kind"]
        .as_str()
        .context("priority_qdisc_conflict: root qdisc kind is missing")?;
    let options = root.get("options").cloned().unwrap_or(Value::Null);
    match kind {
        "noqueue" => Ok(OriginalQueueRoot::noqueue()),
        "fq_codel" => Ok(OriginalQueueRoot {
            kind: kind.to_owned(),
            options: {
                let _ = fq_codel_options(&options)?;
                options
            },
            mq_leaves: Vec::new(),
        }),
        "mq" => {
            let handle = root["handle"]
                .as_str()
                .context("priority_qdisc_conflict: mq root handle is missing")?;
            let major = handle
                .strip_suffix(':')
                .context("priority_qdisc_conflict: invalid mq root handle")?;
            let parent_prefix = if major.is_empty() || major == "0" {
                ":".to_owned()
            } else {
                format!("{major}:")
            };
            let mut leaves = Vec::new();
            for entry in entries {
                if entry.get("root").and_then(Value::as_bool) == Some(true)
                    || entry.get("kind").and_then(Value::as_str) == Some("clsact")
                {
                    continue;
                }
                let Some(parent) = entry.get("parent").and_then(Value::as_str) else {
                    continue;
                };
                let Some(minor) = parent.strip_prefix(&parent_prefix) else {
                    continue;
                };
                if minor.is_empty()
                    || !minor.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || leaves
                        .iter()
                        .any(|leaf: &OriginalMqLeaf| leaf.minor == minor)
                {
                    bail!("priority_qdisc_conflict: mq leaf parent is invalid or duplicated");
                }
                let leaf_kind = entry["kind"]
                    .as_str()
                    .context("priority_qdisc_conflict: mq leaf kind is missing")?;
                if leaf_kind != "fq_codel" {
                    bail!("priority_qdisc_conflict: unsupported mq leaf qdisc {leaf_kind}");
                }
                let leaf_options = entry
                    .get("options")
                    .cloned()
                    .context("priority_qdisc_conflict: mq leaf options are missing")?;
                let _ = fq_codel_options(&leaf_options)?;
                leaves.push(OriginalMqLeaf {
                    minor: minor.to_owned(),
                    kind: leaf_kind.to_owned(),
                    options: leaf_options,
                });
            }
            leaves.sort_by(|left, right| left.minor.cmp(&right.minor));
            Ok(OriginalQueueRoot {
                kind: kind.to_owned(),
                options,
                mq_leaves: leaves,
            })
        }
        _ => bail!("priority_qdisc_conflict: unsupported root qdisc {kind}"),
    }
}

fn fq_codel_options(options: &Value) -> Result<Vec<String>> {
    let required_number = |name: &str| -> Result<String> {
        options
            .get(name)
            .and_then(Value::as_u64)
            .map(|value| value.to_string())
            .with_context(|| format!("priority_qdisc_snapshot_incomplete: fq_codel {name}"))
    };
    let mut args = Vec::with_capacity(16);
    if options.as_object().is_none_or(|object| {
        object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "limit"
                    | "flows"
                    | "quantum"
                    | "target"
                    | "interval"
                    | "memory_limit"
                    | "ecn"
                    | "drop_batch"
            )
        })
    }) {
        bail!("priority_qdisc_snapshot_incomplete: unsupported fq_codel options");
    }
    for name in ["limit", "flows", "quantum"] {
        args.extend([name.to_owned(), required_number(name)?]);
    }
    args.extend([
        "target".to_owned(),
        format!(
            "{}us",
            required_number("target")?
                .parse::<u64>()?
                .checked_add(1)
                .context("priority_qdisc_snapshot_incomplete: target overflow")?
        ),
    ]);
    args.extend([
        "interval".to_owned(),
        format!(
            "{}us",
            required_number("interval")?
                .parse::<u64>()?
                .checked_add(1)
                .context("priority_qdisc_snapshot_incomplete: interval overflow")?
        ),
    ]);
    args.extend([
        "memory_limit".to_owned(),
        format!("{}b", required_number("memory_limit")?),
    ]);
    args.push(match options.get("ecn").and_then(Value::as_bool) {
        Some(true) => "ecn".to_owned(),
        Some(false) => "noecn".to_owned(),
        None => bail!("priority_qdisc_snapshot_incomplete: fq_codel ecn"),
    });
    args.extend(["drop_batch".to_owned(), required_number("drop_batch")?]);
    Ok(args)
}

fn restore_original_root(dev: &str, original: &OriginalQueueRoot) -> Result<()> {
    match original.kind.as_str() {
        "noqueue" => {}
        "fq_codel" => {
            let mut args = vec![
                "qdisc".to_owned(),
                "replace".to_owned(),
                "dev".to_owned(),
                dev.to_owned(),
                "root".to_owned(),
                "fq_codel".to_owned(),
            ];
            args.extend(fq_codel_options(&original.options)?);
            tc(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        "mq" => {
            tc(&["qdisc", "add", "dev", dev, "root", "mq"])?;
            let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")?;
            let roots = qdiscs
                .as_array()
                .context("restored mq qdisc dump is not an array")?
                .iter()
                .filter(|entry| entry.get("root").and_then(Value::as_bool) == Some(true))
                .collect::<Vec<_>>();
            if roots.len() != 1 || roots[0]["kind"] != "mq" {
                bail!("priority_qdisc_restore_failed: mq root readback on {dev}");
            }
            let handle = roots[0]["handle"]
                .as_str()
                .context("priority_qdisc_restore_failed: mq root handle missing")?;
            let major = handle
                .strip_suffix(':')
                .context("priority_qdisc_restore_failed: invalid mq root handle")?;
            let prefix = if major.is_empty() || major == "0" {
                ":".to_owned()
            } else {
                format!("{major}:")
            };
            for leaf in &original.mq_leaves {
                if leaf.kind != "fq_codel" {
                    bail!("priority_qdisc_restore_failed: unsupported saved mq leaf");
                }
                let parent = format!("{prefix}{}", leaf.minor);
                let mut args = vec![
                    "qdisc".to_owned(),
                    "replace".to_owned(),
                    "dev".to_owned(),
                    dev.to_owned(),
                    "parent".to_owned(),
                    parent,
                    "fq_codel".to_owned(),
                ];
                args.extend(fq_codel_options(&leaf.options)?);
                tc(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
            }
        }
        kind => bail!("priority_qdisc_restore_failed: unsupported saved root {kind}"),
    }
    let restored = capture_original_root(&parse_json(
        &tc(&["-j", "qdisc", "show", "dev", dev])?,
        "restored qdisc dump",
    )?)?;
    if restored != *original {
        bail!("priority_qdisc_restore_failed: restored tree differs on {dev}");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QdiscOwnership {
    Absent,
    Foreign,
    Owned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnedFilterState {
    Absent,
    Owned(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinOwnerState {
    Stale,
    Live,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedFilter {
    dev: String,
    hook: &'static str,
    pref: u32,
    handle: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StalePinDir {
    path: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct OwnedPriorityResources {
    roots: BTreeSet<String>,
    filters: Vec<OwnedFilter>,
    agent_hook_filters: Vec<OwnedFilter>,
    ifb: Option<(String, u32)>,
    ifb_filter: Option<OwnedFilter>,
    pin_dirs: Vec<StalePinDir>,
    clsact: BTreeSet<String>,
}

impl OwnedPriorityResources {
    fn is_empty(&self) -> bool {
        self.roots.is_empty()
            && self.filters.is_empty()
            && self.agent_hook_filters.is_empty()
            && self.ifb.is_none()
            && self.ifb_filter.is_none()
            && self.pin_dirs.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryOwner {
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    comm: Option<String>,
    #[serde(default)]
    starttime: Option<u64>,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default)]
    netns: Option<String>,
}

impl RecoveryOwner {
    fn is_empty(&self) -> bool {
        self.pid == 0 && self.comm.is_none() && self.starttime.is_none()
    }
}

#[derive(Debug, Default)]
struct RecoveryEvidence {
    roots: BTreeMap<String, (u32, OriginalQueueRoot)>,
    clsact_created: BTreeSet<String>,
    interface_ifindices: BTreeMap<String, u32>,
    ifb_ifindex: Option<u32>,
    ifb_mac: Option<String>,
    program_ids: BTreeMap<String, u32>,
    boot_id: Option<String>,
    netns: Option<String>,
    owner: Option<RecoveryOwner>,
}

impl RecoveryEvidence {
    fn expected_program_id(&self, dev: &str, hook: &str, handle: u32) -> Option<u32> {
        self.program_ids
            .get(&format!("{dev}:{hook}:{}", handle_text(handle)))
            .copied()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RecoveryPlan {
    filters: Vec<OwnedFilter>,
    pin_dirs: Vec<StalePinDir>,
    clsact: Vec<String>,
    roots: Vec<(String, u32)>,
    ifb: Option<(String, u32)>,
    original_root_unavailable: Vec<String>,
}

impl RecoveryPlan {
    fn is_empty(&self) -> bool {
        self.filters.is_empty()
            && self.pin_dirs.is_empty()
            && self.clsact.is_empty()
            && self.roots.is_empty()
            && self.ifb.is_none()
    }
}

#[derive(Debug, Default)]
struct RecoveryOutcome {
    performed: bool,
    restored_roots: Vec<String>,
    original_root_unavailable: Vec<String>,
    degraded: bool,
}

impl RecoveryOutcome {
    fn degraded_reason(&self) -> Option<&'static str> {
        self.degraded.then_some("original_root_unavailable")
    }
}

fn parse_tc_handle(text: &str) -> Option<(u32, u32)> {
    let text = text.trim();
    let (major, minor) = text.split_once(':')?;
    if major.contains(':') || minor.contains(':') {
        return None;
    }
    let major = if major.is_empty() {
        0
    } else {
        u32::from_str_radix(major, 16).ok()?
    };
    let minor = if minor.is_empty() {
        0
    } else {
        u32::from_str_radix(minor, 16).ok()?
    };
    Some((major, minor))
}

fn value_handle(value: &Value) -> Option<(u32, u32)> {
    match value {
        Value::String(text) => parse_tc_handle(text),
        Value::Number(number) => number
            .as_u64()
            .and_then(|raw| u32::try_from(raw).ok())
            .map(|raw| (raw >> 16, raw & 0xffff)),
        _ => None,
    }
}

fn tc_handle(major: u32, minor: u32) -> String {
    format!("{major:x}:{minor:x}")
}

fn filter_handle(entry: &Value) -> Option<u32> {
    let value = entry
        .get("options")
        .and_then(|options| options.get("handle"))
        .or_else(|| entry.get("handle"))?;
    value
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .or_else(|| {
            let text = value.as_str()?.trim();
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                text.parse::<u32>()
                    .ok()
                    .or_else(|| value_handle(value).map(|(major, minor)| (major << 16) | minor))
            }
        })
}

fn filter_preference(entry: &Value) -> Option<u32> {
    let value = entry.get("pref")?;
    value
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .or_else(|| value.as_str()?.trim().parse::<u32>().ok())
}

fn filter_program_name(entry: &Value) -> Option<&str> {
    entry
        .get("options")
        .and_then(|options| options.get("prog"))
        .or_else(|| entry.get("prog"))
        .and_then(|prog| prog.get("name"))
        .or_else(|| {
            entry
                .get("options")
                .and_then(|options| options.get("bpf_name"))
                .or_else(|| entry.get("bpf_name"))
        })
        .and_then(Value::as_str)
}

fn filter_program_id(entry: &Value) -> Option<u32> {
    entry
        .get("options")
        .and_then(|options| options.get("prog"))
        .or_else(|| entry.get("prog"))
        .and_then(|prog| prog.get("id"))
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
}

/// The kernel stores BPF program names in 16 bytes including the NUL byte.
/// Accept both the source symbol and its kernel truncation.
fn program_name_matches(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    let bytes = expected.as_bytes();
    let kernel_length = bytes.len().min(15);
    actual.as_bytes() == &bytes[..kernel_length]
}

#[cfg(test)]
fn classify_owned_filter(
    dump: &Value,
    handle: u32,
    expected_program: &str,
) -> Result<OwnedFilterState> {
    classify_owned_filter_with_id(dump, handle, expected_program, None)
}

fn classify_owned_filter_with_id(
    dump: &Value,
    handle: u32,
    expected_program: &str,
    expected_program_id: Option<u32>,
) -> Result<OwnedFilterState> {
    let entries = dump
        .as_array()
        .context("priority_filter_ownership_unknown: filter dump is not an array")?;
    let mut matched = Vec::new();
    for entry in entries {
        if filter_handle(entry) != Some(handle) {
            continue;
        }
        if entry.get("kind").and_then(Value::as_str) != Some("bpf") {
            bail!("priority_filter_ownership_unknown: handle 0x{handle:x} is not a BPF filter");
        }
        let Some(name) = filter_program_name(entry) else {
            bail!("priority_filter_ownership_unknown: handle 0x{handle:x} has no program name");
        };
        if !program_name_matches(name, expected_program) {
            bail!(
                "priority_filter_ownership_unknown: handle 0x{handle:x} runs foreign program {name}"
            );
        }
        if let Some(expected_id) = expected_program_id {
            match filter_program_id(entry) {
                Some(actual_id) if actual_id == expected_id => {}
                Some(actual_id) => bail!(
                    "priority_filter_ownership_unknown: handle 0x{handle:x} runs program {name} id {actual_id}, expected {expected_id}"
                ),
                None => bail!(
                    "priority_filter_ownership_unknown: handle 0x{handle:x} has no program id"
                ),
            }
        }
        let Some(pref) = filter_preference(entry) else {
            bail!("priority_filter_ownership_unknown: handle 0x{handle:x} has no preference");
        };
        matched.push(pref);
    }
    if matched.len() > 1 {
        bail!("priority_filter_ownership_unknown: handle 0x{handle:x} appears in multiple filters");
    }
    Ok(matched.first().map_or(OwnedFilterState::Absent, |pref| {
        OwnedFilterState::Owned(*pref)
    }))
}

fn canonical_class_parent(minor: u32, parent: Option<(u32, u32)>, major: u32) -> bool {
    match minor {
        0x0001 => parent.is_none(),
        0xfffe => parent == Some((major, 0x0001)),
        0x0100..=0x01ff => parent == Some((major, 0x0001)),
        0x0200..=0x02ff | 0x1000..=0x1fff => parent.is_some_and(|(parent_major, parent_minor)| {
            parent_major == major && (0x0100..=0x01ff).contains(&parent_minor)
        }),
        _ => false,
    }
}

/// Verify the exact HTB skeleton this runtime installs. Client and application
/// leaves may be missing after a crash, but anything that is present must sit
/// in a canonical NetQMon class slot. A partial or foreign tree is never
/// adopted because deleting it could remove another writer's qdisc.
fn verify_owned_htb_layout(qdiscs: &Value, classes: &Value, major: u32) -> Result<()> {
    let class_entries = classes
        .as_array()
        .context("priority_qdisc_ownership_unknown: class dump is not an array")?;
    let mut seen = BTreeSet::new();
    for entry in class_entries {
        // `tc -j class show` also reports classes owned by leaf qdiscs
        // (for example the fq_codel class `fffe:<minor>`). Those are not
        // HTB classes and must not invalidate the owned skeleton.
        if entry.get("class").and_then(Value::as_str) != Some("htb") {
            continue;
        }
        let classid = entry
            .get("handle")
            .and_then(value_handle)
            .context("priority_qdisc_ownership_unknown: class handle is missing or invalid")?;
        if classid.0 != major || !seen.insert(classid) {
            bail!(
                "priority_qdisc_ownership_unknown: unexpected or duplicate class {}",
                tc_handle(classid.0, classid.1)
            );
        }
        let parent = entry.get("parent").and_then(value_handle);
        let root = entry.get("root").and_then(Value::as_bool).unwrap_or(false);
        if classid.1 == 0x0001 {
            if !root || parent.is_some() {
                bail!("priority_qdisc_ownership_unknown: root class is not canonical");
            }
            continue;
        }
        if root || !canonical_class_parent(classid.1, parent, major) {
            bail!(
                "priority_qdisc_ownership_unknown: class {} has an unexpected parent",
                tc_handle(classid.0, classid.1)
            );
        }
    }
    if !seen.contains(&(major, 0x0001)) || !seen.contains(&(major, 0xfffe)) {
        bail!(
            "priority_qdisc_ownership_unknown: class {}:1 or {}:fffe is missing",
            major,
            major
        );
    }

    let qdisc_entries = qdiscs
        .as_array()
        .context("priority_qdisc_ownership_unknown: qdisc dump is not an array")?;
    let mut leaf_parents = BTreeSet::new();
    for entry in qdisc_entries {
        let kind = entry.get("kind").and_then(Value::as_str);
        if kind == Some("clsact") {
            continue;
        }
        let handle = entry.get("handle").and_then(value_handle);
        let parent = entry.get("parent").and_then(value_handle);
        let root = entry.get("root").and_then(Value::as_bool).unwrap_or(false);
        if root {
            if kind != Some("htb") || handle != Some((major, 0)) {
                bail!("priority_qdisc_ownership_unknown: root qdisc changed during verification");
            }
            continue;
        }
        if let Some(parent) = parent {
            if parent.0 != major {
                continue;
            }
            if kind != Some("fq_codel") || !seen.contains(&parent) {
                bail!(
                    "priority_qdisc_ownership_unknown: unexpected qdisc under {}",
                    tc_handle(parent.0, parent.1)
                );
            }
            if !leaf_parents.insert(parent) {
                bail!(
                    "priority_qdisc_ownership_unknown: duplicate leaf qdisc under {}",
                    tc_handle(parent.0, parent.1)
                );
            }
        } else if handle.is_some_and(|(handle_major, _)| handle_major == major) {
            bail!("priority_qdisc_ownership_unknown: qdisc without a parent");
        }
    }
    if !leaf_parents.contains(&(major, 0xfffe)) {
        bail!(
            "priority_qdisc_ownership_unknown: missing fq_codel leaf under {}:fffe",
            major
        );
    }
    Ok(())
}

fn classify_owned_root(qdiscs: &Value, classes: &Value, major: u32) -> Result<QdiscOwnership> {
    let entries = qdiscs
        .as_array()
        .context("priority_qdisc_ownership_unknown: qdisc dump is not an array")?;
    let roots = entries
        .iter()
        .filter(|entry| entry.get("root").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    if roots.len() > 1 {
        if roots.iter().any(|entry| {
            entry.get("kind").and_then(Value::as_str) == Some("htb")
                && entry.get("handle").and_then(value_handle) == Some((major, 0))
        }) {
            bail!("priority_qdisc_ownership_unknown: multiple root qdiscs include {major:x}:");
        }
        return Ok(QdiscOwnership::Foreign);
    }
    let Some(root) = roots.first() else {
        return Ok(QdiscOwnership::Absent);
    };
    if root.get("kind").and_then(Value::as_str) != Some("htb")
        || root.get("handle").and_then(value_handle) != Some((major, 0))
    {
        return Ok(QdiscOwnership::Foreign);
    }
    verify_owned_htb_layout(qdiscs, classes, major)?;
    Ok(QdiscOwnership::Owned)
}

fn classify_ifb_root(qdiscs: &Value, classes: &Value, major: u32) -> Result<()> {
    match classify_owned_root(qdiscs, classes, major)? {
        QdiscOwnership::Owned => Ok(()),
        _ => bail!("priority_ifb_ownership_unknown: IFB root is not the owned {major:x}: tree"),
    }
}

fn dump_filters(dev: &str, hook: &str) -> Result<Option<Value>> {
    let text = tc(&["-j", "filter", "show", "dev", dev, hook])
        .with_context(|| format!("priority_filter_ownership_unknown: inspect {dev} {hook}"))?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    let value = parse_json(&text, "filter dump").map_err(|_| {
        anyhow!("priority_filter_ownership_unknown: {dev} {hook} filter dump is not JSON")
    })?;
    if !value.is_array() {
        bail!("priority_filter_ownership_unknown: {dev} {hook} filter dump is not an array");
    }
    Ok(Some(value))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinkIdentity {
    ifindex: Option<u32>,
    address: Option<String>,
    kind: Option<String>,
}

fn link_identity(name: &str) -> Result<Option<LinkIdentity>> {
    let output = ip(&["-d", "-j", "link", "show", "dev", name])
        .with_context(|| format!("priority_ifb_ownership_unknown: inspect link {name}"))?;
    let value = parse_json(&output, "link dump")
        .map_err(|_| anyhow!("priority_ifb_ownership_unknown: {name} link dump is not JSON"))?;
    let Some(entry) = value.as_array().and_then(|entries| entries.first()) else {
        return Ok(None);
    };
    Ok(Some(LinkIdentity {
        ifindex: entry
            .get("ifindex")
            .and_then(Value::as_u64)
            .and_then(|index| u32::try_from(index).ok()),
        address: entry
            .get("address")
            .and_then(Value::as_str)
            .map(|address| address.to_ascii_lowercase()),
        kind: entry
            .get("linkinfo")
            .and_then(|info| info.get("info_kind"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }))
}

fn valid_pin_dir_entries(names: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    names.iter().all(|name| {
        matches!(name.as_str(), "matcher" | "ifb-observer") && seen.insert(name.as_str())
    })
}

fn expected_pin_program(name: &str) -> Option<&'static str> {
    match name {
        "matcher" => Some(MATCHER_PROGRAM),
        "ifb-observer" => Some(IFB_OBSERVER_PROGRAM),
        _ => None,
    }
}

fn classify_pin_owner(
    pid: u32,
    current_pid: u32,
    comm: Option<&str>,
    owner: Option<&RecoveryOwner>,
) -> PinOwnerState {
    if pid == current_pid {
        // A PID-named directory matching the current process can only be stale:
        // this process has not created its pins yet.
        return PinOwnerState::Stale;
    }
    if !comm.is_some_and(|comm| comm.trim() == AGENT_COMM) {
        // A missing /proc entry is a dead process; a reused PID with a different
        // command name means the original Agent is dead.
        return PinOwnerState::Stale;
    }
    // When evidence records the old process start time, a PID reuse with the
    // Agent command name is still not the owner.
    if let Some(owner) = owner
        && owner.pid == pid
        && let Some(expected) = owner.starttime
    {
        return if process_starttime(pid) == Some(expected) {
            PinOwnerState::Live
        } else {
            PinOwnerState::Stale
        };
    }
    PinOwnerState::Live
}

fn verify_stale_pin_dir(path: &Path, names: &[String]) -> Result<()> {
    for name in names {
        let expected = expected_pin_program(name)
            .context("priority_pin_ownership_unknown: unexpected pinned entry")?;
        let pinned = ProgramHandle::from_pinned_path(path.join(name)).with_context(|| {
            format!(
                "priority_pin_ownership_unknown: {} is not a pinned BPF program",
                path.join(name).display()
            )
        })?;
        let actual = pinned.name().to_string_lossy();
        if !program_name_matches(&actual, expected) {
            bail!(
                "priority_pin_ownership_unknown: {} pins program {actual}, expected {expected}",
                path.join(name).display()
            );
        }
    }
    Ok(())
}

fn inspect_stale_pin_dirs(
    current_pid: u32,
    owner: Option<&RecoveryOwner>,
) -> Result<Vec<StalePinDir>> {
    let base = Path::new("/sys/fs/bpf");
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name.strip_prefix(PRIORITY_PIN_PREFIX) else {
            continue;
        };
        let pid = suffix.parse::<u32>().map_err(|_| {
            anyhow!("priority_pin_ownership_unknown: malformed pin directory {name}")
        })?;
        if pid == 0 || !entry.file_type()?.is_dir() {
            bail!("priority_pin_ownership_unknown: invalid pin directory {name}");
        }
        let path = entry.path();
        let mut names = Vec::new();
        for item in fs::read_dir(&path)? {
            let item = item?;
            let item_name = item.file_name().to_string_lossy().into_owned();
            if !item.file_type()?.is_file() {
                bail!(
                    "priority_pin_ownership_unknown: {} contains a non-file entry",
                    path.display()
                );
            }
            names.push(item_name);
        }
        if !valid_pin_dir_entries(&names) {
            bail!(
                "priority_pin_ownership_unknown: {} contains an unowned entry",
                path.display()
            );
        }
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok();
        if classify_pin_owner(pid, current_pid, comm.as_deref(), owner) == PinOwnerState::Live {
            bail!(
                "priority_runtime_owned_by_live_process: {name} is owned by a live netqmon-agent process"
            );
        }
        verify_stale_pin_dir(&path, &names)?;
        dirs.push(StalePinDir { path });
    }
    Ok(dirs)
}

fn inspect_owned_priority_resources(
    layout: &DeliveryLayout,
    ifb_name: &str,
    interfaces: &[String],
    agent_hook_handle: u32,
    evidence: &RecoveryEvidence,
) -> Result<OwnedPriorityResources> {
    let mut resources = OwnedPriorityResources::default();
    for interface in interfaces {
        if !evidence_interface_ifindex_matches(evidence, interface) {
            continue;
        }
        for (hook, program) in [("ingress", "netqmon_ingress"), ("egress", "netqmon_egress")] {
            let Some(dump) = dump_filters(interface, hook)? else {
                continue;
            };
            if let OwnedFilterState::Owned(pref) = classify_owned_filter_with_id(
                &dump,
                agent_hook_handle,
                program,
                evidence.expected_program_id(interface, hook, agent_hook_handle),
            )? {
                resources.agent_hook_filters.push(OwnedFilter {
                    dev: interface.clone(),
                    hook,
                    pref,
                    handle: agent_hook_handle,
                });
            }
        }
    }
    for port in &layout.egress_ports {
        // A recreated interface has a different ifindex; its qdiscs cannot be
        // the ones our evidence describes.
        if !evidence_interface_ifindex_matches(evidence, &port.name) {
            continue;
        }
        let qdiscs = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", &port.name])?,
            "qdisc dump",
        )?;
        let classes = parse_class_dump(
            &tc(&["-j", "class", "show", "dev", &port.name])?,
            "class dump",
        )?;
        if has_clsact(&qdiscs) {
            resources.clsact.insert(port.name.clone());
        }
        if classify_owned_root(&qdiscs, &classes, classid::DOWNLOAD_MAJOR)? == QdiscOwnership::Owned
        {
            resources.roots.insert(port.name.clone());
        }
        if has_clsact(&qdiscs)
            && let Some(dump) = dump_filters(&port.name, "ingress")?
            && let OwnedFilterState::Owned(pref) = classify_owned_filter_with_id(
                &dump,
                MATCHER_HANDLE_ID,
                MATCHER_PROGRAM,
                evidence.expected_program_id(&port.name, "ingress", MATCHER_HANDLE_ID),
            )?
        {
            resources.filters.push(OwnedFilter {
                dev: port.name.clone(),
                hook: "ingress",
                pref,
                handle: MATCHER_HANDLE_ID,
            });
        }
    }

    let ifb_ifindex = nix::net::if_::if_nametoindex(ifb_name).ok();
    if let Some(ifb_ifindex) = ifb_ifindex {
        if let Some(expected) = evidence.ifb_ifindex
            && expected != ifb_ifindex
        {
            bail!(
                "priority_ifb_ownership_changed: {ifb_name} index changed from {expected} to {ifb_ifindex}"
            );
        }
        let identity = link_identity(ifb_name)?;
        if identity
            .as_ref()
            .and_then(|identity| identity.kind.as_deref())
            != Some("ifb")
        {
            bail!("priority_ifb_ownership_unknown: {ifb_name} exists but is not an IFB");
        }
        if let (Some(expected), Some(actual)) = (
            evidence.ifb_mac.as_deref(),
            identity
                .as_ref()
                .and_then(|identity| identity.address.as_deref()),
        ) && !actual.eq_ignore_ascii_case(expected)
        {
            bail!(
                "priority_ifb_ownership_changed: {ifb_name} address changed from {expected} to {actual}"
            );
        }
        let qdiscs = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", ifb_name])?,
            "IFB qdisc dump",
        )?;
        let classes = parse_class_dump(
            &tc(&["-j", "class", "show", "dev", ifb_name])?,
            "IFB class dump",
        )?;
        classify_ifb_root(&qdiscs, &classes, classid::UPLOAD_MAJOR)?;
        resources.ifb = Some((ifb_name.to_owned(), ifb_ifindex));
        if has_clsact(&qdiscs) {
            resources.clsact.insert(ifb_name.to_owned());
            if let Some(dump) = dump_filters(ifb_name, "egress")?
                && let OwnedFilterState::Owned(pref) = classify_owned_filter_with_id(
                    &dump,
                    IFB_OBSERVER_HANDLE_ID,
                    IFB_OBSERVER_PROGRAM,
                    evidence.expected_program_id(ifb_name, "egress", IFB_OBSERVER_HANDLE_ID),
                )?
            {
                resources.ifb_filter = Some(OwnedFilter {
                    dev: ifb_name.to_owned(),
                    hook: "egress",
                    pref,
                    handle: IFB_OBSERVER_HANDLE_ID,
                });
            }
        }
    }

    resources.pin_dirs = inspect_stale_pin_dirs(std::process::id(), evidence.owner.as_ref())?;
    Ok(resources)
}

fn collect_program_ids(ports: &[String], ifb: &str) -> BTreeMap<String, u32> {
    let mut ids = BTreeMap::new();
    for dev in std::iter::once(ifb).chain(ports.iter().map(String::as_str)) {
        for hook in ["ingress", "egress"] {
            let Ok(Some(dump)) = dump_filters(dev, hook) else {
                continue;
            };
            let Some(entries) = dump.as_array() else {
                continue;
            };
            for entry in entries {
                let (Some(handle), Some(id)) = (filter_handle(entry), filter_program_id(entry))
                else {
                    continue;
                };
                ids.entry(format!("{dev}:{hook}:{}", handle_text(handle)))
                    .or_insert(id);
            }
        }
    }
    ids
}

fn valid_original_root(root: &OriginalQueueRoot) -> bool {
    match root.kind.as_str() {
        "noqueue" => root.options.is_null() && root.mq_leaves.is_empty(),
        "fq_codel" => root.mq_leaves.is_empty() && fq_codel_options(&root.options).is_ok(),
        "mq" => root.mq_leaves.iter().all(|leaf| {
            leaf.kind == "fq_codel"
                && !leaf.minor.is_empty()
                && leaf.minor.bytes().all(|byte| byte.is_ascii_hexdigit())
                && fq_codel_options(&leaf.options).is_ok()
        }),
        _ => false,
    }
}

fn read_recovery_evidence(path: &Path) -> RecoveryEvidence {
    let Ok(bytes) = fs::read(path) else {
        return RecoveryEvidence::default();
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return RecoveryEvidence::default();
    };
    let mut evidence = RecoveryEvidence::default();
    if let Some(entries) = value.get("original_qdisc_roots").and_then(Value::as_array) {
        for entry in entries {
            let Some(dev) = entry.get("dev").and_then(Value::as_str) else {
                continue;
            };
            let Some(tree) = entry.get("tree") else {
                continue;
            };
            let Ok(tree) = serde_json::from_value::<OriginalQueueRoot>(tree.clone()) else {
                continue;
            };
            if !valid_original_root(&tree) {
                continue;
            }
            let ifindex = entry
                .get("ifindex")
                .and_then(Value::as_u64)
                .and_then(|index| u32::try_from(index).ok())
                .unwrap_or(0);
            evidence
                .roots
                .entry(dev.to_owned())
                .or_insert((ifindex, tree));
        }
    }
    if let Some(entries) = value.get("clsact_created").and_then(Value::as_array) {
        for name in entries.iter().filter_map(Value::as_str) {
            evidence.clsact_created.insert(name.to_owned());
        }
    }
    if let Some(entries) = value.get("interface_ifindices").and_then(Value::as_object) {
        for (dev, ifindex) in entries {
            if let Some(ifindex) = ifindex.as_u64().and_then(|index| u32::try_from(index).ok()) {
                evidence.interface_ifindices.insert(dev.clone(), ifindex);
            }
        }
    }
    if let Some(entries) = value.get("program_ids").and_then(Value::as_object) {
        for (name, id) in entries {
            if let Some(id) = id.as_u64().and_then(|id| u32::try_from(id).ok()) {
                evidence.program_ids.insert(name.clone(), id);
            }
        }
    }
    evidence.ifb_ifindex = value
        .get("ifb_ifindex")
        .and_then(Value::as_u64)
        .and_then(|index| u32::try_from(index).ok())
        .filter(|index| *index != 0);
    evidence.ifb_mac = value
        .get("ifb_mac")
        .and_then(Value::as_str)
        .map(|mac| mac.to_ascii_lowercase());
    evidence.boot_id = value
        .get("boot_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    evidence.netns = value
        .get("netns")
        .and_then(Value::as_str)
        .map(str::to_owned);
    evidence.owner = value
        .get("owner")
        .and_then(|owner| serde_json::from_value::<RecoveryOwner>(owner.clone()).ok());
    evidence
}

fn plan_recovery(resources: &OwnedPriorityResources, evidence: &RecoveryEvidence) -> RecoveryPlan {
    // Remove the previous Agent hook filters first. They are not policy
    // matchers, but they occupy the fixed Agent handle and would otherwise
    // trip the later foreign-filter gate.
    let mut filters = resources.agent_hook_filters.clone();
    filters.extend(resources.filters.iter().cloned());
    if let Some(filter) = &resources.ifb_filter {
        filters.push(filter.clone());
    }
    filters.sort_by(|left, right| {
        left.dev
            .cmp(&right.dev)
            .then_with(|| left.hook.cmp(right.hook))
    });
    let mut pin_dirs = resources.pin_dirs.clone();
    pin_dirs.sort_by(|left, right| left.path.cmp(&right.path));
    let roots = resources
        .roots
        .iter()
        .map(|dev| (dev.clone(), classid::DOWNLOAD_MAJOR))
        .collect::<Vec<_>>();

    let mut candidates = resources.roots.clone();
    candidates.extend(resources.filters.iter().map(|filter| filter.dev.clone()));
    if let Some((ifb, _)) = &resources.ifb {
        candidates.insert(ifb.clone());
    }
    let clsact = candidates
        .into_iter()
        .filter(|dev| {
            resources.clsact.contains(dev)
                && (resources.ifb.as_ref().is_some_and(|(ifb, _)| ifb == dev)
                    || evidence.clsact_created.contains(dev)
                    || resources.filters.iter().any(|filter| &filter.dev == dev))
        })
        .collect::<Vec<_>>();

    let original_root_unavailable = roots
        .iter()
        .filter(|(dev, _)| !evidence.roots.contains_key(dev))
        .map(|(dev, _)| dev.clone())
        .collect();

    RecoveryPlan {
        filters,
        pin_dirs,
        clsact,
        roots,
        ifb: resources.ifb.clone(),
        original_root_unavailable,
    }
}

fn handle_text(handle: u32) -> String {
    format!("0x{handle:x}")
}

fn expected_filter_program(hook: &str, handle_id: u32) -> Option<&'static str> {
    match handle_id {
        MATCHER_HANDLE_ID => Some(MATCHER_PROGRAM),
        IFB_OBSERVER_HANDLE_ID => Some(IFB_OBSERVER_PROGRAM),
        // Agent hook filters use the configured bpf.tc_handle. Their program
        // name depends on the hook, not on the handle value.
        _ => match hook {
            "ingress" => Some("netqmon_ingress"),
            "egress" => Some("netqmon_egress"),
            _ => None,
        },
    }
}

fn remove_owned_filter_filtered(
    dev: &str,
    hook: &str,
    handle_id: u32,
    expected_program_id: Option<u32>,
) -> Result<()> {
    let expected = expected_filter_program(hook, handle_id).with_context(|| {
        format!("priority_filter_ownership_unknown: unknown handle 0x{handle_id:x}")
    })?;
    let Some(dump) = dump_filters(dev, hook)? else {
        return Ok(());
    };
    let state = classify_owned_filter_with_id(&dump, handle_id, expected, expected_program_id)?;
    let OwnedFilterState::Owned(pref) = state else {
        return Ok(());
    };
    let pref = pref.to_string();
    let handle = handle_text(handle_id);
    if let Err(error) = tc(&[
        "filter", "del", "dev", dev, hook, "prio", &pref, "handle", &handle, "bpf",
    ]) {
        // A concurrent or already completed removal is success; only report the
        // command failure when the owned filter is still attached.
        if let Some(dump) = dump_filters(dev, hook)?
            && matches!(
                classify_owned_filter_with_id(&dump, handle_id, expected, expected_program_id)?,
                OwnedFilterState::Owned(_)
            )
        {
            return Err(error).with_context(|| format!("remove priority filter {dev} {hook}"));
        }
        return Ok(());
    }
    if let Some(dump) = dump_filters(dev, hook)?
        && matches!(
            classify_owned_filter_with_id(&dump, handle_id, expected, expected_program_id)?,
            OwnedFilterState::Owned(_)
        )
    {
        bail!("priority_filter_cleanup_failed: {dev} {hook}");
    }
    Ok(())
}

fn remove_stale_pin_dir(path: &Path) -> Result<()> {
    for name in ["matcher", "ifb-observer"] {
        match fs::remove_file(path.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("remove pinned program {}", path.join(name).display())
                });
            }
        }
    }
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("remove priority BPF pin directory {}", path.display())),
    }
}

/// A missing resource is success. This makes a partially completed recovery
/// converge on the next start.
fn delete_owned_root(dev: &str, major: u32, original: Option<&OriginalQueueRoot>) -> Result<()> {
    if nix::net::if_::if_nametoindex(dev).is_err() {
        // The interface disappeared after inspection; its qdisc is gone too.
        return Ok(());
    }
    let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")?;
    let classes = parse_class_dump(&tc(&["-j", "class", "show", "dev", dev])?, "class dump")?;
    match classify_owned_root(&qdiscs, &classes, major)? {
        QdiscOwnership::Absent => return Ok(()),
        QdiscOwnership::Owned => {}
        QdiscOwnership::Foreign => {
            bail!("priority_qdisc_ownership_changed: {dev} no longer has the owned root")
        }
    }
    let handle = format!("{major:x}:");
    if let Err(error) = tc(&["qdisc", "del", "dev", dev, "root", "handle", &handle]) {
        if let Ok(after) = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")
            && after.as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("root").and_then(Value::as_bool) == Some(true)
                        && entry.get("kind").and_then(Value::as_str) == Some("htb")
                        && entry.get("handle").and_then(value_handle) == Some((major, 0))
                })
            })
        {
            return Err(error)
                .with_context(|| format!("remove owned priority root qdisc on {dev}"));
        }
    }
    let after = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")?;
    if after.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("root").and_then(Value::as_bool) == Some(true)
                && entry.get("kind").and_then(Value::as_str) == Some("htb")
        })
    }) {
        bail!("priority_qdisc_cleanup_failed: {dev} handle {handle}");
    }
    if let Some(original) = original {
        restore_original_root(dev, original)
            .with_context(|| format!("restore original root qdisc on {dev}"))?;
    }
    Ok(())
}

fn remove_owned_ifb(name: &str, ifindex: u32) -> Result<()> {
    for hook in ["ingress", "egress"] {
        if let Some(dump) = dump_filters(name, hook)?
            && dump.as_array().is_some_and(|entries| !entries.is_empty())
        {
            bail!("priority_tc_conflict: foreign filter remains on IFB {name} {hook}");
        }
    }
    let qdiscs = parse_json(
        &tc(&["-j", "qdisc", "show", "dev", name])?,
        "IFB qdisc dump",
    )?;
    if qdiscs.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("root").and_then(Value::as_bool) == Some(true)
                && entry.get("kind").and_then(Value::as_str) == Some("htb")
                && entry.get("handle").and_then(value_handle) == Some((classid::UPLOAD_MAJOR, 0))
        })
    }) {
        let handle = format!("{:x}:", classid::UPLOAD_MAJOR);
        tc(&["qdisc", "del", "dev", name, "root", "handle", &handle])?;
    }
    match nix::net::if_::if_nametoindex(name) {
        Ok(actual) if actual == ifindex => {
            ip(&["link", "del", name])?;
            Ok(())
        }
        Ok(actual) => {
            bail!("priority_ifb_ownership_changed: {name} index changed from {ifindex} to {actual}")
        }
        Err(_) => Ok(()),
    }
}

fn execute_recovery_plan(
    plan: &RecoveryPlan,
    evidence: &RecoveryEvidence,
) -> Result<RecoveryOutcome> {
    // Re-check immediately before mutating anything. A process that is still
    // alive may be recreating or using these exact resources.
    ensure_recovery_owner_exited(evidence)?;
    for filter in &plan.filters {
        remove_owned_filter_filtered(
            &filter.dev,
            filter.hook,
            filter.handle,
            evidence.expected_program_id(&filter.dev, filter.hook, filter.handle),
        )?;
    }
    for dir in &plan.pin_dirs {
        remove_stale_pin_dir(&dir.path)?;
    }
    for name in &plan.clsact {
        let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", name])?, "qdisc dump")?;
        if !has_clsact(&qdiscs) {
            continue;
        }
        let ingress = dump_filters(name, "ingress")?;
        let egress = dump_filters(name, "egress")?;
        let empty = |dump: &Option<Value>| {
            dump.as_ref()
                .and_then(Value::as_array)
                .is_none_or(|entries| entries.is_empty())
        };
        if !empty(&ingress) || !empty(&egress) {
            // Foreign filters are not ours to remove. Leave the shared clsact
            // in place and continue reclaiming the owned qdiscs and IFB.
            continue;
        }
        tc(&["qdisc", "del", "dev", name, "clsact"])?;
    }

    ensure_recovery_owner_exited(evidence)?;
    let mut restored_roots = Vec::new();
    let mut original_root_unavailable = plan.original_root_unavailable.clone();
    for (dev, major) in &plan.roots {
        let original = evidence.roots.get(dev).and_then(|(stored_index, root)| {
            let current = nix::net::if_::if_nametoindex(dev.as_str()).ok()?;
            (*stored_index == 0 || *stored_index == current).then_some(root)
        });
        delete_owned_root(dev, *major, original)?;
        if evidence.roots.contains_key(dev) && original.is_some() {
            restored_roots.push(dev.clone());
        } else if !original_root_unavailable.contains(dev) {
            original_root_unavailable.push(dev.clone());
        }
    }
    if let Some((name, ifindex)) = &plan.ifb {
        remove_owned_ifb(name, *ifindex)?;
    }
    Ok(RecoveryOutcome {
        performed: !plan.is_empty(),
        degraded: !original_root_unavailable.is_empty(),
        restored_roots,
        original_root_unavailable,
    })
}

fn recover_stale_priority_resources(
    layout: &DeliveryLayout,
    ifb_name: &str,
    interfaces: &[String],
    agent_hook_handle: u32,
    evidence_path: &Path,
    journal_path: &Path,
    recovery_path: &Path,
) -> Result<RecoveryOutcome> {
    let evidence = read_recovery_evidence(evidence_path);
    let boot_id = current_boot_id();
    let netns = current_netns();
    if !recovery_scope_matches(&evidence, boot_id.as_deref(), netns.as_deref()) {
        // Different boot or network namespace: these objects are not provably
        // ours, so leave them untouched.
        return Ok(RecoveryOutcome::default());
    }
    ensure_recovery_owner_exited(&evidence)?;
    let resources = inspect_owned_priority_resources(
        layout,
        ifb_name,
        interfaces,
        agent_hook_handle,
        &evidence,
    )?;
    if resources.is_empty() {
        let Some(boot_id) = boot_id else {
            return Ok(RecoveryOutcome::default());
        };
        let Some(marker) = recovery_marker(recovery_path, &boot_id) else {
            return Ok(RecoveryOutcome::default());
        };
        if marker
            .get("journal_path")
            .and_then(Value::as_str)
            .is_some_and(|path| path != journal_path.display().to_string())
        {
            return Ok(RecoveryOutcome::default());
        }
        recover_resumed_ifb(&marker, ifb_name)?;
        remove_recovered_journal(journal_path)?;
        let unavailable = marker
            .get("original_root_unavailable")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        write_recovery_record(
            recovery_path,
            serde_json::json!({
                "kind":"client_priority_recovery",
                "schema_version":1,
                "phase":"completed",
                "resumed":true,
                "boot_id":boot_id,
                "owner":evidence.owner.clone(),
                "journal_removed":true,
                "degraded":!unavailable.as_array().is_none_or(Vec::is_empty),
                "degraded_reason":if unavailable.as_array().is_none_or(Vec::is_empty) { Value::Null } else { Value::String("original_root_unavailable".to_owned()) },
                "original_root_unavailable":unavailable,
            }),
        );
        return Ok(RecoveryOutcome {
            performed: true,
            degraded: !marker
                .get("original_root_unavailable")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty),
            ..RecoveryOutcome::default()
        });
    }
    let plan = plan_recovery(&resources, &evidence);
    write_recovery_record(
        recovery_path,
        serde_json::json!({
            "kind":"client_priority_recovery",
            "schema_version":1,
            "phase":"started",
            "boot_id":boot_id,
            "owner":evidence.owner.clone(),
            "journal_path":journal_path.display().to_string(),
            "filters":plan.filters.iter().map(|filter|serde_json::json!({
                "dev":filter.dev,"hook":filter.hook,"pref":filter.pref,"handle":handle_text(filter.handle),
            })).collect::<Vec<_>>(),
            "pin_dirs":plan.pin_dirs.iter().map(|dir|dir.path.display().to_string()).collect::<Vec<_>>(),
            "clsact":plan.clsact,
            "roots":plan.roots.iter().map(|(dev,major)|format!("{dev} {major:x}:")).collect::<Vec<_>>(),
            "ifb":plan.ifb.as_ref().map(|(name,_)|name),
            "ifb_ifindex":plan.ifb.as_ref().map(|(_,ifindex)|*ifindex),
            "ifb_mac":evidence.ifb_mac.clone(),
            "original_root_unavailable":plan.original_root_unavailable.clone(),
        }),
    );
    let outcome = execute_recovery_plan(&plan, &evidence)?;
    remove_recovered_journal(journal_path)?;
    write_recovery_record(
        recovery_path,
        serde_json::json!({
            "kind":"client_priority_recovery",
            "schema_version":1,
            "phase":"completed",
            "reclaimed":true,
            "boot_id":boot_id,
            "owner":evidence.owner.clone(),
            "filters":plan.filters.iter().map(|filter|serde_json::json!({
                "dev":filter.dev,"hook":filter.hook,"pref":filter.pref,"handle":handle_text(filter.handle),
            })).collect::<Vec<_>>(),
            "pin_dirs":plan.pin_dirs.iter().map(|dir|dir.path.display().to_string()).collect::<Vec<_>>(),
            "clsact":plan.clsact,
            "roots":plan.roots.iter().map(|(dev,major)|format!("{dev} {major:x}:")).collect::<Vec<_>>(),
            "ifb":plan.ifb.as_ref().map(|(name,_)|name),
            "restored_original_roots":outcome.restored_roots.clone(),
            "original_root_unavailable":outcome.original_root_unavailable.clone(),
            "degraded":outcome.degraded,
            "degraded_reason":outcome.degraded_reason(),
            "journal_removed":true,
        }),
    );
    if outcome.degraded {
        eprintln!(
            "Priority recovery is degraded (original_root_unavailable): {:?}",
            outcome.original_root_unavailable
        );
    }
    Ok(outcome)
}

fn current_boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn current_netns() -> Option<String> {
    fs::read_link("/proc/self/ns/net")
        .ok()
        .map(|path| path.display().to_string())
}

fn process_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Parse `comm` and field 22 (`starttime`) from `/proc/<pid>/stat`.
/// `comm` may contain spaces and parentheses, so split at the final `)`.
fn parse_proc_stat(text: &str) -> Option<(String, u64)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_owned();
    let starttime = text
        .get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()?;
    Some((comm, starttime))
}

fn process_starttime(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat(&text).map(|(_, starttime)| starttime)
}

fn current_process_owner() -> RecoveryOwner {
    let pid = std::process::id();
    RecoveryOwner {
        pid,
        comm: process_comm(pid),
        starttime: process_starttime(pid),
        boot_id: current_boot_id(),
        netns: current_netns(),
    }
}

/// A matching starttime proves the recorded process is still the one that owns
/// the resources. Without starttime evidence, a matching Agent command name is
/// treated as live and therefore fail-closed.
fn recovery_owner_is_live(owner: &RecoveryOwner) -> bool {
    if owner.pid == 0 {
        return false;
    }
    if let Some(expected) = owner.starttime {
        return process_starttime(owner.pid) == Some(expected);
    }
    match (process_comm(owner.pid), owner.comm.as_deref()) {
        (Some(actual), Some(expected)) => actual == expected.trim(),
        (Some(actual), None) => actual == AGENT_COMM,
        (None, _) => false,
    }
}

fn ensure_recovery_owner_exited(evidence: &RecoveryEvidence) -> Result<()> {
    let Some(owner) = &evidence.owner else {
        return Ok(());
    };
    if !owner.is_empty() && recovery_owner_is_live(owner) {
        bail!(
            "priority_runtime_owned_by_live_process: pid {} starttime {:?} is still running",
            owner.pid,
            owner.starttime
        );
    }
    Ok(())
}

/// Recovery is only allowed in the same boot and network namespace that wrote
/// the evidence. Anything else may belong to a different namespace or boot.
fn recovery_scope_matches(
    evidence: &RecoveryEvidence,
    boot_id: Option<&str>,
    netns: Option<&str>,
) -> bool {
    if let Some(expected) = &evidence.boot_id
        && boot_id != Some(expected.as_str())
    {
        return false;
    }
    if let Some(expected) = &evidence.netns
        && netns != Some(expected.as_str())
    {
        return false;
    }
    true
}

fn evidence_interface_ifindex_matches(evidence: &RecoveryEvidence, dev: &str) -> bool {
    let Some(expected) = evidence.interface_ifindices.get(dev) else {
        return true;
    };
    nix::net::if_::if_nametoindex(dev).is_ok_and(|current| current == *expected)
}

fn recovery_marker(path: &Path, boot_id: &str) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    let value = serde_json::from_slice::<Value>(&bytes).ok()?;
    (value.get("kind").and_then(Value::as_str) == Some("client_priority_recovery")
        && value.get("phase").and_then(Value::as_str) == Some("started")
        && value.get("boot_id").and_then(Value::as_str) == Some(boot_id))
    .then_some(value)
}

/// A crash between deleting the owned IFB root and the link itself leaves an
/// IFB without the 52: tree. The started marker is same-boot ownership proof,
/// so finish that one step only when the link is still an empty IFB.
fn recover_resumed_ifb(marker: &Value, ifb_name: &str) -> Result<()> {
    if marker.get("ifb").and_then(Value::as_str) != Some(ifb_name) {
        return Ok(());
    }
    let Ok(ifindex) = nix::net::if_::if_nametoindex(ifb_name) else {
        return Ok(());
    };
    if marker
        .get("ifb_ifindex")
        .and_then(Value::as_u64)
        .is_some_and(|stored| stored != u64::from(ifindex))
    {
        bail!(
            "priority_ifb_ownership_unknown: {ifb_name} index changed after interrupted recovery"
        );
    }
    let identity = link_identity(ifb_name)?;
    if identity
        .as_ref()
        .and_then(|identity| identity.kind.as_deref())
        != Some("ifb")
    {
        bail!("priority_ifb_ownership_unknown: {ifb_name} changed after interrupted recovery");
    }
    if let (Some(expected), Some(actual)) = (
        marker.get("ifb_mac").and_then(Value::as_str),
        identity
            .as_ref()
            .and_then(|identity| identity.address.as_deref()),
    ) && !actual.eq_ignore_ascii_case(expected)
    {
        bail!(
            "priority_ifb_ownership_changed: {ifb_name} address changed from {expected} to {actual}"
        );
    }
    let qdiscs = parse_json(
        &tc(&["-j", "qdisc", "show", "dev", ifb_name])?,
        "IFB qdisc dump",
    )?;
    let classes = parse_class_dump(
        &tc(&["-j", "class", "show", "dev", ifb_name])?,
        "IFB class dump",
    )?;
    if qdiscs.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("root").and_then(Value::as_bool) == Some(true)
                && entry.get("kind").and_then(Value::as_str) == Some("htb")
        })
    }) || classes
        .as_array()
        .is_some_and(|entries| !entries.is_empty())
    {
        bail!(
            "priority_ifb_ownership_unknown: {ifb_name} gained a qdisc after interrupted recovery"
        );
    }
    for hook in ["ingress", "egress"] {
        if let Some(dump) = dump_filters(ifb_name, hook)?
            && dump.as_array().is_some_and(|entries| !entries.is_empty())
        {
            bail!("priority_tc_conflict: foreign filter remains on resumed IFB {ifb_name} {hook}");
        }
    }
    ip(&["link", "del", ifb_name])?;
    Ok(())
}

fn remove_recovered_journal(journal_path: &Path) -> Result<()> {
    match fs::remove_file(journal_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "remove recovered priority journal {}",
                journal_path.display()
            )
        }),
    }
}

fn write_recovery_record(path: &Path, record: Value) {
    if let Err(error) = serde_json::to_vec_pretty(&record)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| atomic_write(path, &bytes))
    {
        eprintln!(
            "priority recovery evidence could not be recorded at {}: {error:#}",
            path.display()
        );
    }
}

fn link_is_tcx_on(link: &libbpf_rs::query::LinkInfo, ifindex: u32) -> bool {
    matches!(
        &link.info,
        libbpf_rs::query::LinkTypeInfo::Tcx(info) if info.ifindex == ifindex
    )
}

fn has_tcx_attachment(ifindex: u32) -> bool {
    libbpf_rs::query::LinkInfoIter::default().any(|link| link_is_tcx_on(&link, ifindex))
}

fn require_priority_transaction_recovered(policy_state_path: &Path) -> Result<()> {
    let priority_journal = policy_state_path.with_extension("priority-journal.json");
    if priority_journal.exists() {
        bail!(
            "priority_recovery_required: an unfinished priority transaction journal exists; recover and verify it before startup"
        );
    }
    Ok(())
}
fn has_clsact(qdiscs: &Value) -> bool {
    qdiscs.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry.get("kind").and_then(Value::as_str) == Some("clsact"))
    })
}

fn class_edge(output: &str, class: &str, parent: Option<&str>) -> bool {
    output.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.get(..3) == Some(&["class", "htb", class][..])
            && match parent {
                Some(parent) => fields.get(3..5) == Some(&["parent", parent][..]),
                None => fields.get(3) == Some(&"root"),
            }
    })
}

fn empty_priority_plan(plan: &PriorityPlan) -> PriorityPlan {
    let empty_tree = |tree: &QueueTree| {
        let mut tree = tree.clone();
        tree.clients.clear();
        tree.applications.clear();
        tree
    };
    PriorityPlan {
        upload: empty_tree(&plan.upload),
        downloads: plan.downloads.iter().map(empty_tree).collect(),
    }
}

impl PriorityRuntime {
    pub(super) fn prepare(
        agent: &AgentConfig,
        observation_interfaces: &[(String, i32)],
        maps: Arc<Mutex<PriorityMaps>>,
    ) -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("NETQMON_QOS_PRIORITY_CONFIG") else {
            return Ok(None);
        };
        if std::env::var_os("NETQMON_QOS_POC_CONFIG").is_some() {
            bail!(
                "priority_backend_conflict: compatibility PoC and client runtime cannot run together"
            );
        }
        if agent.attach_backend == AttachBackend::Tcx {
            bail!(
                "priority_order_unverified: the client runtime currently requires explicit netlink attachment"
            );
        }
        if super::hardware_flow_offload_status() != netqmon_protocol::v1::OffloadStatus::Disabled {
            bail!("priority_offload_unknown: hardware flow offload is enabled or unspecified");
        }
        let config: RuntimeConfig = serde_json::from_slice(&fs::read(path)?)?;
        let initial_namespace =
            fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")?;
        require_namespace_opt_in(initial_namespace, config.allow_initial_namespace)?;
        if !valid_runtime_name(&agent.interface, config.allow_initial_namespace)
            || !valid_runtime_name(&config.ifb, config.allow_initial_namespace)
        {
            bail!("priority_private_interface_required: runtime interface opt-in is missing");
        }
        if agent
            .interfaces
            .iter()
            .any(|name| !valid_runtime_name(name, config.allow_initial_namespace))
            || observation_interfaces
                .iter()
                .any(|(name, _)| !valid_runtime_name(name, config.allow_initial_namespace))
        {
            bail!("priority_private_interface_required: observation interface opt-in is missing");
        }
        if !config.output.is_absolute()
            || !config.output.starts_with("/tmp")
            || config
                .output
                .components()
                .any(|part| part == std::path::Component::ParentDir)
        {
            bail!("priority_evidence_path_invalid: output must be inside /tmp");
        }
        let priority = agent
            .attach_order
            .tc_priority
            .checked_add(1)
            .filter(|value| *value <= u16::MAX.into())
            .context(
                "priority_order_unverified: no netlink filter priority after the Agent hook",
            )?;
        let layout = priority_delivery::inspect(&agent.interface, &BTreeSet::new())
            .map_err(anyhow::Error::msg)?;
        if layout.egress_ports.is_empty()
            || layout.egress_ports.len() > 32
            || layout.ingress_ports != layout.egress_ports
            || layout.egress_ports.iter().any(|port| {
                !observation_interfaces
                    .iter()
                    .any(|(name, ifindex)| name == &port.name && *ifindex as u32 == port.ifindex)
            })
        {
            bail!("priority_delivery_unknown: Agent hooks do not cover every actual LAN port");
        }
        if agent.policy_interface_capacity_bps.is_empty()
            || layout
                .egress_ports
                .iter()
                .any(|port| !agent.policy_interface_capacity_bps.contains_key(&port.name))
        {
            bail!("priority_capacity_unknown: configure capacity for every actual LAN egress port");
        }
        let policy_state_path = Path::new(&agent.policy_state_path);
        let nft = parse_json(&run("nft", &["-j", "list", "ruleset"])?, "nft ruleset")?;
        if has_legacy_netqmon_mark_rule(&nft) {
            bail!("priority_conflict: legacy NetQmon mark rules remain in nftables");
        }
        if incompatible_nft(&nft) {
            bail!("priority_conflict: nft priority writer or flowtable/offload is present");
        }
        let evidence_path = config.output.with_extension("priority-runtime.json");
        let recovery = recover_stale_priority_resources(
            &layout,
            &config.ifb,
            &agent.interfaces,
            agent.attach_order.tc_handle,
            &evidence_path,
            &policy_state_path.with_extension("priority-journal.json"),
            &config.output.with_extension("priority-recovery.json"),
        )?;
        if recovery.performed {
            eprintln!(
                "Recovered stale NetQMon priority queues, filters or BPF pins before startup"
            );
        }
        if recovery.degraded {
            eprintln!(
                "Priority recovery degraded (original_root_unavailable): {:?}. The previous root qdisc was not restored.",
                recovery.original_root_unavailable
            );
        }
        require_priority_transaction_recovered(policy_state_path)?;
        for name in layout.egress_ports.iter().map(|port| &port.name) {
            let ifindex = layout
                .egress_ports
                .iter()
                .find(|port| &port.name == name)
                .map(|port| port.ifindex)
                .context("priority_attach_order_unverified: interface index is missing")?;
            if has_tcx_attachment(ifindex) {
                bail!("priority_attach_order_unverified: a TCX program is attached to {name}");
            }
            let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", name])?, "qdisc dump")?;
            let _ = capture_original_root(&qdiscs)?;
            if tc(&["filter", "show", "dev", name, "ingress"])?.trim() != ""
                || tc(&["filter", "show", "dev", name, "egress"])?.trim() != ""
            {
                bail!("priority_tc_conflict: foreign filter exists on {name}");
            }
        }
        if nix::net::if_::if_nametoindex(config.ifb.as_str()).is_ok() {
            bail!("priority_ifb_conflict: IFB name already exists");
        }
        let mut ports = Vec::new();
        for port in &layout.egress_ports {
            let qdiscs = parse_json(
                &tc(&["-j", "qdisc", "show", "dev", &port.name])?,
                "LAN qdisc",
            )?;
            let original_root = capture_original_root(&qdiscs)?;
            ports.push(OwnedPort {
                port: port.clone(),
                original_root,
            });
        }
        maps.lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?
            .configure_internal_networks(agent)?;
        let is_one_arm_router = super::network::discover(agent)
            .map(|ctx| ctx.snapshot.mode == crate::topology::TopologyMode::OneArmRouter)
            .unwrap_or(false);
        let ifb_ifindex = 0;
        let runtime = Self {
            agent: agent.clone(),
            output: config.output.with_extension("priority-runtime.json"),
            state_path: agent
                .policy_state_path
                .with_extension("priority-state.json"),
            journal_path: agent
                .policy_state_path
                .with_extension("priority-journal.json"),
            pin_dir: PathBuf::from(format!("/sys/fs/bpf/nqp-priority-{}", std::process::id())),
            pin_dir_owned: false,
            config,
            maps,
            layout,
            ports,
            ifb_ifindex,
            ifb_created: false,
            ifb_original_root: None,
            owned_roots: BTreeSet::new(),
            priority,
            matcher_attached: Vec::new(),
            ifb_observer_attached: false,
            clsact_created: BTreeSet::new(),
            active: None,
            active_plan: None,
            is_one_arm_router,
            force_reapply: false,
            emergency_disabled: false,
            shutdown_done: false,
        };
        // Record process identity, boot/netns and the captured original roots
        // before any qdisc/filter/pin is created. A SIGKILL during setup then
        // still leaves ownership evidence behind.
        if let Err(error) = runtime.write_evidence("prepared") {
            eprintln!("priority runtime evidence could not be written at startup: {error:#}");
        }
        Ok(Some(runtime))
    }

    pub(crate) fn should_handle(&self, snapshot: &PolicyWireFrame) -> bool {
        self.active.is_some() || matches!(snapshot, PolicyWireFrame::PolicySnapshot { .. })
    }

    pub(crate) fn has_enabled_application_flow_policy(&self) -> bool {
        self.active.as_ref().is_some_and(|state| {
            crate::policy::snapshot_has_enabled_application_verdicts(&state.snapshot)
        })
    }

    pub(crate) fn metrics_snapshot(
        &self,
    ) -> Option<(PolicyWireFrame, Result<Vec<PriorityClassMetrics>, String>)> {
        let active = self.active.as_ref()?;
        if self.emergency_disabled {
            return None;
        }
        let result = self.read_policy_class_metrics(active);
        Some((active.snapshot.clone(), result))
    }

    fn read_policy_class_metrics(
        &self,
        active: &PriorityState,
    ) -> Result<Vec<PriorityClassMetrics>, String> {
        let plan = self
            .active_plan
            .as_ref()
            .ok_or_else(|| "priority_metrics_plan_unavailable".to_owned())?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .ok_or_else(|| "priority_metrics_clock_unavailable".to_owned())?;
        let selection =
            PrioritySelection::from_snapshot(&active.snapshot, &active.gateway_id, Some(now_ms))?;
        let mut metrics = Vec::new();
        let trees = std::iter::once((&plan.upload, true))
            .chain(plan.downloads.iter().map(|tree| (tree, false)));
        for (tree, upload) in trees {
            let output = tc(&["-s", "class", "show", "dev", &tree.port.name])
                .map_err(|error| format!("priority_metrics_tc_read_failed: {error:#}"))?;
            let counters = parse_priority_class_metrics(&output);
            for client in &tree.clients {
                let Some(rates) = selection.totals.get(&client.mac) else {
                    continue;
                };
                let classid = format!("{:x}:{:x}", tree.major, client.default_minor);
                let value = counters.get(&classid).copied().unwrap_or_default();
                for policy_id in &rates.policy_ids {
                    metrics.push(PriorityClassMetrics {
                        policy_id: policy_id.clone(),
                        mac: client.mac.clone(),
                        upload,
                        interface: tree.port.name.clone(),
                        bytes: value.bytes,
                        packets: value.packets,
                        drops: value.drops,
                        overlimits: value.overlimits,
                    });
                }
            }
            for application in &tree.applications {
                if !selection.application_limits.iter().any(|selected| {
                    selected.policy_id == application.policy_id
                        && selected.mac.eq_ignore_ascii_case(&application.mac)
                }) {
                    continue;
                }
                let classid = format!("{:x}:{:x}", tree.major, application.minor);
                let value = counters.get(&classid).copied().unwrap_or_default();
                metrics.push(PriorityClassMetrics {
                    policy_id: application.policy_id.clone(),
                    mac: application.mac.clone(),
                    upload,
                    interface: tree.port.name.clone(),
                    bytes: value.bytes,
                    packets: value.packets,
                    drops: value.drops,
                    overlimits: value.overlimits,
                });
            }
        }
        Ok(metrics)
    }

    pub(crate) fn client_delivery_ifindex(&self, client_mac: &str) -> Option<u32> {
        self.layout
            .client_delivery
            .get(&client_mac.to_ascii_lowercase())
            .map(|port| port.ifindex)
            .or_else(|| {
                (!self.layout.bridge && self.layout.egress_ports.len() == 1)
                    .then(|| self.layout.egress_ports[0].ifindex)
            })
    }

    pub(crate) fn client_delivery_map(&self) -> (BTreeMap<String, i32>, Option<i32>) {
        let map = self
            .layout
            .client_delivery
            .iter()
            .map(|(mac, port)| (mac.clone(), port.ifindex as i32))
            .collect();
        let single_port_fallback = (!self.layout.bridge && self.layout.egress_ports.len() == 1)
            .then(|| self.layout.egress_ports[0].ifindex as i32);
        (map, single_port_fallback)
    }

    pub(crate) fn client_block_capability(&self) -> PolicyCapability {
        let tc_hook_coverage_complete = !self.is_one_arm_router
            && !self.layout.ingress_ports.is_empty()
            && self.layout.ingress_ports == self.layout.egress_ports;
        if tc_hook_coverage_complete {
            PolicyCapability::Supported
        } else {
            PolicyCapability::Degraded
        }
    }

    pub(crate) fn controls_flow_hook(&self, hook: u8, ifindex: u32) -> bool {
        if ifindex == 0 {
            return false;
        }
        match hook {
            1 => self
                .layout
                .ingress_ports
                .iter()
                .any(|port| port.ifindex == ifindex),
            2 => self
                .layout
                .egress_ports
                .iter()
                .any(|port| port.ifindex == ifindex),
            _ => false,
        }
    }

    /// Return the class leaf only when the exact FlowCommand names an active
    /// application policy for this client and the alias is on that direction's
    /// client-side shaping hook. Proxy-created upstream connections therefore
    /// cannot inherit a source flow's application class.
    pub(crate) fn application_classid(
        &self,
        policy_ids: &[String],
        client_mac: &str,
        upload: bool,
        ifindex: u32,
    ) -> Option<u32> {
        let active = self.active.as_ref()?;
        if self.emergency_disabled {
            return None;
        }
        if upload {
            if !self
                .layout
                .ingress_ports
                .iter()
                .any(|port| port.ifindex == ifindex)
            {
                return None;
            }
        } else if self
            .layout
            .client_delivery
            .get(&client_mac.to_ascii_lowercase())
            .is_none_or(|port| port.ifindex != ifindex)
        {
            return None;
        }
        active
            .application_classes
            .iter()
            .filter(|application| {
                application.mac.eq_ignore_ascii_case(client_mac)
                    && policy_ids
                        .iter()
                        .any(|policy_id| policy_id == &application.policy_id)
                    && if upload {
                        application.upload_bps.is_some()
                    } else {
                        application.download_bps.is_some()
                    }
            })
            .min_by(|a, b| {
                let a_rate = if upload { a.upload_bps } else { a.download_bps };
                let b_rate = if upload { b.upload_bps } else { b.download_bps };
                a_rate
                    .cmp(&b_rate)
                    .then_with(|| a.policy_id.cmp(&b.policy_id))
            })
            .and_then(|application| {
                let major = if upload {
                    classid::UPLOAD_MAJOR
                } else {
                    classid::DOWNLOAD_MAJOR
                };
                classid::ClassId::leaf(major, application.minor)
                    .ok()
                    .map(classid::ClassId::raw)
            })
    }

    pub(crate) fn application_policy_references_valid(
        &self,
        controller_epoch: &str,
        config_revision: u64,
        policy_ids: &[String],
        client_mac: &str,
        verdict: netqmon_protocol::policy::FlowVerdict,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> bool {
        use netqmon_protocol::policy::{FlowVerdict, PolicyActionKind};

        let Some(active) = self.active.as_ref() else {
            return false;
        };
        let Some((gateway, epoch, revision, _, _)) = active.snapshot.snapshot_identity() else {
            return false;
        };
        let PolicyWireFrame::PolicySnapshot {
            policies,
            schedule_intervals,
            valid_until_ms,
            ..
        } = &active.snapshot
        else {
            return false;
        };
        !self.emergency_disabled
            && gateway == active.gateway_id
            && epoch == controller_epoch
            && revision == config_revision
            && issued_at_ms < expires_at_ms
            && expires_at_ms <= active.expires_at_ms
            && expires_at_ms <= *valid_until_ms
            && !policy_ids.is_empty()
            && policy_ids.iter().all(|policy_id| {
                policies.iter().any(|policy| {
                    policy.id == *policy_id
                        && policy.spec.enabled
                        && (!policy.spec.selectors.applications.is_empty()
                            || !policy.spec.selectors.categories.is_empty())
                        && policy
                            .spec
                            .selectors
                            .clients
                            .iter()
                            .any(|mac| mac.eq_ignore_ascii_case(client_mac))
                        && crate::policy::schedule::evaluate(
                            policy,
                            schedule_intervals,
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .ok()
                                .and_then(|duration| i64::try_from(duration.as_millis()).ok()),
                            *valid_until_ms,
                        ) == crate::policy::schedule::ScheduleState::Active
                        && match verdict {
                            FlowVerdict::Shape => {
                                policy.spec.action.kind == PolicyActionKind::Limit
                                    && active.application_classes.iter().any(|application| {
                                        application.policy_id == *policy_id
                                            && application.mac.eq_ignore_ascii_case(client_mac)
                                    })
                            }
                            FlowVerdict::Block => {
                                policy.spec.action.kind == PolicyActionKind::Block
                            }
                            FlowVerdict::Allow => {
                                policy.spec.action.kind == PolicyActionKind::Allow
                            }
                        }
                })
            })
    }

    pub(crate) fn endpoint_block_expiry(
        &self,
        policy_ids: &[String],
        client_mac: &str,
        issued_at_ms: i64,
        now_ms: i64,
    ) -> Option<i64> {
        let active = self.active.as_ref()?;
        if self.emergency_disabled {
            return None;
        }
        crate::policy::endpoint_block::expires_at_ms(
            &active.snapshot,
            policy_ids,
            client_mac,
            issued_at_ms,
            now_ms,
        )
        .map(|expiry| expiry.min(active.expires_at_ms))
        .filter(|expiry| *expiry > now_ms)
    }

    pub(crate) fn flow_revision_matches(&self, controller_epoch: &str, revision: u64) -> bool {
        self.active
            .as_ref()
            .and_then(|state| state.snapshot.snapshot_identity())
            .is_some_and(|(_, epoch, current_revision, _, _)| {
                !self.emergency_disabled
                    && epoch == controller_epoch
                    && current_revision == revision
            })
    }

    pub(crate) fn emergency_disable(&mut self) -> Result<()> {
        if self.emergency_disabled {
            return Ok(());
        }
        self.maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?
            .publish_empty()?;
        self.force_reapply = true;
        self.emergency_disabled = true;
        self.write_evidence("emergency-disabled")
    }

    pub(crate) fn activate<M: libbpf_rs::MapCore>(
        &mut self,
        matcher: &ProgramMut<'_>,
        ifb_observer: &ProgramMut<'_>,
        observed_ifindexes: &M,
    ) -> Result<()> {
        if let Err(error) = self
            .create_owned_queues()
            .and_then(|()| self.verify_owned_queues())
            .and_then(|()| self.configure_classifier_maps())
        {
            return match self.rollback_prepare() {
                Ok(()) => Err(error).context("priority activation setup failed"),
                Err(rollback) => Err(error).context(format!(
                    "priority activation setup failed; partial setup cleanup failed: {rollback:#}"
                )),
            };
        }
        let matcher_handle = match ProgramHandle::try_from(matcher) {
            Ok(handle) => handle,
            Err(error) => {
                let error = anyhow!(error).context("get priority matcher program handle");
                return match self.rollback_prepare() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(error).context(format!(
                        "matcher handle setup failed; queue rollback also failed: {rollback:#}"
                    )),
                };
            }
        };
        let observer_handle = match ProgramHandle::try_from(ifb_observer) {
            Ok(handle) => handle,
            Err(error) => {
                let error = anyhow!(error).context("get priority IFB observer program handle");
                return match self.rollback_prepare() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(error).context(format!(
                        "observer handle setup failed; queue rollback also failed: {rollback:#}"
                    )),
                };
            }
        };
        if self.pin_dir.exists() {
            let error = anyhow!(
                "priority_pin_directory_exists_unverified: refusing to remove or reuse {}",
                self.pin_dir.display()
            );
            return match self.rollback_prepare() {
                Ok(()) => Err(error),
                Err(rollback) => Err(error).context(format!(
                    "priority pin path is unverified; queue rollback also failed: {rollback:#}"
                )),
            };
        }
        if let Err(error) =
            fs::create_dir(&self.pin_dir).context("create priority BPF pin directory")
        {
            return match self.rollback_prepare() {
                Ok(()) => Err(error),
                Err(rollback) => Err(error).context(format!(
                    "priority pin directory creation failed; queue rollback also failed: {rollback:#}"
                )),
            };
        }
        self.pin_dir_owned = true;
        let matcher_pin = self.pin_dir.join("matcher");
        let observer_pin = self.pin_dir.join("ifb-observer");
        let activation = (|| -> Result<()> {
            matcher_handle.pin(&matcher_pin)?;
            observer_handle.pin(&observer_pin)?;
            for port in self.layout.ingress_ports.clone() {
                self.ensure_clsact(&port.name)?;
                let priority = self.priority.to_string();
                tc(&[
                    "filter",
                    "add",
                    "dev",
                    &port.name,
                    "ingress",
                    "protocol",
                    "all",
                    "prio",
                    &priority,
                    "handle",
                    MATCHER_HANDLE,
                    "bpf",
                    "pinned",
                    matcher_pin.to_str().context("invalid matcher pin path")?,
                    "action",
                    "mirred",
                    "egress",
                    "redirect",
                    "dev",
                    &self.config.ifb,
                ])
                .context("attach priority classifier and IFB redirect")?;
                self.matcher_attached.push(port);
            }
            self.ensure_clsact(&self.config.ifb.clone())?;
            let ifb_priority = self
                .agent
                .attach_order
                .tc_priority
                .checked_add(2)
                .filter(|value| *value <= u16::MAX.into())
                .context("priority_order_unverified: no IFB observer priority")?
                .to_string();
            tc(&[
                "filter",
                "add",
                "dev",
                &self.config.ifb,
                "egress",
                "protocol",
                "all",
                "prio",
                &ifb_priority,
                "handle",
                IFB_OBSERVER_HANDLE,
                "bpf",
                "da",
                "pinned",
                observer_pin
                    .to_str()
                    .context("invalid IFB observer pin path")?,
            ])?;
            self.ifb_observer_attached = true;
            observed_ifindexes.update(&self.ifb_ifindex.to_ne_bytes(), &[1], MapFlags::ANY)?;
            self.write_evidence("active")?;
            Ok(())
        })();
        if let Err(error) = activation {
            return match self.rollback_activation() {
                Ok(()) => {
                    Err(error).context("priority runtime activation failed and was rolled back")
                }
                Err(rollback) => Err(error).context(format!(
                    "priority runtime activation failed; rollback incomplete: {rollback:#}"
                )),
            };
        }
        eprintln!(
            "QoS priority client runtime active on IFB {} and {} LAN egress ports",
            self.config.ifb,
            self.layout.egress_ports.len()
        );
        Ok(())
    }

    fn ensure_clsact(&mut self, name: &str) -> Result<()> {
        let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", name])?, "qdisc dump")?;
        if !has_clsact(&qdiscs) {
            tc(&["qdisc", "add", "dev", name, "clsact"])?;
            self.clsact_created.insert(name.to_owned());
        }
        Ok(())
    }

    fn create_owned_queues(&mut self) -> Result<()> {
        ip(&["link", "add", &self.config.ifb, "type", "ifb"])?;
        self.ifb_created = true;
        self.ifb_ifindex = nix::net::if_::if_nametoindex(self.config.ifb.as_str())?;
        let ifb_ipv6 = PathBuf::from(format!(
            "/proc/sys/net/ipv6/conf/{}/disable_ipv6",
            self.config.ifb
        ));
        if ifb_ipv6.exists() {
            fs::write(&ifb_ipv6, b"1\n")?;
        }
        ip(&["link", "set", &self.config.ifb, "up"])?;
        let ifb_qdiscs = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", &self.config.ifb])?,
            "IFB qdisc",
        )?;
        let ifb_original_root = capture_original_root(&ifb_qdiscs)?;
        self.ifb_original_root = Some(ifb_original_root.clone());
        ensure_no_hw_tc_offload(&self.config.ifb, true)?;
        self.add_root(
            &self.config.ifb.clone(),
            classid::UPLOAD_MAJOR,
            &ifb_original_root,
        )?;
        for port in self.ports.clone() {
            let name = port.port.name.clone();
            let current = parse_json(
                &tc(&["-j", "qdisc", "show", "dev", &name])?,
                "LAN qdisc before ownership",
            )?;
            if capture_original_root(&current)? != port.original_root {
                bail!("priority_qdisc_conflict: {name} queue tree changed after prepare");
            }
            ensure_no_hw_tc_offload(&name, false)?;
            self.add_root(&name, classid::DOWNLOAD_MAJOR, &port.original_root)?;
        }
        Ok(())
    }

    fn add_root(
        &mut self,
        name: &str,
        major: u32,
        expected_original: &OriginalQueueRoot,
    ) -> Result<()> {
        let current = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", name])?,
            "qdisc before replacement",
        )?;
        if capture_original_root(&current)? != *expected_original {
            bail!("priority_qdisc_conflict: {name} queue tree changed before replacement");
        }
        let root = format!("{major:x}:");
        tc(&[
            "qdisc", "replace", "dev", name, "root", "handle", &root, "htb", "default", "fffe",
        ])?;
        self.owned_roots.insert((name.to_owned(), major));
        self.install_tree_base(name, major)?;
        Ok(())
    }

    fn install_tree_base(&self, name: &str, major: u32) -> Result<()> {
        let root = format!("{major:x}:");
        let parent = format!("{major:x}:1");
        let bypass = format!("{major:x}:fffe");
        for (class, ancestor, rate) in [
            (parent.as_str(), root.as_str(), STRUCTURAL_CAPACITY_BPS),
            (bypass.as_str(), parent.as_str(), STRUCTURAL_CAPACITY_BPS),
        ] {
            tc(&[
                "class",
                "add",
                "dev",
                name,
                "parent",
                ancestor,
                "classid",
                class,
                "htb",
                "rate",
                &format!("{rate}bit"),
                "ceil",
                &format!("{rate}bit"),
            ])?;
        }
        self.ensure_leaf_qdisc(name, major, classid::BYPASS_MINOR)?;
        let classes = tc(&["class", "show", "dev", name])?;
        if !class_edge(&classes, &format!("{major:x}:1"), None)
            || !class_edge(
                &classes,
                &format!("{major:x}:fffe"),
                Some(&format!("{major:x}:1")),
            )
        {
            bail!(
                "priority_classid_invalid: {name} root, parent or default bypass class failed readback"
            );
        }
        Ok(())
    }

    fn ensure_leaf_qdisc(&self, dev: &str, major: u32, minor: u32) -> Result<()> {
        let parent = format!("{major:x}:{minor:x}");
        // Use the full minor so application qdisc handles remain unique across
        // client slots whose application classids share a low byte.
        let handle = format!("{minor:x}:");
        let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")?;
        let existing = qdiscs.as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.get("parent").and_then(Value::as_str) == Some(parent.as_str())
                    && entry.get("kind").and_then(Value::as_str) == Some("fq_codel")
            })
        });
        if !existing {
            tc(&[
                "qdisc", "add", "dev", dev, "parent", &parent, "handle", &handle, "fq_codel",
            ])?;
        }
        Ok(())
    }

    fn configure_classifier_maps(&mut self) -> Result<()> {
        let maps = self
            .maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?;
        let configured_ifb = maps.ifb.lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?;
        if configured_ifb.as_deref() != Some(&[0, 0, 0, 0])
            || maps.ingress_ports.keys().next().is_some()
            || maps.roots.keys().next().is_some()
        {
            bail!(
                "priority_map_ownership_changed: classifier config maps are not at their idle values"
            );
        }
        maps.ifb.update(
            &0_u32.to_ne_bytes(),
            &self.ifb_ifindex.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        let mut inserted_ingress: Vec<u32> = Vec::new();
        let mut inserted_roots: Vec<u32> = Vec::new();
        for port in &self.layout.ingress_ports {
            if let Err(error) =
                maps.ingress_ports
                    .update(&port.ifindex.to_ne_bytes(), &[1], MapFlags::NO_EXIST)
            {
                for index in inserted_ingress {
                    let _ = maps.ingress_ports.delete(&index.to_ne_bytes());
                }
                let _ = maps
                    .ifb
                    .update(&0_u32.to_ne_bytes(), &0_u32.to_ne_bytes(), MapFlags::ANY);
                return Err(error.into());
            }
            inserted_ingress.push(port.ifindex);
        }
        for port in &self.layout.egress_ports {
            if let Err(error) =
                maps.roots
                    .update(&port.ifindex.to_ne_bytes(), &[1], MapFlags::NO_EXIST)
            {
                for index in inserted_roots {
                    let _ = maps.roots.delete(&index.to_ne_bytes());
                }
                for index in inserted_ingress {
                    let _ = maps.ingress_ports.delete(&index.to_ne_bytes());
                }
                let _ = maps
                    .ifb
                    .update(&0_u32.to_ne_bytes(), &0_u32.to_ne_bytes(), MapFlags::ANY);
                return Err(error.into());
            }
            inserted_roots.push(port.ifindex);
        }
        if maps
            .ifb
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
            .as_deref()
            != Some(&self.ifb_ifindex.to_ne_bytes())
            || inserted_ingress.len() != self.layout.ingress_ports.len()
            || inserted_roots.len() != self.layout.egress_ports.len()
        {
            bail!("priority_map_readback_failed: classifier ports or IFB");
        }
        Ok(())
    }

    fn verify_owned_queues(&self) -> Result<()> {
        for (name, major) in std::iter::once((self.config.ifb.as_str(), classid::UPLOAD_MAJOR))
            .chain(
                self.ports
                    .iter()
                    .map(|port| (port.port.name.as_str(), classid::DOWNLOAD_MAJOR)),
            )
        {
            let qdiscs = parse_json(
                &tc(&["-j", "qdisc", "show", "dev", name])?,
                "owned qdisc dump",
            )?;
            if !qdiscs.as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["kind"] == "htb"
                        && entry["handle"] == format!("{major:x}:")
                        && entry["root"] == true
                })
            }) {
                bail!("priority_qdisc_readback_failed: {name} root handle {major:x}:");
            }
            let output = tc(&["class", "show", "dev", name])?;
            if !class_edge(&output, &format!("{major:x}:1"), None)
                || !class_edge(
                    &output,
                    &format!("{major:x}:fffe"),
                    Some(&format!("{major:x}:1")),
                )
            {
                bail!("priority_classid_invalid: {name} lacks the verified default bypass leaf");
            }
        }
        Ok(())
    }

    fn rollback_prepare(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = self.clear_classifier_maps() {
            errors.push(error.to_string());
        }
        for (name, major) in self.owned_roots.clone().into_iter().rev() {
            let noqueue = OriginalQueueRoot::noqueue();
            let original = if major == classid::DOWNLOAD_MAJOR {
                self.ports
                    .iter()
                    .find(|port| port.port.name == name)
                    .map(|port| &port.original_root)
                    .unwrap_or(&noqueue)
            } else {
                self.ifb_original_root.as_ref().unwrap_or(&noqueue)
            };
            if let Err(error) = self.remove_owned_root(&name, major, original) {
                errors.push(error.to_string());
            }
        }
        if self.ifb_created
            && nix::net::if_::if_nametoindex(self.config.ifb.as_str()).ok()
                == Some(self.ifb_ifindex)
        {
            if let Err(error) = ip(&["link", "del", &self.config.ifb]) {
                errors.push(error.to_string());
            } else {
                self.ifb_created = false;
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("; "))
        }
    }

    fn rollback_activation(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = self.detach_matchers() {
            errors.push(format!("detach priority matcher filters: {error:#}"));
        }
        if let Err(error) = self.detach_ifb_observer() {
            errors.push(format!("detach priority IFB observer: {error:#}"));
        }
        if self.matcher_attached.is_empty() && !self.ifb_observer_attached {
            if let Err(error) = self.cleanup_pins() {
                errors.push(format!("unpin priority BPF programs: {error:#}"));
            }
        }
        if errors.is_empty() {
            for name in self.clsact_created.clone() {
                let ingress = match tc(&["filter", "show", "dev", &name, "ingress"]) {
                    Ok(filters) => filters,
                    Err(error) => {
                        errors.push(format!(
                            "priority_clsact_ownership_unverified: could not inspect {name} ingress filters: {error:#}"
                        ));
                        continue;
                    }
                };
                let egress = match tc(&["filter", "show", "dev", &name, "egress"]) {
                    Ok(filters) => filters,
                    Err(error) => {
                        errors.push(format!(
                            "priority_clsact_ownership_unverified: could not inspect {name} egress filters: {error:#}"
                        ));
                        continue;
                    }
                };
                if ingress.trim().is_empty() && egress.trim().is_empty() {
                    match tc(&["qdisc", "del", "dev", &name, "clsact"]) {
                        Ok(_) => {
                            self.clsact_created.remove(&name);
                        }
                        Err(error) => errors.push(format!(
                            "priority_clsact_cleanup_failed: could not remove owned clsact on {name}: {error:#}"
                        )),
                    }
                } else {
                    errors.push(format!(
                        "priority_clsact_ownership_changed: left {name} in place because filters remain"
                    ));
                }
            }
        }
        if errors.is_empty()
            && let Err(error) = self.rollback_prepare()
        {
            errors.push(format!("rollback priority queues and IFB: {error:#}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("; "))
        }
    }

    fn detach_ifb_observer(&mut self) -> Result<()> {
        if !self.ifb_observer_attached {
            return Ok(());
        }
        let priority = self
            .agent
            .attach_order
            .tc_priority
            .checked_add(2)
            .filter(|value| *value <= u16::MAX.into())
            .context("priority_order_unverified: no IFB observer priority")?
            .to_string();
        tc(&[
            "filter",
            "del",
            "dev",
            &self.config.ifb,
            "egress",
            "prio",
            &priority,
            "handle",
            IFB_OBSERVER_HANDLE,
            "bpf",
        ])?;
        self.ifb_observer_attached = false;
        Ok(())
    }

    fn cleanup_pins(&mut self) -> Result<()> {
        if !self.pin_dir_owned {
            return Ok(());
        }
        if !self.matcher_attached.is_empty() || self.ifb_observer_attached {
            bail!("priority_pin_still_referenced: TC filter attachments remain");
        }
        for entry in fs::read_dir(&self.pin_dir).context("read owned priority BPF pin directory")? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name != "matcher" && name != "ifb-observer" {
                bail!(
                    "priority_pin_directory_contains_unowned_entry: {}",
                    entry.path().display()
                );
            }
        }
        for name in ["matcher", "ifb-observer"] {
            let path = self.pin_dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("unpin priority BPF program {}", path.display()));
                }
            }
        }
        match fs::remove_dir(&self.pin_dir) {
            Ok(()) => self.pin_dir_owned = false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.pin_dir_owned = false;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "remove priority BPF pin directory {}",
                        self.pin_dir.display()
                    )
                });
            }
        }
        Ok(())
    }

    pub(crate) fn apply_snapshot(
        &mut self,
        snapshot: &PolicyWireFrame,
        gateway: &str,
        boot_id: &str,
        flow_bpf_ready: bool,
    ) -> PolicyWireFrame {
        match self.apply(snapshot, gateway) {
            Ok(mut selection) => {
                let client_block_degraded = !selection.blocked_macs.is_empty()
                    && self.client_block_capability() != PolicyCapability::Supported;
                if client_block_degraded {
                    for result in &mut selection.results {
                        let is_client_block = match snapshot {
                            PolicyWireFrame::PolicySnapshot { policies, .. } => policies
                                .iter()
                                .find(|policy| policy.id == result.policy_id)
                                .is_some_and(|policy| {
                                    policy.spec.enabled
                                        && policy.spec.action.kind
                                            == netqmon_protocol::policy::PolicyActionKind::Block
                                        && policy.spec.network.scope == "internet"
                                        && !policy.spec.selectors.clients.is_empty()
                                        && policy.spec.selectors.applications.is_empty()
                                        && policy.spec.selectors.categories.is_empty()
                                }),
                            _ => false,
                        };
                        if is_client_block && result.status == PolicyResultStatus::Applied {
                            result.status = PolicyResultStatus::Degraded;
                            result.reason_code =
                                Some("priority_client_block_path_degraded".to_owned());
                            result.message = Some(
                                "client packets are dropped on observed LAN ingress and delivery egress; traffic outside those Agent hooks is not covered".to_owned(),
                            );
                        }
                    }
                }
                crate::policy::executor::priority_policy_ack(
                    snapshot,
                    boot_id,
                    crate::policy::executor::priority_runtime_capabilities(
                        flow_bpf_ready,
                        if client_block_degraded {
                            PolicyCapability::Degraded
                        } else {
                            PolicyCapability::Supported
                        },
                    ),
                    if selection.results.iter().any(|result| {
                        matches!(
                            result.status,
                            PolicyResultStatus::Failed
                                | PolicyResultStatus::Unsupported
                                | PolicyResultStatus::Degraded
                        )
                    }) {
                        PolicyAckStatus::Partial
                    } else {
                        PolicyAckStatus::Applied
                    },
                    selection.results,
                )
            }
            Err(error) => {
                crate::policy::executor::priority_failure_ack(snapshot, boot_id, &error.to_string())
            }
        }
    }

    fn apply(&mut self, snapshot: &PolicyWireFrame, gateway: &str) -> Result<PrioritySelection> {
        if self.shutdown_done {
            bail!("priority_runtime_stopped");
        }
        if Path::new(&self.agent.policy_disabled_path).exists() {
            self.emergency_disable()?;
            bail!("emergency_disabled: local emergency policy disable marker is present");
        }
        self.emergency_disabled = false;
        let identity = snapshot
            .snapshot_identity()
            .context("priority_snapshot_required")?;
        if identity.0 != gateway {
            bail!("priority_gateway_mismatch");
        }
        let old = self.load_state(gateway)?;
        if let Some(old) = &old {
            if identity.2 < old.config_revision
                || (identity.1 == old.controller_epoch
                    && (identity.2 < old.config_revision
                        || (identity.2 == old.config_revision
                            && identity.3 < old.bundle_generation)))
            {
                bail!("priority_stale_snapshot");
            }
            if identity.1 == old.controller_epoch
                && identity.2 == old.config_revision
                && identity.3 == old.bundle_generation
                && identity.4 != old.checksum
            {
                bail!("priority_snapshot_identity_conflict");
            }
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok());
        let selection = PrioritySelection::from_snapshot(snapshot, gateway, now_ms)
            .map_err(anyhow::Error::msg)?;
        if !selection.blocked_macs.is_empty()
            && !self
                .maps
                .lock()
                .map_err(|_| anyhow!("priority map lock poisoned"))?
                .client_block_networks_ready()
        {
            bail!(
                "priority_client_block_networks_unknown: client Internet blocks require configured IPv4 and IPv6 LAN, routed-LAN or tunnel prefixes"
            );
        }
        let now = now_ms.ok_or_else(|| anyhow!("clock_invalid"))?;
        if let Some(old) = &old
            && old.controller_epoch == identity.1
            && old.config_revision == identity.2
            && old.bundle_generation == identity.3
            && old.checksum == identity.4
            && now < old.expires_at_ms
            && !self.force_reapply
        {
            self.active = Some(old.clone());
            return Ok(selection);
        }
        let selected = selection.clients.clone();
        let previous_leases = old
            .as_ref()
            .map_or(&[][..], |state| state.leases.as_slice());
        let leases =
            priority_slots::allocate(&selected, previous_leases).map_err(anyhow::Error::msg)?;
        let active_leases = leases
            .iter()
            .filter(|lease| lease.active)
            .cloned()
            .collect::<Vec<_>>();
        let application_classes = allocate_application_classes(&selection, &active_leases)?;
        let application_budgets = application_classes
            .iter()
            .map(|application| ApplicationBudget {
                lease: ClientSlotLease {
                    mac: application.mac.clone(),
                    slot: application.slot,
                    active: true,
                },
                policy_id: application.policy_id.clone(),
                minor: application.minor,
                upload_bps: application.upload_bps,
                download_bps: application.download_bps,
            })
            .collect::<Vec<_>>();
        let layout = priority_delivery::inspect(&self.agent.interface, &selected)
            .map_err(anyhow::Error::msg)?;
        if layout.egress_ports != self.layout.egress_ports
            || layout.ingress_ports != self.layout.ingress_ports
        {
            bail!("priority_delivery_unknown: LAN membership changed while QoS is active");
        }
        let capacities = self
            .ports
            .iter()
            .map(|owned| {
                self.agent
                    .policy_interface_capacity_bps
                    .get(&owned.port.name)
                    .copied()
                    .map(|capacity| (owned.port.ifindex, capacity))
                    .ok_or_else(|| anyhow!("priority_capacity_unknown: {}", owned.port.name))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let budgets = active_leases
            .iter()
            .filter_map(|lease| {
                selection.totals.get(&lease.mac).map(|rates| ClientBudget {
                    lease: lease.clone(),
                    upload_bps: rates.upload_bps,
                    download_bps: rates.download_bps,
                })
            })
            .collect::<Vec<_>>();
        let plan = PriorityPlan::build(
            &layout,
            QueuePort {
                name: self.config.ifb.clone(),
                ifindex: self.ifb_ifindex,
            },
            STRUCTURAL_CAPACITY_BPS,
            &capacities,
            &budgets,
            &application_budgets,
        )
        .map_err(anyhow::Error::msg)?;
        let old_generation = old.as_ref().map_or(0, |state| state.generation);
        let generation = old_generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or_else(|| anyhow!("priority_generation_exhausted"))?;
        let valid_until_ms = match snapshot {
            PolicyWireFrame::PolicySnapshot { valid_until_ms, .. } => *valid_until_ms,
            _ => 0,
        };
        let expiry_ms = selection
            .next_transition_ms
            .map_or(valid_until_ms, |transition| transition.min(valid_until_ms));
        let remaining_ms = expiry_ms.saturating_sub(now);
        let expires_ns = super::monotonic_ns()
            .checked_add(u64::try_from(remaining_ms.max(1))?.saturating_mul(1_000_000))
            .ok_or_else(|| anyhow!("priority_expiry_overflow"))?;
        let mut map_entries = Vec::new();
        for lease in &active_leases {
            let rates = selection.totals.get(&lease.mac);
            let has_application_download = application_classes.iter().any(|application| {
                application.mac == lease.mac && application.download_bps.is_some()
            });
            let delivery_ifindex = if rates.is_some_and(|rates| rates.download_bps.is_some())
                || has_application_download
            {
                layout
                    .client_delivery
                    .get(&lease.mac)
                    .ok_or_else(|| anyhow!("priority_delivery_unknown: missing client port"))?
                    .ifindex
            } else {
                0
            };
            map_entries.push(ClientMapEntry::new(
                lease,
                delivery_ifindex,
                rates.is_some_and(|rates| rates.upload_bps.is_some()),
                rates.is_some_and(|rates| rates.download_bps.is_some()),
                selection.blocked_macs.contains(&lease.mac),
                generation,
                expires_ns,
            )?);
        }
        let prepared = self
            .maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?
            .prepare(map_entries)?;
        let next = PriorityState {
            schema_version: 1,
            gateway_id: identity.0.to_owned(),
            controller_epoch: identity.1.to_owned(),
            config_revision: identity.2,
            bundle_generation: identity.3,
            checksum: identity.4.to_owned(),
            snapshot: snapshot.clone(),
            leases,
            application_classes,
            generation,
            expires_at_ms: expiry_ms,
        };
        self.write_journal(old.as_ref(), &next)?;
        let mut changed = Vec::new();
        let install = self.install_plan(&plan, &mut changed);
        if let Err(error) = install {
            let rollback = self.restore_rates(old.as_ref(), &plan);
            if rollback.is_ok() {
                let _ = fs::remove_file(&self.journal_path);
            }
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => Err(anyhow!("{error:#}; queue rollback failed: {rollback:#}")),
            };
        }
        let previous = match self
            .maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?
            .publish(&prepared)
        {
            Ok(previous) => previous,
            Err(error) => {
                let rollback = self.restore_rates(old.as_ref(), &plan);
                if rollback.is_ok() {
                    let _ = fs::remove_file(&self.journal_path);
                }
                return match rollback {
                    Ok(()) => Err(error.into()),
                    Err(rollback) => Err(anyhow!(
                        "map publish failed: {error:#}; queue rollback failed: {rollback:#}"
                    )),
                };
            }
        };
        if let Err(error) = self.persist_state(&next) {
            let map_rollback = self
                .maps
                .lock()
                .map_err(|_| anyhow!("priority map lock poisoned"))?
                .restore(&previous);
            let queue_rollback = self.restore_rates(old.as_ref(), &plan);
            if map_rollback.is_ok() && queue_rollback.is_ok() {
                let _ = fs::remove_file(&self.journal_path);
            }
            return Err(anyhow!(
                "priority state commit failed: {error}; map rollback: {map_rollback:?}; queue rollback: {queue_rollback:?}"
            ));
        }
        self.active = Some(next);
        self.active_plan = Some(plan);
        self.layout = layout;
        self.force_reapply = false;
        if let Err(error) = fs::remove_file(&self.journal_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("priority journal remains after committed policy: {error}");
            }
        }
        self.write_evidence("applied")?;
        Ok(selection)
    }

    fn install_plan(&self, plan: &PriorityPlan, changed: &mut Vec<QueueTree>) -> Result<()> {
        let trees = std::iter::once(&plan.upload).chain(plan.downloads.iter());
        for tree in trees {
            let dev = tree.port.name.as_str();
            self.verify_owned_tree(tree)?;
            for class in tree.classes().map_err(anyhow::Error::msg)? {
                let classid = classid_text(class.classid);
                let parent = classid_text(class.parent);
                tc(&[
                    "class",
                    "replace",
                    "dev",
                    dev,
                    "parent",
                    &parent,
                    "classid",
                    &classid,
                    "htb",
                    "rate",
                    &format!("{}bit", class.rate_bps),
                    "ceil",
                    &format!("{}bit", class.rate_bps),
                ])?;
            }
            for client in &tree.clients {
                self.ensure_leaf_qdisc(dev, tree.major, client.default_minor)?;
            }
            for application in &tree.applications {
                self.ensure_leaf_qdisc(dev, tree.major, application.minor)?;
            }
            let output = tc(&["class", "show", "dev", dev])?;
            for class in tree.classes().map_err(anyhow::Error::msg)? {
                let classid = classid_text(class.classid);
                let parent = if class.parent == tree.major << 16 {
                    None
                } else {
                    Some(classid_text(class.parent))
                };
                if !class_edge(&output, &classid, parent.as_deref()) {
                    bail!("priority_class_readback_failed: {dev} {classid} parent {parent:?}");
                }
            }
            changed.push(tree.clone());
        }
        Ok(())
    }

    fn verify_owned_tree(&self, tree: &QueueTree) -> Result<()> {
        let dev = tree.port.name.as_str();
        let owned_key = (dev.to_owned(), tree.major);
        if !self.owned_roots.contains(&owned_key) {
            bail!(
                "priority_qdisc_ownership_unknown: {dev} handle {:x}:",
                tree.major
            );
        }
        let qdiscs = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", dev])?,
            "owned priority qdisc",
        )?;
        let root_handle = format!("{:x}:", tree.major);
        if !qdiscs.as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.get("root").and_then(Value::as_bool) == Some(true)
                    && entry.get("kind").and_then(Value::as_str) == Some("htb")
                    && entry.get("handle").and_then(Value::as_str) == Some(root_handle.as_str())
            })
        }) {
            bail!("priority_qdisc_ownership_changed: {dev} handle {root_handle}");
        }
        let classes = tc(&["class", "show", "dev", dev])?;
        if !class_edge(&classes, &format!("{:x}:1", tree.major), None)
            || !class_edge(
                &classes,
                &format!("{:x}:fffe", tree.major),
                Some(&format!("{:x}:1", tree.major)),
            )
        {
            bail!("priority_qdisc_ownership_changed: {dev} base classes");
        }
        Ok(())
    }

    fn remove_unused_priority_classes(&self, tree: &QueueTree) -> Result<()> {
        let dev = tree.port.name.as_str();
        let desired = tree
            .classes()
            .map_err(anyhow::Error::msg)?
            .into_iter()
            .map(|class| class.classid)
            .collect::<BTreeSet<_>>();
        let classes = parse_class_dump(
            &tc(&["-j", "class", "show", "dev", dev])?,
            "priority class dump",
        )?;
        let stale = unused_priority_classes(&classes, tree.major, &desired)?;
        if stale.is_empty() {
            return Ok(());
        }

        let stale_class_ids = stale.iter().map(|class| class.raw).collect::<BTreeSet<_>>();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let qdiscs = parse_json(
                &tc(&["-s", "-j", "qdisc", "show", "dev", dev])?,
                "priority qdisc stats",
            )?;
            let entries = qdiscs
                .as_array()
                .context("priority qdisc stats not array")?;
            let drained = entries.iter().all(|entry| {
                let parent = entry
                    .get("parent")
                    .and_then(Value::as_str)
                    .and_then(parse_classid_text);
                !parent.is_some_and(|parent| stale_class_ids.contains(&parent))
                    || backlog_empty(entry)
            });
            if drained {
                break;
            }
            if Instant::now() >= deadline {
                bail!("priority_class_cleanup_backlog: {dev}");
            }
            thread::sleep(Duration::from_millis(50));
        }

        for class in &stale {
            let classid = classid_text(class.raw);
            tc(&["class", "del", "dev", dev, "classid", &classid])?;
        }

        let remaining_classes = parse_class_dump(
            &tc(&["-j", "class", "show", "dev", dev])?,
            "priority class cleanup readback",
        )?;
        let remaining_ids = remaining_classes
            .as_array()
            .context("priority class cleanup readback not an array")?
            .iter()
            .filter_map(|entry| entry.get("handle").and_then(Value::as_str))
            .filter_map(parse_classid_text)
            .collect::<BTreeSet<_>>();
        if stale.iter().any(|class| remaining_ids.contains(&class.raw)) {
            bail!("priority_class_cleanup_readback_failed: {dev}");
        }
        let stale_ids = stale.iter().map(|class| class.raw).collect::<BTreeSet<_>>();
        let remaining_qdiscs = parse_json(
            &tc(&["-j", "qdisc", "show", "dev", dev])?,
            "priority qdisc cleanup readback",
        )?;
        if remaining_qdiscs.as_array().is_none_or(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("parent")
                    .and_then(Value::as_str)
                    .and_then(parse_classid_text)
                    .is_some_and(|parent| stale_ids.contains(&parent))
            })
        }) {
            bail!("priority_class_cleanup_qdisc_readback_failed: {dev}");
        }
        Ok(())
    }

    /// Remove stale Agent-owned classes only after the receiver has reset the
    /// exact-flow verdict map for the newly applied policy revision. Shape
    /// entries contain class IDs, so pruning before that reset can leave an
    /// existing flow pointing at a class that has already been deleted.
    pub(crate) fn prune_unused_classes_after_flow_reset(&self) -> Result<()> {
        let Some(plan) = self.active_plan.as_ref() else {
            return Ok(());
        };
        for tree in std::iter::once(&plan.upload).chain(plan.downloads.iter()) {
            self.remove_unused_priority_classes(tree)?;
        }
        Ok(())
    }

    fn restore_rates(&self, old: Option<&PriorityState>, attempted: &PriorityPlan) -> Result<()> {
        let Some(old) = old else {
            let plan = empty_priority_plan(attempted);
            let mut changed = Vec::new();
            return self.install_plan(&plan, &mut changed);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok());
        let selected = PrioritySelection::from_snapshot(&old.snapshot, &old.gateway_id, now)
            .map_err(anyhow::Error::msg)?;
        let leases = old
            .leases
            .iter()
            .filter(|lease| lease.active)
            .cloned()
            .collect::<Vec<_>>();
        let layout = priority_delivery::inspect(&self.agent.interface, &selected.clients)
            .map_err(anyhow::Error::msg)?;
        let capacities = self
            .ports
            .iter()
            .map(|owned| {
                self.agent
                    .policy_interface_capacity_bps
                    .get(&owned.port.name)
                    .copied()
                    .map(|capacity| (owned.port.ifindex, capacity))
                    .ok_or_else(|| anyhow!("priority_capacity_unknown"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let budgets = leases
            .iter()
            .filter_map(|lease| {
                selected.totals.get(&lease.mac).map(|rates| ClientBudget {
                    lease: lease.clone(),
                    upload_bps: rates.upload_bps,
                    download_bps: rates.download_bps,
                })
            })
            .collect::<Vec<_>>();
        let lease_by_mac = leases
            .iter()
            .map(|lease| (lease.mac.as_str(), lease))
            .collect::<BTreeMap<_, _>>();
        let application_budgets = old
            .application_classes
            .iter()
            .map(|application| {
                let lease = lease_by_mac
                    .get(application.mac.as_str())
                    .ok_or_else(|| anyhow!("priority_state_invalid: missing app client lease"))?;
                Ok(ApplicationBudget {
                    lease: (*lease).clone(),
                    policy_id: application.policy_id.clone(),
                    minor: application.minor,
                    upload_bps: application.upload_bps,
                    download_bps: application.download_bps,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let plan = PriorityPlan::build(
            &layout,
            QueuePort {
                name: self.config.ifb.clone(),
                ifindex: self.ifb_ifindex,
            },
            STRUCTURAL_CAPACITY_BPS,
            &capacities,
            &budgets,
            &application_budgets,
        )
        .map_err(anyhow::Error::msg)?;
        let mut changed = Vec::new();
        self.install_plan(&plan, &mut changed)
    }

    fn load_state(&self, gateway: &str) -> Result<Option<PriorityState>> {
        if let Some(active) = &self.active
            && active.gateway_id == gateway
        {
            return Ok(Some(active.clone()));
        }
        let Some(state) = self.load_state_any()? else {
            return Ok(None);
        };
        if state.gateway_id != gateway {
            // A state file from another Controller/gateway is stale for the
            // current snapshot. Do not fail the new snapshot; it will replace
            // this file when applied.
            return Ok(None);
        }
        Ok(Some(state))
    }

    fn load_state_any(&self) -> Result<Option<PriorityState>> {
        let bytes = match fs::read(&self.state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.len() > MAX_STATE_BYTES {
            bail!("priority_state_too_large");
        }
        let state: PriorityState = serde_json::from_slice(&bytes)?;
        let identity = state
            .snapshot
            .snapshot_identity()
            .context("priority_state_invalid")?;
        if state.schema_version != 1
            || identity.0 != state.gateway_id
            || identity.1 != state.controller_epoch
            || identity.2 != state.config_revision
            || identity.3 != state.bundle_generation
            || identity.4 != state.checksum
            || state.generation == 0
            || state.expires_at_ms < 0
        {
            bail!("priority_state_invalid: gateway or snapshot identity mismatch");
        }
        for lease in &state.leases {
            lease.validate().map_err(anyhow::Error::msg)?;
        }
        let leases = state
            .leases
            .iter()
            .filter(|lease| lease.active)
            .map(|lease| (lease.mac.as_str(), lease.slot))
            .collect::<BTreeMap<_, _>>();
        let mut app_policies = BTreeSet::new();
        let mut app_minors = BTreeSet::new();
        for application in &state.application_classes {
            let first = classid::APPLICATION_FIRST
                + u32::from(application.slot) * classid::APPLICATIONS_PER_CLIENT;
            if application.policy_id.is_empty()
                || !leases
                    .get(application.mac.as_str())
                    .is_some_and(|slot| *slot == application.slot)
                || application.minor < first
                || application.minor >= first + classid::APPLICATIONS_PER_CLIENT
                || (application.upload_bps.is_none() && application.download_bps.is_none())
                || !app_policies.insert((application.mac.as_str(), application.policy_id.as_str()))
                || !app_minors.insert((application.mac.as_str(), application.minor))
            {
                bail!("priority_state_invalid: application class mapping is inconsistent");
            }
        }
        Ok(Some(state))
    }

    fn write_journal(&self, previous: Option<&PriorityState>, next: &PriorityState) -> Result<()> {
        let value = serde_json::json!({"schema_version":1,"previous":previous,"next":next,
            "interfaces":std::iter::once(self.config.ifb.as_str()).chain(self.ports.iter().map(|p| p.port.name.as_str())).collect::<Vec<_>>()});
        atomic_write(&self.journal_path, &serde_json::to_vec(&value)?)
    }

    fn persist_state(&self, state: &PriorityState) -> Result<()> {
        atomic_write(&self.state_path, &serde_json::to_vec(state)?)
    }

    pub(crate) fn restore_local(
        &mut self,
        gateway: &str,
        boot_id: &str,
        flow_bpf_ready: bool,
    ) -> Option<PolicyWireFrame> {
        let state = match self.load_state_any() {
            Ok(Some(state)) => state,
            Ok(None) => return None,
            Err(error) => {
                eprintln!("priority state restore rejected: {error:#}");
                return None;
            }
        };
        if state.gateway_id != gateway {
            eprintln!(
                "restoring stale local policy state for gateway {} while waiting for {}",
                state.gateway_id, gateway
            );
        }
        self.force_reapply = true;
        self.active = Some(state.clone());
        let ack = self.apply_snapshot(&state.snapshot, &state.gateway_id, boot_id, flow_bpf_ready);
        if matches!(
            ack,
            PolicyWireFrame::PolicyAck {
                status: PolicyAckStatus::Applied | PolicyAckStatus::Partial,
                ..
            }
        ) {
            Some(state.snapshot)
        } else {
            None
        }
    }

    pub(crate) fn reconcile_saved(
        &mut self,
        gateway: &str,
        boot_id: &str,
        flow_bpf_ready: bool,
    ) -> Option<PolicyWireFrame> {
        let state = self.load_state(gateway).ok().flatten()?;
        if self.active.is_none() {
            self.force_reapply = true;
        }
        Some(self.apply_snapshot(&state.snapshot, gateway, boot_id, flow_bpf_ready))
    }

    fn write_evidence(&self, phase: &str) -> Result<()> {
        let classes = std::iter::once(self.config.ifb.as_str()).chain(self.ports.iter().map(|port| port.port.name.as_str()))
            .map(|dev| Ok(serde_json::json!({"dev":dev,"qdisc":parse_json(&tc(&["-s","-j","qdisc","show","dev",dev])?,"qdisc stats")?,
                "classes":tc(&["-s","class","show","dev",dev])?}))).collect::<Result<Vec<_>>>()?;
        let maps = self
            .maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?
            .idle_snapshot()?;
        let mut interface_ifindices = self
            .ports
            .iter()
            .map(|port| (port.port.name.clone(), port.port.ifindex))
            .collect::<BTreeMap<_, _>>();
        if self.ifb_ifindex != 0 {
            interface_ifindices.insert(self.config.ifb.clone(), self.ifb_ifindex);
        }
        let ifb_mac = link_identity(&self.config.ifb)
            .ok()
            .flatten()
            .and_then(|identity| identity.address);
        let program_ids = collect_program_ids(
            &self
                .ports
                .iter()
                .map(|port| port.port.name.clone())
                .collect::<Vec<_>>(),
            &self.config.ifb,
        );
        atomic_write(
            &self.output,
            &serde_json::to_vec_pretty(&serde_json::json!({
                "kind":"client_priority_runtime_evidence","phase":phase,"ifb":self.config.ifb,"ifb_ifindex":self.ifb_ifindex,
                "ifb_mac":ifb_mac,
                "boot_id":current_boot_id(),
                "netns":current_netns(),
                "owner":current_process_owner(),
                "interface_ifindices":interface_ifindices,
                "program_ids":program_ids,
                "lan":self.layout,"agent_hook_priority":self.agent.attach_order.tc_priority,"matcher_priority":self.priority,
                "maps":maps,"classes":classes,
                "original_qdisc_roots":self.ports.iter().map(|port|serde_json::json!({"dev":&port.port.name,"ifindex":port.port.ifindex,"tree":&port.original_root})).collect::<Vec<_>>(),
                "ifb_original_qdisc_root":&self.ifb_original_root,
                "clsact_created":&self.clsact_created,
                "state_path":self.state_path,"journal_path":self.journal_path,
            }))?,
        )
    }

    pub(crate) fn shutdown<M: libbpf_rs::MapCore>(&mut self, observed_ifindexes: &M) -> Result<()> {
        if self.shutdown_done {
            return Ok(());
        }
        let mut errors = Vec::new();
        {
            let mut maps = self
                .maps
                .lock()
                .map_err(|_| anyhow!("priority map lock poisoned"))?;
            if let Err(error) = maps.publish_empty() {
                errors.push(format!("clear active client map: {error:#}"));
            }
        }
        if let Err(error) = self.detach_matchers() {
            errors.push(format!("detach redirect filters: {error:#}"));
        }
        if let Err(error) = self.detach_ifb_observer() {
            errors.push(format!("detach IFB observer: {error:#}"));
        }
        if self.matcher_attached.is_empty() && !self.ifb_observer_attached {
            if let Err(error) = self.clear_classifier_maps() {
                errors.push(format!("clear classifier maps: {error:#}"));
            }
            if let Err(error) = self.cleanup_pins() {
                errors.push(format!("unpin priority BPF programs: {error:#}"));
            }
        } else {
            errors.push(
                "priority_classifier_state_preserved: TC attachments remain, so classifier maps and pins were left in place".to_owned(),
            );
        }
        if let Ok(classes) = self.wait_for_queue_drain() {
            if !classes {
                errors.push(
                    "HTB leaf queue still has backlog; owned roots and IFB were left in place"
                        .to_owned(),
                );
            }
        } else {
            errors.push(
                "could not verify HTB queue drain; owned roots and IFB were left in place"
                    .to_owned(),
            );
        }
        if errors.is_empty()
            && let Err(error) = self.write_evidence("shutdown")
        {
            errors.push(format!("record final queue and BPF counters: {error:#}"));
        }
        for name in self.clsact_created.clone() {
            let remaining_filters = ["ingress", "egress"]
                .iter()
                .map(|hook| {
                    let filters = tc(&["filter", "show", "dev", &name, hook])
                        .unwrap_or_else(|error| format!("filter read failed: {error:#}"));
                    (hook.to_string(), filters)
                })
                .collect::<Vec<_>>();
            let empty = remaining_filters
                .iter()
                .all(|(_, filters)| filters.trim().is_empty());
            if empty {
                if let Err(error) = tc(&["qdisc", "del", "dev", &name, "clsact"]) {
                    errors.push(error.to_string());
                }
            } else {
                errors.push(format!(
                    "clsact ownership changed on {name}; left it in place; remaining filters: {remaining_filters:?}"
                ));
            }
        }
        if errors.is_empty() {
            let ifb_original_root = self
                .ifb_original_root
                .clone()
                .unwrap_or_else(OriginalQueueRoot::noqueue);
            for port in &self.ports {
                if let Err(error) = self.remove_owned_root(
                    &port.port.name,
                    classid::DOWNLOAD_MAJOR,
                    &port.original_root,
                ) {
                    errors.push(error.to_string());
                }
            }
            if let Err(error) =
                self.remove_owned_root(&self.config.ifb, classid::UPLOAD_MAJOR, &ifb_original_root)
            {
                errors.push(error.to_string());
            }
            if errors.is_empty()
                && nix::net::if_::if_nametoindex(self.config.ifb.as_str()).ok()
                    == Some(self.ifb_ifindex)
            {
                if let Err(error) = ip(&["link", "del", &self.config.ifb]) {
                    errors.push(error.to_string());
                } else {
                    let _ = observed_ifindexes.delete(&self.ifb_ifindex.to_ne_bytes());
                }
            }
        }
        let cleanup_path = self.output.with_extension("priority-cleanup.json");
        let cleanup_record = serde_json::json!({"cleanup_ok":errors.is_empty(),"errors":&errors});
        match serde_json::to_vec_pretty(&cleanup_record) {
            Ok(bytes) => {
                if let Err(error) = fs::write(&cleanup_path, bytes) {
                    errors.push(format!("write priority cleanup result: {error}"));
                }
            }
            Err(error) => errors.push(format!("encode priority cleanup result: {error}")),
        }
        if errors.is_empty() {
            self.shutdown_done = true;
            Ok(())
        } else {
            bail!("priority_cleanup_incomplete: {}", errors.join("; "))
        }
    }

    fn detach_matchers(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for port in self.matcher_attached.clone() {
            match tc(&[
                "filter",
                "del",
                "dev",
                &port.name,
                "ingress",
                "prio",
                &self.priority.to_string(),
                "handle",
                MATCHER_HANDLE,
                "bpf",
            ]) {
                Ok(_) => self
                    .matcher_attached
                    .retain(|item| item.ifindex != port.ifindex),
                Err(error) => errors.push(error.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("; "))
        }
    }

    fn clear_classifier_maps(&self) -> Result<()> {
        let maps = self
            .maps
            .lock()
            .map_err(|_| anyhow!("priority map lock poisoned"))?;
        for key in maps.ingress_ports.keys().collect::<Vec<_>>() {
            maps.ingress_ports.delete(&key)?;
        }
        for key in maps.roots.keys().collect::<Vec<_>>() {
            maps.roots.delete(&key)?;
        }
        maps.ifb
            .update(&0_u32.to_ne_bytes(), &0_u32.to_ne_bytes(), MapFlags::ANY)?;
        Ok(())
    }

    fn queue_backlogs(&self) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        for dev in std::iter::once(self.config.ifb.as_str())
            .chain(self.ports.iter().map(|port| port.port.name.as_str()))
        {
            let qdiscs = parse_json(
                &tc(&["-s", "-j", "qdisc", "show", "dev", dev])?,
                "qdisc stats",
            )?;
            let entries = qdiscs.as_array().context("qdisc stats not array")?;
            for entry in entries {
                if entry.get("parent").is_some()
                    && entry.get("kind").and_then(Value::as_str) == Some("fq_codel")
                {
                    result.push(entry.clone());
                }
            }
        }
        if result.is_empty() {
            bail!("priority_queue_drain_unknown: no owned HTB leaf qdisc stats were returned");
        }
        Ok(result)
    }

    fn wait_for_queue_drain(&self) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let entries = self.queue_backlogs()?;
            let empty = entries.iter().all(|entry| backlog_empty(entry));
            if empty {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn remove_owned_root(&self, dev: &str, major: u32, original: &OriginalQueueRoot) -> Result<()> {
        let qdiscs = parse_json(&tc(&["-j", "qdisc", "show", "dev", dev])?, "qdisc dump")?;
        if !qdiscs.as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["kind"] == "htb" && entry["handle"] == format!("{major:x}:"))
        }) {
            bail!("priority_qdisc_ownership_changed: {dev}");
        }
        tc(&[
            "qdisc",
            "del",
            "dev",
            dev,
            "root",
            "handle",
            &format!("{major:x}:"),
        ])?;
        restore_original_root(dev, original)
    }
}

fn allocate_application_classes(
    selection: &PrioritySelection,
    leases: &[ClientSlotLease],
) -> Result<Vec<ActiveApplicationClass>> {
    let leases = leases
        .iter()
        .filter(|lease| lease.active)
        .map(|lease| (lease.mac.as_str(), lease))
        .collect::<BTreeMap<_, _>>();
    let mut indices = BTreeMap::<String, u32>::new();
    let mut classes = Vec::with_capacity(selection.application_limits.len());
    for application in &selection.application_limits {
        let lease = leases
            .get(application.mac.as_str())
            .ok_or_else(|| anyhow!("priority_application_identity_unresolved"))?;
        let index = indices.entry(application.mac.clone()).or_default();
        if *index >= classid::APPLICATIONS_PER_CLIENT {
            bail!("priority_application_class_capacity: client exceeds 16 active app policies");
        }
        let minor = classid::APPLICATION_FIRST
            .checked_add(u32::from(lease.slot) * classid::APPLICATIONS_PER_CLIENT)
            .and_then(|first| first.checked_add(*index))
            .filter(|minor| *minor <= classid::APPLICATION_LAST)
            .ok_or_else(|| anyhow!("priority_application_class_capacity"))?;
        *index += 1;
        classes.push(ActiveApplicationClass {
            policy_id: application.policy_id.clone(),
            mac: application.mac.clone(),
            slot: lease.slot,
            minor,
            upload_bps: application.upload_bps,
            download_bps: application.download_bps,
        });
    }
    Ok(classes)
}

impl Drop for PriorityRuntime {
    fn drop(&mut self) {
        if self.shutdown_done {
            return;
        }
        if let Err(error) = self.detach_matchers() {
            eprintln!("priority cleanup incomplete: {error:#}");
        }
        if let Err(error) = self.detach_ifb_observer() {
            eprintln!("priority cleanup incomplete while detaching IFB observer: {error:#}");
        }
        if self.matcher_attached.is_empty() && !self.ifb_observer_attached {
            if let Err(error) = self.clear_classifier_maps() {
                eprintln!("priority classifier map cleanup incomplete: {error:#}");
            }
            if let Err(error) = self.cleanup_pins() {
                eprintln!("priority BPF unpin incomplete: {error:#}");
            }
        }
        let _ = self.write_evidence("drop");
    }
}

fn classid_text(raw: u32) -> String {
    format!("{:x}:{:x}", raw >> 16, raw & 0xffff)
}

fn parse_priority_class_metrics(output: &str) -> BTreeMap<String, ParsedPriorityClassMetrics> {
    let mut counters = BTreeMap::new();
    let mut current = None::<String>;
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"class") {
            current = fields.get(2).map(|value| value.to_ascii_lowercase());
            if let Some(classid) = &current {
                counters.entry(classid.clone()).or_default();
            }
            continue;
        }
        let Some(classid) = current.as_ref() else {
            continue;
        };
        let Some(sent) = fields.iter().position(|field| *field == "Sent") else {
            continue;
        };
        let bytes = fields.get(sent + 1).and_then(|value| value.parse().ok());
        let packets = fields
            .iter()
            .position(|field| *field == "bytes")
            .and_then(|index| fields.get(index + 1))
            .and_then(|value| value.parse().ok());
        let drops = fields
            .iter()
            .position(|field| {
                field.trim_matches(|character: char| !character.is_ascii_alphanumeric())
                    == "dropped"
            })
            .and_then(|index| fields.get(index + 1))
            .and_then(|value| value.trim_end_matches(',').parse().ok());
        let overlimits = fields
            .iter()
            .position(|field| *field == "overlimits")
            .and_then(|index| fields.get(index + 1))
            .and_then(|value| value.trim_end_matches(',').parse().ok());
        counters.insert(
            classid.clone(),
            ParsedPriorityClassMetrics {
                bytes,
                packets,
                drops,
                overlimits,
            },
        );
    }
    counters
}

fn backlog_empty(qdisc: &Value) -> bool {
    match qdisc.get("backlog") {
        Some(Value::Number(value)) => value.as_u64() == Some(0),
        Some(Value::String(value)) => {
            value
                .split_whitespace()
                .next()
                .and_then(|field| field.trim_end_matches('b').parse::<u64>().ok())
                == Some(0)
        }
        Some(Value::Object(object)) => object.values().all(|value| {
            value.as_u64() == Some(0)
                || value.as_str().is_some_and(|field| {
                    field
                        .trim_end_matches('b')
                        .parse::<u64>()
                        .is_ok_and(|amount| amount == 0)
                })
        }),
        _ => false,
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("priority state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod priority_recovery_gate_tests {
    use super::{
        MATCHER_HANDLE_ID, MATCHER_PROGRAM, OriginalQueueRoot, OwnedFilter, OwnedPriorityResources,
        PinOwnerState, QdiscOwnership, RecoveryEvidence, RecoveryOutcome, RecoveryOwner,
        RuntimeConfig, StalePinDir, capture_original_root, classify_owned_filter,
        classify_owned_filter_with_id, classify_owned_root, classify_pin_owner,
        current_process_owner, fq_codel_options, has_legacy_netqmon_mark_rule, parse_class_dump,
        parse_proc_stat, plan_recovery, program_name_matches, recovery_owner_is_live,
        recovery_scope_matches, require_namespace_opt_in, require_priority_transaction_recovered,
        valid_pin_dir_entries, valid_runtime_name,
    };

    fn owned_qdiscs() -> serde_json::Value {
        serde_json::json!([
            {"kind":"htb","handle":"51:","root":true,"options":{}},
            {"kind":"fq_codel","handle":"fffe:","parent":"51:fffe","options":{}},
            {"kind":"fq_codel","handle":"200:","parent":"51:200","options":{}},
            {"kind":"clsact","handle":"ffff:","parent":"ffff:","options":{}}
        ])
    }

    fn owned_classes() -> serde_json::Value {
        serde_json::json!([
            {"class":"htb","handle":"51:1","root":true},
            {"class":"htb","handle":"51:fffe","parent":"51:1"},
            {"class":"htb","handle":"51:100","parent":"51:1"},
            {"class":"htb","handle":"51:200","parent":"51:100"},
            {"class":"htb","handle":"51:1000","parent":"51:100"}
        ])
    }

    #[test]
    fn complete_owned_htb_layout_is_reclaimable() {
        assert_eq!(
            classify_owned_root(&owned_qdiscs(), &owned_classes(), 0x51).expect("owned layout"),
            QdiscOwnership::Owned
        );
    }

    #[test]
    fn incomplete_or_noncanonical_htb_layout_fails_closed() {
        let missing_bypass = serde_json::json!([
            {"class":"htb","handle":"51:1","root":true},
            {"class":"htb","handle":"51:100","parent":"51:1"}
        ]);
        let error = classify_owned_root(&owned_qdiscs(), &missing_bypass, 0x51)
            .expect_err("missing bypass class must fail closed");
        assert!(
            error
                .to_string()
                .contains("priority_qdisc_ownership_unknown"),
            "{error}"
        );

        let wrong_parent = serde_json::json!([
            {"class":"htb","handle":"51:1","root":true},
            {"class":"htb","handle":"51:fffe","parent":"51:1"},
            {"class":"htb","handle":"51:200","parent":"51:fffe"}
        ]);
        let error = classify_owned_root(&owned_qdiscs(), &wrong_parent, 0x51)
            .expect_err("noncanonical parent must fail closed");
        assert!(
            error
                .to_string()
                .contains("priority_qdisc_ownership_unknown"),
            "{error}"
        );
    }

    #[test]
    fn foreign_qdisc_major_and_root_are_preserved() {
        let foreign = serde_json::json!([
            {"kind":"htb","handle":"99:","root":true,"options":{}},
            {"kind":"fq_codel","handle":"99:fffe","parent":"99:1","options":{}}
        ]);
        assert_eq!(
            classify_owned_root(&foreign, &serde_json::json!([]), 0x51).expect("foreign root"),
            QdiscOwnership::Foreign
        );
        // A tree for the other direction's major is not an owned tree either.
        assert_eq!(
            classify_owned_root(&foreign, &serde_json::json!([]), 0x52).expect("foreign root"),
            QdiscOwnership::Foreign
        );
    }

    #[test]
    fn only_the_exact_priority_filter_handle_is_reclaimed() {
        let dump = serde_json::json!([
            {"protocol":"all","pref":49153,"kind":"bpf","options":{
                "handle":MATCHER_HANDLE_ID,"bpf_name":"matcher:[*fsobj]",
                "prog":{"id":7,"name":"netqmon_qos_pri"}
            }},
            {"protocol":"all","pref":10,"kind":"bpf","options":{
                "handle":1234,"bpf_name":"foreign_prog"
            }}
        ]);
        assert_eq!(
            classify_owned_filter(&dump, MATCHER_HANDLE_ID, MATCHER_PROGRAM).expect("owned filter"),
            super::OwnedFilterState::Owned(49153)
        );
        assert_eq!(
            classify_owned_filter(&dump, 0x4e515007, super::IFB_OBSERVER_PROGRAM)
                .expect("foreign handle ignored"),
            super::OwnedFilterState::Absent
        );

        let same_handle_foreign_program = serde_json::json!([
            {"protocol":"all","pref":49153,"kind":"bpf","options":{
                "handle":MATCHER_HANDLE_ID,"bpf_name":"foreign_prog"
            }}
        ]);
        let error = classify_owned_filter(
            &same_handle_foreign_program,
            MATCHER_HANDLE_ID,
            MATCHER_PROGRAM,
        )
        .expect_err("same handle with a foreign program must fail closed");
        assert!(
            error
                .to_string()
                .contains("priority_filter_ownership_unknown"),
            "{error}"
        );
    }

    #[test]
    fn live_agent_pins_refuse_reclaim_but_dead_or_reused_pids_do_not() {
        assert_eq!(
            classify_pin_owner(4242, 7, Some("netqmon-agent\n"), None),
            PinOwnerState::Live
        );
        assert_eq!(
            classify_pin_owner(4242, 7, None, None),
            PinOwnerState::Stale
        );
        assert_eq!(
            classify_pin_owner(4242, 7, Some("unrelated-daemon\n"), None),
            PinOwnerState::Stale
        );
        // A PID-named directory for the current process predates its own pins.
        assert_eq!(
            classify_pin_owner(7, 7, Some("netqmon-agent\n"), None),
            PinOwnerState::Stale
        );
    }

    #[test]
    fn pin_directory_with_an_extra_entry_fails_closed() {
        assert!(valid_pin_dir_entries(&[
            "matcher".to_owned(),
            "ifb-observer".to_owned()
        ]));
        assert!(valid_pin_dir_entries(&[]));
        assert!(!valid_pin_dir_entries(&[
            "matcher".to_owned(),
            "map".to_owned()
        ]));
        assert!(!valid_pin_dir_entries(&[
            "matcher".to_owned(),
            "matcher".to_owned()
        ]));
    }

    #[test]
    fn kernel_truncated_program_names_still_match() {
        assert!(program_name_matches(
            "netqmon_qos_pri",
            "netqmon_qos_priority_match"
        ));
        assert!(program_name_matches(
            "netqmon_qos_pri",
            "netqmon_qos_priority_ifb"
        ));
        assert!(!program_name_matches("foreign_prog", MATCHER_PROGRAM));
    }

    #[test]
    fn second_recovery_is_a_noop() {
        assert_eq!(
            classify_owned_root(&serde_json::json!([]), &serde_json::json!([]), 0x51)
                .expect("no root"),
            QdiscOwnership::Absent
        );
        assert_eq!(
            classify_owned_filter(&serde_json::json!([]), MATCHER_HANDLE_ID, MATCHER_PROGRAM)
                .expect("no filter"),
            super::OwnedFilterState::Absent
        );
        let resources = OwnedPriorityResources::default();
        assert!(resources.is_empty());
        assert!(plan_recovery(&resources, &RecoveryEvidence::default()).is_empty());
    }

    #[test]
    fn interrupted_recovery_marker_is_only_resumed_within_the_same_boot() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("priority-recovery.json");
        std::fs::write(
            &path,
            br#"{"kind":"client_priority_recovery","phase":"started","boot_id":"boot-a"}"#,
        )
        .expect("write recovery marker");
        assert!(super::recovery_marker(&path, "boot-a").is_some());
        assert!(super::recovery_marker(&path, "boot-b").is_none());

        std::fs::write(
            &path,
            br#"{"kind":"client_priority_recovery","phase":"completed","boot_id":"boot-a"}"#,
        )
        .expect("write completed marker");
        assert!(super::recovery_marker(&path, "boot-a").is_none());
    }

    #[test]
    fn missing_original_root_is_recorded_instead_of_guessed() {
        let resources = OwnedPriorityResources {
            roots: ["br-lan".to_owned()].into_iter().collect(),
            filters: vec![OwnedFilter {
                dev: "br-lan".to_owned(),
                hook: "ingress",
                pref: 10,
                handle: MATCHER_HANDLE_ID,
            }],
            pin_dirs: vec![StalePinDir {
                path: "/sys/fs/bpf/nqp-priority-42".into(),
            }],
            ..OwnedPriorityResources::default()
        };
        let plan = plan_recovery(&resources, &RecoveryEvidence::default());
        assert_eq!(plan.roots, vec![("br-lan".to_owned(), 0x51)]);
        assert_eq!(plan.original_root_unavailable, vec!["br-lan".to_owned()]);

        let evidence = RecoveryEvidence {
            roots: [(
                "br-lan".to_owned(),
                (
                    3,
                    OriginalQueueRoot {
                        kind: "noqueue".to_owned(),
                        options: serde_json::Value::Null,
                        mq_leaves: Vec::new(),
                    },
                ),
            )]
            .into_iter()
            .collect(),
            ..RecoveryEvidence::default()
        };
        let plan = plan_recovery(&resources, &evidence);
        assert!(plan.original_root_unavailable.is_empty());
    }

    #[test]
    fn empty_tc_class_dump_means_no_classes_not_invalid_evidence() {
        assert_eq!(
            parse_class_dump("", "priority class dump").expect("empty dump is no classes"),
            serde_json::json!([])
        );
        assert_eq!(
            parse_class_dump(" \n", "priority class cleanup readback").expect("blank dump"),
            serde_json::json!([])
        );
        let malformed =
            parse_class_dump("not-json", "priority class dump").expect_err("malformed dump fails");
        assert!(malformed.to_string().contains("invalid JSON"));
    }

    #[test]
    fn classic_tc_class_table_is_accepted_without_json_support() {
        // iproute2 6.1 ignores -j for `class show` and prints this table.
        let table = "class htb 52:1000 parent 52:100 leaf 1000: prio 0 rate 4Mbit ceil 4Mbit burst 1600b cburst 1600b \n Sent 1 bytes 1 pkt (dropped 0, overlimits 0 requeues 0) \nclass htb 52:100 parent 52:1 rate 4Mbit ceil 4Mbit burst 1600b cburst 1600b \nclass htb 52:1 root rate 100Gbit ceil 100Gbit burst 0b cburst 0b \nclass fq_codel 1000:26c parent 1000: \n";
        assert_eq!(
            parse_class_dump(table, "priority class dump").expect("classic table"),
            serde_json::json!([
                {"class":"htb","handle":"52:1000","parent":"52:100"},
                {"class":"htb","handle":"52:100","parent":"52:1"},
                {"class":"htb","handle":"52:1","root":true}
            ])
        );
        let desired = std::collections::BTreeSet::new();
        let stale = crate::policy::priority_cleanup::unused_priority_classes(
            &parse_class_dump(table, "priority class dump").unwrap(),
            0x52,
            &desired,
        )
        .expect("reserved classes are removable");
        assert_eq!(stale.len(), 2);
    }

    #[test]
    fn initial_namespace_requires_an_explicit_runtime_config_opt_in() {
        assert!(require_namespace_opt_in(false, false).is_ok());
        assert!(require_namespace_opt_in(false, true).is_ok());
        assert!(require_namespace_opt_in(true, false).is_err());
        assert!(require_namespace_opt_in(true, true).is_ok());

        assert!(valid_runtime_name("nqp-lan", false));
        assert!(!valid_runtime_name("br-lan", false));
        assert!(valid_runtime_name("br-lan", true));
        assert!(!valid_runtime_name("br/lan", true));

        let config: RuntimeConfig = serde_json::from_value(serde_json::json!({
            "ifb": "nqp-ifb0",
            "output": "/tmp/priority-evidence"
        }))
        .expect("legacy isolated config remains valid");
        assert!(!config.allow_initial_namespace);
    }

    #[test]
    fn mq_snapshot_preserves_each_fq_codel_leaf_for_restore() {
        let options = serde_json::json!({
            "limit": 10240,
            "flows": 1024,
            "quantum": 1514,
            "target": 4999,
            "interval": 99999,
            "memory_limit": 33_554_432,
            "ecn": true,
            "drop_batch": 64
        });
        let qdiscs = serde_json::json!([
            {"kind":"mq","handle":"0:","root":true,"options":{}},
            {"kind":"fq_codel","handle":"0:","parent":":2","options":options.clone()},
            {"kind":"fq_codel","handle":"0:","parent":":1","options":options},
            {"kind":"clsact","handle":"ffff:","options":{}}
        ]);

        let root = capture_original_root(&qdiscs).expect("supported mq tree");

        assert_eq!(root.kind, "mq");
        assert_eq!(
            root.mq_leaves
                .iter()
                .map(|leaf| leaf.minor.as_str())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert_eq!(
            fq_codel_options(&root.mq_leaves[0].options).unwrap(),
            [
                "limit",
                "10240",
                "flows",
                "1024",
                "quantum",
                "1514",
                "target",
                "5000us",
                "interval",
                "100000us",
                "memory_limit",
                "33554432b",
                "ecn",
                "drop_batch",
                "64"
            ]
        );
    }

    #[test]
    fn ifb_default_fq_codel_root_is_snapshotted_for_rollback() {
        let options = serde_json::json!({
            "limit": 10240,
            "flows": 1024,
            "quantum": 1514,
            "target": 4999,
            "interval": 99999,
            "memory_limit": 33_554_432,
            "ecn": true,
            "drop_batch": 64
        });
        let qdiscs = serde_json::json!([
            {"kind":"fq_codel","handle":"0:","root":true,"options":options}
        ]);

        let root = capture_original_root(&qdiscs).expect("supported IFB default qdisc");

        assert_eq!(root.kind, "fq_codel");
        assert_eq!(root.mq_leaves, Vec::new());
        assert_eq!(
            fq_codel_options(&root.options).unwrap(),
            [
                "limit",
                "10240",
                "flows",
                "1024",
                "quantum",
                "1514",
                "target",
                "5000us",
                "interval",
                "100000us",
                "memory_limit",
                "33554432b",
                "ecn",
                "drop_batch",
                "64"
            ]
        );
    }

    #[test]
    fn unsupported_mq_leaf_does_not_become_an_incomplete_restore_snapshot() {
        let qdiscs = serde_json::json!([
            {"kind":"mq","handle":"8002:","root":true,"options":{}},
            {"kind":"cake","handle":"0:","parent":"8002:1","options":{}}
        ]);

        let error = capture_original_root(&qdiscs).expect_err("unsupported leaf must fail closed");

        assert!(error.to_string().contains("unsupported mq leaf qdisc cake"));
        assert_eq!(OriginalQueueRoot::noqueue().kind, "noqueue");
    }

    #[test]
    fn proc_stat_starttime_handles_spaces_and_parentheses_in_comm() {
        // pid (comm with spaces) state ... starttime (field 22).
        let mut fields = vec!["S"; 19];
        fields.push("1234567");
        let stat = format!("4242 (netqmon agent (v2)) {}\n", fields.join(" "));
        assert_eq!(
            parse_proc_stat(&stat),
            Some(("netqmon agent (v2)".to_owned(), 1_234_567))
        );
        assert!(parse_proc_stat("not a stat line").is_none());
    }

    #[test]
    fn recovery_evidence_is_scoped_to_the_same_boot_and_network_namespace() {
        let same_boot = RecoveryEvidence {
            boot_id: Some("boot-a".to_owned()),
            netns: Some("net:[1]".to_owned()),
            ..RecoveryEvidence::default()
        };
        assert!(recovery_scope_matches(
            &same_boot,
            Some("boot-a"),
            Some("net:[1]")
        ));
        assert!(!recovery_scope_matches(
            &same_boot,
            Some("boot-b"),
            Some("net:[1]")
        ));
        assert!(!recovery_scope_matches(
            &same_boot,
            Some("boot-a"),
            Some("net:[2]")
        ));
        // Missing evidence cannot prove a foreign owner, so the existing
        // per-object ownership checks remain authoritative.
        assert!(recovery_scope_matches(
            &RecoveryEvidence::default(),
            Some("boot-a"),
            Some("net:[1]")
        ));
    }

    #[test]
    fn owner_starttime_and_comm_are_recorded_for_liveness_checks() {
        let owner = RecoveryOwner {
            pid: 4242,
            comm: Some("netqmon-agent".to_owned()),
            starttime: Some(1_234_567),
            boot_id: Some("boot-a".to_owned()),
            netns: Some("net:[1]".to_owned()),
        };
        assert!(!owner.is_empty());
        assert!(RecoveryOwner::default().is_empty());
    }

    #[test]
    fn current_process_identity_is_read_from_proc_and_matches_itself() {
        let owner = current_process_owner();
        assert_eq!(owner.pid, std::process::id());
        assert!(owner.starttime.is_some());
        assert!(owner.boot_id.is_some());
        assert!(owner.netns.is_some());
        assert!(recovery_owner_is_live(&owner));

        let mut reused = owner;
        reused.starttime = reused.starttime.map(|starttime| starttime + 1);
        assert!(!recovery_owner_is_live(&reused));
    }

    #[test]
    fn recorded_program_id_mismatch_fails_closed_but_truncated_names_match() {
        let dump = serde_json::json!([
            {"protocol":"all","pref":49153,"kind":"bpf","options":{
                "handle":MATCHER_HANDLE_ID,"bpf_name":"matcher:[*fsobj]",
                "prog":{"id":7,"name":"netqmon_qos_pri"}
            }}
        ]);
        assert_eq!(
            classify_owned_filter_with_id(&dump, MATCHER_HANDLE_ID, MATCHER_PROGRAM, Some(7))
                .expect("same program id"),
            super::OwnedFilterState::Owned(49153)
        );
        let error =
            classify_owned_filter_with_id(&dump, MATCHER_HANDLE_ID, MATCHER_PROGRAM, Some(8))
                .expect_err("reused handle with a different program id must fail closed");
        assert!(error.to_string().contains("expected 8"), "{error}");

        let evidence = RecoveryEvidence {
            program_ids: [("br-lan:ingress:0x4e515006".to_owned(), 7)]
                .into_iter()
                .collect(),
            ..RecoveryEvidence::default()
        };
        assert_eq!(
            evidence.expected_program_id("br-lan", "ingress", MATCHER_HANDLE_ID),
            Some(7)
        );
    }

    #[test]
    fn unavailable_original_root_reports_degraded_recovery() {
        let degraded = RecoveryOutcome {
            performed: true,
            degraded: true,
            original_root_unavailable: vec!["br-lan".to_owned()],
            ..RecoveryOutcome::default()
        };
        assert_eq!(
            degraded.degraded_reason(),
            Some("original_root_unavailable")
        );
        let clean = RecoveryOutcome {
            performed: true,
            ..RecoveryOutcome::default()
        };
        assert!(clean.degraded_reason().is_none());
    }

    #[test]
    fn unfinished_priority_journal_is_preserved_and_blocks_startup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = directory.path().join("policy-state.json");
        let journal = state.with_extension("priority-journal.json");
        std::fs::write(&journal, b"priority-journal-bytes").expect("write priority journal");

        let error = require_priority_transaction_recovered(&state)
            .expect_err("unfinished priority transaction must require recovery");

        assert!(error.to_string().contains("priority_recovery_required"));
        assert_eq!(
            std::fs::read(&journal).expect("priority journal retained"),
            b"priority-journal-bytes"
        );
    }

    #[test]
    fn no_priority_journal_allows_startup_and_passwall_marks_are_not_netqmon_conflicts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = directory.path().join("policy-state.json");
        require_priority_transaction_recovered(&state).expect("no unfinished journal");

        let passwall = serde_json::json!({"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1_347_637_042}}]});
        assert!(!has_legacy_netqmon_mark_rule(&passwall));

        let owned = serde_json::json!({"comment":"netqmon:shared:upload"});
        assert!(has_legacy_netqmon_mark_rule(&owned));
    }
}
