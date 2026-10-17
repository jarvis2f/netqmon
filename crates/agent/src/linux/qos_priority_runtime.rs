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

#[derive(Clone, Debug, PartialEq, Serialize)]
struct OriginalQueueRoot {
    kind: String,
    options: Value,
    mq_leaves: Vec<OriginalMqLeaf>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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
    priority: u32,
    matcher_attached: Vec<QueuePort>,
    ifb_observer_attached: bool,
    clsact_created: BTreeSet<String>,
    active: Option<PriorityState>,
    active_plan: Option<PriorityPlan>,
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

fn tc(args: &[&str]) -> Result<String> {
    run("tc", args)
}

fn ip(args: &[&str]) -> Result<String> {
    run("ip", args)
}

fn parse_json(text: &str, what: &str) -> Result<Value> {
    serde_json::from_str(text).with_context(|| format!("{what} returned invalid JSON"))
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
        if agent.attach_backend != AttachBackend::Netlink {
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
        require_priority_transaction_recovered(policy_state_path)?;
        let nft = parse_json(&run("nft", &["-j", "list", "ruleset"])?, "nft ruleset")?;
        if has_legacy_netqmon_mark_rule(&nft) {
            bail!("priority_conflict: legacy NetQmon mark rules remain in nftables");
        }
        if incompatible_nft(&nft) {
            bail!("priority_conflict: nft priority writer or flowtable/offload is present");
        }
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
            force_reapply: false,
            emergency_disabled: false,
            shutdown_done: false,
        };
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
        let matcher_handle = ProgramHandle::try_from(matcher)?;
        let observer_handle = ProgramHandle::try_from(ifb_observer)?;
        fs::create_dir(&self.pin_dir).context("create priority BPF pin directory")?;
        let matcher_pin = self.pin_dir.join("matcher");
        let observer_pin = self.pin_dir.join("ifb-observer");
        matcher_handle.pin(&matcher_pin)?;
        observer_handle.pin(&observer_pin)?;
        for port in self.layout.ingress_ports.clone() {
            self.ensure_clsact(&port.name)?;
            let priority = self.priority.to_string();
            let result = tc(&[
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
            ]);
            if let Err(error) = result {
                let _ = self.detach_matchers();
                return Err(error).context("attach priority classifier and IFB redirect");
            }
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
        let offload = run("ethtool", &["-k", &self.config.ifb])
            .context("priority_offload_unknown: ethtool feature inspection is required")?;
        if offload
            .lines()
            .any(|line| line.starts_with("hw-tc-offload:") && line.contains(": on"))
        {
            bail!("priority_offload_conflict: IFB hw-tc-offload is enabled");
        }
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
            let offload = run("ethtool", &["-k", &name])
                .context("priority_offload_unknown: ethtool feature inspection is required")?;
            if offload
                .lines()
                .any(|line| line.starts_with("hw-tc-offload:") && line.contains(": on"))
            {
                bail!("priority_offload_conflict: hw-tc-offload is enabled on {name}");
            }
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

    pub(crate) fn apply_snapshot(
        &mut self,
        snapshot: &PolicyWireFrame,
        gateway: &str,
        boot_id: &str,
        flow_bpf_ready: bool,
    ) -> PolicyWireFrame {
        match self.apply(snapshot, gateway) {
            Ok(mut selection) => {
                let client_block_degraded = !selection.blocked_macs.is_empty();
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
        let classes = parse_json(
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

        let remaining_classes = parse_json(
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
            || state.gateway_id != gateway
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
        let state = match self.load_state(gateway) {
            Ok(Some(state)) => state,
            Ok(None) => return None,
            Err(error) => {
                eprintln!("priority state restore rejected: {error:#}");
                return None;
            }
        };
        self.force_reapply = true;
        self.active = Some(state.clone());
        let ack = self.apply_snapshot(&state.snapshot, gateway, boot_id, flow_bpf_ready);
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
        atomic_write(
            &self.output,
            &serde_json::to_vec_pretty(&serde_json::json!({
                "kind":"client_priority_runtime_evidence","phase":phase,"ifb":self.config.ifb,"ifb_ifindex":self.ifb_ifindex,
                "lan":self.layout,"agent_hook_priority":self.agent.attach_order.tc_priority,"matcher_priority":self.priority,
                "maps":maps,"classes":classes,
                "original_qdisc_roots":self.ports.iter().map(|port|serde_json::json!({"dev":&port.port.name,"ifindex":port.port.ifindex,"tree":&port.original_root})).collect::<Vec<_>>(),
                "ifb_original_qdisc_root":&self.ifb_original_root,
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
        if self.ifb_observer_attached {
            if let Err(error) = tc(&[
                "filter",
                "del",
                "dev",
                &self.config.ifb,
                "egress",
                "prio",
                &self
                    .agent
                    .attach_order
                    .tc_priority
                    .saturating_add(2)
                    .to_string(),
                "handle",
                IFB_OBSERVER_HANDLE,
                "bpf",
            ]) {
                errors.push(format!("detach IFB observer: {error:#}"));
            } else {
                self.ifb_observer_attached = false;
            }
        }
        if let Err(error) = self.clear_classifier_maps() {
            errors.push(format!("clear classifier maps: {error:#}"));
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
        let _ = fs::write(
            self.output.with_extension("priority-cleanup.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"cleanup_ok":errors.is_empty(),"errors":errors}),
            )?,
        );
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
        let _ = self.write_evidence("drop");
    }
}

fn classid_text(raw: u32) -> String {
    format!("{:x}:{:x}", raw >> 16, raw & 0xffff)
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
        OriginalQueueRoot, RuntimeConfig, capture_original_root, fq_codel_options,
        has_legacy_netqmon_mark_rule, require_namespace_opt_in,
        require_priority_transaction_recovered, valid_runtime_name,
    };

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
