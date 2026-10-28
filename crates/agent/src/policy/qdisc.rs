use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::capabilities::PolicyTopology;
use super::shaper::{
    APPLICATION_MARK_MASK, ApplicationClass, CLIENT_MARK_MASK, ClientClass, ManagedInterface,
    ShapingState, application_leaf_minor, application_mark_value, burst_bytes, client_mark_value,
    default_class_minor,
};

const ROOT_HANDLE: &str = "51:";
const MAX_SHAPING_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ClassCounters {
    pub client: ClientClass,
    pub application: Option<ApplicationClass>,
    pub interface: String,
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub drops: Option<u64>,
    pub overlimits: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FeatureSupport {
    pub supported: bool,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

impl FeatureSupport {
    fn supported() -> Self {
        Self {
            supported: true,
            reason_code: None,
            reason: None,
        }
    }

    fn unsupported(code: &str, reason: impl Into<String>) -> Self {
        Self {
            supported: false,
            reason_code: Some(code.to_owned()),
            reason: Some(reason.into()),
        }
    }
}

pub(super) fn inspect_capability(topology: &PolicyTopology) -> FeatureSupport {
    if !topology.supported {
        return FeatureSupport::unsupported(
            topology
                .reason_code
                .as_deref()
                .unwrap_or("unsupported_topology"),
            topology
                .reason
                .as_deref()
                .unwrap_or("the client Internet route is not verified"),
        );
    }
    if topology.lan_interfaces.len() != 1 || topology.shaping_wan().is_none() {
        return FeatureSupport::unsupported(
            "unsupported_multi_egress",
            "aggregate client shaping requires one verified LAN egress and one WAN egress",
        );
    }
    let wan_queue = topology.shaping_wan().expect("checked above");
    if is_tunnel_interface(wan_queue) || super::egress::is_ppp_interface(wan_queue) {
        return FeatureSupport::unsupported(
            "unsupported_topology",
            "VPN and tunnel default routes are outside the verified Internet shaping path",
        );
    }
    if !topology.is_one_arm_router() && topology.lan_interfaces.iter().any(|lan| lan == wan_queue) {
        return FeatureSupport::unsupported(
            "unsupported_topology",
            "LAN and WAN shaping queues overlap without a verified one-arm path",
        );
    }
    if topology.wan_shaping_interface.is_some()
        && topology
            .lan_interfaces
            .iter()
            .any(|lan| super::egress::overlaps_lan(lan, wan_queue))
    {
        return FeatureSupport::unsupported(
            "unsupported_topology",
            "the common WAN queue is also reachable through the managed LAN",
        );
    }
    if topology.lan_capacity_bps.is_none() || topology.wan_capacity_bps.is_none() {
        return FeatureSupport::unsupported(
            "unsupported_interface_speed",
            "a measured link speed or explicit policy_interface_capacity_bps is required for each egress",
        );
    }
    match probe_kernel_features() {
        Ok(()) => FeatureSupport::supported(),
        Err(error) => FeatureSupport::unsupported("unsupported_kernel_feature", error),
    }
}

pub(super) fn inspect_ownership(topology: &PolicyTopology, state_path: &Path) -> FeatureSupport {
    let saved = match super::state::load_any(state_path) {
        Ok(saved) => saved,
        Err(error) => return FeatureSupport::unsupported("invalid_local_state", error),
    };
    for name in topology
        .lan_interfaces
        .iter()
        .map(String::as_str)
        .chain(topology.shaping_wan())
        .collect::<BTreeSet<_>>()
    {
        let owned = saved
            .as_ref()
            .and_then(|state| state.shaping_state.as_ref())
            .and_then(|state| state.interfaces().find(|interface| interface.name == name));
        let result = owned.map_or_else(|| inspect_default_root(name).map(|_| ()), verify_owned);
        if let Err(error) = result {
            return FeatureSupport::unsupported("qdisc_ownership_conflict", error);
        }
    }
    FeatureSupport::supported()
}

pub(super) fn prepare_state(
    desired: &ShapingState,
    previous: Option<&ShapingState>,
) -> Result<ShapingState, String> {
    desired.validate()?;
    let mut prepared = desired.clone();
    prepared.schema_version = if prepared.shared_egress.is_some() {
        2
    } else {
        1
    };
    for desired_interface in [
        &mut prepared.upload_interface,
        &mut prepared.download_interface,
        &mut prepared.shared_egress,
    ]
    .into_iter()
    .flatten()
    {
        let prior = previous.and_then(|state| {
            state
                .interfaces()
                .find(|interface| interface.name == desired_interface.name)
        });
        if let Some(prior) = prior {
            if prior.shared_egress != desired_interface.shared_egress {
                return Err("degraded_ownership_conflict: remove the old shaping layout before changing physical root roles".to_owned());
            }
            if prior.ifindex != desired_interface.ifindex {
                return Err(format!(
                    "degraded_ownership_conflict: interface {} changed ifindex from {} to {}",
                    desired_interface.name, prior.ifindex, desired_interface.ifindex
                ));
            }
            verify_owned(prior)?;
            desired_interface.original_root_kind = prior.original_root_kind.clone();
        } else {
            desired_interface.original_root_kind = inspect_default_root(&desired_interface.name)?;
        }
    }
    if let Some(previous) = previous {
        for old in previous.interfaces() {
            let retained = prepared.interfaces().any(|next| next.name == old.name);
            if !retained {
                verify_owned(old)?;
            }
        }
    }
    Ok(prepared)
}

pub(super) fn apply(desired: &ShapingState, previous: Option<&ShapingState>) -> Result<(), String> {
    desired.validate()?;
    for interface in desired.interfaces() {
        for client in &interface.clients {
            if client_guarantee(interface, client) < 8 {
                return Err("unsupported_client_limit: interface capacity cannot provide one byte per second to every client class".to_owned());
            }
            let children = interface
                .application_classes
                .iter()
                .filter(|app| app.parent_class_minor == client.class_minor)
                .count();
            if children > 0 && client_guarantee(interface, client) < 8 * (children as u64 + 1) {
                return Err("unsupported_application_limit: interface capacity cannot provide one byte per second to every application/default class".to_owned());
            }
        }
    }
    if let Some(previous) = previous {
        previous.validate()?;
    }
    let mut changed = Vec::<(ManagedInterface, Option<ManagedInterface>)>::new();
    let desired_interfaces = desired.interfaces().collect::<Vec<_>>();
    for interface in desired_interfaces.iter().copied() {
        let prior =
            previous.and_then(|state| state.interfaces().find(|item| item.name == interface.name));
        // Track the interface before touching tc. A command may fail after
        // replacing the root or some child classes, so rollback must include
        // this partially-applied interface too.
        changed.push((interface.clone(), prior.cloned()));
        if let Err(error) = apply_interface(interface, prior) {
            rollback_changed(&changed, previous, desired);
            return Err(error);
        }
    }
    if let Some(previous) = previous {
        for old in previous.interfaces() {
            let retained = desired_interfaces.iter().any(|next| next.name == old.name);
            if !retained {
                changed.push((old.clone(), Some(old.clone())));
                if let Err(error) = restore_interface(old) {
                    rollback_changed(&changed, Some(previous), desired);
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn restore(state: &ShapingState) -> Result<(), String> {
    state.validate()?;
    let mut errors = Vec::new();
    for interface in state.interfaces() {
        if let Err(error) = restore_interface(interface) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("manual_cleanup_required: {}", errors.join("; ")))
    }
}

pub(super) fn read_metrics(state: &ShapingState) -> Result<Vec<ClassCounters>, String> {
    let mut metrics = Vec::new();
    for interface in state_interfaces(state) {
        verify_owned(interface)?;
        let output = run_capture("tc", &["-s", "class", "show", "dev", &interface.name])?;
        let counters = parse_class_counters(&output);
        for client in &interface.clients {
            let class_id = format!("51:{}", client.class_minor);
            let value = counters.get(&class_id);
            metrics.push(ClassCounters {
                client: client.clone(),
                application: None,
                interface: interface.name.clone(),
                bytes: value
                    .and_then(|value| value.bytes)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                packets: value
                    .and_then(|value| value.packets)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                drops: value
                    .and_then(|value| value.drops)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                overlimits: value
                    .and_then(|value| value.overlimits)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
            });
        }
        for application in &interface.application_classes {
            let class_id = format!("51:{}", application.class_minor);
            let value = counters.get(&class_id);
            let Some(client) = interface
                .clients
                .iter()
                .find(|client| client.class_minor == application.parent_class_minor)
            else {
                return Err("application metric class has no client parent".to_owned());
            };
            metrics.push(ClassCounters {
                client: client.clone(),
                application: Some(application.clone()),
                interface: interface.name.clone(),
                bytes: value
                    .and_then(|value| value.bytes)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                packets: value
                    .and_then(|value| value.packets)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                drops: value
                    .and_then(|value| value.drops)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
                overlimits: value
                    .and_then(|value| value.overlimits)
                    .filter(|count| *count <= netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER),
            });
        }
    }
    Ok(metrics)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ParsedClassCounters {
    bytes: Option<u64>,
    packets: Option<u64>,
    drops: Option<u64>,
    overlimits: Option<u64>,
}

fn parse_class_counters(output: &str) -> HashMap<String, ParsedClassCounters> {
    let mut counters = HashMap::new();
    let mut current = None::<String>;
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"class") {
            current = fields.get(2).map(|value| (*value).to_owned());
            if let Some(class_id) = &current {
                counters.entry(class_id.clone()).or_default();
            }
            continue;
        }
        let Some(class_id) = current.as_ref() else {
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
            class_id.clone(),
            ParsedClassCounters {
                bytes,
                packets,
                drops,
                overlimits,
            },
        );
    }
    counters
}

pub(super) fn write_journal(
    state_path: &Path,
    previous: Option<&ShapingState>,
    next: Option<&ShapingState>,
) -> Result<(), String> {
    let mut interfaces = HashMap::<String, ManagedInterface>::new();
    for interface in previous
        .into_iter()
        .flat_map(state_interfaces)
        .chain(next.into_iter().flat_map(state_interfaces))
    {
        interfaces.insert(interface.name.clone(), interface.clone());
    }
    let journal = ShapingJournal {
        schema_version: 1,
        previous: previous.cloned(),
        next: next.cloned(),
        interfaces: interfaces.into_values().collect(),
    };
    let bytes = serde_json::to_vec(&journal).map_err(|error| error.to_string())?;
    if bytes.len() > 256 * 1024 {
        return Err("refuse to persist a shaping recovery journal above 256 KiB".to_owned());
    }
    atomic_write(&journal_path(state_path), &bytes)
}

pub(super) fn clear_journal(state_path: &Path) -> Result<(), String> {
    let path = journal_path(state_path);
    match fs::remove_file(&path) {
        Ok(()) => sync_parent(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove shaping recovery journal: {error}")),
    }
}

pub(super) fn recover_journal(
    state_path: &Path,
    committed: Option<&ShapingState>,
) -> Result<bool, String> {
    let path = journal_path(state_path);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("read shaping recovery journal: {error}")),
    };
    let mut bytes = Vec::new();
    file.take((MAX_SHAPING_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read shaping recovery journal: {error}"))?;
    if bytes.len() > MAX_SHAPING_JOURNAL_BYTES {
        return Err("shaping recovery journal exceeds the size limit".to_owned());
    }
    let journal: ShapingJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode shaping recovery journal: {error}"))?;
    if journal.schema_version != 1 {
        return Err("unsupported shaping recovery journal schema".to_owned());
    }
    if let Some(state) = &journal.previous {
        state.validate()?;
    }
    if let Some(state) = &journal.next {
        state.validate()?;
    }
    let target = if committed == journal.next.as_ref() {
        committed
    } else {
        journal.previous.as_ref()
    };
    for interface in &journal.interfaces {
        restore_from_journal(interface, &journal)?;
    }
    if let Some(target) = target {
        for interface in state_interfaces(target) {
            apply_interface(interface, None)?;
        }
    }
    clear_journal(state_path)?;
    Ok(true)
}

fn restore_from_journal(
    interface: &ManagedInterface,
    journal: &ShapingJournal,
) -> Result<(), String> {
    let ifindex = nix::net::if_::if_nametoindex(interface.name.as_str()).map_err(|error| {
        format!(
            "manual_cleanup_required: interface {} disappeared during recovery: {error}",
            interface.name
        )
    })?;
    if ifindex != interface.ifindex {
        return Err(format!(
            "manual_cleanup_required: interface {} changed ifindex from {} to {ifindex} during recovery",
            interface.name, interface.ifindex
        ));
    }
    let root = inspect_root(&interface.name)?;
    let kind = root_kind(&root).unwrap_or_default();
    if kind == interface.original_root_kind {
        if inspect_default_root(&interface.name)? != interface.original_root_kind {
            return Err(format!(
                "manual_cleanup_required: original qdisc on {} changed during recovery",
                interface.name
            ));
        }
        return Ok(());
    }
    if kind != "htb" || root.get("handle").and_then(Value::as_str) != Some(ROOT_HANDLE) {
        return Err(format!(
            "manual_cleanup_required: {} no longer has the expected NetQmon qdisc or saved system default",
            interface.name
        ));
    }
    let known_interfaces = [journal.previous.as_ref(), journal.next.as_ref()]
        .into_iter()
        .flatten()
        .flat_map(state_interfaces)
        .filter(|item| item.name == interface.name)
        .cloned()
        .collect::<Vec<_>>();
    let known_clients = known_interfaces
        .iter()
        .flat_map(|item| item.clients.iter().cloned())
        .collect::<Vec<_>>();
    let known_applications = known_interfaces
        .iter()
        .flat_map(|item| item.application_classes.iter().cloned())
        .collect::<Vec<_>>();
    verify_partial_tree(interface, &known_clients, &known_applications)?;
    restore_root_kind(&interface.name, &interface.original_root_kind)
}

fn verify_partial_tree(
    interface: &ManagedInterface,
    known_clients: &[ClientClass],
    known_applications: &[ApplicationClass],
) -> Result<(), String> {
    let allowed_classes = std::iter::once("51:1".to_owned())
        .chain(shared_class_ids(interface))
        .chain(
            known_clients
                .iter()
                .map(|client| format!("51:{}", client.class_minor)),
        )
        .chain(
            known_applications
                .iter()
                .map(|application| format!("51:{}", application.class_minor)),
        )
        .chain(known_applications.iter().filter_map(|application| {
            known_clients
                .iter()
                .find(|client| client.class_minor == application.parent_class_minor)
                .map(|client| format!("51:{}", default_class_minor(client.tag)))
        }))
        .collect::<BTreeSet<_>>();
    let class_output = run_capture("tc", &["-r", "class", "show", "dev", &interface.name])?;
    for class_id in class_output
        .lines()
        .filter(|line| line.split_whitespace().nth(1) == Some("htb"))
        .filter_map(|line| line.split_whitespace().nth(2))
    {
        if !allowed_classes.contains(class_id) {
            return Err(format!(
                "manual_cleanup_required: unknown class {class_id} exists on {}",
                interface.name
            ));
        }
    }
    verify_partial_leaves(interface, known_clients, known_applications)?;
    let filters = run_capture(
        "tc",
        &[
            "filter",
            "show",
            "dev",
            &interface.name,
            "parent",
            ROOT_HANDLE,
        ],
    )?;
    for line in filters.lines() {
        if line.trim().is_empty() || !line.contains("handle") {
            continue;
        }
        let expected = shared_fallbacks(interface)
            .into_iter()
            .filter(|(tag, _)| *tag != 0)
            .any(|(tag, minor)| {
                line.contains(&format!(
                    "0x{:x}/0x{:x}",
                    client_mark_value(tag),
                    CLIENT_MARK_MASK
                )) && line.contains(&format!("51:{minor}"))
                    && line.contains(" fw ")
            })
            || known_clients.iter().any(|client| {
                let handle = format!(
                    "0x{:x}/0x{:x}",
                    client_mark_value(client.tag),
                    CLIENT_MARK_MASK
                );
                let classid = format!("51:{}", client.class_minor);
                line.contains(&handle) && line.contains(&classid) && line.contains(" fw ")
            });
        if !expected {
            return Err(format!(
                "manual_cleanup_required: unknown root filter exists on {}",
                interface.name
            ));
        }
    }
    let parent_classes = known_applications
        .iter()
        .map(|application| application.parent_class_minor)
        .collect::<BTreeSet<_>>();
    for parent_minor in parent_classes {
        let parent = format!("51:{parent_minor}");
        let filters = run_capture(
            "tc",
            &["filter", "show", "dev", &interface.name, "parent", &parent],
        )?;
        for line in filters
            .lines()
            .filter(|line| !line.trim().is_empty() && line.contains("handle"))
        {
            let known_application_filter = known_applications.iter().any(|application| {
                let handle = format!(
                    "0x{:x}/0x{:x}",
                    application_mark_value(application.tag),
                    APPLICATION_MARK_MASK
                );
                let classid = format!("51:{}", application.class_minor);
                application.parent_class_minor == parent_minor
                    && line.contains(&handle)
                    && line.contains(&classid)
                    && line.contains(" fw ")
            });
            let default_class = known_clients
                .iter()
                .find(|client| client.class_minor == parent_minor)
                .map(|client| format!("51:{}", default_class_minor(client.tag)));
            let default_filter = default_class
                .as_ref()
                .is_some_and(|classid| line.contains("matchall") && line.contains(classid));
            let expected = known_application_filter || default_filter;
            if !expected {
                return Err(format!(
                    "manual_cleanup_required: unknown application filter exists under {parent} on {}",
                    interface.name
                ));
            }
        }
    }
    Ok(())
}

fn restore_root_kind(interface: &str, kind: &str) -> Result<(), String> {
    run_tc(&[
        "qdisc",
        "del",
        "dev",
        interface,
        "root",
        "handle",
        ROOT_HANDLE,
    ])?;
    if kind != "noqueue" {
        run_tc(&["qdisc", "replace", "dev", interface, "root", kind])?;
    }
    if root_kind(&inspect_root(interface)?).as_deref() != Some(kind) {
        return Err(format!(
            "manual_cleanup_required: root qdisc on {interface} did not return to {kind}"
        ));
    }
    Ok(())
}

fn state_interfaces(state: &ShapingState) -> impl Iterator<Item = &ManagedInterface> {
    state.interfaces()
}

fn journal_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("shaping-journal.json")
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "shaping journal path has no parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create shaping journal directory: {error}"))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create shaping journal: {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("write shaping journal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync shaping journal: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("install shaping journal: {error}"))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "shaping journal path has no parent directory".to_owned())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync shaping journal directory: {error}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShapingJournal {
    schema_version: u32,
    previous: Option<ShapingState>,
    next: Option<ShapingState>,
    interfaces: Vec<ManagedInterface>,
}

fn rollback_changed(
    changed: &[(ManagedInterface, Option<ManagedInterface>)],
    previous: Option<&ShapingState>,
    desired: &ShapingState,
) {
    let mut interfaces = HashMap::<String, ManagedInterface>::new();
    for interface in previous
        .into_iter()
        .flat_map(state_interfaces)
        .chain(state_interfaces(desired))
    {
        interfaces.insert(interface.name.clone(), interface.clone());
    }
    let journal = ShapingJournal {
        schema_version: 1,
        previous: previous.cloned(),
        next: (!desired.is_empty()).then(|| desired.clone()),
        interfaces: interfaces.into_values().collect(),
    };
    for (new, old) in changed.iter().rev() {
        let interface = old.as_ref().unwrap_or(new);
        if let Err(error) = restore_from_journal(interface, &journal) {
            eprintln!(
                "policy qdisc rollback failed for {}: {error}",
                interface.name
            );
            continue;
        }
        if let Some(previous) = previous
            && let Some(previous_interface) =
                state_interfaces(previous).find(|previous| previous.name == interface.name)
            && let Err(error) = apply_interface(previous_interface, None)
        {
            eprintln!(
                "policy qdisc rollback failed for {}: {error}",
                interface.name
            );
        }
    }
    if let Some(previous) = previous {
        for old in previous.interfaces() {
            if !changed.iter().any(|(new, _)| new.name == old.name)
                && let Err(error) = verify_owned(old)
            {
                eprintln!(
                    "policy qdisc rollback verification failed for {}: {error}",
                    old.name
                );
            }
        }
    }
    let _ = desired;
}

fn apply_interface(
    interface: &ManagedInterface,
    previous: Option<&ManagedInterface>,
) -> Result<(), String> {
    let ifindex = nix::net::if_::if_nametoindex(interface.name.as_str()).map_err(|error| {
        format!(
            "degraded_ownership_conflict: interface {} disappeared: {error}",
            interface.name
        )
    })?;
    if ifindex != interface.ifindex {
        return Err(format!(
            "degraded_ownership_conflict: interface {} changed ifindex from {} to {ifindex}",
            interface.name, interface.ifindex
        ));
    }
    let mut migrate_legacy = false;
    if let Some(previous) = previous {
        verify_owned(previous)?;
        if previous.shared_egress && previous.application_classes.is_empty() {
            let classes = read_class_details(&interface.name)?;
            migrate_legacy = classes
                .get("51:11")
                .is_some_and(|class| class.rate_bps == Some(8))
                || previous.clients.iter().any(|client| {
                    classes
                        .get(&format!("51:{}", client.class_minor))
                        .is_some_and(|class| class.rate_bps == Some(8))
                });
        } else if !previous.shared_egress {
            let classes = read_class_details(&interface.name)?;
            migrate_legacy = previous.clients.iter().any(|client| {
                !class_has_rates(
                    classes.get(&format!("51:{}", client.class_minor)),
                    client_guarantee(previous, client),
                    client.rate_bps,
                )
            });
        }
        if previous == interface && !migrate_legacy {
            return Ok(());
        }
    } else {
        let current = inspect_default_root(&interface.name)?;
        if current != interface.original_root_kind {
            return Err(format!(
                "degraded_ownership_conflict: root qdisc on {} changed from {} to {current}",
                interface.name, interface.original_root_kind
            ));
        }
    }

    if migrate_legacy && interface.shared_egress {
        install_shared_directions(interface)?;
    }
    if previous.is_none_or(|previous| previous.shared_egress != interface.shared_egress) {
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            &interface.name,
            "root",
            "handle",
            ROOT_HANDLE,
            "htb",
            "default",
            if interface.shared_egress { "11" } else { "1" },
        ])?;
    }
    let base_rate = format!("{}bit", interface.capacity_bps);
    let base_burst = format!("{}b", burst_bytes(interface.capacity_bps));
    if previous.is_none_or(|previous| {
        previous.capacity_bps != interface.capacity_bps
            || previous.shared_egress != interface.shared_egress
    }) {
        run_tc(&[
            "class",
            "replace",
            "dev",
            &interface.name,
            "parent",
            ROOT_HANDLE,
            "classid",
            "51:1",
            "htb",
            "rate",
            &base_rate,
            "ceil",
            &base_rate,
            "burst",
            &base_burst,
            "cburst",
            &base_burst,
        ])?;
        if interface.shared_egress {
            install_shared_directions(interface)?;
        }
    }
    if interface.clients.is_empty() && !interface.shared_egress {
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            &interface.name,
            "parent",
            "51:1",
            "handle",
            "4096:",
            "fq_codel",
        ])?;
    }

    if let Some(previous) = previous {
        for old in &previous.clients {
            let old_apps = previous
                .application_classes
                .iter()
                .filter(|app| app.parent_class_minor == old.class_minor)
                .collect::<Vec<_>>();
            let next_client = interface.clients.iter().find(|client| {
                client.class_minor == old.class_minor
                    && client.mac == old.mac
                    && client.direction == old.direction
                    && client.tag == old.tag
            });
            let next_apps = interface
                .application_classes
                .iter()
                .filter(|app| next_client.is_some() && app.parent_class_minor == old.class_minor)
                .collect::<Vec<_>>();
            if !old_apps.is_empty() {
                let retained = |app: &ApplicationClass| {
                    next_apps.iter().any(|next| {
                        next.class_minor == app.class_minor
                            && next.policy_id == app.policy_id
                            && next.mac == app.mac
                            && next.direction == app.direction
                            && next.tag == app.tag
                    })
                };
                // Updating rates must retain the live leaf queues. Apart
                // from dropping backlog, rebuilding them loses counters
                // and can stall TCP senders during repeated revisions.
                if old_apps.len() != next_apps.len() || old_apps.iter().any(|app| !retained(app)) {
                    run_tc(&[
                        "filter",
                        "del",
                        "dev",
                        &interface.name,
                        "parent",
                        &format!("51:{}", old.class_minor),
                    ])?;
                }
                for app in old_apps {
                    if retained(app) {
                        continue;
                    }
                    run_tc(&[
                        "class",
                        "del",
                        "dev",
                        &interface.name,
                        "classid",
                        &format!("51:{}", app.class_minor),
                    ])?;
                }
                if next_apps.is_empty() {
                    run_tc(&[
                        "class",
                        "del",
                        "dev",
                        &interface.name,
                        "classid",
                        &format!("51:{}", default_class_minor(old.tag)),
                    ])?;
                }
            } else if !next_apps.is_empty() {
                run_tc(&[
                    "qdisc",
                    "del",
                    "dev",
                    &interface.name,
                    "parent",
                    &format!("51:{}", old.class_minor),
                ])?;
            }
        }
    }
    for client in &interface.clients {
        if !migrate_legacy
            && previous.is_some_and(|previous| previous.clients.contains(client))
            && previous.is_some_and(|previous| {
                client_guarantee(previous, client) == client_guarantee(interface, client)
            })
            && !interface
                .application_classes
                .iter()
                .any(|app| app.parent_class_minor == client.class_minor)
            && previous.is_some_and(|previous| {
                !previous
                    .application_classes
                    .iter()
                    .any(|app| app.parent_class_minor == client.class_minor)
            })
        {
            continue;
        }
        let applications = interface
            .application_classes
            .iter()
            .filter(|application| application.parent_class_minor == client.class_minor)
            .collect::<Vec<_>>();
        let child_rates = application_child_rates(
            client_guarantee(interface, client),
            default_class_minor(client.tag),
            &applications,
        );
        let default_rate =
            (!applications.is_empty()).then(|| child_rates[&default_class_minor(client.tag)]);
        add_client_class(
            &interface.name,
            client,
            default_rate,
            interface.shared_egress,
            client_guarantee(interface, client),
        )?;
        for application in applications {
            add_application_class(
                &interface.name,
                application,
                child_rates[&application.class_minor],
            )?;
        }
    }
    if let Some(previous) = previous {
        for removed in previous.clients.iter().filter(|old| {
            !interface
                .clients
                .iter()
                .any(|next| next.class_minor == old.class_minor)
        }) {
            let handle = format!(
                "0x{:x}/0x{:x}",
                client_mark_value(removed.tag),
                CLIENT_MARK_MASK
            );
            run_tc(&[
                "filter",
                "del",
                "dev",
                &interface.name,
                "parent",
                ROOT_HANDLE,
                "protocol",
                "all",
                "prio",
                "100",
                "handle",
                &handle,
                "fw",
            ])?;
            run_tc(&[
                "class",
                "del",
                "dev",
                &interface.name,
                "classid",
                &format!("51:{}", removed.class_minor),
            ])?;
        }
    }
    verify_owned(interface)
}

fn shared_class_ids(interface: &ManagedInterface) -> impl Iterator<Item = String> {
    [10, 20, 11, 21]
        .into_iter()
        .filter(|_| interface.shared_egress)
        .map(|minor| format!("51:{minor}"))
}

fn shared_fallbacks(interface: &ManagedInterface) -> Vec<(u16, u16)> {
    if interface.shared_egress {
        vec![(0, 11), (super::shaper::SHARED_DIRECTION_TAG, 21)]
    } else {
        Vec::new()
    }
}

fn install_shared_directions(interface: &ManagedInterface) -> Result<(), String> {
    let capacity = format!("{}bit", interface.capacity_bps);
    let guarantee = format!("{}bit", interface.capacity_bps / 2);
    let fallback_rate = format!("{}bit", shared_fallback_guarantee(interface));
    let parent_burst = format!("{}b", burst_bytes(interface.capacity_bps / 2));
    let fallback_burst = format!("{}b", burst_bytes(shared_fallback_guarantee(interface)));
    let capacity_burst = format!("{}b", burst_bytes(interface.capacity_bps));
    for (parent, fallback, tag, leaf) in [
        (10, 11, 0, 4097),
        (20, 21, super::shaper::SHARED_DIRECTION_TAG, 4098),
    ] {
        let parent_id = format!("51:{parent}");
        let fallback_id = format!("51:{fallback}");
        run_tc(&[
            "class",
            "replace",
            "dev",
            &interface.name,
            "parent",
            "51:1",
            "classid",
            &parent_id,
            "htb",
            "rate",
            &guarantee,
            "ceil",
            &capacity,
            "burst",
            &parent_burst,
            "cburst",
            &capacity_burst,
        ])?;
        run_tc(&[
            "class",
            "replace",
            "dev",
            &interface.name,
            "parent",
            &parent_id,
            "classid",
            &fallback_id,
            "htb",
            "rate",
            &fallback_rate,
            "ceil",
            &capacity,
            "burst",
            &fallback_burst,
            "cburst",
            &capacity_burst,
        ])?;
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            &interface.name,
            "parent",
            &fallback_id,
            "handle",
            &format!("{leaf}:"),
            "fq_codel",
        ])?;
        if tag != 0 {
            run_tc(&[
                "filter",
                "replace",
                "dev",
                &interface.name,
                "parent",
                ROOT_HANDLE,
                "protocol",
                "all",
                "prio",
                "200",
                "handle",
                &format!("0x{:x}/0x{:x}", client_mark_value(tag), CLIENT_MARK_MASK),
                "fw",
                "classid",
                &fallback_id,
            ])?;
        }
    }
    Ok(())
}

fn application_child_rates(
    parent_rate_bps: u64,
    default_minor: u16,
    applications: &[&ApplicationClass],
) -> BTreeMap<u16, u64> {
    let mut rates = BTreeMap::new();
    if applications.is_empty() {
        return rates;
    }

    let total_application_rate = applications
        .iter()
        .map(|application| u128::from(application.rate_bps / 8))
        .sum::<u128>();
    let parent_rate_bps = parent_rate_bps / 8;
    if total_application_rate < u128::from(parent_rate_bps) {
        let used_application_rate =
            u64::try_from(total_application_rate).expect("rate is below the u64 parent budget");
        for application in applications {
            rates.insert(application.class_minor, application.rate_bps / 8 * 8);
        }
        rates.insert(default_minor, (parent_rate_bps - used_application_rate) * 8);
        return rates;
    }

    // HTB guarantees each leaf class's `rate` before it can borrow. Keep the
    // sum of child guarantees at the client's parent rate so application caps
    // and the default class cannot collectively exceed that aggregate budget.
    let default_rate_bps = 1;
    let application_budget = parent_rate_bps - default_rate_bps - applications.len() as u64;
    let mut allocated = 0_u64;
    let mut remainders = Vec::with_capacity(applications.len());
    for application in applications {
        let weighted_budget = u128::from(application_budget) * u128::from(application.rate_bps / 8);
        let guaranteed_rate = u64::try_from(weighted_budget / total_application_rate)
            .expect("application share is within the parent rate budget");
        let remainder = weighted_budget % total_application_rate;
        rates.insert(application.class_minor, (guaranteed_rate + 1) * 8);
        allocated += guaranteed_rate;
        remainders.push((remainder, application.class_minor));
    }
    remainders.sort_by(|left, right| right.cmp(left));
    let remaining = usize::try_from(application_budget - allocated)
        .expect("fractional remainder count fits the application list");
    for (_, class_minor) in remainders.into_iter().take(remaining) {
        *rates
            .get_mut(&class_minor)
            .expect("every application class was allocated") += 8;
    }
    rates.insert(default_minor, default_rate_bps * 8);
    rates
}

// Divide each direction's guarantee across every client. Tiny placeholder
// rates cannot represent normal HTB burst sizes and stall GSO TCP traffic.
fn shared_fallback_guarantee(interface: &ManagedInterface) -> u64 {
    // Keep Agent control traffic and unselected clients moving even when all
    // selected client guarantees consume their direction's capacity.
    (interface.capacity_bps / 32).min(1_000_000) / 8 * 8
}

fn client_guarantee(interface: &ManagedInterface, client: &ClientClass) -> u64 {
    let peers = interface
        .clients
        .iter()
        .filter(|peer| !interface.shared_egress || peer.direction == client.direction)
        .collect::<Vec<_>>();
    let budget = if interface.shared_egress {
        (interface.capacity_bps / 2).saturating_sub(shared_fallback_guarantee(interface))
    } else {
        interface.capacity_bps
    };
    let demand = peers
        .iter()
        .map(|peer| u128::from(peer.rate_bps))
        .sum::<u128>();
    let share = (u128::from(budget) * u128::from(client.rate_bps) / demand.max(1)) as u64;
    client.rate_bps.min(share) / 8 * 8
}

fn add_client_class(
    interface: &str,
    client: &ClientClass,
    default_rate_bps: Option<u64>,
    shared: bool,
    guaranteed_rate_bps: u64,
) -> Result<(), String> {
    let classid = format!("51:{}", client.class_minor);
    let parent_rate = format!("{}bit", client.rate_bps);
    let guaranteed_rate = format!("{guaranteed_rate_bps}bit");
    let parent = if shared {
        match client.direction {
            super::shaper::Direction::Upload => "51:10",
            super::shaper::Direction::Download => "51:20",
        }
    } else {
        "51:1"
    };
    let burst = format!("{}b", burst_bytes(client.rate_bps));
    run_tc(&[
        "class",
        "replace",
        "dev",
        interface,
        "parent",
        parent,
        "classid",
        &classid,
        "htb",
        "rate",
        &guaranteed_rate,
        "ceil",
        &parent_rate,
        "burst",
        &burst,
        "cburst",
        &burst,
    ])?;
    if let Some(default_rate_bps) = default_rate_bps {
        let default_minor = default_class_minor(client.tag);
        let default_classid = format!("51:{default_minor}");
        let default_rate = format!("{default_rate_bps}bit");
        run_tc(&[
            "class",
            "replace",
            "dev",
            interface,
            "parent",
            &classid,
            "classid",
            &default_classid,
            "htb",
            "rate",
            &default_rate,
            "ceil",
            &parent_rate,
            "burst",
            &burst,
            "cburst",
            &burst,
        ])?;
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            interface,
            "parent",
            &default_classid,
            "handle",
            &format!("{}:", client.leaf_minor),
            "fq_codel",
        ])?;
        // cls_matchall refuses replacing an existing head on supported older
        // kernels. Its target does not change when only the budget changes.
        let default_filter = run_capture(
            "tc",
            &[
                "filter", "show", "dev", interface, "parent", &classid, "prio", "200",
            ],
        )?;
        if default_filter.trim().is_empty() {
            run_tc(&[
                "filter",
                "add",
                "dev",
                interface,
                "parent",
                &classid,
                "protocol",
                "all",
                "prio",
                "200",
                "handle",
                "1",
                "matchall",
                "classid",
                &default_classid,
            ])?;
        } else if !default_filter.contains("matchall") || !default_filter.contains(&default_classid)
        {
            return Err(format!(
                "degraded_ownership_conflict: unexpected default classifier on {interface}/{classid}"
            ));
        }
    } else {
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            interface,
            "parent",
            &classid,
            "handle",
            &format!("{}:", client.leaf_minor),
            "fq_codel",
        ])?;
    }
    let handle = format!(
        "0x{:x}/0x{:x}",
        client_mark_value(client.tag),
        CLIENT_MARK_MASK
    );
    run_tc(&[
        "filter",
        "replace",
        "dev",
        interface,
        "parent",
        ROOT_HANDLE,
        "protocol",
        "all",
        "prio",
        "100",
        "handle",
        &handle,
        "fw",
        "classid",
        &classid,
    ])
}

fn add_application_class(
    interface: &str,
    application: &ApplicationClass,
    guaranteed_rate_bps: u64,
) -> Result<(), String> {
    let classid = format!("51:{}", application.class_minor);
    let parent = format!("51:{}", application.parent_class_minor);
    let rate = format!("{guaranteed_rate_bps}bit");
    let ceil = format!("{}bit", application.rate_bps);
    let burst = format!("{}b", burst_bytes(application.rate_bps));
    run_tc(&[
        "class", "replace", "dev", interface, "parent", &parent, "classid", &classid, "htb",
        "rate", &rate, "ceil", &ceil, "burst", &burst, "cburst", &burst,
    ])?;
    run_tc(&[
        "qdisc",
        "replace",
        "dev",
        interface,
        "parent",
        &classid,
        "handle",
        &format!("{:x}:", application_leaf_minor(application.class_minor)),
        "fq_codel",
    ])?;
    let handle = format!(
        "0x{:x}/0x{:x}",
        application_mark_value(application.tag),
        APPLICATION_MARK_MASK
    );
    run_tc(&[
        "filter", "replace", "dev", interface, "parent", &parent, "protocol", "all", "prio", "100",
        "handle", &handle, "fw", "classid", &classid,
    ])
}

fn restore_interface(interface: &ManagedInterface) -> Result<(), String> {
    verify_owned(interface)?;
    run_tc(&[
        "qdisc",
        "del",
        "dev",
        &interface.name,
        "root",
        "handle",
        ROOT_HANDLE,
    ])?;
    if interface.original_root_kind != "noqueue" {
        run_tc(&[
            "qdisc",
            "replace",
            "dev",
            &interface.name,
            "root",
            &interface.original_root_kind,
        ])?;
    }
    let restored = inspect_root(&interface.name)?;
    if root_kind(&restored).as_deref() != Some(interface.original_root_kind.as_str()) {
        return Err(format!(
            "manual_cleanup_required: root qdisc on {} did not return to {}",
            interface.name, interface.original_root_kind
        ));
    }
    Ok(())
}

fn inspect_default_root(interface: &str) -> Result<String, String> {
    let ifindex = nix::net::if_::if_nametoindex(interface).map_err(|error| {
        format!("unsupported_existing_qdisc: cannot resolve {interface}: {error}")
    })?;
    let root = inspect_root(interface)?;
    let kind = root_kind(&root).ok_or_else(|| {
        format!("unsupported_existing_qdisc: {interface} has no unique root qdisc")
    })?;
    if !matches!(kind.as_str(), "fq_codel" | "pfifo_fast" | "noqueue")
        || !default_root_options_match(&kind, &root)
    {
        return Err(format!(
            "unsupported_existing_qdisc: {interface} root qdisc {kind} is not a known system default"
        ));
    }
    let classes = run_capture("tc", &["class", "show", "dev", interface])?;
    if !classes.trim().is_empty() {
        return Err(format!(
            "unsupported_existing_qdisc: {interface} has existing traffic-control classes"
        ));
    }
    let filters = run_json("tc", &["-j", "filter", "show", "dev", interface])?;
    let root_handle = root
        .get("handle")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let has_root_filters = filters.as_array().is_none_or(|filters| {
        filters
            .iter()
            .any(|filter| filter.get("parent").and_then(Value::as_str) == Some(root_handle))
    });
    if has_root_filters {
        return Err(format!(
            "unsupported_existing_qdisc: {interface} has existing root traffic-control filters"
        ));
    }
    if ifindex == 0 {
        return Err(format!(
            "unsupported_topology: {interface} has invalid ifindex"
        ));
    }
    Ok(kind)
}

fn inspect_root(interface: &str) -> Result<Value, String> {
    let qdiscs = run_json("tc", &["-j", "qdisc", "show", "dev", interface])?;
    let roots = qdiscs
        .as_array()
        .ok_or_else(|| "tc returned an invalid qdisc list".to_owned())?
        .iter()
        .filter(|qdisc| qdisc.get("root").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(format!(
            "unsupported_existing_qdisc: {interface} did not report exactly one root qdisc"
        ));
    }
    Ok(roots[0].clone())
}

fn root_kind(root: &Value) -> Option<String> {
    root.get("kind")?.as_str().map(str::to_owned)
}

fn default_root_options_match(kind: &str, root: &Value) -> bool {
    match kind {
        "noqueue" | "pfifo_fast" => root
            .get("options")
            .is_none_or(|value| value.as_object().is_none_or(|options| options.is_empty())),
        "fq_codel" => {
            let Some(options) = root.get("options").and_then(Value::as_object) else {
                return false;
            };
            option_near(options, "limit", 10_240, 0)
                && option_near(options, "flows", 1_024, 0)
                && option_near(options, "quantum", 1_514, 0)
                && option_near(options, "target", 5_000, 1)
                && option_near(options, "interval", 100_000, 1)
                && option_near(options, "memory_limit", 33_554_432, 0)
                && options.get("ecn").and_then(Value::as_bool) == Some(true)
                && option_near(options, "drop_batch", 64, 0)
        }
        _ => false,
    }
}

fn option_near(
    options: &serde_json::Map<String, Value>,
    key: &str,
    expected: u64,
    tolerance: u64,
) -> bool {
    options
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|actual| actual.abs_diff(expected) <= tolerance)
}

pub(super) fn verify_owned(interface: &ManagedInterface) -> Result<(), String> {
    let ifindex = nix::net::if_::if_nametoindex(interface.name.as_str()).map_err(|error| {
        format!(
            "degraded_ownership_conflict: cannot resolve {}: {error}",
            interface.name
        )
    })?;
    if ifindex != interface.ifindex {
        return Err(format!(
            "degraded_ownership_conflict: interface {} changed ifindex from {} to {ifindex}",
            interface.name, interface.ifindex
        ));
    }
    let root = inspect_root(&interface.name)?;
    if root_kind(&root).as_deref() != Some("htb")
        || root.get("handle").and_then(Value::as_str) != Some(ROOT_HANDLE)
    {
        return Err(format!(
            "degraded_ownership_conflict: NetQmon HTB root is no longer present on {}",
            interface.name
        ));
    }
    let class_output = run_capture("tc", &["-r", "class", "show", "dev", &interface.name])?;
    let actual = class_output
        .lines()
        .filter(|line| line.split_whitespace().nth(1) == Some("htb"))
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let application_parents = interface
        .application_classes
        .iter()
        .map(|application| application.parent_class_minor)
        .collect::<BTreeSet<_>>();
    let expected = std::iter::once("51:1".to_owned())
        .chain(shared_class_ids(interface))
        .chain(
            interface
                .clients
                .iter()
                .map(|client| format!("51:{}", client.class_minor)),
        )
        .chain(
            interface
                .application_classes
                .iter()
                .map(|application| format!("51:{}", application.class_minor)),
        )
        .chain(interface.clients.iter().filter_map(|client| {
            application_parents
                .contains(&client.class_minor)
                .then(|| format!("51:{}", default_class_minor(client.tag)))
        }))
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "degraded_ownership_conflict: class tree on {} differs from the saved NetQmon plan",
            interface.name
        ));
    }
    let class_details = read_class_details(&interface.name)?;
    if class_details.len() != expected.len()
        || !class_has_exact_rates(class_details.get("51:1"), interface.capacity_bps)
        || interface.clients.iter().any(|client| {
            !class_has_rates(
                class_details.get(&format!("51:{}", client.class_minor)),
                client_guarantee(interface, client),
                client.rate_bps,
            ) && !(interface.shared_egress
                && interface.application_classes.is_empty()
                && class_has_rates(
                    class_details.get(&format!("51:{}", client.class_minor)),
                    8,
                    client.rate_bps,
                ))
                && !(!interface.shared_egress
                    && class_has_exact_rates(
                        class_details.get(&format!("51:{}", client.class_minor)),
                        client.rate_bps,
                    ))
        })
        || interface.clients.iter().any(|client| {
            let applications = interface
                .application_classes
                .iter()
                .filter(|application| application.parent_class_minor == client.class_minor)
                .collect::<Vec<_>>();
            if applications.is_empty() {
                return false;
            }
            let default_rate = application_child_rates(
                client_guarantee(interface, client),
                default_class_minor(client.tag),
                &applications,
            )[&default_class_minor(client.tag)];
            let class = class_details.get(&format!("51:{}", default_class_minor(client.tag)));
            let legacy_rate = application_child_rates(
                client.rate_bps,
                default_class_minor(client.tag),
                &applications,
            )[&default_class_minor(client.tag)];
            !class_has_rates_or_legacy(class, default_rate, client.rate_bps, client.rate_bps)
                && !(!interface.shared_egress
                    && class_has_rates(class, legacy_rate, client.rate_bps))
        })
        || interface.application_classes.iter().any(|application| {
            let applications = interface
                .application_classes
                .iter()
                .filter(|sibling| sibling.parent_class_minor == application.parent_class_minor)
                .collect::<Vec<_>>();
            let client = interface
                .clients
                .iter()
                .find(|client| client.class_minor == application.parent_class_minor)
                .expect("application parent was validated");
            let guaranteed_rate = application_child_rates(
                client_guarantee(interface, client),
                default_class_minor(client.tag),
                &applications,
            )[&application.class_minor];
            let class = class_details.get(&format!("51:{}", application.class_minor));
            let legacy_rate = application_child_rates(
                client.rate_bps,
                default_class_minor(client.tag),
                &applications,
            )[&application.class_minor];
            !class_has_rates_or_legacy(
                class,
                guaranteed_rate,
                application.rate_bps,
                application.rate_bps,
            ) && !(!interface.shared_egress
                && class_has_rates(class, legacy_rate, application.rate_bps))
        })
    {
        return Err(format!(
            "degraded_ownership_conflict: class rates on {} differ from the saved NetQmon plan",
            interface.name
        ));
    }
    if interface.shared_egress {
        let cap = interface.capacity_bps;
        for (minor, parent, rate, ceil) in [
            (10, "51:1", cap / 2, cap),
            (20, "51:1", cap / 2, cap),
            (11, "51:10", shared_fallback_guarantee(interface), cap),
            (21, "51:20", shared_fallback_guarantee(interface), cap),
        ] {
            let id = format!("51:{minor}");
            if !(class_has_rates(class_details.get(&id), rate, ceil)
                || (matches!(minor, 11 | 21) && class_has_rates(class_details.get(&id), 8, ceil)))
                || !class_has_parent(&class_output, &id, parent)
            {
                return Err("degraded_ownership_conflict: shared direction/fallback tree differs from saved state".to_owned());
            }
        }
        for client in &interface.clients {
            let parent = match client.direction {
                super::shaper::Direction::Upload => "51:10",
                super::shaper::Direction::Download => "51:20",
            };
            if !class_has_parent(&class_output, &format!("51:{}", client.class_minor), parent) {
                return Err(
                    "degraded_ownership_conflict: shared client has the wrong direction parent"
                        .to_owned(),
                );
            }
        }
    }
    verify_owned_leaves(interface)?;
    verify_owned_filters(
        &interface.name,
        ROOT_HANDLE,
        &interface
            .clients
            .iter()
            .map(|client| (client.tag, client.class_minor, false))
            .chain(
                shared_fallbacks(interface)
                    .into_iter()
                    .filter(|(tag, _)| *tag != 0)
                    .map(|(tag, minor)| (tag, minor, false)),
            )
            .collect::<Vec<_>>(),
    )?;
    for parent_minor in application_parents {
        let parent_tag = interface
            .clients
            .iter()
            .find(|client| client.class_minor == parent_minor)
            .map(|client| client.tag)
            .ok_or_else(|| "application class parent disappeared during verification".to_owned())?;
        let mut expected = interface
            .application_classes
            .iter()
            .filter(|application| application.parent_class_minor == parent_minor)
            .map(|application| (application.tag, application.class_minor, true))
            .collect::<Vec<_>>();
        expected.push((0, default_class_minor(parent_tag), true));
        verify_owned_filters(&interface.name, &format!("51:{parent_minor}"), &expected)?;
    }
    Ok(())
}

fn class_has_parent(output: &str, classid: &str, parent: &str) -> bool {
    output.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.get(2) == Some(&classid) && find_field(&fields, "parent") == Some(parent)
    })
}

fn verify_owned_filters(
    interface: &str,
    parent: &str,
    expected: &[(u16, u16, bool)],
) -> Result<(), String> {
    let filters = run_capture(
        "tc",
        &["filter", "show", "dev", interface, "parent", parent],
    )?;
    let lines = filters
        .lines()
        .filter(|line| !line.trim().is_empty() && line.contains("handle"))
        .collect::<Vec<_>>();
    if lines.len() != expected.len()
        || lines.iter().any(|line| {
            !expected.iter().any(|(tag, class_minor, application)| {
                let handle = if *application {
                    if *tag == 0 {
                        "matchall".to_owned()
                    } else {
                        format!(
                            "0x{:x}/0x{:x}",
                            application_mark_value(*tag),
                            APPLICATION_MARK_MASK
                        )
                    }
                } else {
                    format!("0x{:x}/0x{:x}", client_mark_value(*tag), CLIENT_MARK_MASK)
                };
                line.contains(&handle)
                    && line.contains(&format!("51:{class_minor}"))
                    && (*application && *tag == 0 || line.contains(" fw "))
            })
        })
    {
        return Err(format!(
            "degraded_ownership_conflict: filters under {parent} on {interface} differ from the saved NetQmon plan"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ParsedClassDetails {
    rate_bps: Option<u64>,
    ceil_bps: Option<u64>,
    rate_tolerance_bps: u64,
    ceil_tolerance_bps: u64,
}

fn read_class_details(interface: &str) -> Result<HashMap<String, ParsedClassDetails>, String> {
    let output = run_capture("tc", &["-j", "class", "show", "dev", interface])?;
    // Older iproute2 prints HTB classes as text even with -j. Newer tc
    // provides exact byte/second rates and also lists dynamic fq_codel classes.
    let Ok(Value::Array(classes)) = serde_json::from_str::<Value>(&output) else {
        return Ok(parse_class_details(&output));
    };
    Ok(classes
        .into_iter()
        .filter(|class| class.get("class").and_then(Value::as_str) == Some("htb"))
        .filter_map(|class| {
            let id = class.get("handle")?.as_str()?.to_owned();
            Some((
                id,
                ParsedClassDetails {
                    rate_bps: class
                        .get("rate")
                        .and_then(Value::as_u64)
                        .and_then(|rate| rate.checked_mul(8)),
                    ceil_bps: class
                        .get("ceil")
                        .and_then(Value::as_u64)
                        .and_then(|rate| rate.checked_mul(8)),
                    rate_tolerance_bps: 7,
                    ceil_tolerance_bps: 7,
                },
            ))
        })
        .collect())
}

fn parse_class_details(output: &str) -> HashMap<String, ParsedClassDetails> {
    let mut details = HashMap::new();
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() != Some(&"class") || fields.get(1) != Some(&"htb") {
            continue;
        }
        let Some(class_id) = fields.get(2) else {
            continue;
        };
        let rate = find_field(fields.as_slice(), "rate");
        let ceil = find_field(fields.as_slice(), "ceil");
        let rate_bps = rate.and_then(parse_rate_bps);
        let ceil_bps = ceil.and_then(parse_rate_bps);
        details.insert(
            (*class_id).to_owned(),
            ParsedClassDetails {
                rate_bps,
                ceil_bps,
                rate_tolerance_bps: if rate.is_some_and(|rate| rate.ends_with("Kbit")) {
                    1007
                } else {
                    7
                },
                ceil_tolerance_bps: if ceil.is_some_and(|rate| rate.ends_with("Kbit")) {
                    1007
                } else {
                    7
                },
            },
        );
    }
    details
}

fn find_field<'a>(fields: &'a [&str], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .position(|field| *field == key)
        .and_then(|index| fields.get(index + 1).copied())
}

fn parse_rate_bps(value: &str) -> Option<u64> {
    let unit_start = value.find(|character: char| character.is_ascii_alphabetic())?;
    let number = value[..unit_start].parse::<f64>().ok()?;
    let multiplier = match &value[unit_start..] {
        "bit" => 1.0,
        "Kbit" => 1_000.0,
        "Mbit" => 1_000_000.0,
        "Gbit" => 1_000_000_000.0,
        _ => return None,
    };
    let bps = (number * multiplier).round();
    (bps.is_finite() && bps >= 0.0 && bps <= u64::MAX as f64).then_some(bps as u64)
}

fn class_has_exact_rates(class: Option<&ParsedClassDetails>, expected_bps: u64) -> bool {
    class_has_rates(class, expected_bps, expected_bps)
}

fn class_has_rates(
    class: Option<&ParsedClassDetails>,
    expected_rate_bps: u64,
    expected_ceil_bps: u64,
) -> bool {
    class.is_some_and(|class| {
        class
            .rate_bps
            .is_some_and(|rate| rate.abs_diff(expected_rate_bps) <= class.rate_tolerance_bps)
            && class
                .ceil_bps
                .is_some_and(|ceil| ceil.abs_diff(expected_ceil_bps) <= class.ceil_tolerance_bps)
    })
}

fn class_has_rates_or_legacy(
    class: Option<&ParsedClassDetails>,
    expected_rate_bps: u64,
    expected_ceil_bps: u64,
    legacy_exact_rate_bps: u64,
) -> bool {
    class_has_rates(class, expected_rate_bps, expected_ceil_bps)
        || class_has_exact_rates(class, legacy_exact_rate_bps)
}

fn is_observation_clsact(qdisc: &Value) -> bool {
    qdisc.get("kind").and_then(Value::as_str) == Some("clsact")
        && qdisc.get("handle").and_then(Value::as_str) == Some("ffff:")
        && qdisc.get("parent").and_then(Value::as_str) == Some("ffff:fff1")
}

fn verify_owned_leaves(interface: &ManagedInterface) -> Result<(), String> {
    let qdiscs = run_json("tc", &["-j", "qdisc", "show", "dev", &interface.name])?;
    let application_parents = interface
        .application_classes
        .iter()
        .map(|application| application.parent_class_minor)
        .collect::<BTreeSet<_>>();
    let expected = interface
        .clients
        .is_empty()
        .then_some(!interface.shared_egress)
        .filter(|value| *value)
        .map(|_| ("4096:".to_owned(), "51:1".to_owned()))
        .into_iter()
        .chain(shared_fallbacks(interface).into_iter().map(|(_, minor)| {
            (
                if minor == 11 {
                    "4097:".to_owned()
                } else {
                    "4098:".to_owned()
                },
                format!("51:{minor}"),
            )
        }))
        .chain(interface.clients.iter().map(|client| {
            let parent = if application_parents.contains(&client.class_minor) {
                format!("51:{}", default_class_minor(client.tag))
            } else {
                format!("51:{}", client.class_minor)
            };
            (format!("{}:", client.leaf_minor), parent)
        }))
        .chain(interface.application_classes.iter().map(|application| {
            (
                format!("{:x}:", application_leaf_minor(application.class_minor)),
                format!("51:{}", application.class_minor),
            )
        }))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let root_matches = qdiscs.as_array().is_some_and(|qdiscs| {
        qdiscs.iter().all(|qdisc| {
            if is_observation_clsact(qdisc) {
                return true;
            }
            if qdisc.get("root").and_then(Value::as_bool) == Some(true) {
                return qdisc.get("kind").and_then(Value::as_str) == Some("htb")
                    && qdisc.get("handle").and_then(Value::as_str) == Some(ROOT_HANDLE);
            }
            let Some(parent) = qdisc.get("parent").and_then(Value::as_str) else {
                return false;
            };
            let handle = qdisc
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if qdisc.get("kind").and_then(Value::as_str) != Some("fq_codel") {
                return false;
            }
            actual.insert((handle.to_owned(), parent.to_owned()));
            true
        })
    });
    if !root_matches || actual != expected {
        return Err(format!(
            "degraded_ownership_conflict: leaf qdiscs on {} differ from the saved NetQmon plan",
            interface.name
        ));
    }
    Ok(())
}

fn verify_partial_leaves(
    interface: &ManagedInterface,
    known_clients: &[ClientClass],
    known_applications: &[ApplicationClass],
) -> Result<(), String> {
    let qdiscs = run_json("tc", &["-j", "qdisc", "show", "dev", &interface.name])?;
    let application_parents = known_applications
        .iter()
        .map(|application| application.parent_class_minor)
        .collect::<BTreeSet<_>>();
    let allowed = std::iter::once(("4096:".to_owned(), "51:1".to_owned()))
        .filter(|_| !interface.shared_egress)
        .chain(shared_fallbacks(interface).into_iter().map(|(_, minor)| {
            (
                if minor == 11 {
                    "4097:".to_owned()
                } else {
                    "4098:".to_owned()
                },
                format!("51:{minor}"),
            )
        }))
        .chain(known_clients.iter().flat_map(|client| {
            // A failed migration can leave the owned queue at either its old
            // client class or its new default child. Both belong to this plan.
            let parents = std::iter::once(client.class_minor).chain(
                application_parents
                    .contains(&client.class_minor)
                    .then_some(default_class_minor(client.tag)),
            );
            parents.map(|parent| (format!("{}:", client.leaf_minor), format!("51:{parent}")))
        }))
        .chain(known_applications.iter().map(|application| {
            (
                format!("{:x}:", application_leaf_minor(application.class_minor)),
                format!("51:{}", application.class_minor),
            )
        }))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let valid = qdiscs.as_array().is_some_and(|qdiscs| {
        qdiscs.iter().all(|qdisc| {
            if is_observation_clsact(qdisc) {
                return true;
            }
            if qdisc.get("root").and_then(Value::as_bool) == Some(true) {
                return qdisc.get("kind").and_then(Value::as_str) == Some("htb")
                    && qdisc.get("handle").and_then(Value::as_str) == Some(ROOT_HANDLE);
            }
            let Some(parent) = qdisc.get("parent").and_then(Value::as_str) else {
                return false;
            };
            let handle = qdisc
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if qdisc.get("kind").and_then(Value::as_str) != Some("fq_codel") {
                return false;
            }
            actual.insert((handle.to_owned(), parent.to_owned()));
            true
        })
    });
    if !valid || !actual.is_subset(&allowed) {
        return Err(format!(
            "manual_cleanup_required: unknown leaf qdisc exists on {}",
            interface.name
        ));
    }
    Ok(())
}

fn run_json(binary: &str, args: &[&str]) -> Result<Value, String> {
    let output = run_output(binary, args)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{binary} returned invalid JSON: {error}"))
}

fn run_capture(binary: &str, args: &[&str]) -> Result<String, String> {
    let output = run_output(binary, args)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_tc(args: &[&str]) -> Result<(), String> {
    let output = run_output("tc", args)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("tc {} failed: {}", args.join(" "), stderr.trim()))
    }
}

fn run_output(binary: &str, args: &[&str]) -> Result<Output, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| format!("could not start {binary}: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "{binary} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn probe_kernel_features() -> Result<(), String> {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    RESULT.get_or_init(run_kernel_feature_probe).clone()
}

pub(super) fn application_shaping_supported() -> Result<(), String> {
    probe_kernel_features()
}

fn run_kernel_feature_probe() -> Result<(), String> {
    let pid = std::process::id();
    let namespace = format!("nqm{pid}");
    let host_interface = format!("nqa{}", pid % 100_000);
    let peer_interface = format!("nqb{}", pid % 100_000);
    run_ip(&["netns", "add", &namespace])?;
    let _cleanup = NamespaceCleanup {
        namespace: namespace.clone(),
        host_interface: host_interface.clone(),
    };
    run_ip(&[
        "link",
        "add",
        &host_interface,
        "type",
        "veth",
        "peer",
        "name",
        &peer_interface,
    ])?;
    run_ip(&["link", "set", &peer_interface, "netns", &namespace])?;
    run_ip(&["link", "set", &host_interface, "up"])?;
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &namespace, "link", "set", &peer_interface, "up"])?;
    for args in [
        vec![
            "qdisc",
            "add",
            "dev",
            &host_interface,
            "root",
            "handle",
            "51:",
            "htb",
            "default",
            "1",
        ],
        vec![
            "class",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:",
            "classid",
            "51:1",
            "htb",
            "rate",
            "100mbit",
            "ceil",
            "100mbit",
        ],
        vec![
            "class",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:1",
            "classid",
            "51:101",
            "htb",
            "rate",
            "5mbit",
            "ceil",
            "5mbit",
            "burst",
            "62500",
            "cburst",
            "62500",
        ],
        vec![
            "class",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:101",
            "classid",
            "51:401",
            "htb",
            "rate",
            "4mbit",
            "ceil",
            "5mbit",
        ],
        vec![
            "qdisc",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:401",
            "handle",
            "1002:",
            "fq_codel",
        ],
        vec![
            "class",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:101",
            "classid",
            "51:2000",
            "htb",
            "rate",
            "1mbit",
            "ceil",
            "5mbit",
        ],
        vec![
            "qdisc",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:2000",
            "handle",
            "4e20:",
            "fq_codel",
        ],
        vec![
            "filter",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:",
            "protocol",
            "all",
            "prio",
            "100",
            "handle",
            "0x00010000/0x01ff0000",
            "fw",
            "classid",
            "51:101",
        ],
        vec![
            "filter",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:101",
            "protocol",
            "all",
            "prio",
            "100",
            "handle",
            "0x02000000/0xfe000000",
            "fw",
            "classid",
            "51:2000",
        ],
        vec![
            "filter",
            "add",
            "dev",
            &host_interface,
            "parent",
            "51:101",
            "protocol",
            "all",
            "prio",
            "200",
            "matchall",
            "classid",
            "51:401",
        ],
    ] {
        run_tc(&args)?;
    }
    let name = format!("nft-qos-probe-{pid}");
    let script = format!(
        "table inet {name} {{\n chain forward_test {{\n  type filter hook forward priority -5;\n  policy accept;\n  meta mark set ((meta mark & 0x0000ffff) | 0x00010000)\n }}\n}}\n"
    );
    let output = Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start nft: {error}"))?;
    let mut child = output;
    use std::io::Write as _;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|error| format!("could not send nft capability probe: {error}"))?;
    }
    let result = child
        .wait_with_output()
        .map_err(|error| format!("could not finish nft capability probe: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "nftables cannot install the required skb mark expression: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    run_output("ip", args).map(|_| ())
}

struct NamespaceCleanup {
    namespace: String,
    host_interface: String,
}

impl Drop for NamespaceCleanup {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_interface])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.namespace])
            .output();
    }
}

fn is_tunnel_interface(interface: &str) -> bool {
    let lower = interface.to_ascii_lowercase();
    ["tun", "tap", "wg", "ppp", "gre", "sit", "ip6tnl", "vxlan"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn live_multigig_shared_root_keeps_one_mbit_application_budget() {
        assert!(nix::unistd::geteuid().is_root());
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap()
        );
        run_output("ip", &["link", "add", "multi0", "type", "dummy"]).unwrap();
        run_output("ip", &["link", "set", "multi0", "up"]).unwrap();
        let ifindex = nix::net::if_::if_nametoindex("multi0").unwrap();
        let mac = "02:00:00:00:00:01".to_owned();
        let mut prior = None;
        for capacity_bps in [2_500_000_000, 10_000_000_000] {
            let clients = super::super::shaper::allocate_shared_client_classes(
                "gw",
                super::super::shaper::Direction::Download,
                "multi0",
                ifindex,
                &BTreeMap::from([(mac.clone(), capacity_bps)]),
                &[],
            )
            .unwrap();
            let applications = super::super::shaper::allocate_application_classes(
                "gw",
                super::super::shaper::Direction::Download,
                "multi0",
                ifindex,
                &BTreeMap::from([(("app".into(), mac.clone()), 1_000_000)]),
                &clients,
                &[],
            )
            .unwrap();
            let desired = ShapingState {
                schema_version: 2,
                upload_interface: None,
                download_interface: None,
                shared_egress: Some(ManagedInterface {
                    name: "multi0".into(),
                    ifindex,
                    capacity_bps,
                    original_root_kind: String::new(),
                    shared_egress: true,
                    clients,
                    application_classes: applications,
                }),
            };
            let prepared = prepare_state(&desired, prior.as_ref()).unwrap();
            apply(&prepared, prior.as_ref()).unwrap();
            let classes = read_class_details("multi0").unwrap();
            assert!(class_has_exact_rates(classes.get("51:1"), capacity_bps));
            let application = &prepared.shared_egress.as_ref().unwrap().application_classes[0];
            assert!(class_has_exact_rates(
                classes.get(&format!("51:{}", application.class_minor)),
                1_000_000
            ));
            println!(
                "PASS: {capacity_bps} bps shared root with a separate 1 Mbps application ceiling"
            );
            prior = Some(prepared);
        }
        restore(&prior.unwrap()).unwrap();
        assert_eq!(
            root_kind(&inspect_root("multi0").unwrap()).as_deref(),
            Some("noqueue")
        );
        run_output("ip", &["link", "del", "multi0"]).unwrap();
    }

    #[test]
    fn dynamic_fq_codel_classes_are_not_htb_ownership_entries() {
        let parsed = parse_class_details(
            "class htb 51:1 root rate 100Mbit ceil 100Mbit\nclass fq_codel 1223:9f parent 1223:\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed["51:1"].rate_bps, Some(100_000_000));
    }
    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn live_router_client_to_application_migration_preserves_queues_and_rolls_back() {
        use super::super::shaper::{Direction, allocate_application_classes, allocate_classes};
        assert!(nix::unistd::geteuid().is_root());
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap()
        );
        run_output("ip", &["link", "add", "app0", "type", "dummy"]).unwrap();
        run_output("ip", &["link", "set", "app0", "up"]).unwrap();
        let ifindex = nix::net::if_::if_nametoindex("app0").unwrap();
        let mac = "02:00:00:00:00:01".to_owned();
        let clients = allocate_classes(
            "gw",
            Direction::Download,
            "app0",
            ifindex,
            &BTreeMap::from([
                (mac.clone(), 100_000_000),
                ("02:00:00:00:00:02".to_owned(), 100_000_000),
            ]),
            &[],
        )
        .unwrap();
        let desired = ShapingState {
            schema_version: 1,
            upload_interface: None,
            download_interface: Some(ManagedInterface {
                shared_egress: false,
                name: "app0".to_owned(),
                ifindex,
                capacity_bps: 100_000_000,
                original_root_kind: String::new(),
                clients,
                application_classes: Vec::new(),
            }),
            shared_egress: None,
        };
        let initial = prepare_state(&desired, None).unwrap();
        apply(&initial, None).unwrap();
        // Older Router snapshots assigned each client its full ceiling as
        // guarantee, even when their sum exceeded the physical capacity.
        for client in &initial.download_interface.as_ref().unwrap().clients {
            run_tc(&[
                "class",
                "replace",
                "dev",
                "app0",
                "parent",
                "51:1",
                "classid",
                &format!("51:{}", client.class_minor),
                "htb",
                "rate",
                "100mbit",
                "ceil",
                "100mbit",
            ])
            .unwrap();
        }
        verify_owned(initial.download_interface.as_ref().unwrap()).unwrap();
        apply(&initial, Some(&initial)).unwrap();
        let details = read_class_details("app0").unwrap();
        for client in &initial.download_interface.as_ref().unwrap().clients {
            assert!(class_has_rates(
                details.get(&format!("51:{}", client.class_minor)),
                50_000_000,
                100_000_000
            ));
        }
        let mut application = initial.clone();
        let interface = application.download_interface.as_mut().unwrap();
        interface.application_classes = allocate_application_classes(
            "gw",
            Direction::Download,
            "app0",
            ifindex,
            &BTreeMap::from([(("app-policy".to_owned(), mac), 4_000_000)]),
            &interface.clients,
            &[],
        )
        .unwrap();
        apply(&application, Some(&initial)).unwrap();
        run_output("ip", &["address", "add", "198.18.0.1/24", "dev", "app0"]).unwrap();
        run_output(
            "ip",
            &[
                "neigh",
                "replace",
                "198.18.0.2",
                "lladdr",
                "02:00:00:00:00:02",
                "nud",
                "permanent",
                "dev",
                "app0",
            ],
        )
        .unwrap();
        let interface = application.download_interface.as_ref().unwrap();
        let client = interface
            .clients
            .iter()
            .find(|client| client.mac == "02:00:00:00:00:01")
            .unwrap();
        let client_mark = client_mark_value(client.tag);
        let app_mark = client_mark | application_mark_value(interface.application_classes[0].tag);
        for mark in [client_mark, app_mark] {
            run_output("python3", &["-c", "import socket,sys,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,struct.pack('=I',int(sys.argv[1]))); [s.sendto(b'x'*500,('198.18.0.2',18081)) for _ in range(10)]", &mark.to_string()]).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        let counters = || {
            let data = run_json("tc", &["-s", "-j", "qdisc", "show", "dev", "app0"]).unwrap();
            data.as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry["kind"] == "fq_codel")
                .map(|entry| {
                    (
                        entry["handle"].as_str().unwrap().to_owned(),
                        entry["bytes"].as_u64().unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = counters();
        assert_eq!(before.len(), 3);
        assert!(
            before.values().filter(|bytes| **bytes > 0).count() == 2,
            "both application and default queues must transmit"
        );
        let mut updated = application.clone();
        updated
            .download_interface
            .as_mut()
            .unwrap()
            .application_classes[0]
            .rate_bps = 2_000_000;
        apply(&updated, Some(&application)).unwrap();
        let after = counters();
        assert!(
            before
                .iter()
                .all(|(handle, bytes)| after.get(handle).is_some_and(|after| after >= bytes)),
            "rate update discarded a live Router queue"
        );
        let journal_dir = tempfile::tempdir().unwrap();
        let state_path = journal_dir.path().join("policy-state.json");
        write_journal(&state_path, Some(&initial), Some(&updated)).unwrap();
        assert!(recover_journal(&state_path, Some(&initial)).unwrap());
        verify_owned(initial.download_interface.as_ref().unwrap()).unwrap();
        apply(&updated, Some(&initial)).unwrap();
        apply(&initial, Some(&updated)).unwrap();
        verify_owned(initial.download_interface.as_ref().unwrap()).unwrap();
        restore(&initial).unwrap();
    }

    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn live_shared_application_classes_update_replace_and_remove() {
        use super::super::shaper::{Direction, allocate_shared_client_classes};
        assert!(nix::unistd::geteuid().is_root());
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap()
        );
        run_output("ip", &["link", "add", "app0", "type", "dummy"]).unwrap();
        run_output("ip", &["link", "set", "app0", "up"]).unwrap();
        let ifindex = nix::net::if_::if_nametoindex("app0").unwrap();
        let rates = BTreeMap::from([("02:00:00:00:00:01".to_owned(), 10_000_000)]);
        let mut clients = Vec::new();
        let mut apps = Vec::new();
        for (index, direction) in [Direction::Upload, Direction::Download]
            .into_iter()
            .enumerate()
        {
            let directional =
                allocate_shared_client_classes("gw", direction, "app0", ifindex, &rates, &[])
                    .unwrap();
            apps.push(ApplicationClass {
                policy_id: "app".to_owned(),
                gateway_id: "gw".to_owned(),
                mac: rates.first_key_value().unwrap().0.clone(),
                direction,
                interface: "app0".to_owned(),
                ifindex,
                tag: 1,
                class_minor: 2000 + index as u16,
                parent_class_minor: directional[0].class_minor,
                rate_bps: 4_000_000,
            });
            clients.extend(directional);
        }
        let desired = ShapingState {
            schema_version: 2,
            upload_interface: None,
            download_interface: None,
            shared_egress: Some(ManagedInterface {
                shared_egress: true,
                name: "app0".to_owned(),
                ifindex,
                capacity_bps: 100_000_000,
                original_root_kind: String::new(),
                clients,
                application_classes: apps,
            }),
        };
        let initial = prepare_state(&desired, None).unwrap();
        apply(&initial, None).unwrap();
        run_output("ip", &["address", "add", "198.18.0.1/24", "dev", "app0"]).unwrap();
        run_output(
            "ip",
            &[
                "neigh",
                "replace",
                "198.18.0.2",
                "lladdr",
                "02:00:00:00:00:02",
                "nud",
                "permanent",
                "dev",
                "app0",
            ],
        )
        .unwrap();
        let client = &initial.shared_egress.as_ref().unwrap().clients[0];
        run_output("python3", &["-c", "import socket,sys,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,struct.pack('=I',int(sys.argv[1]))); [s.sendto(b'x'*500,('198.18.0.2',18081)) for _ in range(10)]", &client_mark_value(client.tag).to_string()]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let default_bytes = || {
            let qdiscs: Value = serde_json::from_str(
                &run_capture("tc", &["-s", "-j", "qdisc", "show", "dev", "app0"]).unwrap(),
            )
            .unwrap();
            qdiscs
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["parent"] == format!("51:{}", default_class_minor(client.tag)))
                .unwrap()["bytes"]
                .as_u64()
                .unwrap()
        };
        let before_update = default_bytes();
        assert!(
            before_update > 0,
            "default queue did not transmit the marked workload"
        );
        let mut updated = initial.clone();
        let shared = updated.shared_egress.as_mut().unwrap();
        shared.application_classes[0].rate_bps = 2_000_000;
        shared.application_classes[1].policy_id = "replacement".to_owned();
        shared.application_classes[1].tag = 2;
        apply(&updated, Some(&initial)).unwrap();
        assert!(
            default_bytes() >= before_update,
            "rate-only application updates destroyed the active default queue"
        );
        verify_owned(updated.shared_egress.as_ref().unwrap()).unwrap();
        let journal_dir = tempfile::tempdir().unwrap();
        let state_path = journal_dir.path().join("policy-state.json");
        write_journal(&state_path, Some(&initial), Some(&updated)).unwrap();
        assert!(recover_journal(&state_path, Some(&initial)).unwrap());
        verify_owned(initial.shared_egress.as_ref().unwrap()).unwrap();
        apply(&updated, Some(&initial)).unwrap();
        let mut one = updated.clone();
        one.shared_egress
            .as_mut()
            .unwrap()
            .application_classes
            .pop();
        apply(&one, Some(&updated)).unwrap();
        let mut none = one.clone();
        none.shared_egress
            .as_mut()
            .unwrap()
            .application_classes
            .clear();
        apply(&none, Some(&one)).unwrap();
        verify_owned(none.shared_egress.as_ref().unwrap()).unwrap();
        restore(&none).unwrap();
    }
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Agent component test; requires root in a private Linux netns, not product QoS acceptance"]
    #[allow(clippy::too_many_lines)] // Keep one end-to-end rollback and recovery scenario together.
    fn live_shared_egress_updates_rolls_back_and_recovers_one_root() {
        use super::super::shaper::{Direction, allocate_shared_client_classes};
        use std::os::unix::fs::PermissionsExt;
        assert!(nix::unistd::geteuid().is_root());
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing host network namespace"
        );
        if std::env::var_os("NETQMON_SHARED_TEST_WORKER").is_none() {
            let temp = tempfile::tempdir().unwrap();
            let wrapper = temp.path().join("tc");
            fs::write(
                &wrapper,
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$NETQMON_SHARED_TEST_TRACE"
case "$*" in
  'class replace dev one0 parent 51:20 classid '*)
    if test -e "$NETQMON_SHARED_TEST_FAIL"; then
      rm "$NETQMON_SHARED_TEST_FAIL"
      echo 'injected shared direction class failure' >&2
      exit 77
    fi
    ;;
esac
exec "${NETQMON_SHARED_TEST_TC_BIN:-/usr/sbin/tc}" "$@"
"#,
            )
            .unwrap();
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "policy::qdisc::tests::live_shared_egress_updates_rolls_back_and_recovers_one_root", "--ignored", "--nocapture"])
                .env("NETQMON_SHARED_TEST_WORKER", "1")
                .env("NETQMON_SHARED_TEST_TRACE", temp.path().join("trace"))
                .env("NETQMON_SHARED_TEST_FAIL", temp.path().join("fail"))
                .env("PATH", format!("{}:{}", temp.path().display(), std::env::var("PATH").unwrap_or_default()))
                .output().unwrap();
            println!("{}", String::from_utf8_lossy(&output.stdout));
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            assert!(output.status.success());
            return;
        }
        run_output("ip", &["link", "add", "one0", "type", "dummy"]).unwrap();
        run_output("ip", &["link", "set", "one0", "up"]).unwrap();
        let ifindex = nix::net::if_::if_nametoindex("one0").unwrap();
        let rates = BTreeMap::from([
            ("02:00:00:00:00:01".to_owned(), 5_000_000),
            ("02:00:00:00:00:02".to_owned(), 7_000_000),
        ]);
        let mut clients = allocate_shared_client_classes(
            "gw-test",
            Direction::Upload,
            "one0",
            ifindex,
            &rates,
            &[],
        )
        .unwrap();
        clients.extend(
            allocate_shared_client_classes(
                "gw-test",
                Direction::Download,
                "one0",
                ifindex,
                &rates,
                &[],
            )
            .unwrap(),
        );
        let desired = ShapingState {
            schema_version: 2,
            upload_interface: None,
            download_interface: None,
            shared_egress: Some(ManagedInterface {
                shared_egress: true,
                name: "one0".to_owned(),
                ifindex,
                // Explicit component-test ceiling, never presented as measured capacity.
                capacity_bps: 100_000_000,
                original_root_kind: String::new(),
                clients,
                application_classes: Vec::new(),
            }),
        };
        let state = prepare_state(&desired, None).unwrap();
        let original = state
            .shared_egress
            .as_ref()
            .unwrap()
            .original_root_kind
            .clone();
        apply(&state, None).unwrap();
        let shared = state.shared_egress.as_ref().unwrap();
        verify_owned(shared).unwrap();
        let roots = run_json("tc", &["-j", "qdisc", "show", "dev", "one0"]).unwrap();
        assert_eq!(
            roots
                .as_array()
                .unwrap()
                .iter()
                .filter(|qdisc| qdisc.get("root").and_then(Value::as_bool) == Some(true))
                .count(),
            1
        );
        let mut topology = super::super::capabilities::PolicyTopology::unsupported(
            "component_test",
            "explicit test ceiling, not measured capacity",
        );
        topology.supported = true;
        topology.lan_interfaces = vec!["one0".to_owned()];
        topology.wan_interfaces = topology.lan_interfaces.clone();
        topology.internal_networks = vec!["192.0.2.0/24".to_owned(), "fd00::/64".to_owned()];
        topology.ipv6_coverage = true;
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
        let addresses = vec![
            ("02:00:00:00:00:01".to_owned(), "192.0.2.2".parse().unwrap()),
            ("02:00:00:00:00:01".to_owned(), "fd00::2".parse().unwrap()),
        ];
        let plan = super::super::nft::NftPlan {
            mark_rules: super::super::mark::rules_for_clients(
                &upload, &download, &addresses, "one0", "one0",
            ),
            ..Default::default()
        };
        super::super::nft::replace(&topology, &plan)
            .expect("kernel must accept actual Agent conntrack direction rules");
        super::super::mark::inspect_conflicts(&["one0".to_owned()], Some(&state)).unwrap();
        println!(
            "{}",
            run_capture("nft", &["list", "table", "inet", "netqmon_policy"]).unwrap()
        );
        let trace = PathBuf::from(std::env::var_os("NETQMON_SHARED_TEST_TRACE").unwrap());
        let root_installs = || {
            fs::read_to_string(&trace)
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("qdisc replace dev one0 root"))
                .count()
        };
        assert_eq!(root_installs(), 1);
        apply(&state, Some(&state)).unwrap();
        assert_eq!(
            root_installs(),
            1,
            "repeat snapshot must not reinstall root"
        );
        let mut updated = state.clone();
        updated.shared_egress.as_mut().unwrap().clients[0].rate_bps = 6_000_000;
        apply(&updated, Some(&state)).unwrap();
        assert_eq!(
            root_installs(),
            1,
            "online update must preserve root and other clients"
        );
        verify_owned(updated.shared_egress.as_ref().unwrap()).unwrap();
        let unchanged_b = shared
            .clients
            .iter()
            .filter(|client| client.mac.ends_with("02"))
            .collect::<Vec<_>>();
        assert_eq!(
            unchanged_b,
            updated
                .shared_egress
                .as_ref()
                .unwrap()
                .clients
                .iter()
                .filter(|client| client.mac.ends_with("02"))
                .collect::<Vec<_>>()
        );
        fs::write(
            std::env::var_os("NETQMON_SHARED_TEST_FAIL").unwrap(),
            b"fail once",
        )
        .unwrap();
        let mut failing = state.clone();
        failing
            .shared_egress
            .as_mut()
            .unwrap()
            .clients
            .iter_mut()
            .find(|client| client.direction == Direction::Download && client.mac.ends_with("01"))
            .unwrap()
            .rate_bps = 6_000_000;
        assert!(apply(&failing, Some(&updated)).is_err());
        verify_owned(updated.shared_egress.as_ref().unwrap())
            .expect("rollback must recover previous shared direction budgets");
        let mut removed = updated.clone();
        removed
            .shared_egress
            .as_mut()
            .unwrap()
            .clients
            .retain(|client| !client.mac.ends_with("01"));
        apply(&removed, Some(&updated)).unwrap();
        verify_owned(removed.shared_egress.as_ref().unwrap()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("policy.json");
        write_journal(&state_path, Some(&removed), Some(&state)).unwrap();
        apply(&state, Some(&removed)).unwrap();
        assert!(recover_journal(&state_path, Some(&removed)).unwrap());
        verify_owned(removed.shared_egress.as_ref().unwrap()).unwrap();
        assert!(!journal_path(&state_path).exists());
        println!(
            "{}",
            run_capture("tc", &["-s", "class", "show", "dev", "one0"]).unwrap()
        );
        super::super::nft::clear_owned().unwrap();
        restore(&removed).unwrap();
        assert_eq!(
            root_kind(&inspect_root("one0").unwrap()).as_deref(),
            Some(original.as_str())
        );
        run_tc(&[
            "qdisc", "add", "dev", "one0", "root", "handle", "1:", "htb", "default", "1",
        ])
        .unwrap();
        let foreign = run_capture("tc", &["qdisc", "show", "dev", "one0"]).unwrap();
        assert!(prepare_state(&desired, None).is_err());
        assert_eq!(
            foreign,
            run_capture("tc", &["qdisc", "show", "dev", "one0"]).unwrap()
        );
        run_tc(&["qdisc", "del", "dev", "one0", "root"]).unwrap();
        run_output("ip", &["link", "del", "one0"]).unwrap();
        println!(
            "PASS Agent component: one physical root, separate directions/fallbacks, repeat/update/delete, failure rollback, journal restart recovery and foreign-root refusal; no product throughput claim"
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and creates a temporary network namespace"]
    fn probes_nested_application_htb_support_on_the_current_kernel() {
        application_shaping_supported().expect("kernel should support application HTB tree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and CAP_NET_ADMIN in a private Linux network namespace"]
    fn rejects_existing_cake_root_without_mutating_it() {
        use std::process::Command;

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
        run("ip", &["link", "add", "wan0", "type", "dummy"]);
        run("ip", &["link", "set", "wan0", "up"]);
        run("tc", &["qdisc", "replace", "dev", "wan0", "root", "cake"]);
        let before: Value =
            serde_json::from_slice(&run("tc", &["-j", "qdisc", "show", "dev", "wan0"]).stdout)
                .unwrap();
        assert!(before.as_array().unwrap().iter().any(|qdisc| {
            qdisc.get("root").and_then(Value::as_bool) == Some(true)
                && qdisc.get("kind").and_then(Value::as_str) == Some("cake")
        }));

        let desired = ShapingState {
            shared_egress: None,
            schema_version: 1,
            upload_interface: Some(ManagedInterface {
                shared_egress: false,
                name: "wan0".to_owned(),
                ifindex: nix::net::if_::if_nametoindex("wan0").unwrap(),
                capacity_bps: 100_000_000,
                original_root_kind: String::new(),
                clients: Vec::new(),
                application_classes: Vec::new(),
            }),
            download_interface: None,
        };
        let error = prepare_state(&desired, None).unwrap_err();
        assert!(error.starts_with("unsupported_existing_qdisc:"), "{error}");
        let after: Value =
            serde_json::from_slice(&run("tc", &["-j", "qdisc", "show", "dev", "wan0"]).stdout)
                .unwrap();
        assert_eq!(
            before, after,
            "rejected policy changed the existing CAKE qdisc"
        );

        run("ip", &["link", "del", "wan0"]);
        println!("PASS: existing CAKE root was rejected and remained unchanged");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root, CAP_NET_ADMIN, and an isolated Linux network namespace"]
    fn recovers_interrupted_shaping_journal_before_and_after_commit() {
        use std::process::Command;

        assert!(nix::unistd::geteuid().is_root(), "test requires root");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to mutate a process in the host network namespace"
        );

        let interface = format!("nqrec{:x}", std::process::id());
        let output = Command::new("ip")
            .args(["link", "add", interface.as_str(), "type", "dummy"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create isolated test interface: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        struct InterfaceCleanup(String);

        impl Drop for InterfaceCleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip")
                    .args(["link", "del", self.0.as_str()])
                    .output();
            }
        }

        let _cleanup = InterfaceCleanup(interface.clone());
        let output = Command::new("ip")
            .args(["link", "set", interface.as_str(), "up"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to raise isolated test interface: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let state_dir = tempfile::tempdir().unwrap();
        let state_path = state_dir.path().join("policy-state.json");
        let desired = ShapingState {
            shared_egress: None,
            schema_version: 1,
            upload_interface: Some(ManagedInterface {
                shared_egress: false,
                name: interface.clone(),
                ifindex: nix::net::if_::if_nametoindex(interface.as_str()).unwrap(),
                capacity_bps: 100_000_000,
                original_root_kind: String::new(),
                clients: Vec::new(),
                application_classes: Vec::new(),
            }),
            download_interface: None,
        };
        let next = prepare_state(&desired, None).expect("capture original qdisc");
        assert_eq!(
            next.upload_interface.as_ref().unwrap().original_root_kind,
            "noqueue"
        );

        write_journal(&state_path, None, Some(&next)).expect("write interrupted journal");
        apply(&next, None).expect("apply next shaping state");
        assert_eq!(
            root_kind(&inspect_root(&interface).unwrap()).as_deref(),
            Some("htb"),
            "test setup did not install the NetQmon qdisc"
        );

        assert!(recover_journal(&state_path, None).expect("recover uncommitted journal"));
        assert_eq!(
            root_kind(&inspect_root(&interface).unwrap()).as_deref(),
            Some("noqueue"),
            "uncommitted shaping transaction did not restore the previous root"
        );
        assert!(!journal_path(&state_path).exists());

        write_journal(&state_path, None, Some(&next)).expect("write committed journal");
        apply(&next, None).expect("reapply next shaping state");
        assert!(recover_journal(&state_path, Some(&next)).expect("recover committed journal"));
        assert_eq!(
            root_kind(&inspect_root(&interface).unwrap()).as_deref(),
            Some("htb"),
            "committed shaping state was not restored"
        );
        assert!(!journal_path(&state_path).exists());

        restore(&next).expect("restore original test qdisc");
        assert_eq!(
            root_kind(&inspect_root(&interface).unwrap()).as_deref(),
            Some("noqueue"),
            "test cleanup did not restore the original root qdisc"
        );
        println!(
            "PASS: interrupted shaping journal recovered for uncommitted and committed policy state"
        );
    }

    #[test]
    fn accepts_only_unambiguous_known_default_root_qdiscs() {
        let root = serde_json::json!({"kind":"fq_codel","handle":"0:","root":true,"options":{"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":true,"drop_batch":64}});
        assert!(default_root_options_match("fq_codel", &root));
        let custom = serde_json::json!({"kind":"fq_codel","options":{"limit":2048}});
        assert!(!default_root_options_match("fq_codel", &custom));
        assert!(!default_root_options_match(
            "cake",
            &serde_json::json!({"kind":"cake"})
        ));
    }

    #[test]
    fn rejects_tunnel_interfaces_and_accepts_ordinary_ethernet_names() {
        assert!(is_tunnel_interface("wg0"));
        assert!(is_tunnel_interface("tun-home"));
        assert!(!is_tunnel_interface("eth0"));
        assert!(!is_tunnel_interface("br-lan"));
    }

    #[test]
    fn parses_tc_class_counters_without_assuming_every_counter_is_present() {
        let counters = parse_class_counters(
            "class htb 51:1 root rate 100Mbit ceil 100Mbit\n Sent 999 bytes 12 pkt (dropped 0, overlimits 0 requeues 0)\nclass htb 51:101 parent 51:1 rate 5Mbit ceil 5Mbit\n Sent 3456 bytes 42 pkt (dropped 2, overlimits 3 requeues 0)\n",
        );
        assert_eq!(counters["51:101"].bytes, Some(3456));
        assert_eq!(counters["51:101"].packets, Some(42));
        assert_eq!(counters["51:101"].drops, Some(2));
        assert_eq!(counters["51:101"].overlimits, Some(3));
        assert_eq!(counters["51:1"].bytes, Some(999));
    }

    #[test]
    fn verifies_reported_htb_rates_match_the_saved_budget() {
        let details = parse_class_details(
            "class htb 51:1 root rate 100Mbit ceil 100Mbit burst 12500b\nclass htb 51:101 parent 51:1 rate 5Mbit ceil 5Mbit burst 625000b\n",
        );
        assert!(class_has_exact_rates(details.get("51:1"), 100_000_000));
        assert!(class_has_exact_rates(details.get("51:101"), 5_000_000));
        assert!(!class_has_exact_rates(details.get("51:101"), 8_000_000));
        assert_eq!(parse_rate_bps("64Kbit"), Some(64_000));
        assert_eq!(parse_rate_bps("1Gbit"), Some(1_000_000_000));

        let old_application = parse_class_details(
            "class htb 51:2000 parent 51:101 rate 8Mbit ceil 8Mbit burst 2000b\n",
        );
        assert!(class_has_rates_or_legacy(
            old_application.get("51:2000"),
            5_000_000,
            8_000_000,
            8_000_000,
        ));
        let unexpected_application = parse_class_details(
            "class htb 51:2000 parent 51:101 rate 7Mbit ceil 7Mbit burst 2000b\n",
        );
        assert!(!class_has_rates_or_legacy(
            unexpected_application.get("51:2000"),
            4_000_000,
            8_000_000,
            8_000_000,
        ));
    }

    #[test]
    fn application_leaf_guarantees_fit_within_the_client_aggregate_budget() {
        let application = |policy_id: &str, class_minor, rate_bps| ApplicationClass {
            policy_id: policy_id.to_owned(),
            gateway_id: "gw-test".to_owned(),
            mac: "aa:bb:cc:dd:ee:ff".to_owned(),
            direction: super::super::shaper::Direction::Download,
            interface: "br-lan".to_owned(),
            ifindex: 2,
            tag: class_minor - 1_999,
            class_minor,
            parent_class_minor: 101,
            rate_bps,
        };
        let five_mbit = application("app-a", 2_000, 5_000_000);
        let normal = application_child_rates(10_000_000, 401, &[&five_mbit]);
        assert_eq!(normal[&2_000], 5_000_000);
        assert_eq!(normal[&401], 5_000_000);

        let first = application("app-a", 2_000, 8_000_000);
        let second = application("app-b", 2_001, 8_000_000);
        let overcommitted = application_child_rates(10_000_000, 401, &[&first, &second]);
        assert_eq!(overcommitted[&2_000], 4_999_992);
        assert_eq!(overcommitted[&2_001], 5_000_000);
        assert_eq!(overcommitted[&401], 8);
        assert_eq!(overcommitted.values().sum::<u64>(), 10_000_000);
        assert!(overcommitted[&2_000] <= first.rate_bps);
        assert!(overcommitted[&2_001] <= second.rate_bps);
    }

    #[test]
    fn router_guarantees_fit_the_physical_root_when_client_ceilings_exceed_capacity() {
        use super::super::shaper::{Direction, allocate_classes};
        for capacity in [64_000, 100_000_000, 1_000_000_000] {
            let rates = BTreeMap::from([
                ("02:00:00:00:00:01".to_owned(), capacity),
                ("02:00:00:00:00:02".to_owned(), capacity),
            ]);
            let interface = ManagedInterface {
                name: "test0".to_owned(),
                ifindex: 1,
                capacity_bps: capacity,
                original_root_kind: "noqueue".to_owned(),
                shared_egress: false,
                clients: allocate_classes("gw", Direction::Download, "test0", 1, &rates, &[])
                    .unwrap(),
                application_classes: Vec::new(),
            };
            let sum = interface
                .clients
                .iter()
                .map(|client| client_guarantee(&interface, client))
                .sum::<u64>();
            assert!(sum <= capacity);
            for client in &interface.clients {
                assert_eq!(client_guarantee(&interface, client), capacity / 2);
                assert_eq!(client.rate_bps, capacity);
            }
        }
    }

    #[test]
    fn shared_guarantees_reserve_control_capacity_without_overcommitting_directions() {
        use super::super::shaper::{Direction, allocate_shared_client_classes};
        for capacity in [64_000, 100_000_000, 1_000_000_000] {
            let rates = BTreeMap::from([
                ("02:00:00:00:00:01".to_owned(), capacity),
                ("02:00:00:00:00:02".to_owned(), capacity),
            ]);
            let mut interface = ManagedInterface {
                name: "test0".to_owned(),
                ifindex: 1,
                capacity_bps: capacity,
                original_root_kind: "noqueue".to_owned(),
                shared_egress: true,
                clients: Vec::new(),
                application_classes: Vec::new(),
            };
            for direction in [Direction::Upload, Direction::Download] {
                interface.clients.extend(
                    allocate_shared_client_classes("gw", direction, "test0", 1, &rates, &[])
                        .unwrap(),
                );
            }
            for direction in [Direction::Upload, Direction::Download] {
                let guarantees = interface
                    .clients
                    .iter()
                    .filter(|client| client.direction == direction)
                    .map(|client| client_guarantee(&interface, client))
                    .sum::<u64>();
                assert!(shared_fallback_guarantee(&interface) >= 8);
                assert!(guarantees + shared_fallback_guarantee(&interface) <= capacity / 2);
            }
        }
    }

    #[test]
    fn keeps_the_agent_observation_clsact_outside_the_owned_root_tree() {
        let qdisc = serde_json::json!({
            "kind": "clsact",
            "handle": "ffff:",
            "parent": "ffff:fff1",
            "options": {}
        });
        assert!(is_observation_clsact(&qdisc));
        let foreign = serde_json::json!({
            "kind": "clsact",
            "handle": "ffff:",
            "parent": "51:1",
            "options": {}
        });
        assert!(!is_observation_clsact(&foreign));
    }
}
