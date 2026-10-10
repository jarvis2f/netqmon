//! Read-only client-path evidence. Never advertises policy support or shapes packets.
use std::{collections::BTreeSet, fs, path::PathBuf, process::Command};

use anyhow::{Context as _, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapHandle, ProgramHandle, ProgramMut};
use serde_json::{Value, json};

use crate::config::{AgentConfig, AttachBackend};

const HANDLE: &str = "0x4e515004";

pub(super) struct PathProbe {
    output: PathBuf,
    lan: String,
    selected_clients: BTreeSet<String>,
    control: MapHandle,
    frames: MapHandle,
    overflow: MapHandle,
    extra_interfaces: Vec<String>,
    priority: String,
    program_id: u32,
    pin_dir: PathBuf,
    attached_interfaces: BTreeSet<String>,
    clsact_created_interfaces: BTreeSet<String>,
    disabled_reason: Option<String>,
}

fn tc(args: &[&str]) -> Result<String> {
    let result = Command::new("tc").args(args).output()?;
    if !result.status.success() {
        bail!(
            "path probe tc {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(String::from_utf8(result.stdout)?)
}

pub(super) fn prepare(
    config: &AgentConfig,
    observation: &[(String, i32)],
    control: MapHandle,
    frames: MapHandle,
    overflow: MapHandle,
) -> Result<Option<PathProbe>> {
    let Some(output) = std::env::var_os("NETQMON_QOS_PATH_PROBE_OUTPUT") else {
        return Ok(None);
    };
    let output = PathBuf::from(output);
    if fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")?
        || config.attach_backend != AttachBackend::Netlink
        || config.interfaces != [config.interface.clone()]
        || !output.is_absolute()
        || !output.starts_with("/tmp")
        || output
            .components()
            .any(|p| p == std::path::Component::ParentDir)
    {
        bail!(
            "path probe requires an isolated netns, explicit netlink, one test LAN and /tmp output"
        );
    }
    let requested_egress = std::env::var("NETQMON_QOS_PATH_PROBE_EGRESS_INTERFACES")
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let observed = observation
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    // A regular Agent observation hook and this probe write to different BPF
    // maps. An interface being sampled already does not make it visible to the
    // path probe, so explicitly requested egress devices must still get the
    // read-only probe program.
    let mut extra_interfaces = requested_egress;
    if !observed.contains(config.interface.as_str()) {
        extra_interfaces.insert(config.interface.clone());
    }
    for name in std::iter::once(&config.interface)
        .chain(observation.iter().map(|(name, _)| name))
        .chain(extra_interfaces.iter())
    {
        if !name.starts_with("nqp-")
            || name.len() > 15
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("path probe refuses non-test interface {name}");
        }
    }
    if control.key_size() != 4
        || control.value_size() != 4
        || frames.key_size() != 40
        || frames.value_size() != 16
        || frames.max_entries() != 4096
        || overflow.key_size() != 4
        || overflow.value_size() != 8
    {
        bail!("path probe BPF ABI mismatch");
    }
    for name in &extra_interfaces {
        if !tc(&["filter", "show", "dev", name, "egress"])?
            .trim()
            .is_empty()
        {
            bail!("path probe refuses pre-existing bridge egress filters");
        }
    }
    Ok(Some(PathProbe {
        output,
        lan: config.interface.clone(),
        selected_clients: std::env::var("NETQMON_QOS_PATH_PROBE_CLIENTS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        control,
        frames,
        overflow,
        extra_interfaces: extra_interfaces.into_iter().collect(),
        priority: config
            .attach_order
            .tc_priority
            .checked_add(2)
            .filter(|p| *p <= u16::MAX.into())
            .context("no ordered path-probe priority")?
            .to_string(),
        program_id: 0,
        pin_dir: PathBuf::from(format!("/sys/fs/bpf/nqpp-{}", std::process::id())),
        attached_interfaces: BTreeSet::new(),
        clsact_created_interfaces: BTreeSet::new(),
        disabled_reason: None,
    }))
}

impl PathProbe {
    #[cfg(feature = "qos-client-priority")]
    pub(super) fn record_idle_priority_maps(&self, evidence: &Value) -> Result<()> {
        fs::write(
            self.output.with_extension("priority-maps.json"),
            serde_json::to_vec_pretty(evidence)?,
        )?;
        Ok(())
    }

    #[cfg(feature = "qos-client-priority")]
    pub(super) fn record_final_priority_maps(&self, evidence: &Value) -> Result<()> {
        fs::write(
            self.output.with_extension("priority-maps-final.json"),
            serde_json::to_vec_pretty(evidence)?,
        )?;
        Ok(())
    }

    pub(super) fn activate(&mut self, program: &ProgramMut<'_>) -> Result<()> {
        if !self.extra_interfaces.is_empty() {
            let handle = ProgramHandle::try_from(program)?;
            self.program_id = handle.id();
            fs::create_dir(&self.pin_dir)?;
            let pin = self.pin_dir.join("observer");
            handle.pin(&pin)?;
            for name in self.extra_interfaces.clone() {
                let qdiscs: Value =
                    serde_json::from_str(&tc(&["-j", "qdisc", "show", "dev", &name])?)?;
                if !qdiscs
                    .as_array()
                    .context("qdisc array")?
                    .iter()
                    .any(|q| q["kind"] == "clsact")
                {
                    tc(&["qdisc", "add", "dev", &name, "clsact"])?;
                    self.clsact_created_interfaces.insert(name.clone());
                }
                tc(&[
                    "filter",
                    "add",
                    "dev",
                    &name,
                    "egress",
                    "protocol",
                    "all",
                    "prio",
                    &self.priority,
                    "handle",
                    HANDLE,
                    "bpf",
                    "da",
                    "pinned",
                    pin.to_str().unwrap(),
                ])?;
                self.attached_interfaces.insert(name.clone());
                if !self.extra_filter_owned(&name)? {
                    bail!("path probe egress attachment readback failed on {name}");
                }
            }
        }
        self.control
            .update(&0_u32.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)?;
        self.write_evidence()?;
        eprintln!("QoS client path probe active (read-only; no client policy acceptance)");
        Ok(())
    }

    fn extra_filter_owned(&self, name: &str) -> Result<bool> {
        let filters: Value =
            serde_json::from_str(&tc(&["-j", "filter", "show", "dev", name, "egress"])?)?;
        fs::write(
            self.output
                .with_extension(format!("{name}.attachment.json")),
            serde_json::to_vec_pretty(&json!({"expected_program_id":self.program_id,
                "priority":self.priority,"handle":HANDLE,"filters":filters}))?,
        )?;
        Ok(filters.as_array().context("filter array")?.iter().any(|f| {
            f["kind"] == "bpf"
                && f["pref"].as_u64() == self.priority.parse().ok()
                && f["options"]["handle"] == HANDLE
                && f["options"]["prog"]["id"] == self.program_id
        }))
    }

    pub(super) fn disable(&mut self, reason: &str) -> Result<()> {
        self.control
            .update(&0_u32.to_ne_bytes(), &0_u32.to_ne_bytes(), MapFlags::ANY)?;
        self.disabled_reason
            .get_or_insert_with(|| reason.to_owned());
        self.write_evidence()
    }

    fn write_evidence(&self) -> Result<()> {
        let mut records = Vec::new();
        for key in self.frames.keys() {
            let Some(value) = self.frames.lookup(&key, MapFlags::ANY)? else {
                continue;
            };
            let u32_at = |i| u32::from_ne_bytes(key[i..i + 4].try_into().unwrap());
            let u16_at = |i| u16::from_ne_bytes(key[i..i + 2].try_into().unwrap());
            let mac = |i| {
                key[i..i + 6]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            records.push(
                json!({"ifindex":u32_at(0), "hook":u32_at(4), "priority":u32_at(8),
                "mark":u32_at(12), "skb_iif":u32_at(16), "ether_type":u16_at(20),
                "vlan_depth":key[22], "source_mac":mac(24), "destination_mac":mac(30),
                "vlan_outer":u16_at(36), "vlan_inner":u16_at(38),
                "packets":u64::from_ne_bytes(value[..8].try_into().unwrap()),
                "bytes":u64::from_ne_bytes(value[8..].try_into().unwrap())}),
            );
        }
        let lost = self
            .overflow
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
            .context("overflow counter")?;
        let delivery =
            match crate::policy::priority_delivery::inspect(&self.lan, &self.selected_clients) {
                Ok(layout) => json!({"verified":true, "layout":layout}),
                Err(reason) => json!({"verified":false, "reason":reason}),
            };
        fs::write(
            &self.output,
            serde_json::to_vec_pretty(&json!({
                "kind":"read_only_client_path_probe_not_policy_acceptance", "abi_version":1,
                "frames_map_id":self.frames.info()?.info.id,
                "overflow_map_id":self.overflow.info()?.info.id,
                "disabled_reason":self.disabled_reason, "records":records,
            "delivery_resolution":delivery,
                "unrecorded_frames":u64::from_ne_bytes(lost.try_into().unwrap()),
            }))?,
        )?;
        Ok(())
    }
}

impl Drop for PathProbe {
    fn drop(&mut self) {
        let mut errors = Vec::new();
        let mut retain_pin = false;
        if let Err(error) = self.disable("Agent stopped") {
            errors.push(error.to_string());
        }
        for name in self.attached_interfaces.iter().rev() {
            match self.extra_filter_owned(name) {
                Ok(true) => {
                    if let Err(error) = tc(&[
                        "filter",
                        "del",
                        "dev",
                        name,
                        "egress",
                        "prio",
                        &self.priority,
                        "handle",
                        HANDLE,
                        "bpf",
                    ]) {
                        errors.push(error.to_string());
                        retain_pin = true;
                    }
                }
                _ => {
                    errors.push(format!(
                        "path probe filter ownership changed on {name}; retained"
                    ));
                    retain_pin = true;
                }
            }
        }
        for name in self.clsact_created_interfaces.iter().rev() {
            if ["ingress", "egress"].iter().all(|hook| {
                tc(&["filter", "show", "dev", name, hook]).is_ok_and(|s| s.trim().is_empty())
            }) {
                if let Err(error) = tc(&["qdisc", "del", "dev", name, "clsact"]) {
                    errors.push(error.to_string());
                }
            } else {
                errors.push("path probe clsact is not empty; retained".to_owned());
            }
        }
        if self.pin_dir.exists() && !retain_pin {
            if let Err(error) = fs::remove_file(self.pin_dir.join("observer"))
                .and_then(|()| fs::remove_dir(&self.pin_dir))
            {
                errors.push(error.to_string());
            }
        }
        let _ = fs::write(
            self.output.with_extension("cleanup.json"),
            serde_json::to_vec_pretty(&json!({"cleanup_ok":errors.is_empty(), "errors":errors}))
                .unwrap(),
        );
        if !errors.is_empty() {
            eprintln!("path probe cleanup incomplete: {errors:?}");
        }
    }
}
