//! Explicit, compile-time opt-in compatibility experiment in a test netns.
//! Does not read/write policy snapshots or advertise policy QoS capability.
use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::Command,
};

use anyhow::{Context as _, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapHandle, ProgramHandle, ProgramMut};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    config::{AgentConfig, AttachBackend},
    policy::classid::*,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    lan: String,
    ingress: Option<String>,
    ifb: String,
    client_v4: Ipv4Addr,
    remote_v4: Ipv4Addr,
    client_v6: Ipv6Addr,
    remote_v6: Ipv6Addr,
    output: PathBuf,
}

pub(super) struct QosPoc {
    config: Config,
    control: MapHandle,
    observations: MapHandle,
    observed_ifindexes: MapHandle,
    lan_ifindex: u32,
    ingress: String,
    ingress_ifindex: u32,
    ifb_ifindex: u32,
    redirect_priority: u32,
    pin_dir: PathBuf,
    ifb_created: bool,
    lan_root_created: bool,
    redirect_attached: bool,
    lan_classifier_attached: bool,
    lan_clsact_created: bool,
    control_bytes: Vec<u8>,
}

fn capture(binary: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(binary).args(args).output()?;
    if !output.status.success() {
        bail!(
            "{binary} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn tc(args: &[&str]) -> Result<String> {
    capture("tc", args)
}
fn ip(args: &[&str]) -> Result<String> {
    capture("ip", args)
}

fn parse_json(output: &str, operation: &str) -> Result<Value> {
    serde_json::from_str(output)
        .with_context(|| format!("{operation} returned invalid JSON: {output:?}"))
}

fn incompatible_nft(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(incompatible_nft),
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

pub(super) fn prepare(
    agent: &AgentConfig,
    observation_interfaces: &[(String, i32)],
    control: MapHandle,
    observations: MapHandle,
    observed_ifindexes: MapHandle,
) -> Result<Option<QosPoc>> {
    let Some(path) = std::env::var_os("NETQMON_QOS_POC_CONFIG") else {
        return Ok(None);
    };
    let config: Config = serde_json::from_slice(&fs::read(path)?)?;
    let ingress = config.ingress.clone().unwrap_or_else(|| config.lan.clone());
    if fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")? {
        bail!("QoS PoC refuses the initial network namespace");
    }
    for name in [&config.lan, &config.ifb, &ingress]
        .into_iter()
        .chain(observation_interfaces.iter().map(|(name, _)| name))
    {
        if !name.starts_with("nqp-")
            || name.len() > 15
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            bail!("QoS PoC requires exclusively nqp-* test interfaces");
        }
    }
    if config.lan != agent.interface || agent.interfaces != [config.lan.clone()] {
        bail!("QoS PoC requires exactly its single test capture interface");
    }
    if !observation_interfaces
        .iter()
        .any(|(name, _)| name == &ingress)
        || (ingress != config.lan
            && observation_interfaces
                .iter()
                .any(|(name, _)| name == &config.lan))
    {
        bail!(
            "QoS PoC ingress must be an actual Agent observation point; bridge classification must occur once"
        );
    }
    if agent.attach_backend != AttachBackend::Netlink {
        bail!("QoS PoC TCX remains gated until the netlink compatibility gate passes");
    }
    if !config.output.is_absolute()
        || !config.output.starts_with("/tmp")
        || config
            .output
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        bail!("QoS PoC evidence must be written inside /tmp");
    }
    if config.client_v4 == config.remote_v4 || config.client_v6 == config.remote_v6 {
        bail!("QoS PoC endpoints must be distinct");
    }
    if control.key_size() != 4
        || control.value_size() != 60
        || observations.key_size() != 4
        || observations.value_size() != 32
    {
        bail!("QoS PoC BPF ABI mismatch");
    }
    let nft = parse_json(&capture("nft", &["-j", "list", "ruleset"])?, "nft ruleset")?;
    if incompatible_nft(&nft) {
        bail!(
            "QoS PoC refuses nft priority writers or flow offload; packet marks alone are allowed"
        );
    }
    let lan_ifindex = nix::net::if_::if_nametoindex(config.lan.as_str())?;
    let ingress_ifindex = nix::net::if_::if_nametoindex(ingress.as_str())?;
    if nix::net::if_::if_nametoindex(config.ifb.as_str()).is_ok() {
        bail!("QoS PoC refuses an existing IFB name");
    }
    let root = parse_json(
        &tc(&["-j", "qdisc", "show", "dev", &config.lan])?,
        "LAN qdisc dump",
    )?;
    if !root
        .as_array()
        .context("qdisc JSON array")?
        .iter()
        .all(|entry| {
            matches!(
                entry.get("kind").and_then(Value::as_str),
                Some("noqueue" | "fq_codel" | "clsact")
            )
        })
    {
        bail!("QoS PoC refuses a non-default qdisc (including SQM/CAKE/HTB)");
    }
    for name in
        std::iter::once(&config.lan).chain(observation_interfaces.iter().map(|(name, _)| name))
    {
        for hook in ["ingress", "egress"] {
            if tc(&["filter", "show", "dev", name, hook])?.trim() != "" {
                bail!("QoS PoC refuses pre-existing {name}/{hook} filters");
            }
        }
    }
    let redirect_priority = agent
        .attach_order
        .tc_priority
        .checked_add(1)
        .filter(|p| *p <= u16::MAX.into())
        .context("no priority after observation hook")?;
    let mut poc = QosPoc {
        config,
        control,
        observations,
        observed_ifindexes,
        lan_ifindex,
        ingress,
        ingress_ifindex,
        ifb_ifindex: 0,
        redirect_priority,
        pin_dir: PathBuf::from(format!("/sys/fs/bpf/nqp-{}", std::process::id())),
        ifb_created: false,
        lan_root_created: false,
        redirect_attached: false,
        lan_classifier_attached: false,
        lan_clsact_created: false,
        control_bytes: Vec::new(),
    };
    ip(&["link", "add", &poc.config.ifb, "type", "ifb"])?;
    poc.ifb_created = true;
    poc.ifb_ifindex = nix::net::if_::if_nametoindex(poc.config.ifb.as_str())?;
    // IFB is an L2 queue, never an L3 endpoint. Suppress automatic link-local
    // addresses/routes and neighbor probes on this newly owned device only.
    let ipv6 = PathBuf::from(format!(
        "/proc/sys/net/ipv6/conf/{}/disable_ipv6",
        poc.config.ifb
    ));
    if ipv6.exists() {
        fs::write(ipv6, b"1\n")?;
    }
    ip(&["link", "set", &poc.config.ifb, "up"])?;
    poc.add_tree(&poc.config.ifb.clone(), UPLOAD_MAJOR)?;
    poc.add_tree(&poc.config.lan.clone(), DOWNLOAD_MAJOR)?;
    poc.lan_root_created = true;
    fs::create_dir(&poc.pin_dir).context("create exclusive PoC bpffs pin directory")?;
    for value in [
        POC_ABI_VERSION,
        poc.lan_ifindex,
        poc.ifb_ifindex,
        0,
        poc.ingress_ifindex,
    ] {
        poc.control_bytes.extend(value.to_ne_bytes());
    }
    poc.control_bytes.extend(poc.config.client_v4.octets());
    poc.control_bytes.extend(poc.config.remote_v4.octets());
    poc.control_bytes.extend(poc.config.client_v6.octets());
    poc.control_bytes.extend(poc.config.remote_v6.octets());
    poc.control
        .update(&0_u32.to_ne_bytes(), &poc.control_bytes, MapFlags::ANY)?;
    Ok(Some(poc))
}

impl QosPoc {
    fn add_tree(&mut self, interface: &str, major: u32) -> Result<()> {
        let root = format!("{major:x}:");
        let parent = format!("{major:x}:{ROOT_MINOR:x}");
        let client = format!("{major:x}:{POC_CLIENT_MINOR:x}");
        let leaf = ClassId::leaf(major, POC_LEAF_MINOR)
            .map_err(anyhow::Error::msg)?
            .to_string();
        let bypass = ClassId::leaf(major, BYPASS_MINOR)
            .map_err(anyhow::Error::msg)?
            .to_string();
        tc(&[
            "qdisc", "add", "dev", interface, "root", "handle", &root, "htb", "default", "fffe",
        ])?;
        // Track partial creation too, so a failed class install can roll back.
        if major == DOWNLOAD_MAJOR {
            self.lan_root_created = true;
        }
        // These are structural classes for the isolated compatibility gate,
        // not requested global link budgets. Keep bypass eligible without
        // borrowing behind a busy client. Real client rates belong to stage 2.
        for (class, ancestor, rate) in [
            (&parent, &root, "100000mbit"),
            (&client, &parent, "100000mbit"),
            (&leaf, &client, "100000mbit"),
            (&bypass, &parent, "100000mbit"),
        ] {
            tc(&[
                "class",
                "add",
                "dev",
                interface,
                "parent",
                ancestor,
                "classid",
                class,
                "htb",
                "rate",
                rate,
                "ceil",
                "100000mbit",
            ])?;
        }
        for (target, handle) in [(&leaf, "7000:"), (&bypass, "7001:")] {
            tc(&[
                "qdisc", "add", "dev", interface, "parent", target, "handle", handle, "fq_codel",
            ])?;
        }
        // iproute2 6.1's HTB class printer does not implement JSON, even
        // with -j. Request text deliberately and verify exact parent edges.
        let classes = tc(&["class", "show", "dev", interface])?;
        for expected in [&parent, &client, &leaf, &bypass] {
            let ancestor = if expected == &parent {
                None
            } else if expected == &leaf {
                Some(client.as_str())
            } else {
                Some(parent.as_str())
            };
            if !has_class_edge(&classes, expected, ancestor) {
                bail!("QoS PoC missing class/parent edge {expected} -> {ancestor:?}");
            }
        }
        Ok(())
    }

    pub(super) fn activate(
        &mut self,
        matcher: &ProgramMut<'_>,
        ifb_observer: &ProgramMut<'_>,
        lan_classifier: &ProgramMut<'_>,
    ) -> Result<()> {
        let matcher_pin = self.pin_dir.join("matcher");
        let observer_pin = self.pin_dir.join("observer");
        ProgramHandle::try_from(matcher)?.pin(&matcher_pin)?;
        ProgramHandle::try_from(ifb_observer)?.pin(&observer_pin)?;
        let priority = self.redirect_priority.to_string();
        if self.ingress != self.config.lan {
            let lan_pin = self.pin_dir.join("lan_classifier");
            ProgramHandle::try_from(lan_classifier)?.pin(&lan_pin)?;
            let qdiscs = parse_json(
                &tc(&["-j", "qdisc", "show", "dev", &self.config.lan])?,
                "LAN qdisc",
            )?;
            if !qdiscs
                .as_array()
                .context("qdisc array")?
                .iter()
                .any(|q| q["kind"] == "clsact")
            {
                tc(&["qdisc", "add", "dev", &self.config.lan, "clsact"])?;
                self.lan_clsact_created = true;
            }
            tc(&[
                "filter",
                "add",
                "dev",
                &self.config.lan,
                "egress",
                "protocol",
                "all",
                "prio",
                &priority,
                "handle",
                "0x4e515003",
                "bpf",
                "da",
                "pinned",
                lan_pin.to_str().unwrap(),
            ])?;
            self.lan_classifier_attached = true;
        }
        tc(&[
            "filter",
            "add",
            "dev",
            &self.ingress,
            "ingress",
            "protocol",
            "all",
            "prio",
            &priority,
            "handle",
            "0x4e515001",
            "bpf",
            "pinned",
            matcher_pin.to_str().unwrap(),
            "classid",
            "52:200",
            "action",
            "mirred",
            "egress",
            "redirect",
            "dev",
            &self.config.ifb,
        ])?;
        self.redirect_attached = true;
        tc(&["qdisc", "add", "dev", &self.config.ifb, "clsact"])?;
        tc(&[
            "filter",
            "add",
            "dev",
            &self.config.ifb,
            "egress",
            "protocol",
            "all",
            "prio",
            "1",
            "handle",
            "0x4e515002",
            "bpf",
            "da",
            "pinned",
            observer_pin.to_str().unwrap(),
        ])?;
        self.observed_ifindexes
            .update(&self.ifb_ifindex.to_ne_bytes(), &[1], MapFlags::ANY)?;
        self.control_bytes[12..16].copy_from_slice(&1_u32.to_ne_bytes());
        self.control
            .update(&0_u32.to_ne_bytes(), &self.control_bytes, MapFlags::ANY)?;
        self.write_evidence()?;
        eprintln!(
            "QoS compatibility PoC active on {} via {} (not policy QoS support)",
            self.config.lan, self.config.ifb
        );
        Ok(())
    }

    fn write_evidence(&self) -> Result<()> {
        let mut observations = Vec::new();
        for slot in 0_u32..6 {
            let bytes = self
                .observations
                .lookup(&slot.to_ne_bytes(), MapFlags::ANY)?
                .context("PoC observation missing")?;
            let u32_at = |offset| u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let u64_at = |offset| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
            observations.push(json!({"slot":slot, "packets":u64_at(0), "bytes":u64_at(8),
                "mark":u32_at(16), "priority":u32_at(20), "ifindex":u32_at(24), "skb_iif":u32_at(28)}));
        }
        fs::write(
            &self.config.output,
            serde_json::to_vec_pretty(&json!({
                "kind":"compatibility_poc_not_policy_acceptance", "abi_version":POC_ABI_VERSION,
                "lan_ifindex":self.lan_ifindex, "ifb_ifindex":self.ifb_ifindex,
                "ingress_ifindex":self.ingress_ifindex, "ingress":self.ingress,
                "control_map_id":self.control.info()?.info.id,
                "observations_map_id":self.observations.info()?.info.id,
                "observations":observations,
            }))?,
        )?;
        Ok(())
    }
}

fn has_class_edge(output: &str, class: &str, parent: Option<&str>) -> bool {
    output.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(..3) == Some(&["class", "htb", class][..])
            && match parent {
                Some(parent) => fields.get(3..5) == Some(&["parent", parent][..]),
                None => fields.get(3) == Some(&"root"),
            }
    })
}

impl Drop for QosPoc {
    fn drop(&mut self) {
        let mut errors = Vec::new();
        if let Err(error) = self.write_evidence() {
            errors.push(error.to_string());
        }
        if self.control_bytes.len() == 60 {
            self.control_bytes[12..16].copy_from_slice(&0_u32.to_ne_bytes());
            if let Err(error) =
                self.control
                    .update(&0_u32.to_ne_bytes(), &self.control_bytes, MapFlags::ANY)
            {
                errors.push(error.to_string());
            }
        }
        if self.redirect_attached {
            if let Err(error) = tc(&[
                "filter",
                "del",
                "dev",
                &self.ingress,
                "ingress",
                "prio",
                &self.redirect_priority.to_string(),
                "handle",
                "0x4e515001",
                "bpf",
            ]) {
                errors.push(error.to_string());
            }
        }
        if self.lan_classifier_attached {
            if let Err(error) = tc(&[
                "filter",
                "del",
                "dev",
                &self.config.lan,
                "egress",
                "prio",
                &self.redirect_priority.to_string(),
                "handle",
                "0x4e515003",
                "bpf",
            ]) {
                errors.push(error.to_string());
            }
        }
        if self.lan_clsact_created {
            let empty = ["ingress", "egress"].iter().all(|hook| {
                tc(&["filter", "show", "dev", &self.config.lan, hook])
                    .is_ok_and(|s| s.trim().is_empty())
            });
            if empty {
                if let Err(error) = tc(&["qdisc", "del", "dev", &self.config.lan, "clsact"]) {
                    errors.push(error.to_string());
                }
            } else {
                errors.push("LAN clsact ownership changed; left untouched".to_owned());
            }
        }
        if self.lan_root_created {
            match tc(&["-j", "qdisc", "show", "dev", &self.config.lan])
                .and_then(|text| Ok(serde_json::from_str::<Value>(&text)?))
            {
                Ok(qdiscs)
                    if qdiscs.as_array().is_some_and(|entries| {
                        entries
                            .iter()
                            .any(|q| q["kind"] == "htb" && q["handle"] == "51:")
                    }) =>
                {
                    if let Err(error) = tc(&[
                        "qdisc",
                        "del",
                        "dev",
                        &self.config.lan,
                        "root",
                        "handle",
                        "51:",
                    ]) {
                        errors.push(error.to_string());
                    }
                }
                _ => errors.push("LAN root ownership changed; left untouched".to_owned()),
            }
        }
        if self.ifb_created {
            if nix::net::if_::if_nametoindex(self.config.ifb.as_str()).ok()
                == Some(self.ifb_ifindex)
            {
                if let Err(error) = ip(&["link", "del", &self.config.ifb]) {
                    errors.push(error.to_string());
                }
            } else {
                errors.push("IFB identity changed; left untouched".to_owned());
            }
            let _ = self
                .observed_ifindexes
                .delete(&self.ifb_ifindex.to_ne_bytes());
        }
        for name in ["matcher", "observer", "lan_classifier"] {
            let path = self.pin_dir.join(name);
            if path.exists() {
                if let Err(error) = fs::remove_file(path) {
                    errors.push(error.to_string());
                }
            }
        }
        if self.pin_dir.exists() {
            if let Err(error) = fs::remove_dir(&self.pin_dir) {
                errors.push(error.to_string());
            }
        }
        let _ = fs::write(
            self.config.output.with_extension("cleanup.json"),
            serde_json::to_vec_pretty(&json!({"cleanup_ok":errors.is_empty(), "errors":errors}))
                .unwrap(),
        );
        if !errors.is_empty() {
            eprintln!("QoS PoC cleanup incomplete: {errors:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_edges_require_actual_htb_handles_and_correct_parent() {
        let dump = "class htb 51:1 root rate 1Gbit\nclass htb 51:100 parent 51:1\nclass htb 51:200 parent 51:100\nclass htb 51:fffe parent 51:1\n";
        assert!(has_class_edge(dump, "51:1", None));
        assert!(has_class_edge(dump, "51:200", Some("51:100")));
        assert!(has_class_edge(dump, "51:fffe", Some("51:1")));
        assert!(!has_class_edge(dump, "51:fffe", Some("51:100")));
        assert!(!has_class_edge(dump, "52:200", Some("52:100")));
        assert!(!has_class_edge(
            "class cake 51:200 parent 51:100",
            "51:200",
            Some("51:100")
        ));
    }

    #[test]
    fn priority_writes_and_offload_conflict_but_mark_use_and_priority_reads_do_not() {
        assert!(incompatible_nft(&json!({"mangle":{
            "key":{"meta":{"key":"priority"}},"value":"51:200"}})));
        assert!(incompatible_nft(
            &json!({"nftables":[{"flowtable":{"name":"ft"}}]})
        ));
        assert!(!incompatible_nft(&json!({"mangle":{
            "key":{"meta":{"key":"mark"}},"value":0x5053_5732_u32}})));
        assert!(!incompatible_nft(&json!({"match":{
            "left":{"meta":{"key":"priority"}},"op":"==","right":"52:200"}})));
    }
}
