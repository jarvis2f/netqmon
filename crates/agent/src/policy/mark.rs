use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use serde_json::Value;

#[cfg(target_os = "linux")]
use super::qdisc;
use super::shaper::{ClientClass, Direction, client_mark_value};
#[cfg(target_os = "linux")]
use super::shaper::{ManagedInterface, ShapingState};

pub(super) const PRESERVED_MARK_MASK: u32 = 0x0000_ffff;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MarkRule {
    pub interface_in: String,
    pub interface_out: String,
    pub address: IpAddr,
    pub direction: Direction,
    pub tag: u16,
}

impl MarkRule {
    pub(super) fn render(&self) -> String {
        let (field, address) = match self.address {
            IpAddr::V4(address) => ("ip", address.to_string()),
            IpAddr::V6(address) => ("ip6", address.to_string()),
        };
        let tag = client_mark_value(self.tag);
        if self.interface_in == self.interface_out {
            let internal = if self.address.is_ipv4() {
                "internal_v4"
            } else {
                "internal_v6"
            };
            let (client_origin, remote_origin) = match self.direction {
                Direction::Upload => ("original", "reply"),
                Direction::Download => ("reply", "original"),
            };
            // Match original client identity across SNAT, and the translated
            // reply-source identity for inbound DNAT. The forward hook runs
            // after destination NAT and before source NAT/HTB enqueue.
            return format!(
                "    iifname \"{interface}\" oifname \"{interface}\" ct direction {client_origin} ct original {field} saddr {address} ct original {field} daddr != @{internal} meta mark set ((meta mark & 0x{PRESERVED_MARK_MASK:08x}) | 0x{tag:08x}) comment \"netqmon:shared:{}\"\n    iifname \"{interface}\" oifname \"{interface}\" ct direction {remote_origin} ct reply {field} saddr {address} ct original {field} saddr != @{internal} meta mark set ((meta mark & 0x{PRESERVED_MARK_MASK:08x}) | 0x{tag:08x}) comment \"netqmon:shared:{}\"\n",
                self.direction.as_str(),
                self.direction.as_str(),
                interface = self.interface_in,
            );
        }
        format!(
            "    iifname \"{}\" oifname \"{}\" {field} {} {address} meta mark set ((meta mark & 0x{PRESERVED_MARK_MASK:08x}) | 0x{tag:08x}) comment \"netqmon:traffic-limit:{}\"\n",
            self.interface_in,
            self.interface_out,
            match self.direction {
                Direction::Upload => "saddr",
                Direction::Download => "daddr",
            },
            self.direction.as_str(),
        )
    }
}

pub(super) fn rules_for_clients(
    upload: &[ClientClass],
    download: &[ClientClass],
    addresses: &[(String, IpAddr)],
    lan_interface: &str,
    wan_interface: &str,
) -> Vec<MarkRule> {
    let mut rules = Vec::new();
    for class in upload {
        for (mac, address) in addresses {
            if mac.eq_ignore_ascii_case(&class.mac) {
                rules.push(MarkRule {
                    interface_in: lan_interface.to_owned(),
                    interface_out: wan_interface.to_owned(),
                    address: *address,
                    direction: Direction::Upload,
                    tag: class.tag,
                });
            }
        }
    }
    for class in download {
        for (mac, address) in addresses {
            if mac.eq_ignore_ascii_case(&class.mac) {
                rules.push(MarkRule {
                    interface_in: wan_interface.to_owned(),
                    interface_out: lan_interface.to_owned(),
                    address: *address,
                    direction: Direction::Download,
                    tag: class.tag,
                });
            }
        }
    }
    rules.sort_by(|left, right| {
        (
            left.direction,
            left.interface_in.as_str(),
            left.interface_out.as_str(),
            left.address,
            left.tag,
        )
            .cmp(&(
                right.direction,
                right.interface_in.as_str(),
                right.interface_out.as_str(),
                right.address,
                right.tag,
            ))
    });
    rules.dedup();
    rules
}

#[cfg(target_os = "linux")]
pub(super) fn inspect_conflicts(
    interfaces: &[String],
    owned: Option<&ShapingState>,
) -> Result<(), String> {
    inspect_nft_conflicts()?;
    for (binary, args) in [
        ("iptables-save", Vec::<&str>::new()),
        ("ip6tables-save", Vec::<&str>::new()),
        ("iptables-legacy-save", Vec::<&str>::new()),
        ("ip6tables-legacy-save", Vec::<&str>::new()),
    ] {
        inspect_optional_marker_command(binary, &args, &|output| {
            output.contains("MARK") || output.contains("CONNMARK")
        })?;
    }
    inspect_marker_command("ip", &["rule", "show"], &|output| output.contains("fwmark"))?;
    inspect_marker_command("ip", &["-6", "rule", "show"], &|output| {
        output.contains("fwmark")
    })?;
    for interface in interfaces {
        let output = run_capture("tc", &["-j", "filter", "show", "dev", interface])?;
        let owned_interface =
            owned.and_then(|state| state.interfaces().find(|entry| entry.name == *interface));
        let filters: Option<Value> = match serde_json::from_str(&output) {
            Ok(filters) => Some(filters),
            Err(error) => {
                let text_output = run_capture("tc", &["filter", "show", "dev", interface])?;
                let has_foreign_fw = text_output.lines().any(|line| {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    fields.iter().any(|field| *field == "fw")
                        && !owned_fw_parent(find_field(&fields, "parent"), owned_interface)
                });
                if has_foreign_fw {
                    return Err(format!(
                        "unsupported_mark_conflict: an existing tc fw classifier uses marks on {interface}"
                    ));
                }

                let has_owned_fw = text_output.lines().any(|line| {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    fields.iter().any(|field| *field == "fw")
                        && owned_fw_parent(find_field(&fields, "parent"), owned_interface)
                });
                if owned_interface.is_none() || !has_owned_fw {
                    return Err(format!(
                        "unsupported_mark_conflict: tc returned invalid filter data: {error}"
                    ));
                }
                None
            }
        };
        if let Some(owned_interface) = owned_interface {
            qdisc::verify_owned(owned_interface)?;
        }
        let has_foreign_fw = filters.as_ref().is_some_and(|filters| {
            filters.as_array().is_none_or(|filters| {
                filters.iter().any(|filter| {
                    filter.get("kind").and_then(Value::as_str) == Some("fw")
                        && !owned_fw_parent(
                            filter.get("parent").and_then(Value::as_str),
                            owned_interface,
                        )
                })
            })
        });
        if has_foreign_fw {
            return Err(format!(
                "unsupported_mark_conflict: an existing tc fw classifier uses marks on {interface}"
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn find_field<'a>(fields: &'a [&str], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .position(|field| *field == key)
        .and_then(|index| fields.get(index + 1).copied())
}

#[cfg(target_os = "linux")]
fn owned_fw_parent(parent: Option<&str>, owned: Option<&ManagedInterface>) -> bool {
    owned.is_some_and(|interface| {
        parent == Some("51:")
            || interface.application_classes.iter().any(|application| {
                parent == Some(format!("51:{}", application.parent_class_minor).as_str())
            })
    })
}

#[cfg(target_os = "linux")]
fn inspect_nft_conflicts() -> Result<(), String> {
    let ruleset = run_capture("nft", &["list", "ruleset"])?;
    let external = strip_netqmon_policy_table(&ruleset);
    if external.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("meta mark") || lower.contains("ct mark")
    }) {
        return Err(
            "unsupported_mark_conflict: an existing nftables rule uses skb or conntrack marks"
                .to_owned(),
        );
    }
    Ok(())
}

fn strip_netqmon_policy_table(ruleset: &str) -> String {
    let mut output = String::new();
    let mut skipping = false;
    let mut depth = 0_i32;
    for line in ruleset.lines() {
        if !skipping && line.trim_start().starts_with("table inet netqmon_policy {") {
            skipping = true;
            depth = brace_delta(line);
            if depth <= 0 {
                skipping = false;
            }
            continue;
        }
        if skipping {
            depth += brace_delta(line);
            if depth <= 0 {
                skipping = false;
            }
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn brace_delta(line: &str) -> i32 {
    line.bytes().fold(0_i32, |depth, byte| match byte {
        b'{' => depth + 1,
        b'}' => depth - 1,
        _ => depth,
    })
}

#[cfg(target_os = "linux")]
fn inspect_optional_marker_command(
    binary: &str,
    args: &[&str],
    uses_marker: &impl Fn(&str) -> bool,
) -> Result<(), String> {
    match Command::new(binary).args(args).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            if uses_marker(&text) {
                Err(format!(
                    "unsupported_mark_conflict: {binary} reports an existing packet-mark rule"
                ))
            } else {
                Ok(())
            }
        }
        Ok(_) => Err(format!(
            "unsupported_mark_conflict: could not inspect existing packet-mark rules with {binary}"
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "unsupported_mark_conflict: could not inspect {binary}: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn inspect_marker_command(
    binary: &str,
    args: &[&str],
    uses_marker: &impl Fn(&str) -> bool,
) -> Result<(), String> {
    let text = run_capture(binary, args)?;
    if uses_marker(&text) {
        Err(format!(
            "unsupported_mark_conflict: {binary} reports an existing packet-mark rule"
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn run_capture(binary: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| format!("unsupported_mark_conflict: could not start {binary}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "unsupported_mark_conflict: {binary} could not inspect packet-mark use: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn shared_marks_use_conntrack_identity_and_direction_without_consuming_low_bits() {
        let mut rule = MarkRule {
            interface_in: "one0".to_owned(),
            interface_out: "one0".to_owned(),
            address: "192.0.2.2".parse().unwrap(),
            direction: Direction::Upload,
            tag: 7,
        };
        let upload = rule.render();
        assert!(upload.contains("ct direction original ct original ip saddr 192.0.2.2"));
        assert!(upload.contains("ct direction reply ct reply ip saddr 192.0.2.2"));
        assert!(upload.contains("meta mark & 0x0000ffff"));
        rule.direction = Direction::Download;
        rule.tag = 0x107;
        rule.address = "fd00::2".parse().unwrap();
        let download = rule.render();
        assert!(download.contains("ct direction reply ct original ip6 saddr fd00::2"));
        assert!(download.contains("0x01070000"));
        assert!(download.contains("ct direction original ct reply ip6 saddr fd00::2"));
    }

    #[test]
    fn renders_forward_stage_marks_without_clobbering_low_mark_bits() {
        let rule = MarkRule {
            interface_in: "br-lan".to_owned(),
            interface_out: "eth0".to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            direction: Direction::Upload,
            tag: 7,
        };
        let rendered = rule.render();
        assert!(rendered.contains("iifname \"br-lan\" oifname \"eth0\""));
        assert!(rendered.contains("ip saddr 192.0.2.10"));
        assert!(rendered.contains("meta mark & 0x0000ffff"));
        assert!(rendered.contains("0x00070000"));
    }

    #[test]
    fn router_client_marks_follow_packet_path_for_both_families() {
        let class = |direction, interface: &str| ClientClass {
            gateway_id: "test".to_owned(),
            mac: "02:10:10:10:10:01".to_owned(),
            direction,
            interface: interface.to_owned(),
            ifindex: 1,
            tag: 1,
            class_minor: 2,
            leaf_minor: 3,
            rate_bps: 10_000_000,
            has_total_budget: true,
        };
        let upload = class(Direction::Upload, "wan0");
        let download = class(Direction::Download, "lan0");
        for (address, family) in [("192.0.2.10", "ip"), ("2001:db8::10", "ip6")] {
            let rules = rules_for_clients(
                std::slice::from_ref(&upload),
                std::slice::from_ref(&download),
                &[(upload.mac.clone(), address.parse().unwrap())],
                "lan0",
                "wan0",
            );
            assert_eq!(rules.len(), 2);
            for rule in rules {
                let rendered = rule.render();
                match rule.direction {
                    Direction::Upload => assert!(rendered.contains(&format!(
                        "iifname \"lan0\" oifname \"wan0\" {family} saddr {address}"
                    ))),
                    Direction::Download => assert!(rendered.contains(&format!(
                        "iifname \"wan0\" oifname \"lan0\" {family} daddr {address}"
                    ))),
                }
            }
        }
    }

    #[test]
    fn mark_conflict_scan_ignores_only_the_owned_policy_table() {
        let input = "table inet filter {\n chain forward { meta mark set 7 }\n}\ntable inet netqmon_policy {\n chain forward_guard { meta mark set 65536 }\n}\n";
        assert!(strip_netqmon_policy_table(input).contains("meta mark"));
        let input = "table inet netqmon_policy {\n chain forward_guard { meta mark set 65536 }\n}\ntable inet filter {\n chain forward { accept }\n}\n";
        assert!(!strip_netqmon_policy_table(input).contains("meta mark"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_fw_parent_requires_a_matching_saved_interface() {
        let owned = ManagedInterface {
            shared_egress: false,
            name: "wan0".to_owned(),
            ifindex: 2,
            capacity_bps: 10_000_000,
            original_root_kind: "noqueue".to_owned(),
            clients: Vec::new(),
            application_classes: Vec::new(),
        };

        assert!(owned_fw_parent(Some("51:"), Some(&owned)));
        assert!(!owned_fw_parent(Some("51:"), None));
        assert!(!owned_fw_parent(Some("1:"), Some(&owned)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and CAP_NET_ADMIN in a private Linux network namespace"]
    fn rejects_live_foreign_nft_packet_mark_without_mutating_ruleset() {
        use std::process::Command;

        assert!(nix::unistd::geteuid().is_root(), "test requires root");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to mutate a process in the host network namespace"
        );
        let run = |arguments: &[&str]| {
            let output = Command::new("nft").args(arguments).output().unwrap();
            assert!(
                output.status.success(),
                "nft {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };
        run(&["add", "table", "inet", "nq_mark_conflict_test"]);
        run(&["add", "chain", "inet", "nq_mark_conflict_test", "probe"]);
        run(&[
            "add",
            "rule",
            "inet",
            "nq_mark_conflict_test",
            "probe",
            "meta",
            "mark",
            "set",
            "42",
        ]);
        let before = run(&["list", "table", "inet", "nq_mark_conflict_test"]).stdout;

        let error = inspect_conflicts(&[], None).unwrap_err();
        assert!(error.starts_with("unsupported_mark_conflict:"), "{error}");
        assert!(error.contains("existing nftables rule uses skb or conntrack marks"));
        let after = run(&["list", "table", "inet", "nq_mark_conflict_test"]).stdout;
        assert_eq!(before, after, "mark conflict preflight mutated the ruleset");

        run(&["delete", "table", "inet", "nq_mark_conflict_test"]);
        println!("PASS: foreign nft packet-mark rule was rejected without mutation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and CAP_NET_ADMIN in a private Linux network namespace"]
    fn rejects_live_foreign_tc_fw_filter_without_mutating_filter_tree() {
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
        run(
            "tc",
            &[
                "qdisc", "add", "dev", "wan0", "root", "handle", "1:", "htb", "default", "1",
            ],
        );
        run(
            "tc",
            &[
                "class", "add", "dev", "wan0", "parent", "1:", "classid", "1:1", "htb", "rate",
                "1mbit",
            ],
        );
        run(
            "tc",
            &[
                "filter", "add", "dev", "wan0", "parent", "1:", "protocol", "ip", "pref", "100",
                "handle", "0x1", "fw", "classid", "1:1",
            ],
        );
        let before = run("tc", &["-j", "filter", "show", "dev", "wan0"]).stdout;
        assert!(String::from_utf8_lossy(&before).contains("\"kind\":\"fw\""));

        let error = inspect_conflicts(&["wan0".to_owned()], None).unwrap_err();
        assert!(
            error.contains("existing tc fw classifier uses marks on wan0"),
            "{error}"
        );
        let after = run("tc", &["-j", "filter", "show", "dev", "wan0"]).stdout;
        assert_eq!(
            before, after,
            "mark conflict preflight mutated the TC filter tree"
        );

        run("tc", &["qdisc", "del", "dev", "wan0", "root"]);
        run("ip", &["link", "del", "wan0"]);
        println!("PASS: foreign tc fw filter was rejected without mutation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and CAP_NET_ADMIN in a private Linux network namespace"]
    fn rechecks_owned_tc_fw_filters_when_iproute_json_is_invalid() {
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
        let ifindex = nix::net::if_::if_nametoindex("wan0").unwrap();
        let state = ShapingState {
            shared_egress: None,
            schema_version: 1,
            upload_interface: Some(ManagedInterface {
                shared_egress: false,
                name: "wan0".to_owned(),
                ifindex,
                capacity_bps: 10_000_000,
                original_root_kind: "noqueue".to_owned(),
                clients: vec![ClientClass {
                    gateway_id: "gw-test".to_owned(),
                    mac: "02:00:00:00:00:01".to_owned(),
                    direction: Direction::Upload,
                    interface: "wan0".to_owned(),
                    ifindex,
                    tag: 1,
                    class_minor: 101,
                    leaf_minor: 1001,
                    rate_bps: 1_000_000,
                    has_total_budget: true,
                }],
                application_classes: Vec::new(),
            }),
            download_interface: None,
        };

        qdisc::apply(&state, None).expect("install test-owned HTB qdisc");
        let json = run("tc", &["-j", "filter", "show", "dev", "wan0"]).stdout;
        assert!(
            serde_json::from_slice::<Value>(&json).is_err(),
            "fixture must reproduce this iproute2 fw-filter JSON encoding"
        );
        inspect_conflicts(&["wan0".to_owned()], Some(&state))
            .expect("saved NetQmon fw filters should pass after ownership verification");

        qdisc::restore(&state).expect("restore original test qdisc");
        run("ip", &["link", "del", "wan0"]);
        println!(
            "PASS: owned tc fw filters passed conflict inspection after ownership verification"
        );
    }
}
