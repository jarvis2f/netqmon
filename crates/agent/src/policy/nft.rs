use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::topology::NetworkPrefix;

use super::capabilities::PolicyTopology;

pub(super) const TABLE_NAME: &str = "netqmon_policy";
const TABLE_MARKER: &str = "netqmon:managed-policy:v1";
pub(super) const RULESET_VERSION: u8 = 2;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BLOCKED_ADDRESSES_PER_FAMILY: usize = 16_384;
const MAX_NFT_SCRIPT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NftPlan {
    pub blocked_v4: Vec<Ipv4Addr>,
    pub blocked_v6: Vec<Ipv6Addr>,
    pub mark_rules: Vec<super::mark::MarkRule>,
}

pub(crate) fn replace(topology: &PolicyTopology, plan: &NftPlan) -> Result<(), String> {
    validate_interfaces(topology)?;
    if plan.blocked_v4.len() > MAX_BLOCKED_ADDRESSES_PER_FAMILY
        || plan.blocked_v6.len() > MAX_BLOCKED_ADDRESSES_PER_FAMILY
    {
        return Err("refusing to install a policy set above the blocked-address limit".to_owned());
    }
    let previous = table_exists_and_owned()?;
    let script = render(topology, plan, previous);
    if script.len() > MAX_NFT_SCRIPT_BYTES {
        return Err("refusing to install an nft batch above the size limit".to_owned());
    }
    run_nft(&["-c", "-f", "-"], script.as_bytes())?;
    run_nft(&["-f", "-"], script.as_bytes())?;
    verify_plan(plan)
}

fn verify_plan(plan: &NftPlan) -> Result<(), String> {
    if !table_exists_and_owned()? {
        return Err("nft verification failed: the owned policy table is missing".to_owned());
    }
    let table = String::from_utf8_lossy(&run_nft_capture(&["list", "table", "inet", TABLE_NAME])?)
        .into_owned();
    for rule in &plan.mark_rules {
        let address = rule.address.to_string();
        let tag = format!("0x{:08x}", u32::from(rule.tag) << 16);
        if !table.contains(&address) || !table.contains(&tag) {
            return Err(format!(
                "nft verification failed: {} mark for {address} is missing",
                rule.direction.as_str()
            ));
        }
    }
    for address in &plan.blocked_v4 {
        if !table.contains(&address.to_string()) {
            return Err(format!(
                "nft verification failed: blocked client address {address} is missing"
            ));
        }
    }
    for address in &plan.blocked_v6 {
        if !table.contains(&address.to_string()) {
            return Err(format!(
                "nft verification failed: blocked client address {address} is missing"
            ));
        }
    }
    Ok(())
}

pub(crate) fn clear_owned() -> Result<(), String> {
    if !table_exists_and_owned()? {
        return Ok(());
    }
    let script = format!("delete table inet {TABLE_NAME}\n");
    run_nft(&["-c", "-f", "-"], script.as_bytes())?;
    run_nft(&["-f", "-"], script.as_bytes())
}

pub(crate) fn is_installed() -> Result<bool, String> {
    table_exists_and_owned()
}

fn table_exists_and_owned() -> Result<bool, String> {
    let tables = run_nft_capture(&["list", "tables"])?;
    let exists = String::from_utf8_lossy(&tables)
        .lines()
        .any(|line| line.trim() == format!("table inet {TABLE_NAME}"));
    if !exists {
        return Ok(false);
    }
    let table = run_nft_capture(&["list", "table", "inet", TABLE_NAME])?;
    let table = String::from_utf8_lossy(&table);
    if !table.contains(TABLE_MARKER) {
        return Err(
            "refusing to replace inet netqmon_policy because its ownership marker is missing"
                .to_owned(),
        );
    }
    Ok(true)
}

fn validate_interfaces(topology: &PolicyTopology) -> Result<(), String> {
    for name in topology
        .lan_interfaces
        .iter()
        .chain(topology.wan_interfaces.iter())
    {
        if name.is_empty()
            || name.len() > 15
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            })
        {
            return Err(format!(
                "interface name {name:?} cannot be safely represented in nft syntax"
            ));
        }
    }
    if topology.lan_interfaces.is_empty() || topology.wan_interfaces.is_empty() {
        return Err(
            "refusing to install policy rules without verified LAN and WAN interfaces".to_owned(),
        );
    }
    Ok(())
}

fn render(topology: &PolicyTopology, plan: &NftPlan, delete_previous: bool) -> String {
    let mut output = String::new();
    if delete_previous {
        output.push_str(&format!("delete table inet {TABLE_NAME}\n"));
    }
    output.push_str(&format!(
        "table inet {TABLE_NAME} {{\n  comment \"{TABLE_MARKER}\"\n"
    ));
    set_ifnames(&mut output, "managed_lan", &topology.lan_interfaces);
    set_ifnames(&mut output, "wan_egress", &topology.wan_interfaces);
    set_networks(
        &mut output,
        "internal_v4",
        "ipv4_addr",
        topology
            .internal_networks
            .iter()
            .filter(|value| value.contains('.'))
            .map(String::as_str),
    );
    set_networks(
        &mut output,
        "internal_v6",
        "ipv6_addr",
        topology
            .internal_networks
            .iter()
            .filter(|value| value.contains(':'))
            .map(String::as_str),
    );
    set_addresses(
        &mut output,
        "blocked_clients_v4",
        "ipv4_addr",
        plan.blocked_v4.iter().map(ToString::to_string),
    );
    set_addresses(
        &mut output,
        "blocked_clients_v6",
        "ipv6_addr",
        plan.blocked_v6.iter().map(ToString::to_string),
    );
    // Before conntrack/NAT and transparent-proxy mangle hooks: evaluate the
    // client's original Internet destination, not the redirected local socket.
    output.push_str(concat!(
        "  chain prerouting_guard {\n    type filter hook prerouting priority -305; policy accept;\n",
        "    iifname != @managed_lan return\n",
        "    ip saddr != @blocked_clients_v4 return\n",
        "    ip6 saddr != @blocked_clients_v6 return\n",
        "    iifname @managed_lan fib daddr type local return comment \"netqmon preserves router services\"\n",
        "    iifname @managed_lan ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } return comment \"netqmon preserves IPv4 link traffic\"\n",
        "    iifname @managed_lan ip6 daddr { fe80::/10, ff00::/8 } return comment \"netqmon preserves IPv6 link traffic\"\n",
        "    iifname @managed_lan ip saddr @blocked_clients_v4 ip daddr != @internal_v4 counter drop comment \"netqmon pre-proxy client Internet block\"\n",
    ));
    if topology.ipv6_coverage {
        output.push_str(
            "    iifname @managed_lan ip6 saddr @blocked_clients_v6 ip6 daddr != @internal_v6 counter drop comment \"netqmon pre-proxy IPv6 client Internet block\"\n",
        );
    }
    output.push_str("  }\n");
    output.push_str(
        "  chain forward_guard {\n    type filter hook forward priority -5; policy accept;\n",
    );
    if topology.is_one_arm_router() && !plan.mark_rules.is_empty() {
        for (family, internal) in [("ip", "internal_v4"), ("ip6", "internal_v6")] {
            let _ = write!(
                output,
                "    iifname @managed_lan oifname @wan_egress {family} saddr @{internal} {family} daddr != @{internal} meta mark set (meta mark & 0x0000ffff) comment \"netqmon shared upload fallback\"\n    iifname @managed_lan oifname @wan_egress {family} daddr @{internal} {family} saddr != @{internal} meta mark set ((meta mark & 0x0000ffff) | 0x01000000) comment \"netqmon shared download fallback\"\n"
            );
        }
    }
    for rule in &plan.mark_rules {
        output.push_str(&rule.render());
    }
    output.push_str(
        "    icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"netqmon preserves IPv6 neighbor discovery\"\n",
    );
    output.push_str(
        "    iifname @managed_lan oifname @wan_egress ip saddr @blocked_clients_v4 ip daddr != @internal_v4 counter drop comment \"netqmon outbound client Internet block\"\n",
    );
    output.push_str(
        "    iifname @wan_egress oifname @managed_lan ip daddr @blocked_clients_v4 ip saddr != @internal_v4 counter drop comment \"netqmon inbound client Internet block\"\n",
    );
    if topology.ipv6_coverage {
        output.push_str(
            "    iifname @managed_lan oifname @wan_egress ip6 saddr @blocked_clients_v6 ip6 daddr != @internal_v6 ip6 daddr != fe80::/10 counter drop comment \"netqmon outbound IPv6 client Internet block\"\n",
        );
        output.push_str(
            "    iifname @wan_egress oifname @managed_lan ip6 daddr @blocked_clients_v6 ip6 saddr != @internal_v6 ip6 saddr != fe80::/10 counter drop comment \"netqmon inbound IPv6 client Internet block\"\n",
        );
    }
    output.push_str("  }\n");
    // REDIRECT replies originate locally and bypass forward. After reverse
    // source NAT (priority 100), their original Internet source is visible
    // again; preserve real router/LAN services while blocking proxy downloads.
    output.push_str(concat!(
        "  chain postrouting_guard {\n    type filter hook postrouting priority 110; policy accept;\n",
        "    oifname != @managed_lan return\n",
        "    ip daddr != @blocked_clients_v4 return\n",
        "    ip6 daddr != @blocked_clients_v6 return\n",
        "    oifname @managed_lan fib saddr type local return comment \"netqmon preserves router replies\"\n",
        "    oifname @managed_lan ip saddr 169.254.0.0/16 return comment \"netqmon preserves IPv4 link replies\"\n",
        "    oifname @managed_lan ip6 saddr fe80::/10 return comment \"netqmon preserves IPv6 link replies\"\n",
        "    oifname @managed_lan ip daddr @blocked_clients_v4 ip saddr != @internal_v4 counter drop comment \"netqmon post-proxy client Internet block\"\n",
    ));
    if topology.ipv6_coverage {
        output.push_str(
            "    oifname @managed_lan ip6 daddr @blocked_clients_v6 ip6 saddr != @internal_v6 counter drop comment \"netqmon post-proxy IPv6 client Internet block\"\n",
        );
    }
    output.push_str("  }\n}\n");
    output
}

fn set_ifnames(output: &mut String, name: &str, values: &[String]) {
    output.push_str(&format!("  set {name} {{ type ifname;\n"));
    if !values.is_empty() {
        output.push_str("    elements = { ");
        output.push_str(
            &values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str(" }\n");
    }
    output.push_str("  }\n");
}

fn set_networks<'a>(
    output: &mut String,
    name: &str,
    kind: &str,
    values: impl Iterator<Item = &'a str>,
) {
    output.push_str(&format!("  set {name} {{ type {kind}; flags interval;\n"));
    let values = compact_networks(values);
    if !values.is_empty() {
        output.push_str("    elements = { ");
        output.push_str(&values.join(", "));
        output.push_str(" }\n");
    }
    output.push_str("  }\n");
}

fn compact_networks<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut networks = Vec::new();
    let mut invalid = Vec::new();
    for value in values {
        if let Ok(network) = value.parse::<NetworkPrefix>() {
            networks.push(network);
        } else {
            // Preserve malformed input so nft reports the same configuration error as before.
            invalid.push(value.to_owned());
        }
    }
    networks.sort_by_key(|network| {
        (
            network.network.is_ipv6(),
            network.prefix_length,
            network.network,
        )
    });

    let mut compacted = Vec::<NetworkPrefix>::new();
    for network in networks {
        if compacted
            .iter()
            .any(|parent| parent.contains(network.network))
        {
            continue;
        }
        compacted.push(network);
    }
    compacted.sort_by_key(|network| (network.network, network.prefix_length));

    compacted
        .into_iter()
        .map(|network| network.to_string())
        .chain(invalid)
        .collect()
}

fn set_addresses(
    output: &mut String,
    name: &str,
    kind: &str,
    values: impl Iterator<Item = String>,
) {
    output.push_str(&format!("  set {name} {{ type {kind};\n"));
    let values = values.collect::<Vec<_>>();
    if !values.is_empty() {
        output.push_str("    elements = { ");
        output.push_str(&values.join(", "));
        output.push_str(" }\n");
    }
    output.push_str("  }\n");
}

fn run_nft(args: &[&str], input: &[u8]) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start nft: {error}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|error| format!("send nft transaction: {error}"))?;
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let output = child
                    .wait_with_output()
                    .map_err(|error| format!("read nft result: {error}"))?;
                return Err(format!(
                    "nft {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                thread::sleep(Duration::from_millis(25))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "nft {} exceeded the five-second timeout",
                    args.join(" ")
                ));
            }
            Err(error) => return Err(format!("wait for nft: {error}")),
        }
    }
}

fn run_nft_capture(args: &[&str]) -> Result<Vec<u8>, String> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start nft: {error}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| format!("read nft result: {error}"))?;
                if status.success() {
                    return Ok(output.stdout);
                }
                return Err(format!(
                    "nft {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                thread::sleep(Duration::from_millis(25))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "nft {} exceeded the five-second timeout",
                    args.join(" ")
                ));
            }
            Err(error) => return Err(format!("wait for nft: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> PolicyTopology {
        PolicyTopology {
            supported: true,
            reason_code: None,
            reason: None,
            capabilities: netqmon_protocol::policy::PolicyCapabilities::unsupported(),
            client_limit_reason_code: None,
            client_limit_reason: None,
            lan_interfaces: vec!["br-lan".to_owned()],
            wan_interfaces: vec!["eth0".to_owned()],
            lan_ifindex: Some(1),
            wan_ifindex: Some(2),
            lan_capacity_bps: Some(100_000_000),
            wan_capacity_bps: Some(100_000_000),
            internal_networks: vec!["192.168.1.0/24".to_owned(), "fd00::/64".to_owned()],
            neighbor_bindings: Vec::new(),
            ipv6_coverage: true,
        }
    }

    #[test]
    fn generated_table_guards_proxy_paths_and_preserves_local_services() {
        let script = render(
            &topology(),
            &NftPlan {
                blocked_v4: vec!["192.168.1.42".parse().unwrap()],
                blocked_v6: vec!["fd00::42".parse().unwrap()],
                mark_rules: Vec::new(),
            },
            true,
        );
        assert!(script.starts_with("delete table inet netqmon_policy"));
        assert!(script.contains(TABLE_MARKER));
        assert!(script.contains("hook forward priority -5; policy accept"));
        assert!(script.contains("hook prerouting priority -305; policy accept"));
        assert!(script.contains("hook postrouting priority 110; policy accept"));
        assert!(script.contains("fib daddr type local return"));
        assert!(script.contains("fib saddr type local return"));
        assert!(script.contains("ip6 daddr { fe80::/10, ff00::/8 } return"));
        assert!(script.contains("255.255.255.255 } return"));
        assert!(
            script.contains("ip saddr @blocked_clients_v4 ip daddr != @internal_v4 counter drop")
        );
        assert!(
            script.contains("ip daddr @blocked_clients_v4 ip saddr != @internal_v4 counter drop")
        );
        assert!(script.contains("192.168.1.42"));
        assert!(script.contains("fd00::42"));
        assert!(script.contains("nd-neighbor-solicit"));
        assert!(!script.contains("flush ruleset"));
        assert!(!script.contains("hook input"));
    }

    #[test]
    fn incomplete_ipv6_coverage_does_not_install_ipv6_proxy_blocks() {
        let mut topology = topology();
        topology.ipv6_coverage = false;
        let script = render(&topology, &NftPlan::default(), false);
        assert!(!script.contains("ip6 saddr @blocked_clients_v6"));
        assert!(!script.contains("ip6 daddr @blocked_clients_v6"));
        assert!(script.contains("ip6 daddr { fe80::/10, ff00::/8 } return"));
    }

    #[test]
    fn interval_sets_compact_contained_ipv4_and_ipv6_networks() {
        let mut topology = topology();
        topology.internal_networks = vec![
            "192.168.0.0/16".to_owned(),
            "192.168.1.0/24".to_owned(),
            "2001:db8:1::/64".to_owned(),
            "2001:db8:1::1/128".to_owned(),
        ];

        let script = render(&topology, &NftPlan::default(), false);

        assert!(script.contains("elements = { 192.168.0.0/16 }"));
        assert!(script.contains("elements = { 2001:db8:1::/64 }"));
        assert!(!script.contains("192.168.1.0/24"));
        assert!(!script.contains("2001:db8:1::1/128"));
    }

    #[test]
    fn interface_names_are_restricted_before_being_quoted() {
        let mut unsafe_topology = topology();
        unsafe_topology.lan_interfaces = vec!["lan\"; flush ruleset".to_owned()];
        assert!(validate_interfaces(&unsafe_topology).is_err());
    }

    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn applies_agent_owned_policy_from_test_namespace_neighbors() {
        use std::net::IpAddr;

        match std::env::var("NETQMON_POLICY_NETNS_ACTION").as_deref() {
            Ok("clear") => {
                clear_owned().expect("clear the Agent-owned policy table");
                println!("PASS: Agent nft executor removed its owned table");
            }
            Ok("replace") => {
                let neighbor_rows: Vec<(String, String)> = serde_json::from_str(
                    &std::env::var("NETQMON_POLICY_NETNS_NEIGHBORS")
                        .expect("test must provide live namespace neighbors as JSON"),
                )
                .expect("parse test namespace neighbors");
                let neighbors = neighbor_rows
                    .into_iter()
                    .map(|(mac, address)| {
                        (
                            mac,
                            address
                                .parse::<IpAddr>()
                                .expect("neighbor address must be an IP address"),
                        )
                    })
                    .collect::<Vec<_>>();
                let blocked_mac = std::env::var("NETQMON_POLICY_NETNS_BLOCK_MAC")
                    .expect("test must provide the policy client MAC");
                let addresses =
                    super::super::identity::ClientAddresses::from_neighbors(neighbors.clone())
                        .resolve(&blocked_mac)
                        .expect("policy MAC must resolve unambiguously in the router namespace");
                let mut test_topology = topology();
                test_topology.lan_interfaces =
                    vec![std::env::var("NETQMON_POLICY_NETNS_LAN").expect("test LAN interface")];
                test_topology.wan_interfaces =
                    vec![std::env::var("NETQMON_POLICY_NETNS_WAN").expect("test WAN interface")];
                test_topology.internal_networks = vec![
                    std::env::var("NETQMON_POLICY_NETNS_INTERNAL_V4")
                        .expect("test internal IPv4 network"),
                    std::env::var("NETQMON_POLICY_NETNS_INTERNAL_V6")
                        .expect("test internal IPv6 network"),
                ];
                test_topology.neighbor_bindings = neighbors;
                test_topology.ipv6_coverage = true;
                let plan = NftPlan {
                    blocked_v4: addresses
                        .iter()
                        .filter_map(|address| match address {
                            IpAddr::V4(address) => Some(*address),
                            IpAddr::V6(_) => None,
                        })
                        .collect(),
                    blocked_v6: addresses
                        .iter()
                        .filter_map(|address| match address {
                            IpAddr::V4(_) => None,
                            IpAddr::V6(address) => Some(*address),
                        })
                        .collect(),
                    mark_rules: Vec::new(),
                };
                replace(&test_topology, &plan)
                    .expect("apply and verify policy inside the isolated namespace");
                println!(
                    "PASS: Agent nft executor applied policy for {blocked_mac} to {} live address(es)",
                    addresses.len()
                );
            }
            other => panic!("NETQMON_POLICY_NETNS_ACTION must be replace or clear, got {other:?}"),
        }
    }
}
