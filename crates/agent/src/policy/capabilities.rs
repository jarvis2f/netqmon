#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::process::Command;

use netqmon_protocol::policy::{PolicyCapabilities, PolicyCapability};

use crate::config::AgentConfig;
#[cfg(target_os = "linux")]
use crate::topology::{SegmentRole, TopologyMode};

#[cfg(target_os = "linux")]
const MAX_POLICY_NEIGHBOR_BINDINGS: usize = 32_768;

#[derive(Clone, Debug)]
pub(crate) struct PolicyTopology {
    pub supported: bool,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub capabilities: PolicyCapabilities,
    pub client_limit_reason_code: Option<String>,
    pub client_limit_reason: Option<String>,
    pub lan_interfaces: Vec<String>,
    pub wan_interfaces: Vec<String>,
    /// A verified common packet queue, distinct from the routed WAN interfaces.
    pub wan_shaping_interface: Option<String>,
    pub lan_ifindex: Option<u32>,
    pub wan_ifindex: Option<u32>,
    pub lan_capacity_bps: Option<u64>,
    pub wan_capacity_bps: Option<u64>,
    pub internal_networks: Vec<String>,
    pub neighbor_bindings: Vec<(String, std::net::IpAddr)>,
    pub ipv6_coverage: bool,
}

impl PolicyTopology {
    pub(crate) fn shaping_wan(&self) -> Option<&str> {
        self.wan_shaping_interface
            .as_deref()
            .or_else(|| (self.wan_interfaces.len() == 1).then(|| self.wan_interfaces[0].as_str()))
    }

    pub(crate) fn is_one_arm_router(&self) -> bool {
        self.supported
            && self.lan_interfaces.len() == 1
            && self.wan_interfaces.len() == 1
            && self.lan_interfaces[0] == self.wan_interfaces[0]
    }

    pub(crate) fn unsupported(reason_code: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            supported: false,
            reason_code: Some(reason_code.to_owned()),
            reason: Some(reason.clone()),
            capabilities: PolicyCapabilities::unsupported(),
            client_limit_reason_code: Some(reason_code.to_owned()),
            client_limit_reason: Some(reason),
            lan_interfaces: Vec::new(),
            wan_interfaces: Vec::new(),
            wan_shaping_interface: None,
            lan_ifindex: None,
            wan_ifindex: None,
            lan_capacity_bps: None,
            wan_capacity_bps: None,
            internal_networks: Vec::new(),
            neighbor_bindings: Vec::new(),
            ipv6_coverage: false,
        }
    }
}

pub(crate) fn inspect(config: &AgentConfig) -> PolicyTopology {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        return PolicyTopology::unsupported(
            "unsupported_platform",
            "policy packet enforcement is only available on Linux",
        );
    }

    #[cfg(target_os = "linux")]
    {
        let topology = match crate::linux::network::discover(config) {
            Ok(context) => context,
            Err(error) => {
                return PolicyTopology::unsupported(
                    "topology_unavailable",
                    format!("could not inspect local routes and interfaces: {error}"),
                );
            }
        };
        let snapshot = &topology.snapshot;
        let one_arm_router = snapshot.mode == TopologyMode::OneArmRouter;
        if !matches!(
            snapshot.mode,
            TopologyMode::Router | TopologyMode::OneArmRouter
        ) {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                format!(
                    "client Internet blocking requires Router or verified One-arm Router topology; found {}",
                    snapshot.mode
                ),
            );
        }
        if !snapshot.ipv4_forwarding || !snapshot.ipv4_default_route {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "IPv4 forwarding and a default WAN route are both required",
            );
        }
        if let Some((reason_code, reason)) =
            offload_reason(snapshot.flow_offloading, snapshot.flow_offloading_hw)
        {
            return PolicyTopology::unsupported(reason_code, reason);
        }
        let lan_interfaces = snapshot
            .segments
            .iter()
            .filter(|segment| segment.role == SegmentRole::Lan)
            .filter_map(|segment| segment.interface.clone())
            .collect::<BTreeSet<_>>();
        let wan_interfaces = snapshot
            .routes
            .iter()
            .filter(|route| route.destination.prefix_length == 0)
            .map(|route| route.interface.clone())
            .collect::<BTreeSet<_>>();
        if lan_interfaces.is_empty() || wan_interfaces.is_empty() {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "could not identify both managed LAN ingress and WAN egress interfaces",
            );
        }
        if one_arm_router {
            let capture_interface = config.interface.as_str();
            let expected_lan_wan = lan_interfaces.len() == 1
                && lan_interfaces.contains(capture_interface)
                && wan_interfaces.len() == 1
                && wan_interfaces.contains(capture_interface);
            let default_gateway_on_capture_lan = snapshot.routes.iter().any(|route| {
                route.destination.prefix_length == 0
                    && route.interface == capture_interface
                    && route.gateway.is_some_and(|gateway| {
                        snapshot.segments.iter().any(|segment| {
                            segment.role == SegmentRole::Lan
                                && segment.interface.as_deref() == Some(capture_interface)
                                && segment.subnet.contains(gateway)
                        })
                    })
            });
            if !expected_lan_wan || !default_gateway_on_capture_lan {
                return PolicyTopology::unsupported(
                    "unsupported_topology",
                    "One-arm Router blocking requires the capture interface to be both the verified LAN and default-route interface, with its gateway inside the LAN prefix",
                );
            }
        } else if lan_interfaces
            .iter()
            .any(|interface| wan_interfaces.contains(interface))
        {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "LAN and default-route WAN interfaces overlap",
            );
        }
        let internal_networks = snapshot
            .segments
            .iter()
            .filter(|segment| {
                matches!(
                    segment.role,
                    SegmentRole::Lan | SegmentRole::RoutedLan | SegmentRole::Tunnel
                )
            })
            .map(|segment| segment.subnet.to_string())
            .collect::<BTreeSet<_>>();
        if internal_networks.is_empty() {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "no verified LAN, routed-LAN, or tunnel destination networks are known",
            );
        }
        let v6_default = snapshot.ipv6_default_route;
        let has_internal_v4 = internal_networks.iter().any(|value| value.contains('.'));
        let has_internal_v6 = internal_networks.iter().any(|value| value.contains(':'));
        if v6_default && (!snapshot.ipv6_forwarding || !has_internal_v6) {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "IPv6 default routing exists but verified IPv6 forwarding and LAN prefixes are incomplete",
            );
        }
        if !has_internal_v4 {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "no verified IPv4 LAN destination network is known",
            );
        }
        let lan_ifindices = lan_interfaces
            .iter()
            .filter_map(|interface| {
                nix::net::if_::if_nametoindex(interface.as_str())
                    .ok()
                    .map(|index| (interface, index))
            })
            .collect::<BTreeSet<_>>();
        if lan_ifindices.is_empty() {
            return PolicyTopology::unsupported(
                "unsupported_topology",
                "managed LAN interface indexes could not be resolved",
            );
        }
        let neighbor_bindings = crate::linux::neighbor::discover_all()
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| {
                lan_ifindices.iter().any(|(interface, ifindex)| {
                    *ifindex == entry.ifindex
                        && snapshot.segments.iter().any(|segment| {
                            segment.role == SegmentRole::Lan
                                && segment.interface.as_deref() == Some(interface.as_str())
                                && segment.subnet.contains(entry.ip)
                        })
                })
            })
            .map(|entry| (entry.mac.to_string(), entry.ip))
            .collect::<Vec<_>>();
        if neighbor_bindings.len() > MAX_POLICY_NEIGHBOR_BINDINGS {
            return PolicyTopology::unsupported(
                "identity_limit_exceeded",
                "current LAN neighbor bindings exceed the safe policy-resolution limit",
            );
        }
        let nft = Command::new("nft").arg("--version").output();
        if nft.is_err() || !nft.is_ok_and(|output| output.status.success()) {
            return PolicyTopology::unsupported(
                "nft_unavailable",
                "the nft command is missing or did not run successfully",
            );
        }
        match nft_ruleset_has_flowtable() {
            Ok(false) => {}
            Ok(true) => {
                return PolicyTopology::unsupported(
                    "unsupported_offload",
                    "an nftables flowtable is configured and may bypass policy enforcement",
                );
            }
            Err(_) => {
                return PolicyTopology::unsupported(
                    "offload_unknown",
                    "could not verify whether nftables flow offload is configured",
                );
            }
        }

        let mut report = PolicyTopology {
            supported: true,
            reason_code: None,
            reason: None,
            capabilities: PolicyCapabilities {
                client_block: client_block_capability(one_arm_router, v6_default),
                client_limit: PolicyCapability::Unsupported,
                application_block: PolicyCapability::Unsupported,
                application_limit: PolicyCapability::Unsupported,
            },
            client_limit_reason_code: None,
            client_limit_reason: None,
            lan_interfaces: lan_interfaces.into_iter().collect(),
            wan_interfaces: wan_interfaces.into_iter().collect(),
            wan_shaping_interface: None,
            lan_ifindex: None,
            wan_ifindex: None,
            lan_capacity_bps: None,
            wan_capacity_bps: None,
            internal_networks: internal_networks.into_iter().collect(),
            neighbor_bindings,
            ipv6_coverage: v6_default,
        };
        if report.lan_interfaces.len() == 1 {
            let interface = &report.lan_interfaces[0];
            report.lan_ifindex = nix::net::if_::if_nametoindex(interface.as_str())
                .ok()
                .filter(|index| *index > 0);
            report.lan_capacity_bps = super::capacity::effective(
                interface,
                config.policy_interface_capacity_bps.get(interface).copied(),
            )
            .ok()
            .map(|capacity| capacity.bps);
        }
        if !one_arm_router {
            report.wan_shaping_interface = super::egress::common_egress(&report.wan_interfaces);
        }
        if let Some(interface) = report.shaping_wan().map(str::to_owned) {
            report.wan_ifindex = nix::net::if_::if_nametoindex(interface.as_str())
                .ok()
                .filter(|index| *index > 0);
            report.wan_capacity_bps = super::capacity::effective(
                &interface,
                config
                    .policy_interface_capacity_bps
                    .get(&interface)
                    .copied(),
            )
            .ok()
            .map(|capacity| capacity.bps);
        }
        if one_arm_router {
            let (reason_code, reason) = one_arm_client_block_reason(
                snapshot.icmp_redirects,
                config.policy_one_arm_return_path_verified,
            );
            report.reason_code = Some(reason_code.to_owned());
            report.reason = Some(reason.to_owned());
        } else if !v6_default {
            report.reason_code = Some("ipv6_unavailable".to_owned());
            report.reason = Some(
                "IPv6 has no default route; enforcement covers IPv4 Internet traffic only"
                    .to_owned(),
            );
        }
        if one_arm_router {
            if let Some((code, reason)) = one_arm_shaping_reason(
                config.policy_one_arm_return_path_verified,
                snapshot.icmp_redirects,
            ) {
                report.client_limit_reason_code = Some(code.to_owned());
                report.client_limit_reason = Some(reason.to_owned());
                return report;
            }
            if v6_default
                && !snapshot.routes.iter().any(|route| {
                    route.destination.prefix_length == 0
                        && route.destination.network.is_ipv6()
                        && route.interface == config.interface
                        && route.gateway.is_some_and(|gateway| {
                            snapshot.segments.iter().any(|segment| {
                                segment.role == SegmentRole::Lan
                                    && segment.interface.as_deref()
                                        == Some(config.interface.as_str())
                                    && segment.subnet.contains(gateway)
                            })
                        })
                })
            {
                report.client_limit_reason_code = Some("one_arm_ipv6_path_unverified".to_owned());
                report.client_limit_reason =
                    Some("the IPv6 default gateway must be on the shared LAN interface".to_owned());
                return report;
            }
        }
        let mut shaping = super::qdisc::inspect_capability(&report);
        if shaping.supported {
            shaping = super::qdisc::inspect_ownership(&report, &config.policy_state_path);
        }
        report.capabilities.client_limit = if shaping.supported {
            if report.ipv6_coverage {
                PolicyCapability::Supported
            } else {
                PolicyCapability::Degraded
            }
        } else {
            report.client_limit_reason_code = shaping.reason_code;
            report.client_limit_reason = shaping.reason;
            PolicyCapability::Unsupported
        };
        report
    }
}

#[cfg(target_os = "linux")]
fn one_arm_shaping_reason(
    verified: bool,
    redirects: Option<bool>,
) -> Option<(&'static str, &'static str)> {
    if !verified {
        Some((
            "one_arm_return_path_unverified",
            "confirm symmetric return routing for all enabled address families using policy_one_arm_return_path_verified",
        ))
    } else if redirects != Some(false) {
        Some((
            "one_arm_redirects_unsafe",
            "ICMP redirects must be confirmed disabled for shared-egress shaping",
        ))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn client_block_capability(one_arm_router: bool, ipv6_coverage: bool) -> PolicyCapability {
    if one_arm_router || !ipv6_coverage {
        PolicyCapability::Degraded
    } else {
        PolicyCapability::Supported
    }
}

#[cfg(target_os = "linux")]
fn one_arm_client_block_reason(
    icmp_redirects: Option<bool>,
    return_path_verified: bool,
) -> (&'static str, &'static str) {
    match icmp_redirects {
        Some(true) => (
            "one_arm_icmp_redirects_enabled",
            "One-arm forwarding is active and ICMP redirects are enabled; clients may learn the upstream gateway and bypass this policy",
        ),
        None => (
            "one_arm_icmp_redirects_unknown",
            "One-arm forwarding is active and ICMP redirect state is unknown; clients may bypass this policy",
        ),
        Some(false) if return_path_verified => (
            "one_arm_client_block_degraded",
            "One-arm client blocking covers observed forwarding; the declared external return routing cannot be independently verified locally",
        ),
        Some(false) => (
            "one_arm_return_path_unverified",
            "One-arm forwarding is active and ICMP redirects are disabled, but the upstream return path is not verified; clients may bypass this policy",
        ),
    }
}

#[cfg(target_os = "linux")]
fn offload_reason(
    software: Option<bool>,
    hardware: Option<bool>,
) -> Option<(&'static str, &'static str)> {
    if software == Some(true) || hardware == Some(true) {
        Some((
            "unsupported_offload",
            "software or hardware flow offloading is enabled and may bypass nftables policy enforcement",
        ))
    } else if software != Some(false) || hardware != Some(false) {
        Some((
            "offload_unknown",
            "software and hardware flow offloading must both be confirmed disabled before policy enforcement",
        ))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn nft_ruleset_has_flowtable() -> Result<bool, String> {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let ruleset = String::from_utf8_lossy(&output.stdout);
    Ok(ruleset
        .lines()
        .any(|line| line.trim_start().starts_with("flowtable ")))
}

pub(crate) fn report_text(config: &AgentConfig) -> String {
    let report = inspect(config);
    let default_topology_reason = if report.is_one_arm_router() {
        "verified One-arm Router path; LAN and WAN share the capture interface"
    } else {
        "verified Linux Router path; no flowtable offload detected"
    };
    format!(
        "Client policy block: {}\nClient aggregate limit: {}\nTopology reason: {}\nLimit reason: {}\nLAN interfaces: {}\nWAN interfaces: {}\nIPv4/IPv6 coverage: {}/{}\n",
        match report.capabilities.client_block {
            PolicyCapability::Supported => "supported",
            PolicyCapability::Degraded => "degraded",
            PolicyCapability::Unsupported => "unsupported",
        },
        match report.capabilities.client_limit {
            PolicyCapability::Supported => "supported",
            PolicyCapability::Degraded => "degraded",
            PolicyCapability::Unsupported => "unsupported",
        },
        report.reason.as_deref().unwrap_or(default_topology_reason),
        report.client_limit_reason.as_deref().unwrap_or("none"),
        if report.lan_interfaces.is_empty() {
            "none".to_owned()
        } else {
            report.lan_interfaces.join(",")
        },
        if report.wan_interfaces.is_empty() {
            "none".to_owned()
        } else {
            report.wan_interfaces.join(",")
        },
        report.supported,
        report.ipv6_coverage,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn shared_shaping_requires_explicit_return_path_and_disabled_redirects() {
        assert_eq!(
            super::one_arm_shaping_reason(false, Some(false)).unwrap().0,
            "one_arm_return_path_unverified"
        );
        assert_eq!(
            super::one_arm_shaping_reason(true, None).unwrap().0,
            "one_arm_redirects_unsafe"
        );
        assert!(super::one_arm_shaping_reason(true, Some(true)).is_some());
        assert!(super::one_arm_shaping_reason(true, Some(false)).is_none());
    }
    #[cfg(target_os = "linux")]
    use super::{client_block_capability, offload_reason, one_arm_client_block_reason};
    #[cfg(target_os = "linux")]
    use netqmon_protocol::policy::PolicyCapability;

    #[test]
    fn internal_prefix_type_is_usable_for_both_families() {
        #[cfg(target_os = "linux")]
        {
            use crate::topology::NetworkPrefix;
            let v4: NetworkPrefix = "192.0.2.0/24".parse().unwrap();
            let v6: NetworkPrefix = "2001:db8::/64".parse().unwrap();
            assert_ne!(v4.to_string(), v6.to_string());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_or_enabled_flow_offload_is_not_policy_capable() {
        assert_eq!(
            offload_reason(None, Some(false)).unwrap().0,
            "offload_unknown"
        );
        assert_eq!(
            offload_reason(Some(true), Some(false)).unwrap().0,
            "unsupported_offload"
        );
        assert!(offload_reason(Some(false), Some(false)).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disabled_redirects_do_not_claim_complete_one_arm_client_block_coverage() {
        let (reason_code, reason) = one_arm_client_block_reason(Some(false), false);

        assert_eq!(
            client_block_capability(true, true),
            PolicyCapability::Degraded
        );
        assert_eq!(reason_code, "one_arm_return_path_unverified");
        assert!(reason.contains("upstream return path is not verified"));
        assert_eq!(
            one_arm_client_block_reason(Some(false), true).0,
            "one_arm_client_block_degraded"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_arm_redirect_risks_keep_specific_reasons() {
        assert_eq!(
            one_arm_client_block_reason(Some(true), true).0,
            "one_arm_icmp_redirects_enabled"
        );
        assert_eq!(
            one_arm_client_block_reason(None, true).0,
            "one_arm_icmp_redirects_unknown"
        );
        assert_eq!(
            client_block_capability(false, true),
            PolicyCapability::Supported
        );
        assert_eq!(
            client_block_capability(false, false),
            PolicyCapability::Degraded
        );
    }
}
