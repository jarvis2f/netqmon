use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use nix::ifaddrs::getifaddrs;

use super::neighbor;
use crate::config::AgentConfig;
use crate::topology::{
    InterfaceInfo, NatStatus, NetworkPrefix, NetworkSegment, RouteInfo, SegmentRole, SegmentSource,
    TopologyContext, TopologySnapshot,
};

pub(super) fn discover(config: &AgentConfig) -> Result<TopologyContext, String> {
    let interfaces = discover_interfaces()?;
    let mut routes = parse_ipv4_routes(&fs::read_to_string("/proc/net/route").unwrap_or_default());
    routes.extend(parse_ipv6_routes(
        &fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default(),
    ));
    let local_addresses = interfaces
        .iter()
        .flat_map(|interface| interface.addresses.iter().map(|(address, _)| *address))
        .collect::<Vec<_>>();
    let mut neighbors = neighbor::discover_all()
        .unwrap_or_default()
        .into_iter()
        .map(|entry| entry.ip)
        .collect::<Vec<_>>();
    neighbors.sort_unstable();
    neighbors.dedup();
    let gateways = routes
        .iter()
        .filter_map(|route| route.gateway)
        .collect::<Vec<_>>();
    let firewall = fs::read_to_string("/etc/config/firewall").ok();
    let (flow_offloading, flow_offloading_hw) =
        firewall.as_deref().map_or((None, None), parse_offloading);
    let nat = firewall.as_deref().map_or(NatStatus::Unknown, |contents| {
        if contains_enabled_option(contents, "masq") {
            NatStatus::Masquerade
        } else {
            NatStatus::Disabled
        }
    });
    let mut snapshot = TopologySnapshot {
        ipv4_forwarding: read_bool("/proc/sys/net/ipv4/ip_forward").unwrap_or(false),
        ipv6_forwarding: read_bool("/proc/sys/net/ipv6/conf/all/forwarding").unwrap_or(false),
        ipv4_default_route: routes
            .iter()
            .any(|route| route.destination == "0.0.0.0/0".parse().expect("valid prefix")),
        ipv6_default_route: routes
            .iter()
            .any(|route| route.destination == "::/0".parse().expect("valid prefix")),
        icmp_redirects: read_redirects(&config.interface),
        interfaces,
        routes,
        gateways,
        neighbors,
        local_addresses,
        nat,
        flow_offloading,
        flow_offloading_hw,
        ..TopologySnapshot::default()
    };
    snapshot.infer_mode(&config.interface);
    snapshot.segments = infer_segments(config, &snapshot)?;
    snapshot.finish_health();
    Ok(TopologyContext { snapshot })
}

fn discover_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    let mut interfaces = BTreeMap::<String, Vec<(IpAddr, u8)>>::new();
    for entry in getifaddrs().map_err(|error| error.to_string())? {
        let Some(address) = entry.address.and_then(sockaddr_ip) else {
            continue;
        };
        let Some(netmask) = entry.netmask.and_then(sockaddr_ip) else {
            continue;
        };
        let Some(prefix) = prefix_length(netmask) else {
            continue;
        };
        interfaces
            .entry(entry.interface_name)
            .or_default()
            .push((address, prefix));
    }
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                interfaces.entry(name.to_owned()).or_default();
            }
        }
    }
    Ok(interfaces
        .into_iter()
        .map(|(name, addresses)| {
            let sys = Path::new("/sys/class/net").join(&name);
            InterfaceInfo {
                is_bridge: sys.join("bridge").exists(),
                is_tunnel: is_tunnel_name(&name) || sys.join("tun_flags").exists(),
                name,
                addresses,
            }
        })
        .collect())
}

fn infer_segments(
    config: &AgentConfig,
    snapshot: &TopologySnapshot,
) -> Result<Vec<NetworkSegment>, String> {
    let default_interfaces = snapshot
        .routes
        .iter()
        .filter(|route| route.destination.prefix_length == 0)
        .map(|route| route.interface.as_str())
        .collect::<Vec<_>>();
    let mut segments = Vec::new();
    for interface in &snapshot.interfaces {
        for (address, prefix) in &interface.addresses {
            if address.is_loopback() || address.is_unspecified() || is_link_local(*address) {
                continue;
            }
            let role = if interface.is_tunnel {
                SegmentRole::Tunnel
            } else if config.interfaces.iter().any(|name| name == &interface.name) {
                SegmentRole::Lan
            } else if default_interfaces.contains(&interface.name.as_str()) {
                SegmentRole::Wan
            } else {
                SegmentRole::Unknown
            };
            upsert_segment(
                &mut segments,
                NetworkSegment {
                    subnet: NetworkPrefix::new(*address, *prefix)
                        .map_err(|error| error.to_string())?,
                    interface: Some(interface.name.clone()),
                    role,
                    source: SegmentSource::InterfaceAddress,
                    confidence: 70,
                },
            );
        }
    }
    for route in &snapshot.routes {
        if route.destination.prefix_length == 0
            || route.destination.network.is_loopback()
            || route.destination.network.is_multicast()
            || is_link_local(route.destination.network)
        {
            continue;
        }
        let interface = snapshot
            .interfaces
            .iter()
            .find(|interface| interface.name == route.interface);
        let role = if interface.is_some_and(|interface| interface.is_tunnel) {
            SegmentRole::Tunnel
        } else if config
            .interfaces
            .iter()
            .any(|name| name == &route.interface)
            && route.gateway.is_none()
        {
            SegmentRole::Lan
        } else if route.gateway.is_some() {
            SegmentRole::RoutedLan
        } else {
            SegmentRole::Unknown
        };
        upsert_segment(
            &mut segments,
            NetworkSegment {
                subnet: route.destination,
                interface: Some(route.interface.clone()),
                role,
                source: SegmentSource::KernelRoute,
                confidence: 85,
            },
        );
    }
    if let Ok(openwrt) = fs::read_to_string("/etc/config/network") {
        for segment in parse_openwrt_networks(&openwrt) {
            upsert_segment(&mut segments, segment);
        }
    }
    for configured in &config.topology_networks {
        upsert_segment(
            &mut segments,
            NetworkSegment {
                subnet: configured.subnet.parse()?,
                interface: configured.interface.clone(),
                role: configured.role.parse()?,
                source: SegmentSource::Config,
                confidence: 100,
            },
        );
    }
    Ok(segments)
}

fn parse_openwrt_networks(contents: &str) -> Vec<NetworkSegment> {
    #[derive(Default)]
    struct Section {
        name: String,
        device: Option<String>,
        address: Option<String>,
        netmask: Option<String>,
        protocol: Option<String>,
    }
    fn finish(section: &Section, output: &mut Vec<NetworkSegment>) {
        let Some(address) = section.address.as_deref() else {
            return;
        };
        let prefix = if address.contains('/') {
            address.parse().ok()
        } else {
            address
                .parse::<IpAddr>()
                .ok()
                .zip(
                    section
                        .netmask
                        .as_deref()
                        .and_then(|mask| mask.parse().ok())
                        .and_then(prefix_length),
                )
                .and_then(|(address, length)| NetworkPrefix::new(address, length).ok())
        };
        let Some(subnet) = prefix else { return };
        let role = if section.name.contains("wan") {
            SegmentRole::Wan
        } else if section.protocol.as_deref() == Some("wireguard")
            || section.device.as_deref().is_some_and(is_tunnel_name)
        {
            SegmentRole::Tunnel
        } else if section.name.contains("lan") {
            SegmentRole::Lan
        } else {
            SegmentRole::Unknown
        };
        output.push(NetworkSegment {
            subnet,
            interface: section.device.clone(),
            role,
            source: SegmentSource::OpenWrt,
            confidence: 90,
        });
    }
    let mut output = Vec::new();
    let mut section = Section::default();
    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"config") && fields.get(1) == Some(&"interface") {
            finish(&section, &mut output);
            section = Section {
                name: fields.get(2).map_or(String::new(), |value| {
                    value.trim_matches(['\'', '"']).to_owned()
                }),
                ..Section::default()
            };
        } else if fields.first() == Some(&"option") && fields.len() >= 3 {
            let value = fields[2].trim_matches(['\'', '"']).to_owned();
            match fields[1] {
                "device" | "ifname" => section.device = Some(value),
                "ipaddr" | "ip6addr" => section.address = Some(value),
                "netmask" => section.netmask = Some(value),
                "proto" => section.protocol = Some(value),
                _ => {}
            }
        }
    }
    finish(&section, &mut output);
    output
}

fn upsert_segment(segments: &mut Vec<NetworkSegment>, candidate: NetworkSegment) {
    if let Some(existing) = segments
        .iter_mut()
        .find(|segment| segment.subnet == candidate.subnet)
    {
        if candidate.source >= existing.source {
            *existing = candidate;
        }
    } else {
        segments.push(candidate);
    }
}

fn parse_ipv4_routes(contents: &str) -> Vec<RouteInfo> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 {
                return None;
            }
            let destination = ipv4_from_proc_hex(fields[1])?;
            let gateway = ipv4_from_proc_hex(fields[2]).filter(|address| !address.is_unspecified());
            let mask = ipv4_from_proc_hex(fields[7])?;
            let prefix = prefix_length(IpAddr::V4(mask))?;
            Some(RouteInfo {
                destination: NetworkPrefix::new(IpAddr::V4(destination), prefix).ok()?,
                gateway: gateway.map(IpAddr::V4),
                interface: fields[0].to_owned(),
            })
        })
        .collect()
}

fn parse_ipv6_routes(contents: &str) -> Vec<RouteInfo> {
    contents
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10 {
                return None;
            }
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            if fields[9] == "lo" || flags & 0x200 != 0 {
                return None;
            }
            let destination = ipv6_from_hex(fields[0])?;
            let prefix = u8::from_str_radix(fields[1], 16).ok()?;
            let gateway = ipv6_from_hex(fields[4]).filter(|address| !address.is_unspecified());
            Some(RouteInfo {
                destination: NetworkPrefix::new(IpAddr::V6(destination), prefix).ok()?,
                gateway: gateway.map(IpAddr::V6),
                interface: fields[9].to_owned(),
            })
        })
        .collect()
}

fn ipv4_from_proc_hex(value: &str) -> Option<Ipv4Addr> {
    let bytes = u32::from_str_radix(value, 16).ok()?.to_le_bytes();
    Some(Ipv4Addr::from(bytes))
}

fn ipv6_from_hex(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

fn sockaddr_ip(address: nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
    if let Some(address) = address.as_sockaddr_in() {
        Some(IpAddr::V4(address.ip()))
    } else {
        address
            .as_sockaddr_in6()
            .map(|address| IpAddr::V6(address.ip()))
    }
}

fn prefix_length(netmask: IpAddr) -> Option<u8> {
    let (mask, bits) = match netmask {
        IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
        IpAddr::V6(address) => (u128::from(address), 128),
    };
    let prefix = u8::try_from(mask.count_ones()).ok()?;
    let expected = if prefix == 0 {
        0
    } else if prefix == 128 {
        u128::MAX
    } else {
        ((1_u128 << prefix) - 1) << (bits - prefix)
    };
    (mask == expected).then_some(prefix)
}

fn read_bool(path: &str) -> Option<bool> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim() == "1")
}

fn read_redirects(interface: &str) -> Option<bool> {
    [
        format!("/proc/sys/net/ipv4/conf/{interface}/send_redirects"),
        "/proc/sys/net/ipv4/conf/all/send_redirects".into(),
    ]
    .into_iter()
    .find_map(|path| read_bool(&path))
}

fn parse_offloading(contents: &str) -> (Option<bool>, Option<bool>) {
    (
        option_value(contents, "flow_offloading"),
        option_value(contents, "flow_offloading_hw"),
    )
}

fn contains_enabled_option(contents: &str, name: &str) -> bool {
    option_value(contents, name) == Some(true)
}

fn option_value(contents: &str, name: &str) -> Option<bool> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 3 && fields[0] == "option" && fields[1] == name).then(|| {
                matches!(
                    fields[2]
                        .trim_matches(['\'', '"'])
                        .to_ascii_lowercase()
                        .as_str(),
                    "1" | "on" | "true" | "yes" | "enabled"
                )
            })
        })
}

fn is_tunnel_name(name: &str) -> bool {
    [
        "tun",
        "tap",
        "wg",
        "gre",
        "sit",
        "ip6tnl",
        "vxlan",
        "tailscale",
        "zt",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_default_and_routed_subnets() {
        let v4 = parse_ipv4_routes(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nbr-lan 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0\nbr-lan 000AA8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0",
        );
        assert_eq!(v4[0].gateway, Some("192.168.2.1".parse().unwrap()));
        assert_eq!(v4[1].destination.to_string(), "192.168.10.0/24");
        let v6 = parse_ipv6_routes(
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000000 00000000 00000000 00000001 eth0",
        );
        assert_eq!(v6[0].destination.to_string(), "::/0");
    }

    #[test]
    fn recognizes_both_openwrt_offload_switches() {
        assert_eq!(
            parse_offloading("option flow_offloading '1'\noption flow_offloading_hw '0'"),
            (Some(true), Some(false))
        );
    }

    #[test]
    fn parses_openwrt_lan_and_tunnel_networks() {
        let networks = parse_openwrt_networks(
            "config interface 'lan'\n option device 'br-lan'\n option ipaddr '192.168.2.8'\n option netmask '255.255.255.0'\nconfig interface 'vpn'\n option proto 'wireguard'\n option ipaddr '10.10.10.1/24'",
        );
        assert_eq!(networks[0].role, SegmentRole::Lan);
        assert_eq!(networks[1].role, SegmentRole::Tunnel);
        assert!(
            networks
                .iter()
                .all(|network| network.source == SegmentSource::OpenWrt)
        );
    }
}
