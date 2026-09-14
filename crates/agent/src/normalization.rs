use std::fmt;
use std::net::IpAddr;

use crate::conntrack::{ConntrackContext, ConntrackEntry};
use crate::flow::FlowKey;
use crate::topology::{NetworkPrefix, SegmentRole, TopologyContext};

pub type NetworkContext = TopologyContext;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
    Internal,
    Unknown,
}

impl fmt::Display for Direction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowScope {
    Client,
    RouterLocal,
    Internal,
    Tunnel,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathType {
    Forwarded,
    RouterLocal,
    Internal,
    Tunnel,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatInfo {
    pub source_nat: bool,
    pub destination_nat: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedFlow {
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub source_segment: Option<NetworkPrefix>,
    pub destination_segment: Option<NetworkPrefix>,
    pub direction: Direction,
    pub scope: FlowScope,
    pub path_type: PathType,
    pub nat: NatInfo,
}

#[allow(clippy::too_many_lines)]
pub fn normalize(
    key: &FlowKey,
    topology: &TopologyContext,
    conntrack: &ConntrackContext,
) -> Option<NormalizedFlow> {
    normalize_with_resolution(key, topology, conntrack).map(|(flow, _)| flow)
}

#[allow(clippy::too_many_lines)]
pub fn normalize_with_resolution(
    key: &FlowKey,
    topology: &TopologyContext,
    conntrack: &ConntrackContext,
) -> Option<(NormalizedFlow, bool)> {
    let (captured_source, captured_destination) = key.addresses()?;
    let tracked = conntrack.resolve(key);
    let resolved = tracked.is_some();
    let (source, source_port, destination, destination_port) = tracked.map_or(
        (
            captured_source,
            key.source_port,
            captured_destination,
            key.destination_port,
        ),
        |entry| original_orientation(key, entry),
    );
    let source_segment = topology.segment(source);
    let destination_segment = topology.segment(destination);
    let source_local = topology.is_local(source);
    let destination_local = topology.is_local(destination);
    let source_internal = source_segment.is_some_and(|segment| segment.role.is_internal());
    let destination_internal =
        destination_segment.is_some_and(|segment| segment.role.is_internal());
    let source_tunnel = source_segment.is_some_and(|segment| segment.role == SegmentRole::Tunnel);
    let destination_tunnel =
        destination_segment.is_some_and(|segment| segment.role == SegmentRole::Tunnel);
    let nat = tracked.map_or(NatInfo::default(), |entry| NatInfo {
        source_nat: entry.source_nat,
        destination_nat: entry.destination_nat,
    });

    let (client_addr, client_port, remote_addr, remote_port, direction, scope, path_type) =
        if source_local && !destination_local {
            (
                source,
                source_port,
                destination,
                destination_port,
                Direction::Upload,
                FlowScope::RouterLocal,
                PathType::RouterLocal,
            )
        } else if destination_local && !source_local {
            (
                destination,
                destination_port,
                source,
                source_port,
                Direction::Download,
                FlowScope::RouterLocal,
                PathType::RouterLocal,
            )
        } else if source_tunnel || destination_tunnel {
            let upload = source_tunnel;
            if upload {
                (
                    source,
                    source_port,
                    destination,
                    destination_port,
                    Direction::Upload,
                    FlowScope::Tunnel,
                    PathType::Tunnel,
                )
            } else {
                (
                    destination,
                    destination_port,
                    source,
                    source_port,
                    Direction::Download,
                    FlowScope::Tunnel,
                    PathType::Tunnel,
                )
            }
        } else if source_internal && destination_internal {
            (
                source,
                source_port,
                destination,
                destination_port,
                Direction::Internal,
                FlowScope::Internal,
                PathType::Internal,
            )
        } else if source_internal {
            (
                source,
                source_port,
                destination,
                destination_port,
                Direction::Upload,
                FlowScope::Client,
                PathType::Forwarded,
            )
        } else if destination_internal {
            (
                destination,
                destination_port,
                source,
                source_port,
                Direction::Download,
                FlowScope::Client,
                PathType::Forwarded,
            )
        } else {
            (
                source,
                source_port,
                destination,
                destination_port,
                Direction::Unknown,
                FlowScope::Unknown,
                PathType::Unknown,
            )
        };

    Some((
        NormalizedFlow {
            client_addr,
            client_port,
            remote_addr,
            remote_port,
            source_segment: source_segment.map(|segment| segment.subnet),
            destination_segment: destination_segment.map(|segment| segment.subnet),
            direction,
            scope,
            path_type,
            nat,
        },
        resolved,
    ))
}

fn original_orientation(key: &FlowKey, entry: ConntrackEntry) -> (IpAddr, u16, IpAddr, u16) {
    let Some((captured_source, captured_destination)) = key.addresses() else {
        return (
            entry.original.source,
            entry.original.source_port,
            entry.original.destination,
            entry.original.destination_port,
        );
    };
    let captured_is_reply =
        captured_source == entry.reply.source || captured_destination == entry.reply.destination;
    if captured_is_reply {
        (
            entry.original.destination,
            entry.original.destination_port,
            entry.original.source,
            entry.original.source_port,
        )
    } else {
        (
            entry.original.source,
            entry.original.source_port,
            entry.original.destination,
            entry.original.destination_port,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{NetworkSegment, SegmentSource};

    #[test]
    fn standard_router_and_multi_segment_flows_do_not_depend_on_interface_direction() {
        let topology = topology();
        let upload = normalize(
            &key("192.168.2.20", 50_000, "1.1.1.1", 443),
            &topology,
            &ConntrackContext::default(),
        )
        .unwrap();
        let download = normalize(
            &key("1.1.1.1", 443, "192.168.10.20", 50_000),
            &topology,
            &ConntrackContext::default(),
        )
        .unwrap();
        assert_eq!(upload.direction, Direction::Upload);
        assert_eq!(download.direction, Direction::Download);
        assert_eq!(
            download.client_addr,
            "192.168.10.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn nat_uses_conntrack_original_client_and_router_local_is_separate() {
        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.100 dst=1.1.1.1 sport=50000 dport=443 src=1.1.1.1 dst=192.168.2.8 sport=443 dport=50000",
        );
        let flow = normalize(
            &key("192.168.2.8", 50_000, "1.1.1.1", 443),
            &topology(),
            &conntrack,
        )
        .unwrap();
        assert_eq!(flow.client_addr, "192.168.2.100".parse::<IpAddr>().unwrap());
        assert_eq!(flow.scope, FlowScope::Client);
        assert!(flow.nat.source_nat);

        let local = normalize(
            &key("192.168.2.8", 12345, "1.1.1.1", 443),
            &topology(),
            &ConntrackContext::default(),
        )
        .unwrap();
        assert_eq!(local.scope, FlowScope::RouterLocal);
    }

    #[test]
    fn redirect_reply_restores_original_client_and_destination() {
        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.100 dst=8.8.8.8 sport=50000 dport=443 src=192.168.2.8 dst=192.168.2.100 sport=7890 dport=50000",
        );
        let flow = normalize(
            &key("192.168.2.8", 7_890, "192.168.2.100", 50_000),
            &topology(),
            &conntrack,
        )
        .unwrap();
        assert_eq!(flow.client_addr, "192.168.2.100".parse::<IpAddr>().unwrap());
        assert_eq!(flow.remote_addr, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(flow.remote_port, 443);
        assert_eq!(flow.direction, Direction::Download);
        assert_eq!(flow.scope, FlowScope::Client);
        assert!(flow.nat.destination_nat);
    }

    #[test]
    fn ipv6_udp_redirect_reply_restores_original_tuple() {
        let conntrack = ConntrackContext::parse(
            "ipv6 2 udp 17 29 src=fd00::100 dst=2001:4860:4860::8888 sport=53000 dport=443 src=fd00::1 dst=fd00::100 sport=7891 dport=53000",
        );
        let flow = normalize(
            &ip_key("fd00::1", 7_891, "fd00::100", 53_000, 17),
            &topology(),
            &conntrack,
        )
        .unwrap();
        assert_eq!(flow.client_addr, "fd00::100".parse::<IpAddr>().unwrap());
        assert_eq!(
            flow.remote_addr,
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
        assert_eq!(flow.remote_port, 443);
        assert_eq!(flow.direction, Direction::Download);
        assert_eq!(flow.scope, FlowScope::Client);
        assert!(flow.nat.destination_nat);
    }

    #[test]
    fn tproxy_preserved_tuple_needs_no_proxy_specific_metadata() {
        let flow = normalize(
            &key("8.8.8.8", 443, "192.168.2.100", 50_000),
            &topology(),
            &ConntrackContext::default(),
        )
        .unwrap();
        assert_eq!(flow.client_addr, "192.168.2.100".parse::<IpAddr>().unwrap());
        assert_eq!(flow.remote_addr, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(flow.direction, Direction::Download);
        assert_eq!(flow.scope, FlowScope::Client);
    }

    #[test]
    fn tunnel_and_internal_paths_are_explicit() {
        let topology = topology();
        let tunnel = normalize(
            &key("10.10.10.5", 1, "1.1.1.1", 2),
            &topology,
            &ConntrackContext::default(),
        )
        .unwrap();
        let internal = normalize(
            &key("192.168.2.5", 1, "192.168.10.5", 2),
            &topology,
            &ConntrackContext::default(),
        )
        .unwrap();
        assert_eq!(tunnel.scope, FlowScope::Tunnel);
        assert_eq!(internal.scope, FlowScope::Internal);
    }

    fn topology() -> TopologyContext {
        let mut topology = TopologyContext::default();
        topology
            .snapshot
            .local_addresses
            .push("192.168.2.8".parse().unwrap());
        topology
            .snapshot
            .local_addresses
            .push("fd00::1".parse().unwrap());
        for (subnet, role) in [
            ("192.168.2.0/24", SegmentRole::Lan),
            ("192.168.10.0/24", SegmentRole::RoutedLan),
            ("192.168.8.0/21", SegmentRole::RoutedLan),
            ("10.10.10.0/24", SegmentRole::Tunnel),
            ("fd00::/64", SegmentRole::Lan),
        ] {
            topology.snapshot.segments.push(NetworkSegment {
                subnet: subnet.parse().unwrap(),
                interface: None,
                role,
                source: SegmentSource::Config,
                confidence: 100,
            });
        }
        topology
    }

    fn key(source: &str, source_port: u16, destination: &str, destination_port: u16) -> FlowKey {
        ip_key(source, source_port, destination, destination_port, 6)
    }

    fn ip_key(
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        protocol: u8,
    ) -> FlowKey {
        let source = source.parse::<IpAddr>().unwrap();
        let destination = destination.parse::<IpAddr>().unwrap();
        let mut source_address = [0; 16];
        let mut destination_address = [0; 16];
        let ip_version = match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                source_address[..4].copy_from_slice(&source.octets());
                destination_address[..4].copy_from_slice(&destination.octets());
                4
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                source_address.copy_from_slice(&source.octets());
                destination_address.copy_from_slice(&destination.octets());
                6
            }
            _ => panic!("source and destination address families must match"),
        };
        FlowKey {
            ip_version,
            protocol,
            direction: 0,
            ifindex: 1,
            source_address,
            destination_address,
            source_port,
            destination_port,
        }
    }
}
