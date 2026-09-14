use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TopologyMode {
    Router,
    OneArmRouter,
    Bridge,
    Host,
    #[default]
    Unknown,
}

impl fmt::Display for TopologyMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Router => "Router",
            Self::OneArmRouter => "One-arm Router",
            Self::Bridge => "Bridge",
            Self::Host => "Host",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentRole {
    Lan,
    RoutedLan,
    Tunnel,
    Wan,
    Unknown,
}

impl SegmentRole {
    pub fn is_internal(self) -> bool {
        matches!(self, Self::Lan | Self::RoutedLan)
    }
}

impl fmt::Display for SegmentRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lan => "lan",
            Self::RoutedLan => "routed_lan",
            Self::Tunnel => "tunnel",
            Self::Wan => "wan",
            Self::Unknown => "unknown",
        })
    }
}

impl FromStr for SegmentRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lan" => Ok(Self::Lan),
            "routed_lan" => Ok(Self::RoutedLan),
            "tunnel" => Ok(Self::Tunnel),
            "wan" => Ok(Self::Wan),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown network role {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum SegmentSource {
    Inference,
    InterfaceAddress,
    KernelRoute,
    OpenWrt,
    Config,
}

impl fmt::Display for SegmentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inference => "inference",
            Self::InterfaceAddress => "interface",
            Self::KernelRoute => "kernel-route",
            Self::OpenWrt => "openwrt",
            Self::Config => "config",
        })
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct NetworkPrefix {
    pub network: IpAddr,
    pub prefix_length: u8,
}

impl NetworkPrefix {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, PrefixError> {
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix_length > max {
            return Err(PrefixError { prefix_length, max });
        }
        let network = match address {
            IpAddr::V4(address) => {
                let mask = u32::try_from(prefix_mask(prefix_length, 32))
                    .expect("32-bit prefix mask always fits u32");
                IpAddr::V4((u32::from(address) & mask).into())
            }
            IpAddr::V6(address) => {
                IpAddr::V6((u128::from(address) & prefix_mask(prefix_length, 128)).into())
            }
        };
        Ok(Self {
            network,
            prefix_length,
        })
    }

    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.network.is_ipv4()
            && Self::new(address, self.prefix_length)
                .is_ok_and(|candidate| candidate.network == self.network)
    }
}

impl FromStr for NetworkPrefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("network {value} must use CIDR notation"))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| error.to_string())?;
        let prefix = prefix.parse::<u8>().map_err(|error| error.to_string())?;
        Self::new(address, prefix).map_err(|error| error.to_string())
    }
}

impl fmt::Display for NetworkPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_length)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSegment {
    pub subnet: NetworkPrefix,
    pub interface: Option<String>,
    pub role: SegmentRole,
    pub source: SegmentSource,
    pub confidence: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<(IpAddr, u8)>,
    pub is_bridge: bool,
    pub is_tunnel: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    pub destination: NetworkPrefix,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NatStatus {
    #[default]
    Unknown,
    Disabled,
    Masquerade,
}

impl fmt::Display for NatStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Disabled => "Disabled",
            Self::Masquerade => "Masquerade",
        })
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopologySnapshot {
    pub mode: TopologyMode,
    pub interfaces: Vec<InterfaceInfo>,
    pub segments: Vec<NetworkSegment>,
    pub routes: Vec<RouteInfo>,
    pub gateways: Vec<IpAddr>,
    pub neighbors: Vec<IpAddr>,
    pub local_addresses: Vec<IpAddr>,
    pub nat: NatStatus,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub ipv4_default_route: bool,
    pub ipv6_default_route: bool,
    pub icmp_redirects: Option<bool>,
    pub flow_offloading: Option<bool>,
    pub flow_offloading_hw: Option<bool>,
    pub warnings: Vec<String>,
    pub confidence: u8,
}

impl TopologySnapshot {
    pub fn infer_mode(&mut self, capture_interface: &str) {
        let default_interfaces = self
            .routes
            .iter()
            .filter(|route| route.destination.prefix_length == 0)
            .map(|route| route.interface.as_str())
            .collect::<Vec<_>>();
        let forwarding = self.ipv4_forwarding || self.ipv6_forwarding;
        let capture_is_default = default_interfaces.contains(&capture_interface);
        let gateway_on_capture_subnet = self.routes.iter().any(|route| {
            route.interface == capture_interface
                && route.gateway.is_some_and(|gateway| {
                    self.interfaces.iter().any(|interface| {
                        interface.name == capture_interface
                            && interface.addresses.iter().any(|(address, prefix)| {
                                NetworkPrefix::new(*address, *prefix)
                                    .is_ok_and(|network| network.contains(gateway))
                            })
                    })
                })
        });
        let has_bridge = self
            .interfaces
            .iter()
            .any(|interface| interface.name == capture_interface && interface.is_bridge);
        self.mode = if forwarding
            && (capture_is_default || gateway_on_capture_subnet)
            && gateway_on_capture_subnet
        {
            TopologyMode::OneArmRouter
        } else if forwarding && !default_interfaces.is_empty() {
            TopologyMode::Router
        } else if has_bridge {
            TopologyMode::Bridge
        } else if !self.local_addresses.is_empty() {
            TopologyMode::Host
        } else {
            TopologyMode::Unknown
        };
        self.confidence = match self.mode {
            TopologyMode::OneArmRouter => 95,
            TopologyMode::Router => 85,
            TopologyMode::Bridge | TopologyMode::Host => 70,
            TopologyMode::Unknown => 20,
        };
    }

    pub fn finish_health(&mut self) {
        if self.mode == TopologyMode::OneArmRouter && self.icmp_redirects == Some(true) {
            self.warnings
                .push("Clients may bypass this agent through ICMP redirects.".into());
        }
        if !self.ipv6_default_route {
            self.warnings
                .push("IPv6 Internet coverage is unavailable (no IPv6 default route).".into());
        }
        if self.flow_offloading == Some(true) || self.flow_offloading_hw == Some(true) {
            self.warnings.push(
                "Flow offloading is enabled and may bypass eBPF/TC traffic visibility.".into(),
            );
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopologyContext {
    pub snapshot: TopologySnapshot,
}

impl TopologyContext {
    #[allow(dead_code)]
    pub fn add_interface_address(
        &mut self,
        address: IpAddr,
        prefix_length: u8,
    ) -> Result<(), PrefixError> {
        let prefix = NetworkPrefix::new(address, prefix_length)?;
        if !self.snapshot.local_addresses.contains(&address) {
            self.snapshot.local_addresses.push(address);
        }
        if !self
            .snapshot
            .segments
            .iter()
            .any(|segment| segment.subnet == prefix)
        {
            self.snapshot.segments.push(NetworkSegment {
                subnet: prefix,
                interface: None,
                role: SegmentRole::Lan,
                source: SegmentSource::InterfaceAddress,
                confidence: 70,
            });
        }
        Ok(())
    }

    pub fn segment(&self, address: IpAddr) -> Option<&NetworkSegment> {
        self.snapshot
            .segments
            .iter()
            .filter(|segment| segment.subnet.contains(address))
            .max_by_key(|segment| (segment.source, segment.subnet.prefix_length))
    }

    pub fn is_local(&self, address: IpAddr) -> bool {
        self.snapshot.local_addresses.contains(&address)
    }
}

fn prefix_mask(prefix_length: u8, bits: u8) -> u128 {
    if prefix_length == 0 {
        0
    } else if prefix_length == 128 {
        u128::MAX
    } else {
        ((1_u128 << prefix_length) - 1) << (bits - prefix_length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixError {
    prefix_length: u8,
    max: u8,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "prefix length {} exceeds {} bits",
            self.prefix_length, self.max
        )
    }
}

impl std::error::Error for PrefixError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_one_arm_router_from_forwarding_and_same_interface_gateway() {
        let mut snapshot = TopologySnapshot {
            interfaces: vec![InterfaceInfo {
                name: "br-lan".into(),
                addresses: vec![("192.168.2.8".parse().unwrap(), 24)],
                is_bridge: true,
                is_tunnel: false,
            }],
            routes: vec![RouteInfo {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("192.168.2.1".parse().unwrap()),
                interface: "br-lan".into(),
            }],
            local_addresses: vec!["192.168.2.8".parse().unwrap()],
            ipv4_forwarding: true,
            ipv4_default_route: true,
            ..TopologySnapshot::default()
        };
        snapshot.infer_mode("br-lan");
        assert_eq!(snapshot.mode, TopologyMode::OneArmRouter);
    }

    #[test]
    fn longest_and_highest_priority_segment_wins() {
        let mut context = TopologyContext::default();
        context.snapshot.segments = vec![
            NetworkSegment {
                subnet: "192.168.0.0/16".parse().unwrap(),
                interface: None,
                role: SegmentRole::Lan,
                source: SegmentSource::KernelRoute,
                confidence: 80,
            },
            NetworkSegment {
                subnet: "192.168.10.0/24".parse().unwrap(),
                interface: None,
                role: SegmentRole::RoutedLan,
                source: SegmentSource::Config,
                confidence: 100,
            },
        ];
        assert_eq!(
            context
                .segment("192.168.10.4".parse().unwrap())
                .unwrap()
                .role,
            SegmentRole::RoutedLan
        );
    }
}
