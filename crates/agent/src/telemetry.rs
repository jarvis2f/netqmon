use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::v1::{
    DeviceObservation as WireDeviceObservation, DhcpMetadata as WireDhcpMetadata,
    Direction as WireDirection, DnsObservation as WireDnsObservation,
    DnsRecordType as WireDnsRecordType, FlowDelta as WireFlowDelta, FlowLifecycle,
    FlowScope as WireFlowScope, NatType as WireNatType, PathType as WirePathType,
};

use crate::device::DeviceObservation;
use crate::dns_observation::{DnsObservation, DnsRecordType};
use crate::flow::FlowDelta;
use crate::identity::MacAddress;
use crate::normalization::{Direction, FlowScope, NatInfo, NormalizedFlow, PathType};

pub(super) fn flow_delta(
    delta: &FlowDelta,
    flow: &NormalizedFlow,
    client_mac: Option<MacAddress>,
    boot_epoch_ms: u64,
) -> WireFlowDelta {
    let (upload_bytes, download_bytes) = match flow.direction {
        Direction::Download => (0, delta.bytes),
        Direction::Upload | Direction::Internal | Direction::Unknown => (delta.bytes, 0),
    };
    WireFlowDelta {
        ip_version: u32::from(delta.key.ip_version),
        protocol: u32::from(delta.key.protocol),
        client_ip: ip_bytes(flow.client_addr),
        client_port: u32::from(flow.client_port),
        remote_ip: ip_bytes(flow.remote_addr),
        remote_port: u32::from(flow.remote_port),
        direction: wire_direction(flow.direction) as i32,
        upload_bytes,
        download_bytes,
        packets: delta.packets,
        first_seen_unix_ms: boot_epoch_ms.saturating_add(delta.counters.first_seen_ns / 1_000_000),
        last_seen_unix_ms: boot_epoch_ms.saturating_add(delta.counters.last_seen_ns / 1_000_000),
        tcp_flags: u32::try_from(delta.counters.tcp_flags).unwrap_or(u32::MAX),
        lifecycle: FlowLifecycle::Active as i32,
        client_mac: client_mac.map_or_else(Vec::new, |mac| mac.octets().to_vec()),
        protocol_hint: String::new(),
        scope: wire_scope(flow.scope) as i32,
        path_type: wire_path_type(flow.path_type) as i32,
        nat: wire_nat(flow.nat) as i32,
        source_segment: flow
            .source_segment
            .map_or_else(String::new, |value| value.to_string()),
        destination_segment: flow
            .destination_segment
            .map_or_else(String::new, |value| value.to_string()),
    }
}

pub(super) fn lifecycle_delta(
    flow: &NormalizedFlow,
    client_mac: Option<MacAddress>,
    protocol: u8,
    lifecycle: FlowLifecycle,
    observed_at_ms: u64,
) -> WireFlowDelta {
    WireFlowDelta {
        ip_version: if flow.client_addr.is_ipv4() { 4 } else { 6 },
        protocol: u32::from(protocol),
        client_ip: ip_bytes(flow.client_addr),
        client_port: u32::from(flow.client_port),
        remote_ip: ip_bytes(flow.remote_addr),
        remote_port: u32::from(flow.remote_port),
        direction: wire_direction(flow.direction) as i32,
        first_seen_unix_ms: observed_at_ms,
        last_seen_unix_ms: observed_at_ms,
        lifecycle: lifecycle as i32,
        client_mac: client_mac.map_or_else(Vec::new, |mac| mac.octets().to_vec()),
        scope: wire_scope(flow.scope) as i32,
        path_type: wire_path_type(flow.path_type) as i32,
        nat: wire_nat(flow.nat) as i32,
        source_segment: flow
            .source_segment
            .map_or_else(String::new, |value| value.to_string()),
        destination_segment: flow
            .destination_segment
            .map_or_else(String::new, |value| value.to_string()),
        ..WireFlowDelta::default()
    }
}

pub(super) fn dns(observation: DnsObservation) -> WireDnsObservation {
    WireDnsObservation {
        client_ip: ip_bytes(observation.client_addr),
        domain: observation.domain,
        answer_ip: ip_bytes(observation.answer_ip),
        record_type: match observation.record_type {
            DnsRecordType::A => WireDnsRecordType::A,
            DnsRecordType::Aaaa => WireDnsRecordType::Aaaa,
        } as i32,
        ttl_seconds: observation.ttl,
        observed_at_unix_ms: unix_ms(observation.observed_at),
    }
}

pub(super) fn device(observation: DeviceObservation) -> WireDeviceObservation {
    WireDeviceObservation {
        mac: observation.mac.octets().to_vec(),
        ip: ip_bytes(observation.ip),
        hostname: observation.hostname.unwrap_or_default(),
        last_seen_unix_ms: unix_ms(observation.last_seen),
        dhcp: observation.dhcp.map(|dhcp| WireDhcpMetadata {
            parameter_request_list: dhcp
                .parameter_request_list
                .into_iter()
                .map(u32::from)
                .collect(),
            vendor_class: dhcp.vendor_class.unwrap_or_default(),
            client_identifier: dhcp.client_identifier,
        }),
    }
}

pub(super) fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

pub(super) fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |duration| {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    })
}

fn wire_direction(direction: Direction) -> WireDirection {
    match direction {
        Direction::Upload => WireDirection::Upload,
        Direction::Download => WireDirection::Download,
        Direction::Internal | Direction::Unknown => WireDirection::Unspecified,
    }
}

fn wire_scope(scope: FlowScope) -> WireFlowScope {
    match scope {
        FlowScope::Client => WireFlowScope::Internet,
        FlowScope::Internal => WireFlowScope::Internal,
        FlowScope::Tunnel => WireFlowScope::Tunnel,
        FlowScope::Unknown | FlowScope::RouterLocal => WireFlowScope::Unknown,
    }
}

fn wire_path_type(path_type: PathType) -> WirePathType {
    match path_type {
        PathType::Forwarded => WirePathType::Forwarded,
        PathType::Internal => WirePathType::Internal,
        PathType::Tunnel => WirePathType::Tunnel,
        PathType::Unknown | PathType::RouterLocal => WirePathType::Unknown,
    }
}

fn wire_nat(nat: NatInfo) -> WireNatType {
    match (nat.source_nat, nat.destination_nat) {
        (false, false) => WireNatType::None,
        (true, false) => WireNatType::Snat,
        (false, true) => WireNatType::Dnat,
        (true, true) => WireNatType::Both,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::dhcp::DhcpMetadata;
    use crate::flow::{FlowCounters, FlowKey};
    use crate::normalization::FlowScope;

    use super::*;

    #[test]
    fn maps_download_delta_and_monotonic_timestamps() {
        let delta = FlowDelta {
            key: FlowKey {
                ip_version: 4,
                protocol: 6,
                direction: 0,
                ifindex: 1,
                source_address: [0; 16],
                destination_address: [0; 16],
                source_port: 443,
                destination_port: 50_000,
            },
            packets: 3,
            bytes: 512,
            counters: FlowCounters {
                first_seen_ns: 2_000_000,
                last_seen_ns: 3_000_000,
                tcp_flags: 0x12,
                ..FlowCounters::default()
            },
        };
        let normalized = NormalizedFlow {
            client_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            client_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            remote_port: 443,
            direction: Direction::Download,
            scope: FlowScope::Client,
            source_segment: None,
            destination_segment: None,
            path_type: crate::normalization::PathType::Forwarded,
            nat: crate::normalization::NatInfo::default(),
        };

        let wire = flow_delta(&delta, &normalized, None, 1_700_000_000_000);
        assert_eq!((wire.upload_bytes, wire.download_bytes), (0, 512));
        assert_eq!(wire.first_seen_unix_ms, 1_700_000_000_002);
        assert_eq!(wire.last_seen_unix_ms, 1_700_000_000_003);
        assert_eq!(wire.direction, WireDirection::Download as i32);
        assert!(wire.protocol_hint.is_empty());
    }

    #[test]
    fn maps_dhcp_metadata_into_device_observations() {
        let wire = device(DeviceObservation {
            mac: "02:00:00:00:00:20".parse().unwrap(),
            ip: "192.0.2.20".parse().unwrap(),
            hostname: Some("phone".to_owned()),
            dhcp: Some(DhcpMetadata {
                parameter_request_list: vec![1, 3, 6, 252],
                vendor_class: Some("android-dhcp-13".to_owned()),
                client_identifier: vec![1, 2, 0, 0, 0, 20],
            }),
            last_seen: UNIX_EPOCH + Duration::from_secs(1),
        });

        let dhcp = wire.dhcp.expect("DHCP metadata should be present");
        assert_eq!(dhcp.parameter_request_list, vec![1, 3, 6, 252]);
        assert_eq!(dhcp.vendor_class, "android-dhcp-13");
        assert_eq!(dhcp.client_identifier, vec![1, 2, 0, 0, 0, 20]);
    }
}
