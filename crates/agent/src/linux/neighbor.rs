use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    RouteNetlinkMessage,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::identity::MacAddress;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NeighborEntry {
    pub(super) ip: IpAddr,
    pub(super) mac: MacAddress,
}

pub(super) fn discover(ifindex: u32) -> Result<Vec<NeighborEntry>, NeighborDiscoveryError> {
    discover_matching(Some(ifindex))
}

pub(super) fn discover_all() -> Result<Vec<NeighborEntry>, NeighborDiscoveryError> {
    discover_matching(None)
}

fn discover_matching(ifindex: Option<u32>) -> Result<Vec<NeighborEntry>, NeighborDiscoveryError> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(NeighborDiscoveryError::io)?;
    socket.bind_auto().map_err(NeighborDiscoveryError::io)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(NeighborDiscoveryError::io)?;

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    header.sequence_number = 1;
    let mut request = NetlinkMessage::new(
        header,
        NetlinkPayload::from(RouteNetlinkMessage::GetNeighbour(
            NeighbourMessage::default(),
        )),
    );
    request.finalize();
    let mut bytes = vec![0; request.header.length as usize];
    request.serialize(&mut bytes);
    socket.send(&bytes, 0).map_err(NeighborDiscoveryError::io)?;

    let mut entries = Vec::new();
    'responses: loop {
        let (datagram, _) = socket
            .recv_from_full()
            .map_err(NeighborDiscoveryError::io)?;
        let mut offset = 0;
        while offset < datagram.len() {
            let message: NetlinkMessage<RouteNetlinkMessage> =
                NetlinkMessage::deserialize(&datagram[offset..])
                    .map_err(|error| NeighborDiscoveryError(error.to_string()))?;
            let length = message.header.length as usize;
            if length == 0 || offset + length > datagram.len() {
                return Err(NeighborDiscoveryError(
                    "kernel returned an invalid netlink message length".to_owned(),
                ));
            }
            match message.payload {
                NetlinkPayload::Done(_) => break 'responses,
                NetlinkPayload::Error(error) if error.raw_code() != 0 => {
                    return Err(NeighborDiscoveryError(format!(
                        "kernel rejected neighbour dump: {error}"
                    )));
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(message)) => {
                    if let Some(entry) = parse_entry(&message, ifindex) {
                        entries.push(entry);
                    }
                }
                _ => {}
            }
            offset += align_netlink(length);
        }
    }
    entries.sort_by_key(|entry| (entry.mac, entry.ip));
    entries.dedup();
    Ok(entries)
}

fn parse_entry(message: &NeighbourMessage, ifindex: Option<u32>) -> Option<NeighborEntry> {
    if ifindex.is_some_and(|ifindex| message.header.ifindex != ifindex)
        || matches!(
            message.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed
        )
    {
        return None;
    }
    let ip = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(address)) => {
                Some(IpAddr::V4(*address))
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(address)) => {
                Some(IpAddr::V6(*address))
            }
            _ => None,
        })?;
    let mac = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            NeighbourAttribute::LinkLayerAddress(bytes) => MacAddress::from_bytes(bytes).ok(),
            _ => None,
        })?;
    if !mac.is_unicast() {
        return None;
    }
    Some(NeighborEntry { ip, mac })
}

fn align_netlink(length: usize) -> usize {
    (length + 3) & !3
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NeighborDiscoveryError(String);

impl NeighborDiscoveryError {
    fn io(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl fmt::Display for NeighborDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "neighbour discovery failed: {}", self.0)
    }
}

impl Error for NeighborDiscoveryError {}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use netlink_packet_route::{
        AddressFamily,
        neighbour::{NeighbourHeader, NeighbourState},
    };

    use super::*;

    #[test]
    fn parses_ipv4_arp_and_ipv6_ndp_entries() {
        let ipv4 = message(
            AddressFamily::Inet,
            NeighbourAddress::Inet(Ipv4Addr::new(192, 0, 2, 20)),
        );
        let ipv6 = message(
            AddressFamily::Inet6,
            NeighbourAddress::Inet6("2001:db8::20".parse::<Ipv6Addr>().unwrap()),
        );

        assert_eq!(
            parse_entry(&ipv4, Some(7)).unwrap().ip,
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            parse_entry(&ipv6, Some(7)).unwrap().ip,
            "2001:db8::20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ignores_other_interfaces_failed_entries_and_invalid_link_addresses() {
        let mut entry = message(
            AddressFamily::Inet,
            NeighbourAddress::Inet(Ipv4Addr::new(192, 0, 2, 20)),
        );
        assert!(parse_entry(&entry, None).is_some());
        assert_eq!(parse_entry(&entry, Some(8)), None);
        entry.header.state = NeighbourState::Failed;
        assert_eq!(parse_entry(&entry, Some(7)), None);
        entry.header.state = NeighbourState::Reachable;
        entry.attributes[1] = NeighbourAttribute::LinkLayerAddress(vec![1, 2, 3]);
        assert_eq!(parse_entry(&entry, Some(7)), None);
    }

    fn message(family: AddressFamily, address: NeighbourAddress) -> NeighbourMessage {
        let mut message = NeighbourMessage::default();
        message.header = NeighbourHeader {
            family,
            ifindex: 7,
            state: NeighbourState::Reachable,
            ..Default::default()
        };
        message.attributes = vec![
            NeighbourAttribute::Destination(address),
            NeighbourAttribute::LinkLayerAddress(vec![0x02, 0, 0, 0, 0, 0x20]),
        ];
        message
    }
}
