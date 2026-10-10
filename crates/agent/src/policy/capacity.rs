//! Resolve physical link capacity without trusting virtual bridge/veth speeds.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use crate::config::{MAX_POLICY_CAPACITY_BPS, MIN_POLICY_CAPACITY_BPS};
use crate::linux::neighbor::{self, BridgeFdbEntry, NeighborEntry};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Capacity {
    pub bps: u64,
    pub source: &'static str,
    pub link_interfaces: Vec<String>,
}

pub(super) fn effective(interface: &str, configured: Option<u64>) -> Result<Capacity, String> {
    let root = Path::new("/sys/class/net");
    let bridge = root.join(interface).join("bridge").exists();
    let neighbors = if bridge {
        neighbor::discover_all().unwrap_or_default()
    } else {
        Vec::new()
    };
    let fdb = if bridge {
        neighbor::discover_bridge_fdb().unwrap_or_default()
    } else {
        Vec::new()
    };
    let gateways = crate::linux::network::discover_routes()
        .into_iter()
        .filter(|route| route.destination.prefix_length == 0 && route.interface == interface)
        .filter_map(|route| route.gateway)
        .collect::<Vec<_>>();
    let measured = detect(root, interface, &gateways, &neighbors, &fdb, 0);
    resolve(measured, configured)
}

fn resolve(
    measured: Result<Capacity, String>,
    configured: Option<u64>,
) -> Result<Capacity, String> {
    if configured
        .is_some_and(|bps| !(MIN_POLICY_CAPACITY_BPS..=MAX_POLICY_CAPACITY_BPS).contains(&bps))
    {
        return Err(
            "unsupported_interface_speed: configured capacity is outside the safe numeric range"
                .into(),
        );
    }
    match (measured, configured) {
        (Ok(mut link), Some(cap)) => {
            link.bps = link.bps.min(cap);
            link.source = "configured_and_link";
            Ok(link)
        }
        (Ok(link), None) => Ok(link),
        (Err(_), Some(bps)) => Ok(Capacity {
            bps,
            source: "configured",
            link_interfaces: Vec::new(),
        }),
        (Err(error), None) => Err(format!(
            "unsupported_interface_speed: {error}; configure policy_interface_capacity_bps to override"
        )),
    }
}

fn detect(
    root: &Path,
    interface: &str,
    gateways: &[IpAddr],
    neighbors: &[NeighborEntry],
    fdb: &[BridgeFdbEntry],
    depth: usize,
) -> Result<Capacity, String> {
    if depth >= 8
        || interface.is_empty()
        || interface.len() > 15
        || interface.contains('/')
        || matches!(interface, "." | "..")
    {
        return Err("invalid or recursive link topology".into());
    }
    let sys = root.join(interface);
    if fs::read_to_string(sys.join("carrier")).is_ok_and(|value| value.trim() == "0") {
        return Err(format!("{interface} has no active carrier"));
    }
    if sys.join("bridge").exists() {
        let members = children(&sys.join("brif"), "")?;
        if !gateways.is_empty() {
            let ifindex = read_index(&sys)?;
            let ports = members
                .iter()
                .map(|name| read_index(&root.join(name)).map(|index| (index, name)))
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let mut selected = BTreeSet::new();
            for gateway in gateways {
                let mac = neighbors
                    .iter()
                    .find(|entry| entry.ifindex == ifindex && entry.ip == *gateway)
                    .ok_or_else(|| {
                        format!("{interface} gateway {gateway} has no resolved neighbour")
                    })?
                    .mac;
                let matches = fdb
                    .iter()
                    .filter(|entry| entry.mac == mac && ports.contains_key(&entry.ifindex))
                    .map(|entry| entry.ifindex)
                    .collect::<BTreeSet<_>>();
                if matches.len() != 1 {
                    return Err(format!(
                        "{interface} gateway {gateway} has no unique bridge forwarding port"
                    ));
                }
                selected.insert(ports[&matches.into_iter().next().expect("one port")].as_str());
            }
            let links = selected
                .into_iter()
                .map(|name| detect(root, name, &[], neighbors, fdb, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            return combine(links, "bridge_gateway");
        }
        // A LAN bridge without a routed next hop may still have one physical
        // attachment. Ignore virtual members; multiple links are ambiguous,
        // rather than summing speeds or choosing the bridge's synthetic speed.
        let links = members
            .iter()
            .filter_map(|name| detect(root, name, &[], neighbors, fdb, depth + 1).ok())
            .collect::<Vec<_>>();
        let interfaces = links
            .iter()
            .flat_map(|link| &link.link_interfaces)
            .collect::<BTreeSet<_>>();
        if interfaces.len() != 1 {
            return Err(format!(
                "{interface} has no unique physical bridge capacity"
            ));
        }
        return combine(links, "bridge_single_link");
    }
    let lowers = children(&sys, "lower_")?;
    if !lowers.is_empty() {
        if lowers.len() != 1 {
            return Err(format!(
                "{interface} has multiple lower links with unknown aggregate capacity"
            ));
        }
        let mut capacity = detect(root, &lowers[0], &[], neighbors, fdb, depth + 1)?;
        capacity.source = "lower_link";
        return Ok(capacity);
    }
    if !sys.join("device").exists() {
        return Err(format!(
            "{interface} is virtual and has no physical lower link"
        ));
    }
    let speed = fs::read_to_string(sys.join("speed"))
        .map_err(|error| format!("cannot read {interface} speed: {error}"))?;
    let mbps = speed
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{interface} has no measured link speed"))?;
    let bps = mbps
        .checked_mul(1_000_000)
        .filter(|bps| (MIN_POLICY_CAPACITY_BPS..=MAX_POLICY_CAPACITY_BPS).contains(bps))
        .ok_or_else(|| format!("{interface} link speed is outside the safe numeric range"))?;
    Ok(Capacity {
        bps,
        source: "link",
        link_interfaces: vec![interface.into()],
    })
}

fn read_index(sys: &Path) -> Result<u32, String> {
    fs::read_to_string(sys.join("ifindex"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|index| *index != 0)
        .ok_or_else(|| format!("{} has no interface index", sys.display()))
}

fn children(path: &Path, prefix: &str) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate {}: {error}", path.display()))?;
    let mut names = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_prefix(prefix).map(str::to_owned))
        .collect::<Vec<_>>();
    names.sort_unstable();
    if names.len() > 256 {
        return Err("link topology exceeds the member limit".into());
    }
    Ok(names)
}

fn combine(links: Vec<Capacity>, source: &'static str) -> Result<Capacity, String> {
    let bps = links
        .iter()
        .map(|link| link.bps)
        .min()
        .ok_or_else(|| "no physical link capacity".to_owned())?;
    let link_interfaces = links
        .into_iter()
        .flat_map(|link| link.link_interfaces)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(Capacity {
        bps,
        source,
        link_interfaces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MacAddress;

    fn interface(root: &Path, name: &str, index: u32, speed: &str, physical: bool) {
        let path = root.join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("ifindex"), index.to_string()).unwrap();
        fs::write(path.join("speed"), speed).unwrap();
        fs::write(path.join("carrier"), "1").unwrap();
        if physical {
            fs::create_dir(path.join("device")).unwrap();
        }
    }

    #[test]
    fn gateway_fdb_selects_the_physical_port_instead_of_virtual_bridge_speeds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        interface(root, "br-lan", 1, "10000", false);
        interface(root, "eth0", 2, "2500", true);
        interface(root, "veth0", 3, "10000", false);
        interface(root, "eth1", 4, "1000", true);
        fs::create_dir(root.join("br-lan/bridge")).unwrap();
        for member in ["eth0", "veth0", "eth1"] {
            fs::create_dir_all(root.join("br-lan/brif").join(member)).unwrap();
        }
        let mac = MacAddress::from_bytes(&[2, 0, 0, 0, 0, 1]).unwrap();
        let neighbors = vec![NeighborEntry {
            ifindex: 1,
            ip: "192.0.2.1".parse().unwrap(),
            mac,
        }];
        let fdb = vec![
            BridgeFdbEntry { ifindex: 2, mac },
            BridgeFdbEntry { ifindex: 99, mac },
        ];
        let measured = detect(root, "br-lan", &[neighbors[0].ip], &neighbors, &fdb, 0).unwrap();
        assert_eq!(
            measured,
            Capacity {
                bps: 2_500_000_000,
                source: "bridge_gateway",
                link_interfaces: vec!["eth0".into()]
            }
        );
        assert!(detect(root, "br-lan", &[], &neighbors, &fdb, 0).is_err());
        assert!(detect(root, "br-lan", &[neighbors[0].ip], &[], &fdb, 0).is_err());
        assert!(
            detect(
                root,
                "br-lan",
                &[neighbors[0].ip],
                &neighbors,
                &[BridgeFdbEntry { ifindex: 3, mac }],
                0
            )
            .is_err()
        );
        let mut ambiguous = fdb.clone();
        ambiguous.push(BridgeFdbEntry { ifindex: 4, mac });
        assert!(
            detect(
                root,
                "br-lan",
                &[neighbors[0].ip],
                &neighbors,
                &ambiguous,
                0
            )
            .is_err()
        );
        fs::remove_dir(root.join("br-lan/brif/eth1")).unwrap();
        assert_eq!(
            detect(root, "br-lan", &[], &[], &[], 0).unwrap().bps,
            2_500_000_000
        );
    }

    #[test]
    fn follows_vlan_lower_links_and_rejects_down_unknown_or_overflowing_speeds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        interface(root, "eth0", 2, "10000", true);
        interface(root, "eth0.10", 3, "1000", false);
        fs::create_dir(root.join("eth0.10/lower_eth0")).unwrap();
        assert_eq!(
            detect(root, "eth0.10", &[], &[], &[], 0).unwrap().bps,
            10_000_000_000
        );
        fs::write(root.join("eth0/carrier"), "0").unwrap();
        assert!(detect(root, "eth0", &[], &[], &[], 0).is_err());
        fs::write(root.join("eth0/carrier"), "1").unwrap();
        for speed in ["-1", "0", "18446744073709551615"] {
            fs::write(root.join("eth0/speed"), speed).unwrap();
            assert!(detect(root, "eth0", &[], &[], &[], 0).is_err());
        }
        assert!(detect(root, "../eth0", &[], &[], &[], 0).is_err());
    }

    #[test]
    fn manual_capacity_is_a_fallback_or_a_cap_on_the_detected_link() {
        let measured = || {
            Ok(Capacity {
                bps: 2_500_000_000,
                source: "bridge_gateway",
                link_interfaces: vec!["eth0".into()],
            })
        };
        assert_eq!(resolve(measured(), None).unwrap().bps, 2_500_000_000);
        assert_eq!(
            resolve(measured(), Some(10_000_000_000)).unwrap().bps,
            2_500_000_000
        );
        assert_eq!(
            resolve(measured(), Some(1_000_000_000)).unwrap().bps,
            1_000_000_000
        );
        assert_eq!(
            resolve(Err("unknown".into()), Some(10_000_000_000))
                .unwrap()
                .source,
            "configured"
        );
        assert!(resolve(Err("unknown".into()), None).is_err());
        assert!(resolve(measured(), Some(0)).is_err());
    }
}
