//! Discover actual LAN queue locations without assigning identity to proxy sockets.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::Serialize;

use crate::{
    identity::MacAddress,
    linux::neighbor::{self, BridgeFdbEntry},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct QueuePort {
    pub name: String,
    pub ifindex: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DeliveryLayout {
    pub capture_interface: String,
    pub bridge: bool,
    pub ingress_ports: Vec<QueuePort>,
    pub egress_ports: Vec<QueuePort>,
    pub client_delivery: BTreeMap<String, QueuePort>,
}

pub(crate) fn inspect(lan: &str, selected: &BTreeSet<String>) -> Result<DeliveryLayout, String> {
    inspect_at(Path::new("/sys/class/net"), lan, selected, || {
        neighbor::discover_bridge_fdb()
            .map_err(|e| format!("priority_delivery_unknown: FDB dump failed: {e}"))
    })
}

fn inspect_at(
    sys: &Path,
    lan: &str,
    selected: &BTreeSet<String>,
    fdb: impl FnOnce() -> Result<Vec<BridgeFdbEntry>, String>,
) -> Result<DeliveryLayout, String> {
    validate_name(lan)?;
    if selected.len() > 256 {
        return Err("priority_delivery_unknown: too many selected clients".to_owned());
    }
    let selected = selected
        .iter()
        .map(|text| {
            let mac = text
                .parse::<MacAddress>()
                .map_err(|e| format!("priority_identity_invalid: {e}"))?;
            if !mac.is_unicast() || mac.to_string() != *text {
                return Err("priority_identity_invalid: expected canonical unicast MAC".to_owned());
            }
            Ok((text.clone(), mac))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let bridge = sys.join(lan).join("bridge").is_dir();
    let names = if bridge {
        fs::read_dir(sys.join(lan).join("brif"))
            .map_err(|e| format!("priority_delivery_unknown: cannot read bridge ports: {e}"))?
            .map(|entry| {
                entry.map_err(|e| e.to_string()).and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "invalid bridge port name".to_owned())
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?
    } else {
        BTreeSet::from([lan.to_owned()])
    };
    let ports = names
        .into_iter()
        .map(|name| {
            validate_name(&name)?;
            let ifindex = fs::read_to_string(sys.join(&name).join("ifindex"))
                .map_err(|e| format!("priority_delivery_unknown: cannot read {name} index: {e}"))?
                .trim()
                .parse::<u32>()
                .map_err(|_| "priority_delivery_unknown: invalid interface index".to_owned())?;
            if ifindex == 0 {
                return Err("priority_delivery_unknown: zero interface index".to_owned());
            }
            Ok(QueuePort { name, ifindex })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if ports.is_empty()
        || ports.len() > 32
        || ports
            .iter()
            .map(|p| p.ifindex)
            .collect::<BTreeSet<_>>()
            .len()
            != ports.len()
    {
        return Err(
            "priority_delivery_unknown: bridge ports are empty, excessive or ambiguous".to_owned(),
        );
    }
    let bindings = if bridge { fdb()? } else { Vec::new() };
    let mut deliveries = BTreeMap::new();
    for (text, mac) in selected {
        let matching = if bridge {
            bindings
                .iter()
                .filter(|b| b.mac == mac && ports.iter().any(|p| p.ifindex == b.ifindex))
                .map(|b| b.ifindex)
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::from([ports[0].ifindex])
        };
        if matching.len() != 1 {
            return Err(format!(
                "priority_delivery_unknown: client {text} has {} verified LAN delivery ports",
                matching.len()
            ));
        }
        let ifindex = *matching.first().unwrap();
        deliveries.insert(
            text,
            ports.iter().find(|p| p.ifindex == ifindex).unwrap().clone(),
        );
    }
    Ok(DeliveryLayout {
        capture_interface: lan.to_owned(),
        bridge,
        ingress_ports: ports.clone(),
        egress_ports: ports,
        client_delivery: deliveries,
    })
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err("priority_delivery_unknown: invalid interface name".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("lan/bridge")).unwrap();
        fs::create_dir_all(root.path().join("lan/brif/a")).unwrap();
        fs::create_dir_all(root.path().join("lan/brif/b")).unwrap();
        for (name, index) in [("a", 10), ("b", 11)] {
            fs::create_dir_all(root.path().join(name)).unwrap();
            fs::write(root.path().join(name).join("ifindex"), index.to_string()).unwrap();
        }
        root
    }

    #[test]
    fn one_client_budget_has_one_port_and_includes_bridge_forwarding_hooks() {
        let root = fixture();
        let mac = "02:00:00:00:00:01".parse::<MacAddress>().unwrap();
        let layout = inspect_at(
            root.path(),
            "lan",
            &BTreeSet::from([mac.to_string()]),
            || {
                Ok(vec![
                    BridgeFdbEntry { mac, ifindex: 10 },
                    BridgeFdbEntry { mac, ifindex: 10 },
                    BridgeFdbEntry { mac, ifindex: 2 },
                ])
            },
        )
        .unwrap();
        assert_eq!(layout.client_delivery[&mac.to_string()].ifindex, 10);
        assert_eq!(layout.ingress_ports, layout.egress_ports);
        assert_eq!(layout.egress_ports.len(), 2);
        assert!(!layout.egress_ports.iter().any(|p| p.name == "lan"));
    }

    #[test]
    fn unresolved_multiport_or_unreadable_fdb_cannot_duplicate_a_budget() {
        let root = fixture();
        let mac = "02:00:00:00:00:01".parse::<MacAddress>().unwrap();
        let selected = BTreeSet::from([mac.to_string()]);
        for entries in [
            vec![],
            vec![
                BridgeFdbEntry { mac, ifindex: 10 },
                BridgeFdbEntry { mac, ifindex: 11 },
            ],
        ] {
            assert!(inspect_at(root.path(), "lan", &selected, || Ok(entries)).is_err());
        }
        assert!(
            inspect_at(root.path(), "lan", &selected, || Err(
                "FDB read failed".to_owned()
            ))
            .is_err()
        );
    }
}
