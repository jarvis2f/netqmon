//! Find a common queue for routed interfaces that share a physical link.
use std::{collections::BTreeSet, fs, path::Path, process::Command};

use serde_json::Value;

pub(super) fn common_egress(wans: &[String]) -> Option<String> {
    // Preserve the established queue placement for ordinary single-WAN setups.
    let root = Path::new("/sys/class/net");
    if wans.len() == 1 && !is_ppp(root, &wans[0]) {
        return None;
    }
    let ubus = Command::new("ubus")
        .args(["-S", "call", "network.interface", "dump"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok());
    let sessions = fs::read_to_string("/proc/net/pppoe").unwrap_or_default();
    common_egress_at(
        root,
        Path::new("/proc/net/vlan"),
        wans,
        ubus.as_ref(),
        &sessions,
    )
}

fn common_egress_at(
    root: &Path,
    vlan_root: &Path,
    wans: &[String],
    ubus: Option<&Value>,
    sessions: &str,
) -> Option<String> {
    if wans.is_empty() {
        return None;
    }
    let mut common = BTreeSet::new();
    for wan in wans {
        if !valid_name(wan) {
            return None;
        }
        let mut current = wan.clone();
        if is_ppp(root, wan) {
            let entries = ubus?.get("interface")?.as_array()?;
            let candidates = entries
                .iter()
                .filter_map(|entry| {
                    (entry.get("up")?.as_bool()?
                        && entry.get("proto")?.as_str()? == "pppoe"
                        && entry.get("l3_device")?.as_str()? == wan)
                        .then(|| entry.get("device")?.as_str().map(str::to_owned))?
                })
                .collect::<BTreeSet<_>>();
            if candidates.len() != 1 {
                return None;
            }
            current = candidates.into_iter().next()?;
            if !sessions
                .lines()
                .skip(1)
                .any(|line| line.split_whitespace().nth(2) == Some(current.as_str()))
            {
                return None;
            }
        }
        let mut visited = BTreeSet::new();
        loop {
            if !valid_name(&current) || !visited.insert(current.clone()) || visited.len() > 8 {
                return None;
            }
            let path = root.join(&current);
            let links = fs::read_dir(&path)
                .ok()?
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|name| name.strip_prefix("lower_").map(str::to_owned))
                .collect::<BTreeSet<_>>();
            if links.is_empty() {
                if fs::read_to_string(path.join("type")).ok()?.trim() != "1"
                    || path.join("bridge").exists()
                    || !path.join("device").exists()
                {
                    return None;
                }
                break;
            }
            if links.len() != 1 {
                return None;
            }
            // A lower link alone is not proof that encapsulation preserves
            // skb marks. VLAN and PPPoE are the paths validated here.
            if !vlan_root.join(&current).is_file() {
                return None;
            }
            current = links.into_iter().next()?;
        }
        common.insert(current);
    }
    (common.len() == 1)
        .then(|| common.into_iter().next())
        .flatten()
}

fn is_ppp(root: &Path, name: &str) -> bool {
    valid_name(name)
        && fs::read_to_string(root.join(name).join("type")).is_ok_and(|kind| kind.trim() == "512")
}

pub(super) fn is_ppp_interface(name: &str) -> bool {
    is_ppp(Path::new("/sys/class/net"), name)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

/// Reject a WAN queue reachable through the managed LAN's bridge/lower links.
pub(super) fn overlaps_lan(lan: &str, queue: &str) -> bool {
    overlaps_lan_at(Path::new("/sys/class/net"), lan, queue)
}

fn overlaps_lan_at(root: &Path, lan: &str, queue: &str) -> bool {
    let mut pending = vec![lan.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == queue {
            return true;
        }
        if !valid_name(&current) || seen.len() > 128 {
            return true;
        }
        if !seen.insert(current.clone()) {
            continue;
        }
        let path = root.join(&current);
        let Ok(entries) = fs::read_dir(&path) else {
            return true;
        };
        for entry in entries {
            let Ok(entry) = entry else { return true };
            let Ok(name) = entry.file_name().into_string() else {
                return true;
            };
            if let Some(lower) = name.strip_prefix("lower_") {
                pending.push(lower.to_owned());
            }
        }
        let bridge = path.join("brif");
        if bridge.exists() {
            let Ok(ports) = fs::read_dir(bridge) else {
                return true;
            };
            for port in ports {
                let Ok(port) = port else { return true };
                let Ok(name) = port.file_name().into_string() else {
                    return true;
                };
                pending.push(name);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(root: &Path, name: &str, kind: &str) {
        fs::create_dir(root.join(name)).unwrap();
        fs::write(root.join(name).join("type"), kind).unwrap();
    }

    #[test]
    fn pppoe_and_source_routed_ethernet_share_one_verified_queue() {
        let temp = tempfile::tempdir().unwrap();
        device(temp.path(), "pppoe-wan", "512");
        device(temp.path(), "eth2", "1");
        fs::create_dir(temp.path().join("eth2/device")).unwrap();
        let status = serde_json::json!({"interface": [{"up": true, "proto": "pppoe", "device": "eth2", "l3_device": "pppoe-wan"}]});
        let sessions = "Id Address Device\n00000100 00:11:22:33:44:55 eth2\n";
        let wans = vec!["eth2".into(), "pppoe-wan".into()];
        assert_eq!(
            common_egress_at(temp.path(), temp.path(), &wans, Some(&status), sessions).as_deref(),
            Some("eth2")
        );
        assert_eq!(
            common_egress_at(
                temp.path(),
                temp.path(),
                &wans,
                Some(&status),
                "Id Address Device\n"
            ),
            None
        );
        assert_eq!(
            common_egress_at(temp.path(), temp.path(), &wans, None, sessions),
            None
        );
    }

    #[test]
    fn vlan_parents_share_queue_but_distinct_or_ambiguous_parents_do_not() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["vlan1", "vlan2", "eth0", "eth1"] {
            device(temp.path(), name, "1");
        }
        for name in ["eth0", "eth1"] {
            fs::create_dir(temp.path().join(name).join("device")).unwrap();
        }
        fs::create_dir(temp.path().join("vlan1/lower_eth0")).unwrap();
        fs::create_dir(temp.path().join("vlan2/lower_eth0")).unwrap();
        let vlan_root = temp.path().join("vlans");
        fs::create_dir(&vlan_root).unwrap();
        fs::write(vlan_root.join("vlan1"), "").unwrap();
        fs::write(vlan_root.join("vlan2"), "").unwrap();
        let wans = vec!["vlan1".into(), "vlan2".into()];
        assert_eq!(
            common_egress_at(temp.path(), &vlan_root, &wans, None, "").as_deref(),
            Some("eth0")
        );
        fs::remove_dir(temp.path().join("vlan2/lower_eth0")).unwrap();
        fs::create_dir(temp.path().join("vlan2/lower_eth1")).unwrap();
        assert_eq!(
            common_egress_at(temp.path(), &vlan_root, &wans, None, ""),
            None
        );
        fs::create_dir(temp.path().join("vlan2/lower_eth0")).unwrap();
        assert_eq!(
            common_egress_at(temp.path(), &vlan_root, &wans, None, ""),
            None
        );
    }

    #[test]
    fn bridge_member_or_vlan_parent_cannot_be_a_dedicated_wan_queue() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["br-lan", "lan-vlan", "eth0", "eth1"] {
            device(temp.path(), name, "1");
        }
        fs::create_dir_all(temp.path().join("br-lan/brif/lan-vlan")).unwrap();
        fs::create_dir(temp.path().join("lan-vlan/lower_eth0")).unwrap();
        assert!(overlaps_lan_at(temp.path(), "br-lan", "eth0"));
        assert!(!overlaps_lan_at(temp.path(), "br-lan", "eth1"));
        assert!(overlaps_lan_at(temp.path(), "missing", "eth1"));
    }
}
