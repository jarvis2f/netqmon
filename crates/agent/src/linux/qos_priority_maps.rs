//! Explicit handles and immutable publication for the experimental priority runtime.
#![allow(dead_code)]

use std::{
    collections::BTreeSet,
    net::IpAddr,
    os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd},
};

use anyhow::{Context as _, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use serde::Serialize;

use crate::{
    identity::MacAddress,
    policy::{classid, priority_slots::ClientSlotLease},
};

#[derive(Clone, Debug, Serialize)]
pub(super) struct ClientMapEntry {
    pub mac: String,
    pub slot: u16,
    pub delivery_ifindex: u32,
    pub flags: u32,
    pub generation: u32,
    pub expires_ns: u64,
    pub upload_classid: u32,
    pub download_classid: u32,
}

impl ClientMapEntry {
    pub(super) fn new(
        lease: &ClientSlotLease,
        delivery_ifindex: u32,
        upload: bool,
        download: bool,
        blocked: bool,
        generation: u32,
        expires_ns: u64,
    ) -> Result<Self> {
        lease.validate().map_err(anyhow::Error::msg)?;
        if !lease.active
            || generation == 0
            || expires_ns == 0
            || (download && delivery_ifindex == 0)
        {
            bail!("priority_map_invalid: inactive, incomplete or expired client assignment");
        }
        Ok(Self {
            mac: lease.mac.clone(),
            slot: lease.slot,
            delivery_ifindex,
            flags: u32::from(upload) | (u32::from(download) << 1) | (u32::from(blocked) << 2),
            generation,
            expires_ns,
            upload_classid: lease
                .default_leaf(classid::UPLOAD_MAJOR)
                .map_err(anyhow::Error::msg)?
                .raw(),
            download_classid: lease
                .default_leaf(classid::DOWNLOAD_MAJOR)
                .map_err(anyhow::Error::msg)?
                .raw(),
        })
    }

    fn bytes(&self) -> Result<([u8; 8], [u8; 32])> {
        let lease = ClientSlotLease {
            mac: self.mac.clone(),
            slot: self.slot,
            active: true,
        };
        lease.validate().map_err(anyhow::Error::msg)?;
        if self.flags & !7 != 0
            || self.generation == 0
            || self.expires_ns == 0
            || (self.flags & 2 != 0 && self.delivery_ifindex == 0)
            || self.upload_classid
                != lease
                    .default_leaf(classid::UPLOAD_MAJOR)
                    .map_err(anyhow::Error::msg)?
                    .raw()
            || self.download_classid
                != lease
                    .default_leaf(classid::DOWNLOAD_MAJOR)
                    .map_err(anyhow::Error::msg)?
                    .raw()
        {
            bail!("priority_map_invalid: client assignment is inconsistent with canonical classes");
        }
        let mut key = [0; 8];
        key[..6].copy_from_slice(&self.mac.parse::<MacAddress>()?.octets());
        let mut value = [0; 32];
        for (offset, field) in [
            (0, u32::from(self.slot)),
            (4, self.delivery_ifindex),
            (8, self.flags),
            (12, self.generation),
            (24, self.upload_classid),
            (28, self.download_classid),
        ] {
            value[offset..offset + 4].copy_from_slice(&field.to_ne_bytes());
        }
        value[16..24].copy_from_slice(&self.expires_ns.to_ne_bytes());
        Ok((key, value))
    }
}

pub(super) struct PreparedClients {
    map: MapHandle,
    pub entries: Vec<ClientMapEntry>,
}

pub(super) struct PriorityMaps {
    outer: MapHandle,
    active: MapHandle,
    pub ifb: MapHandle,
    pub ingress_ports: MapHandle,
    pub roots: MapHandle,
    pub counters: MapHandle,
    internal_v4: MapHandle,
    internal_v6: MapHandle,
    configured_internal_v4: bool,
    configured_internal_v6: bool,
    poisoned: bool,
}

impl PriorityMaps {
    pub(super) fn new(
        outer: MapHandle,
        empty: MapHandle,
        ifb: MapHandle,
        ingress_ports: MapHandle,
        roots: MapHandle,
        counters: MapHandle,
        internal_v4: MapHandle,
        internal_v6: MapHandle,
    ) -> Result<Self> {
        if outer.map_type() != MapType::ArrayOfMaps
            || outer.key_size() != 4
            || outer.value_size() != 4
            || outer.max_entries() != 1
            || !client_map_abi(&empty)
            || empty.keys().next().is_some()
            || ifb.map_type() != MapType::Array
            || ifb.key_size() != 4
            || ifb.value_size() != 4
            || ifb.max_entries() != 1
            || ingress_ports.map_type() != MapType::Hash
            || ingress_ports.key_size() != 4
            || ingress_ports.value_size() != 1
            || ingress_ports.max_entries() != 32
            || roots.map_type() != MapType::Hash
            || roots.key_size() != 4
            || roots.value_size() != 1
            || roots.max_entries() != 32
            || counters.map_type() != MapType::Array
            || counters.key_size() != 4
            || counters.value_size() != 16
            || counters.max_entries() != 8
            || !internal_prefix_map_abi(&internal_v4)
            || !internal_prefix_map_abi(&internal_v6)
        {
            bail!("priority_map_abi_mismatch");
        }
        empty.freeze().context("freeze initial empty client map")?;
        let maps = Self {
            outer,
            active: empty,
            ifb,
            ingress_ports,
            roots,
            counters,
            internal_v4,
            internal_v6,
            configured_internal_v4: false,
            configured_internal_v6: false,
            poisoned: false,
        };
        if maps.published_id()? != maps.active.info()?.info.id {
            bail!("priority_map_ownership_changed: initial client map is not the loaded template");
        }
        Ok(maps)
    }

    pub(super) fn configure_internal_networks(
        &mut self,
        config: &crate::config::AgentConfig,
    ) -> Result<()> {
        if self.configured_internal_v4 || self.configured_internal_v6 {
            bail!("priority_internal_networks_already_configured");
        }
        let configured = config
            .topology_networks
            .iter()
            .filter(|network| matches!(network.role.as_str(), "lan" | "routed_lan" | "tunnel"))
            .map(|network| network.subnet.as_str())
            .collect::<Vec<_>>();
        let mut v4 = BTreeSet::new();
        let mut v6 = BTreeSet::new();
        for prefix in [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
        ]
        .into_iter()
        .chain(configured.iter().copied())
        {
            let (address, prefix) = parse_network_prefix(prefix)?;
            if let IpAddr::V4(address) = address {
                let mut key = [0_u8; 20];
                key[..4].copy_from_slice(&u32::from(prefix).to_ne_bytes());
                key[4..8].copy_from_slice(&address.octets());
                v4.insert(key);
            }
        }
        for prefix in ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
            .into_iter()
            .chain(configured.iter().copied())
        {
            let (address, prefix) = parse_network_prefix(prefix)?;
            if let IpAddr::V6(address) = address {
                let mut key = [0_u8; 20];
                key[..4].copy_from_slice(&u32::from(prefix).to_ne_bytes());
                key[4..20].copy_from_slice(&address.octets());
                v6.insert(key);
            }
        }
        self.configured_internal_v4 = configured.iter().any(|prefix| {
            prefix
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_ipv4())
                || prefix.split_once('/').is_some_and(|(address, _)| {
                    address.parse::<IpAddr>().is_ok_and(|a| a.is_ipv4())
                })
        });
        self.configured_internal_v6 = configured.iter().any(|prefix| {
            prefix
                .split_once('/')
                .is_some_and(|(address, _)| address.parse::<IpAddr>().is_ok_and(|a| a.is_ipv6()))
        });
        if v4.len() > 256 || v6.len() > 256 {
            bail!("priority_internal_networks_limit_exceeded");
        }
        publish_prefixes(&self.internal_v4, &v4)?;
        publish_prefixes(&self.internal_v6, &v6)?;
        Ok(())
    }

    pub(super) fn client_block_networks_ready(&self) -> bool {
        self.configured_internal_v4 && self.configured_internal_v6
    }

    pub(super) fn prepare(&self, entries: Vec<ClientMapEntry>) -> Result<PreparedClients> {
        if self.poisoned || entries.len() > 256 {
            bail!("priority_map_unavailable_or_full");
        }
        let mut macs = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut encoded = Vec::new();
        let generation = entries.first().map(|entry| entry.generation);
        let now = super::monotonic_ns();
        if now == 0 {
            bail!("priority_clock_unavailable");
        }
        for entry in &entries {
            if entry.expires_ns <= now {
                bail!("priority_map_expired: refusing an inactive budget");
            }
            if !macs.insert(entry.mac.clone())
                || !slots.insert(entry.slot)
                || Some(entry.generation) != generation
            {
                bail!("priority_map_invalid: duplicate client or class slot");
            }
            encoded.push(entry.bytes()?);
        }
        let mut options = super::map_options::map_create_options();
        options.map_flags = libbpf_rs::libbpf_sys::BPF_F_RDONLY_PROG;
        // Reuse the loaded template's exact BTF. On 6.1, map-in-map metadata
        // includes the timer offset: typed structs without a timer and maps
        // without BTF have different negative sentinel values. Matching only
        // key/value sizes and flags is insufficient for kernel publication.
        let template = self.active.info()?.info;
        if template.btf_id == 0 || template.btf_key_type_id == 0 || template.btf_value_type_id == 0
        {
            bail!("priority_map_abi_mismatch: template BTF is required");
        }
        let btf = template_btf_fd(template.btf_id)?;
        options.btf_fd = u32::try_from(btf.as_raw_fd())?;
        options.btf_key_type_id = template.btf_key_type_id;
        options.btf_value_type_id = template.btf_value_type_id;
        let map = MapHandle::create(MapType::Hash, Some("nqm_clients"), 8, 32, 256, &options)
            .context("create replacement client map")?;
        for (key, value) in &encoded {
            map.update(key, value, MapFlags::NO_EXIST)?;
        }
        if map.keys().count() != encoded.len() {
            bail!("priority_map_readback_failed: entry count");
        }
        for (key, value) in encoded {
            if map.lookup(&key, MapFlags::ANY)?.as_deref() != Some(value.as_slice()) {
                bail!("priority_map_readback_failed: client assignment");
            }
        }
        map.freeze().context("freeze prepared client assignments")?;
        Ok(PreparedClients { map, entries })
    }

    /// Retains a prior map FD for transaction rollback. Never edits active entries.
    pub(super) fn publish(&mut self, next: &PreparedClients) -> Result<MapHandle> {
        if self.poisoned || self.published_id()? != self.active.info()?.info.id {
            bail!("priority_map_ownership_changed: refusing publication");
        }
        let previous = MapHandle::try_from(&self.active)?;
        let next_handle = MapHandle::try_from(&next.map)?;
        let outcome = self.set_outer(&next_handle);
        if let Err(error) = outcome {
            if let Err(rollback) = self.set_outer(&previous) {
                self.poisoned = true;
                bail!("priority_map_rollback_failed: {error:#}; {rollback:#}");
            }
            return Err(error);
        }
        self.active = next_handle;
        Ok(previous)
    }

    pub(super) fn restore(&mut self, previous: &MapHandle) -> Result<()> {
        if self.poisoned || self.published_id()? != self.active.info()?.info.id {
            bail!("priority_map_ownership_changed: rollback requires verified active ownership");
        }
        if !client_map_abi(previous) {
            bail!("priority_map_abi_mismatch: rollback map");
        }
        let retained = MapHandle::try_from(previous)?;
        if let Err(error) = self.set_outer(&retained) {
            self.poisoned = true;
            return Err(error).context("priority_map_rollback_failed");
        }
        self.active = retained;
        self.poisoned = false;
        Ok(())
    }

    /// Atomically stop all client assignment lookups while preserving the
    /// owned IFB/root configuration needed to send every packet to bypass.
    pub(super) fn publish_empty(&mut self) -> Result<()> {
        let empty = self.prepare(Vec::new())?;
        let _previous = self.publish(&empty)?;
        Ok(())
    }

    fn set_outer(&self, map: &MapHandle) -> Result<()> {
        let fd = u32::try_from(map.as_fd().as_raw_fd())?;
        self.outer
            .update(&0_u32.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| {
                format!(
                    "publish client map FD {fd} (inner flags {}, template flags {})",
                    map.info().map(|i| i.info.map_flags).unwrap_or(0),
                    self.active.info().map(|i| i.info.map_flags).unwrap_or(0)
                )
            })?;
        if self.published_id()? != map.info()?.info.id {
            bail!("priority_map_readback_failed: published map ID");
        }
        Ok(())
    }

    pub(super) fn published_id(&self) -> Result<u32> {
        let value = self
            .outer
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
            .context("active client map missing")?;
        Ok(u32::from_ne_bytes(
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid outer map value"))?,
        ))
    }

    /// Run only before attaching hooks, inside the validated private path
    /// fixture. Exercises actual kernel publication without activating a budget.
    pub(super) fn verify_idle_publication(&mut self) -> Result<serde_json::Value> {
        if self.active.keys().next().is_some()
            || self.ingress_ports.keys().next().is_some()
            || self.roots.keys().next().is_some()
            || self
                .ifb
                .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
                .as_deref()
                != Some(&[0, 0, 0, 0])
        {
            bail!("priority_map_probe_requires_inactive_configuration");
        }
        let original_id = self.published_id()?;
        let prepared = self.prepare(Vec::new())?;
        let prepared_id = prepared.map.info()?.info.id;
        verify_frozen(&self.active)?;
        verify_frozen(&prepared.map)?;
        let previous = self.publish(&prepared)?;
        let published_id = self.published_id()?;
        self.restore(&previous)?;
        let restored_id = self.published_id()?;
        if published_id != prepared_id
            || restored_id != original_id
            || original_id == prepared_id
            || self.active.keys().next().is_some()
        {
            bail!("priority_map_probe_readback_failed");
        }
        Ok(serde_json::json!({
            "kind":"empty_map_publication_not_policy_acceptance",
            "outer_map_id":self.outer.info()?.info.id,
            "original_map_id":original_id,"prepared_map_id":prepared_id,
            "published_map_id":published_id,"restored_map_id":restored_id,
            "initial_and_prepared_updates_denied":true,"active_client_count":0,
            "ifb_configured":false,"ingress_ports":0,"managed_roots":0,
        }))
    }

    pub(super) fn idle_snapshot(&self) -> Result<serde_json::Value> {
        let names = [
            "upload_classified",
            "upload_redirected",
            "download_classified",
            "lan_bypass",
            "invalid_classid",
            "delivery_port_mismatch",
            "upload_class_egress_bypassed",
            "client_block_drop",
        ];
        let mut counters = Vec::new();
        for slot in 0_u32..8 {
            let value = self
                .counters
                .lookup(&slot.to_ne_bytes(), MapFlags::ANY)?
                .context("priority counter missing")?;
            counters.push(serde_json::json!({"slot":slot,"name":names[slot as usize],
                "packets":u64::from_ne_bytes(value[..8].try_into()?),
                "bytes":u64::from_ne_bytes(value[8..16].try_into()?),
            }));
        }
        let ifb = self
            .ifb
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
            .context("priority IFB configuration missing")?;
        Ok(serde_json::json!({
            "kind":"idle_priority_configuration_not_policy_acceptance",
            "counter_map_id":self.counters.info()?.info.id,
            "published_map_id":self.published_id()?,
            "retained_map_id":self.active.info()?.info.id,
            "active_client_count":self.active.keys().count(),
            "ifb_ifindex":u32::from_ne_bytes(ifb.try_into().map_err(|_| anyhow::anyhow!("invalid IFB map value"))?),
            "ingress_port_count":self.ingress_ports.keys().count(),
            "managed_root_count":self.roots.keys().count(),"counters":counters,
        }))
    }
}

fn verify_frozen(map: &MapHandle) -> Result<()> {
    match map.update(&[0; 8], &[0; 32], MapFlags::NO_EXIST) {
        Err(error) if error.kind() == libbpf_rs::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error).context("frozen client map returned an unexpected error"),
        Ok(()) => bail!("priority_map_not_immutable: kernel accepted a write to a frozen map"),
    }
}

#[allow(unsafe_code)]
fn template_btf_fd(id: u32) -> Result<OwnedFd> {
    // SAFETY: the ID comes from a retained live map's info. On success this
    // syscall returns a fresh owned descriptor; on failure no FD is constructed.
    let fd = unsafe { libbpf_rs::libbpf_sys::bpf_btf_get_fd_by_id(id) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open template BTF");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn client_map_abi(map: &MapHandle) -> bool {
    map.map_type() == MapType::Hash
        && map.key_size() == 8
        && map.value_size() == 32
        && map.max_entries() == 256
        && map
            .info()
            .is_ok_and(|info| info.info.map_flags & libbpf_rs::libbpf_sys::BPF_F_RDONLY_PROG != 0)
}

fn internal_prefix_map_abi(map: &MapHandle) -> bool {
    map.map_type() == MapType::LpmTrie
        && map.key_size() == 20
        && map.value_size() == 1
        && map.max_entries() == 256
        && map
            .info()
            .is_ok_and(|info| info.info.map_flags & libbpf_rs::libbpf_sys::BPF_F_NO_PREALLOC != 0)
}

fn parse_network_prefix(value: &str) -> Result<(IpAddr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("priority_internal_network_invalid: expected CIDR"))?;
    let address = address.parse::<IpAddr>()?;
    let prefix = prefix.parse::<u8>()?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        bail!("priority_internal_network_invalid: prefix exceeds address width");
    }
    Ok((address, prefix))
}

fn publish_prefixes(map: &MapHandle, prefixes: &BTreeSet<[u8; 20]>) -> Result<()> {
    for key in prefixes {
        map.update(key, &[1], MapFlags::NO_EXIST)
            .context("publish configured internal network prefix")?;
        if map.lookup(key, MapFlags::ANY)?.as_deref() != Some(&[1]) {
            bail!("priority_internal_network_readback_failed");
        }
    }
    if map.keys().count() != prefixes.len() {
        bail!("priority_internal_network_readback_failed: prefix count");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_assignment_matches_bpf_key_value_layout_and_rejects_direct_targets() {
        let lease = ClientSlotLease {
            mac: "02:00:00:00:00:01".to_owned(),
            slot: 255,
            active: true,
        };
        let entry = ClientMapEntry::new(&lease, 123, true, true, false, 7, 123456).unwrap();
        let (key, value) = entry.bytes().unwrap();
        assert_eq!(key, [2, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(u32::from_ne_bytes(value[..4].try_into().unwrap()), 255);
        assert_eq!(u32::from_ne_bytes(value[4..8].try_into().unwrap()), 123);
        assert_eq!(u32::from_ne_bytes(value[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_ne_bytes(value[12..16].try_into().unwrap()), 7);
        assert_eq!(
            u64::from_ne_bytes(value[16..24].try_into().unwrap()),
            123456
        );
        assert_eq!(
            u32::from_ne_bytes(value[24..28].try_into().unwrap()),
            0x005202ff
        );
        assert_eq!(
            u32::from_ne_bytes(value[28..32].try_into().unwrap()),
            0x005102ff
        );
        for raw in [0, 0x00510001, 0x005101ff, 0x0052ffff] {
            let mut bad = entry.clone();
            bad.download_classid = raw;
            assert!(bad.bytes().is_err());
        }
        assert!(ClientMapEntry::new(&lease, 0, true, true, false, 7, 123456).is_err());
    }

    #[test]
    fn client_block_flag_is_independent_of_rate_budget_and_validates_canonical_classids() {
        let lease = ClientSlotLease {
            mac: "02:00:00:00:00:01".to_owned(),
            slot: 0,
            active: true,
        };
        let entry = ClientMapEntry::new(&lease, 0, false, false, true, 8, 123456).unwrap();
        let (_, value) = entry.bytes().unwrap();
        assert_eq!(u32::from_ne_bytes(value[8..12].try_into().unwrap()), 4);
    }

    #[test]
    fn internal_network_prefixes_are_family_checked_and_bounded() {
        assert_eq!(
            parse_network_prefix("192.0.2.0/24").unwrap(),
            ("192.0.2.0".parse().unwrap(), 24)
        );
        assert_eq!(
            parse_network_prefix("fd42:1::/64").unwrap(),
            ("fd42:1::".parse().unwrap(), 64)
        );
        assert!(parse_network_prefix("192.0.2.0/33").is_err());
        assert!(parse_network_prefix("fd42:1::/129").is_err());
        assert!(parse_network_prefix("192.0.2.0").is_err());
    }
}
