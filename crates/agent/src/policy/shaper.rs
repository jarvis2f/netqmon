use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const MAX_CLIENTS_PER_EGRESS: usize = 256;
const MAX_CLASS_TAG: u16 = MAX_CLIENTS_PER_EGRESS as u16;
pub(super) const MAX_APPLICATION_CLASSES_PER_EGRESS: usize = 4_096;
const FIRST_APPLICATION_TAG: u16 = 1;
pub(super) const MAX_APPLICATION_TAG: u16 = 0x7f;
const FIRST_APPLICATION_CLASS_MINOR: u16 = 2_000;
const FIRST_APPLICATION_LEAF_MINOR: u16 = 20_000;
pub(super) const CLIENT_MARK_SHIFT: u32 = 16;
pub(super) const CLIENT_MARK_MASK: u32 = 0x01ff_0000;
pub(super) const APPLICATION_MARK_SHIFT: u32 = 25;
pub(super) const APPLICATION_MARK_MASK: u32 = 0xfe00_0000;
// Shared egress retains the existing high-16-bit reservation. Bit 24 is
// direction, bits 16..23 are client identity; zero is each direction's fallback.
pub(super) const SHARED_DIRECTION_TAG: u16 = 0x100;
pub(super) const MAX_SHARED_CLIENTS_PER_DIRECTION: usize = 255;

pub(super) const fn client_mark_value(tag: u16) -> u32 {
    ((tag as u32) << CLIENT_MARK_SHIFT) & CLIENT_MARK_MASK
}

pub(super) const fn application_mark_value(tag: u16) -> u32 {
    ((tag as u32) << APPLICATION_MARK_SHIFT) & APPLICATION_MARK_MASK
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Direction {
    Upload,
    Download,
}

impl Direction {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientClass {
    pub gateway_id: String,
    pub mac: String,
    pub direction: Direction,
    pub interface: String,
    pub ifindex: u32,
    /// The tag occupies the lower 9 bits of NetQmon's reserved high 16 mark bits.
    pub tag: u16,
    pub class_minor: u16,
    pub leaf_minor: u16,
    pub rate_bps: u64,
    #[serde(default = "default_has_total_budget")]
    pub has_total_budget: bool,
}

fn default_has_total_budget() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationClass {
    pub policy_id: String,
    pub gateway_id: String,
    pub mac: String,
    pub direction: Direction,
    pub interface: String,
    pub ifindex: u32,
    /// The tag occupies the upper 7 bits of NetQmon's reserved high 16 mark bits.
    pub tag: u16,
    pub class_minor: u16,
    pub parent_class_minor: u16,
    pub rate_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedInterface {
    #[serde(default, skip_serializing_if = "is_dedicated_egress")]
    pub shared_egress: bool,
    pub name: String,
    pub ifindex: u32,
    pub capacity_bps: u64,
    pub original_root_kind: String,
    pub clients: Vec<ClientClass>,
    #[serde(default)]
    pub application_classes: Vec<ApplicationClass>,
}

// serde's skip_serializing_if hook requires a reference argument.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_dedicated_egress(shared: &bool) -> bool {
    !shared
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShapingState {
    pub schema_version: u32,
    pub upload_interface: Option<ManagedInterface>,
    pub download_interface: Option<ManagedInterface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_egress: Option<ManagedInterface>,
}

impl ShapingState {
    pub(super) fn empty() -> Self {
        Self {
            schema_version: 1,
            upload_interface: None,
            download_interface: None,
            shared_egress: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.interfaces().next().is_none()
    }

    pub(super) fn interfaces(&self) -> impl Iterator<Item = &ManagedInterface> {
        [
            &self.upload_interface,
            &self.download_interface,
            &self.shared_egress,
        ]
        .into_iter()
        .flatten()
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.schema_version != if self.shared_egress.is_some() { 2 } else { 1 } {
            return Err("unsupported local traffic-shaping state schema".to_owned());
        }
        if self.shared_egress.is_some()
            && (self.upload_interface.is_some() || self.download_interface.is_some())
        {
            return Err("shared egress cannot coexist with dedicated direction roots".to_owned());
        }
        if self
            .shared_egress
            .as_ref()
            .is_some_and(|interface| !interface.shared_egress)
            || [&self.upload_interface, &self.download_interface]
                .into_iter()
                .flatten()
                .any(|interface| interface.shared_egress)
        {
            return Err("shaping layout does not match its physical root".to_owned());
        }
        let interfaces = self.interfaces();
        let mut names = BTreeSet::new();
        for interface in interfaces {
            if interface.name.is_empty()
                || interface.name.len() > 15
                || interface.ifindex == 0
                || !(64_000..=1_000_000_000).contains(&interface.capacity_bps)
                || !matches!(
                    interface.original_root_kind.as_str(),
                    "" | "fq_codel" | "pfifo_fast" | "noqueue"
                )
                || !names.insert(interface.name.as_str())
                || interface.clients.len()
                    > if interface.shared_egress {
                        2 * MAX_SHARED_CLIENTS_PER_DIRECTION
                    } else {
                        MAX_CLIENTS_PER_EGRESS
                    }
            {
                return Err(
                    "local traffic-shaping state contains invalid interface metadata".to_owned(),
                );
            }
            let mut tags = BTreeSet::new();
            let mut classes = BTreeSet::new();
            for client in &interface.clients {
                if client.gateway_id.is_empty()
                    || client.mac.len() != 17
                    || client.ifindex != interface.ifindex
                    || client.interface != interface.name
                    || !valid_client_tag(client, interface.shared_egress)
                    || client.class_minor != client_class_minor(client.tag, interface.shared_egress)
                    || client.leaf_minor != 1_000 + client.tag
                    || !(64_000..=1_000_000_000).contains(&client.rate_bps)
                    || (interface.shared_egress && client.rate_bps > interface.capacity_bps)
                    || !tags.insert(client.tag)
                    || !classes.insert(client.class_minor)
                {
                    return Err(
                        "local traffic-shaping state contains invalid client assignments"
                            .to_owned(),
                    );
                }
            }
            let clients_by_class = interface
                .clients
                .iter()
                .map(|client| (client.class_minor, client))
                .collect::<BTreeMap<_, _>>();
            if interface.application_classes.len() > MAX_APPLICATION_CLASSES_PER_EGRESS {
                return Err(
                    "local traffic-shaping state exceeds the application class limit".to_owned(),
                );
            }
            let mut application_tags = BTreeSet::new();
            let mut application_keys = BTreeSet::new();
            for application in &interface.application_classes {
                let Some(parent) = clients_by_class.get(&application.parent_class_minor) else {
                    return Err(
                        "local traffic-shaping state contains an orphan application class"
                            .to_owned(),
                    );
                };
                if !(FIRST_APPLICATION_TAG..=MAX_APPLICATION_TAG).contains(&application.tag) {
                    return Err(
                        "local traffic-shaping state contains an invalid application class"
                            .to_owned(),
                    );
                }
                if application.policy_id.is_empty()
                    || application.gateway_id != parent.gateway_id
                    || application.mac != parent.mac
                    || application.direction != parent.direction
                    || application.interface != interface.name
                    || application.ifindex != interface.ifindex
                    || !(FIRST_APPLICATION_CLASS_MINOR
                        ..FIRST_APPLICATION_CLASS_MINOR + MAX_APPLICATION_CLASSES_PER_EGRESS as u16)
                        .contains(&application.class_minor)
                    || !(64_000..=1_000_000_000).contains(&application.rate_bps)
                    || application.rate_bps > parent.rate_bps
                    || !application_tags.insert((application.parent_class_minor, application.tag))
                    || !application_keys.insert((
                        application.policy_id.as_str(),
                        application.mac.as_str(),
                        application.direction,
                    ))
                    || !classes.insert(application.class_minor)
                {
                    return Err(
                        "local traffic-shaping state contains an invalid application class"
                            .to_owned(),
                    );
                }
            }
            let application_parents = interface
                .application_classes
                .iter()
                .map(|application| application.parent_class_minor)
                .collect::<BTreeSet<_>>();
            for parent_minor in application_parents {
                let parent = clients_by_class[&parent_minor];
                let default_class_minor = default_class_minor(parent.tag);
                if !classes.insert(default_class_minor) {
                    return Err(
                        "local traffic-shaping state contains duplicate default classes".to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

fn valid_client_tag(client: &ClientClass, shared: bool) -> bool {
    if !shared {
        return (1..=MAX_CLASS_TAG).contains(&client.tag);
    }
    client.tag < 512
        && client.tag & 0xff != 0
        && (client.tag & SHARED_DIRECTION_TAG != 0) == (client.direction == Direction::Download)
}

pub(super) const fn client_class_minor(tag: u16, shared: bool) -> u16 {
    if shared && tag & SHARED_DIRECTION_TAG != 0 {
        1_000 + (tag & 0xff)
    } else {
        100 + tag
    }
}

pub(super) fn allocate_shared_client_classes(
    gateway_id: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
    rates: &BTreeMap<String, u64>,
    previous: &[ClientClass],
) -> Result<Vec<ClientClass>, String> {
    if rates.len() > MAX_SHARED_CLIENTS_PER_DIRECTION {
        return Err(
            "unsupported_client_limit: shared egress supports 255 clients per direction".to_owned(),
        );
    }
    let logical_previous = previous
        .iter()
        .filter(|client| client.direction == direction && valid_client_tag(client, true))
        .cloned()
        .map(|mut client| {
            client.tag &= 0xff;
            client
        })
        .collect::<Vec<_>>();
    let mut clients = allocate_classes(
        gateway_id,
        direction,
        interface,
        ifindex,
        rates,
        &logical_previous,
    )?;
    let mut used = clients
        .iter()
        .map(|client| client.tag)
        .collect::<BTreeSet<_>>();
    for client in &mut clients {
        if client.tag == 256 {
            client.tag = (1..256)
                .find(|tag| !used.contains(tag))
                .ok_or_else(|| "shared egress client tag space exhausted".to_owned())?;
            used.insert(client.tag);
        }
        if direction == Direction::Download {
            client.tag |= SHARED_DIRECTION_TAG;
        }
        client.class_minor = client_class_minor(client.tag, true);
        client.leaf_minor = 1_000 + client.tag;
    }
    Ok(clients)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ClientRates {
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
}

impl ClientRates {
    pub(super) fn add_limit(&mut self, upload_bps: Option<u64>, download_bps: Option<u64>) {
        self.upload_bps = min_rate(self.upload_bps, upload_bps);
        self.download_bps = min_rate(self.download_bps, download_bps);
    }
}

pub(super) fn min_rate(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(rate), None) | (None, Some(rate)) => Some(rate),
        (None, None) => None,
    }
}

pub(super) fn allocate_classes(
    gateway_id: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
    rates: &BTreeMap<String, u64>,
    previous: &[ClientClass],
) -> Result<Vec<ClientClass>, String> {
    if rates.len() > MAX_CLIENTS_PER_EGRESS {
        return Err(
            "unsupported_client_limit: at most 256 client budgets are allowed per egress"
                .to_owned(),
        );
    }
    if rates
        .values()
        .any(|rate| !(64_000..=1_000_000_000).contains(rate))
    {
        return Err(
            "invalid_client_rate: client rates must be between 64000 and 1000000000 bps".to_owned(),
        );
    }

    let mut assigned = BTreeMap::<String, u16>::new();
    let mut occupied = BTreeSet::<u16>::new();
    for prior in previous {
        if prior.gateway_id != gateway_id
            || prior.direction != direction
            || prior.interface != interface
            || prior.ifindex != ifindex
            || !rates.contains_key(&prior.mac)
            || !(1..=MAX_CLASS_TAG).contains(&prior.tag)
        {
            continue;
        }
        if !occupied.insert(prior.tag) {
            return Err(
                "degraded_ownership_conflict: saved client class tags are duplicated".to_owned(),
            );
        }
        assigned.insert(prior.mac.clone(), prior.tag);
    }

    for mac in rates.keys() {
        if assigned.contains_key(mac) {
            continue;
        }
        let first = initial_tag(gateway_id, mac, direction, interface, ifindex);
        let tag = (0..MAX_CLASS_TAG)
            .map(|offset| {
                ((u32::from(first) - 1 + u32::from(offset)) % u32::from(MAX_CLASS_TAG) + 1) as u16
            })
            .find(|candidate| !occupied.contains(candidate))
            .ok_or_else(|| {
                "unsupported_client_limit: no collision-free class tag is available".to_owned()
            })?;
        occupied.insert(tag);
        assigned.insert(mac.clone(), tag);
    }

    Ok(rates
        .iter()
        .map(|(mac, rate_bps)| {
            let tag = assigned[mac];
            ClientClass {
                gateway_id: gateway_id.to_owned(),
                mac: mac.clone(),
                direction,
                interface: interface.to_owned(),
                ifindex,
                tag,
                class_minor: 100 + tag,
                leaf_minor: 1_000 + tag,
                rate_bps: *rate_bps,
                has_total_budget: true,
            }
        })
        .collect())
}

pub(super) fn allocate_application_classes(
    gateway_id: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
    rates: &BTreeMap<(String, String), u64>,
    clients: &[ClientClass],
    previous: &[ApplicationClass],
) -> Result<Vec<ApplicationClass>, String> {
    allocate_application_classes_reserved(
        gateway_id,
        direction,
        interface,
        ifindex,
        rates,
        clients,
        previous,
        &BTreeSet::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn allocate_application_classes_reserved(
    gateway_id: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
    rates: &BTreeMap<(String, String), u64>,
    clients: &[ClientClass],
    previous: &[ApplicationClass],
    reserved_minors: &BTreeSet<u16>,
) -> Result<Vec<ApplicationClass>, String> {
    if rates.len() > MAX_APPLICATION_CLASSES_PER_EGRESS {
        return Err(
            "unsupported_application_limit: at most 4096 application budgets are allowed per egress"
                .to_owned(),
        );
    }
    if rates
        .values()
        .any(|rate| !(64_000..=1_000_000_000).contains(rate))
    {
        return Err(
            "invalid_application_rate: application rates must be between 64000 and 1000000000 bps"
                .to_owned(),
        );
    }

    let parents = clients
        .iter()
        .filter(|client| client.direction == direction)
        .map(|client| (client.mac.as_str(), client))
        .collect::<BTreeMap<_, _>>();
    let mut assigned = BTreeMap::<(String, String), u16>::new();
    let mut occupied = BTreeMap::<u16, BTreeSet<u16>>::new();
    let mut assigned_minors = BTreeMap::<(String, String), u16>::new();
    let mut occupied_minors = reserved_minors.clone();
    for prior in previous {
        let key = (prior.policy_id.clone(), prior.mac.clone());
        let Some(parent) = parents.get(prior.mac.as_str()) else {
            continue;
        };
        if prior.gateway_id != gateway_id
            || prior.direction != direction
            || prior.interface != interface
            || prior.ifindex != ifindex
            || !rates.contains_key(&key)
            || prior.parent_class_minor != parent.class_minor
            || !(FIRST_APPLICATION_TAG..=MAX_APPLICATION_TAG).contains(&prior.tag)
        {
            continue;
        }
        if !occupied
            .entry(parent.class_minor)
            .or_default()
            .insert(prior.tag)
        {
            return Err(
                "degraded_ownership_conflict: saved application class tags are duplicated"
                    .to_owned(),
            );
        }
        if !(FIRST_APPLICATION_CLASS_MINOR
            ..FIRST_APPLICATION_CLASS_MINOR + MAX_APPLICATION_CLASSES_PER_EGRESS as u16)
            .contains(&prior.class_minor)
            || !occupied_minors.insert(prior.class_minor)
        {
            return Err(
                "degraded_ownership_conflict: saved application class IDs are invalid or duplicated"
                    .to_owned(),
            );
        }
        assigned.insert(key, prior.tag);
        assigned_minors.insert(
            (prior.policy_id.clone(), prior.mac.clone()),
            prior.class_minor,
        );
    }

    for key in rates.keys() {
        if !assigned.contains_key(key) {
            let parent = parents.get(key.1.as_str()).ok_or_else(|| {
                "invalid_application_parent: application class has no client parent class"
                    .to_owned()
            })?;
            let first =
                initial_application_tag(gateway_id, &key.0, &key.1, direction, interface, ifindex);
            let tags_for_parent = occupied.entry(parent.class_minor).or_default();
            let tag = (0..MAX_APPLICATION_TAG)
                .map(|offset| (first - 1 + offset) % MAX_APPLICATION_TAG + 1)
                .find(|candidate| !tags_for_parent.contains(candidate))
                .ok_or_else(|| {
                    "unsupported_application_limit: a client cannot own more than 127 application budgets"
                        .to_owned()
                })?;
            tags_for_parent.insert(tag);
            assigned.insert(key.clone(), tag);
        }
        if !assigned_minors.contains_key(key) {
            let first = initial_application_class_minor(
                gateway_id, &key.0, &key.1, direction, interface, ifindex,
            );
            let class_minor = (0..MAX_APPLICATION_CLASSES_PER_EGRESS as u16)
                .map(|offset| {
                    FIRST_APPLICATION_CLASS_MINOR
                        + ((first - FIRST_APPLICATION_CLASS_MINOR + offset)
                            % MAX_APPLICATION_CLASSES_PER_EGRESS as u16)
                })
                .find(|candidate| !occupied_minors.contains(candidate))
                .ok_or_else(|| {
                    "unsupported_application_limit: no collision-free application class ID is available"
                        .to_owned()
                })?;
            occupied_minors.insert(class_minor);
            assigned_minors.insert(key.clone(), class_minor);
        }
    }

    rates
        .iter()
        .map(|((policy_id, mac), rate_bps)| {
            let parent = parents.get(mac.as_str()).ok_or_else(|| {
                "invalid_application_parent: application class has no client parent class"
                    .to_owned()
            })?;
            if *rate_bps > parent.rate_bps {
                return Err(
                    "invalid_application_rate: application budget exceeds its client parent rate"
                        .to_owned(),
                );
            }
            let tag = assigned[&(policy_id.clone(), mac.clone())];
            Ok(ApplicationClass {
                policy_id: policy_id.clone(),
                gateway_id: gateway_id.to_owned(),
                mac: mac.clone(),
                direction,
                interface: interface.to_owned(),
                ifindex,
                tag,
                class_minor: assigned_minors[&(policy_id.clone(), mac.clone())],
                parent_class_minor: parent.class_minor,
                rate_bps: *rate_bps,
            })
        })
        .collect()
}

pub(super) const fn default_class_minor(client_tag: u16) -> u16 {
    400 + client_tag
}

pub(super) fn application_leaf_minor(class_minor: u16) -> u16 {
    FIRST_APPLICATION_LEAF_MINOR + (class_minor - FIRST_APPLICATION_CLASS_MINOR)
}

pub(super) fn burst_bytes(rate_bps: u64) -> u64 {
    // HTB receives a 100 ms token budget. Keep small classes above a frame and
    // cap the value to a size accepted by the kernel's rate tables.
    (rate_bps / 80).clamp(2_000, 16 * 1024 * 1024)
}

fn initial_tag(
    gateway_id: &str,
    mac: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
) -> u16 {
    let digest = Sha256::digest(format!(
        "netqmon-policy-class-v1\0{gateway_id}\0{mac}\0{}\0{interface}\0{ifindex}",
        direction.as_str()
    ));
    let seed = u16::from_be_bytes([digest[0], digest[1]]) % MAX_CLASS_TAG;
    seed + 1
}

fn initial_application_tag(
    gateway_id: &str,
    policy_id: &str,
    mac: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
) -> u16 {
    let digest = Sha256::digest(format!(
        "netqmon-application-class-v1\0{gateway_id}\0{policy_id}\0{mac}\0{}\0{interface}\0{ifindex}",
        direction.as_str()
    ));
    let seed = u16::from_be_bytes([digest[0], digest[1]]);
    seed % MAX_APPLICATION_TAG + 1
}

fn initial_application_class_minor(
    gateway_id: &str,
    policy_id: &str,
    mac: &str,
    direction: Direction,
    interface: &str,
    ifindex: u32,
) -> u16 {
    let digest = Sha256::digest(format!(
        "netqmon-application-class-id-v1\0{gateway_id}\0{policy_id}\0{mac}\0{}\0{interface}\0{ifindex}",
        direction.as_str()
    ));
    let seed = u16::from_be_bytes([digest[0], digest[1]]);
    FIRST_APPLICATION_CLASS_MINOR + (seed % MAX_APPLICATION_CLASSES_PER_EGRESS as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_rates_do_not_create_zero_budget_and_overlaps_use_the_minimum() {
        let mut rates = ClientRates::default();
        rates.add_limit(Some(5_000_000), None);
        rates.add_limit(Some(8_000_000), Some(10_000_000));
        rates.add_limit(None, Some(3_000_000));
        assert_eq!(rates.upload_bps, Some(5_000_000));
        assert_eq!(rates.download_bps, Some(3_000_000));
        assert!(rates.upload_bps.is_some() || rates.download_bps.is_some());
        assert_eq!(min_rate(None, None), None);
    }

    #[test]
    fn allocates_distinct_stable_tags_for_each_client_and_preserves_saved_tags() {
        let rates = BTreeMap::from([
            ("aa:bb:cc:dd:ee:ff".to_owned(), 5_000_000),
            ("00:11:22:33:44:55".to_owned(), 3_000_000),
        ]);
        let first = allocate_classes("gw-1", Direction::Upload, "wan0", 2, &rates, &[]).unwrap();
        assert_ne!(first[0].tag, first[1].tag);
        let extended = BTreeMap::from([
            ("aa:bb:cc:dd:ee:ff".to_owned(), 4_000_000),
            ("00:11:22:33:44:55".to_owned(), 3_000_000),
            ("12:34:56:78:9a:bc".to_owned(), 1_000_000),
        ]);
        let second =
            allocate_classes("gw-1", Direction::Upload, "wan0", 2, &extended, &first).unwrap();
        for prior in &first {
            let updated = second.iter().find(|item| item.mac == prior.mac).unwrap();
            assert_eq!(updated.tag, prior.tag);
            assert_eq!(updated.class_minor, prior.class_minor);
        }
        let repeat = allocate_classes("gw-1", Direction::Upload, "wan0", 2, &rates, &[]).unwrap();
        assert_eq!(first, repeat);
    }

    #[test]
    fn rejects_rates_outside_the_wire_contract_and_more_than_256_clients() {
        assert!(
            allocate_classes(
                "gw-1",
                Direction::Upload,
                "wan0",
                2,
                &BTreeMap::from([("aa:bb:cc:dd:ee:ff".to_owned(), 63_999)]),
                &[],
            )
            .is_err()
        );
        let many = (0..257)
            .map(|index| (format!("{index:012x}"), 64_000))
            .collect::<BTreeMap<_, _>>();
        assert!(allocate_classes("gw-1", Direction::Upload, "wan0", 2, &many, &[]).is_err());
    }

    #[test]
    fn allocates_stable_application_tags_and_classes_under_client_parent() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let clients = allocate_classes(
            "gw-1",
            Direction::Upload,
            "wan0",
            2,
            &BTreeMap::from([(mac.clone(), 8_000_000)]),
            &[],
        )
        .unwrap();
        let rates = BTreeMap::from([
            (("policy-a".to_owned(), mac.clone()), 5_000_000),
            (("policy-b".to_owned(), mac.clone()), 3_000_000),
        ]);
        let first = allocate_application_classes(
            "gw-1",
            Direction::Upload,
            "wan0",
            2,
            &rates,
            &clients,
            &[],
        )
        .unwrap();
        assert!(
            first
                .iter()
                .all(|class| (1..=MAX_APPLICATION_TAG).contains(&class.tag))
        );
        assert!(
            first
                .iter()
                .all(|class| class.parent_class_minor == clients[0].class_minor)
        );
        assert_ne!(first[0].tag, first[1].tag);
        assert_ne!(first[0].class_minor, first[1].class_minor);
        let repeated = allocate_application_classes(
            "gw-1",
            Direction::Upload,
            "wan0",
            2,
            &rates,
            &clients,
            &first,
        )
        .unwrap();
        assert_eq!(first, repeated);
    }

    #[test]
    fn rejects_application_classes_without_a_parent_or_above_parent_rate() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let rates = BTreeMap::from([(("policy-a".to_owned(), mac.clone()), 9_000_000)]);
        let clients = allocate_classes(
            "gw-1",
            Direction::Upload,
            "wan0",
            2,
            &BTreeMap::from([(mac.clone(), 8_000_000)]),
            &[],
        )
        .unwrap();
        assert!(
            allocate_application_classes(
                "gw-1",
                Direction::Upload,
                "wan0",
                2,
                &rates,
                &clients,
                &[],
            )
            .is_err()
        );
        assert!(
            allocate_application_classes(
                "gw-1",
                Direction::Upload,
                "wan0",
                2,
                &BTreeMap::from([(("policy-a".to_owned(), mac), 7_000_000)]),
                &[],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn packs_client_and_application_selectors_inside_reserved_high_mark_bits() {
        assert_eq!(client_mark_value(1), 0x0001_0000);
        assert_eq!(client_mark_value(256), 0x0100_0000);
        assert_eq!(application_mark_value(1), 0x0200_0000);
        assert_eq!(application_mark_value(MAX_APPLICATION_TAG), 0xfe00_0000);
        assert_eq!(CLIENT_MARK_MASK | APPLICATION_MARK_MASK, 0xffff_0000);
        assert_eq!(
            client_mark_value(256) | application_mark_value(127),
            0xff00_0000
        );
    }

    #[test]
    fn rejects_more_than_127_application_budgets_for_one_client() {
        let mac = "aa:bb:cc:dd:ee:ff".to_owned();
        let clients = allocate_classes(
            "gw-1",
            Direction::Upload,
            "wan0",
            2,
            &BTreeMap::from([(mac.clone(), 1_000_000_000)]),
            &[],
        )
        .unwrap();
        let rates = (0..128)
            .map(|index| ((format!("policy-{index}"), mac.clone()), 64_000))
            .collect::<BTreeMap<_, _>>();
        assert!(
            allocate_application_classes(
                "gw-1",
                Direction::Upload,
                "wan0",
                2,
                &rates,
                &clients,
                &[],
            )
            .unwrap_err()
            .contains("127")
        );
    }

    #[test]
    fn shared_direction_tags_are_disjoint_stable_and_reserve_both_fallbacks() {
        let rates = (0..255)
            .map(|index| {
                (
                    format!("02:00:00:00:{:02x}:{:02x}", index / 256, index % 256),
                    5_000_000,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let upload =
            allocate_shared_client_classes("gw", Direction::Upload, "one0", 2, &rates, &[])
                .unwrap();
        let download =
            allocate_shared_client_classes("gw", Direction::Download, "one0", 2, &rates, &[])
                .unwrap();
        let clients = upload.iter().chain(&download).cloned().collect::<Vec<_>>();
        assert_eq!(
            clients
                .iter()
                .map(|client| client.tag)
                .collect::<BTreeSet<_>>()
                .len(),
            510
        );
        assert!(
            clients
                .iter()
                .all(|client| client.tag != 0 && client.tag != SHARED_DIRECTION_TAG)
        );
        let state = ShapingState {
            schema_version: 2,
            upload_interface: None,
            download_interface: None,
            shared_egress: Some(ManagedInterface {
                shared_egress: true,
                name: "one0".to_owned(),
                ifindex: 2,
                capacity_bps: 100_000_000,
                original_root_kind: "noqueue".to_owned(),
                clients: clients.clone(),
                application_classes: Vec::new(),
            }),
        };
        state.validate().unwrap();
        assert_eq!(state.interfaces().count(), 1);
        let updated =
            allocate_shared_client_classes("gw", Direction::Upload, "one0", 2, &rates, &clients)
                .unwrap();
        assert_eq!(upload, updated);
        let mut invalid = state.clone();
        invalid.upload_interface = state.shared_egress.clone();
        assert!(invalid.validate().is_err());
        invalid = state.clone();
        invalid.shared_egress.as_mut().unwrap().clients[0].direction = Direction::Download;
        assert!(invalid.validate().is_err());
        let mut oversized = rates;
        oversized.insert("02:00:00:00:ff:ff".to_owned(), 5_000_000);
        assert!(
            allocate_shared_client_classes("gw", Direction::Upload, "one0", 2, &oversized, &[])
                .is_err()
        );
    }

    #[test]
    fn dedicated_state_keeps_legacy_json_without_shared_layout_fields() {
        let state = ShapingState {
            schema_version: 1,
            upload_interface: Some(ManagedInterface {
                shared_egress: false,
                name: "wan0".to_owned(),
                ifindex: 2,
                capacity_bps: 100_000_000,
                original_root_kind: "noqueue".to_owned(),
                clients: Vec::new(),
                application_classes: Vec::new(),
            }),
            download_interface: None,
            shared_egress: None,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert!(json.get("shared_egress").is_none());
        assert!(json["upload_interface"].get("shared_egress").is_none());
        assert_eq!(serde_json::from_value::<ShapingState>(json).unwrap(), state);
    }

    #[test]
    fn burst_budget_is_bounded_to_100ms_and_at_least_one_frame() {
        assert_eq!(burst_bytes(64_000), 2_000);
        assert_eq!(burst_bytes(8_000_000), 100_000);
        assert_eq!(burst_bytes(1_000_000_000), 12_500_000);
    }
}
