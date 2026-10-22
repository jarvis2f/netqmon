use crate::flow::{FLOW_KEY_SIZE, FlowKey};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

use super::endpoint_block;

const VERDICT_VALUE_SIZE: usize = 64;
const POLICY_STATE_VALUE_SIZE: usize = 16;
const MAX_VERDICT_ENTRIES: usize = 16_384;
const MAX_POLICY_DROP_ENTRIES: usize = 4096;
const VERDICT_BLOCK: u8 = 1;
const VERDICT_SHAPE: u8 = 2;
pub(crate) type PolicyDropIdentity = ([u8; 16], [u8; 6]);
pub(crate) type PolicyDropCounters = BTreeMap<PolicyDropIdentity, (u64, u64)>;

#[derive(Clone, Copy)]
struct VerdictIdentity {
    flow_hash: [u8; 16],
    policy_hash: [u8; 16],
    client_mac: [u8; 6],
}

pub(crate) struct FlowVerdictWriter {
    verdict_map: Option<MapHandle>,
    endpoint_map: Option<MapHandle>,
    policy_state_map: Option<MapHandle>,
    policy_drop_map: Option<MapHandle>,
    policy_drop_map_ready: bool,
    ready: bool,
}

impl FlowVerdictWriter {
    pub(crate) fn new(
        verdict_map: MapHandle,
        endpoint_map: MapHandle,
        policy_state_map: MapHandle,
        policy_drop_map: Option<MapHandle>,
    ) -> Self {
        let ready = verdict_map.key_size() as usize == FLOW_KEY_SIZE
            && verdict_map.value_size() as usize == VERDICT_VALUE_SIZE
            && verdict_map.max_entries() as usize == MAX_VERDICT_ENTRIES
            && policy_state_map.key_size() == 4
            && policy_state_map.value_size() as usize == POLICY_STATE_VALUE_SIZE;
        let ready = ready
            && endpoint_map.key_size() as usize == endpoint_block::KEY_SIZE
            && endpoint_map.value_size() as usize == VERDICT_VALUE_SIZE
            && endpoint_map.max_entries() as usize == endpoint_block::MAX_ENTRIES;
        let policy_drop_map_ready = policy_drop_map.as_ref().is_some_and(|map| {
            policy_drop_map_abi_matches(
                map.key_size() as usize,
                map.value_size() as usize,
                map.max_entries() as usize,
            )
        });
        Self {
            verdict_map: Some(verdict_map),
            endpoint_map: Some(endpoint_map),
            policy_state_map: Some(policy_state_map),
            policy_drop_map,
            policy_drop_map_ready,
            ready,
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            verdict_map: None,
            endpoint_map: None,
            policy_state_map: None,
            policy_drop_map: None,
            policy_drop_map_ready: false,
            ready: false,
        }
    }

    #[must_use]
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn reset(&self, generation: u64, enabled: bool) -> Result<(), String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        let verdict_map = self
            .verdict_map
            .as_ref()
            .ok_or_else(|| "BPF verdict map is unavailable".to_owned())?;
        let mut errors = Vec::new();
        if let Err(error) = self.write_policy_state(false, generation) {
            errors.push(error);
        }
        let keys = verdict_map.keys().collect::<Vec<_>>();
        for key in keys {
            if let Err(error) = verdict_map.delete(&key) {
                errors.push(format!("clear BPF flow verdict: {error}"));
            }
        }
        if let Some(map) = &self.endpoint_map {
            for key in map.keys().collect::<Vec<_>>() {
                if let Err(error) = map.delete(&key) {
                    errors.push(format!("clear BPF endpoint block: {error}"));
                }
            }
        }
        let next_enabled = enabled && errors.is_empty();
        if let Err(error) = self.write_policy_state(next_enabled, generation) {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub(crate) fn install_block(
        &self,
        aliases: &[FlowKey],
        command_id: &str,
        policy_flow_id: &str,
        policy_id: &str,
        client_mac: &str,
        generation: u64,
        expires_monotonic_ns: u64,
    ) -> Result<usize, String> {
        let tagged_aliases = aliases
            .iter()
            .cloned()
            .map(|alias| (alias, 0_u32))
            .collect::<Vec<_>>();
        let identity = VerdictIdentity {
            flow_hash: flow_identity_hash(policy_flow_id)?,
            policy_hash: policy_identity_hash(policy_id),
            client_mac: client_mac_identity(client_mac)?,
        };
        self.install_verdict(
            &tagged_aliases,
            command_id,
            policy_flow_id,
            identity,
            generation,
            expires_monotonic_ns,
            VERDICT_BLOCK,
        )
    }

    pub(crate) fn remember_endpoint_blocks(
        &self,
        aliases: &[FlowKey],
        policy_flow_id: &str,
        policy_id: &str,
        client_mac: &str,
        generation: u64,
        expires_monotonic_ns: u64,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        let map = self
            .endpoint_map
            .as_ref()
            .ok_or_else(|| "BPF endpoint block map is unavailable".to_owned())?;
        let client_mac = client_mac_identity(client_mac)?;
        let value = encode_verdict(
            expires_monotonic_ns,
            generation,
            VerdictIdentity {
                flow_hash: flow_identity_hash(policy_flow_id)?,
                policy_hash: policy_identity_hash(policy_id),
                client_mac,
            },
            0,
            VERDICT_BLOCK,
        );
        let mut previous_values: Vec<([u8; endpoint_block::KEY_SIZE], Option<Vec<u8>>)> =
            Vec::new();
        for alias in aliases {
            let key = endpoint_block::key(alias, client_mac);
            let previous = map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| format!("read BPF endpoint block: {error}"))?;
            if let Err(error) = map.update(&key, &value, MapFlags::ANY) {
                let mut rollback_errors = Vec::new();
                for (key, previous) in previous_values.iter().rev() {
                    let rollback = match previous {
                        Some(value) => map.update(key, value, MapFlags::ANY),
                        None => map.delete(key),
                    };
                    if let Err(error) = rollback {
                        rollback_errors.push(error.to_string());
                    }
                }
                return Err(format!(
                    "write BPF endpoint block: {error}; rollback errors: {rollback_errors:?}"
                ));
            }
            previous_values.push((key, previous));
        }
        Ok(previous_values.len())
    }

    /// Explicit Allow invalidates the endpoint decision. Ordinary Revoke (flow
    /// end or loss of classifier evidence) must not forget a valid block lease.
    pub(crate) fn forget_endpoint_blocks(
        &self,
        aliases: &[FlowKey],
        client_mac: &str,
    ) -> Result<(), String> {
        let map = self
            .endpoint_map
            .as_ref()
            .ok_or_else(|| "BPF endpoint block map is unavailable".to_owned())?;
        let client_mac = client_mac_identity(client_mac)?;
        for alias in aliases {
            let key = endpoint_block::key(alias, client_mac);
            if map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| format!("read BPF endpoint block: {error}"))?
                .is_some()
            {
                map.delete(&key)
                    .map_err(|error| format!("delete BPF endpoint block: {error}"))?;
            }
        }
        Ok(())
    }

    pub(crate) fn install_shape(
        &self,
        aliases: &[(FlowKey, u32)],
        command_id: &str,
        policy_flow_id: &str,
        generation: u64,
        expires_monotonic_ns: u64,
    ) -> Result<usize, String> {
        if aliases
            .iter()
            .any(|(key, classid)| key.ifindex == 0 || !valid_shape_tag(key.hook, *classid))
        {
            return Err("application shape alias has no valid egress class tag".to_owned());
        }
        let identity = VerdictIdentity {
            flow_hash: flow_identity_hash(policy_flow_id)?,
            policy_hash: [0; 16],
            client_mac: [0; 6],
        };
        self.install_verdict(
            aliases,
            command_id,
            policy_flow_id,
            identity,
            generation,
            expires_monotonic_ns,
            VERDICT_SHAPE,
        )
    }

    fn install_verdict(
        &self,
        aliases: &[(FlowKey, u32)],
        command_id: &str,
        policy_flow_id: &str,
        identity: VerdictIdentity,
        generation: u64,
        expires_monotonic_ns: u64,
        verdict: u8,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        if aliases.is_empty() || aliases.len() > 8 {
            return Err("flow alias count is outside the supported range".to_owned());
        }
        if aliases.iter().any(|(key, classid)| {
            !matches!(key.ip_version, 4 | 6)
                || !matches!(key.protocol, 6 | 17)
                || !matches!(key.hook, 1 | 2)
                || key.ifindex == 0
                || (verdict == VERDICT_SHAPE && !valid_shape_tag(key.hook, *classid))
        }) {
            return Err("flow alias is not an exact supported on-wire key".to_owned());
        }
        let mut previous_values: Vec<([u8; FLOW_KEY_SIZE], Option<Vec<u8>>)> =
            Vec::with_capacity(aliases.len());
        let verdict_map = self
            .verdict_map
            .as_ref()
            .ok_or_else(|| "BPF verdict map is unavailable".to_owned())?;
        let hooks = aliases.iter().map(|(key, _)| key.hook).collect::<Vec<_>>();
        let ifindices = aliases
            .iter()
            .map(|(key, _)| key.ifindex)
            .collect::<Vec<_>>();
        for (alias, classid) in aliases {
            let key = alias.bpf_key_bytes();
            let value = encode_verdict(
                expires_monotonic_ns,
                generation,
                identity,
                *classid,
                verdict,
            );
            let previous = match verdict_map.lookup(&key, MapFlags::ANY) {
                Ok(previous) => previous,
                Err(error) => {
                    tracing::warn!(
                        target: "netqmon_agent::policy::flow_trace",
                        command_id,
                        policy_flow_id,
                        revision = generation,
                        hook = alias.hook,
                        ifindex = alias.ifindex,
                        error = %error,
                        "could not read prior BPF verdict while applying FlowCommand"
                    );
                    return Err(format!("read previous BPF flow verdict: {error}"));
                }
            };
            if let Err(error) = verdict_map.update(&key, &value, MapFlags::ANY) {
                let mut rollback_errors = Vec::new();
                for (rollback_key, previous_value) in previous_values.into_iter().rev() {
                    let rollback = match previous_value {
                        Some(previous_value) => {
                            verdict_map.update(&rollback_key, &previous_value, MapFlags::ANY)
                        }
                        None => verdict_map.delete(&rollback_key),
                    };
                    if let Err(rollback_error) = rollback {
                        rollback_errors.push(rollback_error.to_string());
                    }
                }
                let rollback_detail = if rollback_errors.is_empty() {
                    String::new()
                } else {
                    format!("; rollback failed: {}", rollback_errors.join("; "))
                };
                tracing::warn!(
                    target: "netqmon_agent::policy::flow_trace",
                    command_id,
                    policy_flow_id,
                    revision = generation,
                    hook = alias.hook,
                    ifindex = alias.ifindex,
                    error = %error,
                    rollback_failed = !rollback_errors.is_empty(),
                    "BPF verdict map update failed"
                );
                return Err(format!("write BPF flow verdict: {error}{rollback_detail}"));
            }
            previous_values.push((key, previous));
        }
        tracing::debug!(
            target: "netqmon_agent::policy::flow_trace",
            command_id,
            policy_flow_id,
            revision = generation,
            verdict,
            alias_count = previous_values.len(),
            hooks = ?hooks,
            ifindices = ?ifindices,
            "BPF verdict map updated for FlowCommand"
        );
        Ok(previous_values.len())
    }

    pub(crate) fn clear_aliases(
        &self,
        aliases: &[FlowKey],
        expected_flow_id: Option<&str>,
        command_id: &str,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        let verdict_map = self
            .verdict_map
            .as_ref()
            .ok_or_else(|| "BPF verdict map is unavailable".to_owned())?;
        let mut removed = 0;
        let expected_hash = expected_flow_id.map(flow_identity_hash).transpose()?;
        for alias in aliases {
            let key = alias.bpf_key_bytes();
            let value = verdict_map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| {
                    tracing::warn!(
                        target: "netqmon_agent::policy::flow_trace",
                        command_id,
                        policy_flow_id = expected_flow_id.unwrap_or(""),
                        hook = alias.hook,
                        ifindex = alias.ifindex,
                        error = %error,
                        "could not read BPF verdict while revoking FlowCommand"
                    );
                    format!("look up BPF flow verdict: {error}")
                })?
                .filter(|value| {
                    expected_hash.is_none_or(|expected| value.get(16..32) == Some(&expected))
                });
            if value.is_some() {
                verdict_map.delete(&key).map_err(|error| {
                    tracing::warn!(
                        target: "netqmon_agent::policy::flow_trace",
                        command_id,
                        policy_flow_id = expected_flow_id.unwrap_or(""),
                        hook = alias.hook,
                        ifindex = alias.ifindex,
                        error = %error,
                        "could not delete BPF verdict while revoking FlowCommand"
                    );
                    format!("delete BPF flow verdict: {error}")
                })?;
                removed += 1;
            }
        }
        tracing::debug!(
            target: "netqmon_agent::policy::flow_trace",
            command_id,
            policy_flow_id = expected_flow_id.unwrap_or(""),
            alias_count = aliases.len(),
            removed,
            hooks = ?aliases.iter().map(|alias| alias.hook).collect::<Vec<_>>(),
            ifindices = ?aliases.iter().map(|alias| alias.ifindex).collect::<Vec<_>>(),
            "BPF verdict aliases cleared for FlowCommand"
        );
        Ok(removed)
    }

    pub(crate) fn policy_drop_counters(&self) -> Result<PolicyDropCounters, String> {
        if !self.policy_drop_map_ready {
            return Err(
                "BPF policy drop counter map is unavailable or has an incompatible ABI".to_owned(),
            );
        }
        let map = self
            .policy_drop_map
            .as_ref()
            .ok_or_else(|| "BPF policy drop counter map is unavailable".to_owned())?;
        let mut counters = BTreeMap::new();
        for key in map.keys() {
            if key.len() != 24 {
                return Err("BPF policy drop counter key has an invalid size".to_owned());
            }
            let Some(value) = map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| format!("read BPF policy drop counter: {error}"))?
            else {
                continue;
            };
            if value.len() != 16 {
                return Err("BPF policy drop counter value has an invalid size".to_owned());
            }
            let mut identity = [0; 16];
            identity.copy_from_slice(&key[..16]);
            let mut client_mac = [0; 6];
            client_mac.copy_from_slice(&key[16..22]);
            let packets = u64::from_ne_bytes(value[0..8].try_into().expect("checked counter size"));
            let bytes = u64::from_ne_bytes(value[8..16].try_into().expect("checked counter size"));
            counters.insert((identity, client_mac), (packets, bytes));
        }
        Ok(counters)
    }

    fn write_policy_state(&self, enabled: bool, generation: u64) -> Result<(), String> {
        let key = 0_u32.to_ne_bytes();
        let value = encode_policy_state(enabled, generation);
        self.policy_state_map
            .as_ref()
            .ok_or_else(|| "BPF policy state map is unavailable".to_owned())?
            .update(&key, &value, MapFlags::ANY)
            .map_err(|error| format!("update BPF policy state: {error}"))
    }
}

fn policy_drop_map_abi_matches(key_size: usize, value_size: usize, max_entries: usize) -> bool {
    key_size == 24 && value_size == 16 && max_entries == MAX_POLICY_DROP_ENTRIES
}

fn encode_verdict(
    expires_monotonic_ns: u64,
    generation: u64,
    identity: VerdictIdentity,
    policy_tag: u32,
    verdict: u8,
) -> [u8; VERDICT_VALUE_SIZE] {
    let mut value = [0; VERDICT_VALUE_SIZE];
    value[0..8].copy_from_slice(&expires_monotonic_ns.to_ne_bytes());
    value[8..16].copy_from_slice(&generation.to_ne_bytes());
    value[16..32].copy_from_slice(&identity.flow_hash);
    value[32..48].copy_from_slice(&identity.policy_hash);
    value[48..54].copy_from_slice(&identity.client_mac);
    value[56..60].copy_from_slice(&policy_tag.to_ne_bytes());
    value[60] = verdict;
    value
}

pub(crate) fn policy_identity_hash(policy_id: &str) -> [u8; 16] {
    let digest = Sha256::digest(policy_id.as_bytes());
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}

fn valid_application_classid(hook: u8, classid: u32) -> bool {
    let major = classid >> 16;
    let minor = classid & 0xffff;
    let expected_major = match hook {
        1 => super::classid::UPLOAD_MAJOR,
        2 => super::classid::DOWNLOAD_MAJOR,
        _ => return false,
    };
    major == expected_major
        && (super::classid::APPLICATION_FIRST..=super::classid::APPLICATION_LAST).contains(&minor)
}

fn valid_shape_tag(hook: u8, tag: u32) -> bool {
    valid_application_classid(hook, tag)
        || (hook == 2 && (1..=super::shaper::MAX_APPLICATION_TAG as u32).contains(&tag))
}

fn client_mac_identity(client_mac: &str) -> Result<[u8; 6], String> {
    if client_mac.len() != 17 || !client_mac.is_ascii() {
        return Err("client MAC must contain 48 bits".to_owned());
    }
    let bytes = client_mac.as_bytes();
    let mut identity = [0; 6];
    for (index, byte) in identity.iter_mut().enumerate() {
        let start = index * 3;
        if index < 5 && bytes[start + 2] != b':' {
            return Err("client MAC is not colon-delimited hexadecimal".to_owned());
        }
        *byte = u8::from_str_radix(&client_mac[start..start + 2], 16)
            .map_err(|_| "client MAC is not hexadecimal".to_owned())?;
    }
    Ok(identity)
}

fn flow_identity_hash(policy_flow_id: &str) -> Result<[u8; 16], String> {
    if policy_flow_id.len() != 32 || !policy_flow_id.is_ascii() {
        return Err("policy flow identity must contain 128 bits".to_owned());
    }
    let mut output = [0; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&policy_flow_id[index * 2..index * 2 + 2], 16)
            .map_err(|_| "policy flow identity is not hexadecimal".to_owned())?;
    }
    Ok(output)
}

fn encode_policy_state(enabled: bool, generation: u64) -> [u8; POLICY_STATE_VALUE_SIZE] {
    let mut value = [0; POLICY_STATE_VALUE_SIZE];
    value[0] = u8::from(enabled);
    value[8..16].copy_from_slice(&generation.to_ne_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires Linux BPF privileges; run on the Debian test server"]
    fn endpoint_blocks_enforce_reconnects_and_expire_in_the_kernel() {
        use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
        let mut open_object = std::mem::MaybeUninit::uninit();
        let builder = crate::bpf::FlowSkelBuilder::default();
        let open = builder.open(&mut open_object).unwrap();
        let skeleton = open
            .load()
            .expect("kernel must verify all datapath programs");
        let writer = FlowVerdictWriter::new(
            MapHandle::try_from(&skeleton.maps.flow_verdict_map).unwrap(),
            MapHandle::try_from(&skeleton.maps.endpoint_blocks).unwrap(),
            MapHandle::try_from(&skeleton.maps.bss).unwrap(),
            Some(MapHandle::try_from(&skeleton.maps.policy_drop_counters).unwrap()),
        );
        let mac = "aa:bb:cc:dd:ee:ff";
        let flow_id = "00112233445566778899aabbccddeeff";
        for version in [4, 6] {
            for protocol in [6, 17] {
                writer.reset(7, true).unwrap();
                let mut alias = FlowKey {
                    ip_version: version,
                    protocol,
                    direction: 1,
                    hook: 1,
                    ifindex: 1,
                    source_address: [0; 16],
                    destination_address: [0; 16],
                    source_port: 50_000,
                    destination_port: 443,
                };
                if version == 4 {
                    alias.source_address[..4].copy_from_slice(&[192, 0, 2, 1]);
                    alias.destination_address[..4].copy_from_slice(&[198, 51, 100, 1]);
                } else {
                    alias.source_address = "2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets();
                    alias.destination_address = "2001:db8::2"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets();
                }
                let packet = endpoint_test_packet(&alias, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                let run_ingress = |packet: &[u8]| {
                    skeleton
                        .progs
                        .netqmon_ingress
                        .test_run(libbpf_rs::ProgramInput {
                            data_in: Some(packet),
                            ..Default::default()
                        })
                        .unwrap()
                        .return_value
                };
                assert_eq!(run_ingress(&packet), 0);
                let now = crate::linux::monotonic_ns();
                let flow_expiry = now + 30_000_000_000;
                let expiry = now + super::endpoint_block::CACHE_TTL_MS as u64 * 1_000_000;
                writer
                    .install_block(
                        &[alias.clone()],
                        "block",
                        flow_id,
                        "p-1",
                        mac,
                        7,
                        flow_expiry,
                    )
                    .unwrap();
                writer
                    .remember_endpoint_blocks(&[alias.clone()], flow_id, "p-1", mac, 7, expiry)
                    .unwrap();
                if version == 4 && protocol == 17 {
                    // Exercise real kernel time: the original UDP verdict has
                    // expired, while the independent endpoint lease still blocks.
                    std::thread::sleep(std::time::Duration::from_secs(31));
                    assert_eq!(run_ingress(&packet), 2);
                }
                // Flow end clears only the exact verdict. A fresh ephemeral
                // port still hits the independent client/endpoint lease.
                writer
                    .clear_aliases(&[alias.clone()], Some(flow_id), "revoke")
                    .unwrap();
                let mut reconnect = alias.clone();
                reconnect.source_port = 60_000;
                let reconnect_packet =
                    endpoint_test_packet(&reconnect, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(run_ingress(&reconnect_packet), 2);
                let mut reverse = reconnect.clone();
                std::mem::swap(
                    &mut reverse.source_address,
                    &mut reverse.destination_address,
                );
                std::mem::swap(&mut reverse.source_port, &mut reverse.destination_port);
                let mut response = endpoint_test_packet(&reverse, [0x11; 6]);
                response[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(
                    skeleton
                        .progs
                        .netqmon_egress
                        .test_run(libbpf_rs::ProgramInput {
                            data_in: Some(&response),
                            ..Default::default()
                        })
                        .unwrap()
                        .return_value,
                    2
                );
                // Same IP assigned to another MAC must not inherit the block.
                assert_eq!(run_ingress(&endpoint_test_packet(&reconnect, [0x22; 6])), 0);
                for variant in 0..4 {
                    let mut other = reconnect.clone();
                    match variant {
                        0 => other.destination_port = 8443,
                        1 => other.protocol = if protocol == 6 { 17 } else { 6 },
                        2 => other.source_address[0] ^= 1,
                        _ => other.destination_address[0] ^= 1,
                    }
                    assert_eq!(
                        run_ingress(&endpoint_test_packet(
                            &other,
                            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
                        )),
                        0
                    );
                }
                let cache_key = endpoint_block::key(&alias, client_mac_identity(mac).unwrap());
                let value = skeleton
                    .maps
                    .endpoint_blocks
                    .lookup(&cache_key, MapFlags::ANY)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    &value[..8],
                    &expiry.to_ne_bytes(),
                    "cache hits cannot extend the lease"
                );
                writer
                    .forget_endpoint_blocks(&[alias.clone()], mac)
                    .unwrap();
                assert_eq!(run_ingress(&reconnect_packet), 0);
                writer
                    .remember_endpoint_blocks(&[alias.clone()], flow_id, "p-1", mac, 7, 1)
                    .unwrap();
                assert_eq!(
                    run_ingress(&reconnect_packet),
                    0,
                    "expired endpoint must pass"
                );
                writer
                    .remember_endpoint_blocks(&[alias.clone()], flow_id, "p-1", mac, 7, expiry)
                    .unwrap();
                writer.write_policy_state(true, 8).unwrap();
                assert_eq!(
                    run_ingress(&reconnect_packet),
                    0,
                    "old policy generation must pass"
                );
                writer
                    .remember_endpoint_blocks(&[alias.clone()], flow_id, "p-1", mac, 8, expiry)
                    .unwrap();
                // A rule edit must clear cached blocks even while application
                // enforcement remains enabled; disabling clears them as well.
                writer.reset(9, true).unwrap();
                assert!(skeleton.maps.endpoint_blocks.keys().next().is_none());
                assert_eq!(run_ingress(&reconnect_packet), 0);
                writer
                    .remember_endpoint_blocks(&[alias], flow_id, "p-1", mac, 9, expiry)
                    .unwrap();
                writer.reset(10, false).unwrap();
                assert!(skeleton.maps.endpoint_blocks.keys().next().is_none());
                assert_eq!(run_ingress(&reconnect_packet), 0);
            }
        }
    }

    fn endpoint_test_packet(alias: &FlowKey, source_mac: [u8; 6]) -> Vec<u8> {
        let network_length = if alias.ip_version == 4 { 20 } else { 40 };
        let transport_length = if alias.protocol == 6 { 20 } else { 8 };
        let mut packet = vec![0; 14 + network_length + transport_length];
        packet[..6].fill(0x11);
        packet[6..12].copy_from_slice(&source_mac);
        let ether_type: u16 = if alias.ip_version == 4 {
            0x0800
        } else {
            0x86dd
        };
        packet[12..14].copy_from_slice(&ether_type.to_be_bytes());
        let ip = &mut packet[14..];
        if alias.ip_version == 4 {
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((network_length + transport_length) as u16).to_be_bytes());
            ip[8] = 64;
            ip[9] = alias.protocol;
            ip[12..16].copy_from_slice(&alias.source_address[..4]);
            ip[16..20].copy_from_slice(&alias.destination_address[..4]);
        } else {
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&(transport_length as u16).to_be_bytes());
            ip[6] = alias.protocol;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&alias.source_address);
            ip[24..40].copy_from_slice(&alias.destination_address);
        }
        let transport = &mut ip[network_length..];
        transport[..2].copy_from_slice(&alias.source_port.to_be_bytes());
        transport[2..4].copy_from_slice(&alias.destination_port.to_be_bytes());
        if alias.protocol == 6 {
            transport[12] = 0x50;
            transport[13] = 2;
        } else {
            transport[4..6].copy_from_slice(&(transport_length as u16).to_be_bytes());
        }
        packet
    }

    #[test]
    fn verdict_and_control_abis_use_native_integer_layout() {
        let verdict = encode_verdict(
            0x0102_0304_0506_0708,
            12,
            VerdictIdentity {
                flow_hash: [0xAB; 16],
                policy_hash: [0xCD; 16],
                client_mac: [0xEF; 6],
            },
            0,
            VERDICT_BLOCK,
        );
        assert_eq!(&verdict[..8], &0x0102_0304_0506_0708_u64.to_ne_bytes());
        assert_eq!(&verdict[8..16], &12_u64.to_ne_bytes());
        assert_eq!(&verdict[16..32], &[0xAB; 16]);
        assert_eq!(&verdict[32..48], &[0xCD; 16]);
        assert_eq!(&verdict[48..54], &[0xEF; 6]);
        assert_eq!(&verdict[54..56], &[0; 2]);
        assert_eq!(&verdict[56..60], &0_u32.to_ne_bytes());
        assert_eq!(verdict[60], VERDICT_BLOCK);
        let state = encode_policy_state(true, 12);
        assert_eq!(state[0], 1);
        assert_eq!(&state[1..8], &[0; 7]);
        assert_eq!(&state[8..16], &12_u64.to_ne_bytes());
    }

    #[test]
    fn shape_verdict_carries_the_application_classid_in_the_existing_bpf_abi() {
        let verdict = encode_verdict(
            500,
            12,
            VerdictIdentity {
                flow_hash: [0xAB; 16],
                policy_hash: [0; 16],
                client_mac: [0; 6],
            },
            0x0052_1001,
            VERDICT_SHAPE,
        );
        assert_eq!(&verdict[32..48], &[0; 16]);
        assert_eq!(&verdict[48..56], &[0; 8]);
        assert_eq!(&verdict[56..60], &0x0052_1001_u32.to_ne_bytes());
        assert_eq!(verdict[60], VERDICT_SHAPE);
        assert_eq!(&verdict[61..], &[0; 3]);
    }

    #[test]
    fn application_classid_must_match_hook_and_reserved_leaf_range() {
        assert!(valid_application_classid(1, 0x0052_1001));
        assert!(valid_application_classid(2, 0x0051_1001));
        assert!(!valid_application_classid(1, 0x0051_1001));
        assert!(!valid_application_classid(2, 0x0052_1001));
        assert!(!valid_application_classid(2, 0x0051_fffe));
    }

    #[test]
    fn flow_identity_tag_is_exactly_the_opaque_128_bit_id() {
        assert_eq!(
            flow_identity_hash("00112233445566778899aabbccddeeff").unwrap(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert!(flow_identity_hash("not-an-id").is_err());
        assert!(flow_identity_hash("éééééééééééééééé").is_err());
    }

    #[test]
    fn policy_drop_identity_keeps_policy_and_client_dimensions() {
        assert_eq!(
            policy_identity_hash("policy-1"),
            policy_identity_hash("policy-1")
        );
        assert_ne!(
            policy_identity_hash("policy-1"),
            policy_identity_hash("policy-2")
        );
        assert_eq!(
            client_mac_identity("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(client_mac_identity("aa-bb-cc-dd-ee-ff").is_err());
    }

    #[test]
    fn policy_drop_map_abi_is_validated_independently() {
        assert!(policy_drop_map_abi_matches(24, 16, MAX_POLICY_DROP_ENTRIES));
        assert!(!policy_drop_map_abi_matches(
            23,
            16,
            MAX_POLICY_DROP_ENTRIES
        ));
        assert!(!policy_drop_map_abi_matches(
            24,
            15,
            MAX_POLICY_DROP_ENTRIES
        ));
        assert!(!policy_drop_map_abi_matches(
            24,
            16,
            MAX_POLICY_DROP_ENTRIES + 1
        ));
    }
}
