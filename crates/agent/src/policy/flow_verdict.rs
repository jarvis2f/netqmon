use crate::flow::{FLOW_KEY_SIZE, FlowKey};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

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
    policy_state_map: Option<MapHandle>,
    policy_drop_map: Option<MapHandle>,
    policy_drop_map_ready: bool,
    ready: bool,
}

impl FlowVerdictWriter {
    pub(crate) fn new(
        verdict_map: MapHandle,
        policy_state_map: MapHandle,
        policy_drop_map: Option<MapHandle>,
    ) -> Self {
        let ready = verdict_map.key_size() as usize == FLOW_KEY_SIZE
            && verdict_map.value_size() as usize == VERDICT_VALUE_SIZE
            && verdict_map.max_entries() as usize == MAX_VERDICT_ENTRIES
            && policy_state_map.key_size() == 4
            && policy_state_map.value_size() as usize == POLICY_STATE_VALUE_SIZE;
        let policy_drop_map_ready = policy_drop_map.as_ref().is_some_and(|map| {
            policy_drop_map_abi_matches(
                map.key_size() as usize,
                map.value_size() as usize,
                map.max_entries() as usize,
            )
        });
        Self {
            verdict_map: Some(verdict_map),
            policy_state_map: Some(policy_state_map),
            policy_drop_map,
            policy_drop_map_ready,
            ready,
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            verdict_map: None,
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
            identity,
            generation,
            expires_monotonic_ns,
            VERDICT_BLOCK,
        )
    }

    pub(crate) fn install_shape(
        &self,
        aliases: &[(FlowKey, u32)],
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
            identity,
            generation,
            expires_monotonic_ns,
            VERDICT_SHAPE,
        )
    }

    fn install_verdict(
        &self,
        aliases: &[(FlowKey, u32)],
        identity: VerdictIdentity,
        generation: u64,
        expires_monotonic_ns: u64,
        verdict: u8,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        if aliases.is_empty() || aliases.len() > 4 {
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
        for (alias, classid) in aliases {
            let key = alias.bpf_key_bytes();
            let value = encode_verdict(
                expires_monotonic_ns,
                generation,
                identity,
                *classid,
                verdict,
            );
            let previous = verdict_map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| format!("read previous BPF flow verdict: {error}"))?;
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
                return Err(format!("write BPF flow verdict: {error}{rollback_detail}"));
            }
            previous_values.push((key, previous));
        }
        Ok(previous_values.len())
    }

    pub(crate) fn clear_aliases(
        &self,
        aliases: &[FlowKey],
        expected_flow_id: Option<&str>,
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
                .map_err(|error| format!("look up BPF flow verdict: {error}"))?
                .filter(|value| {
                    expected_hash.is_none_or(|expected| value.get(16..32) == Some(&expected))
                });
            if value.is_some() {
                verdict_map
                    .delete(&key)
                    .map_err(|error| format!("delete BPF flow verdict: {error}"))?;
                removed += 1;
            }
        }
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
