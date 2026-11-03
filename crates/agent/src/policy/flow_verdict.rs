use crate::flow::{FLOW_KEY_SIZE, FlowKey};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use super::endpoint_block;

const VERDICT_VALUE_SIZE: usize = 64;
const POLICY_STATE_VALUE_SIZE: usize = 16;
const MAX_VERDICT_ENTRIES: usize = 16_384;
const MAX_POLICY_DROP_ENTRIES: usize = 4096;
const VERDICT_BLOCK: u8 = 1;
const VERDICT_SHAPE: u8 = 2;
const MAX_BLOCK_CLAIMS: usize = MAX_VERDICT_ENTRIES * 2;
const MAX_BLOCK_OWNERS_PER_ALIAS: usize = 16;
pub(crate) type PolicyDropIdentity = ([u8; 16], [u8; 6]);
pub(crate) type PolicyDropCounters = BTreeMap<PolicyDropIdentity, (u64, u64)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerdictIdentity {
    flow_hash: [u8; 16],
    policy_hash: [u8; 16],
    client_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug)]
struct BlockClaim {
    identity: VerdictIdentity,
    generation: u64,
    expires_monotonic_ns: u64,
    /// A real observation of this tuple orientation takes precedence over a
    /// reverse/hook alias synthesized by another directional flow.
    observed_orientation: bool,
}

#[derive(Default)]
struct BlockClaims {
    aliases: HashMap<FlowKey, Vec<BlockClaim>>,
    count: usize,
    next_expired_sweep_ns: u64,
}

fn same_observed_orientation(alias: &FlowKey, observed: &FlowKey) -> bool {
    alias.ip_version == observed.ip_version
        && alias.protocol == observed.protocol
        && alias.direction == observed.direction
        && alias.ifindex == observed.ifindex
        && alias.source_address == observed.source_address
        && alias.destination_address == observed.destination_address
        && alias.source_port == observed.source_port
        && alias.destination_port == observed.destination_port
}

fn block_claim_matches_value(claim: &BlockClaim, value: &[u8]) -> bool {
    value.len() == VERDICT_VALUE_SIZE
        && value[60] == VERDICT_BLOCK
        && value[8..16] == claim.generation.to_ne_bytes()
        && value[16..32] == claim.identity.flow_hash
        && value[32..48] == claim.identity.policy_hash
        && value[48..54] == claim.identity.client_mac
}

fn select_block_claim<'a>(
    claims: &'a [BlockClaim],
    current: Option<&[u8]>,
) -> Option<&'a BlockClaim> {
    claims.iter().max_by_key(|claim| {
        (
            claim.observed_orientation,
            current.is_some_and(|value| block_claim_matches_value(claim, value)),
        )
    })
}

fn encode_block_claim(claim: &BlockClaim, claims: &[BlockClaim]) -> [u8; VERDICT_VALUE_SIZE] {
    encode_verdict(
        claims
            .iter()
            .map(|owner| owner.expires_monotonic_ns)
            .max()
            .unwrap_or(claim.expires_monotonic_ns),
        claim.generation,
        claim.identity,
        0,
        VERDICT_BLOCK,
    )
}

type VerdictUpdate = ([u8; FLOW_KEY_SIZE], Option<Vec<u8>>, Option<Vec<u8>>);

fn apply_verdict_updates(map: &MapHandle, updates: &[VerdictUpdate]) -> Result<(), String> {
    let mut applied: Vec<([u8; FLOW_KEY_SIZE], Option<Vec<u8>>)> = Vec::new();
    for (key, previous, next) in updates {
        if previous == next {
            continue;
        }
        let result = match next {
            Some(value) => map.update(key, value, MapFlags::ANY),
            None => map.delete(key),
        };
        if let Err(error) = result {
            let mut rollback_errors = Vec::new();
            for (rollback_key, value) in applied.iter().rev() {
                let rollback = match value {
                    Some(value) => map.update(rollback_key, value, MapFlags::ANY),
                    None => map.delete(rollback_key),
                };
                if let Err(error) = rollback {
                    rollback_errors.push(error.to_string());
                }
            }
            return Err(format!(
                "write BPF flow verdict: {error}; rollback errors: {rollback_errors:?}"
            ));
        }
        applied.push((*key, previous.clone()));
    }
    Ok(())
}

pub(crate) struct FlowVerdictWriter {
    verdict_map: Option<MapHandle>,
    endpoint_map: Option<MapHandle>,
    policy_state_map: Option<MapHandle>,
    policy_drop_map: Option<MapHandle>,
    policy_drop_map_ready: bool,
    ready: bool,
    block_claims: Mutex<BlockClaims>,
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
            block_claims: Mutex::new(BlockClaims::default()),
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
            block_claims: Mutex::new(BlockClaims::default()),
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
        let mut claims = self
            .block_claims
            .lock()
            .map_err(|_| "block ownership lock poisoned".to_owned())?;
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
        claims.aliases.clear();
        claims.count = 0;
        claims.next_expired_sweep_ns = 0;
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
        observed_aliases: &[FlowKey],
        command_id: &str,
        policy_flow_id: &str,
        policy_id: &str,
        client_mac: &str,
        generation: u64,
        expires_monotonic_ns: u64,
    ) -> Result<usize, String> {
        let identity = VerdictIdentity {
            flow_hash: flow_identity_hash(policy_flow_id)?,
            policy_hash: policy_identity_hash(policy_id),
            client_mac: client_mac_identity(client_mac)?,
        };
        let count = self.install_owned_block(
            aliases,
            observed_aliases,
            identity,
            generation,
            expires_monotonic_ns,
        )?;
        tracing::debug!(target: "netqmon_agent::policy::flow_trace", command_id, policy_flow_id, count,
            "BPF block claims installed");
        Ok(count)
    }

    fn install_owned_block(
        &self,
        aliases: &[FlowKey],
        observed_aliases: &[FlowKey],
        identity: VerdictIdentity,
        generation: u64,
        expires_monotonic_ns: u64,
    ) -> Result<usize, String> {
        if !self.ready {
            return Err("BPF policy map ABI does not match the Agent".to_owned());
        }
        if aliases.is_empty()
            || aliases.len() > 8
            || aliases.iter().any(|key| {
                !matches!(key.ip_version, 4 | 6)
                    || !matches!(key.protocol, 6 | 17)
                    || !matches!(key.hook, 1 | 2)
                    || key.ifindex == 0
            })
            || aliases
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != aliases.len()
        {
            return Err("flow alias is not an exact supported on-wire key".to_owned());
        }
        let map = self
            .verdict_map
            .as_ref()
            .ok_or_else(|| "BPF verdict map is unavailable".to_owned())?;
        let now = crate::linux::monotonic_ns();
        let mut registry = self
            .block_claims
            .lock()
            .map_err(|_| "block ownership lock poisoned".to_owned())?;
        if registry.count.saturating_add(aliases.len()) > MAX_BLOCK_CLAIMS
            && now >= registry.next_expired_sweep_ns
        {
            // Removing a key whose claims are all expired cannot remove a
            // live owner or create a temporary gap for another owner.
            registry
                .aliases
                .retain(|_, claims| claims.iter().any(|claim| claim.expires_monotonic_ns > now));
            registry.count = registry.aliases.values().map(Vec::len).sum();
            registry.next_expired_sweep_ns = now.saturating_add(1_000_000_000);
        }
        let mut count = registry.count;
        let mut staged = Vec::with_capacity(aliases.len());
        for alias in aliases {
            let key = alias.bpf_key_bytes();
            let previous = map
                .lookup(&key, MapFlags::ANY)
                .map_err(|error| format!("read previous BPF flow verdict: {error}"))?;
            let old = registry.aliases.get(alias).cloned().unwrap_or_default();
            let mut claims = old.clone();
            if previous.as_deref().is_none_or(|value| {
                !claims
                    .iter()
                    .any(|claim| block_claim_matches_value(claim, value))
            }) {
                // An independently installed shape or removed/evicted map
                // entry must never revive stale block claims.
                claims.clear();
            }
            claims.retain(|claim| claim.expires_monotonic_ns > now);
            if claims.iter().any(|claim| {
                claim.generation != generation
                    || claim.identity.policy_hash != identity.policy_hash
                    || claim.identity.client_mac != identity.client_mac
            }) {
                // Different policy/client decisions are not interchangeable.
                // Replace their ownership rather than resurrecting them later.
                claims.clear();
            }
            claims.retain(|claim| claim.identity.flow_hash != identity.flow_hash);
            claims.push(BlockClaim {
                identity,
                generation,
                expires_monotonic_ns,
                observed_orientation: observed_aliases
                    .iter()
                    .any(|observed| same_observed_orientation(alias, observed)),
            });
            if claims.len() > MAX_BLOCK_OWNERS_PER_ALIAS {
                return Err(
                    "block_owner_capacity_exceeded: too many owners for a flow alias".to_owned(),
                );
            }
            count = count.saturating_sub(old.len()).saturating_add(claims.len());
            let winner =
                select_block_claim(&claims, previous.as_deref()).expect("new claim is present");
            let next = encode_block_claim(winner, &claims);
            staged.push((alias.clone(), key, previous, claims, next));
        }
        if count > MAX_BLOCK_CLAIMS {
            return Err("block_owner_capacity_exceeded: block ownership table is full".to_owned());
        }
        let updates = staged
            .iter()
            .map(|(_, key, previous, _, next)| (*key, previous.clone(), Some(next.to_vec())))
            .collect::<Vec<_>>();
        apply_verdict_updates(map, &updates)?;
        for (alias, _, _, claims, _) in staged {
            registry.aliases.insert(alias, claims);
        }
        registry.count = count;
        Ok(aliases.len())
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
            return Err("application shape alias has no valid hook or class tag".to_owned());
        }
        let identity = VerdictIdentity {
            flow_hash: flow_identity_hash(policy_flow_id)?,
            policy_hash: [0; 16],
            client_mac: [0; 6],
        };
        let mut registry = self
            .block_claims
            .lock()
            .map_err(|_| "block ownership lock poisoned".to_owned())?;
        let count = self.install_verdict(
            aliases,
            command_id,
            policy_flow_id,
            identity,
            generation,
            expires_monotonic_ns,
            VERDICT_SHAPE,
        )?;
        // A shape verdict supersedes any block claims at the same exact key;
        // they must never be promoted again on a later revoke.
        for (alias, _) in aliases {
            if let Some(removed) = registry.aliases.remove(alias) {
                registry.count = registry.count.saturating_sub(removed.len());
            }
        }
        Ok(count)
    }

    /// Read the owner of a live shape verdict for this exact hook and tuple.
    /// Absence, malformed state and lookup errors never count as coverage.
    #[cfg(feature = "qos-client-priority")]
    pub(crate) fn active_shape_owner(
        &self,
        key: &FlowKey,
        generation: u64,
        now_monotonic_ns: u64,
    ) -> Option<(String, u32)> {
        let map = self.verdict_map.as_ref()?;
        let value = map.lookup(&key.bpf_key_bytes(), MapFlags::ANY).ok()??;
        shape_owner_from_value(key, &value, generation, now_monotonic_ns)
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
        let expected_hash = expected_flow_id.map(flow_identity_hash).transpose()?;
        let mut registry = self
            .block_claims
            .lock()
            .map_err(|_| "block ownership lock poisoned".to_owned())?;
        let now = crate::linux::monotonic_ns();
        let mut count = registry.count;
        let mut staged = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for alias in aliases.iter().filter(|alias| seen.insert(*alias)) {
            let key = alias.bpf_key_bytes();
            let previous = verdict_map.lookup(&key, MapFlags::ANY).map_err(|error| {
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
            })?;
            let old = registry.aliases.get(alias).cloned().unwrap_or_default();
            let previous_was_known = previous.as_deref().is_some_and(|value| {
                old.iter()
                    .any(|claim| block_claim_matches_value(claim, value))
            });
            let mut claims = if previous_was_known {
                old.clone()
            } else {
                Vec::new()
            };
            claims.retain(|claim| {
                claim.expires_monotonic_ns > now
                    && expected_hash.is_some_and(|expected| claim.identity.flow_hash != expected)
            });
            let previous_is_target = previous.as_deref().is_some_and(|value| {
                expected_hash.is_none_or(|expected| value.get(16..32) == Some(&expected))
            });
            let next = if previous_was_known {
                select_block_claim(&claims, previous.as_deref())
                    .map(|claim| encode_block_claim(claim, &claims).to_vec())
            } else if previous_is_target {
                None
            } else {
                previous.clone()
            };
            count = count.saturating_sub(old.len()).saturating_add(claims.len());
            staged.push((alias.clone(), key, previous, claims, next));
        }
        let updates = staged
            .iter()
            .map(|(_, key, previous, _, next)| (*key, previous.clone(), next.clone()))
            .collect::<Vec<_>>();
        apply_verdict_updates(verdict_map, &updates)?;
        let removed = staged
            .iter()
            .filter(|(_, _, previous, _, next)| previous.is_some() && next.is_none())
            .count();
        for (alias, _, _, claims, _) in staged {
            if claims.is_empty() {
                registry.aliases.remove(&alias);
            } else {
                registry.aliases.insert(alias, claims);
            }
        }
        registry.count = count;
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

#[cfg(feature = "qos-client-priority")]
fn shape_owner_from_value(
    key: &FlowKey,
    value: &[u8],
    generation: u64,
    now_monotonic_ns: u64,
) -> Option<(String, u32)> {
    if value.len() != VERDICT_VALUE_SIZE || value[60] != VERDICT_SHAPE {
        return None;
    }
    let expiry = u64::from_ne_bytes(value[0..8].try_into().ok()?);
    let installed_generation = u64::from_ne_bytes(value[8..16].try_into().ok()?);
    let tag = u32::from_ne_bytes(value[56..60].try_into().ok()?);
    if expiry <= now_monotonic_ns
        || installed_generation != generation
        || !valid_shape_tag(key.hook, tag)
    {
        return None;
    }
    Some((
        value[16..32]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        tag,
    ))
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
        || (matches!(hook, 1 | 2) && (1..=super::shaper::MAX_APPLICATION_TAG as u32).contains(&tag))
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
    fn overlapping_directional_blocks_transfer_only_to_live_compatible_owners() {
        use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
        let mut open_object = std::mem::MaybeUninit::uninit();
        let skeleton = crate::bpf::FlowSkelBuilder::default()
            .open(&mut open_object)
            .unwrap()
            .load()
            .unwrap();
        let writer = FlowVerdictWriter::new(
            MapHandle::try_from(&skeleton.maps.flow_verdict_map).unwrap(),
            MapHandle::try_from(&skeleton.maps.endpoint_blocks).unwrap(),
            MapHandle::try_from(&skeleton.maps.bss).unwrap(),
            Some(MapHandle::try_from(&skeleton.maps.policy_drop_counters).unwrap()),
        );
        let a_id = "00112233445566778899aabbccddeeff";
        let b_id = "ffeeddccbbaa99887766554433221100";
        let a = FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            hook: 1,
            ifindex: 1,
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 1000,
            destination_port: 2000,
        };
        let mut b = a.clone();
        b.hook = 2;
        std::mem::swap(&mut b.source_address, &mut b.destination_address);
        std::mem::swap(&mut b.source_port, &mut b.destination_port);
        let mut a_other = a.clone();
        a_other.hook = 2;
        let mut b_other = b.clone();
        b_other.hook = 1;
        let aliases = vec![a.clone(), a_other.clone(), b.clone(), b_other.clone()];
        let deadline = crate::linux::monotonic_ns() + 30_000_000_000;
        let owner = |key: &FlowKey| -> Option<[u8; 16]> {
            writer
                .verdict_map
                .as_ref()
                .unwrap()
                .lookup(&key.bpf_key_bytes(), MapFlags::ANY)
                .unwrap()
                .map(|value| value[16..32].try_into().unwrap())
        };
        let apply = |id: &str, observed: &FlowKey, policy: &str| {
            writer
                .install_block(
                    &aliases,
                    std::slice::from_ref(observed),
                    "cmd",
                    id,
                    policy,
                    "aa:bb:cc:dd:ee:ff",
                    7,
                    deadline,
                )
                .unwrap();
        };
        for (first_id, first, second_id, second) in [(a_id, &a, b_id, &b), (b_id, &b, a_id, &a)] {
            writer.reset(7, true).unwrap();
            apply(first_id, first, "policy");
            apply(second_id, second, "policy");
            assert_eq!(owner(&a), Some(flow_identity_hash(a_id).unwrap()));
            assert_eq!(owner(&a_other), Some(flow_identity_hash(a_id).unwrap()));
            assert_eq!(owner(&b), Some(flow_identity_hash(b_id).unwrap()));
            assert_eq!(owner(&b_other), Some(flow_identity_hash(b_id).unwrap()));
            writer
                .clear_aliases(&aliases, Some(first_id), "revoke-first")
                .unwrap();
            for alias in &aliases {
                assert_eq!(owner(alias), Some(flow_identity_hash(second_id).unwrap()));
            }
            writer
                .clear_aliases(&aliases, Some(second_id), "revoke-second")
                .unwrap();
            for alias in &aliases {
                assert!(owner(alias).is_none());
            }
        }
        writer.reset(7, true).unwrap();
        apply(a_id, &a, "old-policy");
        apply(b_id, &b, "new-policy");
        writer
            .clear_aliases(&aliases, Some(b_id), "revoke-new")
            .unwrap();
        for alias in &aliases {
            assert!(
                owner(alias).is_none(),
                "a superseded policy must not return"
            );
        }
        writer.reset(7, true).unwrap();
        apply(a_id, &a, "policy");
        writer
            .install_shape(&[(a.clone(), 3)], "shape", b_id, 7, deadline)
            .unwrap();
        writer
            .clear_aliases(&aliases, Some(a_id), "revoke-block")
            .unwrap();
        assert_eq!(owner(&a), Some(flow_identity_hash(b_id).unwrap()));
        let value = writer
            .verdict_map
            .as_ref()
            .unwrap()
            .lookup(&a.bpf_key_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        assert_eq!(value[60], VERDICT_SHAPE);

        writer.reset(7, true).unwrap();
        apply(a_id, &a, "policy");
        writer
            .install_block(
                &aliases,
                &[b.clone()],
                "cmd",
                b_id,
                "policy",
                "aa:bb:cc:dd:ee:00",
                7,
                deadline,
            )
            .unwrap();
        writer
            .clear_aliases(&aliases, Some(b_id), "revoke-new-client")
            .unwrap();
        for alias in &aliases {
            assert!(
                owner(alias).is_none(),
                "a former client's block must not return"
            );
        }

        writer.reset(7, true).unwrap();
        let soon = crate::linux::monotonic_ns() + 100_000_000;
        writer
            .install_block(
                &aliases,
                &[a.clone()],
                "cmd",
                a_id,
                "policy",
                "aa:bb:cc:dd:ee:ff",
                7,
                soon,
            )
            .unwrap();
        apply(b_id, &b, "policy");
        let expiry = || {
            let value = writer
                .verdict_map
                .as_ref()
                .unwrap()
                .lookup(&a.bpf_key_bytes(), MapFlags::ANY)
                .unwrap()
                .unwrap();
            u64::from_ne_bytes(value[..8].try_into().unwrap())
        };
        assert_eq!(owner(&a), Some(flow_identity_hash(a_id).unwrap()));
        assert_eq!(expiry(), deadline, "the live peer extends the shared rule");
        writer
            .clear_aliases(&aliases, Some(b_id), "revoke-peer")
            .unwrap();
        assert_eq!(expiry(), soon, "a revoked peer must not extend the rule");
        apply(b_id, &b, "policy");
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(
            expiry(),
            deadline,
            "a live peer must keep the shared rule valid"
        );
        writer
            .clear_aliases(&aliases, Some(b_id), "revoke-live")
            .unwrap();
        for alias in &aliases {
            assert!(owner(alias).is_none(), "an expired claim must not return");
        }

        writer.reset(7, true).unwrap();
        for number in 0..MAX_BLOCK_OWNERS_PER_ALIAS {
            let id = format!("{number:032x}");
            writer
                .install_block(
                    &[a.clone()],
                    &[a.clone()],
                    "cmd",
                    &id,
                    "policy",
                    "aa:bb:cc:dd:ee:ff",
                    7,
                    deadline,
                )
                .unwrap();
        }
        let before = owner(&a);
        let extra_id = format!("{:032x}", MAX_BLOCK_OWNERS_PER_ALIAS);
        assert!(
            writer
                .install_block(
                    &[a.clone()],
                    &[a.clone()],
                    "cmd",
                    &extra_id,
                    "policy",
                    "aa:bb:cc:dd:ee:ff",
                    7,
                    deadline
                )
                .unwrap_err()
                .contains("block_owner_capacity_exceeded")
        );
        assert_eq!(
            owner(&a),
            before,
            "failed claim must preserve the previous owner"
        );
    }

    #[cfg(feature = "qos-client-priority")]
    #[test]
    #[ignore = "requires Linux BPF privileges; run on the Debian test server"]
    fn directional_shape_owners_survive_each_others_revoke() {
        use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
        let mut open_object = std::mem::MaybeUninit::uninit();
        let skeleton = crate::bpf::FlowSkelBuilder::default()
            .open(&mut open_object)
            .unwrap()
            .load()
            .unwrap();
        let writer = FlowVerdictWriter::new(
            MapHandle::try_from(&skeleton.maps.flow_verdict_map).unwrap(),
            MapHandle::try_from(&skeleton.maps.endpoint_blocks).unwrap(),
            MapHandle::try_from(&skeleton.maps.bss).unwrap(),
            Some(MapHandle::try_from(&skeleton.maps.policy_drop_counters).unwrap()),
        );
        let first_id = "00112233445566778899aabbccddeeff";
        let second_id = "ffeeddccbbaa99887766554433221100";
        let first = FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            hook: 1,
            ifindex: 1,
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 1000,
            destination_port: 2000,
        };
        let mut second = first.clone();
        second.hook = 2;
        std::mem::swap(&mut second.source_address, &mut second.destination_address);
        std::mem::swap(&mut second.source_port, &mut second.destination_port);
        let now = crate::linux::monotonic_ns();
        writer.reset(7, true).unwrap();
        writer
            .install_shape(
                &[(first.clone(), 3)],
                "first",
                first_id,
                7,
                now + 30_000_000_000,
            )
            .unwrap();
        writer
            .install_shape(
                &[(second.clone(), 4)],
                "second",
                second_id,
                7,
                now + 30_000_000_000,
            )
            .unwrap();
        assert_eq!(
            writer.active_shape_owner(&first, 7, now),
            Some((first_id.to_owned(), 3))
        );
        assert_eq!(
            writer.active_shape_owner(&second, 7, now),
            Some((second_id.to_owned(), 4))
        );
        writer
            .clear_aliases(&[first.clone(), second.clone()], Some(first_id), "revoke")
            .unwrap();
        assert!(writer.active_shape_owner(&first, 7, now).is_none());
        assert_eq!(
            writer.active_shape_owner(&second, 7, now),
            Some((second_id.to_owned(), 4))
        );
    }

    #[test]
    #[ignore = "requires Linux BPF privileges; run on the Debian test server"]
    fn ingress_application_verdict_sets_the_packet_mark() {
        use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
        let mut open_object = std::mem::MaybeUninit::uninit();
        let skeleton = crate::bpf::FlowSkelBuilder::default()
            .open(&mut open_object)
            .unwrap()
            .load()
            .unwrap();
        let writer = FlowVerdictWriter::new(
            MapHandle::try_from(&skeleton.maps.flow_verdict_map).unwrap(),
            MapHandle::try_from(&skeleton.maps.endpoint_blocks).unwrap(),
            MapHandle::try_from(&skeleton.maps.bss).unwrap(),
            Some(MapHandle::try_from(&skeleton.maps.policy_drop_counters).unwrap()),
        );
        for version in [4, 6] {
            for protocol in [6, 17] {
                writer.reset(7, true).unwrap();
                let mut alias = FlowKey {
                    ip_version: version,
                    protocol,
                    direction: 0,
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
                writer
                    .install_shape(
                        &[(alias.clone(), 3)],
                        "shape",
                        "00112233445566778899aabbccddeeff",
                        7,
                        crate::linux::monotonic_ns() + 30_000_000_000,
                    )
                    .unwrap();
                let packet = endpoint_test_packet(&alias, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                let mut context = [0_u8; 192];
                let output = skeleton
                    .progs
                    .netqmon_ingress
                    .test_run(libbpf_rs::ProgramInput {
                        data_in: Some(&packet),
                        context_out: Some(&mut context),
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(output.return_value, 0);
                assert_eq!(
                    u32::from_ne_bytes(output.context.unwrap()[8..12].try_into().unwrap()),
                    3 << 25
                );
            }
        }
    }

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

    #[cfg(feature = "qos-client-priority")]
    #[test]
    fn peer_shape_owner_requires_valid_live_matching_bpf_verdict() {
        let key = FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            hook: 1,
            ifindex: 3,
            source_address: [0; 16],
            destination_address: [0; 16],
            source_port: 1,
            destination_port: 2,
        };
        let mut value = encode_verdict(
            500,
            12,
            VerdictIdentity {
                flow_hash: [0xab; 16],
                policy_hash: [0; 16],
                client_mac: [0; 6],
            },
            0x0052_1001,
            VERDICT_SHAPE,
        );
        assert_eq!(
            shape_owner_from_value(&key, &value, 12, 499),
            Some(("ab".repeat(16), 0x0052_1001))
        );
        assert!(shape_owner_from_value(&key, &value, 12, 500).is_none());
        assert!(shape_owner_from_value(&key, &value, 13, 499).is_none());
        assert!(shape_owner_from_value(&key, &value[..63], 12, 499).is_none());
        value[60] = VERDICT_BLOCK;
        assert!(shape_owner_from_value(&key, &value, 12, 499).is_none());
        value[60] = VERDICT_SHAPE;
        value[56..60].copy_from_slice(&0x0051_1001_u32.to_ne_bytes());
        assert!(shape_owner_from_value(&key, &value, 12, 499).is_none());
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
