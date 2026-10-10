use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::flow::FlowKey;

pub(crate) const DEFAULT_POLICY_FLOW_CAPACITY: usize = 8_192;
pub(crate) const MIN_POLICY_FLOW_CAPACITY: usize = 1_024;
pub(crate) const MAX_POLICY_FLOW_CAPACITY: usize = 16_384;
pub(crate) const MAX_ALIASES_PER_FLOW: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowAliasError {
    CapacityFull,
    AliasLimitReached,
    FlowEnded,
}

#[derive(Debug)]
struct AliasEntry {
    keys: Vec<FlowKey>,
    directions: HashMap<FlowKey, super::shaper::Direction>,
    client_mac: Option<String>,
    client_identity_conflict: bool,
    last_seen: Instant,
    ended: bool,
    partial: bool,
    last_command_issued_at_ms: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct PolicyFlowAliasCache {
    entries: HashMap<String, AliasEntry>,
    capacity: usize,
}

impl Default for PolicyFlowAliasCache {
    fn default() -> Self {
        Self::new(DEFAULT_POLICY_FLOW_CAPACITY)
    }
}

impl PolicyFlowAliasCache {
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_POLICY_FLOW_CAPACITY, MAX_POLICY_FLOW_CAPACITY);
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    pub(crate) fn observe(
        &mut self,
        policy_flow_id: &str,
        key: FlowKey,
        now: Instant,
    ) -> Result<usize, FlowAliasError> {
        self.observe_with_client(policy_flow_id, key, None, now)
    }

    pub(crate) fn observe_with_client(
        &mut self,
        policy_flow_id: &str,
        key: FlowKey,
        client_mac: Option<&str>,
        now: Instant,
    ) -> Result<usize, FlowAliasError> {
        let client_mac = client_mac.map(str::to_ascii_lowercase);
        if let Some(entry) = self.entries.get_mut(policy_flow_id) {
            if entry.ended {
                return Err(FlowAliasError::FlowEnded);
            }
            entry.last_seen = now;
            if let Some(client_mac) = client_mac {
                match (entry.client_identity_conflict, entry.client_mac.as_deref()) {
                    (true, _) => {}
                    (false, Some(current)) if current != client_mac => {
                        entry.client_mac = None;
                        entry.client_identity_conflict = true;
                        entry.partial = true;
                    }
                    (false, None) => entry.client_mac = Some(client_mac),
                    (false, Some(_)) => {}
                }
            }
            if entry.keys.contains(&key) {
                return Ok(entry.keys.len());
            }
            if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
                entry.partial = true;
                return Err(FlowAliasError::AliasLimitReached);
            }
            entry.keys.push(key);
            return Ok(entry.keys.len());
        }
        if self.entries.len() >= self.capacity {
            return Err(FlowAliasError::CapacityFull);
        }
        self.entries.insert(
            policy_flow_id.to_owned(),
            AliasEntry {
                keys: vec![key],
                directions: HashMap::new(),
                client_mac,
                client_identity_conflict: false,
                last_seen: now,
                ended: false,
                partial: false,
                last_command_issued_at_ms: None,
            },
        );
        Ok(1)
    }

    pub(crate) fn aliases(&self, policy_flow_id: &str) -> Option<&[FlowKey]> {
        self.entries
            .get(policy_flow_id)
            .map(|entry| entry.keys.as_slice())
    }

    pub(super) fn direction(&self, id: &str, key: &FlowKey) -> Option<super::shaper::Direction> {
        self.entries.get(id)?.directions.get(key).copied()
    }

    /// Preserve normalized direction and add the exact translated egress tuple
    /// for forwarding, whose second observation is deliberately suppressed.
    /// A classified request also controls its exact reverse connection tuple.
    pub(crate) fn observe_direction(
        &mut self,
        id: &str,
        key: &FlowKey,
        direction: crate::normalization::Direction,
        egress_ifindexes: Option<(u32, u32)>,
        tracked: Option<crate::conntrack::ConntrackEntry>,
    ) {
        let direction = match direction {
            crate::normalization::Direction::Upload => super::shaper::Direction::Upload,
            crate::normalization::Direction::Download => super::shaper::Direction::Download,
            _ => return,
        };
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        // observe_with_client may have rejected this key at the alias bound.
        // Direction metadata must obey the same bound as the exact tuples.
        if !entry.keys.contains(key) {
            return;
        }
        entry.directions.insert(key.clone(), direction);
        let Some((upload_ifindex, download_ifindex)) = egress_ifindexes else {
            return;
        };
        if key.hook != 1 {
            return;
        }
        let opposite = match direction {
            super::shaper::Direction::Upload => super::shaper::Direction::Download,
            super::shaper::Direction::Download => super::shaper::Direction::Upload,
        };
        let mut reverse = key.clone();
        reverse.hook = 2;
        reverse.ifindex = if opposite == super::shaper::Direction::Upload {
            upload_ifindex
        } else {
            download_ifindex
        };
        std::mem::swap(
            &mut reverse.source_address,
            &mut reverse.destination_address,
        );
        std::mem::swap(&mut reverse.source_port, &mut reverse.destination_port);
        let mut egress = key.clone();
        egress.hook = 2;
        egress.ifindex = if direction == super::shaper::Direction::Upload {
            upload_ifindex
        } else {
            download_ifindex
        };
        if let Some(tracked) = tracked {
            let Some((source, destination)) = key.addresses() else {
                return;
            };
            let original_orientation = (source == tracked.original.source
                && destination == tracked.original.destination
                && key.source_port == tracked.original.source_port
                && key.destination_port == tracked.original.destination_port)
                || (source == tracked.reply.destination
                    && destination == tracked.reply.source
                    && key.source_port == tracked.reply.destination_port
                    && key.destination_port == tracked.reply.source_port);
            let translated = if original_orientation {
                tracked.reply
            } else {
                tracked.original
            };
            let reverse_translated = if original_orientation {
                tracked.original
            } else {
                tracked.reply
            };
            reverse.source_address = ip_bytes(reverse_translated.destination);
            reverse.destination_address = ip_bytes(reverse_translated.source);
            reverse.source_port = reverse_translated.destination_port;
            reverse.destination_port = reverse_translated.source_port;
            egress.source_address = ip_bytes(translated.destination);
            egress.destination_address = ip_bytes(translated.source);
            egress.source_port = translated.destination_port;
            egress.destination_port = translated.source_port;
        }
        if !entry.keys.contains(&egress) {
            if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
                entry.partial = true;
                return;
            }
            entry.keys.push(egress.clone());
        }
        entry.directions.insert(egress, direction);
        if !entry.keys.contains(&reverse) {
            if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
                entry.partial = true;
                return;
            }
            entry.keys.push(reverse.clone());
        }
        entry.directions.insert(reverse, opposite);
    }

    pub(crate) fn client_mac(&self, policy_flow_id: &str) -> Option<&str> {
        self.entries
            .get(policy_flow_id)
            .and_then(|entry| entry.client_mac.as_deref())
    }

    pub(crate) fn remove(&mut self, policy_flow_id: &str) -> bool {
        self.entries.remove(policy_flow_id).is_some()
    }

    pub(crate) fn mark_ended(&mut self, policy_flow_id: &str) -> bool {
        self.entries.get_mut(policy_flow_id).is_some_and(|entry| {
            entry.ended = true;
            true
        })
    }

    pub(crate) fn is_ended(&self, policy_flow_id: &str) -> bool {
        self.entries
            .get(policy_flow_id)
            .is_some_and(|entry| entry.ended)
    }

    pub(crate) fn is_partial(&self, policy_flow_id: &str) -> bool {
        self.entries
            .get(policy_flow_id)
            .is_some_and(|entry| entry.partial)
    }

    pub(crate) fn command_is_stale(&self, policy_flow_id: &str, issued_at_ms: i64) -> bool {
        self.entries.get(policy_flow_id).is_none_or(|entry| {
            entry
                .last_command_issued_at_ms
                .is_some_and(|last| issued_at_ms < last)
        })
    }

    pub(crate) fn record_command(&mut self, policy_flow_id: &str, issued_at_ms: i64) -> bool {
        let Some(entry) = self.entries.get_mut(policy_flow_id) else {
            return false;
        };
        if entry
            .last_command_issued_at_ms
            .is_some_and(|last| issued_at_ms < last)
        {
            return false;
        }
        entry.last_command_issued_at_ms = Some(issued_at_ms);
        true
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn prune(&mut self, now: Instant, tcp_idle: Duration, udp_idle: Duration) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            let idle_for = now.saturating_duration_since(entry.last_seen);
            let timeout = if entry.keys.iter().all(|key| key.protocol == 17) {
                udp_idle
            } else {
                tcp_idle
            };
            idle_for < timeout
        });
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn ip_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            bytes
        }
        std::net::IpAddr::V6(ip) => ip.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_aliases_cannot_grow_direction_metadata() {
        let mut cache = PolicyFlowAliasCache::default();
        for port in 0..100 {
            let mut observed = key(1, 2);
            observed.source_port += port;
            let _ = cache.observe("bounded", observed.clone(), Instant::now());
            cache.observe_direction(
                "bounded",
                &observed,
                crate::normalization::Direction::Upload,
                None,
                None,
            );
        }
        let entry = &cache.entries["bounded"];
        assert_eq!(entry.keys.len(), MAX_ALIASES_PER_FLOW);
        assert_eq!(entry.directions.len(), MAX_ALIASES_PER_FLOW);
        assert!(entry.partial);
    }

    #[test]
    fn shared_egress_alias_uses_translated_tuple_and_normalized_direction() {
        let mut cache = PolicyFlowAliasCache::default();
        let observed = key(1, 2);
        let tracked = crate::conntrack::ConntrackEntry {
            original: crate::conntrack::FlowTuple {
                protocol: 6,
                source: "192.0.2.1".parse().unwrap(),
                source_port: 50_000,
                destination: "198.51.100.1".parse().unwrap(),
                destination_port: 443,
            },
            reply: crate::conntrack::FlowTuple {
                protocol: 6,
                source: "198.51.100.1".parse().unwrap(),
                source_port: 443,
                destination: "192.0.2.254".parse().unwrap(),
                destination_port: 60_000,
            },
            source_nat: true,
            destination_nat: false,
        };
        cache
            .observe_with_client(
                "nat-flow",
                observed.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                Instant::now(),
            )
            .unwrap();
        cache.observe_direction(
            "nat-flow",
            &observed,
            crate::normalization::Direction::Upload,
            Some((3, 2)),
            Some(tracked),
        );
        let egress = &cache.aliases("nat-flow").unwrap()[1];
        assert_eq!(egress.hook, 2);
        assert_eq!(egress.ifindex, 3);
        let reverse = &cache.aliases("nat-flow").unwrap()[2];
        assert_eq!(reverse.ifindex, 2);
        assert_eq!(
            reverse.addresses(),
            Some((tracked.original.destination, tracked.original.source))
        );
        assert_eq!(
            cache.direction("nat-flow", reverse),
            Some(super::super::shaper::Direction::Download)
        );
        assert_eq!(egress.source_port, 60_000);
        assert_eq!(egress.addresses().unwrap().0, tracked.reply.destination);
        assert_eq!(
            cache.direction("nat-flow", egress),
            Some(super::super::shaper::Direction::Upload)
        );
    }

    fn key(hook: u8, ifindex: u32) -> FlowKey {
        FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            hook,
            ifindex,
            source_address: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination_address: [198, 51, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 50_000,
            destination_port: 443,
        }
    }

    #[test]
    fn dnat_aliases_translate_both_directions_for_ipv4_and_ipv6() {
        use crate::conntrack::{ConntrackEntry, FlowTuple};
        for (client, public, translated, version) in [
            ("192.0.2.1", "198.51.100.8", "203.0.113.9", 4),
            ("fd00::1", "2001:db8::8", "2001:db8:1::9", 6),
        ] {
            let original = FlowTuple {
                protocol: 6,
                source: client.parse().unwrap(),
                source_port: 40_000,
                destination: public.parse().unwrap(),
                destination_port: 443,
            };
            let reply = FlowTuple {
                protocol: 6,
                source: translated.parse().unwrap(),
                source_port: 8443,
                destination: original.source,
                destination_port: original.source_port,
            };
            let tracked = ConntrackEntry {
                original,
                reply,
                source_nat: false,
                destination_nat: true,
            };
            for (tuple, expected, direction) in [
                (original, reply, crate::normalization::Direction::Upload),
                (reply, original, crate::normalization::Direction::Download),
            ] {
                let mut observed = key(1, 2);
                observed.ip_version = version;
                observed.source_address = ip_bytes(tuple.source);
                observed.destination_address = ip_bytes(tuple.destination);
                observed.source_port = tuple.source_port;
                observed.destination_port = tuple.destination_port;
                let mut cache = PolicyFlowAliasCache::default();
                cache
                    .observe("dnat", observed.clone(), Instant::now())
                    .unwrap();
                cache.observe_direction("dnat", &observed, direction, Some((2, 2)), Some(tracked));
                let egress = &cache.aliases("dnat").unwrap()[1];
                assert_eq!(
                    egress.addresses(),
                    Some((expected.destination, expected.source))
                );
                assert_eq!(
                    (egress.source_port, egress.destination_port),
                    (expected.destination_port, expected.source_port)
                );
                assert_eq!(egress.hook, 2);
                assert_eq!(
                    cache.direction("dnat", egress),
                    cache.direction("dnat", &observed)
                );
            }
        }
    }

    #[test]
    fn retains_exact_hook_and_interface_aliases_and_removes_on_end() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        assert_eq!(cache.observe("flow-1", key(1, 2), now), Ok(1));
        assert_eq!(cache.observe("flow-1", key(2, 3), now), Ok(2));
        assert_eq!(cache.aliases("flow-1").unwrap().len(), 2);
        assert!(cache.mark_ended("flow-1"));
        assert!(cache.is_ended("flow-1"));
        assert_eq!(
            cache.observe("flow-1", key(1, 2), now),
            Err(FlowAliasError::FlowEnded)
        );
        assert!(cache.remove("flow-1"));
        assert!(cache.aliases("flow-1").is_none());
    }

    #[test]
    fn retains_a_consistent_client_identity_and_rejects_conflicts_for_shaping() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe_with_client("flow-1", key(1, 2), Some("AA:BB:CC:DD:EE:FF"), now)
            .unwrap();
        cache
            .observe_with_client("flow-1", key(2, 3), Some("aa:bb:cc:dd:ee:ff"), now)
            .unwrap();
        assert_eq!(cache.client_mac("flow-1"), Some("aa:bb:cc:dd:ee:ff"));

        cache
            .observe_with_client("flow-1", key(2, 4), Some("00:11:22:33:44:55"), now)
            .unwrap();
        cache
            .observe_with_client("flow-1", key(2, 5), Some("aa:bb:cc:dd:ee:ff"), now)
            .unwrap();
        assert!(cache.client_mac("flow-1").is_none());
        assert!(cache.is_partial("flow-1"));
    }

    #[test]
    fn reports_partial_coverage_when_a_flow_exceeds_four_exact_aliases() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        for ifindex in 0..MAX_ALIASES_PER_FLOW as u32 {
            cache.observe("flow", key(1, ifindex + 1), now).unwrap();
        }
        assert!(!cache.is_partial("flow"));
        assert_eq!(
            cache.observe("flow", key(2, 20), now),
            Err(FlowAliasError::AliasLimitReached)
        );
        assert!(cache.is_partial("flow"));
        assert_eq!(cache.aliases("flow").unwrap().len(), MAX_ALIASES_PER_FLOW);
    }

    #[test]
    fn cache_capacity_does_not_evict_live_aliases() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::new(MIN_POLICY_FLOW_CAPACITY);
        for index in 0..MIN_POLICY_FLOW_CAPACITY {
            cache
                .observe(&format!("flow-{index}"), key(1, index as u32), now)
                .unwrap();
        }
        assert_eq!(
            cache.observe("overflow", key(1, 99), now),
            Err(FlowAliasError::CapacityFull)
        );
        assert!(cache.aliases("flow-0").is_some());
        assert_eq!(cache.len(), MIN_POLICY_FLOW_CAPACITY);
    }

    #[test]
    fn prunes_using_protocol_idle_timeouts() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache.observe("tcp", key(1, 1), now).unwrap();
        let mut udp = key(1, 2);
        udp.protocol = 17;
        cache.observe("udp", udp, now).unwrap();
        assert_eq!(
            cache.prune(
                now + Duration::from_secs(31),
                Duration::from_secs(120),
                Duration::from_secs(30)
            ),
            1
        );
        assert!(cache.aliases("tcp").is_some());
        assert!(cache.aliases("udp").is_none());
    }

    #[test]
    fn rejects_stale_commands_and_keeps_equal_timestamp_retries_idempotent() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache.observe("flow", key(1, 1), now).unwrap();
        assert!(!cache.command_is_stale("flow", 100));
        assert!(cache.record_command("flow", 100));
        assert!(cache.command_is_stale("flow", 99));
        assert!(!cache.command_is_stale("flow", 100));
        assert!(cache.record_command("flow", 100));
        assert!(!cache.record_command("flow", 99));
    }
}
