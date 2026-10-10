//! Bounded exact-lifetime telemetry context for asynchronous DPI decisions.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use netqmon_protocol::v1::{FlowDelta, FlowLifecycle, TelemetryBatch};

use crate::dpi::CachedResult;

const CAPACITY: usize = 16_384;
const TTL: Duration = Duration::from_secs(300);
const PENDING_SAMPLE_CAPACITY: usize = 1_024;
const PENDING_SAMPLE_TTL: Duration = Duration::from_secs(5);
type Key = (String, String, String);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct FlowIdentity {
    gateway: String,
    boot: String,
    ip_version: u32,
    protocol: u32,
    client_ip: Vec<u8>,
    client_port: u32,
    remote_ip: Vec<u8>,
    remote_port: u32,
}

type AnonymousKey = (FlowIdentity, u64);

impl FlowIdentity {
    fn from_flow(gateway: &str, boot: &str, flow: &FlowDelta) -> Self {
        Self {
            gateway: gateway.to_owned(),
            boot: boot.to_owned(),
            ip_version: flow.ip_version,
            protocol: flow.protocol,
            client_ip: flow.client_ip.clone(),
            client_port: flow.client_port,
            remote_ip: flow.remote_ip.clone(),
            remote_port: flow.remote_port,
        }
    }

    fn from_sample(sample: &CachedResult) -> Self {
        Self {
            gateway: sample.gateway.clone(),
            boot: sample.boot.clone(),
            ip_version: sample.key.ip_version,
            protocol: sample.key.protocol,
            client_ip: sample.key.client_ip.clone(),
            client_port: sample.key.client_port,
            remote_ip: sample.key.remote_ip.clone(),
            remote_port: sample.key.remote_port,
        }
    }
}

#[derive(Default)]
pub(crate) struct FlowContextCache {
    entries: HashMap<Key, (Instant, FlowDelta)>,
    expirations: BTreeSet<(Instant, Key)>,
    identities: HashMap<FlowIdentity, HashSet<Key>>,
    anonymous_entries: HashMap<AnonymousKey, (Instant, FlowDelta)>,
    anonymous_expirations: BTreeSet<(Instant, AnonymousKey)>,
    anonymous_identities: HashMap<FlowIdentity, HashSet<AnonymousKey>>,
    anonymous_ambiguities: HashSet<AnonymousKey>,
}

/// Holds completed DPI results briefly when the matching Agent flow delta has
/// not arrived yet. The tuple and flow lifetime still have to match before a
/// result can be attached to an application Flow.
#[derive(Default)]
pub(crate) struct PendingFlowSamples {
    entries: VecDeque<(Instant, CachedResult)>,
}

impl PendingFlowSamples {
    pub(crate) fn defer(&mut self, sample: CachedResult, now: Instant) {
        self.expire(now);
        if self.entries.len() == PENDING_SAMPLE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((now + PENDING_SAMPLE_TTL, sample));
    }

    pub(crate) fn take_ready(
        &mut self,
        contexts: &FlowContextCache,
        now: Instant,
    ) -> Vec<CachedResult> {
        self.expire(now);
        let mut ready = Vec::new();
        let mut waiting = VecDeque::new();
        while let Some((expires, sample)) = self.entries.pop_front() {
            if contexts.matching(&sample, now).is_empty() {
                waiting.push_back((expires, sample));
            } else {
                ready.push(sample);
            }
        }
        self.entries = waiting;
        ready
    }

    fn expire(&mut self, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            self.entries.pop_front();
        }
    }
}

impl FlowContextCache {
    pub(crate) fn observe(&mut self, batch: &TelemetryBatch, now: Instant) {
        loop {
            let explicit_expired = self
                .expirations
                .first()
                .is_some_and(|(expires, _)| *expires <= now);
            let anonymous_expired = self
                .anonymous_expirations
                .first()
                .is_some_and(|(expires, _)| *expires <= now);
            if !explicit_expired && !anonymous_expired {
                break;
            }
            self.remove_oldest();
        }
        for flow in &batch.flows {
            let identity = FlowIdentity::from_flow(&batch.gateway_id, &batch.boot_id, flow);
            let anonymous_key = (identity.clone(), flow.first_seen_unix_ms);
            let has_counters =
                flow.packets != 0 || flow.upload_bytes != 0 || flow.download_bytes != 0;
            let ended = flow.lifecycle == FlowLifecycle::Ended as i32;
            if flow.policy_flow_id.is_empty() {
                if !has_counters {
                    if ended
                        && let Some((_, context)) = self.anonymous_entries.get_mut(&anonymous_key)
                    {
                        context.lifecycle = FlowLifecycle::Ended as i32;
                    }
                    continue;
                }
                self.observe_anonymous(anonymous_key, flow.clone(), now);
                continue;
            }
            let key = (
                batch.gateway_id.clone(),
                batch.boot_id.clone(),
                flow.policy_flow_id.clone(),
            );
            // Synthetic lifecycle timestamps do not describe the sampled
            // lifetime. Keep the actual packet interval and client metadata.
            if !has_counters {
                if ended && let Some((_, context)) = self.entries.get_mut(&key) {
                    context.lifecycle = FlowLifecycle::Ended as i32;
                }
                continue;
            }
            if let Some((expires, previous)) = self.entries.remove(&key) {
                self.expirations.remove(&(expires, key.clone()));
                self.remove_identity(
                    &FlowIdentity::from_flow(&batch.gateway_id, &batch.boot_id, &previous),
                    &key,
                );
            } else if self.entries.len() + self.anonymous_entries.len() >= CAPACITY {
                self.remove_oldest();
            }
            let expires = now + TTL;
            self.entries.insert(key.clone(), (expires, flow.clone()));
            self.expirations.insert((expires, key));
            self.identities
                .entry(FlowIdentity::from_flow(
                    &batch.gateway_id,
                    &batch.boot_id,
                    flow,
                ))
                .or_default()
                .insert((
                    batch.gateway_id.clone(),
                    batch.boot_id.clone(),
                    flow.policy_flow_id.clone(),
                ));
        }
    }

    fn observe_anonymous(&mut self, key: AnonymousKey, flow: FlowDelta, now: Instant) {
        let mut flow = flow;
        if let Some((expires, previous)) = self.anonymous_entries.remove(&key) {
            self.anonymous_expirations.remove(&(expires, key.clone()));
            if previous.client_mac.len() == 6 && flow.client_mac.len() != 6 {
                flow.client_mac = previous.client_mac.clone();
            }
            let mac_conflict = previous.client_mac.len() == 6
                && flow.client_mac.len() == 6
                && previous.client_mac != flow.client_mac;
            if mac_conflict
                || previous.scope != flow.scope
                || previous.path_type != flow.path_type
                || previous.nat != flow.nat
            {
                self.anonymous_ambiguities.insert(key.clone());
            }
        } else if self.entries.len() + self.anonymous_entries.len() >= CAPACITY {
            self.remove_oldest();
        }
        let expires = now + TTL;
        self.anonymous_entries.insert(key.clone(), (expires, flow));
        self.anonymous_expirations.insert((expires, key.clone()));
        self.anonymous_identities
            .entry(key.0.clone())
            .or_default()
            .insert(key);
    }

    fn remove_oldest(&mut self) {
        let explicit_first = self.expirations.first();
        let anonymous_first = self.anonymous_expirations.first();
        if explicit_first.is_some()
            && (anonymous_first.is_none()
                || explicit_first.map(|item| item.0) <= anonymous_first.map(|item| item.0))
            && let Some((_, key)) = self.expirations.pop_first()
        {
            if let Some((_, flow)) = self.entries.remove(&key) {
                self.remove_identity(&FlowIdentity::from_flow(&key.0, &key.1, &flow), &key);
            }
        } else if let Some((_, key)) = self.anonymous_expirations.pop_first()
            && self.anonymous_entries.remove(&key).is_some()
        {
            self.anonymous_ambiguities.remove(&key);
            let remove_identity = self
                .anonymous_identities
                .get_mut(&key.0)
                .is_some_and(|keys| {
                    keys.remove(&key);
                    keys.is_empty()
                });
            if remove_identity {
                self.anonymous_identities.remove(&key.0);
            }
        }
    }

    fn remove_identity(&mut self, identity: &FlowIdentity, key: &Key) {
        let remove_identity = self.identities.get_mut(identity).is_some_and(|keys| {
            keys.remove(key);
            keys.is_empty()
        });
        if remove_identity {
            self.identities.remove(identity);
        }
    }

    pub(crate) fn matching(&self, sample: &CachedResult, now: Instant) -> Vec<FlowDelta> {
        let exact = sample
            .policy_flow_ids
            .iter()
            .filter_map(|id| {
                let (expires, flow) =
                    self.entries
                        .get(&(sample.gateway.clone(), sample.boot.clone(), id.clone()))?;
                sample_context_matches(flow, *expires, sample, now).then(|| flow.clone())
            })
            .collect::<Vec<_>>();
        // An explicit sample ID must resolve to a live exact context first.
        // Once it does, include other raw hook/ifindex observations only when
        // their normalized five-tuple and packet lifetime also match. Passwall2
        // can expose one client connection as multiple raw TC keys; a proxy-
        // rebuilt upstream connection has a different tuple and stays separate.
        if !sample.policy_flow_ids.is_empty() && exact.is_empty() {
            return Vec::new();
        }

        // Some TC paths provide the exact sampled tuple and lifetime while the
        // sample event has no policy_flow_id. Associate it only with telemetry
        // contexts for the same normalized five-tuple and overlapping lifetime.
        // This preserves REDIRECT/TPROXY attribution when the kernel path omits
        // the optional ID without joining a proxy-rebuilt upstream connection.
        let identity = FlowIdentity::from_sample(sample);
        let explicit_ids = !sample.policy_flow_ids.is_empty();
        let mut candidates = BTreeMap::<String, FlowDelta>::new();
        for flow in exact {
            candidates.insert(flow.policy_flow_id.clone(), flow);
        }
        for key in self.identities.get(&identity).into_iter().flatten() {
            let Some((expires, flow)) = self.entries.get(key) else {
                continue;
            };
            if sample_context_matches(flow, *expires, sample, now) {
                candidates.insert(flow.policy_flow_id.clone(), flow.clone());
            }
        }
        if !explicit_ids {
            for key in self
                .anonymous_identities
                .get(&identity)
                .into_iter()
                .flatten()
            {
                let Some((expires, flow)) = self.anonymous_entries.get(key) else {
                    continue;
                };
                if !self.anonymous_ambiguities.contains(key)
                    && sample_context_matches(flow, *expires, sample, now)
                {
                    candidates.insert(format!("anonymous:{}", key.1), flow.clone());
                }
            }
        }
        let Some(first) = candidates.values().next() else {
            return Vec::new();
        };
        // An app verdict needs a known client and a single consistent path
        // identity. Fail closed if overlapping contexts disagree on ownership
        // or NAT/path metadata, or if the sample spans too many BPF aliases.
        if first.client_mac.len() != 6
            || candidates.len() > 16
            || candidates.values().any(|flow| {
                flow.client_mac != first.client_mac
                    || flow.scope != first.scope
                    || flow.path_type != first.path_type
                    || flow.nat != first.nat
            })
        {
            return Vec::new();
        }
        candidates.into_values().collect()
    }
}

fn sample_context_matches(
    flow: &FlowDelta,
    expires: Instant,
    sample: &CachedResult,
    now: Instant,
) -> bool {
    let key = &sample.key;
    expires > now
        && flow.lifecycle != FlowLifecycle::Ended as i32
        && flow.ip_version == key.ip_version
        && flow.protocol == key.protocol
        && flow.client_ip == key.client_ip
        && flow.client_port == key.client_port
        && flow.remote_ip == key.remote_ip
        && flow.remote_port == key.remote_port
        && flow.first_seen_unix_ms <= sample.last_packet_ms.saturating_add(1)
        && flow.last_seen_unix_ms.saturating_add(1) >= key.first_seen_unix_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_protocol::v1::FlowSampleKey;

    #[test]
    fn context_is_bounded_expiring_and_scoped_to_exact_lifetime() {
        let now = Instant::now();
        let mut cache = FlowContextCache::default();
        let flow = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_100,
            policy_flow_id: "flow".into(),
            packets: 1,
            ..Default::default()
        };
        let mut batch = TelemetryBatch {
            gateway_id: "gw".into(),
            boot_id: "boot".into(),
            flows: vec![flow.clone()],
            ..Default::default()
        };
        cache.observe(&batch, now);
        let mut sample = CachedResult::for_test(
            "gw".into(),
            "boot".into(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: 1_020,
            },
            1_100,
            None,
        );
        sample.policy_flow_ids.push("flow".into());
        assert_eq!(cache.matching(&sample, now)[0].client_mac, flow.client_mac);
        sample.gateway = "other".into();
        assert!(cache.matching(&sample, now).is_empty());
        sample.gateway = "gw".into();
        sample.boot = "other".into();
        assert!(cache.matching(&sample, now).is_empty());
        sample.boot = "boot".into();
        sample.key.first_seen_unix_ms = 2_000;
        assert!(cache.matching(&sample, now).is_empty());
        sample.key.first_seen_unix_ms = 1_020;
        assert!(cache.matching(&sample, now + TTL).is_empty());
        batch.flows[0].packets = 0;
        batch.flows[0].lifecycle = FlowLifecycle::Ended as i32;
        cache.observe(&batch, now);
        assert!(cache.matching(&sample, now).is_empty());
        batch.flows[0].packets = 1;
        for id in 0..=CAPACITY {
            batch.flows[0].policy_flow_id = id.to_string();
            cache.observe(&batch, now);
        }
        assert_eq!(cache.entries.len(), CAPACITY);
        assert_eq!(cache.expirations.len(), CAPACITY);
        // Refreshing an entry cannot leave unbounded expiration records.
        for _ in 0..10 {
            cache.observe(&batch, now + Duration::from_secs(1));
        }
        assert_eq!(cache.expirations.len(), CAPACITY);
        cache.observe(
            &TelemetryBatch::default(),
            now + TTL + Duration::from_secs(1),
        );
        assert!(cache.entries.is_empty());
        assert!(cache.expirations.is_empty());
    }

    #[test]
    fn explicit_sample_identity_includes_only_exact_tuple_lifetime_aliases() {
        let now = Instant::now();
        let base = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 2],
            client_port: 40_001,
            remote_ip: vec![203, 0, 113, 9],
            remote_port: 7000,
            client_mac: vec![2, 0, 0, 0, 0, 2],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_150,
            policy_flow_id: "sampled-key".into(),
            packets: 4,
            ..Default::default()
        };
        let mut same_connection_other_hook = base.clone();
        same_connection_other_hook.policy_flow_id = "other-hook-key".into();
        same_connection_other_hook.first_seen_unix_ms = 1_010;

        // A proxy-created upstream connection has a different client tuple,
        // even when it overlaps the original socket in time.
        let mut proxy_upstream = base.clone();
        proxy_upstream.policy_flow_id = "proxy-upstream-key".into();
        proxy_upstream.client_ip = vec![192, 0, 2, 1];
        proxy_upstream.client_port = 39_500;

        let mut old_reused_tuple = base.clone();
        old_reused_tuple.policy_flow_id = "old-lifetime-key".into();
        old_reused_tuple.first_seen_unix_ms = 700;
        old_reused_tuple.last_seen_unix_ms = 900;

        let mut cache = FlowContextCache::default();
        cache.observe(
            &TelemetryBatch {
                gateway_id: "gw".into(),
                boot_id: "boot".into(),
                flows: vec![
                    base.clone(),
                    same_connection_other_hook,
                    proxy_upstream,
                    old_reused_tuple,
                ],
                ..Default::default()
            },
            now,
        );
        let mut sample = CachedResult::for_test(
            "gw".into(),
            "boot".into(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: base.client_ip.clone(),
                client_port: base.client_port,
                remote_ip: base.remote_ip.clone(),
                remote_port: base.remote_port,
                first_seen_unix_ms: 1_050,
            },
            1_150,
            None,
        );
        sample.policy_flow_ids.push("sampled-key".into());

        let matched = cache.matching(&sample, now);
        let matched_ids = matched
            .iter()
            .map(|flow| flow.policy_flow_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(matched_ids, ["other-hook-key", "sampled-key"]);
    }

    #[test]
    fn explicit_sample_identity_fails_closed_on_conflicting_alias_path() {
        let now = Instant::now();
        let base = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 2],
            client_port: 40_001,
            remote_ip: vec![203, 0, 113, 9],
            remote_port: 7000,
            client_mac: vec![2, 0, 0, 0, 0, 2],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_150,
            policy_flow_id: "sampled-key".into(),
            packets: 4,
            ..Default::default()
        };
        let mut conflicting = base.clone();
        conflicting.policy_flow_id = "conflicting-key".into();
        conflicting.nat ^= 1;
        let mut cache = FlowContextCache::default();
        cache.observe(
            &TelemetryBatch {
                gateway_id: "gw".into(),
                boot_id: "boot".into(),
                flows: vec![base.clone(), conflicting],
                ..Default::default()
            },
            now,
        );
        let mut sample = CachedResult::for_test(
            "gw".into(),
            "boot".into(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: base.client_ip,
                client_port: base.client_port,
                remote_ip: base.remote_ip,
                remote_port: base.remote_port,
                first_seen_unix_ms: 1_050,
            },
            1_150,
            None,
        );
        sample.policy_flow_ids.push("sampled-key".into());

        assert!(cache.matching(&sample, now).is_empty());
    }

    #[test]
    fn completed_sample_waits_for_late_flow_context_before_association() {
        let now = Instant::now();
        let gateway = "gw".to_owned();
        let boot = "boot".to_owned();
        let flow = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 2],
            client_port: 40_001,
            remote_ip: vec![203, 0, 113, 9],
            remote_port: 7000,
            client_mac: vec![2, 0, 0, 0, 0, 2],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_150,
            packets: 4,
            ..Default::default()
        };
        let sample = CachedResult::for_test(
            gateway.clone(),
            boot.clone(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                client_port: flow.client_port,
                remote_ip: flow.remote_ip.clone(),
                remote_port: flow.remote_port,
                first_seen_unix_ms: 1_100,
            },
            1_150,
            None,
        );
        let mut pending = PendingFlowSamples::default();
        let mut contexts = FlowContextCache::default();
        pending.defer(sample, now);

        assert!(pending.take_ready(&contexts, now).is_empty());
        contexts.observe(
            &TelemetryBatch {
                gateway_id: gateway,
                boot_id: boot,
                flows: vec![flow.clone()],
                ..Default::default()
            },
            now,
        );

        let ready = pending.take_ready(&contexts, now);
        assert_eq!(ready.len(), 1);
        assert_eq!(contexts.matching(&ready[0], now), [flow]);
    }

    #[test]
    fn missing_sample_policy_id_uses_only_exact_tuple_and_overlapping_lifetime() {
        let now = Instant::now();
        let mut cache = FlowContextCache::default();
        let flow = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_100,
            policy_flow_id: String::new(),
            packets: 1,
            ..Default::default()
        };
        cache.observe(
            &TelemetryBatch {
                gateway_id: "gw".into(),
                boot_id: "boot".into(),
                flows: vec![flow.clone()],
                ..Default::default()
            },
            now,
        );
        let sample = CachedResult::for_test(
            "gw".into(),
            "boot".into(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 1],
                client_port: 50_000,
                remote_ip: vec![198, 51, 100, 1],
                remote_port: 443,
                first_seen_unix_ms: 1_020,
            },
            1_100,
            None,
        );

        let matched = cache.matching(&sample, now);
        assert_eq!(matched.len(), 1);
        assert!(matched[0].policy_flow_id.is_empty());

        let mut refreshed = flow.clone();
        refreshed.last_seen_unix_ms = 1_200;
        refreshed.packets = 2;
        cache.observe(
            &TelemetryBatch {
                gateway_id: "gw".into(),
                boot_id: "boot".into(),
                flows: vec![refreshed],
                ..Default::default()
            },
            now + Duration::from_secs(1),
        );
        assert_eq!(cache.anonymous_entries.len(), 1);
        assert_eq!(
            cache.matching(&sample, now + Duration::from_secs(1)).len(),
            1
        );

        let mut unrelated = sample.clone();
        unrelated.key.client_port += 1;
        assert!(cache.matching(&unrelated, now).is_empty());
        unrelated = sample.clone();
        unrelated.key.first_seen_unix_ms = 2_000;
        assert!(cache.matching(&unrelated, now).is_empty());
    }

    #[test]
    fn missing_sample_policy_id_fails_closed_on_conflicting_client_identity() {
        let now = Instant::now();
        let mut cache = FlowContextCache::default();
        let base = FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 50_000,
            remote_ip: vec![198, 51, 100, 1],
            remote_port: 443,
            client_mac: vec![2, 0, 0, 0, 0, 1],
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 1_100,
            policy_flow_id: String::new(),
            packets: 1,
            ..Default::default()
        };
        let mut conflicting = base.clone();
        conflicting.client_mac = vec![2, 0, 0, 0, 0, 2];
        cache.observe(
            &TelemetryBatch {
                gateway_id: "gw".into(),
                boot_id: "boot".into(),
                flows: vec![base, conflicting],
                ..Default::default()
            },
            now,
        );
        let sample = CachedResult::for_test(
            "gw".into(),
            "boot".into(),
            FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: vec![192, 0, 2, 1],
                client_port: 50_000,
                remote_ip: vec![198, 51, 100, 1],
                remote_port: 443,
                first_seen_unix_ms: 1_020,
            },
            1_100,
            None,
        );

        assert!(cache.matching(&sample, now).is_empty());
    }
}
