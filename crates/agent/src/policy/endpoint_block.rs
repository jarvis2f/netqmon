//! Client-side endpoint blocks deliberately omit the client's ephemeral port.
//! These leases outlive exact flow verdicts, but remain bounded by the current
//! policy snapshot and schedule. Only a validated Block command may create one.

use crate::flow::FlowKey;
use netqmon_protocol::policy::{PolicyActionKind, PolicyWireFrame};

pub(crate) const KEY_SIZE: usize = 44;
pub(crate) const MAX_ENTRIES: usize = 8_192;
pub(crate) const CACHE_TTL_MS: i64 = 5 * 60 * 1_000;

/// Called only after validating the command's gateway, boot, revision and short
/// flow lease. The accepted snapshot authorizes this independent endpoint cache;
/// stale commands or cache hits cannot extend it on their own.
pub(crate) fn expires_at_ms(
    snapshot: &PolicyWireFrame,
    policy_ids: &[String],
    client_mac: &str,
    issued_at_ms: i64,
    now_ms: i64,
) -> Option<i64> {
    let PolicyWireFrame::PolicySnapshot {
        policies,
        schedule_intervals,
        valid_until_ms,
        ..
    } = snapshot
    else {
        return None;
    };
    if policy_ids.is_empty() || issued_at_ms < 0 || now_ms < 0 {
        return None;
    }
    let mut expiry = issued_at_ms
        .saturating_add(CACHE_TTL_MS)
        .min(*valid_until_ms);
    for id in policy_ids {
        let policy = policies.iter().find(|policy| policy.id == *id)?;
        if !policy.spec.enabled
            || policy.spec.action.kind != PolicyActionKind::Block
            || (policy.spec.selectors.applications.is_empty()
                && policy.spec.selectors.categories.is_empty())
            || !policy
                .spec
                .selectors
                .clients
                .iter()
                .any(|mac| mac.eq_ignore_ascii_case(client_mac))
        {
            return None;
        }
        if policy.spec.schedule.is_some() {
            let intervals = schedule_intervals
                .iter()
                .find(|entry| entry.policy_id == *id)?;
            let active = intervals
                .intervals
                .iter()
                .find(|interval| interval.start_ms <= now_ms && now_ms < interval.end_ms)?;
            expiry = expiry.min(active.end_ms);
        }
    }
    // Another matching rule (including Allow) can change the winning verdict
    // at its next schedule transition. Do not carry a cached block across it.
    for policy in policies.iter().filter(|policy| {
        policy.spec.enabled
            && policy.spec.schedule.is_some()
            && (!policy.spec.selectors.applications.is_empty()
                || !policy.spec.selectors.categories.is_empty())
            && policy
                .spec
                .selectors
                .clients
                .iter()
                .any(|mac| mac.eq_ignore_ascii_case(client_mac))
    }) {
        let intervals = schedule_intervals
            .iter()
            .find(|entry| entry.policy_id == policy.id)?;
        for boundary in intervals
            .intervals
            .iter()
            .flat_map(|interval| [interval.start_ms, interval.end_ms])
            .filter(|boundary| *boundary > now_ms)
        {
            expiry = expiry.min(boundary);
        }
    }
    (expiry > now_ms).then_some(expiry)
}

/// Canonical client -> remote key, matching `endpoint_block_key` in the BPF ABI.
/// Only verified client-ingress aliases may be used to learn these keys.
pub(crate) fn key(alias: &FlowKey, client_mac: [u8; 6]) -> [u8; KEY_SIZE] {
    let mut bytes = [0; KEY_SIZE];
    bytes[0] = alias.ip_version;
    bytes[1] = alias.protocol;
    bytes[2..4].copy_from_slice(&alias.destination_port.to_be_bytes());
    bytes[4..20].copy_from_slice(&alias.source_address);
    bytes[20..36].copy_from_slice(&alias.destination_address);
    bytes[36..42].copy_from_slice(&client_mac);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const MAC: &str = "AA:BB:CC:DD:EE:FF";

    fn snapshot() -> PolicyWireFrame {
        serde_json::from_value(serde_json::json!({
            "type": "policy_snapshot", "wire_version": 1,
            "gateway_id": "gw-test", "controller_epoch": "epoch", "config_revision": 7,
            "bundle_generation": 1, "generated_at_ms": NOW, "valid_until_ms": NOW + 600_000,
            "checksum": "test", "schedule_intervals": [],
            "policies": [{"id": "block", "spec": {
                "schema_version": 1, "gateway_id": "gw-test", "name": "Block app",
                "enabled": true, "priority": 500,
                "selectors": {"clients": [MAC], "applications": ["app"], "categories": []},
                "network": {"scope": "internet", "direction": "both"},
                "action": {"type": "block"}, "schedule": null
            }}]
        }))
        .unwrap()
    }

    fn schedule(policy: &mut netqmon_protocol::policy::PolicySnapshotEntry) {
        policy.spec.schedule = Some(
            serde_json::from_value(serde_json::json!({
                "timezone": "UTC", "windows": [{"days": ["mon"], "start": "09:00", "end": "10:00"}]
            }))
            .unwrap(),
        );
    }

    #[test]
    fn cache_outlives_udp_flow_but_is_bounded_from_the_original_decision() {
        let snapshot = snapshot();
        let ids = ["block".to_owned()];
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW),
            Some(NOW + 300_000)
        );
        // Reconnection after the UDP flow's 30-second lease has ended still
        // falls within the endpoint lease. Time passing cannot renew the lease.
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW + 45_000),
            Some(NOW + 300_000)
        );
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW + 300_000),
            None
        );
    }

    #[test]
    fn cache_requires_an_enabled_block_for_the_same_client_and_snapshot() {
        let mut snapshot = snapshot();
        let ids = ["block".to_owned()];
        assert_eq!(
            expires_at_ms(&snapshot, &ids, "00:11:22:33:44:55", NOW, NOW),
            None
        );
        assert_eq!(
            expires_at_ms(&snapshot, &["missing".into()], MAC, NOW, NOW),
            None
        );
        let PolicyWireFrame::PolicySnapshot { valid_until_ms, .. } = &mut snapshot else {
            unreachable!()
        };
        *valid_until_ms = NOW + 60_000;
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW),
            Some(NOW + 60_000)
        );
        let PolicyWireFrame::PolicySnapshot { policies, .. } = &mut snapshot else {
            unreachable!()
        };
        policies[0].spec.enabled = false;
        assert_eq!(expires_at_ms(&snapshot, &ids, MAC, NOW, NOW), None);
        let PolicyWireFrame::PolicySnapshot { policies, .. } = &mut snapshot else {
            unreachable!()
        };
        policies[0].spec.enabled = true;
        policies[0].spec.action.kind = PolicyActionKind::Allow;
        assert_eq!(expires_at_ms(&snapshot, &ids, MAC, NOW, NOW), None);
    }

    #[test]
    fn cache_stops_at_block_window_end_or_another_rules_next_transition() {
        use netqmon_protocol::policy::{PolicyScheduleInterval, PolicyScheduleIntervals};
        let mut snapshot = snapshot();
        let ids = ["block".to_owned()];
        let PolicyWireFrame::PolicySnapshot {
            policies,
            schedule_intervals,
            ..
        } = &mut snapshot
        else {
            unreachable!()
        };
        schedule(&mut policies[0]);
        schedule_intervals.push(PolicyScheduleIntervals {
            policy_id: "block".into(),
            intervals: vec![PolicyScheduleInterval {
                start_ms: NOW - 1000,
                end_ms: NOW + 90_000,
            }],
        });
        let mut allow = policies[0].clone();
        allow.id = "allow".into();
        allow.spec.action.kind = PolicyActionKind::Allow;
        allow.spec.priority = 100;
        policies.push(allow);
        schedule_intervals.push(PolicyScheduleIntervals {
            policy_id: "allow".into(),
            intervals: vec![PolicyScheduleInterval {
                start_ms: NOW + 40_000,
                end_ms: NOW + 120_000,
            }],
        });
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW),
            Some(NOW + 40_000)
        );
        let PolicyWireFrame::PolicySnapshot { policies, .. } = &mut snapshot else {
            unreachable!()
        };
        policies[1].spec.enabled = false;
        assert_eq!(
            expires_at_ms(&snapshot, &ids, MAC, NOW, NOW),
            Some(NOW + 90_000)
        );
        assert_eq!(expires_at_ms(&snapshot, &ids, MAC, NOW, NOW + 90_000), None);
    }

    #[test]
    fn reconnects_share_a_key_but_other_clients_and_endpoints_do_not() {
        let original = FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 1,
            hook: 1,
            ifindex: 7,
            source_address: [1; 16],
            destination_address: [2; 16],
            source_port: 50_000,
            destination_port: 443,
        };
        let mac = [0xAA; 6];
        let expected = key(&original, mac);
        let mut reconnect = original.clone();
        reconnect.source_port = 60_000;
        reconnect.ifindex = 8;
        assert_eq!(expected, key(&reconnect, mac));
        assert_ne!(expected, key(&original, [0xBB; 6]));
        for variant in 0..5 {
            let mut different = original.clone();
            match variant {
                0 => different.source_address[0] += 1,
                1 => different.destination_address[0] += 1,
                2 => different.destination_port = 8443,
                3 => different.protocol = 17,
                _ => different.ip_version = 6,
            }
            assert_ne!(expected, key(&different, mac));
        }
        assert_eq!(&expected[2..4], &443_u16.to_be_bytes());
        assert_eq!(&expected[42..], &[0; 2]);
    }
}
