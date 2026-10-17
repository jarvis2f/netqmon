//! Pure policy selection for the priority backend; no legacy mark compilation.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use netqmon_protocol::policy::{
    PolicyActionKind, PolicyResult, PolicyResultStatus, PolicyWireFrame, is_client_total_spec,
};

use crate::identity::MacAddress;

use super::schedule::{self, ScheduleState};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TotalRates {
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
    pub policy_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationRates {
    pub mac: String,
    pub policy_id: String,
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct PrioritySelection {
    pub totals: BTreeMap<String, TotalRates>,
    /// A class budget exists for the selected client, but packets enter it only
    /// when an exact, high-confidence Flow verdict names this policy.
    pub application_limits: Vec<ApplicationRates>,
    pub clients: BTreeSet<String>,
    /// Existing Internet block semantics; address resolution remains a separate
    /// verified step. A client total itself requires MAC/FDB, not an IP guess.
    pub blocked_macs: BTreeSet<String>,
    pub results: Vec<PolicyResult>,
    pub next_transition_ms: Option<i64>,
}

impl PrioritySelection {
    pub(crate) fn from_snapshot(
        snapshot: &PolicyWireFrame,
        gateway: &str,
        now_ms: Option<i64>,
    ) -> Result<Self, String> {
        snapshot.validate()?;
        let PolicyWireFrame::PolicySnapshot {
            gateway_id,
            policies,
            schedule_intervals,
            valid_until_ms,
            ..
        } = snapshot
        else {
            return Err("priority_snapshot_required".to_owned());
        };
        if gateway_id != gateway {
            return Err("priority_gateway_mismatch".to_owned());
        }
        let mut ordered = policies.iter().collect::<Vec<_>>();
        ordered.sort_by(|a, b| {
            a.spec
                .priority
                .cmp(&b.spec.priority)
                .then_with(|| a.id.cmp(&b.id))
        });
        let mut selection = Self {
            totals: BTreeMap::new(),
            application_limits: Vec::new(),
            clients: BTreeSet::new(),
            blocked_macs: BTreeSet::new(),
            results: Vec::new(),
            next_transition_ms: None,
        };
        let mut block_decided = BTreeSet::new();
        for policy in ordered {
            let mut result = PolicyResult {
                policy_id: policy.id.clone(),
                status: PolicyResultStatus::Applied,
                reason_code: None,
                message: None,
                details: None,
            };
            if !policy.spec.enabled {
                result.status = PolicyResultStatus::Disabled;
                selection.results.push(result);
                continue;
            }
            let is_application_policy = !policy.spec.selectors.applications.is_empty()
                || !policy.spec.selectors.categories.is_empty();
            if is_application_policy
                && matches!(
                    policy.spec.action.kind,
                    PolicyActionKind::Block | PolicyActionKind::Allow | PolicyActionKind::Limit
                )
                && policy.spec.selectors.clients.is_empty()
            {
                return Err("application_client_selector_required".to_owned());
            }
            let total = is_client_total_spec(&policy.spec);
            let application_limit = policy.spec.action.kind == PolicyActionKind::Limit
                && policy.spec.network.scope == "internet"
                && !policy.spec.selectors.clients.is_empty()
                && (!policy.spec.selectors.applications.is_empty()
                    || !policy.spec.selectors.categories.is_empty());
            let application_block = policy.spec.action.kind == PolicyActionKind::Block
                && policy.spec.network.scope == "internet"
                && !policy.spec.selectors.clients.is_empty()
                && (!policy.spec.selectors.applications.is_empty()
                    || !policy.spec.selectors.categories.is_empty());
            let application_allow = policy.spec.action.kind == PolicyActionKind::Allow
                && policy.spec.network.scope == "internet"
                && !policy.spec.selectors.clients.is_empty()
                && (!policy.spec.selectors.applications.is_empty()
                    || !policy.spec.selectors.categories.is_empty());
            let internet_decision = policy.spec.network.scope == "internet"
                && policy.spec.network.direction == "both"
                && !policy.spec.selectors.clients.is_empty()
                && policy.spec.selectors.applications.is_empty()
                && policy.spec.selectors.categories.is_empty()
                && matches!(
                    policy.spec.action.kind,
                    PolicyActionKind::Block | PolicyActionKind::Allow
                );
            if !total
                && !internet_decision
                && !application_limit
                && !application_block
                && !application_allow
            {
                return Err("priority_policy_shape_not_verified".to_owned());
            }
            if policy.spec.schedule.is_some() {
                let intervals = schedule_intervals
                    .iter()
                    .find(|entry| entry.policy_id == policy.id)
                    .ok_or("schedule_window_missing")?;
                let now = now_ms
                    .filter(|now| *now >= 1_500_000_000_000)
                    .ok_or("clock_invalid")?;
                for transition in intervals
                    .intervals
                    .iter()
                    .flat_map(|interval| [interval.start_ms, interval.end_ms])
                    .chain(std::iter::once(*valid_until_ms))
                    .filter(|transition| *transition > now)
                {
                    selection.next_transition_ms = Some(
                        selection
                            .next_transition_ms
                            .map_or(transition, |old| old.min(transition)),
                    );
                }
            }
            match schedule::evaluate(policy, schedule_intervals, now_ms, *valid_until_ms) {
                ScheduleState::ClockInvalid => return Err("clock_invalid".to_owned()),
                ScheduleState::Expired => {
                    result.status = PolicyResultStatus::Failed;
                    result.reason_code = Some("schedule_expired".to_owned());
                    result.message = Some("the Collector schedule window has expired".to_owned());
                    selection.results.push(result);
                    continue;
                }
                ScheduleState::Inactive => {
                    selection.results.push(result);
                    continue;
                }
                ScheduleState::Active => {}
            }
            for text in &policy.spec.selectors.clients {
                let mac = text
                    .parse::<MacAddress>()
                    .map_err(|error| error.to_string())?;
                if !mac.is_unicast() {
                    return Err("priority_identity_invalid".to_owned());
                }
                let mac = mac.to_string();
                if total {
                    selection.clients.insert(mac.clone());
                    let rates = selection.totals.entry(mac).or_default();
                    let min = |a: Option<u64>, b: Option<u64>| match (a, b) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, None) => a,
                        (None, b) => b,
                    };
                    rates.upload_bps = min(rates.upload_bps, policy.spec.action.upload_bps);
                    rates.download_bps = min(rates.download_bps, policy.spec.action.download_bps);
                    rates.policy_ids.insert(policy.id.clone());
                } else if application_limit {
                    selection.clients.insert(mac.clone());
                    selection.application_limits.push(ApplicationRates {
                        mac,
                        policy_id: policy.id.clone(),
                        upload_bps: policy.spec.action.upload_bps,
                        download_bps: policy.spec.action.download_bps,
                    });
                } else if application_block {
                    // The client lease is needed to validate exact FlowCommand
                    // identities; this does not block the entire client.
                    selection.clients.insert(mac);
                } else if application_allow {
                    // Allow is enforced by the exact FlowVerdict path. Retain
                    // the client's identity lease without removing its limits.
                    selection.clients.insert(mac);
                } else if block_decided.insert(mac.clone())
                    && policy.spec.action.kind == PolicyActionKind::Block
                {
                    selection.clients.insert(mac.clone());
                    selection.blocked_macs.insert(mac);
                }
            }
            selection.results.push(result);
        }
        selection.application_limits.sort_by(|a, b| {
            a.mac
                .cmp(&b.mac)
                .then_with(|| a.policy_id.cmp(&b.policy_id))
        });
        if selection.clients.len() > 256 {
            return Err("priority_class_slots_exhausted".to_owned());
        }
        selection
            .results
            .sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Ok(selection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_protocol::policy::{
        PolicyScheduleInterval, PolicyScheduleIntervals, PolicySnapshotEntry,
    };
    const NOW: i64 = 1_800_000_000_000;

    fn policy(id: &str, scope: &str, kind: &str, priority: u16) -> PolicySnapshotEntry {
        serde_json::from_value(serde_json::json!({"id":id,"spec":{
            "schema_version":1,"gateway_id":"gw-test","name":id,"enabled":true,"priority":priority,
            "selectors":{"clients":["02:00:00:00:AA:01"]},"network":{"scope":scope,"direction":"both"},
            "action":{"type":kind,"upload_bps":if kind=="limit" {Some(8_000_000)} else {None},
                "download_bps":if kind=="limit" {Some(16_000_000)} else {None}}
        }})).unwrap()
    }
    fn snapshot(
        policies: Vec<PolicySnapshotEntry>,
        intervals: Vec<PolicyScheduleIntervals>,
    ) -> PolicyWireFrame {
        PolicyWireFrame::snapshot(
            "gw-test".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            1,
            1,
            NOW,
            NOW + 300,
            policies,
            intervals,
        )
        .unwrap()
    }

    #[test]
    fn totals_do_not_need_ip_inference_and_allow_only_overrides_lower_block() {
        let mut tighter = policy("tight", "agent", "limit", 500);
        tighter.spec.action.download_bps = Some(4_000_000);
        let frame = snapshot(
            vec![
                policy("total", "agent", "limit", 500),
                tighter,
                policy("allow", "internet", "allow", 100),
                policy("block", "internet", "block", 200),
            ],
            vec![],
        );
        let selected = PrioritySelection::from_snapshot(&frame, "gw-test", None).unwrap();
        let rates = &selected.totals["02:00:00:00:aa:01"];
        assert_eq!(rates.upload_bps, Some(8_000_000));
        assert_eq!(rates.download_bps, Some(4_000_000));
        assert_eq!(rates.policy_ids.len(), 2);
        assert!(selected.blocked_macs.is_empty());
        assert_eq!(selected.results.len(), 4);
    }

    #[test]
    fn internet_client_limit_without_application_scope_is_not_verified() {
        let total = policy("total", "agent", "limit", 500);
        let internet_total = policy("internet-total", "internet", "limit", 500);
        assert_eq!(
            PrioritySelection::from_snapshot(
                &snapshot(vec![total.clone(), internet_total], vec![]),
                "gw-test",
                Some(NOW)
            )
            .unwrap_err(),
            "priority_policy_shape_not_verified"
        );
        assert_eq!(total.spec.network.scope, "agent");
    }

    #[test]
    fn application_limits_prepare_child_budgets_without_turning_them_into_client_totals() {
        let total = policy("total", "agent", "limit", 500);
        let mut app = policy("app", "internet", "limit", 300);
        app.spec.selectors.applications.push("video-app".to_owned());
        app.spec.action.upload_bps = Some(4_000_000);
        app.spec.action.download_bps = Some(6_000_000);
        let selection = PrioritySelection::from_snapshot(
            &snapshot(vec![total, app], vec![]),
            "gw-test",
            Some(NOW),
        )
        .unwrap();
        assert_eq!(
            selection.clients,
            BTreeSet::from(["02:00:00:00:aa:01".to_owned()])
        );
        assert_eq!(selection.totals.len(), 1);
        assert_eq!(selection.application_limits.len(), 1);
        let limit = &selection.application_limits[0];
        assert_eq!(limit.policy_id, "app");
        assert_eq!(limit.upload_bps, Some(4_000_000));
        assert_eq!(limit.download_bps, Some(6_000_000));

        let mut app_only = selection;
        app_only.totals.clear();
        assert!(app_only.clients.contains("02:00:00:00:aa:01"));
    }

    #[test]
    fn application_block_allocates_only_an_identity_lease_not_a_client_block() {
        let mut app_block = policy("app-block", "internet", "block", 50);
        app_block.spec.selectors.applications = vec!["netqmon_qos_test".to_owned()];
        let selection = PrioritySelection::from_snapshot(
            &snapshot(vec![app_block], vec![]),
            "gw-test",
            Some(NOW),
        )
        .unwrap();

        assert!(selection.blocked_macs.is_empty());
        assert!(selection.totals.is_empty());
        assert!(selection.application_limits.is_empty());
        assert!(selection.clients.contains("02:00:00:00:aa:01"));
    }

    #[test]
    fn application_allow_preserves_independent_client_and_application_limits() {
        let total = policy("total", "agent", "limit", 100);
        let mut app_block = policy("app-block", "internet", "block", 10);
        app_block.spec.selectors.applications = vec!["netqmon_qos_test".to_owned()];
        let mut app_allow = policy("app-allow", "internet", "allow", 5);
        app_allow.spec.selectors.applications = vec!["netqmon_qos_test".to_owned()];
        let mut app_limit = policy("app-limit", "internet", "limit", 20);
        app_limit.spec.selectors.applications = vec!["netqmon_qos_test".to_owned()];
        app_limit.spec.action.upload_bps = Some(2_000_000);
        app_limit.spec.action.download_bps = Some(4_000_000);

        let selected = PrioritySelection::from_snapshot(
            &snapshot(vec![app_allow, app_block, app_limit, total], vec![]),
            "gw-test",
            Some(NOW),
        )
        .unwrap();

        assert!(selected.clients.contains("02:00:00:00:aa:01"));
        assert!(selected.blocked_macs.is_empty());
        assert_eq!(
            selected.totals["02:00:00:00:aa:01"].upload_bps,
            Some(8_000_000)
        );
        assert_eq!(
            selected.totals["02:00:00:00:aa:01"].download_bps,
            Some(16_000_000)
        );
        assert_eq!(selected.application_limits.len(), 1);
        assert_eq!(selected.application_limits[0].policy_id, "app-limit");
        assert_eq!(selected.application_limits[0].upload_bps, Some(2_000_000));
        assert_eq!(selected.application_limits[0].download_bps, Some(4_000_000));
        assert_eq!(selected.results.len(), 4);
    }

    #[test]
    fn client_block_selects_exact_l2_identity_without_inventing_an_ip() {
        let block = policy("client-block", "internet", "block", 50);
        let selection =
            PrioritySelection::from_snapshot(&snapshot(vec![block], vec![]), "gw-test", Some(NOW))
                .unwrap();

        assert_eq!(
            selection.blocked_macs,
            BTreeSet::from(["02:00:00:00:aa:01".to_owned()])
        );
        assert!(selection.totals.is_empty());
        assert!(selection.application_limits.is_empty());
        assert!(selection.clients.contains("02:00:00:00:aa:01"));
    }

    #[test]
    fn schedules_bound_active_budgets_and_do_not_guess_when_clock_or_intervals_are_missing() {
        let mut entry = policy("timed", "agent", "limit", 500);
        entry.spec.schedule = Some(
            serde_json::from_value(serde_json::json!({"timezone":"UTC",
            "windows":[{"days":["mon"],"start":"09:00","end":"10:00"}]}))
            .unwrap(),
        );
        let intervals = vec![PolicyScheduleIntervals {
            policy_id: entry.id.clone(),
            intervals: vec![PolicyScheduleInterval {
                start_ms: NOW + 100,
                end_ms: NOW + 200,
            }],
        }];
        let frame = snapshot(vec![entry.clone()], intervals);
        let active = PrioritySelection::from_snapshot(&frame, "gw-test", Some(NOW + 100)).unwrap();
        assert_eq!(active.totals.len(), 1);
        assert_eq!(active.next_transition_ms, Some(NOW + 200));
        assert!(
            PrioritySelection::from_snapshot(&frame, "gw-test", Some(NOW + 200))
                .unwrap()
                .totals
                .is_empty()
        );
        let expired = PrioritySelection::from_snapshot(&frame, "gw-test", Some(NOW + 300)).unwrap();
        assert!(expired.totals.is_empty());
        assert_eq!(
            expired.results[0].reason_code.as_deref(),
            Some("schedule_expired")
        );
        assert_eq!(
            PrioritySelection::from_snapshot(&frame, "gw-test", None).unwrap_err(),
            "clock_invalid"
        );
        assert_eq!(
            PrioritySelection::from_snapshot(&snapshot(vec![entry], vec![]), "gw-test", Some(NOW))
                .unwrap_err(),
            "schedule_window_missing"
        );
    }

    #[test]
    fn disabled_unsupported_rules_do_not_convert_legacy_state_and_gateway_binding_is_checked() {
        let mut disabled = policy("disabled", "internet", "limit", 500);
        disabled.spec.enabled = false;
        let frame = snapshot(vec![disabled], vec![]);
        let selection = PrioritySelection::from_snapshot(&frame, "gw-test", Some(NOW)).unwrap();
        assert!(selection.totals.is_empty());
        assert_eq!(selection.results[0].status, PolicyResultStatus::Disabled);
        assert!(PrioritySelection::from_snapshot(&frame, "other-gateway", Some(NOW)).is_err());
    }
}
