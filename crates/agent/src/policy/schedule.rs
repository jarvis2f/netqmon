use netqmon_protocol::policy::{PolicyScheduleIntervals, PolicySnapshotEntry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScheduleState {
    Active,
    Inactive,
    Expired,
    ClockInvalid,
}

pub(crate) fn evaluate(
    policy: &PolicySnapshotEntry,
    schedule_intervals: &[PolicyScheduleIntervals],
    now_ms: Option<i64>,
    valid_until_ms: i64,
) -> ScheduleState {
    if policy.spec.schedule.is_none() {
        return ScheduleState::Active;
    }
    let Some(now_ms) = now_ms.filter(|value| *value >= 1_500_000_000_000) else {
        return ScheduleState::ClockInvalid;
    };
    if now_ms >= valid_until_ms {
        return ScheduleState::Expired;
    }
    let intervals = schedule_intervals
        .iter()
        .find(|entry| entry.policy_id == policy.id);
    if intervals.is_some_and(|entry| {
        entry
            .intervals
            .iter()
            .any(|interval| interval.start_ms <= now_ms && now_ms < interval.end_ms)
    }) {
        ScheduleState::Active
    } else {
        ScheduleState::Inactive
    }
}

#[cfg(test)]
mod tests {
    use netqmon_protocol::policy::{
        PolicyAction, PolicyActionKind, PolicyNetworkSelector, PolicySchedule,
        PolicyScheduleIntervals, PolicyScheduleWindow, PolicySelectors, PolicySpecV1,
        PolicyWeekday,
    };

    use super::*;

    fn scheduled_entry() -> PolicySnapshotEntry {
        PolicySnapshotEntry {
            id: "policy-1".to_owned(),
            spec: PolicySpecV1 {
                schema_version: 1,
                gateway_id: "gw-test".to_owned(),
                name: "scheduled".to_owned(),
                description: String::new(),
                enabled: true,
                priority: 100,
                selectors: PolicySelectors {
                    clients: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
                    applications: Vec::new(),
                    categories: Vec::new(),
                    min_application_confidence: 0.85,
                },
                network: PolicyNetworkSelector {
                    scope: "internet".to_owned(),
                    direction: "both".to_owned(),
                },
                action: PolicyAction {
                    kind: PolicyActionKind::Block,
                    download_bps: None,
                    upload_bps: None,
                },
                schedule: Some(PolicySchedule {
                    timezone: "UTC".to_owned(),
                    windows: vec![PolicyScheduleWindow {
                        days: vec![PolicyWeekday::Mon],
                        start: "09:00".to_owned(),
                        end: "10:00".to_owned(),
                    }],
                }),
            },
        }
    }

    #[test]
    fn precompiled_intervals_switch_without_collector_and_expire_safely() {
        let entry = scheduled_entry();
        let intervals = vec![PolicyScheduleIntervals {
            policy_id: entry.id.clone(),
            intervals: vec![netqmon_protocol::policy::PolicyScheduleInterval {
                start_ms: 1_800_000_000_100,
                end_ms: 1_800_000_000_200,
            }],
        }];
        assert_eq!(
            evaluate(
                &entry,
                &intervals,
                Some(1_800_000_000_150),
                1_800_000_000_300
            ),
            ScheduleState::Active
        );
        assert_eq!(
            evaluate(
                &entry,
                &intervals,
                Some(1_800_000_000_200),
                1_800_000_000_300
            ),
            ScheduleState::Inactive
        );
        assert_eq!(
            evaluate(
                &entry,
                &intervals,
                Some(1_800_000_000_300),
                1_800_000_000_300
            ),
            ScheduleState::Expired
        );
        assert_eq!(
            evaluate(&entry, &intervals, None, 1_800_000_000_300),
            ScheduleState::ClockInvalid
        );
    }
}
