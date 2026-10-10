use chrono::{DateTime, Datelike, Timelike, Utc};
use chrono_tz::Tz;
use netqmon_protocol::policy::{PolicyActionKind, PolicySnapshotEntry, PolicyWireFrame};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyPreviewRequest {
    pub gateway_id: String,
    pub client_mac: String,
    pub application_id: String,
    pub category_id: String,
    pub application_confidence: f64,
    pub scope: String,
    pub at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PolicyPreviewResult {
    pub matched_policies: Vec<PolicyPreviewMatch>,
    pub selected_block_verdict: String,
    pub active_limits: Vec<PolicyPreviewLimit>,
    pub explanation: String,
    pub unsupported_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PolicyPreviewMatch {
    pub policy_id: String,
    pub name: String,
    pub action: String,
    pub priority: u16,
    pub selected: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PolicyPreviewLimit {
    pub policy_id: String,
    pub name: String,
    pub download_bps: Option<u64>,
    pub upload_bps: Option<u64>,
    pub status: String,
    pub reason_code: Option<String>,
}

pub(crate) fn evaluate_preview(
    request: &PolicyPreviewRequest,
    policies: &[PolicySnapshotEntry],
    application_block_supported: bool,
    application_limit_supported: bool,
) -> PolicyPreviewResult {
    let client_mac = request.client_mac.to_ascii_uppercase();
    let mut unsupported_reasons = Vec::new();
    let mut matches = policies
        .iter()
        .filter(|policy| policy.spec.gateway_id == request.gateway_id)
        .filter(|policy| policy.spec.enabled)
        .filter(|policy| policy.spec.network.scope == "internet")
        .filter(|policy| policy.spec.network.direction == "both")
        .filter(|policy| is_application_policy(policy))
        .filter(|policy| schedule_active(policy, request.at_ms))
        .filter(|policy| selectors_match(policy, &client_mac, request))
        .collect::<Vec<_>>();

    if request.scope != "internet" {
        unsupported_reasons.push("unsupported_scope".to_owned());
        matches.clear();
    }
    if request.application_id == "unknown" {
        unsupported_reasons.push("application_id_unknown_fail_open".to_owned());
        matches.clear();
    } else if !request.application_confidence.is_finite()
        || !(0.0..=1.0).contains(&request.application_confidence)
    {
        unsupported_reasons.push("invalid_application_confidence".to_owned());
        matches.clear();
    }

    matches.sort_by(|left, right| {
        left.spec
            .priority
            .cmp(&right.spec.priority)
            .then_with(|| specificity(right, request).cmp(&specificity(left, request)))
            .then_with(|| left.id.cmp(&right.id))
    });

    let winning_verdict = matches.iter().find(|policy| {
        matches!(
            policy.spec.action.kind,
            PolicyActionKind::Block | PolicyActionKind::Allow
        )
    });
    let verdict = winning_verdict.map_or_else(
        || "none".to_owned(),
        |policy| match policy.spec.action.kind {
            PolicyActionKind::Block if application_block_supported => "block".to_owned(),
            PolicyActionKind::Allow if application_block_supported => "allow".to_owned(),
            _ => {
                unsupported_reasons.push("unsupported_application_block".to_owned());
                "unsupported".to_owned()
            }
        },
    );

    let mut active_limits = Vec::new();
    for policy in matches
        .iter()
        .filter(|policy| policy.spec.action.kind == PolicyActionKind::Limit)
    {
        let (status, reason_code) = if policy.spec.selectors.clients.is_empty() {
            unsupported_reasons.push("unsupported_global_app_limit".to_owned());
            (
                "unsupported",
                Some("unsupported_global_app_limit".to_owned()),
            )
        } else if !application_limit_supported {
            unsupported_reasons.push("unsupported_application_shaping".to_owned());
            (
                "unsupported",
                Some("unsupported_application_shaping".to_owned()),
            )
        } else {
            ("supported", None)
        };
        active_limits.push(PolicyPreviewLimit {
            policy_id: policy.id.clone(),
            name: policy.spec.name.clone(),
            download_bps: policy.spec.action.download_bps,
            upload_bps: policy.spec.action.upload_bps,
            status: status.to_owned(),
            reason_code,
        });
    }

    unsupported_reasons.sort();
    unsupported_reasons.dedup();
    let selected_id = winning_verdict.map(|policy| policy.id.as_str());
    let matched_policies = matches
        .iter()
        .map(|policy| PolicyPreviewMatch {
            policy_id: policy.id.clone(),
            name: policy.spec.name.clone(),
            action: action_name(policy.spec.action.kind).to_owned(),
            priority: policy.spec.priority,
            selected: selected_id == Some(policy.id.as_str()),
        })
        .collect::<Vec<_>>();
    let explanation = if request.scope != "internet" {
        "Application policies only apply to internet flows.".to_owned()
    } else if request.application_id == "unknown" {
        "The application is unknown, so application policies fail open.".to_owned()
    } else if matches.is_empty() {
        "No enabled application policy matches this client, application, confidence, and time window.".to_owned()
    } else if verdict == "unsupported" {
        "A policy matches, but this gateway has no verified application-flow enforcement capability.".to_owned()
    } else if verdict == "block" {
        "The selected application policy blocks this identified flow after classification."
            .to_owned()
    } else if verdict == "allow" {
        "The selected application allow rule clears an application-layer block; client blocks and limits still apply.".to_owned()
    } else {
        "An application policy matches; its action does not select a block or allow verdict."
            .to_owned()
    };

    PolicyPreviewResult {
        matched_policies,
        selected_block_verdict: verdict,
        active_limits,
        explanation,
        unsupported_reasons,
    }
}

/// Return an expiry bounded by every selected policy's currently active UTC
/// schedule window. `None` means the selected policies are missing, disabled,
/// or outside their active schedule window.
pub(crate) fn flow_verdict_expiry(
    frame: &PolicyWireFrame,
    policy_ids: &[String],
    now_ms: i64,
    ttl_ms: i64,
) -> Option<i64> {
    let PolicyWireFrame::PolicySnapshot {
        policies,
        schedule_intervals,
        valid_until_ms,
        ..
    } = frame
    else {
        return None;
    };
    if policy_ids.is_empty() || now_ms < 0 || now_ms >= *valid_until_ms || ttl_ms <= 0 {
        return None;
    }
    let mut expiry = now_ms.saturating_add(ttl_ms).min(*valid_until_ms);
    for policy_id in policy_ids {
        let policy = policies.iter().find(|policy| policy.id == *policy_id)?;
        if !policy.spec.enabled {
            return None;
        }
        if policy.spec.schedule.is_some() {
            let intervals = schedule_intervals
                .iter()
                .find(|intervals| intervals.policy_id == *policy_id)?;
            let active_end = intervals
                .intervals
                .iter()
                .find(|interval| interval.start_ms <= now_ms && now_ms < interval.end_ms)?
                .end_ms;
            expiry = expiry.min(active_end);
        }
    }
    (expiry > now_ms).then_some(expiry)
}

fn is_application_policy(policy: &PolicySnapshotEntry) -> bool {
    !policy.spec.selectors.applications.is_empty() || !policy.spec.selectors.categories.is_empty()
}

fn selectors_match(
    policy: &PolicySnapshotEntry,
    client_mac: &str,
    request: &PolicyPreviewRequest,
) -> bool {
    let selectors = &policy.spec.selectors;
    let client_matches = selectors.clients.is_empty()
        || selectors
            .clients
            .iter()
            .any(|client| client.eq_ignore_ascii_case(client_mac));
    let application_matches = selectors.applications.is_empty()
        || selectors
            .applications
            .iter()
            .any(|application| application == &request.application_id);
    let category_matches = selectors.categories.is_empty()
        || selectors
            .categories
            .iter()
            .any(|category| category == &request.category_id);
    let app_condition = if selectors.applications.is_empty() {
        category_matches
    } else if selectors.categories.is_empty() {
        application_matches
    } else {
        application_matches || category_matches
    };
    client_matches
        && app_condition
        && request.application_confidence >= selectors.min_application_confidence
}

fn specificity(policy: &PolicySnapshotEntry, _request: &PolicyPreviewRequest) -> u8 {
    u8::from(!policy.spec.selectors.clients.is_empty())
        .saturating_add(u8::from(!policy.spec.selectors.applications.is_empty()).saturating_mul(2))
        .saturating_add(u8::from(!policy.spec.selectors.categories.is_empty()))
}

fn schedule_active(policy: &PolicySnapshotEntry, at_ms: i64) -> bool {
    let Some(schedule) = &policy.spec.schedule else {
        return true;
    };
    let Some(at) = DateTime::<Utc>::from_timestamp_millis(at_ms) else {
        return false;
    };
    let Ok(timezone) = schedule.timezone.parse::<Tz>() else {
        return false;
    };
    let local = at.with_timezone(&timezone);
    let weekday = match local.weekday().num_days_from_monday() {
        0 => netqmon_protocol::policy::PolicyWeekday::Mon,
        1 => netqmon_protocol::policy::PolicyWeekday::Tue,
        2 => netqmon_protocol::policy::PolicyWeekday::Wed,
        3 => netqmon_protocol::policy::PolicyWeekday::Thu,
        4 => netqmon_protocol::policy::PolicyWeekday::Fri,
        5 => netqmon_protocol::policy::PolicyWeekday::Sat,
        _ => netqmon_protocol::policy::PolicyWeekday::Sun,
    };
    let minute = local.hour() * 60 + local.minute();
    schedule.windows.iter().any(|window| {
        window.days.contains(&weekday)
            && parse_minute(&window.start).is_some_and(|start| minute >= start)
            && parse_minute(&window.end).is_some_and(|end| minute < end)
    })
}

fn parse_minute(value: &str) -> Option<u32> {
    let (hours, minutes) = value.split_once(':')?;
    Some(hours.parse::<u32>().ok()?.checked_mul(60)? + minutes.parse::<u32>().ok()?)
}

fn action_name(action: PolicyActionKind) -> &'static str {
    match action {
        PolicyActionKind::Block => "block",
        PolicyActionKind::Allow => "allow",
        PolicyActionKind::Limit => "limit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_protocol::policy::{
        PolicyAction, PolicyNetworkSelector, PolicySchedule, PolicyScheduleWindow, PolicySelectors,
        PolicySpecV1, PolicyWeekday,
    };

    fn policy(
        id: &str,
        priority: u16,
        action: PolicyActionKind,
        clients: Vec<&str>,
        applications: Vec<&str>,
        categories: Vec<&str>,
    ) -> PolicySnapshotEntry {
        PolicySnapshotEntry {
            id: id.to_owned(),
            spec: PolicySpecV1 {
                schema_version: 1,
                gateway_id: "gw".to_owned(),
                name: id.to_owned(),
                description: String::new(),
                enabled: true,
                priority,
                selectors: PolicySelectors {
                    clients: clients.into_iter().map(str::to_owned).collect(),
                    applications: applications.into_iter().map(str::to_owned).collect(),
                    categories: categories.into_iter().map(str::to_owned).collect(),
                    min_application_confidence: 0.85,
                },
                network: PolicyNetworkSelector {
                    scope: "internet".to_owned(),
                    direction: "both".to_owned(),
                },
                action: PolicyAction {
                    kind: action,
                    download_bps: (action == PolicyActionKind::Limit).then_some(5_000_000),
                    upload_bps: None,
                },
                schedule: None,
            },
        }
    }

    fn request(application_id: &str, category_id: &str) -> PolicyPreviewRequest {
        PolicyPreviewRequest {
            gateway_id: "gw".to_owned(),
            client_mac: "02:00:00:00:00:01".to_owned(),
            application_id: application_id.to_owned(),
            category_id: category_id.to_owned(),
            application_confidence: 0.95,
            scope: "internet".to_owned(),
            at_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn unknown_and_low_confidence_flows_fail_open() {
        let policies = [policy(
            "block",
            1,
            PolicyActionKind::Block,
            vec![],
            vec!["video"],
            vec![],
        )];
        let unknown = evaluate_preview(&request("unknown", "unknown"), &policies, true, true);
        assert_eq!(unknown.selected_block_verdict, "none");
        assert!(
            unknown
                .unsupported_reasons
                .contains(&"application_id_unknown_fail_open".to_owned())
        );

        let mut low = request("video", "streaming");
        low.application_confidence = 0.5;
        let result = evaluate_preview(&low, &policies, true, true);
        assert!(result.matched_policies.is_empty());
    }

    #[test]
    fn specific_client_application_rule_wins_with_stable_tie_breaks() {
        let policies = [
            policy(
                "global",
                5,
                PolicyActionKind::Block,
                vec![],
                vec!["video"],
                vec![],
            ),
            policy(
                "client",
                5,
                PolicyActionKind::Allow,
                vec!["02:00:00:00:00:01"],
                vec!["video"],
                vec![],
            ),
        ];
        let result = evaluate_preview(&request("video", "streaming"), &policies, true, true);
        assert_eq!(result.selected_block_verdict, "allow");
        assert!(
            result
                .matched_policies
                .iter()
                .any(|item| item.policy_id == "client" && item.selected)
        );
    }

    #[test]
    fn category_match_requires_a_known_application_and_limits_are_capability_gated() {
        let policies = [
            policy(
                "category",
                5,
                PolicyActionKind::Block,
                vec![],
                vec![],
                vec!["streaming"],
            ),
            policy(
                "limit",
                10,
                PolicyActionKind::Limit,
                vec!["02:00:00:00:00:01"],
                vec!["video"],
                vec![],
            ),
            policy(
                "global-limit",
                20,
                PolicyActionKind::Limit,
                vec![],
                vec!["video"],
                vec![],
            ),
        ];
        let result = evaluate_preview(&request("video", "streaming"), &policies, false, false);
        assert_eq!(result.selected_block_verdict, "unsupported");
        assert_eq!(result.active_limits.len(), 2);
        assert!(
            result
                .unsupported_reasons
                .contains(&"unsupported_global_app_limit".to_owned())
        );
        assert!(
            result
                .unsupported_reasons
                .contains(&"unsupported_application_shaping".to_owned())
        );

        let unknown = evaluate_preview(&request("unknown", "streaming"), &policies, true, true);
        assert_eq!(unknown.matched_policies.len(), 0);
    }

    #[test]
    fn application_limits_are_selected_only_when_the_agent_reports_shaping_support() {
        let policies = [policy(
            "app-limit",
            10,
            PolicyActionKind::Limit,
            vec!["02:00:00:00:00:01"],
            vec!["video"],
            vec![],
        )];
        let supported = evaluate_preview(&request("video", "streaming"), &policies, true, true);
        assert_eq!(supported.active_limits.len(), 1);
        assert_eq!(supported.active_limits[0].status, "supported");
        assert!(supported.unsupported_reasons.is_empty());

        let unsupported = evaluate_preview(&request("video", "streaming"), &policies, true, false);
        assert_eq!(unsupported.active_limits[0].status, "unsupported");
        assert_eq!(
            unsupported.active_limits[0].reason_code.as_deref(),
            Some("unsupported_application_shaping")
        );
    }

    #[test]
    fn schedule_evaluation_uses_the_supplied_instant_and_timezone() {
        let mut entry = policy(
            "scheduled",
            1,
            PolicyActionKind::Block,
            vec![],
            vec!["video"],
            vec![],
        );
        entry.spec.schedule = Some(PolicySchedule {
            timezone: "America/New_York".to_owned(),
            windows: vec![PolicyScheduleWindow {
                days: vec![PolicyWeekday::Sun],
                start: "01:00".to_owned(),
                end: "02:00".to_owned(),
            }],
        });
        let inside = request("video", "streaming");
        let start = DateTime::parse_from_rfc3339("2027-01-03T06:30:00Z")
            .unwrap()
            .timestamp_millis();
        let mut inside = inside;
        inside.at_ms = start;
        assert!(
            evaluate_preview(&inside, &[entry.clone()], true, true)
                .matched_policies
                .len()
                == 1
        );
        inside.at_ms += 60 * 60 * 1000;
        assert!(
            evaluate_preview(&inside, &[entry], true, true)
                .matched_policies
                .is_empty()
        );
    }

    #[test]
    fn flow_verdict_expiry_never_crosses_a_scheduled_window() {
        let mut entry = policy(
            "scheduled",
            1,
            PolicyActionKind::Block,
            vec![],
            vec!["video"],
            vec![],
        );
        entry.spec.schedule = Some(PolicySchedule {
            timezone: "UTC".to_owned(),
            windows: vec![PolicyScheduleWindow {
                days: vec![PolicyWeekday::Mon],
                start: "00:00".to_owned(),
                end: "01:00".to_owned(),
            }],
        });
        let frame = PolicyWireFrame::snapshot(
            "gw".to_owned(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
            1,
            1,
            1_000,
            100_000,
            vec![entry],
            vec![netqmon_protocol::policy::PolicyScheduleIntervals {
                policy_id: "scheduled".to_owned(),
                intervals: vec![netqmon_protocol::policy::PolicyScheduleInterval {
                    start_ms: 2_000,
                    end_ms: 3_000,
                }],
            }],
        )
        .unwrap();
        let ids = vec!["scheduled".to_owned()];
        assert_eq!(
            flow_verdict_expiry(&frame, &ids, 2_500, 10_000),
            Some(3_000)
        );
        assert_eq!(flow_verdict_expiry(&frame, &ids, 3_000, 10_000), None);
    }
}
