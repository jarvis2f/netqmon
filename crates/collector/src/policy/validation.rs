use std::collections::HashSet;
use std::str::FromStr;

use chrono::{Datelike, Duration, NaiveTime, Utc};
use chrono_tz::Tz;
use serde::Serialize;

use super::model::{ActionKind, PolicySpecV1};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ValidationIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct KnownSelectors {
    pub gateway_exists: bool,
    pub clients: HashSet<String>,
    pub applications: HashSet<String>,
    pub categories: HashSet<String>,
}

pub(crate) fn normalize_and_validate(
    spec: &mut PolicySpecV1,
    known: Option<&KnownSelectors>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    validate_identity(spec, known, &mut issues);
    validate_selectors(spec, known, &mut issues);
    validate_network(spec, &mut issues);
    validate_action(spec, &mut issues);
    if let Some(schedule) = spec.schedule.as_mut() {
        validate_schedule(schedule, &mut issues);
    }
    issues
}

fn validate_identity(
    spec: &mut PolicySpecV1,
    known: Option<&KnownSelectors>,
    issues: &mut Vec<ValidationIssue>,
) {
    if spec.schema_version != 1 {
        issue(
            issues,
            "schema_version",
            "invalid_spec",
            "schema_version must be 1",
        );
    }
    spec.gateway_id = spec.gateway_id.trim().to_owned();
    if spec.gateway_id.is_empty() || spec.gateway_id.chars().count() > 128 {
        issue(
            issues,
            "gateway_id",
            "invalid_spec",
            "gateway_id must contain 1–128 characters",
        );
    }
    if known.is_some_and(|selectors| !selectors.gateway_exists) {
        issue(
            issues,
            "gateway_id",
            "not_found",
            "gateway is not registered with this Collector",
        );
    }

    spec.name = spec.name.trim().to_owned();
    let name_length = spec.name.chars().count();
    if !(1..=100).contains(&name_length) {
        issue(
            issues,
            "name",
            "invalid_spec",
            "name must contain 1–100 Unicode characters after trimming",
        );
    }
    spec.description = spec.description.trim().to_owned();
    if spec.description.chars().count() > 500 {
        issue(
            issues,
            "description",
            "invalid_spec",
            "description must not exceed 500 Unicode characters",
        );
    }
    if spec.priority > 1000 {
        issue(
            issues,
            "priority",
            "invalid_spec",
            "priority must be between 0 and 1000",
        );
    }
}

fn validate_selectors(
    spec: &mut PolicySpecV1,
    known: Option<&KnownSelectors>,
    issues: &mut Vec<ValidationIssue>,
) {
    let mut canonical_clients = Vec::new();
    let mut unique_clients = HashSet::new();
    for (index, client) in spec.selectors.clients.iter().enumerate() {
        match normalize_mac(client) {
            Some(mac) if unique_clients.insert(mac.clone()) => canonical_clients.push(mac),
            Some(_) => {}
            None => issue(
                issues,
                &format!("selectors.clients[{index}]"),
                "unsupported_selector",
                "client selector must be a six-octet colon-separated MAC address",
            ),
        }
    }
    canonical_clients.sort_unstable();
    spec.selectors.clients = canonical_clients;
    if spec.selectors.clients.len() > 32 {
        issue(
            issues,
            "selectors.clients",
            "invalid_spec",
            "at most 32 clients are allowed",
        );
    }
    if let Some(known) = known {
        for client in &spec.selectors.clients {
            if !known.clients.contains(client) {
                issue(
                    issues,
                    "selectors.clients",
                    "unsupported_selector",
                    &format!(
                        "client {client} is not registered on gateway {}",
                        spec.gateway_id
                    ),
                );
            }
        }
    }

    validate_ids(
        &mut spec.selectors.applications,
        32,
        "selectors.applications",
        known.map(|value| &value.applications),
        issues,
    );
    validate_ids(
        &mut spec.selectors.categories,
        16,
        "selectors.categories",
        known.map(|value| &value.categories),
        issues,
    );
    if !spec.selectors.min_application_confidence.is_finite()
        || !(0.80..=1.0).contains(&spec.selectors.min_application_confidence)
    {
        issue(
            issues,
            "selectors.min_application_confidence",
            "invalid_spec",
            "min_application_confidence must be a finite number from 0.80 through 1.00",
        );
    }
    if spec.selectors.clients.is_empty()
        && spec.selectors.applications.is_empty()
        && spec.selectors.categories.is_empty()
    {
        issue(
            issues,
            "selectors",
            "invalid_spec",
            "at least one client, application, or category selector is required",
        );
    }
}

fn validate_network(spec: &PolicySpecV1, issues: &mut Vec<ValidationIssue>) {
    if spec.network.scope != "internet" && !netqmon_protocol::policy::is_client_total_spec(spec) {
        issue(
            issues,
            "network.scope",
            "unsupported_scope",
            "use internet scope, or agent scope for client-only aggregate limits in both directions",
        );
    }
    if spec.network.direction != "both" {
        issue(
            issues,
            "network.direction",
            "unsupported_selector",
            "V1 supports only both directions",
        );
    }
}

fn validate_action(spec: &PolicySpecV1, issues: &mut Vec<ValidationIssue>) {
    match spec.action.kind {
        ActionKind::Limit => {
            if spec.selectors.clients.is_empty() {
                issue(
                    issues,
                    "selectors.clients",
                    "unsupported_selector",
                    "application limits require at least one client; global application pools are unsupported",
                );
            }
            validate_rate(spec.action.download_bps, "action.download_bps", issues);
            validate_rate(spec.action.upload_bps, "action.upload_bps", issues);
            if spec.action.download_bps.is_none() && spec.action.upload_bps.is_none() {
                issue(
                    issues,
                    "action",
                    "invalid_spec",
                    "limit requires at least one download or upload rate",
                );
            }
        }
        ActionKind::Block | ActionKind::Allow => {
            if spec.action.download_bps.is_some() || spec.action.upload_bps.is_some() {
                issue(
                    issues,
                    "action",
                    "invalid_spec",
                    "block and allow actions cannot include rate limits",
                );
            }
        }
    }
}

fn validate_ids(
    values: &mut [String],
    max: usize,
    path: &str,
    known_values: Option<&HashSet<String>>,
    issues: &mut Vec<ValidationIssue>,
) {
    if values.len() > max {
        issue(
            issues,
            path,
            "invalid_spec",
            &format!("at most {max} selectors are allowed"),
        );
    }
    let mut seen = HashSet::new();
    for (index, value) in values.iter_mut().enumerate() {
        *value = value.trim().to_owned();
        if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
            issue(
                issues,
                &format!("{path}[{index}]"),
                "unsupported_selector",
                "selector ID must be non-empty and at most 128 characters",
            );
        } else if !seen.insert(value.clone()) {
            issue(
                issues,
                &format!("{path}[{index}]"),
                "invalid_spec",
                "duplicate selector IDs are not allowed",
            );
        }
        if let Some(known_values) = known_values
            && !known_values.contains(value)
        {
            issue(
                issues,
                &format!("{path}[{index}]"),
                "unsupported_selector",
                &format!("selector ID {value} is not available in existing metadata"),
            );
        }
    }
    values.sort_unstable();
}

fn validate_rate(value: Option<u64>, path: &str, issues: &mut Vec<ValidationIssue>) {
    if value.is_some_and(|rate| !(64_000..=1_000_000_000).contains(&rate)) {
        issue(
            issues,
            path,
            "invalid_spec",
            "rate must be null or an integer from 64000 through 1000000000 bps",
        );
    }
}

fn validate_schedule(schedule: &mut super::model::Schedule, issues: &mut Vec<ValidationIssue>) {
    if Tz::from_str(&schedule.timezone).is_err() {
        issue(
            issues,
            "schedule.timezone",
            "invalid_spec",
            "timezone must be a valid IANA timezone",
        );
    }
    if schedule.windows.is_empty() || schedule.windows.len() > 32 {
        issue(
            issues,
            "schedule.windows",
            "invalid_spec",
            "schedule must contain 1–32 windows",
        );
    }
    for (index, window) in schedule.windows.iter_mut().enumerate() {
        if window.days.is_empty() || window.days.len() > 7 {
            issue(
                issues,
                &format!("schedule.windows[{index}].days"),
                "invalid_spec",
                "each window must include one or more days",
            );
        }
        let mut days = HashSet::new();
        for day in &window.days {
            if !days.insert(*day) {
                issue(
                    issues,
                    &format!("schedule.windows[{index}].days"),
                    "invalid_spec",
                    "duplicate weekdays are not allowed",
                );
            }
        }
        window.days.sort_unstable();
        let start = parse_time(&window.start);
        let end = parse_time(&window.end);
        match (start, end) {
            (Some(start), Some(end)) if start < end => {}
            (Some(_), Some(_)) => issue(
                issues,
                &format!("schedule.windows[{index}]"),
                "invalid_spec",
                "start must be before end; split cross-midnight windows into two windows",
            ),
            _ => issue(
                issues,
                &format!("schedule.windows[{index}]"),
                "invalid_spec",
                "times must use 24-hour HH:mm format",
            ),
        }
    }
    schedule.windows.sort_by(|left, right| {
        left.days
            .cmp(&right.days)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
}

fn parse_time(value: &str) -> Option<NaiveTime> {
    if value.len() != 5
        || !value.is_ascii()
        || value.as_bytes().get(2) != Some(&b':')
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
    {
        return None;
    }
    NaiveTime::parse_from_str(value, "%H:%M").ok()
}

pub(crate) fn normalize_mac(value: &str) -> Option<String> {
    let parts = value.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(parts.join(":").to_ascii_uppercase())
}

pub(crate) fn application_limits_overlap(left: &PolicySpecV1, right: &PolicySpecV1) -> bool {
    if left.gateway_id != right.gateway_id
        || left.action.kind != ActionKind::Limit
        || right.action.kind != ActionKind::Limit
        || left.selectors.applications.is_empty() && left.selectors.categories.is_empty()
        || right.selectors.applications.is_empty() && right.selectors.categories.is_empty()
    {
        return false;
    }
    let clients_overlap = left
        .selectors
        .clients
        .iter()
        .any(|client| right.selectors.clients.contains(client));
    if !clients_overlap {
        return false;
    }

    let applications_overlap = left
        .selectors
        .applications
        .iter()
        .any(|application| right.selectors.applications.contains(application));
    let categories_overlap = left
        .selectors
        .categories
        .iter()
        .any(|category| right.selectors.categories.contains(category));
    let cross_dimension_overlap_is_unknown = !left.selectors.applications.is_empty()
        && !right.selectors.categories.is_empty()
        || !left.selectors.categories.is_empty() && !right.selectors.applications.is_empty();
    applications_overlap || categories_overlap || cross_dimension_overlap_is_unknown
}

pub(crate) fn schedule_projection_cost(spec: &PolicySpecV1) -> u64 {
    spec.schedule.as_ref().map_or(0, |schedule| {
        let Ok(timezone) = Tz::from_str(&schedule.timezone) else {
            return u64::MAX;
        };
        let today = Utc::now().with_timezone(&timezone).date_naive();
        (0..30)
            .map(|offset| {
                let weekday = (today + Duration::days(offset))
                    .weekday()
                    .num_days_from_monday();
                u64::try_from(
                    schedule
                        .windows
                        .iter()
                        .filter(|window| {
                            window.days.iter().any(|day| day.monday_index() == weekday)
                        })
                        .count(),
                )
                .unwrap_or(u64::MAX)
            })
            .sum()
    })
}

fn issue(issues: &mut Vec<ValidationIssue>, path: &str, code: &str, message: &str) {
    issues.push(ValidationIssue {
        path: path.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::{NetworkSelector, PolicyAction, PolicySpecV1, Selectors, Weekday};

    fn spec(action: ActionKind, clients: Vec<String>) -> PolicySpecV1 {
        PolicySpecV1 {
            schema_version: 1,
            gateway_id: "gw-1".to_owned(),
            name: "Evening TV".to_owned(),
            description: String::new(),
            enabled: false,
            priority: 500,
            selectors: Selectors {
                clients,
                applications: vec!["youtube".to_owned()],
                categories: Vec::new(),
                min_application_confidence: 0.85,
            },
            network: NetworkSelector {
                scope: "internet".to_owned(),
                direction: "both".to_owned(),
            },
            action: PolicyAction {
                kind: action,
                download_bps: (action == ActionKind::Limit).then_some(5_000_000),
                upload_bps: None,
            },
            schedule: None,
        }
    }

    #[test]
    fn client_total_scope_requires_explicit_client_only_limit() {
        let mut total = spec(ActionKind::Limit, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        total.selectors.applications.clear();
        total.network.scope = netqmon_protocol::policy::POLICY_CLIENT_TOTAL_SCOPE.to_owned();
        assert!(normalize_and_validate(&mut total, None).is_empty());
        total.selectors.applications.push("youtube".to_owned());
        assert!(
            normalize_and_validate(&mut total, None)
                .iter()
                .any(|issue| issue.path == "network.scope" && issue.code == "unsupported_scope")
        );
    }

    #[test]
    fn mac_addresses_are_normalized_and_deduplicated() {
        let mut value = spec(
            ActionKind::Block,
            vec![
                "aa:bb:cc:dd:ee:ff".to_owned(),
                "AA:BB:CC:DD:EE:FF".to_owned(),
            ],
        );
        let errors = normalize_and_validate(&mut value, None);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(value.selectors.clients, ["AA:BB:CC:DD:EE:FF"]);
    }

    #[test]
    fn strict_boundaries_and_limit_semantics_are_enforced() {
        let mut global_limit = spec(ActionKind::Limit, Vec::new());
        let errors = normalize_and_validate(&mut global_limit, None);
        assert!(
            errors
                .iter()
                .any(|error| error.code == "unsupported_selector")
        );

        let mut bad_rate = spec(ActionKind::Limit, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        bad_rate.action.download_bps = Some(63_999);
        let errors = normalize_and_validate(&mut bad_rate, None);
        assert!(
            errors
                .iter()
                .any(|error| error.path == "action.download_bps")
        );

        let mut bad_allow = spec(ActionKind::Allow, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        bad_allow.action.download_bps = Some(1_000_000);
        let errors = normalize_and_validate(&mut bad_allow, None);
        assert!(errors.iter().any(|error| error.path == "action"));

        let mut allow = spec(ActionKind::Allow, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        assert!(normalize_and_validate(&mut allow, None).is_empty());
    }

    #[test]
    fn ipv4_ipv6_and_duplicate_application_selectors_are_rejected() {
        let mut value = spec(
            ActionKind::Block,
            vec!["192.0.2.10".to_owned(), "2001:db8::10".to_owned()],
        );
        value.selectors.applications = vec!["youtube".to_owned(), "youtube".to_owned()];
        let errors = normalize_and_validate(&mut value, None);
        assert!(
            errors
                .iter()
                .any(|error| error.path.starts_with("selectors.clients["))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.path == "selectors.applications[1]")
        );
    }

    #[test]
    fn unknown_application_and_category_ids_are_not_silently_accepted() {
        let mut value = spec(ActionKind::Block, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        value.selectors.applications = vec!["nonexistent-app".to_owned()];
        value.selectors.categories = vec!["nonexistent-category".to_owned()];
        let known = KnownSelectors {
            gateway_exists: true,
            clients: ["AA:BB:CC:DD:EE:FF".to_owned()].into_iter().collect(),
            applications: ["youtube".to_owned()].into_iter().collect(),
            categories: ["streaming".to_owned()].into_iter().collect(),
        };
        let errors = normalize_and_validate(&mut value, Some(&known));
        assert!(
            errors
                .iter()
                .any(|error| error.code == "unsupported_selector"
                    && error.path == "selectors.categories[0]")
        );
        assert!(
            errors
                .iter()
                .any(|error| error.code == "unsupported_selector"
                    && error.path == "selectors.applications[0]")
        );
    }

    #[test]
    fn normalized_selectors_and_schedule_windows_have_stable_order() {
        let mut value = spec(
            ActionKind::Block,
            vec![
                "bb:bb:bb:bb:bb:bb".to_owned(),
                "aa:aa:aa:aa:aa:aa".to_owned(),
            ],
        );
        value.schedule = Some(crate::policy::model::Schedule {
            timezone: "Asia/Shanghai".to_owned(),
            windows: vec![
                crate::policy::model::ScheduleWindow {
                    days: vec![Weekday::Fri, Weekday::Mon],
                    start: "18:00".to_owned(),
                    end: "20:00".to_owned(),
                },
                crate::policy::model::ScheduleWindow {
                    days: vec![Weekday::Tue],
                    start: "08:00".to_owned(),
                    end: "09:00".to_owned(),
                },
            ],
        });
        assert!(normalize_and_validate(&mut value, None).is_empty());
        assert_eq!(
            value.selectors.clients,
            ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"]
        );
        assert_eq!(
            value.schedule.unwrap().windows[0].days,
            [Weekday::Mon, Weekday::Fri]
        );
    }

    #[test]
    fn schedule_validates_iana_timezone_and_rejects_cross_midnight() {
        let mut value = spec(ActionKind::Block, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        value.schedule = Some(crate::policy::model::Schedule {
            timezone: "Not/AZone".to_owned(),
            windows: vec![crate::policy::model::ScheduleWindow {
                days: vec![Weekday::Mon],
                start: "23:00".to_owned(),
                end: "01:00".to_owned(),
            }],
        });
        let errors = normalize_and_validate(&mut value, None);
        assert!(errors.iter().any(|error| error.path == "schedule.timezone"));
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("split cross-midnight"))
        );
    }

    #[test]
    fn application_limit_overlap_uses_stable_client_and_selector_semantics() {
        let left = spec(ActionKind::Limit, vec!["AA:BB:CC:DD:EE:FF".to_owned()]);
        let mut right = left.clone();
        right.selectors.applications = vec!["youtube".to_owned()];
        assert!(application_limits_overlap(&left, &right));
        right.selectors.clients = vec!["00:11:22:33:44:55".to_owned()];
        assert!(!application_limits_overlap(&left, &right));
    }
}
