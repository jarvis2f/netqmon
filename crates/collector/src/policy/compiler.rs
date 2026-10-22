use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use netqmon_protocol::policy::{
    PolicyScheduleInterval, PolicyScheduleIntervals, PolicySpecV1, PolicyWeekday, PolicyWireFrame,
};

const SCHEDULE_HORIZON_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

pub(crate) fn compile_snapshot(
    gateway_id: &str,
    controller_epoch: &str,
    bundle_generation: u64,
    generated_at_ms: i64,
    config_revision: u64,
    policies: Vec<netqmon_protocol::policy::PolicySnapshotEntry>,
) -> Result<PolicyWireFrame, String> {
    let valid_until_ms = generated_at_ms
        .checked_add(SCHEDULE_HORIZON_MS)
        .ok_or_else(|| "schedule horizon timestamp overflow".to_owned())?;
    let mut schedule_intervals = Vec::new();
    for policy in &policies {
        if policy.spec.schedule.is_some() {
            schedule_intervals.push(PolicyScheduleIntervals {
                policy_id: policy.id.clone(),
                intervals: expand_schedule(&policy.spec, generated_at_ms, valid_until_ms)?,
            });
        }
    }
    PolicyWireFrame::snapshot(
        gateway_id.to_owned(),
        controller_epoch.to_owned(),
        config_revision,
        bundle_generation,
        generated_at_ms,
        valid_until_ms,
        policies,
        schedule_intervals,
    )
}

fn expand_schedule(
    spec: &PolicySpecV1,
    from_ms: i64,
    until_ms: i64,
) -> Result<Vec<PolicyScheduleInterval>, String> {
    let schedule = spec
        .schedule
        .as_ref()
        .ok_or_else(|| "scheduled policy is missing its schedule".to_owned())?;
    let timezone = schedule
        .timezone
        .parse::<Tz>()
        .map_err(|_| format!("unknown IANA timezone {}", schedule.timezone))?;
    let local_start = DateTime::<Utc>::from_timestamp_millis(from_ms)
        .ok_or_else(|| "invalid schedule start timestamp".to_owned())?
        .with_timezone(&timezone)
        .date_naive();
    let local_end = DateTime::<Utc>::from_timestamp_millis(until_ms)
        .ok_or_else(|| "invalid schedule end timestamp".to_owned())?
        .with_timezone(&timezone)
        .date_naive();

    let mut intervals = Vec::new();
    let mut date = local_start;
    while date <= local_end {
        for window in &schedule.windows {
            if !window.days.iter().any(|day| weekday_matches(*day, date)) {
                continue;
            }
            let start = NaiveTime::parse_from_str(&window.start, "%H:%M")
                .map_err(|error| format!("invalid schedule start: {error}"))?;
            let end = NaiveTime::parse_from_str(&window.end, "%H:%M")
                .map_err(|error| format!("invalid schedule end: {error}"))?;
            if start >= end {
                return Err("schedule windows must end after they start".to_owned());
            }
            let start = resolve_local(timezone, date.and_time(start), true)?;
            let end = resolve_local(timezone, date.and_time(end), false)?;
            if start >= end {
                continue;
            }
            let start_ms = start.max(from_ms);
            let end_ms = end.min(until_ms);
            if start_ms < end_ms {
                intervals.push(PolicyScheduleInterval { start_ms, end_ms });
            }
        }
        date = date
            .succ_opt()
            .ok_or_else(|| "schedule date overflow".to_owned())?;
    }
    intervals.sort_by_key(|interval| (interval.start_ms, interval.end_ms));
    let mut merged: Vec<PolicyScheduleInterval> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        if let Some(previous) = merged.last_mut() {
            if interval.start_ms <= previous.end_ms {
                previous.end_ms = previous.end_ms.max(interval.end_ms);
                continue;
            }
        }
        merged.push(interval);
    }
    Ok(merged)
}

fn resolve_local(timezone: Tz, local: NaiveDateTime, is_start: bool) -> Result<i64, String> {
    let mut candidate = local;
    for _ in 0..=180 {
        match timezone.from_local_datetime(&candidate) {
            LocalResult::Single(value) => return Ok(value.timestamp_millis()),
            LocalResult::Ambiguous(first, second) => {
                return Ok(if is_start {
                    first.min(second).timestamp_millis()
                } else {
                    first.max(second).timestamp_millis()
                });
            }
            LocalResult::None => {
                candidate = candidate
                    .checked_add_signed(Duration::minutes(1))
                    .ok_or_else(|| "schedule local time overflow".to_owned())?;
            }
        }
    }
    Err("schedule local time is not valid within three hours".to_owned())
}

fn weekday_matches(day: PolicyWeekday, date: chrono::NaiveDate) -> bool {
    matches!(
        (day, date.weekday()),
        (PolicyWeekday::Mon, chrono::Weekday::Mon)
            | (PolicyWeekday::Tue, chrono::Weekday::Tue)
            | (PolicyWeekday::Wed, chrono::Weekday::Wed)
            | (PolicyWeekday::Thu, chrono::Weekday::Thu)
            | (PolicyWeekday::Fri, chrono::Weekday::Fri)
            | (PolicyWeekday::Sat, chrono::Weekday::Sat)
            | (PolicyWeekday::Sun, chrono::Weekday::Sun)
    )
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveDate, NaiveTime};
    use netqmon_protocol::policy::{
        PolicyAction, PolicyActionKind, PolicyNetworkSelector, PolicySchedule,
        PolicyScheduleWindow, PolicySelectors, PolicySpecV1, PolicyWeekday,
    };

    use super::*;

    fn scheduled_spec(timezone: &str, start: &str, end: &str, day: PolicyWeekday) -> PolicySpecV1 {
        PolicySpecV1 {
            schema_version: 1,
            gateway_id: "gw-test".to_owned(),
            name: "Scheduled block".to_owned(),
            description: String::new(),
            enabled: true,
            priority: 500,
            selectors: PolicySelectors {
                clients: vec!["AA:BB:CC:DD:EE:FF".to_owned()],
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
                timezone: timezone.to_owned(),
                windows: vec![PolicyScheduleWindow {
                    days: vec![day],
                    start: start.to_owned(),
                    end: end.to_owned(),
                }],
            }),
        }
    }

    #[test]
    fn spring_dst_gap_shifts_to_the_first_valid_minute() {
        let date = NaiveDate::from_ymd_opt(2026, 3, 8).unwrap();
        let gap = resolve_local(
            "America/New_York".parse().unwrap(),
            date.and_time(NaiveTime::from_hms_opt(2, 30, 0).unwrap()),
            true,
        )
        .unwrap();
        assert_eq!(gap, 1_772_953_200_000);
    }

    #[test]
    fn fall_dst_fold_uses_earliest_start_and_latest_end() {
        let date = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        let local = date.and_time(NaiveTime::from_hms_opt(1, 30, 0).unwrap());
        let zone = "America/New_York".parse().unwrap();
        let start = resolve_local(zone, local, true).unwrap();
        let end = resolve_local(zone, local, false).unwrap();
        assert_eq!(end - start, 60 * 60 * 1_000);
    }

    #[test]
    fn schedule_projection_is_sorted_merged_and_limited_to_thirty_days() {
        let spec = scheduled_spec("UTC", "09:00", "12:00", PolicyWeekday::Mon);
        let from = Utc
            .with_ymd_and_hms(2026, 10, 5, 10, 0, 0)
            .unwrap()
            .timestamp_millis();
        let until = from + SCHEDULE_HORIZON_MS;
        let intervals = expand_schedule(&spec, from, until).unwrap();
        assert_eq!(intervals.first().unwrap().start_ms, from);
        assert!(intervals.last().unwrap().end_ms <= until);
        assert!(
            intervals
                .windows(2)
                .all(|pair| pair[0].end_ms < pair[1].start_ms)
        );
    }
}
