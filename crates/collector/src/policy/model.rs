use netqmon_protocol::policy::PolicyResultDetails;
use serde::Serialize;

#[cfg(test)]
pub(crate) use netqmon_protocol::policy::{
    PolicyAction, PolicyNetworkSelector as NetworkSelector, PolicyScheduleWindow as ScheduleWindow,
    PolicySelectors as Selectors, PolicyWeekday as Weekday,
};
pub(crate) use netqmon_protocol::policy::{
    PolicyActionKind as ActionKind, PolicySchedule as Schedule, PolicySpecV1,
};

pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SPEC_BYTES: usize = 8 * 1024;
pub(crate) const MAX_POLICY_COUNT: usize = 256;
pub(crate) const MAX_GATEWAY_SPEC_BYTES: usize = 192 * 1024;
pub(crate) const MAX_PUSH_BUNDLE_BYTES: usize = 768 * 1024;
pub(crate) const MAX_SCHEDULE_COMPLEXITY: u64 = 100_000;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PolicyRecord {
    pub id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub version: u64,
    pub spec: PolicySpecV1,
    pub execution_status: String,
    pub execution_reason_code: Option<String>,
    pub execution_message: Option<String>,
    pub execution_details: Option<PolicyResultDetails>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PolicyEvent {
    pub event_id: i64,
    pub action: String,
    pub actor_user_id: String,
    pub before: Option<PolicySpecV1>,
    pub after: Option<PolicySpecV1>,
    pub revision: u64,
    pub created_at_ms: i64,
}

#[cfg(test)]
fn parse_policy_yaml(source: &str) -> Result<PolicySpecV1, String> {
    if source.len() > MAX_REQUEST_BYTES {
        return Err("YAML input exceeds 64 KiB".to_owned());
    }
    reject_unsafe_yaml_features(source)?;

    let value: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(source).map_err(|error| yaml_error_message(&error))?;
    if yaml_depth(&value, 0)? > 32 {
        return Err("YAML nesting exceeds 32 levels".to_owned());
    }
    if contains_tagged_value(&value) {
        return Err("custom YAML tags are not supported".to_owned());
    }
    serde_yaml_ng::from_str(source).map_err(|error| yaml_error_message(&error))
}

#[cfg(test)]
fn yaml_error_message(error: &serde_yaml_ng::Error) -> String {
    error.location().map_or_else(
        || error.to_string(),
        |location| {
            format!(
                "line {}, column {}: {error}",
                location.line(),
                location.column()
            )
        },
    )
}

#[cfg(test)]
fn yaml_depth(value: &serde_yaml_ng::Value, depth: usize) -> Result<usize, String> {
    if depth > 32 {
        return Ok(depth);
    }
    let next_depth = depth + 1;
    match value {
        serde_yaml_ng::Value::Sequence(items) => items.iter().try_fold(next_depth, |max, item| {
            Ok(max.max(yaml_depth(item, next_depth)?))
        }),
        serde_yaml_ng::Value::Mapping(items) => {
            items.iter().try_fold(next_depth, |max, (key, item)| {
                Ok(max
                    .max(yaml_depth(key, next_depth)?)
                    .max(yaml_depth(item, next_depth)?))
            })
        }
        serde_yaml_ng::Value::Tagged(tagged) => yaml_depth(&tagged.value, next_depth),
        _ => Ok(next_depth),
    }
}

#[cfg(test)]
fn contains_tagged_value(value: &serde_yaml_ng::Value) -> bool {
    match value {
        serde_yaml_ng::Value::Tagged(_) => true,
        serde_yaml_ng::Value::Sequence(items) => items.iter().any(contains_tagged_value),
        serde_yaml_ng::Value::Mapping(items) => items
            .iter()
            .any(|(key, value)| contains_tagged_value(key) || contains_tagged_value(value)),
        _ => false,
    }
}

#[cfg(test)]
fn reject_unsafe_yaml_features(source: &str) -> Result<(), String> {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut previous_significant = None;
    let mut flow_depth = 0usize;

    for (line_index, line) in source.lines().enumerate() {
        let mut comment = false;
        let mut previous_significant_on_line = None;
        let mut characters = line.char_indices().peekable();
        while let Some((column, character)) = characters.next() {
            if comment {
                break;
            }
            if double_quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    double_quoted = false;
                }
                continue;
            }
            if single_quoted {
                if character == '\'' {
                    let rest = &line[column + character.len_utf8()..];
                    if rest.starts_with('\'') {
                        characters.next();
                        continue;
                    }
                    single_quoted = false;
                }
                continue;
            }
            if character == '#'
                && (column == 0
                    || line[..column]
                        .chars()
                        .last()
                        .is_some_and(char::is_whitespace))
            {
                comment = true;
                continue;
            }
            if character == '"' {
                double_quoted = true;
                continue;
            }
            if character == '\'' {
                single_quoted = true;
                continue;
            }
            if matches!(character, '[' | '{') {
                flow_depth += 1;
                if flow_depth > 32 {
                    return Err(format!(
                        "YAML nesting exceeds 32 levels at line {}",
                        line_index + 1
                    ));
                }
            } else if matches!(character, ']' | '}') {
                flow_depth = flow_depth.saturating_sub(1);
            }

            if matches!(character, '&' | '*' | '!') {
                let rest = &line[column + character.len_utf8()..];
                let next = rest.chars().next();
                let at_node_boundary = previous_significant.is_none()
                    || previous_significant_on_line.is_none()
                    || matches!(
                        previous_significant,
                        Some(':' | '-' | '[' | '{' | ',' | '?')
                    );
                if at_node_boundary && next.is_some_and(|value| !value.is_whitespace()) {
                    let feature = match character {
                        '&' => "YAML anchors",
                        '*' => "YAML aliases",
                        _ => "custom YAML tags",
                    };
                    return Err(format!(
                        "{feature} are not supported (line {})",
                        line_index + 1
                    ));
                }
            }
            if !character.is_whitespace() {
                previous_significant_on_line = Some(character);
                previous_significant = Some(character);
            }
        }
        if !comment {
            previous_significant = previous_significant_on_line;
        }
        if line.chars().take_while(|value| *value == ' ').count() > 64 {
            return Err(format!(
                "YAML indentation exceeds 64 spaces at line {}",
                line_index + 1
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{
      "schema_version": 1,
      "gateway_id": "gw-1",
      "name": "Evening TV",
      "description": "Weekday YouTube cap",
      "enabled": false,
      "priority": 500,
      "selectors": {
        "clients": ["aa:bb:cc:dd:ee:ff"],
        "applications": ["youtube"],
        "categories": [],
        "min_application_confidence": 0.85
      },
      "network": {"scope": "internet", "direction": "both"},
      "action": {"type": "limit", "download_bps": 5000000, "upload_bps": 1000000},
      "schedule": {"timezone": "Asia/Shanghai", "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "18:00", "end": "23:00"}]}
    }"#;

    const YAML: &str = "schema_version: 1\ngateway_id: gw-1\nname: Evening TV\ndescription: Weekday YouTube cap\nenabled: false\npriority: 500\nselectors:\n  clients: [aa:bb:cc:dd:ee:ff]\n  applications: [youtube]\n  categories: []\n  min_application_confidence: 0.85\nnetwork:\n  scope: internet\n  direction: both\naction:\n  type: limit\n  download_bps: 5000000\n  upload_bps: 1000000\nschedule:\n  timezone: Asia/Shanghai\n  windows:\n    - days: [mon, tue, wed, thu, fri]\n      start: '18:00'\n      end: '23:00'\n";

    #[test]
    fn json_and_yaml_parse_to_the_same_policy() {
        let json: PolicySpecV1 = serde_json::from_str(JSON).unwrap();
        let yaml = parse_policy_yaml(YAML).unwrap();
        assert_eq!(json, yaml);
    }

    #[test]
    fn yaml_rejects_anchors_aliases_custom_tags_and_deep_values() {
        assert!(parse_policy_yaml("name: &anchor value").is_err());
        assert!(parse_policy_yaml("name: *anchor").is_err());
        assert!(parse_policy_yaml("name: !custom value").is_err());
        let deep = format!("value: {}0{}", "[".repeat(33), "]".repeat(33));
        assert!(parse_policy_yaml(&deep).is_err());
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        let invalid = JSON.replace(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"unexpected\": true",
        );
        assert!(serde_json::from_str::<PolicySpecV1>(&invalid).is_err());
        let yaml = YAML.replace("gateway_id: gw-1", "unexpected: true\ngateway_id: gw-1");
        assert!(parse_policy_yaml(&yaml).is_err());
    }

    #[test]
    fn yaml_description_may_contain_an_ampersand() {
        let yaml = YAML.replace("Weekday YouTube cap", "TV & streaming");
        assert!(parse_policy_yaml(&yaml).is_ok());
    }
}
