//! Pure validation and ordering for removing unused NetQmon HTB classes.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use serde_json::Value;

use super::classid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnusedPriorityClass {
    pub(crate) raw: u32,
    pub(crate) client_parent: bool,
}

pub(crate) fn parse_classid_text(value: &str) -> Option<u32> {
    let (major, minor) = value.split_once(':')?;
    let major = u32::from_str_radix(major.strip_prefix("0x").unwrap_or(major), 16).ok()?;
    let minor = u32::from_str_radix(minor.strip_prefix("0x").unwrap_or(minor), 16).ok()?;
    major.checked_shl(16)?.checked_add(minor)
}

fn dynamic_class_parent(major: u32, minor: u32) -> Option<(u32, bool)> {
    let root = major.checked_shl(16)?;
    if (classid::CLIENT_FIRST..=classid::CLIENT_LAST).contains(&minor) {
        return Some((root | classid::ROOT_MINOR, true));
    }
    if (classid::DEFAULT_FIRST..=classid::DEFAULT_LAST).contains(&minor) {
        let slot = minor.checked_sub(classid::DEFAULT_FIRST)?;
        return Some((root | classid::CLIENT_FIRST.checked_add(slot)?, false));
    }
    if (classid::APPLICATION_FIRST..=classid::APPLICATION_LAST).contains(&minor) {
        let slot =
            minor.checked_sub(classid::APPLICATION_FIRST)? / classid::APPLICATIONS_PER_CLIENT;
        return Some((root | classid::CLIENT_FIRST.checked_add(slot)?, false));
    }
    None
}

/// Select only unused class IDs in the Agent's reserved dynamic ranges and
/// reject unexpected ownership edges before the caller issues any `tc del`.
pub(crate) fn unused_priority_classes(
    class_dump: &Value,
    major: u32,
    desired: &BTreeSet<u32>,
) -> Result<Vec<UnusedPriorityClass>> {
    let entries = class_dump
        .as_array()
        .context("priority class dump not an array")?;
    let mut stale = Vec::new();
    let mut stale_ids = BTreeSet::new();
    for entry in entries {
        let Some(handle) = entry.get("handle").and_then(Value::as_str) else {
            continue;
        };
        let Some(raw) = parse_classid_text(handle) else {
            continue;
        };
        if raw >> 16 != major {
            continue;
        }
        let minor = raw & 0xffff;
        let Some((expected_parent, client_parent)) = dynamic_class_parent(major, minor) else {
            continue;
        };
        if desired.contains(&raw) {
            continue;
        }
        if entry.get("class").and_then(Value::as_str) != Some("htb") {
            bail!("priority_class_cleanup_conflict: unexpected class kind for {handle}");
        }
        let parent = entry
            .get("parent")
            .and_then(Value::as_str)
            .and_then(parse_classid_text)
            .context("priority_class_cleanup_conflict: missing or invalid parent")?;
        if parent != expected_parent {
            bail!("priority_class_cleanup_conflict: unexpected parent for {handle}");
        }
        if !stale_ids.insert(raw) {
            bail!("priority_class_cleanup_conflict: duplicate class {handle}");
        }
        stale.push(UnusedPriorityClass { raw, client_parent });
    }

    for parent in stale.iter().filter(|class| class.client_parent) {
        for child in entries {
            let child_parent = child
                .get("parent")
                .and_then(Value::as_str)
                .and_then(parse_classid_text);
            if child_parent != Some(parent.raw) {
                continue;
            }
            let child_raw = child
                .get("handle")
                .and_then(Value::as_str)
                .and_then(parse_classid_text)
                .context("priority_class_cleanup_conflict: child class has no valid handle")?;
            if !stale_ids.contains(&child_raw) && !desired.contains(&child_raw) {
                bail!(
                    "priority_class_cleanup_conflict: unmanaged child of {:x}",
                    parent.raw
                );
            }
        }
    }

    // HTB leaf/default classes must be deleted before their client parent.
    stale.sort_by_key(|class| (class.client_parent, class.raw));
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::{parse_classid_text, unused_priority_classes};
    use serde_json::json;

    fn class_id(minor: u32) -> u32 {
        (0x51 << 16) | minor
    }

    #[test]
    fn removes_only_unused_dynamic_classes_and_deletes_leaves_first() {
        let dump = json!([
            {"class":"htb","handle":"51:100","parent":"51:1"},
            {"class":"htb","handle":"51:200","parent":"51:100"},
            {"class":"htb","handle":"51:1000","parent":"51:100"},
            {"class":"htb","handle":"51:101","parent":"51:1"},
            {"class":"htb","handle":"51:201","parent":"51:101"},
            {"class":"htb","handle":"51:1","root":true},
            {"class":"htb","handle":"51:fffe","parent":"51:1"},
            {"class":"htb","handle":"52:1000","parent":"52:100"}
        ]);
        let desired = std::collections::BTreeSet::from([class_id(0x101), class_id(0x201)]);

        let stale = unused_priority_classes(&dump, 0x51, &desired).unwrap();

        assert_eq!(
            stale.iter().map(|class| class.raw).collect::<Vec<_>>(),
            [class_id(0x200), class_id(0x1000), class_id(0x100)]
        );
        assert!(stale.last().unwrap().client_parent);
        assert_eq!(parse_classid_text("51:1000"), Some(class_id(0x1000)));
    }

    #[test]
    fn keeps_classes_owned_by_the_current_plan() {
        let dump = json!([
            {"class":"htb","handle":"51:100","parent":"51:1"},
            {"class":"htb","handle":"51:200","parent":"51:100"},
            {"class":"htb","handle":"51:1000","parent":"51:100"}
        ]);
        let desired =
            std::collections::BTreeSet::from([class_id(0x100), class_id(0x200), class_id(0x1000)]);

        assert!(
            unused_priority_classes(&dump, 0x51, &desired)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_a_reserved_class_with_an_unexpected_parent() {
        let dump = json!([
            {"class":"htb","handle":"51:1000","parent":"51:200"}
        ]);

        let error = unused_priority_classes(&dump, 0x51, &Default::default()).unwrap_err();

        assert!(error.to_string().contains("unexpected parent"));
    }

    #[test]
    fn rejects_a_client_parent_with_an_unmanaged_child() {
        let dump = json!([
            {"class":"htb","handle":"51:100","parent":"51:1"},
            {"class":"htb","handle":"51:4000","parent":"51:100"}
        ]);

        let error = unused_priority_classes(&dump, 0x51, &Default::default()).unwrap_err();

        assert!(error.to_string().contains("unmanaged child"));
    }
}
