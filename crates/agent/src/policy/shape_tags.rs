//! Pure alias-to-application-tag selection used by exact flow commands.
//!
//! Kept independent of the Linux runtime so the selection rules (per-alias
//! failure isolation and deterministic tag order) are testable everywhere.

#[cfg(feature = "qos-client-priority")]
use crate::flow::FlowKey;

#[cfg(feature = "qos-client-priority")]
use super::flow_alias::AliasDirection;

#[cfg(feature = "qos-client-priority")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShapeTagGap {
    /// The alias has no direction metadata at all.
    DirectionUnknown,
    /// The direction is known and shapeable, but no application class
    /// resolves for this client/policy/interface.
    ClassUnresolved,
}

#[cfg(feature = "qos-client-priority")]
#[derive(Debug, Default)]
pub(super) struct ShapeTags {
    pub(super) tags: Vec<(FlowKey, u32)>,
    pub(super) unresolved: Vec<ShapeTagGap>,
}

/// Select application tags without letting one bad alias poison the rest.
/// Known `Unshaped` aliases are deliberately skipped and are not unresolved.
#[cfg(feature = "qos-client-priority")]
pub(super) fn select_priority_shape_tags(
    aliases: &[FlowKey],
    mut direction: impl FnMut(&FlowKey) -> Option<AliasDirection>,
    mut classid: impl FnMut(&FlowKey, bool) -> Option<u32>,
) -> ShapeTags {
    let mut selection = ShapeTags::default();
    for alias in aliases {
        let Some(direction) = direction(alias) else {
            selection.unresolved.push(ShapeTagGap::DirectionUnknown);
            continue;
        };
        let upload = match (direction, alias.hook) {
            // Upload is shaped before mirred on LAN ingress. Its routed LAN
            // egress alias is deliberately left on the 51:fffe bypass leaf.
            (AliasDirection::Upload, 1) => true,
            (AliasDirection::Download, 2) => false,
            _ => continue,
        };
        match classid(alias, upload) {
            Some(classid) => selection.tags.push((alias.clone(), classid)),
            None => selection.unresolved.push(ShapeTagGap::ClassUnresolved),
        }
    }
    selection.tags.sort_by_key(|(alias, _)| {
        (
            alias.hook,
            alias.ifindex,
            alias.ip_version,
            alias.protocol,
            alias.source_address,
            alias.destination_address,
            alias.source_port,
            alias.destination_port,
        )
    });
    selection
}

#[allow(clippy::struct_excessive_bools)]
pub(super) struct ShapeTagRejection {
    pub(super) controlled_hook: bool,
    pub(super) client_mac_present: bool,
    pub(super) flow_direction_known: bool,
    pub(super) direction_unknown: bool,
    pub(super) tuple_unverified: bool,
}

impl ShapeTagRejection {
    pub(super) fn reason(self) -> &'static str {
        if !self.controlled_hook {
            "traffic_not_on_controlled_hook"
        } else if !self.client_mac_present {
            "flow_identity_or_alias_mismatch"
        } else if self.direction_unknown {
            "alias_direction_unknown"
        } else if self.tuple_unverified {
            "alias_tuple_unverified"
        } else if !self.flow_direction_known {
            "flow_identity_or_alias_mismatch"
        } else {
            "application_class_unresolved"
        }
    }
}

#[cfg(all(feature = "qos-client-priority", target_os = "linux"))]
pub(super) fn priority_application_shape_tags(
    runtime: &crate::linux::qos_priority_runtime::PriorityRuntime,
    aliases: &[FlowKey],
    client_mac: &str,
    policy_ids: &[String],
    direction: &impl Fn(&FlowKey) -> Option<AliasDirection>,
) -> ShapeTags {
    // No re-anchoring fallback: the alias cache only emits client-side aliases
    // whose controlled hook/ifindex and exact tuple were verified (conntrack, a
    // direct client-hook observation, or a direct non-NAT observation carrying
    // the client address). Re-anchoring an arbitrary alias here could install a
    // WAN tuple on the LAN hook and would mask partial coverage.
    select_priority_shape_tags(
        aliases,
        |alias| direction(alias),
        |alias, upload| runtime.application_classid(policy_ids, client_mac, upload, alias.ifindex),
    )
}

#[cfg(all(test, feature = "qos-client-priority"))]
mod tests {
    use super::*;

    fn flow_key(hook: u8, ifindex: u32) -> FlowKey {
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
    fn undirected_alias_does_not_block_other_valid_tags() {
        let lan = flow_key(1, 1);
        let mut undirected = flow_key(1, 9);
        undirected.source_port += 1;
        let aliases = [undirected.clone(), lan.clone()];
        let selection = select_priority_shape_tags(
            &aliases,
            |alias| {
                if alias == &lan {
                    Some(AliasDirection::Upload)
                } else {
                    None
                }
            },
            |_, upload| Some(if upload { 52 } else { 51 }),
        );
        assert_eq!(selection.tags, vec![(lan, 52)]);
        assert_eq!(selection.unresolved, vec![ShapeTagGap::DirectionUnknown]);
    }

    #[test]
    fn alias_observation_order_does_not_change_installed_tags() {
        let upload_lan = flow_key(1, 1);
        let download_lan = flow_key(2, 2);
        let upload_wan = flow_key(2, 3);
        let aliases = [upload_lan.clone(), download_lan.clone(), upload_wan.clone()];
        let select = |order: &[usize]| {
            let ordered = order
                .iter()
                .map(|index| aliases[*index].clone())
                .collect::<Vec<_>>();
            select_priority_shape_tags(
                &ordered,
                |alias| match alias {
                    alias if alias == &upload_lan || alias == &upload_wan => {
                        Some(AliasDirection::Upload)
                    }
                    alias if alias == &download_lan => Some(AliasDirection::Download),
                    _ => None,
                },
                |_, upload| Some(if upload { 52 } else { 51 }),
            )
        };
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let selection = select(&order);
            assert_eq!(
                selection.tags,
                vec![(upload_lan.clone(), 52), (download_lan.clone(), 51)]
            );
            assert!(selection.unresolved.is_empty());
        }
    }

    #[test]
    fn upload_lan_uses_upload_class_download_lan_uses_download_class_and_wan_upload_is_skipped() {
        let upload_lan = flow_key(1, 1);
        let download_lan = flow_key(2, 2);
        let upload_wan = flow_key(2, 3);
        let unshaped = flow_key(1, 4);
        let aliases = [
            upload_lan.clone(),
            download_lan.clone(),
            upload_wan,
            unshaped.clone(),
        ];
        let selection = select_priority_shape_tags(
            &aliases,
            |alias| {
                if alias == &upload_lan {
                    Some(AliasDirection::Upload)
                } else if alias == &download_lan {
                    Some(AliasDirection::Download)
                } else if alias == &unshaped {
                    Some(AliasDirection::Unshaped)
                } else {
                    Some(AliasDirection::Upload)
                }
            },
            |_, upload| Some(if upload { 52 } else { 51 }),
        );
        assert_eq!(selection.tags, vec![(upload_lan, 52), (download_lan, 51)]);
        assert!(selection.unresolved.is_empty());
    }

    #[test]
    fn known_direction_without_application_class_reports_application_class_unresolved() {
        let lan = flow_key(1, 1);
        let selection = select_priority_shape_tags(
            &[lan.clone()],
            |_| Some(AliasDirection::Upload),
            |_, _| None,
        );
        assert!(selection.tags.is_empty());
        assert_eq!(selection.unresolved, vec![ShapeTagGap::ClassUnresolved]);
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: true,
                client_mac_present: true,
                flow_direction_known: true,
                direction_unknown: false,
                tuple_unverified: false,
            }
            .reason(),
            "application_class_unresolved"
        );

        let unshaped =
            select_priority_shape_tags(&[lan], |_| Some(AliasDirection::Unshaped), |_, _| None);
        assert!(unshaped.tags.is_empty());
        assert!(unshaped.unresolved.is_empty());
    }

    #[test]
    fn rejection_reasons_keep_hook_and_identity_precedence() {
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: false,
                client_mac_present: true,
                flow_direction_known: true,
                direction_unknown: true,
                tuple_unverified: false,
            }
            .reason(),
            "traffic_not_on_controlled_hook"
        );
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: true,
                client_mac_present: false,
                flow_direction_known: true,
                direction_unknown: true,
                tuple_unverified: false,
            }
            .reason(),
            "flow_identity_or_alias_mismatch"
        );
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: true,
                client_mac_present: true,
                flow_direction_known: true,
                direction_unknown: true,
                tuple_unverified: false,
            }
            .reason(),
            "alias_direction_unknown"
        );
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: true,
                client_mac_present: true,
                flow_direction_known: false,
                direction_unknown: false,
                tuple_unverified: false,
            }
            .reason(),
            "flow_identity_or_alias_mismatch"
        );
        assert_eq!(
            ShapeTagRejection {
                controlled_hook: true,
                client_mac_present: true,
                flow_direction_known: true,
                direction_unknown: false,
                tuple_unverified: true,
            }
            .reason(),
            "alias_tuple_unverified"
        );
    }
}
