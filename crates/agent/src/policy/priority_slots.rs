//! Priority-backend class leases, separate from legacy mark/tag allocation.
//! A removed client's slot stays reserved until runtime queue-drain verification.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::identity::MacAddress;

use super::classid::{self, ClassId};

const SLOT_COUNT: u32 = classid::CLIENT_LAST - classid::CLIENT_FIRST + 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientSlotLease {
    pub mac: String,
    pub slot: u16,
    pub active: bool,
}

impl ClientSlotLease {
    pub(crate) fn validate(&self) -> Result<(), String> {
        canonical_mac(&self.mac)?;
        if u32::from(self.slot) >= SLOT_COUNT
            || classid::DEFAULT_FIRST + u32::from(self.slot) > classid::DEFAULT_LAST
        {
            return Err(
                "priority_classid_invalid: client slot is outside the shared ABI".to_owned(),
            );
        }
        Ok(())
    }

    pub(crate) fn parent_minor(&self) -> Result<u32, String> {
        self.validate()?;
        Ok(classid::CLIENT_FIRST + u32::from(self.slot))
    }

    pub(crate) fn default_leaf(&self, major: u32) -> Result<ClassId, String> {
        self.validate()?;
        ClassId::leaf(major, classid::DEFAULT_FIRST + u32::from(self.slot)).map_err(str::to_owned)
    }
}

fn canonical_mac(value: &str) -> Result<MacAddress, String> {
    let mac = value
        .parse::<MacAddress>()
        .map_err(|error| format!("priority_identity_invalid: {error}"))?;
    if !mac.is_unicast() || mac.to_string() != value {
        return Err(
            "priority_identity_invalid: expected a canonical unicast client MAC".to_owned(),
        );
    }
    Ok(mac)
}

/// Pure allocation only. Does not mutate maps, qdiscs, policy files or journals.
/// Passing an old MarkRule/ShapingState is deliberately not supported.
pub(crate) fn allocate(
    selected: &BTreeSet<String>,
    previous: &[ClientSlotLease],
) -> Result<Vec<ClientSlotLease>, String> {
    if selected.len() > SLOT_COUNT as usize || previous.len() > SLOT_COUNT as usize {
        return Err(
            "priority_class_slots_exhausted: at most 256 client leases are available".to_owned(),
        );
    }
    for mac in selected {
        canonical_mac(mac)?;
    }
    let mut leases = BTreeMap::new();
    let mut occupied = BTreeSet::new();
    for lease in previous {
        lease.validate()?;
        if !occupied.insert(lease.slot) || leases.contains_key(&lease.mac) {
            return Err("priority_classid_conflict: duplicate client or class lease".to_owned());
        }
        leases.insert(
            lease.mac.clone(),
            ClientSlotLease {
                active: selected.contains(&lease.mac),
                ..lease.clone()
            },
        );
    }
    for mac in selected {
        if leases.contains_key(mac) {
            continue;
        }
        let slot = (0..SLOT_COUNT as u16).find(|slot| !occupied.contains(slot)).ok_or_else(|| {
            "priority_class_slots_exhausted: retired client queues require verified drain before reuse".to_owned()
        })?;
        occupied.insert(slot);
        leases.insert(
            mac.clone(),
            ClientSlotLease {
                mac: mac.clone(),
                slot,
                active: true,
            },
        );
    }
    let mut result = leases.into_values().collect::<Vec<_>>();
    result.sort_by_key(|lease| lease.slot);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clients(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn updates_keep_live_ids_and_do_not_charge_queued_packets_to_new_clients() {
        let first = allocate(&clients(&["02:00:00:00:00:01", "02:00:00:00:00:02"]), &[]).unwrap();
        let second = allocate(
            &clients(&["02:00:00:00:00:02", "02:00:00:00:00:03"]),
            &first,
        )
        .unwrap();
        assert_eq!(second.len(), 3);
        assert_eq!(
            second[0],
            ClientSlotLease {
                mac: "02:00:00:00:00:01".to_owned(),
                slot: 0,
                active: false
            }
        );
        assert_eq!(second[1], first[1]);
        assert_eq!(second[2].slot, 2);
        let restored = allocate(&clients(&["02:00:00:00:00:01"]), &second).unwrap();
        assert!(restored[0].active);
        assert_eq!(restored[0].slot, first[0].slot);
        assert!(!restored[1].active);
    }

    #[test]
    fn canonical_shared_handles_cover_first_and_last_slot() {
        for (slot, parent, leaf) in [(0, 0x100, 0x200), (255, 0x1ff, 0x2ff)] {
            let lease = ClientSlotLease {
                mac: "02:00:00:00:00:01".to_owned(),
                slot,
                active: true,
            };
            assert_eq!(lease.parent_minor().unwrap(), parent);
            assert_eq!(
                lease.default_leaf(classid::UPLOAD_MAJOR).unwrap().raw(),
                0x0052_0000 | leaf
            );
            assert_eq!(
                lease.default_leaf(classid::DOWNLOAD_MAJOR).unwrap().raw(),
                0x0051_0000 | leaf
            );
            assert!(lease.default_leaf(51).is_err());
        }
    }

    #[test]
    fn corrupt_or_ambiguous_leases_fail_before_allocating_classes() {
        let a = ClientSlotLease {
            mac: "02:00:00:00:00:01".to_owned(),
            slot: 0,
            active: true,
        };
        for bad in [
            ClientSlotLease {
                slot: 256,
                ..a.clone()
            },
            ClientSlotLease {
                mac: "02:00:00:00:00:FF".to_owned(),
                ..a.clone()
            },
            ClientSlotLease {
                mac: "ff:ff:ff:ff:ff:ff".to_owned(),
                ..a.clone()
            },
        ] {
            assert!(allocate(&BTreeSet::new(), &[bad]).is_err());
        }
        assert!(allocate(&BTreeSet::new(), &[a.clone(), a.clone()]).is_err());
        assert!(
            allocate(
                &BTreeSet::new(),
                &[
                    a.clone(),
                    ClientSlotLease {
                        mac: "02:00:00:00:00:02".to_owned(),
                        ..a
                    }
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn removed_clients_cannot_silently_release_all_occupied_slots() {
        let previous = (0..SLOT_COUNT)
            .map(|slot| ClientSlotLease {
                mac: format!("02:00:00:00:00:{slot:02x}"),
                slot: slot as u16,
                active: false,
            })
            .collect::<Vec<_>>();
        let error = allocate(&clients(&["02:00:00:00:01:00"]), &previous).unwrap_err();
        assert!(error.contains("verified drain"));
        assert_eq!(allocate(&BTreeSet::new(), &previous).unwrap(), previous);
    }
}
