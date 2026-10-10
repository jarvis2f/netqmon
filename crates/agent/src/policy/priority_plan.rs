//! Queue layout for client totals. Independent of legacy mark rules and state.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::config::{MAX_POLICY_CAPACITY_BPS, MIN_POLICY_CAPACITY_BPS};

use super::{
    classid::{self, ClassId},
    priority_delivery::{DeliveryLayout, QueuePort},
    priority_slots::ClientSlotLease,
};

const STRUCTURAL_CAPACITY_BPS: u64 = 100_000_000_000;

#[derive(Clone, Debug)]
pub(crate) struct ClientBudget {
    pub lease: ClientSlotLease,
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct BudgetClass {
    pub mac: String,
    pub slot: u16,
    pub parent_minor: u32,
    pub default_minor: u32,
    pub rate_bps: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ApplicationBudget {
    pub lease: ClientSlotLease,
    pub policy_id: String,
    pub minor: u32,
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ApplicationClass {
    pub mac: String,
    pub slot: u16,
    pub policy_id: String,
    pub minor: u32,
    pub rate_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct QueueTree {
    pub port: QueuePort,
    pub major: u32,
    /// Verified structural ceiling, not a client policy or WAN bandwidth guess.
    pub capacity_bps: u64,
    pub clients: Vec<BudgetClass>,
    pub applications: Vec<ApplicationClass>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ClassSpec {
    pub classid: u32,
    pub parent: u32,
    pub rate_bps: u64,
}

impl QueueTree {
    pub(crate) fn classes(&self) -> Result<Vec<ClassSpec>, String> {
        validate_port(&self.port)?;
        if !matches!(self.major, classid::UPLOAD_MAJOR | classid::DOWNLOAD_MAJOR)
            || !(MIN_POLICY_CAPACITY_BPS..=MAX_POLICY_CAPACITY_BPS).contains(&self.capacity_bps)
            || self.clients.len() > 256
        {
            return Err("priority_tree_invalid: root metadata".to_owned());
        }
        let root = self.major << 16;
        let ancestor = root | classid::ROOT_MINOR;
        let mut result = vec![
            ClassSpec {
                classid: ancestor,
                parent: root,
                rate_bps: self.capacity_bps,
            },
            ClassSpec {
                classid: ClassId::leaf(self.major, classid::BYPASS_MINOR)
                    .map_err(str::to_owned)?
                    .raw(),
                parent: ancestor,
                rate_bps: self.capacity_bps,
            },
        ];
        let mut macs = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut application_minors = BTreeSet::new();
        for client in &self.clients {
            let lease = ClientSlotLease {
                mac: client.mac.clone(),
                slot: client.slot,
                active: true,
            };
            lease.validate()?;
            if !macs.insert(&client.mac)
                || !slots.insert(client.slot)
                || client.parent_minor != lease.parent_minor()?
                || client.default_minor != classid::DEFAULT_FIRST + u32::from(client.slot)
                || !(MIN_POLICY_CAPACITY_BPS..=self.capacity_bps).contains(&client.rate_bps)
            {
                return Err("priority_tree_invalid: client budget or class ancestry".to_owned());
            }
            let parent = root | client.parent_minor;
            result.push(ClassSpec {
                classid: parent,
                parent: ancestor,
                rate_bps: client.rate_bps,
            });
            result.push(ClassSpec {
                classid: ClassId::leaf(self.major, client.default_minor)
                    .map_err(str::to_owned)?
                    .raw(),
                parent,
                rate_bps: client.rate_bps,
            });
        }
        for application in &self.applications {
            let client = self
                .clients
                .iter()
                .find(|client| client.mac == application.mac && client.slot == application.slot)
                .ok_or("priority_tree_invalid: application class has no client parent")?;
            if !(classid::APPLICATION_FIRST..=classid::APPLICATION_LAST)
                .contains(&application.minor)
                || !application_minors.insert(application.minor)
                || !(MIN_POLICY_CAPACITY_BPS..=client.rate_bps).contains(&application.rate_bps)
                || application.policy_id.is_empty()
            {
                return Err("priority_tree_invalid: application leaf or parent rate".to_owned());
            }
            result.push(ClassSpec {
                classid: ClassId::leaf(self.major, application.minor)
                    .map_err(str::to_owned)?
                    .raw(),
                parent: root | client.parent_minor,
                rate_bps: application.rate_bps,
            });
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PriorityPlan {
    pub upload: QueueTree,
    pub downloads: Vec<QueueTree>,
}

impl PriorityPlan {
    /// Every selected download budget exists on exactly one verified delivery
    /// port. All other port trees contain only the independent bypass branch.
    pub(crate) fn build(
        layout: &DeliveryLayout,
        ifb: QueuePort,
        upload_capacity_bps: u64,
        download_capacities: &BTreeMap<u32, u64>,
        budgets: &[ClientBudget],
        applications: &[ApplicationBudget],
    ) -> Result<Self, String> {
        validate_port(&ifb)?;
        if layout.egress_ports.is_empty() || layout.egress_ports.len() > 32 {
            return Err("priority_tree_invalid: no verified LAN delivery queues".to_owned());
        }
        let mut port_ids = BTreeSet::new();
        let mut port_names = BTreeSet::new();
        let mut downloads = BTreeMap::new();
        for port in &layout.egress_ports {
            validate_port(port)?;
            if port.ifindex == ifb.ifindex
                || port.name == ifb.name
                || !port_ids.insert(port.ifindex)
                || !port_names.insert(&port.name)
                || (layout.bridge && port.name == layout.capture_interface)
            {
                return Err(
                    "priority_tree_invalid: duplicated, IFB or bridge-master queue".to_owned(),
                );
            }
            let capacity = *download_capacities
                .get(&port.ifindex)
                .ok_or("priority_capacity_unknown: LAN port capacity is required")?;
            downloads.insert(
                port.ifindex,
                QueueTree {
                    port: port.clone(),
                    major: classid::DOWNLOAD_MAJOR,
                    capacity_bps: capacity,
                    clients: Vec::new(),
                    applications: Vec::new(),
                },
            );
        }
        if download_capacities.keys().copied().collect::<BTreeSet<_>>() != port_ids {
            return Err(
                "priority_capacity_unknown: capacity does not match actual LAN ports".to_owned(),
            );
        }
        let ingress = layout
            .ingress_ports
            .iter()
            .map(|port| (port.ifindex, port.name.as_str()))
            .collect::<BTreeSet<_>>();
        let egress = layout
            .egress_ports
            .iter()
            .map(|port| (port.ifindex, port.name.as_str()))
            .collect::<BTreeSet<_>>();
        if ingress != egress
            || ingress.len() != layout.ingress_ports.len()
            || (!layout.bridge
                && (egress.len() != 1 || layout.egress_ports[0].name != layout.capture_interface))
        {
            return Err(
                "priority_delivery_unknown: upload capture must cover every LAN queue port"
                    .to_owned(),
            );
        }
        let mut upload = QueueTree {
            port: ifb,
            major: classid::UPLOAD_MAJOR,
            capacity_bps: upload_capacity_bps,
            clients: Vec::new(),
            applications: Vec::new(),
        };
        let mut macs = BTreeSet::new();
        let mut slots = BTreeSet::new();
        for budget in budgets {
            budget.lease.validate()?;
            if !budget.lease.active
                || !macs.insert(&budget.lease.mac)
                || !slots.insert(budget.lease.slot)
                || (budget.upload_bps.is_none() && budget.download_bps.is_none())
            {
                return Err(
                    "priority_tree_invalid: inactive or duplicate client assignment".to_owned(),
                );
            }
            let class = |rate_bps| -> Result<BudgetClass, String> {
                Ok(BudgetClass {
                    mac: budget.lease.mac.clone(),
                    slot: budget.lease.slot,
                    parent_minor: budget.lease.parent_minor()?,
                    default_minor: classid::DEFAULT_FIRST + u32::from(budget.lease.slot),
                    rate_bps,
                })
            };
            if let Some(rate) = budget.upload_bps {
                upload.clients.push(class(rate)?);
            }
            if let Some(rate) = budget.download_bps {
                let delivery = layout
                    .client_delivery
                    .get(&budget.lease.mac)
                    .ok_or("priority_delivery_unknown: selected client has no unique port")?;
                let tree = downloads
                    .get_mut(&delivery.ifindex)
                    .filter(|tree| tree.port == *delivery)
                    .ok_or(
                        "priority_delivery_unknown: client port is outside the verified layout",
                    )?;
                tree.clients.push(class(rate)?);
            }
        }
        let mut application_keys = BTreeSet::new();
        for application in applications {
            application.lease.validate()?;
            if !application.lease.active
                || application.policy_id.is_empty()
                || !application_keys
                    .insert((application.lease.mac.clone(), application.policy_id.clone()))
                || !(classid::APPLICATION_FIRST..=classid::APPLICATION_LAST)
                    .contains(&application.minor)
                || (application.upload_bps.is_none() && application.download_bps.is_none())
            {
                return Err("priority_tree_invalid: application assignment".to_owned());
            }
            let total = budgets
                .iter()
                .find(|budget| budget.lease.mac == application.lease.mac);
            let client_class = |rate_bps: u64| -> Result<BudgetClass, String> {
                Ok(BudgetClass {
                    mac: application.lease.mac.clone(),
                    slot: application.lease.slot,
                    parent_minor: application.lease.parent_minor()?,
                    default_minor: classid::DEFAULT_FIRST + u32::from(application.lease.slot),
                    rate_bps,
                })
            };
            let upload_parent = total
                .and_then(|budget| budget.upload_bps)
                .unwrap_or(upload_capacity_bps);
            if let Some(rate) = application.upload_bps {
                if !upload
                    .clients
                    .iter()
                    .any(|client| client.mac == application.lease.mac)
                {
                    upload.clients.push(client_class(upload_parent)?);
                }
                upload.applications.push(ApplicationClass {
                    mac: application.lease.mac.clone(),
                    slot: application.lease.slot,
                    policy_id: application.policy_id.clone(),
                    minor: application.minor,
                    rate_bps: rate.min(upload_parent),
                });
            }
            let download_parent =
                total
                    .and_then(|budget| budget.download_bps)
                    .unwrap_or_else(|| {
                        downloads
                            .iter()
                            .find(|(_, tree)| {
                                layout
                                    .client_delivery
                                    .get(&application.lease.mac)
                                    .is_some_and(|delivery| delivery.ifindex == tree.port.ifindex)
                            })
                            .map_or(STRUCTURAL_CAPACITY_BPS, |(_, tree)| tree.capacity_bps)
                    });
            if let Some(rate) = application.download_bps {
                let delivery = layout
                    .client_delivery
                    .get(&application.lease.mac)
                    .ok_or("priority_delivery_unknown: app-limited client has no unique port")?;
                let tree = downloads
                    .iter_mut()
                    .find(|(_, tree)| tree.port == *delivery)
                    .ok_or(
                        "priority_delivery_unknown: app-limited client port is outside the layout",
                    )?;
                let (_, tree) = tree;
                if !tree
                    .clients
                    .iter()
                    .any(|client| client.mac == application.lease.mac)
                {
                    tree.clients.push(client_class(download_parent)?);
                }
                tree.applications.push(ApplicationClass {
                    mac: application.lease.mac.clone(),
                    slot: application.lease.slot,
                    policy_id: application.policy_id.clone(),
                    minor: application.minor,
                    rate_bps: rate.min(download_parent),
                });
            }
        }
        upload.clients.sort_by_key(|client| client.slot);
        upload.applications.sort_by_key(|class| class.minor);
        upload.classes()?;
        let mut downloads = downloads.into_values().collect::<Vec<_>>();
        for tree in &mut downloads {
            tree.clients.sort_by_key(|client| client.slot);
            tree.applications.sort_by_key(|class| class.minor);
            tree.classes()?;
        }
        Ok(Self { upload, downloads })
    }
}

fn validate_port(port: &QueuePort) -> Result<(), String> {
    if port.ifindex == 0
        || port.name.is_empty()
        || port.name.len() > 15
        || !port
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("priority_tree_invalid: queue interface".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        DeliveryLayout,
        QueuePort,
        Vec<ClientBudget>,
        BTreeMap<u32, u64>,
    ) {
        let a = QueuePort {
            name: "lan-a".to_owned(),
            ifindex: 10,
        };
        let b = QueuePort {
            name: "lan-b".to_owned(),
            ifindex: 11,
        };
        let budgets = (0..2)
            .map(|slot| ClientBudget {
                lease: ClientSlotLease {
                    mac: format!("02:00:00:00:00:{:02x}", slot + 1),
                    slot,
                    active: true,
                },
                upload_bps: Some(8_000_000),
                download_bps: Some(16_000_000),
            })
            .collect::<Vec<_>>();
        let layout = DeliveryLayout {
            capture_interface: "lan".to_owned(),
            bridge: true,
            ingress_ports: vec![a.clone(), b.clone()],
            egress_ports: vec![a.clone(), b.clone()],
            client_delivery: BTreeMap::from([
                (budgets[0].lease.mac.clone(), a),
                (budgets[1].lease.mac.clone(), b),
            ]),
        };
        (
            layout,
            QueuePort {
                name: "ifb".to_owned(),
                ifindex: 12,
            },
            budgets,
            BTreeMap::from([(10, 100_000_000), (11, 100_000_000)]),
        )
    }

    #[test]
    fn shared_upload_and_unique_download_budget_with_independent_bypass() {
        let (layout, ifb, budgets, capacities) = fixture();
        let plan =
            PriorityPlan::build(&layout, ifb, 100_000_000, &capacities, &budgets, &[]).unwrap();
        assert_eq!(plan.upload.clients.len(), 2);
        for (slot, tree) in plan.downloads.iter().enumerate() {
            assert_eq!(tree.clients.len(), 1);
            assert_eq!(tree.clients[0].slot, slot as u16);
            let classes = tree.classes().unwrap();
            let bypass = classes.iter().find(|c| c.classid == 0x0051fffe).unwrap();
            let leaf = classes
                .iter()
                .find(|c| c.classid == 0x00510200 + slot as u32)
                .unwrap();
            assert_eq!(bypass.parent, 0x00510001);
            assert_eq!(leaf.parent, 0x00510100 + slot as u32);
            assert_eq!(bypass.rate_bps, 100_000_000);
            assert_eq!(leaf.rate_bps, 16_000_000);
            assert!(!classes.iter().any(|c| c.parent == bypass.classid));
        }
    }

    #[test]
    fn ambiguous_delivery_and_capacity_never_create_a_fallback_client_tree() {
        let (mut layout, ifb, mut budgets, mut capacities) = fixture();
        let mac = budgets[0].lease.mac.clone();
        let binding = layout.client_delivery.remove(&mac).unwrap();
        assert!(
            PriorityPlan::build(
                &layout,
                ifb.clone(),
                100_000_000,
                &capacities,
                &budgets,
                &[]
            )
            .is_err()
        );
        layout.client_delivery.insert(mac, binding);
        capacities.insert(10, 1_000_000);
        assert!(
            PriorityPlan::build(
                &layout,
                ifb.clone(),
                100_000_000,
                &capacities,
                &budgets,
                &[]
            )
            .is_err()
        );
        capacities.insert(10, 100_000_000);
        budgets[1].lease.slot = budgets[0].lease.slot;
        assert!(
            PriorityPlan::build(&layout, ifb, 100_000_000, &capacities, &budgets, &[]).is_err()
        );
    }

    #[test]
    fn corrupted_parent_leaf_and_bridge_master_are_rejected() {
        let (mut layout, ifb, budgets, capacities) = fixture();
        let plan = PriorityPlan::build(
            &layout,
            ifb.clone(),
            100_000_000,
            &capacities,
            &budgets,
            &[],
        )
        .unwrap();
        for minor in [0, 1, 0x100, 0xfffe, 0xffff, 0x10000] {
            let mut tree = plan.downloads[0].clone();
            tree.clients[0].default_minor = minor;
            assert!(tree.classes().is_err());
        }
        layout.egress_ports[0].name = layout.capture_interface.clone();
        assert!(
            PriorityPlan::build(&layout, ifb, 100_000_000, &capacities, &budgets, &[]).is_err()
        );
    }

    #[test]
    fn incomplete_upload_capture_cannot_advertise_client_totals() {
        let (mut layout, ifb, budgets, capacities) = fixture();
        layout.ingress_ports.pop();
        assert!(
            PriorityPlan::build(&layout, ifb, 100_000_000, &capacities, &budgets, &[]).is_err()
        );
    }

    #[test]
    fn app_leaf_is_a_child_of_the_client_total_parent_and_unknown_flows_keep_default() {
        let (layout, ifb, budgets, capacities) = fixture();
        let lease = budgets[0].lease.clone();
        let app_minor = classid::APPLICATION_FIRST + u32::from(lease.slot) * 16;
        let app = ApplicationBudget {
            lease: lease.clone(),
            policy_id: "app-video".to_owned(),
            minor: app_minor,
            upload_bps: Some(4_000_000),
            download_bps: Some(6_000_000),
        };
        let plan = PriorityPlan::build(
            &layout,
            ifb,
            100_000_000,
            &capacities,
            &budgets[..1],
            &[app],
        )
        .unwrap();
        let upload = plan.upload.classes().unwrap();
        let upload_parent = upload
            .iter()
            .find(|class| class.classid == 0x0052_0100 + u32::from(lease.slot))
            .unwrap();
        let upload_app = upload
            .iter()
            .find(|class| class.classid == 0x0052_0000 + app_minor)
            .unwrap();
        let upload_default = upload
            .iter()
            .find(|class| class.classid == 0x0052_0200 + u32::from(lease.slot))
            .unwrap();
        assert_eq!(upload_app.parent, upload_parent.classid);
        assert_eq!(upload_default.parent, upload_parent.classid);
        assert_eq!(upload_app.rate_bps, 4_000_000);
        assert_eq!(upload_default.rate_bps, upload_parent.rate_bps);

        let download = plan.downloads[0].classes().unwrap();
        let download_app = download
            .iter()
            .find(|class| class.classid == 0x0051_0000 + app_minor)
            .unwrap();
        assert_eq!(download_app.rate_bps, 6_000_000);
        assert_eq!(download_app.parent, 0x0051_0100 + u32::from(lease.slot));
    }
}
