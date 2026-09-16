use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dhcp::{DhcpLease, DhcpMetadata, DhcpObservation};
use crate::identity::MacAddress;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeviceObservation {
    pub(super) mac: MacAddress,
    pub(super) ip: IpAddr,
    pub(super) hostname: Option<String>,
    pub(super) dhcp: Option<DhcpMetadata>,
    pub(super) last_seen: SystemTime,
}

#[derive(Debug, Default)]
pub(super) struct DeviceObservationCache {
    devices: HashMap<MacAddress, DeviceState>,
    ip_owners: HashMap<IpAddr, MacAddress>,
    snapshot_dirty: Cell<bool>,
    snapshot_cache: RefCell<Vec<DeviceObservation>>,
    telemetry_dirty: Cell<bool>,
    resolver_dirty: Cell<bool>,
    resolver_cache: RefCell<Arc<HashMap<IpAddr, MacAddress>>>,
}

#[derive(Debug, Default)]
struct DeviceState {
    hostname: Option<String>,
    dhcp: Option<DhcpMetadata>,
    addresses: HashMap<IpAddr, SystemTime>,
}

impl DeviceObservationCache {
    pub(super) fn observe_leases(&mut self, leases: &[DhcpLease], observed_at: SystemTime) {
        let now = observed_at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        for lease in leases {
            if lease.expiry_unix_seconds != 0 && lease.expiry_unix_seconds <= now {
                continue;
            }
            let dhcp = lease
                .client_identifier
                .as_ref()
                .map(|client_identifier| DhcpMetadata {
                    client_identifier: client_identifier.clone(),
                    ..DhcpMetadata::default()
                });
            self.observe(
                lease.mac,
                Some(lease.ip),
                lease.hostname.as_deref(),
                dhcp,
                observed_at,
            );
        }
    }

    pub(super) fn observe_dhcp(&mut self, observation: DhcpObservation, observed_at: SystemTime) {
        self.observe(
            observation.mac,
            observation.ip,
            observation.hostname.as_deref(),
            Some(observation.metadata),
            observed_at,
        );
    }

    pub(super) fn observe(
        &mut self,
        mac: MacAddress,
        ip: Option<IpAddr>,
        hostname: Option<&str>,
        dhcp: Option<DhcpMetadata>,
        last_seen: SystemTime,
    ) {
        self.snapshot_dirty.set(true);
        self.telemetry_dirty.set(true);
        self.resolver_dirty.set(true);
        if let Some(ip) = ip {
            if let Some(previous) = self
                .ip_owners
                .insert(ip, mac)
                .filter(|previous_mac| previous_mac != &mac)
                .and_then(|previous_mac| self.devices.get_mut(&previous_mac))
            {
                previous.addresses.remove(&ip);
            }
        }
        let device = self.devices.entry(mac).or_default();
        if let Some(hostname) = hostname.filter(|hostname| !hostname.is_empty()) {
            device.hostname = Some(hostname.to_owned());
        }
        if let Some(dhcp) = dhcp.filter(|dhcp| {
            !dhcp.parameter_request_list.is_empty()
                || dhcp.vendor_class.is_some()
                || !dhcp.client_identifier.is_empty()
        }) {
            device.dhcp = Some(dhcp);
        }
        if let Some(ip) = ip {
            device
                .addresses
                .entry(ip)
                .and_modify(|seen| *seen = (*seen).max(last_seen))
                .or_insert(last_seen);
        }
    }

    #[cfg(test)]
    pub(super) fn resolve(&self, ip: IpAddr) -> Option<MacAddress> {
        self.ip_owners.get(&ip).copied()
    }

    pub(super) fn resolver_snapshot(&self) -> Arc<HashMap<IpAddr, MacAddress>> {
        if self.resolver_dirty.replace(false) {
            self.resolver_cache
                .replace(Arc::new(self.ip_owners.clone()));
        }
        Arc::clone(&self.resolver_cache.borrow())
    }

    pub(super) fn snapshot(&self) -> Vec<DeviceObservation> {
        if self.snapshot_dirty.replace(false) {
            let snapshot = self
                .devices
                .iter()
                .flat_map(|(mac, device)| {
                    device
                        .addresses
                        .iter()
                        .map(|(ip, last_seen)| DeviceObservation {
                            mac: *mac,
                            ip: *ip,
                            hostname: device.hostname.clone(),
                            dhcp: device.dhcp.clone(),
                            last_seen: *last_seen,
                        })
                })
                .collect();
            self.snapshot_cache.replace(snapshot);
        }
        self.snapshot_cache.borrow().clone()
    }

    pub(super) fn take_telemetry_snapshot(&self) -> Vec<DeviceObservation> {
        if self.telemetry_dirty.replace(false) {
            self.snapshot()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn one_mac_keeps_multiple_ipv4_and_ipv6_addresses() {
        let mut cache = DeviceObservationCache::default();
        let mac = "02:00:00:00:00:20".parse().unwrap();
        let seen = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        cache.observe(mac, Some("192.0.2.20".parse().unwrap()), None, None, seen);
        cache.observe(
            mac,
            Some("2001:db8::20".parse().unwrap()),
            Some("laptop"),
            None,
            seen,
        );

        let observations = cache.snapshot();
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|entry| entry.mac == mac));
        assert!(
            observations
                .iter()
                .all(|entry| entry.hostname.as_deref() == Some("laptop"))
        );
        assert_eq!(cache.resolve("192.0.2.20".parse().unwrap()), Some(mac));
        assert_eq!(cache.resolve("2001:db8::20".parse().unwrap()), Some(mac));
    }

    #[test]
    fn snapshot_cache_is_invalidated_by_later_observations() {
        let mut cache = DeviceObservationCache::default();
        let mac = "02:00:00:00:00:20".parse().unwrap();

        cache.observe(
            mac,
            Some("192.0.2.20".parse().unwrap()),
            None,
            None,
            UNIX_EPOCH,
        );
        assert_eq!(cache.snapshot().len(), 1);

        cache.observe(
            mac,
            Some("2001:db8::20".parse().unwrap()),
            None,
            None,
            UNIX_EPOCH,
        );
        assert_eq!(cache.snapshot().len(), 2);
    }

    #[test]
    fn telemetry_snapshot_is_emitted_only_after_device_changes() {
        let mut cache = DeviceObservationCache::default();
        let mac = "02:00:00:00:00:20".parse().unwrap();
        cache.observe(
            mac,
            Some("192.0.2.20".parse().unwrap()),
            None,
            None,
            UNIX_EPOCH,
        );

        assert_eq!(cache.take_telemetry_snapshot().len(), 1);
        assert!(cache.take_telemetry_snapshot().is_empty());
    }

    #[test]
    fn resolver_snapshot_is_reused_until_device_data_changes() {
        let mut cache = DeviceObservationCache::default();
        let mac = "02:00:00:00:00:20".parse().unwrap();
        let first = cache.resolver_snapshot();
        assert!(Arc::ptr_eq(&first, &cache.resolver_snapshot()));

        cache.observe(
            mac,
            Some("192.0.2.20".parse().unwrap()),
            None,
            None,
            UNIX_EPOCH,
        );
        let updated = cache.resolver_snapshot();
        assert!(!Arc::ptr_eq(&first, &updated));
        assert_eq!(updated.get(&"192.0.2.20".parse().unwrap()), Some(&mac));
    }

    #[test]
    fn a_reassigned_ip_resolves_only_to_the_latest_mac() {
        let mut cache = DeviceObservationCache::default();
        let first = "02:00:00:00:00:20".parse().unwrap();
        let second = "02:00:00:00:00:21".parse().unwrap();
        let ip = "192.0.2.20".parse().unwrap();

        cache.observe(first, Some(ip), Some("old"), None, UNIX_EPOCH);
        cache.observe(
            second,
            Some(ip),
            Some("new"),
            None,
            UNIX_EPOCH + Duration::from_secs(1),
        );

        assert_eq!(cache.resolve(ip), Some(second));
        assert_eq!(cache.snapshot().len(), 1);
        assert_eq!(cache.snapshot()[0].hostname.as_deref(), Some("new"));
    }

    #[test]
    fn ignores_expired_leases_and_accepts_non_expiring_leases() {
        let mut cache = DeviceObservationCache::default();
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let leases = vec![
            DhcpLease {
                expiry_unix_seconds: 99,
                mac: "02:00:00:00:00:10".parse().unwrap(),
                ip: "192.0.2.10".parse().unwrap(),
                hostname: Some("expired".to_owned()),
                client_identifier: None,
            },
            DhcpLease {
                expiry_unix_seconds: 0,
                mac: "02:00:00:00:00:20".parse().unwrap(),
                ip: "192.0.2.20".parse().unwrap(),
                hostname: None,
                client_identifier: Some(vec![1, 2, 0, 0, 0, 0, 20]),
            },
        ];

        cache.observe_leases(&leases, now);

        assert_eq!(cache.snapshot().len(), 1);
        assert_eq!(
            cache.snapshot()[0].ip,
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            cache.snapshot()[0]
                .dhcp
                .as_ref()
                .map(|dhcp| dhcp.client_identifier.as_slice()),
            Some(&[1, 2, 0, 0, 0, 0, 20][..])
        );
    }

    #[test]
    fn dhcp_metadata_can_arrive_before_the_ip_address() {
        let mut cache = DeviceObservationCache::default();
        let mac = "02:00:00:00:00:20".parse().unwrap();
        let seen = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        cache.observe_dhcp(
            DhcpObservation {
                mac,
                ip: None,
                hostname: Some("android".to_owned()),
                metadata: DhcpMetadata {
                    parameter_request_list: vec![1, 3, 6],
                    vendor_class: Some("android-dhcp-13".to_owned()),
                    client_identifier: vec![1, 2, 0, 0, 0, 0, 20],
                },
            },
            seen,
        );
        cache.observe(mac, Some("192.0.2.20".parse().unwrap()), None, None, seen);

        let observation = cache.snapshot().pop().unwrap();
        assert_eq!(observation.hostname.as_deref(), Some("android"));
        assert_eq!(
            observation
                .dhcp
                .as_ref()
                .and_then(|dhcp| dhcp.vendor_class.as_deref()),
            Some("android-dhcp-13")
        );
    }
}
