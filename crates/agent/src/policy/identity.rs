use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClientAddresses {
    by_mac: BTreeMap<String, BTreeSet<IpAddr>>,
    conflicts: BTreeSet<IpAddr>,
}

impl ClientAddresses {
    pub(crate) fn from_neighbors(neighbors: impl IntoIterator<Item = (String, IpAddr)>) -> Self {
        let mut by_mac = BTreeMap::<String, BTreeSet<IpAddr>>::new();
        let mut by_ip = BTreeMap::<IpAddr, BTreeSet<String>>::new();
        for (mac, ip) in neighbors {
            let mac = mac.to_ascii_lowercase();
            by_mac.entry(mac.clone()).or_default().insert(ip);
            by_ip.entry(ip).or_default().insert(mac);
        }
        let conflicts = by_ip
            .into_iter()
            .filter_map(|(ip, macs)| (macs.len() > 1).then_some(ip))
            .collect();
        Self { by_mac, conflicts }
    }

    pub(crate) fn resolve(&self, mac: &str) -> Result<Vec<IpAddr>, IdentityError> {
        let addresses = self
            .by_mac
            .get(&mac.to_ascii_lowercase())
            .ok_or(IdentityError::Unresolved)?;
        if addresses
            .iter()
            .any(|address| self.conflicts.contains(address))
        {
            return Err(IdentityError::Conflict);
        }
        let addresses = addresses.iter().copied().collect::<Vec<_>>();
        if addresses.is_empty() {
            Err(IdentityError::Unresolved)
        } else {
            Ok(addresses)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityError {
    Unresolved,
    Conflict,
}

impl IdentityError {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::Unresolved => "identity_unresolved",
            Self::Conflict => "identity_conflict",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_multiple_ipv4_and_ipv6_addresses_for_a_mac() {
        let identities = ClientAddresses::from_neighbors([
            (
                "AA:BB:CC:DD:EE:FF".to_owned(),
                "192.0.2.10".parse().unwrap(),
            ),
            (
                "aa:bb:cc:dd:ee:ff".to_owned(),
                "2001:db8::10".parse().unwrap(),
            ),
        ]);
        assert_eq!(identities.resolve("aa:bb:cc:dd:ee:ff").unwrap().len(), 2);
    }

    #[test]
    fn rejects_ambiguous_ip_ownership_without_expanding_the_match() {
        let address = "192.0.2.10".parse().unwrap();
        let identities = ClientAddresses::from_neighbors([
            ("aa:bb:cc:dd:ee:ff".to_owned(), address),
            ("00:11:22:33:44:55".to_owned(), address),
        ]);
        assert_eq!(
            identities.resolve("aa:bb:cc:dd:ee:ff"),
            Err(IdentityError::Conflict)
        );
        assert_eq!(
            ClientAddresses::default().resolve("aa:bb:cc:dd:ee:ff"),
            Err(IdentityError::Unresolved)
        );
    }
}
