use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::conntrack::{ConntrackContext, FlowTuple, ProxySocketContext};
use crate::flow::FlowKey;
use crate::topology::TopologyContext;

pub(crate) const DEFAULT_POLICY_FLOW_CAPACITY: usize = 8_192;
pub(crate) const MIN_POLICY_FLOW_CAPACITY: usize = 1_024;
pub(crate) const MAX_POLICY_FLOW_CAPACITY: usize = 16_384;
pub(crate) const MAX_ALIASES_PER_FLOW: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowAliasError {
    CapacityFull,
    AliasLimitReached,
    FlowEnded,
}

/// Direction metadata attached to exact flow aliases.
///
/// `Unshaped` is an explicit observation, not a missing entry: normalized
/// internal or unknown traffic is tracked but deliberately left untagged.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum AliasDirection {
    Upload,
    Download,
    Unshaped,
}

impl AliasDirection {
    fn shaped(self) -> Option<super::shaper::Direction> {
        match self {
            Self::Upload => Some(super::shaper::Direction::Upload),
            Self::Download => Some(super::shaper::Direction::Download),
            Self::Unshaped => None,
        }
    }
}

#[derive(Debug)]
struct AliasEntry {
    keys: Vec<FlowKey>,
    directions: HashMap<FlowKey, AliasDirection>,
    /// Aliases whose client-side tuple was verified from conntrack, a direct
    /// client-hook observation, or a direct non-NAT observation carrying the
    /// client address. Only these may be installed.
    verified: HashSet<FlowKey>,
    /// Aliases that were observed but could not be verified. They are tracked
    /// separately and are never installed into the BPF verdict map.
    unresolved: Vec<FlowKey>,
    client_mac: Option<String>,
    client_ip: Option<std::net::IpAddr>,
    default_client_ifindex: Option<u32>,
    client_identity_conflict: bool,
    last_seen: Instant,
    ended: bool,
    partial: bool,
    last_command_issued_at_ms: Option<i64>,
}

fn insert_alias(entry: &mut AliasEntry, alias: FlowKey, direction: AliasDirection) {
    if !entry.keys.contains(&alias) {
        if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
            entry.partial = true;
            return;
        }
        entry.keys.push(alias.clone());
    }
    entry.verified.insert(alias.clone());
    entry.unresolved.retain(|pending| pending != &alias);
    entry.directions.insert(alias, direction);
}

fn record_unresolved(entry: &mut AliasEntry, alias: FlowKey) {
    if entry.verified.contains(&alias) || entry.unresolved.contains(&alias) {
        return;
    }
    if entry.unresolved.len() >= MAX_ALIASES_PER_FLOW {
        entry.partial = true;
        return;
    }
    entry.unresolved.push(alias);
}

#[derive(Debug)]
pub(crate) struct PolicyFlowAliasCache {
    entries: HashMap<String, AliasEntry>,
    capacity: usize,
}

impl Default for PolicyFlowAliasCache {
    fn default() -> Self {
        Self::new(DEFAULT_POLICY_FLOW_CAPACITY)
    }
}

impl PolicyFlowAliasCache {
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_POLICY_FLOW_CAPACITY, MAX_POLICY_FLOW_CAPACITY);
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    pub(crate) fn observe(
        &mut self,
        policy_flow_id: &str,
        key: FlowKey,
        now: Instant,
    ) -> Result<usize, FlowAliasError> {
        self.observe_with_client(policy_flow_id, key, None, now)
    }

    pub(crate) fn observe_with_client(
        &mut self,
        policy_flow_id: &str,
        key: FlowKey,
        client_mac: Option<&str>,
        now: Instant,
    ) -> Result<usize, FlowAliasError> {
        let client_mac = client_mac.map(str::to_ascii_lowercase);
        if let Some(entry) = self.entries.get_mut(policy_flow_id) {
            if entry.ended {
                return Err(FlowAliasError::FlowEnded);
            }
            entry.last_seen = now;
            if let Some(client_mac) = client_mac {
                match (entry.client_identity_conflict, entry.client_mac.as_deref()) {
                    (true, _) => {}
                    (false, Some(current)) if current != client_mac => {
                        entry.client_mac = None;
                        entry.client_identity_conflict = true;
                        entry.partial = true;
                    }
                    (false, None) => entry.client_mac = Some(client_mac),
                    (false, Some(_)) => {}
                }
            }
            if entry.keys.contains(&key) {
                return Ok(entry.keys.len());
            }
            if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
                entry.partial = true;
                return Err(FlowAliasError::AliasLimitReached);
            }
            entry.keys.push(key);
            return Ok(entry.keys.len());
        }
        if self.entries.len() >= self.capacity {
            return Err(FlowAliasError::CapacityFull);
        }
        self.entries.insert(
            policy_flow_id.to_owned(),
            AliasEntry {
                keys: vec![key],
                directions: HashMap::new(),
                verified: HashSet::new(),
                unresolved: Vec::new(),
                client_mac,
                client_ip: None,
                default_client_ifindex: None,
                client_identity_conflict: false,
                last_seen: now,
                ended: false,
                partial: false,
                last_command_issued_at_ms: None,
            },
        );
        Ok(1)
    }

    pub(crate) fn aliases(&self, policy_flow_id: &str) -> Option<&[FlowKey]> {
        self.entries
            .get(policy_flow_id)
            .map(|entry| entry.keys.as_slice())
    }

    /// Broader endpoint leases must use the original client-ingress tuple.
    /// Never generalize a translated WAN tuple or a local proxy's socket.
    pub(crate) fn endpoint_block_aliases(&self, id: &str) -> Vec<FlowKey> {
        let Some(entry) = self.entries.get(id) else {
            return Vec::new();
        };
        if entry.client_identity_conflict || entry.client_mac.is_none() {
            return Vec::new();
        }
        entry
            .keys
            .iter()
            .filter(|key| {
                key.hook == 1
                    && Some(key.ifindex) == entry.default_client_ifindex
                    && entry.verified.contains(*key)
                    && entry.directions.get(*key) == Some(&AliasDirection::Upload)
                    && key.addresses().map(|(source, _)| source) == entry.client_ip
            })
            .cloned()
            .collect()
    }

    /// Persist a proxy-return alias resolved from an exact conntrack entry so
    /// later Allow/Revoke commands clear the same key.
    pub(crate) fn insert_proxy_return(
        &mut self,
        policy_flow_id: &str,
        alias: FlowKey,
    ) -> Result<(), FlowAliasError> {
        let Some(entry) = self.entries.get_mut(policy_flow_id) else {
            return Err(FlowAliasError::FlowEnded);
        };
        if entry.ended {
            return Err(FlowAliasError::FlowEnded);
        }
        if entry.keys.contains(&alias) {
            entry.verified.insert(alias.clone());
            entry.directions.insert(alias, AliasDirection::Download);
            return Ok(());
        }
        if entry.keys.len() >= MAX_ALIASES_PER_FLOW {
            entry.partial = true;
            return Err(FlowAliasError::AliasLimitReached);
        }
        entry.keys.push(alias.clone());
        entry.verified.insert(alias.clone());
        entry.unresolved.retain(|pending| pending != &alias);
        entry.directions.insert(alias, AliasDirection::Download);
        Ok(())
    }

    pub(super) fn direction(&self, id: &str, key: &FlowKey) -> Option<super::shaper::Direction> {
        self.shape_direction(id, key)?.shaped()
    }

    /// Direction metadata for the priority shaping path, where an explicit
    /// `Unshaped` observation is different from a missing alias entry.
    pub(crate) fn shape_direction(&self, id: &str, key: &FlowKey) -> Option<AliasDirection> {
        self.entries.get(id)?.directions.get(key).copied()
    }

    /// Preserve normalized direction and synthesize the exact client-side
    /// delivery/ingress alias only when the tuple is verified.
    ///
    /// Verification comes from one of two sources:
    /// * the observation already sits on the controlled client hook, so the
    ///   captured tuple is exactly what the client sends/receives; or
    /// * conntrack supplies the complete original/reply tuples, which are then
    ///   translated per direction (SNAT, DNAT/REDIRECT); or
    /// * without conntrack, the observed tuple is direct (untranslated) and the
    ///   side implied by the direction already carries `client_ip`.
    ///
    /// Anything else (notably a WAN-side observation without conntrack) is
    /// recorded as unresolved and never installed. A reverse alias is never
    /// guessed by swapping an untranslated WAN tuple.
    pub(crate) fn observe_direction(
        &mut self,
        id: &str,
        key: &FlowKey,
        direction: crate::normalization::Direction,
        client_ip: Option<std::net::IpAddr>,
        egress_ifindexes: Option<(u32, u32)>,
        tracked: Option<crate::conntrack::ConntrackEntry>,
    ) {
        let direction = match direction {
            crate::normalization::Direction::Upload => AliasDirection::Upload,
            crate::normalization::Direction::Download => AliasDirection::Download,
            crate::normalization::Direction::Internal
            | crate::normalization::Direction::Unknown => {
                // Track the explicit non-shaping observation without
                // synthesizing egress/reverse aliases for it.
                if let Some(entry) = self.entries.get_mut(id) {
                    if entry.keys.contains(key) {
                        entry
                            .directions
                            .insert(key.clone(), AliasDirection::Unshaped);
                    }
                }
                return;
            }
        };
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        // observe_with_client may have rejected this key at the alias bound.
        // Direction metadata must obey the same bound as the exact tuples.
        if !entry.keys.contains(key) {
            return;
        }
        entry.directions.insert(key.clone(), direction);
        if let Some(ip) = client_ip {
            entry.client_ip = Some(ip);
        }
        // A later observation may now be verifiable by conntrack.
        entry.unresolved.retain(|pending| pending != key);
        let Some((_, client_ifindex)) = egress_ifindexes else {
            return;
        };
        entry.default_client_ifindex = Some(client_ifindex);
        let client_hook = match direction {
            AliasDirection::Upload => 1,
            AliasDirection::Download => 2,
            AliasDirection::Unshaped => return,
        };
        let observed_client_side = key.hook == client_hook && key.ifindex == client_ifindex;
        let client_tuple = if observed_client_side {
            key_tuple(key)
        } else if let Some(tracked) = tracked.as_ref() {
            Some(client_side_tuple(
                tracked,
                match direction {
                    AliasDirection::Upload => crate::normalization::Direction::Upload,
                    _ => crate::normalization::Direction::Download,
                },
            ))
        } else {
            // No conntrack: only an untranslated direct observation that
            // already carries the client on the direction-implied side can
            // prove the client tuple.
            direct_client_tuple(key, direction, client_ip)
        };
        let Some(client_tuple) = client_tuple else {
            // The NAT-translated client tuple cannot be determined. Keep the
            // exact WAN observation unresolved; never synthesize a guess.
            record_unresolved(entry, key.clone());
            return;
        };
        let client_alias = key_with_tuple(key, client_hook, client_ifindex, &client_tuple);
        insert_alias(entry, client_alias, direction);

        let opposite = match direction {
            AliasDirection::Upload => AliasDirection::Download,
            AliasDirection::Download => AliasDirection::Upload,
            AliasDirection::Unshaped => return,
        };
        if let Some(tracked) = tracked {
            let opposite_tuple = client_side_tuple(
                &tracked,
                match opposite {
                    AliasDirection::Upload => crate::normalization::Direction::Upload,
                    _ => crate::normalization::Direction::Download,
                },
            );
            let opposite_hook = if opposite == AliasDirection::Upload {
                1
            } else {
                2
            };
            let opposite_alias =
                key_with_tuple(key, opposite_hook, client_ifindex, &opposite_tuple);
            insert_alias(entry, opposite_alias, opposite);
        } else {
            // Without conntrack the opposite client tuple is only provable
            // when it is observed directly on the client hook. Record the
            // missing direction instead of swapping an untranslated tuple.
            let mut pending = key.clone();
            pending.hook = if opposite == AliasDirection::Upload {
                1
            } else {
                2
            };
            pending.ifindex = client_ifindex;
            std::mem::swap(
                &mut pending.source_address,
                &mut pending.destination_address,
            );
            std::mem::swap(&mut pending.source_port, &mut pending.destination_port);
            record_unresolved(entry, pending);
        }
    }

    pub(crate) fn reconcile_for_command(
        &mut self,
        id: &str,
        client_ifindex: Option<u32>,
        conntrack: &ConntrackContext,
    ) {
        let Some((observations, client_ip, resolved_ifindex)) =
            self.entries.get_mut(id).and_then(|entry| {
                if entry.ended {
                    return None;
                }
                let ifindex = client_ifindex.or(entry.default_client_ifindex)?;
                let has_client_side_upload = entry
                    .keys
                    .iter()
                    .any(|key| key.hook == 1 && key.ifindex == ifindex);
                let has_client_side_download = entry
                    .keys
                    .iter()
                    .any(|key| key.hook == 2 && key.ifindex == ifindex);
                if entry.unresolved.is_empty() && has_client_side_upload && has_client_side_download
                {
                    return None;
                }
                let observations = entry
                    .directions
                    .iter()
                    .filter_map(|(key, direction)| match direction {
                        AliasDirection::Upload => {
                            Some((key.clone(), crate::normalization::Direction::Upload))
                        }
                        AliasDirection::Download => {
                            Some((key.clone(), crate::normalization::Direction::Download))
                        }
                        AliasDirection::Unshaped => None,
                    })
                    .collect::<Vec<_>>();
                if observations.is_empty() {
                    return None;
                }
                entry.unresolved.clear();
                Some((observations, entry.client_ip, ifindex))
            })
        else {
            return;
        };
        for (key, direction) in observations {
            let tracked = conntrack.resolve(&key);
            self.observe_direction(
                id,
                &key,
                direction,
                client_ip,
                Some((resolved_ifindex, resolved_ifindex)),
                tracked,
            );
        }
    }

    pub(crate) fn client_mac(&self, policy_flow_id: &str) -> Option<&str> {
        self.entries
            .get(policy_flow_id)
            .and_then(|entry| entry.client_mac.as_deref())
    }

    pub(crate) fn remove(&mut self, policy_flow_id: &str) -> bool {
        self.entries.remove(policy_flow_id).is_some()
    }

    pub(crate) fn mark_ended(&mut self, policy_flow_id: &str) -> bool {
        self.entries.get_mut(policy_flow_id).is_some_and(|entry| {
            entry.ended = true;
            true
        })
    }

    pub(crate) fn is_ended(&self, policy_flow_id: &str) -> bool {
        self.entries
            .get(policy_flow_id)
            .is_some_and(|entry| entry.ended)
    }

    pub(crate) fn is_partial(&self, policy_flow_id: &str) -> bool {
        self.entries
            .get(policy_flow_id)
            .is_some_and(|entry| entry.partial)
    }

    /// Observed aliases whose client-side tuple could not be verified.
    /// They are tracked separately from the installable aliases.
    #[cfg(test)]
    pub(crate) fn unresolved_aliases(&self, policy_flow_id: &str) -> Option<&[FlowKey]> {
        self.entries
            .get(policy_flow_id)
            .map(|entry| entry.unresolved.as_slice())
    }

    pub(crate) fn has_unverified_aliases(&self, policy_flow_id: &str) -> bool {
        self.entries
            .get(policy_flow_id)
            .is_some_and(|entry| !entry.unresolved.is_empty())
    }

    pub(crate) fn command_is_stale(&self, policy_flow_id: &str, issued_at_ms: i64) -> bool {
        self.entries.get(policy_flow_id).is_none_or(|entry| {
            entry
                .last_command_issued_at_ms
                .is_some_and(|last| issued_at_ms < last)
        })
    }

    pub(crate) fn record_command(&mut self, policy_flow_id: &str, issued_at_ms: i64) -> bool {
        let Some(entry) = self.entries.get_mut(policy_flow_id) else {
            return false;
        };
        if entry
            .last_command_issued_at_ms
            .is_some_and(|last| issued_at_ms < last)
        {
            return false;
        }
        entry.last_command_issued_at_ms = Some(issued_at_ms);
        true
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn prune(&mut self, now: Instant, tcp_idle: Duration, udp_idle: Duration) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            let idle_for = now.saturating_duration_since(entry.last_seen);
            let timeout = if entry.keys.iter().all(|key| key.protocol == 17) {
                udp_idle
            } else {
                tcp_idle
            };
            idle_for < timeout
        });
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn key_tuple(key: &FlowKey) -> Option<crate::conntrack::FlowTuple> {
    let (source, destination) = key.addresses()?;
    Some(crate::conntrack::FlowTuple {
        protocol: key.protocol,
        source,
        source_port: key.source_port,
        destination,
        destination_port: key.destination_port,
    })
}

fn key_with_tuple(
    template: &FlowKey,
    hook: u8,
    ifindex: u32,
    tuple: &crate::conntrack::FlowTuple,
) -> FlowKey {
    let mut alias = template.clone();
    alias.hook = hook;
    alias.ifindex = ifindex;
    alias.source_address = ip_bytes(tuple.source);
    alias.destination_address = ip_bytes(tuple.destination);
    alias.source_port = tuple.source_port;
    alias.destination_port = tuple.destination_port;
    alias
}

/// Exact proxy-return aliases proved by a TCP REDIRECT conntrack entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProxyReturnResolution {
    pub(crate) aliases: Vec<FlowKey>,
    /// A redirect conntrack entry was found and requires a proxy-return alias.
    pub(crate) expected: bool,
    /// A redirect was found but the actual LAN delivery tuple could not be
    /// derived from the available evidence.
    pub(crate) unresolved: bool,
}

/// Resolve the concrete local-proxy return tuple for a client-to-server flow.
///
/// This is deliberately stricter than `client_side_tuple`: it accepts only an
/// exact `original` orientation match, a TCP entry with destination NAT, a
/// local proxy source, and a reply whose destination is the original client.
/// A TPROXY entry (whose reply source is the remote server) does not match.
pub(crate) fn proxy_return_aliases(
    aliases: &[FlowKey],
    conntrack: &ConntrackContext,
    topology: &TopologyContext,
) -> ProxyReturnResolution {
    let mut resolution = ProxyReturnResolution::default();
    // A download-side/client-delivery alias carries the LAN egress ifindex.
    // Fall back to the original alias only when no client egress observation
    // exists yet; the actual value is never guessed from address similarity.
    let client_ifindex = aliases
        .iter()
        .find(|alias| alias.hook == 2)
        .map_or(0, |alias| alias.ifindex);
    for alias in aliases {
        let Some(tuple) = key_tuple(alias) else {
            continue;
        };
        let Some(entry) = conntrack.resolve(alias) else {
            continue;
        };
        let reverse_original = crate::normalization::reverse_tuple(&entry.original);
        if (entry.original != tuple && reverse_original != tuple)
            || entry.original.protocol != 6
            || entry.reply.protocol != 6
            || !entry.destination_nat
        {
            continue;
        }
        // REDIRECT sends the reply from a local proxy socket back to the
        // original client. A normal destination-NAT backend has a non-local
        // reply source and must not be turned into a client alias.
        if entry.reply.destination != entry.original.source
            || entry.reply.destination_port != entry.original.source_port
            || !topology.is_local(entry.reply.source)
            || topology.is_local(entry.original.source)
            || topology.is_local(entry.original.destination)
        {
            continue;
        }
        resolution.expected = true;
        let ifindex = if client_ifindex != 0 {
            client_ifindex
        } else {
            alias.ifindex
        };
        if ifindex == 0 {
            resolution.unresolved = true;
            continue;
        }
        // The local proxy's reply is a client-delivery packet, therefore the
        // LAN egress hook and the client-facing ifindex are the actual keys.
        let proxy = key_with_tuple(alias, 2, ifindex, &entry.reply);
        if !resolution.aliases.contains(&proxy) {
            resolution.aliases.push(proxy);
        }
    }
    resolution
}

/// Resolve a local proxy return from exact accepted-proxy TCP sockets.
///
/// Some REDIRECT kernels expose the accepted proxy socket but not its
/// translated reply tuple in conntrack. The client IP and client port must
/// match exactly, and the local side must be a listener owned by the router.
pub(crate) fn proxy_socket_return_aliases(
    aliases: &[FlowKey],
    sockets: &ProxySocketContext,
    topology: &TopologyContext,
) -> ProxyReturnResolution {
    let mut resolution = ProxyReturnResolution::default();
    let client_ifindex = aliases
        .iter()
        .find(|alias| alias.hook == 2)
        .map_or(0, |alias| alias.ifindex);
    for alias in aliases {
        let Some((source, source_port, destination, destination_port)) = tuple_endpoints(alias)
        else {
            continue;
        };
        for (client_ip, client_port, other_ip) in [
            (source, source_port, destination),
            (destination, destination_port, source),
        ] {
            if topology.is_local(client_ip) || other_ip.is_unspecified() {
                continue;
            }
            let Some((proxy_ip, proxy_port)) = sockets.lookup(client_ip, client_port) else {
                continue;
            };
            if !topology.is_local(proxy_ip) || proxy_ip == client_ip {
                continue;
            }
            resolution.expected = true;
            let ifindex = if client_ifindex != 0 {
                client_ifindex
            } else {
                alias.ifindex
            };
            if ifindex == 0 {
                resolution.unresolved = true;
                continue;
            }
            let proxy_tuple = FlowTuple {
                protocol: alias.protocol,
                source: proxy_ip,
                source_port: proxy_port,
                destination: client_ip,
                destination_port: client_port,
            };
            let proxy = key_with_tuple(alias, 2, ifindex, &proxy_tuple);
            if !resolution.aliases.contains(&proxy) {
                resolution.aliases.push(proxy);
            }
        }
    }
    resolution
}

fn tuple_endpoints(key: &FlowKey) -> Option<(std::net::IpAddr, u16, std::net::IpAddr, u16)> {
    let (source, destination) = key.addresses()?;
    Some((source, key.source_port, destination, key.destination_port))
}

/// Tuple as seen on the client-facing interface for a classified direction.
///
/// Upload packets are captured before SNAT (the conntrack original tuple).
/// Download delivery is the reply tuple after DNAT/REDIRECT, otherwise the
/// reverse of the original tuple (SNAT only rewrites the WAN side).
pub(crate) fn client_side_tuple(
    tracked: &crate::conntrack::ConntrackEntry,
    direction: crate::normalization::Direction,
) -> crate::conntrack::FlowTuple {
    match direction {
        crate::normalization::Direction::Upload => tracked.original,
        _ => {
            if tracked.destination_nat {
                tracked.reply
            } else {
                crate::normalization::reverse_tuple(&tracked.original)
            }
        }
    }
}

/// Verify a direct (non-NAT) observation against the client address.
///
/// Without conntrack there is no NAT translation to consult, so the observed
/// tuple can only be accepted as the client-side tuple when it already carries
/// the client on the side the direction implies: the destination for download
/// delivery and the source for upload. Protocol and ports stay exactly as
/// observed; the tuple itself is never rewritten.
fn direct_client_tuple(
    key: &FlowKey,
    direction: AliasDirection,
    client_ip: Option<std::net::IpAddr>,
) -> Option<crate::conntrack::FlowTuple> {
    let client_ip = ip_bytes(client_ip?);
    let client_side = match direction {
        AliasDirection::Upload => key.source_address == client_ip,
        AliasDirection::Download => key.destination_address == client_ip,
        AliasDirection::Unshaped => false,
    };
    if client_side { key_tuple(key) } else { None }
}

fn ip_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            bytes
        }
        std::net::IpAddr::V6(ip) => ip.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_blocks_learn_only_verified_client_ingress_and_survive_flow_end() {
        let observed = key(1, 2);
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe_with_client(
                "flow",
                observed.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                Instant::now(),
            )
            .unwrap();
        assert!(cache.endpoint_block_aliases("flow").is_empty());
        cache.observe_direction(
            "flow",
            &observed,
            crate::normalization::Direction::Upload,
            Some("192.0.2.1".parse().unwrap()),
            Some((3, 2)),
            None,
        );
        assert_eq!(cache.endpoint_block_aliases("flow"), vec![observed.clone()]);
        cache.mark_ended("flow");
        // Revoking the exact flow must still leave enough identity to clear
        // an endpoint explicitly, but must not itself expire the cached block.
        assert_eq!(cache.endpoint_block_aliases("flow"), vec![observed]);
    }

    #[test]
    fn endpoint_blocks_reject_shared_nat_tuple_and_conflicting_client_identity() {
        let mut wan = key(2, 3);
        wan.source_address = ip_bytes("203.0.113.254".parse().unwrap());
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe_with_client(
                "wan",
                wan.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                Instant::now(),
            )
            .unwrap();
        cache.observe_direction(
            "wan",
            &wan,
            crate::normalization::Direction::Upload,
            Some("192.0.2.1".parse().unwrap()),
            Some((3, 2)),
            None,
        );
        assert!(cache.endpoint_block_aliases("wan").is_empty());

        let client = key(1, 2);
        cache
            .observe_with_client(
                "client",
                client.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                Instant::now(),
            )
            .unwrap();
        cache.observe_direction(
            "client",
            &client,
            crate::normalization::Direction::Upload,
            Some("192.0.2.1".parse().unwrap()),
            Some((3, 2)),
            None,
        );
        cache
            .observe_with_client("client", client, Some("aa:bb:cc:dd:ee:00"), Instant::now())
            .unwrap();
        assert!(cache.endpoint_block_aliases("client").is_empty());
    }

    #[test]
    fn rejected_aliases_cannot_grow_direction_metadata() {
        let mut cache = PolicyFlowAliasCache::default();
        for port in 0..100 {
            let mut observed = key(1, 2);
            observed.source_port += port;
            let _ = cache.observe("bounded", observed.clone(), Instant::now());
            cache.observe_direction(
                "bounded",
                &observed,
                crate::normalization::Direction::Upload,
                None,
                None,
                None,
            );
        }
        let entry = &cache.entries["bounded"];
        assert_eq!(entry.keys.len(), MAX_ALIASES_PER_FLOW);
        assert_eq!(entry.directions.len(), MAX_ALIASES_PER_FLOW);
        assert!(entry.partial);
    }

    #[test]
    fn shared_egress_alias_uses_translated_tuple_and_normalized_direction() {
        let mut cache = PolicyFlowAliasCache::default();
        let observed = key(1, 2);
        let tracked = crate::conntrack::ConntrackEntry {
            original: crate::conntrack::FlowTuple {
                protocol: 6,
                source: "192.0.2.1".parse().unwrap(),
                source_port: 50_000,
                destination: "198.51.100.1".parse().unwrap(),
                destination_port: 443,
            },
            reply: crate::conntrack::FlowTuple {
                protocol: 6,
                source: "198.51.100.1".parse().unwrap(),
                source_port: 443,
                destination: "192.0.2.254".parse().unwrap(),
                destination_port: 60_000,
            },
            source_nat: true,
            destination_nat: false,
        };
        cache
            .observe_with_client(
                "nat-flow",
                observed.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                Instant::now(),
            )
            .unwrap();
        cache.observe_direction(
            "nat-flow",
            &observed,
            crate::normalization::Direction::Upload,
            None,
            Some((3, 2)),
            Some(tracked),
        );
        // The exact download-delivery tuple comes from conntrack, not from
        // swapping the SNAT-translated WAN observation.
        let delivery = &cache.aliases("nat-flow").unwrap()[1];
        assert_eq!((delivery.hook, delivery.ifindex), (2, 2));
        assert_eq!(
            delivery.addresses(),
            Some((tracked.original.destination, tracked.original.source))
        );
        assert_eq!(
            (delivery.source_port, delivery.destination_port),
            (
                tracked.original.destination_port,
                tracked.original.source_port
            )
        );
        assert_eq!(
            cache.direction("nat-flow", delivery),
            Some(super::super::shaper::Direction::Download)
        );
    }

    #[test]
    fn upload_observation_without_conntrack_does_not_guess_the_reverse_alias() {
        let mut cache = PolicyFlowAliasCache::default();
        let observed = key(1, 2);
        cache
            .observe("flow", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "flow",
            &observed,
            crate::normalization::Direction::Upload,
            None,
            Some((3, 2)),
            None,
        );
        let aliases = cache.aliases("flow").unwrap();
        assert_eq!(aliases, std::slice::from_ref(&observed));
        assert_eq!(
            cache.shape_direction("flow", &aliases[0]),
            Some(AliasDirection::Upload)
        );
        let unresolved = cache.unresolved_aliases("flow").unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!((unresolved[0].hook, unresolved[0].ifindex), (2, 2));
        assert!(cache.has_unverified_aliases("flow"));
    }

    #[test]
    fn direct_download_without_conntrack_verifies_the_delivery_alias() {
        let client: std::net::IpAddr = "198.51.100.1".parse().unwrap();
        // WAN ingress observation of an untranslated download: the client is
        // already the destination.
        let mut observed = key(1, 3);
        observed.source_port = 443;
        observed.destination_port = 50_000;

        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("direct-download", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "direct-download",
            &observed,
            crate::normalization::Direction::Download,
            Some(client),
            Some((3, 2)),
            None,
        );

        let aliases = cache.aliases("direct-download").unwrap();
        let delivery = aliases
            .iter()
            .find(|alias| alias.hook == 2)
            .expect("client destination verifies the LAN egress delivery alias");
        assert_eq!((delivery.hook, delivery.ifindex), (2, 2));
        assert_eq!(
            delivery.addresses(),
            Some(("192.0.2.1".parse().unwrap(), client))
        );
        assert_eq!(
            (delivery.source_port, delivery.destination_port),
            (443, 50_000)
        );
        assert_eq!(
            cache.shape_direction("direct-download", delivery),
            Some(AliasDirection::Download)
        );
        // The observed WAN tuple is kept exactly as observed, and the
        // unproven opposite direction still requires partial coverage.
        assert!(aliases.contains(&observed));
        assert!(cache.has_unverified_aliases("direct-download"));
        #[cfg(feature = "qos-client-priority")]
        assert_eq!(
            priority_shape_tags(&cache, "direct-download"),
            vec![(delivery.clone(), 51)]
        );
    }

    #[test]
    fn direct_upload_without_conntrack_verifies_the_ingress_alias() {
        let observed = key(2, 3);
        let client = "192.0.2.1".parse().unwrap();

        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("direct-upload", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "direct-upload",
            &observed,
            crate::normalization::Direction::Upload,
            Some(client),
            Some((3, 2)),
            None,
        );

        let aliases = cache.aliases("direct-upload").unwrap();
        let ingress = aliases
            .iter()
            .find(|alias| alias.hook == 1)
            .expect("client source verifies the LAN ingress alias");
        assert_eq!((ingress.hook, ingress.ifindex), (1, 2));
        assert_eq!(
            ingress.addresses(),
            Some((client, "198.51.100.1".parse().unwrap()))
        );
        assert_eq!(
            (ingress.source_port, ingress.destination_port),
            (50_000, 443)
        );
        assert_eq!(
            cache.shape_direction("direct-upload", ingress),
            Some(AliasDirection::Upload)
        );
        assert!(aliases.contains(&observed));
        assert!(cache.has_unverified_aliases("direct-upload"));
        #[cfg(feature = "qos-client-priority")]
        assert_eq!(
            priority_shape_tags(&cache, "direct-upload"),
            vec![(ingress.clone(), 52)]
        );
    }

    #[test]
    fn direct_fallback_rejects_nat_tuples_that_do_not_carry_the_client() {
        let client: std::net::IpAddr = "192.168.2.100".parse().unwrap();

        // Upload observed after SNAT: the source is the router, not the client.
        let mut upload = key(2, 3);
        upload.source_address = ip_bytes("203.0.113.254".parse().unwrap());
        upload.destination_address = ip_bytes("198.51.100.1".parse().unwrap());
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("snat-upload", upload.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "snat-upload",
            &upload,
            crate::normalization::Direction::Upload,
            Some(client),
            Some((3, 2)),
            None,
        );
        assert_eq!(cache.aliases("snat-upload").unwrap(), &[upload.clone()]);
        assert!(cache.has_unverified_aliases("snat-upload"));
        assert_eq!(cache.unresolved_aliases("snat-upload").unwrap(), &[upload]);
        #[cfg(feature = "qos-client-priority")]
        assert!(priority_shape_tags(&cache, "snat-upload").is_empty());

        // Download observed with a router-side destination, not the client.
        let mut download = key(1, 3);
        download.source_address = ip_bytes("198.51.100.1".parse().unwrap());
        download.destination_address = ip_bytes("203.0.113.254".parse().unwrap());
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("nat-download", download.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "nat-download",
            &download,
            crate::normalization::Direction::Download,
            Some(client),
            Some((3, 2)),
            None,
        );
        assert_eq!(cache.aliases("nat-download").unwrap(), &[download.clone()]);
        assert!(cache.has_unverified_aliases("nat-download"));
        assert_eq!(
            cache.unresolved_aliases("nat-download").unwrap(),
            &[download]
        );
        #[cfg(feature = "qos-client-priority")]
        assert!(priority_shape_tags(&cache, "nat-download").is_empty());
    }

    #[test]
    fn direct_bidirectional_observations_install_both_aliases_in_any_order() {
        let upload = key(1, 2);
        let mut download = key(2, 2);
        download.source_address = upload.destination_address;
        download.destination_address = upload.source_address;
        download.source_port = upload.destination_port;
        download.destination_port = upload.source_port;
        let client: std::net::IpAddr = "192.0.2.1".parse().unwrap();

        for reverse in [false, true] {
            let mut observations = [
                (upload.clone(), crate::normalization::Direction::Upload),
                (download.clone(), crate::normalization::Direction::Download),
            ];
            if reverse {
                observations.reverse();
            }
            let id = if reverse { "reverse" } else { "forward" };
            let now = Instant::now();
            let mut cache = PolicyFlowAliasCache::default();
            for (key, _) in &observations {
                cache.observe(id, key.clone(), now).unwrap();
            }
            for (key, direction) in &observations {
                cache.observe_direction(id, key, *direction, Some(client), Some((3, 2)), None);
            }
            let aliases = cache.aliases(id).unwrap();
            assert_eq!(aliases.len(), 2);
            assert!(!cache.has_unverified_aliases(id));
            assert_eq!(
                cache.shape_direction(id, &upload),
                Some(AliasDirection::Upload)
            );
            assert_eq!(
                cache.shape_direction(id, &download),
                Some(AliasDirection::Download)
            );
            #[cfg(feature = "qos-client-priority")]
            assert_eq!(
                priority_shape_tags(&cache, id),
                vec![(upload.clone(), 52), (download.clone(), 51)]
            );
        }
    }

    #[test]
    fn alias_observation_order_does_not_change_direction_metadata() {
        let lan_ingress = key(1, 2);
        let lan_egress = key(2, 3);
        let mut upload_first = PolicyFlowAliasCache::default();
        let now = Instant::now();
        upload_first
            .observe("flow", lan_ingress.clone(), now)
            .unwrap();
        upload_first
            .observe("flow", lan_egress.clone(), now)
            .unwrap();
        upload_first.observe_direction(
            "flow",
            &lan_ingress,
            crate::normalization::Direction::Upload,
            None,
            None,
            None,
        );
        upload_first.observe_direction(
            "flow",
            &lan_egress,
            crate::normalization::Direction::Download,
            None,
            None,
            None,
        );

        let mut download_first = PolicyFlowAliasCache::default();
        download_first
            .observe("flow", lan_egress.clone(), now)
            .unwrap();
        download_first
            .observe("flow", lan_ingress.clone(), now)
            .unwrap();
        download_first.observe_direction(
            "flow",
            &lan_egress,
            crate::normalization::Direction::Download,
            None,
            None,
            None,
        );
        download_first.observe_direction(
            "flow",
            &lan_ingress,
            crate::normalization::Direction::Upload,
            None,
            None,
            None,
        );

        for alias in [&lan_ingress, &lan_egress] {
            assert_eq!(
                upload_first.shape_direction("flow", alias),
                download_first.shape_direction("flow", alias)
            );
        }
    }

    #[test]
    fn internal_and_unknown_observations_are_explicitly_unshaped() {
        for direction in [
            crate::normalization::Direction::Internal,
            crate::normalization::Direction::Unknown,
        ] {
            let mut cache = PolicyFlowAliasCache::default();
            let observed = key(1, 2);
            cache
                .observe("flow", observed.clone(), Instant::now())
                .unwrap();
            cache.observe_direction("flow", &observed, direction, None, Some((3, 2)), None);
            assert_eq!(cache.aliases("flow").unwrap().len(), 1);
            assert_eq!(
                cache.shape_direction("flow", &observed),
                Some(AliasDirection::Unshaped)
            );
            assert_eq!(cache.direction("flow", &observed), None);
        }
    }

    #[test]
    fn redirect_conntrack_orientation_keeps_upload_on_original_and_download_on_reverse() {
        use crate::conntrack::{ConntrackEntry, FlowTuple};

        let original = FlowTuple {
            protocol: 6,
            source: "192.168.2.100".parse().unwrap(),
            source_port: 50_000,
            destination: "8.8.8.8".parse().unwrap(),
            destination_port: 443,
        };
        let reply = FlowTuple {
            protocol: 6,
            source: "192.168.2.8".parse().unwrap(),
            source_port: 7_890,
            destination: "192.168.2.100".parse().unwrap(),
            destination_port: 50_000,
        };
        let tracked = ConntrackEntry {
            original,
            reply,
            source_nat: false,
            destination_nat: true,
        };
        let mut observed = key(1, 2);
        observed.source_address = ip_bytes(original.source);
        observed.destination_address = ip_bytes(original.destination);
        observed.source_port = original.source_port;
        observed.destination_port = original.destination_port;

        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("redirect", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "redirect",
            &observed,
            crate::normalization::Direction::Upload,
            None,
            Some((2, 2)),
            Some(tracked),
        );
        let aliases = cache.aliases("redirect").unwrap();
        assert_eq!(
            cache.shape_direction("redirect", &aliases[0]),
            Some(AliasDirection::Upload)
        );
        let delivery = &aliases[1];
        assert_eq!(
            delivery.addresses(),
            Some((reply.source, reply.destination))
        );
        assert_eq!(
            cache.shape_direction("redirect", delivery),
            Some(AliasDirection::Download)
        );

        let mut reply_observed = key(2, 2);
        reply_observed.source_address = ip_bytes(reply.source);
        reply_observed.destination_address = ip_bytes(reply.destination);
        reply_observed.source_port = reply.source_port;
        reply_observed.destination_port = reply.destination_port;
        let mut reply_cache = PolicyFlowAliasCache::default();
        reply_cache
            .observe("redirect-reply", reply_observed.clone(), Instant::now())
            .unwrap();
        reply_cache.observe_direction(
            "redirect-reply",
            &reply_observed,
            crate::normalization::Direction::Download,
            None,
            Some((2, 2)),
            Some(tracked),
        );
        assert_eq!(
            reply_cache.shape_direction("redirect-reply", &reply_observed),
            Some(AliasDirection::Download)
        );
    }

    #[test]
    fn proxy_return_alias_uses_exact_redirect_reply_tuple() {
        use crate::topology::TopologyContext;

        let mut topology = TopologyContext::default();
        topology
            .add_interface_address("192.168.2.8".parse().unwrap(), 24)
            .unwrap();
        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.100 dst=8.8.8.8 sport=50000 dport=443 src=192.168.2.8 dst=192.168.2.100 sport=7890 dport=50000",
        );
        let mut client_original = key(1, 2);
        client_original.source_address = ip_bytes("192.168.2.100".parse().unwrap());
        client_original.destination_address = ip_bytes("8.8.8.8".parse().unwrap());
        let resolution = proxy_return_aliases(&[client_original.clone()], &conntrack, &topology);
        assert!(resolution.expected);
        assert!(!resolution.unresolved);
        assert_eq!(resolution.aliases.len(), 1);
        let proxy = &resolution.aliases[0];
        assert_eq!((proxy.hook, proxy.ifindex), (2, 2));
        assert_eq!(
            proxy.addresses(),
            Some((
                "192.168.2.8".parse().unwrap(),
                "192.168.2.100".parse().unwrap()
            ))
        );
        assert_eq!((proxy.source_port, proxy.destination_port), (7_890, 50_000));

        // The cache may have observed the server-to-client side first; it is
        // the reverse of conntrack's original tuple and must still resolve.
        let mut reverse_observed = client_original;
        std::mem::swap(
            &mut reverse_observed.source_address,
            &mut reverse_observed.destination_address,
        );
        std::mem::swap(
            &mut reverse_observed.source_port,
            &mut reverse_observed.destination_port,
        );
        reverse_observed.hook = 2;
        let reverse_resolution = proxy_return_aliases(&[reverse_observed], &conntrack, &topology);
        assert!(reverse_resolution.expected);
        assert_eq!(reverse_resolution.aliases, resolution.aliases);
    }

    #[test]
    fn proxy_socket_alias_uses_exact_client_port_and_local_listener() {
        use crate::conntrack::ProxySocketContext;
        use crate::topology::TopologyContext;

        let mut topology = TopologyContext::default();
        topology
            .add_interface_address("192.168.2.8".parse().unwrap(), 24)
            .unwrap();
        let sockets = ProxySocketContext::from_connections([(
            ("192.168.2.88".parse().unwrap(), 0xD2EC),
            ("192.168.2.8".parse().unwrap(), 0x0411),
        )]);
        let mut alias = key(1, 2);
        alias.source_address = ip_bytes("192.168.2.88".parse().unwrap());
        alias.destination_address = ip_bytes("8.8.8.8".parse().unwrap());
        alias.source_port = 0xD2EC;
        let resolution = proxy_socket_return_aliases(&[alias], &sockets, &topology);
        assert!(resolution.expected);
        assert_eq!(resolution.aliases.len(), 1);
        let proxy = &resolution.aliases[0];
        assert_eq!((proxy.hook, proxy.ifindex), (2, 2));
        assert_eq!(
            proxy.addresses(),
            Some((
                "192.168.2.8".parse().unwrap(),
                "192.168.2.88".parse().unwrap()
            ))
        );
        assert_eq!(
            (proxy.source_port, proxy.destination_port),
            (0x0411, 0xD2EC)
        );
    }

    #[test]
    fn proxy_return_alias_rejects_non_local_and_xray_upstream_entries() {
        use crate::topology::TopologyContext;

        let mut topology = TopologyContext::default();
        topology
            .add_interface_address("192.168.2.8".parse().unwrap(), 24)
            .unwrap();
        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.100 dst=8.8.8.8 sport=50000 dport=443 src=192.168.2.8 dst=192.168.2.100 sport=7890 dport=50000",
        );
        let mut client_original = key(1, 2);
        client_original.source_address = ip_bytes("192.168.2.100".parse().unwrap());
        client_original.destination_address = ip_bytes("8.8.8.8".parse().unwrap());
        let no_local = proxy_return_aliases(
            &[client_original.clone()],
            &conntrack,
            &TopologyContext::default(),
        );
        assert!(!no_local.expected);
        assert!(no_local.aliases.is_empty());

        let mut upstream = client_original;
        upstream.source_address = ip_bytes("192.168.2.8".parse().unwrap());
        let xray_upstream = proxy_return_aliases(&[upstream], &conntrack, &topology);
        assert!(!xray_upstream.expected);
        assert!(xray_upstream.aliases.is_empty());
    }

    #[test]
    fn proxy_return_alias_requires_an_exact_original_tuple() {
        use crate::topology::TopologyContext;

        let mut topology = TopologyContext::default();
        topology
            .add_interface_address("192.168.2.8".parse().unwrap(), 24)
            .unwrap();
        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.100 dst=8.8.8.8 sport=50000 dport=443 src=192.168.2.8 dst=192.168.2.100 sport=7890 dport=50000",
        );
        let mut other = key(1, 2);
        other.source_address = ip_bytes("192.168.2.101".parse().unwrap());
        other.destination_address = ip_bytes("8.8.8.8".parse().unwrap());
        let resolution = proxy_return_aliases(&[other], &conntrack, &topology);
        assert!(!resolution.expected);
        assert!(resolution.aliases.is_empty());
    }

    #[test]
    fn bidirectional_tcp_and_udp_client_observations_install_both_directions() {
        for protocol in [6, 17] {
            let mut cache = PolicyFlowAliasCache::default();
            let mut upload = key(1, 2);
            upload.protocol = protocol;
            let mut download = upload.clone();
            download.hook = 2;
            std::mem::swap(
                &mut download.source_address,
                &mut download.destination_address,
            );
            std::mem::swap(&mut download.source_port, &mut download.destination_port);
            let now = Instant::now();
            cache.observe("flow", upload.clone(), now).unwrap();
            cache.observe("flow", download.clone(), now).unwrap();
            cache.observe_direction(
                "flow",
                &upload,
                crate::normalization::Direction::Upload,
                None,
                Some((3, 2)),
                None,
            );
            cache.observe_direction(
                "flow",
                &download,
                crate::normalization::Direction::Download,
                None,
                Some((3, 2)),
                None,
            );
            let aliases = cache.aliases("flow").unwrap();
            assert_eq!(aliases.len(), 2);
            assert_eq!(
                cache.shape_direction("flow", &upload),
                Some(AliasDirection::Upload)
            );
            assert_eq!(
                cache.shape_direction("flow", &download),
                Some(AliasDirection::Download)
            );
            assert!(!cache.has_unverified_aliases("flow"));
        }
    }

    #[test]
    fn egress_only_observation_uses_conntrack_instead_of_swapping_the_wan_tuple() {
        use crate::conntrack::{ConntrackEntry, FlowTuple};

        // SNAT observed on WAN egress: captured src/dst/port differ from the
        // client-side tuple, so only conntrack can produce the LAN ingress key.
        let original = FlowTuple {
            protocol: 6,
            source: "192.0.2.1".parse().unwrap(),
            source_port: 50_000,
            destination: "198.51.100.1".parse().unwrap(),
            destination_port: 443,
        };
        let reply = FlowTuple {
            protocol: 6,
            source: "198.51.100.1".parse().unwrap(),
            source_port: 443,
            destination: "203.0.113.254".parse().unwrap(),
            destination_port: 60_000,
        };
        let tracked = ConntrackEntry {
            original,
            reply,
            source_nat: true,
            destination_nat: false,
        };
        let mut observed = key(2, 3);
        observed.source_address = ip_bytes(reply.destination);
        observed.destination_address = ip_bytes(reply.source);
        observed.source_port = reply.destination_port;
        observed.destination_port = reply.source_port;
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("egress-only", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "egress-only",
            &observed,
            crate::normalization::Direction::Upload,
            None,
            Some((3, 2)),
            Some(tracked),
        );
        let ingress = cache
            .aliases("egress-only")
            .unwrap()
            .iter()
            .find(|alias| alias.hook == 1)
            .expect("conntrack verifies the LAN ingress alias");
        assert_eq!(ingress.ifindex, 2);
        assert_eq!(
            ingress.addresses(),
            Some((tracked.original.source, tracked.original.destination))
        );
        assert_eq!(
            (ingress.source_port, ingress.destination_port),
            (
                tracked.original.source_port,
                tracked.original.destination_port
            )
        );
        assert_eq!(
            cache.shape_direction("egress-only", ingress),
            Some(AliasDirection::Upload)
        );
        assert!(!cache.has_unverified_aliases("egress-only"));
    }

    #[test]
    fn unverified_wan_tuple_is_left_unresolved_and_never_installed() {
        let mut observed = key(2, 3);
        observed.source_address = ip_bytes("203.0.113.254".parse().unwrap());
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe("wan-only", observed.clone(), Instant::now())
            .unwrap();
        cache.observe_direction(
            "wan-only",
            &observed,
            crate::normalization::Direction::Upload,
            None,
            Some((3, 2)),
            None,
        );
        assert_eq!(cache.aliases("wan-only").unwrap(), &[observed.clone()]);
        assert!(cache.has_unverified_aliases("wan-only"));
        assert_eq!(cache.unresolved_aliases("wan-only").unwrap(), &[observed]);
    }

    fn key(hook: u8, ifindex: u32) -> FlowKey {
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

    #[cfg(feature = "qos-client-priority")]
    fn priority_shape_tags(cache: &PolicyFlowAliasCache, id: &str) -> Vec<(FlowKey, u32)> {
        super::super::shape_tags::select_priority_shape_tags(
            cache.aliases(id).unwrap(),
            |alias| cache.shape_direction(id, alias),
            |_, upload| Some(if upload { 52 } else { 51 }),
        )
        .tags
    }

    #[test]
    fn dnat_aliases_translate_both_directions_for_ipv4_and_ipv6() {
        use crate::conntrack::{ConntrackEntry, FlowTuple};
        for (client, public, translated, version) in [
            ("192.0.2.1", "198.51.100.8", "203.0.113.9", 4),
            ("fd00::1", "2001:db8::8", "2001:db8:1::9", 6),
        ] {
            let original = FlowTuple {
                protocol: 6,
                source: client.parse().unwrap(),
                source_port: 40_000,
                destination: public.parse().unwrap(),
                destination_port: 443,
            };
            let reply = FlowTuple {
                protocol: 6,
                source: translated.parse().unwrap(),
                source_port: 8443,
                destination: original.source,
                destination_port: original.source_port,
            };
            let tracked = ConntrackEntry {
                original,
                reply,
                source_nat: false,
                destination_nat: true,
            };
            for (tuple, expected, direction) in [
                (original, reply, crate::normalization::Direction::Upload),
                (reply, original, crate::normalization::Direction::Download),
            ] {
                let mut observed = key(1, 2);
                observed.ip_version = version;
                observed.source_address = ip_bytes(tuple.source);
                observed.destination_address = ip_bytes(tuple.destination);
                observed.source_port = tuple.source_port;
                observed.destination_port = tuple.destination_port;
                let mut cache = PolicyFlowAliasCache::default();
                cache
                    .observe("dnat", observed.clone(), Instant::now())
                    .unwrap();
                cache.observe_direction(
                    "dnat",
                    &observed,
                    direction,
                    None,
                    Some((2, 2)),
                    Some(tracked),
                );
                let expected_direction = if direction == crate::normalization::Direction::Upload {
                    AliasDirection::Download
                } else {
                    AliasDirection::Upload
                };
                let opposite = cache
                    .aliases("dnat")
                    .unwrap()
                    .iter()
                    .find(|alias| cache.shape_direction("dnat", alias) == Some(expected_direction))
                    .expect("conntrack verifies the opposite client alias");
                assert_eq!(
                    opposite.addresses(),
                    Some((expected.source, expected.destination))
                );
                assert_eq!(
                    (opposite.source_port, opposite.destination_port),
                    (expected.source_port, expected.destination_port)
                );
                assert_eq!(
                    opposite.hook,
                    if expected_direction == AliasDirection::Upload {
                        1
                    } else {
                        2
                    }
                );
            }
        }
    }

    #[test]
    fn retains_exact_hook_and_interface_aliases_and_removes_on_end() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        assert_eq!(cache.observe("flow-1", key(1, 2), now), Ok(1));
        assert_eq!(cache.observe("flow-1", key(2, 3), now), Ok(2));
        assert_eq!(cache.aliases("flow-1").unwrap().len(), 2);
        assert!(cache.mark_ended("flow-1"));
        assert!(cache.is_ended("flow-1"));
        assert_eq!(
            cache.observe("flow-1", key(1, 2), now),
            Err(FlowAliasError::FlowEnded)
        );
        assert!(cache.remove("flow-1"));
        assert!(cache.aliases("flow-1").is_none());
    }

    #[test]
    fn retains_a_consistent_client_identity_and_rejects_conflicts_for_shaping() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache
            .observe_with_client("flow-1", key(1, 2), Some("AA:BB:CC:DD:EE:FF"), now)
            .unwrap();
        cache
            .observe_with_client("flow-1", key(2, 3), Some("aa:bb:cc:dd:ee:ff"), now)
            .unwrap();
        assert_eq!(cache.client_mac("flow-1"), Some("aa:bb:cc:dd:ee:ff"));

        cache
            .observe_with_client("flow-1", key(2, 4), Some("00:11:22:33:44:55"), now)
            .unwrap();
        cache
            .observe_with_client("flow-1", key(2, 5), Some("aa:bb:cc:dd:ee:ff"), now)
            .unwrap();
        assert!(cache.client_mac("flow-1").is_none());
        assert!(cache.is_partial("flow-1"));
    }

    #[test]
    fn reports_partial_coverage_when_a_flow_exceeds_four_exact_aliases() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        for ifindex in 0..MAX_ALIASES_PER_FLOW as u32 {
            cache.observe("flow", key(1, ifindex + 1), now).unwrap();
        }
        assert!(!cache.is_partial("flow"));
        assert_eq!(
            cache.observe("flow", key(2, 20), now),
            Err(FlowAliasError::AliasLimitReached)
        );
        assert!(cache.is_partial("flow"));
        assert_eq!(cache.aliases("flow").unwrap().len(), MAX_ALIASES_PER_FLOW);
    }

    #[test]
    fn cache_capacity_does_not_evict_live_aliases() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::new(MIN_POLICY_FLOW_CAPACITY);
        for index in 0..MIN_POLICY_FLOW_CAPACITY {
            cache
                .observe(&format!("flow-{index}"), key(1, index as u32), now)
                .unwrap();
        }
        assert_eq!(
            cache.observe("overflow", key(1, 99), now),
            Err(FlowAliasError::CapacityFull)
        );
        assert!(cache.aliases("flow-0").is_some());
        assert_eq!(cache.len(), MIN_POLICY_FLOW_CAPACITY);
    }

    #[test]
    fn prunes_using_protocol_idle_timeouts() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache.observe("tcp", key(1, 1), now).unwrap();
        let mut udp = key(1, 2);
        udp.protocol = 17;
        cache.observe("udp", udp, now).unwrap();
        assert_eq!(
            cache.prune(
                now + Duration::from_secs(31),
                Duration::from_secs(120),
                Duration::from_secs(30)
            ),
            1
        );
        assert!(cache.aliases("tcp").is_some());
        assert!(cache.aliases("udp").is_none());
    }

    #[test]
    fn rejects_stale_commands_and_keeps_equal_timestamp_retries_idempotent() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        cache.observe("flow", key(1, 1), now).unwrap();
        assert!(!cache.command_is_stale("flow", 100));
        assert!(cache.record_command("flow", 100));
        assert!(cache.command_is_stale("flow", 99));
        assert!(!cache.command_is_stale("flow", 100));
        assert!(cache.record_command("flow", 100));
        assert!(!cache.record_command("flow", 99));
    }

    #[test]
    fn reconcile_for_command_verifies_missing_download_alias_after_conntrack_refresh() {
        let now = Instant::now();
        let mut cache = PolicyFlowAliasCache::default();
        let mut upload_observed = key(1, 2);
        upload_observed.source_address = ip_bytes("192.0.2.1".parse().unwrap());
        upload_observed.destination_address = ip_bytes("198.51.100.1".parse().unwrap());
        cache
            .observe_with_client(
                "flow-1",
                upload_observed.clone(),
                Some("aa:bb:cc:dd:ee:ff"),
                now,
            )
            .unwrap();
        // Initial observation happens before conntrack snapshot has the entry.
        cache.observe_direction(
            "flow-1",
            &upload_observed,
            crate::normalization::Direction::Upload,
            Some("192.0.2.1".parse().unwrap()),
            Some((2, 2)),
            None,
        );
        assert!(cache.has_unverified_aliases("flow-1"));
        assert_eq!(cache.aliases("flow-1").unwrap().len(), 1);

        let conntrack = ConntrackContext::parse(
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.0.2.1 dst=198.51.100.1 sport=50000 dport=443 src=198.51.100.1 dst=192.0.2.1 sport=443 dport=50000",
        );
        cache.reconcile_for_command("flow-1", Some(2), &conntrack);
        assert!(!cache.has_unverified_aliases("flow-1"));
        let aliases = cache.aliases("flow-1").unwrap();
        assert_eq!(aliases.len(), 2);
        assert!(
            aliases
                .iter()
                .any(|alias| alias.hook == 1 && alias.ifindex == 2)
        );
        assert!(
            aliases
                .iter()
                .any(|alias| alias.hook == 2 && alias.ifindex == 2)
        );
    }
}
