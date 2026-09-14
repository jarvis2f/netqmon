use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::atomic::Ordering;

use portable_atomic::AtomicU64;

use crate::flow::FlowKey;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct FlowTuple {
    pub protocol: u8,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConntrackEntry {
    pub original: FlowTuple,
    pub reply: FlowTuple,
    pub source_nat: bool,
    pub destination_nat: bool,
}

/// Thread-safe cumulative conntrack resolution statistics.
#[derive(Debug, Default)]
pub struct ConntrackStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub refreshes: AtomicU64,
    pub refresh_success: AtomicU64,
    pub refresh_failed: AtomicU64,
    pub entries: AtomicU64,
    pub refresh_duration_us: AtomicU64,
}

impl ConntrackStats {
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_refresh(&self, success: bool, entries: usize, duration_us: u64) {
        self.refreshes.fetch_add(1, Ordering::Relaxed);
        if success {
            self.refresh_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.refresh_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.entries.store(entries as u64, Ordering::Relaxed);
        self.refresh_duration_us
            .store(duration_us, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConntrackStatsSnapshot {
        ConntrackStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            refreshes: self.refreshes.load(Ordering::Relaxed),
            refresh_success: self.refresh_success.load(Ordering::Relaxed),
            refresh_failed: self.refresh_failed.load(Ordering::Relaxed),
            entries: self.entries.load(Ordering::Relaxed),
            refresh_duration_us: self.refresh_duration_us.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConntrackStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub refreshes: u64,
    pub refresh_success: u64,
    pub refresh_failed: u64,
    pub entries: u64,
    pub refresh_duration_us: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ConntrackContext {
    observed: HashMap<FlowTuple, ConntrackEntry>,
}

impl ConntrackContext {
    pub fn discover() -> Self {
        for path in ["/proc/net/nf_conntrack", "/proc/net/ip_conntrack"] {
            if let Ok(contents) = fs::read_to_string(path) {
                return Self::parse(&contents);
            }
        }
        Self::default()
    }

    pub fn parse(contents: &str) -> Self {
        let mut context = Self::default();
        for line in contents.lines() {
            if let Some(entry) = parse_entry(line) {
                context.insert(entry);
            }
        }
        context
    }

    fn insert(&mut self, entry: ConntrackEntry) {
        self.observed.insert(entry.original, entry);
        self.observed.insert(entry.reply, entry);
        self.observed.insert(reverse(entry.reply), entry);
        self.observed.insert(reverse(entry.original), entry);
    }

    pub fn resolve(&self, key: &FlowKey) -> Option<ConntrackEntry> {
        FlowTuple::from_key(key).and_then(|tuple| self.observed.get(&tuple).copied())
    }

    pub fn len(&self) -> usize {
        self.observed.len()
    }
}

impl FlowTuple {
    fn from_key(key: &FlowKey) -> Option<Self> {
        let (source, destination) = key.addresses()?;
        Some(Self {
            protocol: key.protocol,
            source,
            source_port: key.source_port,
            destination,
            destination_port: key.destination_port,
        })
    }
}

fn reverse(tuple: FlowTuple) -> FlowTuple {
    FlowTuple {
        protocol: tuple.protocol,
        source: tuple.destination,
        source_port: tuple.destination_port,
        destination: tuple.source,
        destination_port: tuple.source_port,
    }
}

fn parse_entry(line: &str) -> Option<ConntrackEntry> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let protocol = fields.iter().find_map(|field| match *field {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        _ => None,
    })?;
    let mut tuples = Vec::new();
    let mut current = HashMap::new();
    for field in fields {
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        if name == "src" && current.contains_key("src") {
            tuples.push(std::mem::take(&mut current));
        }
        if matches!(name, "src" | "dst" | "sport" | "dport") {
            current.insert(name, value);
        }
    }
    tuples.push(current);
    if tuples.len() < 2 {
        return None;
    }
    let tuple = |fields: &HashMap<&str, &str>| -> Option<FlowTuple> {
        Some(FlowTuple {
            protocol,
            source: fields.get("src")?.parse().ok()?,
            destination: fields.get("dst")?.parse().ok()?,
            source_port: fields
                .get("sport")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            destination_port: fields
                .get("dport")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
    };
    let original = tuple(&tuples[0])?;
    let reply = tuple(&tuples[1])?;
    Some(ConntrackEntry {
        original,
        reply,
        source_nat: original.source != reply.destination,
        destination_nat: original.destination != reply.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nat_and_maps_translated_tuple_to_original_client() {
        let context = ConntrackContext::parse(
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.2.100 dst=1.1.1.1 sport=50000 dport=443 src=1.1.1.1 dst=192.168.2.8 sport=443 dport=50000 [ASSURED]",
        );
        let entry = context
            .observed
            .get(&FlowTuple {
                protocol: 6,
                source: "192.168.2.8".parse().unwrap(),
                source_port: 50000,
                destination: "1.1.1.1".parse().unwrap(),
                destination_port: 443,
            })
            .unwrap();
        assert_eq!(
            entry.original.source,
            "192.168.2.100".parse::<IpAddr>().unwrap()
        );
        assert!(entry.source_nat);
    }
}
