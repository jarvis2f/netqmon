use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::lifecycle::{FlowLifecycleEvent, FlowState};

pub const FLOW_KEY_SIZE: usize = 44;
pub const FLOW_VALUE_SIZE: usize = 40;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub ip_version: u8,
    pub protocol: u8,
    pub direction: u8,
    pub ifindex: u32,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
}

impl FlowKey {
    pub fn addresses(&self) -> Option<(IpAddr, IpAddr)> {
        match self.ip_version {
            4 => Some((
                IpAddr::V4(Ipv4Addr::new(
                    self.source_address[0],
                    self.source_address[1],
                    self.source_address[2],
                    self.source_address[3],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    self.destination_address[0],
                    self.destination_address[1],
                    self.destination_address[2],
                    self.destination_address[3],
                )),
            )),
            6 => Some((
                IpAddr::V6(Ipv6Addr::from(self.source_address)),
                IpAddr::V6(Ipv6Addr::from(self.destination_address)),
            )),
            _ => None,
        }
    }
}

impl TryFrom<&[u8]> for FlowKey {
    type Error = FlowDecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != FLOW_KEY_SIZE {
            return Err(FlowDecodeError::KeySize(bytes.len()));
        }
        let mut source_address = [0; 16];
        source_address.copy_from_slice(&bytes[8..24]);
        let mut destination_address = [0; 16];
        destination_address.copy_from_slice(&bytes[24..40]);
        Ok(Self {
            ip_version: bytes[0],
            protocol: bytes[1],
            direction: bytes[2],
            ifindex: u32::from_ne_bytes(bytes[4..8].try_into().expect("fixed slice")),
            source_address,
            destination_address,
            source_port: u16::from_be_bytes(bytes[40..42].try_into().expect("fixed slice")),
            destination_port: u16::from_be_bytes(bytes[42..44].try_into().expect("fixed slice")),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowCounters {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub tcp_flags: u64,
}

impl TryFrom<&[u8]> for FlowCounters {
    type Error = FlowDecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != FLOW_VALUE_SIZE {
            return Err(FlowDecodeError::ValueSize(bytes.len()));
        }
        Ok(Self {
            packets: native_u64(bytes, 0),
            bytes: native_u64(bytes, 8),
            first_seen_ns: native_u64(bytes, 16),
            last_seen_ns: native_u64(bytes, 24),
            tcp_flags: native_u64(bytes, 32),
        })
    }
}

fn native_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + size_of::<u64>()]
            .try_into()
            .expect("fixed slice"),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDelta {
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub counters: FlowCounters,
}

#[derive(Clone, Copy, Debug)]
struct FlowRuntimeState {
    counters: FlowCounters,
    last_activity: Duration,
    lifecycle_state: FlowState,
}

#[derive(Debug)]
pub struct FlowRuntime {
    flows: HashMap<FlowKey, FlowRuntimeState>,
    tcp_idle_timeout: Duration,
    udp_idle_timeout: Duration,
}

#[derive(Debug, Default)]
pub struct FlowRuntimeUpdate {
    pub deltas: Vec<FlowDelta>,
    pub lifecycle_events: Vec<FlowLifecycleEvent>,
}

impl FlowRuntime {
    pub fn new(tcp_idle_timeout: Duration, udp_idle_timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            tcp_idle_timeout,
            udp_idle_timeout,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn update(
        &mut self,
        current: impl IntoIterator<Item = (FlowKey, FlowCounters)>,
        now: Duration,
    ) -> FlowRuntimeUpdate {
        let mut update = FlowRuntimeUpdate::default();
        for (key, counters) in current {
            let state = self.flows.entry(key.clone()).or_insert(FlowRuntimeState {
                counters: FlowCounters::default(),
                last_activity: now,
                lifecycle_state: FlowState::Idle,
            });
            let packets = monotonic_delta(counters.packets, state.counters.packets);
            let bytes = monotonic_delta(counters.bytes, state.counters.bytes);
            state.counters = counters;
            if packets != 0 || bytes != 0 {
                state.last_activity = now;
                if state.lifecycle_state != FlowState::Active {
                    state.lifecycle_state = FlowState::Active;
                    update.lifecycle_events.push(FlowLifecycleEvent {
                        key: key.clone(),
                        state: FlowState::Active,
                    });
                }
                update.deltas.push(FlowDelta {
                    key: key.clone(),
                    packets,
                    bytes,
                    counters,
                });
            }
        }

        let tcp_idle_timeout = self.tcp_idle_timeout;
        let udp_idle_timeout = self.udp_idle_timeout;
        self.flows.retain(|key, state| {
            let timeout = if key.protocol == 17 {
                udp_idle_timeout
            } else {
                tcp_idle_timeout
            };
            let inactive_for = now.saturating_sub(state.last_activity);
            if inactive_for >= timeout {
                update.lifecycle_events.push(FlowLifecycleEvent {
                    key: key.clone(),
                    state: FlowState::End,
                });
                false
            } else {
                if inactive_for > Duration::ZERO && state.lifecycle_state == FlowState::Active {
                    state.lifecycle_state = FlowState::Idle;
                    update.lifecycle_events.push(FlowLifecycleEvent {
                        key: key.clone(),
                        state: FlowState::Idle,
                    });
                }
                true
            }
        });
        update
    }
}

fn monotonic_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDecodeError {
    KeySize(usize),
    ValueSize(usize),
}

impl fmt::Display for FlowDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeySize(size) => write!(formatter, "flow key has {size} bytes, expected 44"),
            Self::ValueSize(size) => {
                write!(formatter, "flow value has {size} bytes, expected 40")
            }
        }
    }
}

impl std::error::Error for FlowDecodeError {}

#[cfg(test)]
mod tests {
    use super::{FlowCounters, FlowKey, FlowRuntime, FlowState};
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn computes_non_repeating_monotonic_deltas() {
        let key = key(17);
        let mut poller = FlowRuntime::new(Duration::from_secs(120), Duration::from_secs(30));
        let first = poller.update(snapshot(&key, 10, 740), Duration::ZERO);
        assert_eq!((first.deltas[0].packets, first.deltas[0].bytes), (10, 740));
        assert!(
            poller
                .update(snapshot(&key, 10, 740), Duration::ZERO)
                .deltas
                .is_empty()
        );

        let next = poller.update(snapshot(&key, 25, 1_850), Duration::ZERO);
        assert_eq!((next.deltas[0].packets, next.deltas[0].bytes), (15, 1_110));
    }

    #[test]
    fn handles_counter_reset_and_entry_disappearance() {
        let key = key(6);
        let mut poller = FlowRuntime::new(Duration::from_secs(120), Duration::from_secs(30));
        poller.update(snapshot(&key, 100, 10_000), Duration::ZERO);

        let reset = poller.update(snapshot(&key, 3, 300), Duration::ZERO);
        assert_eq!((reset.deltas[0].packets, reset.deltas[0].bytes), (3, 300));
        assert!(
            poller
                .update(HashMap::new(), Duration::ZERO)
                .deltas
                .is_empty()
        );

        let reappeared = poller.update(snapshot(&key, 1, 100), Duration::ZERO);
        assert_eq!(
            (reappeared.deltas[0].packets, reappeared.deltas[0].bytes),
            (1, 100)
        );
    }

    #[test]
    fn lifecycle_shares_the_counter_state_and_expires_once() {
        let key = key(17);
        let mut runtime = FlowRuntime::new(Duration::from_secs(120), Duration::from_secs(30));
        let active = runtime.update(snapshot(&key, 1, 100), Duration::ZERO);
        assert_eq!(active.lifecycle_events[0].state, FlowState::Active);

        let idle = runtime.update(HashMap::new(), Duration::from_secs(1));
        assert_eq!(idle.lifecycle_events[0].state, FlowState::Idle);
        let ended = runtime.update(HashMap::new(), Duration::from_secs(30));
        assert_eq!(ended.lifecycle_events[0].state, FlowState::End);
        assert_eq!(runtime.len(), 0);
    }

    #[test]
    fn decodes_network_order_ports_and_native_counters() {
        let mut raw_key = [0; 44];
        raw_key[0] = 4;
        raw_key[1] = 17;
        raw_key[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        raw_key[40..42].copy_from_slice(&47_000_u16.to_be_bytes());
        raw_key[42..44].copy_from_slice(&48_000_u16.to_be_bytes());
        let key = FlowKey::try_from(raw_key.as_slice()).unwrap();
        assert_eq!(
            (key.ifindex, key.source_port, key.destination_port),
            (7, 47_000, 48_000)
        );

        let mut raw_value = [0; 40];
        for (offset, value) in [(0, 2), (8, 148), (16, 10), (24, 20), (32, 0x12)] {
            raw_value[offset..offset + 8].copy_from_slice(&u64::to_ne_bytes(value));
        }
        let counters = FlowCounters::try_from(raw_value.as_slice()).unwrap();
        assert_eq!(counters.packets, 2);
        assert_eq!(counters.bytes, 148);
        assert_eq!(counters.tcp_flags, 0x12);
    }

    fn key(protocol: u8) -> FlowKey {
        FlowKey {
            ip_version: 4,
            protocol,
            direction: 0,
            ifindex: 1,
            source_address: [0; 16],
            destination_address: [0; 16],
            source_port: 1,
            destination_port: 2,
        }
    }

    fn snapshot(key: &FlowKey, packets: u64, bytes: u64) -> HashMap<FlowKey, FlowCounters> {
        HashMap::from([(
            key.clone(),
            FlowCounters {
                packets,
                bytes,
                first_seen_ns: 1,
                last_seen_ns: 2,
                tcp_flags: 0,
            },
        )])
    }
}
