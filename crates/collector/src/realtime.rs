use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netqmon_protocol::v1::{
    CounterSanityStatus, FlowLifecycle, FlowScope as WireFlowScope, NatType, OffloadStatus,
    PathType as WirePathType, TelemetryBatch,
};
use netqmon_storage::FlowAttribution;
use serde::Serialize;
use tokio::sync::broadcast;

const DEFAULT_INTERVAL_MS: u64 = 1_000;
const MAX_HISTORY_POINTS: usize = 900;
const MAX_ACTIVE_FLOWS: usize = 10_000;
const EVENT_CHANNEL_CAPACITY: usize = 128;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Throughput {
    pub(crate) upload_bytes_per_second: u64,
    pub(crate) download_bytes_per_second: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ThroughputPoint {
    pub(crate) timestamp: u64,
    pub(crate) upload_bytes_per_second: u64,
    pub(crate) download_bytes_per_second: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ScopedThroughput {
    pub(crate) internet: Throughput,
    pub(crate) internal: Throughput,
    pub(crate) tunnel: Throughput,
    pub(crate) unknown: Throughput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct GatewayHealthSnapshot {
    pub(crate) observed_at: u64,
    pub(crate) uptime_seconds: u64,
    pub(crate) dropped_batches: u64,
    pub(crate) dns_dropped_events: u64,
    pub(crate) protocol_probe_dropped_events: u64,
    pub(crate) tracked_flows: u64,
    pub(crate) agent_version: String,
    pub(crate) kernel_version: String,
    pub(crate) openwrt_version: String,
    pub(crate) hardware_flow_offload: String,
    pub(crate) capture_interface: String,
    pub(crate) capture_interfaces: Vec<String>,
    pub(crate) interface_rx_bytes: u64,
    pub(crate) interface_tx_bytes: u64,
    pub(crate) interface_rx_packets: u64,
    pub(crate) interface_tx_packets: u64,
    pub(crate) interface_delta_bytes: u64,
    pub(crate) interface_delta_packets: u64,
    pub(crate) flow_delta_bytes: u64,
    pub(crate) flow_delta_packets: u64,
    pub(crate) interface_counter_sanity: String,
    pub(crate) topology: Option<TopologySummarySnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TopologySegmentSnapshot {
    pub(crate) subnet: String,
    pub(crate) interface: String,
    pub(crate) role: String,
    pub(crate) confidence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TopologySummarySnapshot {
    pub(crate) topology_mode: String,
    pub(crate) agent_addresses: Vec<String>,
    pub(crate) upstream_gateway: String,
    pub(crate) segments: Vec<TopologySegmentSnapshot>,
    pub(crate) nat_status: String,
    pub(crate) attach_backend: String,
    pub(crate) attach_order: String,
    pub(crate) ipv4_coverage: String,
    pub(crate) ipv6_coverage: String,
    pub(crate) icmp_redirect: String,
    pub(crate) software_flow_offload: String,
    pub(crate) hardware_flow_offload: String,
    pub(crate) topology_warnings: Vec<String>,
    pub(crate) confidence: u32,
    pub(crate) capture_interface: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ActiveFlowSnapshot {
    pub(crate) id: String,
    pub(crate) client_ip: String,
    pub(crate) client_port: u32,
    pub(crate) remote_ip: String,
    pub(crate) remote_port: u32,
    pub(crate) protocol: u32,
    pub(crate) lifecycle: String,
    pub(crate) application: String,
    pub(crate) category: String,
    pub(crate) domain: Option<String>,
    pub(crate) confidence: f64,
    pub(crate) upload_bytes: u64,
    pub(crate) download_bytes: u64,
    pub(crate) packets: u64,
    pub(crate) last_seen: u64,
    pub(crate) scope: String,
    pub(crate) path_type: String,
    pub(crate) nat: String,
    pub(crate) source_segment: String,
    pub(crate) destination_segment: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(crate) struct RealtimeSnapshot {
    pub(crate) generated_at: u64,
    pub(crate) total: Throughput,
    pub(crate) internet: Throughput,
    pub(crate) internal: Throughput,
    pub(crate) tunnel: Throughput,
    pub(crate) unknown: Throughput,
    pub(crate) clients: HashMap<String, Throughput>,
    pub(crate) client_scopes: HashMap<String, ScopedThroughput>,
    pub(crate) applications: HashMap<String, Throughput>,
    pub(crate) active_flows: Vec<ActiveFlowSnapshot>,
    pub(crate) history: Vec<ThroughputPoint>,
    pub(crate) gateway_health: Option<GatewayHealthSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct GatewayStatusEvent {
    pub(crate) gateway_id: String,
    pub(crate) status: String,
    pub(crate) observed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DeviceSeenEvent {
    pub(crate) gateway_id: String,
    pub(crate) ip: String,
    pub(crate) mac: String,
    pub(crate) hostname: Option<String>,
    pub(crate) observed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct WarningEvent {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) observed_at: u64,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum RealtimeEvent {
    Snapshot(RealtimeSnapshot),
    GatewayStatus(GatewayStatusEvent),
    DeviceSeen(DeviceSeenEvent),
    Warning(WarningEvent),
}

impl RealtimeEvent {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Snapshot(_) => "snapshot",
            Self::GatewayStatus(_) => "gateway_status",
            Self::DeviceSeen(_) => "device_seen",
            Self::Warning(_) => "warning",
        }
    }

    pub(crate) fn json(&self) -> serde_json::Result<String> {
        match self {
            Self::Snapshot(value) => serde_json::to_string(value),
            Self::GatewayStatus(value) => serde_json::to_string(value),
            Self::DeviceSeen(value) => serde_json::to_string(value),
            Self::Warning(value) => serde_json::to_string(value),
        }
    }
}

pub(crate) struct RealtimeEngine {
    snapshot: RealtimeSnapshot,
    active_flows: HashMap<String, ActiveFlowSnapshot>,
    last_update_at: Option<u64>,
    sender: broadcast::Sender<RealtimeEvent>,
}

struct FlowDeltaSummary {
    total: Throughput,
    internet: Throughput,
    internal: Throughput,
    tunnel: Throughput,
    unknown: Throughput,
    clients: HashMap<String, Throughput>,
    client_scopes: HashMap<String, ScopedThroughput>,
    applications: HashMap<String, Throughput>,
}

impl Default for RealtimeEngine {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            snapshot: RealtimeSnapshot::default(),
            active_flows: HashMap::new(),
            last_update_at: None,
            sender,
        }
    }
}

impl RealtimeEngine {
    pub(crate) fn snapshot(&self) -> RealtimeSnapshot {
        self.snapshot.clone()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.sender.subscribe()
    }

    pub(crate) fn gateway_status(&self, gateway_id: &str, status: &str, observed_at: u64) {
        let _ = self
            .sender
            .send(RealtimeEvent::GatewayStatus(GatewayStatusEvent {
                gateway_id: gateway_id.to_owned(),
                status: status.to_owned(),
                observed_at,
            }));
    }

    pub(crate) fn update(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        observed_at: u64,
    ) {
        let flow_summary = self.apply_flow_deltas(batch, attributions, observed_at);

        let mut history = VecDeque::from(std::mem::take(&mut self.snapshot.history));
        history.push_back(ThroughputPoint {
            timestamp: observed_at,
            upload_bytes_per_second: flow_summary.internet.upload_bytes_per_second,
            download_bytes_per_second: flow_summary.internet.download_bytes_per_second,
        });
        while history.len() > MAX_HISTORY_POINTS {
            history.pop_front();
        }
        let mut active_flows = self.active_flows.values().cloned().collect::<Vec<_>>();
        active_flows.sort_by(|left, right| {
            right
                .last_seen
                .cmp(&left.last_seen)
                .then_with(|| left.id.cmp(&right.id))
        });
        self.snapshot = RealtimeSnapshot {
            generated_at: observed_at,
            total: flow_summary.total,
            internet: flow_summary.internet,
            internal: flow_summary.internal,
            tunnel: flow_summary.tunnel,
            unknown: flow_summary.unknown,
            clients: flow_summary.clients,
            client_scopes: flow_summary.client_scopes,
            applications: flow_summary.applications,
            active_flows,
            history: history.into(),
            gateway_health: self.gateway_health_snapshot(batch),
        };

        self.publish_batch_events(batch, attributions, observed_at);
    }

    fn gateway_health_snapshot(&self, batch: &TelemetryBatch) -> Option<GatewayHealthSnapshot> {
        batch.health.as_ref().map_or_else(
            || self.snapshot.gateway_health.clone(),
            |health| {
                Some(GatewayHealthSnapshot {
                    observed_at: health.observed_at_unix_ms,
                    uptime_seconds: health.uptime_seconds,
                    dropped_batches: health.dropped_batches,
                    dns_dropped_events: health.dns_dropped_events,
                    protocol_probe_dropped_events: health.protocol_probe_dropped_events,
                    tracked_flows: health.tracked_flows,
                    agent_version: batch.agent_version.clone(),
                    kernel_version: health.kernel_version.clone(),
                    openwrt_version: health.openwrt_version.clone(),
                    hardware_flow_offload: offload_name(health.hardware_flow_offload).to_owned(),
                    capture_interface: health.capture_interface.clone(),
                    capture_interfaces: if health.capture_interfaces.is_empty() {
                        vec![health.capture_interface.clone()]
                    } else {
                        health.capture_interfaces.clone()
                    },
                    interface_rx_bytes: health.interface_rx_bytes,
                    interface_tx_bytes: health.interface_tx_bytes,
                    interface_rx_packets: health.interface_rx_packets,
                    interface_tx_packets: health.interface_tx_packets,
                    interface_delta_bytes: health.interface_delta_bytes,
                    interface_delta_packets: health.interface_delta_packets,
                    flow_delta_bytes: health.flow_delta_bytes,
                    flow_delta_packets: health.flow_delta_packets,
                    interface_counter_sanity: counter_sanity_name(health.interface_counter_sanity)
                        .to_owned(),
                    topology: health
                        .topology
                        .as_ref()
                        .map(|topology| TopologySummarySnapshot {
                            topology_mode: topology.topology_mode.clone(),
                            agent_addresses: topology.agent_addresses.clone(),
                            upstream_gateway: topology.upstream_gateway.clone(),
                            segments: topology
                                .segments
                                .iter()
                                .map(|segment| TopologySegmentSnapshot {
                                    subnet: segment.subnet.clone(),
                                    interface: segment.interface.clone(),
                                    role: segment.role.clone(),
                                    confidence: segment.confidence,
                                })
                                .collect(),
                            nat_status: topology.nat_status.clone(),
                            attach_backend: topology.attach_backend.clone(),
                            attach_order: topology.attach_order.clone(),
                            ipv4_coverage: topology.ipv4_coverage.clone(),
                            ipv6_coverage: topology.ipv6_coverage.clone(),
                            icmp_redirect: topology.icmp_redirect.clone(),
                            software_flow_offload: offload_name(topology.software_flow_offload)
                                .to_owned(),
                            hardware_flow_offload: offload_name(topology.hardware_flow_offload)
                                .to_owned(),
                            topology_warnings: topology.topology_warnings.clone(),
                            confidence: topology.confidence,
                            capture_interface: health.capture_interface.clone(),
                        }),
                })
            },
        )
    }

    fn apply_flow_deltas(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        observed_at: u64,
    ) -> FlowDeltaSummary {
        let interval_ms = self
            .last_update_at
            .and_then(|previous| observed_at.checked_sub(previous))
            .filter(|interval| *interval > 0)
            .unwrap_or(DEFAULT_INTERVAL_MS);
        self.last_update_at = Some(observed_at);
        let mut total = Throughput::default();
        let mut internet = Throughput::default();
        let mut internal = Throughput::default();
        let mut tunnel = Throughput::default();
        let mut unknown_scope = Throughput::default();
        let mut clients = HashMap::<String, Throughput>::new();
        let mut client_scopes = HashMap::<String, ScopedThroughput>::new();
        let mut applications = HashMap::<String, Throughput>::new();
        let unknown = FlowAttribution::default();
        for (index, flow) in batch.flows.iter().enumerate() {
            let attribution = attributions.get(index).unwrap_or(&unknown);
            let upload_rate = rate(flow.upload_bytes, interval_ms);
            let download_rate = rate(flow.download_bytes, interval_ms);
            add_rate(&mut total, upload_rate, download_rate);
            let wire_scope = WireFlowScope::try_from(flow.scope).ok();
            add_rate(
                match wire_scope {
                    Some(WireFlowScope::Internet) => &mut internet,
                    Some(WireFlowScope::Internal) => &mut internal,
                    Some(WireFlowScope::Tunnel) => &mut tunnel,
                    _ => &mut unknown_scope,
                },
                upload_rate,
                download_rate,
            );
            let client_address = format_ip(&flow.client_ip);
            let client_key = client_id(flow);
            add_rate(
                clients.entry(client_key.clone()).or_default(),
                upload_rate,
                download_rate,
            );
            let scoped = client_scopes.entry(client_key).or_default();
            add_rate(
                match wire_scope {
                    Some(WireFlowScope::Internet) => &mut scoped.internet,
                    Some(WireFlowScope::Internal) => &mut scoped.internal,
                    Some(WireFlowScope::Tunnel) => &mut scoped.tunnel,
                    _ => &mut scoped.unknown,
                },
                upload_rate,
                download_rate,
            );
            add_rate(
                applications
                    .entry(attribution.application_id.clone())
                    .or_default(),
                upload_rate,
                download_rate,
            );
            self.update_active_flow(flow, attribution, client_address);
        }
        self.evict_oldest_flows();
        FlowDeltaSummary {
            total,
            internet,
            internal,
            tunnel,
            unknown: unknown_scope,
            clients,
            client_scopes,
            applications,
        }
    }

    fn update_active_flow(
        &mut self,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
        client_ip: String,
    ) {
        let id = flow_id(flow);
        match FlowLifecycle::try_from(flow.lifecycle) {
            Ok(FlowLifecycle::Ended) => {
                self.active_flows.remove(&id);
                return;
            }
            Ok(FlowLifecycle::Active | FlowLifecycle::Idle) => {}
            _ => return,
        }
        let current = self
            .active_flows
            .entry(id.clone())
            .or_insert_with(|| ActiveFlowSnapshot {
                id,
                client_ip,
                client_port: flow.client_port,
                remote_ip: format_ip(&flow.remote_ip),
                remote_port: flow.remote_port,
                protocol: flow.protocol,
                lifecycle: lifecycle_name(flow.lifecycle).to_owned(),
                application: attribution.application_id.clone(),
                category: attribution.category_id.clone(),
                domain: attribution.domain.clone(),
                confidence: attribution.confidence,
                upload_bytes: 0,
                download_bytes: 0,
                packets: 0,
                last_seen: flow.last_seen_unix_ms,
                scope: scope_name(flow.scope).to_owned(),
                path_type: path_name(flow.path_type).to_owned(),
                nat: nat_name(flow.nat).to_owned(),
                source_segment: flow.source_segment.clone(),
                destination_segment: flow.destination_segment.clone(),
            });
        lifecycle_name(flow.lifecycle).clone_into(&mut current.lifecycle);
        current.upload_bytes = current.upload_bytes.saturating_add(flow.upload_bytes);
        current.download_bytes = current.download_bytes.saturating_add(flow.download_bytes);
        current.packets = current.packets.saturating_add(flow.packets);
        current.last_seen = current.last_seen.max(flow.last_seen_unix_ms);
        scope_name(flow.scope).clone_into(&mut current.scope);
        path_name(flow.path_type).clone_into(&mut current.path_type);
        nat_name(flow.nat).clone_into(&mut current.nat);
        current.source_segment.clone_from(&flow.source_segment);
        current
            .destination_segment
            .clone_from(&flow.destination_segment);
        if attribution.confidence.total_cmp(&current.confidence) != Ordering::Less {
            current.application.clone_from(&attribution.application_id);
            current.category.clone_from(&attribution.category_id);
            current.domain.clone_from(&attribution.domain);
            current.confidence = attribution.confidence;
        }
    }

    fn publish_batch_events(
        &self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        observed_at: u64,
    ) {
        self.gateway_status(&batch.gateway_id, "online", observed_at);
        for device in &batch.device_observations {
            let _ = self.sender.send(RealtimeEvent::DeviceSeen(DeviceSeenEvent {
                gateway_id: batch.gateway_id.clone(),
                ip: format_ip(&device.ip),
                mac: format_mac(&device.mac),
                hostname: (!device.hostname.is_empty()).then(|| device.hostname.clone()),
                observed_at: device.last_seen_unix_ms,
            }));
        }
        let unknown_count = attributions
            .iter()
            .filter(|attribution| attribution.application_id == "unknown")
            .count();
        if unknown_count > 0 {
            let _ = self.sender.send(RealtimeEvent::Warning(WarningEvent {
                code: "unclassified_flows".to_owned(),
                message: format!("{unknown_count} flows had no matching application rule"),
                observed_at,
            }));
        }
        let _ = self
            .sender
            .send(RealtimeEvent::Snapshot(self.snapshot.clone()));
    }

    fn evict_oldest_flows(&mut self) {
        let excess = self.active_flows.len().saturating_sub(MAX_ACTIVE_FLOWS);
        if excess == 0 {
            return;
        }
        let mut oldest = self
            .active_flows
            .iter()
            .map(|(id, flow)| (flow.last_seen, id.clone()))
            .collect::<Vec<_>>();
        oldest.sort_unstable();
        for (_, id) in oldest.into_iter().take(excess) {
            self.active_flows.remove(&id);
        }
    }
}

fn add_rate(throughput: &mut Throughput, upload: u64, download: u64) {
    throughput.upload_bytes_per_second = throughput.upload_bytes_per_second.saturating_add(upload);
    throughput.download_bytes_per_second = throughput
        .download_bytes_per_second
        .saturating_add(download);
}

fn rate(bytes: u64, interval_ms: u64) -> u64 {
    bytes.saturating_mul(1_000) / interval_ms
}

fn counter_sanity_name(value: i32) -> &'static str {
    let Ok(status) = CounterSanityStatus::try_from(value) else {
        return "unknown";
    };
    match status {
        CounterSanityStatus::Ok => "ok",
        CounterSanityStatus::Degraded => "degraded",
        CounterSanityStatus::Disabled => "disabled",
        _ => "unknown",
    }
}

fn offload_name(value: i32) -> &'static str {
    match OffloadStatus::try_from(value) {
        Ok(OffloadStatus::Enabled) => "enabled",
        Ok(OffloadStatus::Disabled) => "disabled",
        _ => "unknown",
    }
}

fn scope_name(value: i32) -> &'static str {
    match WireFlowScope::try_from(value) {
        Ok(WireFlowScope::Internet) => "internet",
        Ok(WireFlowScope::Internal) => "internal",
        Ok(WireFlowScope::Tunnel) => "tunnel",
        _ => "unknown",
    }
}

fn path_name(value: i32) -> &'static str {
    match WirePathType::try_from(value) {
        Ok(WirePathType::Forwarded) => "forwarded",
        Ok(WirePathType::Internal) => "internal",
        Ok(WirePathType::Tunnel) => "tunnel",
        _ => "unknown",
    }
}

fn nat_name(value: i32) -> &'static str {
    match NatType::try_from(value) {
        Ok(NatType::None) => "none",
        Ok(NatType::Snat) => "snat",
        Ok(NatType::Dnat) => "dnat",
        Ok(NatType::Both) => "both",
        _ => "unknown",
    }
}

fn flow_id(flow: &netqmon_protocol::v1::FlowDelta) -> String {
    format!(
        "{}:{}-{}:{}-{}-{}",
        format_ip(&flow.client_ip),
        flow.client_port,
        format_ip(&flow.remote_ip),
        flow.remote_port,
        flow.protocol,
        flow.direction
    )
}

fn client_id(flow: &netqmon_protocol::v1::FlowDelta) -> String {
    if flow.client_mac.len() == 6 {
        format_mac(&flow.client_mac)
    } else {
        format_ip(&flow.client_ip)
    }
}

fn lifecycle_name(lifecycle: i32) -> &'static str {
    match FlowLifecycle::try_from(lifecycle) {
        Ok(FlowLifecycle::Active) => "active",
        Ok(FlowLifecycle::Idle) => "idle",
        Ok(FlowLifecycle::Ended) => "ended",
        _ => "unspecified",
    }
}

pub(crate) fn format_ip(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)).to_string(),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().unwrap_or([0; 16]);
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        _ => "unknown".to_owned(),
    }
}

fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        return "unknown".to_owned();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests;
