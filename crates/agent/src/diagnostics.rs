use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use portable_atomic::AtomicU64;

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use serde::{Deserialize, Serialize};

use crate::config::{DiagnosticsAction, DiagnosticsArgs};
use crate::conntrack::ConntrackStats;
use crate::transport::TransportStats;

pub const DEFAULT_SOCKET_PATH: &str = "/var/run/netqmon-agent.sock";

fn rate_ppm(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000_000) / denominator
    }
}

#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("NETQMON_SOCKET_PATH") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

/// Snapshot of runtime agent diagnostics for E2E verification and troubleshooting.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentDiagnostics {
    pub enabled: bool,
    pub flow_map_entries: u64,
    pub flow_map_capacity: u64,
    pub poll_duration_us: u64,
    pub poll_max_duration_us: u64,
    pub poll_interval_ms: u64,
    pub keys_scanned: u64,
    pub flows_changed: u64,
    pub flows_idle: u64,
    pub flows_ended: u64,
    pub sample_budget_entries: u64,
    pub sample_budget_capacity: u64,
    pub sample_events: u64,
    pub sampled_flows: u64,
    pub sample_event_bytes: u64,
    pub sample_drops: u64,
    pub sample_queue_items: u64,
    pub sample_queue_bytes: u64,
    pub device_count: u64,
    pub discovery_dedup_entries: u64,
    pub http_user_agent_dedup_entries: u64,
    pub discovery_events: u64,
    pub discovery_parse_failed: u64,
    pub discovery_duplicates: u64,
    pub discovery_parse_rate_ppm: u64,
    pub discovery_duplicate_rate_ppm: u64,
    pub dns_drops: u64,
    pub neighbor_refresh_duration_us: u64,
    pub dhcp_lease_refresh_duration_us: u64,
    pub cumulative_deltas_emitted: u64,
    pub cumulative_bytes_emitted: u64,
    pub cumulative_packets_emitted: u64,
    pub conntrack_hits: u64,
    pub conntrack_misses: u64,
    pub conntrack_refreshes: u64,
    pub conntrack_refresh_success: u64,
    pub conntrack_refresh_failed: u64,
    pub conntrack_entries: u64,
    pub conntrack_refresh_duration_us: u64,
    pub router_local_filtered_flows: u64,
    pub router_local_filtered_bytes: u64,
    pub router_local_filtered_packets: u64,
    pub queue_depth: u64,
    pub queue_high_watermark: u64,
    pub queue_bytes: u64,
    pub queue_high_watermark_bytes: u64,
    pub dropped_batches: u64,
    pub dropped_flows: u64,
    pub dropped_bytes: u64,
    pub dropped_packets: u64,
    pub transport_sent_batches: u64,
    pub transport_sent_flows: u64,
    pub transport_sent_bytes: u64,
}

impl fmt::Display for AgentDiagnostics {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Diagnostics Status: {}",
            if self.enabled { "enabled" } else { "disabled" }
        )?;
        writeln!(f, "Flow Map:")?;
        writeln!(f, "  Entries:                    {}", self.flow_map_entries)?;
        writeln!(
            f,
            "  Capacity:                   {}",
            self.flow_map_capacity
        )?;
        writeln!(f, "Poller:")?;
        writeln!(
            f,
            "  Last Duration:              {} us",
            self.poll_duration_us
        )?;
        writeln!(
            f,
            "  Poll Interval:              {} ms",
            self.poll_interval_ms
        )?;
        writeln!(f, "  Keys Scanned:               {}", self.keys_scanned)?;
        writeln!(
            f,
            "  Max Duration:               {} us",
            self.poll_max_duration_us
        )?;
        writeln!(f, "  Flows Changed:              {}", self.flows_changed)?;
        writeln!(f, "  Flows Idle:                 {}", self.flows_idle)?;
        writeln!(f, "  Flows Ended:                {}", self.flows_ended)?;
        writeln!(f, "Sampling:")?;
        writeln!(
            f,
            "  Budget Entries:             {}",
            self.sample_budget_entries
        )?;
        writeln!(
            f,
            "  Budget Capacity:            {}",
            self.sample_budget_capacity
        )?;
        writeln!(f, "  Events:                     {}", self.sample_events)?;
        writeln!(f, "  Sampled Flows:              {}", self.sampled_flows)?;
        writeln!(
            f,
            "  Event Bytes:                {}",
            self.sample_event_bytes
        )?;
        writeln!(f, "  Drops:                      {}", self.sample_drops)?;
        writeln!(
            f,
            "  Queue Items:                {}",
            self.sample_queue_items
        )?;
        writeln!(
            f,
            "  Queue Bytes:                {}",
            self.sample_queue_bytes
        )?;
        writeln!(f, "Discovery:")?;
        writeln!(f, "  Events:                     {}", self.discovery_events)?;
        writeln!(
            f,
            "  Parse Failed:               {}",
            self.discovery_parse_failed
        )?;
        writeln!(
            f,
            "  Duplicates:                 {}",
            self.discovery_duplicates
        )?;
        writeln!(
            f,
            "  Parse Rate:                 {} ppm",
            self.discovery_parse_rate_ppm
        )?;
        writeln!(
            f,
            "  Duplicate Rate:             {} ppm",
            self.discovery_duplicate_rate_ppm
        )?;
        writeln!(f, "  DNS Drops:                  {}", self.dns_drops)?;
        writeln!(
            f,
            "  Neighbor Refresh:           {} us",
            self.neighbor_refresh_duration_us
        )?;
        writeln!(
            f,
            "  DHCP Lease Refresh:         {} us",
            self.dhcp_lease_refresh_duration_us
        )?;
        writeln!(f, "Cumulative Emitted:")?;
        writeln!(
            f,
            "  Deltas:                     {}",
            self.cumulative_deltas_emitted
        )?;
        writeln!(
            f,
            "  Bytes:                      {}",
            self.cumulative_bytes_emitted
        )?;
        writeln!(
            f,
            "  Packets:                    {}",
            self.cumulative_packets_emitted
        )?;
        writeln!(f, "Conntrack:")?;
        writeln!(f, "  Hits:                       {}", self.conntrack_hits)?;
        writeln!(f, "  Misses:                     {}", self.conntrack_misses)?;
        writeln!(
            f,
            "  Entries:                    {}",
            self.conntrack_entries
        )?;
        writeln!(
            f,
            "  Refresh Duration:           {} us",
            self.conntrack_refresh_duration_us
        )?;
        writeln!(
            f,
            "  Refreshes:                  {}",
            self.conntrack_refreshes
        )?;
        writeln!(
            f,
            "  Refresh Success:            {}",
            self.conntrack_refresh_success
        )?;
        writeln!(
            f,
            "  Refresh Failed:             {}",
            self.conntrack_refresh_failed
        )?;
        writeln!(f, "Router Local Filter:")?;
        writeln!(
            f,
            "  Filtered Flows:             {}",
            self.router_local_filtered_flows
        )?;
        writeln!(
            f,
            "  Filtered Bytes:             {}",
            self.router_local_filtered_bytes
        )?;
        writeln!(
            f,
            "  Filtered Packets:           {}",
            self.router_local_filtered_packets
        )?;
        writeln!(f, "Transport & Queue:")?;
        writeln!(f, "  Queue Depth:                {}", self.queue_depth)?;
        writeln!(
            f,
            "  Queue High Watermark:       {}",
            self.queue_high_watermark
        )?;
        writeln!(f, "  Queue Bytes:                {}", self.queue_bytes)?;
        writeln!(
            f,
            "  Queue High Watermark Bytes: {}",
            self.queue_high_watermark_bytes
        )?;
        writeln!(f, "  Dropped Batches:            {}", self.dropped_batches)?;
        writeln!(f, "  Dropped Flows:              {}", self.dropped_flows)?;
        writeln!(f, "  Dropped Bytes:              {}", self.dropped_bytes)?;
        writeln!(f, "  Dropped Packets:            {}", self.dropped_packets)?;
        writeln!(
            f,
            "  Sent Batches:               {}",
            self.transport_sent_batches
        )?;
        writeln!(
            f,
            "  Sent Flows:                 {}",
            self.transport_sent_flows
        )?;
        write!(
            f,
            "  Sent Bytes:                 {}",
            self.transport_sent_bytes
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ConntrackBaseline {
    hits: u64,
    misses: u64,
    refreshes: u64,
    refresh_success: u64,
    refresh_failed: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_field_names)]
struct TransportBaseline {
    sent_batches: u64,
    sent_flows: u64,
    sent_bytes: u64,
    dropped_batches: u64,
    dropped_flows: u64,
    dropped_bytes: u64,
}

/// In-memory diagnostics store updated by the agent runtime and read by IPC.
pub struct DiagnosticsHub {
    enabled: AtomicBool,
    flow_map_entries: AtomicU64,
    flow_map_capacity: AtomicU64,
    poll_duration_us: AtomicU64,
    poll_max_duration_us: AtomicU64,
    poll_interval_ms: AtomicU64,
    keys_scanned: AtomicU64,
    flows_changed: AtomicU64,
    flows_idle: AtomicU64,
    flows_ended: AtomicU64,
    sample_budget_entries: AtomicU64,
    sample_budget_capacity: AtomicU64,
    sample_events: AtomicU64,
    sampled_flows: AtomicU64,
    sample_event_bytes: AtomicU64,
    sample_drops: AtomicU64,
    sample_queue_items: AtomicU64,
    sample_queue_bytes: AtomicU64,
    device_count: AtomicU64,
    discovery_dedup_entries: AtomicU64,
    http_user_agent_dedup_entries: AtomicU64,
    discovery_events: AtomicU64,
    discovery_parse_failed: AtomicU64,
    discovery_duplicates: AtomicU64,
    discovery_parse_rate_ppm: AtomicU64,
    discovery_duplicate_rate_ppm: AtomicU64,
    dns_drops: AtomicU64,
    neighbor_refresh_duration_us: AtomicU64,
    dhcp_lease_refresh_duration_us: AtomicU64,
    cumulative_deltas_emitted: AtomicU64,
    cumulative_bytes_emitted: AtomicU64,
    cumulative_packets_emitted: AtomicU64,
    router_local_filtered_flows: AtomicU64,
    router_local_filtered_bytes: AtomicU64,
    router_local_filtered_packets: AtomicU64,
    conntrack_stats: Arc<ConntrackStats>,
    transport_stats: Arc<TransportStats>,
    conntrack_baseline: Mutex<ConntrackBaseline>,
    transport_baseline: Mutex<TransportBaseline>,
}

impl DiagnosticsHub {
    #[must_use]
    pub fn new(
        enabled: bool,
        flow_map_capacity: u64,
        sample_budget_capacity: u64,
        poll_interval_ms: u64,
        conntrack_stats: Arc<ConntrackStats>,
        transport_stats: Arc<TransportStats>,
    ) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            flow_map_entries: AtomicU64::new(0),
            flow_map_capacity: AtomicU64::new(flow_map_capacity),
            poll_duration_us: AtomicU64::new(0),
            poll_max_duration_us: AtomicU64::new(0),
            poll_interval_ms: AtomicU64::new(poll_interval_ms),
            keys_scanned: AtomicU64::new(0),
            flows_changed: AtomicU64::new(0),
            flows_idle: AtomicU64::new(0),
            flows_ended: AtomicU64::new(0),
            sample_budget_entries: AtomicU64::new(0),
            sample_budget_capacity: AtomicU64::new(sample_budget_capacity),
            sample_events: AtomicU64::new(0),
            sampled_flows: AtomicU64::new(0),
            sample_event_bytes: AtomicU64::new(0),
            sample_drops: AtomicU64::new(0),
            sample_queue_items: AtomicU64::new(0),
            sample_queue_bytes: AtomicU64::new(0),
            device_count: AtomicU64::new(0),
            discovery_dedup_entries: AtomicU64::new(0),
            http_user_agent_dedup_entries: AtomicU64::new(0),
            discovery_events: AtomicU64::new(0),
            discovery_parse_failed: AtomicU64::new(0),
            discovery_duplicates: AtomicU64::new(0),
            discovery_parse_rate_ppm: AtomicU64::new(0),
            discovery_duplicate_rate_ppm: AtomicU64::new(0),
            dns_drops: AtomicU64::new(0),
            neighbor_refresh_duration_us: AtomicU64::new(0),
            dhcp_lease_refresh_duration_us: AtomicU64::new(0),
            cumulative_deltas_emitted: AtomicU64::new(0),
            cumulative_bytes_emitted: AtomicU64::new(0),
            cumulative_packets_emitted: AtomicU64::new(0),
            router_local_filtered_flows: AtomicU64::new(0),
            router_local_filtered_bytes: AtomicU64::new(0),
            router_local_filtered_packets: AtomicU64::new(0),
            conntrack_stats,
            transport_stats,
            conntrack_baseline: Mutex::new(ConntrackBaseline::default()),
            transport_baseline: Mutex::new(TransportBaseline::default()),
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn update_poll(
        &self,
        entries: u64,
        duration_us: u64,
        keys_scanned: u64,
        flows_changed: u64,
        flows_idle: u64,
        flows_ended: u64,
    ) {
        self.flow_map_entries.store(entries, Ordering::Relaxed);
        self.poll_duration_us.store(duration_us, Ordering::Relaxed);
        self.keys_scanned.store(keys_scanned, Ordering::Relaxed);
        self.flows_changed.store(flows_changed, Ordering::Relaxed);
        self.flows_idle.store(flows_idle, Ordering::Relaxed);
        self.flows_ended.store(flows_ended, Ordering::Relaxed);
        self.poll_max_duration_us
            .fetch_max(duration_us, Ordering::Relaxed);
    }

    pub fn update_sampling(
        &self,
        budgets: u64,
        events: u64,
        sampled_flows: u64,
        bytes: u64,
        drops: u64,
    ) {
        self.sample_budget_entries.store(budgets, Ordering::Relaxed);
        self.sample_events.store(events, Ordering::Relaxed);
        self.sampled_flows.store(sampled_flows, Ordering::Relaxed);
        self.sample_event_bytes.store(bytes, Ordering::Relaxed);
        self.sample_drops.store(drops, Ordering::Relaxed);
    }

    pub fn update_sample_queue(&self, items: u64, bytes: u64) {
        self.sample_queue_items.store(items, Ordering::Relaxed);
        self.sample_queue_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn update_device_discovery(&self, devices: u64, dedup: u64, http_dedup: u64) {
        self.device_count.store(devices, Ordering::Relaxed);
        self.discovery_dedup_entries.store(dedup, Ordering::Relaxed);
        self.http_user_agent_dedup_entries
            .store(http_dedup, Ordering::Relaxed);
    }

    pub fn update_discovery_metrics(&self, events: u64, parse_failed: u64, duplicates: u64) {
        self.discovery_events.store(events, Ordering::Relaxed);
        self.discovery_parse_failed
            .store(parse_failed, Ordering::Relaxed);
        self.discovery_duplicates
            .store(duplicates, Ordering::Relaxed);
        self.discovery_parse_rate_ppm
            .store(rate_ppm(parse_failed, events), Ordering::Relaxed);
        self.discovery_duplicate_rate_ppm
            .store(rate_ppm(duplicates, events), Ordering::Relaxed);
    }

    pub fn update_dns_drops(&self, drops: u64) {
        self.dns_drops.store(drops, Ordering::Relaxed);
    }

    pub fn update_refresh_durations(&self, neighbor_us: u64, dhcp_lease_us: u64) {
        self.neighbor_refresh_duration_us
            .store(neighbor_us, Ordering::Relaxed);
        self.dhcp_lease_refresh_duration_us
            .store(dhcp_lease_us, Ordering::Relaxed);
    }

    pub fn record_emitted(&self, deltas: u64, bytes: u64, packets: u64) {
        self.cumulative_deltas_emitted
            .fetch_add(deltas, Ordering::Relaxed);
        self.cumulative_bytes_emitted
            .fetch_add(bytes, Ordering::Relaxed);
        self.cumulative_packets_emitted
            .fetch_add(packets, Ordering::Relaxed);
    }

    pub fn record_router_local(&self, flows: u64, bytes: u64, packets: u64) {
        self.router_local_filtered_flows
            .fetch_add(flows, Ordering::Relaxed);
        self.router_local_filtered_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.router_local_filtered_packets
            .fetch_add(packets, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.cumulative_deltas_emitted.store(0, Ordering::Relaxed);
        self.cumulative_bytes_emitted.store(0, Ordering::Relaxed);
        self.cumulative_packets_emitted.store(0, Ordering::Relaxed);
        self.router_local_filtered_flows.store(0, Ordering::Relaxed);
        self.router_local_filtered_bytes.store(0, Ordering::Relaxed);
        self.router_local_filtered_packets
            .store(0, Ordering::Relaxed);

        let ct = self.conntrack_stats.snapshot();
        if let Ok(mut base) = self.conntrack_baseline.lock() {
            base.hits = ct.hits;
            base.misses = ct.misses;
            base.refreshes = ct.refreshes;
            base.refresh_success = ct.refresh_success;
            base.refresh_failed = ct.refresh_failed;
        }

        if let Ok(mut base) = self.transport_baseline.lock() {
            base.sent_batches = self.transport_stats.sent_batches.load(Ordering::Relaxed);
            base.sent_flows = self.transport_stats.sent_flows.load(Ordering::Relaxed);
            base.sent_bytes = self.transport_stats.sent_bytes.load(Ordering::Relaxed);
            base.dropped_batches = self.transport_stats.dropped_batches.load(Ordering::Relaxed);
            base.dropped_flows = self.transport_stats.dropped_flows.load(Ordering::Relaxed);
            base.dropped_bytes = self.transport_stats.dropped_bytes.load(Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> AgentDiagnostics {
        let ct = self.conntrack_stats.snapshot();
        let ct_base = self
            .conntrack_baseline
            .lock()
            .map_or(ConntrackBaseline::default(), |b| *b);
        let ts_base = self
            .transport_baseline
            .lock()
            .map_or(TransportBaseline::default(), |b| *b);

        AgentDiagnostics {
            enabled: self.enabled.load(Ordering::Relaxed),
            flow_map_entries: self.flow_map_entries.load(Ordering::Relaxed),
            flow_map_capacity: self.flow_map_capacity.load(Ordering::Relaxed),
            poll_duration_us: self.poll_duration_us.load(Ordering::Relaxed),
            poll_max_duration_us: self.poll_max_duration_us.load(Ordering::Relaxed),
            poll_interval_ms: self.poll_interval_ms.load(Ordering::Relaxed),
            keys_scanned: self.keys_scanned.load(Ordering::Relaxed),
            flows_changed: self.flows_changed.load(Ordering::Relaxed),
            flows_idle: self.flows_idle.load(Ordering::Relaxed),
            flows_ended: self.flows_ended.load(Ordering::Relaxed),
            sample_budget_entries: self.sample_budget_entries.load(Ordering::Relaxed),
            sample_budget_capacity: self.sample_budget_capacity.load(Ordering::Relaxed),
            sample_events: self.sample_events.load(Ordering::Relaxed),
            sampled_flows: self.sampled_flows.load(Ordering::Relaxed),
            sample_event_bytes: self.sample_event_bytes.load(Ordering::Relaxed),
            sample_drops: self.sample_drops.load(Ordering::Relaxed),
            sample_queue_items: self.sample_queue_items.load(Ordering::Relaxed),
            sample_queue_bytes: self.sample_queue_bytes.load(Ordering::Relaxed),
            device_count: self.device_count.load(Ordering::Relaxed),
            discovery_dedup_entries: self.discovery_dedup_entries.load(Ordering::Relaxed),
            http_user_agent_dedup_entries: self
                .http_user_agent_dedup_entries
                .load(Ordering::Relaxed),
            discovery_events: self.discovery_events.load(Ordering::Relaxed),
            discovery_parse_failed: self.discovery_parse_failed.load(Ordering::Relaxed),
            discovery_duplicates: self.discovery_duplicates.load(Ordering::Relaxed),
            discovery_parse_rate_ppm: self.discovery_parse_rate_ppm.load(Ordering::Relaxed),
            discovery_duplicate_rate_ppm: self.discovery_duplicate_rate_ppm.load(Ordering::Relaxed),
            dns_drops: self.dns_drops.load(Ordering::Relaxed),
            neighbor_refresh_duration_us: self.neighbor_refresh_duration_us.load(Ordering::Relaxed),
            dhcp_lease_refresh_duration_us: self
                .dhcp_lease_refresh_duration_us
                .load(Ordering::Relaxed),
            cumulative_deltas_emitted: self.cumulative_deltas_emitted.load(Ordering::Relaxed),
            cumulative_bytes_emitted: self.cumulative_bytes_emitted.load(Ordering::Relaxed),
            cumulative_packets_emitted: self.cumulative_packets_emitted.load(Ordering::Relaxed),
            conntrack_hits: ct.hits.saturating_sub(ct_base.hits),
            conntrack_misses: ct.misses.saturating_sub(ct_base.misses),
            conntrack_refreshes: ct.refreshes.saturating_sub(ct_base.refreshes),
            conntrack_refresh_success: ct.refresh_success.saturating_sub(ct_base.refresh_success),
            conntrack_refresh_failed: ct.refresh_failed.saturating_sub(ct_base.refresh_failed),
            conntrack_entries: ct.entries,
            conntrack_refresh_duration_us: ct.refresh_duration_us,
            router_local_filtered_flows: self.router_local_filtered_flows.load(Ordering::Relaxed),
            router_local_filtered_bytes: self.router_local_filtered_bytes.load(Ordering::Relaxed),
            router_local_filtered_packets: self
                .router_local_filtered_packets
                .load(Ordering::Relaxed),
            queue_depth: self.transport_stats.queue_depth.load(Ordering::Relaxed),
            queue_high_watermark: self
                .transport_stats
                .queue_high_watermark
                .load(Ordering::Relaxed),
            queue_bytes: self.transport_stats.queue_bytes.load(Ordering::Relaxed),
            queue_high_watermark_bytes: self
                .transport_stats
                .queue_high_watermark_bytes
                .load(Ordering::Relaxed),
            dropped_batches: self
                .transport_stats
                .dropped_batches
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.dropped_batches),
            dropped_flows: self
                .transport_stats
                .dropped_flows
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.dropped_flows),
            dropped_bytes: self
                .transport_stats
                .dropped_bytes
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.dropped_bytes),
            dropped_packets: 0,
            transport_sent_batches: self
                .transport_stats
                .sent_batches
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.sent_batches),
            transport_sent_flows: self
                .transport_stats
                .sent_flows
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.sent_flows),
            transport_sent_bytes: self
                .transport_stats
                .sent_bytes
                .load(Ordering::Relaxed)
                .saturating_sub(ts_base.sent_bytes),
        }
    }
}

#[cfg(unix)]
pub struct DiagnosticsServer {
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl DiagnosticsServer {
    /// Starts the Unix Domain Socket IPC server in a background thread.
    pub fn start(socket_path: PathBuf, hub: Arc<DiagnosticsHub>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(&socket_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::Builder::new()
            .name("netqmon-diag-ipc".into())
            .spawn(move || {
                while !shutdown_clone.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _addr)) => {
                            handle_ipc_connection(&mut stream, &hub);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })?;

        Ok(Self {
            socket_path,
            shutdown,
            handle: Some(handle),
        })
    }
}

#[cfg(unix)]
impl Drop for DiagnosticsServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn handle_ipc_connection(stream: &mut UnixStream, hub: &DiagnosticsHub) {
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_ok() {
        let command = line.trim();
        match command {
            "GET" => {
                let snap = hub.snapshot();
                if let Ok(json) = serde_json::to_string(&snap) {
                    let _ = writeln!(stream, "{json}");
                }
            }
            "RESET" => {
                hub.reset();
                let _ = writeln!(stream, "{{\"ok\":true,\"message\":\"diagnostics reset\"}}");
            }
            "ENABLE" => {
                hub.set_enabled(true);
                let _ = writeln!(
                    stream,
                    "{{\"ok\":true,\"message\":\"diagnostics enabled\"}}"
                );
            }
            "DISABLE" => {
                hub.set_enabled(false);
                let _ = writeln!(
                    stream,
                    "{{\"ok\":true,\"message\":\"diagnostics disabled\"}}"
                );
            }
            _ => {
                let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"unknown command\"}}");
            }
        }
    }
}

#[cfg(unix)]
fn send_ipc_command(socket_path: &Path, command: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!(
            "netqmon-agent is not running or socket {} is inaccessible: {e}",
            socket_path.display()
        )
    })?;

    writeln!(stream, "{command}").map_err(|e| format!("failed to send command: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read response: {e}"))?;

    Ok(response.trim().to_owned())
}

#[cfg(not(unix))]
fn send_ipc_command(_socket_path: &Path, _command: &str) -> Result<String, String> {
    Err("Unix domain sockets are not supported on this platform".to_owned())
}

/// Persists the `diagnostics_enabled` flag into `OpenWrt` UCI configuration if `uci` exists.
pub fn persist_uci(enabled: bool) -> Result<(), String> {
    let val = if enabled { "1" } else { "0" };

    // Try setting netqmon.main.diagnostics_enabled first
    let mut set_status = std::process::Command::new("uci")
        .args(["set", &format!("netqmon.main.diagnostics_enabled={val}")])
        .status();

    // If section 'main' is not found, fallback to '@agent[0]'
    if set_status.as_ref().is_ok_and(|s| !s.success()) {
        set_status = std::process::Command::new("uci")
            .args([
                "set",
                &format!("netqmon.@agent[0].diagnostics_enabled={val}"),
            ])
            .status();
    }

    match set_status {
        Ok(s) if s.success() => {
            let commit_status = std::process::Command::new("uci")
                .args(["commit", "netqmon"])
                .status();
            match commit_status {
                Ok(cs) if cs.success() => Ok(()),
                Ok(cs) => Err(format!("uci commit failed with exit code {:?}", cs.code())),
                Err(e) => Err(format!("failed to execute uci commit: {e}")),
            }
        }
        Ok(s) => Err(format!("uci set failed with exit code {:?}", s.code())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // UCI command is not present (e.g. standard Linux / dev host). Gracefully ignore.
            Ok(())
        }
        Err(e) => Err(format!("failed to execute uci: {e}")),
    }
}

/// Entrypoint for handling `netqmon-agent diagnostics ...` CLI invocations.
pub fn handle_command(args: DiagnosticsArgs) {
    let socket = default_socket_path();

    match args.action {
        Some(DiagnosticsAction::Enable) => {
            let ipc_result = send_ipc_command(&socket, "ENABLE");
            let uci_result = persist_uci(true);

            if args.json {
                let obj = serde_json::json!({
                    "action": "enable",
                    "runtime_updated": ipc_result.is_ok(),
                    "runtime_message": ipc_result.as_deref().unwrap_or("agent not running"),
                    "persisted": uci_result.is_ok(),
                    "persist_error": uci_result.err(),
                });
                println!("{obj}");
            } else {
                match ipc_result {
                    Ok(_) => println!("Diagnostics enabled (runtime updated)."),
                    Err(e) => println!("Note: {e}"),
                }
                if let Err(e) = uci_result {
                    eprintln!("Warning: failed to persist configuration via uci: {e}");
                } else {
                    println!("Diagnostics configuration committed.");
                }
            }
        }
        Some(DiagnosticsAction::Disable) => {
            let ipc_result = send_ipc_command(&socket, "DISABLE");
            let uci_result = persist_uci(false);

            if args.json {
                let obj = serde_json::json!({
                    "action": "disable",
                    "runtime_updated": ipc_result.is_ok(),
                    "runtime_message": ipc_result.as_deref().unwrap_or("agent not running"),
                    "persisted": uci_result.is_ok(),
                    "persist_error": uci_result.err(),
                });
                println!("{obj}");
            } else {
                match ipc_result {
                    Ok(_) => println!("Diagnostics disabled (runtime updated)."),
                    Err(e) => println!("Note: {e}"),
                }
                if let Err(e) = uci_result {
                    eprintln!("Warning: failed to persist configuration via uci: {e}");
                } else {
                    println!("Diagnostics configuration committed.");
                }
            }
        }
        Some(DiagnosticsAction::Reset) => match send_ipc_command(&socket, "RESET") {
            Ok(resp) => {
                if args.json {
                    println!("{resp}");
                } else {
                    println!("Diagnostics counters reset.");
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
        None => match send_ipc_command(&socket, "GET") {
            Ok(resp) => {
                if args.json {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Ok(pretty) = serde_json::to_string_pretty(&parsed) {
                            println!("{pretty}");
                            return;
                        }
                    }
                    println!("{resp}");
                } else {
                    match serde_json::from_str::<AgentDiagnostics>(&resp) {
                        Ok(diag) => print!("{diag}"),
                        Err(_) => println!("{resp}"),
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_snapshot_records_and_resets() {
        let ct_stats = Arc::new(ConntrackStats::default());
        let tp_stats = Arc::new(TransportStats::default());

        let hub = DiagnosticsHub::new(true, 65536, 65536, 1000, ct_stats.clone(), tp_stats.clone());

        hub.update_poll(10, 250, 10, 5, 1, 0);
        hub.record_emitted(5, 1000, 10);
        hub.record_router_local(2, 400, 4);

        ct_stats.record_hit();
        ct_stats.record_hit();
        ct_stats.record_miss();

        tp_stats.record_sent(5, 1000);

        let snap = hub.snapshot();
        assert!(snap.enabled);
        assert_eq!(snap.flow_map_entries, 10);
        assert_eq!(snap.flow_map_capacity, 65536);
        assert_eq!(snap.poll_duration_us, 250);
        assert_eq!(snap.poll_interval_ms, 1000);
        assert_eq!(snap.keys_scanned, 10);
        assert_eq!(snap.cumulative_deltas_emitted, 5);
        assert_eq!(snap.cumulative_bytes_emitted, 1000);
        assert_eq!(snap.cumulative_packets_emitted, 10);
        assert_eq!(snap.router_local_filtered_flows, 2);
        assert_eq!(snap.router_local_filtered_bytes, 400);
        assert_eq!(snap.router_local_filtered_packets, 4);
        assert_eq!(snap.conntrack_hits, 2);
        assert_eq!(snap.conntrack_misses, 1);
        assert_eq!(snap.transport_sent_batches, 1);
        assert_eq!(snap.transport_sent_flows, 5);
        assert_eq!(snap.transport_sent_bytes, 1000);

        // Reset
        hub.reset();
        let snap_after_reset = hub.snapshot();
        assert_eq!(snap_after_reset.cumulative_deltas_emitted, 0);
        assert_eq!(snap_after_reset.cumulative_bytes_emitted, 0);
        assert_eq!(snap_after_reset.cumulative_packets_emitted, 0);
        assert_eq!(snap_after_reset.router_local_filtered_flows, 0);
        assert_eq!(snap_after_reset.conntrack_hits, 0);
        assert_eq!(snap_after_reset.conntrack_misses, 0);
        assert_eq!(snap_after_reset.transport_sent_batches, 0);

        // Additional events after reset
        ct_stats.record_hit();
        hub.record_emitted(2, 200, 2);
        let snap_incremental = hub.snapshot();
        assert_eq!(snap_incremental.conntrack_hits, 1);
        assert_eq!(snap_incremental.cumulative_deltas_emitted, 2);
        assert_eq!(snap_incremental.cumulative_bytes_emitted, 200);
    }

    #[test]
    fn records_sampling_discovery_and_refresh_metrics() {
        let hub = DiagnosticsHub::new(
            true,
            64,
            64,
            1000,
            Arc::new(ConntrackStats::default()),
            Arc::new(TransportStats::default()),
        );
        hub.update_sampling(7, 11, 3, 4096, 2);
        hub.update_device_discovery(4, 5, 6);
        hub.update_discovery_metrics(100, 3, 7);
        hub.update_dns_drops(8);
        hub.update_refresh_durations(9, 10);

        let snapshot = hub.snapshot();
        assert_eq!(snapshot.sample_budget_entries, 7);
        assert_eq!(snapshot.sample_events, 11);
        assert_eq!(snapshot.sampled_flows, 3);
        assert_eq!(snapshot.sample_event_bytes, 4096);
        assert_eq!(snapshot.sample_drops, 2);
        assert_eq!(snapshot.discovery_events, 100);
        assert_eq!(snapshot.discovery_parse_failed, 3);
        assert_eq!(snapshot.discovery_duplicates, 7);
        assert_eq!(snapshot.discovery_parse_rate_ppm, 30_000);
        assert_eq!(snapshot.discovery_duplicate_rate_ppm, 70_000);
        assert_eq!(snapshot.dns_drops, 8);
        assert_eq!(snapshot.neighbor_refresh_duration_us, 9);
        assert_eq!(snapshot.dhcp_lease_refresh_duration_us, 10);
    }

    #[test]
    fn display_formatting() {
        let diag = AgentDiagnostics {
            enabled: true,
            flow_map_entries: 42,
            flow_map_capacity: 65536,
            poll_duration_us: 150,
            poll_interval_ms: 1000,
            keys_scanned: 42,
            cumulative_deltas_emitted: 100,
            cumulative_bytes_emitted: 50000,
            cumulative_packets_emitted: 300,
            conntrack_hits: 200,
            conntrack_misses: 5,
            conntrack_refreshes: 10,
            conntrack_refresh_success: 10,
            conntrack_refresh_failed: 0,
            router_local_filtered_flows: 15,
            router_local_filtered_bytes: 3000,
            router_local_filtered_packets: 30,
            queue_depth: 0,
            queue_high_watermark: 3,
            queue_bytes: 0,
            queue_high_watermark_bytes: 4096,
            dropped_batches: 0,
            dropped_flows: 0,
            dropped_bytes: 0,
            dropped_packets: 0,
            transport_sent_batches: 20,
            transport_sent_flows: 100,
            transport_sent_bytes: 52000,
            ..AgentDiagnostics::default()
        };

        let formatted = format!("{diag}");
        assert!(formatted.contains("Diagnostics Status: enabled"));
        assert!(formatted.contains("Entries:                    42"));
        assert!(formatted.contains("Hits:                       200"));
        assert!(formatted.contains("Sent Batches:               20"));
    }

    #[cfg(unix)]
    #[test]
    fn ipc_server_and_client_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("test-diag.sock");

        let ct_stats = Arc::new(ConntrackStats::default());
        let tp_stats = Arc::new(TransportStats::default());
        let hub = Arc::new(DiagnosticsHub::new(
            false,
            65536,
            65536,
            1000,
            ct_stats.clone(),
            tp_stats.clone(),
        ));

        let server =
            DiagnosticsServer::start(sock_path.clone(), hub.clone()).expect("server start");

        // GET when disabled
        let resp = send_ipc_command(&sock_path, "GET").expect("get");
        let diag: AgentDiagnostics = serde_json::from_str(&resp).expect("parse json");
        assert!(!diag.enabled);

        // ENABLE
        let resp = send_ipc_command(&sock_path, "ENABLE").expect("enable");
        assert!(resp.contains("\"ok\":true"));
        assert!(hub.is_enabled());

        // Snapshot now enabled
        let resp = send_ipc_command(&sock_path, "GET").expect("get");
        let diag: AgentDiagnostics = serde_json::from_str(&resp).expect("parse json");
        assert!(diag.enabled);

        // RESET
        hub.record_emitted(10, 1000, 10);
        let resp = send_ipc_command(&sock_path, "RESET").expect("reset");
        assert!(resp.contains("\"ok\":true"));
        let snap = hub.snapshot();
        assert_eq!(snap.cumulative_deltas_emitted, 0);

        // DISABLE
        let resp = send_ipc_command(&sock_path, "DISABLE").expect("disable");
        assert!(resp.contains("\"ok\":true"));
        assert!(!hub.is_enabled());

        drop(server);
    }

    #[test]
    fn test_cli_parsing() {
        use crate::config::{Cli, Command};
        use clap::Parser as _;

        // netqmon-agent diagnostics
        let cli = Cli::try_parse_from(["netqmon-agent", "diagnostics"]).expect("parse diagnostics");
        assert_eq!(
            cli.command,
            Some(Command::Diagnostics(DiagnosticsArgs {
                action: None,
                json: false,
            }))
        );

        // netqmon-agent diagnostics --json
        let cli =
            Cli::try_parse_from(["netqmon-agent", "diagnostics", "--json"]).expect("parse json");
        assert_eq!(
            cli.command,
            Some(Command::Diagnostics(DiagnosticsArgs {
                action: None,
                json: true,
            }))
        );

        // netqmon-agent diagnostics enable
        let cli =
            Cli::try_parse_from(["netqmon-agent", "diagnostics", "enable"]).expect("parse enable");
        assert_eq!(
            cli.command,
            Some(Command::Diagnostics(DiagnosticsArgs {
                action: Some(DiagnosticsAction::Enable),
                json: false,
            }))
        );

        // netqmon-agent diagnostics disable
        let cli = Cli::try_parse_from(["netqmon-agent", "diagnostics", "disable"])
            .expect("parse disable");
        assert_eq!(
            cli.command,
            Some(Command::Diagnostics(DiagnosticsArgs {
                action: Some(DiagnosticsAction::Disable),
                json: false,
            }))
        );

        // netqmon-agent diagnostics reset
        let cli =
            Cli::try_parse_from(["netqmon-agent", "diagnostics", "reset"]).expect("parse reset");
        assert_eq!(
            cli.command,
            Some(Command::Diagnostics(DiagnosticsArgs {
                action: Some(DiagnosticsAction::Reset),
                json: false,
            }))
        );
    }
}
