use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use portable_atomic::AtomicU64;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapHandle, MapType, RingBufferBuilder};
use netqmon_protocol::PROTOCOL_VERSION;
use netqmon_protocol::v1::{
    AgentHealth, CounterSanityStatus, FlowLifecycle as WireFlowLifecycle, OffloadStatus,
    TelemetryBatch, TopologySegment as WireTopologySegment, TopologySummary,
};
use nix::net::if_::if_nametoindex;
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::bpf::FlowSkelBuilder;
use crate::config::{AgentConfig, AttachOrder, LogLevel, TcxOrder};
use crate::conntrack::{ConntrackContext, ConntrackStats};
use crate::device::DeviceObservationCache;
use crate::dhcp::{DEFAULT_LEASE_PATH, parse_packet, read_leases};
use crate::dhcp_event::DhcpEvent;
use crate::discovery;
use crate::dns_event::{DNS_MAX_PAYLOAD_LENGTH, DnsEvent};
use crate::dns_observation::observations;
use crate::dns_parser::parse_response;
use crate::flow::{FlowCounters, FlowKey, FlowRuntime};
use crate::lifecycle::{FlowLifecycleEvent, FlowState};
use crate::normalization::{NormalizedFlow, normalize_with_resolution};
use crate::sample;
use crate::telemetry;
use crate::topology::{TopologyContext, TopologyMode};
use crate::transport::{self, SampleQueue, TelemetryQueue};

mod capabilities;
mod neighbor;
mod network;
mod tc;

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NEIGHBOR_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const DHCP_LEASE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const SAMPLE_CONNTRACK_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const SAMPLE_BUDGET_GC_INTERVAL: Duration = Duration::from_secs(30);
const SAMPLE_BUDGET_GC_MAX_ENTRIES: usize = 2048;
const PENDING_SAMPLE_EVENT_CAPACITY: usize = 512;
const SAMPLE_EVENT_HEADER_SIZE: usize = 72;
const SAMPLE_EVENT_MAX_PAYLOAD_SIZE: usize = 4096;
const FIREWALL_CONFIG_PATH: &str = "/etc/config/firewall";

type SharedConntrack = Arc<RwLock<Arc<ConntrackContext>>>;

struct PendingSampleEvents {
    events: Mutex<VecDeque<Vec<u8>>>,
    dropped: AtomicU64,
    dropped_bytes: AtomicU64,
    capacity: usize,
}

impl PendingSampleEvents {
    fn new(capacity: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(capacity)),
            dropped: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            capacity,
        }
    }

    fn push(&self, bytes: &[u8]) {
        let Ok(mut events) = self.events.lock() else {
            self.record_drop(bytes);
            return;
        };
        if events.len() >= self.capacity {
            self.record_drop(bytes);
            return;
        }
        let captured_length = usize::try_from(sample_event_captured_length(bytes))
            .unwrap_or(SAMPLE_EVENT_MAX_PAYLOAD_SIZE)
            .min(SAMPLE_EVENT_MAX_PAYLOAD_SIZE);
        let owned_length = SAMPLE_EVENT_HEADER_SIZE
            .saturating_add(captured_length)
            .min(bytes.len());
        events.push_back(bytes[..owned_length].to_vec());
    }

    fn drain(&self) -> VecDeque<Vec<u8>> {
        self.events
            .lock()
            .map(|mut events| std::mem::take(&mut *events))
            .unwrap_or_default()
    }

    fn defer(&self, deferred: &mut VecDeque<Vec<u8>>, bytes: Vec<u8>) {
        if deferred.len() >= self.capacity {
            self.record_drop(&bytes);
        } else {
            deferred.push_back(bytes);
        }
    }

    fn record_drop(&self, bytes: &[u8]) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes
            .fetch_add(sample_event_captured_length(bytes), Ordering::Relaxed);
    }

    fn drops(&self) -> (u64, u64) {
        (
            self.dropped.load(Ordering::Relaxed),
            self.dropped_bytes.load(Ordering::Relaxed),
        )
    }
}

pub(super) fn doctor(config: &AgentConfig) -> bool {
    let report = capabilities::probe(config);
    print!("{report}");
    report.is_healthy()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AgentError {
    MissingInterface(String),
    PermissionDenied(String),
    BpfUnavailable(String),
    TcUnavailable(String),
    MapCreationFailed(String),
    Runtime(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (category, detail) = match self {
            Self::MissingInterface(detail) => ("missing interface", detail),
            Self::PermissionDenied(detail) => ("permission denied", detail),
            Self::BpfUnavailable(detail) => ("BPF unavailable", detail),
            Self::TcUnavailable(detail) => ("TC unavailable", detail),
            Self::MapCreationFailed(detail) => ("map creation failed", detail),
            Self::Runtime(detail) => ("runtime error", detail),
        };
        write!(formatter, "{category}: {detail}")
    }
}

impl Error for AgentError {}

pub(super) fn run(config: AgentConfig) -> Result<(), AgentError> {
    let interface = config.interface.clone();
    let log_level = config.log_level;
    let configured_interfaces = config
        .interfaces
        .iter()
        .map(|name| resolve_interface(name).map(|ifindex| (name.clone(), ifindex)))
        .collect::<Result<Vec<_>, _>>()?;
    let network = network::discover(&config).map_err(AgentError::Runtime)?;
    probe_map_creation()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown))
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown))
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    let session_boot_id = session_boot_id();
    let controller_endpoints = transport::controller_endpoints(&config.controller_url);
    let telemetry_queue =
        TelemetryQueue::spawn(&config, Arc::clone(&shutdown), session_boot_id.clone());
    let sample_queue = Arc::new(SampleQueue::spawn(
        &config,
        Arc::clone(&shutdown),
        session_boot_id,
    ));
    let sample_boot_epoch = boot_epoch_ms();
    let dns_observations = Arc::new(Mutex::new(Vec::new()));
    let discovery_observations = Arc::new(Mutex::new(Vec::new()));
    let devices = Arc::new(Mutex::new(DeviceObservationCache::default()));
    let conntrack = Arc::new(RwLock::new(Arc::new(ConntrackContext::discover())));
    let conntrack_stats = Arc::new(ConntrackStats::default());
    let tcx_supported = if config.attach_backend == crate::config::AttachBackend::Netlink {
        false
    } else {
        capabilities::probe_tcx_backend(&config).is_ok()
    };
    let selected_backend = tc::requested_backend(config.attach_backend, tcx_supported);
    let capture_is_bridge = network
        .snapshot
        .interfaces
        .iter()
        .any(|candidate| candidate.name == interface && candidate.is_bridge);
    let (attach_ingress, attach_egress) = observation_hooks();
    let observation_interfaces = observation_interfaces(
        &configured_interfaces,
        network.snapshot.mode,
        capture_is_bridge,
    )?;
    let observed_ingress_ifindices =
        observed_ingress_ifindices(&config.interfaces, &observation_interfaces);
    let builder = FlowSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skeleton = builder
        .open(&mut open_object)
        .map_err(|error| classify_bpf_error(BpfStage::Open, error))?;
    open_skeleton
        .maps
        .flow_map
        .set_max_entries(config.max_flows)
        .map_err(|err| classify_map_error("flow_map", err))?;
    open_skeleton
        .maps
        .sample_budgets
        .set_max_entries(if config.sample_enabled {
            config.max_flows
        } else {
            1
        })
        .map_err(|err| classify_map_error("sample_budgets", err))?;
    open_skeleton.progs.netqmon_attach_probe.set_autoload(false);
    if let Some(rodata) = open_skeleton.maps.rodata_data.as_deref_mut() {
        rodata.sample_enabled = u8::from(config.sample_enabled);
        rodata.sample_max_packets_per_direction =
            u32::from(config.sample_max_packets_per_direction);
        rodata.sample_max_bytes_per_packet =
            u32::try_from(config.sample_max_bytes_per_packet).unwrap_or(1024);
        rodata.sample_max_bytes_per_flow =
            u32::try_from(config.sample_max_bytes_per_flow).unwrap_or(4096);
    }
    let skeleton = open_skeleton
        .load()
        .map_err(|error| classify_bpf_error(BpfStage::Load, error))?;
    for target_ifindex in &observed_ingress_ifindices {
        let key = u32::try_from(*target_ifindex)
            .map_err(|_| AgentError::Runtime("interface index overflow".to_owned()))?
            .to_ne_bytes();
        skeleton
            .maps
            .observed_ifindexes
            .update(&key, &[1], MapFlags::ANY)
            .map_err(|error| AgentError::Runtime(error.to_string()))?;
    }
    let attach_tcx = || {
        observation_interfaces
            .iter()
            .map(|(_, target_ifindex)| {
                tc::TcxLinks::attach(
                    *target_ifindex,
                    &skeleton.progs.netqmon_ingress,
                    &skeleton.progs.netqmon_egress,
                    config.attach_order,
                    attach_ingress,
                    attach_egress,
                )
                .map(tc::AttachLinks::Tcx)
            })
            .collect::<libbpf_rs::Result<Vec<_>>>()
    };
    let attach_netlink = || {
        observation_interfaces
            .iter()
            .map(|(_, target_ifindex)| {
                tc::NetlinkHooks::attach(
                    *target_ifindex,
                    skeleton.progs.netqmon_ingress.as_fd(),
                    skeleton.progs.netqmon_egress.as_fd(),
                    config.attach_order,
                    attach_ingress,
                    attach_egress,
                )
                .map(tc::AttachLinks::Netlink)
            })
            .collect::<libbpf_rs::Result<Vec<_>>>()
    };
    let mut hooks = match selected_backend {
        tc::ActiveBackend::Tcx => match attach_tcx() {
            Ok(links) => links,
            Err(error) if config.attach_backend == crate::config::AttachBackend::Auto => {
                log_warn(
                    log_level,
                    format_args!("TCX attach failed ({error}); falling back to netlink TC"),
                );
                attach_netlink().map_err(|error| classify_tc_error(&interface, error))?
            }
            Err(error) => return Err(classify_tc_error(&interface, error)),
        },
        tc::ActiveBackend::Netlink => {
            attach_netlink().map_err(|error| classify_tc_error(&interface, error))?
        }
    };
    let active_backend = hooks
        .first()
        .map(tc::AttachLinks::backend)
        .expect("at least one observation interface");
    let observation_names = observation_interfaces
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut ring_buffer_builder = RingBufferBuilder::new();
    let captured_dns_observations = Arc::clone(&dns_observations);
    let dns_log_level = log_level;
    ring_buffer_builder
        .add(&skeleton.maps.dns_events, move |bytes| {
            match DnsEvent::try_from(bytes) {
                Ok(event) => {
                    log_debug(
                        dns_log_level,
                        format_args!(
                            "dns event ip={} client={} packet_length={} payload_length={} truncated={}",
                            if event.client_address.is_ipv4() { 4 } else { 6 },
                            event.client_address,
                            event.packet_length,
                            event.payload.len(),
                            event.truncated
                        ),
                    );
                    let is_truncated = event.truncated
                        || (event.payload.len() >= DNS_MAX_PAYLOAD_LENGTH
                            && event.packet_length > DNS_MAX_PAYLOAD_LENGTH as u32);
                    let observed_at = std::time::SystemTime::now();
                    let parsed = parse_response(&event.payload);
                    drop(event.payload);
                    match parsed {
                        Ok(response) => {
                            log_debug(
                                dns_log_level,
                                format_args!(
                                    "dns response client={} qname={} rcode={} answers={:?}",
                                    event.client_address,
                                    response.qname,
                                    response.rcode,
                                    response.answers
                                ),
                            );
                            for observation in observations(event.client_address, response, observed_at) {
                                let observed_at_ms = observation
                                    .observed_at
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |duration| duration.as_millis());
                                log_debug(
                                    dns_log_level,
                                    format_args!(
                                        "dns observation client_addr={} domain={} answer_ip={} record_type={} ttl={} observed_at={}",
                                        observation.client_addr,
                                        observation.domain,
                                        observation.answer_ip,
                                        observation.record_type,
                                        observation.ttl,
                                        observed_at_ms
                                    ),
                                );
                                if let Ok(mut pending) = captured_dns_observations.lock() {
                                    pending.push(telemetry::dns(observation));
                                }
                            }
                        }
                        Err(error) => {
                            if is_truncated {
                                log_debug(
                                    dns_log_level,
                                    format_args!(
                                        "truncated DNS response parse failed: {error} (client={} packet_length={})",
                                        event.client_address, event.packet_length
                                    ),
                                );
                            } else {
                                log_warn(
                                    dns_log_level,
                                    format_args!("DNS response parse failed: {error}"),
                                );
                            }
                        }
                    }
                }
                Err(error) => log_warn(
                    dns_log_level,
                    format_args!("DNS ring buffer event decode failed: {error}"),
                ),
            }
            0
        })
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    let pending_sample_events = Arc::new(PendingSampleEvents::new(PENDING_SAMPLE_EVENT_CAPACITY));
    if config.sample_enabled {
        let captured_sample_events = Arc::clone(&pending_sample_events);
        ring_buffer_builder
            .add(&skeleton.maps.sample_events, move |bytes| {
                captured_sample_events.push(bytes);
                0
            })
            .map_err(|error| AgentError::Runtime(error.to_string()))?;
    }
    let captured_devices = Arc::clone(&devices);
    let dhcp_log_level = log_level;
    ring_buffer_builder
        .add(&skeleton.maps.dhcp_events, move |bytes| {
            match DhcpEvent::try_from(bytes) {
                Ok(event) => match parse_packet(&event.payload) {
                    Ok(observation) => {
                        log_debug(
                            dhcp_log_level,
                            format_args!(
                                "dhcp observation mac={} ip={} hostname={} prl_len={} vendor_class={} client_id_len={}",
                                observation.mac,
                                observation
                                    .ip
                                    .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                                observation.hostname.as_deref().unwrap_or("-"),
                                observation.metadata.parameter_request_list.len(),
                                observation.metadata.vendor_class.as_deref().unwrap_or("-"),
                                observation.metadata.client_identifier.len()
                            ),
                        );
                        if let Ok(mut devices) = captured_devices.lock() {
                            devices.observe_dhcp(observation, SystemTime::now());
                        }
                    }
                    Err(error) => log_warn(
                        dhcp_log_level,
                        format_args!("DHCP packet parse failed: {error}"),
                    ),
                },
                Err(error) => log_warn(
                    dhcp_log_level,
                    format_args!("DHCP ring buffer event decode failed: {error}"),
                ),
            }
            0
        })
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    let captured_discovery = Arc::clone(&discovery_observations);
    let discovery_log_level = log_level;
    let discovery_processor = Arc::new(Mutex::new(discovery::DiscoveryProcessor::default()));
    let captured_processor = Arc::clone(&discovery_processor);
    ring_buffer_builder
        .add(&skeleton.maps.discovery_events, move |bytes| {
            if let Ok(mut processor) = captured_processor.lock() {
                let observed_at = telemetry::unix_ms(SystemTime::now());
                match processor.process(bytes, observed_at, Instant::now()) {
                    Ok(observations) => {
                        if let Ok(mut pending) = captured_discovery.lock() {
                            let available = 10_000_usize.saturating_sub(pending.len());
                            pending.extend(observations.into_iter().take(available));
                        }
                    }
                    Err(error) => log_debug(
                        discovery_log_level,
                        format_args!("device discovery parse/decode failed: {error}"),
                    ),
                }
            }
            0
        })
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    let ring_buffer = ring_buffer_builder
        .build()
        .map_err(|error| AgentError::Runtime(error.to_string()))?;
    let mut flow_runtime = FlowRuntime::new(
        Duration::from_secs(config.tcp_idle_timeout_seconds),
        Duration::from_secs(config.udp_idle_timeout_seconds),
    );
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let batch_interval = Duration::from_millis(config.batch_interval_ms);
    let started = Instant::now();
    let boot_epoch_ms = boot_epoch_ms();
    let mut next_poll = Instant::now() + poll_interval;
    let mut next_batch = Instant::now() + batch_interval;
    let mut next_neighbor_refresh = Instant::now();
    let mut next_dhcp_lease_refresh = Instant::now();
    let mut next_discovery_report = Instant::now() + Duration::from_secs(30);
    let mut next_conntrack_refresh = Instant::now();
    let mut next_sample_conntrack_refresh = Instant::now();
    let mut next_sample_budget_gc = Instant::now() + SAMPLE_BUDGET_GC_INTERVAL;
    let mut sample_budget_gc = SampleBudgetGc::default();
    let mut deferred_sample_events = VecDeque::new();
    let mut pending_flows = Vec::new();
    let mut asymmetry = AsymmetryDetector::default();
    let mut topology_warnings = network.snapshot.warnings.clone();
    let diagnostics_hub = Arc::new(crate::diagnostics::DiagnosticsHub::new(
        config.diagnostics_enabled,
        u64::from(config.max_flows),
        u64::from(if config.sample_enabled {
            config.max_flows
        } else {
            1
        }),
        config.poll_interval_ms,
        conntrack_stats.clone(),
        telemetry_queue.transport_stats().clone(),
    ));
    let socket_path = crate::diagnostics::default_socket_path();
    let _diagnostics_server = match crate::diagnostics::DiagnosticsServer::start(
        socket_path.clone(),
        diagnostics_hub.clone(),
    ) {
        Ok(server) => Some(server),
        Err(err) => {
            log_warn(
                log_level,
                format_args!(
                    "failed to start diagnostics IPC server at {}: {err}",
                    socket_path.display()
                ),
            );
            None
        }
    };
    let mut last_poll_duration_us: u64;
    let mut last_keys_scanned: u64;
    let mut last_sample_budget_entries: u64 = 0;
    let mut last_neighbor_refresh_duration_us = 0_u64;
    let mut last_dhcp_lease_refresh_duration_us = 0_u64;
    let kernel_version = read_trimmed("/proc/sys/kernel/osrelease");
    let openwrt_version = openwrt_version();
    let offload_status = hardware_flow_offload_status();
    let mut interface_counter = InterfaceCounterSanity::new(
        &interface,
        config.interface_counter_sanity_enabled,
        config.interface_counter_min_bytes,
        config.interface_counter_max_unaccounted_ratio,
    );

    log_info(
        log_level,
        format_args!(
            "attached {active_backend} {} to {observation_names} (configured {interface})",
            hook_description(attach_ingress, attach_egress, hooks.len())
        ),
    );
    while !shutdown.load(Ordering::Relaxed) {
        if let Err(error) = ring_buffer.consume() {
            log_warn(
                log_level,
                format_args!("DNS ring buffer consume failed: {error}"),
            );
        }
        let now = Instant::now();
        let mut conntrack_refreshed_this_iteration = false;
        if now >= next_conntrack_refresh {
            let refresh_started = Instant::now();
            let refreshed = Arc::new(ConntrackContext::discover());
            conntrack_stats.record_refresh(
                true,
                refreshed.len(),
                refresh_started.elapsed().as_micros() as u64,
            );
            if let Ok(mut current) = conntrack.write() {
                *current = refreshed;
                conntrack_refreshed_this_iteration = true;
            }
            next_conntrack_refresh = now + Duration::from_secs(5);
            next_sample_conntrack_refresh = now + SAMPLE_CONNTRACK_REFRESH_INTERVAL;
        }
        if config.sample_enabled {
            process_pending_sample_events(
                pending_sample_events.drain(),
                &mut deferred_sample_events,
                &pending_sample_events,
                &sample_queue,
                &network,
                &conntrack,
                &conntrack_stats,
                &controller_endpoints,
                sample_boot_epoch,
                now,
                &mut next_sample_conntrack_refresh,
                &mut conntrack_refreshed_this_iteration,
            );
        }
        if now >= next_discovery_report {
            if let Ok(mut processor) = discovery_processor.lock() {
                let (dedup_entries, http_dedup_entries) = processor.dedup_entries();
                let device_count = devices
                    .lock()
                    .map(|devices| devices.snapshot().len() as u64)
                    .unwrap_or(0);
                diagnostics_hub.update_device_discovery(
                    device_count,
                    dedup_entries as u64,
                    http_dedup_entries as u64,
                );
                let parse_failed = processor
                    .counters
                    .discovery_parse_failed
                    .saturating_add(processor.counters.discovery_decode_failed);
                diagnostics_hub.update_discovery_metrics(
                    processor.counters.discovery_packets,
                    parse_failed,
                    processor.counters.discovery_duplicate,
                );
                log_debug(
                    log_level,
                    format_args!("discovery counters: {:?}", processor.counters),
                );
                let failures = std::mem::take(&mut processor.failures_since_report);
                if failures != 0 {
                    log_debug(
                        log_level,
                        format_args!(
                            "device discovery parse/decode failures in last 30s: {failures}; totals: {:?}",
                            processor.counters
                        ),
                    );
                }
            }
            next_discovery_report = now + Duration::from_secs(30);
        }
        if now >= next_neighbor_refresh {
            let refresh_started = Instant::now();
            if let Ok(mut devices) = devices.lock() {
                for (_, target_ifindex) in &observation_interfaces {
                    refresh_neighbors(
                        &mut devices,
                        u32::try_from(*target_ifindex).unwrap_or_default(),
                        log_level,
                    );
                }
                log_device_snapshot(&devices, log_level);
            }
            last_neighbor_refresh_duration_us = refresh_started.elapsed().as_micros() as u64;
            diagnostics_hub.update_refresh_durations(
                last_neighbor_refresh_duration_us,
                last_dhcp_lease_refresh_duration_us,
            );
            next_neighbor_refresh = now + NEIGHBOR_REFRESH_INTERVAL;
        }
        if now >= next_dhcp_lease_refresh {
            let refresh_started = Instant::now();
            if let Ok(mut devices) = devices.lock() {
                refresh_dhcp_leases(&mut devices, log_level);
            }
            last_dhcp_lease_refresh_duration_us = refresh_started.elapsed().as_micros() as u64;
            diagnostics_hub.update_refresh_durations(
                last_neighbor_refresh_duration_us,
                last_dhcp_lease_refresh_duration_us,
            );
            next_dhcp_lease_refresh = now + DHCP_LEASE_REFRESH_INTERVAL;
        }
        if now >= next_poll {
            let poll_start = Instant::now();
            let monotonic_ns = monotonic_ns();
            if config.sample_enabled && now >= next_sample_budget_gc {
                last_sample_budget_entries = sample_budget_gc.run(
                    &skeleton.maps.sample_budgets,
                    monotonic_ns,
                    config.tcp_idle_timeout_seconds,
                    config.udp_idle_timeout_seconds,
                );
                next_sample_budget_gc = now + SAMPLE_BUDGET_GC_INTERVAL;
            }
            match read_flow_map(
                &skeleton.maps.flow_map,
                monotonic_ns,
                config.tcp_idle_timeout_seconds,
                config.udp_idle_timeout_seconds,
            ) {
                Ok(snapshot) => {
                    last_keys_scanned = snapshot.keys_scanned;
                    let retained_entries = snapshot.retained_entries;
                    let mut conntrack_refresh_budget = ConntrackRefreshBudget {
                        attempted: conntrack_refreshed_this_iteration,
                    };
                    let mut conntrack_snapshot = current_conntrack_snapshot(&conntrack);
                    let device_snapshot = devices
                        .lock()
                        .map(|devices| devices.resolver_snapshot())
                        .unwrap_or_default();
                    let lifecycle_now = started.elapsed();
                    let runtime_update = flow_runtime.update(snapshot.flows, lifecycle_now);
                    let flows_changed = runtime_update.deltas.len() as u64;
                    let flows_idle = runtime_update
                        .lifecycle_events
                        .iter()
                        .filter(|event| event.state == FlowState::Idle)
                        .count() as u64;
                    let flows_ended = runtime_update
                        .lifecycle_events
                        .iter()
                        .filter(|event| event.state == FlowState::End)
                        .count() as u64;
                    for delta in runtime_update.deltas {
                        if let Some(flow) = normalize_with_current_conntrack(
                            &delta.key,
                            &network,
                            &mut conntrack_snapshot,
                            &conntrack,
                            &conntrack_stats,
                            &mut conntrack_refresh_budget,
                        ) {
                            if flow.scope == crate::normalization::FlowScope::RouterLocal {
                                diagnostics_hub.record_router_local(1, delta.bytes, delta.packets);
                                continue;
                            }
                            diagnostics_hub.record_emitted(1, delta.bytes, delta.packets);
                            asymmetry.observe(flow.direction, delta.packets);
                            let resolved_mac = device_snapshot.get(&flow.client_addr).copied();
                            let client_mac = resolved_mac
                                .map_or_else(|| "unknown".to_owned(), |mac| mac.to_string());
                            log_debug(
                                log_level,
                                format_args!(
                                    "flow delta ip={} protocol={} client={}:{} remote={}:{} direction={} packets={} bytes={} client_mac={}",
                                    delta.key.ip_version,
                                    delta.key.protocol,
                                    flow.client_addr,
                                    flow.client_port,
                                    flow.remote_addr,
                                    flow.remote_port,
                                    flow.direction,
                                    delta.packets,
                                    delta.bytes,
                                    client_mac
                                ),
                            );
                            if !is_controller_transport(&flow, &controller_endpoints) {
                                pending_flows.push(telemetry::flow_delta(
                                    &delta,
                                    &flow,
                                    resolved_mac,
                                    boot_epoch_ms,
                                ));
                            }
                        }
                    }
                    for event in runtime_update.lifecycle_events {
                        print_lifecycle_event(
                            &event,
                            &network,
                            &mut conntrack_snapshot,
                            &conntrack,
                            &conntrack_stats,
                            &mut conntrack_refresh_budget,
                            log_level,
                        );
                        if event.state != FlowState::Active
                            && let Some(flow) = normalize_with_current_conntrack(
                                &event.key,
                                &network,
                                &mut conntrack_snapshot,
                                &conntrack,
                                &conntrack_stats,
                                &mut conntrack_refresh_budget,
                            )
                        {
                            if flow.scope == crate::normalization::FlowScope::RouterLocal {
                                continue;
                            }
                            if !is_controller_transport(&flow, &controller_endpoints) {
                                pending_flows.push(telemetry::lifecycle_delta(
                                    &flow,
                                    device_snapshot.get(&flow.client_addr).copied(),
                                    event.key.protocol,
                                    match event.state {
                                        FlowState::Active => WireFlowLifecycle::Active,
                                        FlowState::Idle => WireFlowLifecycle::Idle,
                                        FlowState::End => WireFlowLifecycle::Ended,
                                    },
                                    telemetry::unix_ms(SystemTime::now()),
                                ));
                            }
                        }
                    }
                    last_poll_duration_us = poll_start.elapsed().as_micros() as u64;
                    diagnostics_hub.update_poll(
                        retained_entries,
                        last_poll_duration_us,
                        last_keys_scanned,
                        flows_changed,
                        flows_idle,
                        flows_ended,
                    );
                }
                Err(error) => log_warn(log_level, format_args!("flow map poll failed: {error}")),
            }
            next_poll = now + poll_interval;
        }
        if now >= next_batch {
            if asymmetry.take_warning() {
                const WARNING: &str =
                    "Asymmetric routing suspected: reply packet coverage is below 5%.";
                log_warn(log_level, format_args!("{WARNING}"));
                if !topology_warnings.iter().any(|value| value == WARNING) {
                    topology_warnings.push(WARNING.to_owned());
                }
            }
            let sent_at = telemetry::unix_ms(SystemTime::now());
            let sample_events = read_indexed_counter(&skeleton.maps.sample_counters, 4);
            let sampled_flows = read_indexed_counter(&skeleton.maps.sample_counters, 0);
            let sampled_bytes = read_indexed_counter(&skeleton.maps.sample_counters, 1);
            let sample_drops = read_indexed_counter(&skeleton.maps.sample_counters, 2)
                + sample_queue.drops().0
                + pending_sample_events.drops().0;
            diagnostics_hub.update_sampling(
                last_sample_budget_entries,
                sample_events,
                sampled_flows,
                sampled_bytes,
                sample_drops,
            );
            let dns_drops = read_indexed_counter(&skeleton.maps.dns_drop_count, 0);
            diagnostics_hub.update_dns_drops(dns_drops);
            let (sample_queue_items, sample_queue_bytes) = sample_queue.queue_stats();
            diagnostics_hub.update_sample_queue(sample_queue_items, sample_queue_bytes);
            let flow_delta_bytes = pending_flows.iter().fold(0_u64, |total, flow| {
                total
                    .saturating_add(flow.upload_bytes)
                    .saturating_add(flow.download_bytes)
            });
            let flow_delta_packets = pending_flows
                .iter()
                .fold(0_u64, |total, flow| total.saturating_add(flow.packets));
            let interface_health = interface_counter.observe(flow_delta_bytes, flow_delta_packets);
            let dns = dns_observations
                .lock()
                .map(|mut pending| std::mem::take(&mut *pending))
                .unwrap_or_default();
            let discovery = discovery_observations
                .lock()
                .map(|mut pending| std::mem::take(&mut *pending))
                .unwrap_or_default();
            let batch = TelemetryBatch {
                sent_at,
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
                flows: std::mem::take(&mut pending_flows),
                dns_observations: dns,
                device_discovery_observations: discovery,
                device_observations: devices
                    .lock()
                    .map(|devices| {
                        devices
                            .take_telemetry_snapshot()
                            .into_iter()
                            .map(telemetry::device)
                            .collect()
                    })
                    .unwrap_or_default(),
                health: Some(AgentHealth {
                    observed_at_unix_ms: sent_at,
                    uptime_seconds: started.elapsed().as_secs(),
                    dropped_batches: telemetry_queue.dropped_batches(),
                    dns_dropped_events: dns_drops,
                    tracked_flows: u64::try_from(flow_runtime.len()).unwrap_or(u64::MAX),
                    kernel_version: kernel_version.clone(),
                    openwrt_version: openwrt_version.clone(),
                    hardware_flow_offload: offload_status as i32,
                    protocol_probe_dropped_events: 0,
                    sampled_flows,
                    sampled_bytes,
                    dropped_samples: sample_drops,
                    dropped_sample_bytes: read_indexed_counter(&skeleton.maps.sample_counters, 3)
                        + sample_queue.drops().1
                        + pending_sample_events.drops().1,
                    sample_config: Some(netqmon_protocol::v1::SampleConfig {
                        enabled: config.sample_enabled,
                        max_bytes_per_flow: u32::try_from(config.sample_max_bytes_per_flow)
                            .unwrap_or(4096),
                        max_packets_per_direction: u32::from(
                            config.sample_max_packets_per_direction,
                        ),
                        max_bytes_per_packet: u32::try_from(config.sample_max_bytes_per_packet)
                            .unwrap_or(1024),
                    }),
                    capture_interface: interface.clone(),
                    capture_interfaces: config.interfaces.clone(),
                    interface_rx_bytes: interface_health
                        .snapshot
                        .as_ref()
                        .map_or(0, |snapshot| snapshot.rx_bytes),
                    interface_tx_bytes: interface_health
                        .snapshot
                        .as_ref()
                        .map_or(0, |snapshot| snapshot.tx_bytes),
                    interface_rx_packets: interface_health
                        .snapshot
                        .as_ref()
                        .map_or(0, |snapshot| snapshot.rx_packets),
                    interface_tx_packets: interface_health
                        .snapshot
                        .as_ref()
                        .map_or(0, |snapshot| snapshot.tx_packets),
                    interface_delta_bytes: interface_health.delta_bytes,
                    interface_delta_packets: interface_health.delta_packets,
                    flow_delta_bytes,
                    flow_delta_packets,
                    interface_counter_sanity: interface_health.status as i32,
                    topology: Some(topology_summary(
                        &network,
                        active_backend,
                        config.attach_order,
                        &topology_warnings,
                    )),
                }),
                ..TelemetryBatch::default()
            };
            telemetry_queue.submit(batch);
            next_batch = now + batch_interval;
        }
        let next_wakeup = next_poll.min(next_batch);
        thread::sleep(SHUTDOWN_POLL_INTERVAL.min(next_wakeup.saturating_duration_since(now)));
    }

    for hook in &mut hooks {
        hook.detach()
            .map_err(|error| AgentError::Runtime(error.to_string()))?;
    }
    log_info(
        log_level,
        format_args!(
            "detached {active_backend} {} from {observation_names} (configured {interface})",
            hook_description(attach_ingress, attach_egress, hooks.len())
        ),
    );
    drop(ring_buffer);
    if let Ok(queue) = Arc::try_unwrap(sample_queue) {
        queue.stop();
    }
    telemetry_queue.stop();
    Ok(())
}

fn observation_hooks() -> (bool, bool) {
    // The dedicated egress program suppresses packets whose ingress interface
    // is already observed while retaining host-originated proxy replies.
    (true, true)
}

fn observation_interfaces(
    configured: &[(String, i32)],
    mode: TopologyMode,
    capture_is_bridge: bool,
) -> Result<Vec<(String, i32)>, AgentError> {
    if mode != TopologyMode::OneArmRouter || !capture_is_bridge {
        return Ok(configured.to_vec());
    }
    let primary = &configured[0].0;
    let directory = Path::new("/sys/class/net").join(primary).join("brif");
    let mut members = fs::read_dir(&directory)
        .map_err(|error| {
            AgentError::MissingInterface(format!(
                "could not enumerate bridge members for {primary:?} ({error})"
            ))
        })?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    members.sort();
    if members.is_empty() {
        return Err(AgentError::MissingInterface(format!(
            "one-arm bridge {primary:?} has no member interfaces"
        )));
    }
    let mut targets = members
        .into_iter()
        .map(|name| resolve_interface(&name).map(|ifindex| (name, ifindex)))
        .collect::<Result<Vec<_>, _>>()?;
    targets.extend_from_slice(&configured[1..]);
    targets.sort_by(|left, right| left.0.cmp(&right.0));
    targets.dedup_by(|left, right| left.1 == right.1);
    Ok(targets)
}

fn observed_ingress_ifindices(configured: &[String], targets: &[(String, i32)]) -> Vec<i32> {
    let mut ifindices = targets
        .iter()
        .map(|(_, ifindex)| *ifindex)
        .collect::<Vec<_>>();
    for interface in configured {
        let directory = Path::new("/sys/class/net").join(interface).join("brif");
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Ok(ifindex) = resolve_interface(name)
            {
                ifindices.push(ifindex);
            }
        }
    }
    ifindices.sort_unstable();
    ifindices.dedup();
    ifindices
}

fn hook_description(ingress: bool, egress: bool, target_count: usize) -> &'static str {
    match (ingress, egress, target_count) {
        (true, true, _) => "ingress and egress hooks",
        (true, false, 1) => "ingress hook",
        (true, false, _) => "ingress hooks",
        (false, true, 1) => "egress hook",
        (false, true, _) => "egress hooks",
        (false, false, _) => "no hooks",
    }
}

#[derive(Default)]
struct AsymmetryDetector {
    original_packets: u64,
    reply_packets: u64,
}

fn topology_summary(
    network: &TopologyContext,
    backend: tc::ActiveBackend,
    order: AttachOrder,
    warnings: &[String],
) -> TopologySummary {
    let snapshot = &network.snapshot;
    let upstream_gateway = snapshot
        .routes
        .iter()
        .find(|route| {
            (route.destination.prefix_length == 0
                || route.interface
                    == network
                        .snapshot
                        .interfaces
                        .iter()
                        .find(|i| i.name == snapshot.mode.to_string())
                        .map_or("", |_| ""))
                && route.gateway.is_some()
        })
        .or_else(|| snapshot.routes.iter().find(|route| route.gateway.is_some()))
        .and_then(|route| route.gateway)
        .map_or_else(String::new, |address| address.to_string());
    TopologySummary {
        topology_mode: snapshot.mode.to_string(),
        agent_addresses: snapshot
            .local_addresses
            .iter()
            .map(ToString::to_string)
            .collect(),
        upstream_gateway,
        segments: snapshot
            .segments
            .iter()
            .map(|segment| WireTopologySegment {
                subnet: segment.subnet.to_string(),
                interface: segment.interface.clone().unwrap_or_default(),
                role: segment.role.to_string(),
                confidence: u32::from(segment.confidence),
            })
            .collect(),
        nat_status: snapshot.nat.to_string(),
        attach_backend: backend.to_string(),
        attach_order: match backend {
            tc::ActiveBackend::Tcx => match order.tcx_order {
                TcxOrder::First => "first".to_owned(),
                TcxOrder::Last => "last".to_owned(),
            },
            tc::ActiveBackend::Netlink => {
                format!(
                    "priority {} / handle 0x{:x}",
                    order.tc_priority, order.tc_handle
                )
            }
        },
        ipv4_coverage: coverage(snapshot.ipv4_forwarding, snapshot.ipv4_default_route).to_owned(),
        ipv6_coverage: coverage(snapshot.ipv6_forwarding, snapshot.ipv6_default_route).to_owned(),
        icmp_redirect: optional_status(snapshot.icmp_redirects).to_owned(),
        software_flow_offload: wire_offload(snapshot.flow_offloading) as i32,
        hardware_flow_offload: wire_offload(snapshot.flow_offloading_hw) as i32,
        topology_warnings: warnings.to_vec(),
        confidence: u32::from(snapshot.confidence),
    }
}

fn coverage(forwarding: bool, default_route: bool) -> &'static str {
    match (forwarding, default_route) {
        (true, true) => "full",
        (true, false) | (false, true) => "partial",
        (false, false) => "none",
    }
}

fn optional_status(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn wire_offload(value: Option<bool>) -> OffloadStatus {
    match value {
        Some(true) => OffloadStatus::Enabled,
        Some(false) => OffloadStatus::Disabled,
        None => OffloadStatus::Unspecified,
    }
}

impl AsymmetryDetector {
    fn observe(&mut self, direction: crate::normalization::Direction, packets: u64) {
        match direction {
            crate::normalization::Direction::Upload => {
                self.original_packets = self.original_packets.saturating_add(packets)
            }
            crate::normalization::Direction::Download => {
                self.reply_packets = self.reply_packets.saturating_add(packets)
            }
            crate::normalization::Direction::Internal
            | crate::normalization::Direction::Unknown => {}
        }
    }

    fn take_warning(&mut self) -> bool {
        let warning = self.original_packets >= 100
            && self.reply_packets.saturating_mul(20) < self.original_packets;
        self.original_packets = 0;
        self.reply_packets = 0;
        warning
    }
}

fn session_boot_id() -> String {
    let boot_id = read_trimmed("/proc/sys/kernel/random/boot_id");
    let started_at = telemetry::unix_ms(SystemTime::now());
    format!("{boot_id}-{started_at}")
}

fn is_controller_transport(
    flow: &NormalizedFlow,
    controller_endpoints: &[std::net::SocketAddr],
) -> bool {
    controller_endpoints.iter().any(|endpoint| {
        (flow.client_addr == endpoint.ip() && flow.client_port == endpoint.port())
            || (flow.remote_addr == endpoint.ip() && flow.remote_port == endpoint.port())
    })
}

fn boot_epoch_ms() -> u64 {
    telemetry::unix_ms(SystemTime::now()).saturating_sub(monotonic_ns() / 1_000_000)
}

fn monotonic_ns() -> u64 {
    // Same clock as bpf_ktime_get_ns; NTP adjustments must not reset active budgets.
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map(|time| {
            u64::try_from(time.tv_sec())
                .unwrap_or(0)
                .saturating_mul(1_000_000_000)
                + u64::try_from(time.tv_nsec()).unwrap_or(0)
        })
        .unwrap_or(0)
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

fn openwrt_version() -> String {
    fs::read_to_string("/etc/openwrt_release")
        .ok()
        .and_then(|release| {
            release.lines().find_map(|line| {
                line.strip_prefix("DISTRIB_RELEASE=")
                    .map(|value| value.trim_matches('\'').to_owned())
            })
        })
        .unwrap_or_default()
}

fn hardware_flow_offload_status() -> OffloadStatus {
    match fs::read_to_string(FIREWALL_CONFIG_PATH) {
        Ok(firewall) if firewall_hw_flow_offload_enabled(&firewall) => OffloadStatus::Enabled,
        Ok(_) => OffloadStatus::Disabled,
        Err(_) => OffloadStatus::Unspecified,
    }
}

fn log_enabled(configured: LogLevel, level: LogLevel) -> bool {
    level <= configured
}

fn log_warn(configured: LogLevel, args: std::fmt::Arguments<'_>) {
    if log_enabled(configured, LogLevel::Warn) {
        eprintln!("{args}");
    }
}

fn log_info(configured: LogLevel, args: std::fmt::Arguments<'_>) {
    if log_enabled(configured, LogLevel::Info) {
        println!("{args}");
    }
}

fn log_debug(configured: LogLevel, args: std::fmt::Arguments<'_>) {
    if log_enabled(configured, LogLevel::Debug) {
        println!("{args}");
    }
}

fn refresh_neighbors(cache: &mut DeviceObservationCache, ifindex: u32, log_level: LogLevel) {
    let observed_at = SystemTime::now();
    match neighbor::discover(ifindex) {
        Ok(entries) => {
            for entry in entries {
                cache.observe(entry.mac, Some(entry.ip), None, None, observed_at);
            }
        }
        Err(error) => log_warn(log_level, format_args!("{error}")),
    }
}

fn refresh_dhcp_leases(cache: &mut DeviceObservationCache, log_level: LogLevel) {
    match read_leases(Path::new(DEFAULT_LEASE_PATH)) {
        Ok(leases) => cache.observe_leases(&leases, SystemTime::now()),
        Err(crate::dhcp::DhcpLeaseReadError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => log_warn(
            log_level,
            format_args!("DHCP lease discovery failed: {error}"),
        ),
    }
}

fn log_device_snapshot(cache: &DeviceObservationCache, log_level: LogLevel) {
    if !log_enabled(log_level, LogLevel::Debug) {
        return;
    }
    for observation in cache.snapshot() {
        let last_seen_ms = observation
            .last_seen
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        log_debug(
            log_level,
            format_args!(
                "device observation mac={} ip={} hostname={} last_seen={}",
                observation.mac,
                observation.ip,
                observation.hostname.as_deref().unwrap_or("-"),
                last_seen_ms
            ),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn process_pending_sample_events(
    mut received: VecDeque<Vec<u8>>,
    deferred: &mut VecDeque<Vec<u8>>,
    event_buffer: &PendingSampleEvents,
    sender: &SampleQueue,
    network: &crate::normalization::NetworkContext,
    conntrack: &SharedConntrack,
    stats: &ConntrackStats,
    excluded: &[std::net::SocketAddr],
    boot_epoch_ms: u64,
    now: Instant,
    next_refresh: &mut Instant,
    refreshed_this_iteration: &mut bool,
) {
    if received.is_empty() && deferred.is_empty() {
        return;
    }
    let current = conntrack
        .read()
        .map(|value| Arc::clone(&value))
        .unwrap_or_default();

    while let Some(bytes) = received.pop_front() {
        if sample_needs_conntrack_refresh(&bytes, network, &current) {
            event_buffer.defer(deferred, bytes);
        } else {
            decode_and_submit_sample(&bytes, sender, network, excluded, boot_epoch_ms, &current);
        }
    }

    if deferred.is_empty() {
        return;
    }

    let refreshed = if *refreshed_this_iteration {
        current
    } else if now >= *next_refresh {
        let refresh_started = Instant::now();
        let refreshed = Arc::new(ConntrackContext::discover());
        let resolved = deferred.iter().any(|bytes| {
            sample_event_key(bytes).is_some_and(|key| refreshed.resolve(&key).is_some())
        });
        stats.record_refresh(
            resolved,
            refreshed.len(),
            refresh_started.elapsed().as_micros() as u64,
        );
        if let Ok(mut current) = conntrack.write() {
            *current = Arc::clone(&refreshed);
        }
        *refreshed_this_iteration = true;
        *next_refresh = now + SAMPLE_CONNTRACK_REFRESH_INTERVAL;
        refreshed
    } else {
        return;
    };

    while let Some(bytes) = deferred.pop_front() {
        decode_and_submit_sample(&bytes, sender, network, excluded, boot_epoch_ms, &refreshed);
    }
}

fn sample_event_key(bytes: &[u8]) -> Option<FlowKey> {
    FlowKey::try_from(bytes.get(..crate::flow::FLOW_KEY_SIZE)?).ok()
}

fn sample_needs_conntrack_refresh(
    bytes: &[u8],
    network: &crate::normalization::NetworkContext,
    conntrack: &ConntrackContext,
) -> bool {
    let Some(key) = sample_event_key(bytes) else {
        return false;
    };
    normalize_with_resolution(&key, network, conntrack).is_some_and(|(flow, resolved)| {
        flow.scope == crate::normalization::FlowScope::RouterLocal && !resolved
    })
}

fn decode_and_submit_sample(
    bytes: &[u8],
    sender: &SampleQueue,
    network: &crate::normalization::NetworkContext,
    excluded: &[std::net::SocketAddr],
    boot_epoch_ms: u64,
    conntrack: &ConntrackContext,
) {
    if let Some(sample) =
        sample::decode_sample(bytes, network, boot_epoch_ms, true, excluded, conntrack)
    {
        sender.submit(sample);
    }
}

fn sample_event_captured_length(bytes: &[u8]) -> u64 {
    bytes
        .get(64..68)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_ne_bytes)
        .map(u64::from)
        .unwrap_or(0)
}

fn print_lifecycle_event(
    event: &FlowLifecycleEvent,
    network: &crate::normalization::NetworkContext,
    conntrack_snapshot: &mut Arc<ConntrackContext>,
    conntrack: &SharedConntrack,
    stats: &ConntrackStats,
    refresh_budget: &mut ConntrackRefreshBudget,
    log_level: LogLevel,
) {
    if !log_enabled(log_level, LogLevel::Debug) {
        return;
    }
    if let Some(flow) = normalize_with_current_conntrack(
        &event.key,
        network,
        conntrack_snapshot,
        conntrack,
        stats,
        refresh_budget,
    ) {
        log_debug(
            log_level,
            format_args!(
                "flow lifecycle state={} protocol={} client={}:{} remote={}:{} direction={}",
                event.state,
                event.key.protocol,
                flow.client_addr,
                flow.client_port,
                flow.remote_addr,
                flow.remote_port,
                flow.direction
            ),
        );
    }
}

#[derive(Debug, Default)]
struct ConntrackRefreshBudget {
    attempted: bool,
}

impl ConntrackRefreshBudget {
    fn claim(&mut self) -> bool {
        if self.attempted {
            return false;
        }
        self.attempted = true;
        true
    }
}

fn normalize_with_current_conntrack(
    key: &FlowKey,
    network: &crate::normalization::NetworkContext,
    current: &mut Arc<ConntrackContext>,
    conntrack: &SharedConntrack,
    stats: &ConntrackStats,
    refresh_budget: &mut ConntrackRefreshBudget,
) -> Option<NormalizedFlow> {
    let (flow, resolved) = normalize_with_resolution(key, network, current)?;
    if flow.scope != crate::normalization::FlowScope::RouterLocal || resolved {
        if resolved {
            stats.record_hit();
        } else {
            stats.record_miss();
        }
        return Some(flow);
    }

    if !refresh_budget.claim() {
        return Some(flow);
    }

    // A reply can be captured before DNAT restores the original client, and a
    // transparent proxy reply is emitted with its translated local tuple. The
    // first eBPF poll can beat the periodic conntrack refresh and would
    // otherwise discard that delta as router-local.
    // Refresh only once per poll for unresolved, router-local-looking tuples.
    // A failed resolution must not turn every such flow into a synchronous
    // full-table conntrack scan.
    let refresh_started = Instant::now();
    let refreshed = Arc::new(ConntrackContext::discover());
    let (flow, resolved) = normalize_with_resolution(key, network, &refreshed)?;
    stats.record_refresh(
        resolved,
        refreshed.len(),
        refresh_started.elapsed().as_micros() as u64,
    );
    *current = Arc::clone(&refreshed);
    if let Ok(mut shared) = conntrack.write() {
        *shared = refreshed;
    }
    Some(flow)
}

fn current_conntrack_snapshot(conntrack: &SharedConntrack) -> Arc<ConntrackContext> {
    conntrack
        .read()
        .map(|current| Arc::clone(&current))
        .unwrap_or_default()
}

struct FlowMapSnapshot {
    flows: Vec<(FlowKey, FlowCounters)>,
    retained_entries: u64,
    keys_scanned: u64,
}

/// Incremental sampler-budget GC state.
///
/// The budget map is intentionally not an LRU map: evicting an active budget
/// would allow a flow to be sampled again.  A full map walk every 30 seconds
/// therefore has to be bounded.  The cursor is a stable key left in the map;
/// stale entries are deleted only after their successor has been read, so a
/// deletion cannot restart `BPF_MAP_GET_NEXT_KEY` from the beginning.
#[derive(Default)]
struct SampleBudgetGc {
    cursor: Option<Vec<u8>>,
    cycle_entries: u64,
    last_entries: u64,
}

impl SampleBudgetGc {
    fn run<M: MapCore + ?Sized>(
        &mut self,
        map: &M,
        now_ns: u64,
        tcp_idle_timeout_seconds: u64,
        udp_idle_timeout_seconds: u64,
    ) -> u64 {
        let key_size = map.key_size() as usize;
        let value_size = map.value_size() as usize;
        if key_size == 0 || value_size < 16 {
            self.cursor = None;
            self.cycle_entries = 0;
            self.last_entries = 0;
            return 0;
        }

        // A deleted/expired cursor means the next complete walk starts at the
        // first key.  `lookup_into` reuses this value buffer for every entry.
        if let Some(cursor) = self.cursor.as_deref()
            && !map
                .lookup_into(cursor, &mut vec![0; value_size], MapFlags::ANY)
                .unwrap_or(false)
        {
            self.cursor = None;
        }
        if self.cursor.is_none() {
            self.cycle_entries = 0;
        }

        let mut value = vec![0_u8; value_size];
        let mut current = match next_map_key(map, self.cursor.as_deref(), key_size) {
            Ok(Some(key)) => key,
            Ok(None) => {
                self.cursor = None;
                self.last_entries = self.cycle_entries;
                self.cycle_entries = 0;
                return self.last_entries;
            }
            Err(_) => return self.last_entries,
        };
        let mut scanned = 0_usize;
        let mut last_live = self.cursor.clone();

        loop {
            // Capture the successor before possibly deleting `current`.
            let successor = next_map_key(map, Some(&current), key_size);
            let found = map
                .lookup_into(&current, &mut value, MapFlags::ANY)
                .unwrap_or(false);
            if found {
                let last_seen_ns =
                    u64::from_ne_bytes(value[8..16].try_into().expect("fixed slice"));
                let timeout_seconds = if current.get(1) == Some(&6) {
                    tcp_idle_timeout_seconds
                } else {
                    udp_idle_timeout_seconds
                };
                let stale = now_ns.saturating_sub(last_seen_ns)
                    > timeout_seconds.saturating_mul(1_000_000_000);
                if stale {
                    let _ = map.delete(&current);
                } else {
                    self.cycle_entries = self.cycle_entries.saturating_add(1);
                    last_live = Some(current.clone());
                }
            }
            scanned += 1;

            match successor {
                Ok(Some(next)) if scanned < SAMPLE_BUDGET_GC_MAX_ENTRIES => current = next,
                Ok(Some(_)) => {
                    // Resume after a key that is still present.  If all keys
                    // in this slice were stale, retaining the previous cursor
                    // causes a bounded re-scan and the stale entries disappear.
                    self.cursor = last_live;
                    break;
                }
                Ok(None) => {
                    self.cursor = None;
                    self.last_entries = self.cycle_entries;
                    self.cycle_entries = 0;
                    break;
                }
                Err(_) => {
                    self.cursor = last_live;
                    break;
                }
            }
        }
        self.last_entries
    }
}

#[allow(unsafe_code)]
fn next_map_key<M: MapCore + ?Sized>(
    map: &M,
    previous: Option<&[u8]>,
    key_size: usize,
) -> Result<Option<Vec<u8>>, libbpf_rs::Error> {
    let mut next = vec![0_u8; key_size];
    let previous_ptr = previous.map_or(std::ptr::null(), |key| key.as_ptr());
    // SAFETY: all pointers reference buffers valid for the duration of the
    // syscall, and the map fd is borrowed from the live MapCore object.
    let ret = unsafe {
        libbpf_rs::libbpf_sys::bpf_map_get_next_key(
            map.as_fd().as_raw_fd(),
            previous_ptr.cast(),
            next.as_mut_ptr().cast(),
        )
    };
    if ret == 0 {
        Ok(Some(next))
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(libbpf_rs::Error::from(error))
        }
    }
}

#[allow(unsafe_code)]
fn read_flow_map<M>(
    map: &M,
    now_ns: u64,
    tcp_idle_timeout_seconds: u64,
    udp_idle_timeout_seconds: u64,
) -> Result<FlowMapSnapshot, libbpf_rs::Error>
where
    M: MapCore + ?Sized,
{
    const BATCH_SIZE: u32 = 512;
    // Keep one batch of raw keys/values and reuse it for every syscall.  The
    // public libbpf-rs iterator allocates a Vec for each yielded pair, which
    // becomes visible on devices with thousands of active flows.
    let key_size = map.key_size() as usize;
    let batch_key_size = if map.map_type().is_hash_map() {
        key_size.max(4)
    } else {
        key_size
    };
    let value_size = map.value_size() as usize;
    let mut batch_keys = vec![0_u8; batch_key_size * BATCH_SIZE as usize];
    let mut batch_values = vec![0_u8; value_size * BATCH_SIZE as usize];
    let mut batch_next = vec![0_u8; batch_key_size];
    let mut batch_previous = vec![0_u8; batch_key_size];
    let mut has_previous = false;
    let batch_options = libbpf_rs::libbpf_sys::bpf_map_batch_opts {
        sz: size_of::<libbpf_rs::libbpf_sys::bpf_map_batch_opts>() as _,
        elem_flags: MapFlags::ANY.bits(),
        flags: MapFlags::ANY.bits(),
        ..Default::default()
    };
    let mut snapshot = Vec::with_capacity(BATCH_SIZE as usize);
    let mut keys_scanned = 0_u64;
    let mut retained_entries = 0_u64;
    let mut batch_supported = true;
    loop {
        let mut count = BATCH_SIZE;
        // SAFETY: the key/value buffers are sized for BATCH_SIZE records and
        // the batch options describe the same map operation.
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_batch(
                map.as_fd().as_raw_fd(),
                if has_previous {
                    batch_previous.as_mut_ptr().cast()
                } else {
                    std::ptr::null_mut()
                },
                batch_next.as_mut_ptr().cast(),
                batch_keys.as_mut_ptr().cast(),
                batch_values.as_mut_ptr().cast(),
                &mut count,
                &batch_options,
            )
        };
        let batch_error = if ret != 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        if let Some(error) = &batch_error
            && error.kind() != std::io::ErrorKind::NotFound
        {
            // Older kernels and map implementations reject lookup_batch;
            // retain the key-iterator fallback below.
            batch_supported = false;
            break;
        }
        if count == 0 {
            break;
        }
        has_previous = true;
        batch_previous.copy_from_slice(&batch_next);
        for index in 0..count as usize {
            let key_start = index * batch_key_size;
            let value_start = index * value_size;
            keys_scanned = keys_scanned.saturating_add(1);
            process_flow_entry(
                map,
                &batch_keys[key_start..key_start + key_size],
                &batch_values[value_start..value_start + value_size],
                now_ns,
                tcp_idle_timeout_seconds,
                udp_idle_timeout_seconds,
                &mut snapshot,
                &mut retained_entries,
            );
        }
        if batch_error.is_some() {
            break;
        }
    }
    if !batch_supported || snapshot.is_empty() {
        // Materialize keys before deleting stale entries. Deleting the current
        // key during BPF_MAP_GET_NEXT_KEY can restart traversal.
        let mut value = vec![0_u8; map.value_size() as usize];
        for key in map.keys() {
            keys_scanned = keys_scanned.saturating_add(1);
            if map
                .lookup_into(&key, &mut value, MapFlags::ANY)
                .unwrap_or(false)
            {
                process_flow_entry(
                    map,
                    &key,
                    &value,
                    now_ns,
                    tcp_idle_timeout_seconds,
                    udp_idle_timeout_seconds,
                    &mut snapshot,
                    &mut retained_entries,
                );
            }
        }
    }
    Ok(FlowMapSnapshot {
        flows: snapshot,
        retained_entries,
        keys_scanned,
    })
}

fn process_flow_entry<M: MapCore + ?Sized>(
    map: &M,
    raw_key: &[u8],
    raw_value: &[u8],
    now_ns: u64,
    tcp_idle_timeout_seconds: u64,
    udp_idle_timeout_seconds: u64,
    snapshot: &mut Vec<(FlowKey, FlowCounters)>,
    retained_entries: &mut u64,
) {
    let Ok(key) = FlowKey::try_from(raw_key) else {
        return;
    };
    let Ok(mut counters) = FlowCounters::try_from(raw_value) else {
        return;
    };
    if flow_is_idle(
        &key,
        &counters,
        now_ns,
        tcp_idle_timeout_seconds,
        udp_idle_timeout_seconds,
    ) {
        // Fetch the latest counters atomically with deletion so packets
        // observed between the first lookup and cleanup are still emitted.
        match map.lookup_and_delete(raw_key) {
            Ok(Some(latest)) => {
                if let Ok(latest) = FlowCounters::try_from(latest.as_slice()) {
                    counters = latest;
                }
            }
            Ok(None) => {}
            Err(_) => *retained_entries = (*retained_entries).saturating_add(1),
        }
    } else {
        *retained_entries = (*retained_entries).saturating_add(1);
    }
    snapshot.push((key, counters));
}

fn flow_is_idle(
    key: &FlowKey,
    counters: &FlowCounters,
    now_ns: u64,
    tcp_idle_timeout_seconds: u64,
    udp_idle_timeout_seconds: u64,
) -> bool {
    let timeout_seconds = if key.protocol == 6 {
        tcp_idle_timeout_seconds
    } else {
        udp_idle_timeout_seconds
    };
    now_ns.saturating_sub(counters.last_seen_ns) > timeout_seconds.saturating_mul(1_000_000_000)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InterfaceCounters {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InterfaceCounterHealth {
    snapshot: Option<InterfaceCounters>,
    delta_bytes: u64,
    delta_packets: u64,
    status: CounterSanityStatus,
}

struct InterfaceCounterSanity {
    interface: String,
    enabled: bool,
    min_bytes: u64,
    max_unaccounted_ratio: u64,
    previous: Option<InterfaceCounters>,
}

impl InterfaceCounterSanity {
    fn new(interface: &str, enabled: bool, min_bytes: u64, max_unaccounted_ratio: u64) -> Self {
        Self {
            interface: interface.to_owned(),
            enabled,
            min_bytes,
            max_unaccounted_ratio,
            previous: None,
        }
    }

    fn observe(
        &mut self,
        flow_delta_bytes: u64,
        _flow_delta_packets: u64,
    ) -> InterfaceCounterHealth {
        if !self.enabled {
            return InterfaceCounterHealth {
                snapshot: None,
                delta_bytes: 0,
                delta_packets: 0,
                status: CounterSanityStatus::Disabled,
            };
        }
        let Ok(snapshot) = read_interface_counters(&self.interface) else {
            self.previous = None;
            return InterfaceCounterHealth {
                snapshot: None,
                delta_bytes: 0,
                delta_packets: 0,
                status: CounterSanityStatus::Unknown,
            };
        };
        let Some(previous) = self.previous.replace(snapshot) else {
            return InterfaceCounterHealth {
                snapshot: Some(snapshot),
                delta_bytes: 0,
                delta_packets: 0,
                status: CounterSanityStatus::Unknown,
            };
        };
        let delta_bytes = snapshot
            .rx_bytes
            .saturating_sub(previous.rx_bytes)
            .saturating_add(snapshot.tx_bytes.saturating_sub(previous.tx_bytes));
        let delta_packets = snapshot
            .rx_packets
            .saturating_sub(previous.rx_packets)
            .saturating_add(snapshot.tx_packets.saturating_sub(previous.tx_packets));
        InterfaceCounterHealth {
            snapshot: Some(snapshot),
            delta_bytes,
            delta_packets,
            status: counter_sanity_status(
                delta_bytes,
                flow_delta_bytes,
                self.min_bytes,
                self.max_unaccounted_ratio,
            ),
        }
    }
}

fn counter_sanity_status(
    interface_delta_bytes: u64,
    flow_delta_bytes: u64,
    min_bytes: u64,
    max_unaccounted_ratio: u64,
) -> CounterSanityStatus {
    if interface_delta_bytes < min_bytes {
        return CounterSanityStatus::Ok;
    }
    if flow_delta_bytes == 0
        || interface_delta_bytes > flow_delta_bytes.saturating_mul(max_unaccounted_ratio)
    {
        CounterSanityStatus::Degraded
    } else {
        CounterSanityStatus::Ok
    }
}

fn read_interface_counters(interface: &str) -> std::io::Result<InterfaceCounters> {
    let base = Path::new("/sys/class/net")
        .join(interface)
        .join("statistics");
    Ok(InterfaceCounters {
        rx_bytes: read_counter_file(&base.join("rx_bytes"))?,
        tx_bytes: read_counter_file(&base.join("tx_bytes"))?,
        rx_packets: read_counter_file(&base.join("rx_packets"))?,
        tx_packets: read_counter_file(&base.join("tx_packets"))?,
    })
}

fn read_counter_file(path: &Path) -> std::io::Result<u64> {
    fs::read_to_string(path).and_then(|value| {
        value
            .trim()
            .parse::<u64>()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })
}

fn firewall_hw_flow_offload_enabled(firewall: &str) -> bool {
    firewall
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.len() >= 3
                && fields[0] == "option"
                && fields[1] == "flow_offloading_hw"
                && truthy_uci_value(fields[2])
        })
}

fn truthy_uci_value(value: &str) -> bool {
    matches!(
        value
            .trim_matches(|character| character == '\'' || character == '"')
            .to_ascii_lowercase()
            .as_str(),
        "1" | "on" | "true" | "yes" | "enabled"
    )
}

fn resolve_interface(interface: &str) -> Result<i32, AgentError> {
    let ifindex = if_nametoindex(interface)
        .map_err(|error| AgentError::MissingInterface(format!("{interface:?} ({error})")))?;
    i32::try_from(ifindex).map_err(|error| {
        AgentError::MissingInterface(format!("{interface:?} has an invalid index ({error})"))
    })
}

fn probe_map_creation() -> Result<(), AgentError> {
    let opts = libbpf_rs::libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
        ..Default::default()
    };

    // 1. Probe BPF syscall & Hash map support (observed_ifindexes, sample_budgets)
    MapHandle::create(
        MapType::Hash,
        Some("nqm_hash_prb"),
        size_of::<u32>() as u32,
        size_of::<u32>() as u32,
        1,
        &opts,
    )
    .map(drop)
    .map_err(|err| classify_map_error("Hash", err))?;

    // 2. Probe LRU Hash map support (flow_map)
    MapHandle::create(
        MapType::LruHash,
        Some("nqm_lru_prb"),
        size_of::<u32>() as u32,
        size_of::<u64>() as u32,
        1,
        &opts,
    )
    .map(drop)
    .map_err(|err| classify_map_error("LRU hash", err))?;

    // 3. Probe Array map support (dns_drop_count, sample_counters)
    MapHandle::create(
        MapType::Array,
        Some("nqm_arr_prb"),
        size_of::<u32>() as u32,
        size_of::<u64>() as u32,
        1,
        &opts,
    )
    .map(drop)
    .map_err(|err| classify_map_error("Array", err))?;

    // 4. Probe Ringbuf support (required for DNS/DHCP/Discovery/Sample events, Linux >= 5.8)
    MapHandle::create(MapType::RingBuf, Some("nqm_rb_prb"), 0, 0, 4096, &opts)
        .map(drop)
        .map_err(|err| classify_map_error("Ringbuf (requires Linux >= 5.8)", err))?;

    Ok(())
}

fn classify_map_error(map_name: &str, error: libbpf_rs::Error) -> AgentError {
    let detail = format!("could not create {map_name} map ({error})");
    match error.kind() {
        ErrorKind::PermissionDenied => AgentError::PermissionDenied(detail),
        ErrorKind::Unsupported => AgentError::BpfUnavailable(detail),
        _ => AgentError::MapCreationFailed(detail),
    }
}

#[derive(Clone, Copy)]
enum BpfStage {
    Open,
    Load,
}

fn classify_bpf_error(stage: BpfStage, error: libbpf_rs::Error) -> AgentError {
    let detail = match stage {
        BpfStage::Open => format!("could not open embedded object ({error})"),
        BpfStage::Load => format!("could not load classifier ({error})"),
    };

    match error.kind() {
        ErrorKind::PermissionDenied => AgentError::PermissionDenied(detail),
        _ => AgentError::BpfUnavailable(detail),
    }
}

fn classify_tc_error(interface: &str, error: libbpf_rs::Error) -> AgentError {
    let detail = format!("could not attach to {interface:?} ({error})");
    if error.kind() == ErrorKind::PermissionDenied {
        AgentError::PermissionDenied(detail)
    } else {
        AgentError::TcUnavailable(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentError, AsymmetryDetector, BpfStage, ConntrackRefreshBudget, CounterSanityStatus,
        PendingSampleEvents, SAMPLE_EVENT_HEADER_SIZE, SAMPLE_EVENT_MAX_PAYLOAD_SIZE,
        classify_bpf_error, classify_map_error, classify_tc_error, counter_sanity_status,
        firewall_hw_flow_offload_enabled, flow_is_idle, hook_description, observation_hooks,
    };
    use crate::flow::{FlowCounters, FlowKey};
    use crate::normalization::Direction;
    use libbpf_rs::Error as LibbpfError;
    use nix::libc::{EINVAL, ENOSYS, EPERM};

    #[test]
    fn all_observation_points_attach_deduplicating_egress() {
        assert_eq!(observation_hooks(), (true, true));
        assert_eq!(hook_description(true, true, 2), "ingress and egress hooks");
    }

    #[test]
    fn reports_required_startup_error_categories() {
        let cases = [
            AgentError::MissingInterface("eth-missing".into()),
            AgentError::PermissionDenied("operation rejected".into()),
            AgentError::BpfUnavailable("syscall missing".into()),
            AgentError::TcUnavailable("clsact missing".into()),
            AgentError::MapCreationFailed("LRU map rejected".into()),
        ];
        let expected = [
            "missing interface",
            "permission denied",
            "BPF unavailable",
            "TC unavailable",
            "map creation failed",
        ];

        for (error, prefix) in cases.iter().zip(expected) {
            assert!(error.to_string().starts_with(prefix));
        }
    }

    #[test]
    fn classifies_libbpf_failures_by_startup_stage() {
        let permission = classify_bpf_error(BpfStage::Load, LibbpfError::from_raw_os_error(EPERM));
        assert!(matches!(permission, AgentError::PermissionDenied(_)));

        let unavailable =
            classify_bpf_error(BpfStage::Open, LibbpfError::from_raw_os_error(ENOSYS));
        assert!(matches!(unavailable, AgentError::BpfUnavailable(_)));

        let map = classify_map_error("LRU hash", LibbpfError::from_raw_os_error(EINVAL));
        assert!(matches!(map, AgentError::MapCreationFailed(_)));

        let tc = classify_tc_error("eth0", LibbpfError::from_raw_os_error(ENOSYS));
        assert!(matches!(tc, AgentError::TcUnavailable(_)));
    }

    #[test]
    fn parses_openwrt_firewall_hfo_option() {
        assert!(firewall_hw_flow_offload_enabled(
            r#"
config defaults
    option flow_offloading '1'
    option flow_offloading_hw '1'
"#
        ));
        assert!(firewall_hw_flow_offload_enabled(
            r#"
config defaults
    option flow_offloading_hw "yes"
"#
        ));
        assert!(!firewall_hw_flow_offload_enabled(
            r#"
config defaults
    # option flow_offloading_hw '1'
    option flow_offloading_hw '0'
"#
        ));
    }

    #[test]
    fn flags_large_interface_counter_gap_as_degraded() {
        assert_eq!(
            counter_sanity_status(1_024, 0, 64 * 1024, 4),
            CounterSanityStatus::Ok
        );
        assert_eq!(
            counter_sanity_status(128 * 1024, 0, 64 * 1024, 4),
            CounterSanityStatus::Degraded
        );
        assert_eq!(
            counter_sanity_status(128 * 1024, 64 * 1024, 64 * 1024, 4),
            CounterSanityStatus::Ok
        );
        assert_eq!(
            counter_sanity_status(512 * 1024, 64 * 1024, 64 * 1024, 4),
            CounterSanityStatus::Degraded
        );
    }

    #[test]
    fn warns_only_for_a_large_batch_with_less_than_five_percent_replies() {
        let mut detector = AsymmetryDetector::default();
        detector.observe(Direction::Upload, 99);
        assert!(!detector.take_warning());

        detector.observe(Direction::Upload, 100);
        detector.observe(Direction::Download, 4);
        assert!(detector.take_warning());

        detector.observe(Direction::Upload, 100);
        detector.observe(Direction::Download, 5);
        assert!(!detector.take_warning());
    }

    #[test]
    fn limits_on_demand_conntrack_refresh_to_once_per_poll() {
        let mut budget = ConntrackRefreshBudget::default();
        assert!(budget.claim());
        assert!(!budget.claim());
        assert!(!budget.claim());
        assert!(ConntrackRefreshBudget::default().claim());
    }

    #[test]
    fn expires_flow_entries_using_protocol_idle_timeouts() {
        let key = FlowKey {
            ip_version: 4,
            protocol: 6,
            direction: 0,
            ifindex: 1,
            source_address: [0; 16],
            destination_address: [0; 16],
            source_port: 1234,
            destination_port: 443,
        };
        let counters = FlowCounters {
            last_seen_ns: 10_000_000_000,
            ..FlowCounters::default()
        };

        assert!(!flow_is_idle(&key, &counters, 130_000_000_000, 120, 30));
        assert!(flow_is_idle(&key, &counters, 131_000_000_000, 120, 30));

        let udp_key = FlowKey {
            protocol: 17,
            ..key
        };
        assert!(!flow_is_idle(&udp_key, &counters, 40_000_000_000, 120, 30));
        assert!(flow_is_idle(&udp_key, &counters, 41_000_000_000, 120, 30));
    }

    #[test]
    fn bounds_pending_sample_events_and_records_drops() {
        let events = PendingSampleEvents::new(1);
        let mut sample = vec![0; 68];
        sample[64..68].copy_from_slice(&42_u32.to_ne_bytes());

        events.push(&sample);
        events.push(&sample);

        assert_eq!(events.drain().len(), 1);
        assert_eq!(events.drops(), (1, 42));
    }

    #[test]
    fn pending_sample_events_copy_only_the_captured_payload() {
        let events = PendingSampleEvents::new(1);
        let mut sample = vec![0; SAMPLE_EVENT_HEADER_SIZE + SAMPLE_EVENT_MAX_PAYLOAD_SIZE];
        sample[64..68].copy_from_slice(&100_u32.to_ne_bytes());

        events.push(&sample);

        assert_eq!(
            events.drain().front().map(Vec::len),
            Some(SAMPLE_EVENT_HEADER_SIZE + 100)
        );
    }
}

fn read_indexed_counter<M: MapCore>(map: &M, index: u32) -> u64 {
    map.lookup(&index.to_ne_bytes(), MapFlags::ANY)
        .ok()
        .flatten()
        .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_ne_bytes))
        .unwrap_or(0)
}
