use std::fmt;
use std::fs;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::AsFd as _;

use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
use libbpf_rs::{MapHandle, MapType};
use nix::net::if_::if_nametoindex;

use super::network;
use super::tc::{self, NetlinkHooks, TcxLinks};
use crate::bpf::FlowSkelBuilder;
use crate::config::AgentConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Fail,
    Warn,
    Unknown,
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ok => "OK",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Unknown => "UNKNOWN",
        })
    }
}

#[derive(Debug)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
    required: bool,
}

#[derive(Debug)]
pub(super) struct CapabilityReport {
    checks: Vec<Check>,
    topology: Option<crate::topology::TopologyContext>,
    attach_backend: Option<tc::ActiveBackend>,
    attach_detail: String,
    capture_interface: String,
}

impl CapabilityReport {
    pub(super) fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| !check.required || check.status == Status::Ok)
    }
}

impl fmt::Display for CapabilityReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(topology) = &self.topology {
            let snapshot = &topology.snapshot;
            writeln!(formatter, "Topology Mode: {}", snapshot.mode)?;
            writeln!(formatter, "Capture Interface: {}", self.capture_interface)?;
            writeln!(
                formatter,
                "Attach Backend: {}",
                self.attach_backend
                    .map_or_else(|| "unavailable".to_owned(), |backend| backend.to_string())
            )?;
            writeln!(formatter, "TC/TCX Attach Status: {}", self.attach_detail)?;
            write_segments(formatter, "Local Networks", snapshot, |role| {
                role == crate::topology::SegmentRole::Lan
            })?;
            write_segments(formatter, "Routed Networks", snapshot, |role| {
                role == crate::topology::SegmentRole::RoutedLan
            })?;
            write_segments(formatter, "Tunnel Networks", snapshot, |role| {
                role == crate::topology::SegmentRole::Tunnel
            })?;
            writeln!(
                formatter,
                "Default Gateway: {}",
                snapshot
                    .gateways
                    .first()
                    .map_or_else(|| "None".into(), ToString::to_string)
            )?;
            writeln!(formatter, "Neighbors: {}", snapshot.neighbors.len())?;
            writeln!(formatter, "NAT Status: {}", snapshot.nat)?;
            writeln!(
                formatter,
                "IPv4 Coverage: {}",
                if snapshot.ipv4_default_route {
                    "Full"
                } else {
                    "None"
                }
            )?;
            writeln!(
                formatter,
                "IPv6 Coverage: {}",
                if snapshot.ipv6_default_route {
                    "Full"
                } else {
                    "None"
                }
            )?;
            writeln!(
                formatter,
                "ICMP Redirect: {}",
                option_status(snapshot.icmp_redirects)
            )?;
            writeln!(
                formatter,
                "Flow Offloading: software={}, hardware={}",
                option_status(snapshot.flow_offloading),
                option_status(snapshot.flow_offloading_hw)
            )?;
            writeln!(formatter, "Warnings:")?;
            if snapshot.warnings.is_empty() {
                writeln!(formatter, "- None")?;
            } else {
                for warning in &snapshot.warnings {
                    writeln!(formatter, "- {warning}")?;
                }
            }
            writeln!(formatter)?;
        }
        for check in &self.checks {
            writeln!(
                formatter,
                "{:<14} {:<7} {}",
                check.name, check.status, check.detail
            )?;
        }
        Ok(())
    }
}

pub(super) fn probe(config: &AgentConfig) -> CapabilityReport {
    let interface = interfaces_check(&config.interfaces);
    let interface_available = interface.status == Status::Ok;
    let mut checks = vec![architecture_check(), kernel_check(), interface];
    checks.push(map_check("BPF syscall", MapType::Hash, 4, 4, 1));
    checks.push(map_check("BPF_MAP_TYPE_HASH", MapType::Hash, 4, 4, 1));
    checks.push(map_check(
        "BPF_MAP_TYPE_LRU_HASH",
        MapType::LruHash,
        4,
        8,
        1,
    ));
    checks.push(map_check("BPF_MAP_TYPE_ARRAY", MapType::Array, 4, 8, 1));
    checks.push(map_check(
        "BPF_MAP_TYPE_RINGBUF",
        MapType::RingBuf,
        0,
        0,
        4096,
    ));
    let (attach_check, attach_backend, attach_detail) = if interface_available {
        attach_check(config)
    } else {
        (
            Check {
                name: "TC clsact",
                status: Status::Fail,
                detail: "interface unavailable".into(),
                required: true,
            },
            None,
            "interface unavailable".into(),
        )
    };
    checks.push(attach_check);
    checks.push(hfo_check());
    CapabilityReport {
        checks,
        topology: network::discover(config).ok(),
        attach_backend,
        attach_detail,
        capture_interface: config.interfaces.join(", "),
    }
}

fn write_segments(
    formatter: &mut fmt::Formatter<'_>,
    label: &str,
    snapshot: &crate::topology::TopologySnapshot,
    predicate: impl Fn(crate::topology::SegmentRole) -> bool,
) -> fmt::Result {
    let value = snapshot
        .segments
        .iter()
        .filter(|segment| predicate(segment.role))
        .map(|segment| segment.subnet.to_string())
        .collect::<Vec<_>>();
    writeln!(
        formatter,
        "{label}: {}",
        if value.is_empty() {
            "None".into()
        } else {
            value.join(", ")
        }
    )
}

fn option_status(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Enabled",
        Some(false) => "Disabled",
        None => "Unknown",
    }
}

fn attach_check(config: &AgentConfig) -> (Check, Option<tc::ActiveBackend>, String) {
    let tcx = if config.attach_backend == crate::config::AttachBackend::Netlink {
        None
    } else {
        Some(probe_tcx_backend(config))
    };
    let (backend, result) = match (config.attach_backend, tcx) {
        (crate::config::AttachBackend::Tcx, Some(result)) => (tc::ActiveBackend::Tcx, result),
        (crate::config::AttachBackend::Auto, Some(Ok(()))) => (tc::ActiveBackend::Tcx, Ok(())),
        (crate::config::AttachBackend::Auto, Some(Err(_)))
        | (crate::config::AttachBackend::Netlink, _) => {
            (tc::ActiveBackend::Netlink, probe_netlink_backend(config))
        }
        _ => unreachable!(),
    };
    match result {
        Ok(()) => (
            Check {
                name: "TC/TCX attach",
                status: Status::Ok,
                detail: format!(
                    "backend={backend}; ingress=attached; egress=attached; order={}; conflict=none",
                    attach_order(config, backend)
                ),
                required: true,
            },
            Some(backend),
            "ingress=OK, egress=OK, conflict=none".into(),
        ),
        Err(error) => {
            let conflict = if error.kind() == libbpf_rs::ErrorKind::AlreadyExists {
                "detected"
            } else {
                "unknown"
            };
            let detail = format!(
                "backend={backend}; attach=failed; order={}; conflict={conflict}; error={error}",
                attach_order(config, backend)
            );
            (
                Check {
                    name: "TC/TCX attach",
                    status: Status::Fail,
                    detail: detail.clone(),
                    required: true,
                },
                Some(backend),
                detail,
            )
        }
    }
}

fn attach_order(config: &AgentConfig, backend: tc::ActiveBackend) -> String {
    match backend {
        tc::ActiveBackend::Tcx => {
            format!("{:?}", config.attach_order.tcx_order).to_ascii_lowercase()
        }
        tc::ActiveBackend::Netlink => format!(
            "priority={}, handle={:#x}",
            config.attach_order.tc_priority, config.attach_order.tc_handle
        ),
    }
}

pub(super) fn probe_tcx_backend(config: &AgentConfig) -> libbpf_rs::Result<()> {
    let ifindices = resolve_ifindices(&config.interfaces)?;
    let builder = FlowSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skeleton = builder.open(&mut open_object)?;
    open_skeleton.progs.netqmon_ingress.set_autoload(false);
    open_skeleton.progs.netqmon_egress.set_autoload(false);
    open_skeleton
        .maps
        .flow_map
        .set_max_entries(config.max_flows)?;
    let skeleton = open_skeleton.load()?;
    let mut links = Vec::new();
    for ifindex in ifindices {
        links.push(TcxLinks::attach(
            ifindex,
            &skeleton.progs.netqmon_attach_probe,
            &skeleton.progs.netqmon_attach_probe,
            config.attach_order,
            true,
            true,
        )?);
    }
    for link in &mut links {
        link.detach();
    }
    Ok(())
}

fn probe_netlink_backend(config: &AgentConfig) -> libbpf_rs::Result<()> {
    let ifindices = resolve_ifindices(&config.interfaces)?;
    let builder = FlowSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skeleton = builder.open(&mut open_object)?;
    open_skeleton.progs.netqmon_ingress.set_autoload(false);
    open_skeleton.progs.netqmon_egress.set_autoload(false);
    open_skeleton
        .maps
        .flow_map
        .set_max_entries(config.max_flows)?;
    let skeleton = open_skeleton.load()?;
    let mut hooks = Vec::new();
    for ifindex in ifindices {
        hooks.push(NetlinkHooks::attach_probe(
            ifindex,
            skeleton.progs.netqmon_attach_probe.as_fd(),
        )?);
    }
    for hook in &mut hooks {
        hook.detach()
            .map_err(|_| libbpf_rs::Error::from_raw_os_error(nix::libc::EIO))?;
    }
    Ok(())
}

fn resolve_ifindices(interfaces: &[String]) -> libbpf_rs::Result<Vec<i32>> {
    interfaces
        .iter()
        .map(|interface| {
            let raw = if_nametoindex(interface.as_str())
                .map_err(|error| libbpf_rs::Error::from_raw_os_error(error as i32))?;
            i32::try_from(raw)
                .map_err(|_| libbpf_rs::Error::from_raw_os_error(nix::libc::EOVERFLOW))
        })
        .collect()
}

fn architecture_check() -> Check {
    Check {
        name: "Architecture",
        status: Status::Ok,
        detail: std::env::consts::ARCH.into(),
        required: true,
    }
}

fn kernel_check() -> Check {
    match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) => Check {
            name: "Kernel",
            status: Status::Ok,
            detail: release.trim().into(),
            required: true,
        },
        Err(error) => Check {
            name: "Kernel",
            status: Status::Fail,
            detail: error.to_string(),
            required: true,
        },
    }
}

fn interfaces_check(interfaces: &[String]) -> Check {
    let resolved = interfaces
        .iter()
        .map(|interface| match if_nametoindex(interface.as_str()) {
            Ok(index) => Ok(format!("{interface} (ifindex {index})")),
            Err(error) => Err(format!("{interface} ({error})")),
        })
        .collect::<Result<Vec<_>, _>>();
    match resolved {
        Ok(values) => Check {
            name: "Interfaces",
            status: Status::Ok,
            detail: values.join(", "),
            required: true,
        },
        Err(detail) => Check {
            name: "Interfaces",
            status: Status::Fail,
            detail,
            required: true,
        },
    }
}

fn map_check(
    name: &'static str,
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> Check {
    let options = libbpf_rs::libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
        ..Default::default()
    };
    match MapHandle::create(
        map_type,
        Some("nqm_doctor"),
        key_size,
        value_size,
        max_entries,
        &options,
    ) {
        Ok(map) => {
            drop(map);
            Check {
                name,
                status: Status::Ok,
                detail: String::new(),
                required: true,
            }
        }
        Err(error) => Check {
            name,
            status: Status::Fail,
            detail: error.to_string(),
            required: true,
        },
    }
}

fn hfo_check() -> Check {
    let Ok(firewall) = fs::read_to_string("/etc/config/firewall") else {
        return Check {
            name: "HFO",
            status: Status::Unknown,
            detail: "OpenWrt firewall config unavailable".into(),
            required: false,
        };
    };
    let enabled = firewall_hw_flow_offload_enabled(&firewall);
    Check {
        name: "HFO",
        status: if enabled { Status::Warn } else { Status::Ok },
        detail: if enabled {
            "ON; traffic accounting may be incomplete"
        } else {
            "OFF"
        }
        .into(),
        required: false,
    }
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
                && matches!(
                    fields[2]
                        .trim_matches(|character| character == '\'' || character == '"')
                        .to_ascii_lowercase()
                        .as_str(),
                    "1" | "on" | "true" | "yes" | "enabled"
                )
        })
}

#[cfg(test)]
mod tests {
    use super::{CapabilityReport, Check, Status, firewall_hw_flow_offload_enabled};

    #[test]
    fn required_failure_controls_health_and_report_is_tabular() {
        let report = CapabilityReport {
            checks: vec![
                Check {
                    name: "Kernel",
                    status: Status::Ok,
                    detail: "6.6".into(),
                    required: true,
                },
                Check {
                    name: "HFO",
                    status: Status::Warn,
                    detail: "ON".into(),
                    required: false,
                },
            ],
            topology: None,
            attach_backend: None,
            attach_detail: String::new(),
            capture_interface: "br-lan".into(),
        };
        assert!(report.is_healthy());
        assert!(report.to_string().contains("Kernel         OK"));

        let report = CapabilityReport {
            checks: vec![Check {
                name: "Ringbuf",
                status: Status::Fail,
                detail: "unsupported".into(),
                required: true,
            }],
            topology: None,
            attach_backend: None,
            attach_detail: String::new(),
            capture_interface: "br-lan".into(),
        };
        assert!(!report.is_healthy());
    }

    #[test]
    fn tc_failure_mentions_required_kernel_modules() {
        let check = Check {
            name: "TC clsact",
            status: Status::Fail,
            detail: "failed to attach; missing required kernel modules: kmod-sched-core, kmod-sched-bpf (install via: opkg install kmod-sched-core kmod-sched-bpf)".into(),
            required: true,
        };
        assert!(check.detail.contains("kmod-sched-core"));
        assert!(check.detail.contains("kmod-sched-bpf"));
    }

    #[test]
    fn parses_firewall_hardware_offload_uci_values() {
        assert!(firewall_hw_flow_offload_enabled(
            "config defaults\n\toption flow_offloading_hw '1'\n"
        ));
        assert!(firewall_hw_flow_offload_enabled(
            "config defaults\n\toption flow_offloading_hw \"enabled\"\n"
        ));
        assert!(!firewall_hw_flow_offload_enabled(
            "config defaults\n\t# option flow_offloading_hw '1'\n\toption flow_offloading_hw '0'\n"
        ));
    }
}
