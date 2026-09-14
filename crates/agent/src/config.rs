use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use http::Uri;
use serde::Deserialize;

pub const DEFAULT_INTERFACE: &str = "br-lan";
pub const DEFAULT_CONTROLLER_URL: &str = "http://127.0.0.1:8090";
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_BATCH_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_FLOWS: u32 = 65_536;
pub const DEFAULT_RETRY_BUFFER_SECONDS: u64 = 60;
pub const DEFAULT_TELEMETRY_RETRY_BUFFER_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_TCP_IDLE_TIMEOUT_SECONDS: u64 = 120;
pub const DEFAULT_UDP_IDLE_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_SAMPLE_ENABLED: bool = true;
pub const DEFAULT_SAMPLE_MAX_PACKETS_PER_DIRECTION: u8 = 4;
pub const DEFAULT_SAMPLE_MAX_BYTES_PER_PACKET: usize = 1024;
pub const DEFAULT_SAMPLE_MAX_BYTES_PER_FLOW: usize = 4096;
pub const DEFAULT_INTERFACE_COUNTER_SANITY_ENABLED: bool = true;
pub const DEFAULT_INTERFACE_COUNTER_MIN_BYTES: u64 = 64 * 1024;
pub const DEFAULT_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO: u64 = 4;
pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
pub const DEFAULT_DIAGNOSTICS_ENABLED: bool = false;
pub const DEFAULT_TC_PRIORITY: u32 = 49_152;
pub const DEFAULT_TC_HANDLE: u32 = 0x4e51_4d01;
pub const MAX_INTERFACES: usize = 32;

#[derive(Debug, Parser)]
#[command(name = "netqmon-agent", version, about = "netqmon telemetry agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Read configuration from this TOML file.
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,

    /// Override the configured capture interface.
    #[arg(short, long, value_name = "NAME", global = true)]
    pub interface: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Load eBPF and run the telemetry agent.
    #[default]
    Run,
    /// Probe kernel and network capabilities, print a report, and exit.
    Doctor,
    /// Inspect or manage agent runtime diagnostics.
    Diagnostics(DiagnosticsArgs),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::Args)]
pub struct DiagnosticsArgs {
    /// Action to perform: enable, disable, or reset.
    #[command(subcommand)]
    pub action: Option<DiagnosticsAction>,

    /// Output diagnostics in JSON format.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
pub enum DiagnosticsAction {
    /// Enable diagnostics collection at runtime and persist in config.
    Enable,
    /// Disable diagnostics collection at runtime and persist in config.
    Disable,
    /// Reset cumulative diagnostics counters.
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub interface: String,
    pub interfaces: Vec<String>,
    pub controller_url: String,
    pub token: String,
    pub poll_interval_ms: u64,
    pub batch_interval_ms: u64,
    pub max_flows: u32,
    pub retry_buffer_seconds: u64,
    pub telemetry_retry_buffer_bytes: usize,
    pub tcp_idle_timeout_seconds: u64,
    pub udp_idle_timeout_seconds: u64,
    pub sample_enabled: bool,
    pub sample_max_packets_per_direction: u8,
    pub sample_max_bytes_per_packet: usize,
    pub sample_max_bytes_per_flow: usize,
    pub interface_counter_sanity_enabled: bool,
    pub interface_counter_min_bytes: u64,
    pub interface_counter_max_unaccounted_ratio: u64,
    pub log_level: LogLevel,
    pub diagnostics_enabled: bool,
    pub attach_backend: AttachBackend,
    pub attach_order: AttachOrder,
    pub topology_networks: Vec<ConfiguredNetwork>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttachBackend {
    #[default]
    Auto,
    Tcx,
    Netlink,
}

impl std::fmt::Display for AttachBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Tcx => "tcx",
            Self::Netlink => "netlink",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcxOrder {
    First,
    Last,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachOrder {
    pub tc_priority: u32,
    pub tc_handle: u32,
    pub tcx_order: TcxOrder,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredNetwork {
    pub subnet: String,
    pub role: String,
    pub interface: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => bail!("log_level must be one of error, warn, info, debug, or trace"),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            interface: DEFAULT_INTERFACE.into(),
            interfaces: vec![DEFAULT_INTERFACE.into()],
            controller_url: DEFAULT_CONTROLLER_URL.into(),
            token: String::new(),
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            batch_interval_ms: DEFAULT_BATCH_INTERVAL_MS,
            max_flows: DEFAULT_MAX_FLOWS,
            retry_buffer_seconds: DEFAULT_RETRY_BUFFER_SECONDS,
            telemetry_retry_buffer_bytes: DEFAULT_TELEMETRY_RETRY_BUFFER_BYTES,
            tcp_idle_timeout_seconds: DEFAULT_TCP_IDLE_TIMEOUT_SECONDS,
            udp_idle_timeout_seconds: DEFAULT_UDP_IDLE_TIMEOUT_SECONDS,
            sample_enabled: DEFAULT_SAMPLE_ENABLED,
            sample_max_packets_per_direction: DEFAULT_SAMPLE_MAX_PACKETS_PER_DIRECTION,
            sample_max_bytes_per_packet: DEFAULT_SAMPLE_MAX_BYTES_PER_PACKET,
            sample_max_bytes_per_flow: DEFAULT_SAMPLE_MAX_BYTES_PER_FLOW,
            interface_counter_sanity_enabled: DEFAULT_INTERFACE_COUNTER_SANITY_ENABLED,
            interface_counter_min_bytes: DEFAULT_INTERFACE_COUNTER_MIN_BYTES,
            interface_counter_max_unaccounted_ratio:
                DEFAULT_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO,
            log_level: DEFAULT_LOG_LEVEL,
            diagnostics_enabled: DEFAULT_DIAGNOSTICS_ENABLED,
            attach_backend: AttachBackend::Auto,
            attach_order: AttachOrder {
                tc_priority: DEFAULT_TC_PRIORITY,
                tc_handle: DEFAULT_TC_HANDLE,
                tcx_order: TcxOrder::Last,
            },
            topology_networks: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialConfig {
    sample: Option<PartialSampleConfig>,
    bpf: Option<PartialBpfConfig>,
    topology: Option<PartialTopologyConfig>,
    interface: Option<String>,
    interfaces: Option<Vec<String>>,
    controller_url: Option<String>,
    token: Option<String>,
    poll_interval_ms: Option<u64>,
    batch_interval_ms: Option<u64>,
    max_flows: Option<u32>,
    retry_buffer_seconds: Option<u64>,
    telemetry_retry_buffer_bytes: Option<usize>,
    tcp_idle_timeout_seconds: Option<u64>,
    udp_idle_timeout_seconds: Option<u64>,
    sample_enabled: Option<bool>,
    sample_max_packets_per_direction: Option<u8>,
    sample_max_bytes_per_packet: Option<usize>,
    sample_max_bytes_per_flow: Option<usize>,
    interface_counter_sanity_enabled: Option<bool>,
    interface_counter_min_bytes: Option<u64>,
    interface_counter_max_unaccounted_ratio: Option<u64>,
    log_level: Option<LogLevel>,
    diagnostics_enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialBpfConfig {
    backend: Option<AttachBackend>,
    tc_priority: Option<u32>,
    tc_handle: Option<u32>,
    tcx_order: Option<TcxOrder>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialTopologyConfig {
    #[serde(default)]
    networks: Vec<ConfiguredNetwork>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialSampleConfig {
    enabled: Option<bool>,
    max_packets_per_direction: Option<u8>,
    max_bytes_per_packet: Option<usize>,
    max_bytes_per_flow: Option<usize>,
}

impl AgentConfig {
    pub fn load(cli: &Cli) -> Result<Self> {
        Self::load_with_env(cli, |name| env::var_os(name))
    }

    fn load_with_env(cli: &Cli, get_env: impl Fn(&str) -> Option<OsString>) -> Result<Self> {
        let config_path = cli
            .config
            .clone()
            .or_else(|| get_env("NETQMON_CONFIG").map(PathBuf::from));
        let mut config = Self::default();

        if let Some(path) = config_path {
            config.apply(read_toml(&path)?);
        }

        let env_interfaces = env_string(&get_env, "NETQMON_INTERFACES")?
            .map(|value| split_interfaces(&value))
            .transpose()?;
        config.apply(PartialConfig {
            sample: None,
            bpf: None,
            topology: None,
            interface: if env_interfaces.is_none() {
                env_string(&get_env, "NETQMON_INTERFACE")?
            } else {
                None
            },
            interfaces: env_interfaces,
            controller_url: env_string(&get_env, "NETQMON_CONTROLLER_URL")?,
            token: env_string(&get_env, "NETQMON_TOKEN")?,
            poll_interval_ms: env_number(&get_env, "NETQMON_POLL_INTERVAL_MS")?,
            batch_interval_ms: env_number(&get_env, "NETQMON_BATCH_INTERVAL_MS")?,
            max_flows: env_number(&get_env, "NETQMON_MAX_FLOWS")?,
            retry_buffer_seconds: env_number(&get_env, "NETQMON_RETRY_BUFFER_SECONDS")?,
            telemetry_retry_buffer_bytes: env_number(
                &get_env,
                "NETQMON_TELEMETRY_RETRY_BUFFER_BYTES",
            )?,
            tcp_idle_timeout_seconds: env_number(&get_env, "NETQMON_TCP_IDLE_TIMEOUT_SECONDS")?,
            udp_idle_timeout_seconds: env_number(&get_env, "NETQMON_UDP_IDLE_TIMEOUT_SECONDS")?,
            sample_enabled: env_bool(&get_env, "NETQMON_SAMPLE_ENABLED")?,
            sample_max_packets_per_direction: env_number(
                &get_env,
                "NETQMON_SAMPLE_MAX_PACKETS_PER_DIRECTION",
            )?,
            sample_max_bytes_per_packet: env_number(
                &get_env,
                "NETQMON_SAMPLE_MAX_BYTES_PER_PACKET",
            )?,
            sample_max_bytes_per_flow: env_number(&get_env, "NETQMON_SAMPLE_MAX_BYTES_PER_FLOW")?,
            interface_counter_sanity_enabled: env_bool(
                &get_env,
                "NETQMON_INTERFACE_COUNTER_SANITY_ENABLED",
            )?,
            interface_counter_min_bytes: env_number(
                &get_env,
                "NETQMON_INTERFACE_COUNTER_MIN_BYTES",
            )?,
            interface_counter_max_unaccounted_ratio: env_number(
                &get_env,
                "NETQMON_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO",
            )?,
            log_level: env_string(&get_env, "NETQMON_LOG_LEVEL")?
                .map(|value| value.parse())
                .transpose()?,
            diagnostics_enabled: env_bool(&get_env, "NETQMON_DIAGNOSTICS_ENABLED")?,
        });

        if !cli.interface.is_empty() {
            config.set_interfaces(cli.interface.clone());
        }
        config.validate()?;
        Ok(config)
    }

    fn apply(&mut self, partial: PartialConfig) {
        if let Some(bpf) = partial.bpf {
            if let Some(value) = bpf.backend {
                self.attach_backend = value;
            }
            if let Some(value) = bpf.tc_priority {
                self.attach_order.tc_priority = value;
            }
            if let Some(value) = bpf.tc_handle {
                self.attach_order.tc_handle = value;
            }
            if let Some(value) = bpf.tcx_order {
                self.attach_order.tcx_order = value;
            }
        }
        if let Some(topology) = partial.topology {
            self.topology_networks = topology.networks;
        }
        if let Some(sample) = partial.sample {
            if let Some(value) = sample.enabled {
                self.sample_enabled = value;
            }
            if let Some(value) = sample.max_packets_per_direction {
                self.sample_max_packets_per_direction = value;
            }
            if let Some(value) = sample.max_bytes_per_packet {
                self.sample_max_bytes_per_packet = value;
            }
            if let Some(value) = sample.max_bytes_per_flow {
                self.sample_max_bytes_per_flow = value;
            }
        }
        if let Some(value) = partial.interface {
            self.set_interfaces(vec![value]);
        }
        if let Some(value) = partial.interfaces {
            self.set_interfaces(value);
        }
        if let Some(value) = partial.controller_url {
            self.controller_url = value;
        }
        if let Some(value) = partial.token {
            self.token = value;
        }
        if let Some(value) = partial.poll_interval_ms {
            self.poll_interval_ms = value;
        }
        if let Some(value) = partial.batch_interval_ms {
            self.batch_interval_ms = value;
        }
        if let Some(value) = partial.max_flows {
            self.max_flows = value;
        }
        if let Some(value) = partial.retry_buffer_seconds {
            self.retry_buffer_seconds = value;
        }
        if let Some(value) = partial.telemetry_retry_buffer_bytes {
            self.telemetry_retry_buffer_bytes = value;
        }
        if let Some(value) = partial.tcp_idle_timeout_seconds {
            self.tcp_idle_timeout_seconds = value;
        }
        if let Some(value) = partial.udp_idle_timeout_seconds {
            self.udp_idle_timeout_seconds = value;
        }
        if let Some(value) = partial.sample_enabled {
            self.sample_enabled = value;
        }
        if let Some(value) = partial.sample_max_packets_per_direction {
            self.sample_max_packets_per_direction = value;
        }
        if let Some(value) = partial.sample_max_bytes_per_packet {
            self.sample_max_bytes_per_packet = value;
        }
        if let Some(value) = partial.sample_max_bytes_per_flow {
            self.sample_max_bytes_per_flow = value;
        }
        if let Some(value) = partial.interface_counter_sanity_enabled {
            self.interface_counter_sanity_enabled = value;
        }
        if let Some(value) = partial.interface_counter_min_bytes {
            self.interface_counter_min_bytes = value;
        }
        if let Some(value) = partial.interface_counter_max_unaccounted_ratio {
            self.interface_counter_max_unaccounted_ratio = value;
        }
        if let Some(value) = partial.log_level {
            self.log_level = value;
        }
        if let Some(value) = partial.diagnostics_enabled {
            self.diagnostics_enabled = value;
        }
    }

    fn validate(&self) -> Result<()> {
        if self.interfaces.is_empty() || self.interfaces.len() > MAX_INTERFACES {
            bail!("interfaces must contain between 1 and {MAX_INTERFACES} entries");
        }
        if self.interface != self.interfaces[0] {
            bail!("primary interface must be the first interfaces entry");
        }
        let mut unique = std::collections::HashSet::new();
        for interface in &self.interfaces {
            if interface.is_empty() || interface.len() > 15 {
                bail!("interface must contain between 1 and 15 bytes");
            }
            if interface.bytes().any(|byte| byte == 0 || byte == b'/') {
                bail!("interface contains an invalid character");
            }
            if !unique.insert(interface) {
                bail!("interfaces must not contain duplicates");
            }
        }

        let uri = self
            .controller_url
            .parse::<Uri>()
            .context("controller_url is not a valid URI")?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            bail!("controller_url must be an absolute HTTP or HTTPS URL");
        }
        if self.token.chars().any(char::is_control) {
            bail!("token must not contain control characters");
        }
        if self.poll_interval_ms == 0 {
            bail!("poll_interval_ms must be greater than zero");
        }
        if self.batch_interval_ms == 0 {
            bail!("batch_interval_ms must be greater than zero");
        }
        if self.max_flows == 0 {
            bail!("max_flows must be greater than zero");
        }
        if self.retry_buffer_seconds == 0 {
            bail!("retry_buffer_seconds must be greater than zero");
        }
        if self.telemetry_retry_buffer_bytes == 0 {
            bail!("telemetry_retry_buffer_bytes must be greater than zero");
        }
        if self.tcp_idle_timeout_seconds == 0 {
            bail!("tcp_idle_timeout_seconds must be greater than zero");
        }
        if self.udp_idle_timeout_seconds == 0 {
            bail!("udp_idle_timeout_seconds must be greater than zero");
        }
        if self.sample_max_packets_per_direction == 0 || self.sample_max_packets_per_direction > 32
        {
            bail!("sample_max_packets_per_direction must be between 1 and 32");
        }
        if self.sample_max_bytes_per_packet == 0 || self.sample_max_bytes_per_packet > 4096 {
            bail!("sample_max_bytes_per_packet must be between 1 and 4096");
        }
        if self.sample_max_bytes_per_flow == 0 || self.sample_max_bytes_per_flow > 65536 {
            bail!("sample_max_bytes_per_flow must be between 1 and 65536");
        }
        if self.interface_counter_min_bytes == 0 {
            bail!("interface_counter_min_bytes must be greater than zero");
        }
        if self.interface_counter_max_unaccounted_ratio == 0 {
            bail!("interface_counter_max_unaccounted_ratio must be greater than zero");
        }
        if self.attach_order.tc_priority == 0 || self.attach_order.tc_priority > u16::MAX.into() {
            bail!("bpf.tc_priority must be between 1 and 65535");
        }
        if self.attach_order.tc_handle == 0 {
            bail!("bpf.tc_handle must be greater than zero");
        }
        for network in &self.topology_networks {
            if network.subnet.trim().is_empty() {
                bail!("topology network subnet must not be empty");
            }
            if !matches!(
                network.role.as_str(),
                "lan" | "routed_lan" | "tunnel" | "wan" | "unknown"
            ) {
                bail!("topology network role must be lan, routed_lan, tunnel, wan, or unknown");
            }
        }
        Ok(())
    }

    fn set_interfaces(&mut self, interfaces: Vec<String>) {
        if let Some(primary) = interfaces.first() {
            self.interface.clone_from(primary);
        }
        self.interfaces = interfaces;
    }
}

fn split_interfaces(value: &str) -> Result<Vec<String>> {
    let interfaces = value
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if interfaces.iter().any(String::is_empty) {
        bail!("NETQMON_INTERFACES must be a comma-separated list of interface names");
    }
    Ok(interfaces)
}

fn read_toml(path: &Path) -> Result<PartialConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

fn env_string(get_env: &impl Fn(&str) -> Option<OsString>, name: &str) -> Result<Option<String>> {
    get_env(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("{name} must be valid UTF-8"))
        })
        .transpose()
}

fn env_number<T>(get_env: &impl Fn(&str) -> Option<OsString>, name: &str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env_string(get_env, name)?
        .map(|value| {
            value
                .parse::<T>()
                .with_context(|| format!("{name} must be a positive integer"))
        })
        .transpose()
}

fn env_bool(get_env: &impl Fn(&str) -> Option<OsString>, name: &str) -> Result<Option<bool>> {
    env_string(get_env, name)?
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => value
                .parse::<bool>()
                .with_context(|| format!("{name} must be true or false, or 1 or 0")),
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::{
        AgentConfig, Cli, DEFAULT_BATCH_INTERVAL_MS, DEFAULT_CONTROLLER_URL, DEFAULT_INTERFACE,
        DEFAULT_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO, DEFAULT_INTERFACE_COUNTER_MIN_BYTES,
        DEFAULT_LOG_LEVEL, DEFAULT_MAX_FLOWS, DEFAULT_POLL_INTERVAL_MS,
        DEFAULT_RETRY_BUFFER_SECONDS, DEFAULT_TCP_IDLE_TIMEOUT_SECONDS,
        DEFAULT_UDP_IDLE_TIMEOUT_SECONDS, LogLevel,
    };
    use clap::Parser as _;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::fs;

    #[test]
    fn nested_sample_config_and_hard_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "[sample]\nenabled = false\nmax_bytes_per_flow = 4096\nmax_packets_per_direction = 4\nmax_bytes_per_packet = 1024\n").unwrap();
        let config =
            AgentConfig::load_with_env(&cli(&["--config", path.to_str().unwrap()]), |_| None)
                .unwrap();
        assert!(!config.sample_enabled);
        assert_eq!(config.sample_max_bytes_per_flow, 4096);
        for (name, value) in [
            ("NETQMON_SAMPLE_MAX_BYTES_PER_FLOW", "65537"),
            ("NETQMON_SAMPLE_MAX_PACKETS_PER_DIRECTION", "33"),
            ("NETQMON_SAMPLE_MAX_BYTES_PER_PACKET", "4097"),
        ] {
            assert!(
                AgentConfig::load_with_env(&cli(&[]), |key| (key == name)
                    .then(|| OsString::from(value)))
                .is_err()
            );
        }
    }

    #[test]
    fn reads_attach_backend_order_and_explicit_networks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(
            &path,
            r#"
[bpf]
backend = "netlink"
tc_priority = 32000
tc_handle = 1312902401
tcx_order = "first"

[[topology.networks]]
subnet = "192.168.10.0/24"
role = "routed_lan"

[[topology.networks]]
subnet = "10.10.10.0/24"
role = "tunnel"
interface = "tun0"
"#,
        )
        .unwrap();
        let config =
            AgentConfig::load_with_env(&cli(&["--config", path.to_str().unwrap()]), |_| None)
                .unwrap();
        assert_eq!(config.attach_backend, super::AttachBackend::Netlink);
        assert_eq!(config.attach_order.tc_priority, 32_000);
        assert_eq!(config.attach_order.tcx_order, super::TcxOrder::First);
        assert_eq!(config.topology_networks.len(), 2);
        assert_eq!(
            config.topology_networks[1].interface.as_deref(),
            Some("tun0")
        );
    }

    #[test]
    fn provides_documented_defaults() {
        let config = AgentConfig::load_with_env(&cli(&[]), |_| None).unwrap();
        assert_eq!(config.interface, DEFAULT_INTERFACE);
        assert_eq!(config.interfaces, [DEFAULT_INTERFACE]);
        assert_eq!(config.controller_url, DEFAULT_CONTROLLER_URL);
        assert_eq!(config.poll_interval_ms, DEFAULT_POLL_INTERVAL_MS);
        assert_eq!(config.batch_interval_ms, DEFAULT_BATCH_INTERVAL_MS);
        assert_eq!(config.max_flows, DEFAULT_MAX_FLOWS);
        assert_eq!(config.retry_buffer_seconds, DEFAULT_RETRY_BUFFER_SECONDS);
        assert_eq!(
            config.tcp_idle_timeout_seconds,
            DEFAULT_TCP_IDLE_TIMEOUT_SECONDS
        );
        assert_eq!(
            config.udp_idle_timeout_seconds,
            DEFAULT_UDP_IDLE_TIMEOUT_SECONDS
        );
        assert!(config.interface_counter_sanity_enabled);
        assert_eq!(
            config.interface_counter_min_bytes,
            DEFAULT_INTERFACE_COUNTER_MIN_BYTES
        );
        assert_eq!(
            config.interface_counter_max_unaccounted_ratio,
            DEFAULT_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO
        );
        assert_eq!(config.log_level, DEFAULT_LOG_LEVEL);
        assert!(config.token.is_empty());
    }

    #[test]
    fn merges_toml_environment_and_cli_in_priority_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        fs::write(
            &path,
            r#"
interface = "from-file"
controller_url = "http://192.0.2.10:8090"
token = "file-token"
poll_interval_ms = 2000
batch_interval_ms = 3000
max_flows = 1234
retry_buffer_seconds = 90
tcp_idle_timeout_seconds = 150
udp_idle_timeout_seconds = 45
interface_counter_sanity_enabled = true
interface_counter_min_bytes = 131072
interface_counter_max_unaccounted_ratio = 5
log_level = "debug"
"#,
        )
        .unwrap();
        let variables = HashMap::from([
            ("NETQMON_INTERFACE", "from-env"),
            ("NETQMON_TOKEN", "env-token"),
            ("NETQMON_POLL_INTERVAL_MS", "4000"),
            ("NETQMON_UDP_IDLE_TIMEOUT_SECONDS", "50"),
            ("NETQMON_INTERFACE_COUNTER_MIN_BYTES", "262144"),
            ("NETQMON_LOG_LEVEL", "warn"),
        ]);
        let arguments = [
            "netqmon-agent",
            "--config",
            path.to_str().unwrap(),
            "--interface",
            "from-cli",
        ];

        let config = AgentConfig::load_with_env(&cli(&arguments[1..]), |name| {
            variables.get(name).map(OsString::from)
        })
        .unwrap();

        assert_eq!(config.interface, "from-cli");
        assert_eq!(config.interfaces, ["from-cli"]);
        assert_eq!(config.token, "env-token");
        assert_eq!(config.poll_interval_ms, 4000);
        assert_eq!(config.batch_interval_ms, 3000);
        assert_eq!(config.max_flows, 1234);
        assert_eq!(config.retry_buffer_seconds, 90);
        assert_eq!(config.tcp_idle_timeout_seconds, 150);
        assert_eq!(config.udp_idle_timeout_seconds, 50);
        assert!(config.interface_counter_sanity_enabled);
        assert_eq!(config.interface_counter_min_bytes, 262_144);
        assert_eq!(config.interface_counter_max_unaccounted_ratio, 5);
        assert_eq!(config.log_level, LogLevel::Warn);
    }

    #[test]
    fn ordered_interfaces_support_file_env_and_repeated_cli_overrides() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        fs::write(
            &path,
            "interface = \"legacy0\"\ninterfaces = [\"lan0\", \"tun0\"]\n",
        )
        .unwrap();
        let file =
            AgentConfig::load_with_env(&cli(&["--config", path.to_str().unwrap()]), |_| None)
                .unwrap();
        assert_eq!(file.interfaces, ["lan0", "tun0"]);
        assert_eq!(file.interface, "lan0");

        let env = AgentConfig::load_with_env(&cli(&[]), |name| {
            (name == "NETQMON_INTERFACES").then(|| OsString::from("br-lan, tun0"))
        })
        .unwrap();
        assert_eq!(env.interfaces, ["br-lan", "tun0"]);

        let cli = AgentConfig::load_with_env(
            &cli(&["--interface", "eth1", "--interface", "wg0"]),
            |_| None,
        )
        .unwrap();
        assert_eq!(cli.interfaces, ["eth1", "wg0"]);
    }

    #[test]
    fn rejects_empty_duplicate_or_excessive_interfaces() {
        for value in ["", "eth1,eth1"] {
            let result = AgentConfig::load_with_env(&cli(&[]), |name| {
                (name == "NETQMON_INTERFACES").then(|| OsString::from(value))
            });
            assert!(result.is_err(), "{value:?}");
        }
        let too_many = (0..33)
            .map(|index| format!("i{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            AgentConfig::load_with_env(&cli(&[]), |name| {
                (name == "NETQMON_INTERFACES").then(|| OsString::from(&too_many))
            })
            .is_err()
        );
    }

    #[test]
    fn accepts_openwrt_boolean_environment_values() {
        for (raw, expected) in [("1", true), ("0", false), ("true", true), ("false", false)] {
            let variables = HashMap::from([("NETQMON_SAMPLE_ENABLED", raw)]);
            let config = AgentConfig::load_with_env(&cli(&[]), |name| {
                variables.get(name).map(OsString::from)
            })
            .unwrap();
            assert_eq!(config.sample_enabled, expected, "{raw}");
        }
    }

    #[test]
    fn reads_sample_budget_environment_values() {
        let variables = HashMap::from([
            ("NETQMON_SAMPLE_MAX_PACKETS_PER_DIRECTION", "2"),
            ("NETQMON_SAMPLE_MAX_BYTES_PER_PACKET", "64"),
            ("NETQMON_SAMPLE_MAX_BYTES_PER_FLOW", "96"),
        ]);

        let config =
            AgentConfig::load_with_env(&cli(&[]), |name| variables.get(name).map(OsString::from))
                .unwrap();

        assert_eq!(config.sample_max_packets_per_direction, 2);
        assert_eq!(config.sample_max_bytes_per_packet, 64);
        assert_eq!(config.sample_max_bytes_per_flow, 96);
    }

    #[test]
    fn reads_interface_counter_sanity_environment_values() {
        let variables = HashMap::from([
            ("NETQMON_INTERFACE_COUNTER_SANITY_ENABLED", "0"),
            ("NETQMON_INTERFACE_COUNTER_MIN_BYTES", "4096"),
            ("NETQMON_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO", "3"),
        ]);

        let config =
            AgentConfig::load_with_env(&cli(&[]), |name| variables.get(name).map(OsString::from))
                .unwrap();

        assert!(!config.interface_counter_sanity_enabled);
        assert_eq!(config.interface_counter_min_bytes, 4096);
        assert_eq!(config.interface_counter_max_unaccounted_ratio, 3);
    }

    #[test]
    fn reads_log_level_environment_values() {
        let variables = HashMap::from([("NETQMON_LOG_LEVEL", "debug")]);

        let config =
            AgentConfig::load_with_env(&cli(&[]), |name| variables.get(name).map(OsString::from))
                .unwrap();

        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.log_level.as_str(), "debug");
    }

    #[test]
    fn rejects_invalid_values_and_unknown_toml_fields() {
        let variables = HashMap::from([("NETQMON_POLL_INTERVAL_MS", "0")]);
        let error =
            AgentConfig::load_with_env(&cli(&[]), |name| variables.get(name).map(OsString::from))
                .unwrap_err();
        assert!(error.to_string().contains("poll_interval_ms"));

        let variables = HashMap::from([("NETQMON_LOG_LEVEL", "verbose")]);
        let error =
            AgentConfig::load_with_env(&cli(&[]), |name| variables.get(name).map(OsString::from))
                .unwrap_err();
        assert!(error.to_string().contains("log_level"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid.toml");
        fs::write(&path, "unexpected = true\n").unwrap();
        let error =
            AgentConfig::load_with_env(&cli(&["--config", path.to_str().unwrap()]), |_| None)
                .unwrap_err();
        assert!(error.to_string().contains("failed to parse config file"));
    }

    #[test]
    fn clap_reports_invalid_cli_arguments() {
        let error = Cli::try_parse_from(["netqmon-agent", "--unknown"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }

    fn cli(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("netqmon-agent").chain(arguments.iter().copied()))
            .unwrap()
    }
}
