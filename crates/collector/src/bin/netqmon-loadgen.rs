use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netqmon_protocol::v1::{
    AgentHealth, CounterSanityStatus, DeviceObservation, Direction, DnsObservation, DnsRecordType,
    EnrollRequest, EnrollResponse, FlowDelta, FlowLifecycle, OffloadStatus, TelemetryBatch,
};
use netqmon_protocol::{PROTOCOL_VERSION, encode_telemetry_batch};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Basic,
    Pipeline,
    Ipv6,
    Dns,
    All,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "basic" => Ok(Self::Basic),
            "pipeline" => Ok(Self::Pipeline),
            "ipv6" => Ok(Self::Ipv6),
            "dns" => Ok(Self::Dns),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "unknown scenario '{value}', expected basic, pipeline, ipv6, dns, or all"
            )),
        }
    }

    fn includes_pipeline(self) -> bool {
        matches!(self, Self::Basic | Self::Pipeline | Self::All)
    }

    fn includes_ipv6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::All)
    }

    fn includes_dns(self) -> bool {
        matches!(self, Self::Dns | Self::All)
    }
}

struct Config {
    address: String,
    enrollment_token: String,
    batches: u64,
    scenario: Scenario,
    boot_id: String,
    gateway_name: String,
    start_ms: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse(std::env::args().skip(1))?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config))
}

async fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let enrollment = enroll(&config).await?;
    for sequence in 1..=config.batches {
        let batch = batch(&config, &enrollment.gateway_id, sequence);
        let encoded = encode_telemetry_batch(&batch, 1)?;
        let mut headers = vec![
            ("Content-Type", "application/x-protobuf".to_owned()),
            (
                "Authorization",
                format!("Bearer {}", enrollment.agent_token),
            ),
        ];
        if let Some(encoding) = encoded.encoding.http_value() {
            headers.push(("Content-Encoding", encoding.to_owned()));
        }
        let (status, _) = post(
            &config.address,
            "/v1/ingest/telemetry",
            &headers,
            &encoded.body,
        )
        .await?;
        if status != 204 && status != 200 {
            return Err(format!("batch {sequence} returned HTTP {status}").into());
        }
        if config.scenario.includes_pipeline() {
            let samples = bittorrent_sample(&batch);
            let encoded = netqmon_protocol::encode_flow_sample_batch(&samples, usize::MAX)?;
            let (status, _) = post(
                &config.address,
                "/v1/ingest/samples",
                &[
                    ("Content-Type", "application/x-protobuf".into()),
                    (
                        "Authorization",
                        format!("Bearer {}", enrollment.agent_token),
                    ),
                ],
                &encoded.body,
            )
            .await?;
            if status != 204 {
                return Err(format!("sample batch {sequence} returned HTTP {status}").into());
            }
        }
        if sequence < config.batches {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    println!(
        "netqmon-loadgen sent {} {:?} telemetry batches",
        config.batches, config.scenario
    );
    Ok(())
}

// Synthetic IP/TCP packet exercises real Collector DPI instead of trusting a hint.
fn bittorrent_sample(batch: &TelemetryBatch) -> netqmon_protocol::v1::FlowSampleBatch {
    use netqmon_protocol::v1::{FlowSample, FlowSampleBatch, FlowSampleKey, SamplePacket};
    let flow = batch
        .flows
        .iter()
        .find(|flow| flow.remote_port == 51_413)
        .unwrap();
    let mut packet = vec![0u8; 108];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&108u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&flow.client_ip);
    packet[16..20].copy_from_slice(&flow.remote_ip);
    packet[20..22].copy_from_slice(&51_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&51_413u16.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x18;
    packet[40] = 19;
    packet[41..60].copy_from_slice(b"BitTorrent protocol");
    FlowSampleBatch {
        gateway_id: batch.gateway_id.clone(),
        boot_id: batch.boot_id.clone(),
        sequence: batch.sequence,
        sent_at: batch.sent_at,
        agent_version: batch.agent_version.clone(),
        protocol_version: PROTOCOL_VERSION,
        samples: vec![FlowSample {
            flow_id: format!("loadgen-bt-{}", batch.sequence),
            key: Some(FlowSampleKey {
                ip_version: 4,
                protocol: 6,
                client_ip: flow.client_ip.clone(),
                remote_ip: flow.remote_ip.clone(),
                client_port: flow.client_port,
                remote_port: flow.remote_port,
                first_seen_unix_ms: flow.first_seen_unix_ms,
            }),
            packets: vec![SamplePacket {
                direction: Direction::Upload.into(),
                timestamp_unix_ms: flow.last_seen_unix_ms,
                original_length: 108,
                captured_length: 108,
                payload: packet,
            }],
            total_captured_bytes: 108,
        }],
    }
}

impl Config {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut address = None;
        let mut enrollment_token = None;
        let mut batches = 3;
        let mut scenario = Scenario::All;
        let mut boot_id = format!("loadgen-boot-{}", now_ms());
        let mut gateway_name = "netqmon-loadgen".to_owned();
        let mut start_ms = now_ms();
        let mut positional = Vec::new();
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--scenario" => {
                    let value = arguments.next().ok_or("--scenario requires a value")?;
                    scenario = Scenario::parse(&value)?;
                }
                "--boot-id" => {
                    boot_id = arguments.next().ok_or("--boot-id requires a value")?;
                }
                "--gateway-name" => {
                    gateway_name = arguments.next().ok_or("--gateway-name requires a value")?;
                }
                "--start-ms" => {
                    let value = arguments.next().ok_or("--start-ms requires a value")?;
                    start_ms = value.parse()?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                value if value.starts_with('-') => {
                    return Err(format!("unknown option {value}").into());
                }
                value => positional.push(value.to_owned()),
            }
        }
        if let Some(value) = positional.first() {
            address = Some(value.clone());
        }
        if let Some(value) = positional.get(1) {
            enrollment_token = Some(value.clone());
        }
        if let Some(value) = positional.get(2) {
            batches = value.parse()?;
        }
        Ok(Self {
            address: address.ok_or("missing Collector address")?,
            enrollment_token: enrollment_token.ok_or("missing enrollment token")?,
            batches,
            scenario,
            boot_id,
            gateway_name,
            start_ms,
        })
    }
}

fn print_usage() {
    println!(
        "usage: netqmon-loadgen <collector-address> <enrollment-token> [batches] \
         [--scenario basic|pipeline|ipv6|dns|all] [--boot-id ID] [--gateway-name NAME] \
         [--start-ms UNIX_MS]"
    );
}

async fn enroll(config: &Config) -> Result<EnrollResponse, Box<dyn Error>> {
    let request = EnrollRequest {
        enrollment_token: config.enrollment_token.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: config.boot_id.clone(),
        gateway_name: config.gateway_name.clone(),
    };
    let (status, body) = post(
        &config.address,
        "/v1/ingest/enroll",
        &[("Content-Type", "application/x-protobuf".to_owned())],
        &request.encode_to_vec(),
    )
    .await?;
    if status != 200 {
        return Err(format!("enrollment returned HTTP {status}").into());
    }
    Ok(EnrollResponse::decode(body.as_slice())?)
}

fn batch(config: &Config, gateway_id: &str, sequence: u64) -> TelemetryBatch {
    let timestamp = config.start_ms + sequence * 1_000;
    let mut flows = Vec::new();
    let mut dns_observations = Vec::new();
    let device_observations = vec![
        device(
            [0x02, 0x00, 0x00, 0x00, 0x16, 0x01],
            ipv4(192, 0, 2, 10),
            "loadgen-laptop",
            timestamp,
        ),
        device(
            [0x02, 0x00, 0x00, 0x00, 0x16, 0x02],
            ipv6("2001:db8:22::10"),
            "loadgen-phone",
            timestamp,
        ),
    ];
    let lifecycle = if sequence == config.batches {
        FlowLifecycle::Ended
    } else {
        FlowLifecycle::Active
    };

    if config.scenario.includes_pipeline() {
        add_pipeline_traffic(
            &mut dns_observations,
            &mut flows,
            sequence,
            timestamp,
            lifecycle,
        );
    }

    if config.scenario.includes_dns() {
        add_dns_classification_traffic(
            &mut dns_observations,
            &mut flows,
            sequence,
            timestamp,
            lifecycle,
        );
    }

    if config.scenario.includes_ipv6() {
        add_ipv6_traffic(
            &mut dns_observations,
            &mut flows,
            sequence,
            timestamp,
            lifecycle,
        );
    }

    TelemetryBatch {
        gateway_id: gateway_id.to_owned(),
        boot_id: config.boot_id.clone(),
        sequence,
        sent_at: timestamp,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        flows,
        dns_observations,
        device_observations,
        device_discovery_observations: Vec::new(),
        health: Some(AgentHealth {
            observed_at_unix_ms: timestamp,
            uptime_seconds: sequence,
            tracked_flows: 3,
            kernel_version: "loadgen".to_owned(),
            openwrt_version: "synthetic".to_owned(),
            hardware_flow_offload: OffloadStatus::Disabled as i32,
            capture_interface: "synthetic0".to_owned(),
            interface_rx_bytes: 10_000 + sequence * 100,
            interface_tx_bytes: 20_000 + sequence * 100,
            interface_rx_packets: 100 + sequence,
            interface_tx_packets: 200 + sequence,
            interface_delta_bytes: 1_000,
            interface_delta_packets: 10,
            flow_delta_bytes: 1_000,
            flow_delta_packets: 10,
            interface_counter_sanity: CounterSanityStatus::Ok as i32,
            ..AgentHealth::default()
        }),
        probe_results: Vec::new(),
    }
}

fn add_pipeline_traffic(
    dns_observations: &mut Vec<DnsObservation>,
    flows: &mut Vec<FlowDelta>,
    sequence: u64,
    timestamp: u64,
    lifecycle: FlowLifecycle,
) {
    dns_observations.push(dns_a(
        ipv4(192, 0, 2, 10),
        "www.youtube.com",
        ipv4(203, 0, 113, 10),
        timestamp,
    ));
    flows.push(flow(
        ipv4(192, 0, 2, 10),
        50_000,
        ipv4(203, 0, 113, 10),
        443,
        Direction::Upload,
        1_200 + sequence * 10,
        9_000 + sequence * 20,
        timestamp,
        lifecycle,
        Some([0x02, 0x00, 0x00, 0x00, 0x16, 0x01]),
        "",
    ));
    flows.push(flow(
        ipv4(192, 0, 2, 10),
        51_000,
        ipv4(198, 51, 100, 77),
        51_413,
        Direction::Upload,
        4_000 + sequence * 30,
        7_500 + sequence * 40,
        timestamp,
        lifecycle,
        Some([0x02, 0x00, 0x00, 0x00, 0x16, 0x01]),
        "",
    ));
}

fn add_dns_classification_traffic(
    dns_observations: &mut Vec<DnsObservation>,
    flows: &mut Vec<FlowDelta>,
    sequence: u64,
    timestamp: u64,
    lifecycle: FlowLifecycle,
) {
    dns_observations.push(dns_a(
        ipv4(192, 0, 2, 10),
        "github.com",
        ipv4(203, 0, 113, 20),
        timestamp,
    ));
    flows.push(flow(
        ipv4(192, 0, 2, 10),
        52_000,
        ipv4(203, 0, 113, 20),
        443,
        Direction::Upload,
        2_000 + sequence * 20,
        3_000 + sequence * 30,
        timestamp,
        lifecycle,
        Some([0x02, 0x00, 0x00, 0x00, 0x16, 0x01]),
        "",
    ));
}

fn add_ipv6_traffic(
    dns_observations: &mut Vec<DnsObservation>,
    flows: &mut Vec<FlowDelta>,
    sequence: u64,
    timestamp: u64,
    lifecycle: FlowLifecycle,
) {
    dns_observations.push(DnsObservation {
        client_ip: ipv6("2001:db8:22::10"),
        domain: "claude.ai".to_owned(),
        answer_ip: ipv6("2001:db8:22::443"),
        record_type: DnsRecordType::Aaaa as i32,
        ttl_seconds: 300,
        observed_at_unix_ms: timestamp,
    });
    flows.push(flow(
        ipv6("2001:db8:22::10"),
        53_000,
        ipv6("2001:db8:22::443"),
        443,
        Direction::Upload,
        1_500 + sequence * 15,
        4_500 + sequence * 45,
        timestamp,
        lifecycle,
        Some([0x02, 0x00, 0x00, 0x00, 0x16, 0x02]),
        "",
    ));
}

fn device(mac: [u8; 6], ip: Vec<u8>, hostname: &str, timestamp: u64) -> DeviceObservation {
    DeviceObservation {
        mac: mac.to_vec(),
        ip,
        hostname: hostname.to_owned(),
        last_seen_unix_ms: timestamp,
        dhcp: None,
    }
}

fn dns_a(client_ip: Vec<u8>, domain: &str, answer_ip: Vec<u8>, timestamp: u64) -> DnsObservation {
    DnsObservation {
        client_ip,
        domain: domain.to_owned(),
        answer_ip,
        record_type: DnsRecordType::A as i32,
        ttl_seconds: 300,
        observed_at_unix_ms: timestamp,
    }
}

#[allow(clippy::too_many_arguments)]
fn flow(
    client_ip: Vec<u8>,
    client_port: u32,
    remote_ip: Vec<u8>,
    remote_port: u32,
    direction: Direction,
    upload_bytes: u64,
    download_bytes: u64,
    timestamp: u64,
    lifecycle: FlowLifecycle,
    client_mac: Option<[u8; 6]>,
    _legacy_hint: &str,
) -> FlowDelta {
    FlowDelta {
        ip_version: if client_ip.len() == 16 { 6 } else { 4 },
        protocol: 6,
        client_ip,
        client_port,
        remote_ip,
        remote_port,
        direction: direction as i32,
        upload_bytes,
        download_bytes,
        packets: 6,
        first_seen_unix_ms: timestamp.saturating_sub(200),
        last_seen_unix_ms: timestamp,
        lifecycle: lifecycle as i32,
        client_mac: client_mac.map_or_else(Vec::new, |mac| mac.to_vec()),
        protocol_hint: String::new(),
        ..FlowDelta::default()
    }
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> Vec<u8> {
    Ipv4Addr::new(a, b, c, d).octets().to_vec()
}

fn ipv6(value: &str) -> Vec<u8> {
    value
        .parse::<Ipv6Addr>()
        .expect("hard-coded IPv6 address must be valid")
        .octets()
        .to_vec()
}

async fn post(
    address: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("HTTP response has no header terminator")?;
    let headers = std::str::from_utf8(&response[..separator])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP response has no status")?
        .parse()?;
    Ok((status, response[separator + 4..].to_vec()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
