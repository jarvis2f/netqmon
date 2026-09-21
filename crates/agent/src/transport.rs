use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};

use portable_atomic::AtomicU64;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use http::Uri;
use netqmon_protocol::v1::{
    EnrollRequest, EnrollResponse, ProbeResult, TelemetryBatch, TelemetryResponse,
};
use netqmon_protocol::{PROTOCOL_VERSION, encode_telemetry_batch};
use prost::Message as _;
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;

pub(super) const DEFAULT_CREDENTIAL_PATH: &str = "/etc/netqmon/credentials.toml";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_ENROLL_RETRY_DELAY: Duration = Duration::from_secs(30);
const COMPRESSION_THRESHOLD_BYTES: usize = 1_024;

pub(super) struct TelemetryQueue {
    buffer: Option<Arc<TelemetryBuffer>>,
    stats: Arc<TransportStats>,
    worker: Option<JoinHandle<()>>,
}

/// Cumulative transport-level statistics shared between producer and sender.
#[derive(Debug, Default)]
pub(crate) struct TransportStats {
    pub sent_batches: AtomicU64,
    pub sent_flows: AtomicU64,
    pub sent_bytes: AtomicU64,
    pub queue_depth: AtomicU64,
    pub queue_high_watermark: AtomicU64,
    pub queue_bytes: AtomicU64,
    pub queue_high_watermark_bytes: AtomicU64,
    pub dropped_batches: AtomicU64,
    pub dropped_flows: AtomicU64,
    pub dropped_bytes: AtomicU64,
}

impl TransportStats {
    pub(crate) fn record_sent(&self, flow_count: u64, byte_count: u64) {
        self.sent_batches.fetch_add(1, Ordering::Relaxed);
        self.sent_flows.fetch_add(flow_count, Ordering::Relaxed);
        self.sent_bytes.fetch_add(byte_count, Ordering::Relaxed);
    }

    fn update_queue(&self, depth: u64, bytes: u64) {
        self.queue_depth.store(depth, Ordering::Relaxed);
        self.queue_bytes.store(bytes, Ordering::Relaxed);
        let mut current = self.queue_high_watermark.load(Ordering::Relaxed);
        while depth > current {
            match self.queue_high_watermark.compare_exchange_weak(
                current,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let mut current = self.queue_high_watermark_bytes.load(Ordering::Relaxed);
        while bytes > current {
            match self.queue_high_watermark_bytes.compare_exchange_weak(
                current,
                bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn record_dropped(&self, batch: &TelemetryBatch, encoded_bytes: usize) {
        self.dropped_batches.fetch_add(1, Ordering::Relaxed);
        self.dropped_flows
            .fetch_add(batch.flows.len() as u64, Ordering::Relaxed);
        self.dropped_bytes.fetch_add(
            u64::try_from(encoded_bytes).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

struct QueuedTelemetry {
    batch: TelemetryBatch,
    encoded_bytes: usize,
}

#[derive(Default)]
struct TelemetryBufferState {
    batches: VecDeque<QueuedTelemetry>,
    bytes: usize,
    closed: bool,
}

struct TelemetryBuffer {
    capacity_bytes: usize,
    state: Mutex<TelemetryBufferState>,
    available: Condvar,
    stats: Arc<TransportStats>,
}

impl TelemetryBuffer {
    fn new(capacity_bytes: usize, stats: Arc<TransportStats>) -> Self {
        Self {
            capacity_bytes,
            state: Mutex::new(TelemetryBufferState::default()),
            available: Condvar::new(),
            stats,
        }
    }

    fn push(&self, batch: TelemetryBatch) {
        let encoded_bytes = batch.encoded_len();
        let Ok(mut state) = self.state.lock() else {
            self.stats.record_dropped(&batch, encoded_bytes);
            return;
        };
        if state.closed || encoded_bytes > self.capacity_bytes {
            self.stats.record_dropped(&batch, encoded_bytes);
            return;
        }
        while state.bytes.saturating_add(encoded_bytes) > self.capacity_bytes {
            let Some(oldest) = state.batches.pop_front() else {
                break;
            };
            state.bytes = state.bytes.saturating_sub(oldest.encoded_bytes);
            self.stats
                .record_dropped(&oldest.batch, oldest.encoded_bytes);
        }
        state.bytes = state.bytes.saturating_add(encoded_bytes);
        state.batches.push_back(QueuedTelemetry {
            batch,
            encoded_bytes,
        });
        self.stats.update_queue(
            state.batches.len() as u64,
            u64::try_from(state.bytes).unwrap_or(u64::MAX),
        );
        drop(state);
        self.available.notify_one();
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<TelemetryBatch> {
        let state = self.state.lock().ok()?;
        let (mut state, _) = self
            .available
            .wait_timeout_while(state, timeout, |state| {
                state.batches.is_empty() && !state.closed
            })
            .ok()?;
        let queued = state.batches.pop_front()?;
        state.bytes = state.bytes.saturating_sub(queued.encoded_bytes);
        self.stats.update_queue(
            state.batches.len() as u64,
            u64::try_from(state.bytes).unwrap_or(u64::MAX),
        );
        Some(queued.batch)
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.available.notify_all();
    }
}

impl TelemetryQueue {
    pub(super) fn spawn(config: &AgentConfig, shutdown: Arc<AtomicBool>, boot_id: String) -> Self {
        let stats = Arc::new(TransportStats::default());
        let buffer = Arc::new(TelemetryBuffer::new(
            config.telemetry_retry_buffer_bytes,
            Arc::clone(&stats),
        ));
        let worker_buffer = Arc::clone(&buffer);
        let worker_stats = Arc::clone(&stats);
        let settings = SenderSettings {
            controller_url: config.controller_url.clone(),
            enrollment_token: config.token.clone(),
            credential_path: PathBuf::from(DEFAULT_CREDENTIAL_PATH),
            boot_id,
            gateway_name: gateway_name(),
        };
        let worker = thread::Builder::new()
            .name("netqmon-telemetry".into())
            .spawn(move || sender_loop(settings, worker_buffer, shutdown, worker_stats))
            .expect("telemetry sender thread must start");
        Self {
            buffer: Some(buffer),
            stats,
            worker: Some(worker),
        }
    }

    pub(super) fn submit(&self, batch: TelemetryBatch) {
        let Some(buffer) = &self.buffer else {
            return;
        };
        buffer.push(batch);
    }

    pub(super) fn dropped_batches(&self) -> u64 {
        self.stats.dropped_batches.load(Ordering::Relaxed)
    }

    pub(super) fn transport_stats(&self) -> &Arc<TransportStats> {
        &self.stats
    }

    pub(super) fn stop(mut self) {
        if let Some(buffer) = self.buffer.take() {
            buffer.close();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn controller_endpoints(base_url: &str) -> Vec<SocketAddr> {
    let Ok(uri) = base_url.parse::<Uri>() else {
        return Vec::new();
    };
    let Some(authority) = uri.authority() else {
        return Vec::new();
    };
    let port = authority
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    (authority.host(), port)
        .to_socket_addrs()
        .map_or_else(|_| Vec::new(), Iterator::collect)
}

#[derive(Clone, Debug)]
struct SenderSettings {
    controller_url: String,
    enrollment_token: String,
    credential_path: PathBuf,
    boot_id: String,
    gateway_name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct Credentials {
    gateway_id: String,
    agent_token: String,
}

#[allow(clippy::needless_pass_by_value)]
fn sender_loop(
    settings: SenderSettings,
    buffer: Arc<TelemetryBuffer>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<TransportStats>,
) {
    let mut credentials = load_credentials(&settings.credential_path).unwrap_or_else(|error| {
        eprintln!("telemetry credentials could not be loaded: {error:#}");
        None
    });
    let mut sequence = 0_u64;
    let mut probe_results = Vec::<ProbeResult>::new();
    let mut enroll_retry_delay = RETRY_DELAY;
    loop {
        let mut batch = match buffer.pop_timeout(RETRY_DELAY) {
            Some(batch) => batch,
            None if shutdown.load(Ordering::Relaxed) => break,
            None => continue,
        };
        sequence = sequence.saturating_add(1);
        batch.boot_id.clone_from(&settings.boot_id);
        batch.sequence = sequence;
        batch.probe_results.append(&mut probe_results);
        let batch_flow_count = batch.flows.len() as u64;
        let batch_byte_count = batch.flows.iter().fold(0_u64, |total, flow| {
            total
                .saturating_add(flow.upload_bytes)
                .saturating_add(flow.download_bytes)
        });

        loop {
            if credentials.is_none() {
                match enroll(&settings) {
                    Ok(enrolled) => {
                        if let Err(error) = save_credentials(&settings.credential_path, &enrolled) {
                            eprintln!("telemetry credentials could not be persisted: {error:#}");
                        }
                        credentials = Some(enrolled);
                        enroll_retry_delay = RETRY_DELAY;
                    }
                    Err(error) => {
                        eprintln!("agent enrollment failed: {error:#}");
                        let delay = if settings.enrollment_token.is_empty() {
                            MAX_ENROLL_RETRY_DELAY
                        } else {
                            let current = enroll_retry_delay;
                            enroll_retry_delay =
                                (enroll_retry_delay * 2).min(MAX_ENROLL_RETRY_DELAY);
                            current
                        };
                        if should_stop(&shutdown, delay) {
                            return;
                        }
                        continue;
                    }
                }
            }
            let credential = credentials.as_ref().expect("credentials initialized");
            batch.gateway_id.clone_from(&credential.gateway_id);
            match send_batch(&settings.controller_url, credential, &batch) {
                Ok(requests) => {
                    stats.record_sent(batch_flow_count, batch_byte_count);
                    probe_results.extend(requests.iter().map(crate::probe::execute));
                    break;
                }
                Err(SendError::Unauthorized) => {
                    eprintln!("telemetry credential was rejected; attempting enrollment again");
                    credentials = None;
                    enroll_retry_delay = RETRY_DELAY;
                }
                Err(SendError::Other(error)) => {
                    eprintln!("telemetry upload failed: {error:#}");
                }
            }
            if should_stop(&shutdown, RETRY_DELAY) {
                return;
            }
        }
    }
}

fn should_stop(shutdown: &AtomicBool, delay: Duration) -> bool {
    let interval = Duration::from_millis(100);
    let mut remaining = delay;
    while remaining > Duration::ZERO {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let step = remaining.min(interval);
        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
    shutdown.load(Ordering::Relaxed)
}

fn enroll(settings: &SenderSettings) -> Result<Credentials> {
    if settings.enrollment_token.is_empty() {
        bail!("NETQMON_TOKEN is empty");
    }
    let request = EnrollRequest {
        enrollment_token: settings.enrollment_token.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: settings.boot_id.clone(),
        gateway_name: settings.gateway_name.clone(),
    };
    let response = post(
        &settings.controller_url,
        "/v1/ingest/enroll",
        &[("Content-Type", "application/x-protobuf".to_owned())],
        &request.encode_to_vec(),
    )?;
    if response.status != 200 {
        bail!("collector returned HTTP {}", response.status);
    }
    let response = EnrollResponse::decode(response.body.as_slice())
        .context("collector returned an invalid enrollment response")?;
    if response.protocol_version != PROTOCOL_VERSION {
        bail!(
            "collector selected protocol {}, expected {}",
            response.protocol_version,
            PROTOCOL_VERSION
        );
    }
    if response.gateway_id.is_empty() || response.agent_token.is_empty() {
        bail!("collector returned empty gateway credentials");
    }
    Ok(Credentials {
        gateway_id: response.gateway_id,
        agent_token: response.agent_token,
    })
}

enum SendError {
    Unauthorized,
    Other(anyhow::Error),
}

fn send_batch(
    controller_url: &str,
    credentials: &Credentials,
    batch: &TelemetryBatch,
) -> Result<Vec<netqmon_protocol::v1::ProbeRequest>, SendError> {
    let encoded = encode_telemetry_batch(batch, COMPRESSION_THRESHOLD_BYTES)
        .map_err(|error| SendError::Other(error.into()))?;
    let mut headers = vec![
        ("Content-Type", "application/x-protobuf".to_owned()),
        (
            "Authorization",
            format!("Bearer {}", credentials.agent_token),
        ),
    ];
    if let Some(encoding) = encoded.encoding.http_value() {
        headers.push(("Content-Encoding", encoding.to_owned()));
    }
    let response = post(
        controller_url,
        "/v1/ingest/telemetry",
        &headers,
        &encoded.body,
    )
    .map_err(SendError::Other)?;
    match response.status {
        204 => Ok(Vec::new()),
        200 => TelemetryResponse::decode(response.body.as_slice())
            .map(|response| response.probe_requests)
            .map_err(|error| SendError::Other(error.into())),
        401 | 403 => Err(SendError::Unauthorized),
        status => Err(SendError::Other(anyhow!(
            "collector returned HTTP {status}"
        ))),
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn post(
    base_url: &str,
    endpoint: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<HttpResponse> {
    let uri: Uri = base_url.parse().context("invalid controller URL")?;
    if uri.scheme_str() != Some("http") {
        bail!("HTTPS transport is not available in this agent build");
    }
    let authority = uri.authority().context("controller URL has no authority")?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);
    let address = (host, port)
        .to_socket_addrs()
        .context("could not resolve controller address")?
        .next()
        .context("controller address did not resolve")?;
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .context("could not connect to controller")?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let base_path = uri.path().trim_end_matches('/');
    let path = format!("{base_path}{endpoint}");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> Result<HttpResponse> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no header terminator")?;
    let headers = std::str::from_utf8(&response[..separator]).context("invalid HTTP headers")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("HTTP response has no status")?
        .parse()
        .context("invalid HTTP status")?;
    Ok(HttpResponse {
        status,
        body: response[separator + 4..].to_vec(),
    })
}

fn load_credentials(path: &Path) -> Result<Option<Credentials>> {
    match fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents)
            .map(Some)
            .context("invalid credential file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("could not read credential file"),
    }
}

fn save_credentials(path: &Path, credentials: &Credentials) -> Result<()> {
    let parent = path.parent().context("credential path has no parent")?;
    fs::create_dir_all(parent).context("could not create credential directory")?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let contents = toml::to_string(credentials).context("could not encode credentials")?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context("could not create temporary credential file")?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path).context("could not install credential file")?;
    Ok(())
}

fn gateway_name() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "netqmon-openwrt".to_owned())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn credentials_round_trip_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let path = directory.path().join("credentials.toml");
        let credentials = Credentials {
            gateway_id: "gateway-1".into(),
            agent_token: "secret".into(),
        };
        save_credentials(&path, &credentials).unwrap();

        assert_eq!(load_credentials(&path).unwrap(), Some(credentials));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn telemetry_buffer_drops_oldest_batches_to_keep_the_latest() {
        let stats = Arc::new(TransportStats::default());
        let first = TelemetryBatch {
            gateway_id: "first".into(),
            ..TelemetryBatch::default()
        };
        let second = TelemetryBatch {
            gateway_id: "second".into(),
            ..TelemetryBatch::default()
        };
        let buffer = TelemetryBuffer::new(second.encoded_len(), Arc::clone(&stats));

        buffer.push(first);
        buffer.push(second);

        assert_eq!(
            buffer.pop_timeout(Duration::ZERO).unwrap().gateway_id,
            "second"
        );
        assert_eq!(stats.dropped_batches.load(Ordering::Relaxed), 1);
        assert_eq!(stats.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parses_protobuf_http_response_body() {
        let response = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abc");
    }

    #[test]
    fn resolves_literal_controller_endpoint() {
        assert_eq!(
            controller_endpoints("http://192.0.2.10:8090"),
            vec!["192.0.2.10:8090".parse().unwrap()]
        );
    }
}

/// Independent best-effort queue: samples never wait behind telemetry retries.
pub(super) struct SampleQueue {
    sender: Option<SyncSender<netqmon_protocol::v1::FlowSample>>,
    dropped: Arc<AtomicU64>,
    dropped_bytes: Arc<AtomicU64>,
    queued_items: Arc<AtomicU64>,
    queued_bytes: Arc<AtomicU64>,
    worker: Option<JoinHandle<()>>,
}

impl SampleQueue {
    pub(super) fn spawn(config: &AgentConfig, shutdown: Arc<AtomicBool>, boot_id: String) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<netqmon_protocol::v1::FlowSample>(256);
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_bytes = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let worker_bytes = Arc::clone(&dropped_bytes);
        let queued_items = Arc::new(AtomicU64::new(0));
        let queued_bytes = Arc::new(AtomicU64::new(0));
        let worker_queued_items = Arc::clone(&queued_items);
        let worker_queued_bytes = Arc::clone(&queued_bytes);
        let url = config.controller_url.clone();
        let worker = thread::Builder::new()
            .name("netqmon-samples".into())
            .spawn(move || {
                let mut sequence = 0u64;
                while !shutdown.load(Ordering::Relaxed) {
                    let first = match receiver.recv_timeout(Duration::from_millis(100)) {
                        Ok(sample) => sample,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let mut pending = vec![first];
                    pending.extend(receiver.try_iter().take(127));
                    let drained_bytes = pending
                        .iter()
                        .map(prost::Message::encoded_len)
                        .sum::<usize>();
                    worker_queued_items.fetch_sub(pending.len() as u64, Ordering::Relaxed);
                    worker_queued_bytes.fetch_sub(drained_bytes as u64, Ordering::Relaxed);
                    // Merge fragments of one flow, preserving each packet boundary.
                    let samples = merge_samples(pending);
                    let packet_count = samples.iter().map(|s| s.packets.len() as u64).sum::<u64>();
                    let byte_count = samples
                        .iter()
                        .map(|s| u64::from(s.total_captured_bytes))
                        .sum::<u64>();
                    sequence = sequence.saturating_add(1);
                    // Enrollment belongs to telemetry. Never race its credential writer.
                    let sent = load_credentials(Path::new(DEFAULT_CREDENTIAL_PATH))
                        .ok()
                        .flatten()
                        .is_some_and(|credentials| {
                            let batch = netqmon_protocol::v1::FlowSampleBatch {
                                gateway_id: credentials.gateway_id.clone(),
                                boot_id: boot_id.clone(),
                                sequence,
                                sent_at: crate::telemetry::unix_ms(std::time::SystemTime::now()),
                                agent_version: env!("CARGO_PKG_VERSION").into(),
                                protocol_version: PROTOCOL_VERSION,
                                samples,
                            };
                            send_samples(&url, &credentials, &batch).is_ok()
                        });
                    if !sent {
                        worker_dropped.fetch_add(packet_count, Ordering::Relaxed);
                        worker_bytes.fetch_add(byte_count, Ordering::Relaxed);
                    }
                }
            })
            .expect("sample sender thread must start");
        Self {
            sender: Some(sender),
            dropped,
            dropped_bytes,
            queued_items,
            queued_bytes,
            worker: Some(worker),
        }
    }

    pub(super) fn submit(&self, sample: netqmon_protocol::v1::FlowSample) {
        if let Some(sender) = &self.sender {
            let encoded_bytes = sample.encoded_len() as u64;
            self.queued_items.fetch_add(1, Ordering::Relaxed);
            self.queued_bytes
                .fetch_add(encoded_bytes, Ordering::Relaxed);
            if let Err(TrySendError::Full(sample) | TrySendError::Disconnected(sample)) =
                sender.try_send(sample)
            {
                self.queued_items.fetch_sub(1, Ordering::Relaxed);
                self.queued_bytes
                    .fetch_sub(encoded_bytes, Ordering::Relaxed);
                self.dropped
                    .fetch_add(sample.packets.len() as u64, Ordering::Relaxed);
                self.dropped_bytes
                    .fetch_add(u64::from(sample.total_captured_bytes), Ordering::Relaxed);
            }
        }
    }
    pub(super) fn drops(&self) -> (u64, u64) {
        (
            self.dropped.load(Ordering::Relaxed),
            self.dropped_bytes.load(Ordering::Relaxed),
        )
    }
    pub(super) fn queue_stats(&self) -> (u64, u64) {
        (
            self.queued_items.load(Ordering::Relaxed),
            self.queued_bytes.load(Ordering::Relaxed),
        )
    }
    pub(super) fn stop(mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn merge_samples(
    samples: impl IntoIterator<Item = netqmon_protocol::v1::FlowSample>,
) -> Vec<netqmon_protocol::v1::FlowSample> {
    let mut merged: Vec<netqmon_protocol::v1::FlowSample> = Vec::new();
    let mut indexes: HashMap<String, usize> = HashMap::new();
    for sample in samples {
        if let Some(&index) = indexes.get(&sample.flow_id) {
            let existing = &mut merged[index];
            existing.total_captured_bytes += sample.total_captured_bytes;
            existing.packets.extend(sample.packets);
        } else {
            indexes.insert(sample.flow_id.clone(), merged.len());
            merged.push(sample);
        }
    }
    merged
}

fn send_samples(
    url: &str,
    credentials: &Credentials,
    batch: &netqmon_protocol::v1::FlowSampleBatch,
) -> Result<()> {
    netqmon_protocol::validate_flow_sample_batch(batch)?;
    let encoded = netqmon_protocol::encode_flow_sample_batch(batch, COMPRESSION_THRESHOLD_BYTES)?;
    let mut headers = vec![
        ("Content-Type", "application/x-protobuf".into()),
        (
            "Authorization",
            format!("Bearer {}", credentials.agent_token),
        ),
    ];
    if let Some(encoding) = encoded.encoding.http_value() {
        headers.push(("Content-Encoding", encoding.into()));
    }
    let response = post(url, "/v1/ingest/samples", &headers, &encoded.body)?;
    if response.status != 204 && response.status != 200 {
        bail!("sample upload rejected: {}", response.status);
    }
    Ok(())
}

#[cfg(test)]
mod sample_queue_tests {
    use super::*;
    #[test]
    fn saturated_sample_queue_does_not_touch_telemetry_queue() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let queue = SampleQueue {
            sender: Some(sender),
            dropped: Arc::new(AtomicU64::new(0)),
            dropped_bytes: Arc::new(AtomicU64::new(0)),
            queued_items: Arc::new(AtomicU64::new(0)),
            queued_bytes: Arc::new(AtomicU64::new(0)),
            worker: None,
        };
        let sample = netqmon_protocol::v1::FlowSample {
            packets: vec![netqmon_protocol::v1::SamplePacket::default()],
            total_captured_bytes: 1024,
            ..Default::default()
        };
        queue.submit(sample.clone());
        queue.submit(sample);
        assert_eq!(queue.drops(), (1, 1024));
        let stats = Arc::new(TransportStats::default());
        let buffer = Arc::new(TelemetryBuffer::new(1024, Arc::clone(&stats)));
        let telemetry = TelemetryQueue {
            buffer: Some(buffer),
            stats,
            worker: None,
        };
        telemetry.submit(TelemetryBatch::default());
        assert_eq!(telemetry.stats.queue_depth.load(Ordering::Relaxed), 1);
        assert_eq!(telemetry.dropped_batches(), 0);
    }

    #[test]
    fn merges_samples_by_flow_id_preserving_first_seen_order_and_packets() {
        let packet = |timestamp_unix_ms| netqmon_protocol::v1::SamplePacket {
            timestamp_unix_ms,
            ..Default::default()
        };
        let samples = merge_samples([
            netqmon_protocol::v1::FlowSample {
                flow_id: "first".into(),
                packets: vec![packet(1)],
                total_captured_bytes: 10,
                ..Default::default()
            },
            netqmon_protocol::v1::FlowSample {
                flow_id: "second".into(),
                packets: vec![packet(2)],
                total_captured_bytes: 20,
                ..Default::default()
            },
            netqmon_protocol::v1::FlowSample {
                flow_id: "first".into(),
                packets: vec![packet(3)],
                total_captured_bytes: 30,
                ..Default::default()
            },
        ]);

        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].flow_id, "first");
        assert_eq!(samples[0].total_captured_bytes, 40);
        assert_eq!(
            samples[0]
                .packets
                .iter()
                .map(|packet| packet.timestamp_unix_ms)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(samples[1].flow_id, "second");
        assert_eq!(samples[1].total_captured_bytes, 20);
    }
}
