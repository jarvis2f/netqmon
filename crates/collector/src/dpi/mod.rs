//! Independent bounded DPI worker and payload-free, gateway-scoped diagnostics.
pub mod engine;
mod ndpi;

use engine::{DpiEngine, DpiFlow, DpiResult};
use netqmon_protocol::v1::{
    FlowSampleBatch, FlowSampleKey, SampleConfig, SamplePacket, TelemetryBatch,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

const CACHE_CAPACITY: usize = 4096;
const CACHE_TTL: Duration = Duration::from_secs(300);
const WINDOW: Duration = Duration::from_secs(3600);
type CacheKey = (String, String, String);

/// One application matched from sampled packet payloads by classifierd.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureApplicationMatch {
    pub application_id: String,
    pub confidence: f64,
}

/// Matches the bounded packets of a flow sample against Pro payload
/// signatures. Implementations must never block the DPI worker: a missing
/// classifier yields no matches.
pub trait SignatureMatcher: Send + Sync {
    fn match_sample(
        &self,
        key: &FlowSampleKey,
        packets: &[SamplePacket],
    ) -> Vec<SignatureApplicationMatch>;
}

/// Cached sample analysis for one flow: the nDPI result, the payload
/// signature matches, or both.
#[derive(Clone)]
pub struct CachedResult {
    pub gateway: String,
    pub boot: String,
    pub key: FlowSampleKey,
    pub last_packet_ms: u64,
    pub result: Option<DpiResult>,
    pub signatures: Vec<SignatureApplicationMatch>,
    expires: Instant,
}

#[cfg(test)]
impl CachedResult {
    pub(crate) fn for_test(
        gateway: String,
        boot: String,
        key: FlowSampleKey,
        last_packet_ms: u64,
        result: Option<DpiResult>,
    ) -> Self {
        Self {
            gateway,
            boot,
            key,
            last_packet_ms,
            result,
            signatures: Vec::new(),
            expires: Instant::now(),
        }
    }
}

/// Everything the attribution pipeline needs for one analysed flow.
#[derive(Clone, Default)]
pub struct SampleAnalysis {
    pub dpi: Option<DpiResult>,
    pub signatures: Vec<SignatureApplicationMatch>,
}
struct FlowState {
    key: FlowSampleKey,
    bytes: u32,
    packets: [usize; 2],
    last_packet_ms: u64,
    expires: Instant,
    engine: Option<Box<dyn DpiFlow>>,
    result: Option<DpiResult>,
    signatures: Vec<SignatureApplicationMatch>,
}
#[derive(Default)]
struct MinuteStats {
    samples: u64,
    bytes: u64,
    identified: u64,
    attempted: u64,
    drops: u64,
    internal_drops: u64,
    drop_bytes: u64,
    network_bytes: u64,
    new_flows: u64,
    theoretical_bytes: u64,
    // Exact bounded histogram of received FlowSample message sizes (0..65536).
    sizes: HashMap<u32, u64>,
}
struct Stats {
    started: Instant,
    buckets: VecDeque<(Instant, MinuteStats)>,
    configs: HashMap<String, SampleConfig>,
    endings: Vec<(String, String, netqmon_protocol::v1::FlowDelta, Instant)>,
    health: HashMap<(String, String), (u64, u64)>,
    seen_flows: HashMap<String, Instant>,
    results: HashMap<CacheKey, CachedResult>,
}
impl Default for Stats {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            buckets: VecDeque::new(),
            configs: HashMap::new(),
            endings: Vec::new(),
            health: HashMap::new(),
            seen_flows: HashMap::new(),
            results: HashMap::new(),
        }
    }
}
impl Stats {
    fn bucket(&mut self) -> &mut MinuteStats {
        let now = Instant::now();
        while self
            .buckets
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= WINDOW)
        {
            self.buckets.pop_front();
        }
        if self
            .buckets
            .back()
            .is_none_or(|(at, _)| now.duration_since(*at) >= Duration::from_secs(60))
        {
            self.buckets.push_back((now, MinuteStats::default()));
        }
        &mut self.buckets.back_mut().expect("bucket").1
    }
}

pub struct SamplingService {
    sender: mpsc::SyncSender<FlowSampleBatch>,
    stats: Arc<Mutex<Stats>>,
    enabled: bool,
    engine_name: &'static str,
}
impl SamplingService {
    #[allow(clippy::too_many_lines)]
    pub fn new(
        enabled: bool,
        engine: Arc<dyn DpiEngine>,
        signature_matcher: Arc<dyn SignatureMatcher>,
        completed: impl Fn(CachedResult) + Send + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<FlowSampleBatch>(8);
        let stats = Arc::new(Mutex::new(Stats::default()));
        let worker_stats = Arc::clone(&stats);
        let engine_name = engine.name();
        std::thread::Builder::new()
            .name("netqmon-dpi".into())
            .spawn(move || {
                let mut flows: HashMap<CacheKey, FlowState> = HashMap::new();
                let mut sequences: HashMap<(String, String), (u64, Instant)> = HashMap::new();
                loop {
                    let now = Instant::now();
                    // End markers are metadata only; allow queued samples to arrive before finalization.
                    let endings = {
                        let mut stats = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        stats
                            .endings
                            .retain(|(_, _, _, at)| now.duration_since(*at) < CACHE_TTL);
                        stats.endings.clone()
                    };
                    for (id, entry) in &mut flows {
                        let ended = endings.iter().any(|(gateway, boot, flow, at)| {
                            gateway == &id.0
                                && boot == &id.1
                                && now.duration_since(*at) >= Duration::from_secs(1)
                                && entry.key.client_ip == flow.client_ip
                                && entry.key.remote_ip == flow.remote_ip
                                && entry.key.client_port == flow.client_port
                                && entry.key.remote_port == flow.remote_port
                                && entry.key.protocol == flow.protocol
                                && entry.key.first_seen_unix_ms
                                    <= flow.last_seen_unix_ms.saturating_add(1)
                                && entry.last_packet_ms.saturating_add(1) >= flow.first_seen_unix_ms
                        });
                        if (entry.expires <= now || ended) && entry.engine.is_some() {
                            let result = entry.engine.as_mut().and_then(|engine| engine.finish());
                            if let Some(result) = result {
                                entry.result = Some(result);
                            }
                            entry.engine = None;
                            if entry.result.is_some() || !entry.signatures.is_empty() {
                                let cached = CachedResult {
                                    gateway: id.0.clone(),
                                    boot: id.1.clone(),
                                    key: entry.key.clone(),
                                    last_packet_ms: entry.last_packet_ms,
                                    result: entry.result.clone(),
                                    signatures: entry.signatures.clone(),
                                    expires: now + CACHE_TTL,
                                };
                                let mut stats = worker_stats
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                stats.results.retain(|_, value| value.expires > now);
                                if stats.results.len() < CACHE_CAPACITY
                                    || stats.results.contains_key(id)
                                {
                                    stats.results.insert(id.clone(), cached.clone());
                                }
                                drop(stats);
                                completed(cached);
                            }
                        }
                    }
                    flows.retain(|_, entry| entry.expires > now);
                    sequences.retain(|_, (_, expires)| *expires > now);
                    let batch = match receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(batch) => batch,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let sequence_key = (batch.gateway_id.clone(), batch.boot_id.clone());
                    if sequences
                        .get(&sequence_key)
                        .is_some_and(|(sequence, _)| *sequence >= batch.sequence)
                    {
                        continue;
                    }
                    if sequences.len() >= CACHE_CAPACITY && !sequences.contains_key(&sequence_key) {
                        continue;
                    }
                    sequences.insert(sequence_key, (batch.sequence, now + CACHE_TTL));
                    for sample in batch.samples {
                        let id = (
                            batch.gateway_id.clone(),
                            batch.boot_id.clone(),
                            sample.flow_id,
                        );
                        let key = sample.key.expect("validated sample");
                        let mut stats = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let bucket = stats.bucket();
                        bucket.samples += sample.packets.len() as u64;
                        bucket.bytes += u64::from(sample.total_captured_bytes);
                        *bucket.sizes.entry(sample.total_captured_bytes).or_default() += 1;
                        drop(stats);
                        if !flows.contains_key(&id) {
                            if flows.len() >= CACHE_CAPACITY {
                                record_drop(
                                    &worker_stats,
                                    sample.packets.len() as u64,
                                    u64::from(sample.total_captured_bytes),
                                );
                                continue;
                            }
                            let detector = engine.start(&key).ok();
                            flows.insert(
                                id.clone(),
                                FlowState {
                                    key: key.clone(),
                                    bytes: 0,
                                    packets: [0, 0],
                                    last_packet_ms: 0,
                                    expires: now + CACHE_TTL,
                                    engine: detector,
                                    result: None,
                                    signatures: Vec::new(),
                                },
                            );
                            worker_stats
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .bucket()
                                .attempted += 1;
                        }
                        let entry = flows.get_mut(&id).expect("flow inserted");
                        let mut counts = entry.packets;
                        for packet in &sample.packets {
                            counts[usize::from(packet.direction == 2)] += 1;
                        }
                        if key != entry.key
                            || entry.bytes + sample.total_captured_bytes
                                > netqmon_protocol::MAX_SAMPLE_BYTES_PER_FLOW
                            || counts.iter().any(|count| {
                                *count > netqmon_protocol::MAX_SAMPLE_PACKETS_PER_DIRECTION
                            })
                        {
                            record_drop(
                                &worker_stats,
                                sample.packets.len() as u64,
                                u64::from(sample.total_captured_bytes),
                            );
                            continue;
                        }
                        entry.bytes += sample.total_captured_bytes;
                        entry.packets = counts;
                        entry.last_packet_ms = entry.last_packet_ms.max(
                            sample
                                .packets
                                .iter()
                                .map(|p| p.timestamp_unix_ms)
                                .max()
                                .unwrap_or(0),
                        );
                        entry.expires = now + CACHE_TTL;
                        let first_identification = entry.result.is_none();
                        if let Some(result) = entry
                            .engine
                            .as_mut()
                            .and_then(|engine| engine.classify(&sample.packets))
                        {
                            entry.result = Some(result);
                        }
                        if entry.signatures.is_empty() {
                            entry.signatures =
                                signature_matcher.match_sample(&key, &sample.packets);
                        }
                        let config = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .configs
                            .get(&id.0)
                            .copied();
                        let byte_budget = config
                            .map_or(netqmon_protocol::DEFAULT_SAMPLE_BYTES_PER_FLOW, |c| {
                                c.max_bytes_per_flow
                            });
                        let packet_budget = config.map_or(
                            netqmon_protocol::DEFAULT_SAMPLE_PACKETS_PER_DIRECTION,
                            |c| c.max_packets_per_direction,
                        ) as usize;
                        let exhausted = entry.bytes >= byte_budget
                            || entry.packets.iter().all(|count| *count >= packet_budget);
                        if exhausted {
                            if let Some(result) =
                                entry.engine.as_mut().and_then(|engine| engine.finish())
                            {
                                entry.result = Some(result);
                            }
                            entry.engine = None;
                        } else if entry.result.as_ref().is_some_and(|result| {
                            result.source != "ndpi"
                                && !matches!(result.protocol.as_str(), "tls" | "quic" | "http")
                        }) {
                            entry.engine = None;
                        }
                        if first_identification && entry.result.is_some() {
                            worker_stats
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .bucket()
                                .identified += 1;
                        }
                        // The raw packet Vec is released here, after this call only metadata remains.
                        drop(sample.packets);
                        let mut stats = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if entry.result.is_some() || !entry.signatures.is_empty() {
                            let cached = CachedResult {
                                gateway: id.0.clone(),
                                boot: id.1.clone(),
                                key: key.clone(),
                                last_packet_ms: entry.last_packet_ms,
                                result: entry.result.clone(),
                                signatures: entry.signatures.clone(),
                                expires: entry.expires,
                            };
                            stats.results.retain(|_, value| value.expires > now);
                            if stats.results.len() < CACHE_CAPACITY
                                || stats.results.contains_key(&id)
                            {
                                stats.results.insert(id.clone(), cached.clone());
                            }
                            drop(stats);
                            completed(cached);
                        }
                    }
                }
            })
            .expect("DPI worker must start");
        Self {
            sender,
            stats,
            enabled,
            engine_name,
        }
    }
    pub fn submit(&self, batch: FlowSampleBatch) -> bool {
        if !self.enabled {
            return false;
        }
        match self.sender.try_send(batch) {
            Ok(()) => true,
            // The Agent accounts for rejected HTTP uploads in its health counters.
            // Counting them here too would count the same lost packets twice.
            Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => false,
        }
    }
    pub fn lookup_batch(&self, batch: &TelemetryBatch) -> Vec<Option<SampleAnalysis>> {
        batch
            .flows
            .iter()
            .map(|flow| self.lookup(&batch.gateway_id, &batch.boot_id, flow))
            .collect()
    }
    pub fn lookup(
        &self,
        gateway: &str,
        boot: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
    ) -> Option<SampleAnalysis> {
        let stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stats
            .results
            .values()
            .filter(|r| {
                r.gateway == gateway
                    && r.boot == boot
                    && r.expires > Instant::now()
                    && r.key.client_ip == flow.client_ip
                    && r.key.remote_ip == flow.remote_ip
                    && r.key.client_port == flow.client_port
                    && r.key.remote_port == flow.remote_port
                    && r.key.protocol == flow.protocol
                    && r.key.first_seen_unix_ms <= flow.last_seen_unix_ms.saturating_add(1)
                    && r.last_packet_ms.saturating_add(1) >= flow.first_seen_unix_ms
            })
            .max_by_key(|r| r.key.first_seen_unix_ms)
            .map(|r| SampleAnalysis {
                dpi: r.result.clone(),
                signatures: r.signatures.clone(),
            })
    }
    pub fn observe_telemetry(&self, batch: &TelemetryBatch) {
        let mut stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        stats
            .endings
            .retain(|(_, _, _, at)| now.duration_since(*at) < CACHE_TTL);
        for flow in &batch.flows {
            if flow.lifecycle == netqmon_protocol::v1::FlowLifecycle::Ended as i32
                && stats.endings.len() < CACHE_CAPACITY
            {
                stats.endings.push((
                    batch.gateway_id.clone(),
                    batch.boot_id.clone(),
                    flow.clone(),
                    now,
                ));
            }
        }
        stats.seen_flows.retain(|_, expires| *expires > now);
        let mut new_flows = 0;
        for f in &batch.flows {
            if f.packets == 0 {
                continue;
            }
            let id = format!(
                "{}:{}:{:?}:{}:{:?}:{}:{}",
                batch.gateway_id,
                batch.boot_id,
                f.client_ip,
                f.client_port,
                f.remote_ip,
                f.remote_port,
                f.protocol
            );
            if !stats.seen_flows.contains_key(&id) && stats.seen_flows.len() < 65536 {
                new_flows += 1;
            }
            if stats.seen_flows.len() < 65536 || stats.seen_flows.contains_key(&id) {
                stats.seen_flows.insert(id, now + CACHE_TTL);
            }
        }
        let mut drops = 0;
        let mut drop_bytes = 0;
        if let Some(health) = &batch.health {
            if let Some(config) = &health.sample_config {
                stats.configs.insert(batch.gateway_id.clone(), *config);
            }
            let prior = stats
                .health
                .insert(
                    (batch.gateway_id.clone(), batch.boot_id.clone()),
                    (health.dropped_samples, health.dropped_sample_bytes),
                )
                .unwrap_or((0, 0));
            drops = health.dropped_samples.saturating_sub(prior.0);
            drop_bytes = health.dropped_sample_bytes.saturating_sub(prior.1);
        }
        let budget = stats
            .configs
            .get(&batch.gateway_id)
            .filter(|config| config.enabled)
            .map_or(0, |config| u64::from(config.max_bytes_per_flow));
        let bucket = stats.bucket();
        bucket.theoretical_bytes += new_flows * budget;
        bucket.new_flows += new_flows;
        bucket.drops += drops;
        bucket.drop_bytes += drop_bytes;
        bucket.network_bytes += batch
            .flows
            .iter()
            .map(|f| f.upload_bytes.saturating_add(f.download_bytes))
            .sum::<u64>();
    }
    // Ratios and bandwidth are deliberately approximate floating-point metrics.
    #[allow(clippy::cast_precision_loss)]
    pub fn diagnostics(&self) -> Value {
        let mut stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stats.bucket();
        let seconds = stats.started.elapsed().as_secs_f64().clamp(1.0, 3600.0);
        let mut total = MinuteStats::default();
        for (_, b) in &stats.buckets {
            total.samples += b.samples;
            total.bytes += b.bytes;
            total.attempted += b.attempted;
            total.identified += b.identified;
            total.drops += b.drops;
            total.internal_drops += b.internal_drops;
            total.drop_bytes += b.drop_bytes;
            total.network_bytes += b.network_bytes;
            total.new_flows += b.new_flows;
            total.theoretical_bytes += b.theoretical_bytes;
            for (size, count) in &b.sizes {
                *total.sizes.entry(*size).or_default() += count;
            }
        }
        let count = total.sizes.values().sum::<u64>();
        let mut sizes = total.sizes.iter().collect::<Vec<_>>();
        sizes.sort_by_key(|(size, _)| **size);
        let mut cumulative = 0;
        let mut p95 = 0;
        for (size, n) in sizes {
            cumulative += n;
            if cumulative >= count.saturating_mul(95).div_ceil(100) {
                p95 = *size;
                break;
            }
        }
        let ratio = if total.network_bytes > 0 {
            Some(total.bytes as f64 / total.network_bytes as f64)
        } else {
            None
        };
        let attempts = total.samples + total.drops.saturating_sub(total.internal_drops);
        let drop_rate = total.drops as f64 / attempts.max(1) as f64;
        let kbps = total.bytes as f64 * 8.0 / seconds / 1000.0;
        let impact = if drop_rate > 0.1 || ratio.unwrap_or(0.0) > 0.05 || kbps > 10000.0 {
            "High"
        } else if drop_rate > 0.01 || ratio.unwrap_or(0.0) > 0.01 || kbps > 1000.0 {
            "Moderate"
        } else {
            "Low"
        };
        json!({"engine":self.engine_name,"enabled":self.enabled,"available":ndpi::available(),"window_seconds":seconds,
            "configs":stats.configs.iter().map(|(gateway,c)|json!({"gateway_id":gateway,"enabled":c.enabled,"max_bytes_per_flow":c.max_bytes_per_flow,"max_packets_per_direction":c.max_packets_per_direction,"max_bytes_per_packet":c.max_bytes_per_packet})).collect::<Vec<_>>(),
            "sample_count":count,"packet_count":total.samples,"sampled_flows":total.attempted,"sample_bytes":total.bytes,
            "average_sample_bytes":if count>0 {total.bytes as f64/count as f64}else{0.0},"p95_sample_bytes":p95,"max_sample_bytes":total.sizes.keys().max().copied().unwrap_or(0),
            "dpi_success_rate":if total.attempted>0 {total.identified as f64/total.attempted as f64}else{0.0},"sample_drops":total.drops,"dropped_sample_bytes":total.drop_bytes,"sample_drop_rate":drop_rate,
            "new_flows":total.new_flows,"new_flows_per_second":total.new_flows as f64/seconds,"network_bytes":total.network_bytes,"bandwidth_kbps":kbps,"traffic_ratio":ratio,"impact":if total.bytes == 0 && total.network_bytes == 0 {None}else{Some(impact)},
            "theoretical_max_kbps":total.theoretical_bytes as f64*8.0/seconds/1000.0})
    }
}
fn record_drop(stats: &Mutex<Stats>, packets: u64, bytes: u64) {
    let mut stats = stats
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bucket = stats.bucket();
    bucket.drops += packets;
    bucket.internal_drops += packets;
    bucket.drop_bytes += bytes;
}
pub fn default_engine() -> Arc<dyn DpiEngine> {
    Arc::new(ndpi::NdpiEngine)
}
pub fn native_available() -> bool {
    ndpi::available()
}

#[cfg(test)]
impl SamplingService {
    pub(crate) fn seed_for_test(
        &self,
        batch: &TelemetryBatch,
        flow: &netqmon_protocol::v1::FlowDelta,
        protocol: &str,
    ) {
        let key = FlowSampleKey {
            ip_version: flow.ip_version,
            protocol: flow.protocol,
            client_ip: flow.client_ip.clone(),
            client_port: flow.client_port,
            remote_ip: flow.remote_ip.clone(),
            remote_port: flow.remote_port,
            first_seen_unix_ms: flow.first_seen_unix_ms,
        };
        self.stats.lock().unwrap().results.insert(
            (
                batch.gateway_id.clone(),
                batch.boot_id.clone(),
                "fixture".into(),
            ),
            CachedResult {
                gateway: batch.gateway_id.clone(),
                boot: batch.boot_id.clone(),
                key,
                last_packet_ms: flow.last_seen_unix_ms,
                result: Some(DpiResult {
                    protocol: protocol.into(),
                    confidence: 1.0,
                    source: "ndpi".into(),
                    metadata: std::collections::BTreeMap::new(),
                }),
                signatures: Vec::new(),
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }
}
#[cfg(test)]
mod tests;
