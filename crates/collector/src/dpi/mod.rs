//! Independent bounded DPI worker and payload-free, gateway-scoped diagnostics.
pub mod engine;
mod ndpi;

use engine::{DpiEngine, DpiFlow, DpiResult};
use netqmon_protocol::v1::{
    FlowSampleBatch, FlowSampleKey, SampleConfig, SamplePacket, TelemetryBatch,
};
use serde_json::{Value, json};
use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

const CACHE_CAPACITY: usize = 4096;
const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
const SEEN_FLOWS_CAPACITY: usize = 65_536;
const SEEN_FLOWS_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const ENDING_DELAY: Duration = Duration::from_secs(1);
const WINDOW: Duration = Duration::from_secs(3600);
type CacheKey = (String, String, String);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct FlowIdentity {
    gateway: String,
    boot: String,
    ip_version: u32,
    protocol: u32,
    client_ip: Vec<u8>,
    client_port: u32,
    remote_ip: Vec<u8>,
    remote_port: u32,
}

impl FlowIdentity {
    fn from_sample(gateway: &str, boot: &str, key: &FlowSampleKey) -> Self {
        Self {
            gateway: gateway.to_owned(),
            boot: boot.to_owned(),
            ip_version: key.ip_version,
            protocol: key.protocol,
            client_ip: key.client_ip.clone(),
            client_port: key.client_port,
            remote_ip: key.remote_ip.clone(),
            remote_port: key.remote_port,
        }
    }

    fn from_delta(gateway: &str, boot: &str, flow: &netqmon_protocol::v1::FlowDelta) -> Self {
        Self {
            gateway: gateway.to_owned(),
            boot: boot.to_owned(),
            ip_version: flow.ip_version,
            protocol: flow.protocol,
            client_ip: flow.client_ip.clone(),
            client_port: flow.client_port,
            remote_ip: flow.remote_ip.clone(),
            remote_port: flow.remote_port,
        }
    }
}

type FlowIndex = HashMap<FlowIdentity, HashSet<CacheKey>>;

struct EndingIntervalIndex {
    starts: Vec<u64>,
    prefix_max_ends: Vec<u64>,
}

impl EndingIntervalIndex {
    fn new(mut windows: Vec<(u64, u64)>) -> Option<Self> {
        if windows.is_empty() {
            return None;
        }
        windows.sort_unstable_by_key(|(first, _)| *first);
        let mut starts = Vec::with_capacity(windows.len());
        let mut prefix_max_ends = Vec::with_capacity(windows.len());
        let mut max_end = 0;
        for (first, last) in windows {
            starts.push(first);
            max_end = max_end.max(last);
            prefix_max_ends.push(max_end);
        }
        Some(Self {
            starts,
            prefix_max_ends,
        })
    }

    fn overlaps(&self, sample_first_seen_unix_ms: u64, sample_last_packet_ms: u64) -> bool {
        let eligible = self
            .starts
            .partition_point(|first| *first <= sample_last_packet_ms.saturating_add(1));
        eligible > 0
            && self.prefix_max_ends[eligible - 1].saturating_add(1) >= sample_first_seen_unix_ms
    }
}

struct EndingWindow {
    id: u64,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
    received_at: Instant,
    expires: Instant,
}

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
    next_cleanup: Instant,
    buckets: VecDeque<(Instant, MinuteStats)>,
    configs: HashMap<String, SampleConfig>,
    endings: HashMap<FlowIdentity, Vec<EndingWindow>>,
    ending_expirations: BTreeSet<(Instant, FlowIdentity, u64)>,
    pending_ending_deadlines: HashMap<u64, (Instant, FlowIdentity)>,
    ending_index_dirty: bool,
    ending_count: usize,
    next_ending_id: u64,
    health: HashMap<(String, String), (u64, u64)>,
    seen_flows: HashMap<Arc<str>, Instant>,
    seen_flow_expirations: BTreeSet<(Instant, Arc<str>)>,
    next_seen_flows_cleanup: Instant,
    results: HashMap<CacheKey, CachedResult>,
    results_by_identity: FlowIndex,
    result_expirations: BTreeSet<(Instant, CacheKey)>,
}
impl Default for Stats {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            next_cleanup: now + CACHE_MAINTENANCE_INTERVAL,
            next_seen_flows_cleanup: now + SEEN_FLOWS_CLEANUP_INTERVAL,
            buckets: VecDeque::new(),
            configs: HashMap::new(),
            endings: HashMap::new(),
            ending_expirations: BTreeSet::new(),
            pending_ending_deadlines: HashMap::new(),
            ending_index_dirty: false,
            ending_count: 0,
            next_ending_id: 0,
            health: HashMap::new(),
            seen_flows: HashMap::new(),
            seen_flow_expirations: BTreeSet::new(),
            results: HashMap::new(),
            results_by_identity: HashMap::new(),
            result_expirations: BTreeSet::new(),
        }
    }
}
impl Stats {
    fn cleanup_seen_flows_if_due(&mut self, now: Instant) {
        if now < self.next_seen_flows_cleanup {
            return;
        }
        self.next_seen_flows_cleanup = now + SEEN_FLOWS_CLEANUP_INTERVAL;
        self.expire_seen_flows(now);
    }

    fn expire_seen_flows(&mut self, now: Instant) {
        while let Some((expires, id)) = self.seen_flow_expirations.first().cloned() {
            if expires > now {
                break;
            }
            self.seen_flow_expirations.pop_first();
            if self.seen_flows.get(id.as_ref()) == Some(&expires) {
                self.seen_flows.remove(id.as_ref());
            }
        }
    }

    /// Records a flow observation and returns true when it is a new flow.
    fn record_seen_flow(&mut self, id: String, now: Instant) -> bool {
        let existing = self
            .seen_flows
            .get_key_value(id.as_str())
            .map(|(key, expires)| (Arc::clone(key), *expires));
        let is_new = existing.as_ref().is_none_or(|(_, expires)| *expires <= now);

        if let Some((key, expires)) = &existing {
            self.seen_flow_expirations
                .remove(&(*expires, Arc::clone(key)));
            if is_new {
                self.seen_flows.remove(key.as_ref());
            }
        }

        if is_new && self.seen_flows.len() >= SEEN_FLOWS_CAPACITY {
            // At capacity, reclaim expired entries immediately before rejecting
            // a new flow instead of waiting for the periodic sweep.
            self.expire_seen_flows(now);
        }
        if is_new && self.seen_flows.len() >= SEEN_FLOWS_CAPACITY {
            return false;
        }

        let key = existing
            .filter(|_| !is_new)
            .map_or_else(|| Arc::<str>::from(id), |(key, _)| key);
        let expires = now + CACHE_TTL;
        self.seen_flows.insert(Arc::clone(&key), expires);
        self.seen_flow_expirations.insert((expires, key));
        is_new
    }

    fn cleanup_if_due(&mut self, now: Instant) {
        if now < self.next_cleanup {
            return;
        }
        self.next_cleanup = now + CACHE_MAINTENANCE_INTERVAL;
        self.expire_endings(now);
        self.expire_results(now);
    }

    fn insert_ending(
        &mut self,
        identity: FlowIdentity,
        first_seen_unix_ms: u64,
        last_seen_unix_ms: u64,
        now: Instant,
    ) -> bool {
        if self.ending_count >= CACHE_CAPACITY {
            self.expire_endings(now);
        }
        if self.ending_count >= CACHE_CAPACITY {
            return false;
        }

        let id = self.next_ending_id;
        self.next_ending_id = self.next_ending_id.wrapping_add(1);
        let expires = now + CACHE_TTL;
        self.endings
            .entry(identity.clone())
            .or_default()
            .push(EndingWindow {
                id,
                first_seen_unix_ms,
                last_seen_unix_ms,
                received_at: now,
                expires,
            });
        self.ending_expirations
            .insert((expires, identity.clone(), id));
        self.pending_ending_deadlines
            .insert(id, (now + ENDING_DELAY, identity));
        self.ending_count += 1;
        true
    }

    fn take_ending_updates(
        &mut self,
    ) -> (Vec<(Instant, FlowIdentity)>, HashSet<FlowIdentity>, bool) {
        let pending = std::mem::take(&mut self.pending_ending_deadlines);
        let mut refresh = HashSet::new();
        let deadlines = pending
            .into_values()
            .inspect(|(_, identity)| {
                refresh.insert(identity.clone());
            })
            .collect();
        let rebuild_all = std::mem::take(&mut self.ending_index_dirty);
        if rebuild_all {
            refresh.extend(self.endings.keys().cloned());
        }
        (deadlines, refresh, rebuild_all)
    }

    fn mature_ending_windows(&self, identity: &FlowIdentity, now: Instant) -> Vec<(u64, u64)> {
        self.endings
            .get(identity)
            .into_iter()
            .flatten()
            .filter(|ending| {
                ending.expires > now
                    && now.saturating_duration_since(ending.received_at) >= ENDING_DELAY
            })
            .map(|ending| (ending.first_seen_unix_ms, ending.last_seen_unix_ms))
            .collect()
    }

    fn insert_result(&mut self, id: CacheKey, result: CachedResult, now: Instant) -> bool {
        if !self.results.contains_key(&id) && self.results.len() >= CACHE_CAPACITY {
            self.expire_results(now);
        }
        if !self.results.contains_key(&id) && self.results.len() >= CACHE_CAPACITY {
            return false;
        }

        if let Some(previous) = self.results.remove(&id) {
            self.result_expirations
                .remove(&(previous.expires, id.clone()));
            remove_index_entry(
                &mut self.results_by_identity,
                &FlowIdentity::from_sample(&previous.gateway, &previous.boot, &previous.key),
                &id,
            );
        }

        let identity = FlowIdentity::from_sample(&result.gateway, &result.boot, &result.key);
        self.result_expirations.insert((result.expires, id.clone()));
        self.results_by_identity
            .entry(identity)
            .or_default()
            .insert(id.clone());
        self.results.insert(id, result);
        true
    }

    fn expire_endings(&mut self, now: Instant) {
        let mut expired = HashMap::<FlowIdentity, HashSet<u64>>::new();
        while let Some((expires, identity, id)) = self.ending_expirations.first().cloned() {
            if expires > now {
                break;
            }
            self.ending_expirations.pop_first();
            self.pending_ending_deadlines.remove(&id);
            expired.entry(identity).or_default().insert(id);
        }
        for (identity, ids) in expired {
            if let Some(entries) = self.endings.get_mut(&identity) {
                let before = entries.len();
                entries.retain(|entry| !ids.contains(&entry.id));
                let removed = before - entries.len();
                self.ending_count -= removed;
                self.ending_index_dirty |= removed > 0;
                if entries.is_empty() {
                    self.endings.remove(&identity);
                }
            }
        }
    }

    fn expire_results(&mut self, now: Instant) {
        while let Some((expires, id)) = self.result_expirations.first().cloned() {
            if expires > now {
                break;
            }
            self.result_expirations.pop_first();
            if let Some(result) = self.results.remove(&id) {
                remove_index_entry(
                    &mut self.results_by_identity,
                    &FlowIdentity::from_sample(&result.gateway, &result.boot, &result.key),
                    &id,
                );
            }
        }
    }

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

fn remove_index_entry(index: &mut FlowIndex, identity: &FlowIdentity, id: &CacheKey) {
    if let Some(entries) = index.get_mut(identity) {
        entries.remove(id);
        if entries.is_empty() {
            index.remove(identity);
        }
    }
}

fn matching_flows_for_endings(
    identities: &HashSet<FlowIdentity>,
    endings: &HashMap<FlowIdentity, EndingIntervalIndex>,
    flow_index: &FlowIndex,
    flows: &HashMap<CacheKey, FlowState>,
) -> HashSet<CacheKey> {
    let mut matching = HashSet::new();
    for identity in identities {
        let Some(endings) = endings.get(identity) else {
            continue;
        };
        let Some(flow_ids) = flow_index.get(identity) else {
            continue;
        };
        for id in flow_ids {
            let Some(entry) = flows.get(id) else {
                continue;
            };
            if entry.engine.is_some()
                && endings.overlaps(entry.key.first_seen_unix_ms, entry.last_packet_ms)
            {
                matching.insert(id.clone());
            }
        }
    }
    matching
}

fn finish_flows<F: Fn(CachedResult)>(
    ids: &HashSet<CacheKey>,
    flows: &mut HashMap<CacheKey, FlowState>,
    stats: &Mutex<Stats>,
    completed: &F,
    now: Instant,
) {
    for id in ids {
        let Some(entry) = flows.get_mut(id) else {
            continue;
        };
        if let Some(mut engine) = entry.engine.take() {
            if let Some(result) = engine.finish() {
                entry.result = Some(result);
            }
        }
        if entry.result.is_none() && entry.signatures.is_empty() {
            continue;
        }

        let cached = CachedResult {
            gateway: id.0.clone(),
            boot: id.1.clone(),
            key: entry.key.clone(),
            last_packet_ms: entry.last_packet_ms,
            result: entry.result.clone(),
            signatures: entry.signatures.clone(),
            expires: now + CACHE_TTL,
        };
        stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert_result(id.clone(), cached.clone(), now);
        completed(cached);
    }
}

fn remove_flow(
    id: &CacheKey,
    flows: &mut HashMap<CacheKey, FlowState>,
    flow_index: &mut FlowIndex,
) {
    if let Some(entry) = flows.remove(id) {
        let identity = FlowIdentity::from_sample(&id.0, &id.1, &entry.key);
        remove_index_entry(flow_index, &identity, id);
    }
}

fn expired_flow_ids(flows: &HashMap<CacheKey, FlowState>, now: Instant) -> Vec<CacheKey> {
    flows
        .iter()
        .filter(|(_, entry)| entry.expires <= now)
        .map(|(id, _)| id.clone())
        .collect()
}

fn remove_flows(ids: &[CacheKey], flows: &mut HashMap<CacheKey, FlowState>, index: &mut FlowIndex) {
    for id in ids {
        remove_flow(id, flows, index);
    }
}

fn expire_sequences(sequences: &mut HashMap<(String, String), (u64, Instant)>, now: Instant) {
    sequences.retain(|_, (_, expires)| *expires > now);
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
                let mut flow_index = FlowIndex::new();
                let mut sequences: HashMap<(String, String), (u64, Instant)> = HashMap::new();
                let mut ending_deadlines = BinaryHeap::<Reverse<(Instant, FlowIdentity)>>::new();
                let mut ready_endings: HashMap<FlowIdentity, EndingIntervalIndex> = HashMap::new();
                let mut dirty_flow_identities = HashSet::new();
                let mut next_cleanup = Instant::now() + CACHE_MAINTENANCE_INTERVAL;
                loop {
                    let now = Instant::now();
                    let cleanup_due = now >= next_cleanup;
                    let mut finalizable = HashSet::new();
                    let expired_flows = if cleanup_due {
                        let expired = expired_flow_ids(&flows, now);
                        finalizable.extend(
                            expired
                                .iter()
                                .filter(|id| {
                                    flows.get(*id).is_some_and(|entry| entry.engine.is_some())
                                })
                                .cloned(),
                        );
                        expire_sequences(&mut sequences, now);
                        next_cleanup = now + CACHE_MAINTENANCE_INTERVAL;
                        expired
                    } else {
                        Vec::new()
                    };

                    let (identities, ending_snapshots, rebuild_all_endings) = {
                        let mut stats = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if now >= stats.next_cleanup {
                            stats.cleanup_if_due(now);
                        } else {
                            // Expire ready ending windows from the local interval index
                            // without walking the full ending cache on every batch.
                            stats.expire_endings(now);
                        }
                        let (deadlines, mut refresh_identities, rebuild_all) =
                            stats.take_ending_updates();
                        ending_deadlines.extend(deadlines.into_iter().map(Reverse));
                        let mut identities = std::mem::take(&mut dirty_flow_identities);
                        while ending_deadlines
                            .peek()
                            .is_some_and(|Reverse((deadline, _))| *deadline <= now)
                        {
                            if let Some(Reverse((_, identity))) = ending_deadlines.pop() {
                                identities.insert(identity.clone());
                                refresh_identities.insert(identity);
                            }
                        }
                        let snapshots = refresh_identities
                            .into_iter()
                            .map(|identity| {
                                let windows = stats.mature_ending_windows(&identity, now);
                                (identity, windows)
                            })
                            .collect::<Vec<_>>();
                        (identities, snapshots, rebuild_all)
                    };
                    if rebuild_all_endings {
                        ready_endings.clear();
                    }
                    for (identity, windows) in ending_snapshots {
                        if let Some(index) = EndingIntervalIndex::new(windows) {
                            ready_endings.insert(identity, index);
                        } else {
                            ready_endings.remove(&identity);
                        }
                    }
                    finalizable.extend(matching_flows_for_endings(
                        &identities,
                        &ready_endings,
                        &flow_index,
                        &flows,
                    ));

                    finish_flows(&finalizable, &mut flows, &worker_stats, &completed, now);
                    if cleanup_due {
                        remove_flows(&expired_flows, &mut flows, &mut flow_index);
                    }

                    let batch = match receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(batch) => batch,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let sequence_key = (batch.gateway_id.clone(), batch.boot_id.clone());
                    if sequences
                        .get(&sequence_key)
                        .is_some_and(|(sequence, expires)| {
                            *expires > now && *sequence >= batch.sequence
                        })
                    {
                        continue;
                    }
                    if sequences.len() >= CACHE_CAPACITY && !sequences.contains_key(&sequence_key) {
                        expire_sequences(&mut sequences, now);
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
                        let identity = FlowIdentity::from_sample(&id.0, &id.1, &key);
                        let mut stats = worker_stats
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let bucket = stats.bucket();
                        bucket.samples += sample.packets.len() as u64;
                        bucket.bytes += u64::from(sample.total_captured_bytes);
                        *bucket.sizes.entry(sample.total_captured_bytes).or_default() += 1;
                        drop(stats);
                        if flows.get(&id).is_some_and(|entry| entry.expires <= now) {
                            if flows.get(&id).is_some_and(|entry| entry.engine.is_some()) {
                                finish_flows(
                                    &HashSet::from([id.clone()]),
                                    &mut flows,
                                    &worker_stats,
                                    &completed,
                                    now,
                                );
                            }
                            remove_flow(&id, &mut flows, &mut flow_index);
                        }
                        if !flows.contains_key(&id) {
                            if flows.len() >= CACHE_CAPACITY {
                                let expired = expired_flow_ids(&flows, now);
                                let expired_set = expired
                                    .iter()
                                    .filter(|id| {
                                        flows.get(*id).is_some_and(|entry| entry.engine.is_some())
                                    })
                                    .cloned()
                                    .collect::<HashSet<_>>();
                                finish_flows(
                                    &expired_set,
                                    &mut flows,
                                    &worker_stats,
                                    &completed,
                                    now,
                                );
                                remove_flows(&expired, &mut flows, &mut flow_index);
                            }
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
                            flow_index
                                .entry(identity.clone())
                                .or_default()
                                .insert(id.clone());
                            worker_stats
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .bucket()
                                .attempted += 1;
                        }
                        let entry = flows.get_mut(&id).expect("flow inserted");
                        dirty_flow_identities.insert(identity);
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
                            stats.insert_result(id.clone(), cached.clone(), now);
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
        let identity = FlowIdentity::from_delta(gateway, boot, flow);
        stats
            .results_by_identity
            .get(&identity)
            .into_iter()
            .flatten()
            .filter_map(|id| stats.results.get(id))
            .filter(|r| {
                r.expires > Instant::now()
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
        stats.cleanup_if_due(now);
        stats.cleanup_seen_flows_if_due(now);
        for flow in &batch.flows {
            if flow.lifecycle == netqmon_protocol::v1::FlowLifecycle::Ended as i32 {
                let identity = FlowIdentity::from_delta(&batch.gateway_id, &batch.boot_id, flow);
                stats.insert_ending(
                    identity,
                    flow.first_seen_unix_ms,
                    flow.last_seen_unix_ms,
                    now,
                );
            }
        }
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
            if stats.record_seen_flow(id, now) {
                new_flows += 1;
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
        let now = Instant::now();
        self.stats.lock().unwrap().insert_result(
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
                expires: now + CACHE_TTL,
            },
            now,
        );
    }
}
#[cfg(test)]
mod tests;
