pub(crate) mod policies;

use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::broadcast;

use crate::classifier::{EntityMetadata, IconMetadata};
use crate::realtime::{
    ActiveFlowSnapshot, GatewayHealthSnapshot, RealtimeEvent, RealtimeSnapshot, ScopedThroughput,
    Throughput, ThroughputPoint, format_ip, format_mac,
};
use crate::{CollectorState, unix_time_ms};
use netqmon_classifier_client::EntityKind;

const DEMO_TICK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_HISTORY_POINTS: usize = 900;
const EVENT_CHANNEL_CAPACITY: usize = 128;

/// Deterministic 64-bit mixer (SplitMix64)
fn hash64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// Simple deterministic string hash (FNV-1a 64-bit)
fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h = (h ^ (*b as u64)).wrapping_mul(0x100000001b3);
    }
    h
}

/// Float in [0.0, 1.0) for a given integer grid index
fn rand_at_grid(seed: u64, index: i64) -> f64 {
    let combined = seed.wrapping_add((index as u64).wrapping_mul(0x9e3779b97f4a7c15));
    let h = hash64(combined);
    (h >> 11) as f64 / ((1u64 << 53) as f64)
}

/// C1 continuous smooth cubic noise at time t_sec with grid scale scale_sec
fn smooth_noise(seed: u64, t_sec: f64, scale_sec: f64) -> f64 {
    let p = t_sec / scale_sec;
    let idx = p.floor() as i64;
    let u = p - idx as f64;
    // Cubic Hermite smoothstep: 3u^2 - 2u^3
    let w = u * u * (3.0 - 2.0 * u);
    let v0 = rand_at_grid(seed, idx);
    let v1 = rand_at_grid(seed, idx + 1);
    v0 + (v1 - v0) * w
}

/// Continuous multi-octave non-periodic factor with smooth heavy-tail bursts
#[allow(clippy::too_many_arguments)]
fn generate_direction_factor(
    seed: u64,
    t_sec: f64,
    macro_scale: f64,
    burst_scale: f64,
    micro_scale: f64,
    burst_intensity: f64,
    micro_intensity: f64,
    baseline_floor: f64,
) -> f64 {
    let n_base = smooth_noise(seed ^ 0x1111222233334444, t_sec, macro_scale);
    let n_burst = smooth_noise(seed ^ 0x5555666677778888, t_sec, burst_scale);
    let n_micro = smooth_noise(seed ^ 0x9999AAAABBBBCCCC, t_sec, micro_scale);
    let n_jit = smooth_noise(seed ^ 0xDDDDEEEEFFFF0000, t_sec, 2.0);

    // Non-linear thresholding for natural, non-periodic bell bursts
    let b = (n_burst - 0.45).max(0.0) / 0.55;
    let burst_curve = b * b * burst_intensity;

    let m = (n_micro - 0.55).max(0.0) / 0.45;
    let micro_curve = m * m * micro_intensity;

    let jitter = 0.88 + 0.24 * n_jit;
    let base = baseline_floor + (1.0 - baseline_floor) * n_base;

    (base * (1.0 + burst_curve + micro_curve) * jitter).max(0.02)
}

/// Returns true if netqmon is configured to run in Demo Mode.
pub fn demo_mode() -> bool {
    env::var("NETQMON_DEMO_MODE")
        .ok()
        .as_deref()
        .map_or(false, is_demo_mode_val)
}

fn is_demo_mode_val(val: &str) -> bool {
    let s = val.trim();
    s.eq_ignore_ascii_case("true") || s == "1"
}

/// Formatted HTTP 403 response for mutating operations in Demo Mode.
pub(crate) fn read_only_rejection() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "code": "demo_read_only",
                "message": "This demo environment is read-only."
            }
        })),
    )
        .into_response()
}

#[allow(dead_code)]
struct DemoGatewayMeta {
    id: String,
    name: String,
    agent_version: String,
    kernel_version: String,
    openwrt_version: String,
}

#[derive(Clone, Debug)]
struct DemoClientProfile {
    ip: String,
    mac: Option<String>,
    device_type: String,
    #[allow(dead_code)]
    hostname: String,
    up_weight: f64,
    down_weight: f64,
    seed: u64,
}

#[derive(Clone, Debug)]
struct DemoAppProfile {
    id: String,
    weight: f64,
    seed: u64,
}

struct DemoTrafficFrame {
    total: Throughput,
    internet: Throughput,
    internal: Throughput,
    clients: HashMap<String, Throughput>,
    client_scopes: HashMap<String, ScopedThroughput>,
    applications: HashMap<String, Throughput>,
}

pub(crate) struct DemoRealtimeProvider {
    current_snapshot: Arc<RwLock<RealtimeSnapshot>>,
    sender: broadcast::Sender<RealtimeEvent>,
    _task: tokio::task::JoinHandle<()>,
}

impl DemoRealtimeProvider {
    pub(crate) fn start(state: &CollectorState) -> Arc<Self> {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (initial_snapshot, gateway_meta, clients, apps, base_up, base_down, flows) = {
            let inner = state.lock();
            let connection = inner.storage.connection();
            Self::load_baseline_from_db(connection)
        };

        let current_snapshot = Arc::new(RwLock::new(initial_snapshot));
        let snapshot_ref = Arc::clone(&current_snapshot);
        let sender_clone = sender.clone();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DEMO_TICK_INTERVAL);
            let total_rx = AtomicU64::new(50_000_000_000);
            let total_tx = AtomicU64::new(12_000_000_000);

            loop {
                ticker.tick().await;
                let now = unix_time_ms();
                let snapshot = Self::generate_tick(
                    now,
                    &snapshot_ref,
                    &gateway_meta,
                    &clients,
                    &apps,
                    base_up,
                    base_down,
                    &flows,
                    &total_rx,
                    &total_tx,
                );

                *snapshot_ref
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot.clone();
                let _ = sender_clone.send(RealtimeEvent::Snapshot(snapshot));
            }
        });

        Arc::new(Self {
            current_snapshot,
            sender,
            _task: task,
        })
    }

    pub(crate) fn snapshot(&self) -> RealtimeSnapshot {
        self.current_snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.sender.subscribe()
    }

    #[allow(clippy::too_many_lines)]
    fn load_baseline_from_db(
        conn: &rusqlite::Connection,
    ) -> (
        RealtimeSnapshot,
        DemoGatewayMeta,
        Vec<DemoClientProfile>,
        Vec<DemoAppProfile>,
        u64,
        u64,
        Vec<ActiveFlowSnapshot>,
    ) {
        let now = unix_time_ms();

        // 1. Gateway info
        let gateway = conn
            .query_row(
                "SELECT id, name, agent_version, kernel_version, openwrt_version
                 FROM gateways ORDER BY created_at LIMIT 1",
                [],
                |row| {
                    Ok(DemoGatewayMeta {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        kernel_version: row.get(3)?,
                        openwrt_version: row.get(4)?,
                    })
                },
            )
            .unwrap_or_else(|_| DemoGatewayMeta {
                id: "demo-gateway".to_owned(),
                name: "Demo Gateway".to_owned(),
                agent_version: "v1.0.0-demo".to_owned(),
                kernel_version: "6.6.0".to_owned(),
                openwrt_version: "OpenWrt 24.10".to_owned(),
            });

        // 2. Base throughput from recent traffic_total_minute
        let mut recent_rates: Vec<(i64, i64, i64)> = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT timestamp, upload_bytes, download_bytes
             FROM traffic_total_minute
             ORDER BY timestamp DESC
             LIMIT 15",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            {
                for r in rows.flatten() {
                    recent_rates.push(r);
                }
            }
        }

        let (base_up, base_down) = if !recent_rates.is_empty() {
            let sum_up: i64 = recent_rates.iter().map(|r| r.1).sum();
            let sum_down: i64 = recent_rates.iter().map(|r| r.2).sum();
            let count = recent_rates.len() as i64 * 60; // seconds
            let up_rate = (sum_up / count.max(1)).max(50_000) as u64;
            let down_rate = (sum_down / count.max(1)).max(300_000) as u64;
            (up_rate, down_rate)
        } else {
            (250_000, 1_800_000) // Fallback: 250 KB/s up, 1.8 MB/s down
        };

        // 3. Client profiles
        let mut clients: Vec<DemoClientProfile> = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT da.ip, d.mac, COALESCE(d.device_type, 'unknown'), COALESCE(d.hostname, ''),
                    COALESCE(SUM(t.upload_bytes), 1000) as up_vol,
                    COALESCE(SUM(t.download_bytes), 5000) as down_vol
             FROM devices d
             JOIN device_addresses da ON da.device_id = d.id
             LEFT JOIN traffic_device_minute t ON t.device_id = d.id
             GROUP BY da.ip, d.mac, d.device_type, d.hostname
             ORDER BY (up_vol + down_vol) DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let ip_blob: Vec<u8> = row.get(0)?;
                let mac_blob: Option<Vec<u8>> = row.get(1)?;
                let dev_type: String = row.get(2)?;
                let hostname: String = row.get(3)?;
                let up_vol: i64 = row.get(4)?;
                let down_vol: i64 = row.get(5)?;
                let mac = mac_blob.map(|b| format_mac(&b));
                let ip = format_ip(&ip_blob);
                Ok((
                    ip,
                    mac,
                    dev_type,
                    hostname,
                    up_vol.max(1) as f64,
                    down_vol.max(1) as f64,
                ))
            }) {
                let mut list = Vec::new();
                let mut total_up_vol = 0.0;
                let mut total_down_vol = 0.0;
                for r in rows.flatten() {
                    total_up_vol += r.4;
                    total_down_vol += r.5;
                    list.push(r);
                }
                if total_up_vol > 0.0 && total_down_vol > 0.0 {
                    for (ip, mac, dev_type, hostname, up_vol, down_vol) in list {
                        let seed_src = mac.as_deref().unwrap_or(&ip);
                        let seed = hash_str(seed_src);
                        clients.push(DemoClientProfile {
                            ip,
                            mac,
                            device_type: dev_type,
                            hostname,
                            up_weight: up_vol / total_up_vol,
                            down_weight: down_vol / total_down_vol,
                            seed,
                        });
                    }
                }
            }
        }
        if clients.is_empty() {
            clients = vec![
                DemoClientProfile {
                    ip: "192.168.1.101".to_owned(),
                    mac: Some("02:00:00:00:00:01".to_owned()),
                    device_type: "laptop".to_owned(),
                    hostname: "demo-macbook".to_owned(),
                    up_weight: 0.30,
                    down_weight: 0.35,
                    seed: hash_str("02:00:00:00:00:01"),
                },
                DemoClientProfile {
                    ip: "192.168.1.102".to_owned(),
                    mac: Some("02:00:00:00:00:02".to_owned()),
                    device_type: "mobile".to_owned(),
                    hostname: "demo-iphone".to_owned(),
                    up_weight: 0.15,
                    down_weight: 0.25,
                    seed: hash_str("02:00:00:00:00:02"),
                },
                DemoClientProfile {
                    ip: "192.168.1.103".to_owned(),
                    mac: Some("02:00:00:00:00:03".to_owned()),
                    device_type: "tv".to_owned(),
                    hostname: "demo-appletv".to_owned(),
                    up_weight: 0.05,
                    down_weight: 0.30,
                    seed: hash_str("02:00:00:00:00:03"),
                },
                DemoClientProfile {
                    ip: "192.168.1.104".to_owned(),
                    mac: Some("02:00:00:00:00:04".to_owned()),
                    device_type: "nas".to_owned(),
                    hostname: "demo-nas".to_owned(),
                    up_weight: 0.50,
                    down_weight: 0.10,
                    seed: hash_str("02:00:00:00:00:04"),
                },
            ];
        }

        // 4. Application profiles
        let mut apps: Vec<DemoAppProfile> = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT application_id, COALESCE(SUM(upload_bytes + download_bytes), 1) as vol
             FROM traffic_application_minute
             GROUP BY application_id
             ORDER BY vol DESC
             LIMIT 10",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64))
            }) {
                let mut total_vol = 0.0;
                let mut list = Vec::new();
                for r in rows.flatten() {
                    total_vol += r.1;
                    list.push(r);
                }
                if total_vol > 0.0 {
                    for (id, vol) in list {
                        let seed = hash_str(&id);
                        apps.push(DemoAppProfile {
                            id,
                            weight: vol / total_vol,
                            seed,
                        });
                    }
                }
            }
        }
        if apps.is_empty() {
            apps = vec![
                DemoAppProfile {
                    id: "youtube".to_owned(),
                    weight: 0.40,
                    seed: hash_str("youtube"),
                },
                DemoAppProfile {
                    id: "github".to_owned(),
                    weight: 0.25,
                    seed: hash_str("github"),
                },
                DemoAppProfile {
                    id: "google".to_owned(),
                    weight: 0.20,
                    seed: hash_str("google"),
                },
                DemoAppProfile {
                    id: "apple".to_owned(),
                    weight: 0.15,
                    seed: hash_str("apple"),
                },
            ];
        }

        // 5. Active flows from flow_sessions
        let mut flows: Vec<ActiveFlowSnapshot> = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, client_ip, client_port, remote_ip, remote_port, protocol,
                    application_id, category_id, domain, classification_confidence,
                    upload_bytes, download_bytes, packets, last_seen_at, scope, path_type,
                    nat, source_segment, destination_segment
             FROM flow_sessions
             ORDER BY last_seen_at DESC
             LIMIT 50",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let client_ip_blob: Vec<u8> = row.get(1)?;
                let remote_ip_blob: Vec<u8> = row.get(3)?;
                Ok(ActiveFlowSnapshot {
                    id: row.get(0)?,
                    client_ip: format_ip(&client_ip_blob),
                    client_port: row.get(2)?,
                    remote_ip: format_ip(&remote_ip_blob),
                    remote_port: row.get(4)?,
                    protocol: row.get(5)?,
                    lifecycle: "active".to_owned(),
                    application: row
                        .get::<_, Option<String>>(6)?
                        .unwrap_or_else(|| "unknown".to_owned()),
                    category: row
                        .get::<_, Option<String>>(7)?
                        .unwrap_or_else(|| "general".to_owned()),
                    domain: row.get(8)?,
                    confidence: row.get::<_, Option<f64>>(9)?.unwrap_or(0.9),
                    upload_bytes: row.get::<_, i64>(10)? as u64,
                    download_bytes: row.get::<_, i64>(11)? as u64,
                    packets: row.get::<_, i64>(12)? as u64,
                    last_seen: now,
                    scope: "internet".to_owned(),
                    path_type: "direct".to_owned(),
                    nat: "masquerade".to_owned(),
                    source_segment: "lan".to_owned(),
                    destination_segment: "wan".to_owned(),
                })
            }) {
                for flow in rows.flatten() {
                    flows.push(flow);
                }
            }
        }
        if flows.is_empty() {
            flows = vec![
                ActiveFlowSnapshot {
                    id: "demo-flow-1".to_owned(),
                    client_ip: "192.168.1.101".to_owned(),
                    client_port: 54321,
                    remote_ip: "142.250.190.46".to_owned(),
                    remote_port: 443,
                    protocol: 6,
                    lifecycle: "active".to_owned(),
                    application: "youtube".to_owned(),
                    category: "streaming".to_owned(),
                    domain: Some("youtube.com".to_owned()),
                    confidence: 0.98,
                    upload_bytes: 45_000,
                    download_bytes: 1_250_000,
                    packets: 980,
                    last_seen: now,
                    scope: "internet".to_owned(),
                    path_type: "direct".to_owned(),
                    nat: "masquerade".to_owned(),
                    source_segment: "lan".to_owned(),
                    destination_segment: "wan".to_owned(),
                },
                ActiveFlowSnapshot {
                    id: "demo-flow-2".to_owned(),
                    client_ip: "192.168.1.102".to_owned(),
                    client_port: 51234,
                    remote_ip: "140.82.121.4".to_owned(),
                    remote_port: 443,
                    protocol: 6,
                    lifecycle: "active".to_owned(),
                    application: "github".to_owned(),
                    category: "technology".to_owned(),
                    domain: Some("github.com".to_owned()),
                    confidence: 0.99,
                    upload_bytes: 12_000,
                    download_bytes: 84_000,
                    packets: 120,
                    last_seen: now,
                    scope: "internet".to_owned(),
                    path_type: "direct".to_owned(),
                    nat: "masquerade".to_owned(),
                    source_segment: "lan".to_owned(),
                    destination_segment: "wan".to_owned(),
                },
            ];
        }

        // 6. Build initial 15-minute history points (900 points, 1s step)
        let mut history: Vec<ThroughputPoint> = Vec::with_capacity(MAX_HISTORY_POINTS);
        let start_ts = now.saturating_sub((MAX_HISTORY_POINTS as u64) * 1_000);
        for step in 0..MAX_HISTORY_POINTS {
            let point_ts = start_ts + (step as u64 * 1_000);
            let frame =
                Self::calculate_snapshot_state(point_ts, &clients, &apps, base_up, base_down);
            history.push(ThroughputPoint {
                timestamp: point_ts,
                upload_bytes_per_second: frame.internet.upload_bytes_per_second,
                download_bytes_per_second: frame.internet.download_bytes_per_second,
            });
        }

        let initial_frame =
            Self::calculate_snapshot_state(now, &clients, &apps, base_up, base_down);

        let initial_snapshot = RealtimeSnapshot {
            generated_at: now,
            agent_batch_time: now,
            total: initial_frame.total,
            internet: initial_frame.internet.clone(),
            internal: initial_frame.internal,
            tunnel: Throughput::default(),
            unknown: Throughput::default(),
            clients: initial_frame.clients,
            client_scopes: initial_frame.client_scopes,
            applications: initial_frame.applications,
            active_flows: flows.clone(),
            history,
            gateway_health: Some(GatewayHealthSnapshot {
                observed_at: now,
                uptime_seconds: 86400,
                dropped_batches: 0,
                dns_dropped_events: 0,
                protocol_probe_dropped_events: 0,
                tracked_flows: flows.len() as u64,
                agent_version: gateway.agent_version.clone(),
                kernel_version: gateway.kernel_version.clone(),
                openwrt_version: gateway.openwrt_version.clone(),
                hardware_flow_offload: "disabled".to_owned(),
                capture_interface: "br-lan".to_owned(),
                capture_interfaces: vec!["br-lan".to_owned()],
                interface_rx_bytes: 50_000_000_000,
                interface_tx_bytes: 12_000_000_000,
                interface_rx_packets: 35_000_000,
                interface_tx_packets: 15_000_000,
                interface_delta_bytes: initial_frame.internet.download_bytes_per_second,
                interface_delta_packets: (initial_frame.internet.download_bytes_per_second / 1400)
                    .max(1),
                flow_delta_bytes: initial_frame.internet.download_bytes_per_second,
                flow_delta_packets: (initial_frame.internet.download_bytes_per_second / 1400)
                    .max(1),
                interface_counter_sanity: "ok".to_owned(),
                topology: None,
            }),
        };

        (
            initial_snapshot,
            gateway,
            clients,
            apps,
            base_up,
            base_down,
            flows,
        )
    }

    fn simulate_client_traffic(
        client: &DemoClientProfile,
        t_secs: u64,
        base_up_total: u64,
        base_down_total: u64,
    ) -> (Throughput, ScopedThroughput) {
        let nominal_down = (base_down_total as f64 * client.down_weight).max(1_500.0);
        let nominal_up = (base_up_total as f64 * client.up_weight).max(500.0);
        let t_sec = t_secs as f64;

        let seed_down = client.seed ^ 0x5555555555555555;
        let seed_up = client.seed ^ 0xAAAAAAAAAAAAAAAA;

        let (factor_down, factor_up, internal_ratio) = match client.device_type.as_str() {
            "tv" | "entertainment" => (
                generate_direction_factor(seed_down, t_sec, 120.0, 28.0, 8.0, 3.2, 2.2, 0.25),
                generate_direction_factor(seed_up, t_sec, 160.0, 50.0, 15.0, 0.2, 0.1, 0.04),
                0.15,
            ),
            "console" => (
                generate_direction_factor(seed_down, t_sec, 140.0, 35.0, 10.0, 2.8, 1.8, 0.20),
                generate_direction_factor(seed_up, t_sec, 150.0, 40.0, 12.0, 1.5, 0.8, 0.15),
                0.12,
            ),
            "laptop" | "desktop" | "pc" => (
                generate_direction_factor(seed_down, t_sec, 130.0, 25.0, 8.0, 2.5, 1.6, 0.25),
                generate_direction_factor(seed_up, t_sec, 160.0, 32.0, 11.0, 1.8, 1.2, 0.20),
                0.20,
            ),
            "mobile" | "tablet" | "phone" => (
                generate_direction_factor(seed_down, t_sec, 110.0, 22.0, 6.0, 2.8, 2.0, 0.15),
                generate_direction_factor(seed_up, t_sec, 140.0, 30.0, 9.0, 1.0, 0.8, 0.10),
                0.08,
            ),
            "server" | "nas" => (
                generate_direction_factor(seed_down, t_sec, 150.0, 45.0, 15.0, 1.8, 1.0, 0.35),
                generate_direction_factor(seed_up, t_sec, 180.0, 55.0, 18.0, 3.2, 1.5, 0.40),
                0.40,
            ),
            "speaker" | "audio" => (
                generate_direction_factor(seed_down, t_sec, 200.0, 60.0, 20.0, 0.25, 0.15, 0.75),
                generate_direction_factor(seed_up, t_sec, 200.0, 60.0, 20.0, 0.10, 0.05, 0.04),
                0.15,
            ),
            "camera" => (
                generate_direction_factor(seed_down, t_sec, 200.0, 60.0, 20.0, 0.10, 0.05, 0.03),
                generate_direction_factor(seed_up, t_sec, 180.0, 60.0, 20.0, 0.25, 0.15, 0.85),
                0.10,
            ),
            _ => (
                generate_direction_factor(seed_down, t_sec, 120.0, 40.0, 12.0, 0.4, 0.2, 0.05),
                generate_direction_factor(seed_up, t_sec, 140.0, 45.0, 15.0, 0.4, 0.2, 0.05),
                0.06,
            ),
        };

        let down_bps = (nominal_down * factor_down).max(200.0) as u64;
        let up_bps = (nominal_up * factor_up).max(80.0) as u64;

        let internal_factor_up = internal_ratio * smooth_noise(client.seed ^ 0x3333, t_sec, 15.0);
        let internal_factor_down = internal_ratio * smooth_noise(client.seed ^ 0x4444, t_sec, 15.0);

        let internal_up = (up_bps as f64 * internal_factor_up).max(30.0) as u64;
        let internal_down = (down_bps as f64 * internal_factor_down).max(50.0) as u64;

        let internet_tp = Throughput {
            upload_bytes_per_second: up_bps,
            download_bytes_per_second: down_bps,
        };
        let internal_tp = Throughput {
            upload_bytes_per_second: internal_up,
            download_bytes_per_second: internal_down,
        };
        let total_tp = Throughput {
            upload_bytes_per_second: up_bps + internal_up,
            download_bytes_per_second: down_bps + internal_down,
        };

        let scoped = ScopedThroughput {
            internet: internet_tp,
            internal: internal_tp,
            tunnel: Throughput::default(),
            unknown: Throughput::default(),
        };

        (total_tp, scoped)
    }

    fn calculate_snapshot_state(
        t_ms: u64,
        clients: &[DemoClientProfile],
        apps: &[DemoAppProfile],
        base_up: u64,
        base_down: u64,
    ) -> DemoTrafficFrame {
        let t_secs = t_ms / 1000;
        let t_sec = t_secs as f64;
        let mut client_map: HashMap<String, Throughput> = HashMap::with_capacity(clients.len() * 3);
        let mut client_scopes: HashMap<String, ScopedThroughput> =
            HashMap::with_capacity(clients.len() * 3);

        let mut sum_internet_up: u64 = 0;
        let mut sum_internet_down: u64 = 0;
        let mut sum_internal_up: u64 = 0;
        let mut sum_internal_down: u64 = 0;

        for client in clients {
            let (total_tp, scoped) =
                Self::simulate_client_traffic(client, t_secs, base_up, base_down);
            sum_internet_up += scoped.internet.upload_bytes_per_second;
            sum_internet_down += scoped.internet.download_bytes_per_second;
            sum_internal_up += scoped.internal.upload_bytes_per_second;
            sum_internal_down += scoped.internal.download_bytes_per_second;

            client_map.insert(client.ip.clone(), total_tp.clone());
            client_scopes.insert(client.ip.clone(), scoped.clone());
            if let Some(mac) = &client.mac {
                client_map.insert(mac.clone(), total_tp.clone());
                client_map.insert(mac.to_lowercase(), total_tp.clone());
                client_scopes.insert(mac.clone(), scoped.clone());
                client_scopes.insert(mac.to_lowercase(), scoped.clone());
            }
        }

        // Add background gateway router noise (DNS/NTP/pings)
        let gw_up = (3_500.0 * (0.8 + 0.4 * smooth_noise(0xdeadbeef, t_sec, 3.0))) as u64;
        let gw_down = (7_500.0 * (0.8 + 0.4 * smooth_noise(0xbeefcafe, t_sec, 3.0))) as u64;
        sum_internet_up += gw_up;
        sum_internet_down += gw_down;

        let internet = Throughput {
            upload_bytes_per_second: sum_internet_up,
            download_bytes_per_second: sum_internet_down,
        };
        let internal = Throughput {
            upload_bytes_per_second: sum_internal_up,
            download_bytes_per_second: sum_internal_down,
        };
        let total = Throughput {
            upload_bytes_per_second: sum_internet_up + sum_internal_up,
            download_bytes_per_second: sum_internet_down + sum_internal_down,
        };

        // Application distribution using continuous smooth noise
        let mut app_weights: Vec<f64> = Vec::with_capacity(apps.len());
        for app in apps {
            let app_wave = (0.7 + 0.6 * smooth_noise(app.seed ^ 0x7777, t_sec, 25.0)).max(0.15);
            let app_jitter = 0.85 + 0.3 * smooth_noise(app.seed ^ 0x8888, t_sec, 2.0);
            app_weights.push(app.weight * app_wave * app_jitter);
        }
        let sum_app_weights: f64 = app_weights.iter().sum::<f64>().max(0.001);

        let mut app_map: HashMap<String, Throughput> = HashMap::with_capacity(apps.len());
        for (i, app) in apps.iter().enumerate() {
            let frac = app_weights[i] / sum_app_weights;
            let app_down = (sum_internet_down as f64 * frac) as u64;
            let app_up = (sum_internet_up as f64 * frac) as u64;
            app_map.insert(
                app.id.clone(),
                Throughput {
                    upload_bytes_per_second: app_up,
                    download_bytes_per_second: app_down,
                },
            );
        }

        DemoTrafficFrame {
            total,
            internet,
            internal,
            clients: client_map,
            client_scopes,
            applications: app_map,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_tick(
        now: u64,
        prev_snapshot_lock: &Arc<RwLock<RealtimeSnapshot>>,
        gateway_meta: &DemoGatewayMeta,
        clients: &[DemoClientProfile],
        apps: &[DemoAppProfile],
        base_up: u64,
        base_down: u64,
        base_flows: &[ActiveFlowSnapshot],
        total_rx: &AtomicU64,
        total_tx: &AtomicU64,
    ) -> RealtimeSnapshot {
        let t_secs = now / 1000;
        let frame = Self::calculate_snapshot_state(now, clients, apps, base_up, base_down);
        let current_up = frame.internet.upload_bytes_per_second;
        let current_down = frame.internet.download_bytes_per_second;

        let mut active_flows = base_flows.to_vec();
        let flow_count = (active_flows.len() as u64).max(1);
        for (idx, flow) in active_flows.iter_mut().enumerate() {
            flow.last_seen = now;
            let flow_seed = hash64((idx as u64).wrapping_add(t_secs));
            let flow_delta_down = ((current_down / flow_count) as f64
                * (0.5 + 0.8 * smooth_noise(flow_seed, t_secs as f64, 4.0)))
                as u64;
            let flow_delta_up = ((current_up / flow_count) as f64
                * (0.5 + 0.8 * smooth_noise(flow_seed ^ 0x9999, t_secs as f64, 4.0)))
                as u64;
            flow.download_bytes = flow.download_bytes.saturating_add(flow_delta_down);
            flow.upload_bytes = flow.upload_bytes.saturating_add(flow_delta_up);
            flow.packets = flow
                .packets
                .saturating_add((flow_delta_down + flow_delta_up) / 1200 + 1);
        }

        let mut history = {
            let prev = prev_snapshot_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            prev.history.clone()
        };
        history.push(ThroughputPoint {
            timestamp: now,
            upload_bytes_per_second: current_up,
            download_bytes_per_second: current_down,
        });
        if history.len() > MAX_HISTORY_POINTS {
            let excess = history.len() - MAX_HISTORY_POINTS;
            history.drain(0..excess);
        }

        // Tick interval is 1s, so delta bytes equals current bytes/sec
        let delta_bytes_down = current_down;
        let delta_bytes_up = current_up;
        let rx = total_rx.fetch_add(delta_bytes_down, Ordering::Relaxed) + delta_bytes_down;
        let tx = total_tx.fetch_add(delta_bytes_up, Ordering::Relaxed) + delta_bytes_up;

        let gateway_health = GatewayHealthSnapshot {
            observed_at: now,
            uptime_seconds: 86400 + (t_secs % 86400),
            dropped_batches: 0,
            dns_dropped_events: 0,
            protocol_probe_dropped_events: 0,
            tracked_flows: active_flows.len() as u64,
            agent_version: gateway_meta.agent_version.clone(),
            kernel_version: gateway_meta.kernel_version.clone(),
            openwrt_version: gateway_meta.openwrt_version.clone(),
            hardware_flow_offload: "disabled".to_owned(),
            capture_interface: "br-lan".to_owned(),
            capture_interfaces: vec!["br-lan".to_owned()],
            interface_rx_bytes: rx,
            interface_tx_bytes: tx,
            interface_rx_packets: rx / 1400,
            interface_tx_packets: tx / 1400,
            interface_delta_bytes: delta_bytes_down,
            interface_delta_packets: (delta_bytes_down / 1400).max(1),
            flow_delta_bytes: delta_bytes_down,
            flow_delta_packets: (delta_bytes_down / 1400).max(1),
            interface_counter_sanity: "ok".to_owned(),
            topology: None,
        };

        RealtimeSnapshot {
            generated_at: now,
            agent_batch_time: now,
            total: frame.total,
            internet: frame.internet,
            internal: frame.internal,
            tunnel: Throughput::default(),
            unknown: Throughput::default(),
            clients: frame.clients,
            client_scopes: frame.client_scopes,
            applications: frame.applications,
            active_flows,
            history,
            gateway_health: Some(gateway_health),
        }
    }
}

/// Automatically shifts all historical timestamps in the SQLite database to the present
/// so that Demo mode always displays rich, fresh data in the current observation window.
pub fn ensure_demo_database_freshness(
    conn: &rusqlite::Connection,
) -> Result<bool, rusqlite::Error> {
    let mut latest_ts: Option<i64> = None;

    // 1. Check traffic_total_minute
    if table_exists(conn, "traffic_total_minute") {
        if let Ok(ts) = conn.query_row(
            "SELECT MAX(timestamp) FROM traffic_total_minute",
            [],
            |row| row.get::<_, Option<i64>>(0),
        ) {
            latest_ts = ts;
        }
    }

    // 2. Fallback to flow_sessions if traffic_total_minute is empty
    if latest_ts.is_none() && table_exists(conn, "flow_sessions") {
        if let Ok(ts) = conn.query_row("SELECT MAX(last_seen_at) FROM flow_sessions", [], |row| {
            row.get::<_, Option<i64>>(0)
        }) {
            latest_ts = ts;
        }
    }

    let Some(latest) = latest_ts else {
        return Ok(false);
    };

    if latest <= 0 {
        return Ok(false);
    }

    let now = unix_time_ms() as i64;
    // Align latest data point to ~30 seconds ago (rounded to top of minute)
    let target_ts = ((now - 30_000) / 60_000) * 60_000;
    let delta = target_ts - latest;

    // If already fresh (within 60 seconds), no shift needed
    if delta.abs() < 60_000 {
        return Ok(false);
    }

    tracing::info!(
        latest_ts = latest,
        target_ts,
        delta_ms = delta,
        delta_hours = delta as f64 / (3600.0 * 1000.0),
        "shifting demo database timestamps to present"
    );

    let tx = conn.unchecked_transaction()?;

    const TABLES_SINGLE_COL: &[(&str, &str)] = &[
        ("traffic_total_minute", "timestamp"),
        ("traffic_device_minute", "timestamp"),
        ("traffic_application_minute", "timestamp"),
        ("traffic_domain_minute", "timestamp"),
        ("traffic_destination_minute", "timestamp"),
        ("traffic_scope_minute", "timestamp"),
        ("traffic_total_hour", "timestamp"),
        ("traffic_device_hour", "timestamp"),
        ("traffic_application_hour", "timestamp"),
        ("traffic_domain_hour", "timestamp"),
        ("traffic_destination_hour", "timestamp"),
        ("traffic_total_day", "timestamp"),
        ("traffic_device_day", "timestamp"),
        ("traffic_application_day", "timestamp"),
        ("traffic_domain_day", "timestamp"),
        ("traffic_destination_day", "timestamp"),
        ("sites", "created_at"),
        ("users", "created_at"),
        ("ingest_batches", "received_at"),
        ("settings", "updated_at"),
    ];

    for (table, col) in TABLES_SINGLE_COL {
        if table_exists(conn, table) {
            let sql = format!("UPDATE {table} SET {col} = {col} + ?1");
            let _ = tx.execute(&sql, rusqlite::params![delta]);
        }
    }

    if table_exists(conn, "flow_sessions") {
        let _ = tx.execute(
            "UPDATE flow_sessions SET started_at = started_at + ?1, last_seen_at = last_seen_at + ?1, checkpointed_at = checkpointed_at + ?1, ended_at = CASE WHEN ended_at IS NOT NULL THEN ended_at + ?1 ELSE NULL END",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "devices") {
        let _ = tx.execute(
            "UPDATE devices SET first_seen = first_seen + ?1, last_seen = last_seen + ?1",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "device_addresses") {
        let _ = tx.execute(
            "UPDATE device_addresses SET first_seen = first_seen + ?1, last_seen = last_seen + ?1, application_last_seen = CASE WHEN application_last_seen IS NOT NULL THEN application_last_seen + ?1 ELSE NULL END",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "device_evidence") {
        let _ = tx.execute(
            "UPDATE device_evidence SET first_seen = first_seen + ?1, last_seen = last_seen + ?1",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "gateways") {
        let _ = tx.execute(
            "UPDATE gateways SET created_at = created_at + ?1, last_seen = last_seen + ?1",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "dns_observations") {
        let _ = tx.execute(
            "UPDATE dns_observations SET observed_at = observed_at + ?1, expires_at = expires_at + ?1",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "self_host_endpoint_evidence") {
        let _ = tx.execute(
            "UPDATE self_host_endpoint_evidence SET last_seen = last_seen + ?1, expires_at = expires_at + ?1",
            rusqlite::params![delta],
        );
    }

    if table_exists(conn, "auth_sessions") {
        let _ = tx.execute(
            "UPDATE auth_sessions SET created_at = created_at + ?1, expires_at = expires_at + ?1",
            rusqlite::params![delta],
        );
    }

    tx.commit()?;
    tracing::info!("successfully refreshed demo database timestamps to present");
    Ok(true)
}

fn table_exists(conn: &rusqlite::Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

pub(crate) fn spawn_demo_freshness_task(state: CollectorState, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let state = state.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let inner = state.lock();
                let conn = inner.storage.connection();
                let _ = ensure_demo_database_freshness(conn);
            })
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo_mode_detection() {
        assert!(is_demo_mode_val("true"));
        assert!(is_demo_mode_val("1"));
        assert!(is_demo_mode_val("TRUE"));
        assert!(is_demo_mode_val("  true  "));
        assert!(!is_demo_mode_val("false"));
        assert!(!is_demo_mode_val("0"));
        assert!(!is_demo_mode_val(""));
        assert!(!is_demo_mode_val("anything_else"));
    }

    #[test]
    fn test_ensure_demo_database_freshness() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE traffic_total_minute (timestamp INTEGER, gateway_id TEXT, upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER, PRIMARY KEY (timestamp, gateway_id))",
            [],
        ).unwrap();
        let old_ts = 1704240000000_i64; // Jan 3 2024
        conn.execute(
            "INSERT INTO traffic_total_minute VALUES (?1, 'demo-gateway', 100, 200, 5, 1)",
            [old_ts],
        )
        .unwrap();

        let shifted = ensure_demo_database_freshness(&conn).unwrap();
        assert!(shifted);

        let new_ts: i64 = conn
            .query_row("SELECT timestamp FROM traffic_total_minute", [], |row| {
                row.get(0)
            })
            .unwrap();
        let now = unix_time_ms() as i64;
        assert!((now - new_ts).abs() < 120_000);

        // Second call should not shift because it is already fresh
        let shifted_again = ensure_demo_database_freshness(&conn).unwrap();
        assert!(!shifted_again);
    }

    #[test]
    fn test_realistic_traffic_engine_simulation() {
        let clients = vec![
            DemoClientProfile {
                ip: "192.168.1.101".to_owned(),
                mac: Some("02:00:00:00:00:01".to_owned()),
                device_type: "laptop".to_owned(),
                hostname: "demo-macbook".to_owned(),
                up_weight: 0.35,
                down_weight: 0.30,
                seed: hash_str("02:00:00:00:00:01"),
            },
            DemoClientProfile {
                ip: "192.168.1.102".to_owned(),
                mac: Some("02:00:00:00:00:02".to_owned()),
                device_type: "tv".to_owned(),
                hostname: "demo-appletv".to_owned(),
                up_weight: 0.05,
                down_weight: 0.50,
                seed: hash_str("02:00:00:00:00:02"),
            },
            DemoClientProfile {
                ip: "192.168.1.103".to_owned(),
                mac: Some("02:00:00:00:00:03".to_owned()),
                device_type: "nas".to_owned(),
                hostname: "demo-nas".to_owned(),
                up_weight: 0.60,
                down_weight: 0.20,
                seed: hash_str("02:00:00:00:00:03"),
            },
        ];
        let apps = vec![DemoAppProfile {
            id: "youtube".to_owned(),
            weight: 1.0,
            seed: hash_str("youtube"),
        }];

        let base_up = 200_000;
        let base_down = 1_500_000;

        let frame1 = DemoRealtimeProvider::calculate_snapshot_state(
            1700000000000,
            &clients,
            &apps,
            base_up,
            base_down,
        );
        let frame2 = DemoRealtimeProvider::calculate_snapshot_state(
            1700000005000,
            &clients,
            &apps,
            base_up,
            base_down,
        );

        assert!(frame1.internet.download_bytes_per_second > 0);
        assert!(frame1.internet.upload_bytes_per_second > 0);
        assert!(frame2.internet.download_bytes_per_second > 0);
        // Ensure values fluctuate and are not identical
        assert_ne!(
            frame1.internet.download_bytes_per_second,
            frame2.internet.download_bytes_per_second
        );

        // TV vs NAS traffic behavior: NAS has substantially higher upload than TV
        let tv_tp = frame1.clients.get("02:00:00:00:00:02").unwrap();
        let nas_tp = frame1.clients.get("02:00:00:00:00:03").unwrap();
        assert!(nas_tp.upload_bytes_per_second > tv_tp.upload_bytes_per_second);
    }
}

pub(crate) fn metadata(kind: EntityKind, id: &str) -> Option<EntityMetadata> {
    let (name, icon_domain, fallback_domains, local_fallback) = match (kind, id) {
        // Applications
        (EntityKind::Application, "youtube") => (
            "YouTube",
            Some("youtube.com"),
            vec!["googlevideo.com"],
            Some("youtube"),
        ),
        (EntityKind::Application, "netflix") => (
            "Netflix",
            Some("netflix.com"),
            vec!["nflxvideo.net"],
            Some("netflix"),
        ),
        (EntityKind::Application, "bilibili") => (
            "Bilibili",
            Some("bilibili.com"),
            vec!["bilivideo.com"],
            Some("bilibili"),
        ),
        (EntityKind::Application, "github") => (
            "GitHub",
            Some("github.com"),
            vec!["githubassets.com"],
            Some("github"),
        ),
        (EntityKind::Application, "openai") => (
            "OpenAI",
            Some("openai.com"),
            vec!["chatgpt.com"],
            Some("openai"),
        ),
        (EntityKind::Application, "steam") => (
            "Steam",
            Some("steampowered.com"),
            vec!["steamcommunity.com"],
            Some("steam"),
        ),
        (EntityKind::Application, "playstation-network" | "playstation") => (
            "PlayStation Network",
            Some("playstation.com"),
            vec!["playstation.net"],
            Some("playstation"),
        ),
        (EntityKind::Application, "nintendo-eshop" | "nintendo") => (
            "Nintendo eShop",
            Some("nintendo.com"),
            vec!["nintendo.net"],
            None,
        ),
        (EntityKind::Application, "spotify") => {
            ("Spotify", Some("spotify.com"), vec![], Some("spotify"))
        }
        (EntityKind::Application, "apple-music") => (
            "Apple Music",
            Some("music.apple.com"),
            vec!["apple.com"],
            Some("applemusic"),
        ),
        (EntityKind::Application, "icloud") => (
            "Apple iCloud",
            Some("icloud.com"),
            vec!["apple.com"],
            Some("icloud"),
        ),
        (EntityKind::Application, "slack") => ("Slack", Some("slack.com"), vec![], Some("slack")),
        (EntityKind::Application, "discord") => (
            "Discord",
            Some("discord.com"),
            vec!["discord.gg"],
            Some("discord"),
        ),
        (EntityKind::Application, "wechat") => (
            "WeChat",
            Some("weixin.qq.com"),
            vec!["qq.com"],
            Some("wechat"),
        ),
        (EntityKind::Application, "telegram") => {
            ("Telegram", Some("telegram.org"), vec![], Some("telegram"))
        }
        (EntityKind::Application, "reddit") => (
            "Reddit",
            Some("reddit.com"),
            vec!["redd.it"],
            Some("reddit"),
        ),
        (EntityKind::Application, "microsoft-365" | "microsoft") => (
            "Microsoft 365",
            Some("office.com"),
            vec!["microsoft.com"],
            Some("microsoft"),
        ),
        (EntityKind::Application, "notion") => {
            ("Notion", Some("notion.so"), vec![], Some("notion"))
        }
        (EntityKind::Application, "amazon-prime-video" | "primevideo") => (
            "Prime Video",
            Some("primevideo.com"),
            vec!["amazon.com"],
            Some("primevideo"),
        ),
        (EntityKind::Application, "docker-hub" | "docker") => (
            "Docker Hub",
            Some("docker.com"),
            vec!["docker.io"],
            Some("docker"),
        ),
        (EntityKind::Application, "wikipedia") => (
            "Wikipedia",
            Some("wikipedia.org"),
            vec![],
            Some("wikipedia"),
        ),
        (EntityKind::Application, "cloudflare-dns" | "cloudflare") => (
            "Cloudflare",
            Some("cloudflare.com"),
            vec!["1.1.1.1"],
            Some("cloudflare"),
        ),
        (EntityKind::Application, "google-dns" | "google") => (
            "Google",
            Some("google.com"),
            vec!["dns.google"],
            Some("google"),
        ),
        (EntityKind::Application, "ntp") => (
            "NTP Service",
            Some("cloudflare.com"),
            vec!["pool.ntp.org"],
            None,
        ),
        (EntityKind::Application, "twitch") => {
            ("Twitch", Some("twitch.tv"), vec![], Some("twitch"))
        }
        (EntityKind::Application, "aqara-cloud" | "aqara") => {
            ("Aqara IoT", Some("aqara.com"), vec![], None)
        }
        (EntityKind::Application, "cloudflare-backup") => (
            "Cloudflare R2",
            Some("cloudflare.com"),
            vec![],
            Some("cloudflare"),
        ),
        (EntityKind::Application, "nas-smb") => ("LAN File Sharing", None, vec![], None),
        (EntityKind::Application, "plex") => {
            ("Plex Media Server", Some("plex.tv"), vec![], Some("plex"))
        }
        (EntityKind::Application, "synology-dsm" | "synology") => (
            "Synology DSM",
            Some("synology.com"),
            vec![],
            Some("synology"),
        ),
        (EntityKind::Application, "speedtest") => (
            "Speedtest",
            Some("speedtest.net"),
            vec![],
            Some("speedtest"),
        ),
        (EntityKind::Application, "xiaohongshu") => {
            ("Xiaohongshu", None, vec![], Some("xiaohongshu"))
        }
        (EntityKind::Application, "tiktok") => {
            ("TikTok", Some("tiktok.com"), vec![], Some("tiktok"))
        }
        (EntityKind::Application, "twitter" | "x") => {
            ("X", Some("x.com"), vec!["twitter.com"], Some("x"))
        }
        (EntityKind::Application, "facebook") => {
            ("Facebook", Some("facebook.com"), vec![], Some("facebook"))
        }
        (EntityKind::Application, "instagram") => (
            "Instagram",
            Some("instagram.com"),
            vec![],
            Some("instagram"),
        ),
        (EntityKind::Application, "zoom") => ("Zoom", Some("zoom.us"), vec![], Some("zoom")),
        (EntityKind::Application, "whatsapp") => {
            ("WhatsApp", Some("whatsapp.com"), vec![], Some("whatsapp"))
        }

        // Organizations
        (EntityKind::Organization, "google") => {
            ("Google", Some("google.com"), vec![], Some("google"))
        }
        (EntityKind::Organization, "apple") => ("Apple", Some("apple.com"), vec![], Some("apple")),
        (EntityKind::Organization, "microsoft") => (
            "Microsoft",
            Some("microsoft.com"),
            vec![],
            Some("microsoft"),
        ),
        (EntityKind::Organization, "amazon") => {
            ("Amazon", Some("amazon.com"), vec![], Some("amazon"))
        }
        (EntityKind::Organization, "meta") => ("Meta", Some("meta.com"), vec![], Some("meta")),
        (EntityKind::Organization, "netflix") => {
            ("Netflix", Some("netflix.com"), vec![], Some("netflix"))
        }
        (EntityKind::Organization, "bilibili") => {
            ("Bilibili", Some("bilibili.com"), vec![], Some("bilibili"))
        }
        (EntityKind::Organization, "github") => {
            ("GitHub", Some("github.com"), vec![], Some("github"))
        }
        (EntityKind::Organization, "openai") => {
            ("OpenAI", Some("openai.com"), vec![], Some("openai"))
        }
        (EntityKind::Organization, "valve") => {
            ("Valve", Some("valvesoftware.com"), vec![], Some("valve"))
        }
        (EntityKind::Organization, "sony") => ("Sony", Some("sony.com"), vec![], Some("sony")),
        (EntityKind::Organization, "nintendo") => ("Nintendo", Some("nintendo.com"), vec![], None),
        (EntityKind::Organization, "spotify") => {
            ("Spotify", Some("spotify.com"), vec![], Some("spotify"))
        }
        (EntityKind::Organization, "salesforce") => (
            "Salesforce",
            Some("salesforce.com"),
            vec![],
            Some("salesforce"),
        ),
        (EntityKind::Organization, "discord") => {
            ("Discord", Some("discord.com"), vec![], Some("discord"))
        }
        (EntityKind::Organization, "tencent") => ("Tencent", Some("tencent.com"), vec![], None),
        (EntityKind::Organization, "telegram") => {
            ("Telegram", Some("telegram.org"), vec![], Some("telegram"))
        }
        (EntityKind::Organization, "reddit") => {
            ("Reddit", Some("reddit.com"), vec![], Some("reddit"))
        }
        (EntityKind::Organization, "notion") => {
            ("Notion Labs", Some("notion.so"), vec![], Some("notion"))
        }
        (EntityKind::Organization, "docker") => {
            ("Docker", Some("docker.com"), vec![], Some("docker"))
        }
        (EntityKind::Organization, "wikimedia") => (
            "Wikimedia",
            Some("wikimedia.org"),
            vec![],
            Some("wikipedia"),
        ),
        (EntityKind::Organization, "cloudflare") => (
            "Cloudflare",
            Some("cloudflare.com"),
            vec![],
            Some("cloudflare"),
        ),
        (EntityKind::Organization, "synology") => {
            ("Synology", Some("synology.com"), vec![], Some("synology"))
        }
        (EntityKind::Organization, "lumi") => ("Lumi / Aqara", Some("aqara.com"), vec![], None),
        (EntityKind::Organization, "xingyin") => ("Xingyin", Some("xiaohongshu.com"), vec![], None),
        _ => return None,
    };
    Some(EntityMetadata {
        id: id.to_owned(),
        name: name.to_owned(),
        icon: IconMetadata {
            domain: icon_domain.map(str::to_owned),
            fallback_domains: fallback_domains.into_iter().map(str::to_owned).collect(),
            local_fallback: local_fallback.map(str::to_owned),
        },
        organization_id: if matches!(kind, EntityKind::Application) {
            fallback_application_org_id(id)
        } else {
            None
        },
    })
}

fn fallback_application_org_id(id: &str) -> Option<String> {
    let org = match id {
        "youtube" | "google-dns" => "google",
        "netflix" => "netflix",
        "bilibili" => "bilibili",
        "github" => "github",
        "openai" => "openai",
        "steam" => "valve",
        "playstation-network" => "sony",
        "nintendo-eshop" => "nintendo",
        "spotify" => "spotify",
        "apple-music" | "icloud" => "apple",
        "slack" => "salesforce",
        "discord" => "discord",
        "wechat" => "tencent",
        "telegram" => "telegram",
        "reddit" => "reddit",
        "microsoft-365" => "microsoft",
        "notion" => "notion",
        "amazon-prime-video" | "twitch" => "amazon",
        "docker-hub" => "docker",
        "wikipedia" => "wikimedia",
        "cloudflare-dns" | "cloudflare-backup" => "cloudflare",
        "synology-dsm" => "synology",
        "aqara-cloud" => "lumi",
        "xiaohongshu" => "xingyin",
        _ => return None,
    };
    Some(org.to_owned())
}
