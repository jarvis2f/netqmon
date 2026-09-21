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

use crate::realtime::{
    ActiveFlowSnapshot, GatewayHealthSnapshot, RealtimeEvent, RealtimeSnapshot, ScopedThroughput,
    Throughput, ThroughputPoint, format_ip,
};
use crate::{CollectorState, unix_time_ms};

const DEMO_TICK_INTERVAL: Duration = Duration::from_secs(3);
const MAX_HISTORY_POINTS: usize = 900;
const EVENT_CHANNEL_CAPACITY: usize = 128;

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

#[derive(Clone)]
struct DemoClientProfile {
    ip: String,
    weight: f64,
}

#[derive(Clone)]
struct DemoAppProfile {
    id: String,
    weight: f64,
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
            "SELECT da.ip, COALESCE(SUM(t.upload_bytes + t.download_bytes), 1) as vol
             FROM devices d
             JOIN device_addresses da ON da.device_id = d.id
             LEFT JOIN traffic_device_minute t ON t.device_id = d.id
             GROUP BY da.ip
             ORDER BY vol DESC
             LIMIT 12",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let ip_blob: Vec<u8> = row.get(0)?;
                let vol: i64 = row.get(1)?;
                Ok((format_ip(&ip_blob), vol as f64))
            }) {
                let mut total_vol = 0.0;
                let mut list = Vec::new();
                for r in rows.flatten() {
                    total_vol += r.1;
                    list.push(r);
                }
                if total_vol > 0.0 {
                    for (ip, vol) in list {
                        clients.push(DemoClientProfile {
                            ip,
                            weight: vol / total_vol,
                        });
                    }
                }
            }
        }
        if clients.is_empty() {
            clients = vec![
                DemoClientProfile {
                    ip: "192.168.1.101".to_owned(),
                    weight: 0.45,
                },
                DemoClientProfile {
                    ip: "192.168.1.102".to_owned(),
                    weight: 0.30,
                },
                DemoClientProfile {
                    ip: "192.168.1.103".to_owned(),
                    weight: 0.15,
                },
                DemoClientProfile {
                    ip: "192.168.1.104".to_owned(),
                    weight: 0.10,
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
                        apps.push(DemoAppProfile {
                            id,
                            weight: vol / total_vol,
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
                },
                DemoAppProfile {
                    id: "github".to_owned(),
                    weight: 0.25,
                },
                DemoAppProfile {
                    id: "google".to_owned(),
                    weight: 0.20,
                },
                DemoAppProfile {
                    id: "apple".to_owned(),
                    weight: 0.15,
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

        // 6. Build initial 15-minute history points
        let mut history: Vec<ThroughputPoint> = Vec::with_capacity(300);
        let start_ts = now.saturating_sub(15 * 60 * 1_000);
        for step in 0..180 {
            let point_ts = start_ts + (step as u64 * 5_000);
            let t_secs = point_ts / 1000;
            let wave =
                0.85 + 0.15 * (t_secs as f64 * 0.08).sin() + 0.05 * (t_secs as f64 * 0.02).cos();
            let wave = wave.clamp(0.4, 1.6);
            history.push(ThroughputPoint {
                timestamp: point_ts,
                upload_bytes_per_second: (base_up as f64 * (2.0 - wave)).max(10_000.0) as u64,
                download_bytes_per_second: (base_down as f64 * wave).max(50_000.0) as u64,
            });
        }

        let initial_snapshot = RealtimeSnapshot {
            generated_at: now,
            total: Throughput {
                upload_bytes_per_second: base_up,
                download_bytes_per_second: base_down,
            },
            internet: Throughput {
                upload_bytes_per_second: base_up,
                download_bytes_per_second: base_down,
            },
            internal: Throughput {
                upload_bytes_per_second: base_up / 10,
                download_bytes_per_second: base_down / 10,
            },
            tunnel: Throughput::default(),
            unknown: Throughput::default(),
            clients: HashMap::new(),
            client_scopes: HashMap::new(),
            applications: HashMap::new(),
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
                interface_delta_bytes: base_down * 3,
                interface_delta_packets: (base_down / 1400) * 3,
                flow_delta_bytes: base_down * 3,
                flow_delta_packets: (base_down / 1400) * 3,
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
        let wave = 0.85 + 0.15 * (t_secs as f64 * 0.08).sin() + 0.05 * (t_secs as f64 * 0.02).cos();
        let wave = wave.clamp(0.4, 1.6);

        let current_down = (base_down as f64 * wave).max(50_000.0) as u64;
        let current_up = (base_up as f64 * (2.0 - wave)).max(10_000.0) as u64;

        let total = Throughput {
            upload_bytes_per_second: current_up,
            download_bytes_per_second: current_down,
        };
        let internet = total.clone();
        let internal = Throughput {
            upload_bytes_per_second: current_up / 10,
            download_bytes_per_second: current_down / 10,
        };

        let mut client_map: HashMap<String, Throughput> = HashMap::new();
        let mut client_scopes: HashMap<String, ScopedThroughput> = HashMap::new();
        for client in clients {
            let cl_down = (current_down as f64 * client.weight) as u64;
            let cl_up = (current_up as f64 * client.weight) as u64;
            let tp = Throughput {
                upload_bytes_per_second: cl_up,
                download_bytes_per_second: cl_down,
            };
            client_map.insert(client.ip.clone(), tp.clone());
            client_scopes.insert(
                client.ip.clone(),
                ScopedThroughput {
                    internet: tp.clone(),
                    internal: Throughput {
                        upload_bytes_per_second: cl_up / 10,
                        download_bytes_per_second: cl_down / 10,
                    },
                    tunnel: Throughput::default(),
                    unknown: Throughput::default(),
                },
            );
        }

        let mut app_map: HashMap<String, Throughput> = HashMap::new();
        for app in apps {
            let app_down = (current_down as f64 * app.weight) as u64;
            let app_up = (current_up as f64 * app.weight) as u64;
            app_map.insert(
                app.id.clone(),
                Throughput {
                    upload_bytes_per_second: app_up,
                    download_bytes_per_second: app_down,
                },
            );
        }

        let mut active_flows = base_flows.to_vec();
        for flow in &mut active_flows {
            flow.last_seen = now;
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

        let delta_bytes_down = current_down.saturating_mul(3);
        let delta_bytes_up = current_up.saturating_mul(3);
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
            total,
            internet,
            internal,
            tunnel: Throughput::default(),
            unknown: Throughput::default(),
            clients: client_map,
            client_scopes,
            applications: app_map,
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
}
