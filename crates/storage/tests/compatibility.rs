#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use netqmon_protocol::v1::{DnsObservation, FlowDelta, FlowLifecycle, TelemetryBatch};
use netqmon_storage::{
    ClickHouseConfig, ClickHouseStorage, FlowAttribution, PersistDisposition, RetentionPolicy,
    SqliteStorage, StorageBackend,
};
use serde_json::{Value, json};

#[derive(Default)]
struct MockClickHouseDb {
    gateways: Vec<Value>,
    users: Vec<Value>,
    auth_sessions: Vec<Value>,
    devices: Vec<Value>,
    device_addresses: Vec<Value>,
    dns_observations: Vec<Value>,
    flow_sessions: Vec<Value>,
    ingest_batches: Vec<Value>,
    settings: HashMap<String, String>,
    traffic_total_minute: Vec<Value>,
}

fn start_mock_clickhouse() -> Option<(String, Arc<Mutex<MockClickHouseDb>>, Arc<AtomicBool>)> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("bind mock clickhouse: {e}"),
    };
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}");
    let db = Arc::new(Mutex::new(MockClickHouseDb::default()));
    let running = Arc::new(AtomicBool::new(true));

    let db_clone = Arc::clone(&db);
    let running_clone = Arc::clone(&running);

    thread::spawn(move || {
        listener.set_nonblocking(true).expect("set nonblocking");
        while running_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    handle_client(&mut stream, &db_clone);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    Some((url, db, running))
}

fn handle_client(stream: &mut TcpStream, db: &Arc<Mutex<MockClickHouseDb>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }

    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(val) = line.to_lowercase().strip_prefix("content-length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok();
    let body_str = String::from_utf8_lossy(&body);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let uri = parts.get(1).copied().unwrap_or("/");

    let response_body = if uri.contains("INSERT%20INTO") || uri.contains("INSERT INTO") {
        let mut mock = db.lock().unwrap();
        let table = if uri.contains("auth_sessions") {
            "auth_sessions"
        } else if uri.contains("gateways") {
            "gateways"
        } else if uri.contains("users") {
            "users"
        } else if uri.contains("devices") && !uri.contains("device_addresses") {
            "devices"
        } else if uri.contains("device_addresses") {
            "device_addresses"
        } else if uri.contains("dns_observations") {
            "dns_observations"
        } else if uri.contains("flow_sessions") {
            "flow_sessions"
        } else if uri.contains("ingest_batches") {
            "ingest_batches"
        } else if uri.contains("traffic_total_minute") {
            "traffic_total_minute"
        } else if uri.contains("settings") {
            "settings"
        } else {
            "other"
        };

        for line in body_str.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                match table {
                    "auth_sessions" => mock.auth_sessions.push(v),
                    "gateways" => mock.gateways.push(v),
                    "users" => mock.users.push(v),
                    "devices" => mock.devices.push(v),
                    "device_addresses" => mock.device_addresses.push(v),
                    "dns_observations" => mock.dns_observations.push(v),
                    "flow_sessions" => mock.flow_sessions.push(v),
                    "ingest_batches" => mock.ingest_batches.push(v),
                    "traffic_total_minute" => mock.traffic_total_minute.push(v),
                    "settings" => {
                        let key = v["key"].as_str().unwrap_or("").to_owned();
                        let val = v["value"].as_str().unwrap_or("").to_owned();
                        mock.settings.insert(key, val);
                    }
                    _ => {}
                }
            }
        }
        String::new()
    } else if body_str.trim().starts_with("CREATE TABLE")
        || body_str.trim().starts_with("CREATE DATABASE")
    {
        String::new()
    } else if body_str.contains("ALTER TABLE auth_sessions DELETE") {
        let mut mock = db.lock().unwrap();
        // Extract token_hash from query: WHERE token_hash = '...'
        if let Some(pos) = body_str.find("token_hash = '") {
            let start = pos + 14;
            if let Some(end) = body_str[start..].find('\'') {
                let token_hash = &body_str[start..start + end];
                mock.auth_sessions
                    .retain(|row| row["token_hash"].as_str() != Some(token_hash));
            }
        }
        String::new()
    } else if body_str.contains("INSERT INTO settings") {
        let mut mock = db.lock().unwrap();
        if let Some(pos) = body_str.find("VALUES ('") {
            let rest = &body_str[pos + 9..];
            let parts: Vec<&str> = rest.split("', '").collect();
            if parts.len() >= 2 {
                let key = parts[0];
                let val = parts[1].split('\'').next().unwrap_or("");
                mock.settings.insert(key.to_owned(), val.to_owned());
            }
        }
        String::new()
    } else if body_str.contains("FROM settings") {
        let mock = db.lock().unwrap();
        if let Some(pos) = body_str.find("key = '") {
            let start = pos + 7;
            if let Some(end) = body_str[start..].find('\'') {
                let key = &body_str[start..start + end];
                if let Some(val) = mock.settings.get(key) {
                    serde_json::to_string(&json!({
                        "data": [{ "value": val }]
                    }))
                    .unwrap()
                } else {
                    serde_json::to_string(&json!({ "data": [] })).unwrap()
                }
            } else {
                serde_json::to_string(&json!({ "data": [] })).unwrap()
            }
        } else {
            serde_json::to_string(&json!({ "data": [] })).unwrap()
        }
    } else if body_str.contains("INSERT INTO gateways") {
        let mut mock = db.lock().unwrap();
        let Some(current) = mock
            .gateways
            .iter()
            .max_by_key(|gateway| gateway["last_seen"].as_i64().unwrap_or(0))
            .cloned()
        else {
            return;
        };
        let current_last_seen = current["last_seen"].as_i64().unwrap_or(0);
        let cutoff = body_str
            .split("AND last_seen <= ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(i64::MIN);
        if current_last_seen <= cutoff {
            let Some(select_values) = body_str.split("SELECT id, site_id, '").nth(1) else {
                return;
            };
            let Some((name, select_values)) = select_values.split_once("', '") else {
                return;
            };
            let Some((agent_hash, select_values)) = select_values.split_once("', '") else {
                return;
            };
            let Some((agent_version, select_values)) = select_values.split_once("', arch") else {
                return;
            };
            let Some(now) = select_values
                .split("openwrt_version, 'online', ")
                .nth(1)
                .and_then(|value| value.split(", created_at").next())
                .and_then(|value| value.trim().parse::<i64>().ok())
            else {
                return;
            };
            let mut replacement = current;
            replacement["name"] = Value::String(name.to_owned());
            replacement["agent_token_hash"] = Value::String(agent_hash.to_owned());
            replacement["agent_version"] = Value::String(agent_version.to_owned());
            replacement["status"] = Value::String("online".to_owned());
            replacement["last_seen"] = json!(now);
            mock.gateways.push(replacement);
        }
        String::new()
    } else if body_str.contains("FROM gateways") {
        let mock = db.lock().unwrap();
        let mut latest = HashMap::<String, Value>::new();
        for gateway in &mock.gateways {
            let id = gateway["id"].as_str().unwrap_or("").to_owned();
            let is_newer = latest.get(&id).is_none_or(|current| {
                gateway["last_seen"].as_i64().unwrap_or(0)
                    >= current["last_seen"].as_i64().unwrap_or(0)
            });
            if is_newer {
                latest.insert(id, gateway.clone());
            }
        }
        let rows: Vec<Value> = latest
            .values()
            .map(|g| {
                json!({
                    "id": g["id"],
                    "name": g["name"],
                    "agent_version": g["agent_version"],
                    "agent_token_hash": g["agent_token_hash"],
                    "kernel_version": g["kernel_version"],
                    "openwrt_version": g["openwrt_version"],
                    "last_seen": g["last_seen"],
                })
            })
            .collect();
        serde_json::to_string(&json!({ "data": rows })).unwrap()
    } else if body_str.contains("FROM users") {
        let mock = db.lock().unwrap();
        if body_str.contains("count() AS count") {
            let count = mock.users.len();
            serde_json::to_string(&json!({ "data": [{ "count": count }] })).unwrap()
        } else if let Some(pos) = body_str.find("username = '") {
            let start = pos + 12;
            let end = body_str[start..].find('\'').unwrap_or(0);
            let username = &body_str[start..start + end];
            let found: Vec<Value> = mock
                .users
                .iter()
                .filter(|u| u["username"].as_str() == Some(username))
                .cloned()
                .collect();
            serde_json::to_string(&json!({ "data": found })).unwrap()
        } else {
            serde_json::to_string(&json!({ "data": mock.users })).unwrap()
        }
    } else if body_str.contains("FROM auth_sessions") {
        let mock = db.lock().unwrap();
        if let Some(pos) = body_str.find("s.token_hash = '") {
            let start = pos + 16;
            let end = body_str[start..].find('\'').unwrap_or(0);
            let token_hash = &body_str[start..start + end];
            let mut found = Vec::new();
            for s in &mock.auth_sessions {
                if s["token_hash"].as_str() == Some(token_hash) {
                    let user_id = s["user_id"].as_str().unwrap_or("");
                    let username = mock
                        .users
                        .iter()
                        .find(|u| u["id"].as_str() == Some(user_id))
                        .and_then(|u| u["username"].as_str())
                        .unwrap_or("admin");
                    found.push(json!({
                        "user_id": user_id,
                        "username": username,
                        "expires_at": s["expires_at"]
                    }));
                }
            }
            serde_json::to_string(&json!({ "data": found })).unwrap()
        } else {
            serde_json::to_string(&json!({ "data": [] })).unwrap()
        }
    } else if body_str.contains("FROM ingest_batches") {
        let mock = db.lock().unwrap();
        // dup check: gateway_id, boot_id, sequence
        let mut count = 0;
        if let (Some(g_pos), Some(b_pos), Some(s_pos)) = (
            body_str.find("gateway_id = '"),
            body_str.find("boot_id = '"),
            body_str.find("sequence = "),
        ) {
            let g =
                &body_str[g_pos + 14..g_pos + 14 + body_str[g_pos + 14..].find('\'').unwrap_or(0)];
            let b =
                &body_str[b_pos + 11..b_pos + 11 + body_str[b_pos + 11..].find('\'').unwrap_or(0)];
            let seq_str = body_str[s_pos + 11..]
                .split_whitespace()
                .next()
                .unwrap_or("0");
            let seq: i64 = seq_str.parse().unwrap_or(0);
            for batch in &mock.ingest_batches {
                if batch["gateway_id"].as_str() == Some(g)
                    && batch["boot_id"].as_str() == Some(b)
                    && batch["sequence"].as_i64() == Some(seq)
                {
                    count += 1;
                }
            }
        }
        serde_json::to_string(&json!({ "data": [{ "count": count }] })).unwrap()
    } else if body_str.contains("FROM dns_observations") {
        let mock = db.lock().unwrap();
        let rows: Vec<Value> = mock
            .dns_observations
            .iter()
            .map(|d| {
                json!({
                    "domain": d["domain"],
                    "ttl_seconds": d["ttl_seconds"],
                    "observed_at": d["observed_at"]
                })
            })
            .collect();
        serde_json::to_string(&json!({ "data": rows })).unwrap()
    } else if body_str.contains("FROM traffic_total_minute") {
        let mock = db.lock().unwrap();
        let mut total_up: i64 = 0;
        let mut total_down: i64 = 0;
        let mut total_pkts: i64 = 0;
        let mut total_flows: i64 = 0;
        let mut ts: i64 = 0;

        for r in &mock.traffic_total_minute {
            ts = r["timestamp"].as_i64().unwrap_or(0);
            total_up += r["upload_bytes"].as_i64().unwrap_or(0);
            total_down += r["download_bytes"].as_i64().unwrap_or(0);
            total_pkts += r["packets"].as_i64().unwrap_or(0);
            total_flows += r["flow_count"].as_i64().unwrap_or(0);
        }

        if mock.traffic_total_minute.is_empty() {
            serde_json::to_string(&json!({ "data": [] })).unwrap()
        } else {
            serde_json::to_string(&json!({
                "data": [{
                    "timestamp": ts,
                    "upload_bytes": total_up,
                    "download_bytes": total_down,
                    "packets": total_pkts,
                    "flow_count": total_flows
                }]
            }))
            .unwrap()
        }
    } else if body_str.contains("FROM flow_sessions") {
        let mock = db.lock().unwrap();
        serde_json::to_string(&json!({ "data": [{ "c": mock.flow_sessions.len() }] })).unwrap()
    } else {
        serde_json::to_string(&json!({ "data": [] })).unwrap()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    stream.write_all(response.as_bytes()).ok();
}

#[test]
fn backend_compatibility_identical_fixtures_and_semantic_parity() {
    let mut sqlite = SqliteStorage::open_in_memory().expect("sqlite in-memory opened");

    let Some((mock_url, _mock_db, running)) = start_mock_clickhouse() else {
        return;
    };
    let ch_config = ClickHouseConfig {
        url: mock_url,
        database: "default".to_owned(),
        user: None,
        password: None,
        timeout_ms: 3000,
    };
    let mut clickhouse = match ClickHouseStorage::open(ch_config) {
        Ok(ch) => ch,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
                return;
            }
            panic!("clickhouse storage opened: {e:?}");
        }
    };

    // 1. Gateway registration
    let token_hash = [42u8; 32];
    assert!(
        sqlite
            .save_gateway("gw-100", "Main Gateway", "1.0.0", &token_hash, 1_000)
            .unwrap()
    );
    assert!(
        clickhouse
            .save_gateway("gw-100", "Main Gateway", "1.0.0", &token_hash, 1_000)
            .unwrap()
    );

    let sqlite_gw = sqlite.gateway().unwrap().expect("sqlite gateway");
    let ch_gw = clickhouse.gateway().unwrap().expect("clickhouse gateway");

    assert_eq!(sqlite_gw.id, ch_gw.id);
    assert_eq!(sqlite_gw.agent_token_hash, ch_gw.agent_token_hash);
    assert_eq!(sqlite_gw.last_seen_ms, ch_gw.last_seen_ms);

    assert!(
        clickhouse
            .replace_stale_gateway(
                "gw-100",
                "Replacement Gateway",
                "0.1.0-beta.4",
                &[9; 32],
                1_000,
                2_000,
            )
            .unwrap()
    );
    let replaced = clickhouse.gateway().unwrap().expect("replaced gateway");
    assert_eq!(replaced.id, "gw-100");
    assert_eq!(replaced.agent_token_hash, [9; 32]);
    assert_eq!(replaced.last_seen_ms, 2_000);
    assert!(
        !clickhouse
            .replace_stale_gateway(
                "gw-100",
                "Should Not Replace",
                "0.1.0-beta.4",
                &[11; 32],
                1_999,
                3_000,
            )
            .unwrap()
    );

    // 2. Admin user management
    assert!(!sqlite.admin_exists().unwrap());
    assert!(!clickhouse.admin_exists().unwrap());

    assert!(
        sqlite
            .create_admin("u-1", "admin", "hash123", 1_000)
            .unwrap()
    );
    assert!(
        clickhouse
            .create_admin("u-1", "admin", "hash123", 1_000)
            .unwrap()
    );

    assert!(sqlite.admin_exists().unwrap());
    assert!(clickhouse.admin_exists().unwrap());

    let sqlite_user = sqlite
        .user_by_username("admin")
        .unwrap()
        .expect("sqlite user");
    let ch_user = clickhouse
        .user_by_username("admin")
        .unwrap()
        .expect("ch user");

    assert_eq!(sqlite_user.id, ch_user.id);
    assert_eq!(sqlite_user.username, ch_user.username);
    assert_eq!(sqlite_user.password_hash, ch_user.password_hash);

    // 3. Auth Sessions & deletion
    let session_token = [7u8; 32];
    sqlite
        .create_session("u-1", &session_token, 1_000, 10_000)
        .unwrap();
    clickhouse
        .create_session("u-1", &session_token, 1_000, 10_000)
        .unwrap();

    let s_session = sqlite
        .session(&session_token, 2_000)
        .unwrap()
        .expect("sqlite session");
    let ch_session = clickhouse
        .session(&session_token, 2_000)
        .unwrap()
        .expect("ch session");

    assert_eq!(s_session.user_id, ch_session.user_id);
    assert_eq!(s_session.username, ch_session.username);

    sqlite.delete_session(&session_token).unwrap();
    clickhouse.delete_session(&session_token).unwrap();

    assert!(sqlite.session(&session_token, 2_000).unwrap().is_none());
    assert!(clickhouse.session(&session_token, 2_000).unwrap().is_none());

    // 4. Batch persistence & deduplication
    let batch = TelemetryBatch {
        gateway_id: "gw-100".to_owned(),
        boot_id: "boot-xyz".to_owned(),
        sequence: 1,
        sent_at: 60_000,
        flows: vec![FlowDelta {
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 168, 1, 100],
            client_port: 54321,
            remote_ip: vec![93, 184, 216, 34],
            remote_port: 443,
            direction: 1,
            lifecycle: FlowLifecycle::Ended as i32,
            client_mac: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            first_seen_unix_ms: 60_000,
            last_seen_unix_ms: 60_000,
            upload_bytes: 1500,
            download_bytes: 4500,
            packets: 20,
            ..FlowDelta::default()
        }],
        dns_observations: vec![DnsObservation {
            client_ip: vec![192, 168, 1, 100],
            domain: "example.com".to_owned(),
            answer_ip: vec![93, 184, 216, 34],
            record_type: 1,
            ttl_seconds: 300,
            observed_at_unix_ms: 60_000,
        }],
        ..TelemetryBatch::default()
    };

    let attributions = vec![FlowAttribution {
        domain: Some("example.com".to_owned()),
        application_id: "web".to_owned(),
        category_id: "internet".to_owned(),
        confidence: 0.95,
        reason: "dns".to_owned(),
        ..FlowAttribution::default()
    }];

    let s_disp = sqlite
        .persist_classified_batch(&batch, &attributions, &[], 60_000)
        .unwrap();
    let ch_disp = clickhouse
        .persist_classified_batch(&batch, &attributions, &[], 60_000)
        .unwrap();

    assert_eq!(s_disp, PersistDisposition::Accepted);
    assert_eq!(ch_disp, PersistDisposition::Accepted);
    let gateway_after_batch = clickhouse.gateway().unwrap().expect("gateway after batch");
    assert_eq!(gateway_after_batch.agent_token_hash, [9; 32]);

    // Duplicate batch check
    let s_dup = sqlite
        .persist_classified_batch(&batch, &attributions, &[], 60_000)
        .unwrap();
    let ch_dup = clickhouse
        .persist_classified_batch(&batch, &attributions, &[], 60_000)
        .unwrap();

    assert_eq!(s_dup, PersistDisposition::Duplicate);
    assert_eq!(ch_dup, PersistDisposition::Duplicate);

    // 5. DNS Resolution
    let s_dom = sqlite
        .resolve_domain("gw-100", &[192, 168, 1, 100], &[93, 184, 216, 34], 60_001)
        .unwrap();
    let ch_dom = clickhouse
        .resolve_domain("gw-100", &[192, 168, 1, 100], &[93, 184, 216, 34], 60_001)
        .unwrap();

    assert_eq!(s_dom, Some("example.com".to_owned()));
    assert_eq!(ch_dom, Some("example.com".to_owned()));

    // 6. Traffic Totals
    let s_traffic = sqlite.query_total_traffic(0, 120_000).unwrap();
    let ch_traffic = clickhouse.query_total_traffic(0, 120_000).unwrap();

    assert_eq!(s_traffic.len(), ch_traffic.len());
    if !s_traffic.is_empty() {
        assert_eq!(s_traffic[0].upload_bytes, ch_traffic[0].upload_bytes);
        assert_eq!(s_traffic[0].download_bytes, ch_traffic[0].download_bytes);
        assert_eq!(s_traffic[0].packets, ch_traffic[0].packets);
        assert_eq!(s_traffic[0].flow_count, ch_traffic[0].flow_count);
    }

    // 7. Retention Policy Roundtrip
    let policy = RetentionPolicy {
        flow_sessions_days: 14,
        dns_days: 7,
        minute_days: 2,
        hour_days: 30,
        day_days: 365,
    };
    sqlite.save_retention_policy(&policy, 60_000).unwrap();
    clickhouse.save_retention_policy(&policy, 60_000).unwrap();

    let s_pol = sqlite.load_retention_policy().unwrap();
    let ch_pol = clickhouse.load_retention_policy().unwrap();

    assert_eq!(s_pol.flow_sessions_days, ch_pol.flow_sessions_days);
    assert_eq!(s_pol.dns_days, ch_pol.dns_days);
    assert_eq!(s_pol.minute_days, ch_pol.minute_days);
    assert_eq!(s_pol.hour_days, ch_pol.hour_days);
    assert_eq!(s_pol.day_days, ch_pol.day_days);

    running.store(false, Ordering::Relaxed);
}
