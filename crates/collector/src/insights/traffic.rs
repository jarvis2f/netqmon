use rusqlite::{Connection, params};
use serde_json::json;

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

pub fn query_high_upload_insights(
    connection: &Connection,
    window: InsightWindow,
    threshold_bytes: u64,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT devices.id,
                COALESCE(devices.display_name, devices.hostname, 'Unknown device'),
                devices.mac, SUM(traffic_device_minute.upload_bytes),
                MAX(traffic_device_minute.timestamp),
                (SELECT ip FROM device_addresses
                 WHERE device_addresses.device_id = devices.id
                 ORDER BY last_seen DESC, ip_version ASC LIMIT 1)
         FROM traffic_device_minute
         JOIN devices ON devices.id = traffic_device_minute.device_id
         WHERE traffic_device_minute.timestamp >= ?1
           AND traffic_device_minute.timestamp < ?2
         GROUP BY devices.id, devices.display_name, devices.hostname, devices.mac
         HAVING SUM(traffic_device_minute.upload_bytes) >= ?3
         ORDER BY SUM(traffic_device_minute.upload_bytes) DESC, devices.id ASC",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                to_i64(threshold_bytes)
            ],
            |row| {
                let id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Vec<u8> = row.get(2)?;
                let upload_bytes: i64 = row.get(3)?;
                let time: i64 = row.get(4)?;
                let ip: Option<Vec<u8>> = row.get(5)?;
                let mac = format_mac(&mac);
                let ip = ip.as_deref().map(format_ip);
                Ok(Insight {
                    id: format!("high-upload-{id}-{}-{}", window.from, window.to),
                    category: "traffic".to_owned(),
                    code: "traffic.high_upload".to_owned(),
                    severity: InsightSeverity::Warning,
                    time,
                    source: "traffic-history".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: Some(id),
                        name: name.clone(),
                        mac: Some(mac.clone()),
                        ip: ip.clone(),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "upload_bytes": upload_bytes,
                        "bytes": upload_bytes,
                        "tx_bytes": upload_bytes,
                        "threshold_bytes": threshold_bytes,
                    }),
                    evidence: json!({
                        "upload_bytes": upload_bytes,
                        "threshold_bytes": threshold_bytes,
                        "window_from": window.from,
                        "window_to": window.to,
                        "action": "observation_only",
                    }),
                    fingerprint: None,
                    status: None,
                    first_seen: Some(time),
                    last_seen: Some(time),
                    occurrences: Some(1),
                    confidence: Some(1.0),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}

pub fn query_client_spike_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let window_duration = window.to.saturating_sub(window.from);
    let baseline_from = window.from.saturating_sub(window_duration);
    let mut statement = connection.prepare(
        "WITH current_window AS (
            SELECT device_id, SUM(upload_bytes + download_bytes) AS current_bytes, MAX(timestamp) AS last_seen
            FROM traffic_device_minute
            WHERE timestamp >= ?1 AND timestamp < ?2
            GROUP BY device_id
            HAVING current_bytes >= 10485760
         ),
         baseline_window AS (
            SELECT device_id, SUM(upload_bytes + download_bytes) AS baseline_bytes
            FROM traffic_device_minute
            WHERE timestamp >= ?3 AND timestamp < ?1
            GROUP BY device_id
         )
         SELECT c.device_id,
                COALESCE(devices.display_name, devices.hostname, 'Unknown device'),
                devices.mac,
                c.current_bytes,
                COALESCE(b.baseline_bytes, 0) AS baseline_bytes,
                c.last_seen,
                (SELECT ip FROM device_addresses
                 WHERE device_addresses.device_id = c.device_id
                 ORDER BY last_seen DESC, ip_version ASC LIMIT 1)
         FROM current_window c
         JOIN baseline_window b ON b.device_id = c.device_id
         JOIN devices ON devices.id = c.device_id
         WHERE b.baseline_bytes > 0 AND c.current_bytes >= (b.baseline_bytes * 3)
         ORDER BY c.current_bytes DESC
         LIMIT ?4",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                to_i64(baseline_from),
                window.limit
            ],
            |row| {
                let id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Vec<u8> = row.get(2)?;
                let current_bytes: i64 = row.get(3)?;
                let baseline_bytes: i64 = row.get(4)?;
                let time: i64 = row.get(5)?;
                let ip: Option<Vec<u8>> = row.get(6)?;
                let mac = format_mac(&mac);
                let ip = ip.as_deref().map(format_ip);
                let multiplier = (current_bytes as f64) / (baseline_bytes as f64);
                Ok(Insight {
                    id: format!("client-spike-{id}-{}-{}", window.from, window.to),
                    category: "traffic".to_owned(),
                    code: "traffic.client_spike".to_owned(),
                    severity: if multiplier >= 5.0 {
                        InsightSeverity::Warning
                    } else {
                        InsightSeverity::Notice
                    },
                    time,
                    source: "traffic-history".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: Some(id),
                        name: name.clone(),
                        mac: Some(mac.clone()),
                        ip: ip.clone(),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "bytes": current_bytes,
                        "current_bytes": current_bytes,
                        "baseline_bytes": baseline_bytes,
                        "multiplier": format!("{multiplier:.1}"),
                        "ratio": format!("{multiplier:.1}x"),
                    }),
                    evidence: json!({
                        "current_bytes": current_bytes,
                        "baseline_bytes": baseline_bytes,
                        "multiplier": multiplier,
                        "window_from": window.from,
                        "window_to": window.to,
                    }),
                    fingerprint: None,
                    status: None,
                    first_seen: Some(time),
                    last_seen: Some(time),
                    occurrences: Some(1),
                    confidence: Some(1.0),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}

pub fn query_application_spike_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let window_duration = window.to.saturating_sub(window.from);
    let baseline_from = window.from.saturating_sub(window_duration);
    let mut statement = connection.prepare(
        "WITH current_window AS (
            SELECT application_id, SUM(upload_bytes + download_bytes) AS current_bytes, MAX(timestamp) AS last_seen
            FROM traffic_application_minute
            WHERE timestamp >= ?1 AND timestamp < ?2 AND application_id != 'unknown'
            GROUP BY application_id
            HAVING current_bytes >= 10485760
         ),
         baseline_window AS (
            SELECT application_id, SUM(upload_bytes + download_bytes) AS baseline_bytes
            FROM traffic_application_minute
            WHERE timestamp >= ?3 AND timestamp < ?1 AND application_id != 'unknown'
            GROUP BY application_id
         )
         SELECT c.application_id,
                c.current_bytes,
                b.baseline_bytes,
                c.last_seen
         FROM current_window c
         JOIN baseline_window b ON b.application_id = c.application_id
         WHERE b.baseline_bytes > 0 AND c.current_bytes >= (b.baseline_bytes * 3)
         ORDER BY c.current_bytes DESC
         LIMIT ?4",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                to_i64(baseline_from),
                window.limit
            ],
            |row| {
                let app_id: String = row.get(0)?;
                let current_bytes: i64 = row.get(1)?;
                let baseline_bytes: i64 = row.get(2)?;
                let time: i64 = row.get(3)?;
                let multiplier = (current_bytes as f64) / (baseline_bytes as f64);
                Ok(Insight {
                    id: format!("app-spike-{app_id}-{}-{}", window.from, window.to),
                    category: "traffic".to_owned(),
                    code: "traffic.application_spike".to_owned(),
                    severity: if multiplier >= 5.0 {
                        InsightSeverity::Warning
                    } else {
                        InsightSeverity::Notice
                    },
                    time,
                    source: "traffic-history".to_owned(),
                    affected_client: None,
                    params: json!({
                        "application": app_id,
                        "application_name": app_id,
                        "bytes": current_bytes,
                        "current_bytes": current_bytes,
                        "baseline_bytes": baseline_bytes,
                        "multiplier": format!("{multiplier:.1}"),
                        "ratio": format!("{multiplier:.1}x"),
                    }),
                    evidence: json!({
                        "application_id": app_id,
                        "current_bytes": current_bytes,
                        "baseline_bytes": baseline_bytes,
                        "multiplier": multiplier,
                        "window_from": window.from,
                        "window_to": window.to,
                    }),
                    fingerprint: None,
                    status: None,
                    first_seen: Some(time),
                    last_seen: Some(time),
                    occurrences: Some(1),
                    confidence: Some(1.0),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}
