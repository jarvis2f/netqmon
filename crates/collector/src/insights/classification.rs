use rusqlite::{Connection, params};
use serde_json::json;

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

pub fn query_unknown_ratio_insight(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Option<Insight>> {
    let (unknown_bytes, total_bytes, observed_at): (i64, i64, Option<i64>) = connection.query_row(
        "SELECT
             COALESCE(SUM(CASE WHEN application_id = 'unknown'
                               THEN upload_bytes + download_bytes ELSE 0 END), 0),
             COALESCE(SUM(upload_bytes + download_bytes), 0),
             MAX(timestamp)
         FROM traffic_application_minute
         WHERE timestamp >= ?1 AND timestamp < ?2",
        params![to_i64(window.from), to_i64(window.to)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if total_bytes <= 0 {
        return Ok(None);
    }
    let ratio_parts_per_million = unknown_bytes.saturating_mul(1_000_000) / total_bytes;
    let ratio =
        f64::from(u32::try_from(ratio_parts_per_million).unwrap_or(1_000_000)) / 1_000_000.0;
    let percent = ratio * 100.0;
    let time = observed_at.unwrap_or_else(|| to_i64(window.to));
    Ok(Some(Insight {
        id: format!("unknown-traffic-{}-{}", window.from, window.to),
        category: "classification".to_owned(),
        code: "classification.unknown_ratio_high".to_owned(),
        severity: if ratio >= 0.1 {
            InsightSeverity::Warning
        } else {
            InsightSeverity::Info
        },
        time,
        source: "classifier".to_owned(),
        affected_client: None,
        params: json!({
            "unknown_bytes": unknown_bytes,
            "total_bytes": total_bytes,
            "ratio": ratio,
            "percent": format!("{percent:.1}"),
        }),
        evidence: json!({
            "unknown_bytes": unknown_bytes,
            "total_bytes": total_bytes,
            "ratio": ratio,
            "window_from": window.from,
            "window_to": window.to,
            "rule": "application_id = unknown",
        }),
        fingerprint: None,
        status: None,
        first_seen: Some(time),
        last_seen: Some(time),
        occurrences: Some(1),
        confidence: Some(1.0),
    }))
}

pub fn query_client_unknown_ratio_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT flow_sessions.device_id,
                COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
                devices.mac,
                flow_sessions.client_ip,
                SUM(CASE WHEN flow_sessions.application_id = 'unknown'
                         THEN flow_sessions.upload_bytes + flow_sessions.download_bytes ELSE 0 END) AS unknown_bytes,
                SUM(flow_sessions.upload_bytes + flow_sessions.download_bytes) AS total_bytes,
                MAX(flow_sessions.last_seen_at)
         FROM flow_sessions
         LEFT JOIN devices ON devices.id = flow_sessions.device_id
         WHERE flow_sessions.last_seen_at >= ?1 AND flow_sessions.last_seen_at < ?2
         GROUP BY flow_sessions.device_id, flow_sessions.client_ip, devices.display_name, devices.hostname, devices.mac
         HAVING total_bytes >= 1048576 AND unknown_bytes * 2 >= total_bytes
         ORDER BY unknown_bytes DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![to_i64(window.from), to_i64(window.to), window.limit],
            |row| {
                let device_id: Option<i64> = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Option<Vec<u8>> = row.get(2)?;
                let client_ip: Vec<u8> = row.get(3)?;
                let unknown_bytes: i64 = row.get(4)?;
                let total_bytes: i64 = row.get(5)?;
                let time: i64 = row.get(6)?;
                let client_ip_text = format_ip(&client_ip);
                let mac_text = mac.as_deref().map(format_mac);
                let ratio = if total_bytes > 0 {
                    (unknown_bytes as f64) / (total_bytes as f64)
                } else {
                    0.0
                };
                let percent = ratio * 100.0;
                Ok(Insight {
                    id: format!(
                        "client-unknown-traffic-{client_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "classification".to_owned(),
                    code: "classification.client_unknown_ratio_high".to_owned(),
                    severity: if ratio >= 0.8 {
                        InsightSeverity::Warning
                    } else {
                        InsightSeverity::Notice
                    },
                    time,
                    source: "classifier".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: device_id,
                        name: name.clone(),
                        mac: mac_text.clone(),
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "client": name,
                        "unknown_bytes": unknown_bytes,
                        "total_bytes": total_bytes,
                        "ratio": ratio,
                        "percent": format!("{percent:.1}"),
                    }),
                    evidence: json!({
                        "client_ip": client_ip_text,
                        "unknown_bytes": unknown_bytes,
                        "total_bytes": total_bytes,
                        "ratio": ratio,
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
