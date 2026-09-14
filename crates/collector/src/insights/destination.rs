use rusqlite::{Connection, params};
use serde_json::json;

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

pub fn query_fanout_spike_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT flow_sessions.device_id,
                COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
                devices.mac,
                flow_sessions.client_ip,
                COUNT(DISTINCT flow_sessions.remote_ip) AS dest_count,
                MAX(flow_sessions.last_seen_at)
         FROM flow_sessions
         LEFT JOIN devices ON devices.id = flow_sessions.device_id
         WHERE flow_sessions.last_seen_at >= ?1 AND flow_sessions.last_seen_at < ?2
         GROUP BY flow_sessions.device_id, flow_sessions.client_ip, devices.display_name, devices.hostname, devices.mac
         HAVING dest_count >= 50
         ORDER BY dest_count DESC
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
                let dest_count: i64 = row.get(4)?;
                let time: i64 = row.get(5)?;
                let client_ip_text = format_ip(&client_ip);
                let mac_text = mac.as_deref().map(format_mac);
                Ok(Insight {
                    id: format!(
                        "fanout-spike-{client_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "destination".to_owned(),
                    code: "destination.fanout_spike".to_owned(),
                    severity: if dest_count >= 100 {
                        InsightSeverity::Warning
                    } else {
                        InsightSeverity::Notice
                    },
                    time,
                    source: "flow-history".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: device_id,
                        name: name.clone(),
                        mac: mac_text,
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "count": dest_count,
                        "destination_count": dest_count,
                    }),
                    evidence: json!({
                        "client_ip": client_ip_text,
                        "destination_count": dest_count,
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
