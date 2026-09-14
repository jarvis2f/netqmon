use rusqlite::{Connection, params};
use serde_json::json;

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

const PT_CORRELATION_WINDOW_MS: i64 = 30 * 60 * 1000;

pub fn query_pt_tracker_correlation_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT
             COALESCE(devices.id, -1),
             COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
             devices.mac,
             tracker.client_ip,
             COUNT(DISTINCT tracker.id),
             COUNT(DISTINCT peer.id),
             SUM(tracker.upload_bytes + tracker.download_bytes),
             SUM(peer.upload_bytes + peer.download_bytes),
             MAX(CASE
                   WHEN tracker.last_seen_at >= peer.last_seen_at
                   THEN tracker.last_seen_at ELSE peer.last_seen_at
                 END)
         FROM flow_sessions tracker
         JOIN flow_sessions peer
           ON tracker.client_ip = peer.client_ip
          AND tracker.id <> peer.id
          AND peer.protocol_id = 'bittorrent'
          AND ABS(tracker.last_seen_at - peer.last_seen_at) <= ?4
          AND peer.last_seen_at >= ?1 AND peer.last_seen_at < ?2
         LEFT JOIN devices
           ON devices.id = COALESCE(tracker.device_id, peer.device_id)
         WHERE tracker.traffic_role = 'tracker_service'
           AND tracker.category_id = 'p2p'
           AND tracker.last_seen_at >= ?1 AND tracker.last_seen_at < ?2
         GROUP BY tracker.client_ip, devices.id, devices.display_name, devices.hostname, devices.mac
         ORDER BY MAX(CASE
                   WHEN tracker.last_seen_at >= peer.last_seen_at
                   THEN tracker.last_seen_at ELSE peer.last_seen_at
                 END) DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                window.limit,
                PT_CORRELATION_WINDOW_MS
            ],
            |row| {
                let device_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Option<Vec<u8>> = row.get(2)?;
                let client_ip: Vec<u8> = row.get(3)?;
                let tracker_flows: i64 = row.get(4)?;
                let peer_flows: i64 = row.get(5)?;
                let tracker_bytes: Option<i64> = row.get(6)?;
                let peer_bytes: Option<i64> = row.get(7)?;
                let time: i64 = row.get(8)?;
                let client_ip_text = format_ip(&client_ip);
                Ok(Insight {
                    id: format!(
                        "pt-bittorrent-correlation-{client_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "protocol".to_owned(),
                    code: "protocol.p2p_tracker_correlation".to_owned(),
                    severity: InsightSeverity::Notice,
                    time,
                    source: "classifier-correlation".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: if device_id >= 0 {
                            Some(device_id)
                        } else {
                            None
                        },
                        name: name.clone(),
                        mac: mac.as_deref().map(format_mac),
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "tracker_flows": tracker_flows,
                        "peer_flows": peer_flows,
                    }),
                    evidence: json!({
                        "tracker_role": "tracker_service",
                        "tracker_class": "p2p",
                        "peer_protocol": "bittorrent",
                        "tracker_flows": tracker_flows,
                        "peer_flows": peer_flows,
                        "tracker_bytes": tracker_bytes.unwrap_or(0),
                        "peer_bytes": peer_bytes.unwrap_or(0),
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

pub fn query_ike_esp_correlation_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT
             COALESCE(devices.id, -1),
             COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
             devices.mac,
             ike.client_ip,
             ike.remote_ip,
             COUNT(DISTINCT ike.id),
             COUNT(DISTINCT esp.id),
             SUM(ike.upload_bytes + ike.download_bytes),
             SUM(esp.upload_bytes + esp.download_bytes),
             MAX(CASE
                   WHEN ike.last_seen_at >= esp.last_seen_at
                   THEN ike.last_seen_at ELSE esp.last_seen_at
                 END)
         FROM flow_sessions ike
         JOIN flow_sessions esp
           ON ike.client_ip = esp.client_ip
          AND ike.remote_ip = esp.remote_ip
          AND ike.id <> esp.id
          AND esp.protocol_id = 'ipsec_esp'
          AND ABS(ike.last_seen_at - esp.last_seen_at) <= ?4
          AND esp.last_seen_at >= ?1 AND esp.last_seen_at < ?2
         LEFT JOIN devices
           ON devices.id = COALESCE(ike.device_id, esp.device_id)
         WHERE ike.protocol_id = 'ike'
           AND ike.last_seen_at >= ?1 AND ike.last_seen_at < ?2
         GROUP BY ike.client_ip, ike.remote_ip, devices.id, devices.display_name, devices.hostname, devices.mac
         ORDER BY MAX(CASE
                   WHEN ike.last_seen_at >= esp.last_seen_at
                   THEN ike.last_seen_at ELSE esp.last_seen_at
                 END) DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                window.limit,
                PT_CORRELATION_WINDOW_MS
            ],
            |row| {
                let device_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Option<Vec<u8>> = row.get(2)?;
                let client_ip: Vec<u8> = row.get(3)?;
                let remote_ip: Vec<u8> = row.get(4)?;
                let ike_flows: i64 = row.get(5)?;
                let esp_flows: i64 = row.get(6)?;
                let ike_bytes: Option<i64> = row.get(7)?;
                let esp_bytes: Option<i64> = row.get(8)?;
                let time: i64 = row.get(9)?;
                let client_ip_text = format_ip(&client_ip);
                let remote_ip_text = format_ip(&remote_ip);
                Ok(Insight {
                    id: format!(
                        "ike-esp-correlation-{client_ip_text}-{remote_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "protocol".to_owned(),
                    code: "protocol.ipsec_detected".to_owned(),
                    severity: InsightSeverity::Notice,
                    time,
                    source: "classifier-correlation".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: if device_id >= 0 {
                            Some(device_id)
                        } else {
                            None
                        },
                        name: name.clone(),
                        mac: mac.as_deref().map(format_mac),
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip_text,
                        "remote_ip": remote_ip_text,
                    }),
                    evidence: json!({
                        "remote_ip": remote_ip_text,
                        "ike_flows": ike_flows,
                        "esp_flows": esp_flows,
                        "ike_bytes": ike_bytes.unwrap_or(0),
                        "esp_bytes": esp_bytes.unwrap_or(0),
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

pub fn query_pptp_gre_correlation_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT
             COALESCE(devices.id, -1),
             COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
             devices.mac,
             pptp.client_ip,
             pptp.remote_ip,
             COUNT(DISTINCT pptp.id),
             COUNT(DISTINCT gre.id),
             SUM(pptp.upload_bytes + pptp.download_bytes),
             SUM(gre.upload_bytes + gre.download_bytes),
             MAX(CASE
                   WHEN pptp.last_seen_at >= gre.last_seen_at
                   THEN pptp.last_seen_at ELSE gre.last_seen_at
                 END)
         FROM flow_sessions pptp
         JOIN flow_sessions gre
           ON pptp.client_ip = gre.client_ip
          AND pptp.remote_ip = gre.remote_ip
          AND pptp.id <> gre.id
          AND (gre.protocol_id = 'gre' OR gre.protocol = 47)
          AND ABS(pptp.last_seen_at - gre.last_seen_at) <= ?4
          AND gre.last_seen_at >= ?1 AND gre.last_seen_at < ?2
         LEFT JOIN devices
           ON devices.id = COALESCE(pptp.device_id, gre.device_id)
         WHERE (pptp.protocol_id = 'pptp' OR (pptp.protocol = 6 AND pptp.remote_port = 1723))
           AND pptp.last_seen_at >= ?1 AND pptp.last_seen_at < ?2
         GROUP BY pptp.client_ip, pptp.remote_ip, devices.id, devices.display_name, devices.hostname, devices.mac
         ORDER BY MAX(CASE
                   WHEN pptp.last_seen_at >= gre.last_seen_at
                   THEN pptp.last_seen_at ELSE gre.last_seen_at
                 END) DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                window.limit,
                PT_CORRELATION_WINDOW_MS
            ],
            |row| {
                let device_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Option<Vec<u8>> = row.get(2)?;
                let client_ip: Vec<u8> = row.get(3)?;
                let remote_ip: Vec<u8> = row.get(4)?;
                let pptp_flows: i64 = row.get(5)?;
                let gre_flows: i64 = row.get(6)?;
                let pptp_bytes: Option<i64> = row.get(7)?;
                let gre_bytes: Option<i64> = row.get(8)?;
                let time: i64 = row.get(9)?;
                let client_ip_text = format_ip(&client_ip);
                let remote_ip_text = format_ip(&remote_ip);
                Ok(Insight {
                    id: format!(
                        "pptp-gre-correlation-{client_ip_text}-{remote_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "protocol".to_owned(),
                    code: "protocol.pptp_detected".to_owned(),
                    severity: InsightSeverity::Notice,
                    time,
                    source: "classifier-correlation".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: if device_id >= 0 {
                            Some(device_id)
                        } else {
                            None
                        },
                        name: name.clone(),
                        mac: mac.as_deref().map(format_mac),
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip_text,
                        "remote_ip": remote_ip_text,
                    }),
                    evidence: json!({
                        "remote_ip": remote_ip_text,
                        "pptp_flows": pptp_flows,
                        "gre_flows": gre_flows,
                        "pptp_bytes": pptp_bytes.unwrap_or(0),
                        "gre_bytes": gre_bytes.unwrap_or(0),
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

pub fn query_l2tp_ipsec_correlation_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT
             COALESCE(devices.id, -1),
             COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
             devices.mac,
             l2tp.client_ip,
             l2tp.remote_ip,
             COUNT(DISTINCT l2tp.id),
             COUNT(DISTINCT CASE WHEN ipsec.protocol_id = 'ike' THEN ipsec.id END),
             COUNT(DISTINCT CASE WHEN ipsec.protocol_id = 'ipsec_esp' OR ipsec.protocol = 50 THEN ipsec.id END),
             SUM(l2tp.upload_bytes + l2tp.download_bytes),
             SUM(ipsec.upload_bytes + ipsec.download_bytes),
             MAX(CASE
                   WHEN l2tp.last_seen_at >= ipsec.last_seen_at
                   THEN l2tp.last_seen_at ELSE ipsec.last_seen_at
                 END)
         FROM flow_sessions l2tp
         JOIN flow_sessions ipsec
           ON l2tp.client_ip = ipsec.client_ip
          AND l2tp.remote_ip = ipsec.remote_ip
          AND l2tp.id <> ipsec.id
          AND (ipsec.protocol_id IN ('ike', 'ipsec_esp') OR ipsec.protocol = 50)
          AND ABS(l2tp.last_seen_at - ipsec.last_seen_at) <= ?4
          AND ipsec.last_seen_at >= ?1 AND ipsec.last_seen_at < ?2
         LEFT JOIN devices
           ON devices.id = COALESCE(l2tp.device_id, ipsec.device_id)
         WHERE (l2tp.protocol_id = 'l2tp' OR (l2tp.protocol = 17 AND l2tp.remote_port = 1701))
           AND l2tp.last_seen_at >= ?1 AND l2tp.last_seen_at < ?2
         GROUP BY l2tp.client_ip, l2tp.remote_ip, devices.id, devices.display_name, devices.hostname, devices.mac
         ORDER BY MAX(CASE
                   WHEN l2tp.last_seen_at >= ipsec.last_seen_at
                   THEN l2tp.last_seen_at ELSE ipsec.last_seen_at
                 END) DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![
                to_i64(window.from),
                to_i64(window.to),
                window.limit,
                PT_CORRELATION_WINDOW_MS
            ],
            |row| {
                let device_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let mac: Option<Vec<u8>> = row.get(2)?;
                let client_ip: Vec<u8> = row.get(3)?;
                let remote_ip: Vec<u8> = row.get(4)?;
                let l2tp_flows: i64 = row.get(5)?;
                let ike_flows: i64 = row.get(6)?;
                let esp_flows: i64 = row.get(7)?;
                let l2tp_bytes: Option<i64> = row.get(8)?;
                let ipsec_bytes: Option<i64> = row.get(9)?;
                let time: i64 = row.get(10)?;
                let client_ip_text = format_ip(&client_ip);
                let remote_ip_text = format_ip(&remote_ip);
                Ok(Insight {
                    id: format!(
                        "l2tp-ipsec-correlation-{client_ip_text}-{remote_ip_text}-{}-{}",
                        window.from, window.to
                    ),
                    category: "protocol".to_owned(),
                    code: "protocol.l2tp_ipsec_detected".to_owned(),
                    severity: InsightSeverity::Notice,
                    time,
                    source: "classifier-correlation".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: if device_id >= 0 {
                            Some(device_id)
                        } else {
                            None
                        },
                        name: name.clone(),
                        mac: mac.as_deref().map(format_mac),
                        ip: Some(client_ip_text.clone()),
                    }),
                    params: json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip_text,
                        "remote_ip": remote_ip_text,
                    }),
                    evidence: json!({
                        "remote_ip": remote_ip_text,
                        "l2tp_flows": l2tp_flows,
                        "ike_flows": ike_flows,
                        "esp_flows": esp_flows,
                        "l2tp_bytes": l2tp_bytes.unwrap_or(0),
                        "ipsec_bytes": ipsec_bytes.unwrap_or(0),
                        "observed_time": time,
                        "window_ms": PT_CORRELATION_WINDOW_MS,
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

pub fn query_new_protocol_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT flow_sessions.protocol_id,
                MAX(flow_sessions.last_seen_at)
         FROM flow_sessions
         WHERE flow_sessions.last_seen_at >= ?1 AND flow_sessions.last_seen_at < ?2
           AND flow_sessions.protocol_id IS NOT NULL
           AND flow_sessions.protocol_id != 'unknown'
           AND flow_sessions.protocol_id NOT IN (
               SELECT DISTINCT protocol_id FROM flow_sessions
               WHERE last_seen_at < ?1 AND protocol_id IS NOT NULL
           )
         GROUP BY flow_sessions.protocol_id
         ORDER BY MAX(flow_sessions.last_seen_at) DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![to_i64(window.from), to_i64(window.to), window.limit],
            |row| {
                let protocol_id: String = row.get(0)?;
                let time: i64 = row.get(1)?;
                Ok(Insight {
                    id: format!("new-protocol-{protocol_id}-{time}"),
                    category: "protocol".to_owned(),
                    code: "protocol.new_protocol".to_owned(),
                    severity: InsightSeverity::Info,
                    time,
                    source: "classifier".to_owned(),
                    affected_client: None,
                    params: json!({
                        "protocol": protocol_id,
                        "protocol_name": protocol_id,
                    }),
                    evidence: json!({
                        "protocol_id": protocol_id,
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
