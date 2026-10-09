use serde_json::{Value, json};

use netqmon_storage::{ClickHouseClient, StorageResult};

use crate::realtime::RealtimeSnapshot;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac};

pub(crate) fn detect(
    client: &ClickHouseClient,
    snapshot: &RealtimeSnapshot,
    window: InsightWindow,
    lag_threshold_ms: u64,
    high_upload_threshold_bytes: u64,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let limit = window.limit;
    let mut items = Vec::new();

    let devices_sql = format!(
        "SELECT d.id, d.mac, coalesce(d.display_name, d.hostname, 'Unknown device') AS name,
                d.first_seen, coalesce(a.ip, '') AS ip
         FROM devices AS d FINAL
         LEFT JOIN (
             SELECT device_id, argMax(ip, tuple(last_seen, -toInt64(ip_version))) AS ip
             FROM device_addresses FINAL GROUP BY device_id
         ) AS a ON a.device_id = d.id
         WHERE d.first_seen >= {from} AND d.first_seen < {to}
         ORDER BY d.first_seen DESC, d.id DESC LIMIT {limit} FORMAT JSON"
    );
    let devices = client.query_json(&devices_sql)?;
    if let Some(rows) = devices["data"].as_array() {
        for row in rows {
            let id = number(&row["id"]);
            let time = number(&row["first_seen"]);
            let mac_bytes = netqmon_storage::from_hex(row["mac"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let mac = format_mac(&mac_bytes);
            let name = string(&row["name"], "Unknown device");
            let ip = netqmon_storage::from_hex(row["ip"].as_str().unwrap_or_default())
                .ok()
                .filter(|bytes| !bytes.is_empty())
                .map(|bytes| format_ip(&bytes));
            items.push(Insight {
                id: format!("new-device-{id}"),
                category: "device".to_owned(),
                code: "device.new_device".to_owned(),
                severity: InsightSeverity::Info,
                time,
                source: "device-discovery".to_owned(),
                affected_client: Some(AffectedClient {
                    id: Some(id),
                    name: name.clone(),
                    mac: Some(mac.clone()),
                    ip: ip.clone(),
                }),
                params: json!({ "name": name, "mac": mac, "ip": ip, "first_seen": time }),
                evidence: json!({ "first_seen": time, "mac": mac, "ip": ip }),
                fingerprint: None,
                status: None,
                first_seen: Some(time),
                last_seen: Some(time),
                occurrences: Some(1),
                confidence: Some(1.0),
            });
        }
    }

    let upload_threshold = i64::try_from(high_upload_threshold_bytes).unwrap_or(i64::MAX);
    let upload_sql = format!(
        "SELECT d.id, d.mac, coalesce(d.display_name, d.hostname, 'Unknown device') AS name,
                t.upload_bytes, t.last_seen, coalesce(a.ip, '') AS ip
         FROM (
             SELECT device_id, sum(upload_bytes) AS upload_bytes, max(timestamp) AS last_seen
             FROM traffic_device_minute
             WHERE timestamp >= {from} AND timestamp < {to}
             GROUP BY device_id HAVING upload_bytes >= {upload_threshold}
         ) AS t
         INNER JOIN devices AS d FINAL ON d.id = t.device_id
         LEFT JOIN (
             SELECT device_id, argMax(ip, tuple(last_seen, -toInt64(ip_version))) AS ip
             FROM device_addresses FINAL GROUP BY device_id
         ) AS a ON a.device_id = d.id
         ORDER BY t.upload_bytes DESC, d.id ASC FORMAT JSON"
    );
    let uploads = client.query_json(&upload_sql)?;
    if let Some(rows) = uploads["data"].as_array() {
        for row in rows {
            let id = number(&row["id"]);
            let time = number(&row["last_seen"]);
            let bytes = number(&row["upload_bytes"]);
            let mac = format_mac(
                &netqmon_storage::from_hex(row["mac"].as_str().unwrap_or_default())
                    .unwrap_or_default(),
            );
            let name = string(&row["name"], "Unknown device");
            let ip = netqmon_storage::from_hex(row["ip"].as_str().unwrap_or_default())
                .ok()
                .filter(|bytes| !bytes.is_empty())
                .map(|bytes| format_ip(&bytes));
            items.push(Insight {
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
                    "upload_bytes": bytes,
                    "bytes": bytes,
                    "tx_bytes": bytes,
                    "threshold_bytes": high_upload_threshold_bytes,
                }),
                evidence: json!({
                    "upload_bytes": bytes,
                    "threshold_bytes": high_upload_threshold_bytes,
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
            });
        }
    }

    let unknown_sql = format!(
        "SELECT sumIf(upload_bytes + download_bytes, application_id = 'unknown') AS unknown_bytes,
                sum(upload_bytes + download_bytes) AS total_bytes, max(timestamp) AS observed_at
         FROM traffic_application_minute
         WHERE timestamp >= {from} AND timestamp < {to} FORMAT JSON"
    );
    let unknown = client.query_json(&unknown_sql)?;
    if let Some(row) = unknown["data"].as_array().and_then(|rows| rows.first()) {
        let unknown_bytes = number(&row["unknown_bytes"]);
        let total_bytes = number(&row["total_bytes"]);
        if total_bytes > 0 {
            let ratio_parts_per_million = unknown_bytes.saturating_mul(1_000_000) / total_bytes;
            let ratio = f64::from(u32::try_from(ratio_parts_per_million).unwrap_or(1_000_000))
                / 1_000_000.0;
            let time = number(&row["observed_at"]);
            items.push(Insight {
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
                    "percent": format!("{:.1}", ratio * 100.0),
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
            });
        }
    }

    let client_unknown_sql = format!(
        "SELECT f.device_id, f.client_ip,
                coalesce(any(d.display_name), any(d.hostname), 'Unknown client') AS name,
                any(d.mac) AS mac,
                sumIf(f.upload_bytes + f.download_bytes, f.application_id = 'unknown') AS unknown_bytes,
                sum(f.upload_bytes + f.download_bytes) AS total_bytes, max(f.last_seen_at) AS last_seen
         FROM flow_sessions AS f FINAL
         LEFT JOIN devices AS d FINAL ON d.id = f.device_id
         WHERE f.last_seen_at >= {from} AND f.last_seen_at < {to}
         GROUP BY f.device_id, f.client_ip
         HAVING total_bytes >= 1048576 AND unknown_bytes * 2 >= total_bytes
         ORDER BY unknown_bytes DESC LIMIT {limit} FORMAT JSON"
    );
    let client_unknown = client
        .query_json(&client_unknown_sql)
        .unwrap_or(Value::Null);
    if let Some(rows) = client_unknown["data"].as_array() {
        for row in rows {
            let id = row
                .get("device_id")
                .filter(|value| !value.is_null())
                .map(number);
            let ip_bytes = netqmon_storage::from_hex(row["client_ip"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let ip = format_ip(&ip_bytes);
            let name = string(&row["name"], "Unknown client");
            let mac = row["mac"]
                .as_str()
                .and_then(|value| netqmon_storage::from_hex(value).ok())
                .filter(|value| !value.is_empty())
                .map(|value| format_mac(&value));
            let unknown_bytes = number(&row["unknown_bytes"]);
            let total_bytes = number(&row["total_bytes"]);
            let ratio = if total_bytes > 0 {
                (unknown_bytes.max(0) as f64) / (total_bytes as f64)
            } else {
                0.0
            };
            let time = number(&row["last_seen"]);
            items.push(Insight {
                id: format!("client-unknown-traffic-{ip}-{}-{}", window.from, window.to),
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
                    id,
                    name: name.clone(),
                    mac: mac.clone(),
                    ip: Some(ip.clone()),
                }),
                params: json!({
                    "client": name,
                    "unknown_bytes": unknown_bytes,
                    "total_bytes": total_bytes,
                    "ratio": ratio,
                    "percent": format!("{:.1}", ratio * 100.0),
                }),
                evidence: json!({
                    "client_ip": ip,
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
            });
        }
    }

    items.extend(query_encrypted_dns(client, window)?);
    items.extend(query_new_protocols(client, window).unwrap_or_default());
    items.extend(query_protocol_correlations(client, window)?);
    items.extend(query_fanout_spikes(client, window).unwrap_or_default());
    items.extend(query_traffic_spikes(client, window).unwrap_or_default());

    let gateway_result = client
        .query_json("SELECT maxOrNull(last_seen) AS last_seen FROM gateways FINAL FORMAT JSON")?;
    let received_at = gateway_result["data"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("last_seen"))
        .filter(|value| !value.is_null())
        .map(number)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(snapshot.generated_at);
    items.extend(crate::insights::detect_capture_clickhouse(
        snapshot,
        window,
        lag_threshold_ms,
        received_at,
    ));

    items.sort_by_key(|item| std::cmp::Reverse(item.time));
    items.truncate(window.limit as usize);
    Ok(items)
}

fn query_encrypted_dns(
    client: &ClickHouseClient,
    window: InsightWindow,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let limit = window.limit;
    let sql = format!(
        "SELECT f.id, f.device_id, coalesce(d.display_name, d.hostname, 'Unknown client') AS name,
                d.mac, f.client_ip, f.remote_ip, f.remote_port, f.last_seen_at,
                f.upload_bytes + f.download_bytes AS bytes
         FROM flow_sessions AS f FINAL LEFT JOIN devices AS d FINAL ON d.id = f.device_id
         WHERE f.last_seen_at >= {from} AND f.last_seen_at < {to}
           AND (f.remote_port = 853 OR (f.remote_port = 443 AND f.remote_ip IN (
             '01010101', '01000001', '26064700470000000000000000001111',
             '26064700470000000000000000001001', '08080808', '08080404',
             '20014860486000000000000000008888', '20014860486000000000000000008844',
             '09090909', '95707070', '262000fe0000000000000000000000fe',
             '262000fe000000000000000000000009')))
         ORDER BY f.last_seen_at DESC, f.id DESC LIMIT {limit} FORMAT JSON"
    );
    let result = client.query_json(&sql)?;
    let mut items = Vec::new();
    if let Some(rows) = result["data"].as_array() {
        for row in rows {
            let remote_ip = ip_from_hex(row["remote_ip"].as_str().unwrap_or_default());
            let port = number(&row["remote_port"]);
            let provider = encrypted_dns_provider(&remote_ip);
            if port != 853 && provider.is_none() {
                continue;
            }
            let protocol = if port == 853 { "DoT" } else { "DoH" };
            let provider = provider.unwrap_or(protocol);
            let time = number(&row["last_seen_at"]);
            let client_ip = ip_from_hex(row["client_ip"].as_str().unwrap_or_default());
            let device_id = row
                .get("device_id")
                .filter(|value| !value.is_null())
                .map(number);
            let mac = row["mac"]
                .as_str()
                .and_then(|value| netqmon_storage::from_hex(value).ok())
                .filter(|value| !value.is_empty())
                .map(|value| format_mac(&value));
            let name = string(&row["name"], "Unknown client");
            let rule = if port == 853 {
                "dot_port_853"
            } else {
                "known_doh_provider"
            };
            items.push(Insight {
                id: format!("encrypted-dns-{}", string(&row["id"], "")),
                category: "dns".to_owned(),
                code: "dns.encrypted_dns_detected".to_owned(),
                severity: InsightSeverity::Notice,
                time,
                source: "flow-rules".to_owned(),
                affected_client: Some(AffectedClient {
                    id: device_id,
                    name: name.clone(),
                    mac,
                    ip: Some(client_ip),
                }),
                params: json!({
                    "name": name,
                    "client": name,
                    "remote_ip": remote_ip,
                    "remote_port": port,
                    "protocol": protocol,
                    "provider": provider,
                    "rule": rule,
                    "provider_or_rule": provider,
                }),
                evidence: json!({
                    "rule": rule,
                    "provider": provider,
                    "remote_ip": remote_ip,
                    "remote_port": port,
                    "protocol": protocol,
                    "observed_bytes": number(&row["bytes"]),
                    "domain": Value::Null,
                    "domain_limit": "Encrypted DNS contents are not visible",
                }),
                fingerprint: None,
                status: None,
                first_seen: Some(time),
                last_seen: Some(time),
                occurrences: Some(1),
                confidence: Some(1.0),
            });
        }
    }
    Ok(items)
}

fn query_new_protocols(
    client: &ClickHouseClient,
    window: InsightWindow,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let limit = window.limit;
    let sql = format!(
        "SELECT protocol_id, max(last_seen_at) AS observed_at
         FROM flow_sessions FINAL
         WHERE last_seen_at >= {from} AND last_seen_at < {to}
           AND protocol_id IS NOT NULL AND protocol_id != 'unknown'
           AND protocol_id NOT IN (
             SELECT DISTINCT protocol_id FROM flow_sessions FINAL
             WHERE last_seen_at < {from} AND protocol_id IS NOT NULL)
         GROUP BY protocol_id ORDER BY observed_at DESC LIMIT {limit} FORMAT JSON"
    );
    let result = client.query_json(&sql)?;
    let mut items = Vec::new();
    if let Some(rows) = result["data"].as_array() {
        for row in rows {
            let protocol = string(&row["protocol_id"], "unknown");
            let time = number(&row["observed_at"]);
            items.push(Insight {
                id: format!("new-protocol-{protocol}-{time}"),
                category: "protocol".to_owned(),
                code: "protocol.new_protocol".to_owned(),
                severity: InsightSeverity::Info,
                time,
                source: "classifier".to_owned(),
                affected_client: None,
                params: json!({ "protocol": protocol, "protocol_name": protocol }),
                evidence: json!({
                    "protocol_id": protocol,
                    "window_from": window.from,
                    "window_to": window.to,
                }),
                fingerprint: None,
                status: None,
                first_seen: Some(time),
                last_seen: Some(time),
                occurrences: Some(1),
                confidence: Some(1.0),
            });
        }
    }
    Ok(items)
}

#[derive(Clone, Copy)]
enum ProtocolInsightKind {
    Tracker,
    IkeEsp,
    PptpGre,
    L2tpIpsec,
}

fn query_protocol_correlations(
    client: &ClickHouseClient,
    window: InsightWindow,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let limit = window.limit;
    let correlation_window = 30 * 60 * 1_000;
    let tracker_sql = format!(
        "SELECT d.id AS device_id,
                coalesce(d.display_name, d.hostname, 'Unknown client') AS name,
                d.mac, t.client_ip, '' AS remote_ip,
                countDistinct(t.id) AS first_flows, countDistinct(p.id) AS second_flows,
                sum(t.upload_bytes + t.download_bytes) AS first_bytes,
                sum(p.upload_bytes + p.download_bytes) AS second_bytes,
                max(greatest(t.last_seen_at, p.last_seen_at)) AS observed_at
         FROM flow_sessions AS t FINAL INNER JOIN flow_sessions AS p FINAL
           ON t.client_ip = p.client_ip
         LEFT JOIN devices AS d FINAL ON d.id = coalesce(t.device_id, p.device_id)
         WHERE t.id != p.id AND p.protocol_id = 'bittorrent'
           AND abs(t.last_seen_at - p.last_seen_at) <= {correlation_window}
           AND p.last_seen_at >= {from} AND p.last_seen_at < {to}
           AND t.traffic_role = 'tracker_service' AND t.category_id = 'p2p'
           AND t.last_seen_at >= {from} AND t.last_seen_at < {to}
         GROUP BY t.client_ip, d.id, d.display_name, d.hostname, d.mac
         ORDER BY observed_at DESC LIMIT {limit} FORMAT JSON"
    );
    let ike_sql = format!(
        "SELECT d.id AS device_id,
                coalesce(d.display_name, d.hostname, 'Unknown client') AS name,
                d.mac, ike.client_ip, ike.remote_ip,
                countDistinct(ike.id) AS first_flows, countDistinct(esp.id) AS second_flows,
                sum(ike.upload_bytes + ike.download_bytes) AS first_bytes,
                sum(esp.upload_bytes + esp.download_bytes) AS second_bytes,
                max(greatest(ike.last_seen_at, esp.last_seen_at)) AS observed_at
         FROM flow_sessions AS ike FINAL INNER JOIN flow_sessions AS esp FINAL
           ON ike.client_ip = esp.client_ip AND ike.remote_ip = esp.remote_ip
         LEFT JOIN devices AS d FINAL ON d.id = coalesce(ike.device_id, esp.device_id)
         WHERE ike.id != esp.id AND esp.protocol_id = 'ipsec_esp'
           AND abs(ike.last_seen_at - esp.last_seen_at) <= {correlation_window}
           AND esp.last_seen_at >= {from} AND esp.last_seen_at < {to}
           AND ike.protocol_id = 'ike'
           AND ike.last_seen_at >= {from} AND ike.last_seen_at < {to}
         GROUP BY ike.client_ip, ike.remote_ip, d.id, d.display_name, d.hostname, d.mac
         ORDER BY observed_at DESC LIMIT {limit} FORMAT JSON"
    );
    let pptp_sql = format!(
        "SELECT d.id AS device_id,
                coalesce(d.display_name, d.hostname, 'Unknown client') AS name,
                d.mac, pptp.client_ip, pptp.remote_ip,
                countDistinct(pptp.id) AS first_flows, countDistinct(gre.id) AS second_flows,
                sum(pptp.upload_bytes + pptp.download_bytes) AS first_bytes,
                sum(gre.upload_bytes + gre.download_bytes) AS second_bytes,
                max(greatest(pptp.last_seen_at, gre.last_seen_at)) AS observed_at
         FROM flow_sessions AS pptp FINAL INNER JOIN flow_sessions AS gre FINAL
           ON pptp.client_ip = gre.client_ip AND pptp.remote_ip = gre.remote_ip
         LEFT JOIN devices AS d FINAL ON d.id = coalesce(pptp.device_id, gre.device_id)
         WHERE pptp.id != gre.id AND (gre.protocol_id = 'gre' OR gre.protocol = 47)
           AND abs(pptp.last_seen_at - gre.last_seen_at) <= {correlation_window}
           AND gre.last_seen_at >= {from} AND gre.last_seen_at < {to}
           AND (pptp.protocol_id = 'pptp' OR (pptp.protocol = 6 AND pptp.remote_port = 1723))
           AND pptp.last_seen_at >= {from} AND pptp.last_seen_at < {to}
         GROUP BY pptp.client_ip, pptp.remote_ip, d.id, d.display_name, d.hostname, d.mac
         ORDER BY observed_at DESC LIMIT {limit} FORMAT JSON"
    );
    let l2tp_sql = format!(
        "SELECT d.id AS device_id,
                coalesce(d.display_name, d.hostname, 'Unknown client') AS name,
                d.mac, l2tp.client_ip, l2tp.remote_ip,
                countDistinct(l2tp.id) AS first_flows,
                countDistinctIf(ipsec.id, ipsec.protocol_id = 'ike') AS ike_flows,
                countDistinctIf(ipsec.id, ipsec.protocol_id = 'ipsec_esp' OR ipsec.protocol = 50) AS esp_flows,
                sum(l2tp.upload_bytes + l2tp.download_bytes) AS first_bytes,
                sum(ipsec.upload_bytes + ipsec.download_bytes) AS second_bytes,
                max(greatest(l2tp.last_seen_at, ipsec.last_seen_at)) AS observed_at
         FROM flow_sessions AS l2tp FINAL INNER JOIN flow_sessions AS ipsec FINAL
           ON l2tp.client_ip = ipsec.client_ip AND l2tp.remote_ip = ipsec.remote_ip
         LEFT JOIN devices AS d FINAL ON d.id = coalesce(l2tp.device_id, ipsec.device_id)
         WHERE l2tp.id != ipsec.id
           AND (ipsec.protocol_id IN ('ike', 'ipsec_esp') OR ipsec.protocol = 50)
           AND abs(l2tp.last_seen_at - ipsec.last_seen_at) <= {correlation_window}
           AND ipsec.last_seen_at >= {from} AND ipsec.last_seen_at < {to}
           AND (l2tp.protocol_id = 'l2tp' OR (l2tp.protocol = 17 AND l2tp.remote_port = 1701))
           AND l2tp.last_seen_at >= {from} AND l2tp.last_seen_at < {to}
         GROUP BY l2tp.client_ip, l2tp.remote_ip, d.id, d.display_name, d.hostname, d.mac
         ORDER BY observed_at DESC LIMIT {limit} FORMAT JSON"
    );

    let mut items = Vec::new();
    items.extend(query_protocol_correlation_rows(
        client,
        &tracker_sql,
        window,
        ProtocolInsightKind::Tracker,
    )?);
    items.extend(
        query_protocol_correlation_rows(client, &ike_sql, window, ProtocolInsightKind::IkeEsp)
            .unwrap_or_default(),
    );
    items.extend(
        query_protocol_correlation_rows(client, &pptp_sql, window, ProtocolInsightKind::PptpGre)
            .unwrap_or_default(),
    );
    items.extend(
        query_protocol_correlation_rows(client, &l2tp_sql, window, ProtocolInsightKind::L2tpIpsec)
            .unwrap_or_default(),
    );
    Ok(items)
}

fn query_protocol_correlation_rows(
    client: &ClickHouseClient,
    sql: &str,
    window: InsightWindow,
    kind: ProtocolInsightKind,
) -> StorageResult<Vec<Insight>> {
    let result = client.query_json(sql)?;
    let mut items = Vec::new();
    if let Some(rows) = result["data"].as_array() {
        for row in rows {
            let name = string(&row["name"], "Unknown client");
            let client_ip = ip_from_hex(row["client_ip"].as_str().unwrap_or_default());
            let remote_ip = ip_from_hex(row["remote_ip"].as_str().unwrap_or_default());
            let device_id = row
                .get("device_id")
                .filter(|value| !value.is_null())
                .map(number);
            let mac = row["mac"]
                .as_str()
                .and_then(|value| netqmon_storage::from_hex(value).ok())
                .filter(|value| !value.is_empty())
                .map(|value| format_mac(&value));
            let time = number(&row["observed_at"]);
            let first_flows = number(&row["first_flows"]);
            let second_flows = number(&row["second_flows"]);
            let first_bytes = number(&row["first_bytes"]);
            let second_bytes = number(&row["second_bytes"]);
            let (id, code, params, evidence) = match kind {
                ProtocolInsightKind::Tracker => (
                    format!(
                        "pt-bittorrent-correlation-{client_ip}-{}-{}",
                        window.from, window.to
                    ),
                    "protocol.p2p_tracker_correlation",
                    json!({
                        "name": name,
                        "client": name,
                        "tracker_flows": first_flows,
                        "peer_flows": second_flows,
                    }),
                    json!({
                        "tracker_role": "tracker_service",
                        "tracker_class": "p2p",
                        "peer_protocol": "bittorrent",
                        "tracker_flows": first_flows,
                        "peer_flows": second_flows,
                        "tracker_bytes": first_bytes,
                        "peer_bytes": second_bytes,
                        "window_from": window.from,
                        "window_to": window.to,
                        "action": "observation_only",
                    }),
                ),
                ProtocolInsightKind::IkeEsp => (
                    format!(
                        "ike-esp-correlation-{client_ip}-{remote_ip}-{}-{}",
                        window.from, window.to
                    ),
                    "protocol.ipsec_detected",
                    json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip,
                        "remote_ip": remote_ip,
                    }),
                    json!({
                        "remote_ip": remote_ip,
                        "ike_flows": first_flows,
                        "esp_flows": second_flows,
                        "ike_bytes": first_bytes,
                        "esp_bytes": second_bytes,
                    }),
                ),
                ProtocolInsightKind::PptpGre => (
                    format!(
                        "pptp-gre-correlation-{client_ip}-{remote_ip}-{}-{}",
                        window.from, window.to
                    ),
                    "protocol.pptp_detected",
                    json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip,
                        "remote_ip": remote_ip,
                    }),
                    json!({
                        "remote_ip": remote_ip,
                        "pptp_flows": first_flows,
                        "gre_flows": second_flows,
                        "pptp_bytes": first_bytes,
                        "gre_bytes": second_bytes,
                    }),
                ),
                ProtocolInsightKind::L2tpIpsec => (
                    format!(
                        "l2tp-ipsec-correlation-{client_ip}-{remote_ip}-{}-{}",
                        window.from, window.to
                    ),
                    "protocol.l2tp_ipsec_detected",
                    json!({
                        "name": name,
                        "client": name,
                        "client_ip": client_ip,
                        "remote_ip": remote_ip,
                    }),
                    json!({
                        "remote_ip": remote_ip,
                        "l2tp_flows": first_flows,
                        "ike_flows": number(&row["ike_flows"]),
                        "esp_flows": number(&row["esp_flows"]),
                        "l2tp_bytes": first_bytes,
                        "ipsec_bytes": second_bytes,
                        "observed_time": time,
                        "window_ms": 30 * 60 * 1_000,
                    }),
                ),
            };
            items.push(Insight {
                id,
                category: "protocol".to_owned(),
                code: code.to_owned(),
                severity: InsightSeverity::Notice,
                time,
                source: "classifier-correlation".to_owned(),
                affected_client: Some(AffectedClient {
                    id: device_id,
                    name,
                    mac,
                    ip: Some(client_ip),
                }),
                params,
                evidence,
                fingerprint: None,
                status: None,
                first_seen: Some(time),
                last_seen: Some(time),
                occurrences: Some(1),
                confidence: Some(1.0),
            });
        }
    }
    Ok(items)
}

fn query_fanout_spikes(
    client: &ClickHouseClient,
    window: InsightWindow,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let limit = window.limit;
    let sql = format!(
        "SELECT f.device_id, f.client_ip,
                coalesce(any(d.display_name), any(d.hostname), 'Unknown client') AS name,
                any(d.mac) AS mac, uniqExact(f.remote_ip) AS destination_count,
                max(f.last_seen_at) AS observed_at
         FROM flow_sessions AS f FINAL LEFT JOIN devices AS d FINAL ON d.id = f.device_id
         WHERE f.last_seen_at >= {from} AND f.last_seen_at < {to}
         GROUP BY f.device_id, f.client_ip
         HAVING destination_count >= 50
         ORDER BY destination_count DESC LIMIT {limit} FORMAT JSON"
    );
    let result = client.query_json(&sql)?;
    let mut items = Vec::new();
    if let Some(rows) = result["data"].as_array() {
        for row in rows {
            let device_id = row
                .get("device_id")
                .filter(|value| !value.is_null())
                .map(number);
            let ip = ip_from_hex(row["client_ip"].as_str().unwrap_or_default());
            let destinations = number(&row["destination_count"]);
            let time = number(&row["observed_at"]);
            let name = string(&row["name"], "Unknown client");
            let mac = row["mac"]
                .as_str()
                .and_then(|value| netqmon_storage::from_hex(value).ok())
                .filter(|value| !value.is_empty())
                .map(|value| format_mac(&value));
            items.push(Insight {
                id: format!("fanout-spike-{ip}-{}-{}", window.from, window.to),
                category: "destination".to_owned(),
                code: "destination.fanout_spike".to_owned(),
                severity: if destinations >= 100 {
                    InsightSeverity::Warning
                } else {
                    InsightSeverity::Notice
                },
                time,
                source: "flow-history".to_owned(),
                affected_client: Some(AffectedClient {
                    id: device_id,
                    name: name.clone(),
                    mac,
                    ip: Some(ip.clone()),
                }),
                params: json!({
                    "name": name,
                    "client": name,
                    "count": destinations,
                    "destination_count": destinations,
                }),
                evidence: json!({
                    "client_ip": ip,
                    "destination_count": destinations,
                    "window_from": window.from,
                    "window_to": window.to,
                }),
                fingerprint: None,
                status: None,
                first_seen: Some(time),
                last_seen: Some(time),
                occurrences: Some(1),
                confidence: Some(1.0),
            });
        }
    }
    Ok(items)
}

fn query_traffic_spikes(
    client: &ClickHouseClient,
    window: InsightWindow,
) -> StorageResult<Vec<Insight>> {
    let from = i64::try_from(window.from).unwrap_or(i64::MAX);
    let to = i64::try_from(window.to).unwrap_or(i64::MAX);
    let duration = window.to.saturating_sub(window.from);
    let baseline_from = i64::try_from(window.from.saturating_sub(duration)).unwrap_or(i64::MAX);
    let limit = window.limit;
    let client_sql = format!(
        "WITH current_window AS (
             SELECT device_id, sum(upload_bytes + download_bytes) AS current_bytes,
                    max(timestamp) AS last_seen
             FROM traffic_device_minute WHERE timestamp >= {from} AND timestamp < {to}
             GROUP BY device_id HAVING current_bytes >= 10485760
         ), baseline_window AS (
             SELECT device_id, sum(upload_bytes + download_bytes) AS baseline_bytes
             FROM traffic_device_minute WHERE timestamp >= {baseline_from} AND timestamp < {from}
             GROUP BY device_id
         )
         SELECT c.device_id, coalesce(d.display_name, d.hostname, 'Unknown device') AS name,
                d.mac, c.current_bytes, b.baseline_bytes, c.last_seen,
                coalesce(a.ip, '') AS ip
         FROM current_window AS c
         INNER JOIN baseline_window AS b ON b.device_id = c.device_id
         INNER JOIN devices AS d FINAL ON d.id = c.device_id
         LEFT JOIN (
             SELECT device_id, argMax(ip, tuple(last_seen, -toInt64(ip_version))) AS ip
             FROM device_addresses FINAL GROUP BY device_id
         ) AS a ON a.device_id = c.device_id
         WHERE b.baseline_bytes > 0 AND c.current_bytes >= b.baseline_bytes * 3
         ORDER BY c.current_bytes DESC LIMIT {limit} FORMAT JSON"
    );
    let client_result = client.query_json(&client_sql)?;
    let mut items = Vec::new();
    if let Some(rows) = client_result["data"].as_array() {
        for row in rows {
            let id = number(&row["device_id"]);
            let bytes = number(&row["current_bytes"]);
            let baseline = number(&row["baseline_bytes"]);
            if baseline <= 0 {
                continue;
            }
            let multiplier = bytes as f64 / baseline as f64;
            let time = number(&row["last_seen"]);
            let name = string(&row["name"], "Unknown device");
            let mac = netqmon_storage::from_hex(row["mac"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let ip = netqmon_storage::from_hex(row["ip"].as_str().unwrap_or_default())
                .ok()
                .filter(|value| !value.is_empty())
                .map(|value| format_ip(&value));
            items.push(Insight {
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
                    mac: Some(format_mac(&mac)),
                    ip: ip.clone(),
                }),
                params: json!({
                    "name": name,
                    "client": name,
                    "bytes": bytes,
                    "current_bytes": bytes,
                    "baseline_bytes": baseline,
                    "multiplier": format!("{multiplier:.1}"),
                    "ratio": format!("{multiplier:.1}x"),
                }),
                evidence: json!({
                    "current_bytes": bytes,
                    "baseline_bytes": baseline,
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
            });
        }
    }

    let application_sql = format!(
        "WITH current_window AS (
             SELECT application_id, sum(upload_bytes + download_bytes) AS current_bytes,
                    max(timestamp) AS last_seen
             FROM traffic_application_minute
             WHERE timestamp >= {from} AND timestamp < {to} AND application_id != 'unknown'
             GROUP BY application_id HAVING current_bytes >= 10485760
         ), baseline_window AS (
             SELECT application_id, sum(upload_bytes + download_bytes) AS baseline_bytes
             FROM traffic_application_minute
             WHERE timestamp >= {baseline_from} AND timestamp < {from}
               AND application_id != 'unknown'
             GROUP BY application_id
         )
         SELECT c.application_id, c.current_bytes, b.baseline_bytes, c.last_seen
         FROM current_window AS c INNER JOIN baseline_window AS b USING application_id
         WHERE b.baseline_bytes > 0 AND c.current_bytes >= b.baseline_bytes * 3
         ORDER BY c.current_bytes DESC LIMIT {limit} FORMAT JSON"
    );
    if let Ok(application_result) = client.query_json(&application_sql)
        && let Some(rows) = application_result["data"].as_array()
    {
        for row in rows {
            let application = string(&row["application_id"], "unknown");
            let bytes = number(&row["current_bytes"]);
            let baseline = number(&row["baseline_bytes"]);
            if baseline <= 0 {
                continue;
            }
            let multiplier = bytes as f64 / baseline as f64;
            let time = number(&row["last_seen"]);
            items.push(Insight {
                id: format!("app-spike-{application}-{}-{}", window.from, window.to),
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
                    "application": application,
                    "application_name": application,
                    "bytes": bytes,
                    "current_bytes": bytes,
                    "baseline_bytes": baseline,
                    "multiplier": format!("{multiplier:.1}"),
                    "ratio": format!("{multiplier:.1}x"),
                }),
                evidence: json!({
                    "application_id": application,
                    "current_bytes": bytes,
                    "baseline_bytes": baseline,
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
            });
        }
    }
    Ok(items)
}

fn encrypted_dns_provider(ip: &str) -> Option<&'static str> {
    match ip {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => {
            Some("Cloudflare")
        }
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => Some("Google"),
        "9.9.9.9" | "149.112.112.112" | "2620:fe::fe" | "2620:fe::9" => Some("Quad9"),
        _ => None,
    }
}

fn ip_from_hex(value: &str) -> String {
    netqmon_storage::from_hex(value)
        .map(|bytes| format_ip(&bytes))
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn number(value: &Value) -> i64 {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .unwrap_or(0)
}

fn string(value: &Value, default: &str) -> String {
    value.as_str().unwrap_or(default).to_owned()
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => <[u8; 16]>::try_from(bytes)
            .map(std::net::Ipv6Addr::from)
            .map_or_else(|_| "unknown".to_owned(), |ip| ip.to_string()),
        _ => "unknown".to_owned(),
    }
}
