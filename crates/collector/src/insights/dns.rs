use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

pub fn query_encrypted_dns_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let cloudflare_v4_primary = [1_u8, 1, 1, 1];
    let cloudflare_v4_secondary = [1_u8, 0, 0, 1];
    let cloudflare_v6_primary = [
        0x26_u8, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
    ];
    let cloudflare_v6_secondary = [
        0x26_u8, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01,
    ];
    let google_v4_primary = [8_u8, 8, 8, 8];
    let google_v4_secondary = [8_u8, 8, 4, 4];
    let google_v6_primary = [
        0x20_u8, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let google_v6_secondary = [
        0x20_u8, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44,
    ];
    let quad9_v4_primary = [9_u8, 9, 9, 9];
    let quad9_v4_secondary = [149_u8, 112, 112, 112];
    let quad9_v6_primary = [
        0x26_u8, 0x20, 0x00, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
    ];
    let quad9_v6_secondary = [
        0x26_u8, 0x20, 0x00, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
    ];
    let mut statement = connection.prepare(
        "SELECT flow_sessions.id, flow_sessions.device_id,
                COALESCE(devices.display_name, devices.hostname, 'Unknown client'),
                devices.mac, flow_sessions.client_ip, flow_sessions.remote_ip,
                flow_sessions.remote_port, flow_sessions.protocol,
                flow_sessions.last_seen_at,
                flow_sessions.upload_bytes + flow_sessions.download_bytes
         FROM flow_sessions
         LEFT JOIN devices ON devices.id = flow_sessions.device_id
         WHERE flow_sessions.last_seen_at >= ?1 AND flow_sessions.last_seen_at < ?2
           AND (
             flow_sessions.remote_port = 853
             OR (
               flow_sessions.remote_port = 443
               AND flow_sessions.remote_ip IN (?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             )
           )
         ORDER BY flow_sessions.last_seen_at DESC, flow_sessions.id DESC
         LIMIT ?15",
    )?;
    let candidates = statement.query_map(
        params![
            to_i64(window.from),
            to_i64(window.to),
            &cloudflare_v4_primary[..],
            &cloudflare_v4_secondary[..],
            &cloudflare_v6_primary[..],
            &cloudflare_v6_secondary[..],
            &google_v4_primary[..],
            &google_v4_secondary[..],
            &google_v6_primary[..],
            &google_v6_secondary[..],
            &quad9_v4_primary[..],
            &quad9_v4_secondary[..],
            &quad9_v6_primary[..],
            &quad9_v6_secondary[..],
            window.limit,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
            ))
        },
    )?;
    let mut items = Vec::new();
    for candidate in candidates {
        let (flow_id, device_id, name, mac, client_ip, remote_ip, port, _ip_proto, time, bytes) =
            candidate?;
        let remote_ip = format_ip(&remote_ip);
        let provider = encrypted_dns_provider(&remote_ip);
        let rule = if port == 853 {
            "dot_port_853"
        } else if provider.is_some() {
            "known_doh_provider"
        } else {
            continue;
        };
        let protocol = if port == 853 { "DoT" } else { "DoH" };
        let provider_name = provider.unwrap_or(protocol);
        let provider_str = provider.unwrap_or(protocol);
        items.push(Insight {
            id: format!("encrypted-dns-{flow_id}"),
            category: "dns".to_owned(),
            code: "dns.encrypted_dns_detected".to_owned(),
            severity: InsightSeverity::Notice,
            time,
            source: "flow-rules".to_owned(),
            affected_client: Some(AffectedClient {
                id: device_id,
                name: name.clone(),
                mac: mac.as_deref().map(format_mac),
                ip: Some(format_ip(&client_ip)),
            }),
            params: json!({
                "name": name,
                "client": name,
                "remote_ip": remote_ip,
                "remote_port": port,
                "protocol": protocol,
                "provider": provider_name,
                "rule": rule,
                "provider_or_rule": provider_str,
            }),
            evidence: json!({
                "rule": rule,
                "provider": provider,
                "remote_ip": remote_ip,
                "remote_port": port,
                "protocol": protocol,
                "observed_bytes": bytes,
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
