use rusqlite::{Connection, params};
use serde_json::json;

use crate::realtime::format_ip;

use super::model::{AffectedClient, Insight, InsightSeverity, InsightWindow, format_mac, to_i64};

pub fn query_new_device_insights(
    connection: &Connection,
    window: InsightWindow,
) -> rusqlite::Result<Vec<Insight>> {
    let mut statement = connection.prepare(
        "SELECT devices.id, devices.mac,
                COALESCE(devices.display_name, devices.hostname, 'Unknown device'),
                devices.first_seen,
                (SELECT ip FROM device_addresses
                 WHERE device_addresses.device_id = devices.id
                 ORDER BY last_seen DESC, ip_version ASC LIMIT 1)
         FROM devices
         WHERE devices.first_seen >= ?1 AND devices.first_seen < ?2
         ORDER BY devices.first_seen DESC, devices.id DESC
         LIMIT ?3",
    )?;
    let items = statement
        .query_map(
            params![to_i64(window.from), to_i64(window.to), window.limit],
            |row| {
                let id: i64 = row.get(0)?;
                let mac: Vec<u8> = row.get(1)?;
                let name: String = row.get(2)?;
                let first_seen: i64 = row.get(3)?;
                let ip: Option<Vec<u8>> = row.get(4)?;
                let mac = format_mac(&mac);
                let ip = ip.as_deref().map(format_ip);
                Ok(Insight {
                    id: format!("new-device-{id}"),
                    category: "device".to_owned(),
                    code: "device.new_device".to_owned(),
                    severity: InsightSeverity::Info,
                    time: first_seen,
                    source: "device-discovery".to_owned(),
                    affected_client: Some(AffectedClient {
                        id: Some(id),
                        name: name.clone(),
                        mac: Some(mac.clone()),
                        ip: ip.clone(),
                    }),
                    params: json!({
                        "name": name,
                        "mac": mac,
                        "ip": ip,
                        "first_seen": first_seen,
                    }),
                    evidence: json!({
                        "first_seen": first_seen,
                        "mac": mac,
                        "ip": ip,
                    }),
                    fingerprint: None,
                    status: None,
                    first_seen: Some(first_seen),
                    last_seen: Some(first_seen),
                    occurrences: Some(1),
                    confidence: Some(1.0),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}
