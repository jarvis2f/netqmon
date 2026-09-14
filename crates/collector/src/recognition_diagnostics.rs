//! Counts unique stored clients and flow sessions, never sample packets or payloads.
use crate::CollectorInner;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn diagnostics(inner: &CollectorInner, since: u64) -> Result<Value, String> {
    let device_sql = "SELECT device_type, vendor, private_mac, identity_evidence_json FROM devices";
    let flow_sql = format!(
        "SELECT application_id, protocol_id, domain, classification_evidence_json, count(*) AS count FROM flow_sessions {{final}} WHERE last_seen_at >= {since} GROUP BY application_id, protocol_id, domain, classification_evidence_json"
    );
    let (devices, flows) = if let Some(ch) = inner.storage.clickhouse_storage() {
        let devices = ch
            .client()
            .query_json(&format!("{device_sql} FINAL FORMAT JSON"))
            .map_err(|e| e.to_string())?;
        let flows = ch
            .client()
            .query_json(&format!(
                "{} FORMAT JSON",
                flow_sql.replace("{final}", "FINAL")
            ))
            .map_err(|e| e.to_string())?;
        (
            devices["data"].as_array().cloned().unwrap_or_default(),
            flows["data"].as_array().cloned().unwrap_or_default(),
        )
    } else {
        let connection = inner.storage.connection();
        let mut statement = connection.prepare(device_sql).map_err(|e| e.to_string())?;
        let devices = statement.query_map([], |r| Ok(json!({"device_type":r.get::<_,Option<String>>(0)?, "vendor":r.get::<_,Option<String>>(1)?, "private_mac":r.get::<_,i64>(2)?, "identity_evidence_json":r.get::<_,String>(3)?})))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        let mut statement = connection
            .prepare(&flow_sql.replace("{final}", ""))
            .map_err(|e| e.to_string())?;
        let flows = statement.query_map([], |r| Ok(json!({"application_id":r.get::<_,Option<String>>(0)?, "protocol_id":r.get::<_,Option<String>>(1)?, "domain":r.get::<_,Option<String>>(2)?, "classification_evidence_json":r.get::<_,String>(3)?, "count":r.get::<_,i64>(4)?})))
            .map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
        (devices, flows)
    };
    Ok(summarize(&devices, &flows, since))
}
fn known(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s != "unknown")
}
fn number(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}
fn evidence(value: &Value) -> Vec<Value> {
    value
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}
fn top(values: BTreeMap<String, u64>) -> Vec<Value> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    values
        .into_iter()
        .take(20)
        .map(|(value, count)| json!({"value":value,"flows":count}))
        .collect()
}
#[allow(clippy::cast_precision_loss)]
fn summarize(devices: &[Value], flows: &[Value], since: u64) -> Value {
    let (mut typed, mut vendors, mut private, mut no_rules, mut no_evidence) =
        (0_u64, 0_u64, 0_u64, 0_u64, 0_u64);
    let mut coverage = BTreeMap::<String, u64>::new();
    for device in devices {
        typed += u64::from(known(&device["device_type"]));
        vendors += u64::from(known(&device["vendor"]));
        private += u64::from(number(&device["private_mac"]) != 0);
        let sources: BTreeSet<_> = evidence(&device["identity_evidence_json"])
            .iter()
            .filter_map(|e| e["source"].as_str())
            .filter(|s| *s != "mac_random")
            .map(str::to_owned)
            .collect();
        if !known(&device["device_type"]) {
            if sources.is_empty() {
                no_evidence += 1;
            } else {
                no_rules += 1;
            }
        }
        for source in sources {
            *coverage.entry(source).or_default() += 1;
        }
    }
    let (mut total, mut apps, mut domains, mut ndpi, mut protocols, mut generic, mut unknown) =
        (0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64);
    let mut unmatched_domains = BTreeMap::<String, u64>::new();
    let mut unmatched_ndpi = BTreeMap::<String, u64>::new();
    for flow in flows {
        let count = number(&flow["count"]);
        total += count;
        let app = known(&flow["application_id"]);
        let protocol = known(&flow["protocol_id"]);
        let entries = evidence(&flow["classification_evidence_json"]);
        let has = |kind| entries.iter().any(|e| e["type"] == kind);
        if app {
            apps += count;
        }
        if app && has("domain_application") {
            domains += count;
        }
        if app && has("ndpi_application") {
            ndpi += count;
        }
        if !app && protocol {
            protocols += count;
        }
        if !app && matches!(flow["protocol_id"].as_str(), Some("tls" | "quic")) {
            generic += count;
        }
        if !app && !protocol {
            unknown += count;
        }
        if !has("domain_application") && known(&flow["domain"]) {
            *unmatched_domains
                .entry(flow["domain"].as_str().unwrap().into())
                .or_default() += count;
        }
        for entry in &entries {
            if entry["type"] == "unmatched_ndpi_application" {
                if let Some(name) = entry["value"].as_str() {
                    *unmatched_ndpi.entry(name.into()).or_default() += count;
                }
            }
        }
    }
    let rate = |n| {
        if total == 0 {
            0.0
        } else {
            n as f64 / total as f64
        }
    };
    json!({"device": {"total_clients": devices.len(), "device_type_identified":typed,"device_type_unknown":devices.len() as u64-typed,"vendor_identified":vendors,"private_mac":private,"evidence_source_coverage":coverage,"unknown_with_evidence_no_matching_device_type":no_rules,"unknown_without_evidence":no_evidence},
        "traffic":{"since_unix_ms":since,"denominator":"stored_flow_sessions","total_flows":total,"application_identified_rate":rate(apps),"domain_application_hit_rate":rate(domains),"ndpi_application_hit_rate":rate(ndpi),"protocol_only_rate":rate(protocols),"tls_quic_only_rate":rate(generic),"unknown_rate":rate(unknown),"top_unmatched_ndpi_application":top(unmatched_ndpi),"top_unmatched_domain_sni":top(unmatched_domains)}})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separates_missing_evidence_and_rules_and_uses_flows_as_denominator() {
        let devices = vec![
            json!({"identity_evidence_json":"[]"}),
            json!({"identity_evidence_json":"[{\"source\":\"mdns\"},{\"source\":\"mdns\"}]"}),
            json!({"device_type":"printer","vendor":"HP","private_mac":1,"identity_evidence_json":"[{\"source\":\"mdns\"}]"}),
        ];
        let flows = vec![
            json!({"application_id":"youtube","protocol_id":"tls","count":2,"classification_evidence_json":"[{\"type\":\"domain_application\"}]"}),
            json!({"protocol_id":"quic","domain":"unmatched.test","count":2,"classification_evidence_json":"[{\"type\":\"unmatched_ndpi_application\",\"value\":\"MissingApp\"}]"}),
        ];
        let value = summarize(&devices, &flows, 0);
        assert_eq!(value["device"]["unknown_without_evidence"], 1);
        assert_eq!(
            value["device"]["unknown_with_evidence_no_matching_device_type"],
            1
        );
        assert_eq!(value["device"]["evidence_source_coverage"]["mdns"], 2);
        assert_eq!(value["traffic"]["domain_application_hit_rate"], 0.5);
        assert_eq!(value["traffic"]["tls_quic_only_rate"], 0.5);
        assert_eq!(
            value["traffic"]["top_unmatched_ndpi_application"][0]["flows"],
            2
        );
    }
}
