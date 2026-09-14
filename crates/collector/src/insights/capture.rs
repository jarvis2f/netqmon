use rusqlite::Connection;
use serde_json::json;

use crate::realtime::{GatewayHealthSnapshot, RealtimeSnapshot};

use super::model::{Insight, InsightSeverity, InsightWindow, to_i64, to_u64};

pub(crate) fn query_capture_insights(
    connection: &Connection,
    snapshot: &RealtimeSnapshot,
    window: InsightWindow,
    lag_threshold_ms: u64,
) -> rusqlite::Result<Vec<Insight>> {
    let Some(health) = snapshot.gateway_health.as_ref() else {
        return Ok(Vec::new());
    };
    if health.observed_at < window.from || health.observed_at >= window.to {
        return Ok(Vec::new());
    }
    let observed_time = to_i64(health.observed_at);
    let mut items = Vec::new();
    push_hfo_insight(&mut items, health, observed_time);
    push_topology_insights(&mut items, health, observed_time);
    push_interface_counter_insight(&mut items, health, observed_time);
    if health.dns_dropped_events > 0 {
        items.push(Insight {
            id: format!("capture-agent-drops-{}", health.observed_at),
            category: "capture".to_owned(),
            code: "capture.dns_event_drops".to_owned(),
            severity: InsightSeverity::Warning,
            time: observed_time,
            source: "agent-health".to_owned(),
            affected_client: None,
            params: json!({
                "count": health.dns_dropped_events,
            }),
            evidence: json!({
                "condition": "agent_drops",
                "dns_dropped_events": health.dns_dropped_events,
                "action": "warning_only",
            }),
            fingerprint: None,
            status: None,
            first_seen: Some(observed_time),
            last_seen: Some(observed_time),
            occurrences: Some(1),
            confidence: Some(1.0),
        });
    }
    if health.protocol_probe_dropped_events > 0 {
        items.push(Insight {
            id: format!("capture-probe-drops-{}", health.observed_at),
            category: "capture".to_owned(),
            code: "capture.protocol_probe_drops".to_owned(),
            severity: InsightSeverity::Warning,
            time: observed_time,
            source: "agent-health".to_owned(),
            affected_client: None,
            params: json!({
                "count": health.protocol_probe_dropped_events,
            }),
            evidence: json!({
                "condition": "protocol_probe_drops",
                "protocol_probe_dropped_events": health.protocol_probe_dropped_events,
                "action": "warning_only",
            }),
            fingerprint: None,
            status: None,
            first_seen: Some(observed_time),
            last_seen: Some(observed_time),
            occurrences: Some(1),
            confidence: Some(1.0),
        });
    }
    if health.dropped_batches > 0 {
        items.push(Insight {
            id: format!("capture-queue-drops-{}", health.observed_at),
            category: "capture".to_owned(),
            code: "capture.telemetry_queue_drops".to_owned(),
            severity: InsightSeverity::Warning,
            time: observed_time,
            source: "agent-health".to_owned(),
            affected_client: None,
            params: json!({
                "count": health.dropped_batches,
            }),
            evidence: json!({
                "condition": "telemetry_queue_drops",
                "dropped_batches": health.dropped_batches,
                "action": "warning_only",
            }),
            fingerprint: None,
            status: None,
            first_seen: Some(observed_time),
            last_seen: Some(observed_time),
            occurrences: Some(1),
            confidence: Some(1.0),
        });
    }
    let received_at: Option<i64> =
        connection.query_row("SELECT MAX(last_seen) FROM gateways", [], |row| row.get(0))?;
    let received_at = received_at.map_or(snapshot.generated_at, to_u64);
    let lag_ms = received_at.saturating_sub(snapshot.generated_at);
    if lag_ms >= lag_threshold_ms {
        items.push(Insight {
            id: format!("capture-collector-lag-{}", health.observed_at),
            category: "capture".to_owned(),
            code: "capture.collector_lag".to_owned(),
            severity: InsightSeverity::Warning,
            time: observed_time,
            source: "collector-ingest".to_owned(),
            affected_client: None,
            params: json!({
                "lag_ms": lag_ms,
                "threshold_ms": lag_threshold_ms,
            }),
            evidence: json!({
                "condition": "collector_lag",
                "lag_ms": lag_ms,
                "threshold_ms": lag_threshold_ms,
                "agent_batch_time": snapshot.generated_at,
                "collector_received_time": received_at,
                "action": "warning_only",
            }),
            fingerprint: None,
            status: None,
            first_seen: Some(observed_time),
            last_seen: Some(observed_time),
            occurrences: Some(1),
            confidence: Some(1.0),
        });
    }
    Ok(items)
}

fn push_topology_insights(
    items: &mut Vec<Insight>,
    health: &GatewayHealthSnapshot,
    observed_time: i64,
) {
    let Some(topology) = health.topology.as_ref() else {
        return;
    };
    let mut risks = Vec::new();
    if topology.icmp_redirect == "enabled" {
        risks.push((
            "capture.icmp_redirect_enabled",
            "ICMP Redirect enabled; clients may bypass netqmon.",
        ));
    }
    if topology.ipv4_coverage != "full" {
        risks.push((
            "capture.ipv4_coverage",
            "IPv4 capture coverage is incomplete.",
        ));
    }
    if topology.ipv6_coverage != "full" {
        risks.push((
            "capture.ipv6_coverage",
            "IPv6 capture coverage is incomplete.",
        ));
    }
    if topology.software_flow_offload == "enabled" {
        risks.push((
            "capture.software_flow_offload",
            "Software flow offload may bypass dataplane observation.",
        ));
    }
    if topology.confidence < 70 {
        risks.push((
            "capture.topology_confidence",
            "Topology inference confidence is low or unknown.",
        ));
    }
    if topology
        .topology_warnings
        .iter()
        .any(|warning| warning.contains("Asymmetric routing"))
    {
        risks.push((
            "capture.asymmetric_routing",
            "Asymmetric routing is suspected from packet coverage.",
        ));
    }
    for (code, message) in risks {
        items.push(Insight {
            id: format!("{}-{}", code.replace('.', "-"), health.observed_at),
            category: "capture".to_owned(),
            code: code.to_owned(),
            severity: InsightSeverity::Warning,
            time: observed_time,
            source: "topology-engine".to_owned(),
            affected_client: None,
            params: json!({
                "message": message,
                "topology_mode": topology.topology_mode,
                "ipv4_coverage": topology.ipv4_coverage,
                "ipv6_coverage": topology.ipv6_coverage,
                "confidence": topology.confidence,
            }),
            evidence: json!({
                "condition": code,
                "warnings": topology.topology_warnings,
                "action": "warning_only",
            }),
            fingerprint: None,
            status: None,
            first_seen: Some(observed_time),
            last_seen: Some(observed_time),
            occurrences: Some(1),
            confidence: Some(f64::from(topology.confidence) / 100.0),
        });
    }
}

fn push_hfo_insight(items: &mut Vec<Insight>, health: &GatewayHealthSnapshot, observed_time: i64) {
    if health.hardware_flow_offload != "enabled" {
        return;
    }
    items.push(Insight {
        id: format!("capture-hfo-{}", health.observed_at),
        category: "capture".to_owned(),
        code: "capture.hardware_flow_offload".to_owned(),
        severity: InsightSeverity::Warning,
        time: observed_time,
        source: "agent-health".to_owned(),
        affected_client: None,
        params: json!({
            "hardware_flow_offload": "enabled",
        }),
        evidence: json!({
            "condition": "hardware_flow_offload_enabled",
            "hardware_flow_offload": "enabled",
            "action": "warning_only",
        }),
        fingerprint: None,
        status: None,
        first_seen: Some(observed_time),
        last_seen: Some(observed_time),
        occurrences: Some(1),
        confidence: Some(1.0),
    });
}

fn push_interface_counter_insight(
    items: &mut Vec<Insight>,
    health: &GatewayHealthSnapshot,
    observed_time: i64,
) {
    if health.interface_counter_sanity != "degraded" {
        return;
    }
    items.push(Insight {
        id: format!("capture-interface-counter-{}", health.observed_at),
        category: "capture".to_owned(),
        code: "capture.interface_counter_gap".to_owned(),
        severity: InsightSeverity::Warning,
        time: observed_time,
        source: "agent-health".to_owned(),
        affected_client: None,
        params: json!({
            "interface": health.capture_interface,
            "interface_delta": health.interface_delta_bytes,
            "flow_delta": health.flow_delta_bytes,
        }),
        evidence: json!({
            "condition": "interface_counter_gap",
            "capture_interface": health.capture_interface,
            "interface_delta_bytes": health.interface_delta_bytes,
            "interface_delta_packets": health.interface_delta_packets,
            "flow_delta_bytes": health.flow_delta_bytes,
            "flow_delta_packets": health.flow_delta_packets,
            "action": "warning_only",
        }),
        fingerprint: None,
        status: None,
        first_seen: Some(observed_time),
        last_seen: Some(observed_time),
        occurrences: Some(1),
        confidence: Some(1.0),
    });
}
