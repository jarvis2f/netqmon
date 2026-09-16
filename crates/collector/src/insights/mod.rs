#![allow(clippy::pedantic)]

mod model;

pub use model::{
    AffectedClient, Insight, InsightCategory, InsightSeverity, InsightWindow, format_mac, to_i64,
    to_u64,
};

use std::collections::{HashMap, HashSet};

use netqmon_storage::StorageError;
use netqmon_storage::analytics::{
    AnalyticsFlow, AnalyticsStore, FlowQuery, FlowSort, SummaryQuery, TrafficBreakdownQuery,
    TrafficDimension, resolution_for_range,
};
use netqmon_storage::metadata::{DeviceRecord, MetadataStore};
use serde_json::{Value, json};

use crate::realtime::{RealtimeSnapshot, format_ip};

const DEFAULT_HIGH_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_COLLECTOR_LAG_MS: u64 = 30_000;
const PAGE_SIZE: u32 = 1_000;
const CORRELATION_WINDOW_MS: u64 = 30 * 60 * 1_000;

#[must_use]
pub fn high_upload_threshold_bytes() -> u64 {
    std::env::var("NETQMON_INSIGHTS_HIGH_UPLOAD_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HIGH_UPLOAD_BYTES)
}

#[must_use]
pub fn collector_lag_threshold_ms() -> u64 {
    std::env::var("NETQMON_INSIGHTS_COLLECTOR_LAG_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_COLLECTOR_LAG_MS)
}

#[derive(Clone)]
struct ClientProfile {
    id: i64,
    name: String,
    mac: String,
    ip: Option<String>,
}

fn profiles(metadata: &dyn MetadataStore) -> Result<HashMap<u64, ClientProfile>, StorageError> {
    let mut profiles = HashMap::new();
    let mut offset = 0_u64;
    loop {
        let (devices, total) = metadata.devices(PAGE_SIZE, offset)?;
        for device in &devices {
            let address = metadata
                .device_addresses(device.id)?
                .into_iter()
                .max_by_key(|a| a.last_seen);
            profiles.insert(
                device.id as u64,
                profile(device, address.map(|a| format_ip(&a.ip))),
            );
        }
        offset = offset.saturating_add(devices.len() as u64);
        if devices.is_empty() || offset >= total {
            break;
        }
    }
    Ok(profiles)
}

fn profile(device: &DeviceRecord, ip: Option<String>) -> ClientProfile {
    ClientProfile {
        id: device.id,
        name: device
            .display_name
            .clone()
            .or_else(|| device.hostname.clone())
            .unwrap_or_else(|| "Unknown client".to_owned()),
        mac: format_mac(&device.mac),
        ip,
    }
}

fn client_for_flow(flow: &AnalyticsFlow, profiles: &HashMap<u64, ClientProfile>) -> AffectedClient {
    profiles.get(&flow.device_id).map_or_else(
        || AffectedClient {
            id: (flow.device_id > 0).then_some(flow.device_id as i64),
            name: "Unknown client".to_owned(),
            mac: None,
            ip: Some(format_ip(&flow.client_ip)),
        },
        |profile| AffectedClient {
            id: Some(profile.id),
            name: profile.name.clone(),
            mac: Some(profile.mac.clone()),
            ip: Some(format_ip(&flow.client_ip)),
        },
    )
}

fn collect_flows(
    analytics: &dyn AnalyticsStore,
    from: u64,
    to: u64,
) -> Result<Vec<AnalyticsFlow>, StorageError> {
    let mut query = FlowQuery {
        from,
        to,
        sort_by: FlowSort::LastSeen,
        descending: true,
        limit: PAGE_SIZE,
        ..FlowQuery::default()
    };
    let mut rows = Vec::new();
    loop {
        let page = analytics.flows(&query)?;
        let count = page.rows.len();
        rows.extend(page.rows);
        if count < PAGE_SIZE as usize || rows.len() as u64 >= page.total {
            break;
        }
        query.offset = query.offset.saturating_add(count as u64);
    }
    Ok(rows)
}

struct BaseInsight<'a> {
    category: &'a str,
    code: &'a str,
    severity: InsightSeverity,
    time: u64,
    source: &'a str,
    affected_client: Option<AffectedClient>,
    params: Value,
    evidence: Value,
}

fn base_insight(id: String, input: BaseInsight<'_>) -> Insight {
    let BaseInsight {
        category,
        code,
        severity,
        time,
        source,
        affected_client,
        params,
        evidence,
    } = input;
    let time = to_i64(time);
    Insight {
        id,
        category: category.to_owned(),
        code: code.to_owned(),
        severity,
        time,
        source: source.to_owned(),
        affected_client,
        params,
        evidence,
        fingerprint: None,
        status: None,
        first_seen: Some(time),
        last_seen: Some(time),
        occurrences: Some(1),
        confidence: Some(1.0),
    }
}

macro_rules! insight {
    ($id:expr, $category:expr, $code:expr, $severity:expr, $time:expr, $source:expr, $affected_client:expr, $params:expr, $evidence:expr $(,)?) => {
        base_insight(
            $id,
            BaseInsight {
                category: $category,
                code: $code,
                severity: $severity,
                time: $time,
                source: $source,
                affected_client: $affected_client,
                params: $params,
                evidence: $evidence,
            },
        )
    };
}

/// Builds insights from backend-neutral analytics and metadata contracts.
///
/// # Errors
///
/// Returns a storage error if a metadata or analytics query fails.
pub(crate) fn detect_from_analytics(
    analytics: &dyn AnalyticsStore,
    metadata: &dyn MetadataStore,
    snapshot: &RealtimeSnapshot,
    window: InsightWindow,
    lag_threshold_ms: u64,
    high_upload_threshold_bytes: u64,
) -> Result<Vec<Insight>, StorageError> {
    let flows = collect_flows(analytics, window.from, window.to)?;
    let profiles = profiles(metadata)?;
    let mut items = Vec::new();

    append_new_devices(metadata, &profiles, window, &mut items)?;
    append_unknown_ratio(&flows, window, &mut items);
    append_client_unknown_ratios(&flows, &profiles, window, &mut items);
    append_encrypted_dns(&flows, &profiles, window, &mut items);
    append_protocol_correlations(&flows, &profiles, window, &mut items);
    append_new_protocols(analytics, &flows, &profiles, window, &mut items)?;
    append_traffic_insights(
        analytics,
        &profiles,
        window,
        high_upload_threshold_bytes,
        &mut items,
    )?;
    append_fanout(&flows, &profiles, window, &mut items);
    append_capture_insights(metadata, snapshot, window, lag_threshold_ms, &mut items)?;

    items.sort_by_key(|item| std::cmp::Reverse(item.time));
    items.truncate(window.limit as usize);
    Ok(items)
}

fn append_new_devices(
    metadata: &dyn MetadataStore,
    profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &mut Vec<Insight>,
) -> Result<(), StorageError> {
    let mut offset = 0_u64;
    loop {
        let (devices, total) = metadata.devices(PAGE_SIZE, offset)?;
        for device in &devices {
            if device.first_seen < window.from || device.first_seen >= window.to {
                continue;
            }
            let client = profiles
                .get(&(device.id as u64))
                .cloned()
                .unwrap_or_else(|| profile(device, None));
            let time = device.first_seen;
            items.push(insight!(
                format!("new-device-{}", device.id),
                "device",
                "device.new_device",
                InsightSeverity::Info,
                time,
                "device-discovery",
                Some(AffectedClient {
                    id: Some(client.id),
                    name: client.name.clone(),
                    mac: Some(client.mac.clone()),
                    ip: client.ip.clone(),
                }),
                json!({"name":client.name,"mac":client.mac,"ip":client.ip,"first_seen":time}),
                json!({"first_seen":time,"mac":client.mac,"ip":client.ip}),
            ));
        }
        offset = offset.saturating_add(devices.len() as u64);
        if devices.is_empty() || offset >= total {
            break;
        }
    }
    Ok(())
}

fn append_unknown_ratio(flows: &[AnalyticsFlow], window: InsightWindow, items: &mut Vec<Insight>) {
    let total = flows.iter().fold(0_u64, |sum, flow| {
        sum.saturating_add(flow.upload_bytes)
            .saturating_add(flow.download_bytes)
    });
    let unknown = flows
        .iter()
        .filter(|flow| flow.application_id == "unknown")
        .fold(0_u64, |sum, flow| {
            sum.saturating_add(flow.upload_bytes)
                .saturating_add(flow.download_bytes)
        });
    if total == 0 {
        return;
    }
    let ratio = unknown as f64 / total as f64;
    let time = flows
        .iter()
        .map(|flow| flow.last_seen_at)
        .max()
        .unwrap_or(window.to);
    items.push(insight!(
        format!("unknown-traffic-{}-{}", window.from, window.to), "classification",
        "classification.unknown_ratio_high",
        if ratio >= 0.1 { InsightSeverity::Warning } else { InsightSeverity::Info },
        time, "classifier", None,
        json!({"unknown_bytes":unknown,"total_bytes":total,"ratio":ratio,"percent":format!("{:.1}",ratio*100.0)}),
        json!({"unknown_bytes":unknown,"total_bytes":total,"ratio":ratio,"window_from":window.from,"window_to":window.to,"rule":"application_id = unknown"}),
    ));
}

fn append_client_unknown_ratios(
    flows: &[AnalyticsFlow],
    profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &mut Vec<Insight>,
) {
    let mut groups = HashMap::<(u64, Vec<u8>), (u64, u64, u64)>::new();
    for flow in flows {
        let totals = groups
            .entry((flow.device_id, flow.client_ip.clone()))
            .or_default();
        let bytes = flow.upload_bytes.saturating_add(flow.download_bytes);
        totals.1 = totals.1.saturating_add(bytes);
        if flow.application_id == "unknown" {
            totals.0 = totals.0.saturating_add(bytes);
        }
        totals.2 = totals.2.max(flow.last_seen_at);
    }
    for ((device_id, ip), (unknown, total, time)) in groups {
        if total < 1_048_576 || unknown.saturating_mul(2) < total {
            continue;
        }
        let ratio = unknown as f64 / total as f64;
        let client = profiles.get(&device_id);
        let ip = format_ip(&ip);
        let affected = AffectedClient {
            id: (device_id > 0).then_some(device_id as i64),
            name: client.map_or_else(|| "Unknown client".to_owned(), |v| v.name.clone()),
            mac: client.map(|v| v.mac.clone()),
            ip: Some(ip.clone()),
        };
        items.push(insight!(
            format!("client-unknown-traffic-{ip}-{}-{}",window.from,window.to),
            "classification","classification.client_unknown_ratio_high",
            if ratio >= 0.8 { InsightSeverity::Warning } else { InsightSeverity::Notice },
            time,"classifier",Some(affected.clone()),
            json!({"client":affected.name,"unknown_bytes":unknown,"total_bytes":total,"ratio":ratio,"percent":format!("{:.1}",ratio*100.0)}),
            json!({"client_ip":ip,"unknown_bytes":unknown,"total_bytes":total,"ratio":ratio,"window_from":window.from,"window_to":window.to}),
        ));
    }
}

fn append_encrypted_dns(
    flows: &[AnalyticsFlow],
    profiles: &HashMap<u64, ClientProfile>,
    _window: InsightWindow,
    items: &mut Vec<Insight>,
) {
    for flow in flows {
        let remote = format_ip(&flow.remote_ip);
        let provider = encrypted_dns_provider(&remote);
        let rule = if flow.remote_port == 853 {
            Some("dot_port_853")
        } else if flow.remote_port == 443 && provider.is_some() {
            Some("known_doh_provider")
        } else {
            None
        };
        let Some(rule) = rule else {
            continue;
        };
        let protocol = if flow.remote_port == 853 {
            "DoT"
        } else {
            "DoH"
        };
        let provider_name = provider.unwrap_or(protocol);
        let client = client_for_flow(flow, profiles);
        items.push(insight!(
            format!("encrypted-dns-{}",flow.flow_id),"dns","dns.encrypted_dns_detected",
            InsightSeverity::Notice,flow.last_seen_at,"flow-rules",Some(client.clone()),
            json!({"name":client.name,"client":client.name,"remote_ip":remote,"remote_port":flow.remote_port,"protocol":protocol,"provider":provider_name,"rule":rule,"provider_or_rule":provider_name}),
            json!({"rule":rule,"provider":provider,"remote_ip":remote,"remote_port":flow.remote_port,"protocol":protocol,"domain":null,"domain_limit":"Encrypted DNS contents are not visible","action":"observation_only"}),
        ));
    }
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

fn append_protocol_correlations(
    flows: &[AnalyticsFlow],
    profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &mut Vec<Insight>,
) {
    let trackers = flows
        .iter()
        .filter(|f| f.traffic_role == "tracker_service" && f.category_id == "p2p")
        .collect::<Vec<_>>();
    let peers = flows
        .iter()
        .filter(|f| f.protocol_id == "bittorrent")
        .collect::<Vec<_>>();
    for tracker in &trackers {
        let peers = peers
            .iter()
            .filter(|peer| {
                peer.device_id == tracker.device_id
                    && peer.client_ip == tracker.client_ip
                    && peer.flow_id != tracker.flow_id
                    && peer.last_seen_at.abs_diff(tracker.last_seen_at) <= CORRELATION_WINDOW_MS
            })
            .collect::<Vec<_>>();
        if peers.is_empty() {
            continue;
        }
        let peer_bytes = peers
            .iter()
            .map(|flow| flow.upload_bytes.saturating_add(flow.download_bytes))
            .sum::<u64>();
        let time = peers
            .iter()
            .map(|f| f.last_seen_at)
            .chain(std::iter::once(tracker.last_seen_at))
            .max()
            .unwrap_or(tracker.last_seen_at);
        let client = client_for_flow(tracker, profiles);
        items.push(insight!(
            format!("pt-bittorrent-correlation-{}-{}-{}",format_ip(&tracker.client_ip),window.from,window.to),
            "protocol","protocol.p2p_tracker_correlation",InsightSeverity::Notice,time,"classifier-correlation",Some(client.clone()),
            json!({"name":client.name,"client":client.name,"tracker_flows":1,"peer_flows":peers.len()}),
            json!({"tracker_role":"tracker_service","tracker_class":"p2p","peer_protocol":"bittorrent","tracker_flows":1,"peer_flows":peers.len(),"tracker_bytes":tracker.upload_bytes.saturating_add(tracker.download_bytes),"peer_bytes":peer_bytes,"window_from":window.from,"window_to":window.to,"action":"observation_only"}),
        ));
    }

    let mut pair_context = PairInsightContext {
        profiles,
        window,
        items,
    };
    for first in flows {
        for second in flows.iter().filter(|f| {
            f.device_id == first.device_id
                && f.client_ip == first.client_ip
                && f.remote_ip == first.remote_ip
                && f.flow_id != first.flow_id
                && f.last_seen_at.abs_diff(first.last_seen_at) <= CORRELATION_WINDOW_MS
        }) {
            let first_proto = first.protocol_id.as_str();
            let second_proto = second.protocol_id.as_str();
            let pair = (first, second);
            if first_proto == "ike" && (second_proto == "ipsec_esp" || second.protocol == 50) {
                push_pair_insight(
                    pair.0,
                    pair.1,
                    PairInsight {
                        code: "protocol.ipsec_detected",
                        first_name: "ike",
                        second_name: "esp",
                    },
                    &mut pair_context,
                );
            }
            let is_l2tp = |flow: &AnalyticsFlow| {
                flow.protocol_id == "l2tp" || (flow.protocol == 17 && flow.remote_port == 1701)
            };
            let is_ipsec = |flow: &AnalyticsFlow| {
                matches!(flow.protocol_id.as_str(), "ike" | "ipsec_esp") || flow.protocol == 50
            };
            if (is_l2tp(first) && is_ipsec(second)) || (is_l2tp(second) && is_ipsec(first)) {
                let (l2tp, ipsec) = if is_l2tp(first) {
                    (first, second)
                } else {
                    (second, first)
                };
                push_pair_insight(
                    l2tp,
                    ipsec,
                    PairInsight {
                        code: "protocol.l2tp_ipsec_detected",
                        first_name: "l2tp",
                        second_name: "esp",
                    },
                    &mut pair_context,
                );
            }
            let is_pptp = |flow: &AnalyticsFlow| {
                flow.protocol_id == "pptp" || (flow.protocol == 6 && flow.remote_port == 1723)
            };
            let is_gre = |flow: &AnalyticsFlow| flow.protocol_id == "gre" || flow.protocol == 47;
            if (is_pptp(first) && is_gre(second)) || (is_pptp(second) && is_gre(first)) {
                let (pptp, gre) = if is_pptp(first) {
                    (first, second)
                } else {
                    (second, first)
                };
                push_pair_insight(
                    pptp,
                    gre,
                    PairInsight {
                        code: "protocol.pptp_detected",
                        first_name: "pptp",
                        second_name: "gre",
                    },
                    &mut pair_context,
                );
            }
        }
    }
}

struct PairInsight<'a> {
    code: &'a str,
    first_name: &'a str,
    second_name: &'a str,
}

struct PairInsightContext<'a> {
    profiles: &'a HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &'a mut Vec<Insight>,
}

fn push_pair_insight(
    first: &AnalyticsFlow,
    second: &AnalyticsFlow,
    pair: PairInsight<'_>,
    context: &mut PairInsightContext<'_>,
) {
    let PairInsight {
        code,
        first_name,
        second_name,
    } = pair;
    // These protocol pairs are symmetric in the source data, so emit once.
    if first.flow_id > second.flow_id {
        return;
    }
    let client = client_for_flow(first, context.profiles);
    let remote = format_ip(&first.remote_ip);
    let time = first.last_seen_at.max(second.last_seen_at);
    let (evidence, id) = match code {
        "protocol.l2tp_ipsec_detected" => (
            json!({"remote_ip":remote,"l2tp_flows":1,"ike_flows":u64::from(first_name=="l2tp" && second.protocol_id=="ike")+u64::from(first_name=="l2tp" && first.protocol_id=="ike"),"esp_flows":1,"l2tp_bytes":first.upload_bytes+first.download_bytes,"ipsec_bytes":second.upload_bytes+second.download_bytes,"observed_time":time,"window_ms":CORRELATION_WINDOW_MS}),
            format!(
                "l2tp-ipsec-correlation-{}-{}-{}-{}",
                format_ip(&first.client_ip),
                remote,
                context.window.from,
                context.window.to
            ),
        ),
        "protocol.pptp_detected" => (
            json!({"remote_ip":remote,"pptp_flows":1,"gre_flows":1,"pptp_bytes":first.upload_bytes+first.download_bytes,"gre_bytes":second.upload_bytes+second.download_bytes}),
            format!(
                "pptp-gre-correlation-{}-{}-{}-{}",
                format_ip(&first.client_ip),
                remote,
                context.window.from,
                context.window.to
            ),
        ),
        _ => (
            json!({"remote_ip":remote,"ike_flows":1,"esp_flows":1,"ike_bytes":first.upload_bytes+first.download_bytes,"esp_bytes":second.upload_bytes+second.download_bytes}),
            format!(
                "ike-esp-correlation-{}-{}-{}-{}",
                format_ip(&first.client_ip),
                remote,
                context.window.from,
                context.window.to
            ),
        ),
    };
    context.items.push(insight!(id,"protocol",code,InsightSeverity::Notice,time,"classifier-correlation",Some(client.clone()),json!({"name":client.name,"client":client.name,"client_ip":format_ip(&first.client_ip),"remote_ip":remote,"protocol_pair":[first_name,second_name]}),evidence));
}

fn append_new_protocols(
    analytics: &dyn AnalyticsStore,
    flows: &[AnalyticsFlow],
    _profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &mut Vec<Insight>,
) -> Result<(), StorageError> {
    if window.from == 0 {
        return Ok(());
    }
    let baseline = collect_flows(analytics, 0, window.from)?;
    let known = baseline
        .iter()
        .map(|f| f.protocol_id.as_str())
        .collect::<HashSet<_>>();
    let mut current = HashMap::<String, u64>::new();
    for flow in flows {
        if !flow.protocol_id.is_empty()
            && flow.protocol_id != "unknown"
            && !known.contains(flow.protocol_id.as_str())
        {
            current
                .entry(flow.protocol_id.clone())
                .and_modify(|time| *time = (*time).max(flow.last_seen_at))
                .or_insert(flow.last_seen_at);
        }
    }
    for (protocol, time) in current {
        items.push(insight!(
            format!("new-protocol-{protocol}-{time}"),
            "protocol",
            "protocol.new_protocol",
            InsightSeverity::Info,
            time,
            "classifier",
            None,
            json!({"protocol":protocol,"protocol_name":protocol}),
            json!({"protocol_id":protocol,"window_from":window.from,"window_to":window.to}),
        ));
    }
    Ok(())
}

fn breakdown(
    analytics: &dyn AnalyticsStore,
    from: u64,
    to: u64,
    dimension: TrafficDimension,
) -> Result<Vec<netqmon_storage::analytics::TrafficBreakdown>, StorageError> {
    let query = SummaryQuery {
        from,
        to,
        resolution: resolution_for_range(from, to),
        gateway_id: None,
        device_id: None,
        scope: None,
        direction: None,
        organization_id: None,
        application_id: None,
        category_id: None,
        protocol_id: None,
        domain: None,
        remote_ip: None,
        limit: 100_000,
        offset: 0,
    };
    analytics.traffic_breakdown(&TrafficBreakdownQuery {
        traffic: netqmon_storage::analytics::TrafficQuery {
            from: query.from,
            to: query.to,
            resolution: query.resolution,
            gateway_id: None,
            scope: None,
            direction: None,
            device_id: None,
            organization_id: None,
            application_id: None,
            category_id: None,
            protocol_id: None,
            domain: None,
            remote_ip: None,
        },
        dimension,
        limit: query.limit,
        offset: query.offset,
    })
}

fn append_traffic_insights(
    analytics: &dyn AnalyticsStore,
    profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    high_upload_threshold: u64,
    items: &mut Vec<Insight>,
) -> Result<(), StorageError> {
    let current_clients = breakdown(analytics, window.from, window.to, TrafficDimension::Device)?;
    for row in &current_clients {
        let Ok(device_id) = row.key.parse::<u64>() else {
            continue;
        };
        if row.upload_bytes < high_upload_threshold {
            continue;
        }
        let profile = profiles.get(&device_id);
        let affected = profile.map(|p| AffectedClient {
            id: Some(p.id),
            name: p.name.clone(),
            mac: Some(p.mac.clone()),
            ip: p.ip.clone(),
        });
        items.push(insight!(format!("high-upload-{device_id}-{}-{}",window.from,window.to),"traffic","traffic.high_upload",InsightSeverity::Warning,row.last_seen_at,"traffic-history",affected.clone(),json!({"name":profile.map_or("Unknown device",|p|p.name.as_str()),"client":profile.map_or("Unknown device",|p|p.name.as_str()),"upload_bytes":row.upload_bytes,"bytes":row.upload_bytes,"tx_bytes":row.upload_bytes,"threshold_bytes":high_upload_threshold}),json!({"upload_bytes":row.upload_bytes,"threshold_bytes":high_upload_threshold,"window_from":window.from,"window_to":window.to,"action":"observation_only"})));
    }

    let duration = window.to.saturating_sub(window.from);
    let baseline_from = window.from.saturating_sub(duration);
    if baseline_from < window.from {
        let baseline_clients = breakdown(
            analytics,
            baseline_from,
            window.from,
            TrafficDimension::Device,
        )?;
        let baseline = baseline_clients
            .into_iter()
            .map(|r| (r.key, r.upload_bytes.saturating_add(r.download_bytes)))
            .collect::<HashMap<_, _>>();
        for row in &current_clients {
            let current = row.upload_bytes.saturating_add(row.download_bytes);
            let Some(old) = baseline.get(&row.key).copied().filter(|v| *v > 0) else {
                continue;
            };
            if current < 10 * 1024 * 1024 || current < old.saturating_mul(3) {
                continue;
            }
            let ratio = current as f64 / old as f64;
            let device_id = row.key.parse::<u64>().unwrap_or_default();
            let profile = profiles.get(&device_id);
            let affected = profile.map(|p| AffectedClient {
                id: Some(p.id),
                name: p.name.clone(),
                mac: Some(p.mac.clone()),
                ip: p.ip.clone(),
            });
            items.push(insight!(format!("client-spike-{device_id}-{}-{}",window.from,window.to),"traffic","traffic.client_spike",if ratio>=5.0{InsightSeverity::Warning}else{InsightSeverity::Notice},row.last_seen_at,"traffic-history",affected.clone(),json!({"name":profile.map_or("Unknown device",|p|p.name.as_str()),"client":profile.map_or("Unknown device",|p|p.name.as_str()),"bytes":current,"current_bytes":current,"baseline_bytes":old,"multiplier":format!("{ratio:.1}"),"ratio":format!("{ratio:.1}x")}),json!({"current_bytes":current,"baseline_bytes":old,"multiplier":ratio,"window_from":window.from,"window_to":window.to})));
        }
        let current_apps = breakdown(
            analytics,
            window.from,
            window.to,
            TrafficDimension::Application,
        )?;
        let baseline_apps = breakdown(
            analytics,
            baseline_from,
            window.from,
            TrafficDimension::Application,
        )?
        .into_iter()
        .map(|r| (r.key, r.upload_bytes.saturating_add(r.download_bytes)))
        .collect::<HashMap<_, _>>();
        for row in current_apps.iter().filter(|r| r.key != "unknown") {
            let current = row.upload_bytes.saturating_add(row.download_bytes);
            let Some(old) = baseline_apps.get(&row.key).copied().filter(|v| *v > 0) else {
                continue;
            };
            if current < 10 * 1024 * 1024 || current < old.saturating_mul(3) {
                continue;
            }
            let ratio = current as f64 / old as f64;
            items.push(insight!(format!("app-spike-{}-{}-{}",row.key,window.from,window.to),"traffic","traffic.application_spike",if ratio>=5.0{InsightSeverity::Warning}else{InsightSeverity::Notice},row.last_seen_at,"traffic-history",None,json!({"application":row.key,"application_name":row.key,"bytes":current,"current_bytes":current,"baseline_bytes":old,"multiplier":format!("{ratio:.1}"),"ratio":format!("{ratio:.1}x")}),json!({"application_id":row.key,"current_bytes":current,"baseline_bytes":old,"multiplier":ratio,"window_from":window.from,"window_to":window.to})));
        }
    }
    Ok(())
}

fn append_fanout(
    flows: &[AnalyticsFlow],
    profiles: &HashMap<u64, ClientProfile>,
    window: InsightWindow,
    items: &mut Vec<Insight>,
) {
    let mut groups = HashMap::<(u64, Vec<u8>), (HashSet<Vec<u8>>, u64)>::new();
    for flow in flows {
        let group = groups
            .entry((flow.device_id, flow.client_ip.clone()))
            .or_default();
        group.0.insert(flow.remote_ip.clone());
        group.1 = group.1.max(flow.last_seen_at);
    }
    for ((device_id, ip), (destinations, time)) in groups {
        if destinations.len() < 50 {
            continue;
        }
        let client = profiles.get(&device_id);
        let name = client.map_or("Unknown client", |p| p.name.as_str());
        let affected = AffectedClient {
            id: (device_id > 0).then_some(device_id as i64),
            name: name.to_owned(),
            mac: client.map(|p| p.mac.clone()),
            ip: Some(format_ip(&ip)),
        };
        items.push(insight!(format!("fanout-spike-{}-{}-{}",format_ip(&ip),window.from,window.to),"destination","destination.fanout_spike",if destinations.len()>=100{InsightSeverity::Warning}else{InsightSeverity::Notice},time,"flow-history",Some(affected),json!({"name":name,"client":name,"count":destinations.len(),"destination_count":destinations.len()}),json!({"client_ip":format_ip(&ip),"destination_count":destinations.len(),"window_from":window.from,"window_to":window.to})));
    }
}

fn append_capture_insights(
    metadata: &dyn MetadataStore,
    snapshot: &RealtimeSnapshot,
    window: InsightWindow,
    lag_threshold_ms: u64,
    items: &mut Vec<Insight>,
) -> Result<(), StorageError> {
    let Some(health) = snapshot.gateway_health.as_ref() else {
        return Ok(());
    };
    if health.observed_at < window.from || health.observed_at >= window.to {
        return Ok(());
    }
    let time = health.observed_at;
    if health.hardware_flow_offload == "enabled" {
        items.push(insight!(format!("capture-hfo-{time}"),"capture","capture.hardware_flow_offload",InsightSeverity::Warning,time,"agent-health",None,json!({"hardware_flow_offload":"enabled"}),json!({"condition":"hardware_flow_offload_enabled","hardware_flow_offload":"enabled","action":"warning_only"})));
    }
    if health.interface_counter_sanity == "degraded" {
        items.push(insight!(format!("capture-interface-counter-{time}"),"capture","capture.interface_counter_gap",InsightSeverity::Warning,time,"agent-health",None,json!({"interface":health.capture_interface,"interface_delta":health.interface_delta_bytes,"flow_delta":health.flow_delta_bytes}),json!({"condition":"interface_counter_gap","capture_interface":health.capture_interface,"interface_delta_bytes":health.interface_delta_bytes,"interface_delta_packets":health.interface_delta_packets,"flow_delta_bytes":health.flow_delta_bytes,"flow_delta_packets":health.flow_delta_packets,"action":"warning_only"})));
    }
    for (code, count) in [
        ("capture.dns_event_drops", health.dns_dropped_events),
        (
            "capture.protocol_probe_drops",
            health.protocol_probe_dropped_events,
        ),
        ("capture.telemetry_queue_drops", health.dropped_batches),
    ] {
        if count > 0 {
            items.push(insight!(
                format!("{}-{time}", code.replace('.', "-")),
                "capture",
                code,
                InsightSeverity::Warning,
                time,
                "agent-health",
                None,
                json!({"count":count}),
                json!({"condition":code,"count":count,"action":"warning_only"}),
            ));
        }
    }
    if let Some(topology) = health.topology.as_ref() {
        let mut warnings = Vec::new();
        if topology.icmp_redirect == "enabled" {
            warnings.push((
                "capture.icmp_redirect_enabled",
                "ICMP Redirect enabled; clients may bypass netqmon.",
            ));
        }
        if topology.ipv4_coverage != "full" {
            warnings.push((
                "capture.ipv4_coverage",
                "IPv4 capture coverage is incomplete.",
            ));
        }
        if topology.ipv6_coverage != "full" {
            warnings.push((
                "capture.ipv6_coverage",
                "IPv6 capture coverage is incomplete.",
            ));
        }
        if topology.software_flow_offload == "enabled" {
            warnings.push((
                "capture.software_flow_offload",
                "Software flow offload may bypass dataplane observation.",
            ));
        }
        if topology.confidence < 70 {
            warnings.push((
                "capture.topology_confidence",
                "Topology inference confidence is low or unknown.",
            ));
        }
        if topology
            .topology_warnings
            .iter()
            .any(|w| w.contains("Asymmetric routing"))
        {
            warnings.push((
                "capture.asymmetric_routing",
                "Asymmetric routing is suspected from packet coverage.",
            ));
        }
        for (code, message) in warnings {
            items.push(insight!(format!("{}-{time}",code.replace('.',"-")),"capture",code,InsightSeverity::Warning,time,"topology-engine",None,json!({"message":message,"topology_mode":topology.topology_mode,"ipv4_coverage":topology.ipv4_coverage,"ipv6_coverage":topology.ipv6_coverage,"confidence":topology.confidence}),json!({"condition":code,"warnings":topology.topology_warnings,"action":"warning_only"})));
        }
    }
    let received = metadata
        .gateway_details()?
        .map_or(snapshot.generated_at, |gateway| gateway.last_seen);
    let agent_batch_time = if health.observed_at == 0 {
        snapshot.generated_at
    } else {
        health.observed_at
    };
    let lag = received.saturating_sub(agent_batch_time);
    if lag >= lag_threshold_ms {
        items.push(insight!(format!("capture-collector-lag-{time}"),"capture","capture.collector_lag",InsightSeverity::Warning,time,"collector-ingest",None,json!({"lag_ms":lag,"threshold_ms":lag_threshold_ms}),json!({"condition":"collector_lag","lag_ms":lag,"threshold_ms":lag_threshold_ms,"agent_batch_time":agent_batch_time,"collector_received_time":received,"action":"warning_only"})));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_unknown_ratio_from_flow_bytes() {
        let flow = AnalyticsFlow {
            flow_id: "unknown".into(),
            gateway_id: "gw".into(),
            device_id: 1,
            ip_version: 4,
            protocol: 6,
            client_ip: vec![192, 0, 2, 1],
            client_port: 1,
            remote_ip: vec![203, 0, 113, 1],
            remote_port: 443,
            direction: 1,
            domain: String::new(),
            organization_id: "unknown".into(),
            application_id: "unknown".into(),
            category_id: "unknown".into(),
            traffic_role: "unknown".into(),
            protocol_id: "unknown".into(),
            organization_confidence: 0.0,
            application_confidence: 0.0,
            protocol_confidence: 0.0,
            classification_confidence: 0.0,
            classification_reason: String::new(),
            classification_evidence_json: "[]".into(),
            upload_bytes: 100,
            download_bytes: 50,
            packets: 1,
            started_at: 1,
            last_seen_at: 2,
            ended_at: Some(2),
            checkpointed_at: 2,
            scope: 1,
            path_type: 1,
            nat: 1,
            source_segment: String::new(),
            destination_segment: String::new(),
        };
        let mut items = Vec::new();
        append_unknown_ratio(
            &[flow],
            InsightWindow {
                from: 0,
                to: 3,
                limit: 10,
            },
            &mut items,
        );
        assert_eq!(items[0].evidence["unknown_bytes"], 150);
        assert_eq!(items[0].evidence["total_bytes"], 150);
    }
}
