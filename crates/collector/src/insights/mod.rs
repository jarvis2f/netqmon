#![allow(clippy::pedantic)]

pub mod capture;
pub mod classification;
pub mod destination;
pub mod device;
pub mod dns;
pub mod model;
pub mod protocol;
pub mod traffic;

pub use model::{
    AffectedClient, Insight, InsightCategory, InsightSeverity, InsightWindow, format_mac, to_i64,
    to_u64,
};
use rusqlite::Connection;

use crate::realtime::RealtimeSnapshot;

const DEFAULT_HIGH_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_COLLECTOR_LAG_MS: u64 = 30_000;

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

pub(crate) fn detect(
    connection: &Connection,
    snapshot: &RealtimeSnapshot,
    window: InsightWindow,
    lag_threshold_ms: u64,
    high_upload_threshold_bytes: u64,
) -> rusqlite::Result<Vec<Insight>> {
    let mut items = device::query_new_device_insights(connection, window)?;
    if let Some(insight) = classification::query_unknown_ratio_insight(connection, window)? {
        items.push(insight);
    }
    items.extend(
        classification::query_client_unknown_ratio_insights(connection, window).unwrap_or_default(),
    );
    items.extend(dns::query_encrypted_dns_insights(connection, window)?);
    items.extend(protocol::query_pt_tracker_correlation_insights(
        connection, window,
    )?);
    items.extend(
        protocol::query_ike_esp_correlation_insights(connection, window).unwrap_or_default(),
    );
    items.extend(
        protocol::query_pptp_gre_correlation_insights(connection, window).unwrap_or_default(),
    );
    items.extend(
        protocol::query_l2tp_ipsec_correlation_insights(connection, window).unwrap_or_default(),
    );
    items.extend(protocol::query_new_protocol_insights(connection, window).unwrap_or_default());
    items.extend(traffic::query_high_upload_insights(
        connection,
        window,
        high_upload_threshold_bytes,
    )?);
    items.extend(traffic::query_client_spike_insights(connection, window).unwrap_or_default());
    items.extend(traffic::query_application_spike_insights(connection, window).unwrap_or_default());
    items.extend(destination::query_fanout_spike_insights(connection, window).unwrap_or_default());
    items.extend(capture::query_capture_insights(
        connection,
        snapshot,
        window,
        lag_threshold_ms,
    )?);
    items.sort_by_key(|item| std::cmp::Reverse(item.time));
    items.truncate(window.limit as usize);
    Ok(items)
}
