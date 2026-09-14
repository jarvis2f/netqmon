use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightCategory {
    Device,
    Traffic,
    Classification,
    Dns,
    Protocol,
    Capture,
    Destination,
    NetworkQuality,
    Connectivity,
    Routing,
}

impl InsightCategory {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Traffic => "traffic",
            Self::Classification => "classification",
            Self::Dns => "dns",
            Self::Protocol => "protocol",
            Self::Capture => "capture",
            Self::Destination => "destination",
            Self::NetworkQuality => "network_quality",
            Self::Connectivity => "connectivity",
            Self::Routing => "routing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightSeverity {
    Info,
    Notice,
    Warning,
}

impl InsightSeverity {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedClient {
    pub id: Option<i64>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct InsightWindow {
    pub from: u64,
    pub to: u64,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Insight {
    pub id: String,
    pub category: String,
    pub code: String,
    pub severity: InsightSeverity,
    pub time: i64,
    pub source: String,
    pub affected_client: Option<AffectedClient>,
    pub params: Value,
    pub evidence: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

#[must_use]
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        return "unknown".to_owned();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[must_use]
pub fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[must_use]
pub fn to_u64(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or_default()
}
