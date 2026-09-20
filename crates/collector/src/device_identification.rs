use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netqmon_classifier_client::{DeviceEvidenceInput, DeviceEvidenceResult};
use netqmon_protocol::v1::DeviceObservation;
use netqmon_storage::{
    DeviceEvidenceRecord, DeviceEvidenceUpdate, DeviceIdentityUpdate, FlowAttribution,
};
use reqwest::Url;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classifier::{ClassifierHandle, DeviceFingerprintInput};

const DEFAULT_SOURCE: &str = "IEEE";
const DEFAULT_LICENSE: &str = "IEEE Registration Authority public registry";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default)]
pub(crate) struct DeviceIdentifier {
    mac_dataset: MacPrefixDataset,
}

impl DeviceIdentifier {
    pub(crate) fn replace_mac_dataset(&mut self, dataset: MacPrefixDataset) {
        self.mac_dataset = dataset;
    }

    #[allow(dead_code)]
    pub(crate) fn mac_prefix_count(&self) -> usize {
        self.mac_dataset.metadata.entry_count
    }

    #[allow(clippy::if_not_else)]
    pub(crate) fn load(dataset_path: &Path) -> Self {
        let mac_dataset = if !dataset_path.exists() {
            tracing::info!(
                path = %dataset_path.display(),
                "MAC prefix dataset cache not found; device vendor lookup will use hostname/DHCP evidence until refresh completes"
            );
            MacPrefixDataset::default()
        } else {
            match MacPrefixDataset::load(dataset_path) {
                Ok(dataset) => {
                    tracing::info!(
                        path = %dataset_path.display(),
                        entries = dataset.metadata.entry_count,
                        updated_at = %dataset.metadata.updated_at,
                        "MAC prefix dataset loaded"
                    );
                    dataset
                }
                Err(error) => {
                    tracing::warn!(
                        path = %dataset_path.display(),
                        error = %error,
                        "MAC prefix dataset unavailable; device vendor lookup will return unknown"
                    );
                    MacPrefixDataset::default()
                }
            }
        };
        Self { mac_dataset }
    }

    pub(crate) fn identify_batch(
        &self,
        classifier: &ClassifierHandle,
        observations: &[DeviceObservation],
        historical: &HashMap<Vec<u8>, Vec<DeviceEvidenceRecord>>,
        supplemental: &HashMap<Vec<u8>, Vec<DeviceEvidenceUpdate>>,
    ) -> Vec<DeviceIdentityUpdate> {
        let mut latest = HashMap::<Vec<u8>, &DeviceObservation>::new();
        for observation in observations {
            latest
                .entry(observation.mac.clone())
                .and_modify(|current| {
                    if observation.last_seen_unix_ms > current.last_seen_unix_ms {
                        *current = observation;
                    }
                })
                .or_insert(observation);
        }
        let latest = latest.into_values().collect::<Vec<_>>();
        let inputs = latest
            .iter()
            .enumerate()
            .map(|(index, observation)| {
                let mut evidence = observation_device_inputs(observation);
                if !is_locally_administered(&observation.mac) {
                    if let Some(vendor) = self.mac_dataset.lookup(&observation.mac) {
                        evidence.push(device_text_input("mac_vendor", vendor));
                    }
                }
                DeviceFingerprintInput {
                    entry_id: index.to_string(),
                    evidence,
                }
            })
            .collect();
        let mut matches = classifier.classify_devices(inputs).unwrap_or_else(|error| {
            tracing::debug!(%error, "classifier device identification skipped");
            HashMap::new()
        });
        latest
            .into_iter()
            .enumerate()
            .map(|observation| {
                let (index, observation) = observation;
                let mut current = supplemental
                    .get(&observation.mac)
                    .cloned()
                    .unwrap_or_default();
                current.extend(device_results_to_updates(
                    matches.remove(&index.to_string()).unwrap_or_default(),
                    observation.last_seen_unix_ms,
                    &serde_json::Value::Null,
                ));
                self.identify(
                    observation,
                    historical
                        .get(&observation.mac)
                        .map_or(&[][..], Vec::as_slice),
                    &current,
                )
            })
            .collect()
    }

    pub(crate) fn destination_evidence(
        classifier: &ClassifierHandle,
        batch: &netqmon_protocol::v1::TelemetryBatch,
        attributions: &[FlowAttribution],
    ) -> HashMap<Vec<u8>, Vec<DeviceEvidenceUpdate>> {
        let mut pending = Vec::new();
        for (index, flow) in batch.flows.iter().enumerate() {
            if flow.client_mac.len() != 6 {
                continue;
            }
            let Some(domain) = attributions
                .get(index)
                .and_then(|item| item.domain.as_deref())
            else {
                continue;
            };
            pending.push((
                index.to_string(),
                flow.client_mac.clone(),
                flow.last_seen_unix_ms,
                domain.to_owned(),
            ));
        }
        let inputs = pending
            .iter()
            .map(|(entry_id, _, _, domain)| DeviceFingerprintInput {
                entry_id: entry_id.clone(),
                evidence: vec![device_text_input("destination", domain)],
            })
            .collect();
        let mut matches = classifier.classify_devices(inputs).unwrap_or_else(|error| {
            tracing::debug!(%error, "classifier destination evidence skipped");
            HashMap::new()
        });
        let mut evidence = HashMap::new();
        for (entry_id, mac, observed_at, domain) in pending {
            evidence
                .entry(mac)
                .or_insert_with(Vec::new)
                .extend(device_results_to_updates(
                    matches.remove(&entry_id).unwrap_or_default(),
                    observed_at,
                    &serde_json::json!({"domain": domain}),
                ));
        }
        evidence
    }

    pub(crate) fn discovery_evidence(
        classifier: &ClassifierHandle,
        observations: &[netqmon_protocol::v1::DeviceDiscoveryObservation],
    ) -> HashMap<Vec<u8>, Vec<DeviceEvidenceUpdate>> {
        let observations = observations
            .iter()
            .filter(|observation| observation.mac.len() == 6)
            .collect::<Vec<_>>();
        let inputs = observations
            .iter()
            .enumerate()
            .map(|(index, observation)| DeviceFingerprintInput {
                entry_id: index.to_string(),
                evidence: discovery_device_inputs(observation),
            })
            .collect();
        let mut matches = classifier.classify_devices(inputs).unwrap_or_else(|error| {
            tracing::debug!(%error, "classifier discovery evidence skipped");
            HashMap::new()
        });
        let mut evidence = HashMap::new();
        for (index, observation) in observations.into_iter().enumerate() {
            let items = evidence
                .entry(observation.mac.clone())
                .or_insert_with(Vec::new);
            items.push(DeviceEvidenceUpdate {
                source: observation.protocol.clone(),
                field: "observation".to_owned(),
                value: if observation.service.is_empty() {
                    observation.protocol.clone()
                } else {
                    observation.service.clone()
                },
                confidence: 1.0,
                observed_at: observation.observed_at_unix_ms,
                metadata_json: "{}".to_owned(),
            });
            items.extend(device_results_to_updates(
                matches.remove(&index.to_string()).unwrap_or_default(),
                observation.observed_at_unix_ms,
                &serde_json::json!({
                    "protocol": observation.protocol,
                    "service": observation.service,
                    "instance": observation.instance,
                    "hostname": observation.hostname,
                    "port": observation.port,
                    "attributes": observation.attributes
                }),
            ));
            if matches!(observation.protocol.as_str(), "mdns" | "matter") {
                if let Some(model) = observation
                    .attributes
                    .get("md")
                    .or_else(|| observation.attributes.get("model"))
                    .filter(|value| !value.is_empty())
                {
                    items.push(DeviceEvidenceUpdate {
                        source: observation.protocol.clone(),
                        field: "model".to_owned(),
                        value: model.clone(),
                        confidence: 0.75,
                        observed_at: observation.observed_at_unix_ms,
                        metadata_json: "{}".to_owned(),
                    });
                }
            }
        }
        evidence
    }
    fn identify(
        &self,
        observation: &DeviceObservation,
        historical: &[DeviceEvidenceRecord],
        supplemental: &[DeviceEvidenceUpdate],
    ) -> DeviceIdentityUpdate {
        let observed_at = observation.last_seen_unix_ms;
        let mut resolver = IdentityResolver {
            now: observed_at,
            ..Default::default()
        };

        for evidence in historical {
            if is_locally_administered(&observation.mac) && evidence.source == "mac_oui" {
                continue;
            }
            resolver.add_historical(evidence);
        }

        if is_locally_administered(&observation.mac) {
            resolver.add(DeviceEvidence::new(
                "mac_random",
                "private_mac",
                "true",
                1.0,
                observed_at,
            ));
        } else if let Some(vendor) = self.mac_dataset.lookup(&observation.mac) {
            resolver.add(DeviceEvidence::new(
                "mac_oui",
                "vendor",
                vendor,
                0.9,
                observed_at,
            ));
        }

        if !observation.hostname.is_empty() {
            resolver.add(DeviceEvidence::new(
                "hostname",
                "observation",
                "hostname",
                1.0,
                observed_at,
            ));
        }
        if observation.dhcp.is_some() {
            resolver.add(DeviceEvidence::new(
                "dhcp",
                "observation",
                "dhcp",
                1.0,
                observed_at,
            ));
        }
        for evidence in supplemental {
            resolver.add(DeviceEvidence::from_update(evidence));
        }

        resolver.resolve(observation.mac.clone())
    }
}

fn device_text_input(field: &str, value: &str) -> DeviceEvidenceInput {
    DeviceEvidenceInput {
        field: field.to_owned(),
        text: Some(value.to_owned()),
        sequence: None,
    }
}

fn device_sequence_input(field: &str, value: Vec<u32>) -> DeviceEvidenceInput {
    DeviceEvidenceInput {
        field: field.to_owned(),
        text: None,
        sequence: Some(value),
    }
}

fn observation_device_inputs(observation: &DeviceObservation) -> Vec<DeviceEvidenceInput> {
    let mut inputs = Vec::new();
    if !observation.hostname.is_empty() {
        inputs.push(device_text_input("hostname", &observation.hostname));
    }
    if let Some(dhcp) = &observation.dhcp {
        inputs.push(device_text_input("vendor_class", &dhcp.vendor_class));
        let identifier = dhcp
            .client_identifier
            .iter()
            .fold(String::new(), |mut output, byte| {
                use std::fmt::Write as _;
                let _ = write!(output, "{byte:02x}");
                output
            });
        inputs.push(device_text_input("client_identifier", &identifier));
        inputs.push(device_sequence_input(
            "prl",
            dhcp.parameter_request_list.clone(),
        ));
    }
    inputs
}

#[allow(clippy::too_many_lines)]
fn discovery_device_inputs(
    observation: &netqmon_protocol::v1::DeviceDiscoveryObservation,
) -> Vec<DeviceEvidenceInput> {
    let mut inputs = Vec::new();
    let search = observation.protocol == "ssdp"
        && observation
            .attributes
            .get("message_kind")
            .is_some_and(|value| value == "M-SEARCH");
    if !search && !observation.service.is_empty() {
        inputs.push(device_text_input("service", &observation.service));
    }
    match observation.protocol.as_str() {
        "ssdp" => {
            if !search {
                inputs.push(device_text_input("ssdp_type", &observation.service));
            }
            for (attribute, field) in [
                ("server", "ssdp_server"),
                ("user-agent", "ssdp_user_agent"),
                ("st", "ssdp_type"),
                ("nt", "ssdp_type"),
                ("usn", "ssdp_usn"),
            ] {
                if search && attribute != "user-agent" {
                    continue;
                }
                if let Some(value) = observation.attributes.get(attribute) {
                    inputs.push(device_text_input(field, value));
                }
            }
        }
        "dhcp6" => {
            for attribute in ["duid", "vendor_specific", "client_fqdn"] {
                if let Some(value) = observation.attributes.get(attribute) {
                    inputs.push(device_text_input(&format!("dhcp6_{attribute}"), value));
                }
            }
            if let Some(value) = observation.attributes.get("vendor_class") {
                inputs.push(device_text_input("dhcp6_vendor_class", value));
            }
            if let Some(value) = observation.attributes.get("oro") {
                inputs.push(device_sequence_input(
                    "oro",
                    value
                        .split(',')
                        .filter_map(|part| part.parse().ok())
                        .collect(),
                ));
            }
        }
        "http" => {
            if let Some(user_agent) = observation
                .attributes
                .get("user-agent")
                .filter(|value| !value.is_empty())
            {
                inputs.push(device_text_input("http_user_agent", user_agent));
            }
        }
        "matter" => {
            if let Some(device_type) = observation
                .attributes
                .get("dt")
                .and_then(|value| parse_matter_id(value))
            {
                inputs.push(device_text_input(
                    "matter_device_type",
                    &device_type.to_string(),
                ));
            }
            let pair = observation
                .attributes
                .get("vp")
                .and_then(|value| value.split_once('+'))
                .and_then(|(vid, pid)| Some((parse_matter_id(vid)?, parse_matter_id(pid)?)))
                .or_else(|| {
                    Some((
                        parse_matter_id(observation.attributes.get("vid")?)?,
                        parse_matter_id(observation.attributes.get("pid")?)?,
                    ))
                });
            if let Some((vid, pid)) = pair {
                inputs.push(device_sequence_input(
                    "matter_vendor_product",
                    vec![u32::from(vid), u32::from(pid)],
                ));
            }
        }
        _ => {}
    }
    if matches!(observation.protocol.as_str(), "mdns" | "matter") {
        inputs.push(device_text_input("mdns_instance", &observation.instance));
        inputs.push(device_text_input("mdns_hostname", &observation.hostname));
        for (key, value) in &observation.attributes {
            inputs.push(device_text_input("mdns_txt", &format!("{key}={value}")));
            if matches!(key.as_str(), "md" | "model") {
                inputs.push(device_text_input("mdns_model", value));
            }
        }
    }
    inputs
}

fn device_results_to_updates(
    results: Vec<DeviceEvidenceResult>,
    observed_at: u64,
    context: &serde_json::Value,
) -> Vec<DeviceEvidenceUpdate> {
    results
        .into_iter()
        .map(|result| {
            let metadata_json = serde_json::json!({
                "rule_metadata": {
                    "rule": result.rule_id,
                    "priority": result.priority,
                    "private": true,
                    "dataset": result.metadata,
                },
                "context": context,
            })
            .to_string();
            DeviceEvidenceUpdate {
                source: result.source,
                field: result.field,
                value: result.value,
                confidence: result.confidence,
                observed_at,
                metadata_json,
            }
        })
        .collect()
}

pub(crate) fn refresh_mac_dataset(
    path: &Path,
    source_url: &str,
) -> Result<MacPrefixDataset, String> {
    let mut raw = String::new();
    let sources = source_url
        .split(',')
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Err("MAC dataset source URL list is empty".to_owned());
    }
    for source in &sources {
        raw.push_str(&fetch_http(source)?);
        raw.push('\n');
    }
    let dataset = MacPrefixDataset::from_ieee_oui(&raw, source_url)?;
    if let Err(error) = dataset.save_atomic(path) {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "MAC prefix dataset refreshed but could not be persisted"
        );
    }
    Ok(dataset)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct MacPrefixDataset {
    pub(crate) metadata: MacDatasetMetadata,
    entries: Vec<MacPrefixEntry>,
    #[serde(skip)]
    by_length: HashMap<u8, Vec<MacPrefixEntry>>,
}

impl MacPrefixDataset {
    fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let mut dataset: Self = serde_json::from_str(&data).map_err(|error| error.to_string())?;
        dataset.rebuild_index();
        Ok(dataset)
    }

    fn from_ieee_oui(raw: &str, source_url: &str) -> Result<Self, String> {
        let entries = raw
            .lines()
            .filter_map(parse_ieee_oui_line)
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Err("IEEE OUI source did not contain any parseable entries".to_owned());
        }
        let checksum = hex_digest(raw.as_bytes());
        let mut dataset = Self {
            metadata: MacDatasetMetadata {
                source: DEFAULT_SOURCE.to_owned(),
                source_url: source_url.to_owned(),
                source_version: checksum.chars().take(12).collect(),
                updated_at: iso_time(SystemTime::now()),
                license: DEFAULT_LICENSE.to_owned(),
                checksum,
                entry_count: entries.len(),
            },
            entries,
            by_length: HashMap::new(),
        };
        dataset.rebuild_index();
        Ok(dataset)
    }

    fn save_atomic(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let tmp = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        {
            let mut file = fs::File::create(&tmp).map_err(|error| error.to_string())?;
            file.write_all(&data).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
        }
        fs::rename(&tmp, path).map_err(|error| error.to_string())
    }

    fn lookup(&self, mac: &[u8]) -> Option<&str> {
        if mac.len() != 6 {
            return None;
        }
        for bits in (1..=48).rev() {
            if let Some(entries) = self.by_length.get(&bits) {
                if let Some(entry) = entries
                    .iter()
                    .find(|entry| prefix_matches(mac, &entry.prefix, bits))
                {
                    return Some(entry.vendor.as_str());
                }
            }
        }
        None
    }

    fn rebuild_index(&mut self) {
        self.by_length.clear();
        for entry in &mut self.entries {
            if entry.prefix_bits == 0 {
                entry.prefix_bits = u8::try_from(entry.prefix.len().saturating_mul(8)).unwrap_or(0);
            }
            self.by_length
                .entry(entry.prefix_bits)
                .or_default()
                .push(entry.clone());
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct MacDatasetMetadata {
    source: String,
    source_url: String,
    source_version: String,
    updated_at: String,
    license: String,
    checksum: String,
    pub(crate) entry_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MacPrefixEntry {
    prefix: Vec<u8>,
    #[serde(default)]
    prefix_bits: u8,
    vendor: String,
}

#[derive(Default)]
struct IdentityResolver {
    now: u64,
    evidence: Vec<DeviceEvidence>,
}

impl IdentityResolver {
    fn add(&mut self, evidence: DeviceEvidence) {
        self.evidence.push(evidence);
    }

    fn add_historical(&mut self, evidence: &DeviceEvidenceRecord) {
        self.evidence.push(DeviceEvidence {
            source: evidence.source.clone(),
            field: evidence.field.clone(),
            value: evidence.value.clone(),
            confidence: evidence.confidence,
            observed_at: evidence.last_seen,
            hit_count: evidence.hit_count,
            metadata_json: evidence.metadata_json.clone(),
            pending: false,
        });
    }

    fn resolve(self, mac: Vec<u8>) -> DeviceIdentityUpdate {
        let (vendor, vendor_confidence) = self.best("vendor");
        let (device_type, device_type_confidence) = self.best("device_type");
        let (os_family, os_confidence) = self.best("os_family");
        let (model, model_confidence) = self.best("model");
        let private_mac = self
            .evidence
            .iter()
            .any(|item| item.field == "private_mac" && item.value == "true");
        let confidence = overall_confidence([
            vendor_confidence,
            device_type_confidence,
            os_confidence,
            model_confidence,
        ]);
        let evidence_json =
            serde_json::to_string(&self.evidence).unwrap_or_else(|_| "[]".to_owned());
        let evidence = self
            .evidence
            .iter()
            .filter(|item| item.pending)
            .map(|item| DeviceEvidenceUpdate {
                source: item.source.clone(),
                field: item.field.clone(),
                value: item.value.clone(),
                confidence: item.confidence,
                observed_at: item.observed_at,
                metadata_json: item.metadata_json.clone(),
            })
            .collect();
        DeviceIdentityUpdate {
            mac,
            vendor,
            device_type,
            os_family,
            model,
            confidence: Some(confidence),
            vendor_confidence,
            device_type_confidence,
            os_confidence,
            model_confidence,
            private_mac,
            evidence_json,
            evidence,
        }
    }

    fn best(&self, field: &str) -> (Option<String>, f64) {
        // One vote per independent source. Repeated packets never manufacture confidence.
        let now = self.now.max(
            self.evidence
                .iter()
                .map(|e| e.observed_at)
                .max()
                .unwrap_or(0),
        );
        let mut candidates = HashMap::<String, HashMap<String, (f64, i64)>>::new();
        for evidence in self.evidence.iter().filter(|item| item.field == field) {
            let metadata: serde_json::Value =
                serde_json::from_str(&evidence.metadata_json).unwrap_or_default();
            let priority = metadata
                .get("priority")
                .or_else(|| {
                    metadata
                        .get("rule_metadata")
                        .and_then(|m| m.get("priority"))
                })
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let priority_weight =
                1.0 + 0.05 * (f64::from(i32::try_from(priority).unwrap_or(0)) / 100.0).tanh();
            let age_days =
                std::time::Duration::from_millis(now.saturating_sub(evidence.observed_at))
                    .as_secs_f64()
                    / 86400.0;
            let decay = if matches!(evidence.source.as_str(), "mac_oui" | "matter_dataset") {
                1.0
            } else {
                // Weak observations have a one-day half-life; stronger ones a week.
                2.0_f64.powf(-age_days / if evidence.confidence < 0.7 { 1.0 } else { 7.0 })
            };
            let score = (evidence.confidence * priority_weight * decay).clamp(0.0, 0.99);
            let by_source = candidates.entry(evidence.value.clone()).or_default();
            let candidate = by_source
                .entry(evidence.source.clone())
                .or_insert((0.0, i64::MIN));
            if score
                .total_cmp(&candidate.0)
                .then(priority.cmp(&candidate.1))
                .is_gt()
            {
                *candidate = (score, priority);
            }
        }
        candidates
            .into_iter()
            .map(|(value, sources)| {
                let score = 1.0
                    - sources
                        .values()
                        .fold(1.0, |miss, (confidence, _)| miss * (1.0 - confidence));
                let priority = sources
                    .values()
                    .map(|(_, priority)| *priority)
                    .max()
                    .unwrap_or(0);
                (value, score, priority)
            })
            .filter(|(_, score, _)| *score >= 0.25)
            .max_by(|left, right| {
                left.1
                    .total_cmp(&right.1)
                    .then(left.2.cmp(&right.2))
                    .then_with(|| right.0.cmp(&left.0))
            })
            .map_or((None, 0.0), |(value, score, _)| (Some(value), score))
    }
}

#[derive(Clone, Debug, Serialize)]
struct DeviceEvidence {
    source: String,
    field: String,
    value: String,
    confidence: f64,
    observed_at: u64,
    hit_count: u64,
    #[serde(skip_serializing_if = "metadata_is_empty")]
    metadata_json: String,
    #[serde(skip)]
    pending: bool,
}

impl DeviceEvidence {
    fn new(
        source: impl Into<String>,
        field: impl Into<String>,
        value: impl Into<String>,
        confidence: f64,
        observed_at: u64,
    ) -> Self {
        Self {
            source: source.into(),
            field: field.into(),
            value: value.into(),
            confidence,
            observed_at,
            hit_count: 1,
            metadata_json: "{}".to_owned(),
            pending: true,
        }
    }

    fn from_update(update: &DeviceEvidenceUpdate) -> Self {
        Self {
            source: update.source.clone(),
            field: update.field.clone(),
            value: update.value.clone(),
            confidence: update.confidence,
            observed_at: update.observed_at,
            hit_count: 1,
            metadata_json: update.metadata_json.clone(),
            pending: true,
        }
    }
}

fn metadata_is_empty(value: &str) -> bool {
    value == "{}"
}

fn overall_confidence(confidences: [f64; 4]) -> String {
    let strongest = confidences.into_iter().fold(0.0_f64, f64::max);
    if strongest == 0.0 {
        return "unknown".to_owned();
    }
    if strongest >= 0.85 {
        "high"
    } else if strongest >= 0.55 {
        "medium"
    } else {
        "low"
    }
    .to_owned()
}

fn parse_ieee_oui_line(line: &str) -> Option<MacPrefixEntry> {
    let (prefix, vendor) = line
        .split_once("(hex)")
        .or_else(|| line.split_once("(base 16)"))?;
    let (prefix, prefix_bits) = parse_prefix(prefix.trim())?;
    let vendor = vendor.trim();
    if vendor.is_empty() {
        return None;
    }
    Some(MacPrefixEntry {
        prefix,
        prefix_bits,
        vendor: vendor.to_owned(),
    })
}

fn parse_prefix(value: &str) -> Option<(Vec<u8>, u8)> {
    let mut hex = value.replace(['-', ':', '.'], "");
    if hex.is_empty()
        || hex.len() > 12
        || !hex.chars().all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    let prefix_bits = u8::try_from(hex.len().saturating_mul(4)).ok()?;
    if hex.len() % 2 != 0 {
        hex.push('0');
    }
    let prefix = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((prefix, prefix_bits))
}

fn prefix_matches(mac: &[u8], prefix: &[u8], bits: u8) -> bool {
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    if mac.len() < full_bytes + usize::from(remaining_bits != 0) || prefix.len() <= full_bytes {
        return remaining_bits == 0 && mac.get(..full_bytes) == prefix.get(..full_bytes);
    }
    if mac[..full_bytes] != prefix[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    mac[full_bytes] & mask == prefix[full_bytes] & mask
}

fn is_locally_administered(mac: &[u8]) -> bool {
    mac.len() == 6 && mac[0] & 0x02 != 0
}

fn parse_matter_id(value: &str) -> Option<u16> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u16::from_str_radix(hex, 16).ok(),
        )
}

fn fetch_http(url: &str) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|error| error.to_string())?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "unsupported MAC dataset URL scheme: {scheme}; expected http or https"
            ));
        }
    }

    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("netqmon-collector/0.1")
        .no_proxy()
        .build()
        .map_err(|error| error.to_string())?;
    client
        .get(parsed)
        .send()
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?
        .text()
        .map_err(|error| error.to_string())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn iso_time(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_normalizes_device_observations_without_loading_rules() {
        let observation = DeviceObservation {
            hostname: "Example.local".to_owned(),
            dhcp: Some(netqmon_protocol::v1::DhcpMetadata {
                vendor_class: "vendor".to_owned(),
                client_identifier: vec![0xab, 0xcd],
                parameter_request_list: vec![1, 3, 6],
            }),
            ..Default::default()
        };
        let inputs = observation_device_inputs(&observation);
        assert!(inputs.iter().any(|input| {
            input.field == "client_identifier" && input.text.as_deref() == Some("abcd")
        }));
        assert!(inputs.iter().any(|input| {
            input.field == "prl" && input.sequence.as_deref() == Some(&[1, 3, 6][..])
        }));
    }

    #[test]
    fn collector_forwards_matter_ids_as_basic_classifier_evidence() {
        let observation = netqmon_protocol::v1::DeviceDiscoveryObservation {
            protocol: "matter".to_owned(),
            attributes: HashMap::from([
                ("vp".to_owned(), "65521+32768".to_owned()),
                ("dt".to_owned(), "769".to_owned()),
            ]),
            ..Default::default()
        };
        let inputs = discovery_device_inputs(&observation);
        assert!(inputs.iter().any(|input| {
            input.field == "matter_vendor_product"
                && input.sequence.as_deref() == Some(&[65_521, 32_768][..])
        }));
        assert!(inputs.iter().any(|input| {
            input.field == "matter_device_type" && input.text.as_deref() == Some("769")
        }));
    }

    #[test]
    fn collector_maps_http_user_agent_to_device_evidence() {
        let observation = netqmon_protocol::v1::DeviceDiscoveryObservation {
            protocol: "http".to_owned(),
            attributes: HashMap::from([(
                "user-agent".to_owned(),
                "Mozilla/5.0 (iPad2,1; CPU OS 7_1 like Mac OS X)".to_owned(),
            )]),
            ..Default::default()
        };
        let inputs = discovery_device_inputs(&observation);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].field, "http_user_agent");
        assert_eq!(
            inputs[0].text.as_deref(),
            Some("Mozilla/5.0 (iPad2,1; CPU OS 7_1 like Mac OS X)")
        );
    }

    #[test]
    fn collector_skips_http_observations_without_user_agent() {
        let observation = netqmon_protocol::v1::DeviceDiscoveryObservation {
            protocol: "http".to_owned(),
            ..Default::default()
        };
        assert!(discovery_device_inputs(&observation).is_empty());
    }

    #[test]
    fn independent_sources_outweigh_twenty_repeats_and_priority_breaks_ties() {
        let mut resolver = IdentityResolver::default();
        for _ in 0..20 {
            resolver.add(DeviceEvidence::new(
                "hostname",
                "device_type",
                "tv",
                0.6,
                100,
            ));
        }
        for source in ["mdns", "ssdp"] {
            resolver.add(DeviceEvidence::new(
                source,
                "device_type",
                "printer",
                0.6,
                100,
            ));
        }
        assert_eq!(resolver.best("device_type").0.as_deref(), Some("printer"));
        let mut resolver = IdentityResolver::default();
        for (value, priority) in [("aaa", 100), ("zzz", 1000)] {
            let mut evidence = DeviceEvidence::new("mdns", "model", value, 0.6, 100);
            evidence.metadata_json =
                serde_json::json!({"rule_metadata": {"priority": priority}}).to_string();
            resolver.add(evidence);
        }
        assert_eq!(resolver.best("model").0.as_deref(), Some("zzz"));
    }

    #[test]
    fn old_weak_evidence_decays_but_stable_vendor_does_not() {
        let now = 30 * 86400 * 1000;
        let mut resolver = IdentityResolver {
            now,
            ..Default::default()
        };
        resolver.add(DeviceEvidence::new("hostname", "device_type", "tv", 0.6, 0));
        assert!(resolver.best("device_type").0.is_none());
        for source in ["mdns", "ssdp"] {
            resolver.add(DeviceEvidence::new(
                source,
                "device_type",
                "printer",
                0.5,
                now,
            ));
        }
        resolver.add(DeviceEvidence::new("mac_oui", "vendor", "Stable", 0.9, 0));
        assert_eq!(resolver.best("device_type").0.as_deref(), Some("printer"));
        assert!(resolver.best("vendor").1 >= 0.89);
    }

    #[test]
    fn parses_ieee_entries_and_uses_longest_prefix_match() {
        let raw = "A0-B2-C3   (hex)\t\tMA-L Vendor\nA0B2C3D (base 16)\t\tMA-M Vendor\nA0B2C3D4E (base 16)\t\tMA-S Vendor\n";
        let dataset = MacPrefixDataset::from_ieee_oui(raw, "http://example.test/oui.txt").unwrap();

        assert_eq!(
            dataset.lookup(&[0xa0, 0xb2, 0xc3, 0xd4, 0xe5, 0xff]),
            Some("MA-S Vendor")
        );
        assert_eq!(
            dataset.lookup(&[0xa0, 0xb2, 0xc3, 0xdf, 0x00, 0x01]),
            Some("MA-M Vendor")
        );
        assert_eq!(
            dataset.lookup(&[0xa0, 0xb2, 0xc3, 0x01, 0x00, 0x01]),
            Some("MA-L Vendor")
        );
    }

    #[test]
    fn locally_administered_mac_skips_vendor_lookup() {
        let dataset = MacPrefixDataset::from_ieee_oui(
            "02-00-00 (hex)\t\tIncorrect Vendor\n",
            "http://example.test/oui.txt",
        )
        .unwrap();
        let identifier = DeviceIdentifier {
            mac_dataset: dataset,
        };
        let observation = DeviceObservation {
            mac: vec![0x02, 0, 0, 0, 0, 1],
            ip: vec![192, 0, 2, 1],
            hostname: String::new(),
            last_seen_unix_ms: 10,
            dhcp: None,
        };

        let identity = identifier.identify(&observation, &[], &[]);
        assert!(identity.vendor.is_none());
        assert!(identity.private_mac);
        assert!(
            identity
                .evidence
                .iter()
                .any(|item| item.source == "mac_random")
        );
    }

    #[test]
    fn identify_batch_supplies_mac_vendor_to_classifier() {
        let dataset = MacPrefixDataset::from_ieee_oui(
            "24-0A-C4 (hex)\t\tEspressif Inc.\n",
            "http://example.test/oui.txt",
        )
        .unwrap();
        let identifier = DeviceIdentifier {
            mac_dataset: dataset,
        };
        let observation = DeviceObservation {
            mac: vec![0x24, 0x0a, 0xc4, 0x01, 0x02, 0x03],
            ip: vec![192, 168, 1, 100],
            hostname: String::new(),
            last_seen_unix_ms: 100,
            dhcp: None,
        };
        let classifier = ClassifierHandle::test_default();
        let mut updates = identifier.identify_batch(
            &classifier,
            &[observation],
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(updates.len(), 1);
        let update = updates.remove(0);
        assert_eq!(update.vendor.as_deref(), Some("Espressif Inc."));
    }

    #[test]
    fn historical_independent_sources_raise_field_confidence() {
        let observation = DeviceObservation {
            mac: vec![0, 1, 2, 3, 4, 5],
            ip: vec![192, 0, 2, 5],
            hostname: String::new(),
            last_seen_unix_ms: 20,
            dhcp: None,
        };
        let historical = vec![
            DeviceEvidenceRecord {
                gateway_id: "gateway-1".to_owned(),
                mac: observation.mac.clone(),
                source: "mdns".to_owned(),
                field: "device_type".to_owned(),
                value: "printer".to_owned(),
                confidence: 0.7,
                first_seen: 10,
                last_seen: 10,
                hit_count: 2,
                metadata_json: "{}".to_owned(),
            },
            DeviceEvidenceRecord {
                source: "ssdp".to_owned(),
                ..DeviceEvidenceRecord {
                    gateway_id: "gateway-1".to_owned(),
                    mac: observation.mac.clone(),
                    source: "mdns".to_owned(),
                    field: "device_type".to_owned(),
                    value: "printer".to_owned(),
                    confidence: 0.7,
                    first_seen: 10,
                    last_seen: 10,
                    hit_count: 2,
                    metadata_json: "{}".to_owned(),
                }
            },
        ];

        let identity = DeviceIdentifier::default().identify(&observation, &historical, &[]);
        assert_eq!(identity.device_type.as_deref(), Some("printer"));
        assert!(identity.device_type_confidence > 0.9);
        assert!(identity.evidence.is_empty());
    }

    #[tokio::test]
    async fn fetch_http_follows_redirects() {
        let oui = "AA-BB-CC (hex)\t\tRedirect Vendor\n";
        let redirect_url = match spawn_redirecting_oui_server(oui) {
            Ok(url) => url,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("test server binding failed: {error}"),
        };

        let fetched = match tokio::task::spawn_blocking(move || fetch_http(&redirect_url))
            .await
            .unwrap()
        {
            Ok(fetched) => fetched,
            Err(error)
                if error.contains("error sending request")
                    || error.contains("PermissionDenied")
                    || error.contains("Operation not permitted")
                    || error.contains("permission denied") =>
            {
                return;
            }
            Err(error) => panic!("fetch failed: {error}"),
        };
        assert_eq!(fetched, oui);
    }

    #[tokio::test]
    async fn refresh_mac_dataset_returns_dataset_when_cache_cannot_be_persisted() {
        let oui = "AA-BB-CC (hex)\t\tVolatile Vendor\n";
        let source_url = match spawn_redirecting_oui_server(oui) {
            Ok(url) => url,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("test server binding failed: {error}"),
        };
        let temp = tempfile::tempdir().unwrap();
        let blocker = temp.path().join("not-a-directory");
        std::fs::write(&blocker, "").unwrap();
        let cache_path = blocker.join("mac-prefixes.json");

        let dataset = match tokio::task::spawn_blocking(move || {
            refresh_mac_dataset(&cache_path, &source_url)
        })
        .await
        .unwrap()
        {
            Ok(dataset) => dataset,
            Err(error)
                if error.contains("error sending request")
                    || error.contains("PermissionDenied")
                    || error.contains("Operation not permitted")
                    || error.contains("permission denied") =>
            {
                return;
            }
            Err(error) => panic!("refresh failed: {error}"),
        };

        assert_eq!(
            dataset.lookup(&[0xaa, 0xbb, 0xcc, 0, 0, 1]),
            Some("Volatile Vendor")
        );
    }

    fn spawn_redirecting_oui_server(oui: &str) -> Result<String, std::io::Error> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let oui = oui.to_owned();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf) else {
                    break;
                };
                if n == 0 {
                    continue;
                }
                let request_str = String::from_utf8_lossy(&buf[..n]);
                let first_line = request_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                if path == "/redirect" {
                    let response = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{address}/oui.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                } else {
                    let body = oui.as_bytes();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                }
            }
        });
        Ok(format!("http://{address}/redirect"))
    }
}
