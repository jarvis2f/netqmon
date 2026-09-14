//! Bounded, authenticated telemetry ingestion for netqmon.

mod auth;
mod classifier;
mod device_identification;
mod dpi;
mod icons;
pub mod insights;
mod license;
mod query_api;
mod realtime;
mod recognition_diagnostics;

use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, FromRequestParts, State};
use axum::http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use classifier::{ClassificationInput, ClassifierHandle, DpiEvidence};
use futures_util::stream;
use getrandom::fill;
#[cfg(test)]
use netqmon_geo::DisabledGeoProvider;
use netqmon_geo::{DEFAULT_GEO_DIRECTORY, GeoProvider, LocalDbProvider};
use netqmon_protocol::v1::probe_request::Target as ProbeTarget;
use netqmon_protocol::v1::probe_result::Outcome as ProbeOutcome;
use netqmon_protocol::v1::{
    EnrollRequest, EnrollResponse, FaviconProbe, ProbeRequest, TelemetryBatch, TelemetryResponse,
};
use netqmon_protocol::{
    ContentEncoding, DecodeError, PROTOCOL_VERSION, decode_telemetry_batch, validate_batch_metadata,
};
use netqmon_storage::{
    ClickHouseConfig, ClickHouseStorage, DEFAULT_DATABASE_PATH, FlowAttribution,
    PersistDisposition, SqliteStorage, Storage, StorageError,
};
use prost::Message;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::icons::{IconCacheConfig, IconService};
use crate::realtime::{RealtimeEngine, RealtimeEvent, RealtimeSnapshot};
use device_identification::{DeviceIdentifier, refresh_mac_dataset};

pub(crate) mod geo_updater;

const DEFAULT_PUBLIC_ADDR: &str = "0.0.0.0:8090";
const DEFAULT_INTERNAL_ADDR: &str = "127.0.0.1:8091";
const DEFAULT_CLASSIFIER_SOCKET: &str = "/run/netqmon/classifierd.sock";
const DEFAULT_MAC_DATASET_FILENAME: &str = "mac-prefixes.json";
const DEFAULT_MAC_DATASET_SOURCE_URL: &str = "https://standards-oui.ieee.org/oui/oui.txt,https://standards-oui.ieee.org/oui28/mam.txt,https://standards-oui.ieee.org/oui36/oui36.txt";
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_FLOWS_PER_BATCH: usize = 10_000;
const MAX_DISCOVERY_OBSERVATIONS_PER_BATCH: usize = 10_000;
const MAX_PROBE_RESULTS_PER_BATCH: usize = 64;
const MAX_HASHES_PER_FAVICON_RESULT: usize = 8;
const ROLLUP_INTERVAL: Duration = Duration::from_secs(60);
const RETENTION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAC_DATASET_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
#[cfg(not(test))]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const REQUEST_TIMEOUT: Duration = Duration::from_millis(25);
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Starts both Collector listeners using `NETQMON_COLLECTOR_*` environment
/// variables.
///
/// # Errors
///
/// Returns an error for missing or invalid configuration, listener binding
/// failures, or serving failures.
pub async fn run_from_env() -> Result<(), Box<dyn Error>> {
    let config = CollectorConfig::from_env()?;
    let dpi_enabled = dpi_enabled_from_env()?;
    if dpi_enabled && !dpi::native_available() {
        return Err(ConfigError("DPI enabled but nDPI 4.14 is unavailable; install libndpi and rebuild or set NETQMON_DPI_ENABLED=false".into()).into());
    }
    let classifier =
        ClassifierHandle::connect(config.classifier_socket.clone()).map_err(ConfigError)?;
    tracing::info!(
        socket = %config.classifier_socket.display(),
        "classifier IPC configured; Collector will accept traffic while it reconnects"
    );
    let geo_load = LocalDbProvider::load(&config.geo_directory);
    for warning in &geo_load.warnings {
        tracing::warn!(warning, "optional Geo database skipped");
    }
    tracing::info!(
        enabled = geo_load.provider.is_enabled(),
        directory = %config.geo_directory.display(),
        "Geo enrichment configured"
    );

    let storage = if config.storage_backend == "clickhouse" {
        tracing::info!(
            url = %config.clickhouse_config.url,
            database = %config.clickhouse_config.database,
            "connecting to ClickHouse backend"
        );
        let ch = ClickHouseStorage::open(config.clickhouse_config.clone())
            .map_err(|err| ConfigError(format!("failed to connect to ClickHouse: {err}")))?;
        Storage::clickhouse(ch)
    } else {
        if let Some(parent) = config.database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sqlite = SqliteStorage::open(&config.database_path)
            .map_err(|err| ConfigError(format!("failed to open SQLite: {err}")))?;
        Storage::sqlite(sqlite)
    };

    let state = CollectorState::with_geo_provider(
        &config.enrollment_token,
        storage,
        classifier.clone(),
        Arc::new(geo_load.provider),
        config.geo_directory.clone(),
        DeviceIdentifier::load(&config.mac_dataset_path),
        config.icon_cache_config,
    )
    .map_err(|err| ConfigError(format!("failed to initialize collector state: {err}")))?;
    state.license.ensure_identity().map_err(ConfigError)?;

    let (public_listener, internal_listener) = bind_listeners(&config).await?;

    spawn_maintenance(state.clone(), ROLLUP_INTERVAL, false);
    spawn_maintenance(state.clone(), RETENTION_INTERVAL, true);
    spawn_mac_dataset_updates(
        state.clone(),
        config.mac_dataset_path.clone(),
        config.mac_dataset_source_url.clone(),
        MAC_DATASET_UPDATE_INTERVAL,
    );
    license::spawn(Arc::clone(&state.license));
    spawn_classifier_probe(classifier, Arc::clone(&state.license));

    tracing::info!(address = %config.public_addr, "public ingestion listener started");
    tracing::info!(address = %config.internal_addr, "internal listener started");

    let public = axum::serve(public_listener, public_router(state.clone()));
    let internal = axum::serve(internal_listener, internal_router(state));
    tokio::try_join!(public, internal)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct CollectorConfig {
    public_addr: SocketAddr,
    internal_addr: SocketAddr,
    enrollment_token: String,
    database_path: PathBuf,
    storage_backend: String,
    clickhouse_config: ClickHouseConfig,
    classifier_socket: PathBuf,
    geo_directory: PathBuf,
    mac_dataset_path: PathBuf,
    mac_dataset_source_url: String,
    icon_cache_config: IconCacheConfig,
}

impl CollectorConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let public_addr = parse_addr("NETQMON_COLLECTOR_PUBLIC_ADDR", DEFAULT_PUBLIC_ADDR)?;
        let internal_addr = parse_addr("NETQMON_COLLECTOR_INTERNAL_ADDR", DEFAULT_INTERNAL_ADDR)?;
        if !internal_addr.ip().is_loopback() {
            return Err(ConfigError(
                "NETQMON_COLLECTOR_INTERNAL_ADDR must use a loopback address".to_owned(),
            ));
        }
        let enrollment_token = env::var("NETQMON_COLLECTOR_ENROLLMENT_TOKEN").map_err(|_| {
            ConfigError("NETQMON_COLLECTOR_ENROLLMENT_TOKEN is required".to_owned())
        })?;
        if enrollment_token.is_empty() {
            return Err(ConfigError(
                "NETQMON_COLLECTOR_ENROLLMENT_TOKEN must not be empty".to_owned(),
            ));
        }
        let database_path = env::var_os("NETQMON_COLLECTOR_DATABASE_PATH")
            .map_or_else(|| PathBuf::from(DEFAULT_DATABASE_PATH), PathBuf::from);
        let storage_backend = env::var("NETQMON_STORAGE_BACKEND")
            .unwrap_or_else(|_| "sqlite".to_owned())
            .to_ascii_lowercase();
        let clickhouse_url = env::var("NETQMON_CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8123".to_owned());
        let clickhouse_database =
            env::var("NETQMON_CLICKHOUSE_DATABASE").unwrap_or_else(|_| "default".to_owned());
        let clickhouse_user = env::var("NETQMON_CLICKHOUSE_USER").ok();
        let clickhouse_password = env::var("NETQMON_CLICKHOUSE_PASSWORD").ok();
        let clickhouse_config = ClickHouseConfig {
            url: clickhouse_url,
            database: clickhouse_database,
            user: clickhouse_user,
            password: clickhouse_password,
            timeout_ms: 5000,
        };
        let classifier_socket = env::var_os("NETQMON_CLASSIFIER_SOCKET")
            .map_or_else(|| PathBuf::from(DEFAULT_CLASSIFIER_SOCKET), PathBuf::from);
        let geo_directory = env::var_os("NETQMON_COLLECTOR_GEO_DIR")
            .map_or_else(|| default_geo_directory(&database_path), PathBuf::from);
        let mac_dataset_path = env::var_os("NETQMON_COLLECTOR_MAC_DATASET_PATH")
            .map_or_else(|| default_mac_dataset_path(&database_path), PathBuf::from);
        let mac_dataset_source_url = env::var("NETQMON_COLLECTOR_MAC_DATASET_SOURCE_URL")
            .unwrap_or_else(|_| DEFAULT_MAC_DATASET_SOURCE_URL.to_owned());
        let icon_cache_config = IconCacheConfig::from_env();
        Ok(Self {
            public_addr,
            internal_addr,
            enrollment_token,
            database_path,
            storage_backend,
            clickhouse_config,
            classifier_socket,
            geo_directory,
            mac_dataset_path,
            mac_dataset_source_url,
            icon_cache_config,
        })
    }
}

pub(crate) fn default_geo_directory(database_path: &Path) -> PathBuf {
    if Path::new(DEFAULT_GEO_DIRECTORY).is_dir() || Path::new("/data").is_dir() {
        PathBuf::from(DEFAULT_GEO_DIRECTORY)
    } else if let Some(parent) = database_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        parent.join("geo")
    } else if Path::new("target").is_dir() {
        PathBuf::from("target/geo")
    } else {
        PathBuf::from("geo")
    }
}

fn default_mac_dataset_path(database_path: &Path) -> PathBuf {
    database_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(
            || PathBuf::from(DEFAULT_MAC_DATASET_FILENAME),
            |parent| parent.join(DEFAULT_MAC_DATASET_FILENAME),
        )
}

fn parse_addr(name: &str, default: &str) -> Result<SocketAddr, ConfigError> {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|error| ConfigError(format!("invalid {name}: {error}")))
}

#[derive(Debug)]
struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ConfigError {}

async fn bind_listeners(
    config: &CollectorConfig,
) -> Result<(TcpListener, TcpListener), std::io::Error> {
    let public = TcpListener::bind(config.public_addr).await?;
    let internal = TcpListener::bind(config.internal_addr).await?;
    Ok((public, internal))
}

#[derive(Clone)]
struct CollectorState {
    enrollment_token_hash: [u8; 32],
    inner: Arc<Mutex<CollectorInner>>,
    icon_service: Arc<IconService>,
    sampling: Arc<dpi::SamplingService>,
    license: Arc<license::LicenseCoordinator>,
}

impl CollectorState {
    #[cfg(test)]
    fn open(enrollment_token: &str, database_path: &Path) -> Result<Self, rusqlite::Error> {
        Self::with_storage(
            enrollment_token,
            SqliteStorage::open(database_path)?,
            ClassifierHandle::test_default(),
        )
    }

    #[cfg(test)]
    fn new(enrollment_token: &str) -> Self {
        Self::with_storage(
            enrollment_token,
            SqliteStorage::open_in_memory().expect("in-memory SQLite must open"),
            ClassifierHandle::test_default(),
        )
        .expect("in-memory SQLite must load")
    }

    #[cfg(test)]
    fn with_storage(
        enrollment_token: &str,
        storage: SqliteStorage,
        classifier: ClassifierHandle,
    ) -> Result<Self, rusqlite::Error> {
        Self::with_geo_provider(
            enrollment_token,
            Storage::sqlite(storage),
            classifier,
            Arc::new(DisabledGeoProvider),
            PathBuf::from(DEFAULT_GEO_DIRECTORY),
            DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
            IconCacheConfig::default(),
        )
        .map_err(|e| match e {
            StorageError::Sqlite(err) => err,
            _ => rusqlite::Error::InvalidQuery,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn with_geo_provider(
        enrollment_token: &str,
        storage: Storage,
        classifier: ClassifierHandle,
        geo_provider: Arc<dyn GeoProvider>,
        geo_directory: PathBuf,
        device_identifier: DeviceIdentifier,
        icon_cache_config: IconCacheConfig,
    ) -> Result<Self, StorageError> {
        let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
            classifier.clone(),
        ));
        let license = Arc::new(license::LicenseCoordinator::from_env(classifier.clone()));
        let gateway = storage.gateway()?.map(|record| GatewayCredential {
            gateway_id: record.id,
            agent_token_hash: record.agent_token_hash,
        });
        let inner = Arc::new(Mutex::new(CollectorInner {
            gateway,
            storage,
            classifier,
            geo_provider,
            geo_directory,
            device_identifier,
            service_bindings: ServiceBindingCache::default(),
            favicon_endpoints: FaviconEndpointCache::default(),
            pending_probe_requests: Vec::new(),
            realtime: RealtimeEngine::default(),
            accepted_batches: 0,
            dedupe_hits: 0,
            traffic_bytes: 0,
        }));
        let weak = Arc::downgrade(&inner);
        let sampling = Arc::new(dpi::SamplingService::new(
            !cfg!(test) && dpi_enabled_from_env().unwrap_or(false),
            dpi::default_engine(),
            signature_matcher,
            move |cached| {
                if let Some(inner) = weak.upgrade() {
                    let mut inner = inner
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Err(error) = apply_sample_result(&mut inner, &cached) {
                        tracing::warn!(%error, "sample classification update failed");
                    }
                }
            },
        ));
        Ok(Self {
            enrollment_token_hash: hash_token(enrollment_token),
            inner,
            icon_service: Arc::new(IconService::new(icon_cache_config)),
            sampling,
            license,
        })
    }

    fn lock(&self) -> MutexGuard<'_, CollectorInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn enrollment_token_matches(&self, token: &str) -> bool {
        bool::from(self.enrollment_token_hash.ct_eq(&hash_token(token)))
    }

    fn enroll(&self, request: &EnrollRequest) -> Result<Enrollment, EnrollError> {
        let mut inner = self.lock();
        if inner.gateway.is_some() {
            return Err(EnrollError::GatewayAlreadyEnrolled);
        }
        let gateway_id = random_hex(16).map_err(|_| EnrollError::Random)?;
        let agent_token = random_hex(32).map_err(|_| EnrollError::Random)?;
        let agent_token_hash = hash_token(&agent_token);
        let saved = inner
            .storage
            .save_gateway(
                &gateway_id,
                &request.gateway_name,
                &request.agent_version,
                &agent_token_hash,
                unix_time_ms(),
            )
            .map_err(|_| EnrollError::Storage)?;
        if !saved {
            return Err(EnrollError::GatewayAlreadyEnrolled);
        }
        inner.gateway = Some(GatewayCredential {
            gateway_id: gateway_id.clone(),
            agent_token_hash,
        });
        inner
            .realtime
            .gateway_status(&gateway_id, "enrolled", unix_time_ms());
        Ok(Enrollment {
            gateway_id,
            agent_token,
        })
    }

    fn authenticate(&self, token: &str) -> Option<String> {
        let inner = self.lock();
        inner.gateway.as_ref().and_then(|gateway| {
            bool::from(gateway.agent_token_hash.ct_eq(&hash_token(token)))
                .then(|| gateway.gateway_id.clone())
        })
    }

    fn accept_batch(&self, batch: &TelemetryBatch) -> Result<BatchDisposition, StorageError> {
        let mut inner = self.lock();
        let mut favicon_endpoints = std::mem::take(&mut inner.favicon_endpoints);
        favicon_endpoints.observe_results(&inner.classifier, batch);
        let dpi_results = self.sampling.lookup_batch(batch);
        let mut service_bindings = std::mem::take(&mut inner.service_bindings);
        let classified = classify_batch(
            &inner.storage,
            &inner.classifier,
            &mut service_bindings,
            &favicon_endpoints,
            batch,
            &dpi_results,
        );
        inner.service_bindings = service_bindings;
        // Restore probe state before any fallible storage work below. A rejected
        // telemetry batch must not discard previously learned endpoint identities
        // or outstanding request correlation.
        inner.favicon_endpoints = favicon_endpoints;
        let attributions = classified?;
        let mut supplemental_evidence =
            DeviceIdentifier::destination_evidence(&inner.classifier, batch, &attributions);
        for (mac, evidence) in DeviceIdentifier::discovery_evidence(
            &inner.classifier,
            &batch.device_discovery_observations,
        ) {
            supplemental_evidence
                .entry(mac)
                .or_default()
                .extend(evidence);
        }
        let mut effective_batch = batch.clone();
        for flow in &batch.flows {
            if supplemental_evidence.contains_key(&flow.client_mac)
                && matches!(flow.client_ip.len(), 4 | 16)
                && !effective_batch
                    .device_observations
                    .iter()
                    .any(|item| item.mac == flow.client_mac)
            {
                effective_batch
                    .device_observations
                    .push(netqmon_protocol::v1::DeviceObservation {
                        mac: flow.client_mac.clone(),
                        ip: flow.client_ip.clone(),
                        last_seen_unix_ms: flow.last_seen_unix_ms,
                        ..Default::default()
                    });
            }
        }
        for discovery in &batch.device_discovery_observations {
            if discovery.mac.len() != 6 || !matches!(discovery.ip.len(), 4 | 16) {
                continue;
            }
            if effective_batch
                .device_observations
                .iter()
                .any(|item| item.mac == discovery.mac && item.ip == discovery.ip)
            {
                continue;
            }
            effective_batch
                .device_observations
                .push(netqmon_protocol::v1::DeviceObservation {
                    mac: discovery.mac.clone(),
                    ip: discovery.ip.clone(),
                    hostname: discovery.hostname.clone(),
                    last_seen_unix_ms: discovery.observed_at_unix_ms,
                    dhcp: None,
                });
        }
        let mut historical_evidence = std::collections::HashMap::new();
        for observation in &effective_batch.device_observations {
            if !historical_evidence.contains_key(&observation.mac) {
                historical_evidence.insert(
                    observation.mac.clone(),
                    inner
                        .storage
                        .device_evidence(&batch.gateway_id, &observation.mac)?,
                );
            }
        }
        let device_identities = inner.device_identifier.identify_batch(
            &inner.classifier,
            &effective_batch.device_observations,
            &historical_evidence,
            &supplemental_evidence,
        );
        match inner.storage.persist_classified_batch(
            &effective_batch,
            &attributions,
            &device_identities,
            unix_time_ms(),
        )? {
            PersistDisposition::Duplicate => {
                inner.dedupe_hits = inner.dedupe_hits.saturating_add(1);
                Ok(BatchDisposition::Duplicate)
            }
            PersistDisposition::Accepted => {
                self.sampling.observe_telemetry(batch);
                let observed_at = if batch.sent_at == 0 {
                    unix_time_ms()
                } else {
                    batch.sent_at
                };
                inner.realtime.update(batch, &attributions, observed_at);
                inner.accepted_batches = inner.accepted_batches.saturating_add(1);
                inner.traffic_bytes =
                    batch.flows.iter().fold(inner.traffic_bytes, |total, flow| {
                        total
                            .saturating_add(flow.upload_bytes)
                            .saturating_add(flow.download_bytes)
                    });
                let requests = inner
                    .favicon_endpoints
                    .schedule(batch, &attributions, observed_at);
                inner.pending_probe_requests.extend(requests);
                Ok(BatchDisposition::Accepted)
            }
        }
    }

    fn take_probe_requests(&self) -> Vec<ProbeRequest> {
        std::mem::take(&mut self.lock().pending_probe_requests)
    }

    fn run_maintenance(&self, retention: bool) -> Result<(), StorageError> {
        let mut inner = self.lock();
        if retention {
            let policy = inner.storage.load_retention_policy()?;
            inner.storage.run_retention(unix_time_ms(), policy)
        } else {
            inner.storage.roll_up_hour_and_day(unix_time_ms())
        }
    }

    #[cfg(test)]
    fn stats(&self) -> IngestStats {
        let inner = self.lock();
        IngestStats {
            accepted_batches: inner.accepted_batches,
            dedupe_hits: inner.dedupe_hits,
            traffic_bytes: inner.traffic_bytes,
        }
    }

    fn realtime_snapshot(&self) -> RealtimeSnapshot {
        self.lock().realtime.snapshot()
    }

    fn realtime_subscription(
        &self,
    ) -> (
        RealtimeSnapshot,
        tokio::sync::broadcast::Receiver<RealtimeEvent>,
    ) {
        let inner = self.lock();
        (inner.realtime.snapshot(), inner.realtime.subscribe())
    }

    fn icon_service(&self) -> Arc<IconService> {
        self.icon_service.clone()
    }

    fn icon_application_context(
        &self,
        id: &str,
    ) -> (
        Option<classifier::EntityMetadata>,
        Option<classifier::EntityMetadata>,
    ) {
        let inner = self.lock();
        let application = inner.classifier.application_metadata(id);
        let organization = application.as_ref().and_then(|metadata| {
            inner
                .classifier
                .application_organization_id(&metadata.id)
                .and_then(|organization_id| {
                    inner.classifier.organization_metadata(&organization_id)
                })
        });
        (application, organization)
    }

    fn icon_organization_context(&self, id: &str) -> Option<classifier::EntityMetadata> {
        self.lock().classifier.organization_metadata(id)
    }
}

struct CollectorInner {
    gateway: Option<GatewayCredential>,
    storage: Storage,
    classifier: ClassifierHandle,
    geo_provider: Arc<dyn GeoProvider>,
    geo_directory: PathBuf,
    realtime: RealtimeEngine,
    device_identifier: DeviceIdentifier,
    service_bindings: ServiceBindingCache,
    favicon_endpoints: FaviconEndpointCache,
    pending_probe_requests: Vec<ProbeRequest>,
    accepted_batches: u64,
    dedupe_hits: u64,
    traffic_bytes: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ServiceBindingKey {
    ip: IpAddr,
    protocol: u8,
    port: u16,
}

#[derive(Clone, Debug)]
struct FaviconEndpointIdentity {
    application_id: String,
    organization_id: String,
    traffic_class: String,
    evidence_json: String,
    expires_at: u64,
}

#[derive(Debug)]
struct FaviconEndpointCache {
    identities: HashMap<ServiceBindingKey, FaviconEndpointIdentity>,
    outstanding: HashMap<String, (ServiceBindingKey, u64)>,
    last_requested: HashMap<ServiceBindingKey, u64>,
    next_request: u64,
    ttl_ms: u64,
    retry_ms: u64,
}

impl Default for FaviconEndpointCache {
    fn default() -> Self {
        Self {
            identities: HashMap::new(),
            outstanding: HashMap::new(),
            last_requested: HashMap::new(),
            next_request: 0,
            ttl_ms: 24 * 60 * 60 * 1_000,
            retry_ms: 6 * 60 * 60 * 1_000,
        }
    }
}

impl FaviconEndpointCache {
    fn observe_results(&mut self, classifier: &ClassifierHandle, batch: &TelemetryBatch) {
        let now = if batch.sent_at == 0 {
            unix_time_ms()
        } else {
            batch.sent_at
        };
        self.expire(now);
        for result in &batch.probe_results {
            let Some((requested_key, _)) = self.outstanding.remove(&result.request_id) else {
                continue;
            };
            let Some(ProbeOutcome::Favicon(favicon)) = result.outcome.as_ref() else {
                continue;
            };
            let Some(ip) = decode_ip(&favicon.target_ip) else {
                continue;
            };
            let Ok(port) = u16::try_from(favicon.port) else {
                continue;
            };
            let key = ServiceBindingKey {
                ip,
                protocol: 6,
                port,
            };
            if key != requested_key || result.status != "ok" {
                continue;
            }
            let mut matches = favicon
                .sha256
                .iter()
                .filter_map(|digest| classifier.classify_favicon_sha256(digest).ok())
                .filter(|classification| classification.application.is_some())
                .collect::<Vec<_>>();
            matches.sort_by(|left, right| {
                left.application
                    .as_ref()
                    .map(|value| &value.id)
                    .cmp(&right.application.as_ref().map(|value| &value.id))
            });
            matches.dedup_by(|left, right| {
                left.application.as_ref().map(|value| &value.id)
                    == right.application.as_ref().map(|value| &value.id)
            });
            if matches.len() != 1 {
                self.identities.remove(&key);
                continue;
            }
            let classification = matches.pop().expect("one favicon classification");
            let application_id = classification.application.expect("matched application").id;
            let organization_id = classification
                .organization
                .expect("matched organization")
                .id;
            let traffic_class = classification
                .traffic_class
                .expect("matched traffic class")
                .id;
            let evidence_json = serde_json::to_string(
                &classification
                    .evidence
                    .iter()
                    .map(|evidence| {
                        json!({
                            "type": evidence.evidence_type,
                            "value": evidence.value,
                            "source": evidence.source,
                            "weight": evidence.weight,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_owned());
            self.identities.insert(
                key,
                FaviconEndpointIdentity {
                    application_id,
                    organization_id,
                    traffic_class,
                    evidence_json,
                    expires_at: now.saturating_add(self.ttl_ms),
                },
            );
        }
    }

    fn schedule(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        now: u64,
    ) -> Vec<ProbeRequest> {
        self.expire(now);
        let mut requests = Vec::new();
        for (flow, attribution) in batch.flows.iter().zip(attributions) {
            if requests.len() >= 8 || flow.protocol != 6 || attribution.application_id != "unknown"
            {
                continue;
            }
            let Some(ip) = decode_ip(&flow.remote_ip).filter(|ip| is_private_endpoint(*ip)) else {
                continue;
            };
            let Ok(port) = u16::try_from(flow.remote_port) else {
                continue;
            };
            if port == 0 {
                continue;
            }
            let key = ServiceBindingKey {
                ip,
                protocol: 6,
                port,
            };
            if self.identities.contains_key(&key)
                || self
                    .outstanding
                    .values()
                    .any(|(pending, _)| pending == &key)
                || self
                    .last_requested
                    .get(&key)
                    .is_some_and(|last| last.saturating_add(self.retry_ms) > now)
            {
                continue;
            }
            self.next_request = self.next_request.saturating_add(1);
            let request_id = format!("{}-{}", batch.sequence, self.next_request);
            self.outstanding
                .insert(request_id.clone(), (key.clone(), now));
            self.last_requested.insert(key, now);
            requests.push(ProbeRequest {
                request_id,
                target: Some(ProbeTarget::Favicon(FaviconProbe {
                    target_ip: flow.remote_ip.clone(),
                    port: flow.remote_port,
                })),
            });
        }
        requests
    }

    fn identity(&self, key: &ServiceBindingKey, now: u64) -> Option<&FaviconEndpointIdentity> {
        self.identities
            .get(key)
            .filter(|identity| identity.expires_at > now)
    }

    fn expire(&mut self, now: u64) {
        self.identities
            .retain(|_, identity| identity.expires_at > now);
        self.outstanding
            .retain(|_, (_, requested)| requested.saturating_add(self.retry_ms) > now);
        self.last_requested
            .retain(|_, requested| requested.saturating_add(self.retry_ms) > now);
    }
}

#[derive(Clone, Debug)]
struct ServiceBinding {
    attribution: FlowAttribution,
    source: String,
    last_seen: u64,
    expires_at: u64,
}

#[derive(Debug)]
struct ServiceBindingCache {
    entries: HashMap<ServiceBindingKey, ServiceBinding>,
    ttl_ms: u64,
    max_entries: usize,
}

impl Default for ServiceBindingCache {
    fn default() -> Self {
        let ttl_seconds = env::var("NETQMON_SERVICE_BINDING_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(900);
        let max_entries = env::var("NETQMON_SERVICE_BINDING_MAX_ENTRIES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(4_096);
        Self {
            entries: HashMap::new(),
            ttl_ms: ttl_seconds.saturating_mul(1_000),
            max_entries,
        }
    }
}

impl ServiceBindingCache {
    fn apply(
        &mut self,
        key: ServiceBindingKey,
        _client_ip: Option<IpAddr>,
        observed_at: u64,
        attribution: &mut FlowAttribution,
    ) {
        self.entries
            .retain(|_, binding| binding.expires_at > observed_at);
        let strong_self_host = attribution.application_id != "unknown"
            && attribution.application_confidence >= 0.9
            && attribution_has_evidence(attribution, "self_host_application");
        // HTTP(S) reverse proxies commonly multiplex many applications on one
        // socket, so they are never eligible for endpoint-wide reuse.
        let multiplexed_port = matches!(key.port, 80 | 443);
        if strong_self_host && !multiplexed_port {
            if self.entries.get(&key).is_some_and(|binding| {
                binding.attribution.application_id != attribution.application_id
            }) {
                self.entries.remove(&key);
                return;
            }
            let source = attribution
                .reason
                .split_once(':')
                .map_or("classifier", |(source, _)| source)
                .to_owned();
            self.entries.insert(
                key,
                ServiceBinding {
                    attribution: attribution.clone(),
                    source,
                    last_seen: observed_at,
                    expires_at: observed_at.saturating_add(self.ttl_ms),
                },
            );
            self.enforce_bound();
            return;
        }
        if attribution.application_confidence >= 0.9 || multiplexed_port {
            return;
        }
        let Some(binding) = self.entries.get_mut(&key) else {
            return;
        };
        let domain = attribution.domain.clone();
        let mut bound = binding.attribution.clone();
        bound.domain = domain;
        bound.reason = format!(
            "service_binding:{}:{}/{}",
            key.ip,
            if key.protocol == 17 { "udp" } else { "tcp" },
            key.port
        );
        bound.evidence_json = append_evidence(
            &bound.evidence_json,
            json!({
                "type": "service_binding",
                "value": format!("{}:{}/{}", key.ip, key.protocol, key.port),
                "source": binding.source,
                "weight": bound.application_confidence,
                "last_seen": binding.last_seen,
                "expires_at": binding.expires_at,
            }),
        );
        *attribution = bound;
        binding.last_seen = observed_at;
        binding.expires_at = observed_at.saturating_add(self.ttl_ms);
    }

    fn enforce_bound(&mut self) {
        while self.entries.len() > self.max_entries {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, binding)| binding.last_seen)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

fn attribution_has_evidence(attribution: &FlowAttribution, evidence_type: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(&attribution.evidence_json)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("type").and_then(|value| value.as_str()) == Some(evidence_type)
            })
        })
}

fn append_evidence(existing: &str, evidence: serde_json::Value) -> String {
    let mut items = serde_json::from_str::<Vec<serde_json::Value>>(existing).unwrap_or_default();
    items.push(evidence);
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_owned())
}

struct GatewayCredential {
    gateway_id: String,
    agent_token_hash: [u8; 32],
}

struct Enrollment {
    gateway_id: String,
    agent_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchDisposition {
    Accepted,
    Duplicate,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IngestStats {
    accepted_batches: u64,
    dedupe_hits: u64,
    traffic_bytes: u64,
}

#[allow(clippy::too_many_lines)]
fn classify_batch(
    storage: &Storage,
    classifier: &ClassifierHandle,
    service_bindings: &mut ServiceBindingCache,
    favicon_endpoints: &FaviconEndpointCache,
    batch: &TelemetryBatch,
    analyses: &[Option<dpi::SampleAnalysis>],
) -> Result<Vec<FlowAttribution>, StorageError> {
    batch
        .flows
        .iter()
        .enumerate()
        .map(|(index, flow)| {
            let observed_at = if flow.last_seen_unix_ms == 0 {
                batch.sent_at
            } else {
                flow.last_seen_unix_ms
            };
            let dpi_result = analyses
                .get(index)
                .and_then(Option::as_ref)
                .and_then(|analysis| analysis.dpi.as_ref());
            let signature_matches = analyses
                .get(index)
                .and_then(Option::as_ref)
                .map(|analysis| analysis.signatures.clone())
                .unwrap_or_default();
            let mut domain =
                resolve_batch_domain(batch, &flow.client_ip, &flow.remote_ip, observed_at)
                    .map(str::to_owned)
                    .or(storage.resolve_domain(
                        &batch.gateway_id,
                        &flow.client_ip,
                        &flow.remote_ip,
                        observed_at,
                    )?)
                    .or_else(|| {
                        dpi_result
                            .and_then(|r| r.metadata.get("hostname"))
                            .filter(|host| !host.is_empty())
                            .cloned()
                    });
            let Some(remote_ip) = decode_ip(&flow.remote_ip) else {
                return Ok(FlowAttribution {
                    domain,
                    ..FlowAttribution::default()
                });
            };
            let input = ClassificationInput {
                domain: domain.as_deref(),
                remote_ip,
                remote_asn: None,
                remote_port: u16::try_from(flow.remote_port).unwrap_or(0),
                protocol: u8::try_from(flow.protocol).unwrap_or(0),
                dpi: dpi_result.map(|result| DpiEvidence {
                    protocol: &result.protocol,
                    application_protocol: result
                        .metadata
                        .get("application_protocol")
                        .map(String::as_str),
                    source: &result.source,
                    confidence: result.confidence,
                }),
                signatures: signature_matches,
            };
            let mut classification = classifier.classify(&input).unwrap_or_else(|error| {
                tracing::debug!(%error, "classifier flow classification skipped");
                classifier::ClassificationResult::default()
            });
            // A DNS attribution can be a generic CDN name. Still run SNI/Host through
            // the same domain rules, while retaining an already matched DNS application.
            if !classification
                .evidence
                .iter()
                .any(|e| e.evidence_type == "domain_application")
            {
                if let Some(hostname) = dpi_result
                    .and_then(|r| r.metadata.get("hostname"))
                    .filter(|h| !h.is_empty() && domain.as_ref() != Some(h))
                {
                    let host_input = ClassificationInput {
                        domain: Some(hostname),
                        ..input.clone()
                    };
                    let host_result = classifier.classify(&host_input).unwrap_or_default();
                    if host_result
                        .evidence
                        .iter()
                        .any(|e| e.evidence_type == "domain_application")
                    {
                        classification = host_result;
                        domain = Some(hostname.clone());
                    }
                }
            }
            let organization_id = classification
                .organization
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |value| value.id.clone());
            let organization_confidence = classification
                .organization
                .as_ref()
                .map_or(0.0, |value| value.confidence);
            let application_id = classification
                .application
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |value| value.id.clone());
            let application_confidence = classification
                .application
                .as_ref()
                .map_or(0.0, |value| value.confidence);
            let category_id = classification
                .traffic_class
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |value| value.id.clone());
            let traffic_role = classification
                .traffic_role
                .clone()
                .unwrap_or_else(|| "unknown".to_owned());
            let protocol_id = classification
                .protocol
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |value| value.id.clone());
            let protocol_confidence = classification
                .protocol
                .as_ref()
                .map_or(0.0, |value| value.confidence);
            let confidence = if application_id != "unknown" {
                application_confidence
            } else if protocol_id != "unknown" {
                protocol_confidence
            } else {
                organization_confidence
            };
            let evidence_json = serde_json::to_string(
                &classification
                    .evidence
                    .iter()
                    .map(|value| {
                        json!({
                            "type": value.evidence_type,
                            "value": value.value,
                            "source": value.source,
                            "weight": value.weight
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_owned());
            let mut attribution = FlowAttribution {
                domain,
                organization_id,
                application_id,
                category_id,
                traffic_role,
                protocol_id,
                organization_confidence,
                application_confidence,
                protocol_confidence,
                confidence,
                reason: classification.evidence.first().map_or_else(
                    || "no matching rule".to_owned(),
                    |value| format!("{}:{}", value.evidence_type, value.value),
                ),
                evidence_json,
            };
            let endpoint_key = ServiceBindingKey {
                ip: remote_ip,
                protocol: u8::try_from(flow.protocol).unwrap_or(0),
                port: u16::try_from(flow.remote_port).unwrap_or(0),
            };
            if attribution.application_id == "unknown" {
                if let Some(identity) = favicon_endpoints.identity(&endpoint_key, observed_at) {
                    attribution
                        .organization_id
                        .clone_from(&identity.organization_id);
                    attribution
                        .application_id
                        .clone_from(&identity.application_id);
                    attribution.category_id.clone_from(&identity.traffic_class);
                    attribution.traffic_role = "server".to_owned();
                    attribution.organization_confidence = 1.0;
                    attribution.application_confidence = 1.0;
                    attribution.confidence = 1.0;
                    attribution.reason = format!("favicon_sha256:{}", identity.application_id);
                    attribution
                        .evidence_json
                        .clone_from(&identity.evidence_json);
                }
            }
            service_bindings.apply(
                endpoint_key,
                decode_ip(&flow.client_ip),
                observed_at,
                &mut attribution,
            );
            Ok(attribution)
        })
        .collect()
}

fn resolve_batch_domain<'a>(
    batch: &'a TelemetryBatch,
    client_ip: &[u8],
    answer_ip: &[u8],
    at_ms: u64,
) -> Option<&'a str> {
    batch
        .dns_observations
        .iter()
        .filter(|observation| {
            observation.client_ip == client_ip
                && observation.answer_ip == answer_ip
                && observation.observed_at_unix_ms <= at_ms
                && observation
                    .observed_at_unix_ms
                    .saturating_add(u64::from(observation.ttl_seconds).saturating_mul(1_000))
                    > at_ms
        })
        .max_by_key(|observation| observation.observed_at_unix_ms)
        .map(|observation| observation.domain.as_str())
}

fn decode_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).into()),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(Ipv6Addr::from(octets).into())
        }
        _ => None,
    }
}

fn is_private_endpoint(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn public_router(state: CollectorState) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/v1/ingest/health", get(health))
        .route("/v1/ingest/enroll", post(enroll))
        .route("/v1/ingest/telemetry", post(telemetry))
        .route("/v1/ingest/samples", post(samples));
    #[cfg(test)]
    let router = router.route("/test/slow", get(slow_test_handler));
    router
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

fn internal_router(state: CollectorState) -> Router {
    Router::new()
        .route("/internal/health", get(health))
        .route("/internal/realtime/stream", get(realtime_stream))
        .merge(auth::router())
        .merge(icons::router())
        .merge(query_api::router())
        .with_state(state)
}

async fn realtime_stream(
    State(state): State<CollectorState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let (snapshot, receiver) = state.realtime_subscription();
    let initial = RealtimeEvent::Snapshot(snapshot);
    let events = stream::unfold(
        (Some(initial), receiver),
        |(initial, mut receiver)| async move {
            let event = if let Some(initial) = initial {
                initial
            } else {
                loop {
                    match receiver.recv().await {
                        Ok(event) => break event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            };
            let payload = event
                .json()
                .unwrap_or_else(|_| "{\"code\":\"serialization_failed\"}".to_owned());
            Some((
                Ok(Event::default().event(event.name()).data(payload)),
                (None, receiver),
            ))
        },
    );
    Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
async fn slow_test_handler() -> &'static str {
    tokio::time::sleep(Duration::from_millis(100)).await;
    "late"
}

async fn enroll(State(state): State<CollectorState>, body: Bytes) -> Response {
    let Ok(request) = EnrollRequest::decode(body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid protobuf enrollment request",
        );
    };
    if !state.enrollment_token_matches(&request.enrollment_token) {
        return error(StatusCode::UNAUTHORIZED, "invalid enrollment token");
    }
    if request.protocol_version != PROTOCOL_VERSION {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported protocol version",
        );
    }
    let enrollment = match state.enroll(&request) {
        Ok(enrollment) => enrollment,
        Err(EnrollError::GatewayAlreadyEnrolled) => {
            return error(
                StatusCode::CONFLICT,
                "an active gateway is already enrolled",
            );
        }
        Err(EnrollError::Random) => {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "token generation failed");
        }
        Err(EnrollError::Storage) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway persistence failed",
            );
        }
    };
    let response = EnrollResponse {
        gateway_id: enrollment.gateway_id,
        agent_token: enrollment.agent_token,
        protocol_version: PROTOCOL_VERSION,
    };
    let mut response = response.encode_to_vec().into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    response
}

#[derive(Clone, Debug)]
struct AgentIdentity {
    gateway_id: String,
}

impl<S> FromRequestParts<S> for AgentIdentity
where
    CollectorState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = (|| {
            let token = bearer_token(&parts.headers)
                .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
            let collector = CollectorState::from_ref(state);
            let gateway_id = collector
                .authenticate(token)
                .ok_or((StatusCode::UNAUTHORIZED, "invalid agent token"))?;
            Ok(Self { gateway_id })
        })();
        std::future::ready(result)
    }
}

async fn telemetry(
    State(state): State<CollectorState>,
    identity: AgentIdentity,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(encoding) = ContentEncoding::from_http_value(
        headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
    ) else {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported content encoding",
        );
    };
    let batch = match decode_telemetry_batch(&body, encoding) {
        Ok(batch) => batch,
        Err(DecodeError::TooLarge) => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "decoded batch is too large");
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid telemetry batch"),
    };
    if let Err(metadata) = validate_batch_metadata(&batch) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &metadata.to_string());
    }
    if batch.gateway_id != identity.gateway_id {
        return error(
            StatusCode::FORBIDDEN,
            "gateway_id does not match agent token",
        );
    }
    if batch.flows.len() > MAX_FLOWS_PER_BATCH {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too many flows in telemetry batch",
        );
    }
    if batch.device_discovery_observations.len() > MAX_DISCOVERY_OBSERVATIONS_PER_BATCH {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too many device discovery observations in telemetry batch",
        );
    }
    if batch.probe_results.len() > MAX_PROBE_RESULTS_PER_BATCH
        || batch.probe_results.iter().any(|result| {
            matches!(
                result.outcome.as_ref(),
                Some(ProbeOutcome::Favicon(favicon))
                    if favicon.sha256.len() > MAX_HASHES_PER_FAVICON_RESULT
                        || favicon.sha256.iter().any(|digest| digest.len() != 32)
            )
        })
    {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid probe results");
    }
    match state.accept_batch(&batch) {
        Ok(BatchDisposition::Accepted) => {
            let requests = state.take_probe_requests();
            if requests.is_empty() {
                return StatusCode::NO_CONTENT.into_response();
            }
            let body = TelemetryResponse {
                probe_requests: requests,
            }
            .encode_to_vec();
            (
                StatusCode::OK,
                [(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-protobuf"),
                )],
                body,
            )
                .into_response()
        }
        Ok(BatchDisposition::Duplicate) => StatusCode::OK.into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "telemetry persistence failed",
        ),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_hex(byte_count: usize) -> Result<String, getrandom::Error> {
    let mut bytes = vec![0; byte_count];
    fill(&mut bytes)?;
    let mut encoded = String::with_capacity(byte_count * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn spawn_maintenance(state: CollectorState, interval: Duration, retention: bool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let state = state.clone();
            let result =
                tokio::task::spawn_blocking(move || state.run_maintenance(retention)).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!(%error, retention, "SQLite maintenance failed"),
                Err(error) => tracing::error!(%error, retention, "SQLite maintenance task failed"),
            }
        }
    });
}

/// Keeps a late-starting or restarted dynamically managed classifier visible
/// without placing a health check on the ingestion path. The handle itself
/// enforces the 1–30 second retry circuit; this task merely makes a probe when
/// it becomes eligible and refreshes an existing entitlement after recovery.
fn spawn_classifier_probe(classifier: ClassifierHandle, license: Arc<license::LicenseCoordinator>) {
    tokio::spawn(async move {
        let mut was_ready = false;
        loop {
            let delay = match classifier.health() {
                Ok(()) => {
                    if !was_ready {
                        tracing::info!("classifier probe succeeded");
                        if license.status().is_ok_and(|status| status.activated) {
                            if let Err(error) = license.check().await {
                                tracing::warn!(%error, "license refresh after classifier recovery failed");
                            }
                        }
                    }
                    was_ready = true;
                    Duration::from_secs(30)
                }
                Err(error) => {
                    if was_ready {
                        tracing::warn!(%error, "classifier probe failed");
                    }
                    was_ready = false;
                    Duration::from_secs(1)
                }
            };
            tokio::time::sleep(delay).await;
        }
    });
}

fn spawn_mac_dataset_updates(
    state: CollectorState,
    path: PathBuf,
    source_url: String,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let update_path = path.clone();
            let source_url = source_url.clone();
            let result =
                tokio::task::spawn_blocking(move || refresh_mac_dataset(&update_path, &source_url))
                    .await;
            match result {
                Ok(Ok(dataset)) => {
                    let entries = dataset.metadata.entry_count;
                    let mut inner = state.lock();
                    inner.device_identifier.replace_mac_dataset(dataset);
                    tracing::info!(entries, "MAC prefix dataset refreshed");
                }
                Ok(Err(error)) => tracing::warn!(%error, "MAC prefix dataset refresh failed"),
                Err(error) => tracing::warn!(%error, "MAC prefix dataset refresh task failed"),
            }
        }
    });
}

#[derive(Debug)]
enum EnrollError {
    GatewayAlreadyEnrolled,
    Random,
    Storage,
}

#[cfg(test)]
mod tests;

fn dpi_enabled_from_env() -> Result<bool, ConfigError> {
    match std::env::var("NETQMON_DPI_ENABLED")
        .unwrap_or_else(|_| "true".into())
        .as_str()
    {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError(
            "NETQMON_DPI_ENABLED must be true or false".into(),
        )),
    }
}
async fn samples(
    State(state): State<CollectorState>,
    identity: AgentIdentity,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(encoding) = ContentEncoding::from_http_value(
        headers.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
    ) else {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported content encoding",
        );
    };
    let batch = match netqmon_protocol::decode_flow_sample_batch(&body, encoding) {
        Ok(batch) => batch,
        Err(DecodeError::TooLarge) => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "sample batch too large");
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid sample batch"),
    };
    if batch.gateway_id != identity.gateway_id {
        return error(
            StatusCode::FORBIDDEN,
            "gateway_id does not match agent token",
        );
    }
    if netqmon_protocol::validate_flow_sample_batch(&batch).is_err() {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid sample metadata or limits",
        );
    }
    if state.sampling.submit(batch) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "DPI disabled or sample queue full",
        )
    }
}
fn apply_sample_result(
    inner: &mut CollectorInner,
    cached: &dpi::CachedResult,
) -> Result<(), StorageError> {
    let key = &cached.key;
    let flow = netqmon_protocol::v1::FlowDelta {
        ip_version: key.ip_version,
        protocol: key.protocol,
        client_ip: key.client_ip.clone(),
        client_port: key.client_port,
        remote_ip: key.remote_ip.clone(),
        remote_port: key.remote_port,
        first_seen_unix_ms: key.first_seen_unix_ms,
        last_seen_unix_ms: cached.last_packet_ms,
        ..Default::default()
    };
    let batch = TelemetryBatch {
        gateway_id: cached.gateway.clone(),
        boot_id: cached.boot.clone(),
        sent_at: cached.last_packet_ms,
        flows: vec![flow],
        ..Default::default()
    };
    let mut service_bindings = std::mem::take(&mut inner.service_bindings);
    let classified = classify_batch(
        &inner.storage,
        &inner.classifier,
        &mut service_bindings,
        &inner.favicon_endpoints,
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: cached.result.clone(),
            signatures: cached.signatures.clone(),
        })],
    );
    inner.service_bindings = service_bindings;
    let attributions = classified?;
    inner
        .storage
        .reclassify_flow(&cached.gateway, &batch.flows[0], &attributions[0])
}
