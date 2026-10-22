//! Bounded, authenticated telemetry ingestion for netqmon.

mod auth;
mod classifier;
mod device_identification;
mod dpi;
mod icons;
pub mod insights;
mod license;
mod policy;
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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{DefaultBodyLimit, FromRef, FromRequestParts, State};
use axum::http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use classifier::{ClassificationInput, ClassificationResult, ClassifierHandle, DpiEvidence};
use futures_util::stream;
use getrandom::fill;
#[cfg(test)]
use netqmon_geo::DisabledGeoProvider;
use netqmon_geo::{DEFAULT_GEO_DIRECTORY, GeoProvider, LocalDbProvider};
use netqmon_protocol::policy::{FlowCommandOperation, POLICY_WIRE_VERSION, PolicyWireFrame};
use netqmon_protocol::v1::probe_request::Target as ProbeTarget;
use netqmon_protocol::v1::probe_result::Outcome as ProbeOutcome;
use netqmon_protocol::v1::{
    EnrollRequest, EnrollResponse, FaviconProbe, FlowLifecycle, FlowScope, ProbeRequest,
    TelemetryBatch, TelemetryResponse,
};
use netqmon_protocol::{
    ContentEncoding, DecodeError, PROTOCOL_VERSION, decode_telemetry_batch, validate_batch_metadata,
};
use netqmon_storage::{
    ClickHouseConfig, ClickHouseStorage, DEFAULT_DATABASE_PATH, FlowAttribution,
    PersistDisposition, SqliteStorage, Storage, StorageError,
};
use policy::PolicyHub;
use prost::Message;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::icons::{IconCacheConfig, IconService};
use crate::policy::PolicyService;
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
const MIN_UNAMBIGUOUS_SIGNATURE_CONFIDENCE: f64 = 0.80;
const GATEWAY_REPLACEMENT_STALE_AFTER_MS: u64 = 5 * 60 * 1_000;
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
    let flow_sample_matching_enabled = flow_sample_matching_enabled_from_env(dpi_enabled)?;
    if dpi_enabled && !dpi::native_available() {
        return Err(ConfigError("DPI enabled but nDPI 4.14 is unavailable; install libndpi and rebuild or set NETQMON_DPI_ENABLED=false".into()).into());
    }
    let classifier =
        ClassifierHandle::connect(config.classifier_socket.clone()).map_err(ConfigError)?;
    tracing::info!(
        socket = %config.classifier_socket.display(),
        "classifier IPC configured; telemetry ingest will retry while it reconnects"
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
    let policy_service =
        Arc::new(PolicyService::open_from_env().map_err(|error| {
            ConfigError(format!("failed to initialize policy storage: {error}"))
        })?);

    let state = CollectorState::with_geo_provider(
        &config.enrollment_token,
        storage,
        classifier.clone(),
        Arc::new(geo_load.provider),
        config.geo_directory.clone(),
        DeviceIdentifier::load(&config.mac_dataset_path),
        config.icon_cache_config,
        policy_service,
        flow_sample_matching_enabled,
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
    policy::push::spawn_schedule_refresh(
        Arc::clone(&state.policy_service),
        state.policy_hub.clone(),
    );

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
    processing: Arc<Mutex<()>>,
    query_storage: Option<Arc<Mutex<Storage>>>,
    query_classifier: ClassifierHandle,
    query_geo: Arc<RwLock<Arc<dyn GeoProvider>>>,
    active_flow_count: Arc<AtomicI64>,
    icon_service: Arc<IconService>,
    sampling: Arc<dpi::SamplingService>,
    license: Arc<license::LicenseCoordinator>,
    policy_service: Arc<PolicyService>,
    policy_hub: PolicyHub,
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
        let policy_service = Arc::new(
            PolicyService::open_in_memory().expect("in-memory test policy database must open"),
        );
        Self::with_geo_provider(
            enrollment_token,
            Storage::sqlite(storage),
            classifier,
            Arc::new(DisabledGeoProvider),
            PathBuf::from(DEFAULT_GEO_DIRECTORY),
            DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
            IconCacheConfig::default(),
            policy_service,
            false,
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
        policy_service: Arc<PolicyService>,
        flow_sample_matching_enabled: bool,
    ) -> Result<Self, StorageError> {
        let signature_matcher = Arc::new(classifier::ClassifierdSignatureMatcher::new(
            classifier.clone(),
        ));
        let license = Arc::new(license::LicenseCoordinator::from_env(classifier.clone()));
        let gateway = storage.gateway()?.map(|record| GatewayCredential {
            gateway_id: record.id,
            agent_token_hash: record.agent_token_hash,
        });
        let query_storage = storage
            .query_reader()?
            .map(|reader| Arc::new(Mutex::new(reader)));
        let query_classifier = classifier.clone();
        let query_geo = Arc::new(RwLock::new(Arc::clone(&geo_provider)));
        let active_flow_count =
            Arc::new(AtomicI64::new(if matches!(storage, Storage::Sqlite(_)) {
                storage.active_flow_count()?
            } else {
                0
            }));
        let inner = Arc::new(Mutex::new(CollectorInner {
            gateway,
            storage,
            classifier,
            geo_provider,
            geo_directory,
            device_identifier,
            service_bindings: ServiceBindingCache::default(),
            dns_domains: DnsDomainCache::default(),
            favicon_endpoints: FaviconEndpointCache::default(),
            pending_probe_requests: Vec::new(),
            policy_flow_contexts: policy::FlowContextCache::default(),
            pending_flow_samples: policy::PendingFlowSamples::default(),
            realtime: RealtimeEngine::default(),
            accepted_batches: 0,
            dedupe_hits: 0,
            traffic_bytes: 0,
        }));
        let policy_hub = PolicyHub::new();
        let processing = Arc::new(Mutex::new(()));
        let callback_processing = Arc::clone(&processing);
        let weak = Arc::downgrade(&inner);
        let callback_policy_hub = policy_hub.clone();
        let sampling = Arc::new(dpi::SamplingService::new(
            !cfg!(test) && flow_sample_matching_enabled,
            dpi::default_engine(),
            signature_matcher,
            move |cached| {
                if let Some(inner) = weak.upgrade() {
                    let processing_guard = callback_processing
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let result = process_sample(&inner, &cached, &processing_guard);
                    if result.as_ref().is_ok_and(Vec::is_empty) {
                        inner
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .pending_flow_samples
                            .defer(cached, std::time::Instant::now());
                    }
                    match result {
                        Ok(decisions) => {
                            for (batch, attribution) in decisions {
                                queue_policy_flow_decisions(
                                    &callback_policy_hub,
                                    &batch,
                                    std::slice::from_ref(&attribution),
                                );
                            }
                        }
                        Err(error) => tracing::warn!(%error, "sample classification update failed"),
                    }
                }
            },
        ));
        Ok(Self {
            enrollment_token_hash: hash_token(enrollment_token),
            inner,
            processing,
            query_storage,
            query_classifier,
            query_geo,
            active_flow_count,
            icon_service: Arc::new(IconService::new(icon_cache_config)),
            sampling,
            license,
            policy_service,
            policy_hub,
        })
    }

    fn lock(&self) -> MutexGuard<'_, CollectorInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn query(&self) -> QueryContext<'_> {
        if let Some(source) = &self.query_storage {
            let reader = source
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .query_reader();
            if let Ok(Some(storage)) = reader {
                let active_flows = matches!(storage, Storage::Sqlite(_))
                    .then(|| self.active_flow_count.load(Ordering::Relaxed));
                return QueryContext {
                    storage: QueryStorage::Independent(storage),
                    classifier: self.query_classifier.clone(),
                    geo_provider: Arc::clone(
                        &self
                            .query_geo
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    ),
                    active_flows,
                };
            }
        }
        let inner = self.lock();
        let classifier = inner.classifier.clone();
        let geo_provider = Arc::clone(&inner.geo_provider);
        let active_flows = if matches!(inner.storage, Storage::Sqlite(_)) {
            inner.storage.active_flow_count().ok()
        } else {
            None
        };
        let storage = match inner.storage.query_reader() {
            Ok(Some(storage)) => QueryStorage::Independent(storage),
            Ok(None) => QueryStorage::Locked(inner),
            Err(error) => {
                tracing::warn!(%error, "independent query connection unavailable");
                QueryStorage::Locked(inner)
            }
        };
        QueryContext {
            storage,
            classifier,
            geo_provider,
            active_flows,
        }
    }

    fn enrollment_token_matches(&self, token: &str) -> bool {
        bool::from(self.enrollment_token_hash.ct_eq(&hash_token(token)))
    }

    fn enroll(&self, request: &EnrollRequest) -> Result<Enrollment, EnrollError> {
        let mut inner = self.lock();
        let now_ms = unix_time_ms();
        if let Some(record) = inner.storage.gateway().map_err(|_| EnrollError::Storage)? {
            let stale_before_ms = now_ms.saturating_sub(GATEWAY_REPLACEMENT_STALE_AFTER_MS);
            if record.last_seen_ms <= stale_before_ms {
                let agent_token = random_hex(32).map_err(|_| EnrollError::Random)?;
                let agent_token_hash = hash_token(&agent_token);
                let replaced = inner
                    .storage
                    .replace_stale_gateway(
                        &record.id,
                        &request.gateway_name,
                        &request.agent_version,
                        &agent_token_hash,
                        stale_before_ms,
                        now_ms,
                    )
                    .map_err(|_| EnrollError::Storage)?;
                if !replaced {
                    tracing::debug!(gateway_id = %record.id, "stale gateway enrollment lost a concurrent replacement");
                    return Err(EnrollError::GatewayAlreadyEnrolled);
                }
                inner.gateway = Some(GatewayCredential {
                    gateway_id: record.id.clone(),
                    agent_token_hash,
                });
                inner
                    .realtime
                    .gateway_status(&record.id, "enrolled", now_ms);
                tracing::info!(
                    gateway_id = %record.id,
                    previous_last_seen_ms = record.last_seen_ms,
                    "stale gateway credentials rotated during enrollment"
                );
                return Ok(Enrollment {
                    gateway_id: record.id,
                    agent_token,
                });
            }
            tracing::debug!(
                gateway_id = %record.id,
                last_seen_ms = record.last_seen_ms,
                "enrollment rejected because gateway is still active"
            );
            return Err(EnrollError::GatewayAlreadyEnrolled);
        }
        if inner.gateway.is_some() {
            tracing::warn!(
                "enrollment rejected because the in-memory gateway has no persisted record"
            );
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
                now_ms,
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
            .gateway_status(&gateway_id, "enrolled", now_ms);
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

    fn accept_batch(
        &self,
        batch: &TelemetryBatch,
    ) -> Result<BatchDisposition, TelemetryIngestError> {
        // Serialize writer-side caches without holding the query/state mutex
        // while classifier IPC is in flight.
        let processing_guard = self
            .processing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut work, domains) = {
            let mut inner = self.lock();
            inner.dns_domains.observe(batch);
            let domains = resolve_batch_domains(&inner.storage, batch)?;
            (ClassificationWork::take(&mut inner), domains)
        };
        let analyses = self.sampling.lookup_batch(batch);
        let prepared = (|| -> Result<_, TelemetryIngestError> {
            work.favicon_endpoints
                .observe_results(&work.classifier, batch);
            let attributions = classify_resolved_batch(
                &work.classifier,
                work.geo_provider.as_ref(),
                &mut work.service_bindings,
                &work.dns_domains,
                &work.favicon_endpoints,
                batch,
                &analyses,
                false,
                &domains,
            )?;
            let mut supplemental_evidence =
                DeviceIdentifier::destination_evidence(&work.classifier, batch, &attributions);
            for (mac, evidence) in DeviceIdentifier::discovery_evidence(
                &work.classifier,
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
                    effective_batch.device_observations.push(
                        netqmon_protocol::v1::DeviceObservation {
                            mac: flow.client_mac.clone(),
                            ip: flow.client_ip.clone(),
                            last_seen_unix_ms: flow.last_seen_unix_ms,
                            ..Default::default()
                        },
                    );
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
            let historical_evidence = {
                let inner = self.lock();
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
                historical_evidence
            };
            let device_identities = work.device_identifier.identify_batch(
                &work.classifier,
                &effective_batch.device_observations,
                &historical_evidence,
                &supplemental_evidence,
            );
            Ok((effective_batch, attributions, device_identities))
        })();
        let mut inner = self.lock();
        work.restore(&mut inner);
        let (effective_batch, attributions, device_identities) = prepared?;
        let mut ready_samples = Vec::new();
        let mut late_sample_decisions = Vec::new();
        let result = match inner.storage.persist_classified_batch(
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
                inner
                    .policy_flow_contexts
                    .observe(batch, std::time::Instant::now());
                ready_samples = {
                    let CollectorInner {
                        policy_flow_contexts,
                        pending_flow_samples,
                        ..
                    } = &mut *inner;
                    pending_flow_samples.take_ready(policy_flow_contexts, std::time::Instant::now())
                };
                self.sampling.observe_telemetry(batch);
                let observed_at = if batch.sent_at == 0 {
                    unix_time_ms()
                } else {
                    batch.sent_at
                };
                let received_at = unix_time_ms();
                inner
                    .realtime
                    .update(batch, &attributions, observed_at, received_at);
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
        };
        self.refresh_active_flow_count(&inner.storage);
        if matches!(&result, Ok(BatchDisposition::Accepted)) {
            drop(inner);
            for sample in ready_samples {
                match process_sample(&self.inner, &sample, &processing_guard) {
                    Ok(mut decisions) => late_sample_decisions.append(&mut decisions),
                    Err(error) => {
                        tracing::warn!(%error, "deferred sample classification update failed");
                        self.lock()
                            .pending_flow_samples
                            .defer(sample, std::time::Instant::now());
                    }
                }
            }
            queue_policy_flow_decisions(&self.policy_hub, batch, &attributions);
            for (late_batch, attribution) in late_sample_decisions {
                queue_policy_flow_decisions(
                    &self.policy_hub,
                    &late_batch,
                    std::slice::from_ref(&attribution),
                );
            }
        }
        result
    }

    fn take_probe_requests(&self) -> Vec<ProbeRequest> {
        std::mem::take(&mut self.lock().pending_probe_requests)
    }

    fn run_maintenance(&self, retention: bool) -> Result<(), StorageError> {
        let mut inner = self.lock();
        let now = unix_time_ms();
        inner.storage.prune_reclassification(now)?;
        self.refresh_active_flow_count(&inner.storage);
        if let Some(mut writer) = inner.storage.maintenance_writer()? {
            drop(inner);
            return if retention {
                let policy = writer.load_retention_policy()?;
                writer.run_retention(now, policy)
            } else {
                writer.roll_up_hour_and_day(now)
            };
        }
        if retention {
            let policy = inner.storage.load_retention_policy()?;
            inner.storage.run_retention(unix_time_ms(), policy)
        } else {
            let now = unix_time_ms();
            inner.storage.prune_reclassification(now)?;
            inner.storage.roll_up_hour_and_day(now)
        }
    }

    fn refresh_active_flow_count(&self, storage: &Storage) {
        if matches!(storage, Storage::Sqlite(_)) {
            self.active_flow_count
                .store(storage.active_flow_count().unwrap_or(0), Ordering::Relaxed);
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

    fn realtime_snapshot(&self) -> Arc<RealtimeSnapshot> {
        self.lock().realtime.snapshot()
    }

    fn realtime_subscription(
        &self,
    ) -> (
        Arc<RealtimeSnapshot>,
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
        let classifier = self.lock().classifier.clone();
        let application = classifier.application_metadata(id);
        let organization = application.as_ref().and_then(|metadata| {
            metadata
                .organization_id
                .as_ref()
                .and_then(|organization_id| classifier.organization_metadata(organization_id))
        });
        (application, organization)
    }

    fn icon_organization_context(&self, id: &str) -> Option<classifier::EntityMetadata> {
        let classifier = self.lock().classifier.clone();
        classifier.organization_metadata(id)
    }
}

struct QueryContext<'a> {
    storage: QueryStorage<'a>,
    classifier: ClassifierHandle,
    geo_provider: Arc<dyn GeoProvider>,
    active_flows: Option<i64>,
}

enum QueryStorage<'a> {
    Independent(Storage),
    Locked(MutexGuard<'a, CollectorInner>),
}

impl std::ops::Deref for QueryStorage<'_> {
    type Target = Storage;
    fn deref(&self) -> &Storage {
        match self {
            Self::Independent(storage) => storage,
            Self::Locked(inner) => &inner.storage,
        }
    }
}

struct ClassificationWork {
    classifier: ClassifierHandle,
    geo_provider: Arc<dyn GeoProvider>,
    device_identifier: DeviceIdentifier,
    service_bindings: ServiceBindingCache,
    dns_domains: DnsDomainCache,
    favicon_endpoints: FaviconEndpointCache,
}

impl ClassificationWork {
    fn take(inner: &mut CollectorInner) -> Self {
        Self {
            classifier: inner.classifier.clone(),
            geo_provider: Arc::clone(&inner.geo_provider),
            device_identifier: inner.device_identifier.clone(),
            service_bindings: std::mem::take(&mut inner.service_bindings),
            dns_domains: std::mem::take(&mut inner.dns_domains),
            favicon_endpoints: std::mem::take(&mut inner.favicon_endpoints),
        }
    }

    fn restore(self, inner: &mut CollectorInner) {
        inner.service_bindings = self.service_bindings;
        inner.dns_domains = self.dns_domains;
        inner.favicon_endpoints = self.favicon_endpoints;
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
    dns_domains: DnsDomainCache,
    favicon_endpoints: FaviconEndpointCache,
    pending_probe_requests: Vec<ProbeRequest>,
    policy_flow_contexts: policy::FlowContextCache,
    pending_flow_samples: policy::PendingFlowSamples,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct DnsDomainKey {
    gateway_id: String,
    client_ip: Vec<u8>,
    answer_ip: Vec<u8>,
}

#[derive(Clone, Debug)]
struct DnsDomainValue {
    domain: String,
    observed_at: u64,
}

/// Short-lived DNS history used only when an encrypted flow has no usable SNI.
///
/// A DNS answer may expire while a QUIC/TLS connection keeps its endpoint
/// alive. Keeping the exact client/answer pair briefly gives the classifier a
/// real domain without falling back to an IP-prefix or CDN-wide guess.
#[derive(Debug)]
struct DnsDomainCache {
    entries: HashMap<DnsDomainKey, DnsDomainValue>,
    ttl_ms: u64,
}

impl Default for DnsDomainCache {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            ttl_ms: 6 * 60 * 60 * 1_000,
        }
    }
}

impl DnsDomainCache {
    fn observe(&mut self, batch: &TelemetryBatch) {
        for observation in &batch.dns_observations {
            if observation.domain.is_empty() || observation.answer_ip.is_empty() {
                continue;
            }
            let key = DnsDomainKey {
                gateway_id: batch.gateway_id.clone(),
                client_ip: observation.client_ip.clone(),
                answer_ip: observation.answer_ip.clone(),
            };
            let observed_at = observation.observed_at_unix_ms;
            match self.entries.get_mut(&key) {
                Some(value) if value.observed_at <= observed_at => {
                    value.domain.clone_from(&observation.domain);
                    value.observed_at = observed_at;
                }
                Some(_) => {}
                None => {
                    self.entries.insert(
                        key,
                        DnsDomainValue {
                            domain: observation.domain.clone(),
                            observed_at,
                        },
                    );
                }
            }
        }
        let oldest = batch.sent_at.saturating_sub(self.ttl_ms);
        self.entries.retain(|_, value| value.observed_at >= oldest);
    }

    fn resolve(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> Option<&str> {
        self.entries
            .get(&DnsDomainKey {
                gateway_id: gateway_id.to_owned(),
                client_ip: client_ip.to_vec(),
                answer_ip: answer_ip.to_vec(),
            })
            .filter(|value| {
                value.observed_at <= at_ms && at_ms.saturating_sub(value.observed_at) <= self.ttl_ms
            })
            .map(|value| value.domain.as_str())
    }
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

#[derive(Debug)]
enum TelemetryIngestError {
    ClassifierUnavailable(String),
    Storage(StorageError),
}

impl From<StorageError> for TelemetryIngestError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IngestStats {
    accepted_batches: u64,
    dedupe_hits: u64,
    traffic_bytes: u64,
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
fn classify_batch(
    storage: &Storage,
    classifier: &ClassifierHandle,
    geo_provider: &dyn GeoProvider,
    service_bindings: &mut ServiceBindingCache,
    dns_domains: &DnsDomainCache,
    favicon_endpoints: &FaviconEndpointCache,
    batch: &TelemetryBatch,
    analyses: &[Option<dpi::SampleAnalysis>],
    fail_open_on_classifier_error: bool,
) -> Result<Vec<FlowAttribution>, TelemetryIngestError> {
    let domains = resolve_batch_domains(storage, batch)?;
    classify_resolved_batch(
        classifier,
        geo_provider,
        service_bindings,
        dns_domains,
        favicon_endpoints,
        batch,
        analyses,
        fail_open_on_classifier_error,
        &domains,
    )
}

fn resolve_batch_domains(
    storage: &Storage,
    batch: &TelemetryBatch,
) -> Result<Vec<Option<String>>, StorageError> {
    let mut cached: HashMap<_, Option<String>> = HashMap::new();
    batch
        .flows
        .iter()
        .map(|flow| {
            let at = if flow.last_seen_unix_ms == 0 {
                batch.sent_at
            } else {
                flow.last_seen_unix_ms
            };
            if let Some(domain) = resolve_batch_domain(batch, &flow.client_ip, &flow.remote_ip, at)
            {
                return Ok(Some(domain.to_owned()));
            }
            let key = (&flow.client_ip, &flow.remote_ip, at);
            if let Some(domain) = cached.get(&key) {
                return Ok(domain.clone());
            }
            let domain =
                storage.resolve_domain(&batch.gateway_id, &flow.client_ip, &flow.remote_ip, at)?;
            cached.insert(key, domain.clone());
            Ok(domain)
        })
        .collect()
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn classify_resolved_batch(
    classifier: &ClassifierHandle,
    geo_provider: &dyn GeoProvider,
    service_bindings: &mut ServiceBindingCache,
    dns_domains: &DnsDomainCache,
    favicon_endpoints: &FaviconEndpointCache,
    batch: &TelemetryBatch,
    analyses: &[Option<dpi::SampleAnalysis>],
    fail_open_on_classifier_error: bool,
    domains: &[Option<String>],
) -> Result<Vec<FlowAttribution>, TelemetryIngestError> {
    let remote_asns = lookup_batch_remote_asns(geo_provider, batch);
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
            let ambiguous_signature_ids =
                ambiguous_signature_application_ids(&signature_matches);
            let ambiguous_signatures = !ambiguous_signature_ids.is_empty();
            let mut domain = domains.get(index).cloned().flatten();
            if domain.is_none() {
                domain = dpi_result
                    .and_then(|r| r.metadata.get("hostname"))
                    .filter(|host| !host.is_empty())
                    .cloned();
            }
            if domain.is_none() {
                let encrypted = dpi_result.is_some_and(|result| {
                    matches!(result.protocol.as_str(), "tls" | "quic")
                }) || (flow.protocol == 17 && flow.remote_port == 443);
                if encrypted {
                    domain = dns_domains
                        .resolve(
                            &batch.gateway_id,
                            &flow.client_ip,
                            &flow.remote_ip,
                            observed_at,
                        )
                        .map(str::to_owned);
                }
            }
            let Some(remote_ip) = decode_ip(&flow.remote_ip) else {
                return Ok(FlowAttribution {
                    domain,
                    ..FlowAttribution::default()
                });
            };
            let input = ClassificationInput {
                domain: domain.as_deref(),
                remote_ip,
                remote_asn: remote_asns
                    .get(&remote_ip)
                    .copied()
                    .and_then(BatchAsnLookup::asn),
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
            let (mut classification, classifier_available) = match classifier.classify(&input) {
                Ok(classification) => (classification, true),
                Err(error) => {
                    if !fail_open_on_classifier_error {
                        return Err(TelemetryIngestError::ClassifierUnavailable(error));
                    }
                    tracing::debug!(%error, "classifier unavailable; flow attribution fails open");
                    (ClassificationResult::default(), false)
                }
            };
            // A DNS attribution can be a generic CDN name. Still run SNI/Host through
            // the same domain rules, while retaining an already matched DNS application.
            if let Some(hostname) = dpi_result
                .and_then(|r| r.metadata.get("hostname"))
                .filter(|h| classifier_available && !h.is_empty() && domain.as_ref() != Some(h))
            {
                // Ask for domain-only identities: domain evidence can describe
                // an organization while the application came from unrelated DPI.
                // This also avoids depending on private evidence type names.
                let host_result = (|| -> Result<Option<ClassificationResult>, String> {
                    let dns_identity =
                        classifier.classify_domain(domain.as_deref().unwrap_or_default())?;
                    if dns_identity.application.is_some() {
                        return Ok(None);
                    }
                    let host_input = ClassificationInput {
                        domain: Some(hostname),
                        ..input.clone()
                    };
                    let host_result = classifier.classify(&host_input)?;
                    let host_identity = classifier.classify_domain(hostname)?;
                    Ok(host_identity.application.is_some().then_some(host_result))
                })();
                match host_result {
                    Ok(Some(host_result)) => {
                        classification = host_result;
                        domain = Some(hostname.clone());
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if !fail_open_on_classifier_error {
                            return Err(TelemetryIngestError::ClassifierUnavailable(error));
                        }
                        tracing::debug!(%error, "classifier unavailable for DPI hostname; flow attribution fails open");
                    }
                }
            }
            // A single flow can contain multiplexed or colliding application
            // signatures. Choosing the classifier's highest-ranked match would
            // guess which application owns the whole flow, so leave it on the
            // client's default budget and avoid endpoint-cache attribution too.
            if ambiguous_signatures {
                classification.application = None;
                classification.traffic_class = None;
                classification.traffic_role = None;
                classification.evidence.retain(|evidence| {
                    !matches!(
                        evidence.evidence_type.as_str(),
                        "payload_signature" | "domain_application"
                    )
                });
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
                reason: if ambiguous_signatures {
                    format!(
                        "ambiguous_application_signatures:{}",
                        ambiguous_signature_ids.join(",")
                    )
                } else {
                    classification.evidence.first().map_or_else(
                        || "no matching rule".to_owned(),
                        |value| format!("{}:{}", value.evidence_type, value.value),
                    )
                },
                evidence_json,
            };
            if ambiguous_signatures {
                attribution.evidence_json = append_evidence(
                    &attribution.evidence_json,
                    json!({
                        "type": "ambiguous_application_signatures",
                        "value": ambiguous_signature_ids,
                        "source": "payload_signature",
                        "weight": 0.0
                    }),
                );
            }
            let endpoint_key = ServiceBindingKey {
                ip: remote_ip,
                protocol: u8::try_from(flow.protocol).unwrap_or(0),
                port: u16::try_from(flow.remote_port).unwrap_or(0),
            };
            if attribution.application_id == "unknown" && !ambiguous_signatures {
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
            if !ambiguous_signatures {
                service_bindings.apply(
                    endpoint_key,
                    decode_ip(&flow.client_ip),
                    observed_at,
                    &mut attribution,
                );
            }
            Ok(attribution)
        })
        .collect()
}

fn ambiguous_signature_application_ids(
    signatures: &[dpi::SignatureApplicationMatch],
) -> Vec<String> {
    let mut ids = signatures
        .iter()
        .filter(|matched| {
            matched.confidence.is_finite()
                && matched.confidence >= MIN_UNAMBIGUOUS_SIGNATURE_CONFIDENCE
                && !matched.application_id.is_empty()
        })
        .map(|matched| matched.application_id.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.len() > 1 { ids } else { Vec::new() }
}

/// Result of one Geo ASN lookup retained only for a single classification batch.
///
/// Keeping misses and failures distinct ensures a repeatedly observed address never
/// causes repeated provider work, even when its ASN cannot be supplied.
#[derive(Clone, Copy, Debug)]
enum BatchAsnLookup {
    Found(u32),
    Missing,
    Failed,
}

impl BatchAsnLookup {
    const fn asn(self) -> Option<u32> {
        match self {
            Self::Found(asn) => Some(asn),
            Self::Missing | Self::Failed => None,
        }
    }
}

fn lookup_batch_remote_asns(
    geo_provider: &dyn GeoProvider,
    batch: &TelemetryBatch,
) -> HashMap<IpAddr, BatchAsnLookup> {
    if !geo_provider.is_enabled() {
        return HashMap::new();
    }

    let mut lookups = HashMap::new();
    for flow in &batch.flows {
        let Some(remote_ip) = decode_ip(&flow.remote_ip) else {
            continue;
        };
        if lookups.contains_key(&remote_ip) {
            continue;
        }
        let result = match geo_provider.lookup(remote_ip) {
            Ok(Some(record)) => record
                .asn
                .map_or(BatchAsnLookup::Missing, BatchAsnLookup::Found),
            Ok(None) => BatchAsnLookup::Missing,
            Err(error) => {
                tracing::debug!(%error, %remote_ip, "Geo ASN lookup skipped for classification");
                BatchAsnLookup::Failed
            }
        };
        lookups.insert(remote_ip, result);
    }
    lookups
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
            (observation.client_ip == client_ip
                || same_batch_device(batch, client_ip, &observation.client_ip, at_ms))
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

// Link DNS across IPv4/IPv6 only when this batch identifies both addresses
// unambiguously by the same MAC. An answer shared by other clients is insufficient.
fn same_batch_device(batch: &TelemetryBatch, left: &[u8], right: &[u8], at_ms: u64) -> bool {
    let owners = |ip: &[u8]| {
        let mut macs = batch
            .device_observations
            .iter()
            .filter(|item| item.ip == ip && item.last_seen_unix_ms.abs_diff(at_ms) <= 300_000)
            .map(|item| item.mac.as_slice())
            .chain(
                batch
                    .flows
                    .iter()
                    .filter(|flow| {
                        flow.client_ip == ip
                            && flow.first_seen_unix_ms <= at_ms
                            && flow.last_seen_unix_ms >= at_ms
                    })
                    .map(|flow| flow.client_mac.as_slice()),
            )
            .filter(|mac| mac.len() == 6 && mac[0] & 1 == 0 && mac.iter().any(|byte| *byte != 0))
            .collect::<Vec<_>>();
        macs.sort_unstable();
        macs.dedup();
        (macs.len() == 1).then(|| macs[0])
    };
    owners(left).is_some_and(|mac| owners(right) == Some(mac))
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
        .route("/v1/ingest/samples", post(samples))
        .route("/v1/agent/policies/stream", get(agent_policy_stream));
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

async fn agent_policy_stream(
    State(state): State<CollectorState>,
    identity: AgentIdentity,
    websocket: WebSocketUpgrade,
) -> Response {
    if let Err(error) =
        state
            .policy_hub
            .refresh_gateway(&state.policy_service, &identity.gateway_id, false)
    {
        tracing::error!(gateway_id = identity.gateway_id, %error, "could not build initial policy snapshot");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    websocket
        .max_message_size(netqmon_protocol::policy::POLICY_MAX_FRAME_BYTES)
        .max_frame_size(netqmon_protocol::policy::POLICY_MAX_FRAME_BYTES)
        .on_upgrade(move |mut socket| async move {
            // Register only after the upgrade actually succeeded; a rejected or
            // dropped handshake must not replace a live agent session.
            let session = match state.policy_hub.register(&identity.gateway_id) {
                Ok(session) => session,
                Err(error) => {
                    tracing::error!(gateway_id = identity.gateway_id, %error, "could not register policy stream");
                    let _ = socket
                        .send(axum::extract::ws::Message::Close(Some(
                            axum::extract::ws::CloseFrame {
                                code: 1011,
                                reason: "policy hub unavailable".into(),
                            },
                        )))
                        .await;
                    return;
                }
            };
            policy::push::run_socket(
                socket,
                Arc::clone(&state.policy_service),
                state.policy_hub.clone(),
                session,
            )
            .await;
        })
}

fn internal_router(state: CollectorState) -> Router {
    Router::new()
        .route("/internal/health", get(health))
        .route("/internal/realtime/stream", get(realtime_stream))
        .merge(auth::router())
        .merge(icons::router())
        .merge(policy::router())
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
        Err(TelemetryIngestError::ClassifierUnavailable(classifier_error)) => {
            tracing::debug!(%classifier_error, "deferring telemetry until classifier is ready");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "classifier unavailable; retry telemetry batch",
            )
        }
        Err(TelemetryIngestError::Storage(storage_error)) => {
            tracing::warn!(%storage_error, "telemetry persistence failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "telemetry persistence failed",
            )
        }
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
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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

fn flow_sample_matching_enabled_from_env(dpi_enabled: bool) -> Result<bool, ConfigError> {
    match env::var("NETQMON_FLOW_SAMPLE_MATCHING_ENABLED") {
        Ok(value) => match value.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(ConfigError(
                "NETQMON_FLOW_SAMPLE_MATCHING_ENABLED must be true or false".into(),
            )),
        },
        Err(env::VarError::NotPresent) => Ok(dpi_enabled),
        Err(_) => Err(ConfigError(
            "NETQMON_FLOW_SAMPLE_MATCHING_ENABLED is not valid Unicode".into(),
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
fn queue_policy_flow_decisions(
    hub: &PolicyHub,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
) {
    let Some(bundle) = hub.current_bundle(&batch.gateway_id) else {
        return;
    };
    let PolicyWireFrame::PolicySnapshot {
        controller_epoch,
        config_revision,
        policies,
        ..
    } = &bundle.frame
    else {
        return;
    };
    let now = policy::push::now_ms();
    let (application_block_supported, application_limit_supported) =
        hub.flow_capabilities(&batch.gateway_id);
    for (index, flow) in batch.flows.iter().enumerate() {
        tracing::debug!(
            target: "netqmon_collector::policy::flow_trace",
            gateway_id = batch.gateway_id,
            flow_scope = flow.scope,
            flow_lifecycle = flow.lifecycle,
            flow_packets = flow.packets,
            flow_upload_bytes = flow.upload_bytes,
            flow_download_bytes = flow.download_bytes,
            policy_flow_id = %flow.policy_flow_id,
            client_mac_bytes = flow.client_mac.len(),
            "received policy flow context"
        );
        let Some(policy_flow_id) =
            (!flow.policy_flow_id.is_empty()).then_some(flow.policy_flow_id.as_str())
        else {
            continue;
        };
        // Active/idle lifecycle notifications carry the observation time rather than
        // the flow's original sampling interval. They have no new classifier
        // evidence and must not revoke a still-leased exact verdict merely
        // because the sample lookup cannot overlap that synthetic interval.
        // End notifications, real packet deltas, and late classifier results
        // continue through the normal evaluation/revocation path.
        if matches!(
            FlowLifecycle::try_from(flow.lifecycle),
            Ok(FlowLifecycle::Active | FlowLifecycle::Idle)
        ) && flow.packets == 0
            && flow.upload_bytes == 0
            && flow.download_bytes == 0
        {
            continue;
        }
        let is_ended = flow.lifecycle == FlowLifecycle::Ended as i32;
        let is_internet = flow.scope == FlowScope::Internet as i32;
        let Some(client_mac) = canonical_mac(&flow.client_mac) else {
            hub.forget_flow_context(&batch.gateway_id, &batch.boot_id, policy_flow_id);
            if is_ended || !is_internet {
                let _ = hub.revoke_flow_if_active(
                    &batch.gateway_id,
                    &batch.boot_id,
                    controller_epoch,
                    *config_revision,
                    policy_flow_id,
                    now,
                );
            }
            continue;
        };
        if is_ended || !is_internet {
            hub.forget_flow_context(&batch.gateway_id, &batch.boot_id, policy_flow_id);
            let _ = hub.revoke_flow_if_active(
                &batch.gateway_id,
                &batch.boot_id,
                controller_epoch,
                *config_revision,
                policy_flow_id,
                now,
            );
            continue;
        }
        let Some(attribution) = attributions.get(index) else {
            continue;
        };
        tracing::debug!(
            target: "netqmon_collector::policy::flow_trace",
            gateway_id = batch.gateway_id,
            boot_id = batch.boot_id,
            config_revision,
            policy_flow_id,
            classification_at_ms = now,
            client_port = flow.client_port,
            ip_version = flow.ip_version,
            protocol = flow.protocol,
            direction = flow.direction,
            application_id = attribution.application_id,
            application_confidence = attribution.application_confidence,
            "classified policy flow"
        );
        let request = policy::PolicyPreviewRequest {
            gateway_id: batch.gateway_id.clone(),
            client_mac,
            application_id: attribution.application_id.clone(),
            category_id: attribution.category_id.clone(),
            application_confidence: attribution.application_confidence,
            scope: "internet".to_owned(),
            at_ms: now,
        };
        let context_generation = hub.remember_flow_context(
            &batch.gateway_id,
            &batch.boot_id,
            policy_flow_id,
            flow.protocol,
            request.clone(),
            now,
        );
        // This evaluation selects the intended rule. The Agent still verifies its
        // runtime capability and policy revision before applying any command.
        let evaluated = policy::evaluate_preview(
            &request,
            policies,
            application_block_supported,
            application_limit_supported,
        );
        let (verdict, policy_ids) = policy::flow_command_decision(&evaluated);
        if let Some(verdict) = verdict.filter(|_| !policy_ids.is_empty() && policy_ids.len() <= 16)
            && let Some(ttl_ms) = match flow.protocol {
                17 => Some(30_000),
                6 => Some(120_000),
                _ => None,
            }
            && let Some(expires_at_ms) =
                policy::flow_verdict_expiry(&bundle.frame, &policy_ids, now, ttl_ms)
        {
            let command_id = uuid::Uuid::new_v4().to_string();
            tracing::debug!(
                target: "netqmon_collector::policy::flow_trace",
                command_id,
                gateway_id = batch.gateway_id,
                boot_id = batch.boot_id,
                config_revision,
                policy_flow_id,
                classification_at_ms = now,
                command_issued_at_ms = now,
                client_port = flow.client_port,
                ip_version = flow.ip_version,
                protocol = flow.protocol,
                direction = flow.direction,
                ?verdict,
                operation = "Upsert",
                policy_ids = ?policy_ids,
                "evaluated application flow command"
            );
            let command = PolicyWireFrame::FlowCommand {
                wire_version: POLICY_WIRE_VERSION,
                gateway_id: batch.gateway_id.clone(),
                boot_id: batch.boot_id.clone(),
                controller_epoch: controller_epoch.clone(),
                config_revision: *config_revision,
                command_id,
                policy_flow_id: policy_flow_id.to_owned(),
                operation: FlowCommandOperation::Upsert,
                verdict: Some(verdict),
                policy_ids,
                expires_at_ms,
                issued_at_ms: now,
            };
            let queued = context_generation.map_or_else(
                || Err("flow evaluation context backpressure".to_owned()),
                |generation| hub.queue_flow_command_for_context(command, generation),
            );
            if let Err(error) = queued {
                tracing::warn!(gateway_id = batch.gateway_id, policy_flow_id, %error, "could not queue application flow command");
            }
        } else if let Err(error) = hub.revoke_flow_if_active(
            &batch.gateway_id,
            &batch.boot_id,
            controller_epoch,
            *config_revision,
            policy_flow_id,
            now,
        ) {
            tracing::warn!(gateway_id = batch.gateway_id, policy_flow_id, %error, "could not queue application flow revoke");
        }
    }
}

fn canonical_mac(value: &[u8]) -> Option<String> {
    (value.len() == 6).then(|| {
        value
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

#[cfg(test)]
fn apply_sample_result(
    inner: &mut CollectorInner,
    cached: &dpi::CachedResult,
) -> Result<Vec<(TelemetryBatch, FlowAttribution)>, StorageError> {
    let batch = sample_batch(cached);
    let mut service_bindings = std::mem::take(&mut inner.service_bindings);
    let classified = classify_batch(
        &inner.storage,
        &inner.classifier,
        inner.geo_provider.as_ref(),
        &mut service_bindings,
        &inner.dns_domains,
        &inner.favicon_endpoints,
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: cached.result.clone(),
            signatures: cached.signatures.clone(),
        })],
        false,
    );
    inner.service_bindings = service_bindings;
    let attributions = match classified {
        Ok(attributions) => attributions,
        Err(TelemetryIngestError::ClassifierUnavailable(classifier_error)) => {
            tracing::debug!(%classifier_error, "skipping late DPI update while classifier is unavailable");
            return Ok(Vec::new());
        }
        Err(TelemetryIngestError::Storage(error)) => return Err(error),
    };
    commit_sample_result(inner, cached, &batch, &attributions)
}

fn sample_batch(cached: &dpi::CachedResult) -> TelemetryBatch {
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
        policy_flow_id: cached.policy_flow_ids.first().cloned().unwrap_or_default(),
        ..Default::default()
    };
    TelemetryBatch {
        gateway_id: cached.gateway.clone(),
        boot_id: cached.boot.clone(),
        sent_at: cached.last_packet_ms,
        flows: vec![flow],
        ..Default::default()
    }
}

fn process_sample(
    shared: &Arc<Mutex<CollectorInner>>,
    cached: &dpi::CachedResult,
    _processing_guard: &MutexGuard<'_, ()>,
) -> Result<Vec<(TelemetryBatch, FlowAttribution)>, StorageError> {
    let batch = sample_batch(cached);
    let (mut work, domains) = {
        let mut inner = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let domains = resolve_batch_domains(&inner.storage, &batch)?;
        (ClassificationWork::take(&mut inner), domains)
    };
    let classified = classify_resolved_batch(
        &work.classifier,
        work.geo_provider.as_ref(),
        &mut work.service_bindings,
        &work.dns_domains,
        &work.favicon_endpoints,
        &batch,
        &[Some(dpi::SampleAnalysis {
            dpi: cached.result.clone(),
            signatures: cached.signatures.clone(),
        })],
        false,
        &domains,
    );
    let mut inner = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    work.restore(&mut inner);
    match classified {
        Ok(attributions) => commit_sample_result(&mut inner, cached, &batch, &attributions),
        Err(TelemetryIngestError::ClassifierUnavailable(error)) => {
            tracing::debug!(%error, "skipping late DPI update while classifier is unavailable");
            Ok(Vec::new())
        }
        Err(TelemetryIngestError::Storage(error)) => Err(error),
    }
}

fn commit_sample_result(
    inner: &mut CollectorInner,
    cached: &dpi::CachedResult,
    batch: &TelemetryBatch,
    attributions: &[FlowAttribution],
) -> Result<Vec<(TelemetryBatch, FlowAttribution)>, StorageError> {
    inner
        .storage
        .reclassify_flow(&cached.gateway, &batch.flows[0], &attributions[0])?;
    let contexts = inner
        .policy_flow_contexts
        .matching(cached, std::time::Instant::now())
        .into_iter()
        .map(|context| {
            let mut decision_batch = batch.clone();
            decision_batch.flows[0] = context;
            (decision_batch, attributions[0].clone())
        })
        .collect::<Vec<_>>();
    let context_flow_ids = contexts
        .iter()
        .flat_map(|(batch, _)| batch.flows.iter().map(|flow| flow.policy_flow_id.clone()))
        .collect::<Vec<_>>();
    tracing::debug!(
        target: "netqmon_collector::policy::flow_trace",
        gateway_id = cached.gateway,
        boot_id = cached.boot,
        flow_ids = ?cached.policy_flow_ids,
        context_flow_ids = ?context_flow_ids,
        sample_ip_version = cached.key.ip_version,
        sample_protocol = cached.key.protocol,
        sample_client_ip = ?cached.key.client_ip,
        sample_client_port = cached.key.client_port,
        sample_remote_ip = ?cached.key.remote_ip,
        sample_remote_port = cached.key.remote_port,
        sample_first_seen_unix_ms = cached.key.first_seen_unix_ms,
        sample_last_packet_ms = cached.last_packet_ms,
        context_count = contexts.len(),
        application_id = %attributions[0].application_id,
        application_confidence = attributions[0].application_confidence,
        classification_reason = %attributions[0].reason,
        "completed asynchronous flow sample classification"
    );
    Ok(contexts)
}
