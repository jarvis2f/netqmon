use std::ops::{Deref, DerefMut};
#[cfg(feature = "analytics-duckdb")]
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use netqmon_protocol::v1::{FlowDelta, TelemetryBatch};

use crate::analytics::{
    AnalyticsBatch, AnalyticsStore, ApplyBatchResult, FlowPage, FlowQuery, GeoTraffic,
    SummaryQuery, TrafficBreakdown, TrafficBreakdownQuery, TrafficPoint, TrafficQuery,
};
use crate::metadata::{
    CompletedFlowCheckpoint, DeviceAddressRecord, DeviceRecord, GatewayDetails, MetadataStore,
    SqliteMetadataStore,
};
use crate::{
    DeviceEvidenceRecord, DeviceIdentityUpdate, FlowAttribution, GatewayRecord, PersistDisposition,
    RetentionPolicy, SessionRecord, StorageError, StorageResult, UserRecord,
};

/// The configured analytics implementation. Metadata always remains SQLite.
#[derive(Debug)]
pub enum AnalyticsBackend {
    #[cfg(feature = "analytics-duckdb")]
    DuckDb(crate::analytics::duckdb::DuckDbAnalyticsStore),
    #[cfg(feature = "analytics-clickhouse")]
    ClickHouse(crate::analytics::clickhouse::ClickHouseAnalyticsStore),
    #[cfg(test)]
    AnalyticsFailure,
}

impl AnalyticsBackend {
    #[cfg(feature = "analytics-duckdb")]
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn open_duckdb(path: impl AsRef<Path>) -> StorageResult<Self> {
        crate::analytics::duckdb::DuckDbAnalyticsStore::open(path).map(Self::DuckDb)
    }

    #[cfg(feature = "analytics-duckdb")]
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn open_duckdb_in_memory() -> StorageResult<Self> {
        crate::analytics::duckdb::DuckDbAnalyticsStore::open_in_memory().map(Self::DuckDb)
    }

    #[cfg(feature = "analytics-clickhouse")]
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn open_clickhouse(config: crate::ClickHouseConfig) -> StorageResult<Self> {
        crate::analytics::clickhouse::ClickHouseAnalyticsStore::open(config).map(Self::ClickHouse)
    }

    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => AnalyticsStore::backend_name(store),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => AnalyticsStore::backend_name(store),
            #[cfg(test)]
            Self::AnalyticsFailure => "test-failure",
        }
    }
}

impl AnalyticsStore for AnalyticsBackend {
    fn overview(&self, from: u64, to: u64) -> StorageResult<crate::analytics::AnalyticsOverview> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.overview(from, to),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.overview(from, to),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn apply_batch(&mut self, batch: &AnalyticsBatch) -> StorageResult<ApplyBatchResult> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.apply_batch(batch),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.apply_batch(batch),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn apply_batches(
        &mut self,
        batches: &[AnalyticsBatch],
    ) -> StorageResult<Vec<ApplyBatchResult>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.apply_batches(batches),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.apply_batches(batches),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn traffic_series(&self, query: &TrafficQuery) -> StorageResult<Vec<TrafficPoint>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.traffic_series(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.traffic_series(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn traffic_breakdown(
        &self,
        query: &TrafficBreakdownQuery,
    ) -> StorageResult<Vec<TrafficBreakdown>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.traffic_breakdown(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.traffic_breakdown(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn flows(&self, query: &FlowQuery) -> StorageResult<FlowPage> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.flows(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.flows(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn flow_by_id(
        &self,
        gateway_id: &str,
        flow_id: &str,
    ) -> StorageResult<Option<crate::analytics::AnalyticsFlow>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.flow_by_id(gateway_id, flow_id),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.flow_by_id(gateway_id, flow_id),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn flow_by_tuple(
        &self,
        identity: &crate::analytics::AnalyticsFlowIdentity,
    ) -> StorageResult<Option<crate::analytics::AnalyticsFlow>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.flow_by_tuple(identity),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.flow_by_tuple(identity),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn application_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.application_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.application_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn organization_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.organization_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.organization_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn protocol_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.protocol_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.protocol_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn transport_protocol_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.transport_protocol_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.transport_protocol_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn category_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.category_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.category_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn domain_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.domain_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.domain_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn destination_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.destination_summary(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.destination_summary(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn client_traffic(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<crate::analytics::AnalyticsSummary>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.client_traffic(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.client_traffic(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn geo_traffic(&self, query: &SummaryQuery) -> StorageResult<Vec<GeoTraffic>> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.geo_traffic(query),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.geo_traffic(query),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn unknown_ratio(&self, since: u64) -> StorageResult<f64> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.unknown_ratio(since),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.unknown_ratio(since),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn rollup(&mut self, now: u64) -> StorageResult<u64> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.rollup(now),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.rollup(now),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn run_retention(&mut self, now: u64, policy: RetentionPolicy) -> StorageResult<()> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.run_retention(now, policy),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.run_retention(now, policy),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn database_size_bytes(&self) -> StorageResult<u64> {
        match self {
            #[cfg(feature = "analytics-duckdb")]
            Self::DuckDb(store) => store.database_size_bytes(),
            #[cfg(feature = "analytics-clickhouse")]
            Self::ClickHouse(store) => store.database_size_bytes(),
            #[cfg(test)]
            Self::AnalyticsFailure => Err(test_analytics_error()),
        }
    }

    fn backend_name(&self) -> &'static str {
        AnalyticsBackend::backend_name(self)
    }
}

#[cfg(test)]
fn test_analytics_error() -> StorageError {
    StorageError::Connection("injected analytics failure".to_owned())
}

/// Coordinates the SQLite metadata store and a separate analytics backend.
#[derive(Debug)]
pub struct Storage {
    metadata: SqliteMetadataStore,
    analytics: Arc<Mutex<AnalyticsBackend>>,
}

/// Read guard for the analytics backend. Queries lock only the backend and do
/// not need to hold the collector's state mutex.
pub struct AnalyticsReadGuard<'a>(MutexGuard<'a, AnalyticsBackend>);

impl Deref for AnalyticsReadGuard<'_> {
    type Target = dyn AnalyticsStore;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

pub struct AnalyticsMutGuard<'a>(MutexGuard<'a, AnalyticsBackend>);

impl Deref for AnalyticsMutGuard<'_> {
    type Target = dyn AnalyticsStore;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for AnalyticsMutGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl Storage {
    #[cfg(feature = "analytics-duckdb")]
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn open_in_memory() -> StorageResult<Self> {
        Ok(Self::from_stores(
            SqliteMetadataStore::open_in_memory()?,
            AnalyticsBackend::open_duckdb_in_memory()?,
        ))
    }

    #[cfg(feature = "analytics-duckdb")]
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn open(
        metadata_path: impl AsRef<Path>,
        analytics_path: impl AsRef<Path>,
    ) -> StorageResult<Self> {
        Ok(Self {
            metadata: SqliteMetadataStore::open(metadata_path)?,
            analytics: Arc::new(Mutex::new(AnalyticsBackend::open_duckdb(analytics_path)?)),
        })
    }

    pub fn from_stores(metadata: SqliteMetadataStore, analytics: AnalyticsBackend) -> Self {
        Self {
            metadata,
            analytics: Arc::new(Mutex::new(analytics)),
        }
    }

    pub fn metadata(&self) -> &dyn MetadataStore {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut dyn MetadataStore {
        &mut self.metadata
    }

    pub fn analytics(&self) -> AnalyticsReadGuard<'_> {
        AnalyticsReadGuard(
            self.analytics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn analytics_mut(&mut self) -> AnalyticsMutGuard<'_> {
        AnalyticsMutGuard(
            self.analytics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn analytics_backend_handle(&self) -> Arc<Mutex<AnalyticsBackend>> {
        Arc::clone(&self.analytics)
    }

    /// Applies and acknowledges at most `limit` committed SQLite outbox rows.
    /// A failed analytics write leaves its row in SQLite for retry.
    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn process_outbox(&mut self, limit: u32) -> StorageResult<u32> {
        let records = self.metadata.outbox_batch(limit)?;
        if records.is_empty() {
            return Ok(0);
        }
        let batches = records
            .iter()
            .map(|record| {
                AnalyticsBatch::decode(&record.payload).map_err(StorageError::Serialization)
            })
            .collect::<StorageResult<Vec<_>>>()?;
        self.analytics_mut().apply_batches(&batches)?;
        let ids = records.iter().map(|record| record.id).collect::<Vec<_>>();
        let completed_flows = batches
            .iter()
            .flat_map(|batch| batch.flows.iter())
            .filter(|flow| flow.ended_at.is_some())
            .map(|flow| CompletedFlowCheckpoint { flow: flow.clone() })
            .collect::<Vec<_>>();
        self.metadata
            .acknowledge_outbox_batch(&ids, &completed_flows)?;
        Ok(u32::try_from(records.len()).unwrap_or(u32::MAX))
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        self.metadata.gateway()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn gateway_details(&self) -> StorageResult<Option<GatewayDetails>> {
        self.metadata.gateway_details()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        self.metadata
            .save_gateway(gateway_id, name, agent_version, agent_token_hash, now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        self.metadata.replace_stale_gateway(
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            stale_before_ms,
            now_ms,
        )
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn admin_exists(&self) -> StorageResult<bool> {
        self.metadata.admin_exists()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        self.metadata
            .create_admin(id, username, password_hash, now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        self.metadata.user_by_username(username)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        self.metadata
            .create_session(user_id, token_hash, now_ms, expires_at)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        self.metadata.session(token_hash, now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        self.metadata.delete_session(token_hash)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        identities: &[DeviceIdentityUpdate],
        received_at: u64,
    ) -> StorageResult<PersistDisposition> {
        self.metadata
            .persist_classified_batch(batch, attributions, identities, received_at)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn persist_batch(
        &mut self,
        batch: &TelemetryBatch,
        received_at: u64,
    ) -> StorageResult<PersistDisposition> {
        self.persist_classified_batch(batch, &[], &[], received_at)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        self.metadata.device_evidence(gateway_id, mac)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn devices(&self, limit: u32, offset: u64) -> StorageResult<(Vec<DeviceRecord>, u64)> {
        self.metadata.devices(limit, offset)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn device(&self, id: i64) -> StorageResult<Option<DeviceRecord>> {
        self.metadata.device(id)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn device_addresses(&self, id: i64) -> StorageResult<Vec<DeviceAddressRecord>> {
        self.metadata.device_addresses(id)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn device_count(&self) -> StorageResult<u64> {
        self.metadata.device_count()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        self.metadata
            .resolve_domain(gateway_id, client_ip, answer_ip, at_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        self.metadata.load_retention_policy()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        self.metadata.save_retention_policy(policy, now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn run_retention(&mut self, now_ms: u64, policy: RetentionPolicy) -> StorageResult<()> {
        self.metadata.run_metadata_retention(now_ms, policy)?;
        self.analytics_mut().run_retention(now_ms, policy)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn roll_up_hour_and_day(&mut self, now_ms: u64) -> StorageResult<u64> {
        self.analytics_mut().rollup(now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn active_flow_count(&self) -> StorageResult<i64> {
        self.metadata.active_flow_count()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn unknown_ratio(&self, since_ms: u64) -> StorageResult<f64> {
        self.analytics().unknown_ratio(since_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn metadata_database_size_bytes(&self) -> StorageResult<u64> {
        self.metadata.metadata_database_size_bytes()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn analytics_database_size_bytes(&self) -> StorageResult<u64> {
        self.analytics().database_size_bytes()
    }

    pub fn analytics_backend(&self) -> &'static str {
        self.analytics().backend_name()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn outbox_depth(&self) -> StorageResult<u64> {
        self.metadata.outbox_depth()
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn outbox_oldest_age_ms(&self, now_ms: u64) -> StorageResult<u64> {
        self.metadata.outbox_oldest_age_ms(now_ms)
    }

    /// # Errors
    /// Returns a storage error if the underlying metadata or analytics operation fails.
    pub fn reclassify_flow(
        &mut self,
        gateway: &str,
        flow: &FlowDelta,
        attribution: &FlowAttribution,
    ) -> StorageResult<()> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        let identity = crate::analytics::AnalyticsFlowIdentity {
            gateway_id: gateway.to_owned(),
            ip_version: u8::try_from(flow.ip_version).unwrap_or_default(),
            protocol: u8::try_from(flow.protocol).unwrap_or_default(),
            client_ip: flow.client_ip.clone(),
            client_port: u16::try_from(flow.client_port).unwrap_or_default(),
            remote_ip: flow.remote_ip.clone(),
            remote_port: u16::try_from(flow.remote_port).unwrap_or_default(),
            started_at: flow.first_seen_unix_ms,
        };
        let latest_result = {
            let analytics = self.analytics();
            analytics.flow_by_tuple(&identity)
        };
        let latest = match latest_result {
            Ok(latest) => latest,
            Err(analytics_error) => {
                let queued = self.metadata.append_reclassification_with_latest(
                    gateway,
                    flow,
                    attribution,
                    now_ms,
                    None,
                )?;
                if queued {
                    return Ok(());
                }
                return Err(analytics_error);
            }
        };
        let _ = self.metadata.append_reclassification_with_latest(
            gateway,
            flow,
            attribution,
            now_ms,
            latest.as_ref(),
        )?;
        Ok(())
    }
}

#[cfg(all(test, feature = "analytics-duckdb"))]
mod tests {
    use super::*;

    #[test]
    fn analytics_failure_leaves_outbox_batch_for_retry() {
        let mut storage = Storage::from_stores(
            SqliteMetadataStore::open_in_memory().unwrap(),
            AnalyticsBackend::AnalyticsFailure,
        );
        storage
            .save_gateway("failure-gateway", "router", "test", &[7; 32], 10)
            .unwrap();
        let batch = TelemetryBatch {
            gateway_id: "failure-gateway".to_owned(),
            boot_id: "failure-boot".to_owned(),
            sequence: 1,
            sent_at: 10,
            ..TelemetryBatch::default()
        };
        assert_eq!(
            storage
                .persist_classified_batch(&batch, &[], &[], 10)
                .unwrap(),
            PersistDisposition::Accepted
        );

        assert!(storage.process_outbox(1).is_err());
        assert_eq!(storage.outbox_depth().unwrap(), 1);
    }
}
