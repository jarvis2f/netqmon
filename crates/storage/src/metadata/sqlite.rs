use std::path::Path;

use netqmon_protocol::v1::TelemetryBatch;

use super::{DeviceAddressRecord, DeviceRecord, GatewayDetails, MetadataStore, OutboxRecord};
use crate::{
    DeviceEvidenceRecord, DeviceIdentityUpdate, FlowAttribution, GatewayRecord, PersistDisposition,
    RetentionPolicy, SessionRecord, SqliteStorage, StorageError, StorageResult, UserRecord,
};

/// SQLite-backed metadata and outbox store.
#[derive(Debug)]
pub struct SqliteMetadataStore {
    inner: SqliteStorage,
}

impl SqliteMetadataStore {
    /// Opens the SQLite metadata database and applies its schema.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        SqliteStorage::open(path)
            .map(|inner| Self { inner })
            .map_err(StorageError::from)
    }

    /// Opens an in-memory SQLite metadata database.
    ///
    /// # Errors
    /// Returns an error if the database cannot be initialized.
    pub fn open_in_memory() -> StorageResult<Self> {
        SqliteStorage::open_in_memory()
            .map(|inner| Self { inner })
            .map_err(StorageError::from)
    }

    pub fn from_storage(inner: SqliteStorage) -> Self {
        Self { inner }
    }
}

impl MetadataStore for SqliteMetadataStore {
    fn gateway(&self) -> StorageResult<Option<GatewayRecord>> {
        MetadataStore::gateway(&self.inner)
    }

    fn gateway_details(&self) -> StorageResult<Option<GatewayDetails>> {
        MetadataStore::gateway_details(&self.inner)
    }

    fn save_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        now_ms: u64,
    ) -> StorageResult<bool> {
        MetadataStore::save_gateway(
            &mut self.inner,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            now_ms,
        )
    }

    fn replace_stale_gateway(
        &mut self,
        gateway_id: &str,
        name: &str,
        agent_version: &str,
        agent_token_hash: &[u8],
        stale_before_ms: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        MetadataStore::replace_stale_gateway(
            &mut self.inner,
            gateway_id,
            name,
            agent_version,
            agent_token_hash,
            stale_before_ms,
            now_ms,
        )
    }

    fn admin_exists(&self) -> StorageResult<bool> {
        MetadataStore::admin_exists(&self.inner)
    }

    fn create_admin(
        &mut self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: u64,
    ) -> StorageResult<bool> {
        MetadataStore::create_admin(&mut self.inner, id, username, password_hash, now_ms)
    }

    fn user_by_username(&self, username: &str) -> StorageResult<Option<UserRecord>> {
        MetadataStore::user_by_username(&self.inner, username)
    }

    fn create_session(
        &mut self,
        user_id: &str,
        token_hash: &[u8],
        now_ms: u64,
        expires_at: u64,
    ) -> StorageResult<()> {
        MetadataStore::create_session(&mut self.inner, user_id, token_hash, now_ms, expires_at)
    }

    fn session(&self, token_hash: &[u8], now_ms: u64) -> StorageResult<Option<SessionRecord>> {
        MetadataStore::session(&self.inner, token_hash, now_ms)
    }

    fn delete_session(&mut self, token_hash: &[u8]) -> StorageResult<bool> {
        MetadataStore::delete_session(&mut self.inner, token_hash)
    }

    fn persist_classified_batch(
        &mut self,
        batch: &TelemetryBatch,
        attributions: &[FlowAttribution],
        device_identities: &[DeviceIdentityUpdate],
        received_at_ms: u64,
    ) -> StorageResult<PersistDisposition> {
        MetadataStore::persist_classified_batch(
            &mut self.inner,
            batch,
            attributions,
            device_identities,
            received_at_ms,
        )
    }

    fn append_reclassification(
        &mut self,
        gateway_id: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
    ) -> StorageResult<bool> {
        MetadataStore::append_reclassification(
            &mut self.inner,
            gateway_id,
            flow,
            attribution,
            now_ms,
        )
    }

    fn append_reclassification_with_latest(
        &mut self,
        gateway_id: &str,
        flow: &netqmon_protocol::v1::FlowDelta,
        attribution: &FlowAttribution,
        now_ms: u64,
        latest: Option<&super::AnalyticsFlow>,
    ) -> StorageResult<bool> {
        MetadataStore::append_reclassification_with_latest(
            &mut self.inner,
            gateway_id,
            flow,
            attribution,
            now_ms,
            latest,
        )
    }

    fn device_evidence(
        &self,
        gateway_id: &str,
        mac: &[u8],
    ) -> StorageResult<Vec<DeviceEvidenceRecord>> {
        MetadataStore::device_evidence(&self.inner, gateway_id, mac)
    }

    fn devices(&self, limit: u32, offset: u64) -> StorageResult<(Vec<DeviceRecord>, u64)> {
        MetadataStore::devices(&self.inner, limit, offset)
    }

    fn device(&self, id: i64) -> StorageResult<Option<DeviceRecord>> {
        MetadataStore::device(&self.inner, id)
    }

    fn device_addresses(&self, id: i64) -> StorageResult<Vec<DeviceAddressRecord>> {
        MetadataStore::device_addresses(&self.inner, id)
    }

    fn device_count(&self) -> StorageResult<u64> {
        MetadataStore::device_count(&self.inner)
    }

    fn resolve_domain(
        &self,
        gateway_id: &str,
        client_ip: &[u8],
        answer_ip: &[u8],
        at_ms: u64,
    ) -> StorageResult<Option<String>> {
        MetadataStore::resolve_domain(&self.inner, gateway_id, client_ip, answer_ip, at_ms)
    }

    fn load_retention_policy(&self) -> StorageResult<RetentionPolicy> {
        MetadataStore::load_retention_policy(&self.inner)
    }

    fn save_retention_policy(
        &mut self,
        policy: &RetentionPolicy,
        now_ms: u64,
    ) -> StorageResult<()> {
        MetadataStore::save_retention_policy(&mut self.inner, policy, now_ms)
    }

    fn active_flow_count(&self) -> StorageResult<i64> {
        MetadataStore::active_flow_count(&self.inner)
    }

    fn run_metadata_retention(
        &mut self,
        now_ms: u64,
        policy: RetentionPolicy,
    ) -> StorageResult<()> {
        MetadataStore::run_metadata_retention(&mut self.inner, now_ms, policy)
    }

    fn outbox_batch(&self, limit: u32) -> StorageResult<Vec<OutboxRecord>> {
        MetadataStore::outbox_batch(&self.inner, limit)
    }

    fn acknowledge_outbox(&mut self, id: i64) -> StorageResult<()> {
        MetadataStore::acknowledge_outbox(&mut self.inner, id)
    }

    fn acknowledge_outbox_with_completed_flows(
        &mut self,
        id: i64,
        completed_flows: &[super::CompletedFlowCheckpoint],
    ) -> StorageResult<()> {
        MetadataStore::acknowledge_outbox_with_completed_flows(&mut self.inner, id, completed_flows)
    }

    fn acknowledge_outbox_batch(
        &mut self,
        ids: &[i64],
        completed_flows: &[super::CompletedFlowCheckpoint],
    ) -> StorageResult<()> {
        MetadataStore::acknowledge_outbox_batch(&mut self.inner, ids, completed_flows)
    }

    fn outbox_depth(&self) -> StorageResult<u64> {
        MetadataStore::outbox_depth(&self.inner)
    }

    fn outbox_oldest_age_ms(&self, now_ms: u64) -> StorageResult<u64> {
        MetadataStore::outbox_oldest_age_ms(&self.inner, now_ms)
    }

    fn metadata_database_size_bytes(&self) -> StorageResult<u64> {
        MetadataStore::metadata_database_size_bytes(&self.inner)
    }
}
