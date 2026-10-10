use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::policy::{
    PolicyAckStatus, PolicyCapabilities as WireCapabilities, PolicyClientMetrics,
    PolicyDirectionMetrics, PolicyResult, PolicyResultDetails, PolicySnapshotEntry,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Serialize;
use uuid::Uuid;

use super::model::{
    MAX_GATEWAY_SPEC_BYTES, MAX_POLICY_COUNT, MAX_PUSH_BUNDLE_BYTES, MAX_SCHEDULE_COMPLEXITY,
    MAX_SPEC_BYTES, PolicyEvent, PolicyRecord, PolicySpecV1,
};
use super::repository::PolicyRepository;
use super::validation::{application_limits_overlap, schedule_projection_cost};

pub(crate) const DEFAULT_POLICY_DATABASE_PATH: &str = "/data/netqmon-policies.db";
const PROJECTED_WINDOW_BYTES: u64 = 64;
const MAX_AUDIT_EVENTS: u32 = 100;

/// Identity of one authenticated Agent policy WebSocket session.
///
/// `connection_epoch` belongs to a single Collector process and
/// `connection_id` increases for every accepted stream within that process, so
/// the pair is unique for the lifetime of the persisted deployment row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionIdentity<'a> {
    connection_epoch: &'a str,
    connection_id: u64,
}

impl<'a> SessionIdentity<'a> {
    pub(crate) const fn new(connection_epoch: &'a str, connection_id: u64) -> Self {
        Self {
            connection_epoch,
            connection_id,
        }
    }
}

/// Outcome of a write that belongs to one authenticated Agent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionWrite {
    /// The write matched the current session and was committed.
    Applied,
    /// A newer session (or newer persisted state) owns the row; nothing changed.
    Superseded,
}

impl SessionWrite {
    #[cfg(test)]
    pub(crate) const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

fn session_write(affected_rows: usize) -> SessionWrite {
    if affected_rows == 0 {
        SessionWrite::Superseded
    } else {
        SessionWrite::Applied
    }
}

pub(crate) struct PolicyService {
    repository: PolicyRepository,
    last_metrics_prune_ms: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyPage {
    pub items: Vec<PolicyRecord>,
    pub total: u64,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub capabilities: PolicyCapabilities,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyCapabilities {
    pub enforcement_supported: bool,
    pub status: String,
    pub reason: String,
    pub client_block: String,
    pub client_limit: String,
    pub application_block: String,
    pub application_limit: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyDetail {
    pub policy: PolicyRecord,
    pub events: Vec<PolicyEvent>,
    pub desired_revision: u64,
    pub applied_revision: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyDeployment {
    pub gateway_id: String,
    pub desired_revision: u64,
    pub delivered_revision: u64,
    pub delivery_status: String,
    pub delivered_at_ms: Option<i64>,
    pub acknowledged_revision: u64,
    pub acknowledged_status: Option<String>,
    pub applied_revision: u64,
    pub status: String,
    pub last_error_code: Option<String>,
    pub last_error_message: Option<String>,
    pub last_reported_at_ms: Option<i64>,
    pub last_heartbeat_at_ms: Option<i64>,
    pub agent_connected: bool,
    pub agent_boot_id: Option<String>,
    pub controller_epoch: Option<String>,
    pub bundle_generation: u64,
    pub bundle_checksum: Option<String>,
    pub capabilities: PolicyCapabilities,
    pub policies: Vec<PolicyDeploymentStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyDeploymentStatus {
    pub policy_id: String,
    pub status: String,
    pub reason_code: Option<String>,
    pub message: Option<String>,
    pub details: Option<PolicyResultDetails>,
    pub traffic_metrics: Vec<PolicyClientMetrics>,
}

#[derive(Clone, Debug)]
pub(crate) struct MutationResult {
    pub policy: Option<PolicyRecord>,
    pub gateway_id: String,
    pub revision: u64,
    pub changed: bool,
}

#[derive(Debug)]
pub(crate) enum PolicyFailure {
    NotFound,
    RevisionConflict {
        current_revision: u64,
    },
    VersionConflict {
        current_revision: u64,
        current_version: u64,
    },
    LimitOverlapUnsupported,
    PolicyLimitExceeded,
    PolicyTooLarge,
    PolicyBundleTooLarge,
    ScheduleComplexityExceeded,
    Invalid {
        code: &'static str,
        message: String,
    },
    Store(String),
}

impl PolicyService {
    pub(crate) fn open_from_env() -> Result<Self, String> {
        let path = env::var_os("NETQMON_COLLECTOR_POLICY_DB_PATH").map_or_else(
            || PathBuf::from(DEFAULT_POLICY_DATABASE_PATH),
            PathBuf::from,
        );
        Self::open(&path)
    }

    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        Ok(Self {
            repository: PolicyRepository::open(path)?,
            last_metrics_prune_ms: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, String> {
        Ok(Self {
            repository: PolicyRepository::open_in_memory()?,
            last_metrics_prune_ms: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn agent_applied_revision(&self, gateway_id: &str) -> Result<u64, PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let revision = connection
            .query_row(
                "SELECT agent_applied_revision FROM policy_deployments WHERE gateway_id = ?1",
                [gateway_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(store_error)?;
        Ok(to_u64(revision))
    }

    pub(crate) fn snapshot(
        &self,
        gateway_id: &str,
    ) -> Result<(u64, Vec<PolicySnapshotEntry>), PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let revision = read_revision(&connection, gateway_id)?;
        let mut statement = connection
            .prepare(
                "SELECT id, spec_json FROM traffic_policies WHERE gateway_id = ?1 ORDER BY id ASC",
            )
            .map_err(store_error)?;
        let policies = statement
            .query_map([gateway_id], |row| {
                let id: String = row.get(0)?;
                let json: String = row.get(1)?;
                let spec = serde_json::from_str(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(PolicySnapshotEntry { id, spec })
            })
            .map_err(store_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(store_error)?;
        Ok((revision, policies))
    }

    pub(crate) fn mark_agent_connected(
        &self,
        gateway_id: &str,
        connection_epoch: &str,
        connection_id: u64,
    ) -> Result<SessionWrite, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        // Connection ids only increase within one Collector process. A different
        // controller epoch always wins so a Collector restart can reclaim the row.
        let updated = transaction
            .execute(
                "UPDATE policy_deployments SET agent_connected = 1,
                 agent_connection_epoch = ?2, agent_connection_id = ?3,
                 delivered_revision = 0, delivered_at_ms = NULL,
                 status = CASE WHEN desired_revision > reported_revision THEN 'pending' ELSE status END
                 WHERE gateway_id = ?1
                   AND (agent_connection_epoch IS NOT ?2 OR agent_connection_id <= ?3)",
                params![gateway_id, connection_epoch, to_i64(connection_id)],
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        Ok(session_write(updated))
    }

    pub(crate) fn record_delivery(
        &self,
        gateway_id: &str,
        session: SessionIdentity<'_>,
        revision: u64,
        delivered_at_ms: i64,
    ) -> Result<SessionWrite, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        let updated = transaction
            .execute(
                "UPDATE policy_deployments SET delivered_revision = ?1, delivered_at_ms = ?2
                 WHERE gateway_id = ?3
                   AND agent_connection_epoch = ?4 AND agent_connection_id = ?5
                   AND delivered_revision <= ?1",
                params![
                    to_i64(revision),
                    delivered_at_ms,
                    gateway_id,
                    session.connection_epoch,
                    to_i64(session.connection_id)
                ],
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        Ok(session_write(updated))
    }

    pub(crate) fn mark_agent_disconnected(
        &self,
        gateway_id: &str,
        connection_epoch: &str,
        connection_id: u64,
    ) -> Result<(), PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        // A superseded session must never clear the connected state of the
        // session that replaced it.
        connection
            .execute(
                "UPDATE policy_deployments SET agent_connected = 0,
                 status = CASE WHEN desired_revision = 0 THEN 'not_deployed' ELSE 'offline' END
                 WHERE gateway_id = ?1 AND agent_connection_epoch = ?2 AND agent_connection_id = ?3",
                params![gateway_id, connection_epoch, to_i64(connection_id)],
            )
            .map_err(store_error)?;
        Ok(())
    }

    pub(crate) fn record_health(
        &self,
        gateway_id: &str,
        session: SessionIdentity<'_>,
        boot_id: &str,
        controller_epoch: &str,
        agent_revision: u64,
        capabilities: &WireCapabilities,
        emergency_disabled: bool,
        reported_at_ms: i64,
    ) -> Result<SessionWrite, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        let desired_revision = read_revision(&transaction, gateway_id)?;
        let capabilities_json = serde_json::to_string(capabilities)
            .map_err(|error| PolicyFailure::Store(error.to_string()))?;
        let rollback = agent_revision > desired_revision;
        let error_code = if rollback {
            Some("revision_rollback_detected")
        } else if emergency_disabled {
            Some("emergency_disabled")
        } else {
            None
        };
        let error_message = error_code.map(|code| match code {
            "revision_rollback_detected" => {
                "agent has a persisted policy revision newer than the Collector database; explicitly republish policies".to_owned()
            }
            _ => "policies are locally disabled by the emergency marker".to_owned(),
        });
        let updated = transaction
            .execute(
                "UPDATE policy_deployments SET agent_connected = 1, agent_boot_id = ?1,
                 controller_epoch = ?2,
                 bundle_generation = CASE WHEN controller_epoch = ?2 THEN bundle_generation ELSE 0 END,
                 bundle_checksum = CASE WHEN controller_epoch = ?2 THEN bundle_checksum ELSE NULL END,
                 reported_revision = CASE WHEN controller_epoch IS NOT ?2 OR agent_boot_id IS NOT ?1 THEN 0 ELSE reported_revision END,
                 acknowledged_status = CASE WHEN controller_epoch IS NOT ?2 OR agent_boot_id IS NOT ?1 THEN NULL ELSE acknowledged_status END,
                 agent_applied_revision = MAX(agent_applied_revision, ?3),
                 capabilities_json = CASE
                     WHEN controller_epoch = ?2 AND agent_boot_id = ?1
                          AND ?3 < reported_revision THEN capabilities_json
                     ELSE ?4 END,
                 last_heartbeat_at_ms = ?5,
                 last_error_code = ?6, last_error_message = ?7,
                 status = CASE WHEN ?8 = 1 THEN 'failed'
                               WHEN (controller_epoch IS NOT ?2 OR agent_boot_id IS NOT ?1) AND desired_revision > 0 THEN 'pending'
                               WHEN desired_revision > reported_revision THEN 'pending'
                               ELSE status END
                 WHERE gateway_id = ?9
                   AND agent_connection_epoch = ?10 AND agent_connection_id = ?11",
                params![
                    boot_id,
                    controller_epoch,
                    to_i64(agent_revision),
                    capabilities_json,
                    reported_at_ms,
                    error_code,
                    error_message,
                    rollback || emergency_disabled,
                    gateway_id,
                    session.connection_epoch,
                    to_i64(session.connection_id)
                ],
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        Ok(session_write(updated))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_ack(
        &self,
        gateway_id: &str,
        session: SessionIdentity<'_>,
        boot_id: &str,
        controller_epoch: &str,
        config_revision: u64,
        bundle_generation: u64,
        checksum: &str,
        status: PolicyAckStatus,
        capabilities: &WireCapabilities,
        results: &[PolicyResult],
        reported_at_ms: i64,
    ) -> Result<SessionWrite, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        let desired_revision = read_revision(&transaction, gateway_id)?;
        let row = deployment_row(&transaction, gateway_id)?;
        // A frame from a session that has already been replaced must never
        // mutate the deployment row, even if its revision numbers look current.
        if row.agent_connection_epoch.as_deref() != Some(session.connection_epoch)
            || row.agent_connection_id != session.connection_id
            || config_revision < row.agent_applied_revision
            || (row.controller_epoch.as_deref() == Some(controller_epoch)
                && bundle_generation < row.bundle_generation)
        {
            transaction.commit().map_err(store_error)?;
            return Ok(SessionWrite::Superseded);
        }

        let results_json = serde_json::to_string(results)
            .map_err(|error| PolicyFailure::Store(error.to_string()))?;
        let capabilities_json = serde_json::to_string(capabilities)
            .map_err(|error| PolicyFailure::Store(error.to_string()))?;
        let ack_status_text = match status {
            PolicyAckStatus::Applied => "applied",
            PolicyAckStatus::Partial => "partial",
            PolicyAckStatus::Failed => "failed",
            PolicyAckStatus::Unsupported => "unsupported",
        };
        let status_text = match status {
            PolicyAckStatus::Applied if config_revision == desired_revision => "applied",
            PolicyAckStatus::Applied => "pending",
            PolicyAckStatus::Partial => "partial",
            PolicyAckStatus::Failed => "failed",
            PolicyAckStatus::Unsupported => "unsupported",
        };
        let error = results.iter().find(|result| {
            result.reason_code.is_some()
                && matches!(
                    result.status,
                    netqmon_protocol::policy::PolicyResultStatus::Failed
                )
        });
        let error_code = error.and_then(|result| result.reason_code.as_deref());
        let error_message = error.and_then(|result| result.message.as_deref());
        let updated = transaction
            .execute(
                "UPDATE policy_deployments SET agent_connected = 1, agent_boot_id = ?1,
                 controller_epoch = ?2, bundle_generation = ?3, bundle_checksum = ?4,
                 reported_revision = ?5,
                 acknowledged_status = ?6,
                 agent_applied_revision = CASE WHEN ?6 IN ('applied', 'partial') THEN MAX(agent_applied_revision, ?5) ELSE agent_applied_revision END,
                 applied_revision = CASE WHEN ?6 = 'applied' AND ?5 >= applied_revision THEN ?5 ELSE applied_revision END,
                 policy_results_json = ?7, capabilities_json = ?8,
                 last_reported_at_ms = ?9, last_heartbeat_at_ms = ?9,
                 last_error_code = ?10, last_error_message = ?11,
                 status = ?12 WHERE gateway_id = ?13
                   AND agent_connection_epoch = ?14 AND agent_connection_id = ?15",
                params![
                    boot_id,
                    controller_epoch,
                    to_i64(bundle_generation),
                    checksum,
                    to_i64(config_revision),
                    ack_status_text,
                    results_json,
                    capabilities_json,
                    reported_at_ms,
                    error_code,
                    error_message,
                    status_text,
                    gateway_id,
                    session.connection_epoch,
                    to_i64(session.connection_id)
                ],
            )
            .map_err(store_error)?;
        if updated == 0 {
            // Nothing matched the authenticated session; do not touch any
            // dependent metric rows either.
            transaction.commit().map_err(store_error)?;
            return Ok(SessionWrite::Superseded);
        }
        if matches!(status, PolicyAckStatus::Applied | PolicyAckStatus::Partial) {
            transaction
                .execute(
                    "DELETE FROM policy_client_metrics WHERE gateway_id = ?1 AND policy_id NOT IN (
                         SELECT json_extract(value, '$.policy_id') FROM json_each(?2)
                         WHERE json_extract(value, '$.status') IN ('applied', 'degraded')
                     )",
                    params![gateway_id, results_json],
                )
                .map_err(store_error)?;
        }
        transaction.commit().map_err(store_error)?;
        Ok(session_write(updated))
    }

    pub(crate) fn record_metrics(
        &self,
        gateway_id: &str,
        session: SessionIdentity<'_>,
        boot_id: &str,
        sampled_at_ms: i64,
        metrics: &[PolicyClientMetrics],
    ) -> Result<SessionWrite, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        let deployment = deployment_row(&transaction, gateway_id)?;
        if !deployment.agent_connected
            || deployment.agent_boot_id.as_deref() != Some(boot_id)
            || deployment.agent_connection_epoch.as_deref() != Some(session.connection_epoch)
            || deployment.agent_connection_id != session.connection_id
        {
            transaction.commit().map_err(store_error)?;
            return Ok(SessionWrite::Superseded);
        }
        let now = now_ms();
        if sampled_at_ms > now.saturating_add(30_000) {
            transaction.commit().map_err(store_error)?;
            return Ok(SessionWrite::Superseded);
        }
        for metric in metrics {
            let upload = metric.upload.as_ref();
            let download = metric.download.as_ref();
            transaction
                .execute(
                    "INSERT INTO policy_client_metrics(
                        gateway_id, policy_id, mac,
                        upload_interface, upload_bytes, upload_packets, upload_drops, upload_overlimits,
                        download_interface, download_bytes, download_packets, download_drops, download_overlimits,
                        sampled_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                     ON CONFLICT(gateway_id, policy_id, mac) DO UPDATE SET
                        upload_interface = excluded.upload_interface,
                        upload_bytes = excluded.upload_bytes,
                        upload_packets = excluded.upload_packets,
                        upload_drops = excluded.upload_drops,
                        upload_overlimits = excluded.upload_overlimits,
                        download_interface = excluded.download_interface,
                        download_bytes = excluded.download_bytes,
                        download_packets = excluded.download_packets,
                        download_drops = excluded.download_drops,
                        download_overlimits = excluded.download_overlimits,
                        sampled_at_ms = excluded.sampled_at_ms
                     WHERE excluded.sampled_at_ms >= policy_client_metrics.sampled_at_ms",
                    params![
                        gateway_id,
                        metric.policy_id,
                        metric.mac,
                        upload.map(|value| value.interface.as_str()),
                        upload.and_then(|value| sql_count(value.bytes)),
                        upload.and_then(|value| sql_count(value.packets)),
                        upload.and_then(|value| sql_count(value.drops)),
                        upload.and_then(|value| sql_count(value.overlimits)),
                        download.map(|value| value.interface.as_str()),
                        download.and_then(|value| sql_count(value.bytes)),
                        download.and_then(|value| sql_count(value.packets)),
                        download.and_then(|value| sql_count(value.drops)),
                        download.and_then(|value| sql_count(value.overlimits)),
                        sampled_at_ms,
                    ],
                )
                .map_err(store_error)?;
        }
        let cutoff_ms = now.saturating_sub(24 * 60 * 60 * 1000);
        let should_prune = sampled_at_ms < cutoff_ms
            || self
                .last_metrics_prune_ms
                .lock()
                .map_or(true, |mut last_prune| {
                    let due = last_prune
                        .get(gateway_id)
                        .is_none_or(|last| now.saturating_sub(*last) >= 60_000);
                    if due {
                        last_prune.insert(gateway_id.to_owned(), now);
                    }
                    due
                });
        if should_prune {
            transaction
                .execute(
                    "DELETE FROM policy_client_metrics WHERE gateway_id = ?1 AND sampled_at_ms < ?2",
                    params![gateway_id, cutoff_ms],
                )
                .map_err(store_error)?;
        }
        transaction.commit().map_err(store_error)?;
        Ok(SessionWrite::Applied)
    }

    pub(crate) fn republish(
        &self,
        gateway_id: &str,
        actor_user_id: &str,
    ) -> Result<u64, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, gateway_id)?;
        let revision = read_revision(&transaction, gateway_id)?;
        let remote_revision = deployment_row(&transaction, gateway_id)?.agent_applied_revision;
        let next_revision = revision.max(remote_revision).saturating_add(1);
        if next_revision > netqmon_protocol::policy::MAX_SAFE_JSON_INTEGER {
            return Err(PolicyFailure::Store("policy revision exhausted".to_owned()));
        }
        transaction
            .execute(
                "UPDATE policy_gateways SET desired_revision = ?1 WHERE gateway_id = ?2",
                params![to_i64(next_revision), gateway_id],
            )
            .map_err(store_error)?;
        transaction
            .execute(
                "UPDATE policy_deployments SET desired_revision = ?1, status =
                 CASE WHEN agent_connected = 1 THEN 'pending' ELSE 'offline' END,
                 last_error_code = NULL, last_error_message = NULL WHERE gateway_id = ?2",
                params![to_i64(next_revision), gateway_id],
            )
            .map_err(store_error)?;
        transaction
            .execute(
                "INSERT INTO policy_events(gateway_id, policy_id, action, actor_user_id, before_json, after_json, revision, created_at_ms)
                 VALUES (?1, NULL, 'republish', ?2, NULL, NULL, ?3, ?4)",
                params![gateway_id, actor_user_id, to_i64(next_revision), now_ms()],
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        Ok(next_revision)
    }

    pub(crate) fn list(
        &self,
        gateway_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<PolicyPage, PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let offset = u64::from(page.saturating_sub(1)) * u64::from(page_size);
        let total = connection
            .query_row(
                "SELECT COUNT(*) FROM traffic_policies WHERE gateway_id = ?1",
                [gateway_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(store_error)?;
        let mut statement = connection
            .prepare(
                "SELECT id, created_at_ms, updated_at_ms, version, spec_json
                 FROM traffic_policies WHERE gateway_id = ?1
                 ORDER BY priority ASC, id ASC LIMIT ?2 OFFSET ?3",
            )
            .map_err(store_error)?;
        let mut items = statement
            .query_map(
                params![gateway_id, i64::from(page_size), to_i64(offset)],
                map_record,
            )
            .map_err(store_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(store_error)?;
        let (desired_revision, applied_revision, deployment_row) =
            read_deployment(&connection, gateway_id)?;
        if let Some(row) = &deployment_row {
            for item in &mut items {
                let execution =
                    policy_execution(&item.id, item.spec.enabled, desired_revision, row);
                item.execution_status = execution.status;
                item.execution_reason_code = execution.reason_code;
                item.execution_message = execution.message;
                item.execution_details = execution.details;
            }
        }
        Ok(PolicyPage {
            items,
            total: to_u64(total),
            desired_revision,
            applied_revision,
            capabilities: capabilities(deployment_row.as_ref()),
        })
    }

    pub(crate) fn detail(&self, id: &str) -> Result<PolicyDetail, PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let mut record = connection
            .query_row(
                "SELECT id, created_at_ms, updated_at_ms, version, spec_json
                 FROM traffic_policies WHERE id = ?1",
                [id],
                map_record,
            )
            .optional()
            .map_err(store_error)?
            .ok_or(PolicyFailure::NotFound)?;
        let mut statement = connection
            .prepare(
                "SELECT event_id, action, actor_user_id, before_json, after_json, revision, created_at_ms
                 FROM policy_events WHERE policy_id = ?1
                 ORDER BY event_id DESC LIMIT ?2",
            )
            .map_err(store_error)?;
        let events = statement
            .query_map(params![id, i64::from(MAX_AUDIT_EVENTS)], map_event)
            .map_err(store_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(store_error)?;
        let (desired_revision, applied_revision, deployment_row) =
            read_deployment(&connection, &record.spec.gateway_id)?;
        if let Some(row) = &deployment_row {
            let execution =
                policy_execution(&record.id, record.spec.enabled, desired_revision, row);
            record.execution_status = execution.status;
            record.execution_reason_code = execution.reason_code;
            record.execution_message = execution.message;
            record.execution_details = execution.details;
        }
        Ok(PolicyDetail {
            policy: record,
            events,
            desired_revision,
            applied_revision,
        })
    }

    pub(crate) fn deployment(&self, gateway_id: &str) -> Result<PolicyDeployment, PolicyFailure> {
        let connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let (desired_revision, applied_revision, deployment_row) =
            read_deployment(&connection, gateway_id)?;
        let traffic_metrics = read_traffic_metrics(&connection, gateway_id)?;
        let mut statement = connection
            .prepare(
                "SELECT id, spec_json FROM traffic_policies WHERE gateway_id = ?1 ORDER BY priority ASC, id ASC",
            )
            .map_err(store_error)?;
        let policies = statement
            .query_map([gateway_id], |row| {
                let id: String = row.get(0)?;
                let spec_json: String = row.get(1)?;
                let spec: PolicySpecV1 = serde_json::from_str(&spec_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                let execution = policy_execution_from_values(
                    &id,
                    spec.enabled,
                    desired_revision,
                    deployment_row.as_ref(),
                );
                Ok(PolicyDeploymentStatus {
                    policy_id: id.clone(),
                    status: execution.status,
                    reason_code: execution.reason_code,
                    message: execution.message,
                    details: execution.details,
                    traffic_metrics: traffic_metrics.get(&id).cloned().unwrap_or_default(),
                })
            })
            .map_err(store_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(store_error)?;
        Ok(PolicyDeployment {
            gateway_id: gateway_id.to_owned(),
            desired_revision,
            delivered_revision: deployment_row
                .as_ref()
                .map_or(0, |row| row.delivered_revision),
            delivery_status: delivery_status(desired_revision, deployment_row.as_ref()),
            delivered_at_ms: deployment_row.as_ref().and_then(|row| row.delivered_at_ms),
            acknowledged_revision: deployment_row
                .as_ref()
                .map_or(0, |row| row.reported_revision),
            acknowledged_status: deployment_row
                .as_ref()
                .and_then(|row| row.acknowledged_status.clone()),
            applied_revision,
            status: deployment_status(desired_revision, deployment_row.as_ref()),
            last_error_code: deployment_row
                .as_ref()
                .and_then(|row| row.last_error_code.clone()),
            last_error_message: deployment_row
                .as_ref()
                .and_then(|row| row.last_error_message.clone()),
            last_reported_at_ms: deployment_row
                .as_ref()
                .and_then(|row| row.last_reported_at_ms),
            last_heartbeat_at_ms: deployment_row
                .as_ref()
                .and_then(|row| row.last_heartbeat_at_ms),
            agent_connected: deployment_row
                .as_ref()
                .is_some_and(|row| row.agent_connected),
            agent_boot_id: deployment_row
                .as_ref()
                .and_then(|row| row.agent_boot_id.clone()),
            controller_epoch: deployment_row
                .as_ref()
                .and_then(|row| row.controller_epoch.clone()),
            bundle_generation: deployment_row
                .as_ref()
                .map_or(0, |row| row.bundle_generation),
            bundle_checksum: deployment_row
                .as_ref()
                .and_then(|row| row.bundle_checksum.clone()),
            capabilities: capabilities(deployment_row.as_ref()),
            policies,
        })
    }

    pub(crate) fn create(
        &self,
        spec: &PolicySpecV1,
        actor_user_id: &str,
        expected_revision: u64,
    ) -> Result<MutationResult, PolicyFailure> {
        let spec_json = serialized_spec(spec)?;
        check_one_spec_size(&spec_json)?;
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        ensure_gateway(&transaction, &spec.gateway_id)?;
        check_revision(&transaction, &spec.gateway_id, expected_revision)?;
        check_policy_overlap(&transaction, spec, None)?;
        check_resource_limits(&transaction, &spec.gateway_id, Some(&spec_json), None)?;

        let now = now_ms();
        let id = Uuid::new_v4().to_string();
        transaction
            .execute(
                "INSERT INTO traffic_policies(id, gateway_id, name, enabled, priority, spec_json, version, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
                params![id, spec.gateway_id, spec.name, spec.enabled, i64::from(spec.priority), spec_json, now],
            )
            .map_err(store_error)?;
        let revision = bump_revision(&transaction, &spec.gateway_id)?;
        insert_event(
            &transaction,
            &spec.gateway_id,
            &id,
            "create",
            actor_user_id,
            None,
            Some(&spec_json),
            revision,
            now,
        )?;
        let policy = transaction
            .query_row(
                "SELECT id, created_at_ms, updated_at_ms, version, spec_json FROM traffic_policies WHERE id = ?1",
                [&id],
                map_record,
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        Ok(MutationResult {
            policy: Some(policy),
            gateway_id: spec.gateway_id.clone(),
            revision,
            changed: true,
        })
    }

    pub(crate) fn update(
        &self,
        id: &str,
        spec: &PolicySpecV1,
        actor_user_id: &str,
        expected_revision: u64,
        expected_version: u64,
    ) -> Result<MutationResult, PolicyFailure> {
        let spec_json = serialized_spec(spec)?;
        check_one_spec_size(&spec_json)?;
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let current = find_record(&transaction, id)?.ok_or(PolicyFailure::NotFound)?;
        if spec.gateway_id != current.spec.gateway_id {
            return Err(PolicyFailure::Invalid {
                code: "invalid_spec",
                message: "gateway_id cannot be changed when editing a policy".to_owned(),
            });
        }
        check_revision(&transaction, &current.spec.gateway_id, expected_revision)?;
        if current.version != expected_version {
            return Err(PolicyFailure::VersionConflict {
                current_revision: read_revision(&transaction, &current.spec.gateway_id)?,
                current_version: current.version,
            });
        }
        if spec_json
            == serde_json::to_string(&current.spec)
                .map_err(|error| PolicyFailure::Store(error.to_string()))?
        {
            let revision = read_revision(&transaction, &current.spec.gateway_id)?;
            transaction.commit().map_err(store_error)?;
            return Ok(MutationResult {
                gateway_id: current.spec.gateway_id.clone(),
                policy: Some(current),
                revision,
                changed: false,
            });
        }
        check_policy_overlap(&transaction, spec, Some(id))?;
        check_resource_limits(
            &transaction,
            &current.spec.gateway_id,
            Some(&spec_json),
            Some(id),
        )?;

        let now = now_ms();
        transaction
            .execute(
                "UPDATE traffic_policies SET name = ?1, enabled = ?2, priority = ?3, spec_json = ?4,
                 version = version + 1, updated_at_ms = ?5 WHERE id = ?6",
                params![spec.name, spec.enabled, i64::from(spec.priority), spec_json, now, id],
            )
            .map_err(store_error)?;
        let revision = bump_revision(&transaction, &current.spec.gateway_id)?;
        let after_json = serialized_spec(spec)?;
        insert_event(
            &transaction,
            &current.spec.gateway_id,
            id,
            "update",
            actor_user_id,
            Some(
                &serde_json::to_string(&current.spec)
                    .map_err(|error| PolicyFailure::Store(error.to_string()))?,
            ),
            Some(&after_json),
            revision,
            now,
        )?;
        let updated = find_record(&transaction, id)?.ok_or(PolicyFailure::NotFound)?;
        transaction.commit().map_err(store_error)?;
        Ok(MutationResult {
            policy: Some(updated),
            gateway_id: current.spec.gateway_id,
            revision,
            changed: true,
        })
    }

    pub(crate) fn set_enabled(
        &self,
        id: &str,
        enabled: bool,
        actor_user_id: &str,
        expected_revision: u64,
        expected_version: u64,
    ) -> Result<MutationResult, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let current = find_record(&transaction, id)?.ok_or(PolicyFailure::NotFound)?;
        let current_revision = read_revision(&transaction, &current.spec.gateway_id)?;
        check_revision(&transaction, &current.spec.gateway_id, expected_revision)?;
        if current.version != expected_version {
            return Err(PolicyFailure::VersionConflict {
                current_revision,
                current_version: current.version,
            });
        }
        if current.spec.enabled == enabled {
            transaction.commit().map_err(store_error)?;
            return Ok(MutationResult {
                gateway_id: current.spec.gateway_id.clone(),
                policy: Some(current),
                revision: current_revision,
                changed: false,
            });
        }
        let mut updated_spec = current.spec.clone();
        updated_spec.enabled = enabled;
        let spec_json = serialized_spec(&updated_spec)?;
        check_one_spec_size(&spec_json)?;
        check_resource_limits(
            &transaction,
            &updated_spec.gateway_id,
            Some(&spec_json),
            Some(id),
        )?;
        let now = now_ms();
        transaction
            .execute(
                "UPDATE traffic_policies SET enabled = ?1, spec_json = ?2, version = version + 1, updated_at_ms = ?3 WHERE id = ?4",
                params![enabled, spec_json, now, id],
            )
            .map_err(store_error)?;
        let revision = bump_revision(&transaction, &updated_spec.gateway_id)?;
        insert_event(
            &transaction,
            &updated_spec.gateway_id,
            id,
            if enabled { "enable" } else { "disable" },
            actor_user_id,
            Some(
                &serde_json::to_string(&current.spec)
                    .map_err(|error| PolicyFailure::Store(error.to_string()))?,
            ),
            Some(&spec_json),
            revision,
            now,
        )?;
        let updated = find_record(&transaction, id)?.ok_or(PolicyFailure::NotFound)?;
        transaction.commit().map_err(store_error)?;
        Ok(MutationResult {
            policy: Some(updated),
            gateway_id: updated_spec.gateway_id,
            revision,
            changed: true,
        })
    }

    pub(crate) fn delete(
        &self,
        id: &str,
        actor_user_id: &str,
        expected_revision: u64,
    ) -> Result<MutationResult, PolicyFailure> {
        let mut connection = self.repository.lock().map_err(PolicyFailure::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let current = find_record(&transaction, id)?.ok_or(PolicyFailure::NotFound)?;
        check_revision(&transaction, &current.spec.gateway_id, expected_revision)?;
        let before_json = serialized_spec(&current.spec)?;
        transaction
            .execute("DELETE FROM traffic_policies WHERE id = ?1", [id])
            .map_err(store_error)?;
        let revision = bump_revision(&transaction, &current.spec.gateway_id)?;
        insert_event(
            &transaction,
            &current.spec.gateway_id,
            id,
            "delete",
            actor_user_id,
            Some(&before_json),
            None,
            revision,
            now_ms(),
        )?;
        transaction.commit().map_err(store_error)?;
        Ok(MutationResult {
            policy: None,
            gateway_id: current.spec.gateway_id,
            revision,
            changed: true,
        })
    }
}

#[derive(Clone)]
struct DeploymentRow {
    status: String,
    last_error_code: Option<String>,
    last_error_message: Option<String>,
    last_reported_at_ms: Option<i64>,
    last_heartbeat_at_ms: Option<i64>,
    agent_connected: bool,
    agent_boot_id: Option<String>,
    agent_connection_epoch: Option<String>,
    agent_connection_id: u64,
    controller_epoch: Option<String>,
    bundle_generation: u64,
    bundle_checksum: Option<String>,
    reported_revision: u64,
    agent_applied_revision: u64,
    capabilities_json: Option<String>,
    policy_results_json: String,
    delivered_revision: u64,
    delivered_at_ms: Option<i64>,
    acknowledged_status: Option<String>,
}

fn read_deployment(
    connection: &Connection,
    gateway_id: &str,
) -> Result<(u64, u64, Option<DeploymentRow>), PolicyFailure> {
    let desired = connection
        .query_row(
            "SELECT desired_revision FROM policy_gateways WHERE gateway_id = ?1",
            [gateway_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(store_error)?
        .unwrap_or(0);
    let deployment = connection
        .query_row(
            "SELECT desired_revision, applied_revision, status, last_error_code, last_error_message,
                    last_reported_at_ms, last_heartbeat_at_ms, agent_connected, agent_boot_id,
                    controller_epoch, bundle_generation, bundle_checksum, reported_revision,
                    agent_applied_revision, capabilities_json, policy_results_json,
                    delivered_revision, delivered_at_ms, acknowledged_status,
                    agent_connection_epoch, agent_connection_id
             FROM policy_deployments WHERE gateway_id = ?1",
            [gateway_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    map_deployment_row(row)?,
                ))
            },
        )
        .optional()
        .map_err(store_error)?;
    Ok(match deployment {
        Some((desired, applied, row)) => (to_u64(desired), to_u64(applied), Some(row)),
        None => (to_u64(desired), 0, None),
    })
}

fn deployment_row(
    connection: &Connection,
    gateway_id: &str,
) -> Result<DeploymentRow, PolicyFailure> {
    connection
        .query_row(
            "SELECT desired_revision, applied_revision, status, last_error_code, last_error_message,
                    last_reported_at_ms, last_heartbeat_at_ms, agent_connected, agent_boot_id,
                    controller_epoch, bundle_generation, bundle_checksum, reported_revision,
                    agent_applied_revision, capabilities_json, policy_results_json,
                    delivered_revision, delivered_at_ms, acknowledged_status,
                    agent_connection_epoch, agent_connection_id
             FROM policy_deployments WHERE gateway_id = ?1",
            [gateway_id],
            map_deployment_row,
        )
        .map_err(store_error)
}

fn map_deployment_row(row: &Row<'_>) -> rusqlite::Result<DeploymentRow> {
    let _: i64 = row.get(0)?;
    let _: i64 = row.get(1)?;
    Ok(DeploymentRow {
        status: row.get(2)?,
        last_error_code: row.get(3)?,
        last_error_message: row.get(4)?,
        last_reported_at_ms: row.get(5)?,
        last_heartbeat_at_ms: row.get(6)?,
        agent_connected: row.get(7)?,
        agent_boot_id: row.get(8)?,
        controller_epoch: row.get(9)?,
        bundle_generation: to_u64(row.get(10)?),
        bundle_checksum: row.get(11)?,
        reported_revision: to_u64(row.get(12)?),
        agent_applied_revision: to_u64(row.get(13)?),
        capabilities_json: row.get(14)?,
        policy_results_json: row.get(15)?,
        delivered_revision: to_u64(row.get(16)?),
        delivered_at_ms: row.get(17)?,
        acknowledged_status: row.get(18)?,
        agent_connection_epoch: row.get(19)?,
        agent_connection_id: to_u64(row.get(20)?),
    })
}

fn deployment_status(desired_revision: u64, row: Option<&DeploymentRow>) -> String {
    let Some(row) = row else {
        return if desired_revision == 0 {
            "not_deployed".to_owned()
        } else {
            "offline".to_owned()
        };
    };
    if !row.agent_connected {
        return if desired_revision == 0 {
            "not_deployed".to_owned()
        } else {
            "offline".to_owned()
        };
    }
    if row.reported_revision < desired_revision {
        return "pending".to_owned();
    }
    row.status.clone()
}

fn delivery_status(desired_revision: u64, row: Option<&DeploymentRow>) -> String {
    if desired_revision == 0 {
        return "not_deployed".to_owned();
    }
    let Some(row) = row else {
        return "offline".to_owned();
    };
    if !row.agent_connected {
        return "offline".to_owned();
    }
    if row.delivered_revision == desired_revision {
        "delivered".to_owned()
    } else {
        "pending".to_owned()
    }
}

struct PolicyExecution {
    status: String,
    reason_code: Option<String>,
    message: Option<String>,
    details: Option<PolicyResultDetails>,
}

fn read_traffic_metrics(
    connection: &Connection,
    gateway_id: &str,
) -> Result<BTreeMap<String, Vec<PolicyClientMetrics>>, PolicyFailure> {
    let mut statement = connection
        .prepare(
            "SELECT policy_id, mac,
                    upload_interface, upload_bytes, upload_packets, upload_drops, upload_overlimits,
                    download_interface, download_bytes, download_packets, download_drops, download_overlimits
             FROM policy_client_metrics WHERE gateway_id = ?1
             ORDER BY policy_id, mac",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map([gateway_id], |row| {
            let policy_id: String = row.get(0)?;
            let mac: String = row.get(1)?;
            let upload_interface: Option<String> = row.get(2)?;
            let upload_bytes: Option<i64> = row.get(3)?;
            let upload_packets: Option<i64> = row.get(4)?;
            let upload_drops: Option<i64> = row.get(5)?;
            let upload_overlimits: Option<i64> = row.get(6)?;
            let download_interface: Option<String> = row.get(7)?;
            let download_bytes: Option<i64> = row.get(8)?;
            let download_packets: Option<i64> = row.get(9)?;
            let download_drops: Option<i64> = row.get(10)?;
            let download_overlimits: Option<i64> = row.get(11)?;
            let upload = upload_interface.map(|interface| PolicyDirectionMetrics {
                interface,
                bytes: upload_bytes.and_then(|value| u64::try_from(value).ok()),
                packets: upload_packets.and_then(|value| u64::try_from(value).ok()),
                drops: upload_drops.and_then(|value| u64::try_from(value).ok()),
                overlimits: upload_overlimits.and_then(|value| u64::try_from(value).ok()),
            });
            let download = download_interface.map(|interface| PolicyDirectionMetrics {
                interface,
                bytes: download_bytes.and_then(|value| u64::try_from(value).ok()),
                packets: download_packets.and_then(|value| u64::try_from(value).ok()),
                drops: download_drops.and_then(|value| u64::try_from(value).ok()),
                overlimits: download_overlimits.and_then(|value| u64::try_from(value).ok()),
            });
            Ok((
                policy_id.clone(),
                PolicyClientMetrics {
                    policy_id,
                    mac,
                    upload,
                    download,
                },
            ))
        })
        .map_err(store_error)?;
    let mut metrics = BTreeMap::<String, Vec<PolicyClientMetrics>>::new();
    for row in rows {
        let (policy_id, metric) = row.map_err(store_error)?;
        metrics.entry(policy_id).or_default().push(metric);
    }
    Ok(metrics)
}

fn policy_execution(
    policy_id: &str,
    enabled: bool,
    desired_revision: u64,
    row: &DeploymentRow,
) -> PolicyExecution {
    policy_execution_from_values(policy_id, enabled, desired_revision, Some(row))
}

fn policy_execution_from_values(
    policy_id: &str,
    enabled: bool,
    desired_revision: u64,
    row: Option<&DeploymentRow>,
) -> PolicyExecution {
    let Some(row) = row else {
        return PolicyExecution {
            status: if enabled { "offline" } else { "not_deployed" }.to_owned(),
            reason_code: None,
            message: None,
            details: None,
        };
    };
    let reported_result = (row.reported_revision == desired_revision)
        .then(|| serde_json::from_str::<Vec<PolicyResult>>(&row.policy_results_json).ok())
        .flatten()
        .and_then(|results| {
            results
                .into_iter()
                .find(|result| result.policy_id == policy_id)
        });
    let reported_status = reported_result.as_ref().map(|result| match result.status {
        netqmon_protocol::policy::PolicyResultStatus::Applied => "applied",
        netqmon_protocol::policy::PolicyResultStatus::Degraded => "degraded",
        netqmon_protocol::policy::PolicyResultStatus::Unsupported => "unsupported",
        netqmon_protocol::policy::PolicyResultStatus::Failed => "failed",
        netqmon_protocol::policy::PolicyResultStatus::Disabled => "disabled",
    });
    let emergency_disabled =
        enabled && row.last_error_code.as_deref() == Some("emergency_disabled");
    let status = if !row.agent_connected {
        if desired_revision == 0 && !enabled {
            "disabled"
        } else {
            "offline"
        }
    } else if emergency_disabled {
        "failed"
    } else if let Some(status) = reported_status {
        status
    } else {
        "pending"
    };
    let reason_code = reported_result
        .as_ref()
        .and_then(|result| result.reason_code.clone())
        .or_else(|| {
            (!row.agent_connected || emergency_disabled)
                .then(|| row.last_error_code.clone())
                .flatten()
        });
    let message = reported_result
        .as_ref()
        .and_then(|result| result.message.clone())
        .or_else(|| {
            (!row.agent_connected || emergency_disabled)
                .then(|| row.last_error_message.clone())
                .flatten()
        });
    PolicyExecution {
        status: status.to_owned(),
        reason_code,
        message,
        details: reported_result.and_then(|result| result.details),
    }
}

fn capabilities(row: Option<&DeploymentRow>) -> PolicyCapabilities {
    let wire = row
        .and_then(|value| value.capabilities_json.as_deref())
        .and_then(|json| serde_json::from_str::<WireCapabilities>(json).ok());
    let capability_name = |capability| match capability {
        netqmon_protocol::policy::PolicyCapability::Supported => "supported",
        netqmon_protocol::policy::PolicyCapability::Unsupported => "unsupported",
        netqmon_protocol::policy::PolicyCapability::Degraded => "degraded",
    };
    let client_block = wire
        .as_ref()
        .map_or("unsupported", |caps| capability_name(caps.client_block));
    let client_limit = wire
        .as_ref()
        .map_or("unsupported", |caps| capability_name(caps.client_limit));
    let application_block = wire.as_ref().map_or("unsupported", |caps| {
        capability_name(caps.application_block)
    });
    let application_limit = wire.as_ref().map_or("unsupported", |caps| {
        capability_name(caps.application_limit)
    });
    let connected = row.is_some_and(|value| value.agent_connected);
    let (status, reason) = if !connected {
        ("unsupported", "agent_offline")
    } else if client_block == "supported" {
        ("supported", "client_block_available")
    } else if client_block == "degraded" {
        ("degraded", "client_block_has_coverage_gaps")
    } else {
        ("unsupported", "client_block_unsupported")
    };
    PolicyCapabilities {
        enforcement_supported: status == "supported",
        status: status.to_owned(),
        reason: reason.to_owned(),
        client_block: client_block.to_owned(),
        client_limit: client_limit.to_owned(),
        application_block: application_block.to_owned(),
        application_limit: application_limit.to_owned(),
    }
}

fn map_record(row: &Row<'_>) -> rusqlite::Result<PolicyRecord> {
    let id: String = row.get(0)?;
    let created_at_ms = row.get(1)?;
    let updated_at_ms = row.get(2)?;
    let version: i64 = row.get(3)?;
    let spec_json: String = row.get(4)?;
    let spec: PolicySpecV1 = serde_json::from_str(&spec_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(PolicyRecord {
        id,
        created_at_ms,
        updated_at_ms,
        version: to_u64(version),
        execution_status: if spec.enabled {
            "offline".to_owned()
        } else {
            "disabled".to_owned()
        },
        execution_reason_code: None,
        execution_message: None,
        execution_details: None,
        spec,
    })
}

fn map_event(row: &Row<'_>) -> rusqlite::Result<PolicyEvent> {
    let before_json: Option<String> = row.get(3)?;
    let after_json: Option<String> = row.get(4)?;
    Ok(PolicyEvent {
        event_id: row.get(0)?,
        action: row.get(1)?,
        actor_user_id: row.get(2)?,
        before: parse_event_spec(before_json)?,
        after: parse_event_spec(after_json)?,
        revision: to_u64(row.get(5)?),
        created_at_ms: row.get(6)?,
    })
}

fn parse_event_spec(value: Option<String>) -> rusqlite::Result<Option<PolicySpecV1>> {
    value
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn find_record(connection: &Connection, id: &str) -> Result<Option<PolicyRecord>, PolicyFailure> {
    connection
        .query_row(
            "SELECT id, created_at_ms, updated_at_ms, version, spec_json FROM traffic_policies WHERE id = ?1",
            [id],
            map_record,
        )
        .optional()
        .map_err(store_error)
}

fn ensure_gateway(transaction: &Transaction<'_>, gateway_id: &str) -> Result<(), PolicyFailure> {
    transaction
        .execute(
            "INSERT INTO policy_gateways(gateway_id) VALUES (?1) ON CONFLICT(gateway_id) DO NOTHING",
            [gateway_id],
        )
        .map_err(store_error)?;
    transaction
        .execute(
            "INSERT INTO policy_deployments(gateway_id) VALUES (?1) ON CONFLICT(gateway_id) DO NOTHING",
            [gateway_id],
        )
        .map_err(store_error)?;
    Ok(())
}

fn read_revision(connection: &Connection, gateway_id: &str) -> Result<u64, PolicyFailure> {
    connection
        .query_row(
            "SELECT desired_revision FROM policy_gateways WHERE gateway_id = ?1",
            [gateway_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(store_error)
        .map(|value| value.map_or(0, to_u64))
}

fn check_revision(
    connection: &Connection,
    gateway_id: &str,
    expected_revision: u64,
) -> Result<(), PolicyFailure> {
    let current_revision = read_revision(connection, gateway_id)?;
    if current_revision != expected_revision {
        return Err(PolicyFailure::RevisionConflict { current_revision });
    }
    Ok(())
}

fn bump_revision(transaction: &Transaction<'_>, gateway_id: &str) -> Result<u64, PolicyFailure> {
    transaction
        .execute(
            "UPDATE policy_gateways SET desired_revision = desired_revision + 1 WHERE gateway_id = ?1",
            [gateway_id],
        )
        .map_err(store_error)?;
    let revision = read_revision(transaction, gateway_id)?;
    let agent_connected: bool = transaction
        .query_row(
            "SELECT agent_connected FROM policy_deployments WHERE gateway_id = ?1",
            [gateway_id],
            |row| row.get(0),
        )
        .map_err(store_error)?;
    transaction
        .execute(
            "UPDATE policy_deployments SET desired_revision = ?1, status = ?2,
             last_error_code = NULL, last_error_message = NULL WHERE gateway_id = ?3",
            params![
                to_i64(revision),
                if agent_connected {
                    "pending"
                } else {
                    "offline"
                },
                gateway_id
            ],
        )
        .map_err(store_error)?;
    Ok(revision)
}

// Keep the values beside their matching SQL columns so audit writes stay reviewable.
#[allow(clippy::too_many_arguments)]
fn insert_event(
    transaction: &Transaction<'_>,
    gateway_id: &str,
    policy_id: &str,
    action: &str,
    actor_user_id: &str,
    before_json: Option<&str>,
    after_json: Option<&str>,
    revision: u64,
    now: i64,
) -> Result<(), PolicyFailure> {
    transaction
        .execute(
            "INSERT INTO policy_events(gateway_id, policy_id, action, actor_user_id, before_json, after_json, revision, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![gateway_id, policy_id, action, actor_user_id, before_json, after_json, to_i64(revision), now],
        )
        .map_err(store_error)?;
    Ok(())
}

fn check_policy_overlap(
    connection: &Connection,
    candidate: &PolicySpecV1,
    exclude_id: Option<&str>,
) -> Result<(), PolicyFailure> {
    let mut statement = connection
        .prepare("SELECT id, spec_json FROM traffic_policies WHERE gateway_id = ?1")
        .map_err(store_error)?;
    let existing = statement
        .query_map([&candidate.gateway_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(store_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(store_error)?;
    for (id, spec_json) in existing {
        if exclude_id == Some(id.as_str()) {
            continue;
        }
        let spec: PolicySpecV1 = serde_json::from_str(&spec_json).map_err(|error| {
            PolicyFailure::Store(format!("invalid policy JSON in database: {error}"))
        })?;
        if application_limits_overlap(candidate, &spec) {
            return Err(PolicyFailure::LimitOverlapUnsupported);
        }
    }
    Ok(())
}

fn check_resource_limits(
    connection: &Connection,
    gateway_id: &str,
    replacement_json: Option<&str>,
    exclude_id: Option<&str>,
) -> Result<(), PolicyFailure> {
    let mut statement = connection
        .prepare("SELECT id, spec_json FROM traffic_policies WHERE gateway_id = ?1")
        .map_err(store_error)?;
    let existing = statement
        .query_map([gateway_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(store_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(store_error)?;
    let mut count = 0usize;
    let mut total_bytes = 0usize;
    let mut bundle_bytes = 0u64;
    let mut schedule_complexity = 0u64;
    let mut schedule_expansions = 0u64;
    for (id, spec_json) in existing {
        if exclude_id == Some(id.as_str()) {
            continue;
        }
        count += 1;
        total_bytes = total_bytes.saturating_add(spec_json.len());
        bundle_bytes =
            bundle_bytes.saturating_add(u64::try_from(spec_json.len()).unwrap_or(u64::MAX));
        let spec: PolicySpecV1 = serde_json::from_str(&spec_json).map_err(|error| {
            PolicyFailure::Store(format!("invalid policy JSON in database: {error}"))
        })?;
        schedule_complexity =
            schedule_complexity.saturating_add(spec.schedule.as_ref().map_or(0, |schedule| {
                u64::try_from(schedule.windows.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(30)
            }));
        schedule_expansions = schedule_expansions.saturating_add(schedule_projection_cost(&spec));
    }
    if let Some(spec_json) = replacement_json {
        count += 1;
        total_bytes = total_bytes.saturating_add(spec_json.len());
        bundle_bytes =
            bundle_bytes.saturating_add(u64::try_from(spec_json.len()).unwrap_or(u64::MAX));
        let spec: PolicySpecV1 = serde_json::from_str(spec_json).map_err(|error| {
            PolicyFailure::Store(format!("invalid candidate policy JSON: {error}"))
        })?;
        schedule_complexity =
            schedule_complexity.saturating_add(spec.schedule.as_ref().map_or(0, |schedule| {
                u64::try_from(schedule.windows.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(30)
            }));
        schedule_expansions = schedule_expansions.saturating_add(schedule_projection_cost(&spec));
    }
    if count > MAX_POLICY_COUNT {
        return Err(PolicyFailure::PolicyLimitExceeded);
    }
    if schedule_complexity > MAX_SCHEDULE_COMPLEXITY {
        return Err(PolicyFailure::ScheduleComplexityExceeded);
    }
    if total_bytes > MAX_GATEWAY_SPEC_BYTES {
        return Err(PolicyFailure::PolicyBundleTooLarge);
    }
    bundle_bytes =
        bundle_bytes.saturating_add(schedule_expansions.saturating_mul(PROJECTED_WINDOW_BYTES));
    if bundle_bytes > u64::try_from(MAX_PUSH_BUNDLE_BYTES).unwrap_or(u64::MAX) {
        return Err(PolicyFailure::PolicyBundleTooLarge);
    }
    Ok(())
}

fn check_one_spec_size(spec_json: &str) -> Result<(), PolicyFailure> {
    if spec_json.len() > MAX_SPEC_BYTES {
        return Err(PolicyFailure::PolicyTooLarge);
    }
    Ok(())
}

fn serialized_spec(spec: &PolicySpecV1) -> Result<String, PolicyFailure> {
    serde_json::to_string(spec).map_err(|error| PolicyFailure::Store(error.to_string()))
}

// `map_err` provides owned SQLite errors; this adapter converts each to a safe message.
#[allow(clippy::needless_pass_by_value)]
fn store_error(error: rusqlite::Error) -> PolicyFailure {
    PolicyFailure::Store(error.to_string())
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn sql_count(value: Option<u64>) -> Option<i64> {
    value.and_then(|value| i64::try_from(value).ok())
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| {
            i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::policy::model::{ActionKind, NetworkSelector, PolicyAction, Selectors};

    const SESSION_EPOCH: &str = "session-epoch-test";

    fn connect(
        service: &PolicyService,
        gateway_id: &str,
        connection_id: u64,
    ) -> SessionIdentity<'static> {
        connect_with_epoch(service, gateway_id, SESSION_EPOCH, connection_id)
    }

    fn connect_with_epoch(
        service: &PolicyService,
        gateway_id: &str,
        connection_epoch: &'static str,
        connection_id: u64,
    ) -> SessionIdentity<'static> {
        assert_eq!(
            service
                .mark_agent_connected(gateway_id, connection_epoch, connection_id)
                .unwrap(),
            SessionWrite::Applied
        );
        SessionIdentity::new(connection_epoch, connection_id)
    }

    fn applied_results(policy_id: &str) -> Vec<PolicyResult> {
        vec![PolicyResult {
            policy_id: policy_id.to_owned(),
            status: netqmon_protocol::policy::PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }]
    }

    #[test]
    fn policy_status_exposes_agent_reason_and_goes_offline_after_disconnect() {
        let row = DeploymentRow {
            status: "failed".to_owned(),
            last_error_code: Some("identity_unresolved".to_owned()),
            last_error_message: Some("no current LAN address was found".to_owned()),
            last_reported_at_ms: Some(1),
            last_heartbeat_at_ms: Some(2),
            agent_connected: true,
            agent_boot_id: Some("boot-1".to_owned()),
            controller_epoch: Some("epoch-1".to_owned()),
            bundle_generation: 3,
            bundle_checksum: Some("sha256:checksum".to_owned()),
            reported_revision: 4,
            agent_applied_revision: 3,
            capabilities_json: None,
            policy_results_json: serde_json::to_string(&[PolicyResult {
                policy_id: "policy-1".to_owned(),
                status: netqmon_protocol::policy::PolicyResultStatus::Failed,
                reason_code: Some("identity_unresolved".to_owned()),
                message: Some("no current LAN address was found".to_owned()),
                details: None,
            }])
            .unwrap(),
            delivered_revision: 4,
            delivered_at_ms: Some(2),
            acknowledged_status: Some("failed".to_owned()),
            agent_connection_epoch: Some("epoch-1".to_owned()),
            agent_connection_id: 1,
        };
        assert_eq!(delivery_status(4, Some(&row)), "delivered");
        assert_eq!(delivery_status(4, None), "offline");
        assert_eq!(delivery_status(0, None), "not_deployed");
        let execution = policy_execution_from_values("policy-1", true, 4, Some(&row));
        assert_eq!(execution.status, "failed");
        assert_eq!(
            execution.reason_code.as_deref(),
            Some("identity_unresolved")
        );
        assert_eq!(
            execution.message.as_deref(),
            Some("no current LAN address was found")
        );

        let mut disconnected = row;
        disconnected.agent_connected = false;
        let execution = policy_execution_from_values("policy-1", true, 4, Some(&disconnected));
        assert_eq!(execution.status, "offline");
        assert_eq!(
            execution.reason_code.as_deref(),
            Some("identity_unresolved")
        );

        let mut emergency_disabled = disconnected;
        emergency_disabled.agent_connected = true;
        emergency_disabled.status = "failed".to_owned();
        emergency_disabled.last_error_code = Some("emergency_disabled".to_owned());
        emergency_disabled.last_error_message =
            Some("policies are locally disabled by the emergency marker".to_owned());
        emergency_disabled.policy_results_json = serde_json::to_string(&[PolicyResult {
            policy_id: "policy-1".to_owned(),
            status: netqmon_protocol::policy::PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }])
        .unwrap();
        let execution =
            policy_execution_from_values("policy-1", true, 4, Some(&emergency_disabled));
        assert_eq!(execution.status, "failed");
        assert_eq!(execution.reason_code.as_deref(), Some("emergency_disabled"));
        assert_eq!(
            execution.message.as_deref(),
            Some("policies are locally disabled by the emergency marker")
        );
    }

    #[test]
    fn policy_deployment_tracks_delivery_acknowledgement_and_application_separately() {
        let service = PolicyService::open_in_memory().unwrap();
        let mutation = service.create(&spec(true), "actor-1", 0).unwrap();
        let policy_id = mutation.policy.unwrap().id;
        let session = connect(&service, "gw-1", 1);

        let pending = service.deployment("gw-1").unwrap();
        assert_eq!(pending.desired_revision, 1);
        assert_eq!(pending.delivered_revision, 0);
        assert_eq!(pending.delivery_status, "pending");
        assert_eq!(pending.acknowledged_revision, 0);
        assert_eq!(pending.acknowledged_status, None);
        assert_eq!(pending.applied_revision, 0);

        assert_eq!(
            service.record_delivery("gw-1", session, 1, 100).unwrap(),
            SessionWrite::Applied
        );
        let delivered = service.deployment("gw-1").unwrap();
        assert_eq!(delivered.delivery_status, "delivered");
        assert_eq!(delivered.delivered_revision, 1);
        assert_eq!(delivered.delivered_at_ms, Some(100));
        assert_eq!(delivered.acknowledged_revision, 0);
        assert_eq!(delivered.applied_revision, 0);
        assert_eq!(delivered.status, "pending");

        service
            .record_health(
                "gw-1",
                session,
                "boot-1",
                "epoch-1",
                0,
                &WireCapabilities::unsupported(),
                false,
                101,
            )
            .unwrap();
        assert_eq!(
            service
                .record_ack(
                    "gw-1",
                    session,
                    "boot-1",
                    "epoch-1",
                    1,
                    1,
                    "sha256:test-checksum",
                    PolicyAckStatus::Failed,
                    &WireCapabilities::unsupported(),
                    &[PolicyResult {
                        policy_id,
                        status: netqmon_protocol::policy::PolicyResultStatus::Failed,
                        reason_code: Some("test_apply_failure".to_owned()),
                        message: Some("injected test failure".to_owned()),
                        details: None,
                    }],
                    102,
                )
                .unwrap(),
            SessionWrite::Applied
        );
        let failed = service.deployment("gw-1").unwrap();
        assert_eq!(failed.delivered_revision, 1);
        assert_eq!(failed.acknowledged_revision, 1);
        assert_eq!(failed.acknowledged_status.as_deref(), Some("failed"));
        assert_eq!(failed.applied_revision, 0);
        assert_eq!(failed.status, "failed");
    }

    #[test]
    fn superseded_policy_connection_cannot_clear_the_connected_state() {
        let service = PolicyService::open_in_memory().unwrap();
        service
            .mark_agent_connected("gw-1", "epoch-test", 1)
            .unwrap();
        service
            .mark_agent_connected("gw-1", "epoch-test", 2)
            .unwrap();

        service
            .mark_agent_disconnected("gw-1", "epoch-test", 1)
            .unwrap();
        assert!(service.deployment("gw-1").unwrap().agent_connected);

        service
            .mark_agent_disconnected("gw-1", "epoch-test", 2)
            .unwrap();
        assert!(!service.deployment("gw-1").unwrap().agent_connected);
    }

    #[test]
    fn a_restarted_collector_can_reclaim_a_connected_agent() {
        let service = PolicyService::open_in_memory().unwrap();
        service
            .mark_agent_connected("gw-1", "epoch-old", 9)
            .unwrap();
        service
            .mark_agent_connected("gw-1", "epoch-new", 1)
            .unwrap();
        service
            .mark_agent_disconnected("gw-1", "epoch-old", 9)
            .unwrap();
        assert!(service.deployment("gw-1").unwrap().agent_connected);
        service
            .mark_agent_disconnected("gw-1", "epoch-new", 1)
            .unwrap();
        assert!(!service.deployment("gw-1").unwrap().agent_connected);
    }

    #[test]
    fn late_health_from_a_superseded_session_cannot_overwrite_the_new_session() {
        let service = PolicyService::open_in_memory().unwrap();
        let capabilities = WireCapabilities::unsupported();
        let old = connect(&service, "gw-1", 1);
        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    old,
                    "boot-old",
                    "controller-1",
                    0,
                    &capabilities,
                    false,
                    100,
                )
                .unwrap(),
            SessionWrite::Applied
        );

        let new = connect(&service, "gw-1", 2);
        let supported = WireCapabilities {
            client_block: netqmon_protocol::policy::PolicyCapability::Supported,
            client_limit: netqmon_protocol::policy::PolicyCapability::Supported,
            application_block: netqmon_protocol::policy::PolicyCapability::Supported,
            application_limit: netqmon_protocol::policy::PolicyCapability::Supported,
        };
        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    old,
                    "boot-late",
                    "controller-1",
                    1,
                    &supported,
                    false,
                    200,
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.agent_boot_id.as_deref(), Some("boot-old"));
        assert_eq!(deployment.last_heartbeat_at_ms, Some(100));
        assert_eq!(deployment.capabilities.application_limit, "unsupported");
        assert!(deployment.agent_connected);

        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    new,
                    "boot-new",
                    "controller-1",
                    0,
                    &supported,
                    false,
                    300,
                )
                .unwrap(),
            SessionWrite::Applied
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.agent_boot_id.as_deref(), Some("boot-new"));
        assert_eq!(deployment.last_heartbeat_at_ms, Some(300));
        assert_eq!(deployment.capabilities.application_limit, "supported");
    }

    #[test]
    fn late_ack_from_a_superseded_session_is_dropped() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let capabilities = WireCapabilities::unsupported();
        let old = connect(&service, "gw-1", 1);
        service
            .record_health(
                "gw-1",
                old,
                "boot-1",
                "controller-1",
                0,
                &capabilities,
                false,
                100,
            )
            .unwrap();

        let new = connect(&service, "gw-1", 2);
        assert_eq!(
            service
                .record_ack(
                    "gw-1",
                    old,
                    "boot-1",
                    "controller-1",
                    1,
                    1,
                    "sha256:late-ack",
                    PolicyAckStatus::Applied,
                    &capabilities,
                    &applied_results(&policy.id),
                    200,
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.acknowledged_revision, 0);
        assert_eq!(deployment.acknowledged_status, None);
        assert_eq!(deployment.applied_revision, 0);
        assert_eq!(service.agent_applied_revision("gw-1").unwrap(), 0);

        assert_eq!(
            service
                .record_ack(
                    "gw-1",
                    new,
                    "boot-1",
                    "controller-1",
                    1,
                    1,
                    "sha256:late-ack",
                    PolicyAckStatus::Applied,
                    &capabilities,
                    &applied_results(&policy.id),
                    300,
                )
                .unwrap(),
            SessionWrite::Applied
        );
        assert_eq!(service.deployment("gw-1").unwrap().applied_revision, 1);
    }

    #[test]
    fn late_delivery_from_a_superseded_session_is_ignored() {
        let service = PolicyService::open_in_memory().unwrap();
        let old = connect(&service, "gw-1", 1);
        assert_eq!(
            service.record_delivery("gw-1", old, 1, 100).unwrap(),
            SessionWrite::Applied
        );

        let new = connect(&service, "gw-1", 2);
        assert_eq!(
            service.record_delivery("gw-1", old, 1, 200).unwrap(),
            SessionWrite::Superseded
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.delivered_revision, 0);
        assert_eq!(deployment.delivered_at_ms, None);

        assert_eq!(
            service.record_delivery("gw-1", new, 1, 300).unwrap(),
            SessionWrite::Applied
        );
        assert_eq!(
            service.deployment("gw-1").unwrap().delivered_at_ms,
            Some(300)
        );
    }

    #[test]
    fn late_metrics_from_a_superseded_session_are_ignored() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let capabilities = WireCapabilities::unsupported();
        let old = connect(&service, "gw-1", 1);
        service
            .record_health(
                "gw-1",
                old,
                "boot-1",
                "controller-1",
                0,
                &capabilities,
                false,
                100,
            )
            .unwrap();
        service
            .record_ack(
                "gw-1",
                old,
                "boot-1",
                "controller-1",
                1,
                1,
                "sha256:metrics",
                PolicyAckStatus::Applied,
                &capabilities,
                &applied_results(&policy.id),
                100,
            )
            .unwrap();
        let metric = |bytes: u64| PolicyClientMetrics {
            policy_id: policy.id.clone(),
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            upload: Some(PolicyDirectionMetrics {
                interface: "policy-block".to_owned(),
                bytes: Some(bytes),
                packets: Some(1),
                drops: None,
                overlimits: None,
            }),
            download: None,
        };
        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    old,
                    "boot-1",
                    now_ms(),
                    std::slice::from_ref(&metric(222))
                )
                .unwrap(),
            SessionWrite::Applied
        );

        let new = connect(&service, "gw-1", 2);
        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    old,
                    "boot-1",
                    now_ms(),
                    std::slice::from_ref(&metric(999))
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(
            deployment.policies[0].traffic_metrics[0]
                .upload
                .as_ref()
                .unwrap()
                .bytes,
            Some(222)
        );

        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    new,
                    "boot-1",
                    now_ms(),
                    std::slice::from_ref(&metric(333))
                )
                .unwrap(),
            SessionWrite::Applied
        );
        assert_eq!(
            service.deployment("gw-1").unwrap().policies[0].traffic_metrics[0]
                .upload
                .as_ref()
                .unwrap()
                .bytes,
            Some(333)
        );
    }

    #[test]
    fn concurrent_replacement_keeps_the_old_session_from_clearing_or_overwriting_the_new_one() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let capabilities = WireCapabilities::unsupported();
        let old = connect(&service, "gw-1", 1);
        service
            .record_health(
                "gw-1",
                old,
                "boot-old",
                "controller-1",
                0,
                &capabilities,
                false,
                100,
            )
            .unwrap();

        let new = connect(&service, "gw-1", 2);
        service
            .record_health(
                "gw-1",
                new,
                "boot-new",
                "controller-1",
                0,
                &capabilities,
                false,
                200,
            )
            .unwrap();

        // Every late old-session write is rejected; none of them may clear or
        // overwrite the deployment state owned by the replacement session.
        service
            .mark_agent_disconnected("gw-1", SESSION_EPOCH, 1)
            .unwrap();
        assert!(service.deployment("gw-1").unwrap().agent_connected);
        assert_eq!(
            service.record_delivery("gw-1", old, 1, 50).unwrap(),
            SessionWrite::Superseded
        );
        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    old,
                    "boot-stale",
                    "controller-1",
                    1,
                    &capabilities,
                    false,
                    50,
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        assert_eq!(
            service
                .record_ack(
                    "gw-1",
                    old,
                    "boot-old",
                    "controller-1",
                    1,
                    1,
                    "sha256:stale",
                    PolicyAckStatus::Applied,
                    &capabilities,
                    &applied_results(&policy.id),
                    50,
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        let metric = PolicyClientMetrics {
            policy_id: policy.id.clone(),
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            upload: Some(PolicyDirectionMetrics {
                interface: "policy-block".to_owned(),
                bytes: Some(999),
                packets: None,
                drops: None,
                overlimits: None,
            }),
            download: None,
        };
        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    old,
                    "boot-old",
                    now_ms(),
                    std::slice::from_ref(&metric)
                )
                .unwrap(),
            SessionWrite::Superseded
        );

        let deployment = service.deployment("gw-1").unwrap();
        assert!(deployment.agent_connected);
        assert_eq!(deployment.agent_boot_id.as_deref(), Some("boot-new"));
        assert_eq!(deployment.last_heartbeat_at_ms, Some(200));
        assert_eq!(deployment.delivered_revision, 0);
        assert_eq!(deployment.applied_revision, 0);
        assert!(deployment.policies[0].traffic_metrics.is_empty());

        service
            .mark_agent_disconnected("gw-1", SESSION_EPOCH, 2)
            .unwrap();
        assert!(!service.deployment("gw-1").unwrap().agent_connected);
    }

    #[test]
    fn collector_restart_rebuilds_the_session_and_keeps_the_previous_one_superseded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.db");
        let before = PolicyService::open(&path).unwrap();
        let old = connect_with_epoch(&before, "gw-1", "collector-epoch-old", 7);
        assert_eq!(
            before
                .record_health(
                    "gw-1",
                    old,
                    "boot-old",
                    "collector-epoch-old",
                    0,
                    &WireCapabilities::unsupported(),
                    false,
                    100,
                )
                .unwrap(),
            SessionWrite::Applied
        );
        drop(before);

        let service = PolicyService::open(&path).unwrap();
        // A new Collector epoch wins even though its first connection id is lower.
        let new = connect_with_epoch(&service, "gw-1", "collector-epoch-new", 1);
        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    new,
                    "boot-new",
                    "collector-epoch-new",
                    0,
                    &WireCapabilities::unsupported(),
                    false,
                    200,
                )
                .unwrap(),
            SessionWrite::Applied
        );
        assert_eq!(
            service
                .record_health(
                    "gw-1",
                    old,
                    "boot-late",
                    "collector-epoch-old",
                    1,
                    &WireCapabilities::unsupported(),
                    false,
                    300,
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        service
            .mark_agent_disconnected("gw-1", "collector-epoch-old", 7)
            .unwrap();
        let deployment = service.deployment("gw-1").unwrap();
        assert!(deployment.agent_connected);
        assert_eq!(deployment.agent_boot_id.as_deref(), Some("boot-new"));
        assert_eq!(deployment.last_heartbeat_at_ms, Some(200));

        service
            .mark_agent_disconnected("gw-1", "collector-epoch-new", 1)
            .unwrap();
        assert!(!service.deployment("gw-1").unwrap().agent_connected);
    }

    fn spec(enabled: bool) -> PolicySpecV1 {
        PolicySpecV1 {
            schema_version: 1,
            gateway_id: "gw-1".to_owned(),
            name: "Client limit".to_owned(),
            description: String::new(),
            enabled,
            priority: 500,
            selectors: Selectors {
                clients: vec!["AA:BB:CC:DD:EE:FF".to_owned()],
                applications: Vec::new(),
                categories: Vec::new(),
                min_application_confidence: 0.85,
            },
            network: NetworkSelector {
                scope: "internet".to_owned(),
                direction: "both".to_owned(),
            },
            action: PolicyAction {
                kind: ActionKind::Limit,
                download_bps: Some(1_000_000),
                upload_bps: None,
            },
            schedule: None,
        }
    }

    #[test]
    fn file_database_migrates_repeatedly_and_keeps_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.db");
        drop(PolicyService::open(&path).unwrap());
        drop(PolicyService::open(&path).unwrap());
        let connection = Connection::open(&path).unwrap();
        let migrations: i64 = connection
            .query_row("SELECT COUNT(*) FROM policy_schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(migrations, 1);
        let versions = connection
            .prepare("SELECT version FROM policy_schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(versions, vec![1]);
        let columns = connection
            .prepare("SELECT name FROM pragma_table_info('policy_deployments')")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for expected in [
            "agent_boot_id",
            "agent_connection_epoch",
            "agent_connection_id",
            "controller_epoch",
            "bundle_generation",
            "bundle_checksum",
            "delivered_revision",
            "delivered_at_ms",
        ] {
            assert!(
                columns.iter().any(|column| column == expected),
                "policy_deployments is missing {expected}"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn create_update_delete_write_revision_and_audit_atomically() {
        let service = PolicyService::open_in_memory().unwrap();
        let created = service.create(&spec(true), "user-1", 0).unwrap();
        let policy = created.policy.unwrap();
        assert_eq!(created.revision, 1);
        assert_eq!(policy.version, 1);
        assert_eq!(policy.execution_status, "offline");

        let mut updated = spec(false);
        updated.name = "Updated limit".to_owned();
        let result = service
            .update(&policy.id, &updated, "user-1", 1, 1)
            .unwrap();
        assert_eq!(result.revision, 2);
        assert_eq!(result.policy.unwrap().version, 2);

        let detail = service.detail(&policy.id).unwrap();
        assert_eq!(detail.events.len(), 2);
        assert_eq!(detail.desired_revision, 2);
        let removed = service.delete(&policy.id, "user-1", 2).unwrap();
        assert_eq!(removed.revision, 3);
        assert!(matches!(
            service.detail(&policy.id),
            Err(PolicyFailure::NotFound)
        ));
        let connection = service.repository.lock().unwrap();
        let deletion: (String, Option<String>, i64) = connection
            .query_row(
                "SELECT action, after_json, revision FROM policy_events WHERE policy_id = ?1 ORDER BY event_id DESC LIMIT 1",
                [&policy.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(deletion, ("delete".to_owned(), None, 3));
    }

    #[test]
    fn policy_traffic_metrics_are_bounded_to_the_active_agent_boot() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let epoch = "00000000-0000-4000-8000-000000000001";
        let capabilities = WireCapabilities::unsupported();
        let session = connect(&service, "gw-1", 1);
        service
            .record_health(
                "gw-1",
                session,
                "boot-1",
                epoch,
                0,
                &capabilities,
                false,
                now_ms(),
            )
            .unwrap();
        let results = vec![PolicyResult {
            policy_id: policy.id.clone(),
            status: netqmon_protocol::policy::PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: Some(PolicyResultDetails {
                clients: Vec::new(),
                controlled_interfaces: vec!["eth0".to_owned()],
                qdisc: Some("HTB + fq_codel".to_owned()),
                mark_conflict_code: None,
            }),
        }];
        service
            .record_ack(
                "gw-1",
                session,
                "boot-1",
                epoch,
                1,
                1,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                PolicyAckStatus::Applied,
                &capabilities,
                &results,
                now_ms(),
            )
            .unwrap();
        let metric = PolicyClientMetrics {
            policy_id: policy.id.clone(),
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            upload: Some(PolicyDirectionMetrics {
                interface: "policy-block".to_owned(),
                bytes: Some(222),
                packets: Some(3),
                drops: Some(3),
                overlimits: None,
            }),
            download: None,
        };
        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    session,
                    "boot-1",
                    now_ms(),
                    std::slice::from_ref(&metric)
                )
                .unwrap(),
            SessionWrite::Applied
        );
        assert_eq!(
            service
                .record_metrics(
                    "gw-1",
                    session,
                    "old-boot",
                    now_ms(),
                    std::slice::from_ref(&metric)
                )
                .unwrap(),
            SessionWrite::Superseded
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(
            deployment.policies[0]
                .details
                .as_ref()
                .unwrap()
                .qdisc
                .as_deref(),
            Some("HTB + fq_codel")
        );
        assert_eq!(
            deployment.policies[0].traffic_metrics[0]
                .upload
                .as_ref()
                .unwrap()
                .bytes,
            Some(222)
        );
        let blocked = deployment.policies[0].traffic_metrics[0]
            .upload
            .as_ref()
            .unwrap();
        assert_eq!(blocked.interface, "policy-block");
        assert_eq!(blocked.packets, Some(3));
        assert_eq!(blocked.drops, Some(3));
    }

    #[test]
    fn stale_health_capabilities_do_not_replace_a_newer_policy_ack() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let epoch = "00000000-0000-4000-8000-000000000001";
        let unsupported = WireCapabilities::unsupported();
        let session = connect(&service, "gw-1", 1);
        service
            .record_health(
                "gw-1",
                session,
                "boot-1",
                epoch,
                0,
                &unsupported,
                false,
                now_ms(),
            )
            .unwrap();
        let supported = WireCapabilities {
            client_block: netqmon_protocol::policy::PolicyCapability::Supported,
            client_limit: netqmon_protocol::policy::PolicyCapability::Supported,
            application_block: netqmon_protocol::policy::PolicyCapability::Supported,
            application_limit: netqmon_protocol::policy::PolicyCapability::Supported,
        };
        service
            .record_ack(
                "gw-1",
                session,
                "boot-1",
                epoch,
                1,
                1,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                PolicyAckStatus::Applied,
                &supported,
                &[PolicyResult {
                    policy_id: policy.id,
                    status: netqmon_protocol::policy::PolicyResultStatus::Applied,
                    reason_code: None,
                    message: None,
                    details: None,
                }],
                now_ms(),
            )
            .unwrap();

        service
            .record_health(
                "gw-1",
                session,
                "boot-1",
                epoch,
                0,
                &unsupported,
                false,
                now_ms().saturating_add(1),
            )
            .unwrap();

        assert_eq!(
            service
                .deployment("gw-1")
                .unwrap()
                .capabilities
                .application_limit,
            "supported"
        );
    }

    #[test]
    fn a_new_controller_epoch_resets_the_generation_before_the_first_ack() {
        let service = PolicyService::open_in_memory().unwrap();
        let policy = service
            .create(&spec(true), "user-1", 0)
            .unwrap()
            .policy
            .unwrap();
        let capabilities = WireCapabilities::unsupported();
        let old_epoch = "00000000-0000-4000-8000-000000000001";
        let new_epoch = "00000000-0000-4000-8000-000000000002";
        let results = vec![PolicyResult {
            policy_id: policy.id,
            status: netqmon_protocol::policy::PolicyResultStatus::Applied,
            reason_code: None,
            message: None,
            details: None,
        }];
        let session = connect(&service, "gw-1", 1);

        service
            .record_health(
                "gw-1",
                session,
                "boot-1",
                old_epoch,
                0,
                &capabilities,
                false,
                now_ms(),
            )
            .unwrap();
        assert!(
            service
                .record_ack(
                    "gw-1",
                    session,
                    "boot-1",
                    old_epoch,
                    1,
                    3,
                    "sha256:old-epoch-checksum",
                    PolicyAckStatus::Applied,
                    &capabilities,
                    &results,
                    now_ms(),
                )
                .unwrap()
                .is_applied()
        );

        service
            .record_health(
                "gw-1",
                session,
                "boot-2",
                new_epoch,
                1,
                &capabilities,
                false,
                now_ms(),
            )
            .unwrap();
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.controller_epoch.as_deref(), Some(new_epoch));
        assert_eq!(deployment.bundle_generation, 0);
        assert_eq!(deployment.bundle_checksum, None);
        assert_eq!(deployment.status, "pending");

        assert!(
            service
                .record_ack(
                    "gw-1",
                    session,
                    "boot-2",
                    new_epoch,
                    1,
                    1,
                    "sha256:new-epoch-checksum",
                    PolicyAckStatus::Applied,
                    &capabilities,
                    &results,
                    now_ms(),
                )
                .unwrap()
                .is_applied()
        );
        let deployment = service.deployment("gw-1").unwrap();
        assert_eq!(deployment.bundle_generation, 1);
        assert_eq!(deployment.status, "applied");
    }

    #[test]
    fn failed_audit_insert_rolls_back_policy_and_revision() {
        let service = PolicyService::open_in_memory().unwrap();
        service
            .repository
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_policy_create_audit
                 BEFORE INSERT ON policy_events WHEN NEW.action = 'create'
                 BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END;",
            )
            .unwrap();

        assert!(matches!(
            service.create(&spec(false), "user-1", 0),
            Err(PolicyFailure::Store(_))
        ));
        let page = service.list("gw-1", 1, 20).unwrap();
        assert_eq!(page.total, 0);
        assert_eq!(page.desired_revision, 0);
    }

    #[test]
    fn stale_revisions_and_policy_versions_do_not_overwrite_edits() {
        let service = PolicyService::open_in_memory().unwrap();
        let created = service.create(&spec(false), "user-1", 0).unwrap();
        let id = created.policy.unwrap().id;
        assert!(matches!(
            service.set_enabled(&id, true, "user-1", 0, 1),
            Err(PolicyFailure::RevisionConflict {
                current_revision: 1
            })
        ));
        assert!(matches!(
            service.set_enabled(&id, true, "user-1", 1, 9),
            Err(PolicyFailure::VersionConflict {
                current_revision: 1,
                current_version: 1
            })
        ));
        assert!(!service.detail(&id).unwrap().policy.spec.enabled);
    }

    #[test]
    fn unchanged_enabled_patch_is_idempotent() {
        let service = PolicyService::open_in_memory().unwrap();
        let created = service.create(&spec(false), "user-1", 0).unwrap();
        let id = created.policy.unwrap().id;
        let result = service.set_enabled(&id, false, "user-1", 1, 1).unwrap();
        assert!(!result.changed);
        assert_eq!(result.revision, 1);
        assert_eq!(service.detail(&id).unwrap().events.len(), 1);
    }

    #[test]
    fn concurrent_if_match_mutations_allow_only_one_commit() {
        let service = Arc::new(PolicyService::open_in_memory().unwrap());
        let created = service.create(&spec(false), "user-1", 0).unwrap();
        let id = created.policy.unwrap().id;
        let barrier = Arc::new(Barrier::new(3));
        let workers = [true, true].map(|enabled| {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            let id = id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.set_enabled(&id, enabled, "user-1", 1, 1)
            })
        });
        barrier.wait();
        let results = workers.map(|worker| worker.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PolicyFailure::RevisionConflict { .. })))
                .count(),
            1
        );
        assert_eq!(service.detail(&id).unwrap().desired_revision, 2);
    }

    #[test]
    fn file_database_does_not_touch_analysis_database() {
        let directory = tempfile::tempdir().unwrap();
        let analysis = directory.path().join("analysis.db");
        let policy = directory.path().join("policy.db");
        let connection = Connection::open(&analysis).unwrap();
        connection.execute_batch("CREATE TABLE flow_sessions(id TEXT PRIMARY KEY); INSERT INTO flow_sessions VALUES ('old-data');").unwrap();
        drop(PolicyService::open(&policy).unwrap());
        let kept: String = connection
            .query_row("SELECT id FROM flow_sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, "old-data");
        assert!(fs::metadata(policy).is_ok());
    }
}
