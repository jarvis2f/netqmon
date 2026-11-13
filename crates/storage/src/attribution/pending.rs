//! Bounded correction work and one recovery checkpoint per session.
use super::{json_error, serialize_recovery_attribution};
use crate::{
    ACTIVE_FLOW_TTL_MS, ActiveFlow, ActiveFlowCache, FlowAttribution, FlowDelta, FlowKey,
    FlowLifecycle, MINUTE_MS, TelemetryBatch, to_i64, write_flow_session,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde::{Deserialize, Serialize};

pub(crate) const CORRECTION_WINDOW_MS: i64 = 30 * MINUTE_MS;
pub(crate) const ENDED_GRACE_MS: i64 = 10 * MINUTE_MS;

#[derive(Serialize, Deserialize)]
struct RecoveryMetadata {
    key: FlowKey,
    client_mac: Vec<u8>,
    device_id: Option<i64>,
    started_at: i64,
    checkpointed_at: i64,
    scope: i64,
    path_type: i64,
    nat: i64,
    source_segment: String,
    destination_segment: String,
}
impl RecoveryMetadata {
    fn new(key: &FlowKey, flow: &ActiveFlow) -> Self {
        Self {
            key: key.clone(),
            client_mac: flow.client_mac.clone(),
            device_id: flow.device_id,
            started_at: flow.started_at,
            checkpointed_at: flow.checkpointed_at,
            scope: flow.scope,
            path_type: flow.path_type,
            nat: flow.nat,
            source_segment: flow.source_segment.clone(),
            destination_segment: flow.destination_segment.clone(),
        }
    }
    fn into_flow(self, attr: FlowAttribution, counters: [i64; 4]) -> (FlowKey, ActiveFlow) {
        let flow = ActiveFlow {
            session_id_override: None,
            client_mac: self.client_mac,
            device_id: self.device_id,
            upload_bytes: counters[0],
            download_bytes: counters[1],
            packets: counters[2],
            started_at: self.started_at,
            last_seen_at: counters[3],
            checkpointed_at: self.checkpointed_at,
            last_received_at: 0, // Filled from the collector's updated_at column.
            attribution: crate::shared_active_attribution(attr),
            scope: self.scope,
            path_type: self.path_type,
            nat: self.nat,
            source_segment: self.source_segment,
            destination_segment: self.destination_segment,
        };
        (self.key, flow)
    }
}

pub(crate) fn record(
    tx: &Transaction<'_>,
    key: &FlowKey,
    current: &ActiveFlow,
    batch: &TelemetryBatch,
    flow: &FlowDelta,
    now: i64,
) -> rusqlite::Result<()> {
    let attr = &current.attribution;
    #[cfg(test)]
    let session_started = crate::benchmark_sql_profile_enabled().then(std::time::Instant::now);
    let (id, ended_at): (i64, Option<i64>) = tx
        .prepare_cached("INSERT INTO flow_rollup_sessions
        (session_id,gateway_id,metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
        ON CONFLICT(session_id) DO UPDATE SET metadata_json=excluded.metadata_json,
        attribution_json=excluded.attribution_json,upload_bytes=excluded.upload_bytes,
        download_bytes=excluded.download_bytes,packets=excluded.packets,last_seen_at=excluded.last_seen_at,
        updated_at=MAX(updated_at,excluded.updated_at),
        ended_at=CASE WHEN excluded.ended_at IS NOT NULL THEN COALESCE(ended_at,excluded.ended_at)
            WHEN ended_at IS NOT NULL AND excluded.updated_at>ended_at THEN NULL
            ELSE ended_at END
        RETURNING id,ended_at")?
        .query_row(params![current.session_id(key).as_ref(),key.gateway_id,
            serde_json::to_string(&RecoveryMetadata::new(key,current)).map_err(json_error)?,
            serialize_recovery_attribution(attr.as_ref())?,current.upload_bytes,current.download_bytes,
            current.packets,current.last_seen_at,now,(flow.lifecycle==FlowLifecycle::Ended as i32).then_some(now)],
            |r| Ok((r.get(0)?, r.get(1)?)))?;
    #[cfg(test)]
    if let Some(started) = session_started {
        crate::benchmark_sql_profile(
            "sql:flow_rollup_sessions_upsert",
            Some(started.elapsed()),
            None,
        );
    }
    if ended_at.is_some_and(|ended| ended.saturating_add(ENDED_GRACE_MS) <= now) {
        #[cfg(test)]
        let delete_started = crate::benchmark_sql_profile_enabled().then(std::time::Instant::now);
        tx.prepare_cached("DELETE FROM flow_rollup_contributions WHERE session_ref=?1")?
            .execute([id])?;
        #[cfg(test)]
        if let Some(started) = delete_started {
            crate::benchmark_sql_profile(
                "sql:flow_rollup_contributions_delete",
                Some(started.elapsed()),
                None,
            );
        }
    }
    // An expired row may still await the minute cleanup. Its historical counts
    // stay frozen; only the newly ingested delta can enter a new correction window.
    #[cfg(test)]
    let contribution_started = crate::benchmark_sql_profile_enabled().then(std::time::Instant::now);
    tx.prepare_cached("INSERT INTO flow_rollup_contributions
        (session_ref,timestamp,scope,direction,device_id,remote_ip,protocol,application_id,category_id,domain,protocol_id,
         upload_bytes,download_bytes,packets,flow_count,hour_upload,hour_download,hour_packets,hour_flows,
         day_upload,day_download,day_packets,day_flows,expires_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1,0,0,0,0,0,0,0,0,?15)
        ON CONFLICT(session_ref,timestamp,scope,direction,device_id,remote_ip,protocol) DO UPDATE SET
        application_id=excluded.application_id,category_id=excluded.category_id,domain=excluded.domain,protocol_id=excluded.protocol_id,
        upload_bytes=CASE WHEN expires_at<=?16 THEN excluded.upload_bytes ELSE upload_bytes+excluded.upload_bytes END,
        download_bytes=CASE WHEN expires_at<=?16 THEN excluded.download_bytes ELSE download_bytes+excluded.download_bytes END,
        packets=CASE WHEN expires_at<=?16 THEN excluded.packets ELSE packets+excluded.packets END,
        flow_count=CASE WHEN expires_at<=?16 THEN 1 ELSE flow_count+1 END,
        hour_upload=CASE WHEN expires_at<=?16 THEN 0 ELSE hour_upload END,
        hour_download=CASE WHEN expires_at<=?16 THEN 0 ELSE hour_download END,
        hour_packets=CASE WHEN expires_at<=?16 THEN 0 ELSE hour_packets END,
        hour_flows=CASE WHEN expires_at<=?16 THEN 0 ELSE hour_flows END,
        day_upload=CASE WHEN expires_at<=?16 THEN 0 ELSE day_upload END,
        day_download=CASE WHEN expires_at<=?16 THEN 0 ELSE day_download END,
        day_packets=CASE WHEN expires_at<=?16 THEN 0 ELSE day_packets END,
        day_flows=CASE WHEN expires_at<=?16 THEN 0 ELSE day_flows END,expires_at=excluded.expires_at")?
        .execute(params![id,to_i64(batch.sent_at)/MINUTE_MS*MINUTE_MS,flow.scope,flow.direction,current.device_id.unwrap_or(0),
            flow.remote_ip,flow.protocol,attr.application_id,attr.category_id,attr.domain.as_deref().unwrap_or("unknown"),
            attr.protocol_id,to_i64(flow.upload_bytes),to_i64(flow.download_bytes),to_i64(flow.packets),
            now.saturating_add(CORRECTION_WINDOW_MS),now])?;
    #[cfg(test)]
    if let Some(started) = contribution_started {
        crate::benchmark_sql_profile(
            "sql:flow_rollup_contributions_upsert",
            Some(started.elapsed()),
            None,
        );
    }
    Ok(())
}

fn read_recovery(row: &Row<'_>) -> rusqlite::Result<(FlowKey, ActiveFlow)> {
    let metadata: RecoveryMetadata =
        serde_json::from_str(&row.get::<_, String>(0)?).map_err(json_error)?;
    let attr = serde_json::from_str(&row.get::<_, String>(1)?).map_err(json_error)?;
    let (key, mut flow) =
        metadata.into_flow(attr, [row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?]);
    flow.last_received_at = row.get(6)?;
    Ok((key, flow))
}

pub(crate) fn restore(
    connection: &Connection,
    key: &FlowKey,
    current: &mut ActiveFlow,
) -> rusqlite::Result<bool> {
    let session_id = current.session_id(key);
    let state = connection
        .prepare_cached(
            "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at
        FROM flow_rollup_sessions WHERE session_id=?1",
        )?
        .query_row(
            [session_id.as_ref()],
            |row| Ok((read_recovery(row)?, row.get::<_, Option<i64>>(7)?.is_none())),
        )
        .optional()?;
    if let Some(((_, restored), was_active)) = state {
        current.merge_attribution(&restored.attribution);
        current.upload_bytes = current.upload_bytes.max(restored.upload_bytes);
        current.download_bytes = current.download_bytes.max(restored.download_bytes);
        current.packets = current.packets.max(restored.packets);
        current.last_seen_at = current.last_seen_at.max(restored.last_seen_at);
        return Ok(was_active);
    } else {
        // A late delta/End can arrive after cache GC. Recover the full counters
        // for this exact lifetime instead of overwriting its historical totals.
        let historical = connection
            .prepare_cached(
                "SELECT upload_bytes,download_bytes,packets,last_seen_at,domain,organization_id,
                application_id,category_id,traffic_role,protocol_id,organization_confidence,
                application_confidence,protocol_confidence,classification_confidence,
                classification_reason,classification_evidence_json,ended_at
             FROM flow_sessions WHERE id=?1",
            )?
            .query_row([session_id.as_ref()], |row| {
                Ok((
                    [row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?, row.get(3)?],
                    super::read_attribution(row, 4)?,
                    row.get::<_, Option<i64>>(16)?.is_none(),
                ))
            })
            .optional()?;
        if let Some((counters, attribution, was_active)) = historical {
            current.upload_bytes = counters[0];
            current.download_bytes = counters[1];
            current.packets = counters[2];
            current.last_seen_at = current.last_seen_at.max(counters[3]);
            current.merge_attribution(&attribution);
            return Ok(was_active);
        }
    }
    Ok(false)
}

pub(crate) fn restore_active(
    connection: &Connection,
    active: &mut ActiveFlowCache,
    now: i64,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(
        "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at
        FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at>?1
        ORDER BY updated_at DESC LIMIT ?2",
    )?;
    for state in statement.query_map(
        params![
            now.saturating_sub(CORRECTION_WINDOW_MS),
            i64::try_from(crate::ACTIVE_FLOW_CACHE_CAPACITY).unwrap_or(i64::MAX)
        ],
        read_recovery,
    )? {
        let (key, mut restored) = state?;
        if let Some(current) = active.get(&key) {
            if current.session_id(&key) == restored.session_id(&key) {
                restored.merge_attribution(&current.attribution);
                restored.upload_bytes = restored.upload_bytes.max(current.upload_bytes);
                restored.download_bytes = restored.download_bytes.max(current.download_bytes);
                restored.packets = restored.packets.max(current.packets);
                restored.last_seen_at = restored.last_seen_at.max(current.last_seen_at);
                restored.checkpointed_at = restored.checkpointed_at.max(current.checkpointed_at);
            } else if current.started_at >= restored.started_at {
                continue;
            }
        }
        active.insert(key, restored);
    }
    Ok(())
}

pub(crate) fn prune(tx: &Transaction<'_>, now: i64) -> rusqlite::Result<()> {
    // Checkpoint orphaned/open recovery state before GC; otherwise a restart
    // before the ordinary five-minute checkpoint could lose session counters.
    let mut statement = tx.prepare(
        "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at
        FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at<=?1",
    )?;
    for state in statement.query_map([now.saturating_sub(CORRECTION_WINDOW_MS)], read_recovery)? {
        let (key, flow) = state?;
        if flow.last_seen_at > 0 {
            write_flow_session(tx, &key, &flow, Some(flow.last_seen_at), now)?;
        }
    }
    drop(statement);
    tx.execute(
        "DELETE FROM flow_rollup_contributions WHERE expires_at<=?1",
        [now],
    )?;
    tx.execute(
        "DELETE FROM flow_rollup_sessions WHERE
        (ended_at IS NOT NULL AND ended_at<=?1) OR updated_at<=?2",
        params![
            now.saturating_sub(ENDED_GRACE_MS),
            now.saturating_sub(CORRECTION_WINDOW_MS)
        ],
    )?;
    Ok(())
}

/// Performs a bounded, restart-safe slice of recovery-state GC. Checkpointing
/// occurs before deleting contributions; each caller commits this slice before
/// asking for the next one.
pub(crate) fn prune_bounded(
    tx: &Transaction<'_>,
    now: i64,
    limit: usize,
) -> rusqlite::Result<bool> {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX).max(1);
    let checkpoint_cutoff = now.saturating_sub(CORRECTION_WINDOW_MS);
    let mut statement = tx.prepare(
        "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at
         FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at<=?1 LIMIT ?2",
    )?;
    let stale = statement
        .query_map(params![checkpoint_cutoff, limit], read_recovery)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (key, flow) in &stale {
        if flow.last_seen_at > 0 {
            write_flow_session(tx, key, flow, Some(flow.last_seen_at), now)?;
        }
    }

    tx.execute(
        "DELETE FROM flow_rollup_contributions
         WHERE (session_ref,timestamp,scope,direction,device_id,remote_ip,protocol) IN
           (SELECT session_ref,timestamp,scope,direction,device_id,remote_ip,protocol
            FROM flow_rollup_contributions WHERE expires_at<=?1 LIMIT ?2)",
        params![now, limit],
    )?;
    tx.execute(
        "DELETE FROM flow_rollup_sessions WHERE id IN
           (SELECT s.id FROM flow_rollup_sessions s
            WHERE ((s.ended_at IS NOT NULL AND s.ended_at<=?1) OR s.updated_at<=?2)
              AND NOT EXISTS (SELECT 1 FROM flow_rollup_contributions c WHERE c.session_ref=s.id)
            LIMIT ?3)",
        params![now.saturating_sub(ENDED_GRACE_MS), checkpoint_cutoff, limit],
    )?;
    tx.execute(
        "UPDATE flow_sessions SET ended_at=last_seen_at WHERE rowid IN
           (SELECT f.rowid FROM flow_sessions f
            WHERE f.ended_at IS NULL AND f.checkpointed_at<=?1
              AND NOT EXISTS (SELECT 1 FROM flow_rollup_sessions r
                WHERE r.session_id=f.id AND r.ended_at IS NULL AND r.updated_at>?1)
            LIMIT ?2)",
        params![now.saturating_sub(ACTIVE_FLOW_TTL_MS), limit],
    )?;

    tx.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM flow_rollup_contributions WHERE expires_at<=?1
           UNION ALL SELECT 1 FROM flow_rollup_sessions s
             WHERE ((s.ended_at IS NOT NULL AND s.ended_at<=?2) OR s.updated_at<=?3)
               AND NOT EXISTS (SELECT 1 FROM flow_rollup_contributions c WHERE c.session_ref=s.id)
           UNION ALL SELECT 1 FROM flow_sessions f
             WHERE f.ended_at IS NULL AND f.checkpointed_at<=?4
               AND NOT EXISTS (SELECT 1 FROM flow_rollup_sessions r
                 WHERE r.session_id=f.id AND r.ended_at IS NULL AND r.updated_at>?4)
         )",
        params![
            now,
            now.saturating_sub(ENDED_GRACE_MS),
            checkpoint_cutoff,
            now.saturating_sub(ACTIVE_FLOW_TTL_MS)
        ],
        |row| row.get(0),
    )
}
