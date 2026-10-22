//! Bounded correction work and one recovery checkpoint per session.
use super::{json_error, merge};
use crate::{
    ActiveFlow, FlowAttribution, FlowDelta, FlowKey, FlowLifecycle, MINUTE_MS, TelemetryBatch,
    to_i64, write_flow_session,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
            session_id: self.key.session_id(self.started_at),
            client_mac: self.client_mac,
            device_id: self.device_id,
            upload_bytes: counters[0],
            download_bytes: counters[1],
            packets: counters[2],
            started_at: self.started_at,
            last_seen_at: counters[3],
            checkpointed_at: self.checkpointed_at,
            attribution: attr,
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
    let (id,ended_at): (i64,Option<i64>)=tx.query_row("INSERT INTO flow_rollup_sessions
        (session_id,gateway_id,metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
        ON CONFLICT(session_id) DO UPDATE SET metadata_json=excluded.metadata_json,
        attribution_json=excluded.attribution_json,upload_bytes=excluded.upload_bytes,
        download_bytes=excluded.download_bytes,packets=excluded.packets,last_seen_at=excluded.last_seen_at,
        updated_at=MAX(updated_at,excluded.updated_at),ended_at=COALESCE(ended_at,excluded.ended_at)
        RETURNING id,ended_at",params![current.session_id,key.gateway_id,
            serde_json::to_string(&RecoveryMetadata::new(key,current)).map_err(json_error)?,
            serde_json::to_string(attr).map_err(json_error)?,current.upload_bytes,current.download_bytes,
            current.packets,current.last_seen_at,now,(flow.lifecycle==FlowLifecycle::Ended as i32).then_some(now)],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if ended_at.is_some_and(|ended| ended.saturating_add(ENDED_GRACE_MS) <= now) {
        tx.execute(
            "DELETE FROM flow_rollup_contributions WHERE session_ref=?1",
            [id],
        )?;
    }
    // An expired row may still await the minute cleanup. Its historical counts
    // stay frozen; only the newly ingested delta can enter a new correction window.
    tx.execute("INSERT INTO flow_rollup_contributions
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
        day_flows=CASE WHEN expires_at<=?16 THEN 0 ELSE day_flows END,expires_at=excluded.expires_at",
        params![id,to_i64(batch.sent_at)/MINUTE_MS*MINUTE_MS,flow.scope,flow.direction,current.device_id.unwrap_or(0),
            flow.remote_ip,flow.protocol,attr.application_id,attr.category_id,attr.domain.as_deref().unwrap_or("unknown"),
            attr.protocol_id,to_i64(flow.upload_bytes),to_i64(flow.download_bytes),to_i64(flow.packets),
            now.saturating_add(CORRECTION_WINDOW_MS),now])?;
    Ok(())
}

fn read_recovery(row: &Row<'_>) -> rusqlite::Result<(FlowKey, ActiveFlow)> {
    let metadata: RecoveryMetadata =
        serde_json::from_str(&row.get::<_, String>(0)?).map_err(json_error)?;
    let attr = serde_json::from_str(&row.get::<_, String>(1)?).map_err(json_error)?;
    Ok(metadata.into_flow(attr, [row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?]))
}

pub(crate) fn restore(connection: &Connection, current: &mut ActiveFlow) -> rusqlite::Result<()> {
    let state = connection
        .query_row(
            "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at
        FROM flow_rollup_sessions WHERE session_id=?1",
            [&current.session_id],
            read_recovery,
        )
        .optional()?;
    if let Some((_, restored)) = state {
        merge(&mut current.attribution, &restored.attribution);
        current.upload_bytes = current.upload_bytes.max(restored.upload_bytes);
        current.download_bytes = current.download_bytes.max(restored.download_bytes);
        current.packets = current.packets.max(restored.packets);
        current.last_seen_at = current.last_seen_at.max(restored.last_seen_at);
    }
    Ok(())
}

pub(crate) fn restore_active(
    connection: &Connection,
    active: &mut HashMap<FlowKey, ActiveFlow>,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(
        "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at
        FROM flow_rollup_sessions WHERE ended_at IS NULL",
    )?;
    for state in statement.query_map([], read_recovery)? {
        let (key, mut restored) = state?;
        if let Some(current) = active.get_mut(&key) {
            if current.session_id == restored.session_id {
                merge(&mut restored.attribution, &current.attribution);
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
        "SELECT metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at
        FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at<=?1",
    )?;
    for state in statement.query_map([now.saturating_sub(CORRECTION_WINDOW_MS)], read_recovery)? {
        let (key, flow) = state?;
        if flow.last_seen_at > 0 {
            write_flow_session(tx, &key, &flow, None, now)?;
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
