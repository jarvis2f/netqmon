//! Independent classification dimensions and exact SQLite rollup reassignment.
use super::{
    DAY_MS, FlowAttribution, FlowDelta, FlowKey, HOUR_MS, MINUTE_MS, PROTOCOL_APPLICATION_PREFIX,
    SqliteStorage, Transaction, Value, adjust_rollup, sample_matches, to_i64,
};
use rusqlite::params;
use rusqlite::{OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn known(id: &str) -> bool {
    !id.is_empty() && id != "unknown"
}
fn improves(old: &str, old_score: f64, new: &str, new_score: f64) -> bool {
    known(new) && (!known(old) || new_score > old_score)
}

pub(super) fn merge(current: &mut FlowAttribution, incoming: &FlowAttribution) {
    let app = improves(
        &current.application_id,
        current.application_confidence,
        &incoming.application_id,
        incoming.application_confidence,
    );
    let org = improves(
        &current.organization_id,
        current.organization_confidence,
        &incoming.organization_id,
        incoming.organization_confidence,
    );
    let protocol = improves(
        &current.protocol_id,
        current.protocol_confidence,
        &incoming.protocol_id,
        incoming.protocol_confidence,
    );
    if app {
        current.application_id.clone_from(&incoming.application_id);
        current.application_confidence = incoming.application_confidence;
    }
    if org {
        current
            .organization_id
            .clone_from(&incoming.organization_id);
        current.organization_confidence = incoming.organization_confidence;
    }
    if protocol {
        current.protocol_id.clone_from(&incoming.protocol_id);
        current.protocol_confidence = incoming.protocol_confidence;
    }
    // Category/role follow application identity when one is known. A generic
    // protocol result must never replace an application's category.
    let category = !known(&current.application_id)
        && known(&incoming.category_id)
        && (!known(&current.category_id) || protocol || org);
    let role = !known(&current.application_id)
        && known(&incoming.traffic_role)
        && (!known(&current.traffic_role) || protocol || org);
    if app {
        current.category_id.clone_from(&incoming.category_id);
        current.traffic_role.clone_from(&incoming.traffic_role);
    } else {
        if category {
            current.category_id.clone_from(&incoming.category_id);
        }
        if role {
            current.traffic_role.clone_from(&incoming.traffic_role);
        }
    }
    if incoming.domain.is_some() && (current.domain.is_none() || app) {
        current.domain.clone_from(&incoming.domain);
    }
    if app || org || protocol || category || role {
        // Preserve evidence from independent dimensions, including the domain
        // that established an application before late protocol metadata arrived.
        let mut evidence: Vec<serde_json::Value> =
            serde_json::from_str(&current.evidence_json).unwrap_or_default();
        for item in serde_json::from_str::<Vec<serde_json::Value>>(&incoming.evidence_json)
            .unwrap_or_default()
        {
            if !evidence.contains(&item) {
                evidence.push(item);
            }
        }
        current.evidence_json = serde_json::to_string(&evidence).unwrap();
        if app || !known(&current.application_id) {
            current.reason.clone_from(&incoming.reason);
        }
    }
    current.confidence = if known(&current.application_id) {
        current.application_confidence
    } else if known(&current.protocol_id) {
        current.protocol_confidence
    } else {
        current.organization_confidence
    };
}

#[derive(Serialize, Deserialize)]
pub(super) struct RollupMetadata {
    scope: i32,
    direction: i32,
    device_id: i64,
    remote_ip: Vec<u8>,
    protocol: u32,
}

fn json_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

mod pending;
#[cfg(test)]
pub(super) use pending::{CORRECTION_WINDOW_MS, ENDED_GRACE_MS};
pub(super) use pending::{prune, record, restore, restore_active};

pub(super) fn mark_aggregated(tx: &Transaction<'_>, now: i64) -> rusqlite::Result<()> {
    tx.execute("UPDATE flow_rollup_contributions SET hour_upload=upload_bytes,hour_download=download_bytes,
        hour_packets=packets,hour_flows=flow_count WHERE timestamp<?1
        AND (hour_upload!=upload_bytes OR hour_download!=download_bytes OR hour_packets!=packets OR hour_flows!=flow_count)",
        [now/HOUR_MS*HOUR_MS])?;
    tx.execute(
        "UPDATE flow_rollup_contributions SET day_upload=hour_upload,day_download=hour_download,
        day_packets=hour_packets,day_flows=hour_flows WHERE timestamp<?1
        AND (day_upload!=hour_upload OR day_download!=hour_download OR day_packets!=hour_packets OR day_flows!=hour_flows)",
        [now / DAY_MS * DAY_MS],
    )?;
    Ok(())
}

// Store counts already materialized at each tier. New deltas for an old minute
// may arrive before the next aggregation, so an hour/day cannot use minute totals.
pub(super) fn reassign(
    tx: &Transaction<'_>,
    session: &str,
    incoming: &FlowAttribution,
    now: i64,
) -> rusqlite::Result<()> {
    let state: Option<String> = tx
        .query_row(
            "SELECT attribution_json FROM flow_rollup_sessions
        WHERE session_id=?1",
            [session],
            |row| row.get(0),
        )
        .optional()?;
    let Some(state) = state else {
        return Ok(());
    };
    let mut new: FlowAttribution = serde_json::from_str(&state).map_err(json_error)?;
    merge(&mut new, incoming);
    let rows = tx.prepare("SELECT c.timestamp,s.gateway_id,c.scope,c.direction,c.device_id,c.remote_ip,c.protocol,
        c.application_id,c.category_id,c.domain,c.protocol_id,
        c.upload_bytes,c.download_bytes,c.packets,c.flow_count,c.hour_upload,c.hour_download,c.hour_packets,c.hour_flows,
        c.day_upload,c.day_download,c.day_packets,c.day_flows,c.session_ref
        FROM flow_rollup_contributions c JOIN flow_rollup_sessions s ON s.id=c.session_ref
        WHERE s.session_id=?1 AND c.expires_at>?2 AND s.updated_at>?3
            AND (s.ended_at IS NULL OR s.ended_at>?4)")?
        .query_map(params![session,now,now.saturating_sub(pending::CORRECTION_WINDOW_MS),now.saturating_sub(pending::ENDED_GRACE_MS)], |row| {
            let mut counts = [[0_i64;4];3];
            for (tier, values) in counts.iter_mut().enumerate() {
                for (metric,value) in values.iter_mut().enumerate() { *value=row.get(11+tier*4+metric)?; }
            }
            Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?,RollupMetadata {
                scope:row.get(2)?,direction:row.get(3)?,device_id:row.get(4)?,remote_ip:row.get(5)?,protocol:row.get(6)? },
                FlowAttribution { application_id:row.get(7)?,category_id:row.get(8)?,domain:Some(row.get(9)?),
                    protocol_id:row.get(10)?,..FlowAttribution::default() }, counts,row.get::<_,i64>(23)?))
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
    for (timestamp, gateway, metadata, old, counts, id) in rows {
        if application_keys(&old) == application_keys(&new)
            && domain(&old) == domain(&new)
            && scope_keys(&metadata, &old) == scope_keys(&metadata, &new)
        {
            continue;
        }
        for (tier, size, metrics) in [
            ("minute", MINUTE_MS, counts[0]),
            ("hour", HOUR_MS, counts[1]),
            ("day", DAY_MS, counts[2]),
        ] {
            if metrics == [0; 4] {
                continue;
            }
            let bucket = timestamp / size * size;
            transfer(
                tx,
                &format!("traffic_application_{tier}"),
                "application_id, category_id",
                &[bucket.into(), gateway.clone().into()],
                &application_keys(&old),
                &application_keys(&new),
                metrics,
            )?;
            transfer(
                tx,
                &format!("traffic_domain_{tier}"),
                "domain",
                &[bucket.into(), gateway.clone().into()],
                &[domain(&old).into()],
                &[domain(&new).into()],
                metrics,
            )?;
            if tier == "minute" {
                transfer(
                    tx,
                    "traffic_scope_minute",
                    "scope, direction, device_id, application_id, category_id, domain, remote_ip, protocol, protocol_id",
                    &[bucket.into(), gateway.clone().into()],
                    &scope_keys(&metadata, &old),
                    &scope_keys(&metadata, &new),
                    metrics,
                )?;
            }
        }
        tx.execute("UPDATE flow_rollup_contributions SET application_id=?1,category_id=?2,domain=?3,protocol_id=?4
            WHERE session_ref=?5 AND timestamp=?6 AND scope=?7 AND direction=?8 AND device_id=?9 AND remote_ip=?10 AND protocol=?11",
            params![new.application_id,new.category_id,domain(&new),new.protocol_id,id,timestamp,metadata.scope,metadata.direction,metadata.device_id,metadata.remote_ip,metadata.protocol])?;
    }
    let updated = serde_json::to_string(&new).map_err(json_error)?;
    if updated != state {
        tx.execute(
            "UPDATE flow_rollup_sessions SET attribution_json=?1 WHERE session_id=?2",
            params![updated, session],
        )?;
    }
    Ok(())
}

fn domain(attr: &FlowAttribution) -> String {
    attr.domain.clone().unwrap_or_else(|| "unknown".into())
}
fn application_keys(attr: &FlowAttribution) -> Vec<Value> {
    if !known(&attr.application_id) && known(&attr.protocol_id) {
        vec![
            format!("{PROTOCOL_APPLICATION_PREFIX}{}", attr.protocol_id).into(),
            "unknown".to_owned().into(),
        ]
    } else {
        vec![
            attr.application_id.clone().into(),
            attr.category_id.clone().into(),
        ]
    }
}
fn scope_keys(meta: &RollupMetadata, attr: &FlowAttribution) -> Vec<Value> {
    vec![
        i64::from(meta.scope).into(),
        i64::from(meta.direction).into(),
        meta.device_id.into(),
        attr.application_id.clone().into(),
        attr.category_id.clone().into(),
        domain(attr).into(),
        meta.remote_ip.clone().into(),
        i64::from(meta.protocol).into(),
        attr.protocol_id.clone().into(),
    ]
}
fn transfer(
    tx: &Transaction<'_>,
    table: &str,
    dimensions: &str,
    base: &[Value],
    old: &[Value],
    new: &[Value],
    metrics: [i64; 4],
) -> rusqlite::Result<()> {
    if old == new {
        return Ok(());
    }
    let old_keys = [base, old].concat();
    let columns = format!("timestamp, gateway_id, {dimensions}");
    let predicate = columns
        .split(',')
        .enumerate()
        .map(|(i, col)| format!("{}=?{}", col.trim(), i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let exists: bool = tx.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
        rusqlite::params_from_iter(&old_keys),
        |r| r.get(0),
    )?;
    // Retention may have removed the source bucket; never recreate expired data.
    if !exists {
        return Ok(());
    }
    adjust_rollup(
        tx,
        table,
        Some(dimensions),
        &old_keys,
        -metrics[0],
        -metrics[1],
        -metrics[2],
        -metrics[3],
    )?;
    adjust_rollup(
        tx,
        table,
        Some(dimensions),
        &[base, new].concat(),
        metrics[0],
        metrics[1],
        metrics[2],
        metrics[3],
    )?;
    if table.ends_with("_hour") || table.ends_with("_day") {
        // The correction ledger updates already-materialized tiers immediately.
        // Cancel that portion of the queued lower-tier delta to avoid applying
        // the same reclassification again during the next maintenance pass.
        let pending = format!("{table}_pending");
        adjust_rollup(
            tx,
            &pending,
            Some(dimensions),
            &old_keys,
            metrics[0],
            metrics[1],
            metrics[2],
            metrics[3],
        )?;
        adjust_rollup(
            tx,
            &pending,
            Some(dimensions),
            &[base, new].concat(),
            -metrics[0],
            -metrics[1],
            -metrics[2],
            -metrics[3],
        )?;
    }
    tx.execute(&format!("DELETE FROM {table} WHERE {predicate} AND upload_bytes=0 AND download_bytes=0 AND packets=0 AND flow_count=0"),rusqlite::params_from_iter(&old_keys))?;
    Ok(())
}

pub(super) fn reclassify_sqlite(
    storage: &mut SqliteStorage,
    gateway: &str,
    flow: &FlowDelta,
    incoming: &FlowAttribution,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = storage.connection.transaction()?;
    let mut staged = FlowKey::sample_keys(gateway, flow)
        .into_iter()
        .filter_map(|key| {
            let current = storage.active_flows.get(&key)?;
            sample_matches(&key, current, gateway, flow).then(|| (key, current.clone()))
        })
        .collect::<HashMap<_, _>>();
    let mut sessions: HashMap<String,FlowAttribution> = tx.prepare_cached("SELECT id,domain,organization_id,
        application_id,category_id,traffic_role,protocol_id,organization_confidence,application_confidence,
        protocol_confidence,classification_confidence,classification_reason,classification_evidence_json
        FROM flow_sessions WHERE gateway_id=?1 AND ip_version=?2 AND protocol=?3 AND client_ip=?4
        AND client_port=?5 AND remote_ip=?6 AND remote_port=?7 AND started_at<=?8 AND last_seen_at>=?9")?
        .query_map(params![gateway,flow.ip_version,flow.protocol,flow.client_ip,flow.client_port,
            flow.remote_ip,flow.remote_port,to_i64(flow.last_seen_unix_ms.saturating_add(1)),
            to_i64(flow.first_seen_unix_ms.saturating_sub(1))],|row| {
            Ok((row.get(0)?, read_attribution(row, 1)?))
        })?.collect::<rusqlite::Result<_>>()?;
    for current in staged.values_mut() {
        merge(&mut current.attribution, incoming);
        sessions.insert(current.session_id.clone(), current.attribution.clone());
    }
    for (id, mut attr) in sessions {
        merge(&mut attr, incoming);
        reassign(&tx, &id, &attr, now)?;
        tx.prepare_cached("UPDATE flow_sessions SET domain=?1,organization_id=?2,application_id=?3,
            category_id=?4,traffic_role=?5,protocol_id=?6,organization_confidence=?7,application_confidence=?8,
            protocol_confidence=?9,classification_confidence=?10,classification_reason=?11,classification_evidence_json=?12 WHERE id=?13")?
            .execute(params![attr.domain,attr.organization_id,attr.application_id,attr.category_id,attr.traffic_role,
                attr.protocol_id,attr.organization_confidence,attr.application_confidence,attr.protocol_confidence,
                attr.confidence,attr.reason,attr.evidence_json,id])?;
    }
    tx.commit()?;
    storage.active_flows.extend(staged);
    Ok(())
}

pub(super) fn read_attribution(row: &Row<'_>, offset: usize) -> rusqlite::Result<FlowAttribution> {
    let identity = |column| -> rusqlite::Result<String> {
        Ok(row
            .get::<_, Option<String>>(column)?
            .unwrap_or_else(|| "unknown".into()))
    };
    let score =
        |column| -> rusqlite::Result<f64> { Ok(row.get::<_, Option<f64>>(column)?.unwrap_or(0.0)) };
    Ok(FlowAttribution {
        domain: row.get(offset)?,
        organization_id: identity(offset + 1)?,
        application_id: identity(offset + 2)?,
        category_id: identity(offset + 3)?,
        traffic_role: identity(offset + 4)?,
        protocol_id: identity(offset + 5)?,
        organization_confidence: score(offset + 6)?,
        application_confidence: score(offset + 7)?,
        protocol_confidence: score(offset + 8)?,
        confidence: score(offset + 9)?,
        reason: row
            .get::<_, Option<String>>(offset + 10)?
            .unwrap_or_default(),
        evidence_json: row.get(offset + 11)?,
    })
}
