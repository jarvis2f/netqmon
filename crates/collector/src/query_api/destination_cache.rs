//! Share the expensive Internet destination aggregation between list/map and geo.

use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use rusqlite::Connection;

use super::to_i64;

type Window = Option<(u64, u64)>;

pub(crate) struct DestinationTraffic {
    pub address: Vec<u8>,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub packets: i64,
    pub flow_count: i64,
    pub last_seen: i64,
}

#[derive(Clone)]
pub(crate) struct DestinationTrafficCache {
    entries: Cache<Window, Arc<Vec<DestinationTraffic>>>,
}

impl DestinationTrafficCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Cache::builder()
                // Bound retained rows across all time windows, including many
                // distinct custom ranges. Empty results still consume a slot.
                .max_capacity(100_000)
                .weigher(|_: &Window, rows: &Arc<Vec<DestinationTraffic>>| {
                    u32::try_from(rows.len().max(1)).unwrap_or(u32::MAX)
                })
                .time_to_live(Duration::from_secs(2))
                .build(),
        }
    }

    pub(crate) fn get(
        &self,
        connection: &Connection,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Arc<Vec<DestinationTraffic>>, Arc<rusqlite::Error>> {
        // Preserve the API's existing all-time behavior when either bound is absent.
        let window = from.zip(to);
        self.entries.try_get_with(window, || {
            let (sql, values) = if let Some((from, to)) = window {
                (
                    "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes),
                            SUM(packets), SUM(flow_count), MAX(timestamp)
                     FROM traffic_scope_minute
                     WHERE scope = ?1 AND timestamp >= ?2 AND timestamp < ?3
                     GROUP BY remote_ip
                     ORDER BY SUM(upload_bytes + download_bytes) DESC, hex(remote_ip)",
                    vec![
                        netqmon_protocol::v1::FlowScope::Internet as i64,
                        to_i64(from),
                        to_i64(to),
                    ],
                )
            } else {
                (
                    "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes),
                            SUM(packets), SUM(flow_count), MAX(timestamp)
                     FROM traffic_scope_minute WHERE scope = ?1
                     GROUP BY remote_ip
                     ORDER BY SUM(upload_bytes + download_bytes) DESC, hex(remote_ip)",
                    vec![netqmon_protocol::v1::FlowScope::Internet as i64],
                )
            };
            let mut statement = connection.prepare(sql)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok(DestinationTraffic {
                        address: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                        packets: row.get(3)?,
                        flow_count: row.get(4)?,
                        last_seen: row.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Arc::new(rows))
        })
    }
}

pub(super) fn destination_metadata_sql() -> &'static str {
    "SELECT ?1, ?2, ?3, ?4, ?5, ?6,
            (SELECT domain FROM flow_sessions
             WHERE remote_ip = ?1 AND domain IS NOT NULL ORDER BY last_seen_at DESC LIMIT 1),
            (SELECT COUNT(DISTINCT device_id) FROM flow_sessions
             WHERE remote_ip = ?1 AND device_id IS NOT NULL),
            (SELECT application_id FROM flow_sessions
             WHERE remote_ip = ?1 AND application_id IS NOT NULL AND application_id != 'unknown'
             ORDER BY last_seen_at DESC LIMIT 1)"
}

pub(super) fn destination_params(row: &DestinationTraffic) -> impl rusqlite::Params {
    // Return owned values so the temporary parameter array cannot outlive its values.
    rusqlite::params_from_iter([
        rusqlite::types::Value::Blob(row.address.clone()),
        row.upload_bytes.into(),
        row.download_bytes.into(),
        row.packets.into(),
        row.flow_count.into(),
        row.last_seen.into(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE traffic_scope_minute (
                timestamp INTEGER, scope INTEGER, remote_ip BLOB,
                upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER);
             INSERT INTO traffic_scope_minute VALUES
                (1000, 1, X'C6336401', 100, 20, 10, 1),
                (2000, 1, X'C6336401', 200, 30, 20, 2),
                (2000, 1, X'C6336402', 300, 50, 30, 3),
                (2000, 2, X'C6336403', 999, 999, 99, 9),
                (3000, 1, X'C6336404', 400, 50, 40, 4);",
            )
            .unwrap();
        connection
    }

    #[test]
    fn aggregates_internet_only_with_exact_bounds_and_deterministic_ties() {
        let connection = database();
        let cache = DestinationTrafficCache::new();
        let rows = cache.get(&connection, Some(1000), Some(3000)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address, vec![198, 51, 100, 1]);
        assert_eq!(rows[1].address, vec![198, 51, 100, 2]);
        assert_eq!((rows[0].upload_bytes, rows[0].download_bytes), (300, 50));
        assert_eq!(
            (rows[0].packets, rows[0].flow_count, rows[0].last_seen),
            (30, 3, 2000)
        );
        assert_eq!(
            cache.get(&connection, Some(2000), Some(3000)).unwrap()[0].address,
            vec![198, 51, 100, 2]
        );
        assert!(
            cache
                .get(&connection, Some(4000), Some(5000))
                .unwrap()
                .is_empty()
        );
        assert_eq!(cache.get(&connection, None, None).unwrap().len(), 3);
        // A missing bound has always meant all time in these endpoints.
        assert_eq!(cache.get(&connection, Some(3000), None).unwrap().len(), 3);
    }

    #[test]
    fn shared_snapshot_expires_and_failed_loads_can_retry() {
        let connection = database();
        let cache = DestinationTrafficCache::new();
        let first = cache.get(&connection, Some(1000), Some(3000)).unwrap();
        let second = cache.get(&connection, Some(1000), Some(3000)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        connection
            .execute("UPDATE traffic_scope_minute SET upload_bytes = 0", [])
            .unwrap();
        assert_eq!(
            cache.get(&connection, Some(1000), Some(3000)).unwrap()[0].upload_bytes,
            300
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert_eq!(
            cache.get(&connection, Some(1000), Some(3000)).unwrap()[0].upload_bytes,
            0
        );

        let missing_table = Connection::open_in_memory().unwrap();
        assert!(cache.get(&missing_table, Some(8000), Some(9000)).is_err());
        let recovered = cache.get(&connection, Some(8000), Some(9000)).unwrap();
        assert!(recovered.is_empty());
    }
}
