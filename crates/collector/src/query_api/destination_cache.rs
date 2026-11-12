//! Bounded caching and database-side pagination for destination traffic.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::sync::Cache;
use rusqlite::Connection;

use super::to_i64;

type Window = Option<(u64, u64)>;

#[derive(Clone)]
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
    pages: Cache<(Window, u32, u64, u64), Arc<(Vec<DestinationTraffic>, u64)>>,
    totals: Cache<Window, (u64, u64)>,
    total_generation: Arc<AtomicU64>,
}

impl DestinationTrafficCache {
    pub(crate) fn new() -> Self {
        Self {
            pages: Cache::builder()
                .max_capacity(10_000)
                .weigher(
                    |_: &(Window, u32, u64, u64), page: &Arc<(Vec<DestinationTraffic>, u64)>| {
                        u32::try_from(page.0.len().max(1)).unwrap_or(u32::MAX)
                    },
                )
                .time_to_live(Duration::from_secs(2))
                .build(),
            totals: Cache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_secs(2))
                .build(),
            total_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn invalidate_totals(&self) {
        self.total_generation.fetch_add(1, Ordering::AcqRel);
        self.totals.invalidate_all();
    }

    pub(crate) fn page(
        &self,
        connection: &Connection,
        from: Option<u64>,
        to: Option<u64>,
        limit: u32,
        offset: u64,
    ) -> Result<(Vec<DestinationTraffic>, u64), Arc<rusqlite::Error>> {
        self.page_with_cache(connection, from, to, limit, offset, true)
    }

    fn page_with_cache(
        &self,
        connection: &Connection,
        from: Option<u64>,
        to: Option<u64>,
        limit: u32,
        offset: u64,
        use_cache: bool,
    ) -> Result<(Vec<DestinationTraffic>, u64), Arc<rusqlite::Error>> {
        // Preserve the API's existing all-time behavior when either bound is absent.
        let window = from.zip(to);
        let generation = self.total_generation.load(Ordering::Acquire);
        if use_cache && let Some(page) = self.pages.get(&(window, limit, offset, generation)) {
            return Ok(page.as_ref().clone());
        }
        let cached_total = use_cache
            .then(|| {
                self.totals
                    .get(&window)
                    .filter(|(cached_generation, _)| *cached_generation == generation)
                    .map(|(_, total)| total)
            })
            .flatten();
        if let Some(total) = cached_total
            && offset >= total
        {
            if self.total_generation.load(Ordering::Acquire) != generation {
                return self.page_with_cache(connection, from, to, limit, offset, false);
            }
            let rows = Vec::new();
            self.pages.insert(
                (window, limit, offset, generation),
                Arc::new((rows.clone(), total)),
            );
            return Ok((rows, total));
        }
        let (predicate, mut values) = window_params(window);
        // The first page computes the exact grouped count. Subsequent page
        // requests use this invalidation-tagged total instead of recounting.
        let total_expression = cached_total.map_or_else(
            || "COUNT(*) OVER ()".to_owned(),
            |total| to_i64(total).to_string(),
        );
        let sql = format!(
            "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes),
                            SUM(packets), SUM(flow_count), MAX(timestamp), {total_expression}
                     FROM traffic_scope_minute WHERE {predicate}
                     GROUP BY remote_ip
                     ORDER BY SUM(upload_bytes + download_bytes) DESC, hex(remote_ip)
                     LIMIT ? OFFSET ?"
        );
        let count_values = values.clone();
        values.push(i64::from(limit));
        values.push(to_i64(offset));
        let mut statement = connection.prepare(&sql).map_err(Arc::new)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(values), |row| {
                Ok((
                    DestinationTraffic {
                        address: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                        packets: row.get(3)?,
                        flow_count: row.get(4)?,
                        last_seen: row.get(5)?,
                    },
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(Arc::new)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Arc::new)?;
        if cached_total.is_some() && self.total_generation.load(Ordering::Acquire) != generation {
            // A write may invalidate totals while this read runs on the
            // independent query connection. Re-read once without the cached
            // count so the page and total come from a current SQLite snapshot.
            return self.page_with_cache(connection, from, to, limit, offset, false);
        }
        let generation_is_current = self.total_generation.load(Ordering::Acquire) == generation;
        let total = if let Some(total) = rows.first().and_then(|row| row.1).map(super::to_u64) {
            if generation_is_current {
                self.cache_total(window, generation, total);
            }
            total
        } else if let Some(total) = cached_total {
            total
        } else {
            let sql = format!(
                "SELECT COUNT(DISTINCT remote_ip) FROM traffic_scope_minute WHERE {predicate}"
            );
            let total = connection
                .query_row(&sql, rusqlite::params_from_iter(count_values), |row| {
                    row.get::<_, i64>(0).map(super::to_u64)
                })
                .map_err(Arc::new)?;
            if generation_is_current {
                self.cache_total(window, generation, total);
            }
            total
        };
        let rows: Vec<_> = rows.into_iter().map(|row| row.0).collect();
        if generation_is_current {
            self.pages.insert(
                (window, limit, offset, generation),
                Arc::new((rows.clone(), total)),
            );
        }
        Ok((rows, total))
    }

    fn cache_total(&self, window: Window, generation: u64, total: u64) {
        // Tag each value so a query that began before invalidation cannot
        // repopulate the shared cache with a stale total afterward.
        self.totals.insert(window, (generation, total));
    }
}

fn window_params(window: Window) -> (&'static str, Vec<i64>) {
    let scope = netqmon_protocol::v1::FlowScope::Internet as i64;
    match window {
        Some((from, to)) => (
            "scope = ? AND timestamp >= ? AND timestamp < ?",
            vec![scope, to_i64(from), to_i64(to)],
        ),
        None => ("scope = ?", vec![scope]),
    }
}

pub(super) fn geo_sql(from: Option<u64>, to: Option<u64>, wide: bool) -> (String, Vec<i64>) {
    let (predicate, values) = window_params(from.zip(to));
    let total = if wide {
        "netqmon_geo_total(upload_bytes, download_bytes)"
    } else {
        "SUM(upload_bytes), SUM(download_bytes)"
    };
    (
        format!(
            "SELECT remote_ip, {total} FROM traffic_scope_minute WHERE {predicate} GROUP BY remote_ip"
        ),
        values,
    )
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

    // File-backed, deterministic workload; run with --ignored --nocapture in release mode.
    #[test]
    #[ignore = "manual destination query benchmark"]
    fn file_destination_benchmark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("destinations.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE traffic_scope_minute (timestamp INTEGER, scope INTEGER, remote_ip BLOB, upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER); CREATE INDEX scope_time ON traffic_scope_minute(scope, timestamp);").unwrap();
        let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100_000);
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute SELECT (i%1440)*60000, 1, CAST(printf('%08x', i%50000) AS BLOB), i%1000, i%300, 1, 1 FROM n", [rows]).unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let mut durations = Vec::new();
        for _ in 0..10 {
            let cache = DestinationTrafficCache::new();
            let start = std::time::Instant::now();
            let result = cache.page(&connection, None, None, 50, 0).unwrap();
            std::hint::black_box(result);
            durations.push(start.elapsed().as_micros());
        }
        durations.sort_unstable();
        let page_cache = DestinationTrafficCache::new();
        let (first_page, total) = page_cache.page(&connection, None, None, 50, 0).unwrap();
        assert_eq!(first_page.len(), 50);
        let mut page_durations = Vec::new();
        for page in 1..=10_u64 {
            let start = std::time::Instant::now();
            let (page_rows, page_total) = page_cache
                .page(&connection, None, None, 50, page * 50)
                .unwrap();
            page_durations.push(start.elapsed().as_micros());
            assert_eq!(page_rows.len(), 50);
            assert_eq!(page_total, total);
        }
        page_durations.sort_unstable();
        eprintln!(
            "rows={rows} db_bytes={} cold_first_page_p50_us={} p95_us={} p99_us={} next_page_p50_us={} p95_us={} p99_us={}",
            std::fs::metadata(path).unwrap().len(),
            durations[5],
            durations[9],
            durations[9],
            page_durations[5],
            page_durations[9],
            page_durations[9],
        );
    }

    #[test]
    #[ignore = "manual empty destination page benchmark"]
    fn file_destination_empty_page_benchmark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty-destinations.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE traffic_scope_minute (timestamp INTEGER, scope INTEGER, remote_ip BLOB, upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER); CREATE INDEX scope_time ON traffic_scope_minute(scope, timestamp);").unwrap();
        let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute SELECT (i%1440)*60000, 1, CAST(printf('%08x', i%50000) AS BLOB), i%1000, i%300, 1, 1 FROM n", [rows]).unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();

        let cache = DestinationTrafficCache::new();
        let (_, total) = cache.page(&connection, None, None, 50, 0).unwrap();
        let (predicate, values) = window_params(None);
        let sql = format!(
            "SELECT remote_ip, SUM(upload_bytes), SUM(download_bytes),
                    SUM(packets), SUM(flow_count), MAX(timestamp), COUNT(*) OVER ()
             FROM traffic_scope_minute WHERE {predicate}
             GROUP BY remote_ip
             ORDER BY SUM(upload_bytes + download_bytes) DESC, hex(remote_ip)
             LIMIT ? OFFSET ?"
        );
        let mut old = Vec::new();
        for index in 0..10_u64 {
            let offset = total + index + 1;
            let start = std::time::Instant::now();
            match connection.query_row(
                &sql,
                rusqlite::params![values[0], 50, to_i64(offset)],
                |_| Ok(()),
            ) {
                Ok(()) | Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(error) => panic!("old empty-page query failed: {error}"),
            }
            old.push(start.elapsed().as_micros());
        }

        // Old-query samples take longer than the production TTL. Refresh the
        // total before timing cache hits so this measures the hot path.
        assert_eq!(cache.page(&connection, None, None, 50, 0).unwrap().1, total);
        let mut current = Vec::new();
        for index in 0..10_u64 {
            let offset = total + index + 1;
            let start = std::time::Instant::now();
            let (page, cached_total) = cache.page(&connection, None, None, 50, offset).unwrap();
            assert!(page.is_empty());
            assert_eq!(cached_total, total);
            current.push(start.elapsed().as_micros());
        }
        old.sort_unstable();
        current.sort_unstable();
        eprintln!(
            "rows={rows} destinations={total} db_bytes={} old_empty_page_us_p50={} p95={} cached_us_p50={} p95={}",
            std::fs::metadata(path).unwrap().len(),
            old[5],
            old[9],
            current[5],
            current[9]
        );
    }

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
        let (rows, total) = cache
            .page(&connection, Some(1000), Some(3000), 10, 0)
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address, vec![198, 51, 100, 1]);
        assert_eq!(rows[1].address, vec![198, 51, 100, 2]);
        assert_eq!((rows[0].upload_bytes, rows[0].download_bytes), (300, 50));
        assert_eq!(
            (rows[0].packets, rows[0].flow_count, rows[0].last_seen),
            (30, 3, 2000)
        );
        assert_eq!(
            cache
                .page(&connection, Some(2000), Some(3000), 10, 0)
                .unwrap()
                .0[0]
                .address,
            vec![198, 51, 100, 2]
        );
        assert!(
            cache
                .page(&connection, Some(4000), Some(5000), 10, 0)
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(cache.page(&connection, None, None, 10, 0).unwrap().1, 3);
        assert_eq!(
            cache.page(&connection, None, None, 1, 1).unwrap().0[0].address,
            vec![198, 51, 100, 1]
        );
        // A missing bound has always meant all time in these endpoints.
        assert_eq!(
            cache.page(&connection, Some(3000), None, 10, 0).unwrap().1,
            3
        );
    }

    #[test]
    fn page_cache_expires_and_failed_loads_can_retry() {
        let connection = database();
        let cache = DestinationTrafficCache::new();
        assert_eq!(
            cache
                .page(&connection, Some(1000), Some(3000), 10, 0)
                .unwrap()
                .1,
            2
        );
        connection
            .execute(
                "DELETE FROM traffic_scope_minute WHERE remote_ip = X'C6336402'",
                [],
            )
            .unwrap();
        assert_eq!(
            cache
                .page(&connection, Some(1000), Some(3000), 10, 0)
                .unwrap()
                .1,
            2
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert_eq!(
            cache
                .page(&connection, Some(1000), Some(3000), 10, 0)
                .unwrap()
                .1,
            1
        );

        let missing_table = Connection::open_in_memory().unwrap();
        assert!(
            cache
                .page(&missing_table, Some(8000), Some(9000), 10, 0)
                .is_err()
        );
        let recovered = cache
            .page(&connection, Some(8000), Some(9000), 10, 0)
            .unwrap();
        assert!(recovered.0.is_empty());
    }

    #[test]
    fn file_empty_pages_reuse_total_and_refresh_after_invalidation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("destination-total-cache.db");
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             CREATE TABLE traffic_scope_minute (
                 timestamp INTEGER, scope INTEGER, remote_ip BLOB,
                 upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER
             );
             INSERT INTO traffic_scope_minute VALUES
                 (1000, 1, X'C6336401', 100, 20, 10, 1),
                 (2000, 1, X'C6336402', 300, 50, 30, 3);",
            )
            .unwrap();
        let cache = DestinationTrafficCache::new();
        assert_eq!(
            cache
                .page(&connection, Some(1000), Some(3000), 1, 100)
                .unwrap()
                .1,
            2
        );
        connection
            .execute(
                "DELETE FROM traffic_scope_minute WHERE remote_ip=X'C6336402'",
                [],
            )
            .unwrap();
        cache.invalidate_totals();
        // Model an old read completing after invalidation. Its generation tag
        // must prevent it from serving or replacing the current total.
        cache.totals.insert(Some((1000, 3000)), (0, 2));
        assert_eq!(
            cache
                .page(&connection, Some(1000), Some(3000), 1, 101)
                .unwrap()
                .1,
            1
        );
    }

    #[test]
    fn file_page_entries_are_scoped_to_the_write_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("destination-page-generation.db");
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             CREATE TABLE traffic_scope_minute (
                 timestamp INTEGER, scope INTEGER, remote_ip BLOB,
                 upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER
             );
             INSERT INTO traffic_scope_minute VALUES
                 (1000, 1, X'C6336401', 100, 20, 10, 1),
                 (1000, 1, X'C6336402', 200, 30, 20, 2);",
            )
            .unwrap();
        let cache = DestinationTrafficCache::new();
        let original = cache.page(&connection, None, None, 1, 0).unwrap();
        assert_eq!(original.0[0].address, vec![198, 51, 100, 2]);
        assert_eq!(original.1, 2);

        connection
            .execute(
                "INSERT INTO traffic_scope_minute VALUES
                 (2000, 1, X'C6336403', 1000, 0, 1, 1)",
                [],
            )
            .unwrap();
        cache.invalidate_totals();

        let refreshed = cache.page(&connection, None, None, 1, 0).unwrap();
        assert_eq!(refreshed.0[0].address, vec![198, 51, 100, 3]);
        assert_eq!(refreshed.1, 3);
    }

    #[test]
    fn file_page_retries_once_when_total_is_invalidated_during_query() {
        use std::sync::atomic::AtomicBool;

        let dir = tempfile::tempdir().unwrap();
        let connection = Connection::open(dir.path().join("destination-total-race.db")).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             CREATE TABLE traffic_scope_minute (
                 timestamp INTEGER, scope INTEGER, remote_ip BLOB,
                 upload_bytes INTEGER, download_bytes INTEGER, packets INTEGER, flow_count INTEGER
             );
             INSERT INTO traffic_scope_minute VALUES
                 (1000, 1, X'C6336401', 100, 20, 10, 1),
                 (1000, 1, X'C6336402', 200, 30, 20, 2);",
            )
            .unwrap();
        let cache = DestinationTrafficCache::new();
        assert_eq!(cache.page(&connection, None, None, 50, 0).unwrap().1, 2);
        connection
            .execute(
                "INSERT INTO traffic_scope_minute VALUES
                 (2000, 1, X'C6336403', 300, 40, 30, 3)",
                [],
            )
            .unwrap();

        let invalidate_during_query = Arc::new(AtomicBool::new(false));
        let should_invalidate = Arc::clone(&invalidate_during_query);
        let query_cache = cache.clone();
        connection
            .create_scalar_function(
                "hex",
                1,
                rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
                move |_: &rusqlite::functions::Context<'_>| {
                    if should_invalidate.swap(false, Ordering::AcqRel) {
                        query_cache.invalidate_totals();
                    }
                    Ok("00".to_owned())
                },
            )
            .unwrap();
        invalidate_during_query.store(true, Ordering::Release);

        // Use a different page key so the request exercises the cached total
        // while still entering SQL rather than returning the warmed page.
        let (rows, total) = cache.page(&connection, None, None, 51, 0).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(total, 3);
        assert_eq!(cache.page(&connection, None, None, 50, 0).unwrap().1, 3);
    }

    #[test]
    fn page_cache_refreshes_totals_after_write_generation() {
        let connection = database();
        let cache = DestinationTrafficCache::new();
        let first = cache.page(&connection, None, None, 1, 0).unwrap();
        assert_eq!(first.1, 3);
        connection
            .execute(
                "DELETE FROM traffic_scope_minute WHERE remote_ip = X'C6336402'",
                [],
            )
            .unwrap();
        cache.invalidate_totals();
        let next = cache.page(&connection, None, None, 1, 1).unwrap();
        assert_eq!(next.1, 2);
        assert_eq!(cache.page(&connection, None, None, 1, 0).unwrap().1, 2);
    }
}
