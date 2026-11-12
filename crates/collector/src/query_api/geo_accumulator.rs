use std::collections::HashMap;

use rusqlite::{Connection, params};
use serde_json::{Value, json};

pub(super) struct ReadSnapshot<'a> {
    connection: &'a Connection,
    active: bool,
}

impl<'a> ReadSnapshot<'a> {
    pub(super) fn begin(connection: &'a Connection) -> rusqlite::Result<Self> {
        connection.execute_batch("SAVEPOINT netqmon_geo_snapshot")?;
        Ok(Self {
            connection,
            active: true,
        })
    }

    pub(super) fn finish(mut self) -> rusqlite::Result<()> {
        self.connection
            .execute_batch("RELEASE netqmon_geo_snapshot")?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ReadSnapshot<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self
                .connection
                .execute_batch("ROLLBACK TO netqmon_geo_snapshot; RELEASE netqmon_geo_snapshot");
        }
    }
}

struct SqliteGeoTotal;

impl rusqlite::functions::Aggregate<i128, Vec<u8>> for SqliteGeoTotal {
    fn init(&self, _: &mut rusqlite::functions::Context<'_>) -> rusqlite::Result<i128> {
        Ok(0)
    }

    fn step(
        &self,
        context: &mut rusqlite::functions::Context<'_>,
        total: &mut i128,
    ) -> rusqlite::Result<()> {
        *total = total
            .saturating_add(i128::from(context.get::<i64>(0)?))
            .saturating_add(i128::from(context.get::<i64>(1)?));
        Ok(())
    }

    fn finalize(
        &self,
        _: &mut rusqlite::functions::Context<'_>,
        total: Option<i128>,
    ) -> rusqlite::Result<Vec<u8>> {
        let total = total.unwrap_or(0).clamp(0, i128::from(u64::MAX));
        Ok(u64::try_from(total)
            .expect("clamped to u64")
            .to_be_bytes()
            .to_vec())
    }
}

pub(super) fn register_sqlite_total(connection: &Connection) -> rusqlite::Result<()> {
    connection.create_aggregate_function(
        "netqmon_geo_total",
        2,
        rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        SqliteGeoTotal,
    )
}

// Most installations fit in memory. Large cardinalities spill to a private,
// automatically deleted SQLite temporary database rather than growing the heap.
const GROUP_LIMIT: usize = 4096;

pub(super) struct GeoAccumulator {
    countries: HashMap<(String, String), u64>,
    asns: HashMap<(u32, String), u64>,
    unknown: u64,
    scratch: Option<Connection>,
    limit: usize,
}

impl GeoAccumulator {
    pub(super) fn new() -> Self {
        Self {
            countries: HashMap::new(),
            asns: HashMap::new(),
            unknown: 0,
            scratch: None,
            limit: GROUP_LIMIT,
        }
    }

    pub(super) fn add_unknown(&mut self, bytes: u64) {
        self.unknown = self.unknown.saturating_add(bytes);
    }

    pub(super) fn add_country(
        &mut self,
        code: String,
        name: String,
        bytes: u64,
    ) -> rusqlite::Result<()> {
        let total = self.countries.entry((code, name)).or_default();
        *total = total.saturating_add(bytes);
        self.maybe_flush()
    }

    pub(super) fn add_asn(
        &mut self,
        asn: u32,
        organization: String,
        bytes: u64,
    ) -> rusqlite::Result<()> {
        let total = self.asns.entry((asn, organization)).or_default();
        *total = total.saturating_add(bytes);
        self.maybe_flush()
    }

    fn maybe_flush(&mut self) -> rusqlite::Result<()> {
        if self.countries.len() + self.asns.len() < self.limit {
            return Ok(());
        }
        self.flush()
    }

    fn flush(&mut self) -> rusqlite::Result<()> {
        if self.scratch.is_none() {
            let db = Connection::open("")?;
            db.execute_batch("PRAGMA temp_store=FILE; PRAGMA cache_size=-2048; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
                CREATE TABLE countries(code TEXT NOT NULL,name TEXT NOT NULL,hi INTEGER NOT NULL,lo INTEGER NOT NULL,PRIMARY KEY(code,name)) WITHOUT ROWID;
                CREATE TABLE asns(asn INTEGER NOT NULL,organization TEXT NOT NULL,hi INTEGER NOT NULL,lo INTEGER NOT NULL,PRIMARY KEY(asn,organization)) WITHOUT ROWID;")?;
            self.scratch = Some(db);
        }
        let tx = self
            .scratch
            .as_mut()
            .expect("scratch initialized")
            .transaction()?;
        // Store unsigned counters as two 32-bit words; SQLite INTEGER alone
        // cannot represent the full saturating u64 range used by the API.
        let update = "hi=CASE WHEN hi+excluded.hi+(lo+excluded.lo)/4294967296>4294967295 THEN 4294967295 ELSE hi+excluded.hi+(lo+excluded.lo)/4294967296 END, lo=CASE WHEN hi+excluded.hi+(lo+excluded.lo)/4294967296>4294967295 THEN 4294967295 ELSE (lo+excluded.lo)%4294967296 END";
        {
            let mut country = tx.prepare(&format!("INSERT INTO countries VALUES(?1,?2,?3,?4) ON CONFLICT(code,name) DO UPDATE SET {update}"))?;
            for ((code, name), bytes) in &self.countries {
                country.execute(params![
                    code,
                    name,
                    i64::try_from(bytes >> 32).expect("high word fits i64"),
                    i64::try_from(bytes & u64::from(u32::MAX)).expect("low word fits i64")
                ])?;
            }
            let mut asn = tx.prepare(&format!("INSERT INTO asns VALUES(?1,?2,?3,?4) ON CONFLICT(asn,organization) DO UPDATE SET {update}"))?;
            for ((number, organization), bytes) in &self.asns {
                asn.execute(params![
                    number,
                    organization,
                    i64::try_from(bytes >> 32).expect("high word fits i64"),
                    i64::try_from(bytes & u64::from(u32::MAX)).expect("low word fits i64")
                ])?;
            }
        }
        tx.commit()?;
        self.countries.clear();
        self.asns.clear();
        Ok(())
    }

    pub(super) fn finish(mut self) -> rusqlite::Result<Value> {
        if self.scratch.is_none() {
            return Ok(super::geo_summary_value(
                self.countries,
                self.asns,
                self.unknown,
            ));
        }
        self.flush()?;
        let db = self.scratch.as_ref().expect("scratch initialized");
        let mut top_countries = Vec::new();
        let mut distribution = Vec::new();
        let mut other = 0_u64;
        let mut has_other = false;
        let visible = if self.unknown > 0 { 4 } else { 5 };
        let mut stmt = db.prepare(
            "SELECT code,name,hi,lo FROM countries ORDER BY hi DESC,lo DESC,code ASC,name ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut index = 0;
        while let Some(row) = rows.next()? {
            let bytes = words(row.get(2)?, row.get(3)?);
            if index < 5 {
                let value = json!({"country_code": row.get::<_, String>(0)?, "country_name": row.get::<_, String>(1)?, "bytes": bytes});
                top_countries.push(value.clone());
                if index < visible {
                    distribution.push(value);
                }
            }
            if index >= visible {
                other = other.saturating_add(bytes);
                has_other = true;
            }
            index += 1;
        }
        if has_other {
            distribution.push(json!({"country_code":"other","country_name":"Other","bytes":other}));
        }
        if self.unknown > 0 {
            distribution.push(
                json!({"country_code":"unknown","country_name":"Unknown","bytes":self.unknown}),
            );
        }
        distribution.sort_by(|a, b| b["bytes"].as_u64().cmp(&a["bytes"].as_u64()));
        let mut stmt = db.prepare("SELECT asn,organization,hi,lo FROM asns ORDER BY hi DESC,lo DESC,asn ASC,organization ASC LIMIT 5")?;
        let top_asns = stmt.query_map([], |row| Ok(json!({"asn": row.get::<_, u32>(0)?, "organization": row.get::<_, String>(1)?, "bytes": words(row.get(2)?, row.get(3)?)})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(
            json!({"enabled":true,"top_countries":top_countries,"top_asns":top_asns,"country_distribution":distribution}),
        )
    }
}

fn words(hi: u32, lo: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_read_snapshot_releases_on_error_and_nests_in_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let connection = Connection::open(dir.path().join("snapshot.db")).unwrap();
        connection
            .execute_batch("CREATE TABLE t(value INTEGER); BEGIN; INSERT INTO t VALUES (1)")
            .unwrap();
        {
            let _snapshot = ReadSnapshot::begin(&connection).unwrap();
            assert!(connection.execute("SELECT * FROM missing", []).is_err());
        }
        assert!(!connection.is_autocommit());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        connection.execute_batch("ROLLBACK").unwrap();
        assert!(connection.is_autocommit());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _snapshot = ReadSnapshot::begin(&connection).unwrap();
            panic!("exercise snapshot cleanup");
        }));
        assert!(connection.is_autocommit());
    }

    #[test]
    fn file_sqlite_geo_total_saturates_only_after_signed_aggregation() {
        let dir = tempfile::tempdir().unwrap();
        let connection = Connection::open(dir.path().join("geo-total.db")).unwrap();
        register_sqlite_total(&connection).unwrap();
        connection.execute_batch("CREATE TABLE input(group_id INTEGER, up INTEGER, down INTEGER); INSERT INTO input VALUES (1,-10,2),(1,0,3),(2,-10,20),(2,5,-3)").unwrap();
        connection
            .execute("INSERT INTO input VALUES (3,?1,?1),(3,1,1)", [i64::MAX])
            .unwrap();
        for (group, expected) in [(1, 0_u64), (2, 12), (3, u64::MAX)] {
            let value: Vec<u8> = connection
                .query_row(
                    "SELECT netqmon_geo_total(up,down) FROM input WHERE group_id=?1",
                    [group],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), expected);
        }
    }

    #[test]
    fn spill_matches_in_memory_with_unsigned_saturation() {
        let mut spill = GeoAccumulator::new();
        spill.limit = 3;
        let mut memory = GeoAccumulator::new();
        for accumulator in [&mut spill, &mut memory] {
            for n in 0..9_u32 {
                accumulator
                    .add_country(format!("C{n}"), format!("Country {n}"), u64::from(n) * 100)
                    .unwrap();
                accumulator
                    .add_asn(n, format!("Org {n}"), u64::from(n) * 100)
                    .unwrap();
            }
            for value in [u64::MAX - 10, 9, 10] {
                accumulator
                    .add_country("C0".into(), "Country 0".into(), value)
                    .unwrap();
                accumulator.add_asn(0, "Org 0".into(), value).unwrap();
            }
            accumulator.add_unknown(17);
        }
        assert!(spill.scratch.is_some());
        assert_eq!(spill.finish().unwrap(), memory.finish().unwrap());
    }

    #[test]
    fn spill_matches_in_memory_without_unknown_and_with_carry() {
        let mut spill = GeoAccumulator::new();
        spill.limit = 2;
        let mut memory = GeoAccumulator::new();
        for accumulator in [&mut spill, &mut memory] {
            for n in 0..12_u32 {
                accumulator
                    .add_country(format!("C{n:02}"), format!("Country {n}"), u64::from(n))
                    .unwrap();
                accumulator
                    .add_asn(n, format!("Org {n}"), u64::from(n))
                    .unwrap();
            }
            for value in [u64::from(u32::MAX), 5, 1_u64 << 63] {
                accumulator
                    .add_country("C00".into(), "Country 0".into(), value)
                    .unwrap();
                accumulator.add_asn(0, "Org 0".into(), value).unwrap();
            }
        }
        assert_eq!(spill.finish().unwrap(), memory.finish().unwrap());
    }
}
