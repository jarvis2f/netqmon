use super::*;
use std::time::Instant;

fn correction_page_fixture(rows: i64) -> (tempfile::TempDir, SqliteStorage, String) {
    let directory = tempdir().unwrap();
    let mut storage = open_at(&directory.path().join("correction-pages.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage
        .persist_classified_batch(
            &batch(1, FlowLifecycle::Active),
            &[transport_attribution()],
            &[],
            NOW,
        )
        .unwrap();
    let db = storage.connection();
    let session: String = db
        .query_row("SELECT session_id FROM flow_rollup_sessions", [], |r| {
            r.get(0)
        })
        .unwrap();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_rollup_contributions SELECT c.session_ref,c.timestamp,c.scope,c.direction,10000+i,c.remote_ip,c.protocol,c.application_id,c.category_id,c.domain,c.protocol_id,1,0,1,1,0,0,0,0,0,0,0,0,c.expires_at FROM flow_rollup_contributions c CROSS JOIN n WHERE c.device_id<10000", [rows]).unwrap();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute SELECT s.timestamp,s.gateway_id,s.scope,s.direction,10000+i,s.application_id,s.category_id,s.domain,s.remote_ip,s.protocol,s.protocol_id,1,0,1,1 FROM traffic_scope_minute s CROSS JOIN n WHERE s.device_id<10000", [rows]).unwrap();
    for table in ["traffic_application_minute", "traffic_domain_minute"] {
        db.execute(&format!("UPDATE {table} SET upload_bytes=upload_bytes+?1,packets=packets+?1,flow_count=flow_count+?1"), [rows]).unwrap();
    }
    (directory, storage, session)
}

#[test]
fn file_correction_many_contributions_remains_exact_and_atomic() {
    let (_directory, mut storage, session) = correction_page_fixture(600);
    storage.connection().execute_batch("CREATE TRIGGER reject_late_correction BEFORE UPDATE OF application_id ON flow_rollup_contributions WHEN OLD.device_id=10550 BEGIN SELECT RAISE(ABORT,'injected late correction failure'); END").unwrap();
    {
        let tx = storage.connection.transaction().unwrap();
        assert!(
            attribution::reassign(&tx, &session, &service_attribution(), to_i64(NOW + 1)).is_err()
        );
        tx.rollback().unwrap();
    }
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (0, 0, 0, 0)
    );
    let unchanged: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_rollup_contributions WHERE application_id!='unknown'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unchanged, 0);
    storage
        .connection()
        .execute_batch("DROP TRIGGER reject_late_correction")
        .unwrap();
    {
        let tx = storage.connection.transaction().unwrap();
        attribution::reassign(&tx, &session, &service_attribution(), to_i64(NOW + 1)).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_application_minute",
            "application_id='video-app'"
        ),
        (700, 50, 603, 601)
    );
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_domain_minute",
            "domain='video.example.test'"
        ),
        (700, 50, 603, 601)
    );
    assert_eq!(
        metrics(
            storage.connection(),
            "traffic_scope_minute",
            "application_id='video-app'"
        ),
        (700, 50, 603, 601)
    );
    let corrected: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_rollup_contributions WHERE application_id='video-app'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(corrected, 601);
}

#[test]
fn file_correction_handles_page_boundaries_and_expired_rows() {
    // Includes exactly one and two full 256-row pages (the fixture adds one).
    for rows in [255_i64, 256, 511, 512] {
        let (_directory, mut storage, session) = correction_page_fixture(rows);
        storage
            .connection()
            .execute(
                "UPDATE flow_rollup_contributions SET expires_at=?1 WHERE device_id=10001",
                [to_i64(NOW)],
            )
            .unwrap();
        for _ in 0..2 {
            let tx = storage.connection.transaction().unwrap();
            attribution::reassign(&tx, &session, &service_attribution(), to_i64(NOW + 1)).unwrap();
            tx.commit().unwrap();
        }
        let corrected: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM flow_rollup_contributions WHERE application_id='video-app'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let expired: i64 = storage.connection().query_row("SELECT COUNT(*) FROM flow_rollup_contributions WHERE device_id=10001 AND application_id='unknown'", [], |r| r.get(0)).unwrap();
        assert_eq!((corrected, expired), (rows, 1));
        assert_eq!(
            metrics(
                storage.connection(),
                "traffic_application_minute",
                "application_id='video-app'"
            ),
            (99 + rows, 50, 2 + rows, rows)
        );
        assert_eq!(
            metrics(
                storage.connection(),
                "traffic_scope_minute",
                "application_id='video-app'"
            ),
            (99 + rows, 50, 2 + rows, rows)
        );
    }
}

#[test]
fn file_correction_continuation_uses_primary_key_without_sorting() {
    let (_directory, storage, session) = correction_page_fixture(2);
    let sql = "EXPLAIN QUERY PLAN SELECT c.timestamp,c.scope,c.direction,c.device_id,c.remote_ip,c.protocol FROM flow_rollup_contributions c JOIN flow_rollup_sessions s ON s.id=c.session_ref WHERE s.session_id=?1 AND c.expires_at>?2 AND s.updated_at>?3 AND (s.ended_at IS NULL OR s.ended_at>?4) AND (c.timestamp,c.scope,c.direction,c.device_id,c.remote_ip,c.protocol)>(?5,?6,?7,?8,?9,?10) ORDER BY c.timestamp,c.scope,c.direction,c.device_id,c.remote_ip,c.protocol LIMIT 256";
    let mut statement = storage.connection().prepare(sql).unwrap();
    let plan = statement
        .query_map(
            params![session, to_i64(NOW), 0, 0, 0, 0, 0, 0, Vec::<u8>::new(), 0],
            |r| r.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("SEARCH c USING PRIMARY KEY")),
        "{plan:?}"
    );
    assert!(
        !plan.iter().any(|line| line.contains("TEMP B-TREE")),
        "{plan:?}"
    );
}

#[test]
fn file_correction_pages_across_all_primary_key_dimensions() {
    let (_directory, mut storage, session) = correction_page_fixture(600);
    let db = storage.connection();
    // Exercise continuation across timestamps, scope, direction, IP and
    // protocol, including many rows sharing the same device ID.
    let change = "timestamp=timestamp+(device_id%3)*60000,scope=device_id%2,direction=device_id%3,remote_ip=unhex(printf('%08x',device_id)),protocol=CASE WHEN device_id%2=0 THEN 6 ELSE 17 END,device_id=10000";
    db.execute(
        &format!("UPDATE flow_rollup_contributions SET {change} WHERE device_id>=10000"),
        [],
    )
    .unwrap();
    db.execute(
        &format!("UPDATE traffic_scope_minute SET {change} WHERE device_id>=10000"),
        [],
    )
    .unwrap();
    db.execute_batch("DELETE FROM traffic_application_minute; INSERT INTO traffic_application_minute SELECT timestamp,gateway_id,application_id,category_id,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count) FROM traffic_scope_minute GROUP BY timestamp,gateway_id,application_id,category_id; DELETE FROM traffic_domain_minute; INSERT INTO traffic_domain_minute SELECT timestamp,gateway_id,domain,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count) FROM traffic_scope_minute GROUP BY timestamp,gateway_id,domain;").unwrap();
    let tx = storage.connection.transaction().unwrap();
    attribution::reassign(&tx, &session, &service_attribution(), to_i64(NOW + 1)).unwrap();
    tx.commit().unwrap();
    for table in [
        "traffic_application_minute",
        "traffic_domain_minute",
        "traffic_scope_minute",
    ] {
        assert_eq!(
            metrics(storage.connection(), table, "1=1"),
            (700, 50, 603, 601),
            "{table}"
        );
    }
    let corrected: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM flow_rollup_contributions WHERE application_id='video-app'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(corrected, 601);
}

#[test]
#[ignore = "manual file-backed correction materialization benchmark"]
fn file_correction_many_contributions_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let (_directory, mut storage, session) = correction_page_fixture(rows);
    let memory = || {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let before_memory = memory();
    let mut times = Vec::new();
    for _ in 0..5 {
        let tx = storage.connection.transaction().unwrap();
        let started = Instant::now();
        attribution::reassign(&tx, &session, &service_attribution(), to_i64(NOW + 1)).unwrap();
        times.push(started.elapsed().as_millis());
        tx.rollback().unwrap();
    }
    times.sort_unstable();
    eprintln!(
        "correction_rows={} p50_ms={} max_ms={} before={before_memory:?} after={:?}",
        rows + 1,
        times[2],
        times[4],
        memory()
    );
}

#[test]
#[ignore = "manual file-backed correction and concurrent writer benchmark"]
fn file_correction_concurrent_writer_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let (directory, mut storage, session) = correction_page_fixture(rows);
    let writer = Connection::open(directory.path().join("correction-pages.db")).unwrap();
    writer.busy_timeout(Duration::from_secs(5)).unwrap();
    let mut waits = Vec::new();
    for _ in 0..5 {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let session = &session;
            let storage = &mut storage;
            let correction = scope.spawn(move || {
                let tx = storage.connection.transaction().unwrap();
                ready_tx.send(()).unwrap();
                attribution::reassign(&tx, session, &service_attribution(), to_i64(NOW + 1))
                    .unwrap();
                tx.rollback().unwrap();
            });
            ready_rx.recv().unwrap();
            let start = Instant::now();
            let changed = writer
                .execute(
                    "UPDATE flow_rollup_sessions SET last_seen_at=last_seen_at WHERE id=1",
                    [],
                )
                .unwrap();
            waits.push(start.elapsed().as_millis());
            assert_eq!(changed, 1);
            correction.join().unwrap();
        });
    }
    waits.sort_unstable();
    eprintln!(
        "correction_writer_rows={} p50_ms={} max_ms={}",
        rows + 1,
        waits[2],
        waits[4]
    );
}

#[test]
fn file_contribution_narrow_key_conflict_rolls_back_without_data_loss() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("contribution-conflict.db");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE flow_rollup_sessions(id INTEGER PRIMARY KEY); INSERT INTO flow_rollup_sessions VALUES (1)").unwrap();
    let migration =
        include_str!("../../../../migrations/sqlite/0006_flow_rollup_contributions.sql");
    let original = format!(
        "CREATE TABLE flow_rollup_contributions{}",
        migration
            .split_once("CREATE TABLE flow_rollup_contributions")
            .unwrap()
            .1
    );
    db.execute_batch(&original).unwrap();
    db.execute("INSERT INTO flow_rollup_contributions VALUES (1,1000,1,1,7,X'C0000201',6,'app','cat','example','tcp',1,2,3,1,0,0,0,0,0,0,0,0,2000),(1,1000,1,2,7,X'C0000201',6,'app','cat','example','tcp',4,5,6,1,0,0,0,0,0,0,0,0,2000)", []).unwrap();
    let candidate = original
        .split_once("CREATE INDEX")
        .unwrap()
        .0
        .replace(
            "CREATE TABLE flow_rollup_contributions",
            "CREATE TABLE candidate",
        )
        .replace(
            "PRIMARY KEY(session_ref, timestamp, scope, direction, device_id, remote_ip, protocol)",
            "PRIMARY KEY(session_ref, timestamp, scope, device_id)",
        );
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    db.execute_batch(&candidate).unwrap();
    assert!(
        db.execute(
            "INSERT INTO candidate SELECT * FROM flow_rollup_contributions",
            []
        )
        .is_err()
    );
    db.execute_batch("ROLLBACK").unwrap();
    drop(db);
    let db = Connection::open(&path).unwrap();
    let (count, upload): (i64, i64) = db
        .query_row(
            "SELECT COUNT(*),SUM(upload_bytes) FROM flow_rollup_contributions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, upload), (2, 5));
    let candidate_exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='candidate')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!candidate_exists);
}

#[test]
#[ignore = "manual file-backed correction contribution layout experiment"]
fn file_contribution_layout_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempdir().unwrap();
    for layout in ["without_rowid", "rowid", "narrow_key"] {
        let path = directory.path().join(format!("{layout}.db"));
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE flow_rollup_sessions(id INTEGER PRIMARY KEY)").unwrap();
        let migration =
            include_str!("../../../../migrations/sqlite/0006_flow_rollup_contributions.sql");
        let schema = format!(
            "CREATE TABLE flow_rollup_contributions{}",
            migration
                .split_once("CREATE TABLE flow_rollup_contributions")
                .unwrap()
                .1
        );
        let schema = match layout {
            "rowid" => schema.replace(") WITHOUT ROWID;", ");"),
            "narrow_key" => schema.replace(
                "PRIMARY KEY(session_ref, timestamp, scope, direction, device_id, remote_ip, protocol)",
                "PRIMARY KEY(session_ref, timestamp, scope, device_id)",
            ),
            _ => schema,
        };
        db.execute_batch(&schema).unwrap();
        db.execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_rollup_sessions SELECT i FROM n",
            [(rows + 9) / 10],
        ).unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        let start = Instant::now();
        db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_rollup_contributions SELECT (i+9)/10,?2+(i%10)*60000,1,1,i%1000,unhex(printf('%08x',((i+9)/10)%50000)),6,printf('app-%d',i%100),printf('cat-%d',i%10),printf('domain-%d.example',i%10000),'tcp',i%1000,i%500,1,1,0,0,0,0,0,0,0,0,?2+i FROM n", params![rows,to_i64(NOW)]).unwrap();
        let insert_ms = start.elapsed().as_millis();
        let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        let file_bytes = std::fs::metadata(&path).unwrap().len();
        let mut statement = db.prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name LIKE '%flow_rollup_contributions%' GROUP BY name ORDER BY name").unwrap();
        let sizes = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let key_columns = if layout == "narrow_key" {
            "session_ref,timestamp,scope,device_id"
        } else {
            "session_ref,timestamp,scope,direction,device_id,remote_ip,protocol"
        };
        let plan_sql = format!(
            "SELECT {key_columns} FROM flow_rollup_contributions WHERE expires_at<=?1 LIMIT 500"
        );
        let mut stmt = db
            .prepare(&format!("EXPLAIN QUERY PLAN {plan_sql}"))
            .unwrap();
        let plan = stmt
            .query_map([to_i64(NOW) + rows / 2], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut delete = Vec::new();
        let mut session = Vec::new();
        for _ in 0..10 {
            db.execute_batch("SAVEPOINT experiment").unwrap();
            let start = Instant::now();
            let removed = db.execute(&format!("DELETE FROM flow_rollup_contributions WHERE ({key_columns}) IN (SELECT {key_columns} FROM flow_rollup_contributions WHERE expires_at<=?1 LIMIT 500)"),[to_i64(NOW)+rows/2]).unwrap();
            delete.push(start.elapsed().as_micros());
            assert_eq!(removed, 500);
            db.execute_batch("ROLLBACK TO experiment; RELEASE experiment")
                .unwrap();
            let start = Instant::now();
            let count: i64 = db.query_row("SELECT COUNT(*) FROM flow_rollup_contributions WHERE session_ref=?1 AND expires_at>?2", params![rows/20,to_i64(NOW)], |r| r.get(0)).unwrap();
            session.push(start.elapsed().as_micros());
            assert_eq!(count, 10);
        }
        delete.sort_unstable();
        session.sort_unstable();
        let total: i64 = db
            .query_row("SELECT COUNT(*) FROM flow_rollup_contributions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(total, rows);
        eprintln!(
            "contribution_layout={} rows={rows} file_bytes={file_bytes} wal_bytes={wal_bytes} insert_ms={insert_ms} delete500_p50_us={} delete500_max_us={} session_p50_us={} objects={sizes:?} plan={plan:?}",
            layout, delete[5], delete[9], session[5]
        );
        if layout == "without_rowid" && std::env::var_os("NETQMON_BENCH_MIGRATE").is_some() {
            drop(stmt);
            drop(statement);
            let before_sum: i64 = db
                .query_row(
                    "SELECT SUM(upload_bytes+download_bytes) FROM flow_rollup_contributions",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let candidate = schema.split_once("CREATE INDEX").unwrap().0
                .replace("CREATE TABLE flow_rollup_contributions", "CREATE TABLE migration_candidate")
                .replace("PRIMARY KEY(session_ref, timestamp, scope, direction, device_id, remote_ip, protocol)", "PRIMARY KEY(session_ref, timestamp, scope, device_id)");
            let other_writer = Connection::open(&path).unwrap();
            other_writer
                .busy_timeout(std::time::Duration::ZERO)
                .unwrap();
            let started = Instant::now();
            db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let competing =
                other_writer.execute("UPDATE flow_rollup_sessions SET id=id WHERE id=1", []);
            assert!(
                matches!(competing, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy)
            );
            db.execute_batch(&candidate).unwrap();
            db.execute(
                "INSERT INTO migration_candidate SELECT * FROM flow_rollup_contributions",
                [],
            )
            .unwrap();
            db.execute_batch("DROP TABLE flow_rollup_contributions; ALTER TABLE migration_candidate RENAME TO flow_rollup_contributions; CREATE INDEX flow_rollup_contributions_expiry ON flow_rollup_contributions(expires_at); COMMIT;").unwrap();
            let elapsed_ms = started.elapsed().as_millis();
            let migration_wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
                .unwrap()
                .len();
            let (after_count, after_sum): (i64, i64) = db.query_row("SELECT COUNT(*), SUM(upload_bytes+download_bytes) FROM flow_rollup_contributions", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
            assert_eq!((after_count, after_sum), (rows, before_sum));
            let old_upsert = "INSERT INTO flow_rollup_contributions SELECT * FROM flow_rollup_contributions WHERE 0 ON CONFLICT(session_ref,timestamp,scope,direction,device_id,remote_ip,protocol) DO NOTHING";
            assert!(
                db.prepare(old_upsert).is_err(),
                "old writer unexpectedly remained compatible"
            );
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
            let after_bytes = std::fs::metadata(&path).unwrap().len();
            let freelist: i64 = db
                .pragma_query_value(None, "freelist_count", |r| r.get(0))
                .unwrap();
            eprintln!(
                "contribution_migration_rows={rows} lock_ms={elapsed_ms} wal_bytes={migration_wal_bytes} file_before={file_bytes} file_after={after_bytes} freelist_pages={freelist} old_upsert_incompatible=true"
            );
        }
    }
}

const EXPERIMENTAL_RECOVERY_EXPIRY: &str = "CASE WHEN ended_at IS NULL THEN updated_at WHEN ended_at < -9223372036853575808 THEN -9223372036854775808 ELSE min(updated_at, ended_at-1200000) END";

#[test]
fn file_recovery_expiry_expression_matches_original_boundaries() {
    let directory = tempdir().unwrap();
    let db = Connection::open(directory.path().join("expiry-boundaries.db")).unwrap();
    db.execute_batch("CREATE TABLE sample(updated_at INTEGER NOT NULL, ended_at INTEGER)")
        .unwrap();
    let values = [
        i64::MIN,
        i64::MIN + 1_199_999,
        -1_200_001,
        -1,
        0,
        1,
        600_000,
        1_800_000,
        i64::MAX - 1,
        i64::MAX,
    ];
    for updated in values {
        for ended in std::iter::once(None).chain(values.into_iter().map(Some)) {
            db.execute("INSERT INTO sample VALUES (?1,?2)", params![updated, ended])
                .unwrap();
        }
    }
    for now in [0_i64, 1, 600_000, 1_800_000, i64::MAX - 1, i64::MAX] {
        let ended_cutoff = now.saturating_sub(600_000);
        let updated_cutoff = now.saturating_sub(1_800_000);
        let sql = format!(
            "SELECT COUNT(*) FROM sample WHERE (((ended_at IS NOT NULL AND ended_at<=?1) OR updated_at<=?2) IS NOT ({EXPERIMENTAL_RECOVERY_EXPIRY}<=?2))"
        );
        let differences: i64 = db
            .query_row(&sql, params![ended_cutoff, updated_cutoff], |r| r.get(0))
            .unwrap();
        assert_eq!(differences, 0, "now={now}");
    }
}

#[test]
fn file_recovery_expiry_index_ddl_rollback_preserves_rows() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("expiry-ddl.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let input = batch(1, FlowLifecycle::Active);
    let expected = i64::try_from(input.flows[0].upload_bytes).unwrap();
    storage.persist_batch(&input, NOW).unwrap();
    let make_index = format!(
        "CREATE INDEX experimental_recovery_expiry ON flow_rollup_sessions((ended_at IS NULL),{EXPERIMENTAL_RECOVERY_EXPIRY})"
    );
    storage.connection().execute_batch(&format!("BEGIN IMMEDIATE; DROP INDEX flow_rollup_sessions_updated; DROP INDEX flow_rollup_sessions_ended; {make_index}; ROLLBACK")).unwrap();
    drop(storage);
    let storage = open_at(&path, NOW).unwrap();
    let old_indexes: i64 = storage.connection().query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('flow_rollup_sessions_updated','flow_rollup_sessions_ended')", [], |r| r.get(0)).unwrap();
    assert_eq!(old_indexes, 2);
    storage.connection().execute_batch(&format!("BEGIN IMMEDIATE; DROP INDEX flow_rollup_sessions_updated; DROP INDEX flow_rollup_sessions_ended; {make_index}; COMMIT")).unwrap();
    storage.connection().execute_batch("BEGIN IMMEDIATE; DROP INDEX experimental_recovery_expiry; CREATE INDEX flow_rollup_sessions_updated ON flow_rollup_sessions(updated_at); CREATE INDEX flow_rollup_sessions_ended ON flow_rollup_sessions(ended_at) WHERE ended_at IS NOT NULL; ROLLBACK").unwrap();
    let index_exists: bool = storage.connection().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='experimental_recovery_expiry')", [], |r| r.get(0)).unwrap();
    assert!(index_exists);
    let bytes: i64 = storage
        .connection()
        .query_row(
            "SELECT SUM(upload_bytes) FROM flow_rollup_sessions",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes, expected);
    let integrity: String = storage
        .connection()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
#[ignore = "manual file-backed combined recovery expiry index experiment"]
fn file_recovery_expiry_index_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempdir().unwrap();
    let ended_percent: i64 = std::env::var("NETQMON_BENCH_ENDED_PERCENT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    assert!((0..=100).contains(&ended_percent));
    let ended_rows =
        (rows / 100) * ended_percent + (rows % 100).min(ended_percent.saturating_sub(1));
    let open_rows = rows - ended_rows;
    for layout in ["original", "combined", "partitioned"] {
        let path = directory.path().join(format!("{layout}.db"));
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        let db = storage.connection();
        db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_rollup_sessions(session_id,gateway_id,metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at) SELECT printf('session-%08d',i),'gateway-1','{}','{}',i,1,1,?2,?2+i,CASE WHEN i%100<?3 THEN ?2+i ELSE NULL END FROM n", params![rows,to_i64(NOW),ended_percent]).unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0")
            .unwrap();
        let file_before = std::fs::metadata(&path).unwrap().len();
        let migration_start = Instant::now();
        if layout != "original" {
            let prefix = if layout == "partitioned" {
                "(ended_at IS NULL),"
            } else {
                ""
            };
            db.execute_batch(&format!("BEGIN IMMEDIATE; DROP INDEX flow_rollup_sessions_updated; DROP INDEX flow_rollup_sessions_ended; CREATE INDEX experimental_recovery_expiry ON flow_rollup_sessions({prefix}{EXPERIMENTAL_RECOVERY_EXPIRY}); COMMIT")).unwrap();
        }
        let migration_ms = migration_start.elapsed().as_millis();
        let migration_wal = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0")
            .unwrap();
        let file_after = std::fs::metadata(&path).unwrap().len();
        let freelist: i64 = db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .unwrap();
        eprintln!(
            "layout={layout} rows={rows} migration_ms={migration_ms} migration_wal={migration_wal} file_before={file_before} file_after={file_after} freelist_pages={freelist}"
        );
        let index_bytes: i64 = db.query_row("SELECT SUM(pgsize) FROM dbstat WHERE name IN ('flow_rollup_sessions_updated','flow_rollup_sessions_ended','experimental_recovery_expiry')", [], |r| r.get(0)).unwrap();
        let gc = match layout {
            "combined" => format!("{EXPERIMENTAL_RECOVERY_EXPIRY}<=?1"),
            "partitioned" => {
                format!("(ended_at IS NULL) IN (0,1) AND ({EXPERIMENTAL_RECOVERY_EXPIRY})<=?1")
            }
            _ => "(ended_at IS NOT NULL AND ended_at<=?1+1200000) OR updated_at<=?1".to_owned(),
        };
        let open = match layout {
            "combined" => format!("ended_at IS NULL AND ({EXPERIMENTAL_RECOVERY_EXPIRY})<=?1"),
            "partitioned" => {
                format!("(ended_at IS NULL)=1 AND ({EXPERIMENTAL_RECOVERY_EXPIRY})<=?1")
            }
            _ => "ended_at IS NULL AND updated_at<=?1".to_owned(),
        };
        let recent = match layout {
            "combined" => format!("ended_at IS NULL AND ({EXPERIMENTAL_RECOVERY_EXPIRY})>?1"),
            "partitioned" => {
                format!("(ended_at IS NULL)=1 AND ({EXPERIMENTAL_RECOVERY_EXPIRY})>?1")
            }
            _ => "ended_at IS NULL AND updated_at>?1".to_owned(),
        };
        for (label, predicate, cutoff, expected) in [
            ("gc_empty", &gc, to_i64(NOW) - 1_800_000, 0),
            ("gc_expired", &gc, to_i64(NOW) + 100_000, 500),
            ("open_empty", &open, to_i64(NOW) - 1_800_000, 0),
            (
                "recent",
                &recent,
                to_i64(NOW) - 1_800_000,
                usize::try_from(open_rows.min(500)).unwrap(),
            ),
            (
                "recent_all",
                &recent,
                to_i64(NOW) - 1_800_000,
                usize::try_from(open_rows).unwrap(),
            ),
        ] {
            let projection = if label.starts_with("gc_") {
                "id"
            } else {
                "metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at"
            };
            let no_contributions = if label.starts_with("gc_") {
                "AND NOT EXISTS (SELECT 1 FROM flow_rollup_contributions c WHERE c.session_ref=flow_rollup_sessions.id)"
            } else {
                ""
            };
            let limit = if label == "recent_all" {
                ""
            } else {
                "LIMIT 500"
            };
            let sql = format!(
                "SELECT {projection} FROM flow_rollup_sessions WHERE ({predicate}) {no_contributions} {limit}"
            );
            let plan = db
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([cutoff], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut samples = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                let mut statement = db.prepare(&sql).unwrap();
                let mut result = statement.query([cutoff]).unwrap();
                let mut count = 0;
                while let Some(row) = result.next().unwrap() {
                    let _ = row.get_ref(0).unwrap();
                    count += 1;
                }
                assert_eq!(count, expected);
                samples.push(start.elapsed().as_micros());
            }
            samples.sort_unstable();
            eprintln!(
                "layout={layout} rows={rows} indexes_bytes={index_bytes} query={label} p50_us={} plan={plan:?}",
                samples[2]
            );
        }
        let start = Instant::now();
        let changed = db.execute("UPDATE flow_rollup_sessions SET updated_at=updated_at+1 WHERE ended_at IS NOT NULL", []).unwrap();
        let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        assert_eq!(i64::try_from(changed).unwrap(), ended_rows);
        eprintln!(
            "layout={layout} rows={rows} update_rows={changed} update_ms={} wal_bytes={wal_bytes}",
            start.elapsed().as_millis()
        );
        if layout == "partitioned" {
            let rollback_start = Instant::now();
            db.execute_batch("BEGIN IMMEDIATE; DROP INDEX experimental_recovery_expiry; CREATE INDEX flow_rollup_sessions_updated ON flow_rollup_sessions(updated_at); CREATE INDEX flow_rollup_sessions_ended ON flow_rollup_sessions(ended_at) WHERE ended_at IS NOT NULL; COMMIT").unwrap();
            let check: String = db
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap();
            assert_eq!(check, "ok");
            let after: i64 = db
                .query_row("SELECT COUNT(*) FROM flow_rollup_sessions", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(after, rows);
            let mismatch: i64 = db.query_row("SELECT COUNT(*) FROM flow_rollup_sessions WHERE updated_at != ?1 + upload_bytes + CASE WHEN ended_at IS NOT NULL THEN 1 ELSE 0 END OR download_bytes != 1", [to_i64(NOW)], |r| r.get(0)).unwrap();
            assert_eq!(mismatch, 0);
            eprintln!(
                "layout={layout} rollback_and_integrity_ms={}",
                rollback_start.elapsed().as_millis()
            );
        }
    }
}

#[test]
#[ignore = "manual file-backed recovery updated-index experiment"]
fn file_recovery_updated_index_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempdir().unwrap();
    for partial in [false, true] {
        let path = directory
            .path()
            .join(if partial { "partial.db" } else { "full.db" });
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        let db = storage.connection();
        db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_rollup_sessions(session_id,gateway_id,metadata_json,attribution_json,upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at) SELECT printf('session-%08d',i),'gateway-1','{}','{}',i,1,1,?2,?2+i,CASE WHEN i%2=0 THEN ?2+i ELSE NULL END FROM n", params![rows,to_i64(NOW)]).unwrap();
        if partial {
            db.execute_batch("DROP INDEX flow_rollup_sessions_updated; CREATE INDEX flow_rollup_sessions_updated ON flow_rollup_sessions(updated_at) WHERE ended_at IS NULL").unwrap();
        }
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0")
            .unwrap();
        let index_bytes: i64 = db
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_rollup_sessions_updated'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for (label, sql) in [
            (
                "open",
                "SELECT id FROM flow_rollup_sessions WHERE ended_at IS NULL AND updated_at<=?1 LIMIT 500",
            ),
            (
                "gc",
                "SELECT id FROM flow_rollup_sessions WHERE (ended_at IS NOT NULL AND ended_at<=?1) OR updated_at<=?1 LIMIT 500",
            ),
            (
                "gc_split",
                "SELECT id FROM flow_rollup_sessions WHERE (ended_at IS NOT NULL AND ended_at<=?1) OR (ended_at IS NULL AND updated_at<=?1) OR (ended_at IS NOT NULL AND updated_at<=?1) LIMIT 500",
            ),
        ] {
            let plan = db
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([to_i64(NOW) - 1], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut samples = Vec::new();
            for _ in 0..5 {
                let started = Instant::now();
                let result = db
                    .prepare(sql)
                    .unwrap()
                    .query_map([to_i64(NOW) - 1], |r| r.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(result.is_empty());
                samples.push(started.elapsed().as_micros());
            }
            samples.sort_unstable();
            eprintln!(
                "partial={partial} rows={rows} index_bytes={index_bytes} query={label} p50_us={} plan={plan:?}",
                samples[2]
            );
        }
        let start = Instant::now();
        let changed = db.execute("UPDATE flow_rollup_sessions SET updated_at=updated_at+1 WHERE ended_at IS NOT NULL", []).unwrap();
        let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        assert_eq!(i64::try_from(changed).unwrap(), rows / 2);
        eprintln!(
            "partial={partial} rows={rows} update_rows={changed} update_ms={} wal_bytes={wal_bytes}",
            start.elapsed().as_millis()
        );
    }
}

#[test]
#[ignore = "manual file-backed JSONB recovery metadata experiment"]
fn file_recovery_jsonb_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let mut expected_total = None;
    for binary in [false, true] {
        let path = dir
            .path()
            .join(if binary { "binary.db" } else { "text.db" });
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE recovery(id INTEGER PRIMARY KEY, metadata NOT NULL, attribution NOT NULL);").unwrap();
        let convert = if binary { "jsonb" } else { "json" };
        let sql = format!(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO recovery SELECT i, {convert}(json_object('key',json_object('gateway_id','gateway-1','ip_version',4,'protocol',6,'client_ip',json_array(192,0,2,10),'client_port',12345,'remote_ip',json_array(i%256,(i/256)%256,(i/65536)%256,1),'remote_port',443,'direction',1),'client_mac',json_array(2,0,0,0,0,1),'device_id',1,'started_at',1700000000000,'checkpointed_at',1700000000000,'scope',1,'path_type',1,'nat',0,'source_segment','','destination_segment','')), {convert}(json_object('domain',NULL,'organization_id','unknown','application_id','unknown','category_id','unknown','traffic_role','unknown','protocol_id','unknown','organization_confidence',0.0,'application_confidence',0.0,'protocol_confidence',0.0,'confidence',0.0,'reason','unknown','evidence',json_array())) FROM n"
        );
        let start = Instant::now();
        connection.execute(&sql, [rows]).unwrap();
        let insert_ms = start.elapsed().as_millis();
        let wal = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let file = std::fs::metadata(&path).unwrap().len();
        let mut samples = Vec::new();
        let expression = if binary {
            "length(json(metadata))+length(json(attribution))"
        } else {
            "length(metadata)+length(attribution)"
        };
        for _ in 0..5 {
            let start = Instant::now();
            let total: i64 = connection
                .query_row(
                    &format!("SELECT SUM({expression}) FROM recovery"),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(total > 0);
            if let Some(expected) = expected_total {
                assert_eq!(total, expected);
            } else {
                expected_total = Some(total);
            }
            samples.push(start.elapsed().as_micros());
        }
        samples.sort_unstable();
        if binary {
            connection
                .execute(
                    "ATTACH DATABASE ?1 AS original",
                    [dir.path().join("text.db").to_str().unwrap()],
                )
                .unwrap();
            let differences: i64 = connection.query_row("SELECT COUNT(*) FROM recovery b JOIN original.recovery t USING(id) WHERE json(b.metadata) != t.metadata OR json(b.attribution) != t.attribution", [], |r| r.get(0)).unwrap();
            assert_eq!(differences, 0);
        }
        let invalid: i64 = connection.query_row("SELECT COUNT(*) FROM recovery WHERE json_valid(json(metadata)) != 1 OR json_valid(json(attribution)) != 1", [], |r| r.get(0)).unwrap();
        assert_eq!(invalid, 0);
        eprintln!(
            "binary={binary} rows={rows} file_bytes={file} wal_bytes={wal} insert_ms={insert_ms} scan_p50_us={}",
            samples[2]
        );
    }
}

fn scope_application_query_us(connection: &Connection, sql: &str) -> u128 {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let mut statement = connection.prepare(sql).unwrap();
        let results = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(results.len(), 50);
        samples.push(start.elapsed().as_micros());
    }
    samples.sort_unstable();
    samples[2]
}

#[test]
#[ignore = "manual file-backed scope-minute layout comparison"]
fn file_scope_layout_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    for without_rowid in [false, true] {
        let path = dir.path().join(if without_rowid {
            "without-rowid.db"
        } else {
            "rowid.db"
        });
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(&format!("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE traffic_scope_minute(timestamp INTEGER NOT NULL,gateway_id TEXT NOT NULL,scope INTEGER NOT NULL,direction INTEGER NOT NULL,device_id INTEGER NOT NULL,application_id TEXT NOT NULL,category_id TEXT NOT NULL,domain TEXT NOT NULL,remote_ip BLOB NOT NULL,protocol INTEGER NOT NULL,protocol_id TEXT NOT NULL,upload_bytes INTEGER NOT NULL,download_bytes INTEGER NOT NULL,packets INTEGER NOT NULL,flow_count INTEGER NOT NULL, PRIMARY KEY(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id)) {};
            CREATE INDEX scope_query ON traffic_scope_minute(scope,direction,timestamp);
            CREATE INDEX scope_device ON traffic_scope_minute(device_id,scope,timestamp);
            CREATE INDEX scope_timestamp ON traffic_scope_minute(scope,timestamp,remote_ip);", if without_rowid { "WITHOUT ROWID" } else { "" })).unwrap();
        let start = Instant::now();
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute SELECT ?2+(i/50000)*60000,'gateway-1',1,1,i%1000,printf('app-%d',i%100),printf('cat-%d',i%10),printf('domain-%d.example',i%10000),CAST(printf('%08x',i%50000) AS BLOB),6,'tcp',i%1000,i%300,1,1 FROM n",params![rows,to_i64(NOW)]).unwrap();
        let insert_elapsed = start.elapsed();
        let wal = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let file = std::fs::metadata(&path).unwrap().len();
        let mut stat = connection.prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name='traffic_scope_minute' OR name LIKE 'scope_%' OR name='sqlite_autoindex_traffic_scope_minute_1' GROUP BY name ORDER BY name").unwrap();
        let sizes = stat
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        drop(stat);
        let start = Instant::now();
        let deleted = if without_rowid {
            connection.execute("DELETE FROM traffic_scope_minute WHERE (timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id) IN (SELECT timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id FROM traffic_scope_minute WHERE timestamp<?1 LIMIT 500)",[to_i64(NOW + 60_000)]).unwrap()
        } else {
            connection.execute("DELETE FROM traffic_scope_minute WHERE rowid IN (SELECT rowid FROM traffic_scope_minute WHERE timestamp<?1 LIMIT 500)",[to_i64(NOW + 60_000)]).unwrap()
        };
        let delete_elapsed = start.elapsed();
        assert_eq!(deleted, 500);
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, rows - 500);
        eprintln!(
            "layout={} rows={rows} db_bytes={file} wal_bytes={wal} insert_ms={} delete_500_us={} objects={sizes:?}",
            if without_rowid {
                "without-rowid"
            } else {
                "rowid"
            },
            insert_elapsed.as_millis(),
            delete_elapsed.as_micros()
        );
        let group_us = scope_application_query_us(
            &connection,
            "SELECT application_id,SUM(upload_bytes+download_bytes) FROM traffic_scope_minute WHERE scope=1 GROUP BY application_id ORDER BY SUM(upload_bytes+download_bytes) DESC,application_id LIMIT 50",
        );
        eprintln!(
            "layout={} application_group_p50_us={group_us}",
            if without_rowid {
                "without-rowid"
            } else {
                "rowid"
            }
        );
        let mut plan = connection.prepare("EXPLAIN QUERY PLAN SELECT remote_ip,SUM(upload_bytes+download_bytes) FROM traffic_scope_minute WHERE scope=1 AND timestamp>=0 AND timestamp<9000000000000 GROUP BY remote_ip ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50").unwrap();
        for step in plan.query_map([], |r| r.get::<_, String>(3)).unwrap() {
            eprintln!(
                "layout={} plan={}",
                if without_rowid {
                    "without-rowid"
                } else {
                    "rowid"
                },
                step.unwrap()
            );
        }
        drop(plan);
        drop(connection);
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
#[ignore = "manual file-backed scope-minute dictionary experiment"]
fn file_scope_dictionary_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("dictionary.db");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0;
        CREATE TABLE dictionary(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,value TEXT NOT NULL, UNIQUE(kind,value));
        INSERT INTO dictionary(kind,value) VALUES('gateway','gateway-1'),('protocol','tcp');
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99) INSERT INTO dictionary(kind,value) SELECT 'application',printf('app-%d',i) FROM n;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<9) INSERT INTO dictionary(kind,value) SELECT 'category',printf('cat-%d',i) FROM n;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<9999) INSERT INTO dictionary(kind,value) SELECT 'domain',printf('domain-%d.example',i) FROM n;
        CREATE TABLE traffic_scope_minute(timestamp INTEGER NOT NULL,gateway_id INTEGER NOT NULL,scope INTEGER NOT NULL,direction INTEGER NOT NULL,device_id INTEGER NOT NULL,application_id INTEGER NOT NULL,category_id INTEGER NOT NULL,domain INTEGER NOT NULL,remote_ip BLOB NOT NULL,protocol INTEGER NOT NULL,protocol_id INTEGER NOT NULL,upload_bytes INTEGER NOT NULL,download_bytes INTEGER NOT NULL,packets INTEGER NOT NULL,flow_count INTEGER NOT NULL,PRIMARY KEY(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id));
        CREATE INDEX scope_query ON traffic_scope_minute(scope,direction,timestamp);
        CREATE INDEX scope_device ON traffic_scope_minute(device_id,scope,timestamp);
        CREATE INDEX scope_timestamp ON traffic_scope_minute(scope,timestamp,remote_ip);").unwrap();
    let started = Instant::now();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute SELECT ?2+(i/50000)*60000,(SELECT id FROM dictionary WHERE kind='gateway' AND value='gateway-1'),1,1,i%1000,a.id,c.id,d.id,CAST(printf('%08x',i%50000) AS BLOB),6,(SELECT id FROM dictionary WHERE kind='protocol' AND value='tcp'),i%1000,i%300,1,1 FROM n JOIN dictionary a ON a.kind='application' AND a.value=printf('app-%d',i%100) JOIN dictionary c ON c.kind='category' AND c.value=printf('cat-%d',i%10) JOIN dictionary d ON d.kind='domain' AND d.value=printf('domain-%d.example',i%10000)",params![rows,to_i64(NOW)]).unwrap();
    let insert_elapsed = started.elapsed();
    let wal = std::fs::metadata(path.with_extension("db-wal"))
        .unwrap()
        .len();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let file = std::fs::metadata(&path).unwrap().len();
    let mut stat = connection.prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name IN ('traffic_scope_minute','dictionary','sqlite_autoindex_dictionary_1','sqlite_autoindex_traffic_scope_minute_1') OR name LIKE 'scope_%' GROUP BY name ORDER BY name").unwrap();
    let sizes = stat
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let started = Instant::now();
    let deleted = connection.execute("DELETE FROM traffic_scope_minute WHERE rowid IN (SELECT rowid FROM traffic_scope_minute WHERE timestamp<?1 LIMIT 500)",[to_i64(NOW + 60_000)]).unwrap();
    let delete_elapsed = started.elapsed();
    assert_eq!(deleted, 500);
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, rows - 500);
    let invalid: i64 = connection.query_row("SELECT COUNT(*) FROM traffic_scope_minute t LEFT JOIN dictionary a ON a.id=t.application_id AND a.kind='application' LEFT JOIN dictionary d ON d.id=t.domain AND d.kind='domain' WHERE a.id IS NULL OR d.id IS NULL",[],|r| r.get(0)).unwrap();
    assert_eq!(invalid, 0);
    let group_us = scope_application_query_us(
        &connection,
        "SELECT a.value,SUM(t.upload_bytes+t.download_bytes) FROM traffic_scope_minute t JOIN dictionary a ON a.id=t.application_id WHERE t.scope=1 GROUP BY a.value ORDER BY SUM(t.upload_bytes+t.download_bytes) DESC,a.value LIMIT 50",
    );
    eprintln!(
        "layout=dictionary rows={rows} db_bytes={file} wal_bytes={wal} insert_ms={} delete_500_us={} application_group_p50_us={group_us} objects={sizes:?}",
        insert_elapsed.as_millis(),
        delete_elapsed.as_micros()
    );
}

#[test]
#[ignore = "manual file-backed incremental scope dictionary comparison"]
fn file_scope_dictionary_incremental_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let batch_rows: i64 = std::env::var("NETQMON_BENCH_BATCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    assert!(rows > 10_000 && batch_rows > 0);
    let directory = tempdir().unwrap();
    let reverse_order =
        std::env::var("NETQMON_BENCH_REVERSE_LAYOUT_ORDER").is_ok_and(|value| value == "1");
    let (string_result, dictionary_result) = if reverse_order {
        let dictionary = run_scope_dictionary_incremental_layout(
            &directory.path().join("scope-dictionary.db"),
            rows,
            batch_rows,
            true,
        );
        let strings = run_scope_dictionary_incremental_layout(
            &directory.path().join("scope-strings.db"),
            rows,
            batch_rows,
            false,
        );
        (strings, dictionary)
    } else {
        let strings = run_scope_dictionary_incremental_layout(
            &directory.path().join("scope-strings.db"),
            rows,
            batch_rows,
            false,
        );
        let dictionary = run_scope_dictionary_incremental_layout(
            &directory.path().join("scope-dictionary.db"),
            rows,
            batch_rows,
            true,
        );
        (strings, dictionary)
    };
    assert_eq!(string_result.row_count, dictionary_result.row_count);
    assert_eq!(string_result.totals, dictionary_result.totals);
    assert_eq!(
        string_result.dimension_groups,
        dictionary_result.dimension_groups
    );
    for (layout, result) in [
        ("string", &string_result),
        ("dictionary", &dictionary_result),
    ] {
        eprintln!(
            "scope_incremental layout={layout} reverse_order={reverse_order} rows={rows} insert_ms={} batch_p50_us={} batch_p95_us={} batch_p99_us={} replay_ms={} attribution_move_ms={} retention_500_us={} db_bytes={} wal_peak_bytes={} wal_after_checkpoint={} app_group_p50_us={} objects={:?}",
            result.insert_ms,
            result.insert_batch_p50_us,
            result.insert_batch_p95_us,
            result.insert_batch_p99_us,
            result.upsert_replay_ms,
            result.attribution_move_ms,
            result.retention_500_us,
            result.db_bytes,
            result.wal_peak_bytes,
            result.wal_bytes_after_checkpoint,
            result.app_group_p50_us,
            result.objects,
        );
    }
}

#[test]
#[ignore = "manual file-backed dictionary cleanup queue benchmark"]
fn file_dictionary_cleanup_queue_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let batch_rows: i64 = std::env::var("NETQMON_BENCH_BATCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500);
    assert!(rows > 0 && rows <= 5_000_000 && batch_rows > 0);
    let gc_enabled = std::env::var("NETQMON_BENCH_GC").is_ok_and(|value| value == "1");

    let directory = tempdir().unwrap();
    let path = directory.path().join("dictionary-gc.db");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; PRAGMA foreign_keys=ON;
        CREATE TABLE dimension_dictionary(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(kind,value));
        INSERT INTO dimension_dictionary(kind,value) VALUES('gateway','g1');
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99) INSERT INTO dimension_dictionary(kind,value) SELECT 'application',printf('app-%d',i) FROM n;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<9) INSERT INTO dimension_dictionary(kind,value) SELECT 'category',printf('cat-%d',i) FROM n;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<9999) INSERT INTO dimension_dictionary(kind,value) SELECT 'domain',printf('domain-%d.example',i) FROM n;
        INSERT INTO dimension_dictionary(kind,value) VALUES('protocol','tcp');
        CREATE TABLE traffic_scope_minute(
            timestamp INTEGER NOT NULL, gateway_id INTEGER NOT NULL REFERENCES dimension_dictionary(id),
            scope INTEGER NOT NULL, direction INTEGER NOT NULL, device_id INTEGER NOT NULL,
            application_id INTEGER NOT NULL REFERENCES dimension_dictionary(id),
            category_id INTEGER NOT NULL REFERENCES dimension_dictionary(id),
            domain_id INTEGER NOT NULL REFERENCES dimension_dictionary(id), remote_ip BLOB NOT NULL,
            protocol INTEGER NOT NULL, protocol_id INTEGER NOT NULL REFERENCES dimension_dictionary(id),
            upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flow_count INTEGER NOT NULL);
        CREATE UNIQUE INDEX scope_pk ON traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain_id,remote_ip,protocol,protocol_id);
        CREATE INDEX scope_query ON traffic_scope_minute(scope,direction,timestamp);
        CREATE INDEX scope_device ON traffic_scope_minute(device_id,scope,timestamp);
        CREATE INDEX scope_timestamp ON traffic_scope_minute(scope,timestamp,remote_ip);").unwrap();
    if gc_enabled {
        connection.execute_batch("CREATE INDEX scope_app_ref ON traffic_scope_minute(application_id);
        CREATE INDEX scope_category_ref ON traffic_scope_minute(category_id);
        CREATE INDEX scope_domain_ref ON traffic_scope_minute(domain_id);
        CREATE INDEX scope_protocol_ref ON traffic_scope_minute(protocol_id);
        CREATE TABLE dimension_gc(kind TEXT NOT NULL, id INTEGER NOT NULL, PRIMARY KEY(kind,id)) WITHOUT ROWID;
        CREATE TRIGGER scope_dimension_gc AFTER DELETE ON traffic_scope_minute BEGIN
            INSERT OR IGNORE INTO dimension_gc VALUES('gateway',OLD.gateway_id),('application',OLD.application_id),('category',OLD.category_id),('domain',OLD.domain_id),('protocol',OLD.protocol_id);
        END;
        CREATE TRIGGER scope_dimension_gc_update AFTER UPDATE OF gateway_id,application_id,category_id,domain_id,protocol_id ON traffic_scope_minute BEGIN
            INSERT OR IGNORE INTO dimension_gc SELECT 'gateway',OLD.gateway_id WHERE OLD.gateway_id!=NEW.gateway_id;
            INSERT OR IGNORE INTO dimension_gc SELECT 'application',OLD.application_id WHERE OLD.application_id!=NEW.application_id;
            INSERT OR IGNORE INTO dimension_gc SELECT 'category',OLD.category_id WHERE OLD.category_id!=NEW.category_id;
            INSERT OR IGNORE INTO dimension_gc SELECT 'domain',OLD.domain_id WHERE OLD.domain_id!=NEW.domain_id;
            INSERT OR IGNORE INTO dimension_gc SELECT 'protocol',OLD.protocol_id WHERE OLD.protocol_id!=NEW.protocol_id;
        END;").unwrap();
    }

    let insert_started = Instant::now();
    let mut first = 1_i64;
    let mut wal_peak = 0_u64;
    while first <= rows {
        let end = (first + 10_000).min(rows + 1);
        let tx = connection.unchecked_transaction().unwrap();
        tx.execute("WITH RECURSIVE n(i) AS (VALUES(?1) UNION ALL SELECT i+1 FROM n WHERE i+1<?2)
            INSERT INTO traffic_scope_minute
            SELECT ?3+(i/50000)*60000,1,1,1,i%1000,2+(i%100),102+(i%10),112+(i/500),CAST(printf('%08x',i%50000) AS BLOB),6,10112,i%1000,i%300,1,1 FROM n",
            params![first,end,to_i64(NOW)]).unwrap();
        tx.commit().unwrap();
        wal_peak = wal_peak.max(scope_benchmark_wal_bytes(&path));
        first = end;
    }
    let insert_ms = insert_started.elapsed().as_millis();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let before_retention_db_bytes = std::fs::metadata(&path).unwrap().len();

    let correction_ms = if gc_enabled {
        connection
            .execute(
                "INSERT INTO dimension_dictionary(kind,value) VALUES('domain','domain-corrected.example')",
                [],
            )
            .unwrap();
        let corrected_domain: i64 = connection
            .query_row(
                "SELECT id FROM dimension_dictionary WHERE kind='domain' AND value='domain-corrected.example'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let correction_started = Instant::now();
        let tx = connection.unchecked_transaction().unwrap();
        let moved = tx
            .execute(
                "UPDATE traffic_scope_minute SET domain_id=?1 WHERE domain_id=?2",
                [corrected_domain, 112 + 100],
            )
            .unwrap();
        assert_eq!(moved, 500);
        tx.commit().unwrap();
        correction_started.elapsed().as_millis()
    } else {
        0
    };

    let mut retention_times = Vec::new();
    let mut gc_times = Vec::new();
    let mut removed = 0_i64;
    for _ in 0..20 {
        let tx = connection.unchecked_transaction().unwrap();
        let started = Instant::now();
        removed += tx.execute("DELETE FROM traffic_scope_minute WHERE rowid IN (SELECT rowid FROM traffic_scope_minute ORDER BY timestamp,rowid LIMIT ?1)", [batch_rows]).unwrap() as i64;
        tx.commit().unwrap();
        retention_times.push(started.elapsed().as_micros());
        if gc_enabled {
            let tx = connection.unchecked_transaction().unwrap();
            let started = Instant::now();
            for (kind, reference_column) in [
                ("gateway", "gateway_id"),
                ("application", "application_id"),
                ("category", "category_id"),
                ("domain", "domain_id"),
                ("protocol", "protocol_id"),
            ] {
                tx.execute(&format!("DELETE FROM dimension_dictionary WHERE id IN (
                    SELECT g.id FROM dimension_gc g WHERE g.kind=?1
                      AND NOT EXISTS (SELECT 1 FROM traffic_scope_minute s WHERE s.{reference_column}=g.id)
                    ORDER BY g.id LIMIT 500)"), [kind]).unwrap();
                tx.execute(
                    "DELETE FROM dimension_gc WHERE kind=?1 AND id IN (
                        SELECT id FROM dimension_gc WHERE kind=?1 ORDER BY id LIMIT 500)",
                    [kind],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            gc_times.push(started.elapsed().as_micros());
        }
        wal_peak = wal_peak.max(scope_benchmark_wal_bytes(&path));
    }
    assert_eq!(removed, batch_rows * 20);
    let remaining: i64 = connection
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| {
            row.get(0)
        })
        .unwrap();
    let dangling: i64 = connection.query_row("SELECT COUNT(*) FROM traffic_scope_minute s LEFT JOIN dimension_dictionary d ON d.id=s.domain_id AND d.kind='domain' WHERE d.id IS NULL", [], |row| row.get(0)).unwrap();
    assert_eq!(remaining, rows - removed);
    assert_eq!(dangling, 0);
    let gc_pending: i64 = if gc_enabled {
        connection
            .query_row("SELECT COUNT(*) FROM dimension_gc", [], |row| row.get(0))
            .unwrap()
    } else {
        0
    };
    let orphan_count: i64 = if gc_enabled {
        connection.query_row("SELECT COUNT(*) FROM dimension_dictionary d WHERE d.kind='domain' AND NOT EXISTS(SELECT 1 FROM traffic_scope_minute s WHERE s.domain_id=d.id)", [], |row| row.get(0)).unwrap()
    } else {
        0
    };
    if gc_enabled {
        assert!(orphan_count > 0);
        let corrected_old_id: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM dimension_dictionary WHERE kind='domain' AND id=212",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(corrected_old_id, 0);
    }
    let reclaimed_domains: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dimension_dictionary WHERE kind='domain' AND id>=112 AND id<133",
            [],
            |row| row.get(0),
        )
        .unwrap();
    if gc_enabled {
        assert_eq!(reclaimed_domains, 1);
    }
    let mut retention_sorted = retention_times.clone();
    retention_sorted.sort_unstable();
    let mut gc_sorted = gc_times.clone();
    gc_sorted.sort_unstable();
    let gc_p50 = gc_sorted.get(gc_sorted.len() / 2).copied().unwrap_or(0);
    let gc_max = gc_sorted.last().copied().unwrap_or(0);
    let file_bytes = std::fs::metadata(&path).unwrap().len();
    let mut object_sizes = connection
        .prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name IN ('traffic_scope_minute','dimension_dictionary','dimension_gc','scope_pk','scope_query','scope_device','scope_timestamp','scope_app_ref','scope_category_ref','scope_domain_ref','scope_protocol_ref','sqlite_autoindex_dimension_dictionary_1') GROUP BY name ORDER BY name")
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    object_sizes.shrink_to_fit();
    eprintln!(
        "dictionary_gc enabled={gc_enabled} rows={rows} delete_batch={batch_rows} insert_ms={insert_ms} correction_ms={correction_ms} retention_p50_us={} retention_max_us={} cleanup_p50_us={} cleanup_max_us={} db_before_retention_bytes={before_retention_db_bytes} db_after_retention_bytes={file_bytes} wal_peak_bytes={wal_peak} pending_gc={gc_pending} orphan_domains={orphan_count} remaining={remaining} dangling={dangling} objects={object_sizes:?}",
        retention_sorted[retention_sorted.len() / 2],
        retention_sorted[retention_sorted.len() - 1],
        gc_p50,
        gc_max
    );
}

#[test]
#[ignore = "manual file-backed domain-only dictionary comparison"]
fn file_domain_only_dictionary_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let batch_rows: i64 = std::env::var("NETQMON_BENCH_BATCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    assert!(rows > 10_000 && rows <= 5_000_000 && batch_rows > 0);
    let directory = tempdir().unwrap();
    let reverse_order =
        std::env::var("NETQMON_BENCH_REVERSE_LAYOUT_ORDER").is_ok_and(|value| value == "1");
    let string_path = directory.path().join("domain-strings.db");
    let dictionary_path = directory.path().join("domain-dictionary.db");
    let (strings, dictionary) = if reverse_order {
        let dictionary =
            run_domain_only_dictionary_layout(&dictionary_path, rows, batch_rows, true);
        let strings = run_domain_only_dictionary_layout(&string_path, rows, batch_rows, false);
        (strings, dictionary)
    } else {
        let strings = run_domain_only_dictionary_layout(&string_path, rows, batch_rows, false);
        let dictionary =
            run_domain_only_dictionary_layout(&dictionary_path, rows, batch_rows, true);
        (strings, dictionary)
    };
    assert_eq!(strings.row_count, dictionary.row_count);
    assert_eq!(strings.totals, dictionary.totals);
    assert_eq!(strings.domain_groups, dictionary.domain_groups);
    for (layout, result) in [("strings", &strings), ("domain_dictionary", &dictionary)] {
        eprintln!(
            "domain_dictionary layout={layout} reverse_order={reverse_order} rows={rows} insert_ms={} replay_ms={} correction_ms={} retention_500_us={} gc_500_us={} db_bytes={} wal_peak_bytes={} wal_after_checkpoint={} domain_group_p50_us={} plan={:?} objects={:?}",
            result.insert_ms,
            result.replay_ms,
            result.correction_ms,
            result.retention_us,
            result.gc_us,
            result.db_bytes,
            result.wal_bytes,
            result.wal_after_checkpoint,
            result.domain_query_us,
            result.domain_plan,
            result.objects,
        );
    }
}

struct DomainDictionaryBenchmarkResult {
    row_count: i64,
    totals: (i64, i64, i64, i64),
    domain_groups: Vec<(String, i64, i64, i64, i64)>,
    insert_ms: u128,
    replay_ms: u128,
    correction_ms: u128,
    retention_us: u128,
    gc_us: u128,
    db_bytes: u64,
    wal_bytes: u64,
    wal_after_checkpoint: u64,
    domain_query_us: u128,
    domain_plan: Vec<String>,
    objects: Vec<(String, i64)>,
}

#[allow(clippy::too_many_lines)]
fn run_domain_only_dictionary_layout(
    path: &std::path::Path,
    rows: i64,
    batch_rows: i64,
    dictionary: bool,
) -> DomainDictionaryBenchmarkResult {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0;",
        )
        .unwrap();
    let domain_type = if dictionary { "INTEGER" } else { "TEXT" };
    connection
        .execute_batch(&format!(
            "CREATE TABLE traffic_scope_minute(
                timestamp INTEGER NOT NULL,gateway_id TEXT NOT NULL,scope INTEGER NOT NULL,
                direction INTEGER NOT NULL,device_id INTEGER NOT NULL,application_id TEXT NOT NULL,
                category_id TEXT NOT NULL,domain {domain_type} NOT NULL,remote_ip BLOB NOT NULL,
                protocol INTEGER NOT NULL,protocol_id TEXT NOT NULL,upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,packets INTEGER NOT NULL,flow_count INTEGER NOT NULL,
                PRIMARY KEY(timestamp,gateway_id,scope,direction,device_id,application_id,
                            category_id,domain,remote_ip,protocol,protocol_id));
             CREATE INDEX scope_query ON traffic_scope_minute(scope,direction,timestamp);
             CREATE INDEX scope_device ON traffic_scope_minute(device_id,scope,timestamp);
             CREATE INDEX scope_timestamp ON traffic_scope_minute(scope,timestamp,remote_ip);"
        ))
        .unwrap();
    if dictionary {
        connection
            .execute_batch(
                "CREATE TABLE domain_dictionary(id INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE);
            CREATE INDEX scope_domain_ref ON traffic_scope_minute(domain);
            CREATE TABLE domain_gc(id INTEGER PRIMARY KEY) WITHOUT ROWID;
            CREATE TRIGGER scope_domain_gc_delete AFTER DELETE ON traffic_scope_minute BEGIN
                INSERT OR IGNORE INTO domain_gc VALUES(OLD.domain);
            END;
            CREATE TRIGGER scope_domain_gc_update AFTER UPDATE OF domain ON traffic_scope_minute
            WHEN OLD.domain!=NEW.domain BEGIN
                INSERT OR IGNORE INTO domain_gc VALUES(OLD.domain);
            END;",
            )
            .unwrap();
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<9999)
            INSERT INTO domain_dictionary(id,value) SELECT i+1,printf('domain-%d.example',i) FROM n", []).unwrap();
    }
    let domain_expr = if dictionary {
        "CASE WHEN i<500 THEN 1+i ELSE 1+500+((i-500)%9500) END"
    } else {
        "CASE WHEN i<500 THEN printf('domain-%d.example',i) ELSE printf('domain-%d.example',500+((i-500)%9500)) END"
    };
    let insert_sql = format!(
        "WITH RECURSIVE n(i) AS (VALUES(?1) UNION ALL SELECT i+1 FROM n WHERE i+1<?2)
         INSERT INTO traffic_scope_minute
         SELECT ?3+(i/50000)*60000,'gateway-1',1,1,i%1000,printf('app-%d',i%100),
                printf('cat-%d',i%10),{domain_expr},CAST(printf('%08x',i%50000) AS BLOB),
                6,'tcp',i%1000+1,i%300+1,1,1 FROM n WHERE true
         ON CONFLICT(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,
                     domain,remote_ip,protocol,protocol_id) DO UPDATE SET
             upload_bytes=upload_bytes+excluded.upload_bytes,
             download_bytes=download_bytes+excluded.download_bytes,
             packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count"
    );
    let insert_started = Instant::now();
    let mut first = 0;
    let mut wal_peak = 0_u64;
    while first < rows {
        let end = (first + batch_rows).min(rows);
        let tx = connection.unchecked_transaction().unwrap();
        tx.execute(&insert_sql, params![first, end, to_i64(NOW)])
            .unwrap();
        tx.commit().unwrap();
        wal_peak = wal_peak.max(scope_benchmark_wal_bytes(path));
        first = end;
    }
    let insert_ms = insert_started.elapsed().as_millis();

    let replay_started = Instant::now();
    let tx = connection.unchecked_transaction().unwrap();
    tx.execute(&insert_sql, params![0, 10_000, to_i64(NOW)])
        .unwrap();
    tx.commit().unwrap();
    let replay_ms = replay_started.elapsed().as_millis();

    let correction_ms = if dictionary {
        connection
            .execute(
                "INSERT INTO domain_dictionary(value) VALUES('domain-corrected.example')",
                [],
            )
            .unwrap();
        let corrected_id: i64 = connection
            .query_row(
                "SELECT id FROM domain_dictionary WHERE value='domain-corrected.example'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let tx = connection.unchecked_transaction().unwrap();
        let started = Instant::now();
        let moved = tx
            .execute(
                "UPDATE traffic_scope_minute SET domain=?1 WHERE rowid IN (
                    SELECT rowid FROM traffic_scope_minute ORDER BY timestamp,rowid LIMIT 500)",
                [corrected_id],
            )
            .unwrap();
        assert_eq!(moved, 500);
        tx.commit().unwrap();
        let elapsed = started.elapsed().as_millis();
        cleanup_domain_dictionary(&connection, 500);
        elapsed
    } else {
        let tx = connection.unchecked_transaction().unwrap();
        let started = Instant::now();
        let moved = tx.execute("UPDATE traffic_scope_minute SET domain='domain-corrected.example' WHERE rowid IN (SELECT rowid FROM traffic_scope_minute ORDER BY timestamp,rowid LIMIT 500)", []).unwrap();
        assert_eq!(moved, 500);
        tx.commit().unwrap();
        started.elapsed().as_millis()
    };
    let retention_started = Instant::now();
    let tx = connection.unchecked_transaction().unwrap();
    let deleted = tx.execute("DELETE FROM traffic_scope_minute WHERE rowid IN (SELECT rowid FROM traffic_scope_minute ORDER BY timestamp,rowid LIMIT 500)", []).unwrap();
    tx.commit().unwrap();
    assert_eq!(deleted, 500);
    let retention_us = retention_started.elapsed().as_micros();
    let gc_us = if dictionary {
        cleanup_domain_dictionary(&connection, 500)
    } else {
        0
    };
    wal_peak = wal_peak.max(scope_benchmark_wal_bytes(path));

    let row_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(row_count, rows - 500);
    let totals = connection.query_row("SELECT SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count) FROM traffic_scope_minute", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
    let domain_sql = if dictionary {
        "SELECT d.value,SUM(t.upload_bytes),SUM(t.download_bytes),SUM(t.packets),SUM(t.flow_count)
         FROM traffic_scope_minute t JOIN domain_dictionary d ON d.id=t.domain
         GROUP BY d.value ORDER BY SUM(t.upload_bytes+t.download_bytes) DESC,d.value LIMIT 50"
    } else {
        "SELECT domain,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count)
         FROM traffic_scope_minute GROUP BY domain ORDER BY SUM(upload_bytes+download_bytes) DESC,domain LIMIT 50"
    };
    let mut domain_query_times = Vec::new();
    let mut domain_groups = Vec::new();
    for _ in 0..5 {
        let domain_started = Instant::now();
        let mut statement = connection.prepare(domain_sql).unwrap();
        let groups = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        domain_query_times.push(domain_started.elapsed().as_micros());
        domain_groups = groups;
    }
    domain_query_times.sort_unstable();
    let domain_query_us = domain_query_times[2];
    assert_eq!(domain_groups.len(), 50);
    let mut plan_statement = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {domain_sql}"))
        .unwrap();
    let domain_plan = plan_statement
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    drop(plan_statement);
    if dictionary {
        let dangling: i64 = connection.query_row("SELECT COUNT(*) FROM traffic_scope_minute t LEFT JOIN domain_dictionary d ON d.id=t.domain WHERE d.id IS NULL", [], |row| row.get(0)).unwrap();
        assert_eq!(dangling, 0);
        let old_corrected: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM domain_dictionary WHERE id BETWEEN 1 AND 500",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_corrected, 0);
        let old_retained: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM domain_dictionary WHERE id=10001",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_retained, 0);
    }
    let mut objects = connection.prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name IN ('traffic_scope_minute','domain_dictionary','domain_gc','scope_pk','scope_query','scope_device','scope_timestamp','scope_domain_ref','sqlite_autoindex_domain_dictionary_1') GROUP BY name ORDER BY name").unwrap()
        .query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?))).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap();
    objects.shrink_to_fit();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let db_bytes = std::fs::metadata(path).unwrap().len();
    let wal_after_checkpoint =
        std::fs::metadata(path.with_extension("db-wal")).map_or(0, |metadata| metadata.len());
    DomainDictionaryBenchmarkResult {
        row_count,
        totals,
        domain_groups,
        insert_ms,
        replay_ms,
        correction_ms,
        retention_us,
        gc_us,
        db_bytes,
        wal_bytes: wal_peak,
        wal_after_checkpoint,
        domain_query_us,
        domain_plan,
        objects,
    }
}

fn cleanup_domain_dictionary(connection: &Connection, limit: i64) -> u128 {
    let tx = connection.unchecked_transaction().unwrap();
    let started = Instant::now();
    tx.execute(
        "DELETE FROM domain_dictionary WHERE id IN (
        SELECT q.id FROM domain_gc q WHERE NOT EXISTS (
          SELECT 1 FROM traffic_scope_minute s WHERE s.domain=q.id)
        ORDER BY q.id LIMIT ?1)",
        [limit],
    )
    .unwrap();
    tx.execute(
        "DELETE FROM domain_gc WHERE id IN (SELECT id FROM domain_gc ORDER BY id LIMIT ?1)",
        [limit],
    )
    .unwrap();
    tx.commit().unwrap();
    started.elapsed().as_micros()
}

struct ScopeDictionaryBenchmarkResult {
    row_count: i64,
    totals: (i64, i64, i64, i64, i64),
    dimension_groups: Vec<(String, String, String, String, i64, i64, i64, i64)>,
    insert_ms: u128,
    insert_batch_p50_us: u128,
    insert_batch_p95_us: u128,
    insert_batch_p99_us: u128,
    upsert_replay_ms: u128,
    attribution_move_ms: u128,
    retention_500_us: u128,
    db_bytes: u64,
    wal_peak_bytes: u64,
    wal_bytes_after_checkpoint: u64,
    app_group_p50_us: u128,
    objects: Vec<(String, i64)>,
}

#[allow(clippy::too_many_lines)]
fn run_scope_dictionary_incremental_layout(
    path: &std::path::Path,
    rows: i64,
    batch_rows: i64,
    dictionary: bool,
) -> ScopeDictionaryBenchmarkResult {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; PRAGMA foreign_keys=ON;",
        )
        .unwrap();
    let dimension_type = if dictionary { "INTEGER" } else { "TEXT" };
    let dimension_reference = if dictionary {
        " REFERENCES dimension_dictionary(id)"
    } else {
        ""
    };
    connection
        .execute_batch(&format!(
            "CREATE TABLE dimension_dictionary(
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE(kind,value)
            );
            CREATE TABLE traffic_scope_minute(
                timestamp INTEGER NOT NULL,
                gateway_id {dimension_type} NOT NULL{dimension_reference},
                scope INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                application_id {dimension_type} NOT NULL{dimension_reference},
                category_id {dimension_type} NOT NULL{dimension_reference},
                domain {dimension_type} NOT NULL{dimension_reference},
                remote_ip BLOB NOT NULL,
                protocol INTEGER NOT NULL,
                protocol_id {dimension_type} NOT NULL{dimension_reference},
                upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                packets INTEGER NOT NULL,
                flow_count INTEGER NOT NULL,
                PRIMARY KEY(timestamp,gateway_id,scope,direction,device_id,
                            application_id,category_id,domain,remote_ip,protocol,protocol_id)
            );
            CREATE INDEX scope_query ON traffic_scope_minute(scope,direction,timestamp);
            CREATE INDEX scope_device ON traffic_scope_minute(device_id,scope,timestamp);
            CREATE INDEX scope_timestamp ON traffic_scope_minute(scope,timestamp,remote_ip);
            CREATE TABLE traffic_scope_total_minute(
                timestamp INTEGER NOT NULL,
                gateway_id {dimension_type} NOT NULL,
                scope INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                packets INTEGER NOT NULL,
                flow_count INTEGER NOT NULL,
                source_rows INTEGER NOT NULL,
                PRIMARY KEY(scope,timestamp,direction,gateway_id)
            ) WITHOUT ROWID;
            CREATE INDEX scope_total_timestamp ON traffic_scope_total_minute(timestamp);
            CREATE TRIGGER scope_total_insert AFTER INSERT ON traffic_scope_minute BEGIN
                INSERT INTO traffic_scope_total_minute
                VALUES(NEW.timestamp,NEW.gateway_id,NEW.scope,NEW.direction,
                       NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count,1)
                ON CONFLICT(scope,timestamp,direction,gateway_id) DO UPDATE SET
                    upload_bytes=upload_bytes+excluded.upload_bytes,
                    download_bytes=download_bytes+excluded.download_bytes,
                    packets=packets+excluded.packets,
                    flow_count=flow_count+excluded.flow_count,
                    source_rows=source_rows+1;
            END;
            CREATE TRIGGER scope_total_counters AFTER UPDATE ON traffic_scope_minute
            WHEN OLD.timestamp=NEW.timestamp AND OLD.gateway_id=NEW.gateway_id
             AND OLD.scope=NEW.scope AND OLD.direction=NEW.direction
             AND (OLD.upload_bytes!=NEW.upload_bytes OR OLD.download_bytes!=NEW.download_bytes
                  OR OLD.packets!=NEW.packets OR OLD.flow_count!=NEW.flow_count)
            BEGIN
                UPDATE traffic_scope_total_minute SET
                    upload_bytes=upload_bytes+NEW.upload_bytes-OLD.upload_bytes,
                    download_bytes=download_bytes+NEW.download_bytes-OLD.download_bytes,
                    packets=packets+NEW.packets-OLD.packets,
                    flow_count=flow_count+NEW.flow_count-OLD.flow_count
                WHERE scope=OLD.scope AND timestamp=OLD.timestamp
                  AND direction=OLD.direction AND gateway_id=OLD.gateway_id;
            END;
            CREATE TRIGGER scope_total_delete AFTER DELETE ON traffic_scope_minute BEGIN
                UPDATE traffic_scope_total_minute SET
                    upload_bytes=upload_bytes-OLD.upload_bytes,
                    download_bytes=download_bytes-OLD.download_bytes,
                    packets=packets-OLD.packets,
                    flow_count=flow_count-OLD.flow_count,
                    source_rows=source_rows-1
                WHERE scope=OLD.scope AND timestamp=OLD.timestamp
                  AND direction=OLD.direction AND gateway_id=OLD.gateway_id;
                DELETE FROM traffic_scope_total_minute
                WHERE scope=OLD.scope AND timestamp=OLD.timestamp
                  AND direction=OLD.direction AND gateway_id=OLD.gateway_id AND source_rows=0;
            END;"
        ))
        .unwrap();
    if dictionary {
        let tx = connection.unchecked_transaction().unwrap();
        tx.execute(
            "INSERT INTO dimension_dictionary(kind,value) VALUES('gateway','gateway-1'),('protocol','tcp')",
            [],
        )
        .unwrap();
        for (kind, count, format) in [
            ("application", 100, "app-%d"),
            ("category", 10, "cat-%d"),
            ("domain", 10_000, "domain-%05d.example"),
        ] {
            let insert = format!(
                "WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<?1) \
                 INSERT INTO dimension_dictionary(kind,value) SELECT ?2,printf(?3,i) FROM n"
            );
            tx.execute(&insert, params![count - 1, kind, format])
                .unwrap();
        }
        tx.commit().unwrap();
    }

    let (gateway, app, category, domain, protocol_id) = if dictionary {
        (
            "(SELECT id FROM dimension_dictionary WHERE kind='gateway' AND value='gateway-1')",
            "(SELECT id FROM dimension_dictionary WHERE kind='application' AND value=printf('app-%d',i%100))",
            "(SELECT id FROM dimension_dictionary WHERE kind='category' AND value=printf('cat-%d',i%10))",
            "(SELECT id FROM dimension_dictionary WHERE kind='domain' AND value=printf('domain-%05d.example',i%10000))",
            "(SELECT id FROM dimension_dictionary WHERE kind='protocol' AND value='tcp')",
        )
    } else {
        (
            "'gateway-1'",
            "printf('app-%d',i%100)",
            "printf('cat-%d',i%10)",
            "printf('domain-%05d.example',i%10000)",
            "'tcp'",
        )
    };
    let conflict_columns = "timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id";
    let insert_sql = format!(
        "WITH RECURSIVE n(i) AS (VALUES(?1) UNION ALL SELECT i+1 FROM n WHERE i+1<?2)
         INSERT INTO traffic_scope_minute
         SELECT ?3+(i/50000)*60000,{gateway},1,1,i%1000,{app},{category},{domain},
                CAST(printf('%08x',i%50000) AS BLOB),6,{protocol_id},
                i%1000+1,i%300+1,1,1 FROM n WHERE true
         ON CONFLICT({conflict_columns}) DO UPDATE SET
             upload_bytes=upload_bytes+excluded.upload_bytes,
             download_bytes=download_bytes+excluded.download_bytes,
             packets=packets+excluded.packets,
             flow_count=flow_count+excluded.flow_count"
    );
    let started = Instant::now();
    let mut batch_times = Vec::new();
    let mut wal_peak_bytes = 0;
    let mut first = 0;
    while first < rows {
        let end = (first + batch_rows).min(rows);
        let tx = connection.unchecked_transaction().unwrap();
        let batch_started = Instant::now();
        tx.execute(&insert_sql, params![first, end, to_i64(NOW)])
            .unwrap();
        tx.commit().unwrap();
        batch_times.push(batch_started.elapsed().as_micros());
        wal_peak_bytes = wal_peak_bytes.max(scope_benchmark_wal_bytes(path));
        first = end;
    }
    let insert_ms = started.elapsed().as_millis();
    batch_times.sort_unstable();
    let batch_percentile = |percent: usize| batch_times[((batch_times.len() - 1) * percent) / 100];

    // Replay an existing batch as counter deltas to exercise the production
    // ON CONFLICT update and the scope-total counter trigger.
    let replay_started = Instant::now();
    let tx = connection.unchecked_transaction().unwrap();
    let replay_sql = format!(
        "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<10000)
         INSERT INTO traffic_scope_minute
         SELECT ?1,{gateway},1,1,i%1000,{app},{category},{domain},
                CAST(printf('%08x',i%50000) AS BLOB),6,{protocol_id},1,1,1,1 FROM n WHERE true
         ON CONFLICT({conflict_columns}) DO UPDATE SET
             upload_bytes=upload_bytes+excluded.upload_bytes,
             download_bytes=download_bytes+excluded.download_bytes,
             packets=packets+excluded.packets,
             flow_count=flow_count+excluded.flow_count"
    );
    tx.execute(&replay_sql, [to_i64(NOW)]).unwrap();
    tx.commit().unwrap();
    wal_peak_bytes = wal_peak_bytes.max(scope_benchmark_wal_bytes(path));
    let replay_ms = replay_started.elapsed().as_millis();

    // Move the first 5,000 rows to a new attribution value, then remove the
    // old keys in the same transaction, matching transfer semantics.
    let (corrected_app, corrected_category, corrected_domain, corrected_protocol) = if dictionary {
        (
            "(SELECT id FROM dimension_dictionary WHERE kind='application' AND value='app-corrected')",
            "(SELECT id FROM dimension_dictionary WHERE kind='category' AND value='cat-corrected')",
            "(SELECT id FROM dimension_dictionary WHERE kind='domain' AND value='domain-corrected.example')",
            "(SELECT id FROM dimension_dictionary WHERE kind='protocol' AND value='tcp-corrected')",
        )
    } else {
        (
            "'app-corrected'",
            "'cat-corrected'",
            "'domain-corrected.example'",
            "'tcp-corrected'",
        )
    };
    let correction_started = Instant::now();
    let tx = connection.unchecked_transaction().unwrap();
    if dictionary {
        tx.execute(
            "INSERT INTO dimension_dictionary(kind,value) VALUES
             ('application','app-corrected'),('category','cat-corrected'),
             ('domain','domain-corrected.example'),('protocol','tcp-corrected')",
            [],
        )
        .unwrap();
    }
    let move_sql = format!(
        "INSERT INTO traffic_scope_minute
         SELECT timestamp,gateway_id,scope,direction,device_id,
                {corrected_app},{corrected_category},{corrected_domain},remote_ip,
                protocol,{corrected_protocol},upload_bytes,download_bytes,packets,flow_count
         FROM traffic_scope_minute
         WHERE timestamp=?1 AND remote_ip IN (
             WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<5000)
             SELECT CAST(printf('%08x',i) AS BLOB) FROM n
         )"
    );
    let moved = tx.execute(&move_sql, [to_i64(NOW)]).unwrap();
    assert_eq!(moved, 5_000);
    let delete_originals = "DELETE FROM traffic_scope_minute WHERE timestamp=?1
        AND application_id != ?2 AND remote_ip IN (
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<5000)
            SELECT CAST(printf('%08x',i) AS BLOB) FROM n
        )";
    let corrected_app_value = if dictionary {
        tx
            .query_row(
                "SELECT id FROM dimension_dictionary WHERE kind='application' AND value='app-corrected'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    } else {
        0
    };
    if dictionary {
        tx.execute(delete_originals, params![to_i64(NOW), corrected_app_value])
            .unwrap();
    } else {
        tx.execute(delete_originals, params![to_i64(NOW), "app-corrected"])
            .unwrap();
    }
    tx.commit().unwrap();
    wal_peak_bytes = wal_peak_bytes.max(scope_benchmark_wal_bytes(path));
    let attribution_move_ms = correction_started.elapsed().as_millis();

    let retention_started = Instant::now();
    let tx = connection.unchecked_transaction().unwrap();
    let deleted = tx
        .execute(
            "DELETE FROM traffic_scope_minute WHERE rowid IN (
                SELECT rowid FROM traffic_scope_minute WHERE timestamp<?1 ORDER BY timestamp,rowid LIMIT 500
            )",
            [to_i64(NOW + 60_000)],
        )
        .unwrap();
    tx.commit().unwrap();
    wal_peak_bytes = wal_peak_bytes.max(scope_benchmark_wal_bytes(path));
    assert_eq!(deleted, 500);
    let retention_500_us = retention_started.elapsed().as_micros();

    let row_count = connection
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(row_count, rows - 500);
    let totals = connection
        .query_row(
            "SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),
                    COALESCE(SUM(packets),0),COALESCE(SUM(flow_count),0),COUNT(*)
             FROM traffic_scope_minute",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    let total_rollups = connection
        .query_row(
            "SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),
                    COALESCE(SUM(packets),0),COALESCE(SUM(flow_count),0),
                    COALESCE(SUM(source_rows),0)
             FROM traffic_scope_total_minute",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(totals, total_rollups);
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let dimension_groups =
        if dictionary {
            connection
            .prepare(
                "SELECT a.value,c.value,d.value,p.value,SUM(t.upload_bytes),SUM(t.download_bytes),
                        SUM(t.packets),SUM(t.flow_count)
                 FROM traffic_scope_minute t
                 JOIN dimension_dictionary a ON a.id=t.application_id
                 JOIN dimension_dictionary c ON c.id=t.category_id
                 JOIN dimension_dictionary d ON d.id=t.domain
                 JOIN dimension_dictionary p ON p.id=t.protocol_id
                 GROUP BY a.value,c.value,d.value,p.value
                 ORDER BY a.value,c.value,d.value,p.value",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        } else {
            connection
                .prepare(
                    "SELECT application_id,category_id,domain,protocol_id,SUM(upload_bytes),
                        SUM(download_bytes),SUM(packets),SUM(flow_count)
                 FROM traffic_scope_minute
                 GROUP BY application_id,category_id,domain,protocol_id
                 ORDER BY application_id,category_id,domain,protocol_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
    let app_group_p50_us = if dictionary {
        scope_application_query_us(
            &connection,
            "SELECT a.value,SUM(t.upload_bytes+t.download_bytes)
             FROM traffic_scope_minute t JOIN dimension_dictionary a ON a.id=t.application_id
             WHERE t.scope=1 GROUP BY a.value
             ORDER BY SUM(t.upload_bytes+t.download_bytes) DESC,a.value LIMIT 50",
        )
    } else {
        scope_application_query_us(
            &connection,
            "SELECT application_id,SUM(upload_bytes+download_bytes)
             FROM traffic_scope_minute WHERE scope=1 GROUP BY application_id
             ORDER BY SUM(upload_bytes+download_bytes) DESC,application_id LIMIT 50",
        )
    };
    let wal_path = std::path::PathBuf::from(format!("{}-wal", path.display()));
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let wal_bytes_after_checkpoint = std::fs::metadata(&wal_path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let db_bytes = std::fs::metadata(path).unwrap().len();
    let mut statement = connection
        .prepare(
            "SELECT name,SUM(pgsize) FROM dbstat
             WHERE name LIKE 'traffic_scope_%' OR name LIKE 'scope_%'
             OR name LIKE 'dimension_dictionary%'
             GROUP BY name ORDER BY name",
        )
        .unwrap();
    let objects = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    ScopeDictionaryBenchmarkResult {
        row_count,
        totals,
        dimension_groups,
        insert_ms,
        insert_batch_p50_us: batch_percentile(50),
        insert_batch_p95_us: batch_percentile(95),
        insert_batch_p99_us: batch_percentile(99),
        upsert_replay_ms: replay_ms,
        attribution_move_ms,
        retention_500_us,
        db_bytes,
        wal_peak_bytes,
        wal_bytes_after_checkpoint,
        app_group_p50_us,
        objects,
    }
}

fn scope_benchmark_wal_bytes(path: &std::path::Path) -> u64 {
    std::fs::metadata(path.with_extension("db-wal"))
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

#[test]
#[ignore = "manual file-backed partial device index experiment"]
fn file_device_index_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let null_percent: i64 = std::env::var("NETQMON_BENCH_NULL_PERCENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    assert!((0..=100).contains(&null_percent));
    let dir = tempdir().unwrap();
    let mut reference = None;
    for mode in ["full", "partial", "split"] {
        let path = dir.path().join(format!("{mode}.db"));
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        let connection = storage.connection();
        if mode != "full" {
            connection.execute_batch("DROP INDEX flow_sessions_device_last_seen; CREATE INDEX flow_sessions_device_last_seen ON flow_sessions(device_id,last_seen_at) WHERE device_id IS NOT NULL;").unwrap();
        }
        if mode == "split" {
            connection.execute_batch("CREATE INDEX flow_sessions_device_null_last_seen ON flow_sessions(last_seen_at) WHERE device_id IS NULL;").unwrap();
        }
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) SELECT i,'gateway-1',CAST(printf('%012x',i) AS BLOB),?1,?1 FROM n",[to_i64(NOW)]).unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0")
            .unwrap();
        let started = Instant::now();
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at,ended_at) SELECT printf('flow-%d',i),'gateway-1',CASE WHEN (i/1000)%100<?2 THEN NULL ELSE i%1000+1 END,4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,printf('app-%d',i%100),'tcp',i%1000,i%500,1,?3,?3+i,?3,?3+i FROM n",params![rows,null_percent,to_i64(NOW)]).unwrap();
        let insert = started.elapsed();
        let wal = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let file = std::fs::metadata(&path).unwrap().len();
        let index_bytes: i64 = connection
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name IN ('flow_sessions_device_last_seen','flow_sessions_device_null_last_seen')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let queries = [
            "SELECT id,last_seen_at,upload_bytes FROM flow_sessions WHERE device_id=100 AND last_seen_at>=0 AND last_seen_at<9000000000000 ORDER BY last_seen_at DESC LIMIT 50",
            "SELECT id,last_seen_at,upload_bytes FROM flow_sessions WHERE device_id IS NULL ORDER BY last_seen_at DESC LIMIT 50",
        ];
        let mut outputs = Vec::new();
        for sql in queries {
            let mut plan = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let plan = plan
                .query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut samples = Vec::new();
            let mut output = Vec::new();
            for _ in 0..10 {
                let start = Instant::now();
                let mut statement = connection.prepare(sql).unwrap();
                output = statement
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                samples.push(start.elapsed().as_micros());
            }
            samples.sort_unstable();
            eprintln!(
                "device_index_mode={mode} query_p50_us={} p95_us={} p99_us={} plan={plan:?}",
                samples[5], samples[9], samples[9]
            );
            outputs.push(output);
        }
        if let Some(expected) = &reference {
            assert_eq!(&outputs, expected);
        } else {
            reference = Some(outputs);
        }
        eprintln!(
            "device_index_mode={mode} rows={rows} null_percent={null_percent} db_bytes={file} index_bytes={index_bytes} wal_bytes={wal} insert_ms={}",
            insert.as_millis()
        );
        if mode == "full" {
            let start = Instant::now();
            connection.execute_batch("BEGIN IMMEDIATE; DROP INDEX flow_sessions_device_last_seen; CREATE INDEX flow_sessions_device_last_seen ON flow_sessions(device_id,last_seen_at) WHERE device_id IS NOT NULL; COMMIT;").unwrap();
            let elapsed = start.elapsed();
            let free: i64 = connection
                .pragma_query_value(None, "freelist_count", |r| r.get(0))
                .unwrap();
            let size: i64 = connection
                .query_row(
                    "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_device_last_seen'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            connection.execute_batch("BEGIN IMMEDIATE; DROP INDEX flow_sessions_device_last_seen; CREATE INDEX flow_sessions_device_last_seen ON flow_sessions(device_id,last_seen_at); COMMIT;").unwrap();
            let integrity: String = connection
                .pragma_query_value(None, "integrity_check", |r| r.get(0))
                .unwrap();
            assert_eq!(integrity, "ok");
            eprintln!(
                "device_index_upgrade_ms={} partial_index_bytes={size} freelist_pages={free} rollback_integrity={integrity}",
                elapsed.as_millis()
            );
        }
    }
}

#[test]
#[ignore = "manual file-backed incremental auto-vacuum comparison"]
fn file_incremental_auto_vacuum_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    assert!(rows >= 1_000);
    let directory = tempdir().unwrap();
    for incremental in [false, true] {
        let layout = if incremental { "incremental" } else { "none" };
        let path = directory.path().join(format!("{layout}-vacuum.db"));
        if incremental {
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "auto_vacuum", "INCREMENTAL")
                .unwrap();
            connection.execute_batch("VACUUM").unwrap();
        }
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        let connection = storage.connection();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        let inserted_at = to_i64(NOW.saturating_sub(31 * DAY_MS as u64));
        let insert_started = Instant::now();
        connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2,'gateway-1',1,1,1,'app','cat','example',CAST(printf('%08x',i) AS BLOB),6,'tcp',1,1,1,1 FROM n", params![rows, inserted_at]).unwrap();
        let insert_elapsed = insert_started.elapsed();
        let wal_path = path.with_extension("db-wal");
        let insert_wal = std::fs::metadata(&wal_path).unwrap().len();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let initial_bytes = std::fs::metadata(&path).unwrap().len();
        let mut writer = storage.independent_connection(false).unwrap().unwrap();
        writer
            .connection()
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();

        let retention_started = Instant::now();
        let mut retention_slices = 0;
        loop {
            retention_slices += 1;
            if writer
                .run_retention_bounded(NOW, RetentionPolicy::default(), RetentionBudget::default())
                .unwrap()
            {
                break;
            }
            assert!(retention_slices < 10_000, "retention did not finish");
        }
        let retention_elapsed = retention_started.elapsed();
        let retained_rows: i64 = writer
            .connection()
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained_rows, 0);
        let retention_wal = std::fs::metadata(&wal_path).unwrap().len();
        writer
            .connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let after_retention_bytes = std::fs::metadata(&path).unwrap().len();
        let free_before: i64 = writer
            .connection()
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap();
        let auto_vacuum: i64 = writer
            .connection()
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
            .unwrap();

        let vacuum_started = Instant::now();
        let mut vacuum_slices = 0;
        if incremental {
            while writer
                .connection()
                .pragma_query_value(None, "freelist_count", |row| row.get::<_, i64>(0))
                .unwrap()
                > 0
            {
                writer
                    .connection()
                    .execute_batch("PRAGMA incremental_vacuum(500)")
                    .unwrap();
                vacuum_slices += 1;
                assert!(vacuum_slices < 100_000, "incremental vacuum did not finish");
            }
        } else {
            writer
                .connection()
                .execute_batch("PRAGMA incremental_vacuum(500)")
                .unwrap();
            vacuum_slices = 1;
        }
        let vacuum_elapsed = vacuum_started.elapsed();
        writer
            .connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let final_bytes = std::fs::metadata(&path).unwrap().len();
        let vacuum_wal = std::fs::metadata(&wal_path).unwrap().len();
        let free_after: i64 = writer
            .connection()
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap();
        let integrity: String = writer
            .connection()
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        eprintln!(
            "auto_vacuum={auto_vacuum} rows={rows} initial_bytes={initial_bytes} after_retention_bytes={after_retention_bytes} final_bytes={final_bytes} insert_ms={} insert_wal={insert_wal} retention_ms={} retention_slices={retention_slices} retention_wal={retention_wal} free_before={free_before} vacuum_ms={} vacuum_slices={vacuum_slices} free_after={free_after} vacuum_wal={vacuum_wal} integrity={integrity}",
            insert_elapsed.as_millis(),
            retention_elapsed.as_millis(),
            vacuum_elapsed.as_millis(),
        );
    }
}

#[test]
#[ignore = "manual file-backed retention, checkpoint and vacuum experiment"]
fn file_retention_space_experiment() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    assert!(rows >= 1_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("retention-space.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let connection = storage.connection();
    connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2,'gateway-1',1,1,1,'app','cat','example',CAST(printf('%016x',i) AS BLOB),6,'tcp',1,2,1,1 FROM n", params![rows,to_i64(NOW)]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let initial_bytes = std::fs::metadata(&path).unwrap().len();
    let reader = storage.independent_connection(true).unwrap().unwrap();
    let snapshot: i64 = reader
        .connection()
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(snapshot, rows);
    let mut writer = storage.independent_connection(false).unwrap().unwrap();
    writer
        .connection()
        .pragma_update(None, "wal_autocheckpoint", 0)
        .unwrap();
    let now = NOW + 31 * DAY_MS as u64;
    let started = Instant::now();
    let mut slices = 0;
    loop {
        slices += 1;
        if writer
            .run_retention_bounded(now, RetentionPolicy::default(), RetentionBudget::default())
            .unwrap()
        {
            break;
        }
        assert!(slices < 1000, "retention did not finish");
    }
    let retention_elapsed = started.elapsed();
    let wal_path = path.with_extension("db-wal");
    let wal_before = std::fs::metadata(&wal_path).unwrap().len();
    let checkpoint: (i64, i64, i64) = writer
        .connection()
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert!(checkpoint.1 > checkpoint.2, "reader must pin WAL frames");
    assert_eq!(
        reader
            .connection()
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        rows
    );
    assert_eq!(
        writer
            .connection()
            .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let free_after: i64 = writer
        .connection()
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .unwrap();
    assert!(free_after > 0);
    drop(reader);
    writer
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let wal_after = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(wal_after, 0);
    let auto_vacuum: i64 = writer
        .connection()
        .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
        .unwrap();
    assert_eq!(auto_vacuum, 0);
    let before_incremental = std::fs::metadata(&path).unwrap().len();
    writer
        .connection()
        .execute_batch("PRAGMA incremental_vacuum(1000)")
        .unwrap();
    let after_incremental = std::fs::metadata(&path).unwrap().len();
    assert_eq!(before_incremental, after_incremental);
    let reuse = rows / 2;
    writer.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2,'gateway-1',1,1,1,'app','cat','example',CAST(printf('%016x',i) AS BLOB),6,'tcp',1,2,1,1 FROM n",params![reuse,to_i64(now)]).unwrap();
    writer
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let reused_bytes = std::fs::metadata(&path).unwrap().len();
    let free_reuse: i64 = writer
        .connection()
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .unwrap();
    assert!(free_reuse < free_after);
    let started = Instant::now();
    writer
        .connection()
        .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let vacuum_elapsed = started.elapsed();
    let compact_bytes = std::fs::metadata(&path).unwrap().len();
    let count: i64 = writer
        .connection()
        .query_row("SELECT COUNT(*) FROM traffic_scope_minute", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, reuse);
    assert!(compact_bytes < reused_bytes);
    assert_eq!(
        metrics(writer.connection(), "traffic_scope_total_minute", "1=1"),
        (reuse, reuse * 2, reuse, reuse)
    );
    eprintln!(
        "retention_rows={rows} slices={slices} retention_ms={} initial_bytes={initial_bytes} wal_before={wal_before} checkpoint={checkpoint:?} wal_after={wal_after} freelist_pages={free_after} incremental_before={before_incremental} incremental_after={after_incremental} reused_bytes={reused_bytes} freelist_after_reuse={free_reuse} vacuum_ms={} compact_bytes={compact_bytes}",
        retention_elapsed.as_millis(),
        vacuum_elapsed.as_millis()
    );
}

#[test]
#[ignore = "manual file-backed active-flow startup memory benchmark"]
fn file_active_restart_memory_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("active-restart.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    storage.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,domain,application_id,category_id,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) SELECT printf('flow-%d',i),'gateway-1',4,6,X'C0000201',i%60000,CAST(printf('%016x',i) AS BLOB),443,1,printf('domain-%d.example',i%10000),printf('app-%d',i%100),'web','tcp',100,50,3,?2,?2,?2 FROM n",params![rows,to_i64(NOW)]).unwrap();
    storage
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let bytes = std::fs::metadata(&path).unwrap().len();
    drop(storage);
    let memory = || {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let before = memory();
    let start = Instant::now();
    let reopened = open_at(&path, NOW + 1).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(
        reopened.active_flows.len(),
        usize::try_from(rows)
            .unwrap()
            .min(ACTIVE_FLOW_CACHE_CAPACITY)
    );
    assert_eq!(
        reopened.active_flows.expiry.len(),
        usize::try_from(rows)
            .unwrap()
            .min(ACTIVE_FLOW_CACHE_CAPACITY)
    );
    eprintln!(
        "restart_rows={rows} db_bytes={bytes} open_ms={} before={before:?} after={:?}",
        elapsed.as_millis(),
        memory()
    );
}

/// Reproducible file-backed schema and query-plan inventory, with synthetic data.
#[test]
#[ignore = "manual SQLite schema diagnostic"]
fn file_schema_diagnostic() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("schema.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let connection = storage.connection();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,domain,application_id,category_id,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) SELECT printf('flow-%d',i),'gateway-1',4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,printf('domain-%d.example',i%10000),printf('app-%d',i%100),printf('cat-%d',i%10),'tcp',printf('org-%d',i%500),i%1000,i%500,1,?2,?2,?2 FROM n", params![rows,to_i64(NOW)]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2+i,'gateway-1',1,1,i%1000,printf('app-%d',i%100),printf('cat-%d',i%10),printf('domain-%d.example',i%10000),CAST(printf('%08x',i%50000) AS BLOB),6,'tcp',1,1,1,1 FROM n",params![rows,to_i64(NOW)]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    eprintln!(
        "rows={rows} bytes={}",
        std::fs::metadata(&path).unwrap().len()
    );
    let mut sizes = connection
        .prepare(
            "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY SUM(pgsize) DESC LIMIT 25",
        )
        .unwrap();
    for row in sizes
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
    {
        eprintln!("dbstat {:?}", row.unwrap());
    }
    for (name, sql) in [
        (
            "destinations",
            "SELECT remote_ip,SUM(upload_bytes+download_bytes) FROM traffic_scope_minute WHERE scope=1 GROUP BY remote_ip ORDER BY SUM(upload_bytes+download_bytes) DESC,hex(remote_ip) LIMIT 50",
        ),
        (
            "organizations",
            "SELECT COALESCE(organization_id,'unknown'),SUM(upload_bytes),COUNT(DISTINCT device_id) FROM flow_sessions GROUP BY COALESCE(organization_id,'unknown') ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50",
        ),
        (
            "protocols",
            "SELECT COALESCE(protocol_id,'unknown'),SUM(upload_bytes) FROM flow_sessions GROUP BY COALESCE(protocol_id,'unknown') ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50",
        ),
        (
            "flows",
            "SELECT id FROM flow_sessions ORDER BY last_seen_at DESC,id ASC LIMIT 51",
        ),
        (
            "traffic_chart",
            "SELECT (timestamp / 60000) * 60000 AS bucket, SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count) FROM traffic_scope_total_minute WHERE timestamp >= 0 AND timestamp < 9000000000000 AND scope = 1 AND direction = 1 GROUP BY bucket ORDER BY bucket",
        ),
        (
            "traffic_client_breakdown",
            "SELECT d.id, SUM(t.upload_bytes), SUM(t.download_bytes), MAX(t.timestamp) FROM traffic_scope_minute t JOIN devices d ON d.id=t.device_id WHERE t.timestamp >= 0 AND t.timestamp < 9000000000000 AND t.scope=1 AND t.direction=1 GROUP BY d.id ORDER BY SUM(t.upload_bytes+t.download_bytes) DESC LIMIT 50",
        ),
        (
            "traffic_application_breakdown",
            "SELECT application_id, SUM(upload_bytes), SUM(download_bytes), MAX(timestamp) FROM traffic_scope_minute WHERE timestamp >= 0 AND timestamp < 9000000000000 AND scope=1 AND direction=1 GROUP BY application_id ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50",
        ),
        (
            "flows_cursor_page",
            "SELECT id FROM flow_sessions WHERE (last_seen_at < 1700000000000 OR (last_seen_at = 1700000000000 AND id > 'flow-cursor')) ORDER BY last_seen_at DESC,id ASC LIMIT 51",
        ),
    ] {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        for row in statement.query_map([], |r| r.get::<_, String>(3)).unwrap() {
            eprintln!("plan {name}: {}", row.unwrap());
        }
    }
    let flow_page_sql = "SELECT id FROM flow_sessions ORDER BY last_seen_at DESC,id ASC LIMIT 51";
    let measure_flow_updates = |connection: &Connection| {
        let mut samples = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let changed = connection
                .execute(
                    "UPDATE flow_sessions SET last_seen_at=last_seen_at+1
                     WHERE rowid IN (SELECT rowid FROM flow_sessions ORDER BY id LIMIT 1000)",
                    [],
                )
                .unwrap();
            let elapsed = started.elapsed().as_micros();
            assert_eq!(changed, 1000);
            connection
                .execute(
                    "UPDATE flow_sessions SET last_seen_at=last_seen_at-1
                     WHERE rowid IN (SELECT rowid FROM flow_sessions ORDER BY id LIMIT 1000)",
                    [],
                )
                .unwrap();
            samples.push(elapsed);
        }
        samples.sort_unstable();
        (samples[2], samples[4])
    };
    let measure_flow_page = |connection: &Connection| {
        let mut samples = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let mut statement = connection.prepare(flow_page_sql).unwrap();
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(rows.len(), 51);
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        (samples[10], samples[18], samples[19])
    };
    let before = measure_flow_page(connection);
    let updates_before = measure_flow_updates(connection);
    connection
        .execute_batch(
            "CREATE INDEX flow_sessions_last_seen_id_bench
             ON flow_sessions(last_seen_at DESC,id ASC)",
        )
        .unwrap();
    let after = measure_flow_page(connection);
    let updates_after = measure_flow_updates(connection);
    let candidate_index_bytes: i64 = connection
        .query_row(
            "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_last_seen_id_bench'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    eprintln!(
        "flow_order_index rows={rows} query_before_p50_p95_p99_us={before:?} query_after_p50_p95_p99_us={after:?} update_1000_before_p50_max_us={updates_before:?} update_1000_after_p50_max_us={updates_after:?} index_bytes={candidate_index_bytes}"
    );
    for pragma in [
        "page_count",
        "page_size",
        "freelist_count",
        "cache_size",
        "auto_vacuum",
        "wal_autocheckpoint",
    ] {
        let value: i64 = connection
            .pragma_query_value(None, pragma, |r| r.get(0))
            .unwrap();
        eprintln!("pragma {pragma}={value}");
    }
}

/// Measures whether the last-seen suffix in the late-DPI tuple index earns its
/// per-update and storage cost. Both layouts keep the seven-column tuple key;
/// the candidate only removes the time column and filters overlapping history
/// rows after the tuple seek.
#[test]
#[ignore = "manual SQLite sample-lookup index comparison"]
fn file_sample_lookup_index_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let row_limit = rows;
    let tuples: i64 = std::env::var("NETQMON_BENCH_TUPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    assert!(rows > 0 && tuples > 0 && tuples <= rows);

    let directory = tempdir().unwrap();
    let mut expected_rows = None;
    let layouts = if std::env::var("NETQMON_BENCH_LAYOUT").as_deref() == Ok("tuple_only") {
        ["tuple_only", "tuple_only"]
    } else if std::env::var("NETQMON_BENCH_LAYOUT").as_deref() == Ok("full") {
        ["full", "full"]
    } else if std::env::var("NETQMON_BENCH_REVERSE_ORDER").is_ok_and(|value| value == "1") {
        ["tuple_only", "full"]
    } else {
        ["full", "tuple_only"]
    };
    for (layout_index, layout) in layouts.into_iter().enumerate() {
        if layout_index == 1 && std::env::var("NETQMON_BENCH_LAYOUT").is_ok() {
            break;
        }
        let path = directory.path().join(format!("sample-lookup-{layout}.db"));
        let mut storage = open_at(&path, NOW).unwrap();
        storage
            .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
            .unwrap();
        let connection = storage.connection();
        if layout == "tuple_only" {
            connection
                .execute_batch(
                    "DROP INDEX flow_sessions_sample_lookup;
                 CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
                    gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port
                 );",
                )
                .unwrap();
        }
        connection
            .execute_batch("PRAGMA wal_autocheckpoint=0")
            .unwrap();
        let started = Instant::now();
        connection
            .execute(
                "WITH RECURSIVE n(i) AS (
                VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1
             )
             INSERT INTO flow_sessions(
                id,gateway_id,ip_version,protocol,client_ip,client_port,
                remote_ip,remote_port,direction,upload_bytes,download_bytes,
                packets,started_at,last_seen_at,checkpointed_at
             )
             SELECT printf('flow-%d',i),'gateway-1',4,6,
                CAST(printf('%08x',(i%?2)%100) AS BLOB),
                10000+((i%?2)/10000),
                CAST(printf('%08x',((i%?2)/100)%100) AS BLOB),
                443+(((i%?2)/1000)%10),1,
                i%1000,i%500,1,?3+i,?3+i,?3+i
             FROM n",
                params![rows + 1, tuples, to_i64(NOW)],
            )
            .unwrap();
        let insert_ms = started.elapsed().as_millis();
        let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let db_bytes = std::fs::metadata(&path).unwrap().len();
        let index_bytes: i64 = connection
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_sample_lookup'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        let query = "SELECT id,domain,organization_id,application_id,category_id,
                traffic_role,protocol_id,organization_confidence,application_confidence,
                protocol_confidence,classification_confidence,classification_reason,
                classification_evidence_json
             FROM flow_sessions
             WHERE gateway_id=?1 AND ip_version=4 AND protocol=6
               AND client_ip=?2 AND client_port=?3 AND remote_ip=?4 AND remote_port=443
               AND started_at<=?5 AND last_seen_at>=?6";
        let indexed_query = query.replace(
            "FROM flow_sessions",
            "FROM flow_sessions INDEXED BY flow_sessions_sample_lookup",
        );
        let tuple = 0_i64;
        let client_ip = format!("{tuple:08x}").into_bytes();
        let remote_ip = format!("{:08x}", (tuple / 100) % 100).into_bytes();
        // Use the full lifetime window so the candidate must find all prior
        // sessions for this reused tuple, not only the latest observation.
        let lower_bound = to_i64(NOW);
        let mut query_samples = Vec::new();
        let mut indexed_query_samples = Vec::new();
        let mut matching_rows = Vec::new();
        let mut indexed_matching_rows = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let rows = connection
                .prepare_cached(query)
                .unwrap()
                .query_map(
                    params![
                        "gateway-1",
                        client_ip,
                        10_000_i64 + tuple % 50_000,
                        remote_ip,
                        to_i64(NOW) + row_limit,
                        lower_bound
                    ],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            query_samples.push(started.elapsed().as_micros());
            matching_rows = rows;

            let started = Instant::now();
            let rows = connection
                .prepare_cached(&indexed_query)
                .unwrap()
                .query_map(
                    params![
                        "gateway-1",
                        client_ip,
                        10_000_i64 + tuple % 50_000,
                        remote_ip,
                        to_i64(NOW) + row_limit,
                        lower_bound
                    ],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            indexed_query_samples.push(started.elapsed().as_micros());
            indexed_matching_rows = rows;
        }
        query_samples.sort_unstable();
        indexed_query_samples.sort_unstable();
        assert_eq!(indexed_matching_rows, matching_rows);
        if let Some(expected) = &expected_rows {
            assert_eq!(&matching_rows, expected);
        } else {
            expected_rows = Some(matching_rows.clone());
        }

        let mut plan_statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap();
        let plan = plan_statement
            .query_map(
                params![
                    "gateway-1",
                    client_ip,
                    10_000_i64 + tuple % 50_000,
                    remote_ip,
                    to_i64(NOW) + row_limit,
                    lower_bound
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let indexed_plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {indexed_query}"))
            .unwrap()
            .query_map(
                params![
                    "gateway-1",
                    client_ip,
                    10_000_i64 + tuple % 50_000,
                    remote_ip,
                    to_i64(NOW) + row_limit,
                    lower_bound
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        let ids = connection
            .prepare("SELECT id FROM flow_sessions ORDER BY id LIMIT 1000")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let update_sql = "UPDATE flow_sessions SET last_seen_at=last_seen_at+1,
            upload_bytes=upload_bytes+1 WHERE id=?1";
        let mut update_samples = Vec::new();
        for _ in 0..10 {
            connection
                .execute_batch("SAVEPOINT index_update_sample")
                .unwrap();
            let started = Instant::now();
            for id in &ids {
                connection.execute(update_sql, [id]).unwrap();
            }
            update_samples.push(started.elapsed().as_micros());
            connection
                .execute_batch("ROLLBACK TO index_update_sample; RELEASE index_update_sample")
                .unwrap();
        }
        update_samples.sort_unstable();
        let update_wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
            .unwrap()
            .len();
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        eprintln!(
            "sample_lookup_layout={layout} rows={rows} tuples={tuples} db_bytes={db_bytes} index_bytes={index_bytes} insert_ms={insert_ms} wal_insert_bytes={wal_bytes} query_matches={} query_p50_p95_p99_us={}/{}/{} indexed_query_p50_p95_p99_us={}/{}/{} update_1000_p50_p95_p99_us={}/{}/{} wal_after_update_samples={update_wal_bytes} plan={plan:?} indexed_plan={indexed_plan:?}",
            expected_rows.as_ref().unwrap().len(),
            query_samples[10],
            query_samples[18],
            query_samples[19],
            indexed_query_samples[10],
            indexed_query_samples[18],
            indexed_query_samples[19],
            update_samples[5],
            update_samples[8],
            update_samples[9],
        );
        if layout == "full" && std::env::var_os("NETQMON_BENCH_MIGRATE").is_some() {
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .unwrap();
            let totals_before: (i64, i64, i64) = connection
                .query_row(
                    "SELECT COUNT(*),SUM(upload_bytes),SUM(download_bytes) FROM flow_sessions",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let started = Instant::now();
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     DROP INDEX flow_sessions_sample_lookup;
                     CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
                        gateway_id,ip_version,protocol,client_ip,client_port,
                        remote_ip,remote_port
                     );
                     COMMIT;",
                )
                .unwrap();
            let migration_ms = started.elapsed().as_millis();
            let migration_wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
                .unwrap()
                .len();
            let new_index_bytes: i64 = connection
                .query_row(
                    "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_sample_lookup'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let migration_integrity: String = connection
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(migration_integrity, "ok");
            let totals_after: (i64, i64, i64) = connection
                .query_row(
                    "SELECT COUNT(*),SUM(upload_bytes),SUM(download_bytes) FROM flow_sessions",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(totals_after, totals_before);
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .unwrap();
            let migrated_file_bytes = std::fs::metadata(&path).unwrap().len();
            let pages: i64 = connection
                .pragma_query_value(None, "page_count", |row| row.get(0))
                .unwrap();
            let freelist: i64 = connection
                .pragma_query_value(None, "freelist_count", |row| row.get(0))
                .unwrap();
            let migrated_plan = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {indexed_query}"))
                .unwrap()
                .query_map(
                    params![
                        "gateway-1",
                        client_ip,
                        10_000_i64 + tuple % 50_000,
                        remote_ip,
                        to_i64(NOW) + row_limit,
                        lower_bound
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!(
                "sample_lookup_migration rows={rows} migration_ms={migration_ms} wal_peak_bytes={migration_wal_bytes} old_index_bytes={index_bytes} new_index_bytes={new_index_bytes} file_bytes_before={db_bytes} file_bytes_after_checkpoint={migrated_file_bytes} pages={pages} freelist={freelist} totals={totals_after:?} integrity={migration_integrity} forced_plan={migrated_plan:?}"
            );
        }
    }
}

fn legacy_delete_older_than(tx: &Transaction<'_>, table: &str, column: &str, now: i64, days: u32) {
    if days != 0 {
        let cutoff = now.saturating_sub(i64::from(days) * DAY_MS);
        tx.execute(
            &format!("DELETE FROM {table} WHERE {column} < ?1"),
            [cutoff],
        )
        .unwrap();
    }
}

fn legacy_full_retention(storage: &mut SqliteStorage, now_ms: u64, policy: RetentionPolicy) {
    let now = to_i64(now_ms);
    let transaction = storage.connection.transaction().unwrap();
    prune_flow_state(&transaction, &storage.active_flows, now).unwrap();
    legacy_delete_older_than(
        &transaction,
        "flow_sessions",
        "last_seen_at",
        now,
        policy.flow_sessions_days,
    );
    if policy.dns_days == 0 {
        transaction
            .execute("DELETE FROM dns_observations WHERE expires_at < ?1", [now])
            .unwrap();
    } else {
        let cutoff = now.saturating_sub(i64::from(policy.dns_days) * DAY_MS);
        transaction
            .execute(
                "DELETE FROM dns_observations WHERE expires_at < ?1 OR observed_at < ?2",
                params![now, cutoff],
            )
            .unwrap();
    }
    legacy_delete_older_than(
        &transaction,
        "ingest_batches",
        "received_at",
        now,
        policy.minute_days,
    );
    legacy_delete_older_than(
        &transaction,
        "traffic_scope_minute",
        "timestamp",
        now,
        policy.minute_days,
    );
    for dimension in DIMENSIONS {
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_minute"),
            "timestamp",
            now,
            policy.minute_days,
        );
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_hour"),
            "timestamp",
            now,
            policy.hour_days,
        );
        legacy_delete_older_than(
            &transaction,
            &format!("traffic_{dimension}_day"),
            "timestamp",
            now,
            policy.day_days,
        );
        for (tier, days) in [("hour", policy.hour_days), ("day", policy.day_days)] {
            legacy_delete_older_than(
                &transaction,
                &format!("traffic_{dimension}_{tier}_pending"),
                "timestamp",
                now,
                days,
            );
        }
    }
    transaction.commit().unwrap();
}

fn process_write_bytes() -> Option<u64> {
    std::fs::read_to_string("/proc/self/io")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("write_bytes:")?.trim().parse().ok())
}

fn process_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
}

// Run separately for each mode using NETQMON_RETENTION_BASELINE=true/false.
#[test]
#[ignore = "manual SQLite retention benchmark"]
fn file_retention_benchmark() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };
    let baseline = std::env::var("NETQMON_RETENTION_BASELINE").as_deref() == Ok("true");
    let rows: u32 = std::env::var("NETQMON_RETENTION_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("retention-bench.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .connection()
        .execute_batch("CREATE TABLE writer_probe (value INTEGER)")
        .unwrap();
    storage.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT ?2,'gateway-1',1,1,1,'app','cat','example',CAST(printf('%016x',i) AS BLOB),6,'tcp',1,1,1,1 FROM n", params![rows, to_i64(NOW)]).unwrap();
    storage
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let autocheckpoint_pages = std::env::var("NETQMON_RETENTION_AUTOCHECKPOINT_PAGES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    storage
        .connection()
        .pragma_update(None, "wal_autocheckpoint", autocheckpoint_pages)
        .unwrap();
    let mut bounded_writer = if baseline {
        None
    } else {
        let writer = storage.independent_connection(false).unwrap().unwrap();
        writer
            .connection()
            .pragma_update(None, "wal_autocheckpoint", autocheckpoint_pages)
            .unwrap();
        Some(writer)
    };
    let wal = dir.path().join("retention-bench.db-wal");
    let running = Arc::new(AtomicBool::new(true));
    let ready = Arc::new(Barrier::new(2));
    let writer = if std::env::var_os("NETQMON_RETENTION_WRITER").is_some() {
        let (worker_running, worker_ready, path) = (running.clone(), ready.clone(), path.clone());
        let worker = std::thread::spawn(move || {
            let connection = Connection::open(path).unwrap();
            connection.busy_timeout(Duration::from_millis(500)).unwrap();
            let mut observations = Vec::new();
            worker_ready.wait();
            while worker_running.load(Ordering::Relaxed) {
                let start = Instant::now();
                let result = connection.execute("INSERT INTO writer_probe VALUES(1)", []);
                observations.push((start.elapsed(), result.is_ok()));
                std::thread::sleep(Duration::from_millis(5));
            }
            observations
        });
        ready.wait();
        Some(worker)
    } else {
        None
    };
    let before = process_write_bytes();
    let cpu_before = process_cpu_ticks();
    RETENTION_TRANSACTION_TIMES.with(|v| v.borrow_mut().clear());
    RETENTION_PHASE_TIMES.with(|v| v.borrow_mut().clear());
    let started = Instant::now();
    let mut cycles = 0;
    if baseline {
        legacy_full_retention(
            &mut storage,
            NOW + 31 * DAY_MS as u64,
            RetentionPolicy::default(),
        );
    } else {
        loop {
            cycles += 1;
            if bounded_writer
                .as_mut()
                .unwrap()
                .run_retention_bounded(
                    NOW + 31 * DAY_MS as u64,
                    RetentionPolicy::default(),
                    RetentionBudget {
                        max_rows_per_batch: std::env::var("NETQMON_RETENTION_BATCH_ROWS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(500),
                        transaction_target: Duration::from_millis(
                            std::env::var("NETQMON_RETENTION_TRANSACTION_MS")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(100),
                        ),
                        ..RetentionBudget::default()
                    },
                )
                .unwrap()
            {
                break;
            }
        }
    }
    let elapsed = started.elapsed();
    running.store(false, Ordering::Relaxed);
    if let Some(writer) = writer {
        let observations = writer.join().unwrap();
        let mut latency: Vec<_> = observations.iter().map(|(duration, _)| *duration).collect();
        latency.sort();
        let p50 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(50)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        let p95 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(95)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        let p99 = latency
            .get(
                latency
                    .len()
                    .saturating_mul(99)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros);
        eprintln!(
            "writer_baseline={baseline} attempts={} success={} errors={} p50_us={p50:?} p95_us={p95:?} p99_us={p99:?} max_us={:?}",
            observations.len(),
            observations.iter().filter(|(_, ok)| *ok).count(),
            observations.iter().filter(|(_, ok)| !*ok).count(),
            latency.last().map(Duration::as_micros)
        );
    }
    let cpu_ticks = cpu_before
        .zip(process_cpu_ticks())
        .and_then(|(a, b)| b.checked_sub(a));
    let mut tx_times = RETENTION_TRANSACTION_TIMES.with(|v| v.borrow().clone());
    if baseline {
        tx_times.push(elapsed);
    }
    tx_times.sort();
    let tx_p95 = tx_times
        .get(
            tx_times
                .len()
                .saturating_mul(95)
                .div_ceil(100)
                .saturating_sub(1),
        )
        .map(Duration::as_micros);
    let tx_max = tx_times.last().map(Duration::as_micros);
    let p99_index = tx_times
        .len()
        .saturating_mul(99)
        .div_ceil(100)
        .saturating_sub(1);
    let tx_p99 = tx_times.get(p99_index).map(Duration::as_micros);
    let phases = RETENTION_PHASE_TIMES.with(|v| v.borrow().clone());
    let phase_percentile = |idx: usize, percentile: usize| {
        let mut values: Vec<_> = phases
            .iter()
            .map(|phase| match idx {
                0 => phase.0,
                1 => phase.1,
                _ => phase.2,
            })
            .collect();
        values.sort();
        values
            .get(
                values
                    .len()
                    .saturating_mul(percentile)
                    .div_ceil(100)
                    .saturating_sub(1),
            )
            .map(Duration::as_micros)
    };
    let phase_p95 = (
        phase_percentile(0, 95),
        phase_percentile(1, 95),
        phase_percentile(2, 95),
    );
    let io = before
        .zip(process_write_bytes())
        .and_then(|(a, b)| b.checked_sub(a));
    let peak = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .map(str::to_owned)
        });
    eprintln!(
        "retention_baseline={baseline} rows={rows} batch_rows={} autocheckpoint_pages={autocheckpoint_pages} elapsed_ms={} cycles={cycles} wal_bytes={} process_write_bytes={io:?} peak_rss={peak:?} cpu_ticks={cpu_ticks:?} tx_count={} tx_p95_us={tx_p95:?} tx_p99_us={tx_p99:?} tx_max_us={tx_max:?} begin_delete_commit_p95_us={phase_p95:?}",
        std::env::var("NETQMON_RETENTION_BATCH_ROWS").unwrap_or_else(|_| "500".into()),
        elapsed.as_millis(),
        std::fs::metadata(wal).unwrap().len(),
        tx_times.len()
    );
    assert_eq!(
        storage
            .connection()
            .query_row("SELECT count(*) FROM traffic_scope_minute", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[allow(unsafe_code)]
fn sqlite_memory_status(reset_highwater: bool) -> Option<(i64, i64)> {
    let mut current = 0_i64;
    let mut highwater = 0_i64;
    // SAFETY: SQLite writes two i64 values to these valid pointers and retains neither.
    let result = unsafe {
        rusqlite::ffi::sqlite3_status64(
            rusqlite::ffi::SQLITE_STATUS_MEMORY_USED,
            &mut current,
            &mut highwater,
            i32::from(reset_highwater),
        )
    };
    (result == rusqlite::ffi::SQLITE_OK).then_some((current, highwater))
}

#[test]
#[ignore = "manual file-backed attribution ledger space benchmark"]
fn file_attribution_ledger_space_benchmark() {
    let count: u32 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger-benchmark.db");
    if let Ok(page_size) = std::env::var("NETQMON_BENCH_PAGE_SIZE") {
        let page_size: i64 = page_size.parse().unwrap();
        let db = Connection::open(&path).unwrap();
        db.pragma_update(None, "page_size", page_size).unwrap();
        db.execute_batch("VACUUM").unwrap();
        let actual: i64 = db
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        assert_eq!(actual, page_size);
    }
    let mut storage = open_at(&path, NOW).unwrap();
    let page_size: i64 = storage
        .connection()
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let auto_checkpoint: u32 = std::env::var("NETQMON_BENCH_AUTOCHECKPOINT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    storage
        .connection()
        .execute_batch(&format!(
            "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint={auto_checkpoint};"
        ))
        .unwrap();
    let start = Instant::now();
    let cpu_before = process_cpu_ticks();
    let sqlite_before = sqlite_memory_status(true);
    for (index, first) in (0..count).step_by(1000).enumerate() {
        let mut input = batch(1, FlowLifecycle::Ended);
        input.sequence = u64::try_from(index).unwrap() + 1;
        let original = input.flows[0].clone();
        input.flows = (first..first.saturating_add(1000).min(count))
            .map(|i| {
                let mut flow = original.clone();
                flow.remote_ip = i.to_be_bytes().to_vec();
                flow
            })
            .collect();
        storage
            .persist_classified_batch(&input, &[], &[], NOW)
            .unwrap();
    }
    let elapsed_ms = start.elapsed().as_millis();
    let cpu_ticks = cpu_before
        .zip(process_cpu_ticks())
        .and_then(|(a, b)| b.checked_sub(a));
    let wal_bytes = std::fs::metadata(dir.path().join("ledger-benchmark.db-wal"))
        .unwrap()
        .len();
    storage
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let file_bytes = std::fs::metadata(&path).unwrap().len();
    for table in [
        "flow_sessions",
        "flow_rollup_sessions",
        "flow_rollup_contributions",
    ] {
        let rows: i64 = storage
            .connection()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, i64::from(count));
    }
    let mut statement = storage.connection().prepare("SELECT name, SUM(pgsize) FROM dbstat WHERE name LIKE 'flow_rollup_%' OR name LIKE 'sqlite_autoindex_flow_rollup_%' OR name='flow_sessions' GROUP BY name ORDER BY name").unwrap();
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let payload: (i64, i64, i64) = storage.connection().query_row(
        "SELECT COALESCE(SUM(LENGTH(metadata_json)),0), COALESCE(SUM(LENGTH(attribution_json)),0), COALESCE(SUM(LENGTH(session_id)),0) FROM flow_rollup_sessions",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    let sqlite_after = sqlite_memory_status(false);
    let mut destination_times = Vec::new();
    let mut destination_query = storage.connection().prepare("SELECT remote_ip,SUM(upload_bytes),SUM(download_bytes) FROM traffic_scope_minute WHERE scope=1 GROUP BY remote_ip ORDER BY SUM(upload_bytes+download_bytes) DESC,hex(remote_ip) LIMIT 50").unwrap();
    for _ in 0..20 {
        let started = Instant::now();
        let results = destination_query
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(results.len(), 50);
        destination_times.push(started.elapsed().as_micros());
    }
    destination_times.sort_unstable();
    eprintln!(
        "flows={count} page_size={page_size} auto_checkpoint={auto_checkpoint} elapsed_ms={elapsed_ms} cpu_ticks={cpu_ticks:?} wal_bytes={wal_bytes} file_bytes={file_bytes} destination_p50_us={} destination_p95_us={} destination_p99_us={} objects={objects:?} metadata_attribution_session_chars={payload:?} sqlite_before={sqlite_before:?} sqlite_after={sqlite_after:?}",
        destination_times[10], destination_times[18], destination_times[19]
    );

    // Compare the current JSON recovery payloads with an experimental zstd
    // BLOB representation. This benchmark does not alter the production
    // schema or serializer; it measures the space/CPU trade-off before any
    // migration or rollback design is considered.
    let compressed_path = dir.path().join("ledger-compressed-candidate.db");
    let compressed_db = Connection::open(&compressed_path).unwrap();
    compressed_db
        .execute_batch(
            "PRAGMA journal_mode=OFF;
             PRAGMA synchronous=OFF;
             CREATE TABLE candidate (
                 id INTEGER PRIMARY KEY,
                 session_id TEXT NOT NULL UNIQUE,
                 gateway_id TEXT NOT NULL,
                 metadata_json BLOB NOT NULL,
                 attribution_json BLOB NOT NULL,
                 upload_bytes INTEGER NOT NULL,
                 download_bytes INTEGER NOT NULL,
                 packets INTEGER NOT NULL,
                 last_seen_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 ended_at INTEGER
             );
             CREATE INDEX candidate_updated ON candidate(updated_at);
             CREATE INDEX candidate_ended ON candidate(ended_at) WHERE ended_at IS NOT NULL;
             CREATE TABLE compact_candidate (
                 id INTEGER PRIMARY KEY,
                 session_id TEXT NOT NULL UNIQUE,
                 gateway_id TEXT NOT NULL,
                 metadata_json TEXT NOT NULL,
                 attribution_json TEXT NOT NULL,
                 upload_bytes INTEGER NOT NULL,
                 download_bytes INTEGER NOT NULL,
                 packets INTEGER NOT NULL,
                 last_seen_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 ended_at INTEGER
             );
             CREATE INDEX compact_candidate_updated ON compact_candidate(updated_at);
             CREATE INDEX compact_candidate_ended ON compact_candidate(ended_at) WHERE ended_at IS NOT NULL;",
        )
        .unwrap();
    let compression_started = Instant::now();
    let tx = compressed_db.unchecked_transaction().unwrap();
    let mut insert = tx
        .prepare_cached("INSERT INTO candidate VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
        .unwrap();
    let mut compact_insert = tx
        .prepare_cached("INSERT INTO compact_candidate VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
        .unwrap();
    let mut source = storage
        .connection()
        .prepare(
            "SELECT id,session_id,gateway_id,metadata_json,attribution_json,
                    upload_bytes,download_bytes,packets,last_seen_at,updated_at,ended_at
             FROM flow_rollup_sessions ORDER BY id",
        )
        .unwrap();
    let mut plain_payload_bytes = 0_u64;
    let mut compressed_payload_bytes = 0_u64;
    let mut compact_payload_bytes = 0_u64;
    let mut compressed_rows = 0_u64;
    let mut rows = source.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let metadata: String = row.get(3).unwrap();
        let stored_attribution: String = row.get(4).unwrap();
        let attr: FlowAttribution = serde_json::from_str(&stored_attribution).unwrap();
        let attribution = serde_json::to_string(&attr).unwrap();
        let compact_attribution = serde_json::to_string(&(
            &attr.domain,
            &attr.organization_id,
            &attr.application_id,
            &attr.category_id,
            &attr.traffic_role,
            &attr.protocol_id,
            attr.organization_confidence,
            attr.application_confidence,
            attr.protocol_confidence,
            attr.confidence,
            &attr.reason,
            &attr.evidence_json,
        ))
        .unwrap();
        assert_eq!(
            serde_json::from_str::<FlowAttribution>(&compact_attribution).unwrap(),
            attr
        );
        let metadata_zstd = zstd::bulk::compress(metadata.as_bytes(), 1).unwrap();
        let attribution_zstd = zstd::bulk::compress(attribution.as_bytes(), 1).unwrap();
        plain_payload_bytes = plain_payload_bytes
            .saturating_add(u64::try_from(metadata.len() + attribution.len()).unwrap());
        compressed_payload_bytes = compressed_payload_bytes
            .saturating_add(u64::try_from(metadata_zstd.len() + attribution_zstd.len()).unwrap());
        compact_payload_bytes = compact_payload_bytes
            .saturating_add(u64::try_from(metadata.len() + compact_attribution.len()).unwrap());
        let id: i64 = row.get(0).unwrap();
        let session_id: String = row.get(1).unwrap();
        let gateway_id: String = row.get(2).unwrap();
        let counters = [
            row.get::<_, i64>(5).unwrap(),
            row.get::<_, i64>(6).unwrap(),
            row.get::<_, i64>(7).unwrap(),
            row.get::<_, i64>(8).unwrap(),
            row.get::<_, i64>(9).unwrap(),
        ];
        let ended_at: Option<i64> = row.get(10).unwrap();
        insert
            .execute(params![
                id,
                &session_id,
                &gateway_id,
                metadata_zstd,
                attribution_zstd,
                counters[0],
                counters[1],
                counters[2],
                counters[3],
                counters[4],
                ended_at,
            ])
            .unwrap();
        compact_insert
            .execute(params![
                id,
                session_id,
                gateway_id,
                metadata,
                compact_attribution,
                counters[0],
                counters[1],
                counters[2],
                counters[3],
                counters[4],
                ended_at,
            ])
            .unwrap();
        compressed_rows = compressed_rows.saturating_add(1);
    }
    drop(rows);
    drop(source);
    drop(insert);
    drop(compact_insert);
    tx.commit().unwrap();
    let compression_elapsed = compression_started.elapsed();
    assert_eq!(compressed_rows, u64::from(count));

    let compressed_path_string = compressed_path.to_string_lossy();
    storage
        .connection()
        .execute(
            "ATTACH DATABASE ?1 AS compressed_candidate",
            [compressed_path_string.as_ref()],
        )
        .unwrap();
    let mut equivalence = storage
        .connection()
        .prepare(
            "SELECT r.metadata_json,r.attribution_json,c.metadata_json,c.attribution_json,
                    j.attribution_json
             FROM flow_rollup_sessions r
             JOIN compressed_candidate.candidate c USING(id)
             JOIN compressed_candidate.compact_candidate j USING(id)
             ORDER BY r.id",
        )
        .unwrap();
    let decode_started = Instant::now();
    let mut decoded_rows = 0_u64;
    let mut rows = equivalence.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let metadata: String = row.get(0).unwrap();
        let stored_attribution: String = row.get(1).unwrap();
        let attribution: FlowAttribution = serde_json::from_str(&stored_attribution).unwrap();
        let legacy_attribution = serde_json::to_string(&attribution).unwrap();
        let metadata_zstd: Vec<u8> = row.get(2).unwrap();
        let attribution_zstd: Vec<u8> = row.get(3).unwrap();
        let compact_attribution: String = row.get(4).unwrap();
        assert_eq!(
            zstd::bulk::decompress(&metadata_zstd, metadata.len()).unwrap(),
            metadata.as_bytes()
        );
        assert_eq!(
            zstd::bulk::decompress(&attribution_zstd, legacy_attribution.len()).unwrap(),
            legacy_attribution.as_bytes()
        );
        let decoded_compact: FlowAttribution = serde_json::from_str(&compact_attribution).unwrap();
        assert_eq!(decoded_compact, attribution);
        decoded_rows = decoded_rows.saturating_add(1);
    }
    let decode_elapsed = decode_started.elapsed();
    assert_eq!(decoded_rows, u64::from(count));
    let candidate_bytes = std::fs::metadata(&compressed_path).unwrap().len();
    let candidate_objects: Vec<(String, i64)> = compressed_db
        .prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name LIKE 'candidate%' OR name='sqlite_autoindex_candidate_1' GROUP BY name ORDER BY name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let compact_objects: Vec<(String, i64)> = compressed_db
        .prepare("SELECT name,SUM(pgsize) FROM dbstat WHERE name LIKE 'compact_candidate%' OR name='sqlite_autoindex_compact_candidate_1' GROUP BY name ORDER BY name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    eprintln!(
        "recovery_payload_encoding rows={compressed_rows} source_file_bytes={file_bytes} combined_candidates_file_bytes={candidate_bytes} payload_bytes_legacy_object_json={plain_payload_bytes} payload_bytes_tuple_json={compact_payload_bytes} payload_bytes_zstd_level1={compressed_payload_bytes} both_candidates_encode_plus_insert_ms={} decode_roundtrip_ms={} zstd_objects={candidate_objects:?} tuple_json_objects={compact_objects:?}",
        compression_elapsed.as_millis(),
        decode_elapsed.as_millis(),
    );
}

// Run with: cargo test -p netqmon-storage --release file_total_rollup_benchmark -- --ignored --nocapture
#[test]
#[ignore = "manual SQLite file benchmark"]
fn file_total_rollup_benchmark() {
    for scenario in ["repeated", "distinct", "mixed"] {
        if std::env::var("NETQMON_BENCH_SCENARIO").is_ok_and(|v| v != scenario) {
            continue;
        }
        for batched in [false, true] {
            if std::env::var("NETQMON_BENCH_BATCHED").is_ok_and(|v| v != batched.to_string()) {
                continue;
            }
            let dir = tempdir().unwrap();
            let path = dir.path().join("bench.db");
            let mut storage = open_at(&path, NOW).unwrap();
            storage
                .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
                .unwrap();
            storage
                .connection()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0;")
                .unwrap();
            let wal = dir.path().join("bench.db-wal");
            let before_wal = std::fs::metadata(&wal).unwrap().len();
            let before_db = std::fs::metadata(&path).unwrap().len();
            let mut input = batch(1, FlowLifecycle::Active);
            let mut flow = input.flows[0].clone();
            if std::env::var_os("NETQMON_PROFILE_ENDED").is_some() {
                flow.lifecycle = FlowLifecycle::Ended as i32;
            }
            input.flows = (0..4096)
                .map(|i| {
                    let mut f = flow.clone();
                    if scenario == "distinct" || (scenario == "mixed" && i % 2 == 0) {
                        f.remote_ip = (i as u32).to_be_bytes().to_vec();
                    }
                    f
                })
                .collect();
            let attrs: Vec<_> = (0..input.flows.len())
                .map(|i| {
                    if scenario == "mixed" && i % 128 == 0 {
                        service_attribution()
                    } else {
                        FlowAttribution::default()
                    }
                })
                .collect();
            if std::env::var_os("NETQMON_PROFILE_SQL").is_some() {
                BENCH_SQL_PROFILE.with(|profile| *profile.borrow_mut() = Some(HashMap::new()));
            }
            let write_before = process_write_bytes();
            let cpu_before = process_cpu_ticks();
            let start = Instant::now();
            storage
                .persist_classified_batch_with_total_batching(&input, &attrs, &[], NOW, batched)
                .unwrap();
            let elapsed = start.elapsed();
            let cpu_ticks = cpu_before
                .zip(process_cpu_ticks())
                .and_then(|(a, b)| b.checked_sub(a));
            let counts = LAST_TOTAL_ROLLUP_COUNTS.get();
            let wal_bytes = std::fs::metadata(&wal).unwrap().len() - before_wal;
            let db_growth = std::fs::metadata(&path).unwrap().len() - before_db;
            let io_written = write_before
                .zip(process_write_bytes())
                .and_then(|(before, after)| after.checked_sub(before));
            let peak_rss = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find(|line| line.starts_with("VmHWM:"))
                        .map(str::to_owned)
                });
            eprintln!(
                "scenario={scenario} batched={batched} flows={} total_original={} total_upserts={} elapsed_us={} wal_file_growth={} db_file_growth={} cache_bytes={} peak_rss={peak_rss:?} process_write_bytes={io_written:?} cpu_ticks={cpu_ticks:?}",
                input.flows.len(),
                counts.0,
                counts.1,
                elapsed.as_micros(),
                wal_bytes,
                db_growth,
                std::mem::size_of::<TotalRollupBatch>()
            );
            BENCH_SQL_PROFILE.with(|profile| {
                if let Some(entries) = profile.borrow_mut().take() {
                    let mut entries: Vec<_> = entries.into_iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    for (name, entry) in entries {
                        eprintln!("sql_profile scenario={scenario} batched={batched} path={name} calls={} elapsed_us={} unique_keys={}", entry.calls, entry.nanos / 1_000, entry.keys.len());
                    }
                }
            });
            assert_eq!(counts.0, 4096);
            assert_eq!(
                metrics(storage.connection(), "traffic_total_minute", "1=1").3,
                4096
            );
        }
    }
}

#[test]
#[ignore = "manual file-backed multi-batch ingestion latency benchmark"]
fn file_dimension_batch_latency_benchmark() {
    for scenario in ["repeated", "distinct", "mixed", "pairs"] {
        if std::env::var("NETQMON_BENCH_SCENARIO").is_ok_and(|value| value != scenario) {
            continue;
        }
        for batch_size in [16_usize, 128, 512] {
            if std::env::var("NETQMON_BENCH_BATCH_SIZE")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|value| value != batch_size)
            {
                continue;
            }
            let directory = tempdir().unwrap();
            let path = directory.path().join("dimensions.db");
            let mut storage = open_at(&path, NOW).unwrap();
            storage
                .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
                .unwrap();
            storage
                .connection()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0")
                .unwrap();
            let mut latencies = Vec::new();
            for sequence in 1..=40_u64 {
                let mut input = batch(sequence, FlowLifecycle::Active);
                input.sent_at = NOW + 1_000;
                let template = input.flows[0].clone();
                input.flows = (0..batch_size)
                    .map(|index| {
                        let mut flow = template.clone();
                        let remote = match scenario {
                            "repeated" => 1,
                            "distinct" => index,
                            "pairs" => index / 2,
                            _ => index / 8,
                        };
                        flow.remote_ip = u32::try_from(remote).unwrap().to_be_bytes().to_vec();
                        flow
                    })
                    .collect();
                let start = Instant::now();
                storage
                    .persist_classified_batch_with_total_batching(
                        &input,
                        &[],
                        &[],
                        NOW + sequence,
                        true,
                    )
                    .unwrap();
                latencies.push(start.elapsed().as_micros());
            }
            latencies.sort_unstable();
            let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
                .unwrap()
                .len();
            eprintln!(
                "scenario={scenario} batch_size={batch_size} samples=40 p50_us={} p95_us={} p99_us={} wal_bytes={wal_bytes}",
                latencies[19], latencies[37], latencies[39]
            );
        }
    }
}

#[test]
#[ignore = "manual historical rollup benchmark"]
fn historical_rollup_benchmark() {
    let mut storage = setup();
    storage.connection().execute(
        "WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99999)
         INSERT INTO traffic_total_minute(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count)
         SELECT ?1+i*60000,'gateway-1',1,1,1,1 FROM n", [to_i64(NOW)]
    ).unwrap();
    let later = NOW + 100_000 * 60_000 + 2 * DAY_MS as u64;
    storage.roll_up_hour_and_day(later).unwrap();
    let start = Instant::now();
    for _ in 0..100 {
        storage.roll_up_hour_and_day(later).unwrap();
    }
    eprintln!(
        "historical_minutes=100000 idle_maintenance_100={:?}",
        start.elapsed()
    );
    assert_eq!(
        metrics(storage.connection(), "traffic_total_day", "1=1"),
        (100000, 100000, 100000, 100000)
    );
}

// Run with: cargo test -p netqmon-storage --release hot_paths_with_large_active_cache -- --ignored --nocapture
#[test]
#[ignore = "manual file-backed active cache drain memory benchmark"]
fn file_active_cache_drain_memory_benchmark() {
    let count: u32 = std::env::var("NETQMON_BENCH_ACTIVE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let directory = tempdir().unwrap();
    let mut storage = open_at(&directory.path().join("active-drain.db"), NOW).unwrap();
    let input = batch(1, FlowLifecycle::Active);
    for index in 0..count {
        let mut flow = input.flows[0].clone();
        flow.remote_ip = index.to_be_bytes().to_vec();
        let key = FlowKey::from_batch("gateway-1", &flow);
        let current = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW));
        storage.active_flows.insert(key, current);
    }
    let memory = || {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let before = memory();
    let before_capacity = storage.active_flows.flows.capacity();
    let start = Instant::now();
    let mut last_us = 0;
    while let Some((_, key)) = storage.active_flows.expiry.first().cloned() {
        let final_entry = storage.active_flows.len() == 1;
        let iteration = Instant::now();
        storage.active_flows.remove(&key);
        if final_entry {
            last_us = iteration.elapsed().as_micros();
        }
    }
    let release_started = Instant::now();
    storage.active_flows.release_large_empty_allocation();
    let release_us = release_started.elapsed().as_micros();
    let elapsed_ms = start.elapsed().as_millis();
    // The bounded worker frees asynchronously; let it finish before sampling RSS.
    std::thread::sleep(Duration::from_millis(250));
    assert!(storage.active_flows.is_empty());
    eprintln!(
        "active_drain={count} before_capacity={before_capacity} after_capacity={} total_ms={elapsed_ms} last_remove_us={last_us} maintenance_release_us={release_us} before={before:?} after={:?}",
        storage.active_flows.flows.capacity(),
        memory()
    );
}

#[test]
#[ignore = "manual file-backed active cache benchmark"]
fn file_active_cache_benchmark() {
    let count: u32 = std::env::var("NETQMON_BENCH_ACTIVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let mut storage = open_at(&dir.path().join("active.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let input = batch(1, FlowLifecycle::Active);
    storage
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    for index in 0..count {
        let mut flow = input.flows[0].clone();
        flow.remote_ip = index.to_be_bytes().to_vec();
        let key = FlowKey::from_batch("gateway-1", &flow);
        let current = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW));
        storage.active_flows.insert(key, current);
    }
    let mut ingest = Vec::new();
    for sequence in 2..202 {
        let start = Instant::now();
        storage
            .persist_classified_batch(
                &batch(sequence, FlowLifecycle::Active),
                &[transport_attribution()],
                &[],
                NOW + sequence,
            )
            .unwrap();
        ingest.push(start.elapsed().as_micros());
    }
    let mut maintenance = Vec::new();
    for _ in 0..30 {
        let start = Instant::now();
        storage
            .prune_reclassification_bounded(NOW + 1000, 500, Duration::from_secs(2))
            .unwrap();
        maintenance.push(start.elapsed().as_micros());
    }
    ingest.sort_unstable();
    maintenance.sort_unstable();
    eprintln!(
        "active={count} ingest_us_p50={} p95={} p99={} idle_gc_us_p50={} p95={} p99={}",
        ingest[100], ingest[190], ingest[198], maintenance[15], maintenance[28], maintenance[29]
    );
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(line) = status.lines().find(|line| line.starts_with("VmHWM:")) {
            eprintln!("{line}");
        }
    }
}

#[test]
#[ignore = "manual file-backed contribution marker index comparison"]
fn file_rollup_marker_timestamp_index_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    assert!(rows > 0);
    let directory = tempdir().unwrap();
    let day_base = to_i64(NOW) / DAY_MS * DAY_MS;
    let now = day_base + 5 * DAY_MS + 2 * HOUR_MS + 5 * MINUTE_MS;
    let hour_cutoff = now / HOUR_MS * HOUR_MS;
    let day_cutoff = now / DAY_MS * DAY_MS;
    let old_timestamp = day_cutoff - DAY_MS;
    let recent_timestamp = hour_cutoff + 15 * MINUTE_MS;
    let marker_sql = format!(
        "BEGIN IMMEDIATE;
         UPDATE flow_rollup_contributions SET hour_upload=upload_bytes,hour_download=download_bytes,
           hour_packets=packets,hour_flows=flow_count WHERE timestamp<{hour_cutoff}
           AND (hour_upload!=upload_bytes OR hour_download!=download_bytes OR hour_packets!=packets OR hour_flows!=flow_count);
         UPDATE flow_rollup_contributions SET day_upload=hour_upload,day_download=hour_download,
           day_packets=hour_packets,day_flows=hour_flows WHERE timestamp<{day_cutoff}
           AND (day_upload!=hour_upload OR day_download!=hour_download OR day_packets!=hour_packets OR day_flows!=hour_flows);
         ROLLBACK;"
    );

    for old_percent in [0_i64, 100] {
        for timestamp_index in [false, true] {
            let variant = if timestamp_index {
                "timestamp_index"
            } else {
                "no_timestamp_index"
            };
            let path = directory
                .path()
                .join(format!("markers-{old_percent}-{variant}.db"));
            let mut storage = open_at(&path, NOW).unwrap();
            storage
                .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
                .unwrap();
            let db = storage.connection();
            db.execute(
                "INSERT INTO flow_rollup_sessions
                 (session_id,gateway_id,metadata_json,attribution_json,upload_bytes,download_bytes,
                  packets,last_seen_at,updated_at,ended_at)
                 SELECT printf('marker-%d',i),'gateway-1','{}','{}',1,0,1,?2,?2,NULL
                 FROM (WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
                       SELECT i FROM n)",
                params![rows, to_i64(NOW)],
            )
            .unwrap();
            if timestamp_index {
                db.execute_batch(
                    "CREATE INDEX flow_rollup_contributions_timestamp_candidate
                     ON flow_rollup_contributions(timestamp)",
                )
                .unwrap();
            }
            let insert_started = Instant::now();
            db.execute(
                "INSERT INTO flow_rollup_contributions
                 (session_ref,timestamp,scope,direction,device_id,remote_ip,protocol,
                  application_id,category_id,domain,protocol_id,upload_bytes,download_bytes,
                  packets,flow_count,hour_upload,hour_download,hour_packets,hour_flows,
                  day_upload,day_download,day_packets,day_flows,expires_at)
                 SELECT i,CASE WHEN ?3>0 AND i%100<?3 THEN ?4 ELSE ?5 END,1,1,i%5000,
                  CAST(printf('%08x',i) AS BLOB),6,'app','cat','example','tcp',1,0,1,1,
                  0,0,0,0,0,0,0,0,?6
                 FROM (WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
                       SELECT i FROM n)",
                params![
                    rows,
                    to_i64(NOW),
                    old_percent,
                    old_timestamp,
                    recent_timestamp,
                    to_i64(NOW + u64::try_from(crate::attribution::CORRECTION_WINDOW_MS).unwrap(),),
                ],
            )
            .unwrap();
            let insert_us = insert_started.elapsed().as_micros();
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
            let file_bytes = std::fs::metadata(&path).unwrap().len();
            let index_bytes: i64 = db
                .query_row(
                    "SELECT COALESCE(SUM(pgsize),0) FROM dbstat
                     WHERE name='flow_rollup_contributions_timestamp_candidate'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let mut plan = db
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    marker_sql.split(';').nth(1).unwrap()
                ))
                .unwrap();
            let plan = plan
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut marker_samples = Vec::new();
            for _ in 0..10 {
                let started = Instant::now();
                db.execute_batch(&marker_sql).unwrap();
                marker_samples.push(started.elapsed().as_micros());
            }
            marker_samples.sort_unstable();
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM flow_rollup_contributions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                rows
            );
            eprintln!(
                "rollup_marker rows={rows} old_percent={old_percent} variant={variant} insert_us={insert_us} db_bytes={file_bytes} candidate_index_bytes={index_bytes} marker_p50_p95_p99_max_us=({},{},{},{}) plan={plan:?}",
                marker_samples[4], marker_samples[8], marker_samples[8], marker_samples[9]
            );
        }
    }
}

#[test]
#[ignore = "manual file-backed concurrent expiry benchmark"]
fn file_active_cache_concurrent_benchmark() {
    use std::sync::{Arc, Barrier, Mutex};
    let count: u32 = std::env::var("NETQMON_BENCH_ACTIVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);
    let dir = tempdir().unwrap();
    let mut sqlite = open_at(&dir.path().join("concurrent-active.db"), NOW).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let input = batch(1, FlowLifecycle::Active);
    sqlite
        .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
        .unwrap();
    // Seed cache-only entries to stress eviction; ordinary writes trim them
    // to the production cap while the concurrent expiry worker is running.
    for index in 0..count {
        let mut flow = input.flows[0].clone();
        flow.remote_ip = index.to_be_bytes().to_vec();
        let key = FlowKey::from_batch("gateway-1", &flow);
        let current = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW));
        sqlite.active_flows.insert(key, current);
    }
    assert_eq!(
        sqlite.active_flows.len(),
        usize::try_from(count).unwrap() + 1
    );
    let storage = Arc::new(Mutex::new(Storage::sqlite(sqlite)));
    let gate = Arc::new(Barrier::new(2));
    let worker_storage = Arc::clone(&storage);
    let worker_gate = Arc::clone(&gate);
    let expired = NOW + ACTIVE_FLOW_TTL_MS as u64;
    let worker = std::thread::spawn(move || {
        worker_gate.wait();
        let started = Instant::now();
        let mut slices = 0;
        loop {
            let done = worker_storage
                .lock()
                .unwrap()
                .prune_owned_flow_cache(expired, RetentionBudget::default())
                .unwrap();
            slices += 1;
            if done {
                break;
            }
            assert!(slices < 10_000, "expiry failed to make progress");
            std::thread::sleep(Duration::from_millis(1));
        }
        (slices, started.elapsed())
    });
    gate.wait();
    let mut writes = Vec::new();
    for sequence in 2..202 {
        let start = Instant::now();
        storage
            .lock()
            .unwrap()
            .persist_classified_batch(
                &batch(sequence, FlowLifecycle::Active),
                &[transport_attribution()],
                &[],
                expired + sequence,
            )
            .unwrap();
        writes.push(start.elapsed().as_micros());
    }
    let (slices, elapsed) = worker.join().unwrap();
    writes.sort_unstable();
    {
        let storage = storage.lock().unwrap();
        match &*storage {
            Storage::Sqlite(storage) => assert_eq!(storage.active_flows.len(), 1),
            Storage::ClickHouse(_) => unreachable!("benchmark uses SQLite"),
        }
    }
    eprintln!(
        "active={count} slices={slices} expiry_ms={} concurrent_ingest_us_p50={} p95={} p99={} max={}",
        elapsed.as_millis(),
        writes[100],
        writes[190],
        writes[198],
        writes[199]
    );
    let storage = storage.lock().unwrap();
    assert_eq!(
        metrics(storage.connection(), "traffic_total_minute", "1=1"),
        (20_100, 10_050, 603, 201)
    );
}

#[test]
#[ignore = "manual domain summary SQL comparison"]
fn file_domain_count_query_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let mut storage = open_at(&dir.path().join("domains.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let connection = storage.connection();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_domain_minute(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) SELECT ?2+i,'gateway-1',printf('domain-%05d.example',i%10000),i%1000,i%300,1,1 FROM n", params![rows, to_i64(NOW)]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let old_count = "SELECT COUNT(*) FROM (SELECT 1 FROM traffic_domain_minute GROUP BY domain)";
    let old_page = "SELECT domain,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count),MAX(timestamp) FROM traffic_domain_minute GROUP BY domain ORDER BY SUM(upload_bytes+download_bytes) DESC,domain LIMIT 50 OFFSET 0";
    let new_page = "SELECT domain,SUM(upload_bytes),SUM(download_bytes),SUM(packets),SUM(flow_count),MAX(timestamp),COUNT(*) OVER () FROM traffic_domain_minute GROUP BY domain ORDER BY SUM(upload_bytes+download_bytes) DESC,domain LIMIT 50 OFFSET 0";
    let mut before = Vec::new();
    let mut after = Vec::new();
    for _ in 0..10 {
        let started = Instant::now();
        let count: i64 = connection.query_row(old_count, [], |r| r.get(0)).unwrap();
        let mut statement = connection.prepare(old_page).unwrap();
        let old = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        before.push(started.elapsed().as_micros());
        let started = Instant::now();
        let mut statement = connection.prepare(new_page).unwrap();
        let new = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        after.push(started.elapsed().as_micros());
        assert_eq!(
            old,
            new.iter()
                .map(|(name, up, down, _)| (name.clone(), *up, *down))
                .collect::<Vec<_>>()
        );
        assert!(new.iter().all(|row| row.3 == count));
    }
    before.sort_unstable();
    after.sort_unstable();
    eprintln!(
        "domain_rows={rows} old_p50={} old_p95={} old_p99={} window_p50={} window_p95={} window_p99={}",
        before[5], before[9], before[9], after[5], after[9], after[9]
    );
    for sql in [old_count, old_page, new_page] {
        let mut plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        for step in plan.query_map([], |r| r.get::<_, String>(3)).unwrap() {
            eprintln!("plan: {}", step.unwrap());
        }
    }
}

#[test]
#[ignore = "manual file-backed organization index comparison"]
fn file_organization_index_comparison() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path().join("org-index.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let db = storage.connection();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) SELECT i,'gateway-1',CAST(printf('%012x',i) AS BLOB),?1,?1 FROM n", [to_i64(NOW)]).unwrap();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) SELECT printf('flow-%d',i),'gateway-1',CASE WHEN i%7=0 THEN NULL ELSE i%999+1 END,4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,'tcp',CASE WHEN i%10=0 THEN NULL ELSE printf('org-%d',i%500) END,i%1000,i%500,1,?2,?2+i,?2 FROM n", params![rows,to_i64(NOW)]).unwrap();
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    let index_bytes: i64 = db
        .query_row(
            "SELECT SUM(pgsize) FROM dbstat WHERE name='flow_sessions_organization_last_seen'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let queries = [
        (
            "count",
            "SELECT COUNT(DISTINCT COALESCE(organization_id,'unknown')) FROM flow_sessions",
        ),
        (
            "count_ordered",
            "SELECT COUNT(*)-(EXISTS(SELECT 1 FROM flow_sessions WHERE organization_id IS NULL) AND EXISTS(SELECT 1 FROM flow_sessions WHERE organization_id='unknown')) FROM (SELECT organization_id FROM flow_sessions GROUP BY organization_id)",
        ),
        (
            "page",
            "SELECT COALESCE(organization_id,'unknown'),SUM(upload_bytes),SUM(download_bytes),COUNT(*),MAX(last_seen_at),COUNT(DISTINCT device_id),COUNT(*) OVER () FROM flow_sessions GROUP BY COALESCE(organization_id,'unknown') ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50",
        ),
        (
            "flows_filter",
            "SELECT id FROM flow_sessions f WHERE LOWER(COALESCE(f.organization_id,'unknown'))='org-17' AND f.last_seen_at>=0 ORDER BY f.last_seen_at DESC,f.id ASC LIMIT 51",
        ),
    ];
    let mut expected: Vec<Vec<Vec<Value>>> = Vec::new();
    for index_present in [true, false] {
        if !index_present {
            db.execute_batch("DROP INDEX flow_sessions_organization_last_seen")
                .unwrap();
        }
        for (number, (name, sql)) in queries.iter().enumerate() {
            let mut stmt = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let plan = stmt
                .query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut samples = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                let mut stmt = db.prepare(sql).unwrap();
                let columns = stmt.column_count();
                let result = stmt
                    .query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get::<_, Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                samples.push(start.elapsed().as_micros());
                if *name == "count_ordered" {
                    assert_eq!(expected[0], result);
                }
                if index_present {
                    if expected.len() <= number {
                        expected.push(result);
                    } else {
                        assert_eq!(expected[number], result);
                    }
                } else {
                    assert_eq!(expected[number], result);
                }
            }
            samples.sort_unstable();
            eprintln!(
                "org_index_rows={rows} index={index_present} query={name} p50_us={} max_us={} plan={plan:?}",
                samples[2], samples[4]
            );
        }
        let mut times = Vec::new();
        for _ in 0..5 {
            db.execute_batch("SAVEPOINT org_update").unwrap();
            let start = Instant::now();
            let changed = db.execute("UPDATE flow_sessions SET organization_id='changed' WHERE last_seen_at>=?1 AND last_seen_at<?2", params![to_i64(NOW)+1,to_i64(NOW)+1001]).unwrap();
            times.push(start.elapsed().as_micros());
            assert_eq!(changed, 1000);
            db.execute_batch("ROLLBACK TO org_update; RELEASE org_update")
                .unwrap();
        }
        times.sort_unstable();
        eprintln!(
            "org_index_rows={rows} index={index_present} update1000_p50_us={} max_us={} index_bytes={index_bytes}",
            times[2], times[4]
        );
    }
}

#[test]
#[ignore = "manual file-backed protocol empty-page count benchmark"]
fn file_protocol_empty_count_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let sample_count: usize = std::env::var("NETQMON_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| (2..=10_000).contains(value))
        .unwrap_or(100);
    let insert_chunk: i64 = std::env::var("NETQMON_BENCH_INSERT_CHUNK")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(rows);
    assert!(rows > 0);
    let dir = tempdir().unwrap();
    let path = dir.path().join("protocol-count.db");
    let mut storage = open_at(&path, NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let db = storage.connection();
    let mut first = 1_i64;
    while first <= rows {
        let last = first.saturating_add(insert_chunk - 1).min(rows);
        db.execute("WITH RECURSIVE n(i) AS (VALUES(?1) UNION ALL SELECT i+1 FROM n WHERE i<?2) INSERT INTO flow_sessions(id,gateway_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,protocol_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) SELECT printf('flow-%d',i),'gateway-1',4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,CASE i%20 WHEN 0 THEN NULL WHEN 1 THEN 'unknown' ELSE printf('protocol-%d',i%20) END,i%1000,i%500,1,?3,?3+i,?3 FROM n", params![first,last,to_i64(NOW)]).unwrap();
        if insert_chunk < rows {
            let busy: i64 = db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                .unwrap();
            assert_eq!(busy, 0, "fixture WAL checkpoint was blocked");
            eprintln!("protocol_fixture_inserted={last}/{rows}");
        }
        if last == rows {
            break;
        }
        first = last.saturating_add(1);
    }
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    eprintln!(
        "protocol_fixture_rows={rows} file_bytes={}",
        std::fs::metadata(&path).unwrap().len()
    );
    let queries = [
        "SELECT COUNT(DISTINCT COALESCE(protocol_id,'unknown')) FROM flow_sessions",
        "SELECT COUNT(*)-(EXISTS(SELECT 1 FROM flow_sessions WHERE protocol_id IS NULL) AND EXISTS(SELECT 1 FROM flow_sessions WHERE protocol_id='unknown')) FROM (SELECT protocol_id FROM flow_sessions GROUP BY protocol_id)",
    ];
    for (name, sql) in ["before", "after"].into_iter().zip(queries) {
        let mut stmt = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan = stmt
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        eprintln!("protocol_count_rows={rows} {name} plan={plan:?}");
    }
    let mut samples = [Vec::new(), Vec::new()];
    for iteration in 0..sample_count {
        let mut counts = [0_i64; 2];
        for pass in 0..2 {
            let index = (iteration + pass) % 2;
            let started = Instant::now();
            counts[index] = db.query_row(queries[index], [], |row| row.get(0)).unwrap();
            samples[index].push(started.elapsed().as_micros());
        }
        assert_eq!(counts, [19, 19]);
    }
    for (name, samples) in ["before", "after"].into_iter().zip(&mut samples) {
        samples.sort_unstable();
        eprintln!(
            "protocol_count_rows={rows} samples={sample_count} {name} p50_us={} p95_us={} p99_us={}",
            samples[(sample_count * 50).div_ceil(100) - 1],
            samples[(sample_count * 95).div_ceil(100) - 1],
            samples[(sample_count * 99).div_ceil(100) - 1]
        );
    }
}

#[test]
#[ignore = "manual organization and protocol summary SQL comparison"]
fn file_flow_group_count_query_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let dir = tempdir().unwrap();
    let mut storage = open_at(&dir.path().join("flow-groups.db"), NOW).unwrap();
    storage
        .save_gateway("gateway-1", "router", "test", &[7; 32], NOW)
        .unwrap();
    let connection = storage.connection();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) SELECT i,'gateway-1',CAST(printf('%012x',i) AS BLOB),?1,?1 FROM n",[to_i64(NOW)]).unwrap();
    connection.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) SELECT printf('flow-%d',i),'gateway-1',CASE WHEN i%7=0 THEN NULL ELSE i%1000+1 END,4,6,CAST(printf('%08x',i%1000) AS BLOB),i%60000,CAST(printf('%08x',i%50000) AS BLOB),443,1,CASE WHEN i%10=0 THEN NULL ELSE printf('protocol-%d',i%20) END,CASE WHEN i%10=0 THEN NULL ELSE printf('org-%d',i%500) END,i%1000,i%500,1,?2,?2,?2 FROM n", params![rows,to_i64(NOW)]).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    for column in ["organization_id", "protocol_id"] {
        let group = format!("COALESCE({column}, 'unknown')");
        let clients = if column == "organization_id" {
            ",COUNT(DISTINCT device_id)"
        } else {
            ""
        };
        let count_index = if column == "organization_id" { 6 } else { 5 };
        let old_count = format!("SELECT COUNT(DISTINCT {group}) FROM flow_sessions");
        let page = format!(
            "SELECT {group},SUM(upload_bytes),SUM(download_bytes),COUNT(*),MAX(last_seen_at){clients} FROM flow_sessions GROUP BY {group} ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50"
        );
        let new_page = format!(
            "SELECT {group},SUM(upload_bytes),SUM(download_bytes),COUNT(*),MAX(last_seen_at){clients},COUNT(*) OVER () FROM flow_sessions GROUP BY {group} ORDER BY SUM(upload_bytes+download_bytes) DESC LIMIT 50"
        );
        let mut before = Vec::new();
        let mut after = Vec::new();
        for _ in 0..10 {
            let start = Instant::now();
            let count: i64 = connection.query_row(&old_count, [], |r| r.get(0)).unwrap();
            let mut statement = connection.prepare(&page).unwrap();
            let old = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        if count_index == 6 {
                            r.get::<_, i64>(5)?
                        } else {
                            0
                        },
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            before.push(start.elapsed().as_micros());
            let start = Instant::now();
            let mut statement = connection.prepare(&new_page).unwrap();
            let new = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        if count_index == 6 {
                            r.get::<_, i64>(5)?
                        } else {
                            0
                        },
                        r.get::<_, i64>(count_index)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            after.push(start.elapsed().as_micros());
            assert_eq!(
                old,
                new.iter()
                    .map(|(id, up, down, flows, last, clients, _)| (
                        id.clone(),
                        *up,
                        *down,
                        *flows,
                        *last,
                        *clients
                    ))
                    .collect::<Vec<_>>()
            );
            assert!(new.iter().all(|row| row.6 == count));
        }
        before.sort_unstable();
        after.sort_unstable();
        eprintln!(
            "group={column} rows={rows} old_p50={} old_p95={} old_p99={} window_p50={} window_p95={} window_p99={}",
            before[5], before[9], before[9], after[5], after[9], after[9]
        );
        for sql in [&old_count, &page, &new_page] {
            let mut plan = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            for step in plan.query_map([], |r| r.get::<_, String>(3)).unwrap() {
                eprintln!("plan: {}", step.unwrap());
            }
        }
    }
}

#[test]
#[ignore = "manual hot-path scaling benchmark"]
fn hot_paths_with_large_active_cache() {
    for size in [100_u32, 10_000, 30_000] {
        let mut storage = setup();
        let input = batch(1, FlowLifecycle::Active);
        storage
            .persist_classified_batch(&input, &[transport_attribution()], &[], NOW)
            .unwrap();
        for index in 0..size {
            let mut flow = input.flows[0].clone();
            flow.remote_ip = index.to_be_bytes().to_vec();
            let key = FlowKey::from_batch("gateway-1", &flow);
            let current = ActiveFlow::new(&key, &flow, transport_attribution(), to_i64(NOW));
            storage.active_flows.insert(key, current);
        }
        let mut unified = Storage::sqlite(storage);
        let start = Instant::now();
        for index in 0..100 {
            unified
                .reclassify_flow_at(
                    "gateway-1",
                    &input.flows[0],
                    &service_attribution(),
                    NOW + index,
                )
                .unwrap();
        }
        let dpi = start.elapsed();
        let Storage::Sqlite(mut storage) = unified else {
            unreachable!()
        };
        let start = Instant::now();
        for sequence in 2..102 {
            storage
                .persist_classified_batch(
                    &batch(sequence, FlowLifecycle::Active),
                    &[transport_attribution()],
                    &[],
                    NOW + sequence,
                )
                .unwrap();
        }
        eprintln!(
            "active_cache={size} dpi_100={dpi:?} ingest_100={:?}",
            start.elapsed()
        );
        assert_eq!(
            metrics(storage.connection(), "traffic_total_minute", "1=1"),
            (10100, 5050, 303, 101)
        );
    }
}
