use super::*;

#[derive(Default)]
struct ConcurrentGeo {
    current: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

impl GeoProvider for ConcurrentGeo {
    fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        use std::sync::atomic::Ordering;
        let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(current, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        let result = DistinctAsnGeo.lookup(ip);
        self.current.fetch_sub(1, Ordering::SeqCst);
        result
    }
    fn is_enabled(&self) -> bool {
        true
    }
}

#[test]
fn file_geo_parallel_requests_are_bounded_and_preserve_writes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("parallel-geo.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES(1000,'benchmark',1,1,1,'app','cat','example',X'00000001',6,'tcp',1,0,1,1)", []).unwrap();
    let geo = Arc::new(ConcurrentGeo::default());
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        geo.clone(),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let router = internal_router(state);
    let gate = Arc::new(std::sync::Barrier::new(18));
    let writer_gate = gate.clone();
    let writer_path = path.clone();
    let writer_geo = geo.clone();
    let writer = std::thread::spawn(move || {
        let db = rusqlite::Connection::open(writer_path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        writer_gate.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while writer_geo.current.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "Geo query did not start"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = std::time::Instant::now();
        db.execute(
            "UPDATE traffic_scope_minute SET upload_bytes=upload_bytes+1",
            [],
        )
        .unwrap();
        started.elapsed().as_micros()
    });
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let router = router.clone();
        let gate = gate.clone();
        tasks.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            gate.wait();
            let started = std::time::Instant::now();
            runtime.block_on(async move {
                let response = router
                    .oneshot(
                        Request::builder()
                            .uri("/internal/geo")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = parse_json(response).await;
                assert_eq!(body["data"]["top_asns"].as_array().unwrap().len(), 1);
                assert!((1..=2).contains(&body["data"]["top_asns"][0]["bytes"].as_u64().unwrap()));
            });
            started.elapsed().as_micros()
        }));
    }
    gate.wait();
    let mut timings = Vec::new();
    for task in tasks {
        timings.push(task.join().unwrap());
    }
    let write_us = writer.join().unwrap();
    let persisted: i64 = rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT upload_bytes FROM traffic_scope_minute", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(persisted, 2);
    timings.sort_unstable();
    let peak = geo.peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(peak <= 4, "unexpected Geo concurrency: {peak}");
    eprintln!(
        "geo_parallel_requests=16 peak={peak} writer_us={write_us} p50_us={} p95_us={} p99_us={}",
        timings[8], timings[15], timings[15]
    );
}

#[derive(Debug)]
pub(super) struct DistinctAsnGeo;

struct PausedGeoSnapshot {
    started: std::sync::mpsc::Sender<()>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
    paused: std::sync::atomic::AtomicBool,
}

impl GeoProvider for PausedGeoSnapshot {
    fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        if !self.paused.swap(true, std::sync::atomic::Ordering::Relaxed) {
            self.started.send(()).unwrap();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        }
        DistinctAsnGeo.lookup(ip)
    }
    fn is_enabled(&self) -> bool {
        true
    }
}

#[test]
fn file_geo_overflow_retry_preserves_concurrent_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geo-retry.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES (1000,'benchmark',1,1,1,'app','cat','example',X'00000001',6,'tcp',1,0,1,1),(1000,'benchmark',1,1,1,'app','cat','example',X'00000002',6,'tcp',?1,0,1,1),(61000,'benchmark',1,1,1,'app','cat','example',X'00000002',6,'tcp',1,0,1,1)", [i64::MAX]).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(PausedGeoSnapshot {
            started: started_tx,
            resume: Mutex::new(resume_rx),
            paused: std::sync::atomic::AtomicBool::new(false),
        }),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let response = internal_router(state)
                    .oneshot(
                        Request::builder()
                            .uri("/internal/geo")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                parse_json(response).await
            })
    });
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let writer = rusqlite::Connection::open(&path).unwrap();
    writer.execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES (121000,'benchmark',1,1,1,'app','cat','example',X'00000003',6,'tcp',100,0,1,1)", []).unwrap();
    resume_tx.send(()).unwrap();
    let value = worker.join().unwrap();
    assert_eq!(value["data"]["top_asns"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["data"]["top_asns"][0]["bytes"].as_u64(),
        Some(u64::try_from(i64::MAX).unwrap() + 1)
    );
}

#[tokio::test]
async fn file_geo_preserves_totals_above_signed_integer_range() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("geo-large.db")).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES(1000,'benchmark',1,1,1,'app','cat','example',X'00000001',6,'tcp',?1,?1,1,1)", [i64::MAX]).unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES(61000,'benchmark',1,1,1,'app','cat','example',X'00000001',6,'tcp',1,0,1,1)", []).unwrap();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = parse_json(response).await;
    assert_eq!(
        value["data"]["top_countries"][0]["bytes"].as_u64(),
        Some(u64::MAX)
    );
}

impl GeoProvider for DistinctAsnGeo {
    fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        let std::net::IpAddr::V4(ip) = ip else {
            return Ok(None);
        };
        Ok(Some(netqmon_geo::GeoRecord {
            country_code: Some("US".to_owned()),
            country_name: Some("United States".to_owned()),
            asn: Some(u32::from(ip)),
            organization: Some("Test network".to_owned()),
            ..Default::default()
        }))
    }
    fn is_enabled(&self) -> bool {
        true
    }
}

struct SignalingGeo {
    started: std::sync::mpsc::Sender<()>,
    signaled: std::sync::atomic::AtomicBool,
}

impl GeoProvider for SignalingGeo {
    fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        if !self
            .signaled
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let _ = self.started.send(());
        }
        DistinctAsnGeo.lookup(ip)
    }
    fn is_enabled(&self) -> bool {
        true
    }
}

#[test]
#[ignore = "manual concurrent file-backed geo and write benchmark"]
fn file_geo_concurrent_write_benchmark() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geo-concurrent.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1_700_000_000_000)
        .unwrap();
    sqlite.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT 1700000000000,'benchmark',1,1,1,'app','cat','example',unhex(printf('%08x',i)),6,'tcp',i%1000,1,1,1 FROM n", []).unwrap();
    let rowid: i64 = sqlite
        .connection()
        .query_row(
            "SELECT rowid FROM traffic_scope_minute LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(SignalingGeo {
            started: sender,
            signaled: std::sync::atomic::AtomicBool::new(false),
        }),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let reader = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                internal_router(state)
                    .oneshot(
                        Request::builder()
                            .uri("/internal/geo")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            });
        assert_eq!(response.status(), StatusCode::OK);
        start.elapsed().as_micros()
    });
    receiver.recv_timeout(Duration::from_secs(60)).unwrap();
    let writer = rusqlite::Connection::open(path).unwrap();
    writer.busy_timeout(Duration::from_secs(10)).unwrap();
    let mut writes = Vec::new();
    for _ in 0..500 {
        let start = std::time::Instant::now();
        writer
            .execute(
                "UPDATE traffic_scope_minute SET upload_bytes=upload_bytes+1 WHERE rowid=?1",
                [rowid],
            )
            .unwrap();
        writes.push(start.elapsed().as_micros());
    }
    writes.sort_unstable();
    eprintln!(
        "geo_us={} write_p50_us={} write_p95_us={} write_p99_us={} write_max_us={}",
        reader.join().unwrap(),
        writes[249],
        writes[474],
        writes[494],
        writes[499]
    );
}

#[tokio::test]
async fn file_geo_summary_spills_and_preserves_top_results() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geo-spill.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1_700_000_000_000)
        .unwrap();
    sqlite.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<5000) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT 1700000000000,'benchmark',1,1,1,'app','cat','example',unhex(printf('%08x',i)),6,'tcp',i%1000,1,1,1 FROM n", []).unwrap();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let response = internal_router(state)
        .oneshot(
            Request::builder()
                .uri("/internal/geo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = parse_json(response).await;
    assert_eq!(result["data"]["top_countries"][0]["bytes"], 2_502_500);
    for (index, asn) in [999, 1999, 2999, 3999, 4999].iter().enumerate() {
        assert_eq!(result["data"]["top_asns"][index]["asn"], *asn);
        assert_eq!(result["data"]["top_asns"][index]["bytes"], 1000);
    }
}

#[tokio::test]
#[ignore = "manual file-backed high-cardinality geo benchmark"]
async fn file_geo_cardinality_benchmark() {
    let rows: i64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geo-cardinality.db");
    let mut sqlite = SqliteStorage::open(&path).unwrap();
    sqlite
        .save_gateway("benchmark", "router", "test", &[7; 32], 1_700_000_000_000)
        .unwrap();
    sqlite.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT 1700000000000,'benchmark',1,1,1,'app','cat','example',unhex(printf('%08x',i)),6,'tcp',i%1000,1,1,1 FROM n",[rows]).unwrap();
    sqlite
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let before = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let router = internal_router(state);
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = std::time::Instant::now();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/geo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result = parse_json(response).await;
        assert_eq!(result["data"]["top_asns"].as_array().unwrap().len(), 5);
        assert_eq!(result["data"]["top_countries"][0]["country_code"], "US");
        samples.push(start.elapsed().as_micros());
    }
    samples.sort_unstable();
    let after = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    eprintln!(
        "geo_rows={rows} db_bytes={} p50_us={} p95_us={} before={before:?} after={after:?}",
        std::fs::metadata(&path).unwrap().len(),
        samples[2],
        samples[4]
    );
}
