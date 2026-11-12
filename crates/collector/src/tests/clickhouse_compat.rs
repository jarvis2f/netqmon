use super::*;
use netqmon_storage::ClickHouseClient;

struct TemporaryDatabase {
    admin: ClickHouseClient,
    name: String,
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        if let Err(error) = self
            .admin
            .execute(&format!("DROP DATABASE {} SYNC", self.name))
        {
            eprintln!("failed to delete temporary ClickHouse database: {error}");
        }
    }
}

#[tokio::test]
#[ignore = "manual high-cardinality ClickHouse Geo benchmark"]
async fn clickhouse_geo_cardinality_benchmark() {
    let rows: u64 = std::env::var("NETQMON_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let mut config = ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL").expect("disposable ClickHouse URL"),
        database: std::env::var("NETQMON_TEST_CLICKHOUSE_DATABASE").expect("admin database"),
        user: std::env::var("NETQMON_TEST_CLICKHOUSE_USER").ok(),
        password: std::env::var("NETQMON_TEST_CLICKHOUSE_PASSWORD").ok(),
        timeout_ms: 120_000,
    };
    let admin = ClickHouseClient::new(config.clone());
    let name = format!(
        "netqmon_geo_bench_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin.execute(&format!("CREATE DATABASE {name}")).unwrap();
    let _database = TemporaryDatabase {
        admin,
        name: name.clone(),
    };
    config.database = name;
    let clickhouse = ClickHouseStorage::open(config).unwrap();
    clickhouse.client().execute(&format!("INSERT INTO traffic_scope_minute SELECT 1000,'gateway-1',1,1,1,'app','cat','example',leftPad(hex(toUInt32(number)),8,'0'),6,'tcp',toInt64(number % 1000),1,1,1 FROM numbers(1,{rows})")).unwrap();
    let state = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::clickhouse(clickhouse),
        repository_rule_engine(),
        Arc::new(super::geo_bounded::DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let router = internal_router(state);
    let mut times = Vec::new();
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
        let value = parse_json(response).await;
        assert_eq!(value["data"]["top_asns"].as_array().unwrap().len(), 5);
        times.push(start.elapsed().as_micros());
    }
    times.sort_unstable();
    let memory = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    eprintln!(
        "clickhouse_geo_rows={rows} p50_us={} max_us={} process_memory={memory:?}",
        times[2], times[4]
    );
}

#[tokio::test]
#[ignore = "requires a disposable ClickHouse server"]
async fn grouped_pages_match_file_sqlite_and_clickhouse() {
    let mut config = ClickHouseConfig {
        url: std::env::var("NETQMON_TEST_CLICKHOUSE_URL").expect("disposable ClickHouse URL"),
        database: std::env::var("NETQMON_TEST_CLICKHOUSE_DATABASE").expect("admin database"),
        user: std::env::var("NETQMON_TEST_CLICKHOUSE_USER").ok(),
        password: std::env::var("NETQMON_TEST_CLICKHOUSE_PASSWORD").ok(),
        ..ClickHouseConfig::default()
    };
    let admin = ClickHouseClient::new(config.clone());
    let name = format!(
        "netqmon_api_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin.execute(&format!("CREATE DATABASE {name}")).unwrap();
    let _database = TemporaryDatabase {
        admin,
        name: name.clone(),
    };
    config.database = name;
    let clickhouse = ClickHouseStorage::open(config).unwrap();
    let client = clickhouse.client();
    client.execute("INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,category_id,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES
        ('a','gateway-1',1,4,6,'c0000201',1,'c6336401',443,1,'app-a','cat-x','tcp','org-a',100,20,2,1000,1000,1000),
        ('b','gateway-1',2,4,6,'c0000202',2,'c6336402',443,1,'app-a','cat-y','tcp','org-a',200,30,3,1000,2000,2000),
        ('c','gateway-1',1,4,6,'c0000201',3,'c6336403',443,1,'unknown','unknown','tcp','unknown',10,5,1,1000,1000,1000)").unwrap();
    client.execute("INSERT INTO devices(id,gateway_id,mac,identity_confidence,identity_evidence_json,first_seen,last_seen) VALUES
        (1,'gateway-1','020000000001','unknown','[]',1000,1000),
        (2,'gateway-1','020000000002','unknown','[]',1000,1000)").unwrap();
    client.execute("INSERT INTO traffic_device_minute(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES
        (1000,'gateway-1',1,100,20,2,1),(2000,'gateway-1',1,200,30,3,1),
        (2000,'gateway-1',2,200,30,3,1)").unwrap();
    client
        .execute(
            "INSERT INTO device_traffic_activity(gateway_id,device_id,last_traffic_seen) VALUES
        ('gateway-1',1,1000),('gateway-1',2,2000)",
        )
        .unwrap();
    client.execute("INSERT INTO traffic_application_minute(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES
        (1000,'gateway-1','app-a','cat-x',100,20,2,1),(2000,'gateway-1','app-a','cat-x',50,10,1,1),
        (2000,'gateway-1','app-a','cat-y',200,30,3,1),(1000,'gateway-1','protocol:tcp','unknown',10,5,1,1)").unwrap();
    client.execute("INSERT INTO traffic_domain_minute(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (1000,'gateway-1','a.example',100,20,2,1),(2000,'gateway-1','a.example',50,10,1,1),(1000,'gateway-1','b.example',10,5,1,1)").unwrap();
    client.execute("INSERT INTO traffic_scope_minute SELECT 1000,'gateway-1',1,1,1,'app','cat','example',leftPad(hex(toUInt32(number)),8,'0'),6,'tcp',toInt64(number % 1000),1,1,1 FROM numbers(1,5000)").unwrap();
    client.execute("INSERT INTO traffic_scope_minute VALUES (2000,'gateway-1',1,1,1,'app','cat','example','00001389',6,'tcp',9223372036854775807,9223372036854775807,1,1)").unwrap();
    client.execute("INSERT INTO traffic_scope_minute VALUES (3000,'gateway-1',1,1,1,'app','cat','example','00001389',6,'tcp',1,0,1,1)").unwrap();
    client.execute("INSERT INTO traffic_scope_minute VALUES (1000,'gateway-1',1,1,1,'app-a','cat-x','x.example','c6336401',6,'tcp',100,20,2,1)").unwrap();

    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("api-parity.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute_batch("INSERT INTO devices(id,gateway_id,mac,first_seen,last_seen) VALUES
        (1,'gateway-1',X'020000000001',1000,1000),(2,'gateway-1',X'020000000002',1000,1000);
      INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,application_id,category_id,protocol_id,organization_id,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES
        ('a','gateway-1',1,4,6,X'C0000201',1,X'C6336401',443,1,'app-a','cat-x','tcp','org-a',100,20,2,1000,1000,1000),
        ('b','gateway-1',2,4,6,X'C0000202',2,X'C6336402',443,1,'app-a','cat-y','tcp','org-a',200,30,3,1000,2000,2000),
        ('c','gateway-1',1,4,6,X'C0000201',3,X'C6336403',443,1,'unknown','unknown','tcp','unknown',10,5,1,1000,1000,1000);
      INSERT INTO traffic_application_minute VALUES
        (1000,'gateway-1','app-a','cat-x',100,20,2,1),(2000,'gateway-1','app-a','cat-x',50,10,1,1),
        (2000,'gateway-1','app-a','cat-y',200,30,3,1),(1000,'gateway-1','protocol:tcp','unknown',10,5,1,1);
      INSERT INTO traffic_domain_minute VALUES (1000,'gateway-1','a.example',100,20,2,1),(2000,'gateway-1','a.example',50,10,1,1),(1000,'gateway-1','b.example',10,5,1,1)").unwrap();
    sqlite.connection().execute_batch("INSERT INTO traffic_device_minute(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES
        (1000,'gateway-1',1,100,20,2,1),(2000,'gateway-1',1,200,30,3,1),
        (2000,'gateway-1',2,200,30,3,1)").unwrap();
    sqlite.connection().execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<5000) INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) SELECT 1000,'gateway-1',1,1,1,'app','cat','example',unhex(printf('%08x',i)),6,'tcp',i%1000,1,1,1 FROM n", []).unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES (2000,'gateway-1',1,1,1,'app','cat','example',X'00001389',6,'tcp',?1,?1,1,1)", [i64::MAX]).unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES (3000,'gateway-1',1,1,1,'app','cat','example',X'00001389',6,'tcp',1,0,1,1)", []).unwrap();
    sqlite.connection().execute("INSERT INTO traffic_scope_minute(timestamp,gateway_id,scope,direction,device_id,application_id,category_id,domain,remote_ip,protocol,protocol_id,upload_bytes,download_bytes,packets,flow_count) VALUES (1000,'gateway-1',1,1,1,'app-a','cat-x','x.example',X'C6336401',6,'tcp',100,20,2,1)", []).unwrap();
    let sqlite = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::sqlite(sqlite),
        repository_rule_engine(),
        Arc::new(super::geo_bounded::DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let clickhouse = CollectorState::with_geo_provider(
        ENROLLMENT_TOKEN,
        Storage::clickhouse(clickhouse),
        repository_rule_engine(),
        Arc::new(super::geo_bounded::DistinctAsnGeo),
        PathBuf::from(DEFAULT_GEO_DIRECTORY),
        DeviceIdentifier::load(Path::new("/missing/netqmon-test-mac-prefixes.json")),
        IconCacheConfig::default(),
        Arc::new(PolicyService::open_in_memory().unwrap()),
        false,
    )
    .unwrap();
    let sqlite = internal_router(sqlite);
    let clickhouse = internal_router(clickhouse);
    for uri in [
        "/internal/geo",
        "/internal/geo?from=1000&to=2000",
        "/internal/geo?from=2000&to=3000",
        "/internal/geo?from=2000&to=4000",
        "/internal/geo?from=4000&to=5000",
    ] {
        let request = || Request::builder().uri(uri).body(Body::empty()).unwrap();
        let left_response = sqlite.clone().oneshot(request()).await.unwrap();
        let right_response = clickhouse.clone().oneshot(request()).await.unwrap();
        assert_eq!(left_response.status(), StatusCode::OK, "{uri}");
        assert_eq!(right_response.status(), StatusCode::OK, "{uri}");
        let left = parse_json(left_response).await;
        let right = parse_json(right_response).await;
        assert_eq!(left["data"]["enabled"], true, "{uri}");
        let expected = if uri.contains("from=4000") {
            0
        } else if uri.contains("from=2000") {
            1
        } else {
            5
        };
        assert_eq!(
            left["data"]["top_asns"].as_array().unwrap().len(),
            expected,
            "{uri}"
        );
        assert_eq!(left["data"], right["data"], "{uri}");
        if uri.contains("from=2000") && uri.contains("to=3000") {
            assert_eq!(
                left["data"]["top_asns"][0]["bytes"].as_u64(),
                Some(u64::MAX - 1)
            );
        }
        if uri.contains("from=2000") && uri.contains("to=4000") {
            assert_eq!(
                left["data"]["top_asns"][0]["bytes"].as_u64(),
                Some(u64::MAX)
            );
        }
    }
    for query in [
        "limit=10",
        "limit=1&offset=1",
        "limit=1&offset=100",
        "limit=10&from=1000&to=2000",
        "limit=10&from=3000&to=4000",
    ] {
        let uri = format!("/internal/applications?{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["pagination"], right["pagination"], "{query}");
        assert_eq!(left["data"], right["data"], "{query}");
    }
    for resource in ["domains", "organizations", "protocols"] {
        for query in ["limit=10", "limit=1&offset=1", "limit=1&offset=100"] {
            let uri = format!("/internal/{resource}?{query}");
            let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
            let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
            let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
            assert_eq!(left["pagination"], right["pagination"], "{uri}");
            assert_eq!(left["data"], right["data"], "{uri}");
        }
    }
    for query in ["limit=10", "limit=1&offset=1", "limit=10&from=1000&to=2000"] {
        let uri = format!("/internal/clients?{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["pagination"], right["pagination"], "{uri}");
        assert_eq!(left["data"], right["data"], "{uri}");
    }
    for query in [
        "limit=2&from=1000&to=2000",
        "limit=1&offset=1&from=1000&to=2000",
        "limit=2&from=3000&to=4000",
    ] {
        let uri = format!("/internal/destinations?{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["pagination"], right["pagination"], "{uri}");
        assert_eq!(left["data"], right["data"], "{uri}");
    }
    for query in [
        "category=cat-x&from=1000&to=3000",
        "category=cat-x&from=3000&to=4000",
    ] {
        let uri = format!("/internal/applications/app-a?{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left_response = sqlite.clone().oneshot(request()).await.unwrap();
        let right_response = clickhouse.clone().oneshot(request()).await.unwrap();
        let left_status = left_response.status();
        let right_status = right_response.status();
        let left = parse_json(left_response).await;
        let right = parse_json(right_response).await;
        assert_eq!(left_status, StatusCode::OK, "{uri}: sqlite={left}");
        assert_eq!(right_status, StatusCode::OK, "{uri}: clickhouse={right}");
        assert_eq!(
            left["data"], right["data"],
            "{uri}: sqlite={left} clickhouse={right}"
        );
    }
    for query in [
        "destinations?category=cat-x&from=1000&to=3000&limit=10",
        "destinations?category=cat-x&from=3000&to=4000&limit=10",
    ] {
        let uri = format!("/internal/applications/app-a/{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["data"], right["data"], "{uri}");
    }
    for relation in [
        "traffic",
        "applications",
        "domains",
        "destinations",
        "flows",
    ] {
        let uri = format!("/internal/clients/1/{relation}?from=1000&to=2000&limit=10");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left_response = sqlite.clone().oneshot(request()).await.unwrap();
        let right_response = clickhouse.clone().oneshot(request()).await.unwrap();
        let left_status = left_response.status();
        let right_status = right_response.status();
        let left = parse_json(left_response).await;
        let right = parse_json(right_response).await;
        assert_eq!(left_status, StatusCode::OK, "{uri}: sqlite={left}");
        assert_eq!(right_status, StatusCode::OK, "{uri}: clickhouse={right}");
        assert_eq!(
            left["data"], right["data"],
            "{uri}: sqlite={left} clickhouse={right}"
        );
    }
    for relation in ["traffic", "clients", "domains", "destinations", "flows"] {
        let uri = format!(
            "/internal/applications/app-a/{relation}?category=cat-x&from=1000&to=3000&limit=10"
        );
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["data"], right["data"], "{uri}");
    }
    for group_by in ["none", "client", "application"] {
        let uri = format!(
            "/internal/traffic?from=1000&to=2000&scope=internet&direction=upload&group_by={group_by}"
        );
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["data"], right["data"], "{uri}");
    }
    for query in ["limit=2", "limit=1&application=app-a"] {
        let uri = format!("/internal/flows?{query}");
        let request = || Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let left = parse_json(sqlite.clone().oneshot(request()).await.unwrap()).await;
        let right = parse_json(clickhouse.clone().oneshot(request()).await.unwrap()).await;
        assert_eq!(left["pagination"], right["pagination"], "{uri}");
        assert_eq!(left["data"], right["data"], "{uri}");
    }
}
