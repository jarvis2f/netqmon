use super::*;

#[tokio::test]
async fn clients_file_pagination_preserves_metadata_and_window_semantics() {
    let directory = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStorage::open(directory.path().join("clients.db")).unwrap();
    sqlite
        .save_gateway("gateway-1", "router", "test", &[7; 32], 1000)
        .unwrap();
    sqlite.connection().execute_batch("INSERT INTO devices(id,gateway_id,mac,hostname,first_seen,last_seen) VALUES
        (1,'gateway-1',X'020000000001','one',1000,9000),(2,'gateway-1',X'020000000002','two',1000,9000),
        (3,'gateway-1',X'020000000003','three',1000,9000),(4,'gateway-1',X'020000000004','four',1000,9000);
      INSERT INTO device_addresses(device_id,ip,ip_version,first_seen,last_seen,application_id,application_confidence,application_source) VALUES
        (1,X'C0000201',4,1000,1000,'nas',0.9,'signature'),
        (2,X'C0000202',4,1000,1000,'nas',0.9,'signature'),
        (2,X'C0000203',4,1000,2000,'other',0.8,'signature');
      INSERT INTO device_evidence(gateway_id,mac,source,field,value,confidence,first_seen,last_seen) VALUES
        ('gateway-1',X'020000000001','test','model','model-one',0.8,1000,2000);
      INSERT INTO flow_sessions(id,gateway_id,device_id,ip_version,protocol,client_ip,client_port,remote_ip,remote_port,direction,upload_bytes,download_bytes,packets,started_at,last_seen_at,checkpointed_at) VALUES
        ('a','gateway-1',1,4,6,X'C0000201',1,X'C6336401',443,1,100,20,2,1000,1000,1000),
        ('b','gateway-1',1,4,6,X'C0000201',2,X'C6336402',443,1,0,0,0,1000,2000,2000),
        ('c','gateway-1',2,4,6,X'C0000202',3,X'C6336403',443,1,200,30,3,1000,2000,2000),
        ('d','gateway-1',4,4,6,X'C0000204',4,X'C6336404',443,1,0,0,0,1000,2000,2000);
      INSERT INTO traffic_device_minute VALUES
        (1000,'gateway-1',1,100,20,2,1),(2000,'gateway-1',1,50,10,1,1),(2000,'gateway-1',2,200,30,3,1)").unwrap();
    let state =
        CollectorState::with_storage(ENROLLMENT_TOKEN, sqlite, repository_rule_engine()).unwrap();
    let router = internal_router(state);
    for (query, ids) in [
        ("limit=10", vec![2, 1, 3, 4]),
        ("limit=2&offset=1", vec![1, 3]),
        ("limit=2&offset=100", vec![]),
        ("limit=10&from=1000&to=2000", vec![1, 2, 3, 4]),
        ("limit=10&from=3000&to=4000", vec![1, 2, 3, 4]),
    ] {
        let uri = format!("/internal/clients?{query}");
        let response = router
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = parse_json(response).await;
        assert_eq!(body["pagination"]["total"], 4, "{query}");
        let items = body["data"].as_array().unwrap();
        assert_eq!(
            items
                .iter()
                .map(|item| item["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            ids,
            "{query}"
        );
        for item in items {
            let id = item["id"].as_i64().unwrap();
            if id == 1 {
                assert_eq!(item["name"], "one");
                assert_eq!(item["ip"], "192.0.2.1");
                assert_eq!(item["self_host_application"]["application_id"], "nas");
                assert_eq!(item["identity"]["evidence"].as_array().unwrap().len(), 1);
                if query.contains("from=3000") {
                    assert!(item["last_traffic_seen"].is_null());
                } else {
                    assert_eq!(item["last_traffic_seen"], 1000);
                }
            } else if id == 2 {
                assert!(item["self_host_application"].is_null());
                assert_eq!(item["ip"], "192.0.2.3");
            }
        }
    }
}
