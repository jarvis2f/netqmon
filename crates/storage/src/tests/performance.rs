use super::*;
use std::time::Instant;

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
