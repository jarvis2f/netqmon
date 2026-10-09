CREATE TABLE IF NOT EXISTS traffic_rollup_dirty (
    gateway_id String,
    dimension String,
    period String,
    timestamp Int64,
    version Int64
) ENGINE = ReplacingMergeTree(version)
ORDER BY (gateway_id, dimension, period, timestamp)
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS traffic_rollup_progress (
    gateway_id String,
    dimension String,
    period String,
    timestamp Int64,
    processed_version Int64
) ENGINE = ReplacingMergeTree(processed_version)
ORDER BY (gateway_id, dimension, period, timestamp)
SETTINGS non_replicated_deduplication_window = 1000;

INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'total', 'minute', timestamp, 1 FROM traffic_total_minute
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'device', 'minute', timestamp, 1 FROM traffic_device_minute
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'application', 'minute', timestamp, 1 FROM traffic_application_minute
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'domain', 'minute', timestamp, 1 FROM traffic_domain_minute
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'destination', 'minute', timestamp, 1 FROM traffic_destination_minute
GROUP BY gateway_id, timestamp;

INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'total', 'hour', timestamp, 1 FROM traffic_total_hour
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'device', 'hour', timestamp, 1 FROM traffic_device_hour
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'application', 'hour', timestamp, 1 FROM traffic_application_hour
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'domain', 'hour', timestamp, 1 FROM traffic_domain_hour
GROUP BY gateway_id, timestamp;
INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'destination', 'hour', timestamp, 1 FROM traffic_destination_hour
GROUP BY gateway_id, timestamp;
