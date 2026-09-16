CREATE TABLE IF NOT EXISTS traffic_scope_minute_v2 (
    timestamp Int64,
    gateway_id String,
    scope Int32,
    direction UInt8,
    device_id Int64,
    application_id String,
    category_id String,
    domain String,
    remote_ip String,
    protocol UInt8,
    protocol_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, scope, direction, timestamp, device_id,
          application_id, category_id, domain, remote_ip, protocol, protocol_id);

INSERT INTO traffic_scope_minute_v2
SELECT
    timestamp, gateway_id, scope, direction, device_id,
    application_id, category_id, domain, remote_ip,
    toUInt8(0) AS protocol, 'unknown' AS protocol_id,
    upload_bytes, download_bytes, packets, flow_count
FROM traffic_scope_minute;

EXCHANGE TABLES traffic_scope_minute AND traffic_scope_minute_v2;
DROP TABLE traffic_scope_minute_v2;
