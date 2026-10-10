ALTER TABLE traffic_application_minute
DELETE WHERE application_id IN ('unknown', 'protocol-only')
SETTINGS mutations_sync = 1;

INSERT INTO traffic_application_minute
SELECT
    timestamp,
    gateway_id,
    if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown', 'protocol-only', 'unknown') AS application_id,
    if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown', 'unknown', coalesce(category_id, 'unknown')) AS category_id,
    sum(upload_bytes),
    sum(download_bytes),
    sum(packets),
    sum(flow_count)
FROM traffic_scope_minute
WHERE traffic_scope_minute.application_id = 'unknown'
GROUP BY
    timestamp,
    gateway_id,
    if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown', 'protocol-only', 'unknown'),
    if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown', 'unknown', coalesce(category_id, 'unknown'));

INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'application', 'minute', timestamp,
       toUnixTimestamp64Milli(now64(3)) * 1000000 + 999999
FROM traffic_application_minute
GROUP BY gateway_id, timestamp;
