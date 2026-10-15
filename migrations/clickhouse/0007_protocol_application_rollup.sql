ALTER TABLE traffic_application_minute
DELETE WHERE application_id IN ('unknown', 'protocol-only')
   OR startsWith(application_id, 'protocol:')
SETTINGS mutations_sync = 1;

INSERT INTO traffic_application_minute
SELECT
    timestamp,
    gateway_id,
    application_id,
    category_id,
    sum(upload_bytes),
    sum(download_bytes),
    sum(packets),
    sum(flow_count)
FROM (
    SELECT
        timestamp,
        gateway_id,
        if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown',
           concat('protocol:', coalesce(nullIf(protocol_id, ''), 'unknown')),
           'unknown') AS application_id,
        if(coalesce(nullIf(protocol_id, ''), 'unknown') != 'unknown',
           'unknown', coalesce(category_id, 'unknown')) AS category_id,
        upload_bytes,
        download_bytes,
        packets,
        flow_count
    FROM traffic_scope_minute
    WHERE application_id = 'unknown'
)
GROUP BY
    timestamp,
    gateway_id,
    application_id,
    category_id;

INSERT INTO traffic_rollup_dirty
SELECT gateway_id, 'application', 'minute', timestamp,
       toUnixTimestamp64Milli(now64(3)) * 1000000 + 999999
FROM traffic_application_minute
WHERE startsWith(application_id, 'protocol:') OR application_id = 'unknown'
GROUP BY gateway_id, timestamp;
