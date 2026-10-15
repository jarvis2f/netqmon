DELETE FROM traffic_application_minute
WHERE application_id IN ('unknown', 'protocol-only');

INSERT INTO traffic_application_minute (
  timestamp, gateway_id, application_id, category_id,
  upload_bytes, download_bytes, packets, flow_count
)
SELECT
  timestamp,
  gateway_id,
  CASE WHEN COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
       THEN 'protocol-only' ELSE 'unknown' END,
  CASE WHEN COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
       THEN 'unknown' ELSE COALESCE(category_id, 'unknown') END,
  SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
FROM traffic_scope_minute
WHERE application_id = 'unknown'
GROUP BY timestamp, gateway_id,
         CASE WHEN COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
              THEN 'protocol-only' ELSE 'unknown' END,
         CASE WHEN COALESCE(NULLIF(protocol_id, ''), 'unknown') != 'unknown'
              THEN 'unknown' ELSE COALESCE(category_id, 'unknown') END;
