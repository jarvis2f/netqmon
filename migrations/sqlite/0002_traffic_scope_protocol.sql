CREATE TABLE IF NOT EXISTS traffic_scope_minute_v2 (
  timestamp INTEGER NOT NULL,
  gateway_id TEXT NOT NULL,
  scope INTEGER NOT NULL,
  direction INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  application_id TEXT NOT NULL,
  category_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  remote_ip BLOB NOT NULL,
  protocol INTEGER NOT NULL DEFAULT 0,
  protocol_id TEXT NOT NULL DEFAULT 'unknown',
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  flow_count INTEGER NOT NULL,
  PRIMARY KEY(timestamp, gateway_id, scope, direction, device_id,
              application_id, category_id, domain, remote_ip, protocol, protocol_id)
);

INSERT INTO traffic_scope_minute_v2 (
  timestamp, gateway_id, scope, direction, device_id,
  application_id, category_id, domain, remote_ip,
  protocol, protocol_id,
  upload_bytes, download_bytes, packets, flow_count
)
SELECT
  timestamp, gateway_id, scope, direction, device_id,
  application_id, category_id, domain, remote_ip,
  0, 'unknown',
  upload_bytes, download_bytes, packets, flow_count
FROM traffic_scope_minute;

DROP TABLE traffic_scope_minute;
ALTER TABLE traffic_scope_minute_v2 RENAME TO traffic_scope_minute;

CREATE INDEX IF NOT EXISTS traffic_scope_minute_query ON traffic_scope_minute(scope, direction, timestamp);
CREATE INDEX IF NOT EXISTS traffic_scope_minute_device ON traffic_scope_minute(device_id, scope, timestamp);
