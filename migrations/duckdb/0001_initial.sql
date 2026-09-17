CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_batches (
  gateway_id VARCHAR NOT NULL,
  boot_id VARCHAR NOT NULL,
  sequence UBIGINT NOT NULL,
  applied_at BIGINT NOT NULL,
  PRIMARY KEY (gateway_id, boot_id, sequence)
);

-- Storage V2 deliberately replaces the old unified fact tables. The previous
-- analytics database can be discarded; metadata and the SQLite outbox are
-- stored separately and are not affected by this cleanup.
DROP TABLE IF EXISTS traffic_minute;
DROP TABLE IF EXISTS traffic_hour;
DROP TABLE IF EXISTS traffic_day;

CREATE TABLE IF NOT EXISTS analytics_rollup_state (
  rollup_name VARCHAR PRIMARY KEY,
  completed_until UBIGINT NOT NULL
);

INSERT OR IGNORE INTO analytics_rollup_state(rollup_name, completed_until)
VALUES ('core_hour', 0), ('core_day', 0), ('endpoint_hour', 0), ('endpoint_day', 0);

CREATE TABLE IF NOT EXISTS flow_session_versions (
  gateway_id VARCHAR NOT NULL,
  flow_id VARCHAR NOT NULL,
  boot_id VARCHAR NOT NULL,
  batch_sequence UBIGINT NOT NULL,
  device_id UBIGINT NOT NULL,
  ip_version UTINYINT NOT NULL,
  protocol UTINYINT NOT NULL,
  client_ip BLOB NOT NULL,
  client_port USMALLINT NOT NULL,
  remote_ip BLOB NOT NULL,
  remote_port USMALLINT NOT NULL,
  direction UTINYINT NOT NULL,
  domain VARCHAR NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  traffic_role VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  organization_confidence DOUBLE NOT NULL,
  application_confidence DOUBLE NOT NULL,
  protocol_confidence DOUBLE NOT NULL,
  classification_confidence DOUBLE NOT NULL,
  classification_reason VARCHAR NOT NULL,
  classification_evidence_json VARCHAR NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  started_at UBIGINT NOT NULL,
  last_seen_at UBIGINT NOT NULL,
  ended_at UBIGINT,
  checkpointed_at UBIGINT NOT NULL,
  scope UTINYINT NOT NULL,
  path_type UTINYINT NOT NULL,
  nat UTINYINT NOT NULL,
  source_segment VARCHAR NOT NULL,
  destination_segment VARCHAR NOT NULL,
  PRIMARY KEY (gateway_id, flow_id, boot_id, batch_sequence)
);

CREATE VIEW IF NOT EXISTS flow_sessions_latest AS
SELECT * EXCLUDE (version_rank)
FROM (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY gateway_id, flow_id
    ORDER BY checkpointed_at DESC, batch_sequence DESC
  ) AS version_rank
  FROM flow_session_versions
)
WHERE version_rank = 1;

CREATE TABLE IF NOT EXISTS flow_traffic_attribution (
  gateway_id VARCHAR NOT NULL,
  flow_id VARCHAR NOT NULL,
  started_at UBIGINT NOT NULL,
  timestamp UBIGINT NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  transport_protocol UTINYINT NOT NULL,
  path_type UTINYINT NOT NULL,
  nat UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  domain VARCHAR NOT NULL,
  remote_ip BLOB NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (gateway_id, flow_id, started_at)
);

CREATE TABLE IF NOT EXISTS traffic_core_minute (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  transport_protocol UTINYINT NOT NULL,
  path_type UTINYINT NOT NULL,
  nat UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (
    timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
    organization_id, application_id, category_id, protocol_id
  )
);

CREATE TABLE IF NOT EXISTS traffic_endpoint_minute (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  domain VARCHAR NOT NULL,
  remote_ip BLOB NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (timestamp, gateway_id, scope, direction, device_id, organization_id, application_id, category_id, protocol_id, domain, remote_ip)
);

CREATE TABLE IF NOT EXISTS traffic_core_hour (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  transport_protocol UTINYINT NOT NULL,
  path_type UTINYINT NOT NULL,
  nat UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (
    timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
    organization_id, application_id, category_id, protocol_id
  )
);

CREATE TABLE IF NOT EXISTS traffic_endpoint_hour (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  domain VARCHAR NOT NULL,
  remote_ip BLOB NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (timestamp, gateway_id, scope, direction, device_id, organization_id, application_id, category_id, protocol_id, domain, remote_ip)
);

CREATE TABLE IF NOT EXISTS traffic_core_day (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  transport_protocol UTINYINT NOT NULL,
  path_type UTINYINT NOT NULL,
  nat UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (
    timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
    organization_id, application_id, category_id, protocol_id
  )
);

CREATE TABLE IF NOT EXISTS traffic_endpoint_day (
  timestamp UBIGINT NOT NULL,
  gateway_id VARCHAR NOT NULL,
  scope UTINYINT NOT NULL,
  direction UTINYINT NOT NULL,
  device_id UBIGINT NOT NULL,
  organization_id VARCHAR NOT NULL,
  application_id VARCHAR NOT NULL,
  category_id VARCHAR NOT NULL,
  protocol_id VARCHAR NOT NULL,
  domain VARCHAR NOT NULL,
  remote_ip BLOB NOT NULL,
  upload_bytes UBIGINT NOT NULL,
  download_bytes UBIGINT NOT NULL,
  packets UBIGINT NOT NULL,
  flow_count UBIGINT NOT NULL,
  PRIMARY KEY (timestamp, gateway_id, scope, direction, device_id, organization_id, application_id, category_id, protocol_id, domain, remote_ip)
);

CREATE INDEX IF NOT EXISTS flow_versions_last_seen ON flow_session_versions(last_seen_at);
CREATE INDEX IF NOT EXISTS flow_traffic_attribution_time ON flow_traffic_attribution(timestamp);
CREATE INDEX IF NOT EXISTS traffic_core_minute_time ON traffic_core_minute(timestamp);
CREATE INDEX IF NOT EXISTS traffic_core_hour_time ON traffic_core_hour(timestamp);
CREATE INDEX IF NOT EXISTS traffic_core_day_time ON traffic_core_day(timestamp);
CREATE INDEX IF NOT EXISTS traffic_endpoint_minute_time ON traffic_endpoint_minute(timestamp);
CREATE INDEX IF NOT EXISTS traffic_endpoint_hour_time ON traffic_endpoint_hour(timestamp);
CREATE INDEX IF NOT EXISTS traffic_endpoint_day_time ON traffic_endpoint_day(timestamp);
