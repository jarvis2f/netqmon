CREATE TABLE IF NOT EXISTS schema_migrations (
  version UInt32,
  applied_at UInt64
) ENGINE = ReplacingMergeTree(applied_at)
ORDER BY version;

CREATE TABLE IF NOT EXISTS processed_batches (
  gateway_id String,
  boot_id String,
  sequence UInt64,
  applied_at UInt64
) ENGINE = ReplacingMergeTree(applied_at)
ORDER BY (gateway_id, boot_id, sequence);

CREATE TABLE IF NOT EXISTS flow_session_versions (
  gateway_id String,
  flow_id String,
  boot_id String,
  batch_sequence UInt64,
  device_id UInt64,
  ip_version UInt8,
  protocol UInt8,
  client_ip String,
  client_port UInt16,
  remote_ip String,
  remote_port UInt16,
  direction UInt8,
  domain String,
  organization_id String,
  application_id String,
  category_id String,
  traffic_role String,
  protocol_id String,
  organization_confidence Float64,
  application_confidence Float64,
  protocol_confidence Float64,
  classification_confidence Float64,
  classification_reason String,
  classification_evidence_json String,
  upload_bytes UInt64,
  download_bytes UInt64,
  packets UInt64,
  started_at UInt64,
  last_seen_at UInt64,
  ended_at Nullable(UInt64),
  checkpointed_at UInt64,
  scope UInt8,
  path_type UInt8,
  nat UInt8,
  source_segment String,
  destination_segment String
) ENGINE = ReplacingMergeTree(checkpointed_at)
PARTITION BY toYYYYMM(toDateTime(last_seen_at / 1000))
ORDER BY (gateway_id, flow_id);

CREATE VIEW IF NOT EXISTS flow_sessions_latest AS
SELECT * FROM flow_session_versions FINAL;

CREATE TABLE IF NOT EXISTS traffic_minute (
  timestamp UInt64,
  gateway_id String,
  scope UInt8,
  direction UInt8,
  transport_protocol UInt8,
  path_type UInt8,
  nat UInt8,
  device_id UInt64,
  organization_id String,
  application_id String,
  category_id String,
  protocol_id String,
  domain String,
  remote_ip String,
  upload_bytes UInt64,
  download_bytes UInt64,
  packets UInt64,
  flow_count UInt64,
  boot_id String,
  batch_sequence UInt64
) ENGINE = ReplacingMergeTree(batch_sequence)
PARTITION BY toYYYYMM(toDateTime(timestamp / 1000))
ORDER BY (
  timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
  organization_id, application_id, category_id, protocol_id, domain, remote_ip,
  boot_id, batch_sequence
);

CREATE TABLE IF NOT EXISTS traffic_hour (
  timestamp UInt64,
  gateway_id String,
  scope UInt8,
  direction UInt8,
  transport_protocol UInt8,
  path_type UInt8,
  nat UInt8,
  device_id UInt64,
  organization_id String,
  application_id String,
  category_id String,
  protocol_id String,
  domain String,
  remote_ip String,
  upload_bytes UInt64,
  download_bytes UInt64,
  packets UInt64,
  flow_count UInt64,
  rollup_version UInt64
) ENGINE = ReplacingMergeTree(rollup_version)
PARTITION BY toYYYYMM(toDateTime(timestamp / 1000))
ORDER BY (
  timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
  organization_id, application_id, category_id, protocol_id, domain, remote_ip
);

CREATE TABLE IF NOT EXISTS traffic_day (
  timestamp UInt64,
  gateway_id String,
  scope UInt8,
  direction UInt8,
  transport_protocol UInt8,
  path_type UInt8,
  nat UInt8,
  device_id UInt64,
  organization_id String,
  application_id String,
  category_id String,
  protocol_id String,
  domain String,
  remote_ip String,
  upload_bytes UInt64,
  download_bytes UInt64,
  packets UInt64,
  flow_count UInt64,
  rollup_version UInt64
) ENGINE = ReplacingMergeTree(rollup_version)
PARTITION BY toYYYYMM(toDateTime(timestamp / 1000))
ORDER BY (
  timestamp, gateway_id, scope, direction, transport_protocol, path_type, nat, device_id,
  organization_id, application_id, category_id, protocol_id, domain, remote_ip
);
