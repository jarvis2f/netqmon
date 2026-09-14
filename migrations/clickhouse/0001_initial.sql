CREATE TABLE IF NOT EXISTS schema_migrations (
    version UInt32,
    applied_at Int64
) ENGINE = MergeTree()
ORDER BY version;

CREATE TABLE IF NOT EXISTS sites (
    id String,
    name String,
    created_at Int64
) ENGINE = ReplacingMergeTree()
ORDER BY id;

CREATE TABLE IF NOT EXISTS gateways (
    id String,
    site_id String,
    name String,
    agent_token_hash String,
    agent_version String,
    arch String,
    kernel_version String,
    openwrt_version String,
    status String,
    last_seen Int64,
    created_at Int64
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY id;

CREATE TABLE IF NOT EXISTS users (
    id String,
    username String,
    password_hash String,
    created_at Int64
) ENGINE = ReplacingMergeTree(created_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash String,
    user_id String,
    created_at Int64,
    expires_at Int64
) ENGINE = ReplacingMergeTree(expires_at)
ORDER BY token_hash;

CREATE TABLE IF NOT EXISTS devices (
    id Int64,
    gateway_id String,
    mac String,
    hostname Nullable(String),
    display_name Nullable(String),
    vendor Nullable(String),
    device_type Nullable(String),
    os_family Nullable(String),
    model Nullable(String),
    identity_confidence String,
    identity_evidence_json String,
    first_seen Int64,
    last_seen Int64,
    vendor_confidence Float64 DEFAULT 0.0,
    device_type_confidence Float64 DEFAULT 0.0,
    os_confidence Float64 DEFAULT 0.0,
    model_confidence Float64 DEFAULT 0.0,
    private_mac UInt8 DEFAULT 0
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (gateway_id, mac);

CREATE TABLE IF NOT EXISTS device_addresses (
    device_id Int64,
    ip String,
    ip_version UInt8,
    first_seen Int64,
    last_seen Int64,
    application_id String DEFAULT '',
    application_confidence Float64 DEFAULT 0,
    application_source String DEFAULT '',
    application_last_seen Int64 DEFAULT 0
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (device_id, ip);

CREATE TABLE IF NOT EXISTS device_evidence (
    gateway_id String,
    mac String,
    source String,
    field String,
    value String,
    confidence Float64,
    first_seen Int64,
    last_seen Int64,
    hit_count UInt64,
    metadata_json String
) ENGINE = ReplacingMergeTree(hit_count)
ORDER BY (gateway_id, mac, source, field, value);

CREATE TABLE IF NOT EXISTS dns_observations (
    id Int64,
    gateway_id String,
    client_ip String,
    domain String,
    answer_ip String,
    record_type UInt16,
    ttl UInt32,
    observed_at Int64,
    expires_at Int64
) ENGINE = MergeTree()
ORDER BY (gateway_id, observed_at, client_ip, domain);

CREATE TABLE IF NOT EXISTS flow_sessions (
    id String,
    gateway_id String,
    device_id Nullable(Int64),
    ip_version UInt8,
    protocol UInt8,
    client_ip String,
    client_port UInt16,
    remote_ip String,
    remote_port UInt16,
    direction UInt8,
    domain Nullable(String),
    organization_id Nullable(String),
    application_id Nullable(String),
    category_id Nullable(String),
    traffic_role Nullable(String),
    protocol_id Nullable(String),
    organization_confidence Float64,
    application_confidence Float64,
    protocol_confidence Float64,
    classification_confidence Float64,
    classification_reason Nullable(String),
    classification_evidence_json String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    started_at Int64,
    last_seen_at Int64,
    ended_at Nullable(Int64),
    checkpointed_at Int64,
    scope Int32 DEFAULT 4,
    path_type Int32 DEFAULT 4,
    nat Int32 DEFAULT 5,
    source_segment String DEFAULT '',
    destination_segment String DEFAULT ''
) ENGINE = ReplacingMergeTree(checkpointed_at)
ORDER BY (gateway_id, id);

CREATE TABLE IF NOT EXISTS ingest_batches (
    gateway_id String,
    boot_id String,
    sequence Int64,
    received_at Int64
) ENGINE = ReplacingMergeTree()
ORDER BY (gateway_id, boot_id, sequence);

CREATE TABLE IF NOT EXISTS settings (
    key String,
    value String,
    updated_at Int64
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;

CREATE TABLE IF NOT EXISTS self_host_endpoint_evidence (
    gateway_id String,
    ip String,
    protocol UInt8,
    port UInt16,
    application_id String,
    confidence Float64,
    source String,
    last_seen Int64,
    expires_at Int64
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (gateway_id, ip, protocol, port, application_id);

CREATE TABLE IF NOT EXISTS traffic_total_minute (
    timestamp Int64,
    gateway_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_device_minute (
    timestamp Int64,
    gateway_id String,
    device_id Int64,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, device_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_application_minute (
    timestamp Int64,
    gateway_id String,
    application_id String,
    category_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, application_id, category_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_domain_minute (
    timestamp Int64,
    gateway_id String,
    domain String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, domain, timestamp);

CREATE TABLE IF NOT EXISTS traffic_destination_minute (
    timestamp Int64,
    gateway_id String,
    remote_ip String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, remote_ip, timestamp);

CREATE TABLE IF NOT EXISTS traffic_scope_minute (
    timestamp Int64,
    gateway_id String,
    scope Int32,
    direction Int32,
    device_id Int64,
    application_id String,
    category_id String,
    domain String,
    remote_ip String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, scope, direction, timestamp, device_id,
          application_id, category_id, domain, remote_ip);

CREATE TABLE IF NOT EXISTS traffic_total_hour (
    timestamp Int64,
    gateway_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_device_hour (
    timestamp Int64,
    gateway_id String,
    device_id Int64,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, device_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_application_hour (
    timestamp Int64,
    gateway_id String,
    application_id String,
    category_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, application_id, category_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_domain_hour (
    timestamp Int64,
    gateway_id String,
    domain String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, domain, timestamp);

CREATE TABLE IF NOT EXISTS traffic_destination_hour (
    timestamp Int64,
    gateway_id String,
    remote_ip String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, remote_ip, timestamp);

CREATE TABLE IF NOT EXISTS traffic_total_day (
    timestamp Int64,
    gateway_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_device_day (
    timestamp Int64,
    gateway_id String,
    device_id Int64,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, device_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_application_day (
    timestamp Int64,
    gateway_id String,
    application_id String,
    category_id String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, application_id, category_id, timestamp);

CREATE TABLE IF NOT EXISTS traffic_domain_day (
    timestamp Int64,
    gateway_id String,
    domain String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, domain, timestamp);

CREATE TABLE IF NOT EXISTS traffic_destination_day (
    timestamp Int64,
    gateway_id String,
    remote_ip String,
    upload_bytes Int64,
    download_bytes Int64,
    packets Int64,
    flow_count Int64
) ENGINE = SummingMergeTree((upload_bytes, download_bytes, packets, flow_count))
ORDER BY (gateway_id, remote_ip, timestamp);

INSERT INTO sites (id, name, created_at) VALUES ('default', 'default', 0);
