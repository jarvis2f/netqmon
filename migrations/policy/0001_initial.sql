CREATE TABLE policy_gateways (
    gateway_id TEXT PRIMARY KEY,
    desired_revision INTEGER NOT NULL DEFAULT 0 CHECK(desired_revision >= 0)
);

CREATE TABLE traffic_policies (
    id TEXT PRIMARY KEY,
    gateway_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 1000),
    spec_json TEXT NOT NULL CHECK(json_valid(spec_json)),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY(gateway_id) REFERENCES policy_gateways(gateway_id)
);

CREATE INDEX policies_gateway_priority ON traffic_policies(gateway_id, priority, id);

CREATE TABLE policy_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    gateway_id TEXT NOT NULL,
    policy_id TEXT,
    action TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    created_at_ms INTEGER NOT NULL,
    FOREIGN KEY(gateway_id) REFERENCES policy_gateways(gateway_id)
);

CREATE INDEX policy_events_gateway_created ON policy_events(gateway_id, created_at_ms DESC);
CREATE INDEX policy_events_policy_created ON policy_events(policy_id, created_at_ms DESC);

CREATE TABLE policy_deployments (
    gateway_id TEXT PRIMARY KEY,
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'not_deployed',
    last_error_code TEXT,
    last_error_message TEXT,
    last_reported_at_ms INTEGER,
    agent_connected INTEGER NOT NULL DEFAULT 0 CHECK(agent_connected IN (0, 1)),
    agent_boot_id TEXT,
    controller_epoch TEXT,
    bundle_generation INTEGER NOT NULL DEFAULT 0 CHECK(bundle_generation >= 0),
    bundle_checksum TEXT,
    capabilities_json TEXT CHECK(capabilities_json IS NULL OR json_valid(capabilities_json)),
    policy_results_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(policy_results_json)),
    last_heartbeat_at_ms INTEGER,
    reported_revision INTEGER NOT NULL DEFAULT 0 CHECK(reported_revision >= 0),
    agent_applied_revision INTEGER NOT NULL DEFAULT 0 CHECK(agent_applied_revision >= 0),
    delivered_revision INTEGER NOT NULL DEFAULT 0 CHECK(delivered_revision >= 0),
    delivered_at_ms INTEGER,
    acknowledged_status TEXT CHECK(acknowledged_status IS NULL OR acknowledged_status IN ('applied', 'partial', 'failed', 'unsupported')),
    FOREIGN KEY(gateway_id) REFERENCES policy_gateways(gateway_id)
);

CREATE TABLE policy_client_metrics (
    gateway_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    mac TEXT NOT NULL CHECK(length(mac) = 17),
    upload_interface TEXT,
    upload_bytes INTEGER CHECK(upload_bytes IS NULL OR upload_bytes >= 0),
    upload_packets INTEGER CHECK(upload_packets IS NULL OR upload_packets >= 0),
    upload_drops INTEGER CHECK(upload_drops IS NULL OR upload_drops >= 0),
    upload_overlimits INTEGER CHECK(upload_overlimits IS NULL OR upload_overlimits >= 0),
    download_interface TEXT,
    download_bytes INTEGER CHECK(download_bytes IS NULL OR download_bytes >= 0),
    download_packets INTEGER CHECK(download_packets IS NULL OR download_packets >= 0),
    download_drops INTEGER CHECK(download_drops IS NULL OR download_drops >= 0),
    download_overlimits INTEGER CHECK(download_overlimits IS NULL OR download_overlimits >= 0),
    sampled_at_ms INTEGER NOT NULL CHECK(sampled_at_ms >= 0),
    PRIMARY KEY(gateway_id, policy_id, mac)
);

CREATE INDEX policy_client_metrics_sampled
    ON policy_client_metrics(gateway_id, sampled_at_ms DESC);
