CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gateways (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  name TEXT NOT NULL,
  agent_token_hash BLOB NOT NULL CHECK(length(agent_token_hash) = 32),
  agent_version TEXT NOT NULL,
  arch TEXT NOT NULL DEFAULT '',
  kernel_version TEXT NOT NULL DEFAULT '',
  openwrt_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS gateways_site_id ON gateways(site_id);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at ON auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  mac BLOB NOT NULL,
  hostname TEXT,
  display_name TEXT,
  vendor TEXT,
  device_type TEXT,
  os_family TEXT,
  model TEXT,
  identity_confidence TEXT NOT NULL DEFAULT 'unknown',
  identity_evidence_json TEXT NOT NULL DEFAULT '[]',
  vendor_confidence REAL NOT NULL DEFAULT 0.0,
  device_type_confidence REAL NOT NULL DEFAULT 0.0,
  os_confidence REAL NOT NULL DEFAULT 0.0,
  model_confidence REAL NOT NULL DEFAULT 0.0,
  private_mac INTEGER NOT NULL DEFAULT 0 CHECK(private_mac IN (0, 1)),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  UNIQUE(gateway_id, mac)
);
CREATE INDEX IF NOT EXISTS devices_gateway_last_seen ON devices(gateway_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS device_addresses (
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ip BLOB NOT NULL,
  ip_version INTEGER NOT NULL CHECK(ip_version IN (4, 6)),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  application_id TEXT,
  application_confidence REAL NOT NULL DEFAULT 0.0,
  application_source TEXT,
  application_last_seen INTEGER,
  PRIMARY KEY(device_id, ip)
);
CREATE INDEX IF NOT EXISTS device_addresses_ip ON device_addresses(ip);

CREATE TABLE IF NOT EXISTS device_evidence (
  gateway_id TEXT NOT NULL,
  mac BLOB NOT NULL CHECK(length(mac) = 6),
  source TEXT NOT NULL CHECK(source <> ''),
  field TEXT NOT NULL CHECK(field IN ('vendor', 'device_type', 'os_family', 'model', 'private_mac', 'observation')),
  value TEXT NOT NULL CHECK(value <> ''),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  hit_count INTEGER NOT NULL DEFAULT 1 CHECK(hit_count > 0),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json)),
  PRIMARY KEY(gateway_id, mac, source, field, value),
  FOREIGN KEY(gateway_id, mac) REFERENCES devices(gateway_id, mac) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_evidence_device_last_seen ON device_evidence(gateway_id, mac, last_seen DESC);

CREATE TABLE IF NOT EXISTS dns_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  client_ip BLOB NOT NULL,
  domain TEXT NOT NULL,
  answer_ip BLOB NOT NULL,
  record_type INTEGER NOT NULL,
  ttl INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_observations_expires_at ON dns_observations(expires_at);
CREATE INDEX IF NOT EXISTS dns_observations_lookup ON dns_observations(gateway_id, client_ip, answer_ip, observed_at);

CREATE TABLE IF NOT EXISTS self_host_endpoint_evidence (
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  ip BLOB NOT NULL,
  protocol INTEGER NOT NULL,
  port INTEGER NOT NULL,
  application_id TEXT NOT NULL,
  confidence REAL NOT NULL,
  source TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(gateway_id, ip, protocol, port, application_id)
);
CREATE INDEX IF NOT EXISTS self_host_endpoint_evidence_expiry ON self_host_endpoint_evidence(gateway_id, ip, expires_at);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_batches (
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  boot_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  PRIMARY KEY(gateway_id, boot_id, sequence)
);

CREATE TABLE IF NOT EXISTS active_flow_sessions (
  id TEXT PRIMARY KEY,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  ip_version INTEGER NOT NULL,
  protocol INTEGER NOT NULL,
  client_ip BLOB NOT NULL,
  client_port INTEGER NOT NULL,
  remote_ip BLOB NOT NULL,
  remote_port INTEGER NOT NULL,
  direction INTEGER NOT NULL,
  domain TEXT,
  application_id TEXT,
  category_id TEXT,
  traffic_role TEXT,
  protocol_id TEXT,
  organization_id TEXT,
  organization_confidence REAL,
  application_confidence REAL,
  protocol_confidence REAL,
  classification_confidence REAL,
  classification_reason TEXT,
  classification_evidence_json TEXT NOT NULL DEFAULT '[]',
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ended_at INTEGER,
  checkpointed_at INTEGER NOT NULL,
  scope INTEGER NOT NULL DEFAULT 4,
  path_type INTEGER NOT NULL DEFAULT 4,
  nat INTEGER NOT NULL DEFAULT 5,
  source_segment TEXT NOT NULL DEFAULT '',
  destination_segment TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS active_flow_sessions_last_seen_at ON active_flow_sessions(last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_organization_last_seen ON active_flow_sessions(organization_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_protocol_last_seen ON active_flow_sessions(protocol_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_remote_last_seen ON active_flow_sessions(remote_ip, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_application_last_seen ON active_flow_sessions(application_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_device_last_seen ON active_flow_sessions(device_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_port_last_seen_remote ON active_flow_sessions(remote_port, last_seen_at, remote_ip);
CREATE INDEX IF NOT EXISTS active_flow_sessions_role_category_client_last_seen ON active_flow_sessions(traffic_role, category_id, client_ip, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_client_protocol_last_seen ON active_flow_sessions(client_ip, protocol_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_client_remote_protocol_last_seen ON active_flow_sessions(client_ip, remote_ip, protocol_id, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_client_remote_proto_last_seen ON active_flow_sessions(client_ip, remote_ip, protocol, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_scope_last_seen ON active_flow_sessions(scope, last_seen_at);
CREATE INDEX IF NOT EXISTS active_flow_sessions_scope_path_nat ON active_flow_sessions(scope, path_type, nat);

CREATE TABLE IF NOT EXISTS analytics_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  boot_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(gateway_id, boot_id, sequence)
);
CREATE INDEX IF NOT EXISTS analytics_outbox_created_at ON analytics_outbox(created_at);

INSERT OR IGNORE INTO sites(id, name, created_at)
VALUES ('default', 'default', CAST(unixepoch('subsec') * 1000 AS INTEGER));
