-- Short-lived correction contributions and one recovery checkpoint per session.
CREATE TABLE flow_rollup_sessions (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  metadata_json TEXT NOT NULL,
  attribution_json TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  ended_at INTEGER
);
CREATE INDEX flow_rollup_sessions_updated ON flow_rollup_sessions(updated_at);
CREATE INDEX flow_rollup_sessions_ended ON flow_rollup_sessions(ended_at) WHERE ended_at IS NOT NULL;

CREATE TABLE flow_rollup_contributions (
  session_ref INTEGER NOT NULL REFERENCES flow_rollup_sessions(id) ON DELETE CASCADE,
  timestamp INTEGER NOT NULL,
  scope INTEGER NOT NULL,
  direction INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  remote_ip BLOB NOT NULL,
  protocol INTEGER NOT NULL,
  application_id TEXT NOT NULL,
  category_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  protocol_id TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  flow_count INTEGER NOT NULL,
  hour_upload INTEGER NOT NULL,
  hour_download INTEGER NOT NULL,
  hour_packets INTEGER NOT NULL,
  hour_flows INTEGER NOT NULL,
  day_upload INTEGER NOT NULL,
  day_download INTEGER NOT NULL,
  day_packets INTEGER NOT NULL,
  day_flows INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(session_ref, timestamp, scope, direction, device_id, remote_ip, protocol)
) WITHOUT ROWID;
CREATE INDEX flow_rollup_contributions_expiry ON flow_rollup_contributions(expires_at);
