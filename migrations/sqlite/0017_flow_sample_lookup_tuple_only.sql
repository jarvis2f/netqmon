-- Late-DPI matching uses the complete five-tuple to find overlapping sessions.
-- last_seen_at is checked after the tuple seek; keeping it in this index causes
-- an index rewrite on every flow update and duplicates a time filter available
-- through other indexes.
DROP INDEX flow_sessions_sample_lookup;
CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
    gateway_id, ip_version, protocol, client_ip, client_port,
    remote_ip, remote_port
);
