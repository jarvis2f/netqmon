-- Late DPI identifies one bidirectional tuple and an overlapping lifetime.
CREATE INDEX flow_sessions_sample_lookup ON flow_sessions(
    gateway_id, ip_version, protocol, client_ip, client_port, remote_ip, remote_port, last_seen_at
);
-- Only open checkpoints need stale-state recovery/expiration.
CREATE INDEX flow_sessions_open_checkpoint ON flow_sessions(checkpointed_at)
    WHERE ended_at IS NULL;
