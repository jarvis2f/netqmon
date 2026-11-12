DROP INDEX IF EXISTS flow_sessions_application_last_seen;
CREATE INDEX flow_sessions_application_last_seen
    ON flow_sessions(application_id, last_seen_at, protocol_id, device_id);
