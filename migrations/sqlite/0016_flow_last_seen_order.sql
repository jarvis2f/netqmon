DROP INDEX flow_sessions_last_seen_at;
CREATE INDEX flow_sessions_last_seen_at
    ON flow_sessions(last_seen_at DESC, id ASC);
