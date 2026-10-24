-- Cover destination distinct counts without looking up the wide scope table.
-- Keep mutable counters out of secondary indexes: every telemetry batch
-- updates them, and indexing them would amplify WAL writes.
DROP INDEX IF EXISTS traffic_scope_minute_scope_timestamp;
CREATE INDEX traffic_scope_minute_scope_timestamp ON traffic_scope_minute(
    scope, timestamp, remote_ip
);
