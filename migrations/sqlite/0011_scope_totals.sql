-- Keep chart totals independent of the number of client/application/domain rows.
-- source_rows preserves zero-byte observations and exact timestamp/retention semantics.
CREATE TABLE traffic_scope_total_minute (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    scope INTEGER NOT NULL,
    direction INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    source_rows INTEGER NOT NULL,
    PRIMARY KEY(scope, timestamp, direction, gateway_id)
) WITHOUT ROWID;

INSERT INTO traffic_scope_total_minute
SELECT timestamp, gateway_id, scope, direction,
       SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count), COUNT(*)
FROM traffic_scope_minute GROUP BY scope, timestamp, direction, gateway_id;

-- All-scope charts and retention filter by time without a scope equality.
CREATE INDEX traffic_scope_total_minute_timestamp ON traffic_scope_total_minute(timestamp);

CREATE TRIGGER traffic_scope_total_insert AFTER INSERT ON traffic_scope_minute
BEGIN
    INSERT INTO traffic_scope_total_minute
    VALUES (NEW.timestamp, NEW.gateway_id, NEW.scope, NEW.direction,
            NEW.upload_bytes, NEW.download_bytes, NEW.packets, NEW.flow_count, 1)
    ON CONFLICT(scope, timestamp, direction, gateway_id) DO UPDATE SET
        upload_bytes = upload_bytes + excluded.upload_bytes,
        download_bytes = download_bytes + excluded.download_bytes,
        packets = packets + excluded.packets,
        flow_count = flow_count + excluded.flow_count,
        source_rows = source_rows + 1;
END;

CREATE TRIGGER traffic_scope_total_counters AFTER UPDATE ON traffic_scope_minute
WHEN OLD.timestamp = NEW.timestamp AND OLD.gateway_id = NEW.gateway_id
 AND OLD.scope = NEW.scope AND OLD.direction = NEW.direction
 AND (OLD.upload_bytes != NEW.upload_bytes OR OLD.download_bytes != NEW.download_bytes
      OR OLD.packets != NEW.packets OR OLD.flow_count != NEW.flow_count)
BEGIN
    UPDATE traffic_scope_total_minute SET
        upload_bytes = upload_bytes + NEW.upload_bytes - OLD.upload_bytes,
        download_bytes = download_bytes + NEW.download_bytes - OLD.download_bytes,
        packets = packets + NEW.packets - OLD.packets,
        flow_count = flow_count + NEW.flow_count - OLD.flow_count
    WHERE scope = OLD.scope AND timestamp = OLD.timestamp
      AND direction = OLD.direction AND gateway_id = OLD.gateway_id;
END;

CREATE TRIGGER traffic_scope_total_move AFTER UPDATE ON traffic_scope_minute
WHEN OLD.timestamp != NEW.timestamp OR OLD.gateway_id != NEW.gateway_id
  OR OLD.scope != NEW.scope OR OLD.direction != NEW.direction
BEGIN
    UPDATE traffic_scope_total_minute SET
        upload_bytes = upload_bytes - OLD.upload_bytes,
        download_bytes = download_bytes - OLD.download_bytes,
        packets = packets - OLD.packets,
        flow_count = flow_count - OLD.flow_count,
        source_rows = source_rows - 1
    WHERE scope = OLD.scope AND timestamp = OLD.timestamp
      AND direction = OLD.direction AND gateway_id = OLD.gateway_id;
    DELETE FROM traffic_scope_total_minute
    WHERE scope = OLD.scope AND timestamp = OLD.timestamp
      AND direction = OLD.direction AND gateway_id = OLD.gateway_id AND source_rows = 0;
    INSERT INTO traffic_scope_total_minute
    VALUES (NEW.timestamp, NEW.gateway_id, NEW.scope, NEW.direction,
            NEW.upload_bytes, NEW.download_bytes, NEW.packets, NEW.flow_count, 1)
    ON CONFLICT(scope, timestamp, direction, gateway_id) DO UPDATE SET
        upload_bytes = upload_bytes + excluded.upload_bytes,
        download_bytes = download_bytes + excluded.download_bytes,
        packets = packets + excluded.packets,
        flow_count = flow_count + excluded.flow_count,
        source_rows = source_rows + 1;
END;

CREATE TRIGGER traffic_scope_total_delete AFTER DELETE ON traffic_scope_minute
BEGIN
    UPDATE traffic_scope_total_minute SET
        upload_bytes = upload_bytes - OLD.upload_bytes,
        download_bytes = download_bytes - OLD.download_bytes,
        packets = packets - OLD.packets,
        flow_count = flow_count - OLD.flow_count,
        source_rows = source_rows - 1
    WHERE scope = OLD.scope AND timestamp = OLD.timestamp
      AND direction = OLD.direction AND gateway_id = OLD.gateway_id;
    DELETE FROM traffic_scope_total_minute
    WHERE scope = OLD.scope AND timestamp = OLD.timestamp
      AND direction = OLD.direction AND gateway_id = OLD.gateway_id AND source_rows = 0;
END;
