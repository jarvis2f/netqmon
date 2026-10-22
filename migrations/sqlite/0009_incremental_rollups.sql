-- Persist only unmaterialized deltas. Retention deletes do not undo historical rollups.

CREATE TABLE traffic_total_hour_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id)
) WITHOUT ROWID;

INSERT INTO traffic_total_hour_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/3600000*3600000 AS timestamp,gateway_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_total_minute GROUP BY 1,2) s
LEFT JOIN traffic_total_hour t USING(timestamp,gateway_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_total_minute_pending_insert AFTER INSERT ON traffic_total_minute
BEGIN
    INSERT INTO traffic_total_hour_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_total_minute_pending_update AFTER UPDATE ON traffic_total_minute
BEGIN
    INSERT INTO traffic_total_hour_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/3600000*3600000,OLD.gateway_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_total_hour_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_device_hour_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,device_id)
) WITHOUT ROWID;

INSERT INTO traffic_device_hour_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.device_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/3600000*3600000 AS timestamp,gateway_id,device_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_device_minute GROUP BY 1,2,3) s
LEFT JOIN traffic_device_hour t USING(timestamp,gateway_id,device_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_device_minute_pending_insert AFTER INSERT ON traffic_device_minute
BEGIN
    INSERT INTO traffic_device_hour_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.device_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_device_minute_pending_update AFTER UPDATE ON traffic_device_minute
BEGIN
    INSERT INTO traffic_device_hour_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/3600000*3600000,OLD.gateway_id,OLD.device_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_device_hour_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.device_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_application_hour_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,application_id,category_id)
) WITHOUT ROWID;

INSERT INTO traffic_application_hour_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.application_id,s.category_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/3600000*3600000 AS timestamp,gateway_id,application_id,category_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_application_minute GROUP BY 1,2,3,4) s
LEFT JOIN traffic_application_hour t USING(timestamp,gateway_id,application_id,category_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_application_minute_pending_insert AFTER INSERT ON traffic_application_minute
BEGIN
    INSERT INTO traffic_application_hour_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.application_id,NEW.category_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_application_minute_pending_update AFTER UPDATE ON traffic_application_minute
BEGIN
    INSERT INTO traffic_application_hour_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/3600000*3600000,OLD.gateway_id,OLD.application_id,OLD.category_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_application_hour_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.application_id,NEW.category_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_domain_hour_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,domain)
) WITHOUT ROWID;

INSERT INTO traffic_domain_hour_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.domain,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/3600000*3600000 AS timestamp,gateway_id,domain,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_domain_minute GROUP BY 1,2,3) s
LEFT JOIN traffic_domain_hour t USING(timestamp,gateway_id,domain)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_domain_minute_pending_insert AFTER INSERT ON traffic_domain_minute
BEGIN
    INSERT INTO traffic_domain_hour_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.domain,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_domain_minute_pending_update AFTER UPDATE ON traffic_domain_minute
BEGIN
    INSERT INTO traffic_domain_hour_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/3600000*3600000,OLD.gateway_id,OLD.domain,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_domain_hour_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.domain,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_destination_hour_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    remote_ip BLOB NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,remote_ip)
) WITHOUT ROWID;

INSERT INTO traffic_destination_hour_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.remote_ip,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/3600000*3600000 AS timestamp,gateway_id,remote_ip,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_destination_minute GROUP BY 1,2,3) s
LEFT JOIN traffic_destination_hour t USING(timestamp,gateway_id,remote_ip)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_destination_minute_pending_insert AFTER INSERT ON traffic_destination_minute
BEGIN
    INSERT INTO traffic_destination_hour_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.remote_ip,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_destination_minute_pending_update AFTER UPDATE ON traffic_destination_minute
BEGIN
    INSERT INTO traffic_destination_hour_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/3600000*3600000,OLD.gateway_id,OLD.remote_ip,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_destination_hour_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/3600000*3600000,NEW.gateway_id,NEW.remote_ip,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_total_day_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id)
) WITHOUT ROWID;

INSERT INTO traffic_total_day_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/86400000*86400000 AS timestamp,gateway_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_total_hour GROUP BY 1,2) s
LEFT JOIN traffic_total_day t USING(timestamp,gateway_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_total_hour_pending_insert AFTER INSERT ON traffic_total_hour
BEGIN
    INSERT INTO traffic_total_day_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_total_hour_pending_update AFTER UPDATE ON traffic_total_hour
BEGIN
    INSERT INTO traffic_total_day_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/86400000*86400000,OLD.gateway_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_total_day_pending(timestamp,gateway_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_device_day_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,device_id)
) WITHOUT ROWID;

INSERT INTO traffic_device_day_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.device_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/86400000*86400000 AS timestamp,gateway_id,device_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_device_hour GROUP BY 1,2,3) s
LEFT JOIN traffic_device_day t USING(timestamp,gateway_id,device_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_device_hour_pending_insert AFTER INSERT ON traffic_device_hour
BEGIN
    INSERT INTO traffic_device_day_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.device_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_device_hour_pending_update AFTER UPDATE ON traffic_device_hour
BEGIN
    INSERT INTO traffic_device_day_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/86400000*86400000,OLD.gateway_id,OLD.device_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_device_day_pending(timestamp,gateway_id,device_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.device_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,device_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_application_day_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,application_id,category_id)
) WITHOUT ROWID;

INSERT INTO traffic_application_day_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.application_id,s.category_id,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/86400000*86400000 AS timestamp,gateway_id,application_id,category_id,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_application_hour GROUP BY 1,2,3,4) s
LEFT JOIN traffic_application_day t USING(timestamp,gateway_id,application_id,category_id)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_application_hour_pending_insert AFTER INSERT ON traffic_application_hour
BEGIN
    INSERT INTO traffic_application_day_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.application_id,NEW.category_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_application_hour_pending_update AFTER UPDATE ON traffic_application_hour
BEGIN
    INSERT INTO traffic_application_day_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/86400000*86400000,OLD.gateway_id,OLD.application_id,OLD.category_id,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_application_day_pending(timestamp,gateway_id,application_id,category_id,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.application_id,NEW.category_id,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,application_id,category_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_domain_day_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,domain)
) WITHOUT ROWID;

INSERT INTO traffic_domain_day_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.domain,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/86400000*86400000 AS timestamp,gateway_id,domain,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_domain_hour GROUP BY 1,2,3) s
LEFT JOIN traffic_domain_day t USING(timestamp,gateway_id,domain)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_domain_hour_pending_insert AFTER INSERT ON traffic_domain_hour
BEGIN
    INSERT INTO traffic_domain_day_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.domain,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_domain_hour_pending_update AFTER UPDATE ON traffic_domain_hour
BEGIN
    INSERT INTO traffic_domain_day_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/86400000*86400000,OLD.gateway_id,OLD.domain,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_domain_day_pending(timestamp,gateway_id,domain,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.domain,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,domain) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TABLE traffic_destination_day_pending (
    timestamp INTEGER NOT NULL,
    gateway_id TEXT NOT NULL,
    remote_ip BLOB NOT NULL,
    upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(timestamp,gateway_id,remote_ip)
) WITHOUT ROWID;

INSERT INTO traffic_destination_day_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count)
SELECT s.timestamp,s.gateway_id,s.remote_ip,MAX(s.upload_bytes-COALESCE(t.upload_bytes,0),0),MAX(s.download_bytes-COALESCE(t.download_bytes,0),0),MAX(s.packets-COALESCE(t.packets,0),0),MAX(s.flow_count-COALESCE(t.flow_count,0),0)
FROM (SELECT timestamp/86400000*86400000 AS timestamp,gateway_id,remote_ip,SUM(upload_bytes) AS upload_bytes,SUM(download_bytes) AS download_bytes,SUM(packets) AS packets,SUM(flow_count) AS flow_count FROM traffic_destination_hour GROUP BY 1,2,3) s
LEFT JOIN traffic_destination_day t USING(timestamp,gateway_id,remote_ip)
WHERE s.upload_bytes>COALESCE(t.upload_bytes,0) OR s.download_bytes>COALESCE(t.download_bytes,0) OR s.packets>COALESCE(t.packets,0) OR s.flow_count>COALESCE(t.flow_count,0);

CREATE TRIGGER traffic_destination_hour_pending_insert AFTER INSERT ON traffic_destination_hour
BEGIN
    INSERT INTO traffic_destination_day_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.remote_ip,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;

CREATE TRIGGER traffic_destination_hour_pending_update AFTER UPDATE ON traffic_destination_hour
BEGIN
    INSERT INTO traffic_destination_day_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (OLD.timestamp/86400000*86400000,OLD.gateway_id,OLD.remote_ip,-OLD.upload_bytes,-OLD.download_bytes,-OLD.packets,-OLD.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
    INSERT INTO traffic_destination_day_pending(timestamp,gateway_id,remote_ip,upload_bytes,download_bytes,packets,flow_count) VALUES (NEW.timestamp/86400000*86400000,NEW.gateway_id,NEW.remote_ip,NEW.upload_bytes,NEW.download_bytes,NEW.packets,NEW.flow_count)
    ON CONFLICT(timestamp,gateway_id,remote_ip) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,packets=packets+excluded.packets,flow_count=flow_count+excluded.flow_count;
END;
