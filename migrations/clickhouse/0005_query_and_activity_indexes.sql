ALTER TABLE dns_observations
ADD PROJECTION IF NOT EXISTS dns_lookup_by_client_answer
(
    SELECT gateway_id, client_ip, answer_ip, observed_at, id, expires_at, domain
    ORDER BY (gateway_id, client_ip, answer_ip, observed_at, id)
);

ALTER TABLE dns_observations
MATERIALIZE PROJECTION dns_lookup_by_client_answer;

CREATE TABLE IF NOT EXISTS device_traffic_activity (
    gateway_id String,
    device_id Int64,
    last_traffic_seen Int64
) ENGINE = ReplacingMergeTree(last_traffic_seen)
ORDER BY (gateway_id, device_id);
