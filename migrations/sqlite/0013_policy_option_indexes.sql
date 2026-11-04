-- Policy selectors enumerate distinct known IDs per gateway. Keep these
-- indexes covering and exclude unclassified flows to limit storage and writes.
CREATE INDEX IF NOT EXISTS flow_sessions_policy_application ON flow_sessions(gateway_id, application_id)
WHERE application_id NOT IN ('unknown', '');

CREATE INDEX IF NOT EXISTS flow_sessions_policy_category ON flow_sessions(gateway_id, category_id)
WHERE category_id IS NOT NULL AND category_id != '' AND category_id != 'unknown';
