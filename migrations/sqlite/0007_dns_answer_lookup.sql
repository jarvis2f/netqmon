-- Cross-address DNS attribution knows the answer IP before the client's other
-- addresses. Bound the search to that answer instead of scanning gateway history.
CREATE INDEX IF NOT EXISTS dns_observations_answer_lookup
  ON dns_observations(gateway_id, answer_ip, observed_at DESC, id DESC);
