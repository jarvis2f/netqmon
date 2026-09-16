#!/usr/bin/env bash
set -euo pipefail

collector=${1:?collector binary is required}
loadgen=${2:?loadgen binary is required}
agent=${3:-}
mock_classifier=${4:?mock classifier binary is required}

base_port=${NETQMON_PHASE22_BASE_PORT:-$((18000 + RANDOM % 1000))}
public_address=${NETQMON_PHASE22_PUBLIC_ADDR:-127.0.0.1:${base_port}}
internal_address=${NETQMON_PHASE22_INTERNAL_ADDR:-127.0.0.1:$((base_port + 1))}
enrollment_token=${NETQMON_PHASE22_ENROLLMENT_TOKEN:-phase22-e2e-token}
temporary_directory=$(mktemp -d)
log_file=${temporary_directory}/collector.log
mock_log_file=${temporary_directory}/mock-classifierd.log
database_path=${temporary_directory}/netqmon.db
analytics_path=${temporary_directory}/netqmon-analytics.duckdb
classifier_socket=${temporary_directory}/classifierd.sock
collector_pid=
mock_classifier_pid=

cleanup() {
  if [[ -n "${collector_pid}" ]]; then
    kill "${collector_pid}" 2>/dev/null || true
    wait "${collector_pid}" 2>/dev/null || true
  fi
  if [[ -n "${mock_classifier_pid}" ]]; then
    kill "${mock_classifier_pid}" 2>/dev/null || true
    wait "${mock_classifier_pid}" 2>/dev/null || true
  fi
  rm -rf "${temporary_directory}"
}
trap cleanup EXIT

fail() {
  echo "Phase 22 E2E failed: $*" >&2
  sed -n '1,220p' "${log_file}" >&2 || true
  exit 1
}

start_collector() {
  NETQMON_COLLECTOR_PUBLIC_ADDR=${public_address} \
  NETQMON_COLLECTOR_INTERNAL_ADDR=${internal_address} \
  NETQMON_COLLECTOR_ENROLLMENT_TOKEN=${enrollment_token} \
  NETQMON_COLLECTOR_DATABASE_PATH=${database_path} \
  NETQMON_DUCKDB_PATH=${analytics_path} \
  NETQMON_CLASSIFIER_SOCKET=${classifier_socket} \
  NETQMON_LICENSE_STATE_PATH=${temporary_directory}/license.json \
    "${collector}" >>"${log_file}" 2>&1 &
  collector_pid=$!
}

start_mock_classifier() {
  "${mock_classifier}" --socket "${classifier_socket}" >"${mock_log_file}" 2>&1 &
  mock_classifier_pid=$!
  for _ in $(seq 1 50); do
    if [[ -S "${classifier_socket}" ]]; then
      return 0
    fi
    if ! kill -0 "${mock_classifier_pid}" 2>/dev/null; then
      cat "${mock_log_file}" >&2
      return 1
    fi
    sleep 0.1
  done
  cat "${mock_log_file}" >&2
  return 1
}

stop_collector() {
  if [[ -n "${collector_pid}" ]]; then
    kill "${collector_pid}" 2>/dev/null || true
    wait "${collector_pid}" 2>/dev/null || true
    collector_pid=
  fi
}

wait_for_collector() {
  for _ in $(seq 1 80); do
    if curl --fail --silent "http://${public_address}/health" >/dev/null &&
       curl --fail --silent "http://${internal_address}/internal/health" >/dev/null; then
      return 0
    fi
    if ! kill -0 "${collector_pid}" 2>/dev/null; then
      fail "collector exited before health checks passed"
    fi
    sleep 0.1
  done
  fail "collector health checks did not pass"
}

start_mock_classifier || fail "mock classifierd did not start"
start_collector
wait_for_collector

"${loadgen}" "${public_address}" "${enrollment_token}" 4 \
  --scenario all \
  --boot-id phase22-e2e \
  --gateway-name phase22-loadgen || fail "loadgen failed"

python3 - "${internal_address}" <<'PY'
import json
import sys
import time
import urllib.request

base = f"http://{sys.argv[1]}"

def get(path):
    with urllib.request.urlopen(base + path, timeout=3) as response:
        payload = json.load(response)
    assert payload["schema_version"] == 1, (path, payload)
    return payload["data"]

overview = get("/internal/overview?limit=10&offset=0")
now = int(time.time() * 1000)
traffic_path = f"/internal/traffic?from={now - 86400000}&to={now + 60000}&limit=10&offset=0&scope=all"
traffic = get(traffic_path)
for _ in range(50):
    traffic_bytes = sum(point["upload_bytes"] + point["download_bytes"] for point in traffic["points"])
    if traffic_bytes == 132900:
        break
    time.sleep(0.1)
    traffic = get(traffic_path)
clients = get("/internal/clients?limit=10&offset=0")
applications = get("/internal/applications?limit=20&offset=0")
domains = get("/internal/domains?limit=20&offset=0")
flows = get("/internal/flows?from=0&to=9223372036854775807&limit=50")
for _ in range(50):
    if flows:
        break
    time.sleep(0.1)
    flows = get("/internal/flows?from=0&to=9223372036854775807&limit=50")

text = json.dumps(
    {
        "overview": overview,
        "traffic": traffic,
        "clients": clients,
        "applications": applications,
        "domains": domains,
        "flows": flows,
    },
    sort_keys=True,
)

for expected in [
    "loadgen-laptop",
    "loadgen-phone",
    "www.youtube.com",
    "github.com",
    "claude.ai",
    "youtube",
    "github",
    "bittorrent",
]:
    assert expected in text, expected

assert "2001:db8:22::10" in text or "20010db8002200000000000000000010" in text, text
assert "2001:db8:22::443" in text or "20010db8002200000000000000000443" in text, text
traffic_bytes = sum(point["upload_bytes"] + point["download_bytes"] for point in traffic["points"])
assert traffic_bytes == 132900, f"traffic_bytes={traffic_bytes}"
assert len(flows) == 4, f"flow_count={len(flows)}"
assert sum(":" in flow["client_ip"] or ":" in flow["remote_ip"] for flow in flows) == 1, flows
PY

python3 - "${database_path}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
gateway_count = connection.execute("SELECT COUNT(*) FROM gateways").fetchone()[0]
device_count = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
dns_count = connection.execute("SELECT COUNT(*) FROM dns_observations").fetchone()[0]
domains = {
    row[0] for row in connection.execute(
        "SELECT DISTINCT domain FROM dns_observations WHERE domain IS NOT NULL"
    )
}

assert gateway_count == 1, f"gateway_count={gateway_count}"
assert device_count >= 2, f"device_count={device_count}"
assert dns_count >= 12, f"dns_count={dns_count}"
assert {"www.youtube.com", "github.com", "claude.ai"}.issubset(domains), f"domains={sorted(domains)}"
assert not connection.execute(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND (name='flow_sessions' OR name GLOB 'traffic_*')"
).fetchone(), "analytics tables leaked into SQLite metadata"
PY

stop_collector
start_collector
wait_for_collector

python3 - "${database_path}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
gateway_count = connection.execute("SELECT COUNT(*) FROM gateways").fetchone()[0]
assert gateway_count == 1, f"gateway_count={gateway_count}"
PY

python3 - "${internal_address}" <<'PY'
import json
import sys
import time
import urllib.request

now = int(time.time() * 1000)
url = f"http://{sys.argv[1]}/internal/traffic?from={now - 86400000}&to={now + 60000}&limit=10&offset=0&scope=all"
for _ in range(50):
    with urllib.request.urlopen(url, timeout=3) as response:
        payload = json.load(response)
    traffic_bytes = sum(point["upload_bytes"] + point["download_bytes"] for point in payload["data"]["points"])
    if traffic_bytes == 132900:
        break
    time.sleep(0.1)
assert payload["schema_version"] == 1, payload
assert traffic_bytes == 132900, f"traffic_bytes={traffic_bytes}"
PY

if [[ -n "${agent}" && ${EUID} -eq 0 ]]; then
  bash tests/integration/tc_hook.sh "${agent}"
else
  echo "Agent restart test skipped; pass an agent binary and run as root to execute it"
fi

echo "Phase 22 synthetic full pipeline, IPv6, DNS, and restart E2E checks passed"
