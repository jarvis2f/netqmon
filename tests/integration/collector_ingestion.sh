#!/usr/bin/env bash
set -euo pipefail

collector=${1:?collector binary is required}
loadgen=${2:?loadgen binary is required}
mock_classifier=${3:?mock classifier binary is required}
public_address=127.0.0.1:18090
internal_address=127.0.0.1:18091
enrollment_token=phase6-integration-token
temporary_directory=$(mktemp -d)
log_file=${temporary_directory}/collector.log
mock_log_file=${temporary_directory}/mock-classifierd.log
database_path=${temporary_directory}/netqmon.db
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

"${mock_classifier}" --socket "${classifier_socket}" >"${mock_log_file}" 2>&1 &
mock_classifier_pid=$!
for _ in $(seq 1 50); do
  if [[ -S "${classifier_socket}" ]]; then
    break
  fi
  if ! kill -0 "${mock_classifier_pid}" 2>/dev/null; then
    cat "${mock_log_file}"
    exit 1
  fi
  sleep 0.1
done
[[ -S "${classifier_socket}" ]] || { cat "${mock_log_file}"; exit 1; }

NETQMON_COLLECTOR_PUBLIC_ADDR=${public_address} \
NETQMON_COLLECTOR_INTERNAL_ADDR=${internal_address} \
NETQMON_COLLECTOR_ENROLLMENT_TOKEN=${enrollment_token} \
NETQMON_COLLECTOR_DATABASE_PATH=${database_path} \
NETQMON_CLASSIFIER_SOCKET=${classifier_socket} \
NETQMON_LICENSE_STATE_PATH=${temporary_directory}/license.json \
  "${collector}" >"${log_file}" 2>&1 &
collector_pid=$!

for _ in $(seq 1 50); do
  if curl --fail --silent "http://${public_address}/health" >/dev/null && \
     curl --fail --silent "http://${internal_address}/internal/health" >/dev/null; then
    break
  fi
  if ! kill -0 "${collector_pid}" 2>/dev/null; then
    cat "${log_file}"
    exit 1
  fi
  sleep 0.1
done

curl --fail --silent "http://${public_address}/health" >/dev/null
curl --fail --silent "http://${internal_address}/internal/health" >/dev/null
if command -v ss >/dev/null 2>&1; then
  ss -ltn | grep -F "127.0.0.1:18091" >/dev/null
elif command -v lsof >/dev/null 2>&1; then
  lsof -nP -iTCP:18091 -sTCP:LISTEN | grep -F "127.0.0.1:18091" >/dev/null
fi
if ! "${loadgen}" "${public_address}" "${enrollment_token}" 3 --scenario basic \
  --boot-id collector-ingestion-smoke; then
  cat "${log_file}"
  exit 1
fi

python3 - "${internal_address}" <<'PY'
import json
import sys
import urllib.request

base = f"http://{sys.argv[1]}"
paths = [
    "/internal/overview?limit=10&offset=0",
    "/internal/traffic?from=0&to=9223372036854775807&limit=10&offset=0",
    "/internal/clients?limit=10&offset=0",
    "/internal/applications?limit=10&offset=0",
    "/internal/domains?limit=10&offset=0",
    "/internal/destinations?limit=10&offset=0",
    "/internal/flows?limit=10",
]
for path in paths:
    with urllib.request.urlopen(base + path, timeout=2) as response:
        payload = json.load(response)
        assert payload["schema_version"] == 1, (path, payload)
        assert "data" in payload, (path, payload)

with urllib.request.urlopen(base + "/internal/realtime/stream", timeout=2) as response:
    assert response.readline().decode().strip() == "event: snapshot"
    assert response.readline().decode().startswith("data: {")
PY

kill "${collector_pid}"
wait "${collector_pid}" || true
collector_pid=

python3 - "${database_path}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
gateway_count = connection.execute("SELECT COUNT(*) FROM gateways").fetchone()[0]
traffic_bytes = connection.execute(
    "SELECT SUM(upload_bytes + download_bytes) FROM traffic_total_minute"
).fetchone()[0]
assert gateway_count == 1, gateway_count
assert traffic_bytes == 65700, traffic_bytes
PY

NETQMON_COLLECTOR_PUBLIC_ADDR=${public_address} \
NETQMON_COLLECTOR_INTERNAL_ADDR=${internal_address} \
NETQMON_COLLECTOR_ENROLLMENT_TOKEN=${enrollment_token} \
NETQMON_COLLECTOR_DATABASE_PATH=${database_path} \
NETQMON_CLASSIFIER_SOCKET=${classifier_socket} \
  "${collector}" >>"${log_file}" 2>&1 &
collector_pid=$!

for _ in $(seq 1 50); do
  if curl --fail --silent "http://${public_address}/health" >/dev/null; then
    echo "Collector restart preserved Gateway and synthetic traffic bytes"
    exit 0
  fi
  if ! kill -0 "${collector_pid}" 2>/dev/null; then
    cat "${log_file}"
    exit 1
  fi
  sleep 0.1
done

cat "${log_file}"
exit 1
