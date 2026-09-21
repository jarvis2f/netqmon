#!/bin/sh
set -eu

mkdir -p /data/geo /data/backups /run/netqmon

runtime_db_path="${NETQMON_COLLECTOR_DATABASE_PATH:-/data/netqmon.db}"
runtime_db_parent=$(dirname "$runtime_db_path")
runtime_db_tmp="${runtime_db_path}.new"
demo_template_path="${NETQMON_DEMO_DATABASE_TEMPLATE:-/demo/netqmon-demo.db}"

mkdir -p "$runtime_db_parent"

echo "[INFO] Initializing Netqmon Demo database..."
rm -f "$runtime_db_tmp" "$runtime_db_tmp-wal" "$runtime_db_tmp-shm"

if [ -f "$demo_template_path" ]; then
  echo "[INFO] Validating demo database template $demo_template_path..."
  python3 /usr/local/bin/validate-demo-db.py "$demo_template_path"
  echo "[INFO] Copying validated demo database template..."
  cp "$demo_template_path" "$runtime_db_tmp"
elif [ -f "/app/netqmon-demo-template.db" ]; then
  echo "[INFO] Validating bundled demo database template..."
  python3 /usr/local/bin/validate-demo-db.py /app/netqmon-demo-template.db
  cp /app/netqmon-demo-template.db "$runtime_db_tmp"
elif [ -f "/usr/local/bin/generate-demo-db.py" ]; then
  echo "[INFO] No database template found; generating fresh synthetic demo database..."
  python3 /usr/local/bin/generate-demo-db.py --output "$runtime_db_tmp"
  python3 /usr/local/bin/validate-demo-db.py "$runtime_db_tmp"
else
  echo "[ERROR] No demo database template or generator is available" >&2
  exit 1
fi

test -s "$runtime_db_tmp"
mv "$runtime_db_tmp" "$runtime_db_path"
rm -f "$runtime_db_path-wal" "$runtime_db_path-shm"

export NETQMON_DEMO_MODE=true

shutdown() {
  terminating=1
  trap - INT TERM
  echo "[INFO] Shutting down demo services..."
  if [ -n "${collector_pid:-}" ] && kill -0 "$collector_pid" 2>/dev/null; then
    kill -TERM "$collector_pid" 2>/dev/null || true
  fi
  if [ -n "${next_pid:-}" ] && kill -0 "$next_pid" 2>/dev/null; then
    kill -TERM "$next_pid" 2>/dev/null || true
  fi
}

trap shutdown INT TERM
terminating=0

echo "[INFO] Starting netqmon-collector in demo mode..."
netqmon-collector &
collector_pid="$!"

echo "[INFO] Starting Next.js controller-ui..."
node /app/apps/controller-ui/server.js &
next_pid="$!"

while :; do
  if ! kill -0 "$collector_pid" 2>/dev/null; then
    if [ "$terminating" -eq 1 ]; then
      wait "$collector_pid" || true
      wait "$next_pid" || true
      exit 0
    fi
    echo "[ERROR] netqmon-collector exited unexpectedly"
    wait "$collector_pid" || exit $?
    exit 1
  fi
  if ! kill -0 "$next_pid" 2>/dev/null; then
    if [ "$terminating" -eq 1 ]; then
      wait "$collector_pid" || true
      wait "$next_pid" || true
      exit 0
    fi
    echo "[ERROR] controller-ui server exited unexpectedly"
    wait "$next_pid" || exit $?
    exit 1
  fi
  sleep 1
done
