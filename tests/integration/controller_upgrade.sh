#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

image_old="${NETQMON_UPGRADE_OLD_IMAGE:-ghcr.io/jarvis2f/netqmon:latest}"
image_new="${NETQMON_UPGRADE_NEW_IMAGE:-netqmon-controller:phase21}"
volume="${NETQMON_UPGRADE_VOLUME:-netqmon_phase21_upgrade_data}"
container_old="netqmon-upgrade-old"
container_new="netqmon-upgrade-new"
token="${NETQMON_COLLECTOR_ENROLLMENT_TOKEN:-netqmon-upgrade-test-token}"

cleanup() {
  docker rm -f "$container_old" "$container_new" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null

cleanup
docker run -d \
  --name "$container_old" \
  -e NETQMON_COLLECTOR_ENROLLMENT_TOKEN="$token" \
  -e NETQMON_COLLECTOR_DATABASE_PATH=/var/lib/netqmon/netqmon.db \
  -v "$volume":/var/lib/netqmon \
  "$image_old" >/dev/null

sleep 5
docker exec "$container_old" test -f /var/lib/netqmon/netqmon.db
docker stop "$container_old" >/dev/null

docker run -d \
  --name "$container_new" \
  -e NETQMON_COLLECTOR_ENROLLMENT_TOKEN="$token" \
  -e NETQMON_COLLECTOR_DATABASE_PATH=/data/netqmon.db \
  -v "$volume":/data \
  "$image_new" >/dev/null

sleep 8
docker exec "$container_new" wget -q -O - http://127.0.0.1:8091/internal/health | grep -q '^ok$'
docker exec "$container_new" test -f /data/netqmon.db

echo "controller upgrade smoke test passed"
