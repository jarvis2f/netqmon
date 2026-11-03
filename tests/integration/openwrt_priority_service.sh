#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/agent" <<'SH'
#!/bin/sh
echo 'netqmon-agent 1.2.3'
SH
cat > "$work/priority" <<'SH'
#!/bin/sh
echo "netqmon-agent ${PRIORITY_VERSION:-1.2.3}"
SH
chmod +x "$work/agent" "$work/priority"
mkdir -p "$work/bin"
cat > "$work/bin/opkg" <<'SH'
#!/bin/sh
case "$2" in
    netqmon-agent) echo "netqmon-agent - ${BASE_PACKAGE_VERSION:-1.2.3-r1}" ;;
    netqmon-agent-priority) echo "netqmon-agent-priority - ${PRIORITY_PACKAGE_VERSION:-1.2.3-r1}" ;;
esac
SH
chmod +x "$work/bin/opkg"
export PATH="$work/bin:$PATH"

# Exercise the real init script with only UCI/procd calls stubbed.
source "$root_dir/packaging/openwrt/files/etc/init.d/netqmon"
PROG="$work/agent"
PRIORITY_PROG="$work/priority"
config_load() { :; }
config_list_foreach() { :; }
config_get_bool() {
    local value="${4:-0}"
    [[ "$3" != policy_client_total_enabled ]] || value="$case_enabled"
    printf -v "$1" '%s' "$value"
}
config_get() {
    local value="${4:-}"
    [[ "$3" != token ]] || value="test-token"
    printf -v "$1" '%s' "$value"
}
logger() { :; }
procd_open_instance() { :; }
procd_close_instance() { :; }
procd_append_param() { :; }
procd_set_param() { [[ "$1" != command ]] || chosen="$2"; return 0; }

case_enabled=0
chosen=
start_service
[[ "$chosen" == "$PROG" ]]
case_enabled=1
chosen=
start_service
[[ "$chosen" == "$PRIORITY_PROG" ]]
export PRIORITY_VERSION=1.2.4
chosen=
start_service
[[ "$chosen" == "$PROG" ]]
unset PRIORITY_VERSION
export PRIORITY_PACKAGE_VERSION=1.2.3-r2
chosen=
start_service
[[ "$chosen" == "$PROG" ]]
unset PRIORITY_PACKAGE_VERSION
chosen=
start_service
[[ "$chosen" == "$PRIORITY_PROG" ]]
rm "$work/bin/opkg"
cat > "$work/bin/apk" <<'SH'
#!/bin/sh
case "$3" in
    netqmon-agent) echo "netqmon-agent-${BASE_PACKAGE_VERSION:-1.2.3-r1}" ;;
    netqmon-agent-priority) echo "netqmon-agent-priority-${PRIORITY_PACKAGE_VERSION:-1.2.3-r1}" ;;
esac
SH
chmod +x "$work/bin/apk"
chosen=
start_service
[[ "$chosen" == "$PRIORITY_PROG" ]]
export PRIORITY_PACKAGE_VERSION=1.2.3-r2
chosen=
start_service
[[ "$chosen" == "$PROG" ]]
unset PRIORITY_PACKAGE_VERSION
rm "$PRIORITY_PROG"
chosen=
start_service
[[ "$chosen" == "$PROG" ]]
cmp "$root_dir/packaging/openwrt/files/etc/init.d/netqmon" \
    "$root_dir/packaging/openwrt/netqmon/files/etc/init.d/netqmon"
cp "$PROG" "$PRIORITY_PROG"
NETQMON_PRIORITY_BINARY_PATH="$PRIORITY_PROG" \
    bash "$root_dir/packaging/openwrt/build-ipk.sh" "$PROG" x86_64 1.2.3 "$work/packages" >/dev/null
python3 - "$work/packages" <<'PY'
import io
import sys
import tarfile
from pathlib import Path

root = Path(sys.argv[1])
with tarfile.open(root / "netqmon-agent-priority_1.2.3_x86_64.ipk", "r:gz") as outer:
    with tarfile.open(fileobj=io.BytesIO(outer.extractfile("./control.tar.gz").read()), mode="r:gz") as control:
        metadata = control.extractfile("./control").read().decode()
        assert "Package: netqmon-agent-priority\n" in metadata
        assert "Depends: netqmon-agent, ethtool\n" in metadata
    with tarfile.open(fileobj=io.BytesIO(outer.extractfile("./data.tar.gz").read()), mode="r:gz") as data:
        assert data.getmember("./usr/bin/netqmon-agent-priority").isfile()
PY
echo 'OpenWrt priority service selection passed.'
