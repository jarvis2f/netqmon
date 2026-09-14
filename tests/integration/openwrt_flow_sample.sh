#!/bin/sh
set -eu
work=/tmp/netqmon-dpi-check
mkdir -p "$work/www"
chmod 700 "$work"
agent_pid=
server_pid=
credential=/etc/netqmon/credentials.toml
restore_credential=false
cleanup() {
    code=$?
    [ -z "$agent_pid" ] || { kill "$agent_pid" 2>/dev/null || true; wait "$agent_pid" 2>/dev/null || true; }
    [ -z "$server_pid" ] || { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
    ip netns del nqm-dpi-check 2>/dev/null || true
    ip link del nqm-dpi-check 2>/dev/null || true
    if [ "$restore_credential" = true ]; then
        mv "$work/original-credentials.toml" "$credential"
    else
        rm -f "$credential"
    fi
    exit "$code"
}
# Refuse to interfere with a running Agent or an existing test namespace.
if [ -f "$work/original-credentials.toml" ]; then echo 'Unrestored test credentials exist' >&2; exit 1; fi
if pidof netqmon-agent >/dev/null; then echo 'An Agent is already running' >&2; exit 1; fi
if ip link show nqm-dpi-check >/dev/null 2>&1; then echo 'Test interface exists' >&2; exit 1; fi
if ip netns exec nqm-dpi-check true 2>/dev/null; then echo 'Test namespace exists' >&2; exit 1; fi
if [ -f "$credential" ]; then mv "$credential" "$work/original-credentials.toml"; restore_credential=true; fi
trap cleanup EXIT INT TERM
ip link add nqm-dpi-check type veth peer name nqm-dpi-peer
ip netns add nqm-dpi-check
ip link set nqm-dpi-peer netns nqm-dpi-check
ip addr add 192.0.2.1/24 dev nqm-dpi-check
ip link set nqm-dpi-check up
ip -6 addr add fd42:6e71::1/64 dev nqm-dpi-check nodad
ip netns exec nqm-dpi-check ip addr add 192.0.2.2/24 dev nqm-dpi-peer
ip netns exec nqm-dpi-check ip link set nqm-dpi-peer up
ip netns exec nqm-dpi-check ip -6 addr add fd42:6e71::2/64 dev nqm-dpi-peer nodad
ip netns exec nqm-dpi-check ip link set lo up
# Isolated interfaces have no OpenWrt firewall zone for IPv6 neighbor discovery.
host_mac=$(cat /sys/class/net/nqm-dpi-check/address)
peer_mac=$(ip netns exec nqm-dpi-check cat /sys/class/net/nqm-dpi-peer/address)
ip -6 neigh replace fd42:6e71::2 lladdr "$peer_mac" nud permanent dev nqm-dpi-check
ip netns exec nqm-dpi-check ip -6 neigh replace fd42:6e71::1 lladdr "$host_mac" nud permanent dev nqm-dpi-peer
sleep 2
ip -6 addr show dev nqm-dpi-check > "$work/ipv6.log"
ip netns exec nqm-dpi-check ip -6 addr show dev nqm-dpi-peer >> "$work/ipv6.log"
: > "$work/httpd.conf"
dd if=/dev/zero of="$work/www/index.html" bs=1024 count=64 2>/dev/null
ip netns exec nqm-dpi-check uhttpd -f -p 192.0.2.2:8088 -p '[::]:8088' -h "$work/www" -c "$work/httpd.conf" > "$work/httpd.log" 2>&1 &
server_pid=$!
sleep 2
for enabled in false true; do
    NETQMON_TCP_IDLE_TIMEOUT_SECONDS=2 NETQMON_UDP_IDLE_TIMEOUT_SECONDS=2 \
      NETQMON_SAMPLE_ENABLED="$enabled" NETQMON_LOG_LEVEL=debug NETQMON_BATCH_INTERVAL_MS=1000 NETQMON_POLL_INTERVAL_MS=100 \
      NETQMON_TOKEN=openwrt-dpi-check NETQMON_CONTROLLER_URL=http://127.0.0.1:18094 \
      "$work/netqmon-agent" --interface nqm-dpi-check > "$work/agent-$enabled.log" 2>&1 &
    agent_pid=$!
    sleep 4
    kill -0 "$agent_pid"
    for count in 1 2 3; do
        curl --noproxy '*' --max-time 5 -fsS http://192.0.2.2:8088/index.html -o /dev/null
        curl --noproxy '*' --max-time 5 -g -fsS 'http://[fd42:6e71::2]:8088/index.html' -o /dev/null
    done
    sleep 3
    curl --max-time 5 -fsS http://127.0.0.1:18095/internal/settings/diagnostics > "$work/diagnostics-$enabled.json"
    kill -TERM "$agent_pid"; wait "$agent_pid"; agent_pid=
done
echo OPENWRT_SAMPLE_CAPTURE_OK
