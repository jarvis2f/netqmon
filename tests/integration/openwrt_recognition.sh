#!/bin/sh
# Run after copying netqmon-agent, recognition-emit and test TLS cert/key to $work.
# The Collector must run on the authorized Debian test host.
set -eu
work=${NETQMON_TEST_WORK:-/tmp/netqmon-recognition-check}
collector=${NETQMON_TEST_COLLECTOR:-http://127.0.0.1:8090}
credential=/etc/netqmon/credentials.toml
agent_pid=
server_pid=
restore_credential=false
if pidof netqmon-agent >/dev/null; then echo 'Agent already running' >&2; exit 1; fi
if [ -f "$work/original-credentials.toml" ]; then echo 'Unrestored credentials exist' >&2; exit 1; fi
if ip link show nqm-rec-port >/dev/null 2>&1; then echo 'Test interface exists' >&2; exit 1; fi
if ip netns exec nqm-rec-client true 2>/dev/null; then echo 'Test namespace exists' >&2; exit 1; fi
if ip addr show | grep -q '192.0.2.1\|198.51.100.1\|fd42:6e71::1'; then echo 'Test addresses in use' >&2; exit 1; fi
mkdir -p "$work/www"
chmod 700 "$work"
cleanup() {
    code=$?
    [ -z "$agent_pid" ] || { kill "$agent_pid" 2>/dev/null || true; wait "$agent_pid" 2>/dev/null || true; }
    [ -z "$server_pid" ] || { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
    ip netns del nqm-rec-client 2>/dev/null || true
    ip link del nqm-rec-port 2>/dev/null || true
    ip addr del 192.0.2.1/24 dev br-lan 2>/dev/null || true
    ip -6 addr del fd42:6e71::1/64 dev br-lan 2>/dev/null || true
    ip addr del 198.51.100.1/32 dev lo 2>/dev/null || true
    if [ "$restore_credential" = true ]; then
        mv "$work/original-credentials.toml" "$credential"
    else
        rm -f "$credential"
    fi
    exit "$code"
}
if [ -f "$credential" ]; then mv "$credential" "$work/original-credentials.toml"; restore_credential=true; fi
trap cleanup EXIT INT TERM
ip addr add 192.0.2.1/24 dev br-lan
ip -6 addr add fd42:6e71::1/64 dev br-lan nodad
ip addr add 198.51.100.1/32 dev lo
ip link add nqm-rec-port type veth peer name nqm-rec-peer
ip link set nqm-rec-port master br-lan
ip link set nqm-rec-port up
ip netns add nqm-rec-client
ip link set nqm-rec-peer netns nqm-rec-client
ip netns exec nqm-rec-client ip link set lo up
ip netns exec nqm-rec-client ip link set nqm-rec-peer address 02:00:00:00:00:02
ip netns exec nqm-rec-client ip link set nqm-rec-peer up
ip netns exec nqm-rec-client ip addr add 192.0.2.2/24 dev nqm-rec-peer
ip netns exec nqm-rec-client ip -6 addr add fd42:6e71::2/64 dev nqm-rec-peer nodad
ip netns exec nqm-rec-client ip route add default via 192.0.2.1
NETQMON_TCP_IDLE_TIMEOUT_SECONDS=2 NETQMON_SAMPLE_ENABLED=true NETQMON_LOG_LEVEL=debug \
    NETQMON_BATCH_INTERVAL_MS=1000 NETQMON_POLL_INTERVAL_MS=100 \
    NETQMON_TOKEN=recognition-openwrt-test NETQMON_CONTROLLER_URL="$collector" \
    "$work/netqmon-agent" --interface br-lan > "$work/agent.log" 2>&1 &
agent_pid=$!
sleep 4
kill -0 "$agent_pid"
grep -Eq 'attached (tcx|netlink) ingress hooks to .+ \(configured br-lan\)' "$work/agent.log"
printf 'netqmon recognition test\n' > "$work/www/index.html"
: > "$work/httpd.conf"
uhttpd -f -p 198.51.100.1:18080 -s 198.51.100.1:18443 -C "$work/cert.der" -K "$work/key.der" \
    -h "$work/www" -c "$work/httpd.conf" > "$work/httpd.log" 2>&1 &
server_pid=$!
sleep 1
ip netns exec nqm-rec-client "$work/recognition-emit" nqm-rec-peer
ip netns exec nqm-rec-client curl --noproxy '*' -kfsS --max-time 10 \
    --resolve www.youtube.com:18443:198.51.100.1 https://www.youtube.com:18443/ -o /dev/null
ip netns exec nqm-rec-client curl --noproxy '*' -fsS --max-time 10 \
    -H 'Host: www.youtube.com' http://198.51.100.1:18080/ -o /dev/null
sleep 6
echo OPENWRT_RECOGNITION_CAPTURE_OK
