#!/bin/sh
# Run on the OpenWrt development router with a freshly built musl Agent.
set -eu
agent=${1:?usage: discovery_verifier.sh /path/to/netqmon-agent}
interface=nqm-disc-test
peer=nqm-disc-peer
output=$(mktemp)
agent_pid=
created=false
cleanup() {
    if [ -n "$agent_pid" ]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [ "$created" = true ]; then
        ip link delete "$interface"
    fi
    rm -f "$output"
}
trap cleanup EXIT INT TERM
ip link add "$interface" type veth peer name "$peer"
created=true
ip link set "$interface" up
ip link set "$peer" up
NETQMON_LOG_LEVEL=debug NETQMON_TOKEN=discovery-verifier-test \
NETQMON_CONTROLLER_URL=http://127.0.0.1:1 \
    "$agent" --interface "$interface" >"$output" 2>&1 &
agent_pid=$!
iteration=0
while [ "$iteration" -lt 20 ]; do
    if grep -Eq 'attached (tcx|netlink) ingress and egress hooks' "$output"; then
        cat "$output"
        kill -TERM "$agent_pid"
        wait "$agent_pid"
        agent_pid=
        echo 'OpenWrt discovery BPF verifier and TC attachment passed'
        exit 0
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    iteration=$((iteration + 1))
    sleep 1
done
cat "$output"
exit 1
