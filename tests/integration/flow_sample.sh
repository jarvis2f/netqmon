#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'flow_sample.sh requires root' >&2; exit 1; }
agent=${1:-target/debug/netqmon-agent}
interface=nqm-sample
peer=nqm-samp-peer
namespace=nqm-sample-ns
output=$(mktemp)
agent_pid=
bpftool_command=$(command -v bpftool || true)
if [[ -z "$bpftool_command" ]] || ! "$bpftool_command" version >/dev/null 2>&1; then
    bpftool_command=$(find /usr/lib/linux-tools -name bpftool -print -quit 2>/dev/null || true)
fi
[[ -n "$bpftool_command" ]] || { echo 'a working bpftool executable is required' >&2; exit 1; }
cleanup() {
    code=$?
    if [[ -n "$agent_pid" ]]; then kill -TERM "$agent_pid" 2>/dev/null || true; wait "$agent_pid" || true; fi
    if [[ $code -ne 0 ]]; then cat "$output" >&2; fi
    ip netns delete "$namespace" 2>/dev/null || true
    ip link delete "$interface" 2>/dev/null || true
    rm -f "$output"
    return "$code"
}
trap cleanup EXIT
ip link add "$interface" type veth peer name "$peer"
ip netns add "$namespace"
ip link set "$peer" netns "$namespace"
ip addr add 192.0.2.1/24 dev "$interface"
ip -6 addr add 2001:db8:1::1/64 dev "$interface"
ip link set "$interface" up
ip netns exec "$namespace" ip link set "$peer" up
host_mac=$(cat "/sys/class/net/$interface/address")
peer_mac=$(ip netns exec "$namespace" cat "/sys/class/net/$peer/address")
map_id() {
    "$bpftool_command" -j map show | python3 -c 'import json,sys; name=sys.argv[1]; print(max(m["id"] for m in json.load(sys.stdin) if m["name"]==name))' "$1"
}
for enabled in false true; do
    : > "$output"
    NETQMON_SAMPLE_ENABLED="$enabled" NETQMON_LOG_LEVEL=debug NETQMON_POLL_INTERVAL_MS=100 NETQMON_CONTROLLER_URL=http://127.0.0.1:9 NETQMON_TOKEN=sample-test \
        "$agent" --interface "$interface" > "$output" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 100); do
        if rg -q 'attached (tcx|netlink) ingress and egress hooks' "$output"; then break; fi
        sleep 0.05
    done
    rg -q 'attached (tcx|netlink) ingress and egress hooks' "$output"
    for version in 4 6; do
        ip netns exec "$namespace" python3 tests/integration/flow_sample_traffic.py "$peer" "$peer_mac" "$host_mac" "$version"
    done
    sleep 1
    rg -q 'flow delta ip=4 protocol=17' "$output"
    rg -q 'flow delta ip=6 protocol=17' "$output"
    "$bpftool_command" -j map dump id "$(map_id sample_counters)" | python3 -c '
import json,sys
raw=lambda values:bytes(int(v,16) if isinstance(v,str) else v for v in values)
counts={int.from_bytes(raw(e["key"]),sys.byteorder):int.from_bytes(raw(e["value"]),sys.byteorder) for e in json.load(sys.stdin)}
if sys.argv[1]=="false": assert counts[0]==counts[1]==0,counts
else:
    # The runner can emit IPv6 neighbour/router-control traffic on a new veth.
    # It is valid for those flows to consume their own bounded sample budgets.
    assert counts[0]>=2,counts
    assert 0<counts[1]<=counts[0]*4096,counts
' "$enabled"
    if [[ "$enabled" == true ]]; then
        "$bpftool_command" -j map dump id "$(map_id sample_budgets)" | python3 -c '
import json,struct,sys
raw=lambda values:bytes(int(v,16) if isinstance(v,str) else v for v in values)
entries=json.load(sys.stdin)
target=[]
for e in entries:
    key=raw(e["key"])
    source_port=int.from_bytes(key[40:42],"big")
    destination_port=int.from_bytes(key[42:44],"big")
    if key[1]==17 and {source_port,destination_port}=={50000,50001}:
        target.append(e)
assert len(target)==2,(len(target),len(entries))
for e in target:
    data=raw(e["value"])
    a,b=struct.unpack_from("=II",data,20)
    assert 0<a<=4 and 0<b<=4,(a,b)
'
    fi
    kill -TERM "$agent_pid"; wait "$agent_pid"; agent_pid=
done
echo 'FLOW_SAMPLE_BUDGET_AND_DISABLED_OK'
