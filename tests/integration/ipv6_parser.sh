#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ipv6_parser.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=netqmon-ipv6
peer=netqmon-peer
namespace=netqmon-test
agent_pid=
output_file=$(mktemp)

bpftool_command=$(command -v bpftool || true)
if [[ -z ${bpftool_command} ]] || ! "${bpftool_command}" version >/dev/null 2>&1; then
  bpftool_command=$(find /usr/lib/linux-tools -name bpftool -print -quit 2>/dev/null || true)
fi
[[ -n ${bpftool_command} ]] || {
  echo "a working bpftool executable is required" >&2
  exit 1
}

cleanup() {
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  ip netns delete "${namespace}" 2>/dev/null || true
  ip link delete "${interface}" 2>/dev/null || true
  rm -f "${output_file}"
}
trap cleanup EXIT INT TERM

fail() {
  echo "IPv6 parser integration test failed: $*" >&2
  exit 1
}

wait_for_hooks() {
  for _ in $(seq 1 100); do
    if ! kill -0 "${agent_pid}" 2>/dev/null; then
      wait "${agent_pid}" || true
      fail "agent exited before both TC hooks were attached"
    fi

    if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"; then
      return 0
    fi
    sleep 0.05
  done
  fail "timed out waiting for ingress and egress TC hooks"
}

ip link add "${interface}" type veth peer name "${peer}"
ip netns add "${namespace}"
ip link set "${peer}" netns "${namespace}"
ip -6 address add 2001:db8:1::1/64 dev "${interface}" nodad
ip link set "${interface}" up
ip netns exec "${namespace}" ip -6 address add 2001:db8:1::2/64 dev "${peer}" nodad
ip netns exec "${namespace}" ip link set "${peer}" up

"${agent}" --interface "${interface}" >"${output_file}" 2>&1 &
agent_pid=$!

map_id=
for _ in $(seq 1 100); do
  if ! kill -0 "${agent_pid}" 2>/dev/null; then
    wait "${agent_pid}" || true
    fail "agent exited before flow_map became available"
  fi
  map_id=$("${bpftool_command}" -j map show | python3 -c '
import json, sys
maps = [item for item in json.load(sys.stdin) if item.get("name") == "flow_map"]
print(max((item["id"] for item in maps), default=""))
')
  if [[ -n ${map_id} ]]; then
    break
  fi
  sleep 0.05
done
[[ -n ${map_id} ]] || fail "flow_map was not created"
wait_for_hooks

host_mac=$(cat "/sys/class/net/${interface}/address")
peer_mac=$(ip netns exec "${namespace}" cat "/sys/class/net/${peer}/address")
ip -6 neigh replace 2001:db8:1::2 lladdr "${peer_mac}" nud permanent dev "${interface}"
ip netns exec "${namespace}" ip -6 neigh replace 2001:db8:1::1 \
  lladdr "${host_mac}" nud permanent dev "${peer}"

python3 tests/integration/ipv6_traffic.py ip 2001:db8:1::1 2001:db8:1::2

ip netns exec "${namespace}" python3 tests/integration/ipv6_traffic.py \
  raw extension "${peer}" "${peer_mac}" "${host_mac}"
ip netns exec "${namespace}" python3 tests/integration/ipv6_traffic.py \
  raw fragment "${peer}" "${peer_mac}" "${host_mac}"

for _ in $(seq 1 100); do
  if "${bpftool_command}" -j map dump id "${map_id}" | python3 -c '
import json, sys

def octets(key):
    return [int(value, 16) if isinstance(value, str) else value for value in key]

keys = [octets(entry["key"]) for entry in json.load(sys.stdin)]
has_tcp = any(key[0] == 6 and key[1] == 6 for key in keys)
has_udp = any(key[0] == 6 and key[1] == 17 for key in keys)
extension_ports = [0xA7, 0xF8, 0xAB, 0xE0]
has_extension_udp = any(
    key[0] == 6 and key[1] == 17 and key[40:44] == extension_ports
    for key in keys
)
has_fragment_udp = any(
    key[0] == 6 and key[1] == 17 and key[40:44] == [0, 0, 0, 0]
    for key in keys
)
sys.exit(
    0 if has_tcp and has_udp and has_extension_udp and has_fragment_udp else 1
)
'; then
    parsed=true
    break
  fi
  sleep 0.05
done
[[ ${parsed:-false} == true ]] || \
  fail "flow_map lacks IPv6 TCP, UDP, extension, or fragment keys"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "IPv6 TCP, UDP, extension-header, and fragment parsing checks passed"
