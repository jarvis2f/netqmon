#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ipv4_parser.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=netqmon-ipv4
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
  echo "IPv4 parser integration test failed: $*" >&2
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
ip address add 192.0.2.1/24 dev "${interface}"
ip link set "${interface}" up
ip netns exec "${namespace}" ip address add 192.0.2.2/24 dev "${peer}"
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
ip neigh replace 192.0.2.2 lladdr "${peer_mac}" nud permanent dev "${interface}"
ip netns exec "${namespace}" ip neigh replace 192.0.2.1 \
  lladdr "${host_mac}" nud permanent dev "${peer}"

python3 tests/integration/ipv4_traffic.py ip 192.0.2.1 192.0.2.2

ip netns exec "${namespace}" python3 tests/integration/ipv4_traffic.py \
  vlan 1 "${peer}" "${peer_mac}" "${host_mac}"
ip netns exec "${namespace}" python3 tests/integration/ipv4_traffic.py \
  vlan 2 "${peer}" "${peer_mac}" "${host_mac}"
counter_packets=1000
counter_frame_length=$(ip netns exec "${namespace}" \
  python3 tests/integration/ipv4_traffic.py counter "${counter_packets}" \
  "${peer}" "${peer_mac}" "${host_mac}")
expected_counter_bytes=$((counter_packets * counter_frame_length))

for _ in $(seq 1 100); do
  if "${bpftool_command}" -j map dump id "${map_id}" | python3 -c '
import json, sys

def octets(key):
    return [int(value, 16) if isinstance(value, str) else value for value in key]

entries = json.load(sys.stdin)
keys = [octets(entry["key"]) for entry in entries]
has_tcp = any(key[0] == 4 and key[1] == 6 for key in keys)
has_udp = any(key[0] == 4 and key[1] == 17 for key in keys)
vlan_ports = [0xA0, 0x28, 0xA4, 0x10]
has_vlan_udp = any(
    key[0] == 4 and key[1] == 17 and key[40:44] == vlan_ports for key in keys
)
qinq_ports = [0xAF, 0xC8, 0xB3, 0xB0]
has_qinq_udp = any(
    key[0] == 4 and key[1] == 17 and key[40:44] == qinq_ports for key in keys
)
counter_ports = [0xB7, 0x98, 0xBB, 0x80]
counter_entry = next(
    (
        entry
        for entry in entries
        if octets(entry["key"])[0:2] == [4, 17]
        and octets(entry["key"])[40:44] == counter_ports
    ),
    None,
)

def u64(value, offset):
    return int.from_bytes(bytes(octets(value)[offset : offset + 8]), "little")

counter_ok = False
if counter_entry:
    value = counter_entry["value"]
    packets = u64(value, 0)
    byte_count = u64(value, 8)
    first_seen = u64(value, 16)
    last_seen = u64(value, 24)
    counter_ok = (
        packets == int(sys.argv[1])
        and byte_count == int(sys.argv[2])
        and first_seen > 0
        and last_seen >= first_seen
    )

tcp_flags_ok = any(
    octets(entry["key"])[0:2] == [4, 6]
    and int.from_bytes(bytes(octets(entry["value"])[32:36]), "little") != 0
    for entry in entries
)
sys.exit(
    0
    if has_tcp and has_udp and has_vlan_udp and has_qinq_udp
    and counter_ok and tcp_flags_ok
    else 1
)
' "${counter_packets}" "${expected_counter_bytes}"; then
    parsed=true
    break
  fi
  sleep 0.05
done
[[ ${parsed:-false} == true ]] || \
  fail "flow_map lacks parser keys or exact counter values"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "IPv4/VLAN parsing and 1000-packet counter checks passed"
