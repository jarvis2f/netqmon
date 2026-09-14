#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "device_discovery.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=nqm-device
peer=nqm-dev-peer
namespace=nqm-device-ns
agent_pid=
output_file=$(mktemp)

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
  echo "device discovery integration test failed: $*" >&2
  sed -n '1,200p' "${output_file}" >&2
  exit 1
}

ip link add "${interface}" type veth peer name "${peer}"
ip netns add "${namespace}"
ip link set "${peer}" netns "${namespace}"
ip address add 192.0.2.1/24 dev "${interface}"
ip -6 address add 2001:db8:4::1/64 dev "${interface}"
ip link set "${interface}" up
ip netns exec "${namespace}" ip link set lo up
ip netns exec "${namespace}" ip address add 192.0.2.2/24 dev "${peer}"
ip netns exec "${namespace}" ip -6 address add 2001:db8:4::2/64 dev "${peer}"
ip netns exec "${namespace}" ip link set "${peer}" up
ip netns exec "${namespace}" ip route add default via 192.0.2.1

peer_mac=$(ip netns exec "${namespace}" cat "/sys/class/net/${peer}/address")
ip neighbour replace 192.0.2.2 lladdr "${peer_mac}" nud reachable dev "${interface}"
ip -6 neighbour replace 2001:db8:4::2 lladdr "${peer_mac}" nud reachable dev "${interface}"

NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=device-discovery-test-token \
  "${agent}" --interface "${interface}" \
  >"${output_file}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}" || \
  fail "agent did not attach TC hooks"

ipv4_observation="device observation mac=${peer_mac} ip=192.0.2.2 hostname=- last_seen="
ipv6_observation="device observation mac=${peer_mac} ip=2001:db8:4::2 hostname=- last_seen="
for _ in $(seq 1 100); do
  if grep -Fq "${ipv4_observation}" "${output_file}" && \
     grep -Fq "${ipv6_observation}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${ipv4_observation}" "${output_file}" || fail "IPv4 ARP observation is missing"
grep -Fq "${ipv6_observation}" "${output_file}" || fail "IPv6 NDP observation is missing"

ip netns exec "${namespace}" python3 tests/integration/ipv4_traffic.py \
  ip 192.0.2.2 198.51.100.2
flow_prefix="flow delta ip=4 protocol=17 client=192.0.2.2:"
for _ in $(seq 1 100); do
  if grep -F "${flow_prefix}" "${output_file}" | \
     grep -F "remote=198.51.100.2:19090 direction=upload" | \
     grep -Fq "client_mac=${peer_mac}"; then
    break
  fi
  sleep 0.05
done
if ! grep -F "${flow_prefix}" "${output_file}" | \
   grep -F "remote=198.51.100.2:19090 direction=upload" | \
   grep -Fq "client_mac=${peer_mac}"; then
  fail "flow did not resolve the client IP to its stable MAC identity"
fi

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "IPv4/IPv6 neighbour discovery and stable flow identity checks passed"
