#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "map_poller.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=nqm-poller
peer=nqm-pol-peer
namespace=nqm-poll-ns
agent_pid=
output_file=$(mktemp)

cleanup() {
  status=$?
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ ${status} -ne 0 && -f ${output_file} ]]; then
    echo "netqmon-agent output from failed map poller test:" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
  fi
  ip netns delete "${namespace}" 2>/dev/null || true
  ip link delete "${interface}" 2>/dev/null || true
  rm -f "${output_file}"
  return "${status}"
}
trap cleanup EXIT INT TERM

ip link add "${interface}" type veth peer name "${peer}"
ip netns add "${namespace}"
ip link set "${peer}" netns "${namespace}"
ip link set "${interface}" up
ip netns exec "${namespace}" ip link set "${peer}" up

NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=map-poller-test-token \
  "${agent}" --interface "${interface}" \
  >"${output_file}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"

host_mac=$(cat "/sys/class/net/${interface}/address")
peer_mac=$(ip netns exec "${namespace}" cat "/sys/class/net/${peer}/address")
frame_length=$(ip netns exec "${namespace}" \
  python3 tests/integration/ipv4_traffic.py counter 10 \
  "${peer}" "${peer_mac}" "${host_mac}")
expected_bytes=$((10 * frame_length))
expected="flow delta ip=4 protocol=17 client=203.0.113.1:47000 remote=203.0.113.2:48000 direction=unknown packets=10 bytes=${expected_bytes}"

for _ in $(seq 1 100); do
  if grep -Fq "${expected}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${expected}" "${output_file}"
initial_expected_count=$(grep -Fc "${expected}" "${output_file}")

ip netns exec "${namespace}" python3 tests/integration/ipv4_traffic.py counter 10 \
  "${peer}" "${peer_mac}" "${host_mac}" >/dev/null
for _ in $(seq 1 100); do
  if [[ $(grep -Fc "${expected}" "${output_file}") -gt ${initial_expected_count} ]]; then
    break
  fi
  sleep 0.05
done
[[ $(grep -Fc "${expected}" "${output_file}") -gt ${initial_expected_count} ]]
! grep -Fq "packets=20 bytes=$((20 * frame_length))" "${output_file}"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "map poller non-repeating delta integration test passed"
