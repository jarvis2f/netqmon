#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "multi_interface.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
left_interface=nqm-mi-left
left_peer=nqm-mi-lpeer
right_interface=nqm-mi-right
right_peer=nqm-mi-rpeer
left_namespace=nqm-mi-lns
right_namespace=nqm-mi-rns
agent_pid=
output_file=$(mktemp)
original_forward=$(sysctl -n net.ipv4.ip_forward)

cleanup() {
  status=$?
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ ${status} -ne 0 && -f ${output_file} ]]; then
    echo "netqmon-agent output from failed multi-interface test:" >&2
    sed -n '1,260p' "${output_file}" >&2 || true
  fi
  sysctl -q -w "net.ipv4.ip_forward=${original_forward}" 2>/dev/null || true
  ip netns delete "${left_namespace}" 2>/dev/null || true
  ip netns delete "${right_namespace}" 2>/dev/null || true
  ip link delete "${left_interface}" 2>/dev/null || true
  ip link delete "${right_interface}" 2>/dev/null || true
  rm -f "${output_file}"
  return "${status}"
}
trap cleanup EXIT INT TERM

ip netns add "${left_namespace}"
ip netns add "${right_namespace}"
ip link add "${left_interface}" type veth peer name "${left_peer}"
ip link add "${right_interface}" type veth peer name "${right_peer}"
ip link set "${left_peer}" netns "${left_namespace}"
ip link set "${right_peer}" netns "${right_namespace}"

ip addr add 192.0.2.1/24 dev "${left_interface}"
ip addr add 198.51.100.1/24 dev "${right_interface}"
ip link set "${left_interface}" up
ip link set "${right_interface}" up
ip netns exec "${left_namespace}" ip link set lo up
ip netns exec "${right_namespace}" ip link set lo up
ip netns exec "${left_namespace}" ip addr add 192.0.2.2/24 dev "${left_peer}"
ip netns exec "${right_namespace}" ip addr add 198.51.100.2/24 dev "${right_peer}"
ip netns exec "${left_namespace}" ip link set "${left_peer}" up
ip netns exec "${right_namespace}" ip link set "${right_peer}" up
sysctl -q -w net.ipv4.ip_forward=1

NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=multi-interface-test-token \
  "${agent}" --interface "${left_interface}" --interface "${right_interface}" \
  >"${output_file}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}" && \
     grep -Fq "${left_interface}" "${output_file}" && \
     grep -Fq "${right_interface}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"
grep -Fq "${left_interface}" "${output_file}"
grep -Fq "${right_interface}" "${output_file}"

left_peer_mac=$(ip netns exec "${left_namespace}" cat "/sys/class/net/${left_peer}/address")
left_host_mac=$(cat "/sys/class/net/${left_interface}/address")
frame_length=$(ip netns exec "${left_namespace}" \
  python3 tests/integration/ipv4_traffic.py counter 10 \
  "${left_peer}" "${left_peer_mac}" "${left_host_mac}" \
  --source-address 192.0.2.2 --destination-address 198.51.100.2)
expected="flow delta ip=4 protocol=17 client=192.0.2.2:47000 remote=198.51.100.2:48000 direction=internal packets=10 bytes=$((10 * frame_length))"

for _ in $(seq 1 100); do
  if grep -Fq "${expected}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${expected}" "${output_file}"
[[ $(grep -Fc "${expected}" "${output_file}") -eq 1 ]]
! grep -Fq "packets=20 bytes=$((20 * frame_length))" "${output_file}"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "multi-interface routing and cross-hook deduplication integration test passed"
