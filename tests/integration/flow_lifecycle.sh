#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "flow_lifecycle.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=nqm-life
peer=nqm-life-peer
namespace=nqm-life-ns
agent_pid=
output_file=$(mktemp)

cleanup() {
  status=$?
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ ${status} -ne 0 && -f ${output_file} ]]; then
    echo "netqmon-agent output from failed flow lifecycle test:" >&2
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
NETQMON_TOKEN=flow-lifecycle-test-token \
NETQMON_UDP_IDLE_TIMEOUT_SECONDS=1 \
  "${agent}" --interface "${interface}" >"${output_file}" 2>&1 &
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
ip netns exec "${namespace}" \
  python3 tests/integration/ipv4_traffic.py counter 1 \
  "${peer}" "${peer_mac}" "${host_mac}" >/dev/null

prefix="flow lifecycle"
for state in active idle end; do
  for _ in $(seq 1 100); do
    if grep -Fq "${prefix} state=${state} protocol=17" "${output_file}"; then
      break
    fi
    sleep 0.05
  done
  grep -Fq "${prefix} state=${state} protocol=17" "${output_file}"
done

active_line=$(grep -Fn "${prefix} state=active protocol=17" "${output_file}" | head -1 | cut -d: -f1)
idle_line=$(grep -Fn "${prefix} state=idle protocol=17" "${output_file}" | head -1 | cut -d: -f1)
end_line=$(grep -Fn "${prefix} state=end protocol=17" "${output_file}" | head -1 | cut -d: -f1)
(( active_line < idle_line && idle_line < end_line ))

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "UDP active, idle, and end lifecycle integration test passed"
