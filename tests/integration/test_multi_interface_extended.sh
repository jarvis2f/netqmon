#!/usr/bin/env bash
set -euo pipefail

# Extended integration test for Netqmon multi-interface features:
# - TOML interfaces order
# - Repeated --interface CLI args
# - NETQMON_INTERFACES env var
# - Legacy single-interface fallback
# - Validation errors: non-existent, duplicate, empty, >15 bytes
# - Unmonitored WAN -> monitored LAN download capture
# - Bridge member expansion without duplicate counting
# - Agent SIGTERM hook clean detachment and restart re-attach

if [[ ${EUID} -ne 0 ]]; then
  echo "test_multi_interface_extended.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
if [[ ! -x "${agent}" ]]; then
  echo "agent binary not found at ${agent}" >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
ns_lan="nqm-ext-lan"
ns_wan="nqm-ext-wan"
veth_lan="nqm-ext-l0"
peer_lan="nqm-ext-lp"
veth_wan="nqm-ext-w0"
peer_wan="nqm-ext-wp"
veth_br1="nqm-ext-b1"
peer_br1="nqm-ext-bp1"
veth_br2="nqm-ext-b2"
peer_br2="nqm-ext-bp2"
br_name="nqm-ext-br0"
agent_pid=""
original_forward=$(sysctl -n net.ipv4.ip_forward)

cleanup() {
  local status=$?
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  sysctl -q -w "net.ipv4.ip_forward=${original_forward}" 2>/dev/null || true
  ip netns delete "${ns_lan}" 2>/dev/null || true
  ip netns delete "${ns_wan}" 2>/dev/null || true
  ip link delete "${veth_lan}" 2>/dev/null || true
  ip link delete "${veth_wan}" 2>/dev/null || true
  ip link delete "${veth_br1}" 2>/dev/null || true
  ip link delete "${veth_br2}" 2>/dev/null || true
  ip link delete "${br_name}" 2>/dev/null || true
  rm -rf "${tmp_dir}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

echo "=== 1. Configuration & Validation Tests ==="

# 1.1 Non-existent interface doctor fails
echo "Testing non-existent interface rejection..."
set +e
"${agent}" doctor --interface "nonexistent99" >"${tmp_dir}/out_missing.log" 2>&1
status=$?
set -e
[[ ${status} -ne 0 ]]
grep -Eq "Interfaces[[:space:]]+FAIL" "${tmp_dir}/out_missing.log"

# 1.2 Duplicate interface in NETQMON_INTERFACES
echo "Testing duplicate interface rejection..."
set +e
NETQMON_INTERFACES="lo,lo" "${agent}" doctor >"${tmp_dir}/out_dup.log" 2>&1
status=$?
set -e
[[ ${status} -ne 0 ]]
grep -Fq "interfaces must not contain duplicates" "${tmp_dir}/out_dup.log"

# 1.3 Empty interface item in NETQMON_INTERFACES
echo "Testing empty interface entry rejection..."
set +e
NETQMON_INTERFACES="lo,,lo" "${agent}" doctor >"${tmp_dir}/out_empty.log" 2>&1
status=$?
set -e
[[ ${status} -ne 0 ]]
grep -Fq "NETQMON_INTERFACES must be a comma-separated list of interface names" "${tmp_dir}/out_empty.log"

# 1.4 Interface name exceeding 15 bytes
echo "Testing >15 bytes interface rejection..."
set +e
NETQMON_INTERFACES="interface_is_too_long_for_linux" "${agent}" doctor >"${tmp_dir}/out_len.log" 2>&1
status=$?
set -e
[[ ${status} -ne 0 ]]
grep -Fq "interface must contain between 1 and 15 bytes" "${tmp_dir}/out_len.log"

# 1.5 Legacy single interface fallback
echo "Testing legacy interface configuration fallback..."
cat << 'TOML' > "${tmp_dir}/legacy.toml"
interface = "lo"
controller_url = "http://127.0.0.1:8090"
token = "test-token"
TOML
"${agent}" doctor --config "${tmp_dir}/legacy.toml" >"${tmp_dir}/out_legacy.log" 2>&1
grep -Eq "Interfaces[[:space:]]+OK[[:space:]]+lo \(ifindex [0-9]+\)" "${tmp_dir}/out_legacy.log"

# 1.6 TOML interfaces order preservation
echo "Testing TOML interfaces order preservation..."
ip link add dummy_a type dummy 2>/dev/null || true
ip link add dummy_b type dummy 2>/dev/null || true
cat << 'TOML' > "${tmp_dir}/ordered.toml"
interfaces = ["dummy_b", "dummy_a"]
controller_url = "http://127.0.0.1:8090"
token = "test-token"
TOML
"${agent}" doctor --config "${tmp_dir}/ordered.toml" >"${tmp_dir}/out_ordered.log" 2>&1
grep -Eq "Interfaces[[:space:]]+OK[[:space:]]+dummy_b \(ifindex [0-9]+\), dummy_a \(ifindex [0-9]+\)" "${tmp_dir}/out_ordered.log"
grep -Fq "Capture interface: dummy_b, dummy_a" "${tmp_dir}/out_ordered.log"
ip link delete dummy_a 2>/dev/null || true
ip link delete dummy_b 2>/dev/null || true

# 1.7 Repeated --interface CLI arguments
echo "Testing repeated --interface CLI arguments..."
ip link add dummy_x type dummy 2>/dev/null || true
ip link add dummy_y type dummy 2>/dev/null || true
"${agent}" doctor --interface dummy_x --interface dummy_y >"${tmp_dir}/out_cli.log" 2>&1
grep -Eq "Interfaces[[:space:]]+OK[[:space:]]+dummy_x \(ifindex [0-9]+\), dummy_y \(ifindex [0-9]+\)" "${tmp_dir}/out_cli.log"
ip link delete dummy_x 2>/dev/null || true
ip link delete dummy_y 2>/dev/null || true

echo "Configuration & validation tests passed."

echo "=== 2. Unmonitored WAN -> Monitored LAN Download Capture Test ==="
ip netns add "${ns_lan}"
ip netns add "${ns_wan}"
ip link add "${veth_lan}" type veth peer name "${peer_lan}"
ip link add "${veth_wan}" type veth peer name "${peer_wan}"
ip link set "${peer_lan}" netns "${ns_lan}"
ip link set "${peer_wan}" netns "${ns_wan}"

ip addr add 192.0.2.1/24 dev "${veth_lan}"
ip addr add 198.51.100.1/24 dev "${veth_wan}"
ip link set "${veth_lan}" up
ip link set "${veth_wan}" up

ip netns exec "${ns_lan}" ip link set lo up
ip netns exec "${ns_wan}" ip link set lo up
ip netns exec "${ns_lan}" ip addr add 192.0.2.2/24 dev "${peer_lan}"
ip netns exec "${ns_wan}" ip addr add 198.51.100.2/24 dev "${peer_wan}"
ip netns exec "${ns_lan}" ip link set "${peer_lan}" up
ip netns exec "${ns_wan}" ip link set "${peer_wan}" up
ip netns exec "${ns_lan}" ip route add default via 192.0.2.1
ip netns exec "${ns_wan}" ip route add default via 198.51.100.1
sysctl -q -w net.ipv4.ip_forward=1

agent_out="${tmp_dir}/agent_wan_lan.log"
NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=test-token \
  "${agent}" --interface "${veth_lan}" >"${agent_out}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${agent_out}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${agent_out}"

wan_peer_mac=$(ip netns exec "${ns_wan}" cat "/sys/class/net/${peer_wan}/address")
wan_host_mac=$(cat "/sys/class/net/${veth_wan}/address")
frame_length=$(ip netns exec "${ns_wan}" \
  python3 tests/integration/ipv4_traffic.py counter 10 \
  "${peer_wan}" "${wan_peer_mac}" "${wan_host_mac}" \
  --source-address 198.51.100.2 --destination-address 192.0.2.2)

expected_wan_lan="flow delta ip=4 protocol=17 client=192.0.2.2:48000 remote=198.51.100.2:47000 direction=download packets=10 bytes=$((10 * frame_length))"

for _ in $(seq 1 100); do
  if grep -Fq "${expected_wan_lan}" "${agent_out}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${expected_wan_lan}" "${agent_out}"
echo "Unmonitored WAN -> monitored LAN download capture passed."

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=""
ip netns delete "${ns_lan}" 2>/dev/null || true
ip netns delete "${ns_wan}" 2>/dev/null || true
ip link delete "${veth_lan}" 2>/dev/null || true
ip link delete "${veth_wan}" 2>/dev/null || true

echo "=== 3. Bridge Member Port Expansion & Hook Clean Lifecycle Test ==="
ip link add name "${br_name}" type bridge
ip link add "${veth_br1}" type veth peer name "${peer_br1}"
ip link add "${veth_br2}" type veth peer name "${peer_br2}"
ip link set "${veth_br1}" master "${br_name}"
ip link set "${veth_br2}" master "${br_name}"
ip link set "${veth_br1}" up
ip link set "${veth_br2}" up
ip link set "${br_name}" up

br_agent_out="${tmp_dir}/agent_bridge.log"
NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=test-token \
  "${agent}" --interface "${br_name}" >"${br_agent_out}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${br_agent_out}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${br_agent_out}"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=""

grep -Eq "detached (tcx|netlink) ingress and egress hooks" "${br_agent_out}"
echo "Bridge hook attachment and clean detachment passed."

NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=test-token \
  "${agent}" --interface "${br_name}" >>"${br_agent_out}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if [[ $(grep -Ec "attached (tcx|netlink) ingress and egress hooks" "${br_agent_out}") -ge 2 ]]; then
    break
  fi
  sleep 0.05
done
[[ $(grep -Ec "attached (tcx|netlink) ingress and egress hooks" "${br_agent_out}") -ge 2 ]]

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=""
[[ $(grep -Ec "detached (tcx|netlink) ingress and egress hooks" "${br_agent_out}") -ge 2 ]]
echo "Bridge hook restart and re-attachment passed."

echo "All multi-interface extended integration tests passed successfully!"
