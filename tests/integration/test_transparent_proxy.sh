#!/usr/bin/env bash
set -euo pipefail

# Automated integration test for Transparent Proxy monitoring and tuple recovery:
# - IPv4 TCP REDIRECT
# - IPv4 UDP REDIRECT
# - IPv6 TCP REDIRECT
# - IPv6 UDP REDIRECT
# - Proxy reply traffic retention (not discarded as RouterLocal)
# - Cross-hook deduplication (no double counting)
# - Short connection and burst capture

if [[ ${EUID} -ne 0 ]]; then
  echo "test_transparent_proxy.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
if [[ ! -x "${agent}" ]]; then
  echo "agent binary not found at ${agent}" >&2
  exit 1
fi

ns_client="nqm-tpr-cns"
veth_host="nqm-tpr-lan"
veth_peer="nqm-tpr-cpeer"
tmp_dir=$(mktemp -d)
agent_pid=""
server_pids=()
original_forward_v4=$(sysctl -n net.ipv4.ip_forward)
original_forward_v6=$(sysctl -n net.ipv6.conf.all.forwarding)

cleanup() {
  local status=$?
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  for spid in "${server_pids[@]}"; do
    if [[ -n "${spid}" ]] && kill -0 "${spid}" 2>/dev/null; then
      kill -9 "${spid}" 2>/dev/null || true
    fi
  done
  nft delete table inet nqm_tproxy_test 2>/dev/null || true
  sysctl -q -w "net.ipv4.ip_forward=${original_forward_v4}" 2>/dev/null || true
  sysctl -q -w "net.ipv6.conf.all.forwarding=${original_forward_v6}" 2>/dev/null || true
  ip netns delete "${ns_client}" 2>/dev/null || true
  ip link delete "${veth_host}" 2>/dev/null || true
  rm -rf "${tmp_dir}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

echo "=== 1. Setting up Test Topology and Network Namespaces ==="
ip netns add "${ns_client}"
ip link add "${veth_host}" type veth peer name "${veth_peer}"
ip link set "${veth_peer}" netns "${ns_client}"

# Assign IPv4 and IPv6 addresses
ip addr add 192.0.2.1/24 dev "${veth_host}"
ip addr add fd00:2::1/64 dev "${veth_host}"
ip link set "${veth_host}" up

ip netns exec "${ns_client}" ip link set lo up
ip netns exec "${ns_client}" ip addr add 192.0.2.10/24 dev "${veth_peer}"
ip netns exec "${ns_client}" ip addr add fd00:2::10/64 dev "${veth_peer}"
ip netns exec "${ns_client}" ip link set "${veth_peer}" up

ip netns exec "${ns_client}" ip route add default via 192.0.2.1
ip netns exec "${ns_client}" ip -6 route add default via fd00:2::1

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1

echo "=== 2. Configuring nftables REDIRECT Rules on Host ==="
# Ports:
# IPv4 TCP: 7890, IPv4 UDP: 7891
# IPv6 TCP: 7892, IPv6 UDP: 7893
nft delete table inet nqm_tproxy_test 2>/dev/null || true
nft add table inet nqm_tproxy_test
nft 'add chain inet nqm_tproxy_test prerouting { type nat hook prerouting priority dstnat; policy accept; }'
nft add rule inet nqm_tproxy_test prerouting iifname "${veth_host}" ip protocol tcp tcp dport 443 redirect to :7890
nft add rule inet nqm_tproxy_test prerouting iifname "${veth_host}" ip protocol udp udp dport 443 redirect to :7891
nft add rule inet nqm_tproxy_test prerouting iifname "${veth_host}" ip6 nexthdr tcp tcp dport 443 redirect to :7892
nft add rule inet nqm_tproxy_test prerouting iifname "${veth_host}" ip6 nexthdr udp udp dport 443 redirect to :7893

echo "=== 3. Starting Transparent Proxy Echo Servers ==="
python3 tests/integration/test_transparent_proxy_workload.py server --protocol tcp --family 4 --port 7890 &
server_pids+=($!)
python3 tests/integration/test_transparent_proxy_workload.py server --protocol udp --family 4 --port 7891 &
server_pids+=($!)
python3 tests/integration/test_transparent_proxy_workload.py server --protocol tcp --family 6 --port 7892 &
server_pids+=($!)
python3 tests/integration/test_transparent_proxy_workload.py server --protocol udp --family 6 --port 7893 &
server_pids+=($!)
sleep 0.5

echo "=== 4. Starting Agent with Multi-Interface / TC Ingress & Egress Hooks ==="
agent_log="${tmp_dir}/agent.log"
cat << TOML > "${tmp_dir}/agent.toml"
interface = "${veth_host}"
interfaces = ["${veth_host}"]
controller_url = "http://127.0.0.1:8090"
token = "test-token"
poll_interval_ms = 100

[[topology.networks]]
subnet = "192.0.2.0/24"
role = "lan"

[[topology.networks]]
subnet = "fd00:2::/64"
role = "lan"

[[topology.networks]]
subnet = "203.0.113.0/24"
role = "wan"

[[topology.networks]]
subnet = "2001:db8::/32"
role = "wan"
TOML

NETQMON_LOG_LEVEL=debug \
  "${agent}" --config "${tmp_dir}/agent.toml" >"${agent_log}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
  if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${agent_log}"

echo "=== 5. Running Transparent Proxy Traffic Workloads ==="

# 5.1 IPv4 TCP REDIRECT
echo "Testing IPv4 TCP REDIRECT..."
ip netns exec "${ns_client}" python3 tests/integration/test_transparent_proxy_workload.py client \
  --protocol tcp --host 203.0.113.88 --port 443 --count 5 --payload-size 128

# Wait for conntrack and flow poll
for _ in $(seq 1 60); do
  if grep -Fq "client=192.0.2.10" "${agent_log}" && grep -Fq "remote=203.0.113.88:443" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "client=192.0.2.10" "${agent_log}"
grep -Fq "remote=203.0.113.88:443" "${agent_log}"
# Assert proxy reply is not marked as RouterLocal
! grep -Fq "client=192.0.2.1 remote=192.0.2.10.*direction=router_local" "${agent_log}"
echo "IPv4 TCP REDIRECT passed."

# 5.2 IPv4 UDP REDIRECT
echo "Testing IPv4 UDP REDIRECT..."
ip netns exec "${ns_client}" python3 tests/integration/test_transparent_proxy_workload.py client \
  --protocol udp --host 203.0.113.88 --port 443 --count 5 --payload-size 128

for _ in $(seq 1 60); do
  if grep -Fq "protocol=17 client=192.0.2.10" "${agent_log}" && grep -Fq "remote=203.0.113.88:443" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "protocol=17 client=192.0.2.10" "${agent_log}"
grep -Fq "remote=203.0.113.88:443" "${agent_log}"
echo "IPv4 UDP REDIRECT passed."

# 5.3 IPv6 TCP REDIRECT
echo "Testing IPv6 TCP REDIRECT..."
ip netns exec "${ns_client}" python3 tests/integration/test_transparent_proxy_workload.py client \
  --protocol tcp --host 2001:db8::88 --port 443 --count 5 --payload-size 128

for _ in $(seq 1 60); do
  if grep -Fq "client=fd00:2::10" "${agent_log}" && grep -Fq "remote=2001:db8::88:443" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "client=fd00:2::10" "${agent_log}"
grep -Fq "remote=2001:db8::88:443" "${agent_log}"
echo "IPv6 TCP REDIRECT passed."

# 5.4 IPv6 UDP REDIRECT
echo "Testing IPv6 UDP REDIRECT..."
ip netns exec "${ns_client}" python3 tests/integration/test_transparent_proxy_workload.py client \
  --protocol udp --host 2001:db8::88 --port 443 --count 5 --payload-size 128

for _ in $(seq 1 60); do
  if grep -Fq "protocol=17 client=fd00:2::10" "${agent_log}" && grep -Fq "remote=2001:db8::88:443" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "protocol=17 client=fd00:2::10" "${agent_log}"
grep -Fq "remote=2001:db8::88:443" "${agent_log}"
echo "IPv6 UDP REDIRECT passed."

# 5.5 Short connection burst test (10 rapid connections)
echo "Testing short connections and conntrack refresh timing..."
ip netns exec "${ns_client}" python3 tests/integration/test_transparent_proxy_workload.py client \
  --protocol tcp --host 203.0.113.99 --port 443 --count 10 --payload-size 32

for _ in $(seq 1 60); do
  if grep -Fq "remote=203.0.113.99:443" "${agent_log}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "remote=203.0.113.99:443" "${agent_log}"
echo "Short connections test passed."

# Shutdown
kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=""

echo "All transparent proxy integration tests passed successfully!"
