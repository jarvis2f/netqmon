#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "dns_event.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=nqm-dns
peer=nqm-dns-peer
namespace=nqm-dns-ns
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
  echo "DNS event integration test failed: $*" >&2
  sed -n '1,160p' "${output_file}" >&2
  exit 1
}

ip link add "${interface}" type veth peer name "${peer}"
ip netns add "${namespace}"
ip link set "${peer}" netns "${namespace}"
ip link set "${interface}" up
ip netns exec "${namespace}" ip link set "${peer}" up

NETQMON_LOG_LEVEL=debug \
NETQMON_POLL_INTERVAL_MS=100 \
NETQMON_TOKEN=dns-event-test-token \
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

if ! "${bpftool_command}" -j map show | python3 -c '
import json, sys
maps = json.load(sys.stdin)
names = {item.get("name"): item.get("type") for item in maps}
sys.exit(0 if names.get("dns_events") == "ringbuf" and names.get("dns_drop_count") == "array" else 1)
'; then
  fail "dns_events ring buffer or dns_drop_count array is missing"
fi

host_mac=$(cat "/sys/class/net/${interface}/address")
peer_mac=$(ip netns exec "${namespace}" cat "/sys/class/net/${peer}/address")

for family in 4 6; do
  ip netns exec "${namespace}" python3 tests/integration/dns_traffic.py \
    noise "${family}" "${peer}" "${peer_mac}" "${host_mac}"
done
sleep 0.3
if grep -Fq "dns event" "${output_file}"; then
  fail "UDP query or TCP source port 53 produced a DNS response event"
fi

for family in 4 6; do
  ip netns exec "${namespace}" python3 tests/integration/dns_traffic.py \
    response "${family}" "${peer}" "${peer_mac}" "${host_mac}"
done

ipv4_event="dns event ip=4 client=198.51.100.20 packet_length=742 payload_length=512"
ipv6_event="dns event ip=6 client=2001:db8:53::20 packet_length=762 payload_length=512"
for _ in $(seq 1 100); do
  if grep -Fq "${ipv4_event}" "${output_file}" && \
     grep -Fq "${ipv6_event}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${ipv4_event}" "${output_file}" || fail "bounded IPv4 DNS response event is missing"
grep -Fq "${ipv6_event}" "${output_file}" || fail "bounded IPv6 DNS response event is missing"

ipv4_observation="dns observation client_addr=198.51.100.20 domain=example.test answer_ip=203.0.113.10 record_type=A ttl=300 observed_at="
ipv6_observation="dns observation client_addr=2001:db8:53::20 domain=example.test answer_ip=203.0.113.10 record_type=A ttl=300 observed_at="
for _ in $(seq 1 100); do
  if grep -Fq "${ipv4_observation}" "${output_file}" && \
     grep -Fq "${ipv6_observation}" "${output_file}"; then
    break
  fi
  sleep 0.05
done
grep -Fq "${ipv4_observation}" "${output_file}" || fail "IPv4 DNS observation is missing"
grep -Fq "${ipv6_observation}" "${output_file}" || fail "IPv6 DNS observation is missing"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=

echo "bounded IPv4/IPv6 DNS response event and observation checks passed"
