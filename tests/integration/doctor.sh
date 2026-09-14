#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "doctor.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=nqm-doctor
peer=nqm-doc-peer

cleanup() {
  ip link delete "${interface}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip link add "${interface}" type veth peer name "${peer}"
ip link set "${interface}" up

output=$("${agent}" doctor --interface "${interface}")
printf '%s\n' "${output}"

for check in Architecture Kernel Interfaces "BPF syscall" BPF_MAP_TYPE_RINGBUF "TC/TCX attach" HFO; do
  grep -Eq "^${check}[[:space:]]+" <<<"${output}"
done
for required in Architecture Kernel Interfaces "BPF syscall" BPF_MAP_TYPE_RINGBUF "TC/TCX attach"; do
  grep -Eq "^${required}[[:space:]]+OK" <<<"${output}"
done

set +e
missing_output=$("${agent}" doctor --interface nqm-missing 2>&1)
status=$?
set -e
[[ ${status} -ne 0 ]]
grep -Eq '^Interfaces[[:space:]]+FAIL' <<<"${missing_output}"

echo "capability doctor integration test passed"
