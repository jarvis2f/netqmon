#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "startup_errors.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=netqmon-errors
peer=nqm-err-peer
test_directory=$(mktemp -d)

cleanup() {
  ip link delete "${interface}" 2>/dev/null || true
  rm -rf "${test_directory}"
}
trap cleanup EXIT INT TERM

fail() {
  echo "startup error integration test failed: $*" >&2
  exit 1
}

assert_failed_with() {
  local expected=$1
  shift
  local output_file="${test_directory}/${expected// /-}.log"

  set +e
  "$@" >"${output_file}" 2>&1
  local status=$?
  set -e

  [[ ${status} -ne 0 ]] || fail "command unexpectedly succeeded for ${expected}"
  grep -Fq "${expected}:" "${output_file}" || {
    cat "${output_file}" >&2
    fail "expected ${expected} diagnostic"
  }
}

assert_failed_with "missing interface" \
  "${agent}" --interface nqm-missing

ip link add "${interface}" type veth peer name "${peer}"
ip link set "${interface}" up
assert_failed_with "permission denied" \
  runuser -u nobody -- "${agent}" --interface "${interface}"

echo "missing-interface and permission diagnostics passed"
