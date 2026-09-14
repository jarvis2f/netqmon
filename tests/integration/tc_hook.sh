#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "tc_hook.sh must run as root" >&2
  exit 1
fi

agent=${1:-target/debug/netqmon-agent}
interface=netqmon-ci0
peer=netqmon-ci1
agent_pid=
output_file=$(mktemp)

cleanup() {
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  ip link delete "${interface}" 2>/dev/null || true
  rm -f "${output_file}"
}
trap cleanup EXIT INT TERM

fail() {
  echo "tc hook integration test failed: $*" >&2
  exit 1
}

wait_for_hooks() {
  for _ in $(seq 1 100); do
    if ! kill -0 "${agent_pid}" 2>/dev/null; then
      wait "${agent_pid}" || true
      fail "agent exited before both hooks were attached"
    fi

    if grep -Eq "attached (tcx|netlink) ingress and egress hooks" "${output_file}"; then
      return 0
    fi
    sleep 0.05
  done
  fail "timed out waiting for ingress and egress hooks"
}

assert_hooks_detached() {
  if [[ -n $(tc filter show dev "${interface}" ingress) ]]; then
    fail "ingress hook remains after SIGTERM"
  fi
  if [[ -n $(tc filter show dev "${interface}" egress) ]]; then
    fail "egress hook remains after SIGTERM"
  fi
  grep -Eq "detached (tcx|netlink) ingress and egress hooks" "${output_file}" ||
    fail "agent did not report clean hook detachment"
}

run_once() {
  : >"${output_file}"
  "${agent}" --interface "${interface}" >"${output_file}" 2>&1 &
  agent_pid=$!
  wait_for_hooks

  kill -TERM "${agent_pid}"
  wait "${agent_pid}"
  agent_pid=
  assert_hooks_detached
}

ip link add "${interface}" type veth peer name "${peer}"
ip link set "${interface}" up
ip link set "${peer}" up

run_once
run_once

echo "TC hook attach, graceful cleanup, and restart checks passed"
