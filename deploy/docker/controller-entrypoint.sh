#!/bin/sh
set -eu

mkdir -p /data/geo /data/backups /data/components/classifierd /run/netqmon

start_classifier_manager() {
  netqmon-classifier-manager &
  classifier_manager_pid="$!"
}

shutdown() {
  terminating=1
  trap - INT TERM
  if [ -n "${collector_pid:-}" ] && kill -0 "$collector_pid" 2>/dev/null; then
    kill -TERM "$collector_pid" 2>/dev/null || true
  fi
  if [ -n "${next_pid:-}" ] && kill -0 "$next_pid" 2>/dev/null; then
    kill -TERM "$next_pid" 2>/dev/null || true
  fi
  if [ -n "${classifier_manager_pid:-}" ] && kill -0 "$classifier_manager_pid" 2>/dev/null; then
    kill -TERM "$classifier_manager_pid" 2>/dev/null || true
  fi
}

trap shutdown INT TERM
terminating=0
classifier_manager_restart_delay=1

start_classifier_manager
netqmon-collector &
collector_pid="$!"

node /app/apps/controller-ui/server.js &
next_pid="$!"

while :; do
  if ! kill -0 "$classifier_manager_pid" 2>/dev/null; then
    wait "$classifier_manager_pid" || true
    if [ "$terminating" -eq 1 ]; then
      wait "$collector_pid" || true
      wait "$next_pid" || true
      exit 0
    fi
    sleep "$classifier_manager_restart_delay"
    if [ "$classifier_manager_restart_delay" -lt 30 ]; then
      classifier_manager_restart_delay=$((classifier_manager_restart_delay * 2))
    fi
    start_classifier_manager
  else
    classifier_manager_restart_delay=1
  fi
  if ! kill -0 "$collector_pid" 2>/dev/null; then
    if [ "$terminating" -eq 1 ]; then
      wait "$collector_pid" || true
      wait "$next_pid" || true
      wait "$classifier_manager_pid" || true
      exit 0
    fi
    wait "$collector_pid" || exit $?
    exit 1
  fi
  if ! kill -0 "$next_pid" 2>/dev/null; then
    if [ "$terminating" -eq 1 ]; then
      wait "$collector_pid" || true
      wait "$next_pid" || true
      wait "$classifier_manager_pid" || true
      exit 0
    fi
    wait "$next_pid" || exit $?
    exit 1
  fi
  sleep 1
done
