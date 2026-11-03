#!/usr/bin/env bash
# Exercise the feature-enabled opt-in without touching the host network or filesystem.
set -euo pipefail

if [[ ${NETQMON_TOTAL_TEST_ISOLATED:-0} != 1 ]]; then
    export NETQMON_TOTAL_TEST_ISOLATED=1
    exec unshare --mount --net -- bash "$0" "$@"
fi
if [[ $(readlink /proc/self/ns/net) == $(readlink /proc/1/ns/net) ||
      $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo 'Refusing to run outside private network and mount namespaces' >&2
    exit 1
fi

agent=${1:?pass the priority-enabled Agent binary}
topology=${2:-direct}
work=$(mktemp -d)
agent_pid=
runtime_dir=
cleanup() {
    local status=$?
    if [[ -n "$agent_pid" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" || true
    fi
    if [[ $status -ne 0 && -f "$work/agent.log" ]]; then cat "$work/agent.log" >&2; fi
    [[ -z "$runtime_dir" ]] || rm -rf -- "$runtime_dir"
    rm -rf -- "$work"
    return "$status"
}
trap cleanup EXIT

# This mount namespace gets its own firewall configuration and sysfs view.
mount -t tmpfs tmpfs /etc
mkdir -p /etc/config
printf "config defaults\n option flow_offloading '0'\n option flow_offloading_hw '0'\n" > /etc/config/firewall
mount -t sysfs sysfs /sys
mount -t bpf bpf /sys/fs/bpf
ip link set lo up
case "$topology" in
    direct|one-arm|dual-wan|foreign-filter|foreign-qdisc|offload-unknown|offload-enabled|legacy-policy|legacy-saved|legacy-journal|stale-journal)
        ip link add nqt-test type veth peer name nqt-peer
        ip link set nqt-test up
        ip link set nqt-peer up
        capacities='{"nqt-test":1000000000}'
        ;;
    bridge|bridge-foreign-filter)
        ip link add nqt-test type bridge
        for number in 1 2; do
            ip link add "nqt-p$number" type veth peer name "nqt-c$number"
            ip link set "nqt-p$number" master nqt-test
            ip link set "nqt-p$number" up
            ip link set "nqt-c$number" up
        done
        ip link set nqt-test up
        capacities='{"nqt-p1":1000000000,"nqt-p2":1000000000}'
        ;;
    *) echo "Unknown test topology: $topology" >&2; exit 2 ;;
esac
ip address add 192.0.2.1/24 dev nqt-test
if [[ "$topology" == one-arm ]]; then
    ip address add 192.0.2.2/24 dev nqt-peer
    ip route add default via 192.0.2.2 dev nqt-test
fi
if [[ "$topology" == dual-wan ]]; then
    for number in 1 2; do
        ip link add "nqt-w$number" type veth peer name "nqt-u$number"
        ip link set "nqt-w$number" up
        ip link set "nqt-u$number" up
        ip address add "198.51.$number.1/24" dev "nqt-w$number"
        ip route add default via "198.51.$number.2" dev "nqt-w$number" metric "$number"
    done
fi
if [[ "$topology" == foreign-filter || "$topology" == bridge-foreign-filter ]]; then
    filter_dev=nqt-test
    [[ "$topology" != bridge-foreign-filter ]] || filter_dev=nqt-p2
    tc qdisc add dev "$filter_dev" clsact
    tc filter add dev "$filter_dev" egress pref 123 matchall action pass
    tc -j filter show dev "$filter_dev" egress > "$work/filters-before.json"
fi
[[ "$topology" != offload-unknown ]] || rm /etc/config/firewall
if [[ "$topology" == offload-enabled ]]; then
    printf "config defaults\n option flow_offloading '0'\n option flow_offloading_hw '1'\n" > /etc/config/firewall
fi
if [[ "$topology" == foreign-qdisc ]]; then
    tc qdisc replace dev nqt-test root handle 42: htb default 1
    tc class add dev nqt-test parent 42: classid 42:1 htb rate 100mbit
    tc -j -d qdisc show dev nqt-test | python3 -c 'import json,sys; print(json.dumps([q for q in json.load(sys.stdin) if q.get("root")], sort_keys=True))' > "$work/qdisc-before.json"
    tc -j class show dev nqt-test > "$work/classes-before.json"
fi
if [[ "$topology" == legacy-policy || "$topology" == stale-journal ]]; then
    nft add table inet netqmon_policy
    nft add chain inet netqmon_policy existing_block
    nft add rule inet netqmon_policy existing_block counter drop
    nft -j list table inet netqmon_policy > "$work/nft-before.json"
fi
if [[ "$topology" == stale-journal ]]; then
    printf 'incomplete transaction\n' > "$work/policy-state.priority-journal.json"
fi
if [[ "$topology" == legacy-saved ]]; then
    printf 'saved legacy state\n' > "$work/policy-state.json"
fi
if [[ "$topology" == legacy-journal ]]; then
    printf 'legacy transaction\n' > "$work/policy-state.shaping-journal.json"
fi
index=$(cat /sys/class/net/nqt-test/ifindex)
ifb=$(printf 'nqt%x' "$index")
namespace=$(readlink /proc/self/ns/net)
namespace=${namespace#net:[}
namespace=${namespace%]}
candidate="/tmp/netqmon-priority-${namespace}-${index}"
[[ ! -e "$candidate" && ! -L "$candidate" ]] || { echo 'Refusing to reuse existing evidence directory' >&2; exit 1; }
runtime_dir=$candidate
unset NETQMON_QOS_PRIORITY_CONFIG
NETQMON_POLICY_CLIENT_TOTAL_ENABLED=1 \
NETQMON_POLICY_INTERFACE_CAPACITY_BPS="$capacities" \
NETQMON_POLICY_STATE_PATH="$work/policy-state.json" \
NETQMON_POLICY_DISABLED_PATH="$work/policy-disabled" \
NETQMON_CONTROLLER_URL=http://127.0.0.1:9 NETQMON_TOKEN=isolated-test \
    "$agent" --interface nqt-test > "$work/agent.log" 2>&1 &
agent_pid=$!
if [[ "$topology" == stale-journal ]]; then
    for _ in $(seq 1 200); do
        kill -0 "$agent_pid" 2>/dev/null || break
        sleep 0.05
    done
    if wait "$agent_pid"; then
        echo 'Priority backend unexpectedly ignored a stale transaction' >&2
        agent_pid=
        exit 1
    fi
    agent_pid=
    grep -q 'priority_conflict: legacy NetQmon policy rules' "$work/agent.log"
    test "$(cat "$work/policy-state.priority-journal.json")" = 'incomplete transaction'
    nft -j list table inet netqmon_policy > "$work/nft-after.json"
    cmp "$work/nft-before.json" "$work/nft-after.json"
    echo "CLIENT_TOTAL_STALE_TRANSACTION_PRESERVED topology=$topology"
    exit 0
fi
if [[ "$topology" == legacy-policy || "$topology" == legacy-saved || "$topology" == legacy-journal ]]; then
    for _ in $(seq 1 200); do
        if grep -q 'retaining the existing policy backend' "$work/agent.log" && grep -q 'attached .* hooks' "$work/agent.log"; then break; fi
        kill -0 "$agent_pid" 2>/dev/null || break
        sleep 0.05
    done
    kill -0 "$agent_pid"
    grep -q 'priority_conflict: legacy' "$work/agent.log"
    grep -q 'retaining the existing policy backend' "$work/agent.log"
    if [[ "$topology" == legacy-policy ]]; then
        nft -j list table inet netqmon_policy > "$work/nft-after.json"
        cmp "$work/nft-before.json" "$work/nft-after.json"
    elif [[ "$topology" == legacy-saved ]]; then
        test "$(cat "$work/policy-state.json")" = 'saved legacy state'
    else
        test "$(cat "$work/policy-state.shaping-journal.json")" = 'legacy transaction'
    fi
    if ip link show "$ifb" >/dev/null 2>&1; then
        echo 'Priority IFB was created despite existing legacy policy' >&2
        exit 1
    fi
    kill -TERM "$agent_pid"
    wait "$agent_pid"
    agent_pid=
    echo "CLIENT_TOTAL_CONFLICT_PRESERVED topology=$topology"
    exit 0
fi
if [[ "$topology" == foreign-filter || "$topology" == bridge-foreign-filter || "$topology" == foreign-qdisc || "$topology" == offload-unknown || "$topology" == offload-enabled ]]; then
    for _ in $(seq 1 200); do
        if grep -q 'retaining the existing policy backend' "$work/agent.log" && grep -q 'attached .* hooks' "$work/agent.log"; then break; fi
        kill -0 "$agent_pid" 2>/dev/null || break
        sleep 0.05
    done
    kill -0 "$agent_pid"
    if [[ "$topology" == offload-unknown || "$topology" == offload-enabled ]]; then
        grep -q 'priority_offload_unknown' "$work/agent.log"
    elif [[ "$topology" == foreign-qdisc ]]; then
        grep -q 'priority_qdisc_conflict' "$work/agent.log"
    else
        grep -q 'priority_tc_conflict' "$work/agent.log"
    fi
    grep -q 'retaining the existing policy backend' "$work/agent.log"
    if ip link show "$ifb" >/dev/null 2>&1; then
        echo 'Priority IFB was created despite a foreign filter' >&2
        exit 1
    fi
    kill -TERM "$agent_pid"
    wait "$agent_pid"
    agent_pid=
    if [[ "$topology" == foreign-qdisc ]]; then
        tc -j -d qdisc show dev nqt-test | python3 -c 'import json,sys; print(json.dumps([q for q in json.load(sys.stdin) if q.get("root")], sort_keys=True))' > "$work/qdisc-after.json"
        cmp "$work/qdisc-before.json" "$work/qdisc-after.json"
        tc -j class show dev nqt-test > "$work/classes-after.json"
        cmp "$work/classes-before.json" "$work/classes-after.json"
    elif [[ "$topology" == foreign-filter || "$topology" == bridge-foreign-filter ]]; then
        tc -j filter show dev "$filter_dev" egress > "$work/filters-after.json"
        cmp "$work/filters-before.json" "$work/filters-after.json"
    fi
    echo "CLIENT_TOTAL_CONFLICT_PRESERVED topology=$topology"
    exit 0
fi
for _ in $(seq 1 200); do
    if grep -q 'QoS priority client runtime active' "$work/agent.log"; then break; fi
    kill -0 "$agent_pid" 2>/dev/null || break
    sleep 0.05
done
grep -q 'QoS priority client runtime active' "$work/agent.log"
test -f "$runtime_dir/evidence.priority-runtime.json"
ip link show "$ifb" >/dev/null
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=
if ip link show "$ifb" >/dev/null 2>&1; then
    echo 'Priority IFB remained after shutdown' >&2
    exit 1
fi
echo "CLIENT_TOTAL_OPT_IN_AND_CLEANUP_OK topology=$topology"
