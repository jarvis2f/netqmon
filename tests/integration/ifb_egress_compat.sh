#!/usr/bin/env bash
# Run on a Linux test host as root. The test re-executes in private namespaces.
set -euo pipefail

if [[ ${NETQMON_IFB_TEST_ISOLATED:-0} != 1 ]]; then
    export NETQMON_IFB_TEST_ISOLATED=1
    exec unshare --mount --net -- bash "$0" "$@"
fi
if [[ $(readlink /proc/self/ns/net) == $(readlink /proc/1/ns/net) ||
      $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo 'Refusing to modify the host network or mount namespace' >&2
    exit 1
fi

work=$(mktemp -d)
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
    ip netns del nq-ifb-peer 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

ip netns add nq-ifb-peer
ip link add nq-ifb-wan numtxqueues 4 type veth peer name nq-ifb-peer
ip link set nq-ifb-peer netns nq-ifb-peer
ip addr add 192.0.2.1/24 dev nq-ifb-wan
ip -n nq-ifb-peer addr add 192.0.2.2/24 dev nq-ifb-peer
ip link set nq-ifb-wan up
ip -n nq-ifb-peer link set nq-ifb-peer up
tc qdisc replace dev nq-ifb-wan root handle 10: mq
# A non-default leaf verifies that the existing tree is not reconstructed.
tc qdisc replace dev nq-ifb-wan parent 10:1 fq_codel memory_limit 4Mb
tc -j -d qdisc show dev nq-ifb-wan > "$work/before.json"

ip link add nq-ifb-test type ifb
ip link set nq-ifb-test up
tc qdisc add dev nq-ifb-wan clsact
tc filter add dev nq-ifb-wan egress pref 49100 matchall action mirred egress redirect dev nq-ifb-test
tc qdisc add dev nq-ifb-test root handle 51: htb default 1
tc class add dev nq-ifb-test parent 51: classid 51:1 htb rate 20mbit
tc class add dev nq-ifb-test parent 51:1 classid 51:10 htb rate 1mbit ceil 1mbit
tc filter add dev nq-ifb-test parent 51: protocol all pref 10 handle 0x10000/0xffff0000 fw classid 51:10
nft add table inet nq_ifb_test
nft 'add chain inet nq_ifb_test output { type route hook output priority mangle; }'
nft add rule inet nq_ifb_test output meta mark set 0x10000

ip netns exec nq-ifb-peer iperf3 -s -1 > "$work/server.log" 2>&1 &
server_pid=$!
for _ in {1..50}; do
    if ip netns exec nq-ifb-peer ss -lnt | grep -q ':5201 '; then break; fi
    sleep 0.1
done
iperf3 -c 192.0.2.2 -t 3 -J > "$work/iperf.json"
wait "$server_pid"
server_pid=
tc -s class show dev nq-ifb-test > "$work/classes.txt"
python3 - "$work/iperf.json" "$work/classes.txt" <<'PY'
import json, re, sys
with open(sys.argv[1]) as f:
    result = json.load(f)
rate = result['end']['sum_received']['bits_per_second']
with open(sys.argv[2]) as f:
    classes = f.read()
marked = re.search(r'class htb 51:10\b.*?Sent (\d+) bytes', classes, re.S)
if not marked or int(marked.group(1)) == 0:
    raise SystemExit('marked packets did not reach the IFB client class')
if not 300_000 <= rate <= 1_500_000:
    raise SystemExit(f'unexpected received throughput: {rate:.0f} bit/s')
print(f'IFB client class received packets; throughput {rate:.0f} bit/s')
PY

tc filter del dev nq-ifb-wan egress pref 49100
tc qdisc del dev nq-ifb-wan clsact
ip link del nq-ifb-test
tc -j -d qdisc show dev nq-ifb-wan > "$work/after.json"
python3 - "$work/before.json" "$work/after.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    before = json.load(f)
with open(sys.argv[2]) as f:
    after = json.load(f)
if before != after:
    raise SystemExit(f'original qdisc changed: {before!r} != {after!r}')
print('Existing mq tree and custom child options remained unchanged')
PY
