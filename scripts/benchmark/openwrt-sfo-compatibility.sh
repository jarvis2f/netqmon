#!/bin/sh
set -eu

interface=${NETQMON_SFO_INTERFACE:-br-lan}
duration=${NETQMON_SFO_DURATION_SECONDS:-10}
traffic_cmd=${NETQMON_SFO_TRAFFIC_CMD:-"ping -c ${duration} -s 1200 1.1.1.1 >/dev/null"}

read_counter() {
    cat "/sys/class/net/${interface}/statistics/$1"
}

cpu_total_idle() {
    awk '/^cpu / { print $2+$3+$4+$5+$6+$7+$8+$9+$10, $5 }' /proc/stat
}

agent_cpu_ticks() {
    pid=$(pgrep -x netqmon-agent 2>/dev/null | head -n 1 || true)
    [ -n "$pid" ] || {
        echo 0
        return
    }
    awk '{ print $14+$15 }' "/proc/${pid}/stat" 2>/dev/null || echo 0
}

set_sfo() {
    enabled=$1
    uci set firewall.@defaults[0].flow_offloading="$enabled"
    uci commit firewall
    /etc/init.d/firewall restart >/dev/null 2>&1 || /etc/init.d/firewall reload >/dev/null 2>&1
    sleep 2
}

run_case() {
    enabled=$1
    set_sfo "$enabled"

    rx_bytes_before=$(read_counter rx_bytes)
    tx_bytes_before=$(read_counter tx_bytes)
    rx_packets_before=$(read_counter rx_packets)
    tx_packets_before=$(read_counter tx_packets)
    set -- $(cpu_total_idle)
    cpu_total_before=$1
    cpu_idle_before=$2
    agent_cpu_before=$(agent_cpu_ticks)
    started=$(date +%s)

    sh -c "$traffic_cmd"

    ended=$(date +%s)
    rx_bytes_after=$(read_counter rx_bytes)
    tx_bytes_after=$(read_counter tx_bytes)
    rx_packets_after=$(read_counter rx_packets)
    tx_packets_after=$(read_counter tx_packets)
    set -- $(cpu_total_idle)
    cpu_total_after=$1
    cpu_idle_after=$2
    agent_cpu_after=$(agent_cpu_ticks)

    elapsed=$((ended - started))
    [ "$elapsed" -gt 0 ] || elapsed=1
    bytes=$((rx_bytes_after - rx_bytes_before + tx_bytes_after - tx_bytes_before))
    packets=$((rx_packets_after - rx_packets_before + tx_packets_after - tx_packets_before))
    throughput_bps=$((bytes * 8 / elapsed))
    cpu_total_delta=$((cpu_total_after - cpu_total_before))
    cpu_idle_delta=$((cpu_idle_after - cpu_idle_before))
    if [ "$cpu_total_delta" -gt 0 ]; then
        cpu_busy_percent=$(((cpu_total_delta - cpu_idle_delta) * 100 / cpu_total_delta))
        agent_cpu_percent=$(((agent_cpu_after - agent_cpu_before) * 100 / cpu_total_delta))
    else
        cpu_busy_percent=0
        agent_cpu_percent=0
    fi

    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$enabled" "$elapsed" "$bytes" "$packets" "$throughput_bps" \
        "$cpu_busy_percent" "$agent_cpu_percent"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "openwrt-sfo-compatibility.sh must run as root" >&2
    exit 1
fi

if [ ! -d "/sys/class/net/${interface}/statistics" ]; then
    echo "interface ${interface} does not expose sysfs counters" >&2
    exit 1
fi

original_sfo=$(uci -q get firewall.@defaults[0].flow_offloading || echo 0)
trap 'uci set firewall.@defaults[0].flow_offloading="'"$original_sfo"'"; uci commit firewall; /etc/init.d/firewall restart >/dev/null 2>&1 || true' EXIT INT TERM

echo "sfo_enabled,elapsed_seconds,bytes,packets,throughput_bps,cpu_busy_percent,agent_cpu_percent"
run_case 0
run_case 1
