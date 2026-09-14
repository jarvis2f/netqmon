#!/usr/bin/env bash
# OpenWrt Packet Sampling On/Off Performance Gate
#
# Run on an OpenWrt target. Optional:
#   COLLECTOR_DIAGNOSTICS_URL=http://127.0.0.1:8091/internal/settings/diagnostics

set -euo pipefail

DURATION=${1:-30}
AGENT_BIN=${AGENT_BIN:-/usr/bin/netqmon-agent}
LOG_DIR=${LOG_DIR:-/tmp/netqmon-probe-gate}
SCENARIO=${SCENARIO:-idle}
TRAFFIC_COMMAND=${TRAFFIC_COMMAND:-}
THROUGHPUT_COMMAND=${THROUGHPUT_COMMAND:-}
LATENCY_COMMAND=${LATENCY_COMMAND:-}
PAGE_SIZE=$(getconf PAGESIZE 2>/dev/null || echo 4096)

mkdir -p "$LOG_DIR"

echo "=== OpenWrt Packet Sampling Performance Gate ==="
echo "Test duration: ${DURATION}s per phase"
echo "Agent: $AGENT_BIN"
echo "Scenario: $SCENARIO"
echo "WARNING: use info logging for performance baselines; debug/trace logging invalidates results."
if [ -n "$TRAFFIC_COMMAND" ]; then
    echo "Traffic command: $TRAFFIC_COMMAND"
else
    echo "Traffic command: none (idle phase; set TRAFFIC_COMMAND for a repeatable workload)"
fi
if [ -n "$THROUGHPUT_COMMAND" ]; then
    echo "Throughput command: $THROUGHPUT_COMMAND"
fi
if [ -n "$LATENCY_COMMAND" ]; then
    echo "Latency command: $LATENCY_COMMAND"
fi

if [ ! -x "$AGENT_BIN" ]; then
    echo "Agent binary not found at $AGENT_BIN"
    exit 1
fi

fetch_optional_metric() {
    local key=$1
    if [ -z "${COLLECTOR_DIAGNOSTICS_URL:-}" ] || ! command -v curl >/dev/null 2>&1; then
        echo "unavailable"
        return
    fi
    local response
    response=$(curl -fsS "$COLLECTOR_DIAGNOSTICS_URL" 2>/dev/null || true)
    printf '%s\n' "$response" |
        sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p"
}

fetch_agent_metric() {
    local key=$1
    local response
    response=$("$AGENT_BIN" diagnostics --json 2>/dev/null || true)
    printf '%s\n' "$response" |
        sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

bpf_map_memory_bytes() {
    if ! command -v bpftool >/dev/null 2>&1; then
        echo "unavailable"
        return
    fi
    local json
    json=$(bpftool -j map show 2>/dev/null || true)
    if [ -n "$json" ]; then
        local json_total
        json_total=$(printf '%s\n' "$json" |
            sed 's/},{/}\n{/g' |
            sed -n 's/.*"name":"\(flow_map\|sample_budgets\)".*"bytes_memlock":\([0-9][0-9]*\).*/\2/p' |
            awk '{sum += $1} END {if (sum) print sum}')
        if [ -n "$json_total" ]; then
            echo "$json_total"
            return
        fi
    fi
    bpftool map show 2>/dev/null |
        awk '/name (flow_map|sample_budgets)/ {for (i=1; i<=NF; i++) if ($i == "memlock") {value=$(i+1); gsub(/B/, "", value); sum += value}} END {if (sum) print sum; else print "unavailable"}'
}

read_system_cpu() {
    awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8, $9; exit}' /proc/stat
}

numeric_delta() {
    local before=$1
    local after=$2
    case "$before:$after" in
        *[!0-9:]*|:|*:|"unavailable":*|*:"unavailable") echo "unavailable" ;;
        *) echo $((after - before)) ;;
    esac
}

measure_performance() {
    local phase=$1
    local enable_sample=$2
    local log_file="$LOG_DIR/${phase}.log"

    echo "---"
    echo "Sample $phase"
    echo "Starting agent with NETQMON_SAMPLE_ENABLED=$enable_sample"

    export NETQMON_SAMPLE_ENABLED="$enable_sample"
    export NETQMON_DIAGNOSTICS_ENABLED=true
    export NETQMON_LOG_LEVEL=info
    "$AGENT_BIN" run >"$log_file" 2>&1 &
    local agent_pid=$!

    sleep 2
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        echo "Agent failed to start; see $log_file"
        exit 1
    fi

    local sample_drops_before
    local lag_before
    local queue_drops_before
    local bpf_memory_before
    sample_drops_before=$(fetch_optional_metric "sample_drops")
    lag_before=$(fetch_optional_metric "lag_ms")
    queue_drops_before=$(fetch_optional_metric "dropped_batches")
    bpf_memory_before=$(bpf_map_memory_bytes)

    local samples=0
    local cpu_sum=0
    local rss_sum=0
    local max_cpu=0
    local max_rss=0
    local system_cpu_sum=0
    local softirq_cpu_sum=0
    local previous_cpu
    previous_cpu=$(read_system_cpu)
    local traffic_pid=""
    local throughput_pid=""
    local latency_pid=""
    if [ -n "$TRAFFIC_COMMAND" ]; then
        sh -c "$TRAFFIC_COMMAND" >"$LOG_DIR/${phase}.traffic.log" 2>&1 &
        traffic_pid=$!
    fi
    if [ -n "$THROUGHPUT_COMMAND" ]; then
        sh -c "$THROUGHPUT_COMMAND" >"$LOG_DIR/${phase}.throughput.log" 2>&1 &
        throughput_pid=$!
    fi
    if [ -n "$LATENCY_COMMAND" ]; then
        sh -c "$LATENCY_COMMAND" >"$LOG_DIR/${phase}.latency.log" 2>&1 &
        latency_pid=$!
    fi

    for ((i = 0; i < DURATION; i++)); do
        if ! kill -0 "$agent_pid" 2>/dev/null; then
            echo "Agent died prematurely; see $log_file"
            break
        fi

        local statm_rss
        statm_rss=$(awk '{print $2}' "/proc/$agent_pid/statm" 2>/dev/null || echo 0)
        local rss_kb=$((statm_rss * PAGE_SIZE / 1024))
        local cpu
        local top_output
        top_output=$(top -b -n 1 2>/dev/null || true)
        cpu=$(printf '%s\n' "$top_output" | awk -v pid="$agent_pid" '
            $1 == pid && !found {gsub(/%/, "", $7); value = int($7); found = 1}
            END {if (found) print value}'
        )
        cpu=${cpu:-0}

        local current_cpu
        current_cpu=$(read_system_cpu)
        local system_cpu
        local softirq_cpu
        system_cpu=$(awk -v before="$previous_cpu" -v after="$current_cpu" 'BEGIN {
            split(before,b); split(after,a); total=0; for(i=1;i<=8;i++) total+=a[i]-b[i]; idle=(a[4]-b[4])+(a[5]-b[5]); print total ? int(100*(total-idle)/total) : 0
        }')
        softirq_cpu=$(awk -v before="$previous_cpu" -v after="$current_cpu" 'BEGIN {
            split(before,b); split(after,a); total=0; for(i=1;i<=8;i++) total+=a[i]-b[i]; print total ? int(100*(a[7]-b[7])/total) : 0
        }')
        previous_cpu=$current_cpu

        cpu_sum=$((cpu_sum + cpu))
        rss_sum=$((rss_sum + rss_kb))
        system_cpu_sum=$((system_cpu_sum + system_cpu))
        softirq_cpu_sum=$((softirq_cpu_sum + softirq_cpu))
        [ "$cpu" -gt "$max_cpu" ] && max_cpu=$cpu
        [ "$rss_kb" -gt "$max_rss" ] && max_rss=$rss_kb
        samples=$((samples + 1))
        sleep 1
    done

    if [ -n "$traffic_pid" ]; then
        kill "$traffic_pid" 2>/dev/null || true
        wait "$traffic_pid" 2>/dev/null || true
    fi
    if [ -n "$throughput_pid" ]; then
        kill "$throughput_pid" 2>/dev/null || true
        wait "$throughput_pid" 2>/dev/null || true
    fi
    if [ -n "$latency_pid" ]; then
        kill "$latency_pid" 2>/dev/null || true
        wait "$latency_pid" 2>/dev/null || true
    fi

    local avg_cpu=0
    local avg_rss=0
    local avg_system_cpu=0
    local avg_softirq_cpu=0
    if [ "$samples" -gt 0 ]; then
        avg_cpu=$((cpu_sum / samples))
        avg_rss=$((rss_sum / samples))
        avg_system_cpu=$((system_cpu_sum / samples))
        avg_softirq_cpu=$((softirq_cpu_sum / samples))
    fi

    local flow_deltas
    flow_deltas=$(grep -c "^flow delta " "$log_file" 2>/dev/null || true)
    local lifecycle_events
    lifecycle_events=$(grep -c "^flow lifecycle " "$log_file" 2>/dev/null || true)
    local sample_drops_after
    local lag_after
    local queue_drops_after
    local bpf_memory_after
    sample_drops_after=$(fetch_optional_metric "sample_drops")
    lag_after=$(fetch_optional_metric "lag_ms")
    queue_drops_after=$(fetch_optional_metric "dropped_batches")
    bpf_memory_after=$(bpf_map_memory_bytes)

    local flow_entries
    local sample_budget_entries
    local poll_duration
    local keys_scanned
    local telemetry_queue_bytes
    local sample_events
    local sampled_flows
    local sample_event_bytes
    local sample_queue_items
    local sample_queue_bytes
    local conntrack_refreshes
    local conntrack_refresh_duration
    local discovery_events
    local discovery_parse_rate
    local discovery_duplicate_rate
    local dns_drops
    local neighbor_refresh_duration
    local dhcp_refresh_duration
    local throughput_result="unavailable"
    local latency_result="unavailable"
    flow_entries=$(fetch_agent_metric "flow_map_entries")
    sample_budget_entries=$(fetch_agent_metric "sample_budget_entries")
    sample_events=$(fetch_agent_metric "sample_events")
    sampled_flows=$(fetch_agent_metric "sampled_flows")
    sample_event_bytes=$(fetch_agent_metric "sample_event_bytes")
    sample_queue_items=$(fetch_agent_metric "sample_queue_items")
    sample_queue_bytes=$(fetch_agent_metric "sample_queue_bytes")
    poll_duration=$(fetch_agent_metric "poll_duration_us")
    keys_scanned=$(fetch_agent_metric "keys_scanned")
    telemetry_queue_bytes=$(fetch_agent_metric "queue_bytes")
    conntrack_refreshes=$(fetch_agent_metric "conntrack_refreshes")
    conntrack_refresh_duration=$(fetch_agent_metric "conntrack_refresh_duration_us")
    discovery_events=$(fetch_agent_metric "discovery_events")
    discovery_parse_rate=$(fetch_agent_metric "discovery_parse_rate_ppm")
    discovery_duplicate_rate=$(fetch_agent_metric "discovery_duplicate_rate_ppm")
    dns_drops=$(fetch_agent_metric "dns_drops")
    neighbor_refresh_duration=$(fetch_agent_metric "neighbor_refresh_duration_us")
    dhcp_refresh_duration=$(fetch_agent_metric "dhcp_lease_refresh_duration_us")
    if [ -f "$LOG_DIR/${phase}.throughput.log" ]; then
        throughput_result=$(sed -n 's/.*"bits_per_second"[[:space:]]*:[[:space:]]*\([0-9.][0-9.]*\).*/\1/p' "$LOG_DIR/${phase}.throughput.log" | tail -n 1)
        throughput_result=${throughput_result:-$(tail -n 1 "$LOG_DIR/${phase}.throughput.log" 2>/dev/null || echo unavailable)}
    fi
    if [ -f "$LOG_DIR/${phase}.latency.log" ]; then
        latency_result=$(awk -F'=' '/rtt|round-trip/ {split($2, values, "/"); print values[2]; exit}' "$LOG_DIR/${phase}.latency.log")
        latency_result=${latency_result:-$(tail -n 1 "$LOG_DIR/${phase}.latency.log" 2>/dev/null || echo unavailable)}
    fi

    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true

    echo "Avg CPU: $avg_cpu%, Max CPU: $max_cpu%"
    echo "Avg system CPU: $avg_system_cpu%, Avg softirq CPU: $avg_softirq_cpu%"
    echo "Avg RSS: ${avg_rss}KB, Max RSS: ${max_rss}KB"
    echo "Flow delta log lines: $flow_deltas"
    echo "Flow lifecycle log lines: $lifecycle_events"
    echo "Protocol probe drops delta: $(numeric_delta "$sample_drops_before" "$sample_drops_after")"
    echo "Agent queue drops delta: $(numeric_delta "$queue_drops_before" "$queue_drops_after")"
    echo "Collector/agent lag delta: $(numeric_delta "$lag_before" "$lag_after")"
    echo "BPF map memory before/after: $bpf_memory_before / $bpf_memory_after bytes"
    echo "Flow/sample budget entries: ${flow_entries:-unavailable} / ${sample_budget_entries:-unavailable}"
    echo "Poll duration/keys scanned: ${poll_duration:-unavailable}us / ${keys_scanned:-unavailable}"
    echo "Telemetry queue bytes: ${telemetry_queue_bytes:-unavailable}"
    echo "Sample events/flows/bytes: ${sample_events:-unavailable} / ${sampled_flows:-unavailable} / ${sample_event_bytes:-unavailable}"
    echo "Sample queue items/bytes: ${sample_queue_items:-unavailable} / ${sample_queue_bytes:-unavailable}"
    echo "Conntrack refreshes/duration: ${conntrack_refreshes:-unavailable} / ${conntrack_refresh_duration:-unavailable}us"
    echo "Discovery events/parse ppm/duplicate ppm: ${discovery_events:-unavailable} / ${discovery_parse_rate:-unavailable} / ${discovery_duplicate_rate:-unavailable}"
    echo "DNS drops/neighbor refresh/DHCP refresh: ${dns_drops:-unavailable} / ${neighbor_refresh_duration:-unavailable}us / ${dhcp_refresh_duration:-unavailable}us"
    echo "Throughput result: $throughput_result (log: $LOG_DIR/${phase}.throughput.log)"
    echo "Latency result: $latency_result ms (log: $LOG_DIR/${phase}.latency.log)"
    echo "Log: $log_file"

    if [ "$phase" = "OFF" ]; then
        OFF_CPU=$avg_cpu
        OFF_RSS=$avg_rss
        OFF_SYSTEM_CPU=$avg_system_cpu
        OFF_SOFTIRQ_CPU=$avg_softirq_cpu
        OFF_POLL_DURATION=${poll_duration:-unavailable}
        OFF_KEYS_SCANNED=${keys_scanned:-unavailable}
        OFF_FLOW_DELTAS=$flow_deltas
        OFF_LIFECYCLE=$lifecycle_events
        OFF_PROBE_DROPS=$(numeric_delta "$sample_drops_before" "$sample_drops_after")
        OFF_QUEUE_DROPS=$(numeric_delta "$queue_drops_before" "$queue_drops_after")
        OFF_LAG=$(numeric_delta "$lag_before" "$lag_after")
        OFF_SAMPLE_EVENTS=${sample_events:-unavailable}
        OFF_SAMPLE_DROPS=${sample_drops_after:-unavailable}
        OFF_DISCOVERY_EVENTS=${discovery_events:-unavailable}
        OFF_DNS_DROPS=${dns_drops:-unavailable}
        OFF_THROUGHPUT=$throughput_result
        OFF_LATENCY=$latency_result
    else
        ON_CPU=$avg_cpu
        ON_RSS=$avg_rss
        ON_SYSTEM_CPU=$avg_system_cpu
        ON_SOFTIRQ_CPU=$avg_softirq_cpu
        ON_POLL_DURATION=${poll_duration:-unavailable}
        ON_KEYS_SCANNED=${keys_scanned:-unavailable}
        ON_FLOW_DELTAS=$flow_deltas
        ON_LIFECYCLE=$lifecycle_events
        ON_PROBE_DROPS=$(numeric_delta "$sample_drops_before" "$sample_drops_after")
        ON_QUEUE_DROPS=$(numeric_delta "$queue_drops_before" "$queue_drops_after")
        ON_LAG=$(numeric_delta "$lag_before" "$lag_after")
        ON_SAMPLE_EVENTS=${sample_events:-unavailable}
        ON_SAMPLE_DROPS=${sample_drops_after:-unavailable}
        ON_DISCOVERY_EVENTS=${discovery_events:-unavailable}
        ON_DNS_DROPS=${dns_drops:-unavailable}
        ON_THROUGHPUT=$throughput_result
        ON_LATENCY=$latency_result
    fi
}

measure_performance "OFF" "false"
measure_performance "ON" "true"

echo "=== Summary ==="
echo "Metric | Sample OFF | Sample ON | Delta"
echo "-------------------------------------"
echo "CPU % | $OFF_CPU | $ON_CPU | $(numeric_delta "$OFF_CPU" "$ON_CPU")"
echo "RSS KB | $OFF_RSS | $ON_RSS | $(numeric_delta "$OFF_RSS" "$ON_RSS")"
echo "System CPU % | $OFF_SYSTEM_CPU | $ON_SYSTEM_CPU | $(numeric_delta "$OFF_SYSTEM_CPU" "$ON_SYSTEM_CPU")"
echo "Softirq CPU % | $OFF_SOFTIRQ_CPU | $ON_SOFTIRQ_CPU | $(numeric_delta "$OFF_SOFTIRQ_CPU" "$ON_SOFTIRQ_CPU")"
echo "Poll duration us | $OFF_POLL_DURATION | $ON_POLL_DURATION | $(numeric_delta "$OFF_POLL_DURATION" "$ON_POLL_DURATION")"
echo "Keys scanned | $OFF_KEYS_SCANNED | $ON_KEYS_SCANNED | $(numeric_delta "$OFF_KEYS_SCANNED" "$ON_KEYS_SCANNED")"
echo "Flow deltas | $OFF_FLOW_DELTAS | $ON_FLOW_DELTAS | $(numeric_delta "$OFF_FLOW_DELTAS" "$ON_FLOW_DELTAS")"
echo "Flow lifecycle events | $OFF_LIFECYCLE | $ON_LIFECYCLE | $(numeric_delta "$OFF_LIFECYCLE" "$ON_LIFECYCLE")"
echo "Protocol probe drops | $OFF_PROBE_DROPS | $ON_PROBE_DROPS | unavailable"
echo "Agent queue drops | $OFF_QUEUE_DROPS | $ON_QUEUE_DROPS | unavailable"
echo "Collector/agent lag ms | $OFF_LAG | $ON_LAG | unavailable"
echo "Sample events | $OFF_SAMPLE_EVENTS | $ON_SAMPLE_EVENTS | unavailable"
echo "Sample drops (cumulative) | $OFF_SAMPLE_DROPS | $ON_SAMPLE_DROPS | unavailable"
echo "Discovery events | $OFF_DISCOVERY_EVENTS | $ON_DISCOVERY_EVENTS | unavailable"
echo "DNS drops | $OFF_DNS_DROPS | $ON_DNS_DROPS | unavailable"
echo "Throughput result | $OFF_THROUGHPUT | $ON_THROUGHPUT | unavailable"
echo "Latency result (ms) | $OFF_LATENCY | $ON_LATENCY | unavailable"
echo
echo "For forwarding acceptance, set TRAFFIC_COMMAND plus the same iperf3 command in THROUGHPUT_COMMAND and a ping command in LATENCY_COMMAND."
echo "Run the script once per matrix item with identical commands for Sample OFF and Sample ON."
echo
echo "Required scenario matrix (rerun with SCENARIO set and identical traffic generation):"
echo "idle, web, tcp-download, udp-throughput, short-connections, 1000-plus-flows, controller-online, controller-offline-60s"
