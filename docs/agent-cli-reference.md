# NetQmon Agent CLI & Configuration Reference

`netqmon-agent` is a lightweight network telemetry daemon designed for OpenWrt routers and Linux gateways. Leveraging the kernel **TC eBPF** subsystem, it captures flow metrics, DNS query events, connection lifecycles, and bounded packet samples without modifying or intercepting user payloads, streaming batches reliably to the NetQmon Controller.

---

## 1. Command-Line Syntax & Global Options

```bash
netqmon-agent [OPTIONS] [COMMAND]
```

### Global Options

| Option | Short | Description | Example |
| :--- | :---: | :--- | :--- |
| `--config <PATH>` | `-c` | Path to the TOML configuration file (defaults to `/etc/netqmon/agent.toml`). | `-c /etc/netqmon/custom.toml` |
| `--interface <NAME>` | `-i` | Capture network interface name. **Can be specified multiple times** to attach to multiple interfaces (defaults to `br-lan`). | `-i br-lan -i eth1` |
| `--help` | `-h` | Print help information. | `-h` |
| `--version` | `-V` | Print current agent version. | `-V` |

---

## 2. Subcommands Reference

### 2.1 `run` (Default)

Loads the eBPF programs into the kernel TC ingress/egress hooks on configured interfaces and runs the telemetry collector daemon. Executing `netqmon-agent` without arguments is equivalent to `netqmon-agent run`.

```bash
# Standard execution
netqmon-agent run

# Running with interface overrides
netqmon-agent run -i br-lan -i eth1
```

On OpenWrt, the agent is supervised as a native `procd` service:
```bash
/etc/init.d/netqmon start
/etc/init.d/netqmon restart
/etc/init.d/netqmon status
```

---

### 2.2 `doctor` (Environment & Capability Probe)

Probes kernel version, architecture, eBPF subsystem availability, TC filter attach modes, resource limits, and network interfaces, outputting a structured diagnosis report. Recommended for verifying new router installations.

```bash
netqmon-agent doctor
```

**Checks Performed:**
* **Kernel & Architecture**: Linux kernel version and CPU architecture validation.
* **eBPF Capabilities**: Verification of the `bpf()` system call and BPF filesystem mount (`/sys/fs/bpf`).
* **TC Filter Attach**: Tests attachment modes on network devices (TCX or Netlink TC fallback).
* **Resource Limits**: Checks `RLIMIT_MEMLOCK` memory lock limits required for BPF map allocations.
* **Network & Conntrack**: Validates device operational status, IP addressing, and connection tracking tables.

---

### 2.3 `diagnostics` / `diag` (Runtime Diagnostics & Control)

Connects to the running agent via its local Unix domain socket (default `/run/netqmon/agent.sock`) to inspect performance counters or adjust runtime collection.

```bash
# Print a human-readable summary of runtime diagnostics
netqmon-agent diagnostics

# Output in JSON format (ideal for script automation or custom monitoring)
netqmon-agent diagnostics --json
```

**Management Actions:**

| Action | Description | Example |
| :--- | :--- | :--- |
| `enable` | Dynamically enables runtime diagnostics collection and persists it in the configuration. | `netqmon-agent diagnostics enable` |
| `disable` | Dynamically disables runtime diagnostics collection to minimize overhead. | `netqmon-agent diagnostics disable` |
| `reset` | Resets cumulative telemetry counters (dropped flows, retry queue depth, error counters). | `netqmon-agent diagnostics reset` |

---

## 3. Configuration File Reference (`agent.toml`)

The default configuration file path is `/etc/netqmon/agent.toml`. Complete options and default values are documented below:

```toml
# Network capture interfaces (single string or array)
interface = "br-lan"
interfaces = ["br-lan"]

# Controller endpoint and security token
controller_url = "http://192.168.1.100:8090"
token = "your-enrollment-or-agent-token"

# Polling and batching intervals
poll_interval_ms = 1000       # Polling interval for reading BPF flow tables (milliseconds)
batch_interval_ms = 1000      # Interval for uploading telemetry batches to Controller (milliseconds)
max_flows = 65536             # Maximum tracked concurrent flows in BPF map

# Buffering and retry
retry_buffer_seconds = 60                   # Maximum buffer duration during network disconnection
telemetry_retry_buffer_bytes = 8388608      # Maximum memory for retry buffer (bytes, default 8MB)

# Idle connection timeouts
tcp_idle_timeout_seconds = 120              # TCP connection idle timeout before emitting close event
udp_idle_timeout_seconds = 30               # UDP flow idle timeout before emitting close event

# Packet payload sampling (for protocol and application recognition)
sample_enabled = true                       # Enable packet payload sampling
sample_max_packets_per_direction = 4        # Maximum sampled packets per flow direction
sample_max_bytes_per_packet = 1024          # Maximum byte depth sampled per packet
sample_max_bytes_per_flow = 4096            # Maximum aggregate sampled bytes per flow

# Logging level: error | warn | info | debug | trace
log_level = "info"

# Runtime diagnostics socket
diagnostics_enabled = false

[bpf]
backend = "auto"              # TC attachment backend: "auto", "tcx", or "netlink"
tc_priority = 49152           # Classic TC filter priority
tc_handle = 1313946881        # Classic TC filter handle (0x4e514d01)
tcx_order = "first"           # TCX link ordering: "first" or "last"
```

---

## 4. Environment Variables Reference

Every configuration option can be overridden via environment variables:

| Environment Variable | Config Equivalent | Example |
| :--- | :--- | :--- |
| `NETQMON_INTERFACE` | `interface` | `br-lan` |
| `NETQMON_INTERFACES` | `interfaces` | `br-lan,eth1` |
| `NETQMON_CONTROLLER_URL`| `controller_url` | `http://192.168.1.100:8090` |
| `NETQMON_TOKEN` | `token` | `secret-token` |
| `NETQMON_POLL_INTERVAL_MS` | `poll_interval_ms` | `1000` |
| `NETQMON_BATCH_INTERVAL_MS`| `batch_interval_ms` | `1000` |
| `NETQMON_MAX_FLOWS` | `max_flows` | `65536` |
| `NETQMON_SAMPLE_ENABLED` | `sample_enabled` | `true` |
| `NETQMON_LOG_LEVEL` | `log_level` | `info` |
| `NETQMON_SOCKET_PATH` | *(Diagnostics socket)* | `/run/netqmon/agent.sock` |

---

## 5. OpenWrt UCI Integration

On OpenWrt, the agent integrates natively with the UCI configuration system (`/etc/config/netqmon`):

```bash
# View active UCI configuration
uci show netqmon

# Set Controller URL and commit changes
uci set netqmon.main.controller_url="http://192.168.1.100:8090"
uci commit netqmon

# Restart agent service
/etc/init.d/netqmon restart
```
