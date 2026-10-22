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

The report also includes policy enforcement eligibility. Client aggregate shaping
is only reported as supported when the Agent verifies its LAN/WAN path, link
capacity, qdisc ownership, packet-mark availability, and disabled flow offload.

### 2.3 `policies` (Local Policy Status and Recovery)

Inspect the policy revision and local enforcement capability, or manage the
emergency disable marker without a Collector connection:

```bash
netqmon-agent policies status
netqmon-agent policies status --json
netqmon-agent policies unlock
netqmon-agent policies resume
```

`unlock` disables future remote snapshots and removes only verified NetQmon
rules and qdiscs. `resume` removes the local disable marker and reapplies the
last valid policy snapshot. Snapshots containing application rules are restored
by the running Agent on its next reconciliation tick, when its eBPF writer is
available. `status --json` includes aggregate-limit capability,
its reason, and the saved shaping interfaces and client-class count.

Egress capacity is detected automatically from the negotiated physical link
speed, including multi-gigabit links. For a bridge with a default gateway, the
Agent uses the gateway neighbour and bridge forwarding table to locate the
physical port; it does not use a bridge or virtual member's synthetic speed.
Single lower links (such as VLAN parents) are followed to the physical device.
A bridge without a default gateway is detected only when it has one unambiguous
physical attachment. Multiple unresolved paths require an explicit capacity.

If automatic detection is unavailable, configure the egress capacity explicitly
(at least 64000 bits per second, within the JSON safe integer range):

```toml
[policy_interface_capacity_bps]
eth1 = 100000000
eth2 = 100000000
```

The environment equivalent is
`NETQMON_POLICY_INTERFACE_CAPACITY_BPS='{"eth1":100000000,"eth2":100000000}'`.
When both an explicit capacity and a measured link speed are available, the
smaller value is used. `policies status --json` reports capacity, its source and
the physical link interfaces. Link capacity is distinct from the application's
configured policy limit and is not an Internet bandwidth measurement.

One-arm policy enforcement is enabled by default, assuming both directions of
every enabled address family traverse the Agent. Configure and verify this
routing externally; the Agent cannot independently verify the upstream return
path. Set `policy_one_arm_return_path_verified = false` in TOML to explicitly
disable one-arm shaping when that routing is unavailable. This setting has no
environment-variable override. One-arm shaping also requires disabled ICMP
redirects and flow offload. The Agent does
not configure NAT or upstream routes. A shared physical HTB root contains
separate upload/download branches, client budgets and application subclasses.
Application budgets aggregate connections per client, policy and direction;
IPv4 and IPv6 share the same budget. Unknown applications use the default class
and remain subject to any client budget. OpenWrt requires `tc-full`, HTB,
fw classifiers and fq_codel support.

For Router application shaping, include both LAN and WAN in `interfaces` so
the Agent can mark the exact egress tuples in both directions. The capability
check rejects application shaping when a shaping interface is not observed.

### 2.4 `diagnostics` / `diag` (Runtime Diagnostics & Control)

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

# Optional policy stream override. Otherwise it is derived from controller_url.
# Plain ws:// is enabled by default for loopback or RFC 1918/ULA IP addresses only.
# policy_ws_url = "wss://controller.example.net:8090/v1/agent/policies/stream"
allow_insecure_policy_ws = true

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
| `NETQMON_POLICY_WS_URL` | `policy_ws_url` | `wss://controller.example.net:8090/v1/agent/policies/stream` |
| `NETQMON_ALLOW_INSECURE_POLICY_WS` | `allow_insecure_policy_ws` | `true` (only loopback or RFC 1918/ULA IP hosts may use `ws://`) |
| `NETQMON_POLL_INTERVAL_MS` | `poll_interval_ms` | `1000` |
| `NETQMON_BATCH_INTERVAL_MS`| `batch_interval_ms` | `1000` |
| `NETQMON_MAX_FLOWS` | `max_flows` | `65536` |
| `NETQMON_SAMPLE_ENABLED` | `sample_enabled` | `true` |
| `NETQMON_LOG_LEVEL` | `log_level` | `info` |
| `NETQMON_SOCKET_PATH` | *(Diagnostics socket)* | `/run/netqmon/agent.sock` |

---

## 5. OpenWrt UCI Integration

On OpenWrt, the agent integrates natively with the UCI configuration system (`/etc/config/netqmon`):

`allow_insecure_policy_ws` defaults to `1`. Plain `ws://` is accepted only for loopback or RFC 1918/ULA IP addresses, and the policy stream is unencrypted. Prefer WSS on untrusted networks; set the option to `0` to disable plain WebSocket policy connections.

```bash
# View active UCI configuration
uci show netqmon

# Set Controller URL and commit changes
uci set netqmon.main.controller_url="http://192.168.1.100:8090"
uci commit netqmon

# Restart agent service
/etc/init.d/netqmon restart
```
