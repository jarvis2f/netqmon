# NetQmon Agent 命令与配置参考

`netqmon-agent` 是安装在 OpenWrt 路由器或 Linux 网关上的轻量级网络遥测采集代理。它利用 Linux 内核的 **TC eBPF** 数据面挂载点，无感知地捕获进出流量的元数据、DNS 解析事件、流生命周期与报文样本，并高效批量推送至 NetQmon Controller。

---

## 1. 命令行语法与全局选项

```bash
netqmon-agent [OPTIONS] [COMMAND]
```

### 全局选项 (Global Options)

| 参数 | 短参数 | 说明 | 示例 |
| :--- | :---: | :--- | :--- |
| `--config <PATH>` | `-c` | 指定 TOML 格式的配置文件路径（默认读取 `/etc/netqmon/agent.toml`）。 | `-c /etc/netqmon/custom.toml` |
| `--interface <NAME>` | `-i` | 指定或覆盖监听的网络接口名称。**可重复指定多次**以监听多网卡（默认 `br-lan`）。 | `-i br-lan -i eth1` |
| `--help` | `-h` | 打印帮助信息。 | `-h` |
| `--version` | `-V` | 打印当前 Agent 版本号。 | `-V` |

---

## 2. 子命令详解 (Subcommands)

### 2.1 `run`（默认命令）

启动遥测代理主服务，挂载 eBPF 程序至指定网络接口并开始流采集和数据上报。直接执行 `netqmon-agent` 亦等同于 `netqmon-agent run`。

```bash
# 标准启动
netqmon-agent run

# 覆盖网卡启动
netqmon-agent run -i br-lan -i eth1
```

在 OpenWrt 生产环境中，通常由 `procd` 服务管理：
```bash
/etc/init.d/netqmon start
/etc/init.d/netqmon restart
/etc/init.d/netqmon status
```

---

### 2.2 `doctor`（环境与内核自检）

自检当前宿主机环境、内核能力、eBPF 支持度、TC 过滤挂载能力和系统资源，输出诊断报告。适合首次安装或排查启动失败时使用。

```bash
netqmon-agent doctor
```

**自检项目包含：**
* **Kernel & Architecture**：Linux 内核版本与处理器架构。
* **eBPF Capabilities**：`bpf()` 系统调用权限、BPF 文件系统挂载（`/sys/fs/bpf`）。
* **TC Filter Attach**：网卡 Traffic Control 挂载能力检测（TCX 或经典 Netlink TC 模式）。
* **Resource Limits**：`RLIMIT_MEMLOCK` 内存锁定上限配置。
* **Network & Conntrack**：网卡在线状态、IPv4/IPv6 地址分配、连接跟踪表状态。

---

### 2.3 `diagnostics` / `diag`（运行期诊断与控制）

通过本地 Unix Domain Socket（默认 `/run/netqmon/agent.sock`）与正在运行中的 Agent 守护进程通信，获取或调整运行期遥测指标。

```bash
# 查看当前运行期诊断摘要（文本展示）
netqmon-agent diagnostics

# 查看 JSON 格式指标（适合自动化采集与监控集成）
netqmon-agent diagnostics --json
```

**管理操作子命令：**

| 操作子命令 | 说明 | 示例 |
| :--- | :--- | :--- |
| `enable` | 动态启用运行期诊断收集，并在配置文件中持久化。 | `netqmon-agent diagnostics enable` |
| `disable` | 动态禁用运行期诊断收集以节省开销。 | `netqmon-agent diagnostics disable` |
| `reset` | 重置运行期累积计数器（如丢失流数、重试队列、异常报文统计）。 | `netqmon-agent diagnostics reset` |

---

## 3. 配置文件规范 (`agent.toml`)

默认配置文件路径为 `/etc/netqmon/agent.toml`。完整格式与默认值说明如下：

```toml
# 采集接口配置：可为单一字符串或字符串数组
interface = "br-lan"
interfaces = ["br-lan"]

# Controller 服务端地址与安全凭证
controller_url = "http://192.168.1.100:8090"
token = "your-enrollment-or-agent-token"

# 采集与上报周期
poll_interval_ms = 1000       # 从 eBPF Map 读取活跃流的轮询周期（毫秒）
batch_interval_ms = 1000      # 向 Controller 批量推送遥测的间隔（毫秒）
max_flows = 65536             # eBPF 流跟踪表最大容量

# 容灾与重试队列
retry_buffer_seconds = 60                   # 网络闪断时最大缓冲秒数
telemetry_retry_buffer_bytes = 8388608      # 重试队列最大内存（字节，默认 8MB）

# 流空闲超时判断
tcp_idle_timeout_seconds = 120              # TCP 流无报文关闭超时
udp_idle_timeout_seconds = 30               # UDP 流无报文关闭超时

# 报文流采样（用于深度协议与应用识别）
sample_enabled = true                       # 是否启用报文头采样
sample_max_packets_per_direction = 4        # 单方向最多采样报文数
sample_max_bytes_per_packet = 1024          # 单个报文最大采样深度
sample_max_bytes_per_flow = 4096            # 单条流最大采样总字节

# 日志级别：error | warn | info | debug | trace
log_level = "info"

# 运行期诊断控制
diagnostics_enabled = false

[bpf]
backend = "auto"              # TC 挂载后端: "auto", "tcx", "netlink"
tc_priority = 49152           # 经典 TC Filter 优先级
tc_handle = 1313946881        # 经典 TC Filter 句柄 (0x4e514d01)
tcx_order = "first"           # TCX 挂载顺序: "first", "last"
```

---

## 4. 环境变量覆盖说明

所有配置项均支持通过环境变量直接覆盖，优先级高于配置文件：

| 环境变量 | 对应 TOML 字段 | 示例 |
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
| `NETQMON_SOCKET_PATH` | *(诊断套接字)* | `/run/netqmon/agent.sock` |

---

## 5. OpenWrt UCI 配置集成

在标准 OpenWrt 系统上，`netqmon-agent` 还可以通过 UCI 系统统一管理（由 `/etc/init.d/netqmon` 转换为启动参数）：

```bash
# 查看当前 UCI 配置
uci show netqmon

# 修改 Controller 地址并生效
uci set netqmon.main.controller_url=http://192.168.1.100:8090
uci commit netqmon
/etc/init.d/netqmon restart
```
