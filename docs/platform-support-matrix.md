# NetQmon Agent 平台与架构支持矩阵

本文档说明 NetQmon Agent 在不同 CPU 架构与平台上的支持级别、构建产物、内核依赖及验证状态。

---

## 1. 支持层级定义 (Support Tiers)

| 级别 | 定义 | 包含架构 / 平台 | 交付要求 |
| :--- | :--- | :--- | :--- |
| **Tier 1: Official** | 生产稳定、Release Blocking、完整 CI/CD 自动化构建与测试 | `x86_64`, `aarch64`, `armv7hf` (`arm_cortex-a7_neon-vfpv4` 等) | 静态 ELF、无动态依赖、Smoke test、全量 ipk/apk 发布 |
| **Tier 2: Candidate Official** | 交叉编译链已就绪、完整 static binary 验证、CI 自动化构建，非 Blocking | `riscv64` (`riscv64gc-unknown-linux-musl`) | 静态 ELF、libbpf/eBPF 兼容、CI 构建通过 |
| **Tier 3: Experimental** | 核心架构支持可用、基于通用 baseline 统一 binary，需更广泛真实硬件反馈 | `mipsel_24kc`, `mipsel_74kc` (`netqmon-agent_mipsel32r2`) | MIPS32r2 O32 soft-float static ELF、QEMU smoke pass、ipk/apk 发布 |
| **Tier 4: Compatibility Test Required** | binary 理论兼容，但硬件/系统存在 ABI 差异 (如 hard-float vs soft-float static)，需真实硬件确认 | `mipsel_24kc_24kf` (`netqmon-agent_mipsel32r2`) | 提供 ipk/apk，待硬件环境实际验证 |
| **Deferred** | 暂时移出矩阵，待后续独立阶段支持 | `armv7` soft-float (`armv7-unknown-linux-musleabi`), MIPS big-endian | 不提供预编译 binary |

---

## 2. 架构与编译目标详细映射

| 架构 / 目标平台 | Rust Target Triple | 编译产物文件名 | ABI / 浮点模型 | OpenWrt 包格式 | 状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **x86_64** | `x86_64-unknown-linux-musl` | `netqmon-agent_x86_64` | 64-bit Musl static | ipk, apk | **Official** |
| **aarch64** | `aarch64-unknown-linux-musl` | `netqmon-agent_aarch64` | 64-bit ARMv8 Musl static | ipk, apk | **Official** |
| **armv7hf** | `armv7-unknown-linux-musleabihf` | `netqmon-agent_armv7hf` | ARM EABI5 Hard-Float Musl static | ipk, apk | **Official** |
| **riscv64** | `riscv64gc-unknown-linux-musl` | `netqmon-agent_riscv64` | 64-bit LP64D Musl static | ipk, apk | **Candidate Official** |
| **mipsel_24kc** | `mipsel-unknown-linux-musl` | `netqmon-agent_mipsel32r2` | MIPS32r2 O32 Soft-Float static | ipk, apk | **Experimental** |
| **mipsel_74kc** | `mipsel-unknown-linux-musl` | `netqmon-agent_mipsel32r2` | MIPS32r2 O32 Soft-Float static | ipk, apk | **Experimental** |
| **mipsel_24kc_24kf** | `mipsel-unknown-linux-musl` | `netqmon-agent_mipsel32r2` | MIPS32r2 O32 Soft-Float static | ipk, apk | **Compatibility Test** |

---

## 3. 运行环境与内核依赖要求

NetQmon Agent 采用完全静态编译 (Fully Static ELF)，运行时不依赖目标系统的 `libc.so` 或动态链接器，但需要宿主 Linux 内核具备相应的 eBPF 与网络子系统特性：

### 3.1 核心内核能力要求
- **BPF Syscall**: 内核启用 `CONFIG_BPF` 与 `CONFIG_BPF_SYSCALL`
- **eBPF Map 类型**:
  - `BPF_MAP_TYPE_HASH` (路由观测索引与采样配额)
  - `BPF_MAP_TYPE_LRU_HASH` (网络流主哈希表 `flow_map`)
  - `BPF_MAP_TYPE_ARRAY` (统计计数器与丢包计数)
  - `BPF_MAP_TYPE_RINGBUF` (DNS/DHCP/Discovery/采样事件缓冲，**要求 Linux >= 5.8**)
- **Traffic Control (TC) BPF Subsystem**:
  - 内核配置 `CONFIG_NET_CLS_ACT=y`, `CONFIG_NET_CLS_BPF=m/y`, `CONFIG_NET_SCH_INGRESS=m/y`
  - OpenWrt 依赖内核模块: `kmod-sched-core`, `kmod-sched-bpf`
  - 若使用 TCX 模式，需要 Linux >= 6.6；低版本内核自动 fallback 至 Netlink TC 模式

### 3.2 运行前检测诊断机制 (Doctor & Self-Probe)
Agent 在执行 `netqmon-agent run` 启动时，以及 `netqmon-agent doctor` 诊断时，会自动执行**非破坏性探测**：
1. 探测 `BPF syscall`、`Hash`、`LRU Hash`、`Array`、`Ringbuf` map 创建与即时销毁。
2. 探测 TC clsact 与 BPF hook 挂载（使用高优先级 `0x7ffe` 与独立 handle `0x4e514d44`，探测结束立即安全卸载）。
3. 遇到缺少特性时输出精确报错（例如提示缺少 `kmod-sched-core` 或 Ringbuf 不支持），避免静默崩溃。
