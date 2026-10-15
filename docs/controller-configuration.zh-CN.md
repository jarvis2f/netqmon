# NetQmon Controller 配置与端口说明

NetQmon Controller 是整个网络监控系统的核心服务端，通常通过 Docker 容器部署。它整合了以下三个核心进程：
* **`netqmon-collector`**：高性能遥测数据接收引擎（支持 SQLite 与 ClickHouse 存储、nDPI 深度报文解析、GeoIP 与 MAC 厂商解析）。
* **`netqmon-classifier-manager`**：分类守护进程与组件热更新管理器。
* **`controller-ui`**：基于 Next.js 的现代化 Web 控制台与 API 网关。

---

## 1. 暴露端口说明

在标准部署（如 `docker-compose.yml`）中，Controller 容器默认涉及以下网络端口：

| 端口号 | 协议 | 暴露范围 | 用途说明 |
| :--- | :--- | :--- | :--- |
| **`3000`** | TCP (HTTP) | 公开 / 局域网 | **Web 控制台访问端口**。管理员通过浏览器访问此端口进入 NetQmon 管理界面。 |
| **`8090`** | TCP (HTTP/Protobuf) | 局域网 / 路由可达 | **Agent 遥测数据上报端口**。部署在 OpenWrt 路由器上的 `netqmon-agent` 通过此端口完成初始注册并持续推送流遥测 Batch。 |
| **`8091`** | TCP (HTTP/JSON) | 仅容器内部 (`127.0.0.1`) | **内部 Collector 查询 API**。由 `controller-ui` 的 Node.js 服务端发起反向代理调用，**禁止直接暴露给公网**。 |
| **`8123`** | TCP (HTTP) | 可选（ClickHouse Profile） | ClickHouse HTTP 查询端口（仅在使用 ClickHouse 存储模式时启用）。 |
| **`9000`** | TCP (Native) | 可选（ClickHouse Profile） | ClickHouse TCP 原生协议端口（仅在使用 ClickHouse 存储模式时启用）。 |

> [!SECURITY]
> * **端口 `3000` 和 `8090`** 应仅在受信任的家庭/企业局域网内开放，若部署于公网 VPS，强烈建议配置反向代理（如 Nginx/Caddy）并启用 HTTPS/TLS 加密。
> * **端口 `8091`** 是未经外部鉴权的后端控制协议端口，仅在容器内部通过回环地址 `127.0.0.1` 监听。

---

## 2. 环境变量参考 (Environment Variables)

### 2.1 核心安全与鉴权配置（⚠️ 生产部署必改）

| 环境变量 | 默认值 | 必填 | 作用说明 |
| :--- | :--- | :---: | :--- |
| `NETQMON_COLLECTOR_ENROLLMENT_TOKEN` | `netqmon-dev-enrollment-token` | **是** | **Agent 注册令牌**。OpenWrt 路由器首次加入时需携带此令牌以换取网关密钥。生产环境必须修改为高强度随机字符串。 |
| `NETQMON_SESSION_SECRET` | `netqmon-dev-session-secret-change-me-32` | **是** | **Web 会话加密密钥**。用于签名与加密控制台 Session Cookie，必须为至少 32 位的随机字符串（推荐 `openssl rand -base64 32` 生成）。 |

### 2.2 存储与数据库配置

| 环境变量 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `NETQMON_STORAGE_BACKEND` | `sqlite` | 数据存储后端类型，可选 `sqlite` 或 `clickhouse`。普通家庭环境推荐 `sqlite`，千万级流数据推荐 `clickhouse`。 |
| `NETQMON_COLLECTOR_DATABASE_PATH` | `/data/netqmon.db` | SQLite 数据库文件存储路径（位于持久化卷 `/data` 中）。 |
| `NETQMON_LICENSE_STATE_PATH` | `/data/license.json` | 持久化许可证身份与安装凭据。必须位于持久化的 `/data` 中，确保替换容器后安装实例 ID 不变。 |
| `NETQMON_CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP 连接地址（当后端为 `clickhouse` 时生效）。 |
| `NETQMON_CLICKHOUSE_DATABASE` | `default` | ClickHouse 数据库名称。 |
| `NETQMON_CLICKHOUSE_USER` | `default` | ClickHouse 认证用户名（可选）。 |
| `NETQMON_CLICKHOUSE_PASSWORD` | *(空)* | ClickHouse 认证密码（可选）。 |

### 2.3 网络监听与服务地址

| 环境变量 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `NETQMON_COLLECTOR_PUBLIC_ADDR` | `0.0.0.0:8090` | Collector 面向 Agent 遥测上报的监听地址与端口。 |
| `NETQMON_COLLECTOR_INTERNAL_ADDR`| `127.0.0.1:8091` | Collector 面向内部 Web 控制台的查询服务监听地址。 |
| `NETQMON_COLLECTOR_INTERNAL_URL` | `http://127.0.0.1:8091` | `controller-ui` 服务端反向代理访问 Collector 的目标基地址。 |

### 2.4 分析与解析引擎配置

| 环境变量 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `NETQMON_DPI_ENABLED` | `true` | 是否启用内置 nDPI 深度报文分析引擎（识别应用层协议如 TLS、WireGuard、BitTorrent 等）。 |
| `NETQMON_COLLECTOR_GEO_DIR` | `/data/geo` | MaxMind IP 地理位置与 ASN 离线库存储目录。 |
| `NETQMON_COLLECTOR_MAC_DATASET_PATH` | `/data/mac-prefixes.json` | MAC 地址前缀厂商识别库离线缓存路径。 |
| `NETQMON_SERVICE_BINDING_TTL_SECONDS` | `86400` | 局域网设备服务发现与端口绑定关系的缓存有效期（秒）。 |

当 ASN 数据库可用时，Collector 会在遥测写入期间查询每个有效的远端 IP，并将 ASN 传给本地分类器。查询结果仅在单个遥测批次或延迟 DPI 重分类批次内去重；未命中或查询失败会保持 ASN 为空，且不会阻塞流量写入或分类。

### 2.5 分类管理器与组件升级（Classifier Manager）

| 环境变量 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `NETQMON_CLASSIFIER_UPDATE_CHANNEL` | `stable` | 分类器组件更新通道，可选 `stable` / `beta` / `dev`。 |
| `NETQMON_CLASSIFIER_UPDATE_INTERVAL_SECONDS` | `300` | 自动检查组件更新的周期（秒，默认 5 分钟）。 |

### 2.6 日志与调试

| 环境变量 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `RUST_LOG` | `info` | Rust 后端日志级别，支持 `error`、`warn`、`info`、`debug`、`trace`，或精细模块过滤（如 `netqmon_collector=debug`）。 |

---

## 3. 典型部署配置示例

生产环境推荐使用的最小化 `docker-compose.override.yml` 或 `.env` 示例：

```yaml
# docker-compose.override.yml
services:
  controller:
    environment:
      # 请务必生成独立的随机令牌
      - NETQMON_COLLECTOR_ENROLLMENT_TOKEN=my-super-secure-token-982173
      - NETQMON_SESSION_SECRET=c29tZS1zZWN1cmUtcmFuZG9tLXN0cmluZy0zMi1ieXRlcw==
      - RUST_LOG=info
    ports:
      # 如仅允许本地通过反代访问，可绑定 127.0.0.1
      - "127.0.0.1:3000:3000"
      - "0.0.0.0:8090:8090"
```
