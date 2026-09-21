# NetQMon 本地运行配置说明

本目录包含适用于 IntelliJ IDEA / RustRover 的本地运行与调试配置。

## 运行配置概览

### 1. 标准开发模式 (Local)

| 运行配置名称 | 类型 | 作用说明 | 默认参数与环境变量 |
| :--- | :--- | :--- | :--- |
| **`Controller Backend (Local)`** | Cargo Command | 启动开源 Collector 后端服务 | `run --package netqmon-collector`<br>• `NETQMON_CLASSIFIER_SOCKET=/tmp/netqmon/classifierd.sock`<br>• `NETQMON_DPI_ENABLED=false`（macOS 免除本地 libndpi 依赖）<br>• `NETQMON_COLLECTOR_DATABASE_PATH=$PROJECT_DIR$/target/netqmon-local.db`<br>• 内部 API 绑定 `127.0.0.1:8091` |
| **`Controller UI (Local)`** | npm / pnpm | 启动开源前端 Next.js 控制台开发服务 | `apps/controller-ui`（默认端口 `3000`）<br>• `NETQMON_COLLECTOR_INTERNAL_URL=http://127.0.0.1:8091` |
| **`Controller (Local)`** | Compound | **复合启动项**：一键并行启动 `Controller Backend (Local)` 与 `Controller UI (Local)` | 推荐日常完整开发调试使用 |

### 2. 演示演示站模式 (Demo)

| 运行配置名称 | 类型 | 作用说明 | 默认参数与环境变量 |
| :--- | :--- | :--- | :--- |
| **`Controller Backend (Demo)`** | Cargo Command | 启动只读 Demo Collector 服务，自动加载 Demo 模板数据库并提供模拟实时流量与只读防护 | `run --package netqmon-collector`<br>• `NETQMON_DEMO_MODE=true`<br>• `NETQMON_COLLECTOR_DATABASE_PATH=$PROJECT_DIR$/target/netqmon-demo.db`<br>• 免除 classifierd、libndpi 与 License 依赖 |
| **`Controller UI (Demo)`** | npm / pnpm | 启动 Demo 前端 Next.js 控制台，自动展示 Demo 标识、隐藏设置页、免登录只读访问 | `apps/controller-ui`（默认端口 `3000`）<br>• `NETQMON_DEMO_MODE=true`<br>• `NETQMON_COLLECTOR_INTERNAL_URL=http://127.0.0.1:8091` |
| **`Controller (Demo)`** | Compound | **一键 Demo 启动项**：一键并行启动 `Controller Backend (Demo)` 与 `Controller UI (Demo)` | 推荐本地一键预览和调试公开 Demo 站效果 |

## 本地启动与调试步骤

### 启动普通开发环境：
1. **启动开源系统**：
   - 选择运行 **`Controller (Local)`**（复合项），将同时启动后端 Collector 与前端 Controller UI。
   - 打开浏览器访问 `http://localhost:3000` 即可体验 NetQMon 控制台。

### 启动 Demo 演示环境：
1. **一键启动 Demo 模式**：
   - 选择运行 **`Controller (Demo)`**（复合项），将自动启动只读 Demo 后端与前端。
   - 若 `target/netqmon-demo.db` 不存在，后端会自动从根目录的 `netqmon-demo-template.db` 复制并对齐当前时间。
   - 打开浏览器访问 `http://localhost:3000` 即可体验只读免登录的公开演示站。
