# NetQMon 本地运行配置说明

本目录包含适用于 IntelliJ IDEA / RustRover 的本地运行与调试配置。

## 运行配置概览

| 运行配置名称 | 类型 | 作用说明 | 默认参数与环境变量 |
| :--- | :--- | :--- | :--- |
| **`Controller Backend (Local)`** | Cargo Command | 启动开源 Collector 后端服务 | `run --package netqmon-collector`<br>• `NETQMON_CLASSIFIER_SOCKET=/tmp/netqmon/classifierd.sock`<br>• `NETQMON_DPI_ENABLED=false`（macOS 免除本地 libndpi 依赖）<br>• `NETQMON_COLLECTOR_DATABASE_PATH=$PROJECT_DIR$/target/netqmon-local.db`<br>• 内部 API 绑定 `127.0.0.1:8091` |
| **`Controller UI (Local)`** | npm / pnpm | 启动开源前端 Next.js 控制台开发服务 | `apps/controller-ui`（默认端口 `3000`）<br>• `NETQMON_COLLECTOR_INTERNAL_URL=http://127.0.0.1:8091` |
| **`Controller (Local)`** | Compound | **复合启动项**：一键并行启动 `Controller Backend (Local)` 与 `Controller UI (Local)` | 推荐日常完整开发调试使用 |

## 本地启动与调试步骤

1. **可选：启动分类守护进程（推荐进行应用/协议分类调试）**：
   - 可启动本地 `classifierd` 守护进程（或运行 `cargo run --example mock-classifierd -- --socket /tmp/netqmon/classifierd.sock` 启动模拟服务），监听在 `/tmp/netqmon/classifierd.sock`。
2. **启动开源系统**：
   - 选择运行 **`Controller (Local)`**（复合项），将同时启动后端 Collector 与前端 Controller UI。
   - 打开浏览器访问 `http://localhost:3000` 即可体验 NetQMon 控制台。
