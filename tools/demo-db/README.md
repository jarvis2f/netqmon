# Netqmon Demo 数据库工具套件

本目录提供了用于构建和验证公开演示站（Demo Mode）模板数据库的完整工具套件。

## 目录结构

```text
tools/demo-db/
├── generate_demo_db.py  # 100% 纯合成数据生成器（零隐私泄露风险）
├── validate_demo_db.py  # 数据完整性与隐私合规验证工具
└── README.md            # 工具使用说明文档
```

---

## 核心设计与安全原则

1. **100% 纯合成数据**：
   - 不读取任何真实用户数据，不脱敏真实环境，避免隐私泄露。
   - 确定性随机种子，保证数据完全可复现。
2. **两层时间保鲜机制**：
   - **Build-time**：`generate_demo_db.py` 支持 `--now` 参数，即时生成与当前时间对齐的历史数据。
   - **Runtime**：后端内置 `ensure_demo_database_freshness`，启动及常驻运行时自动进行微秒级时间平移，保证演示数据永不过期。
3. **严格的局域网单播与子网规范**：
   - 所有设备 MAC 地址严格限制为本地管理单播 MAC（`02:00:00:00:00:xx`）。
   - 私网 IPv4 严格限制在 `192.168.50.0/24`（网关 `192.168.50.1`，设备 `192.168.50.10` 起递增）。
4. **真实公网业务特征**：
   - 覆盖全球主流公共 IP、真实常见应用域名（YouTube, Netflix, GitHub, OpenAI, Steam 等）、自然昼夜节律曲线（Diurnal Pattern）。
5. **敏感表强制清空**：
   - `users`、`auth_sessions`、`ingest_batches`、`settings` 强制为空。
6. **全新无残留导出**：
   - 通过 SQLite `VACUUM INTO` 生成全新文件，确保已删除或无用数据在 freelist/page 中彻底不留痕迹。

---

## 使用说明

### 1. 生成 100% 纯合成 Demo 数据库

直接运行 `generate_demo_db.py` 生成标准 Demo 模板数据库：

```bash
python tools/demo-db/generate_demo_db.py \
  --output ./netqmon-demo-template.db \
  --seed 20260921 \
  --hours 48 \
  --now \
  --force \
  --verbose
```

参数说明：
- `--output`：输出 SQLite 数据库路径（默认 `netqmon-demo-template.db`）。
- `--seed`：随机数种子（默认 `20260921`，相同种子生成完全一致的数据）。
- `--hours`：生成历史数据时长（默认 48 小时）。
- `--now`：将时间戳对齐至当前时间（当前时间前 30 秒）。
- `--force`：若目标文件已存在，强制覆盖。
- `--verbose`：输出生成过程中的明细信息。

### 2. 验证 Demo 模板数据库

使用 `validate_demo_db.py` 进行严格的合规与完整性检查：

```bash
python tools/demo-db/validate_demo_db.py ./netqmon-demo-template.db
```

验证内容包括：
- PRAGMA integrity_check 与 foreign_key_check。
- 敏感表（users, auth_sessions, ingest_batches, settings）是否绝对为空。
- MAC 地址是否全部为合法 locally-administered 单播地址。
- 私网 IP 是否全部属于 Demo 网段。
- 时间戳单调性与聚合表数据一致性。
