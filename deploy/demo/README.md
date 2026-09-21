# Netqmon Controller Demo Mode

This directory contains configuration, deployment files, and instructions for running `netqmon-controller` in **Demo Mode**.

Demo Mode transforms the Netqmon Controller into a secure, read-only public demonstration website:
- **No Agent Required**: Works independently without connecting real OpenWrt/Linux agents.
- **No Classifier Daemon**: Runs without `classifier-manager` or `classifierd`.
- **Pre-seeded SQLite Data**: Populates dashboards using a 100% synthetic SQLite database generated from code.
- **Built-in Time Freshness**: `netqmon-collector` automatically shifts historical database timestamps on startup and periodically in the background so the most recent data is always fresh in the current window.
- **Realtime Simulation**: Generates live SSE throughput snapshots and 15-minute history curves without modifying the database.
- **Full Read-Only Protection**: Blocks mutation API methods (`POST`, `PUT`, `DELETE`, `PATCH`) with HTTP 403 `demo_read_only` at both Next.js proxy and backend internal API layers.
- **Bypassed Auth**: Visitors access the dashboard immediately without login; settings navigation and mutating pages are hidden and redirected.
- **Isolated Network Footprint**: Exposes only port `3000` (Next.js). Ingestion listener port `8090` is disabled.

---

## Architecture

```text
Internet / Cloudflare Reverse Proxy
                 ↓
      Port 3000 (Next.js Server)
                 ↓
     127.0.0.1:8091 (Internal API)
                 ↓
   Runtime SQLite DB (/data/netqmon.db)
```

At container launch:
1. A fresh runtime database is created on every start. Existing runtime data is never trusted or reused.
2. If `/demo/netqmon-demo.db` is mounted, it is validated before being copied; otherwise a fresh synthetic database is generated automatically.
3. `netqmon-collector` starts with `NETQMON_DEMO_MODE=true` and automatically shifts timestamps to the current time.
4. Next.js UI starts with Demo mode active.

---

## Quick Start (Docker Compose)

### 1. (Optional) Generate a Custom Template

Optionally generate a validated synthetic template for local testing:

```bash
python3 tools/demo-db/generate_demo_db.py --output deploy/demo/netqmon-demo.db
```

*(Note: The container automatically generates a fresh synthetic database when no template is mounted.)*

### 2. Start the Demo Service

From `deploy/demo`:

```bash
docker compose up -d --build
```

Access the UI at `http://localhost:3000`.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETQMON_DEMO_MODE` | `false` | Set to `true` or `1` to activate Demo Mode. |
| `NETQMON_DEMO_DATABASE_TEMPLATE` | `/demo/netqmon-demo.db` | Path to the read-only template database (optional). |
| `NETQMON_COLLECTOR_DATABASE_PATH` | `/data/netqmon.db` | Path where the runtime database is stored. |
| `NETQMON_COLLECTOR_INTERNAL_ADDR` | `127.0.0.1:8091` | Loopback address for the internal query API. |
| `NETQMON_SESSION_SECRET` | *(Random/Configured)* | Secret used for cookie sessions (at least 32 characters). |

---

## Local Development & Testing

To run `netqmon-collector` locally in Demo Mode:

```bash
export NETQMON_DEMO_MODE=true
export NETQMON_COLLECTOR_DATABASE_PATH=./netqmon-demo-template.db
cargo run --package netqmon-collector
```
