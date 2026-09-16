# NetQmon Controller Configuration & Port Reference

The NetQmon Controller is the central server component of the NetQmon observability stack, packaged and deployed as a multi-process Docker container. It coordinates three core services:
* **`netqmon-collector`**: High-performance telemetry ingestion and query engine with a local collector database, selectable DuckDB or ClickHouse analytics, bounded nDPI deep packet analysis, GeoIP, and MAC OUI vendor resolution.
* **`netqmon-classifier-manager`**: Classification daemon supervisor and signed component update coordinator.
* **`controller-ui`**: Modern Next.js web console and authenticated API gateway.

---

## 1. Network Ports Reference

In a standard deployment (such as via `docker-compose.yml`), the Controller container exposes or utilizes the following network ports:

| Port | Protocol | Scope | Description |
| :--- | :--- | :--- | :--- |
| **`3000`** | TCP (HTTP) | Public / LAN | **Web Console Port**. Network administrators access this port in a web browser to view the NetQmon dashboard. |
| **`8090`** | TCP (HTTP/Protobuf) | LAN / Routable | **Agent Telemetry Ingestion Port**. OpenWrt routers running `netqmon-agent` connect to this port for initial gateway enrollment and ongoing telemetry batch streaming. |
| **`8091`** | TCP (HTTP/JSON) | Container Internal (`127.0.0.1`) | **Internal Collector Query API**. Used solely by `controller-ui` server-side proxy handlers. **Must not be exposed directly to untrusted networks**. |
| **`8123`** | TCP (HTTP) | Optional (ClickHouse Profile) | ClickHouse HTTP query port, used when `NETQMON_ANALYTICS_BACKEND=clickhouse`. |
| **`9000`** | TCP (Native) | Optional (ClickHouse Profile) | ClickHouse native TCP port, used when `NETQMON_ANALYTICS_BACKEND=clickhouse`. |

> [!SECURITY]
> * **Ports `3000` and `8090`** should be restricted to trusted local network segments. When deploying on a public VPS, put them behind a reverse proxy (e.g. Caddy, Traefik, or Nginx) with TLS/HTTPS enabled.
> * **Port `8091`** is an internal service endpoint bound strictly to `127.0.0.1` within the container.

---

## 2. Environment Variables Reference

### 2.1 Core Security & Authentication (⚠️ Required for Production)

| Variable | Default | Required | Description |
| :--- | :--- | :---: | :--- |
| `NETQMON_COLLECTOR_ENROLLMENT_TOKEN` | `netqmon-dev-enrollment-token` | **Yes** | **Agent Enrollment Token**. OpenWrt gateways present this shared secret token on first startup to enroll and receive persistent credentials. Must be changed in production! |
| `NETQMON_SESSION_SECRET` | `netqmon-dev-session-secret-change-me-32` | **Yes** | **Web Session Secret**. Used to sign and encrypt web console authentication cookies. Must be a secure random string of at least 32 characters (generate with `openssl rand -base64 32`). |

### 2.2 Storage & Database Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NETQMON_COLLECTOR_DATABASE_PATH` | `/data/netqmon.db` | Filesystem path for the collector database, located inside the persistent `/data` volume. |
| `NETQMON_ANALYTICS_BACKEND` | `duckdb` | Analytics backend: `duckdb` for the local default or `clickhouse` for an external ClickHouse service. |
| `NETQMON_DUCKDB_PATH` | `/data/netqmon-analytics.duckdb` | Filesystem path for the DuckDB analytics database. Keep it on the persistent `/data` volume. |
| `NETQMON_LICENSE_STATE_PATH` | `/data/license.json` | Persistent license identity and installation credential state. Keep this path on the persistent `/data` volume so the installation ID survives container replacement. |
| `NETQMON_CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint URL, used when `NETQMON_ANALYTICS_BACKEND=clickhouse`. |
| `NETQMON_CLICKHOUSE_DATABASE` | `default` | ClickHouse database name. |
| `NETQMON_CLICKHOUSE_USER` | *(unset)* | ClickHouse authentication username (optional). |
| `NETQMON_CLICKHOUSE_PASSWORD` | *(unset)* | ClickHouse authentication password (optional). |

### 2.3 Network Listeners & Service Bindings

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NETQMON_COLLECTOR_PUBLIC_ADDR` | `0.0.0.0:8090` | Listen address and port for incoming agent telemetry ingestion. |
| `NETQMON_COLLECTOR_INTERNAL_ADDR`| `127.0.0.1:8091` | Listen address and port for the internal collector query service. |
| `NETQMON_COLLECTOR_INTERNAL_URL` | `http://127.0.0.1:8091` | Upstream base URL used by `controller-ui` to reach the internal collector query API. |

### 2.4 Analytics & Parsing Engines

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NETQMON_DPI_ENABLED` | `true` | Enable or disable the embedded nDPI engine (used for deep protocol classification such as TLS, WireGuard, BitTorrent, etc.). |
| `NETQMON_COLLECTOR_GEO_DIR` | `/data/geo` | Directory containing MaxMind GeoLite2 country, city, and ASN MMDB databases. |
| `NETQMON_COLLECTOR_MAC_DATASET_PATH` | `/data/mac-prefixes.json` | Path to the cached MAC OUI vendor prefix database. |
| `NETQMON_SERVICE_BINDING_TTL_SECONDS` | `86400` | Expiration time (in seconds) for LAN service discovery and port binding observations. |

### 2.5 Classifier Manager & Component Updates

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NETQMON_CLASSIFIER_UPDATE_CHANNEL` | `beta` | Classifier component update channel: `stable`, `beta`, or `dev`. |
| `NETQMON_CLASSIFIER_UPDATE_INTERVAL_SECONDS` | `300` | Periodic check interval for component updates (in seconds, default 5 minutes). |

### 2.6 Logging & Debugging

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RUST_LOG` | `info` | Rust backend logging level: `error`, `warn`, `info`, `debug`, `trace`, or targeted module filters (e.g. `netqmon_collector=debug`). |

---

## 3. Production Deployment Example

Recommended `docker-compose.override.yml` example for production environments:

```yaml
# docker-compose.override.yml
services:
  controller:
    environment:
      # Generate strong random secrets for production
      - NETQMON_COLLECTOR_ENROLLMENT_TOKEN=replace-with-a-random-enrollment-secret
      - NETQMON_SESSION_SECRET=replace-with-at-least-32-random-characters-secret
      - RUST_LOG=info
    ports:
      # Bind web console locally if accessing via reverse proxy
      - "127.0.0.1:3000:3000"
      - "0.0.0.0:8090:8090"
```
