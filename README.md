# HTTP Tap Proxy

Transparent HTTP/HTTPS logging proxy. Sits between reverse proxy and app, captures all traffic without buffering or adding latency. Supports WebSocket and SSE streaming.

## Features

- **Transparent proxy** - No paths intercepted, all traffic forwarded to upstream
- **Tap-style logging** - Captures request/response bodies while streaming (no buffering delay)
- **WebSocket support** - Logs individual frames bidirectionally
- **SSE support** - Logs Server-Sent Events as they stream
- **Dual logging** - JSONL files and/or SQLite database
- **Log rotation** - Size and time-based rotation with retention
- **S3 archival** - Upload rotated logs to S3/R2/MinIO
- **CGO-free** - Pure Go, easy cross-compilation
- **Metrics** - Prometheus-compatible metrics on separate admin port

## Install

```bash
make build

# Or cross-compile (CGO-free)
make build-linux
make build-windows

# Or build directly
go build -o http-tap-proxy .
```

## Usage

```bash
# Basic - single proxy with JSONL logging
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=./requests.jsonl"

# Log to SQLite with admin endpoint
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_sqlite=./requests.db" \
  --listen-admin :9090

# HTTPS with auto-cert
./http-tap-proxy \
  --proxy "name=api,listen_https=:8443,upstream=http://localhost:5000,log_jsonl=./requests.jsonl" \
  --auto-cert

# With path filtering (only log /api/ paths)
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=./requests.jsonl,include_path=^/api/"

# Exclude health checks from logging
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=./requests.jsonl,exclude_path=^/health"

# Multiple proxies (multi-upstream)
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://api-backend:5000,log_jsonl=./logs/api.jsonl" \
  --proxy "name=web,listen_http=:8081,upstream=http://web-backend:3000,log_jsonl=./logs/web.jsonl" \
  --listen-admin :9090

# Directory mode - logs named by route (api.jsonl, web.jsonl, etc.)
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://api:5000,log_jsonl=./logs/" \
  --proxy "name=web,listen_http=:8081,upstream=http://web:3000,log_jsonl=./logs/"
```

## Options

### Proxy Configuration

Each `--proxy` flag defines one proxy instance with comma-separated key=value pairs:

| Key | Required | Description |
|-----|----------|-------------|
| `name` | Yes | Route name (used in logs, metrics, and filenames). Must start with a letter, only alphanumeric, underscore, and hyphen allowed. |
| `upstream` | Yes | Target URL (e.g., `http://localhost:5000`) |
| `listen_http` | * | HTTP listen address (e.g., `:8080`) |
| `listen_https` | * | HTTPS listen address (e.g., `:8443`) |
| `log_jsonl` | | JSONL log file path (or directory ending with `/`) |
| `log_sqlite` | | SQLite database path (or directory ending with `/`) |
| `include_path` | | Regex for paths to log (whitelist mode, can be repeated) |
| `exclude_path` | | Regex for paths to exclude (blacklist mode, can be repeated) |

\* At least one of `listen_http` or `listen_https` is required.

**Directory mode:** If log path ends with `/`, files are named by route name (e.g., `./logs/` → `./logs/api.jsonl`).

**Multiple path patterns:** Repeat `include_path` or `exclude_path` for multiple patterns:
```bash
--proxy "name=api,...,exclude_path=^/health,exclude_path=^/ready,exclude_path=^/metrics"
```

**Note:** Values cannot contain commas since comma is the delimiter. Use `|` for regex alternation (e.g., `exclude_path=^/(health|ready)`).

### Global Options

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-admin` | | Admin port for health/metrics (recommended: `:9090`) |
| `--rotate-size` | `100MB` | Rotate when file exceeds size |
| `--rotate-interval` | `1h` | Rotate at interval |
| `--retention` | `10` | Number of rotated files to keep (when S3 not configured) |
| `--max-body-size` | `100MB` | Max request/response body to capture |

### TLS

| Flag | Default | Description |
|------|---------|-------------|
| `--auto-cert` | `false` | Generate self-signed certificate |
| `--cert` | | TLS certificate file |
| `--key` | | TLS key file |
| `--insecure-skip-verify` | `true` | Skip TLS verification for upstream |

### S3 Archival

| Flag | Default | Description |
|------|---------|-------------|
| `--s3-bucket` | | S3 bucket for archival |
| `--s3-prefix` | | Key prefix for uploads |
| `--s3-endpoint` | | S3-compatible endpoint (for R2, MinIO, etc.) |

When S3 is configured, rotated files are uploaded then deleted locally. On upload failure, files are retained for retry on next rotation.

### Admin Endpoints

| Flag | Default | Description |
|------|---------|-------------|
| `--health-path` | `/_health` | Health check endpoint path |
| `--metrics-path` | `/_metrics` | Prometheus metrics endpoint path |

Admin endpoints are only available when `--listen-admin` is configured. They are served on a separate port to keep the proxy fully transparent.

### Service

| Flag | Description |
|------|-------------|
| `--print-systemd` | Print systemd unit file and exit |
| `--service` | Windows service command: `install`, `uninstall`, `start`, `stop`, `run` |

## Log Format

### JSONL

Each line is a JSON object with `type` field:

**HTTP requests** (`type: "http"`):
```json
{
  "id": "uuid",
  "route_name": "api",
  "correlation_id": "from X-Request-ID header",
  "timestamp": "2024-01-01T00:00:00Z",
  "duration_ms": 45,
  "ttfb_request_ms": 2,
  "ttfb_response_ms": 40,
  "client_ip": "127.0.0.1:54321",
  "type": "http",
  "request": {
    "method": "POST",
    "url": "/api/users",
    "headers": {"Content-Type": ["application/json"]},
    "body": "{\"name\": \"test\"}",
    "body_size": 16
  },
  "response": {
    "status": 201,
    "headers": {"Content-Type": ["application/json"]},
    "body": "{\"id\": 1}",
    "body_size": 9
  }
}
```

**WebSocket frames** (`type: "websocket_frame"`):
```json
{
  "id": "uuid",
  "route_name": "api",
  "connection_id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "type": "websocket_frame",
  "direction": "client_to_server",
  "opcode": 1,
  "opcode_name": "text",
  "payload": "hello",
  "payload_size": 5
}
```

**SSE events** (`type: "sse_event"`):
```json
{
  "id": "uuid",
  "route_name": "api",
  "connection_id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "type": "sse_event",
  "event": "message",
  "data": "hello world",
  "retry": 3000
}
```

Binary bodies are base64-encoded with `body_base64: true`.

### SQLite

Three tables with appropriate indexes:

- `http_entries` - HTTP requests/responses with extracted common headers
- `websocket_frames` - WebSocket frame data
- `sse_events` - Server-Sent Events

All tables include a `route_name` column (indexed) for filtering by proxy instance. Bodies stored as BLOBs (binary, not base64).

## Admin Endpoints

When `--listen-admin` is configured:

**Health check** (`/_health`):
```json
{"status": "healthy", "version": "1.0.0", "uptime": "1h30m", "proxies": 2}
```

**Metrics** (`/_metrics`):

All metrics include a `route` label for per-proxy breakdown:
```
http_tap_proxy_requests_total{route="api"} 5000
http_tap_proxy_requests_total{route="web"} 7345
http_tap_proxy_requests_active{route="api"} 2
http_tap_proxy_requests_active{route="web"} 3
http_tap_proxy_bytes_received_total{route="api"} 500000
http_tap_proxy_bytes_received_total{route="web"} 734567
http_tap_proxy_bytes_sent_total{route="api"} 400000
http_tap_proxy_bytes_sent_total{route="web"} 3654321
http_tap_proxy_errors_total{route="api"} 1
http_tap_proxy_errors_total{route="web"} 2
http_tap_proxy_websocket_connections_active{route="api"} 1
http_tap_proxy_websocket_connections_active{route="web"} 1
http_tap_proxy_sse_connections_active{route="api"} 0
http_tap_proxy_sse_connections_active{route="web"} 1
http_tap_proxy_upstream_latency_avg_microseconds{route="api"} 1234.56
http_tap_proxy_upstream_latency_avg_microseconds{route="web"} 2345.67
http_tap_proxy_log_errors_total{route="api"} 0
http_tap_proxy_log_errors_total{route="web"} 0
http_tap_proxy_uptime_seconds 5400.00
```

To aggregate across routes in Prometheus: `sum(http_tap_proxy_requests_total)`

## Service Installation

### Linux (systemd)

```bash
./http-tap-proxy \
  --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=/var/log/proxy.jsonl" \
  --print-systemd > /etc/systemd/system/http-tap-proxy.service
systemctl daemon-reload
systemctl enable --now http-tap-proxy
```

### Windows

```cmd
http-tap-proxy.exe --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=C:\logs\proxy.jsonl" --service install
http-tap-proxy.exe --service start
```

## Testing

```bash
make test               # Run all unit tests
make test-short         # Quick tests (skip stress tests)
make bench              # Run benchmarks
./test.sh               # Run integration tests
```
