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
# Basic - log to JSONL
./http-tap-proxy --upstream http://localhost:5000 --log-jsonl ./requests.jsonl

# Log to SQLite with admin endpoint
./http-tap-proxy \
  --upstream http://localhost:5000 \
  --log-sqlite ./requests.db \
  --listen-admin :9090

# HTTPS with auto-cert
./http-tap-proxy \
  --upstream http://localhost:5000 \
  --listen-https :8443 \
  --auto-cert \
  --log-jsonl ./requests.jsonl

# With path filtering (only log /api/ paths)
./http-tap-proxy \
  --upstream http://localhost:5000 \
  --log-jsonl ./requests.jsonl \
  --include-path "^/api/"

# Exclude health checks from logging
./http-tap-proxy \
  --upstream http://localhost:5000 \
  --log-jsonl ./requests.jsonl \
  --exclude-path "^/health" \
  --exclude-path "^/ready"
```

## Options

### Core

| Flag | Default | Description |
|------|---------|-------------|
| `--upstream` | required | Target URL (e.g., `http://localhost:5000`) |
| `--listen-http` | `:8080` | HTTP proxy address |
| `--listen-https` | | HTTPS proxy address |
| `--listen-admin` | | Admin port for health/metrics (recommended: `:9090`) |

### Logging

| Flag | Default | Description |
|------|---------|-------------|
| `--log-jsonl` | | JSONL log file path |
| `--log-sqlite` | | SQLite database path |
| `--rotate-size` | `100MB` | Rotate when file exceeds size |
| `--rotate-interval` | `1h` | Rotate at interval |
| `--retention` | `10` | Number of rotated files to keep (when S3 not configured) |
| `--max-body-size` | `100MB` | Max request/response body to capture |

### Path Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--include-path` | | Regex for paths to log (whitelist mode, can repeat) |
| `--exclude-path` | | Regex for paths to exclude (blacklist mode, can repeat) |

If `--include-path` is set, only matching paths are logged. `--exclude-path` patterns are applied after include filtering.

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

Bodies stored as BLOBs (binary, not base64).

## Admin Endpoints

When `--listen-admin` is configured:

**Health check** (`/_health`):
```json
{"status": "healthy", "version": "1.0.0", "uptime": "1h30m"}
```

**Metrics** (`/_metrics`):
```
http_tap_proxy_requests_total 12345
http_tap_proxy_requests_active 5
http_tap_proxy_bytes_received_total 1234567
http_tap_proxy_bytes_sent_total 7654321
http_tap_proxy_errors_total 3
http_tap_proxy_websocket_connections_active 2
http_tap_proxy_sse_connections_active 1
http_tap_proxy_upstream_latency_avg_microseconds 1234.56
http_tap_proxy_log_errors_total 0
http_tap_proxy_uptime_seconds 5400.00
```

## Programmatic Usage

```go
proxy, err := NewProxy(&Config{
    ListenHTTP:  ":8080",
    ListenAdmin: ":9090",
    Upstream:    "http://localhost:5000",
    LogJSONL:    "./requests.jsonl",
})
if err != nil {
    log.Fatal(err)
}

if err := proxy.Start(); err != nil {
    log.Fatal(err)
}

// Get actual addresses (useful with port 0)
fmt.Println("Proxy:", proxy.HTTPAddr())
fmt.Println("Admin:", proxy.AdminAddr())

// Graceful shutdown
proxy.Close()
```

## Service Installation

### Linux (systemd)

```bash
./http-tap-proxy --upstream http://localhost:5000 --log-jsonl /var/log/proxy.jsonl --print-systemd > /etc/systemd/system/http-tap-proxy.service
systemctl daemon-reload
systemctl enable --now http-tap-proxy
```

### Windows

```cmd
http-tap-proxy.exe --upstream http://localhost:5000 --log-jsonl C:\logs\proxy.jsonl --service install
http-tap-proxy.exe --service start
```

## Testing

```bash
make test               # Run all unit tests
make test-short         # Quick tests (skip stress tests)
make bench              # Run benchmarks
./test.sh               # Run integration tests
```
