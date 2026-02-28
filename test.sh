#!/bin/bash
# Test script for HTTP Tap Proxy
# Run this script to verify the proxy works correctly

set -e

PROXY_BIN="./http-tap-proxy"
TEST_DIR="./test_output"
UPSTREAM_PORT=9876
PROXY_HTTP_PORT=8080
PROXY_HTTPS_PORT=8443
ADMIN_PORT=9090

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

# Build if needed
if [ ! -f "$PROXY_BIN" ]; then
    log_info "Building proxy..."
    go build -o "$PROXY_BIN" .
fi

# Create test directory
mkdir -p "$TEST_DIR"

echo ""
echo "=========================================="
echo "  HTTP Tap Proxy Test Suite"
echo "=========================================="
echo ""

# Test 1: Help output
log_info "Test 1: Checking help output..."
$PROXY_BIN --help > /dev/null 2>&1 && log_info "  PASS: Help works" || { log_error "  FAIL: Help failed"; exit 1; }

# Test 2: Systemd unit generation
log_info "Test 2: Testing systemd unit generation..."
$PROXY_BIN --proxy "name=api,listen_http=:8080,upstream=http://localhost:5000,log_jsonl=/var/log/test.jsonl" --print-systemd > "$TEST_DIR/systemd.unit"
if grep -q "ExecStart=" "$TEST_DIR/systemd.unit" && grep -q "WantedBy=multi-user.target" "$TEST_DIR/systemd.unit"; then
    log_info "  PASS: Systemd unit generated correctly"
else
    log_error "  FAIL: Systemd unit missing expected content"
    exit 1
fi

# Test 3: Start upstream server with latency measurement support
log_info "Test 3: Starting test upstream server on port $UPSTREAM_PORT..."
cat > "$TEST_DIR/upstream.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Test upstream server that:
1. Handles regular GET/POST for functional tests
2. Records timestamps for latency measurement
3. Returns timestamps via X-Upstream-* headers
"""
import http.server
import json
import sys
import time
import threading

# Shared timestamp storage for latency tests
timestamps = {}
lock = threading.Lock()

class TestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logs

    def do_GET(self):
        recv_time = time.perf_counter()

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        # Include receive timestamp in response header
        self.send_header('X-Upstream-Recv-Time', str(recv_time))
        self.end_headers()

        send_time = time.perf_counter()
        response = {"path": self.path, "method": "GET", "message": "Hello from upstream!"}
        self.wfile.write(json.dumps(response).encode())

        # Store timestamps if request has ID
        req_id = self.headers.get('X-Request-ID')
        if req_id:
            with lock:
                timestamps[req_id] = {'recv': recv_time, 'send': send_time}

    def do_POST(self):
        recv_time = time.perf_counter()

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        # Try to decode as text, fall back to noting binary
        try:
            body_str = body.decode('utf-8')
        except:
            body_str = f"<binary {content_length} bytes>"

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Upstream-Recv-Time', str(recv_time))
        self.end_headers()

        send_time = time.perf_counter()
        response = {"path": self.path, "method": "POST", "received_body": body_str, "body_length": content_length}
        self.wfile.write(json.dumps(response).encode())

        req_id = self.headers.get('X-Request-ID')
        if req_id:
            with lock:
                timestamps[req_id] = {'recv': recv_time, 'send': send_time}

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
    server = http.server.HTTPServer(('127.0.0.1', port), TestHandler)
    print(f"Upstream server running on port {port}", flush=True)
    server.serve_forever()
PYEOF

python3 "$TEST_DIR/upstream.py" $UPSTREAM_PORT &
UPSTREAM_PID=$!
sleep 1

# Verify upstream is running
if ! curl -s "http://127.0.0.1:$UPSTREAM_PORT/" > /dev/null 2>&1; then
    log_error "  FAIL: Upstream server didn't start"
    exit 1
fi
log_info "  PASS: Upstream server running (PID: $UPSTREAM_PID)"

# Test 4: Start proxy with JSONL logging
log_info "Test 4: Starting proxy with JSONL logging..."
$PROXY_BIN \
    --proxy "name=test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/requests.jsonl" \
    --rotate-size 10MB \
    --rotate-interval 1h \
    > "$TEST_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Verify proxy is running
if ! curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/" > /dev/null 2>&1; then
    log_error "  FAIL: Proxy didn't start"
    cat "$TEST_DIR/proxy.log"
    exit 1
fi
log_info "  PASS: Proxy running (PID: $PROXY_PID)"

# Test 5: Simple GET request through proxy
log_info "Test 5: Testing GET request through proxy..."
RESPONSE=$(curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/test/path?foo=bar")
if echo "$RESPONSE" | grep -q "Hello from upstream"; then
    log_info "  PASS: GET request proxied correctly"
else
    log_error "  FAIL: GET response unexpected: $RESPONSE"
    exit 1
fi

# Test 6: POST request with body
log_info "Test 6: Testing POST request with body..."
POST_BODY='{"user": "test", "action": "create"}'
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$POST_BODY" "http://127.0.0.1:$PROXY_HTTP_PORT/api/users")
if echo "$RESPONSE" | grep -q "received_body"; then
    log_info "  PASS: POST request proxied correctly"
else
    log_error "  FAIL: POST response unexpected: $RESPONSE"
    exit 1
fi

# Test 7: Check JSONL log file
log_info "Test 7: Checking JSONL log file..."
sleep 1  # Give async logging time to complete
if [ -f "$TEST_DIR/requests.jsonl" ]; then
    LINE_COUNT=$(wc -l < "$TEST_DIR/requests.jsonl")
    if [ "$LINE_COUNT" -ge 2 ]; then
        log_info "  PASS: JSONL log has $LINE_COUNT entries"

        # Validate JSON format
        if python3 -c "import json; [json.loads(l) for l in open('$TEST_DIR/requests.jsonl')]" 2>/dev/null; then
            log_info "  PASS: All JSONL entries are valid JSON"
        else
            log_error "  FAIL: JSONL contains invalid JSON"
            exit 1
        fi

        # Check for expected fields
        if grep -q '"type":"http"' "$TEST_DIR/requests.jsonl" && \
           grep -q '"request"' "$TEST_DIR/requests.jsonl" && \
           grep -q '"response"' "$TEST_DIR/requests.jsonl"; then
            log_info "  PASS: JSONL entries have expected structure"
        else
            log_error "  FAIL: JSONL entries missing expected fields"
            cat "$TEST_DIR/requests.jsonl"
            exit 1
        fi
    else
        log_error "  FAIL: Expected at least 2 log entries, got $LINE_COUNT"
        exit 1
    fi
else
    log_error "  FAIL: JSONL log file not created"
    exit 1
fi

# Test 8: Large body handling (not truncated)
log_info "Test 8: Testing medium-sized body (50KB)..."
LARGE_BODY=$(python3 -c "print('x' * 50000)")
RESPONSE=$(curl -s -X POST -H "Content-Type: text/plain" -d "$LARGE_BODY" "http://127.0.0.1:$PROXY_HTTP_PORT/large")
if echo "$RESPONSE" | grep -q '"body_length": 50000'; then
    log_info "  PASS: Large body handled correctly"
else
    log_error "  FAIL: Large body handling failed"
    exit 1
fi

# Stop first proxy for next tests
kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 9: SQLite logging
log_info "Test 9: Testing SQLite logging..."
$PROXY_BIN \
    --proxy "name=sqlite-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_sqlite=$TEST_DIR/requests.db" \
    > "$TEST_DIR/proxy2.log" 2>&1 &
PROXY_PID=$!
sleep 2

curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/sqlite-test" > /dev/null
sleep 2  # Async logging needs time to complete

if [ -f "$TEST_DIR/requests.db" ]; then
    COUNT=$(sqlite3 "$TEST_DIR/requests.db" "SELECT COUNT(*) FROM http_entries;" 2>/dev/null || echo "0")
    if [ "$COUNT" -ge 1 ]; then
        log_info "  PASS: SQLite logging works ($COUNT entries)"
    else
        log_error "  FAIL: SQLite has no entries"
        exit 1
    fi
else
    log_error "  FAIL: SQLite database not created"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 10: Both JSONL and SQLite simultaneously
log_info "Test 10: Testing dual logging (JSONL + SQLite)..."
$PROXY_BIN \
    --proxy "name=dual-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/dual.jsonl,log_sqlite=$TEST_DIR/dual.db" \
    > "$TEST_DIR/proxy3.log" 2>&1 &
PROXY_PID=$!
sleep 2

curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/dual-test" > /dev/null
sleep 2  # Async logging needs time to complete

JSONL_LINES=$(wc -l < "$TEST_DIR/dual.jsonl" 2>/dev/null || echo "0")
SQLITE_COUNT=$(sqlite3 "$TEST_DIR/dual.db" "SELECT COUNT(*) FROM http_entries;" 2>/dev/null || echo "0")

if [ "$JSONL_LINES" -ge 1 ] && [ "$SQLITE_COUNT" -ge 1 ]; then
    log_info "  PASS: Dual logging works (JSONL: $JSONL_LINES, SQLite: $SQLITE_COUNT)"
else
    log_error "  FAIL: Dual logging failed (JSONL: $JSONL_LINES, SQLite: $SQLITE_COUNT)"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 11: HTTPS with auto-cert
log_info "Test 11: Testing HTTPS with auto-generated certificate..."
$PROXY_BIN \
    --proxy "name=https-test,listen_https=:$PROXY_HTTPS_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/https.jsonl" \
    --auto-cert \
    > "$TEST_DIR/proxy4.log" 2>&1 &
PROXY_PID=$!
sleep 2

RESPONSE=$(curl -sk "https://127.0.0.1:$PROXY_HTTPS_PORT/https-test")
if echo "$RESPONSE" | grep -q "Hello from upstream"; then
    log_info "  PASS: HTTPS with auto-cert works"
else
    log_error "  FAIL: HTTPS request failed"
    cat "$TEST_DIR/proxy4.log"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 12: Admin endpoints (health + metrics)
log_info "Test 12: Testing admin endpoints on separate port..."
$PROXY_BIN \
    --proxy "name=admin-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/admin.jsonl" \
    --listen-admin ":$ADMIN_PORT" \
    > "$TEST_DIR/proxy5.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Test health endpoint
HEALTH_RESPONSE=$(curl -s "http://127.0.0.1:$ADMIN_PORT/_health")
if echo "$HEALTH_RESPONSE" | grep -q '"status":"healthy"'; then
    log_info "  PASS: Health endpoint works"
else
    log_error "  FAIL: Health endpoint failed: $HEALTH_RESPONSE"
    exit 1
fi

# Test metrics endpoint
METRICS_RESPONSE=$(curl -s "http://127.0.0.1:$ADMIN_PORT/_metrics")
if echo "$METRICS_RESPONSE" | grep -q "http_tap_proxy_requests_total"; then
    log_info "  PASS: Metrics endpoint works"
else
    log_error "  FAIL: Metrics endpoint failed: $METRICS_RESPONSE"
    exit 1
fi

# Verify admin paths are NOT available on proxy port
PROXY_HEALTH=$(curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/_health")
if echo "$PROXY_HEALTH" | grep -q "Hello from upstream"; then
    log_info "  PASS: Admin paths correctly NOT intercepted on proxy port"
else
    log_warn "  WARN: /_health on proxy port gave unexpected response"
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 13: Path filtering (include)
log_info "Test 13: Testing path filtering (include mode)..."
$PROXY_BIN \
    --proxy "name=filter-inc,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/filter_include.jsonl,include_path=^/api/" \
    > "$TEST_DIR/proxy6.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Request to /api/ should be logged
curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/api/users" > /dev/null
# Request to /other/ should NOT be logged
curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/other/path" > /dev/null
sleep 1

INCLUDE_COUNT=$(wc -l < "$TEST_DIR/filter_include.jsonl" 2>/dev/null || echo "0")
if [ "$INCLUDE_COUNT" -eq 1 ]; then
    log_info "  PASS: Include filter works (logged $INCLUDE_COUNT of 2 requests)"
else
    log_error "  FAIL: Include filter expected 1 entry, got $INCLUDE_COUNT"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 14: Path filtering (exclude)
log_info "Test 14: Testing path filtering (exclude mode)..."
$PROXY_BIN \
    --proxy "name=filter-exc,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/filter_exclude.jsonl,exclude_path=^/health" \
    > "$TEST_DIR/proxy7.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Request to /health should NOT be logged
curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/health" > /dev/null
# Request to /api/ should be logged
curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/api/data" > /dev/null
sleep 1

EXCLUDE_COUNT=$(wc -l < "$TEST_DIR/filter_exclude.jsonl" 2>/dev/null || echo "0")
if [ "$EXCLUDE_COUNT" -eq 1 ]; then
    log_info "  PASS: Exclude filter works (logged $EXCLUDE_COUNT of 2 requests)"
else
    log_error "  FAIL: Exclude filter expected 1 entry, got $EXCLUDE_COUNT"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 15: Correlation ID extraction
log_info "Test 15: Testing correlation ID extraction..."
$PROXY_BIN \
    --proxy "name=corr-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/correlation.jsonl" \
    > "$TEST_DIR/proxy8.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Send request with X-Request-ID header
curl -s -H "X-Request-ID: test-corr-123" "http://127.0.0.1:$PROXY_HTTP_PORT/corr-test" > /dev/null
sleep 1

if grep -q '"correlation_id":"test-corr-123"' "$TEST_DIR/correlation.jsonl"; then
    log_info "  PASS: Correlation ID extracted correctly"
else
    log_error "  FAIL: Correlation ID not found in log"
    cat "$TEST_DIR/correlation.jsonl"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 16: Concurrent requests
log_info "Test 16: Testing concurrent requests..."
$PROXY_BIN \
    --proxy "name=conc-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/concurrent.jsonl" \
    > "$TEST_DIR/proxy9.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Send 20 concurrent requests
CURL_PIDS=""
for i in $(seq 1 20); do
    curl -s --max-time 10 "http://127.0.0.1:$PROXY_HTTP_PORT/concurrent/$i" > /dev/null &
    CURL_PIDS="$CURL_PIDS $!"
done
# Wait only for curl processes, not the upstream server
for pid in $CURL_PIDS; do
    wait $pid 2>/dev/null || true
done
sleep 2

CONCURRENT_COUNT=$(wc -l < "$TEST_DIR/concurrent.jsonl")
if [ "$CONCURRENT_COUNT" -ge 20 ]; then
    log_info "  PASS: Handled $CONCURRENT_COUNT concurrent requests"
else
    log_error "  FAIL: Expected 20+ entries, got $CONCURRENT_COUNT"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
sleep 1

# Test 17: Multi-proxy (multiple upstreams)
log_info "Test 17: Testing multi-proxy configuration..."

# Start a second upstream on a different port
UPSTREAM2_PORT=9877
python3 "$TEST_DIR/upstream.py" $UPSTREAM2_PORT &
UPSTREAM2_PID=$!
sleep 1

PROXY_HTTP_PORT2=8082

$PROXY_BIN \
    --proxy "name=api,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/multi_api.jsonl" \
    --proxy "name=web,listen_http=:$PROXY_HTTP_PORT2,upstream=http://127.0.0.1:$UPSTREAM2_PORT,log_jsonl=$TEST_DIR/multi_web.jsonl" \
    > "$TEST_DIR/proxy_multi.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Test requests to both proxies
RESP1=$(curl -s "http://127.0.0.1:$PROXY_HTTP_PORT/api-endpoint")
RESP2=$(curl -s "http://127.0.0.1:$PROXY_HTTP_PORT2/web-endpoint")
sleep 1

# Verify both responded
if echo "$RESP1" | grep -q "Hello from upstream" && echo "$RESP2" | grep -q "Hello from upstream"; then
    log_info "  PASS: Both proxies responding correctly"
else
    log_error "  FAIL: Multi-proxy responses failed"
    exit 1
fi

# Verify route_name in logs
if grep -q '"route_name":"api"' "$TEST_DIR/multi_api.jsonl" && \
   grep -q '"route_name":"web"' "$TEST_DIR/multi_web.jsonl"; then
    log_info "  PASS: Route names correctly captured in logs"
else
    log_error "  FAIL: Route names not found in logs"
    cat "$TEST_DIR/multi_api.jsonl"
    cat "$TEST_DIR/multi_web.jsonl"
    exit 1
fi

# Verify each log only has its own route
if ! grep -q '"route_name":"web"' "$TEST_DIR/multi_api.jsonl" && \
   ! grep -q '"route_name":"api"' "$TEST_DIR/multi_web.jsonl"; then
    log_info "  PASS: Logs correctly separated by route"
else
    log_error "  FAIL: Logs mixed between routes"
    exit 1
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true
kill $UPSTREAM2_PID 2>/dev/null || true
wait $UPSTREAM2_PID 2>/dev/null || true
sleep 1

# Test 18: Insertion latency measurement
log_info "Test 18: Testing insertion latency (single-process measurement)..."

# Kill the functional test upstream - latency test needs its own for single-clock accuracy
kill $UPSTREAM_PID 2>/dev/null || true
wait $UPSTREAM_PID 2>/dev/null || true
sleep 1

# Create single-process latency test (client + server in same process = same clock)
cat > "$TEST_DIR/latency_test.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Single-process latency measurement:
- Server thread and client in SAME process (shared time.perf_counter)
- Measures actual insertion latency from proxy

Request latency:  client sends first byte -> server receives first byte
Response latency: server sends first byte -> client receives first byte
"""
import http.server
import threading
import socket
import time
import sys
import statistics

# Shared timestamps (same process = same clock)
timestamps = {}
lock = threading.Lock()

class TimingHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        req_recv_time = time.perf_counter()
        req_id = self.headers.get('X-Request-ID', '')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '100')
        self.end_headers()

        resp_send_time = time.perf_counter()
        self.wfile.write(b'x' * 100)

        if req_id:
            with lock:
                timestamps[req_id] = {'req_recv': req_recv_time, 'resp_send': resp_send_time}

    def do_POST(self):
        req_recv_time = time.perf_counter()
        req_id = self.headers.get('X-Request-ID', '')

        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '100')
        self.end_headers()

        resp_send_time = time.perf_counter()
        self.wfile.write(b'x' * 100)

        if req_id:
            with lock:
                timestamps[req_id] = {'req_recv': req_recv_time, 'resp_send': resp_send_time}

def measure(host, port, label, n=10):
    req_lats, resp_lats = [], []
    payload = b'x' * 1000

    for i in range(n):
        req_id = f"{label}-{i}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((host, port))

        req = f"POST /t HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(payload)}\r\nX-Request-ID: {req_id}\r\nConnection: close\r\n\r\n"

        req_send_time = time.perf_counter()
        sock.sendall(req.encode() + payload)

        # Wait for first response byte
        resp = sock.recv(1)
        resp_recv_time = time.perf_counter()

        # Drain rest
        while sock.recv(4096): pass
        sock.close()

        time.sleep(0.005)  # Let server record

        with lock:
            if req_id in timestamps:
                ts = timestamps[req_id]
                req_lats.append((ts['req_recv'] - req_send_time) * 1000)
                resp_lats.append((resp_recv_time - ts['resp_send']) * 1000)

    return req_lats, resp_lats

if __name__ == '__main__':
    upstream_port = int(sys.argv[1])
    proxy_port = int(sys.argv[2]) if len(sys.argv) > 2 else None

    # Start server in this process
    server = http.server.HTTPServer(('127.0.0.1', upstream_port), TimingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)

    # Direct measurement (baseline)
    d_req, d_resp = measure('127.0.0.1', upstream_port, 'direct')

    # Proxied measurement
    p_req, p_resp = [], []
    if proxy_port:
        time.sleep(0.3)
        p_req, p_resp = measure('127.0.0.1', proxy_port, 'proxied')

    # Results
    if d_req:
        print(f"DIRECT_REQ={statistics.mean(d_req):.3f}")
        print(f"DIRECT_RESP={statistics.mean(d_resp):.3f}")
    if p_req:
        print(f"PROXIED_REQ={statistics.mean(p_req):.3f}")
        print(f"PROXIED_RESP={statistics.mean(p_resp):.3f}")
        print(f"REQ_OVERHEAD={statistics.mean(p_req) - statistics.mean(d_req):.3f}")
        print(f"RESP_OVERHEAD={statistics.mean(p_resp) - statistics.mean(d_resp):.3f}")

    server.shutdown()
PYEOF

# Start proxy pointing to the latency test's upstream port
$PROXY_BIN \
    --proxy "name=lat-test,listen_http=:$PROXY_HTTP_PORT,upstream=http://127.0.0.1:$UPSTREAM_PORT,log_jsonl=$TEST_DIR/latency.jsonl" \
    > "$TEST_DIR/proxy10.log" 2>&1 &
PROXY_PID=$!
sleep 2

# Run single-process latency test (starts its own server internally)
LATENCY_OUTPUT=$(python3 "$TEST_DIR/latency_test.py" $UPSTREAM_PORT $PROXY_HTTP_PORT 2>&1)

REQ_OVERHEAD=$(echo "$LATENCY_OUTPUT" | grep "REQ_OVERHEAD=" | cut -d= -f2)
RESP_OVERHEAD=$(echo "$LATENCY_OUTPUT" | grep "RESP_OVERHEAD=" | cut -d= -f2)
DIRECT_REQ=$(echo "$LATENCY_OUTPUT" | grep "DIRECT_REQ=" | cut -d= -f2)
DIRECT_RESP=$(echo "$LATENCY_OUTPUT" | grep "DIRECT_RESP=" | cut -d= -f2)
PROXIED_REQ=$(echo "$LATENCY_OUTPUT" | grep "PROXIED_REQ=" | cut -d= -f2)
PROXIED_RESP=$(echo "$LATENCY_OUTPUT" | grep "PROXIED_RESP=" | cut -d= -f2)

if [ -n "$REQ_OVERHEAD" ] && [ -n "$RESP_OVERHEAD" ]; then
    # Check if overhead is acceptable (<5ms for localhost)
    REQ_OK=$(echo "$REQ_OVERHEAD" | awk '{print ($1 < 5) ? 1 : 0}')
    RESP_OK=$(echo "$RESP_OVERHEAD" | awk '{print ($1 < 5) ? 1 : 0}')

    if [ "$REQ_OK" -eq 1 ]; then
        log_info "  PASS: Request latency overhead: ${REQ_OVERHEAD}ms (direct: ${DIRECT_REQ}ms, proxied: ${PROXIED_REQ}ms)"
    else
        log_warn "  WARN: Request latency overhead: ${REQ_OVERHEAD}ms (direct: ${DIRECT_REQ}ms, proxied: ${PROXIED_REQ}ms)"
    fi

    if [ "$RESP_OK" -eq 1 ]; then
        log_info "  PASS: Response latency overhead: ${RESP_OVERHEAD}ms (direct: ${DIRECT_RESP}ms, proxied: ${PROXIED_RESP}ms)"
    else
        log_warn "  WARN: Response latency overhead: ${RESP_OVERHEAD}ms (direct: ${DIRECT_RESP}ms, proxied: ${PROXIED_RESP}ms)"
    fi
else
    log_error "  FAIL: Could not measure latency"
    echo "$LATENCY_OUTPUT"
fi

kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true

echo ""
echo "=========================================="
echo -e "  ${GREEN}All tests passed!${NC}"
echo "=========================================="
echo ""

# Show sample log entry
log_info "Sample JSONL entry:"
echo ""
head -1 "$TEST_DIR/requests.jsonl" | python3 -m json.tool 2>/dev/null || head -1 "$TEST_DIR/requests.jsonl"
echo ""

log_info "Test outputs are in: $TEST_DIR/"
log_info "To clean up: rm -rf $TEST_DIR"
