package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// testUpstream is an HTTP server for testing that records timestamps
type testUpstream struct {
	server     *http.Server
	listener   net.Listener
	timestamps sync.Map // req_id -> timestamps
}

type reqTimestamps struct {
	ReqRecv  time.Time
	RespSend time.Time
}

func newTestUpstream(t *testing.T) *testUpstream {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	u := &testUpstream{
		listener: listener,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", u.handler)

	u.server = &http.Server{Handler: mux}

	go func() { _ = u.server.Serve(listener) }()

	return u
}

func (u *testUpstream) handler(w http.ResponseWriter, r *http.Request) {
	recvTime := time.Now()

	// Read request body
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// Record timestamps if request has ID
	reqID := r.Header.Get("X-Request-ID")
	if reqID != "" {
		u.timestamps.Store(reqID, &reqTimestamps{ReqRecv: recvTime})
	}

	// Prepare response
	resp := map[string]any{
		"path":        r.URL.Path,
		"method":      r.Method,
		"body_length": len(body),
		"message":     "Hello from upstream!",
	}

	respBody, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Header", "test-value")

	// Record response send time
	sendTime := time.Now()
	if reqID != "" {
		if ts, ok := u.timestamps.Load(reqID); ok {
			ts.(*reqTimestamps).RespSend = sendTime
		}
	}

	_, _ = w.Write(respBody)
}

func (u *testUpstream) Close() {
	_ = u.server.Close()
	_ = u.listener.Close()
}

func (u *testUpstream) URL() string {
	return fmt.Sprintf("http://%s", u.listener.Addr().String())
}

func (u *testUpstream) GetTimestamps(reqID string) *reqTimestamps {
	if ts, ok := u.timestamps.Load(reqID); ok {
		return ts.(*reqTimestamps)
	}
	return nil
}

// testProxy wraps a Proxy for testing
type testProxy struct {
	proxy      *Proxy
	logManager *LogManager
	logDir     string
}

// testProxyOptions configures the test proxy
type testProxyOptions struct {
	name              string // proxy name (default: "test")
	listenHTTP        string
	listenHTTPS       string
	upstream          string
	logJSONL          string
	logSQLite         string
	maxBodySize       int64
	autoCert          bool
	includePathsRegex []string
	excludePathsRegex []string
	jsonlOnly         bool // only create JSONL writer (no SQLite) - useful for benchmarks
}

func startTestProxy(t *testing.T, upstreamURL string) *testProxy {
	t.Helper()
	return startTestProxyWithOptions(t, testProxyOptions{
		upstream: upstreamURL,
	})
}

// startTestProxyTB is like startTestProxy but works with both *testing.T and *testing.B
func startTestProxyTB(tb testing.TB, opts testProxyOptions) *testProxy {
	tb.Helper()
	return startTestProxyWithOptionsTB(tb, opts)
}

func startTestProxyWithOptions(t *testing.T, opts testProxyOptions) *testProxy {
	t.Helper()
	return startTestProxyWithOptionsTB(t, opts)
}

func startTestProxyWithOptionsTB(tb testing.TB, opts testProxyOptions) *testProxy {
	tb.Helper()

	// Create temp dir for logs
	logDir, err := os.MkdirTemp("", "http-tap-proxy-test-*")
	if err != nil {
		tb.Fatalf("failed to create temp dir: %v", err)
	}

	// Set defaults
	if opts.name == "" {
		opts.name = "test"
	}
	if opts.listenHTTP == "" && opts.listenHTTPS == "" {
		opts.listenHTTP = "127.0.0.1:0"
	}
	if opts.maxBodySize == 0 {
		opts.maxBodySize = 100 * 1024 * 1024 // 100MB
	}

	jsonlPath := opts.logJSONL
	if jsonlPath == "" {
		jsonlPath = filepath.Join(logDir, "requests.jsonl")
	}
	sqlitePath := opts.logSQLite
	if sqlitePath == "" && !opts.jsonlOnly {
		sqlitePath = filepath.Join(logDir, "requests.db")
	}

	// Create proxy config
	proxyCfg := &ProxyConfig{
		Name:              opts.name,
		ListenHTTP:        opts.listenHTTP,
		ListenHTTPS:       opts.listenHTTPS,
		Upstream:          opts.upstream,
		LogJSONL:          jsonlPath,
		LogSQLite:         sqlitePath,
		IncludePathsRegex: opts.includePathsRegex,
		ExcludePathsRegex: opts.excludePathsRegex,
	}

	// Create global config
	globalCfg := &Config{
		MaxBodySize: opts.maxBodySize,
		AutoCert:    opts.autoCert,
		HealthPath:  "/_health",
		MetricsPath: "/_metrics",
	}

	// Create log writers
	var writers []LogWriter
	if jsonlPath != "" {
		w, err := newJSONLWriter(jsonlPath, 0, 0, nil, opts.name)
		if err != nil {
			_ = os.RemoveAll(logDir)
			tb.Fatalf("failed to create JSONL writer: %v", err)
		}
		writers = append(writers, w)
	}
	if sqlitePath != "" {
		w, err := newSQLiteWriter(sqlitePath, 0, 0, nil, opts.name)
		if err != nil {
			_ = os.RemoveAll(logDir)
			tb.Fatalf("failed to create SQLite writer: %v", err)
		}
		writers = append(writers, w)
	}

	logManager := newLogManager(writers, 0)

	proxy, err := NewProxy(proxyCfg, globalCfg, logManager)
	if err != nil {
		logManager.Stop()
		_ = os.RemoveAll(logDir)
		tb.Fatalf("failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		logManager.Stop()
		_ = os.RemoveAll(logDir)
		tb.Fatalf("failed to start proxy: %v", err)
	}

	return &testProxy{
		proxy:      proxy,
		logManager: logManager,
		logDir:     logDir,
	}
}

func (p *testProxy) Close() {
	_ = p.proxy.Close()
	if p.logManager != nil {
		p.logManager.Stop()
	}
	_ = os.RemoveAll(p.logDir)
}

func (p *testProxy) URL() string {
	return fmt.Sprintf("http://%s", p.proxy.HTTPAddr())
}

func (p *testProxy) JSONLPath() string {
	return filepath.Join(p.logDir, "requests.jsonl")
}

func (p *testProxy) SQLitePath() string {
	return filepath.Join(p.logDir, "requests.db")
}

// ============ Tests ============

func TestProxy_BasicGET(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL() + "/test/path?foo=bar")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("Hello from upstream")) {
		t.Errorf("unexpected response body: %s", body)
	}

	// Verify response headers are passed through
	if resp.Header.Get("X-Test-Header") != "test-value" {
		t.Errorf("missing or incorrect X-Test-Header")
	}
}

func TestProxy_BasicPOST(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	reqBody := `{"user": "test", "action": "create"}`
	resp, err := http.Post(proxy.URL()+"/api/users", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var respData map[string]any
	if err := json.Unmarshal(body, &respData); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if respData["body_length"].(float64) != float64(len(reqBody)) {
		t.Errorf("body length mismatch: got %v, want %d", respData["body_length"], len(reqBody))
	}
}

func TestProxy_LargeBody(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	// 1MB body
	largeBody := bytes.Repeat([]byte("x"), 1024*1024)

	resp, err := http.Post(proxy.URL()+"/large", "application/octet-stream", bytes.NewReader(largeBody))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var respData map[string]any
	if err := json.Unmarshal(body, &respData); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(respData["body_length"].(float64)) != len(largeBody) {
		t.Errorf("body length mismatch: got %v, want %d", respData["body_length"], len(largeBody))
	}
}

func TestProxy_Concurrent(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	const numRequests = 50
	var wg sync.WaitGroup
	var successCount atomic.Int32

	for i := range numRequests {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			resp, err := http.Get(fmt.Sprintf("%s/concurrent/%d", proxy.URL(), n))
			if err != nil {
				t.Logf("request %d failed: %v", n, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.ReadAll(resp.Body)

			if resp.StatusCode == 200 {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() != numRequests {
		t.Errorf("only %d/%d requests succeeded", successCount.Load(), numRequests)
	}
}

func TestProxy_JSONLLogging(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	// Make a request
	resp, err := http.Get(proxy.URL() + "/test-logging")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	_ = resp.Body.Close()

	// Wait for async logging
	time.Sleep(200 * time.Millisecond)

	// Check JSONL file
	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read JSONL: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("JSONL file is empty")
	}

	// Parse first line
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var entry map[string]any
	if err := json.Unmarshal(lines[0], &entry); err != nil {
		t.Fatalf("failed to parse JSONL entry: %v", err)
	}

	if entry["type"] != "http" {
		t.Errorf("unexpected type: %v", entry["type"])
	}

	req := entry["request"].(map[string]any)
	if req["method"] != "GET" {
		t.Errorf("unexpected method: %v", req["method"])
	}
}

func TestProxy_SQLiteLogging(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	// Make a request
	resp, err := http.Post(proxy.URL()+"/test-sqlite", "text/plain", strings.NewReader("test body"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body) // Must read body for logging to complete
	_ = resp.Body.Close()

	// Wait for async logging
	time.Sleep(300 * time.Millisecond)

	// Check SQLite database
	db, err := sql.Open("sqlite", proxy.SQLitePath())
	if err != nil {
		t.Fatalf("failed to open SQLite: %v", err)
	}
	defer func() { _ = db.Close() }()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM http_entries").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query SQLite: %v", err)
	}

	if count == 0 {
		t.Fatal("no entries in SQLite")
	}

	// Check specific fields - get the POST entry
	var method, url string
	var bodySize int
	err = db.QueryRow("SELECT req_method, req_url, req_body_size FROM http_entries WHERE req_method = 'POST' LIMIT 1").Scan(&method, &url, &bodySize)
	if err != nil {
		t.Fatalf("failed to query entry: %v", err)
	}

	if method != "POST" {
		t.Errorf("unexpected method: %s", method)
	}

	if bodySize != len("test body") {
		t.Errorf("unexpected body size: %d", bodySize)
	}
}

func TestProxy_HTTPS_AutoCert(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxyWithOptions(t, testProxyOptions{
		listenHTTPS: "127.0.0.1:0",
		upstream:    upstream.URL(),
		autoCert:    true,
	})
	defer proxy.Close()

	// Make HTTPS request with insecure client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/https-test", proxy.proxy.HTTPSAddr()))
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("Hello from upstream")) {
		t.Errorf("unexpected response: %s", body)
	}
}

// TestProxy_InsertionLatency measures actual latency added by the proxy
// Uses same-process upstream for accurate time measurement
func TestProxy_InsertionLatency(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	const iterations = 20
	var directLatencies, proxiedLatencies []time.Duration

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	// Measure direct latency (client -> upstream, same process)
	for i := range iterations {
		reqID := fmt.Sprintf("direct-%d", i)

		req, _ := http.NewRequest("GET", upstream.URL()+"/latency-test", nil)
		req.Header.Set("X-Request-ID", reqID)

		sendTime := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("direct request failed: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		recvTime := time.Now()

		// Get server-side timestamp
		time.Sleep(10 * time.Millisecond) // Let server record
		if ts := upstream.GetTimestamps(reqID); ts != nil {
			// Request latency: send -> server recv
			reqLatency := ts.ReqRecv.Sub(sendTime)
			// Response latency: server send -> client recv
			respLatency := recvTime.Sub(ts.RespSend)
			directLatencies = append(directLatencies, reqLatency+respLatency)
		}
	}

	// Measure proxied latency (client -> proxy -> upstream)
	for i := range iterations {
		reqID := fmt.Sprintf("proxied-%d", i)

		req, _ := http.NewRequest("GET", proxy.URL()+"/latency-test", nil)
		req.Header.Set("X-Request-ID", reqID)

		sendTime := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("proxied request failed: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		recvTime := time.Now()

		time.Sleep(10 * time.Millisecond)
		if ts := upstream.GetTimestamps(reqID); ts != nil {
			reqLatency := ts.ReqRecv.Sub(sendTime)
			respLatency := recvTime.Sub(ts.RespSend)
			proxiedLatencies = append(proxiedLatencies, reqLatency+respLatency)
		}
	}

	// Calculate averages
	var directAvg, proxiedAvg time.Duration
	for _, d := range directLatencies {
		directAvg += d
	}
	directAvg /= time.Duration(len(directLatencies))

	for _, d := range proxiedLatencies {
		proxiedAvg += d
	}
	proxiedAvg /= time.Duration(len(proxiedLatencies))

	overhead := proxiedAvg - directAvg

	t.Logf("Direct avg:  %v", directAvg)
	t.Logf("Proxied avg: %v", proxiedAvg)
	t.Logf("Overhead:    %v", overhead)

	// Overhead should be minimal (<5ms on localhost)
	if overhead > 5*time.Millisecond {
		t.Errorf("insertion latency too high: %v (should be <5ms)", overhead)
	}
}

// ============ Benchmarks ============

func BenchmarkProxy_SmallRequest(b *testing.B) {
	upstream := newTestUpstream(&testing.T{})
	defer upstream.Close()

	proxy := startTestProxyTB(b, testProxyOptions{
		name:      "bench",
		upstream:  upstream.URL(),
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
			},
		}
		for pb.Next() {
			resp, err := client.Get(proxyURL + "/bench")
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func BenchmarkProxy_LargeBody(b *testing.B) {
	largeResp := bytes.Repeat([]byte("x"), 100*1024) // 100KB

	// Custom upstream for large responses
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write(largeResp)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	upstreamURL := fmt.Sprintf("http://%s", listener.Addr().String())

	proxy := startTestProxyTB(b, testProxyOptions{
		name:      "bench",
		upstream:  upstreamURL,
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()
	reqBody := bytes.Repeat([]byte("y"), 100*1024) // 100KB

	b.ResetTimer()
	b.SetBytes(int64(len(reqBody) + len(largeResp)))

	for i := 0; i < b.N; i++ {
		resp, err := http.Post(proxyURL+"/bench", "application/octet-stream", bytes.NewReader(reqBody))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
}

// ============ Stress Tests ============

// TestProxy_StressConcurrentLargeBodies tests many parallel large request/response bodies
func TestProxy_StressConcurrentLargeBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	// Upstream that echoes back with large response
	largeResp := bytes.Repeat([]byte("R"), 512*1024) // 512KB response
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read entire request body
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Request-Size", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write(largeResp)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	upstreamURL := fmt.Sprintf("http://%s", listener.Addr().String())

	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "stress",
		upstream:  upstreamURL,
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	const numRequests = 100
	const bodySize = 256 * 1024 // 256KB request body

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var totalBytes atomic.Int64
	errors := make(chan error, numRequests)

	startTime := time.Now()

	for i := range numRequests {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			reqBody := bytes.Repeat([]byte{byte(n % 256)}, bodySize)

			resp, err := http.Post(proxyURL+fmt.Sprintf("/stress/%d", n), "application/octet-stream", bytes.NewReader(reqBody))
			if err != nil {
				errors <- fmt.Errorf("request %d failed: %w", n, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				errors <- fmt.Errorf("request %d read failed: %w", n, err)
				return
			}

			if resp.StatusCode != 200 {
				errors <- fmt.Errorf("request %d got status %d", n, resp.StatusCode)
				return
			}

			if len(respBody) != len(largeResp) {
				errors <- fmt.Errorf("request %d response size mismatch: got %d, want %d", n, len(respBody), len(largeResp))
				return
			}

			totalBytes.Add(int64(bodySize + len(respBody)))
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	close(errors)

	elapsed := time.Since(startTime)

	// Collect errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	t.Logf("Completed %d/%d requests in %v", successCount.Load(), numRequests, elapsed)
	t.Logf("Total data transferred: %.2f MB", float64(totalBytes.Load())/(1024*1024))
	t.Logf("Throughput: %.2f MB/s", float64(totalBytes.Load())/(1024*1024)/elapsed.Seconds())

	if len(errs) > 0 {
		for _, err := range errs[:min(5, len(errs))] {
			t.Logf("Error: %v", err)
		}
		if len(errs) > 5 {
			t.Logf("... and %d more errors", len(errs)-5)
		}
	}

	if successCount.Load() < int32(numRequests*90/100) {
		t.Errorf("too many failures: only %d/%d succeeded", successCount.Load(), numRequests)
	}
}

// TestProxy_WebSocket tests WebSocket proxying
func TestProxy_WebSocket(t *testing.T) {
	// Create WebSocket echo upstream
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// Simple WebSocket handshake
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}

		conn, buf, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Send upgrade response
		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAccept(key)
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
		_, _ = conn.Write([]byte("Upgrade: websocket\r\n"))
		_, _ = conn.Write([]byte("Connection: Upgrade\r\n"))
		_, _ = conn.Write([]byte("Sec-WebSocket-Accept: " + acceptKey + "\r\n"))
		_, _ = conn.Write([]byte("\r\n"))

		// Echo frames back
		for {
			frame, err := readWSFrame(buf.Reader)
			if err != nil {
				return
			}

			// Echo back (unmask and send as server frame)
			if frame.masked {
				for i := range frame.payload {
					frame.payload[i] ^= frame.maskKey[i%4]
				}
			}

			if err := writeWSFrame(conn, frame.opcode, frame.payload); err != nil {
				return
			}

			// Close on close frame
			if frame.opcode == 8 {
				return
			}
		}
	})

	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	upstreamURL := fmt.Sprintf("http://%s", listener.Addr().String())

	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "ws-test",
		upstream:  upstreamURL,
		jsonlOnly: true,
	})
	defer proxy.Close()

	// Connect to proxy WebSocket
	proxyAddr := proxy.proxy.HTTPAddr()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send WebSocket upgrade request
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", proxyAddr, wsKey)
	_, _ = conn.Write([]byte(req))

	// Read upgrade response
	buf := bufio.NewReader(conn)
	resp, err := http.ReadResponse(buf, nil)
	if err != nil {
		t.Fatalf("failed to read upgrade response: %v", err)
	}

	if resp.StatusCode != 101 {
		t.Fatalf("expected 101 Switching Protocols, got %d", resp.StatusCode)
	}

	// Send a text frame
	testMsg := []byte("Hello WebSocket!")
	if err := writeWSFrameMasked(conn, 1, testMsg); err != nil {
		t.Fatalf("failed to write frame: %v", err)
	}

	// Read echo response
	frame, err := readWSFrame(buf)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	if frame.opcode != 1 {
		t.Errorf("expected text frame (opcode 1), got %d", frame.opcode)
	}

	if string(frame.payload) != string(testMsg) {
		t.Errorf("echo mismatch: got %q, want %q", frame.payload, testMsg)
	}

	// Send close frame
	_ = writeWSFrameMasked(conn, 8, []byte{0x03, 0xe8}) // 1000 normal closure

	// Wait for log to be written
	time.Sleep(200 * time.Millisecond)

	// Check that WebSocket frames were logged
	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	if !bytes.Contains(data, []byte("websocket_frame")) {
		t.Errorf("expected websocket_frame entries in log")
	}

	t.Logf("WebSocket test passed, log contains %d bytes", len(data))
}

// TestProxy_SSE tests Server-Sent Events proxying
func TestProxy_SSE(t *testing.T) {
	// Create SSE upstream
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(200)

		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		// Send a few events
		events := []string{
			"event: message\ndata: Hello SSE!\n\n",
			"event: update\ndata: {\"count\": 1}\n\n",
			"event: update\ndata: {\"count\": 2}\n\n",
		}

		for _, event := range events {
			_, _ = w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})

	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	upstreamURL := fmt.Sprintf("http://%s", listener.Addr().String())

	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "sse-test",
		upstream:  upstreamURL,
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	// Make SSE request
	req, _ := http.NewRequest("GET", proxyURL+"/events", nil)
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Read all events
	body, _ := io.ReadAll(resp.Body)

	if !bytes.Contains(body, []byte("Hello SSE!")) {
		t.Errorf("expected SSE data in response")
	}

	// Wait for log to be written
	time.Sleep(200 * time.Millisecond)

	// Check that SSE events were logged
	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	if !bytes.Contains(data, []byte("sse_event")) {
		t.Errorf("expected sse_event entries in log")
	}

	t.Logf("SSE test passed, log contains %d bytes", len(data))
}

// TestProxy_HighParallelism tests very high concurrent request load
func TestProxy_HighParallelism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high parallelism test in short mode")
	}

	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "parallel",
		upstream:  upstream.URL(),
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	const numWorkers = 50
	const requestsPerWorker = 100

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var errorCount atomic.Int32

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: numWorkers,
			MaxConnsPerHost:     numWorkers,
		},
		Timeout: 10 * time.Second,
	}

	startTime := time.Now()

	for w := range numWorkers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range requestsPerWorker {
				resp, err := client.Get(fmt.Sprintf("%s/worker/%d/req/%d", proxyURL, worker, i))
				if err != nil {
					errorCount.Add(1)
					continue
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()

				if resp.StatusCode == 200 {
					successCount.Add(1)
				} else {
					errorCount.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	totalRequests := numWorkers * requestsPerWorker
	t.Logf("Completed %d/%d requests in %v", successCount.Load(), totalRequests, elapsed)
	t.Logf("Errors: %d", errorCount.Load())
	t.Logf("Requests/sec: %.2f", float64(successCount.Load())/elapsed.Seconds())

	if successCount.Load() < int32(totalRequests*95/100) {
		t.Errorf("too many failures: only %d/%d succeeded", successCount.Load(), totalRequests)
	}
}

// TestProxy_LatencyDiagnostic measures TRUE insertion latency
// Insertion latency = time added by proxy to each byte flowing through
// We measure: client_send_time → upstream_recv_time (for same byte)
func TestProxy_LatencyDiagnostic(t *testing.T) {
	// Shared timestamps (same process = same clock)
	var mu sync.Mutex
	var upstreamFirstByteTime time.Time

	// Raw TCP upstream that records EXACT receive time of first byte
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstreamListener.Close() }()

	upstreamAddr := upstreamListener.Addr().String()

	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				// Record time of FIRST BYTE received
				firstByte := make([]byte, 1)
				_, err := c.Read(firstByte)
				if err != nil {
					return
				}
				mu.Lock()
				upstreamFirstByteTime = time.Now()
				mu.Unlock()

				// Read rest of request
				buf := make([]byte, 64*1024)
				for {
					_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						break
					}
				}
				_ = c.SetReadDeadline(time.Time{})

				// Send minimal response
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	// Start plain proxy (no tap) for comparison
	upstreamURL, _ := url.Parse("http://" + upstreamAddr)
	plainProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	plainListener, _ := net.Listen("tcp", "127.0.0.1:0")
	plainServer := &http.Server{Handler: plainProxy}
	go func() { _ = plainServer.Serve(plainListener) }()
	defer func() { _ = plainServer.Close() }()
	plainAddr := plainListener.Addr().String()

	// Start tap proxy
	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "diag",
		upstream:  "http://" + upstreamAddr,
		jsonlOnly: true,
	})
	defer proxy.Close()

	tapAddr := proxy.proxy.HTTPAddr()

	// Measure insertion latency: time from client_send_first_byte to upstream_recv_first_byte
	measure := func(addr string, bodySize int) time.Duration {
		mu.Lock()
		upstreamFirstByteTime = time.Time{}
		mu.Unlock()

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return 0
		}
		defer func() { _ = conn.Close() }()

		body := make([]byte, bodySize)
		req := fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", addr, bodySize)

		// Record when we send first byte
		clientSendTime := time.Now()
		_, _ = conn.Write([]byte(req))
		_, _ = conn.Write(body)

		// Read response (to let upstream finish)
		_, _ = io.Copy(io.Discard, conn)

		// Get upstream receive time
		mu.Lock()
		recvTime := upstreamFirstByteTime
		mu.Unlock()

		if recvTime.IsZero() {
			return 0
		}

		// Insertion latency = upstream_recv - client_send
		return recvTime.Sub(clientSendTime)
	}

	// Test different body sizes
	sizes := []struct {
		name string
		size int
	}{
		{"Tiny (100B)", 100},
		{"Small (1KB)", 1024},
		{"Medium (10KB)", 10 * 1024},
		{"Large (100KB)", 100 * 1024},
		{"XLarge (1MB)", 1024 * 1024},
	}

	t.Log("")
	t.Log("INSERTION LATENCY (client_send_first_byte → upstream_recv_first_byte)")
	t.Log("")
	t.Logf("%-16s %12s %12s %12s %12s", "Body Size", "Direct", "Plain Proxy", "Tap Proxy", "Tap Overhead")
	t.Logf("%-16s %12s %12s %12s %12s", "---------", "------", "-----------", "---------", "------------")

	for _, sz := range sizes {
		// Warmup
		for range 3 {
			measure(upstreamAddr, sz.size)
			measure(plainAddr, sz.size)
			measure(tapAddr, sz.size)
		}

		samples := 10

		// Measure direct
		var directLat time.Duration
		for range samples {
			directLat += measure(upstreamAddr, sz.size)
		}
		directLat /= time.Duration(samples)

		// Measure plain proxy
		var plainLat time.Duration
		for range samples {
			plainLat += measure(plainAddr, sz.size)
		}
		plainLat /= time.Duration(samples)

		// Measure tap proxy
		var tapLat time.Duration
		for range samples {
			tapLat += measure(tapAddr, sz.size)
		}
		tapLat /= time.Duration(samples)

		tapOverhead := tapLat - plainLat

		t.Logf("%-16s %12s %12s %12s %12s",
			sz.name,
			formatDuration(directLat),
			formatDuration(plainLat),
			formatDuration(tapLat),
			formatDuration(tapOverhead))
	}

	t.Log("")
	t.Log("Direct = No proxy (baseline)")
	t.Log("Plain Proxy = httputil.ReverseProxy without body capture")
	t.Log("Tap Proxy = Our proxy with body capture")
	t.Log("Tap Overhead = Additional latency from body capture (should be ~constant)")
}

// ============ Performance Statistics Test ============

// perfStats holds latency measurements and computed statistics
type perfStats struct {
	samples    []time.Duration
	min        time.Duration
	max        time.Duration
	avg        time.Duration
	p50        time.Duration
	p90        time.Duration
	p99        time.Duration
	throughput float64 // requests/sec
	dataRate   float64 // MB/sec
}

func computeStats(samples []time.Duration, elapsed time.Duration, totalBytes int64) perfStats {
	if len(samples) == 0 {
		return perfStats{}
	}

	// Sort for percentiles
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	slices.Sort(sorted)

	// Compute stats
	var total time.Duration
	for _, s := range sorted {
		total += s
	}

	return perfStats{
		samples:    samples,
		min:        sorted[0],
		max:        sorted[len(sorted)-1],
		avg:        total / time.Duration(len(sorted)),
		p50:        sorted[len(sorted)*50/100],
		p90:        sorted[len(sorted)*90/100],
		p99:        sorted[len(sorted)*99/100],
		throughput: float64(len(samples)) / elapsed.Seconds(),
		dataRate:   float64(totalBytes) / elapsed.Seconds() / 1024 / 1024,
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1000000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(b)/1024/1024)
}

func TestProxy_PerformanceReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// Start upstream
	upstream := newTestUpstream(t)
	go func() { _ = upstream.server.Serve(upstream.listener) }()
	defer func() { _ = upstream.server.Close() }()

	upstreamAddr := upstream.listener.Addr().String()

	// Start proxy
	proxy := startTestProxyTB(t, testProxyOptions{
		name:      "perf",
		upstream:  "http://" + upstreamAddr,
		jsonlOnly: true,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     100,
		},
	}

	// Test scenarios
	scenarios := []struct {
		name        string
		method      string
		bodySize    int
		respSize    int
		concurrency int
		requests    int
	}{
		{"Small GET", "GET", 0, 100, 1, 1000},
		{"Small POST", "POST", 100, 100, 1, 1000},
		{"Medium POST", "POST", 10 * 1024, 10 * 1024, 1, 500},
		{"Large POST", "POST", 100 * 1024, 100 * 1024, 1, 100},
		{"Concurrent Small", "GET", 0, 100, 50, 5000},
		{"Concurrent Medium", "POST", 10 * 1024, 10 * 1024, 50, 2000},
		{"Concurrent Large", "POST", 100 * 1024, 100 * 1024, 20, 500},
	}

	// Collect results
	type result struct {
		name   string
		stats  perfStats
		errors int
		memMB  float64
	}
	var results []result

	// Configure upstream response size dynamically
	upstream.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read request body
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}

		// Get desired response size from header
		respSize := 100
		if sizeStr := r.Header.Get("X-Response-Size"); sizeStr != "" {
			_, _ = fmt.Sscanf(sizeStr, "%d", &respSize)
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(make([]byte, respSize))
	})

	var memBefore, memAfter runtime.MemStats

	for _, sc := range scenarios {
		// Force GC and get baseline memory
		runtime.GC()
		runtime.ReadMemStats(&memBefore)

		latencies := make([]time.Duration, 0, sc.requests)
		var latMu sync.Mutex
		var errorCount int32
		var totalBytes int64

		reqBody := make([]byte, sc.bodySize)
		expectedBytes := int64(sc.requests) * int64(sc.bodySize+sc.respSize)

		startTime := time.Now()

		if sc.concurrency == 1 {
			// Sequential
			for i := 0; i < sc.requests; i++ {
				start := time.Now()
				var req *http.Request
				if sc.method == "GET" {
					req, _ = http.NewRequest("GET", proxyURL+"/perf", nil)
				} else {
					req, _ = http.NewRequest("POST", proxyURL+"/perf", bytes.NewReader(reqBody))
				}
				req.Header.Set("X-Response-Size", fmt.Sprintf("%d", sc.respSize))

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt32(&errorCount, 1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()

				latencies = append(latencies, time.Since(start))
				atomic.AddInt64(&totalBytes, int64(sc.bodySize+sc.respSize))
			}
		} else {
			// Concurrent
			var wg sync.WaitGroup
			sem := make(chan struct{}, sc.concurrency)
			requestsPerWorker := sc.requests / sc.concurrency

			for w := 0; w < sc.concurrency; w++ {
				wg.Go(func() {
					for range requestsPerWorker {
						sem <- struct{}{}

						start := time.Now()
						var req *http.Request
						if sc.method == "GET" {
							req, _ = http.NewRequest("GET", proxyURL+"/perf", nil)
						} else {
							req, _ = http.NewRequest("POST", proxyURL+"/perf", bytes.NewReader(reqBody))
						}
						req.Header.Set("X-Response-Size", fmt.Sprintf("%d", sc.respSize))

						resp, err := client.Do(req)
						if err != nil {
							atomic.AddInt32(&errorCount, 1)
							<-sem
							continue
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()

						lat := time.Since(start)
						latMu.Lock()
						latencies = append(latencies, lat)
						latMu.Unlock()
						atomic.AddInt64(&totalBytes, int64(sc.bodySize+sc.respSize))

						<-sem
					}
				})
			}
			wg.Wait()
		}

		elapsed := time.Since(startTime)

		// Get memory after (use TotalAlloc which is cumulative, doesn't decrease)
		runtime.ReadMemStats(&memAfter)
		memAllocMB := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / 1024 / 1024

		stats := computeStats(latencies, elapsed, totalBytes)
		results = append(results, result{
			name:   sc.name,
			stats:  stats,
			errors: int(errorCount),
			memMB:  memAllocMB,
		})

		// Brief pause between scenarios
		time.Sleep(100 * time.Millisecond)
		_ = expectedBytes // silence unused warning
	}

	// Print results
	t.Log("")
	t.Log("LATENCY")
	t.Logf("%-20s %10s %10s %10s %10s %10s %10s", "Scenario", "Min", "Avg", "P50", "P90", "P99", "Max")
	t.Logf("%-20s %10s %10s %10s %10s %10s %10s", "--------", "---", "---", "---", "---", "---", "---")
	for _, r := range results {
		t.Logf("%-20s %10s %10s %10s %10s %10s %10s",
			r.name,
			formatDuration(r.stats.min),
			formatDuration(r.stats.avg),
			formatDuration(r.stats.p50),
			formatDuration(r.stats.p90),
			formatDuration(r.stats.p99),
			formatDuration(r.stats.max))
	}

	t.Log("")
	t.Log("THROUGHPUT")
	t.Logf("%-20s %12s %12s %8s %10s", "Scenario", "Req/sec", "MB/sec", "Errors", "Mem")
	t.Logf("%-20s %12s %12s %8s %10s", "--------", "-------", "------", "------", "---")
	for _, r := range results {
		t.Logf("%-20s %12.1f %12.1f %8d %10.1f MB",
			r.name,
			r.stats.throughput,
			r.stats.dataRate,
			r.errors,
			r.memMB)
	}

	t.Log("")
	t.Logf("Log file size: %s", formatBytes(getFileSize(proxy.JSONLPath())))
}

func getFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// ============ Path Filtering Tests ============

func TestProxy_PathFilterInclude(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxyWithOptions(t, testProxyOptions{
		upstream:          upstream.URL(),
		includePathsRegex: []string{"^/api/"},
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	// Request to /api/ should be logged
	resp, _ := http.Get(proxyURL + "/api/users")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Request to /other/ should NOT be logged
	resp, _ = http.Get(proxyURL + "/other/path")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Wait for async logging
	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Errorf("expected 1 log entry (only /api/), got %d", len(lines))
	}

	if !bytes.Contains(data, []byte("/api/users")) {
		t.Errorf("expected /api/users in log")
	}
	if bytes.Contains(data, []byte("/other/path")) {
		t.Errorf("did not expect /other/path in log")
	}
}

func TestProxy_PathFilterExclude(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxyWithOptions(t, testProxyOptions{
		upstream:          upstream.URL(),
		excludePathsRegex: []string{"^/health", "^/ready"},
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	// Request to /health should NOT be logged
	resp, _ := http.Get(proxyURL + "/health")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Request to /ready should NOT be logged
	resp, _ = http.Get(proxyURL + "/ready")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Request to /api/ should be logged
	resp, _ = http.Get(proxyURL + "/api/data")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Wait for async logging
	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Errorf("expected 1 log entry (only /api/), got %d", len(lines))
	}

	if bytes.Contains(data, []byte("/health")) {
		t.Errorf("did not expect /health in log")
	}
	if bytes.Contains(data, []byte("/ready")) {
		t.Errorf("did not expect /ready in log")
	}
	if !bytes.Contains(data, []byte("/api/data")) {
		t.Errorf("expected /api/data in log")
	}
}

// ============ Admin Endpoints Tests ============

func TestCreateAdminHandler_Health(t *testing.T) {
	// Create a mock proxy for testing
	proxies := []*Proxy{
		{name: "test-proxy", metrics: &ProxyMetrics{startTime: time.Now()}},
	}
	startTime := time.Now()
	cfg := &Config{HealthPath: "/_health", MetricsPath: "/_metrics"}

	handler := createAdminHandler(proxies, startTime, cfg)

	// Test health endpoint
	req := httptest.NewRequest("GET", "/_health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("health endpoint returned wrong status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"status":"healthy"`) {
		t.Errorf("health endpoint missing status field: %s", body)
	}
	if !strings.Contains(body, `"version"`) {
		t.Errorf("health endpoint missing version field: %s", body)
	}
	if !strings.Contains(body, `"proxies":1`) {
		t.Errorf("health endpoint missing proxies count: %s", body)
	}
}

func TestCreateAdminHandler_Metrics(t *testing.T) {
	// Create mock proxies with some metrics
	proxies := []*Proxy{
		{
			name: "api",
			metrics: &ProxyMetrics{
				startTime: time.Now(),
			},
		},
		{
			name: "web",
			metrics: &ProxyMetrics{
				startTime: time.Now(),
			},
		},
	}
	// Set some metric values
	proxies[0].metrics.RequestsTotal.Store(100)
	proxies[0].metrics.BytesReceived.Store(5000)
	proxies[1].metrics.RequestsTotal.Store(200)
	proxies[1].metrics.ErrorsTotal.Store(5)

	startTime := time.Now()
	cfg := &Config{HealthPath: "/_health", MetricsPath: "/_metrics"}

	handler := createAdminHandler(proxies, startTime, cfg)

	// Test metrics endpoint
	req := httptest.NewRequest("GET", "/_metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("metrics endpoint returned wrong status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()

	// Check for per-route metrics
	if !strings.Contains(body, `http_tap_proxy_requests_total{route="api"} 100`) {
		t.Errorf("metrics missing api requests_total: %s", body)
	}
	if !strings.Contains(body, `http_tap_proxy_requests_total{route="web"} 200`) {
		t.Errorf("metrics missing web requests_total: %s", body)
	}
	if !strings.Contains(body, `http_tap_proxy_errors_total{route="web"} 5`) {
		t.Errorf("metrics missing web errors_total: %s", body)
	}
	if !strings.Contains(body, `http_tap_proxy_bytes_received_total{route="api"} 5000`) {
		t.Errorf("metrics missing api bytes_received: %s", body)
	}
	if !strings.Contains(body, "http_tap_proxy_uptime_seconds") {
		t.Errorf("metrics missing uptime_seconds: %s", body)
	}
}

func TestProxy_AdminNotOnProxyPort(t *testing.T) {
	// This test verifies that /_health on the proxy port goes to upstream, not admin
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxy(t, upstream.URL())
	defer proxy.Close()

	// Request to /_health on proxy port should go to upstream
	resp, err := http.Get(proxy.URL() + "/_health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Should get upstream response, not health endpoint
	if strings.Contains(string(body), `"status":"healthy"`) {
		t.Errorf("/_health should NOT be intercepted on proxy port")
	}
	if !strings.Contains(string(body), "Hello from upstream") {
		t.Errorf("expected upstream response on proxy port, got: %s", body)
	}
}

// ============ Correlation ID Tests ============

func TestProxy_CorrelationID(t *testing.T) {
	upstream := newTestUpstream(t)
	defer upstream.Close()

	proxy := startTestProxyWithOptions(t, testProxyOptions{
		upstream: upstream.URL(),
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	// Test X-Request-ID
	req, _ := http.NewRequest("GET", proxyURL+"/test1", nil)
	req.Header.Set("X-Request-ID", "req-id-123")
	resp, _ := http.DefaultClient.Do(req)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Test X-Correlation-ID
	req, _ = http.NewRequest("GET", proxyURL+"/test2", nil)
	req.Header.Set("X-Correlation-ID", "corr-id-456")
	resp, _ = http.DefaultClient.Do(req)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Test X-Trace-ID
	req, _ = http.NewRequest("GET", proxyURL+"/test3", nil)
	req.Header.Set("X-Trace-ID", "trace-id-789")
	resp, _ = http.DefaultClient.Do(req)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Wait for async logging
	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	if !bytes.Contains(data, []byte(`"correlation_id":"req-id-123"`)) {
		t.Errorf("expected X-Request-ID to be extracted as correlation_id")
	}
	if !bytes.Contains(data, []byte(`"correlation_id":"corr-id-456"`)) {
		t.Errorf("expected X-Correlation-ID to be extracted as correlation_id")
	}
	if !bytes.Contains(data, []byte(`"correlation_id":"trace-id-789"`)) {
		t.Errorf("expected X-Trace-ID to be extracted as correlation_id")
	}
}

// ============ Body Truncation Tests ============

func TestProxy_BodyTruncation(t *testing.T) {
	// Create upstream that echoes large response
	largeResp := bytes.Repeat([]byte("R"), 200*1024) // 200KB
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Request-Size", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write(largeResp)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	upstreamURL := fmt.Sprintf("http://%s", listener.Addr().String())

	// Set max body size to 50KB
	maxBodySize := int64(50 * 1024)
	proxy := startTestProxyWithOptions(t, testProxyOptions{
		upstream:    upstreamURL,
		maxBodySize: maxBodySize,
	})
	defer proxy.Close()

	proxyURL := proxy.URL()

	// Send 100KB request body
	largeReqBody := bytes.Repeat([]byte("X"), 100*1024)
	resp, err := http.Post(proxyURL+"/truncate-test", "application/octet-stream", bytes.NewReader(largeReqBody))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Response should still be complete (proxy doesn't truncate actual traffic)
	if len(respBody) != len(largeResp) {
		t.Errorf("response was truncated: got %d, want %d", len(respBody), len(largeResp))
	}

	// Wait for async logging
	time.Sleep(300 * time.Millisecond)

	// Check log file
	data, err := os.ReadFile(proxy.JSONLPath())
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	// Parse log entry
	var entry map[string]any
	if err := json.Unmarshal(bytes.Split(data, []byte("\n"))[0], &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	// Check request body truncation
	req := entry["request"].(map[string]any)
	if req["body_truncated"] != true {
		t.Errorf("expected request body to be marked as truncated")
	}
	reqBodySize := int64(req["body_size"].(float64))
	if reqBodySize != int64(len(largeReqBody)) {
		t.Errorf("expected body_size to reflect original size: got %d, want %d", reqBodySize, len(largeReqBody))
	}

	// Check response body truncation
	respEntry := entry["response"].(map[string]any)
	if respEntry["body_truncated"] != true {
		t.Errorf("expected response body to be marked as truncated")
	}
	respBodySize := int64(respEntry["body_size"].(float64))
	if respBodySize != int64(len(largeResp)) {
		t.Errorf("expected body_size to reflect original size: got %d, want %d", respBodySize, len(largeResp))
	}

	// Verify logged body is actually truncated
	reqBodyLogged := req["body"].(string)
	if int64(len(reqBodyLogged)) > maxBodySize {
		t.Errorf("logged request body exceeds max size: %d > %d", len(reqBodyLogged), maxBodySize)
	}
}

// ============ WebSocket Helper Functions ============

type testWSFrame struct {
	fin     bool
	opcode  byte
	masked  bool
	maskKey [4]byte
	payload []byte
}

func readWSFrame(r *bufio.Reader) (*testWSFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frame := &testWSFrame{
		fin:    header[0]&0x80 != 0,
		opcode: header[0] & 0x0F,
		masked: header[1]&0x80 != 0,
	}

	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = uint64(ext[0])<<56 | uint64(ext[1])<<48 | uint64(ext[2])<<40 | uint64(ext[3])<<32 |
			uint64(ext[4])<<24 | uint64(ext[5])<<16 | uint64(ext[6])<<8 | uint64(ext[7])
	}

	if frame.masked {
		if _, err := io.ReadFull(r, frame.maskKey[:]); err != nil {
			return nil, err
		}
	}

	frame.payload = make([]byte, length)
	if _, err := io.ReadFull(r, frame.payload); err != nil {
		return nil, err
	}

	return frame, nil
}

func writeWSFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode, 0}

	length := len(payload)
	if length <= 125 {
		header[1] = byte(length)
	} else if length <= 65535 {
		header[1] = 126
		header = append(header, byte(length>>8), byte(length))
	} else {
		header[1] = 127
		header = append(header, make([]byte, 8)...)
		for i := range 8 {
			header[2+i] = byte(length >> (56 - 8*i))
		}
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeWSFrameMasked(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode, 0x80}

	length := len(payload)
	if length <= 125 {
		header[1] |= byte(length)
	} else if length <= 65535 {
		header[1] |= 126
		header = append(header, byte(length>>8), byte(length))
	} else {
		header[1] |= 127
		header = append(header, make([]byte, 8)...)
		for i := range 8 {
			header[2+i] = byte(length >> (56 - 8*i))
		}
	}

	// Random mask key
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}
	header = append(header, maskKey[:]...)

	// Mask payload
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func computeWebSocketAccept(key string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ============ Proxy Config Parsing Tests ============

func TestParseProxyFlag_ValidNames(t *testing.T) {
	validNames := []string{
		"api",
		"web",
		"myAPI",
		"my-api",
		"my_api",
		"api123",
		"API-v2",
		"a",
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			flag := fmt.Sprintf("name=%s,listen_http=:8080,upstream=http://localhost:5000", name)
			pc, err := parseProxyFlag(flag)
			if err != nil {
				t.Errorf("expected valid name %q to be accepted, got error: %v", name, err)
			}
			if pc != nil && pc.Name != name {
				t.Errorf("expected name %q, got %q", name, pc.Name)
			}
		})
	}
}

func TestParseProxyFlag_InvalidNames(t *testing.T) {
	invalidNames := []struct {
		name   string
		reason string
	}{
		{"123api", "starts with number"},
		{"-api", "starts with hyphen"},
		{"_api", "starts with underscore"},
		{"api.v2", "contains dot"},
		{"api/v2", "contains slash"},
		{"api:v2", "contains colon"},
		{"api v2", "contains space"},
		{"api\"test", "contains quote"},
		{"api\ntest", "contains newline"},
	}

	for _, tc := range invalidNames {
		t.Run(tc.reason, func(t *testing.T) {
			flag := fmt.Sprintf("name=%s,listen_http=:8080,upstream=http://localhost:5000", tc.name)
			_, err := parseProxyFlag(flag)
			if err == nil {
				t.Errorf("expected invalid name %q (%s) to be rejected, but it was accepted", tc.name, tc.reason)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid") {
				t.Errorf("expected error to mention 'invalid', got: %v", err)
			}
		})
	}
}

func TestParseProxyFlag_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		wantErr string
	}{
		{
			name:    "missing name",
			flag:    "listen_http=:8080,upstream=http://localhost:5000",
			wantErr: "missing required 'name'",
		},
		{
			name:    "missing upstream",
			flag:    "name=api,listen_http=:8080",
			wantErr: "missing required 'upstream'",
		},
		{
			name:    "missing listen address",
			flag:    "name=api,upstream=http://localhost:5000",
			wantErr: "must have at least one of",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseProxyFlag(tc.flag)
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
