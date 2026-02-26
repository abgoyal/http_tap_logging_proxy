// HTTP Tap Proxy - A transparent logging proxy for HTTP/HTTPS traffic
// Designed to sit between a reverse proxy and upstream application
// Logs all requests/responses without adding latency (tap mode)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Version information
const Version = "1.0.0"

// Configuration holds all CLI parameters
type Config struct {
	ListenHTTP         string
	ListenHTTPS        string
	ListenAdmin        string // Separate port for health/metrics endpoints
	Upstream           string
	LogJSONL           string
	LogSQLite          string
	RotateSize         int64
	RotateInterval     time.Duration
	Retention          int
	S3Bucket           string
	S3Prefix           string
	S3Endpoint         string
	MaxBodySize        int64
	CertFile           string
	KeyFile            string
	AutoCert           bool
	InsecureSkipVerify bool
	PrintSystemd       bool
	ServiceCmd         string
	Verbose            bool
	HealthPath         string
	MetricsPath        string
	ExcludePathsRegex  []string         // Paths to exclude from logging (regex)
	IncludePathsRegex  []string         // If set, only log paths matching these (regex)
	excludePatterns    []*regexp.Regexp // compiled exclude patterns
	includePatterns    []*regexp.Regexp // compiled include patterns
}

// Proxy is the main HTTP tap proxy server
type Proxy struct {
	cfg           *Config
	upstreamURL   *url.URL
	logManager    *LogManager
	httpServer    *http.Server
	httpsServer   *http.Server
	adminServer   *http.Server
	httpListener  net.Listener
	httpsListener net.Listener
	adminListener net.Listener
	handler       http.Handler
	wg            sync.WaitGroup
	mu            sync.Mutex
	metrics       *ProxyMetrics
	sseClient     *http.Client
}

// ProxyMetrics holds runtime metrics for the proxy
type ProxyMetrics struct {
	RequestsTotal      atomic.Int64
	RequestsActive     atomic.Int64
	BytesReceived      atomic.Int64
	BytesSent          atomic.Int64
	ErrorsTotal        atomic.Int64
	WebSocketConns     atomic.Int64
	SSEConns           atomic.Int64
	UpstreamLatencySum atomic.Int64 // microseconds
	UpstreamLatencyCnt atomic.Int64
	LogErrorsTotal     atomic.Int64
	startTime          time.Time
}

// LogEntry represents a logged HTTP transaction
type LogEntry struct {
	ID             string       `json:"id"`
	CorrelationID  string       `json:"correlation_id,omitempty"` // From X-Request-ID or X-Correlation-ID header
	Timestamp      time.Time    `json:"timestamp"`
	DurationMs     int64        `json:"duration_ms"`
	TTFBRequestMs  int64        `json:"ttfb_request_ms,omitempty"`  // Time to first byte of request body received
	TTFBResponseMs int64        `json:"ttfb_response_ms,omitempty"` // Time to first byte of response received
	ClientIP       string       `json:"client_ip"`
	Type           string       `json:"type"`
	Request        *RequestLog  `json:"request,omitempty"`
	Response       *ResponseLog `json:"response,omitempty"`
	Error          string       `json:"error,omitempty"`
}

// RequestLog captures HTTP request details
type RequestLog struct {
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Proto         string              `json:"proto"`
	Host          string              `json:"host"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	BodySize      int64               `json:"body_size"`
	BodyTruncated bool                `json:"body_truncated"`
	BodyBase64    bool                `json:"body_base64,omitempty"`
}

// ResponseLog captures HTTP response details
type ResponseLog struct {
	Status        int                 `json:"status"`
	StatusText    string              `json:"status_text"`
	Proto         string              `json:"proto"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	BodySize      int64               `json:"body_size"`
	BodyTruncated bool                `json:"body_truncated"`
	BodyBase64    bool                `json:"body_base64,omitempty"`
}

// WebSocketFrame represents a single WebSocket frame
type WebSocketFrame struct {
	ID            string    `json:"id"`
	ConnectionID  string    `json:"connection_id"`
	Timestamp     time.Time `json:"timestamp"`
	Type          string    `json:"type"`
	Direction     string    `json:"direction"`
	Opcode        int       `json:"opcode"`
	OpcodeName    string    `json:"opcode_name"`
	Fin           bool      `json:"fin"`
	Payload       string    `json:"payload"`
	PayloadSize   int64     `json:"payload_size"`
	PayloadBase64 bool      `json:"payload_base64,omitempty"`
	Masked        bool      `json:"masked"`
}

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	ID           string    `json:"id"`
	ConnectionID string    `json:"connection_id"`
	Timestamp    time.Time `json:"timestamp"`
	Type         string    `json:"type"`
	Event        string    `json:"event"`
	Data         string    `json:"data"`
	IDField      string    `json:"id_field,omitempty"`
	Retry        *int      `json:"retry,omitempty"`
}

// LogWriter interface for different log outputs
type LogWriter interface {
	Write(entry any) error
	Close() error
	Rotate() error
	Size() int64
}

// JSONLWriter writes entries to JSONL files
type JSONLWriter struct {
	mu           sync.Mutex
	basePath     string
	file         *os.File
	size         int64
	rotateSize   int64
	retention    int
	uploader     *S3Uploader
	listenAddr   string
	upstreamAddr string
}

// SQLiteWriter writes entries to SQLite database
type SQLiteWriter struct {
	mu            sync.Mutex
	basePath      string
	db            *sql.DB
	size          int64
	rotateSize    int64
	retention     int
	uploader      *S3Uploader
	listenAddr    string
	upstreamAddr  string
	stmtHTTP      *sql.Stmt
	stmtWebSocket *sql.Stmt
	stmtSSE       *sql.Stmt
	writeCount    int // Counter for periodic size check
}

// S3Uploader handles uploading files to S3
type S3Uploader struct {
	client *s3.Client
	bucket string
	prefix string
}

// LogManager handles multiple log writers and rotation
type LogManager struct {
	writers        []LogWriter
	rotateInterval time.Duration
	done           chan struct{}
	wg             sync.WaitGroup
	errorCount     atomic.Int64
}

// TapTransport wraps http.RoundTripper to log requests/responses
type TapTransport struct {
	transport   http.RoundTripper
	logManager  *LogManager
	maxBodySize int64
	metrics     *ProxyMetrics
	shouldLog   func(path string) bool
}

// Global config (used only by main for verbose logging)
var cfg *Config

// NewProxy creates a new proxy instance with the given configuration
func NewProxy(c *Config) (*Proxy, error) {
	// Validate configuration
	if c.Upstream == "" {
		return nil, errors.New("upstream URL is required")
	}

	if c.LogJSONL == "" && c.LogSQLite == "" {
		return nil, errors.New("at least one of log-jsonl or log-sqlite is required")
	}

	if c.ListenHTTP == "" && c.ListenHTTPS == "" {
		c.ListenHTTP = ":8080"
	}

	if c.MaxBodySize == 0 {
		c.MaxBodySize = 100 * 1024 * 1024 // Default 100MB
	}

	// Set defaults for health/metrics paths
	if c.HealthPath == "" {
		c.HealthPath = "/_health"
	}
	if c.MetricsPath == "" {
		c.MetricsPath = "/_metrics"
	}

	// Compile path exclusion patterns
	for _, pattern := range c.ExcludePathsRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
		c.excludePatterns = append(c.excludePatterns, re)
	}
	for _, pattern := range c.IncludePathsRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid include pattern %q: %w", pattern, err)
		}
		c.includePatterns = append(c.includePatterns, re)
	}

	// Parse upstream URL
	upstreamURL, err := url.Parse(c.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Initialize S3 uploader if configured
	var s3Uploader *S3Uploader
	if c.S3Bucket != "" {
		s3Uploader, err = newS3Uploader(c.S3Bucket, c.S3Prefix, c.S3Endpoint)
		if err != nil {
			log.Printf("WARNING: S3 upload disabled: %v", err)
		}
	}

	// Initialize log writers
	var writers []LogWriter

	listenAddr := c.ListenHTTP
	if listenAddr == "" {
		listenAddr = c.ListenHTTPS
	}
	upstreamAddr := sanitizeFilename(upstreamURL.Host)

	if c.LogJSONL != "" {
		jsonlWriter, err := newJSONLWriter(c.LogJSONL, c.RotateSize, c.Retention, s3Uploader, listenAddr, upstreamAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create JSONL writer: %w", err)
		}
		writers = append(writers, jsonlWriter)
	}

	if c.LogSQLite != "" {
		sqliteWriter, err := newSQLiteWriter(c.LogSQLite, c.RotateSize, c.Retention, s3Uploader, listenAddr, upstreamAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create SQLite writer: %w", err)
		}
		writers = append(writers, sqliteWriter)
	}

	p := &Proxy{
		cfg:         c,
		upstreamURL: upstreamURL,
		logManager:  newLogManager(writers, c.RotateInterval),
		metrics:     &ProxyMetrics{startTime: time.Now()},
		sseClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 0, // No timeout for SSE
		},
	}

	// Create reverse proxy with this instance's logManager
	proxy := p.createReverseProxy()

	// Create HTTP handler - purely transparent proxy, no intercepted paths
	p.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track active requests
		p.metrics.RequestsTotal.Add(1)
		p.metrics.RequestsActive.Add(1)
		defer p.metrics.RequestsActive.Add(-1)

		if isWebSocketUpgrade(r) {
			p.handleWebSocket(w, r)
			return
		}
		if isSSERequest(r) {
			p.handleSSE(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return p, nil
}

// createAdminHandler creates the handler for the admin endpoint (health/metrics)
func (p *Proxy) createAdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(p.cfg.HealthPath, p.handleHealthCheck)
	mux.HandleFunc(p.cfg.MetricsPath, p.handleMetrics)
	return mux
}

// shouldLogPath returns true if the path should be logged based on include/exclude patterns
// Note: Our own health/metrics endpoints are handled before the proxy and never reach here
func (p *Proxy) shouldLogPath(path string) bool {
	// If include patterns are set, path must match at least one
	if len(p.cfg.includePatterns) > 0 {
		matched := false
		for _, re := range p.cfg.includePatterns {
			if re.MatchString(path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check exclude patterns
	for _, re := range p.cfg.excludePatterns {
		if re.MatchString(path) {
			return false
		}
	}

	return true
}

// handleHealthCheck responds to health check requests
func (p *Proxy) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]any{
		"status":  "healthy",
		"version": Version,
		"uptime":  time.Since(p.metrics.startTime).String(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleMetrics responds with Prometheus-compatible metrics
func (p *Proxy) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	uptimeSeconds := time.Since(p.metrics.startTime).Seconds()
	avgLatencyUs := float64(0)
	if cnt := p.metrics.UpstreamLatencyCnt.Load(); cnt > 0 {
		avgLatencyUs = float64(p.metrics.UpstreamLatencySum.Load()) / float64(cnt)
	}

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_requests_total Total number of HTTP requests\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_requests_total counter\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_requests_total %d\n", p.metrics.RequestsTotal.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_requests_active Current number of active requests\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_requests_active gauge\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_requests_active %d\n", p.metrics.RequestsActive.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_bytes_received_total Total bytes received from clients\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_bytes_received_total counter\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_bytes_received_total %d\n", p.metrics.BytesReceived.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_bytes_sent_total Total bytes sent to clients\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_bytes_sent_total counter\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_bytes_sent_total %d\n", p.metrics.BytesSent.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_errors_total Total number of proxy errors\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_errors_total counter\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_errors_total %d\n", p.metrics.ErrorsTotal.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_websocket_connections_active Active WebSocket connections\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_websocket_connections_active gauge\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_websocket_connections_active %d\n", p.metrics.WebSocketConns.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_sse_connections_active Active SSE connections\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_sse_connections_active gauge\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_sse_connections_active %d\n", p.metrics.SSEConns.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_upstream_latency_avg_microseconds Average upstream latency in microseconds\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_upstream_latency_avg_microseconds gauge\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_upstream_latency_avg_microseconds %.2f\n", avgLatencyUs)

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_log_errors_total Total number of logging errors\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_log_errors_total counter\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_log_errors_total %d\n", p.metrics.LogErrorsTotal.Load())

	_, _ = fmt.Fprintf(w, "# HELP http_tap_proxy_uptime_seconds Proxy uptime in seconds\n")
	_, _ = fmt.Fprintf(w, "# TYPE http_tap_proxy_uptime_seconds gauge\n")
	_, _ = fmt.Fprintf(w, "http_tap_proxy_uptime_seconds %.2f\n", uptimeSeconds)
}

// Start begins listening on configured addresses. Returns when servers are ready.
func (p *Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cfg.ListenHTTP != "" {
		listener, err := net.Listen("tcp", p.cfg.ListenHTTP)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", p.cfg.ListenHTTP, err)
		}
		p.httpListener = listener
		p.httpServer = &http.Server{Handler: p.handler}

		p.wg.Go(func() {
			if err := p.httpServer.Serve(listener); err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		})
	}

	if p.cfg.ListenHTTPS != "" {
		tlsConfig, err := p.getTLSConfig()
		if err != nil {
			return err
		}

		listener, err := tls.Listen("tcp", p.cfg.ListenHTTPS, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", p.cfg.ListenHTTPS, err)
		}
		p.httpsListener = listener
		p.httpsServer = &http.Server{Handler: p.handler, TLSConfig: tlsConfig}

		p.wg.Go(func() {
			if err := p.httpsServer.Serve(listener); err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
			}
		})
	}

	// Start admin server for health/metrics if configured
	if p.cfg.ListenAdmin != "" {
		listener, err := net.Listen("tcp", p.cfg.ListenAdmin)
		if err != nil {
			return fmt.Errorf("failed to listen on admin port %s: %w", p.cfg.ListenAdmin, err)
		}
		p.adminListener = listener
		p.adminServer = &http.Server{Handler: p.createAdminHandler()}

		p.wg.Go(func() {
			if err := p.adminServer.Serve(listener); err != http.ErrServerClosed {
				log.Printf("Admin server error: %v", err)
			}
		})
	}

	return nil
}

// HTTPAddr returns the actual HTTP listen address (useful when using port 0)
func (p *Proxy) HTTPAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpListener != nil {
		return p.httpListener.Addr().String()
	}
	return ""
}

// HTTPSAddr returns the actual HTTPS listen address
func (p *Proxy) HTTPSAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpsListener != nil {
		return p.httpsListener.Addr().String()
	}
	return ""
}

// AdminAddr returns the actual admin listen address
func (p *Proxy) AdminAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.adminListener != nil {
		return p.adminListener.Addr().String()
	}
	return ""
}

// Close gracefully shuts down the proxy
func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if p.httpServer != nil {
		_ = p.httpServer.Shutdown(ctx)
	}
	if p.httpsServer != nil {
		_ = p.httpsServer.Shutdown(ctx)
	}
	if p.adminServer != nil {
		_ = p.adminServer.Shutdown(ctx)
	}

	p.wg.Wait()
	p.logManager.Stop()

	return nil
}

func (p *Proxy) getTLSConfig() (*tls.Config, error) {
	if p.cfg.AutoCert {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	if p.cfg.CertFile != "" && p.cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(p.cfg.CertFile, p.cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	return nil, errors.New("HTTPS requires either --auto-cert or both --cert and --key")
}

func main() {
	cfg = parseFlags()

	// Handle special commands
	if cfg.PrintSystemd {
		printSystemdUnit()
		return
	}

	if cfg.ServiceCmd != "" {
		handleServiceCommand(cfg.ServiceCmd)
		return
	}

	// Create and start proxy
	proxy, err := NewProxy(cfg)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}

	log.Printf("HTTP Tap Proxy v%s started", Version)
	log.Printf("Upstream: %s", cfg.Upstream)
	if cfg.ListenHTTP != "" {
		log.Printf("Listening HTTP: %s", proxy.HTTPAddr())
	}
	if cfg.ListenHTTPS != "" {
		log.Printf("Listening HTTPS: %s", proxy.HTTPSAddr())
	}
	if cfg.ListenAdmin != "" {
		log.Printf("Admin (health/metrics): %s", proxy.AdminAddr())
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	_ = proxy.Close()
	log.Println("Shutdown complete")
}

// multiStringFlag allows specifying a flag multiple times
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenHTTP, "listen-http", "", "HTTP listen address (e.g., :8080)")
	flag.StringVar(&cfg.ListenHTTPS, "listen-https", "", "HTTPS listen address (e.g., :8443)")
	flag.StringVar(&cfg.ListenAdmin, "listen-admin", "", "Admin listen address for health/metrics (e.g., :9090)")
	flag.StringVar(&cfg.Upstream, "upstream", "", "Upstream URL (e.g., http://localhost:5000/api/)")
	flag.StringVar(&cfg.LogJSONL, "log-jsonl", "", "Path for JSONL log file")
	flag.StringVar(&cfg.LogSQLite, "log-sqlite", "", "Path for SQLite log database")

	var rotateSizeStr string
	flag.StringVar(&rotateSizeStr, "rotate-size", "100MB", "Rotate logs when size exceeds (e.g., 100MB, 1GB)")

	var rotateIntervalStr string
	flag.StringVar(&rotateIntervalStr, "rotate-interval", "1h", "Rotate logs at interval (e.g., 1h, 24h)")

	flag.IntVar(&cfg.Retention, "retention", 10, "Number of rotated files to keep")
	flag.StringVar(&cfg.S3Bucket, "s3-bucket", "", "S3 bucket for archival")
	flag.StringVar(&cfg.S3Prefix, "s3-prefix", "", "S3 key prefix for uploads")
	flag.StringVar(&cfg.S3Endpoint, "s3-endpoint", "", "S3-compatible endpoint URL")

	var maxBodySizeStr string
	flag.StringVar(&maxBodySizeStr, "max-body-size", "100MB", "Maximum body size to log")

	flag.StringVar(&cfg.CertFile, "cert", "", "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", "", "TLS key file")
	flag.BoolVar(&cfg.AutoCert, "auto-cert", false, "Generate self-signed certificate")
	flag.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", true, "Skip TLS verification for upstream (default true)")
	flag.BoolVar(&cfg.PrintSystemd, "print-systemd", false, "Print systemd unit file and exit")
	flag.StringVar(&cfg.ServiceCmd, "service", "", "Service command: install, uninstall, start, stop (Windows)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")

	// Health and metrics endpoints
	flag.StringVar(&cfg.HealthPath, "health-path", "/_health", "Path for health check endpoint")
	flag.StringVar(&cfg.MetricsPath, "metrics-path", "/_metrics", "Path for Prometheus metrics endpoint")

	// Path exclusion/inclusion
	var excludePaths multiStringFlag
	var includePaths multiStringFlag
	flag.Var(&excludePaths, "exclude-path", "Regex pattern for paths to exclude from logging (can be specified multiple times)")
	flag.Var(&includePaths, "include-path", "Regex pattern for paths to include in logging; if set, only matching paths are logged (can be specified multiple times)")

	flag.Parse()

	cfg.ExcludePathsRegex = excludePaths
	cfg.IncludePathsRegex = includePaths

	// Parse sizes
	var err error
	cfg.RotateSize, err = parseSize(rotateSizeStr)
	if err != nil {
		log.Fatalf("invalid rotate-size: %v", err)
	}

	cfg.MaxBodySize, err = parseSize(maxBodySizeStr)
	if err != nil {
		log.Fatalf("invalid max-body-size: %v", err)
	}

	cfg.RotateInterval, err = time.ParseDuration(rotateIntervalStr)
	if err != nil {
		log.Fatalf("invalid rotate-interval: %v", err)
	}

	return cfg
}

func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))

	// Order matters: check longer suffixes first to avoid "B" matching "MB"
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"B", 1},
	}

	for _, s2 := range suffixes {
		if before, ok := strings.CutSuffix(s, s2.suffix); ok {
			numStr := before
			var num float64
			_, err := fmt.Sscanf(numStr, "%f", &num)
			if err != nil {
				return 0, err
			}
			return int64(num * float64(s2.mult)), nil
		}
	}

	// Try parsing as plain number (bytes)
	var num int64
	_, err := fmt.Sscanf(s, "%d", &num)
	return num, err
}

func sanitizeFilename(s string) string {
	// Replace characters that are problematic in filenames
	re := regexp.MustCompile(`[^a-zA-Z0-9\-_.]`)
	return re.ReplaceAllString(s, "-")
}

// ==================== JSONL Writer ====================

func newJSONLWriter(basePath string, rotateSize int64, retention int, uploader *S3Uploader, listenAddr, upstreamAddr string) (*JSONLWriter, error) {
	dir := filepath.Dir(basePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	w := &JSONLWriter{
		basePath:     basePath,
		rotateSize:   rotateSize,
		retention:    retention,
		uploader:     uploader,
		listenAddr:   sanitizeFilename(listenAddr),
		upstreamAddr: upstreamAddr,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *JSONLWriter) openFile() error {
	f, err := os.OpenFile(w.basePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	w.file = f

	// Get current size
	info, err := f.Stat()
	if err != nil {
		return err
	}
	w.size = info.Size()

	return nil
}

func (w *JSONLWriter) Write(entry any) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return fmt.Errorf("file is nil")
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	data = append(data, '\n')

	n, err := w.file.Write(data)
	if err != nil {
		return fmt.Errorf("file write: %w", err)
	}
	w.size += int64(n)

	// Check if rotation needed
	if w.rotateSize > 0 && w.size >= w.rotateSize {
		return w.rotateInternal()
	}

	return nil
}

func (w *JSONLWriter) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

func (w *JSONLWriter) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rotateInternal()
}

func (w *JSONLWriter) rotateInternal() error {
	if w.file == nil {
		return nil
	}

	// Close current file
	if err := w.file.Close(); err != nil {
		return err
	}

	// Generate rotated filename
	timestamp := time.Now().Format("20060102_150405")
	ext := filepath.Ext(w.basePath)
	base := strings.TrimSuffix(w.basePath, ext)
	rotatedPath := fmt.Sprintf("%s_%s_%s_%s%s", base, timestamp, w.listenAddr, w.upstreamAddr, ext)

	// Rename current file
	if err := os.Rename(w.basePath, rotatedPath); err != nil {
		// If rename fails, try to reopen original
		_ = w.openFile()
		return err
	}

	// Upload to S3 if configured, delete file after successful upload
	if w.uploader != nil {
		go func() {
			if err := w.uploader.Upload(rotatedPath); err != nil {
				log.Printf("S3 upload failed for %s: %v (file retained for retry)", rotatedPath, err)
			} else {
				// Successfully uploaded, delete local file
				if err := os.Remove(rotatedPath); err != nil {
					log.Printf("failed to delete uploaded file %s: %v", rotatedPath, err)
				}
			}
		}()
	} else {
		// No S3 configured - enforce local retention
		w.enforceRetention()
	}

	// Open new file
	w.size = 0
	return w.openFile()
}

func (w *JSONLWriter) enforceRetention() {
	pattern := strings.TrimSuffix(w.basePath, filepath.Ext(w.basePath)) + "_*" + filepath.Ext(w.basePath)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("retention glob error: %v", err)
		return
	}

	if len(matches) <= w.retention {
		return
	}

	// Sort by modification time (oldest first)
	sort.Slice(matches, func(i, j int) bool {
		infoI, _ := os.Stat(matches[i])
		infoJ, _ := os.Stat(matches[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// Delete oldest files
	toDelete := len(matches) - w.retention
	for i := range toDelete {
		if err := os.Remove(matches[i]); err != nil {
			log.Printf("failed to delete old log file %s: %v", matches[i], err)
		}
	}
}

func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// ==================== SQLite Writer ====================

func newSQLiteWriter(basePath string, rotateSize int64, retention int, uploader *S3Uploader, listenAddr, upstreamAddr string) (*SQLiteWriter, error) {
	dir := filepath.Dir(basePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	w := &SQLiteWriter{
		basePath:     basePath,
		rotateSize:   rotateSize,
		retention:    retention,
		uploader:     uploader,
		listenAddr:   sanitizeFilename(listenAddr),
		upstreamAddr: upstreamAddr,
	}

	if err := w.openDB(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *SQLiteWriter) openDB() error {
	db, err := sql.Open("sqlite", w.basePath+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return err
	}

	// Create schema with proper tables for each entry type
	schema := `
		-- HTTP request/response entries
		CREATE TABLE IF NOT EXISTS http_entries (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			duration_ms INTEGER,
			client_ip TEXT,
			error TEXT,

			-- Request fields
			req_method TEXT,
			req_url TEXT,
			req_proto TEXT,
			req_host TEXT,
			req_headers TEXT,
			req_body BLOB,
			req_body_size INTEGER,
			req_body_truncated INTEGER,

			-- Request common headers (extracted for easy querying)
			req_content_type TEXT,
			req_content_length INTEGER,
			req_authorization TEXT,
			req_cookie TEXT,
			req_user_agent TEXT,
			req_accept TEXT,
			req_accept_encoding TEXT,
			req_referer TEXT,
			req_origin TEXT,
			req_x_forwarded_for TEXT,
			req_x_request_id TEXT,

			-- Response fields
			resp_status INTEGER,
			resp_status_text TEXT,
			resp_proto TEXT,
			resp_headers TEXT,
			resp_body BLOB,
			resp_body_size INTEGER,
			resp_body_truncated INTEGER,

			-- Response common headers (extracted for easy querying)
			resp_content_type TEXT,
			resp_content_length INTEGER,
			resp_content_encoding TEXT,
			resp_set_cookie TEXT,
			resp_location TEXT,
			resp_cache_control TEXT,
			resp_etag TEXT,
			resp_last_modified TEXT,
			resp_www_authenticate TEXT,
			resp_x_request_id TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_entries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_http_method ON http_entries(req_method);
		CREATE INDEX IF NOT EXISTS idx_http_status ON http_entries(resp_status);
		CREATE INDEX IF NOT EXISTS idx_http_url ON http_entries(req_url);
		CREATE INDEX IF NOT EXISTS idx_http_content_type ON http_entries(resp_content_type);

		-- WebSocket frame entries
		CREATE TABLE IF NOT EXISTS websocket_frames (
			id TEXT PRIMARY KEY,
			connection_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			direction TEXT,
			opcode INTEGER,
			opcode_name TEXT,
			fin INTEGER,
			masked INTEGER,
			payload BLOB,
			payload_size INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_ws_timestamp ON websocket_frames(timestamp);
		CREATE INDEX IF NOT EXISTS idx_ws_connection ON websocket_frames(connection_id);
		CREATE INDEX IF NOT EXISTS idx_ws_opcode ON websocket_frames(opcode);

		-- SSE event entries
		CREATE TABLE IF NOT EXISTS sse_events (
			id TEXT PRIMARY KEY,
			connection_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			event_type TEXT,
			data TEXT,
			event_id TEXT,
			retry INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_sse_timestamp ON sse_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_sse_connection ON sse_events(connection_id);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return err
	}

	// Prepare insert statements for each table
	stmtHTTP, err := db.Prepare(`INSERT INTO http_entries (
		id, timestamp, duration_ms, client_ip, error,
		req_method, req_url, req_proto, req_host, req_headers, req_body, req_body_size, req_body_truncated,
		req_content_type, req_content_length, req_authorization, req_cookie, req_user_agent,
		req_accept, req_accept_encoding, req_referer, req_origin, req_x_forwarded_for, req_x_request_id,
		resp_status, resp_status_text, resp_proto, resp_headers, resp_body, resp_body_size, resp_body_truncated,
		resp_content_type, resp_content_length, resp_content_encoding, resp_set_cookie, resp_location,
		resp_cache_control, resp_etag, resp_last_modified, resp_www_authenticate, resp_x_request_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = db.Close()
		return err
	}

	stmtWS, err := db.Prepare(`INSERT INTO websocket_frames (
		id, connection_id, timestamp, direction, opcode, opcode_name, fin, masked, payload, payload_size
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = db.Close()
		return err
	}

	stmtSSE, err := db.Prepare(`INSERT INTO sse_events (
		id, connection_id, timestamp, event_type, data, event_id, retry
	) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = db.Close()
		return err
	}

	w.db = db
	w.stmtHTTP = stmtHTTP
	w.stmtWebSocket = stmtWS
	w.stmtSSE = stmtSSE

	// Get current size
	info, err := os.Stat(w.basePath)
	if err == nil {
		w.size = info.Size()
	}

	return nil
}

func (w *SQLiteWriter) Write(entry any) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	var dataSize int64

	switch e := entry.(type) {
	case *LogEntry:
		dataSize, err = w.writeHTTPEntry(e)
	case *WebSocketFrame:
		dataSize, err = w.writeWebSocketFrame(e)
	case *SSEEvent:
		dataSize, err = w.writeSSEEvent(e)
	default:
		return fmt.Errorf("unknown entry type: %T", entry)
	}

	if err != nil {
		return err
	}

	w.writeCount++

	// Check actual file size every 100 writes for accuracy
	if w.writeCount%100 == 0 {
		if info, statErr := os.Stat(w.basePath); statErr == nil {
			w.size = info.Size()
		}
	} else {
		// Estimate based on data written
		w.size += dataSize + 100 // Approximate overhead per row
	}

	// Check if rotation needed
	if w.rotateSize > 0 && w.size >= w.rotateSize {
		return w.rotateInternal()
	}

	return nil
}

// getHeader returns the first value for a header, or empty string
func getHeader(headers map[string][]string, key string) string {
	if v := headers[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// getHeaderInt returns the first value as int, or nil if not present/invalid
func getHeaderInt(headers map[string][]string, key string) *int64 {
	if v := headers[key]; len(v) > 0 {
		var n int64
		if _, err := fmt.Sscanf(v[0], "%d", &n); err == nil {
			return &n
		}
	}
	return nil
}

func (w *SQLiteWriter) writeHTTPEntry(e *LogEntry) (int64, error) {
	var reqMethod, reqURL, reqProto, reqHost, reqHeaders string
	var reqBody []byte
	var reqBodySize int64
	var reqBodyTruncated int

	// Request common headers
	var reqContentType, reqAuthorization, reqCookie, reqUserAgent string
	var reqAccept, reqAcceptEncoding, reqReferer, reqOrigin string
	var reqXForwardedFor, reqXRequestID string
	var reqContentLength *int64

	if e.Request != nil {
		reqMethod = e.Request.Method
		reqURL = e.Request.URL
		reqProto = e.Request.Proto
		reqHost = e.Request.Host
		if h, err := json.Marshal(e.Request.Headers); err == nil {
			reqHeaders = string(h)
		}
		// Store raw body bytes - decode base64 if needed
		if e.Request.BodyBase64 {
			reqBody, _ = base64.StdEncoding.DecodeString(e.Request.Body)
		} else {
			reqBody = []byte(e.Request.Body)
		}
		reqBodySize = e.Request.BodySize
		if e.Request.BodyTruncated {
			reqBodyTruncated = 1
		}

		// Extract common request headers
		h := e.Request.Headers
		reqContentType = getHeader(h, "Content-Type")
		reqContentLength = getHeaderInt(h, "Content-Length")
		reqAuthorization = getHeader(h, "Authorization")
		reqCookie = getHeader(h, "Cookie")
		reqUserAgent = getHeader(h, "User-Agent")
		reqAccept = getHeader(h, "Accept")
		reqAcceptEncoding = getHeader(h, "Accept-Encoding")
		reqReferer = getHeader(h, "Referer")
		reqOrigin = getHeader(h, "Origin")
		reqXForwardedFor = getHeader(h, "X-Forwarded-For")
		reqXRequestID = getHeader(h, "X-Request-Id")
		if reqXRequestID == "" {
			reqXRequestID = getHeader(h, "X-Request-ID")
		}
	}

	var respStatus int
	var respStatusText, respProto, respHeaders string
	var respBody []byte
	var respBodySize int64
	var respBodyTruncated int

	// Response common headers
	var respContentType, respContentEncoding, respSetCookie, respLocation string
	var respCacheControl, respEtag, respLastModified, respWWWAuth, respXRequestID string
	var respContentLength *int64

	if e.Response != nil {
		respStatus = e.Response.Status
		respStatusText = e.Response.StatusText
		respProto = e.Response.Proto
		if h, err := json.Marshal(e.Response.Headers); err == nil {
			respHeaders = string(h)
		}
		// Store raw body bytes
		if e.Response.BodyBase64 {
			respBody, _ = base64.StdEncoding.DecodeString(e.Response.Body)
		} else {
			respBody = []byte(e.Response.Body)
		}
		respBodySize = e.Response.BodySize
		if e.Response.BodyTruncated {
			respBodyTruncated = 1
		}

		// Extract common response headers
		h := e.Response.Headers
		respContentType = getHeader(h, "Content-Type")
		respContentLength = getHeaderInt(h, "Content-Length")
		respContentEncoding = getHeader(h, "Content-Encoding")
		respSetCookie = getHeader(h, "Set-Cookie")
		respLocation = getHeader(h, "Location")
		respCacheControl = getHeader(h, "Cache-Control")
		respEtag = getHeader(h, "Etag")
		if respEtag == "" {
			respEtag = getHeader(h, "ETag")
		}
		respLastModified = getHeader(h, "Last-Modified")
		respWWWAuth = getHeader(h, "Www-Authenticate")
		if respWWWAuth == "" {
			respWWWAuth = getHeader(h, "WWW-Authenticate")
		}
		respXRequestID = getHeader(h, "X-Request-Id")
		if respXRequestID == "" {
			respXRequestID = getHeader(h, "X-Request-ID")
		}
	}

	_, err := w.stmtHTTP.Exec(
		e.ID, e.Timestamp.Format(time.RFC3339Nano), e.DurationMs, e.ClientIP, e.Error,
		reqMethod, reqURL, reqProto, reqHost, reqHeaders, reqBody, reqBodySize, reqBodyTruncated,
		reqContentType, reqContentLength, reqAuthorization, reqCookie, reqUserAgent,
		reqAccept, reqAcceptEncoding, reqReferer, reqOrigin, reqXForwardedFor, reqXRequestID,
		respStatus, respStatusText, respProto, respHeaders, respBody, respBodySize, respBodyTruncated,
		respContentType, respContentLength, respContentEncoding, respSetCookie, respLocation,
		respCacheControl, respEtag, respLastModified, respWWWAuth, respXRequestID,
	)

	return reqBodySize + respBodySize, err
}

func (w *SQLiteWriter) writeWebSocketFrame(e *WebSocketFrame) (int64, error) {
	var payload []byte
	if e.PayloadBase64 {
		payload, _ = base64.StdEncoding.DecodeString(e.Payload)
	} else {
		payload = []byte(e.Payload)
	}

	var fin, masked int
	if e.Fin {
		fin = 1
	}
	if e.Masked {
		masked = 1
	}

	_, err := w.stmtWebSocket.Exec(
		e.ID, e.ConnectionID, e.Timestamp.Format(time.RFC3339Nano),
		e.Direction, e.Opcode, e.OpcodeName, fin, masked, payload, e.PayloadSize,
	)

	return e.PayloadSize, err
}

func (w *SQLiteWriter) writeSSEEvent(e *SSEEvent) (int64, error) {
	_, err := w.stmtSSE.Exec(
		e.ID, e.ConnectionID, e.Timestamp.Format(time.RFC3339Nano),
		e.Event, e.Data, e.IDField, e.Retry,
	)

	return int64(len(e.Data)), err
}

func (w *SQLiteWriter) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

func (w *SQLiteWriter) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rotateInternal()
}

func (w *SQLiteWriter) rotateInternal() error {
	if w.db == nil {
		return nil
	}

	// Close current database and statements
	if w.stmtHTTP != nil {
		_ = w.stmtHTTP.Close()
	}
	if w.stmtWebSocket != nil {
		_ = w.stmtWebSocket.Close()
	}
	if w.stmtSSE != nil {
		_ = w.stmtSSE.Close()
	}
	if err := w.db.Close(); err != nil {
		return err
	}

	// Generate rotated filename
	timestamp := time.Now().Format("20060102_150405")
	ext := filepath.Ext(w.basePath)
	base := strings.TrimSuffix(w.basePath, ext)
	rotatedPath := fmt.Sprintf("%s_%s_%s_%s%s", base, timestamp, w.listenAddr, w.upstreamAddr, ext)

	// Rename current file (and WAL/SHM files)
	if err := os.Rename(w.basePath, rotatedPath); err != nil {
		_ = w.openDB()
		return err
	}
	_ = os.Remove(w.basePath + "-wal")
	_ = os.Remove(w.basePath + "-shm")

	// Upload to S3 if configured, delete file after successful upload
	if w.uploader != nil {
		go func() {
			if err := w.uploader.Upload(rotatedPath); err != nil {
				log.Printf("S3 upload failed for %s: %v (file retained for retry)", rotatedPath, err)
			} else {
				// Successfully uploaded, delete local file
				if err := os.Remove(rotatedPath); err != nil {
					log.Printf("failed to delete uploaded file %s: %v", rotatedPath, err)
				}
			}
		}()
	} else {
		// No S3 configured - enforce local retention
		w.enforceRetention()
	}

	// Open new database
	w.size = 0
	return w.openDB()
}

func (w *SQLiteWriter) enforceRetention() {
	pattern := strings.TrimSuffix(w.basePath, filepath.Ext(w.basePath)) + "_*" + filepath.Ext(w.basePath)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("retention glob error: %v", err)
		return
	}

	if len(matches) <= w.retention {
		return
	}

	// Sort by modification time (oldest first)
	sort.Slice(matches, func(i, j int) bool {
		infoI, _ := os.Stat(matches[i])
		infoJ, _ := os.Stat(matches[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// Delete oldest files
	toDelete := len(matches) - w.retention
	for i := range toDelete {
		if err := os.Remove(matches[i]); err != nil {
			log.Printf("failed to delete old db file %s: %v", matches[i], err)
		}
	}
}

func (w *SQLiteWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stmtHTTP != nil {
		_ = w.stmtHTTP.Close()
	}
	if w.stmtWebSocket != nil {
		_ = w.stmtWebSocket.Close()
	}
	if w.stmtSSE != nil {
		_ = w.stmtSSE.Close()
	}
	if w.db != nil {
		return w.db.Close()
	}
	return nil
}

// ==================== S3 Uploader ====================

func newS3Uploader(bucket, prefix, endpoint string) (*S3Uploader, error) {
	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
	})

	return &S3Uploader{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}, nil
}

func (u *S3Uploader) Upload(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	key := u.prefix + filepath.Base(filePath)

	_, err = u.client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
		Body:   f,
	})

	if err != nil {
		return fmt.Errorf("S3 upload failed: %w", err)
	}

	log.Printf("Uploaded to S3: s3://%s/%s", u.bucket, key)
	return nil
}

// ==================== Log Manager ====================

func newLogManager(writers []LogWriter, rotateInterval time.Duration) *LogManager {
	lm := &LogManager{
		writers:        writers,
		rotateInterval: rotateInterval,
		done:           make(chan struct{}),
	}

	// Start rotation timer
	if rotateInterval > 0 {
		lm.wg.Add(1)
		go lm.rotationLoop()
	}

	return lm
}

func (lm *LogManager) rotationLoop() {
	defer lm.wg.Done()
	ticker := time.NewTicker(lm.rotateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, w := range lm.writers {
				if err := w.Rotate(); err != nil {
					log.Printf("rotation error: %v", err)
				}
			}
		case <-lm.done:
			return
		}
	}
}

func (lm *LogManager) Log(entry any) {
	// Fire and forget - logging errors should never affect proxy
	go func() {
		defer func() {
			if r := recover(); r != nil {
				lm.errorCount.Add(1)
				log.Printf("logging panic recovered: %v", r)
			}
		}()

		for _, w := range lm.writers {
			if err := w.Write(entry); err != nil {
				lm.errorCount.Add(1)
				log.Printf("log write error: %v", err)
			}
		}
	}()
}

func (lm *LogManager) Stop() {
	close(lm.done)
	lm.wg.Wait()

	for _, w := range lm.writers {
		if err := w.Close(); err != nil {
			log.Printf("error closing log writer: %v", err)
		}
	}
}

// ==================== Tap Transport ====================

func newTapTransport(maxBodySize int64, logManager *LogManager, metrics *ProxyMetrics, insecureSkipVerify bool, shouldLog func(string) bool) *TapTransport {
	return &TapTransport{
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		},
		logManager:  logManager,
		maxBodySize: maxBodySize,
		metrics:     metrics,
		shouldLog:   shouldLog,
	}
}

// asyncBodyCapture captures body data while streaming without blocking
// The key optimization: Read() returns immediately after reading from source,
// buffer writes happen via io.TeeReader but buffer is pre-allocated
type asyncBodyCapture struct {
	reader        io.ReadCloser
	buffer        *bytes.Buffer
	teeReader     io.Reader
	maxSize       int64
	truncated     bool
	totalRead     int64 // Total bytes actually read (may exceed buffer size)
	firstByteTime time.Time
	firstByteOnce sync.Once
	startTime     time.Time
}

func newAsyncBodyCapture(r io.ReadCloser, maxSize int64, sizeHint int64, startTime time.Time) *asyncBodyCapture {
	buf := new(bytes.Buffer)
	if sizeHint > 0 {
		allocSize := min(sizeHint, maxSize)
		buf.Grow(int(allocSize))
	}
	a := &asyncBodyCapture{
		reader:    r,
		buffer:    buf,
		maxSize:   maxSize,
		startTime: startTime,
	}
	// Use limitWriter to cap buffer size
	a.teeReader = io.TeeReader(r, &limitWriter{w: buf, limit: maxSize, captured: &a.truncated})
	return a
}

func (a *asyncBodyCapture) Read(p []byte) (int, error) {
	n, err := a.teeReader.Read(p)
	if n > 0 {
		a.totalRead += int64(n)
		a.firstByteOnce.Do(func() {
			a.firstByteTime = time.Now()
		})
	}
	return n, err
}

func (a *asyncBodyCapture) Close() error {
	return a.reader.Close()
}

func (a *asyncBodyCapture) Bytes() []byte {
	return a.buffer.Bytes()
}

// TotalRead returns the total bytes read from the source (may exceed buffer size)
func (a *asyncBodyCapture) TotalRead() int64 {
	return a.totalRead
}

// Truncated returns true if the captured body was truncated
func (a *asyncBodyCapture) Truncated() bool {
	return a.truncated
}

// TTFBMs returns time to first byte in milliseconds (0 if no bytes read)
func (a *asyncBodyCapture) TTFBMs() int64 {
	if a.firstByteTime.IsZero() {
		return 0
	}
	return a.firstByteTime.Sub(a.startTime).Milliseconds()
}

// limitWriter writes up to limit bytes, then discards the rest
type limitWriter struct {
	w        *bytes.Buffer
	limit    int64
	written  int64
	captured *bool
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.written >= l.limit {
		*l.captured = true
		return len(p), nil // discard but report success
	}
	remaining := l.limit - l.written
	if int64(len(p)) > remaining {
		p = p[:remaining]
		*l.captured = true
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return len(p), err // report full length to TeeReader
}

func (tt *TapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	startTime := time.Now()

	// Check if we should log this path
	shouldLog := tt.shouldLog == nil || tt.shouldLog(req.URL.Path)

	// Extract correlation ID from common headers
	correlationID := req.Header.Get("X-Request-ID")
	if correlationID == "" {
		correlationID = req.Header.Get("X-Correlation-ID")
	}
	if correlationID == "" {
		correlationID = req.Header.Get("X-Trace-ID")
	}

	var entry *LogEntry
	var reqCapture *asyncBodyCapture

	if shouldLog {
		entry = &LogEntry{
			ID:            uuid.New().String(),
			CorrelationID: correlationID,
			Timestamp:     startTime,
			Type:          "http",
			ClientIP:      req.RemoteAddr,
		}

		// Capture request body using async pipe - body flows to upstream while we capture in parallel
		if req.Body != nil && req.ContentLength != 0 {
			reqCapture = newAsyncBodyCapture(req.Body, tt.maxBodySize, req.ContentLength, startTime)
			req.Body = reqCapture
		}

		entry.Request = &RequestLog{
			Method:  req.Method,
			URL:     req.URL.String(),
			Proto:   req.Proto,
			Host:    req.Host,
			Headers: cloneHeaders(req.Header),
		}
	}

	// Execute request
	resp, err := tt.transport.RoundTrip(req)
	duration := time.Since(startTime)

	// Update metrics
	if tt.metrics != nil {
		tt.metrics.UpstreamLatencySum.Add(duration.Microseconds())
		tt.metrics.UpstreamLatencyCnt.Add(1)
		if err != nil {
			tt.metrics.ErrorsTotal.Add(1)
		}
	}

	if !shouldLog {
		return resp, err
	}

	entry.DurationMs = duration.Milliseconds()

	// Capture request body after it's been read
	if reqCapture != nil {
		reqBytes := reqCapture.Bytes()
		entry.Request.Body, entry.Request.BodyBase64 = encodeBody(reqBytes)
		entry.Request.BodySize = reqCapture.TotalRead() // Original size, not truncated
		entry.Request.BodyTruncated = reqCapture.Truncated()
		entry.TTFBRequestMs = reqCapture.TTFBMs()

		if tt.metrics != nil {
			tt.metrics.BytesReceived.Add(reqCapture.TotalRead())
		}
	}

	if err != nil {
		entry.Error = err.Error()
		tt.logManager.Log(entry)
		return nil, err
	}

	// Response TTFB is measured from request start to first byte of response headers
	entry.TTFBResponseMs = duration.Milliseconds()

	// Capture response
	entry.Response = &ResponseLog{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		Proto:      resp.Proto,
		Headers:    cloneHeaders(resp.Header),
	}

	// Wrap response body with async capture
	if resp.Body != nil {
		respCapture := newAsyncBodyCapture(resp.Body, tt.maxBodySize, resp.ContentLength, startTime)
		resp.Body = &asyncResponseBody{
			asyncBodyCapture: respCapture,
			entry:            entry,
			logManager:       tt.logManager,
			metrics:          tt.metrics,
		}
	} else {
		// No response body, log immediately
		tt.logManager.Log(entry)
	}

	return resp, nil
}

// asyncResponseBody wraps response body to log after fully read
type asyncResponseBody struct {
	*asyncBodyCapture
	entry      *LogEntry
	logManager *LogManager
	metrics    *ProxyMetrics
	logOnce    sync.Once
}

func (a *asyncResponseBody) Close() error {
	err := a.asyncBodyCapture.Close()
	a.logOnce.Do(func() {
		respBytes := a.Bytes()
		a.entry.Response.Body, a.entry.Response.BodyBase64 = encodeBody(respBytes)
		a.entry.Response.BodySize = a.TotalRead() // Original size, not truncated
		a.entry.Response.BodyTruncated = a.Truncated()
		a.logManager.Log(a.entry)

		if a.metrics != nil {
			a.metrics.BytesSent.Add(a.TotalRead())
		}
	})
	return err
}

// isConnectionReset checks if an error is a connection reset (expected on close)
func isConnectionReset(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection reset")
}

// encodeBody returns the body as a string, base64-encoding if binary
func encodeBody(data []byte) (body string, isBase64 bool) {
	if len(data) == 0 {
		return "", false
	}
	// Check if valid UTF-8 and doesn't contain control chars (except common ones)
	if utf8.Valid(data) && !containsBinaryChars(data) {
		return string(data), false
	}
	// Binary data - base64 encode
	return base64.StdEncoding.EncodeToString(data), true
}

// containsBinaryChars checks for control characters that suggest binary data
func containsBinaryChars(data []byte) bool {
	for _, b := range data {
		// Allow tab, newline, carriage return
		if b < 32 && b != 9 && b != 10 && b != 13 {
			return true
		}
	}
	return false
}

func cloneHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string)
	for k, v := range h {
		clone[k] = append([]string(nil), v...)
	}
	return clone
}

// ==================== Reverse Proxy ====================

func (p *Proxy) createReverseProxy() *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		// Use our tap transport
		Transport: newTapTransport(p.cfg.MaxBodySize, p.logManager, p.metrics, p.cfg.InsecureSkipVerify, p.shouldLogPath),

		// Rewrite modifies the request (replaces deprecated Director)
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(p.upstreamURL)
			pr.SetXForwarded()
			// Preserve original host header
			if pr.Out.Header.Get("X-Forwarded-Host") == "" {
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
		},
	}

	// Error handler - ensure we don't break client connection
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		// Return 502 Bad Gateway but don't panic
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway"))
	}

	// Modify response (optional processing)
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Don't modify anything - we're transparent
		return nil
	}

	return proxy
}

// ==================== WebSocket Handler ====================

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	connID := uuid.New().String()
	p.metrics.WebSocketConns.Add(1)
	defer p.metrics.WebSocketConns.Add(-1)

	shouldLog := p.shouldLogPath(r.URL.Path)

	// Connect to upstream
	upstreamScheme := "ws"
	if p.upstreamURL.Scheme == "https" {
		upstreamScheme = "wss"
	}

	upstreamURL := *p.upstreamURL
	upstreamURL.Scheme = upstreamScheme
	upstreamURL.Path = singleJoiningSlash(p.upstreamURL.Path, r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	// Create upstream connection
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	var upstreamConn net.Conn
	var err error

	if upstreamScheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", upstreamURL.Host, &tls.Config{InsecureSkipVerify: p.cfg.InsecureSkipVerify})
	} else {
		upstreamConn, err = dialer.Dial("tcp", upstreamURL.Host)
	}

	if err != nil {
		log.Printf("WebSocket upstream dial error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		p.metrics.ErrorsTotal.Add(1)
		return
	}

	// Send upgrade request to upstream
	var upgradeReq strings.Builder
	_, _ = fmt.Fprintf(&upgradeReq, "GET %s HTTP/1.1\r\n", upstreamURL.RequestURI())
	_, _ = fmt.Fprintf(&upgradeReq, "Host: %s\r\n", upstreamURL.Host)

	// Forward relevant headers
	for _, hdr := range []string{"Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		if v := r.Header.Get(hdr); v != "" {
			_, _ = fmt.Fprintf(&upgradeReq, "%s: %s\r\n", hdr, v)
		}
	}
	upgradeReq.WriteString("\r\n")

	if _, err := upstreamConn.Write([]byte(upgradeReq.String())); err != nil {
		log.Printf("WebSocket upstream write error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		_ = upstreamConn.Close()
		p.metrics.ErrorsTotal.Add(1)
		return
	}

	// Read upstream response
	upstreamReader := bufio.NewReader(upstreamConn)
	upstreamResp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		log.Printf("WebSocket upstream response error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		_ = upstreamConn.Close()
		p.metrics.ErrorsTotal.Add(1)
		return
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("WebSocket upstream refused upgrade: %d", upstreamResp.StatusCode)
		w.WriteHeader(upstreamResp.StatusCode)
		_ = upstreamConn.Close()
		return
	}

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("WebSocket hijack not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		_ = upstreamConn.Close()
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("WebSocket hijack error: %v", err)
		_ = upstreamConn.Close()
		return
	}

	// Send upgrade response to client
	respLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", upstreamResp.StatusCode, upstreamResp.Status)
	_, _ = clientConn.Write([]byte(respLine))
	_ = upstreamResp.Header.Write(clientConn)
	_, _ = clientConn.Write([]byte("\r\n"))

	// Create a done channel to coordinate shutdown when either side closes
	done := make(chan struct{})
	var closeOnce sync.Once
	closeConns := func() {
		closeOnce.Do(func() {
			close(done)
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}

	// Bidirectional frame relay with logging
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream
	wg.Go(func() {
		relayWebSocketFrames(clientBuf, upstreamConn, connID, "client_to_server", true, p.logManager, p.cfg.MaxBodySize, shouldLog, done)
		closeConns() // Close both when this direction ends
	})

	// Upstream -> Client
	wg.Go(func() {
		relayWebSocketFrames(upstreamReader, clientConn, connID, "server_to_client", false, p.logManager, p.cfg.MaxBodySize, shouldLog, done)
		closeConns() // Close both when this direction ends
	})

	wg.Wait()
}

func relayWebSocketFrames(src io.Reader, dst io.Writer, connID, direction string, clientFrames bool, lm *LogManager, maxBodySize int64, shouldLog bool, done <-chan struct{}) {
	for {
		// Check if we should stop
		select {
		case <-done:
			return
		default:
		}

		frame, payload, err := readWebSocketFrame(src, clientFrames, maxBodySize)
		if err != nil {
			// Silently ignore expected connection close errors
			if err != io.EOF && !errors.Is(err, net.ErrClosed) && !isConnectionReset(err) {
				// Also check if done channel is closed (peer closed)
				select {
				case <-done:
					return
				default:
					log.Printf("WebSocket read error: %v", err)
				}
			}
			return
		}

		// Log the frame if logging is enabled for this path
		if shouldLog {
			payloadStr, payloadBase64 := encodeBody(payload)
			logFrame := &WebSocketFrame{
				ID:            uuid.New().String(),
				ConnectionID:  connID,
				Timestamp:     time.Now(),
				Type:          "websocket_frame",
				Direction:     direction,
				Opcode:        int(frame.opcode),
				OpcodeName:    wsOpcodeName(frame.opcode),
				Fin:           frame.fin,
				Payload:       payloadStr,
				PayloadSize:   int64(len(payload)),
				PayloadBase64: payloadBase64,
				Masked:        frame.masked,
			}
			lm.Log(logFrame)
		}

		// Forward frame to destination
		if err := writeWebSocketFrame(dst, frame, payload); err != nil {
			if !errors.Is(err, net.ErrClosed) && !isConnectionReset(err) {
				// Check if done channel is closed
				select {
				case <-done:
					return
				default:
					log.Printf("WebSocket write error: %v", err)
				}
			}
			return
		}
	}
}

type wsFrame struct {
	fin     bool
	opcode  byte
	masked  bool
	maskKey [4]byte
	length  uint64
}

func readWebSocketFrame(r io.Reader, expectMask bool, maxBodySize int64) (*wsFrame, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}

	frame := &wsFrame{
		fin:    header[0]&0x80 != 0,
		opcode: header[0] & 0x0F,
		masked: header[1]&0x80 != 0,
	}

	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(r, extLen); err != nil {
			return nil, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extLen))
	case 127:
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(r, extLen); err != nil {
			return nil, nil, err
		}
		length = binary.BigEndian.Uint64(extLen)
	}

	frame.length = length

	if frame.masked {
		if _, err := io.ReadFull(r, frame.maskKey[:]); err != nil {
			return nil, nil, err
		}
	}

	// Read payload (limit to max body size for safety)
	maxLen := uint64(maxBodySize)
	if length > maxLen {
		// Still read but truncate
		payload := make([]byte, maxLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
		// Discard remaining
		_, _ = io.CopyN(io.Discard, r, int64(length-maxLen))
		if frame.masked {
			maskPayload(payload, frame.maskKey)
		}
		return frame, payload, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}

	if frame.masked {
		maskPayload(payload, frame.maskKey)
	}

	return frame, payload, nil
}

func writeWebSocketFrame(w io.Writer, frame *wsFrame, payload []byte) error {
	var buf bytes.Buffer

	// First byte: FIN + opcode
	b0 := frame.opcode
	if frame.fin {
		b0 |= 0x80
	}
	buf.WriteByte(b0)

	// Second byte: mask bit + length
	length := uint64(len(payload))
	var b1 byte
	if frame.masked {
		b1 = 0x80
	}

	if length <= 125 {
		b1 |= byte(length)
		buf.WriteByte(b1)
	} else if length <= 65535 {
		b1 |= 126
		buf.WriteByte(b1)
		_ = binary.Write(&buf, binary.BigEndian, uint16(length))
	} else {
		b1 |= 127
		buf.WriteByte(b1)
		_ = binary.Write(&buf, binary.BigEndian, length)
	}

	// Masking key (if masked)
	if frame.masked {
		buf.Write(frame.maskKey[:])
		// Re-mask payload for sending
		maskedPayload := make([]byte, len(payload))
		copy(maskedPayload, payload)
		maskPayload(maskedPayload, frame.maskKey)
		buf.Write(maskedPayload)
	} else {
		buf.Write(payload)
	}

	_, err := w.Write(buf.Bytes())
	return err
}

func maskPayload(payload []byte, key [4]byte) {
	for i := range payload {
		payload[i] ^= key[i%4]
	}
}

func wsOpcodeName(opcode byte) string {
	names := map[byte]string{
		0:  "continuation",
		1:  "text",
		2:  "binary",
		8:  "close",
		9:  "ping",
		10: "pong",
	}
	if name, ok := names[opcode]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", opcode)
}

// ==================== SSE Handler ====================

func isSSERequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}

func (p *Proxy) handleSSE(w http.ResponseWriter, r *http.Request) {
	connID := uuid.New().String()
	p.metrics.SSEConns.Add(1)
	defer p.metrics.SSEConns.Add(-1)

	shouldLog := p.shouldLogPath(r.URL.Path)

	// Create upstream request with context for cancellation propagation
	ctx := r.Context()
	upstreamURL := *p.upstreamURL
	upstreamURL.Path = singleJoiningSlash(p.upstreamURL.Path, r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		log.Printf("SSE upstream request error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		p.metrics.ErrorsTotal.Add(1)
		return
	}

	// Copy headers
	maps.Copy(upstreamReq.Header, r.Header)

	// Use the shared SSE client
	upstreamResp, err := p.sseClient.Do(upstreamReq)
	if err != nil {
		// Check if error is due to context cancellation (client disconnect)
		if ctx.Err() != nil {
			return // Client disconnected, silently return
		}
		log.Printf("SSE upstream error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		p.metrics.ErrorsTotal.Add(1)
		return
	}
	defer func() { _ = upstreamResp.Body.Close() }()

	// Copy response headers
	for k, v := range upstreamResp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(upstreamResp.StatusCode)

	// Check if response is actually SSE
	contentType := upstreamResp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		// Not SSE, just copy response
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	// Flush if possible
	flusher, canFlush := w.(http.Flusher)

	// Parse and relay SSE events
	scanner := bufio.NewScanner(upstreamResp.Body)
	var data, id strings.Builder
	var eventType string
	var retry *int

	for scanner.Scan() {
		// Check for client disconnect
		if ctx.Err() != nil {
			return
		}

		line := scanner.Text()

		// Forward line to client immediately
		_, writeErr := fmt.Fprintln(w, line)
		if writeErr != nil {
			// Client disconnected
			return
		}
		if canFlush {
			flusher.Flush()
		}

		// Parse SSE event
		if line == "" {
			// End of event - log it
			if shouldLog && data.Len() > 0 {
				sseEvent := &SSEEvent{
					ID:           uuid.New().String(),
					ConnectionID: connID,
					Timestamp:    time.Now(),
					Type:         "sse_event",
					Event:        eventType,
					Data:         strings.TrimSuffix(data.String(), "\n"),
					IDField:      id.String(),
					Retry:        retry,
				}
				p.logManager.Log(sseEvent)
			}

			// Reset for next event
			data.Reset()
			id.Reset()
			eventType = "message"
			retry = nil
			continue
		}

		if after, ok := strings.CutPrefix(line, "event:"); ok {
			eventType = strings.TrimSpace(after)
		} else if after, ok := strings.CutPrefix(line, "data:"); ok {
			data.WriteString(after)
			data.WriteByte('\n')
		} else if after, ok := strings.CutPrefix(line, "id:"); ok {
			id.WriteString(strings.TrimSpace(after))
		} else if after, ok := strings.CutPrefix(line, "retry:"); ok {
			var retryMs int
			if _, parseErr := fmt.Sscanf(strings.TrimSpace(after), "%d", &retryMs); parseErr == nil {
				retry = &retryMs
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF && !isConnectionReset(err) {
		if ctx.Err() == nil { // Only log if not client-initiated cancellation
			log.Printf("SSE scan error: %v", err)
		}
	}
}

// ==================== TLS Certificate ====================

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HTTP Tap Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ==================== Service Support ====================

func printSystemdUnit() {
	unit := `[Unit]
Description=HTTP Tap Proxy
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
	// Get current executable path
	exe, err := os.Executable()
	if err != nil {
		exe = "/usr/local/bin/http-tap-proxy"
	}

	// Build command with current flags
	args := []string{exe}
	if cfg.ListenHTTP != "" {
		args = append(args, "--listen-http", cfg.ListenHTTP)
	}
	if cfg.ListenHTTPS != "" {
		args = append(args, "--listen-https", cfg.ListenHTTPS)
	}
	if cfg.Upstream != "" {
		args = append(args, "--upstream", cfg.Upstream)
	}
	if cfg.LogJSONL != "" {
		args = append(args, "--log-jsonl", cfg.LogJSONL)
	}
	if cfg.LogSQLite != "" {
		args = append(args, "--log-sqlite", cfg.LogSQLite)
	}
	if cfg.AutoCert {
		args = append(args, "--auto-cert")
	}
	if cfg.CertFile != "" {
		args = append(args, "--cert", cfg.CertFile)
	}
	if cfg.KeyFile != "" {
		args = append(args, "--key", cfg.KeyFile)
	}

	cmdLine := strings.Join(args, " ")
	fmt.Printf(unit, cmdLine)
}

func handleServiceCommand(cmd string) {
	if runtime.GOOS != "windows" {
		fmt.Println("Service commands are only supported on Windows.")
		fmt.Println("On Linux, use --print-systemd to generate a systemd unit file.")
		os.Exit(1)
	}

	// Windows service handling is in service_windows.go
	handleWindowsService(cmd)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
