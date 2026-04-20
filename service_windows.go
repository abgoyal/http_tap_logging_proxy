//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "http-tap-proxy"
const serviceDisplayName = "HTTP Tap Proxy"
const serviceDescription = "A transparent HTTP/HTTPS logging proxy"

// serviceProxies holds the running proxy instances for Windows service mode
var serviceProxies []*Proxy
var serviceLogManager *LogManager
var serviceS3Uploader *S3Uploader
var serviceAdminServer *http.Server
var serviceAdminListener net.Listener

type httpTapService struct{}

func (m *httpTapService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	var err error
	serviceProxies, serviceLogManager, serviceS3Uploader, err = initProxies(cfg)
	if err != nil {
		slog.Error("failed to initialize proxies", "error", err)
		return false, 1
	}

	// Start admin server if configured
	startTime := time.Now()
	if cfg.ListenAdmin != "" {
		serviceAdminListener, err = net.Listen("tcp", cfg.ListenAdmin)
		if err != nil {
			slog.Error("failed to listen on admin port", "port", cfg.ListenAdmin, "error", err)
			return false, 1
		}

		serviceAdminServer = &http.Server{Handler: createAdminHandler(serviceProxies, serviceLogManager, startTime, cfg)}
		go func() {
			if err := serviceAdminServer.Serve(serviceAdminListener); err != http.ErrServerClosed {
				slog.Error("admin server error", "error", err)
			}
		}()
		slog.Info("admin server listening", "addr", serviceAdminListener.Addr().String())
	}

	slog.Info("HTTP Tap Proxy started as Windows service", "version", Version)
	for _, p := range serviceProxies {
		slog.Info("proxy started", "name", p.name, "upstream", p.proxyCfg.Upstream)
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				// Shutdown admin server
				if serviceAdminServer != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = serviceAdminServer.Shutdown(ctx)
					cancel()
				}
				// Shutdown order: proxies first (waits for in-flight requests),
				// then logManager (flushes pending logs), then S3 (uploads rotated files)
				for _, p := range serviceProxies {
					_ = p.Close()
				}
				if serviceLogManager != nil {
					serviceLogManager.Stop()
				}
				if serviceS3Uploader != nil {
					serviceS3Uploader.Stop()
				}
				return
			default:
				slog.Warn("unexpected control request", "cmd", c.Cmd)
			}
		}
	}
}

func handleWindowsService(cmd string) {
	switch strings.ToLower(cmd) {
	case "install":
		installService()
	case "uninstall", "remove":
		uninstallService()
	case "start":
		startService()
	case "stop":
		stopService()
	case "run":
		runService()
	default:
		fmt.Printf("Unknown service command: %s\n", cmd)
		fmt.Println("Valid commands: install, uninstall, start, stop")
		os.Exit(1)
	}
}

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		slog.Error("failed to get executable path", "error", err)
		os.Exit(1)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		slog.Error("failed to get absolute path", "error", err)
		os.Exit(1)
	}

	m, err := mgr.Connect()
	if err != nil {
		slog.Error("failed to connect to service manager", "error", err)
		os.Exit(1)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		slog.Error("service already exists", "service", serviceName)
		os.Exit(1)
	}

	// Build service arguments
	var args []string
	args = append(args, "--service", "run")

	// Add proxy definitions
	for _, pc := range cfg.Proxies {
		var proxyParts []string
		proxyParts = append(proxyParts, "name="+pc.Name)
		if pc.ListenHTTP != "" {
			proxyParts = append(proxyParts, "listen_http="+pc.ListenHTTP)
		}
		if pc.ListenHTTPS != "" {
			proxyParts = append(proxyParts, "listen_https="+pc.ListenHTTPS)
		}
		proxyParts = append(proxyParts, "upstream="+pc.Upstream)
		if pc.LogJSONL != "" {
			proxyParts = append(proxyParts, "log_jsonl="+pc.LogJSONL)
		}
		if pc.LogSQLite != "" {
			proxyParts = append(proxyParts, "log_sqlite="+pc.LogSQLite)
		}
		for _, pattern := range pc.IncludePathsRegex {
			proxyParts = append(proxyParts, "include_path="+pattern)
		}
		for _, pattern := range pc.ExcludePathsRegex {
			proxyParts = append(proxyParts, "exclude_path="+pattern)
		}
		args = append(args, "--proxy", strings.Join(proxyParts, ","))
	}

	// Global settings
	if cfg.ListenAdmin != "" {
		args = append(args, "--listen-admin", cfg.ListenAdmin)
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

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		slog.Error("failed to create service", "error", err)
		os.Exit(1)
	}
	defer s.Close()

	// Set up event logging
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		slog.Error("failed to set up event log", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Service %s installed successfully\n", serviceName)
}

func uninstallService() {
	m, err := mgr.Connect()
	if err != nil {
		slog.Error("failed to connect to service manager", "error", err)
		os.Exit(1)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		slog.Error("service not found", "service", serviceName, "error", err)
		os.Exit(1)
	}
	defer s.Close()

	// Stop service if running
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		s.Control(svc.Stop)
		// Wait for stop
		for i := 0; i < 10; i++ {
			time.Sleep(time.Second)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	err = s.Delete()
	if err != nil {
		slog.Error("failed to delete service", "error", err)
		os.Exit(1)
	}

	eventlog.Remove(serviceName)
	fmt.Printf("Service %s uninstalled successfully\n", serviceName)
}

func startService() {
	m, err := mgr.Connect()
	if err != nil {
		slog.Error("failed to connect to service manager", "error", err)
		os.Exit(1)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		slog.Error("service not found", "service", serviceName, "error", err)
		os.Exit(1)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		slog.Error("failed to start service", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Service %s started\n", serviceName)
}

func stopService() {
	m, err := mgr.Connect()
	if err != nil {
		slog.Error("failed to connect to service manager", "error", err)
		os.Exit(1)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		slog.Error("service not found", "service", serviceName, "error", err)
		os.Exit(1)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		slog.Error("failed to stop service", "error", err)
		os.Exit(1)
	}

	// Wait for stop
	for i := 0; i < 10; i++ {
		if status.State == svc.Stopped {
			break
		}
		time.Sleep(time.Second)
		status, err = s.Query()
		if err != nil {
			break
		}
	}

	fmt.Printf("Service %s stopped\n", serviceName)
}

func runService() {
	// Running as Windows service
	isService, err := svc.IsWindowsService()
	if err != nil {
		slog.Error("failed to determine if running as service", "error", err)
		os.Exit(1)
	}

	if isService {
		err = svc.Run(serviceName, &httpTapService{})
		if err != nil {
			slog.Error("service failed", "error", err)
			os.Exit(1)
		}
	} else {
		// Not running as service, run normally
		slog.Info("not running as Windows service, starting normally")
	}
}
