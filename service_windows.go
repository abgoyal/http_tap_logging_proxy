//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
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
var serviceAdminServer *http.Server
var serviceAdminListener net.Listener

type httpTapService struct{}

func (m *httpTapService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	var err error
	serviceProxies, serviceLogManager, err = initProxies(cfg)
	if err != nil {
		log.Printf("Failed to initialize proxies: %v", err)
		return false, 1
	}

	// Start admin server if configured
	startTime := time.Now()
	if cfg.ListenAdmin != "" {
		serviceAdminListener, err = net.Listen("tcp", cfg.ListenAdmin)
		if err != nil {
			log.Printf("Failed to listen on admin port %s: %v", cfg.ListenAdmin, err)
			return false, 1
		}

		serviceAdminServer = &http.Server{Handler: createAdminHandler(serviceProxies, startTime, cfg)}
		go func() {
			if err := serviceAdminServer.Serve(serviceAdminListener); err != http.ErrServerClosed {
				log.Printf("Admin server error: %v", err)
			}
		}()
		log.Printf("Admin (health/metrics): %s", serviceAdminListener.Addr().String())
	}

	log.Printf("HTTP Tap Proxy v%s started as Windows service", Version)
	for _, p := range serviceProxies {
		log.Printf("Proxy %q: upstream=%s", p.name, p.proxyCfg.Upstream)
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
				// Shutdown all proxies
				for _, p := range serviceProxies {
					_ = p.Close()
				}
				// Stop log manager
				if serviceLogManager != nil {
					serviceLogManager.Stop()
				}
				return
			default:
				log.Printf("unexpected control request #%d", c)
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
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		log.Fatalf("Service %s already exists", serviceName)
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
		log.Fatalf("Failed to create service: %v", err)
	}
	defer s.Close()

	// Set up event logging
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		log.Fatalf("Failed to set up event log: %v", err)
	}

	fmt.Printf("Service %s installed successfully\n", serviceName)
}

func uninstallService() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("Service %s not found: %v", serviceName, err)
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
		log.Fatalf("Failed to delete service: %v", err)
	}

	eventlog.Remove(serviceName)
	fmt.Printf("Service %s uninstalled successfully\n", serviceName)
}

func startService() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("Service %s not found: %v", serviceName, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}

	fmt.Printf("Service %s started\n", serviceName)
}

func stopService() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("Service %s not found: %v", serviceName, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		log.Fatalf("Failed to stop service: %v", err)
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
		log.Fatalf("Failed to determine if running as service: %v", err)
	}

	if isService {
		err = svc.Run(serviceName, &httpTapService{})
		if err != nil {
			log.Fatalf("Service failed: %v", err)
		}
	} else {
		// Not running as service, run normally
		log.Println("Not running as Windows service, starting normally...")
	}
}
