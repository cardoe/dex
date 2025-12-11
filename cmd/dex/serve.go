package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	gosundheit "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	gosundheithttp "github.com/AppsFlyer/go-sundheit/http"
	"github.com/fsnotify/fsnotify"
	"github.com/ghodss/yaml"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/pkg/featureflags"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
)

type serveOptions struct {
	// Config file path
	config string

	// Flags
	webHTTPAddr   string
	webHTTPSAddr  string
	telemetryAddr string
	grpcAddr      string
}

var buildInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name:      "build_info",
		Namespace: "dex",
		Help:      "A metric with a constant '1' value labeled by version from which Dex was built.",
	},
	[]string{"version", "go_version", "platform"},
)

func commandServe() *cobra.Command {
	options := serveOptions{}

	cmd := &cobra.Command{
		Use:     "serve [flags] [config file]",
		Short:   "Launch Dex",
		Example: "dex serve config.yaml",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			options.config = args[0]

			return runServe(options)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&options.webHTTPAddr, "web-http-addr", "", "Web HTTP address")
	flags.StringVar(&options.webHTTPSAddr, "web-https-addr", "", "Web HTTPS address")
	flags.StringVar(&options.telemetryAddr, "telemetry-addr", "", "Telemetry address")
	flags.StringVar(&options.grpcAddr, "grpc-addr", "", "gRPC API address")

	return cmd
}

func runServe(options serveOptions) error {
	configFile := options.config
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	var c Config
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return fmt.Errorf("error parse config file %s: %v", configFile, err)
	}

	applyConfigOverrides(options, &c)

	logger, err := newLogger(c.Logger.Level, c.Logger.Format)
	if err != nil {
		return fmt.Errorf("invalid config: %v", err)
	}

	logger.Info(
		"Version info",
		"dex_version", version,
		slog.Group("go",
			"version", runtime.Version(),
			"os", runtime.GOOS,
			"arch", runtime.GOARCH,
		),
	)

	if c.Logger.Level != slog.LevelInfo {
		logger.Info("config using log level", "level", c.Logger.Level)
	}
	if err := c.Validate(); err != nil {
		return err
	}

	logger.Info("config issuer", "issuer", c.Issuer)

	prometheusRegistry := prometheus.NewRegistry()

	prometheusRegistry.MustRegister(buildInfo)
	recordBuildInfo()

	err = prometheusRegistry.Register(collectors.NewGoCollector())
	if err != nil {
		return fmt.Errorf("failed to register Go runtime metrics: %v", err)
	}

	err = prometheusRegistry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err != nil {
		return fmt.Errorf("failed to register process metrics: %v", err)
	}

	grpcMetrics := grpcprometheus.NewServerMetrics()
	err = prometheusRegistry.Register(grpcMetrics)
	if err != nil {
		return fmt.Errorf("failed to register gRPC server metrics: %v", err)
	}

	var grpcOptions []grpc.ServerOption

	allowedTLSCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	allowedTLSVersions := map[string]int{
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}

	if c.GRPC.TLSCert != "" {
		tlsMinVersion := tls.VersionTLS12
		if c.GRPC.TLSMinVersion != "" {
			tlsMinVersion = allowedTLSVersions[c.GRPC.TLSMinVersion]
		}
		tlsMaxVersion := 0 // default for max is whatever Go defaults to
		if c.GRPC.TLSMaxVersion != "" {
			tlsMaxVersion = allowedTLSVersions[c.GRPC.TLSMaxVersion]
		}
		baseTLSConfig := &tls.Config{
			MinVersion:               uint16(tlsMinVersion),
			MaxVersion:               uint16(tlsMaxVersion),
			CipherSuites:             allowedTLSCiphers,
			PreferServerCipherSuites: true,
		}

		tlsConfig, err := newTLSReloader(logger, c.GRPC.TLSCert, c.GRPC.TLSKey, c.GRPC.TLSClientCA, baseTLSConfig)
		if err != nil {
			return fmt.Errorf("invalid config: get gRPC TLS: %v", err)
		}

		if c.GRPC.TLSClientCA != "" {
			// Only add metrics if client auth is enabled
			grpcOptions = append(grpcOptions,
				grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
				grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
			)
		}

		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	s, err := c.Storage.Config.Open(logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}
	defer s.Close()

	logger.Info("config storage", "storage_type", c.Storage.Type)

	// Load clients from directory if specified
	if c.StaticClientsDir != "" {
		dirClients, err := loadClientsFromDir(c.StaticClientsDir, logger)
		if err != nil {
			return fmt.Errorf("failed to load clients from directory %q: %w (ensure directory exists and contains valid .yaml or .yml files)", c.StaticClientsDir, err)
		}
		// Merge directory clients with any StaticClients from config
		// Directory clients are added first, then config clients
		c.StaticClients = append(dirClients, c.StaticClients...)
	}

	// Validate no duplicate client IDs
	if err := validateNoDuplicateClientIDs(c.StaticClients); err != nil {
		return err
	}

	if len(c.StaticClients) > 0 {
		for i, client := range c.StaticClients {
			if client.Name == "" {
				return fmt.Errorf("invalid config: Name field is required for a client")
			}
			if client.ID == "" && client.IDEnv == "" {
				return fmt.Errorf("invalid config: ID or IDEnv field is required for a client")
			}
			if client.IDEnv != "" {
				if client.ID != "" {
					return fmt.Errorf("invalid config: ID and IDEnv fields are exclusive for client %q", client.ID)
				}
				c.StaticClients[i].ID = os.Getenv(client.IDEnv)
			}
			if client.Secret == "" && client.SecretEnv == "" && !client.Public {
				return fmt.Errorf("invalid config: Secret or SecretEnv field is required for client %q", client.ID)
			}
			if client.SecretEnv != "" {
				if client.Secret != "" {
					return fmt.Errorf("invalid config: Secret and SecretEnv fields are exclusive for client %q", client.ID)
				}
				c.StaticClients[i].Secret = os.Getenv(client.SecretEnv)
			}
			logger.Info("config static client", "client_name", client.Name)
		}
		s = storage.WithStaticClients(s, c.StaticClients)
	}
	if len(c.StaticPasswords) > 0 {
		passwords := make([]storage.Password, len(c.StaticPasswords))
		for i, p := range c.StaticPasswords {
			passwords[i] = storage.Password(p)
		}
		s = storage.WithStaticPasswords(s, passwords, logger)
	}

	// Load connectors from directory if specified
	if c.StaticConnectorsDir != "" {
		dirConnectors, err := loadConnectorsFromDir(c.StaticConnectorsDir, logger)
		if err != nil {
			return fmt.Errorf("failed to load connectors from directory %q: %w (ensure directory exists and contains valid .yaml or .yml files)", c.StaticConnectorsDir, err)
		}
		// Merge directory connectors with any StaticConnectors from config
		// Directory connectors are added first, then config connectors
		c.StaticConnectors = append(dirConnectors, c.StaticConnectors...)
	}

	// Validate no duplicate connector IDs
	if err := validateNoDuplicateConnectorIDs(c.StaticConnectors); err != nil {
		return err
	}

	storageConnectors := make([]storage.Connector, len(c.StaticConnectors))
	for i, c := range c.StaticConnectors {
		if c.ID == "" || c.Name == "" || c.Type == "" {
			return fmt.Errorf("invalid config: ID, Type and Name fields are required for a connector")
		}
		if c.Config == nil {
			return fmt.Errorf("invalid config: no config field for connector %q", c.ID)
		}
		logger.Info("config connector", "connector_id", c.ID)

		// convert to a storage connector object
		conn, err := ToStorageConnector(c)
		if err != nil {
			return fmt.Errorf("failed to initialize storage connectors: %v", err)
		}
		storageConnectors[i] = conn
	}

	if c.EnablePasswordDB {
		storageConnectors = append(storageConnectors, storage.Connector{
			ID:   server.LocalConnector,
			Name: "Email",
			Type: server.LocalConnector,
		})
		logger.Info("config connector: local passwords enabled")
	}

	s = storage.WithStaticConnectors(s, storageConnectors)

	if len(c.OAuth2.ResponseTypes) > 0 {
		logger.Info("config response types accepted", "response_types", c.OAuth2.ResponseTypes)
	}
	if c.OAuth2.SkipApprovalScreen {
		logger.Info("config skipping approval screen")
	}
	if c.OAuth2.PasswordConnector != "" {
		logger.Info("config using password grant connector", "password_connector", c.OAuth2.PasswordConnector)
	}
	if len(c.Web.AllowedOrigins) > 0 {
		logger.Info("config allowed origins", "origins", c.Web.AllowedOrigins)
	}
	if featureflags.ContinueOnConnectorFailure.Enabled() {
		logger.Info("continue on connector failure feature flag enabled")
	}

	// explicitly convert to UTC.
	now := func() time.Time { return time.Now().UTC() }

	healthChecker := gosundheit.New()

	serverConfig := server.Config{
		AllowedGrantTypes:          c.OAuth2.GrantTypes,
		SupportedResponseTypes:     c.OAuth2.ResponseTypes,
		SkipApprovalScreen:         c.OAuth2.SkipApprovalScreen,
		AlwaysShowLoginScreen:      c.OAuth2.AlwaysShowLoginScreen,
		PasswordConnector:          c.OAuth2.PasswordConnector,
		Headers:                    c.Web.Headers.ToHTTPHeader(),
		AllowedOrigins:             c.Web.AllowedOrigins,
		AllowedHeaders:             c.Web.AllowedHeaders,
		Issuer:                     c.Issuer,
		Storage:                    s,
		Web:                        c.Frontend,
		Logger:                     logger,
		Now:                        now,
		PrometheusRegistry:         prometheusRegistry,
		HealthChecker:              healthChecker,
		ContinueOnConnectorFailure: featureflags.ContinueOnConnectorFailure.Enabled(),
	}
	if c.Expiry.SigningKeys != "" {
		signingKeys, err := time.ParseDuration(c.Expiry.SigningKeys)
		if err != nil {
			return fmt.Errorf("invalid config value %q for signing keys expiry: %v", c.Expiry.SigningKeys, err)
		}
		logger.Info("config signing keys", "expire_after", signingKeys)
		serverConfig.RotateKeysAfter = signingKeys
	}
	if c.Expiry.IDTokens != "" {
		idTokens, err := time.ParseDuration(c.Expiry.IDTokens)
		if err != nil {
			return fmt.Errorf("invalid config value %q for id token expiry: %v", c.Expiry.IDTokens, err)
		}
		logger.Info("config id tokens", "valid_for", idTokens)
		serverConfig.IDTokensValidFor = idTokens
	}
	if c.Expiry.AuthRequests != "" {
		authRequests, err := time.ParseDuration(c.Expiry.AuthRequests)
		if err != nil {
			return fmt.Errorf("invalid config value %q for auth request expiry: %v", c.Expiry.AuthRequests, err)
		}
		logger.Info("config auth requests", "valid_for", authRequests)
		serverConfig.AuthRequestsValidFor = authRequests
	}
	if c.Expiry.DeviceRequests != "" {
		deviceRequests, err := time.ParseDuration(c.Expiry.DeviceRequests)
		if err != nil {
			return fmt.Errorf("invalid config value %q for device request expiry: %v", c.Expiry.AuthRequests, err)
		}
		logger.Info("config device requests", "valid_for", deviceRequests)
		serverConfig.DeviceRequestsValidFor = deviceRequests
	}
	refreshTokenPolicy, err := server.NewRefreshTokenPolicy(
		logger,
		c.Expiry.RefreshTokens.DisableRotation,
		c.Expiry.RefreshTokens.ValidIfNotUsedFor,
		c.Expiry.RefreshTokens.AbsoluteLifetime,
		c.Expiry.RefreshTokens.ReuseInterval,
	)
	if err != nil {
		return fmt.Errorf("invalid refresh token expiration policy config: %v", err)
	}

	serverConfig.RefreshTokenPolicy = refreshTokenPolicy

	serverConfig.RealIPHeader = c.Web.ClientRemoteIP.Header
	serverConfig.TrustedRealIPCIDRs, err = c.Web.ClientRemoteIP.ParseTrustedProxies()
	if err != nil {
		return fmt.Errorf("failed to parse client remote IP settings: %v", err)
	}

	serv, err := server.NewServer(context.Background(), serverConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	telemetryRouter := http.NewServeMux()
	telemetryRouter.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))

	// Configure health checker
	{
		handler := gosundheithttp.HandleHealthJSON(healthChecker)
		telemetryRouter.Handle("/healthz", handler)

		// Kubernetes style health checks
		telemetryRouter.HandleFunc("/healthz/live", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})
		telemetryRouter.Handle("/healthz/ready", handler)
	}

	healthChecker.RegisterCheck(
		&checks.CustomCheck{
			CheckName: "storage",
			CheckFunc: storage.NewCustomHealthCheckFunc(serverConfig.Storage, serverConfig.Now),
		},
		gosundheit.ExecutionPeriod(15*time.Second),
		gosundheit.InitiallyPassing(true),
	)

	var group run.Group

	// Set up telemetry server
	if c.Telemetry.HTTP != "" {
		const name = "telemetry"

		logger.Info("listening on", "server", name, "address", c.Telemetry.HTTP)

		l, err := net.Listen("tcp", c.Telemetry.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Telemetry.HTTP, err)
		}

		if c.Telemetry.EnableProfiling {
			pprofHandler(telemetryRouter)
		}

		server := &http.Server{
			Handler: telemetryRouter,
		}
		defer server.Close()

		group.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debug("starting graceful shutdown", "server", name)
			if err := server.Shutdown(ctx); err != nil {
				logger.Error("graceful shutdown", "server", name, "err", err)
			}
		})
	}

	// Set up http server
	if c.Web.HTTP != "" {
		const name = "http"

		logger.Info("listening on", "server", name, "address", c.Web.HTTP)

		l, err := net.Listen("tcp", c.Web.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTP, err)
		}

		server := &http.Server{
			Handler: serv,
		}
		defer server.Close()

		group.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debug("starting graceful shutdown", "server", name)
			if err := server.Shutdown(ctx); err != nil {
				logger.Error("graceful shutdown", "server", name, "err", err)
			}
		})
	}

	// Set up https server
	if c.Web.HTTPS != "" {
		const name = "https"

		logger.Info("listening on", "server", name, "address", c.Web.HTTPS)

		l, err := net.Listen("tcp", c.Web.HTTPS)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTPS, err)
		}

		tlsMinVersion := tls.VersionTLS12
		if c.Web.TLSMinVersion != "" {
			tlsMinVersion = allowedTLSVersions[c.Web.TLSMinVersion]
		}
		tlsMaxVersion := 0 // default for max is whatever Go defaults to
		if c.Web.TLSMaxVersion != "" {
			tlsMaxVersion = allowedTLSVersions[c.Web.TLSMaxVersion]
		}

		baseTLSConfig := &tls.Config{
			MinVersion:               uint16(tlsMinVersion),
			MaxVersion:               uint16(tlsMaxVersion),
			CipherSuites:             allowedTLSCiphers,
			PreferServerCipherSuites: true,
		}

		tlsConfig, err := newTLSReloader(logger, c.Web.TLSCert, c.Web.TLSKey, "", baseTLSConfig)
		if err != nil {
			return fmt.Errorf("invalid config: get HTTP TLS: %v", err)
		}

		server := &http.Server{
			Handler:   serv,
			TLSConfig: tlsConfig,
		}
		defer server.Close()

		group.Add(func() error {
			return server.ServeTLS(l, "", "")
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debug("starting graceful shutdown", "server", name)
			if err := server.Shutdown(ctx); err != nil {
				logger.Error("graceful shutdown", "server", name, "err", err)
			}
		})
	}

	// Set up grpc server
	if c.GRPC.Addr != "" {
		logger.Info("listening on", "server", "grpc", "address", c.GRPC.Addr)

		grpcListener, err := net.Listen("tcp", c.GRPC.Addr)
		if err != nil {
			return fmt.Errorf("listening (grcp) on %s: %w", c.GRPC.Addr, err)
		}

		grpcSrv := grpc.NewServer(grpcOptions...)
		api.RegisterDexServer(grpcSrv, server.NewAPI(serverConfig.Storage, logger, version, serv))

		grpcMetrics.InitializeMetrics(grpcSrv)
		if c.GRPC.Reflection {
			logger.Info("enabling reflection in grpc service")
			reflection.Register(grpcSrv)
		}

		group.Add(func() error {
			return grpcSrv.Serve(grpcListener)
		}, func(err error) {
			logger.Debug("starting graceful shutdown", "server", "grpc")
			grpcSrv.GracefulStop()
		})
	}

	group.Add(run.SignalHandler(context.Background(), os.Interrupt, syscall.SIGTERM))
	if err := group.Run(); err != nil {
		if _, ok := err.(run.SignalError); !ok {
			return fmt.Errorf("run groups: %w", err)
		}
		logger.Info("shutdown now", "err", err)
	}
	return nil
}

func applyConfigOverrides(options serveOptions, config *Config) {
	if options.webHTTPAddr != "" {
		config.Web.HTTP = options.webHTTPAddr
	}

	if options.webHTTPSAddr != "" {
		config.Web.HTTPS = options.webHTTPSAddr
	}

	if options.telemetryAddr != "" {
		config.Telemetry.HTTP = options.telemetryAddr
	}

	if options.grpcAddr != "" {
		config.GRPC.Addr = options.grpcAddr
	}

	if config.Frontend.Dir == "" {
		config.Frontend.Dir = os.Getenv("DEX_FRONTEND_DIR")
	}

	if len(config.OAuth2.GrantTypes) == 0 {
		config.OAuth2.GrantTypes = []string{
			"authorization_code",
			"implicit",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		}
	}
}

func pprofHandler(router *http.ServeMux) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// newTLSReloader returns a [tls.Config] with GetCertificate or GetConfigForClient set
// to reload certificates from the given paths on SIGHUP or on file creates (atomic update via rename).
func newTLSReloader(logger *slog.Logger, certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	// trigger reload on channel
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)

	// files to watch
	watchFiles := map[string]struct{}{
		certFile: {},
		keyFile:  {},
	}
	if caFile != "" {
		watchFiles[caFile] = struct{}{}
	}
	watchDirs := make(map[string]struct{}) // dedupe dirs
	for f := range watchFiles {
		dir := filepath.Dir(f)
		if !strings.HasPrefix(f, dir) {
			// normalize name to have ./ prefix if only a local path was provided
			// can't pass "" to watcher.Add
			watchFiles[dir+string(filepath.Separator)+f] = struct{}{}
		}
		watchDirs[dir] = struct{}{}
	}
	// trigger reload on file change
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher for TLS reloader: %v", err)
	}
	// recommended by fsnotify: watch the dir to handle renames
	// https://pkg.go.dev/github.com/fsnotify/fsnotify#hdr-Watching_files
	for dir := range watchDirs {
		logger.Debug("watching dir", "dir", dir)
		err := watcher.Add(dir)
		if err != nil {
			return nil, fmt.Errorf("watch dir for TLS reloader: %v", err)
		}
	}

	// load once outside the goroutine so we can return an error on misconfig
	initialConfig, err := loadTLSConfig(certFile, keyFile, caFile, baseConfig)
	if err != nil {
		return nil, fmt.Errorf("load TLS config: %v", err)
	}

	// stored version of current tls config
	ptr := &atomic.Pointer[tls.Config]{}
	ptr.Store(initialConfig)

	// start background worker to reload certs
	go func() {
	loop:
		for {
			select {
			case sig := <-sigc:
				logger.Debug("reloading cert from signal", "signal", sig)
			case evt := <-watcher.Events:
				if _, ok := watchFiles[evt.Name]; !ok || !evt.Has(fsnotify.Create) {
					continue loop
				}
				logger.Debug("reloading cert from fsnotify", "event", evt.Name, "operation", evt.Op.String())
			case err := <-watcher.Errors:
				logger.Error("TLS reloader watch", "err", err)
			}

			loaded, err := loadTLSConfig(certFile, keyFile, caFile, baseConfig)
			if err != nil {
				logger.Error("reload TLS config", "err", err)
			}
			ptr.Store(loaded)
		}
	}()

	// https://pkg.go.dev/crypto/tls#baseConfig
	// Server configurations must set one of Certificates, GetCertificate or GetConfigForClient.
	if caFile != "" {
		// grpc will use this via tls.Server for mTLS
		initialConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) { return ptr.Load(), nil }
	} else {
		// net/http only uses Certificates or GetCertificate
		initialConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return &ptr.Load().Certificates[0], nil }
	}
	return initialConfig, nil
}

// loadTLSConfig loads the given file paths into a [tls.Config]
func loadTLSConfig(certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS keypair: %v", err)
	}
	loadedConfig := baseConfig.Clone() // copy
	loadedConfig.Certificates = []tls.Certificate{cert}
	if caFile != "" {
		cPool := x509.NewCertPool()
		clientCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading from client CA file: %v", err)
		}
		if !cPool.AppendCertsFromPEM(clientCert) {
			return nil, errors.New("failed to parse client CA")
		}

		loadedConfig.ClientAuth = tls.RequireAndVerifyClientCert
		loadedConfig.ClientCAs = cPool
	}
	return loadedConfig, nil
}

// recordBuildInfo publishes information about Dex version and runtime info through an info metric (gauge).
func recordBuildInfo() {
	buildInfo.WithLabelValues(version, runtime.Version(), fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)).Set(1)
}

// loadClientsFromDir reads client configuration files from the specified directory.
// Each file should be named <client-id>.yaml or <client-id>.yml and contain a client configuration.
// The client ID will be derived from the filename. If a client has an ID field in the file,
// it must match the filename or an error will be returned. Non-YAML files and subdirectories
// are silently ignored. Returns nil if the directory doesn't exist (with a warning log).
func loadClientsFromDir(dir string, logger *slog.Logger) ([]storage.Client, error) {
	if dir == "" {
		return nil, nil
	}

	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("static clients directory does not exist", "dir", dir)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat clients directory %s: %v", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("staticClientsDir is not a directory: %s", dir)
	}

	// Read directory contents
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read clients directory %s: %v", dir, err)
	}

	var clients []storage.Client
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		// Only process .yaml and .yml files
		if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
			continue
		}

		// Extract client ID from filename
		clientID := strings.TrimSuffix(filename, filepath.Ext(filename))
		if clientID == "" {
			logger.Warn("skipping file with empty client ID", "file", filename)
			continue
		}

		// Read and parse client file
		filePath := filepath.Join(dir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client file %s: %v", filePath, err)
		}

		var client storage.Client
		if err := yaml.Unmarshal(data, &client); err != nil {
			return nil, fmt.Errorf("failed to parse client file %s: %v", filePath, err)
		}

		// If the client has an ID specified and it doesn't match the filename, that's an error
		if client.ID != "" && client.ID != clientID {
			return nil, fmt.Errorf("client ID mismatch in file %s: filename suggests %q but file contains %q", filename, clientID, client.ID)
		}

		// Set the client ID from the filename
		client.ID = clientID

		clients = append(clients, client)
		logger.Info("loaded client from file", "client_id", clientID, "file", filename)
	}

	return clients, nil
}

// loadConnectorsFromDir reads connector configuration files from the specified directory.
// Each file should be named <connector-id>.yaml or <connector-id>.yml and contain a connector configuration.
// The connector ID will be derived from the filename. If a connector has an ID field in the file,
// it must match the filename or an error will be returned. Non-YAML files and subdirectories
// are silently ignored. Returns nil if the directory doesn't exist (with a warning log).
func loadConnectorsFromDir(dir string, logger *slog.Logger) ([]Connector, error) {
	if dir == "" {
		return nil, nil
	}

	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("static connectors directory does not exist", "dir", dir)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat connectors directory %s: %v", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("staticConnectorsDir is not a directory: %s", dir)
	}

	// Read directory contents
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read connectors directory %s: %v", dir, err)
	}

	var connectors []Connector
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		// Only process .yaml and .yml files
		if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
			continue
		}

		// Extract connector ID from filename
		connectorID := strings.TrimSuffix(filename, filepath.Ext(filename))
		if connectorID == "" {
			logger.Warn("skipping file with empty connector ID", "file", filename)
			continue
		}

		// Read and parse connector file
		filePath := filepath.Join(dir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read connector file %s: %v", filePath, err)
		}

		var connector Connector
		if err := yaml.Unmarshal(data, &connector); err != nil {
			return nil, fmt.Errorf("failed to parse connector file %s: %v", filePath, err)
		}

		// If the connector has an ID specified and it doesn't match the filename, that's an error
		if connector.ID != "" && connector.ID != connectorID {
			return nil, fmt.Errorf("connector ID mismatch in file %s: filename suggests %q but file contains %q", filename, connectorID, connector.ID)
		}

		// Set the connector ID from the filename
		connector.ID = connectorID

		connectors = append(connectors, connector)
		logger.Info("loaded connector from file", "connector_id", connectorID, "file", filename)
	}

	return connectors, nil
}

// validateNoDuplicateClientIDs checks for duplicate client IDs and returns an error if found.
func validateNoDuplicateClientIDs(clients []storage.Client) error {
	seen := make(map[string]bool)
	for _, client := range clients {
		// Use the ID after environment variable expansion if IDEnv is set
		id := client.ID
		if id == "" && client.IDEnv != "" {
			id = os.Getenv(client.IDEnv)
		}
		if id == "" {
			continue // Will be caught by later validation
		}
		if seen[id] {
			return fmt.Errorf("duplicate client ID %q found in static clients configuration (check both staticClients in config and staticClientsDir files)", id)
		}
		seen[id] = true
	}
	return nil
}

// validateNoDuplicateConnectorIDs checks for duplicate connector IDs and returns an error if found.
func validateNoDuplicateConnectorIDs(connectors []Connector) error {
	seen := make(map[string]bool)
	for _, connector := range connectors {
		if connector.ID == "" {
			continue // Will be caught by later validation
		}
		if seen[connector.ID] {
			return fmt.Errorf("duplicate connector ID %q found in static connectors configuration (check both connectors in config and connectorsDir files)", connector.ID)
		}
		seen[connector.ID] = true
	}
	return nil
}
