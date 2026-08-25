// Command endlessh-dashboard runs the whole application: API, embedded
// interface, scraper and datastore in one process, in one container.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"endlessh-dashboard/internal/api"
	"endlessh-dashboard/internal/auth"
	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/maintenance"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/scrape"
	"endlessh-dashboard/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	dataDirectoryMode      = 0o700
	readHeaderTimeout      = 10 * time.Second
	readTimeout            = 30 * time.Second
	writeTimeout           = 120 * time.Second
	idleTimeout            = 120 * time.Second
	shutdownGracePeriod    = 15 * time.Second
	configurationErrorCode = 2
	healthcheckFailureCode = 1
	healthcheckTimeout     = 5 * time.Second
	defaultProbeAddress    = "127.0.0.1:18222"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false,
		"probe this container's own /healthz and exit 0 when healthy; used by the container healthcheck, which has no shell to call curl with")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *healthcheck {
		if err := probeHealth(); err != nil {
			logger.Error("healthcheck failed", "error", err)
			os.Exit(healthcheckFailureCode)
		}
		return
	}

	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(configurationErrorCode)
	}
}

// probeHealth is what the distroless container's healthcheck runs: the image
// carries no shell, curl or wget, so the binary probes itself.
func probeHealth() error {
	address := os.Getenv(config.EnvListenAddress)
	if address == "" {
		address = defaultProbeAddress
	}
	if strings.HasPrefix(address, ":") {
		address = "127.0.0.1" + address
	}

	client := &http.Client{Timeout: healthcheckTimeout}
	response, err := client.Get("http://" + address + "/healthz")
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("/healthz returned %s", response.Status)
	}
	return nil
}

func run(logger *slog.Logger) error {
	configuration, err := config.Load()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(configuration.DataDirectory, dataDirectoryMode); err != nil {
		return err
	}

	restored, err := store.ApplyPendingRestore(configuration.DatabasePath())
	if err != nil {
		return err
	}
	if restored {
		logger.Info("applied a staged restore", "database", configuration.DatabasePath())
	}

	dataStore, err := store.Open(configuration.DatabasePath())
	if err != nil {
		return err
	}
	defer dataStore.Close()

	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := dataStore.Migrate(rootContext); err != nil {
		return err
	}

	authService := auth.NewService(dataStore, config.SessionLifetime)
	created, err := authService.EnsureInitialUser(rootContext, configuration.AdminUsername, configuration.AdminPassword)
	if err != nil {
		return err
	}
	if created {
		logger.Info("created the initial administrator account; you will be asked to choose a new password at first sign-in",
			"username", configuration.AdminUsername)
	}

	geoResolver, err := geo.Open(configuration.GeoIPDatabasePath)
	if err != nil {
		return err
	}
	defer geoResolver.Close()
	if geoResolver.Enabled() {
		logger.Info("local GeoIP enrichment enabled", "database", geoResolver.Path())
	}

	onlineResolver := geo.NewOnlineResolver(
		configuration.GeoIPOnline, configuration.GeoIPOnlineEndpoint, configuration.GeoIPOnlineRate)
	defer onlineResolver.Close()
	if onlineResolver.Enabled() {
		// Loud on purpose: this is the only thing the app sends anywhere, and the
		// operator should see in the log that they really did turn it on.
		logger.Warn("online GeoIP lookups enabled: attacker addresses will be sent to a third party",
			"endpoint", onlineResolver.Endpoint(), "requests_per_minute", configuration.GeoIPOnlineRate)
	}

	validator := registry.NewValidator(configuration.ScrapeAllowlistCIDRs, configuration.ScrapeBlockPrivate)
	registryService := registry.NewService(dataStore, validator)

	backupManager := store.NewBackupManager(
		dataStore, configuration.BackupDirectory(), configuration.DatabasePath(), configuration.BackupKeepLast)
	if err := backupManager.EnsureDirectory(); err != nil {
		return err
	}

	poller := scrape.NewPoller(dataStore, validator, geoResolver, logger,
		configuration.ScrapeInterval, configuration.ScrapeTimeout)

	worker := maintenance.NewWorker(dataStore, authService, backupManager, logger,
		configuration.RetentionDays, configuration.BackupDaily)

	enricher := geo.NewEnricher(dataStore, geoResolver, onlineResolver, logger)

	restart := make(chan struct{}, 1)
	server := api.NewServer(configuration, dataStore, authService, registryService,
		backupManager, geoResolver, poller, logger, version, restart)

	httpServer := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           server.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	workerContext, stopWorkers := context.WithCancel(rootContext)
	defer stopWorkers()
	go poller.Run(workerContext)
	go worker.Run(workerContext)
	go enricher.Run(workerContext)

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("dashboard listening", "address", configuration.ListenAddress, "version", version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-restart:
		logger.Info("restarting to apply a restore")
	case <-rootContext.Done():
		logger.Info("shutting down")
	}

	stopWorkers()
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		logger.Warn("graceful shutdown timed out", "error", err)
	}
	return nil
}
