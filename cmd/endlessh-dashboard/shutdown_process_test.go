package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

// This helper is a separately reaped process so signal handling and run's
// resource defers are exercised without signalling the test runner itself.
func TestShutdownProcessHelper(t *testing.T) {
	if os.Getenv("ENDLESSH_SHUTDOWN_HELPER") != "1" {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(42)
	}
	os.Exit(0)
}

func TestSIGTERMJoinsBlockedScrapeAndEnrichment(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	path := filepath.Join(directory, "endlessh.db")
	scrapeEntered, scrapeCancelled := make(chan struct{}), make(chan struct{})
	geoEntered, geoCancelled := make(chan struct{}), make(chan struct{})
	var scrapeOnce, geoOnce sync.Once
	mock := func(entered, cancelled chan struct{}, once *sync.Once) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(entered) })
			<-r.Context().Done()
			close(cancelled)
		}))
	}
	scrapeServer := mock(scrapeEntered, scrapeCancelled, &scrapeOnce)
	defer scrapeServer.Close()
	geoServer := mock(geoEntered, geoCancelled, &geoOnce)
	defer geoServer.Close()
	_, rawPort, err := net.SplitHostPort(scrapeServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	m, err := db.CreateMachine(ctx, store.Machine{Name: "blocked local mock", Host: "127.0.0.1", Port: port, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.ApplyScrape(ctx, store.ScrapeDelta{MachineID: m.ID, At: time.Now().UTC(), Attackers: []store.AttackerDelta{{IPAddress: "8.8.8.8", Connections: 1}}}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "shutdown.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	child := exec.Command(executable, "-test.run=^TestShutdownProcessHelper$")
	child.Env = []string{"ENDLESSH_SHUTDOWN_HELPER=1", "DATA_DIR=" + directory, "LISTEN_ADDR=127.0.0.1:0", "ADMIN_USERNAME=fixture", "ADMIN_PASSWORD=temporary-shutdown-test-password", "GEOIP_MMDB_PATH=", "GEOIP_ONLINE=true", "GEOIP_ONLINE_RATE_PER_MINUTE=45", "GEOIP_ONLINE_ENDPOINT=" + geoServer.URL + "/{ip}", "SCRAPE_ALLOWLIST_CIDRS=127.0.0.0/8", "SCRAPE_INTERVAL=1h", "SCRAPE_TIMEOUT=30s", "BACKUP_DAILY=true"}
	child.Stdout = logFile
	child.Stderr = logFile
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			child.Process.Kill()
			<-done
		}
		raw, _ := os.ReadFile(logPath)
		t.Logf("subprocess log:\n%s", raw)
	}()
	awaitProcessEvent := func(event <-chan struct{}) {
		t.Helper()
		select {
		case <-event:
		case err := <-done:
			reaped = true
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("child exited before blocked work: %v\n%s", err, raw)
		case <-time.After(8 * time.Second):
			t.Fatal("local mock was not reached")
		}
	}
	awaitProcessEvent(scrapeEntered)
	awaitProcessEvent(geoEntered)
	started := time.Now()
	if err = child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		reaped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not stop cancellable workers promptly")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("shutdown exceeded the fixture budget")
	}
	awaitProcessEvent(scrapeCancelled)
	awaitProcessEvent(geoCancelled)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "background workers and HTTP handlers stopped") || strings.Contains(string(raw), "shutdown timed out") {
		t.Fatalf("missing graceful completion log: %s", raw)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var integrity string
	if err = reopened.DB().QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("shutdown damaged fixture database", integrity, err)
	}
	for _, pattern := range []string{"backups/.snapshot-*", "backups/.endlessh-verify-*"} {
		pending, err := filepath.Glob(filepath.Join(directory, pattern))
		if err != nil || len(pending) != 0 {
			t.Fatal("cancelled backup left temporary work", pending, err)
		}
	}
}
