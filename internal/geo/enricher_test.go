package geo

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func newEnricherFixture(t *testing.T, online *OnlineResolver) (*store.Store, *Enricher) {
	t.Helper()
	dataStore, err := store.Open(filepath.Join(t.TempDir(), "dashboard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	local, err := Open("")
	if err != nil {
		t.Fatalf("open local resolver: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return dataStore, NewEnricher(dataStore, local, online, logger)
}

func seedAttacker(t *testing.T, dataStore *store.Store, machineID int64, ipAddress string) {
	t.Helper()
	if err := dataStore.ApplyScrape(context.Background(), store.ScrapeDelta{
		MachineID: machineID,
		At:        time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC),
		Attackers: []store.AttackerDelta{{IPAddress: ipAddress, Connections: 1}},
	}); err != nil {
		t.Fatalf("seed attacker %s: %v", ipAddress, err)
	}
}

func TestEnricherBackfillsEveryMachinesCopy(t *testing.T) {
	provider := newFakeProvider(t)
	dataStore, enricher := newEnricherFixture(t, newTestOnlineResolver(t, provider))
	ctx := context.Background()

	first, err := dataStore.CreateMachine(ctx, store.Machine{Name: "alpha", Host: "10.0.0.1", Port: 2222, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}
	second, err := dataStore.CreateMachine(ctx, store.Machine{Name: "beta", Host: "10.0.0.2", Port: 2222, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}
	seedAttacker(t, dataStore, first.ID, "8.8.8.8")
	seedAttacker(t, dataStore, second.ID, "8.8.8.8")

	enricher.runOnce(ctx)

	rows, err := dataStore.AttackersMissingLocation(ctx, 10)
	if err != nil {
		t.Fatalf("AttackersMissingLocation: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("%d attackers still have no location, want none left", len(rows))
	}
	// One address, two machines, one request: the address is what is looked up.
	if requests := provider.requests.Load(); requests != 1 {
		t.Errorf("provider saw %d requests for one address on two machines, want 1", requests)
	}

	page, err := dataStore.ListAttackers(ctx, store.AttackerFilter{
		MachineIDs: []int64{first.ID, second.ID},
		Page:       1,
		PerPage:    10,
	})
	if err != nil {
		t.Fatalf("ListAttackers: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("got %d rows, want both machines' copies", len(page.Rows))
	}
	for _, row := range page.Rows {
		if row.Country != "United States" || row.CountryCode != "US" {
			t.Errorf("%s on machine %d = %q/%q, want the resolved country",
				row.IPAddress, row.MachineID, row.Country, row.CountryCode)
		}
		if row.ISP != "Google LLC" {
			t.Errorf("ISP on machine %d = %q, want Google LLC", row.MachineID, row.ISP)
		}
		if row.Latitude == nil || row.Longitude == nil {
			t.Errorf("machine %d has no coordinate after backfill", row.MachineID)
		}
	}
}

func TestEnricherRunDoesNothingWithNoSources(t *testing.T) {
	provider := newFakeProvider(t)
	dataStore, enricher := newEnricherFixture(t, NewOnlineResolver(false, provider.endpoint(), testRatePerMinute))

	machine, err := dataStore.CreateMachine(context.Background(), store.Machine{
		Name: "alpha", Host: "10.0.0.1", Port: 2222, MetricsPath: "/metrics", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}
	seedAttacker(t, dataStore, machine.ID, "8.8.8.8")

	// With no local database and no online provider there is nothing to find, so
	// Run must return rather than tick forever against a context that is open.
	finished := make(chan struct{})
	go func() {
		enricher.Run(context.Background())
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept going with no geography source configured")
	}

	if requests := provider.requests.Load(); requests != 0 {
		t.Errorf("a disabled enricher made %d requests", requests)
	}
}

func TestEnricherStopsOnContextCancel(t *testing.T) {
	provider := newFakeProvider(t)
	dataStore, enricher := newEnricherFixture(t, newTestOnlineResolver(t, provider))

	machine, err := dataStore.CreateMachine(context.Background(), store.Machine{
		Name: "alpha", Host: "10.0.0.1", Port: 2222, MetricsPath: "/metrics", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}
	seedAttacker(t, dataStore, machine.ID, "8.8.8.8")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	finished := make(chan struct{})
	go func() {
		enricher.Run(ctx)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored a cancelled context")
	}
}
