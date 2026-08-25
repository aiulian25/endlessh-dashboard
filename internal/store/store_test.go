package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// baseTime is a fixed, minute-aligned instant so bucket maths in the tests is
// exact and never depends on the wall clock.
var baseTime = time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endlessh.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store, path
}

func createMachine(t *testing.T, store *Store, name string) Machine {
	t.Helper()
	machine, err := store.CreateMachine(context.Background(), Machine{
		Name:        name,
		Host:        "10.0.0.1",
		Port:        2222,
		MetricsPath: "/metrics",
		GroupLabel:  "lab",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("CreateMachine(%q): %v", name, err)
	}
	return machine
}

func applyScrape(t *testing.T, store *Store, delta ScrapeDelta) {
	t.Helper()
	if err := store.ApplyScrape(context.Background(), delta); err != nil {
		t.Fatalf("ApplyScrape: %v", err)
	}
}

func migrationFileCount(t *testing.T) int {
	t.Helper()
	entries, err := fs.ReadDir(migrationFiles, migrationsDirectory)
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			count++
		}
	}
	if count == 0 {
		t.Fatal("no migration files embedded")
	}
	return count
}

func scanInt(t *testing.T, store *Store, query string, args ...any) int64 {
	t.Helper()
	var value int64
	if err := store.DB().QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

func scanFloat(t *testing.T, store *Store, query string, args ...any) float64 {
	t.Helper()
	var value float64
	if err := store.DB().QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

func scanText(t *testing.T, store *Store, query string, args ...any) string {
	t.Helper()
	var value string
	if err := store.DB().QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

func assertFloat(t *testing.T, label string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-6 {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

func assertInt(t *testing.T, label string, got, want int64) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", label, got, want)
	}
}

func TestMigrateCreatesSchemaAndIsIdempotent(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	expectedMigrations := int64(migrationFileCount(t))

	tables := []string{
		"machines", "machine_rollups", "machine_totals",
		"counter_states", "attackers", "users", "sessions",
	}
	for _, table := range tables {
		count := scanInt(t, store,
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table)
		assertInt(t, "table "+table+" exists", count, 1)
	}

	applied := scanInt(t, store, "SELECT COUNT(*) FROM schema_migrations")
	assertInt(t, "schema_migrations rows after first migrate", applied, expectedMigrations)

	firstStamp := scanInt(t, store, "SELECT applied_at FROM schema_migrations ORDER BY version LIMIT 1")

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	applied = scanInt(t, store, "SELECT COUNT(*) FROM schema_migrations")
	assertInt(t, "schema_migrations rows after second migrate", applied, expectedMigrations)

	secondStamp := scanInt(t, store, "SELECT applied_at FROM schema_migrations ORDER BY version LIMIT 1")
	assertInt(t, "applied_at rewritten by no-op migrate", secondStamp, firstStamp)
}

func TestOpenEnablesIncrementalAutoVacuum(t *testing.T) {
	store, path := newStore(t)

	// 2 is SQLite's code for incremental; full (1) reclaims on every commit and
	// none (0) never does. Spelled as a literal on purpose: comparing against
	// the package constant would pass whatever value that constant held.
	const incremental = int64(2)

	mode := scanInt(t, store, "PRAGMA auto_vacuum")
	assertInt(t, "PRAGMA auto_vacuum", mode, incremental)

	// The setting lives in the file header: reopening must not reset it, and the
	// second Open must not need another VACUUM to get there.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	mode = scanInt(t, reopened, "PRAGMA auto_vacuum")
	assertInt(t, "PRAGMA auto_vacuum after reopen", mode, incremental)
}

func TestWALAllowsReadDuringWriteTransaction(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	journalMode := scanText(t, store, "PRAGMA journal_mode")
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("PRAGMA journal_mode = %q, want wal", journalMode)
	}

	createMachine(t, store, "already-there")

	transaction, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx,
		`INSERT INTO machines (name, host, port, metrics_path, group_label, enabled, created_at)
		 VALUES ('held-open', 'h', 1, '/metrics', '', 1, 0)`); err != nil {
		t.Fatalf("write inside transaction: %v", err)
	}

	machines, err := store.ListMachines(ctx)
	if err != nil {
		t.Fatalf("read while a write transaction is open: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("reader saw %d machines, want 1 (uncommitted write must be invisible)", len(machines))
	}
	if machines[0].Name != "already-there" {
		t.Errorf("reader saw %q, want the committed row", machines[0].Name)
	}
}

func TestMachineCRUD(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	created := createMachine(t, store, "mid")
	// Not just a sanity check on the insert: zero is the id the dashboard sends
	// to mean "no machines selected" (NO_MACHINES in web/app.js), which works
	// only while no real machine can hold it. Relaxing this would quietly turn
	// "none selected" into "this one selected" everywhere.
	if created.ID == 0 {
		t.Fatal("CreateMachine returned a zero id, which the dashboard reserves to mean 'no machines selected'")
	}

	fetched, err := store.GetMachine(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if fetched.Name != "mid" || fetched.Host != "10.0.0.1" || fetched.Port != 2222 {
		t.Errorf("GetMachine returned %+v, want the created values", fetched)
	}
	if fetched.MetricsPath != "/metrics" || fetched.GroupLabel != "lab" || !fetched.Enabled {
		t.Errorf("GetMachine returned %+v, want the created values", fetched)
	}
	if fetched.LastScrapeAt != nil || fetched.LastOKAt != nil {
		t.Errorf("fresh machine has scrape timestamps: %+v", fetched)
	}
	if !fetched.CreatedAt.Equal(created.CreatedAt.Truncate(time.Second)) {
		t.Errorf("CreatedAt = %v, want %v", fetched.CreatedAt, created.CreatedAt.Truncate(time.Second))
	}

	createMachine(t, store, "zeta")
	createMachine(t, store, "Alpha")

	machines, err := store.ListMachines(ctx)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	gotOrder := make([]string, len(machines))
	for index, machine := range machines {
		gotOrder[index] = machine.Name
	}
	wantOrder := []string{"Alpha", "mid", "zeta"}
	if strings.Join(gotOrder, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("ListMachines order = %v, want %v (case-insensitive by name)", gotOrder, wantOrder)
	}

	updated := fetched
	updated.Name = "renamed"
	updated.Host = "192.0.2.7"
	updated.Port = 2200
	updated.Enabled = false
	if err := store.UpdateMachine(ctx, updated); err != nil {
		t.Fatalf("UpdateMachine: %v", err)
	}
	reread, err := store.GetMachine(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetMachine after update: %v", err)
	}
	if reread.Name != "renamed" || reread.Host != "192.0.2.7" || reread.Port != 2200 || reread.Enabled {
		t.Errorf("UpdateMachine did not persist: %+v", reread)
	}

	enabled, err := store.ListEnabledMachines(ctx)
	if err != nil {
		t.Fatalf("ListEnabledMachines: %v", err)
	}
	if len(enabled) != 2 {
		t.Errorf("ListEnabledMachines returned %d machines, want 2", len(enabled))
	}
	for _, machine := range enabled {
		if !machine.Enabled {
			t.Errorf("ListEnabledMachines returned a disabled machine: %+v", machine)
		}
	}

	if err := store.DeleteMachine(ctx, created.ID); err != nil {
		t.Fatalf("DeleteMachine: %v", err)
	}
	if _, err := store.GetMachine(ctx, created.ID); !errors.Is(err, ErrMachineNotFound) {
		t.Errorf("GetMachine after delete = %v, want ErrMachineNotFound", err)
	}
	if err := store.DeleteMachine(ctx, created.ID); !errors.Is(err, ErrMachineNotFound) {
		t.Errorf("second DeleteMachine = %v, want ErrMachineNotFound", err)
	}
}

func TestMachineErrors(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	if _, err := store.CreateMachine(ctx, Machine{Name: "alpha", Host: "h", Port: 1}); !errors.Is(err, ErrDuplicateMachineName) {
		t.Errorf("CreateMachine duplicate = %v, want ErrDuplicateMachineName", err)
	}

	beta.Name = "alpha"
	if err := store.UpdateMachine(ctx, beta); !errors.Is(err, ErrDuplicateMachineName) {
		t.Errorf("UpdateMachine to duplicate name = %v, want ErrDuplicateMachineName", err)
	}

	if _, err := store.GetMachine(ctx, alpha.ID+9999); !errors.Is(err, ErrMachineNotFound) {
		t.Errorf("GetMachine unknown id = %v, want ErrMachineNotFound", err)
	}

	missing := Machine{ID: alpha.ID + 9999, Name: "nobody", Host: "h", Port: 1, MetricsPath: "/metrics"}
	if err := store.UpdateMachine(ctx, missing); !errors.Is(err, ErrMachineNotFound) {
		t.Errorf("UpdateMachine unknown id = %v, want ErrMachineNotFound", err)
	}
}

func TestRecordScrapeOutcomes(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	okAt := baseTime
	if err := store.RecordScrapeSuccess(ctx, machine.ID, okAt); err != nil {
		t.Fatalf("RecordScrapeSuccess: %v", err)
	}
	fetched, err := store.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if fetched.LastScrapeAt == nil || !fetched.LastScrapeAt.Equal(okAt) {
		t.Errorf("LastScrapeAt = %v, want %v", fetched.LastScrapeAt, okAt)
	}
	if fetched.LastOKAt == nil || !fetched.LastOKAt.Equal(okAt) {
		t.Errorf("LastOKAt = %v, want %v", fetched.LastOKAt, okAt)
	}

	failAt := okAt.Add(time.Minute)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := store.RecordScrapeFailure(ctx, machine.ID, failAt, "connection refused"); err != nil {
			t.Fatalf("RecordScrapeFailure: %v", err)
		}
		fetched, err = store.GetMachine(ctx, machine.ID)
		if err != nil {
			t.Fatalf("GetMachine: %v", err)
		}
		if fetched.ConsecutiveFailures != attempt {
			t.Errorf("ConsecutiveFailures = %d, want %d", fetched.ConsecutiveFailures, attempt)
		}
		if fetched.LastError != "connection refused" {
			t.Errorf("LastError = %q, want %q", fetched.LastError, "connection refused")
		}
		if fetched.LastOKAt == nil || !fetched.LastOKAt.Equal(okAt) {
			t.Errorf("failure moved LastOKAt to %v, want it left at %v", fetched.LastOKAt, okAt)
		}
		if fetched.LastScrapeAt == nil || !fetched.LastScrapeAt.Equal(failAt) {
			t.Errorf("LastScrapeAt = %v, want %v", fetched.LastScrapeAt, failAt)
		}
	}

	recoverAt := failAt.Add(time.Minute)
	if err := store.RecordScrapeSuccess(ctx, machine.ID, recoverAt); err != nil {
		t.Fatalf("RecordScrapeSuccess after failures: %v", err)
	}
	fetched, err = store.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if fetched.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after success, want 0", fetched.ConsecutiveFailures)
	}
	if fetched.LastError != "" {
		t.Errorf("LastError = %q after success, want empty", fetched.LastError)
	}
	if fetched.LastOKAt == nil || !fetched.LastOKAt.Equal(recoverAt) {
		t.Errorf("LastOKAt = %v, want %v", fetched.LastOKAt, recoverAt)
	}
}

func TestCounterStatesRoundTrip(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")
	other := createMachine(t, store, "beta")

	states := map[string]float64{
		SeriesPrefixTotal + "opens":      12,
		SeriesPrefixTotal + "bytes_sent": 4096.5,
		SeriesPrefixClient + "1.2.3.4":   7,
	}
	if err := store.SaveCounterStates(ctx, machine.ID, states, baseTime); err != nil {
		t.Fatalf("SaveCounterStates: %v", err)
	}
	if err := store.SaveCounterStates(ctx, other.ID, map[string]float64{"total:opens": 99}, baseTime); err != nil {
		t.Fatalf("SaveCounterStates for other machine: %v", err)
	}

	loaded, err := store.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatalf("LoadCounterStates: %v", err)
	}
	if len(loaded) != len(states) {
		t.Fatalf("LoadCounterStates returned %d series, want %d", len(loaded), len(states))
	}
	for series, want := range states {
		assertFloat(t, "series "+series, loaded[series], want)
	}

	states[SeriesPrefixTotal+"opens"] = 20
	if err := store.SaveCounterStates(ctx, machine.ID, states, baseTime.Add(time.Minute)); err != nil {
		t.Fatalf("SaveCounterStates update: %v", err)
	}
	loaded, err = store.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatalf("LoadCounterStates after update: %v", err)
	}
	if len(loaded) != len(states) {
		t.Errorf("upsert duplicated series: got %d, want %d", len(loaded), len(states))
	}
	assertFloat(t, "updated total:opens", loaded[SeriesPrefixTotal+"opens"], 20)

	empty, err := store.LoadCounterStates(ctx, machine.ID+9999)
	if err != nil {
		t.Fatalf("LoadCounterStates unknown machine: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("LoadCounterStates for unknown machine returned %d rows", len(empty))
	}
}

func TestApplyScrapeAccumulates(t *testing.T) {
	store, _ := newStore(t)
	machine := createMachine(t, store, "alpha")
	bucket := baseTime.Unix()

	applyScrape(t, store, ScrapeDelta{
		MachineID:      machine.ID,
		At:             baseTime.Add(30 * time.Second),
		Opens:          4,
		Closes:         1,
		BytesSent:      400,
		TrappedSeconds: 12,
		Attackers: []AttackerDelta{{
			IPAddress:      "1.2.3.4",
			Connections:    2,
			TrappedSeconds: 8,
			Country:        "US",
			Geohash:        "9q8y",
			Location:       "San Francisco",
			Active:         true,
		}},
	})

	assertInt(t, "rollup rows", scanInt(t, store, "SELECT COUNT(*) FROM machine_rollups"), 1)
	assertInt(t, "rollup bucket", scanInt(t, store, "SELECT bucket FROM machine_rollups"), bucket)
	assertInt(t, "rollup opens", scanInt(t, store, "SELECT opens FROM machine_rollups"), 4)
	assertInt(t, "totals opens", scanInt(t, store, "SELECT opens FROM machine_totals WHERE machine_id = ?", machine.ID), 4)
	assertInt(t, "distinct attacker rows", scanInt(t, store, "SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID), 1)
	assertInt(t, "attacker rows", scanInt(t, store, "SELECT COUNT(*) FROM attackers"), 1)
	assertInt(t, "attacker first_seen", scanInt(t, store,
		"SELECT first_seen FROM attackers WHERE ip_address = '1.2.3.4'"), baseTime.Add(30*time.Second).Unix())

	// A second scrape inside the same minute must fold into the same rollup row.
	applyScrape(t, store, ScrapeDelta{
		MachineID:      machine.ID,
		At:             baseTime.Add(45 * time.Second),
		Opens:          3,
		Closes:         2,
		BytesSent:      100,
		TrappedSeconds: 6,
		Attackers: []AttackerDelta{
			{IPAddress: "1.2.3.4", Connections: 1, TrappedSeconds: 4, Active: true},
			{IPAddress: "5.6.7.8", Connections: 9, TrappedSeconds: 3, Country: "DE", Active: false},
		},
	})

	assertInt(t, "rollup rows after same-minute scrape",
		scanInt(t, store, "SELECT COUNT(*) FROM machine_rollups"), 1)
	assertInt(t, "summed rollup opens", scanInt(t, store, "SELECT opens FROM machine_rollups"), 7)
	assertInt(t, "summed rollup closes", scanInt(t, store, "SELECT closes FROM machine_rollups"), 3)
	assertInt(t, "summed rollup bytes", scanInt(t, store, "SELECT bytes_sent FROM machine_rollups"), 500)
	assertFloat(t, "summed rollup trapped", scanFloat(t, store, "SELECT trapped_seconds FROM machine_rollups"), 18)

	assertInt(t, "totals opens", scanInt(t, store, "SELECT opens FROM machine_totals WHERE machine_id = ?", machine.ID), 7)
	assertInt(t, "totals bytes", scanInt(t, store, "SELECT bytes_sent FROM machine_totals WHERE machine_id = ?", machine.ID), 500)
	assertFloat(t, "totals trapped", scanFloat(t, store, "SELECT trapped_seconds FROM machine_totals WHERE machine_id = ?", machine.ID), 18)

	assertInt(t, "attacker rows", scanInt(t, store, "SELECT COUNT(*) FROM attackers"), 2)
	assertInt(t, "distinct attacker rows", scanInt(t, store, "SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID), 2)

	assertInt(t, "repeat attacker connections", scanInt(t, store,
		"SELECT connections FROM attackers WHERE ip_address = '1.2.3.4'"), 3)
	assertFloat(t, "repeat attacker trapped", scanFloat(t, store,
		"SELECT trapped_seconds FROM attackers WHERE ip_address = '1.2.3.4'"), 12)
	assertInt(t, "repeat attacker first_seen unchanged", scanInt(t, store,
		"SELECT first_seen FROM attackers WHERE ip_address = '1.2.3.4'"), baseTime.Add(30*time.Second).Unix())
	assertInt(t, "repeat attacker last_seen", scanInt(t, store,
		"SELECT last_seen FROM attackers WHERE ip_address = '1.2.3.4'"), baseTime.Add(45*time.Second).Unix())
	assertInt(t, "inactive attacker last_activity_at", scanInt(t, store,
		"SELECT last_activity_at FROM attackers WHERE ip_address = '5.6.7.8'"), 0)

	// A third scrape for a known IP must update its row, not add another.
	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID,
		At:        baseTime.Add(2 * time.Minute),
		Attackers: []AttackerDelta{{IPAddress: "1.2.3.4", Connections: 1, Active: true}},
	})
	assertInt(t, "distinct attackers after repeat IP",
		scanInt(t, store, "SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID), 2)
	assertInt(t, "rollup rows for attacker-only scrape",
		scanInt(t, store, "SELECT COUNT(*) FROM machine_rollups"), 1)
}

func TestApplyScrapeKeepsKnownGeographyWhenNewValueIsEmpty(t *testing.T) {
	store, _ := newStore(t)
	machine := createMachine(t, store, "alpha")

	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID,
		At:        baseTime,
		Attackers: []AttackerDelta{{
			IPAddress: "9.9.9.9",
			Country:   "US",
			Geohash:   "9q8y",
			Location:  "San Francisco",
			Active:    true,
		}},
	})

	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID,
		At:        baseTime.Add(time.Minute),
		Attackers: []AttackerDelta{{IPAddress: "9.9.9.9", Connections: 1, Active: true}},
	})

	if country := scanText(t, store, "SELECT country FROM attackers WHERE ip_address = '9.9.9.9'"); country != "US" {
		t.Errorf("country = %q after empty update, want it preserved as US", country)
	}
	if geohash := scanText(t, store, "SELECT geohash FROM attackers WHERE ip_address = '9.9.9.9'"); geohash != "9q8y" {
		t.Errorf("geohash = %q after empty update, want it preserved", geohash)
	}
	if location := scanText(t, store, "SELECT location FROM attackers WHERE ip_address = '9.9.9.9'"); location != "San Francisco" {
		t.Errorf("location = %q after empty update, want it preserved", location)
	}

	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID,
		At:        baseTime.Add(2 * time.Minute),
		Attackers: []AttackerDelta{{IPAddress: "9.9.9.9", Country: "DE", Location: "Berlin", Active: true}},
	})
	if country := scanText(t, store, "SELECT country FROM attackers WHERE ip_address = '9.9.9.9'"); country != "DE" {
		t.Errorf("country = %q, want it overwritten with DE", country)
	}
	if location := scanText(t, store, "SELECT location FROM attackers WHERE ip_address = '9.9.9.9'"); location != "Berlin" {
		t.Errorf("location = %q, want it overwritten with Berlin", location)
	}
	if geohash := scanText(t, store, "SELECT geohash FROM attackers WHERE ip_address = '9.9.9.9'"); geohash != "9q8y" {
		t.Errorf("geohash = %q, want the known value kept when the new one is empty", geohash)
	}
}

func TestOverview(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	outsideWindow := baseTime.Add(-2 * time.Hour)
	insideWindow := baseTime.Add(10 * time.Minute)
	since := baseTime
	activeSince := insideWindow.Add(-time.Minute)

	applyScrape(t, store, ScrapeDelta{
		MachineID: alpha.ID, At: outsideWindow,
		Opens: 10, BytesSent: 100, TrappedSeconds: 60,
		Attackers: []AttackerDelta{{IPAddress: "1.1.1.1", Connections: 1, TrappedSeconds: 60, Active: false}},
	})
	applyScrape(t, store, ScrapeDelta{
		MachineID: alpha.ID, At: insideWindow,
		Opens: 5, BytesSent: 50, TrappedSeconds: 30,
		Attackers: []AttackerDelta{
			{IPAddress: "2.2.2.2", Connections: 2, TrappedSeconds: 30, Active: true},
			// Seen in the same scrape as 2.2.2.2 but no longer accruing trapped
			// time: only last_activity_at separates it from a trapped client.
			{IPAddress: "4.4.4.4", Connections: 1, Active: false},
		},
	})
	applyScrape(t, store, ScrapeDelta{
		MachineID: beta.ID, At: insideWindow,
		Opens: 1, BytesSent: 7, TrappedSeconds: 3,
		Attackers: []AttackerDelta{{IPAddress: "3.3.3.3", Connections: 1, TrappedSeconds: 3, Active: true}},
	})

	both, err := store.Overview(ctx, []int64{alpha.ID, beta.ID}, since, activeSince)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	assertFloat(t, "lifetime TimeWastedSeconds", both.TimeWastedSeconds, 93)
	assertInt(t, "lifetime BytesSent", both.BytesSent, 157)
	assertInt(t, "lifetime AttackersTrapped", both.AttackersTrapped, 4)
	assertFloat(t, "windowed TimeWastedDeltaSeconds", both.TimeWastedDeltaSeconds, 33)
	assertInt(t, "windowed BytesSentDelta", both.BytesSentDelta, 57)
	assertInt(t, "windowed AttackersTrappedDelta", both.AttackersTrappedDelta, 3)
	// 4.4.4.4 was seen just as recently as the trapped clients, so anything
	// counting last_seen instead of last_activity_at would report 3 here.
	assertInt(t, "TrappedNow", both.TrappedNow, 2)
	if both.MachineCount != 2 {
		t.Errorf("MachineCount = %d, want 2", both.MachineCount)
	}

	onlyAlpha, err := store.Overview(ctx, []int64{alpha.ID}, since, activeSince)
	if err != nil {
		t.Fatalf("Overview for one machine: %v", err)
	}
	assertFloat(t, "alpha lifetime TimeWastedSeconds", onlyAlpha.TimeWastedSeconds, 90)
	assertInt(t, "alpha lifetime BytesSent", onlyAlpha.BytesSent, 150)
	assertInt(t, "alpha lifetime AttackersTrapped", onlyAlpha.AttackersTrapped, 3)
	assertFloat(t, "alpha windowed TimeWastedDeltaSeconds", onlyAlpha.TimeWastedDeltaSeconds, 30)
	assertInt(t, "alpha windowed AttackersTrappedDelta", onlyAlpha.AttackersTrappedDelta, 2)
	assertInt(t, "alpha TrappedNow", onlyAlpha.TrappedNow, 1)

	// Nothing counts as trapped once the activity window has moved past it.
	later, err := store.Overview(ctx, []int64{alpha.ID, beta.ID}, since, insideWindow.Add(time.Minute))
	if err != nil {
		t.Fatalf("Overview with later activeSince: %v", err)
	}
	assertInt(t, "TrappedNow after the window moved on", later.TrappedNow, 0)
	assertFloat(t, "lifetime totals are unaffected by activeSince", later.TimeWastedSeconds, 93)

	empty, err := store.Overview(ctx, nil, since, activeSince)
	if err != nil {
		t.Fatalf("Overview with no machines: %v", err)
	}
	if empty != (Overview{}) {
		t.Errorf("Overview with no machines = %+v, want the zero value", empty)
	}
}

func TestTrappedNowByMachine(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "1.1.1.1", Active: true},
		{IPAddress: "1.1.1.2", Active: true},
		{IPAddress: "1.1.1.3", Active: false},
	}})
	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "2.2.2.1", Active: true},
	}})

	counts, err := store.TrappedNowByMachine(ctx, baseTime.Add(-time.Minute))
	if err != nil {
		t.Fatalf("TrappedNowByMachine: %v", err)
	}
	if counts[alpha.ID] != 2 {
		t.Errorf("alpha trapped now = %d, want 2", counts[alpha.ID])
	}
	if counts[beta.ID] != 1 {
		t.Errorf("beta trapped now = %d, want 1", counts[beta.ID])
	}
}

func TestTimeSeriesIsDenseAndAligned(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	const bucketSeconds = 300
	from := baseTime
	to := baseTime.Add(20 * time.Minute)

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: from.Add(30 * time.Second), Opens: 5, BytesSent: 50, TrappedSeconds: 1})
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: from.Add(3 * time.Minute), Opens: 7, BytesSent: 70, TrappedSeconds: 2})
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: from.Add(11 * time.Minute), Opens: 3, BytesSent: 30, TrappedSeconds: 4})
	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: from.Add(20*time.Minute + 10*time.Second), Opens: 9, BytesSent: 90, TrappedSeconds: 8})
	// Outside the requested range: must not appear anywhere.
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: to.Add(30 * time.Minute), Opens: 1000, BytesSent: 1000, TrappedSeconds: 1000})

	series, err := store.TimeSeries(ctx, []Machine{alpha, beta}, from, to, bucketSeconds)
	if err != nil {
		t.Fatalf("TimeSeries: %v", err)
	}
	if len(series) != 2 {
		t.Fatalf("TimeSeries returned %d series, want one per machine", len(series))
	}

	wantPoints := 5
	for _, machineSeries := range series {
		if len(machineSeries.Points) != wantPoints {
			t.Fatalf("series %q has %d points, want %d", machineSeries.MachineName, len(machineSeries.Points), wantPoints)
		}
	}
	for index := range series[0].Points {
		if !series[0].Points[index].At.Equal(series[1].Points[index].At) {
			t.Errorf("point %d timestamps differ: %v vs %v",
				index, series[0].Points[index].At, series[1].Points[index].At)
		}
		want := from.Add(time.Duration(index) * bucketSeconds * time.Second)
		if !series[0].Points[index].At.Equal(want) {
			t.Errorf("point %d at %v, want %v", index, series[0].Points[index].At, want)
		}
	}

	if series[0].MachineID != alpha.ID || series[0].MachineName != "alpha" {
		t.Errorf("first series = %d/%q, want alpha", series[0].MachineID, series[0].MachineName)
	}

	wantAlphaOpens := []int64{12, 0, 3, 0, 0}
	wantAlphaTrapped := []float64{3, 0, 4, 0, 0}
	for index, want := range wantAlphaOpens {
		assertInt(t, "alpha opens bucket", series[0].Points[index].Opens, want)
		assertFloat(t, "alpha trapped bucket", series[0].Points[index].TrappedSeconds, wantAlphaTrapped[index])
	}

	wantBetaOpens := []int64{0, 0, 0, 0, 9}
	for index, want := range wantBetaOpens {
		assertInt(t, "beta opens bucket", series[1].Points[index].Opens, want)
	}
	assertInt(t, "beta bytes in last bucket", series[1].Points[4].BytesSent, 90)

	if none, err := store.TimeSeries(ctx, nil, from, to, bucketSeconds); err != nil || none != nil {
		t.Errorf("TimeSeries with no machines = %v, %v, want nil, nil", none, err)
	}
	if none, err := store.TimeSeries(ctx, []Machine{alpha}, from, to, 0); err != nil || none != nil {
		t.Errorf("TimeSeries with zero bucket = %v, %v, want nil, nil", none, err)
	}
}

func TestRecentActivityByMachine(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")
	silent := createMachine(t, store, "silent")

	const (
		bucketSeconds = 300
		buckets       = 12
	)
	// baseTime is bucket-aligned, so it is the newest bucket; the window reaches
	// back the eleven buckets before it.
	newestBucket := baseTime
	oldestBucket := newestBucket.Add(-(buckets - 1) * bucketSeconds * time.Second)
	// Reading two minutes into the newest bucket: it is still forming, and its
	// traffic must be reported anyway.
	now := newestBucket.Add(2 * time.Minute)

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: oldestBucket.Add(30 * time.Second), TrappedSeconds: 1.5})
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: oldestBucket.Add(4 * time.Minute), TrappedSeconds: 2.5})
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: now, TrappedSeconds: 7})
	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: oldestBucket.Add(30 * time.Minute), TrappedSeconds: 3})
	// One minute before the window opens: it must not leak into the first bucket.
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: oldestBucket.Add(-time.Minute), TrappedSeconds: 99})

	activity, err := store.RecentActivityByMachine(ctx, now, bucketSeconds, buckets)
	if err != nil {
		t.Fatalf("RecentActivityByMachine: %v", err)
	}

	expected := []struct {
		machine Machine
		want    []float64
	}{
		{alpha, []float64{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}},
		{beta, []float64{0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0}},
		// A machine with no rows may be absent from the map, but it must never
		// report traffic.
		{silent, make([]float64, buckets)},
	}
	for _, expectation := range expected {
		got := activity[expectation.machine.ID]
		if expectation.machine.ID != silent.ID && len(got) != buckets {
			t.Fatalf("%s has %d buckets, want %d", expectation.machine.Name, len(got), buckets)
		}
		for index, value := range got {
			assertFloat(t, fmt.Sprintf("%s bucket %d", expectation.machine.Name, index),
				value, expectation.want[index])
		}
	}

	if none, err := store.RecentActivityByMachine(ctx, now, 0, buckets); err != nil || none != nil {
		t.Errorf("RecentActivityByMachine with a zero bucket = %v, %v, want nil, nil", none, err)
	}
	if none, err := store.RecentActivityByMachine(ctx, now, bucketSeconds, 0); err != nil || none != nil {
		t.Errorf("RecentActivityByMachine with no buckets = %v, %v, want nil, nil", none, err)
	}
}

// TestRecentActivityByMachineCoversTheNewestBucket pins the bug the wide-bucket
// upper bound exists for: a filter stopping at the aligned minute keeps only
// traffic from that one minute and drops the rest of the newest bucket.
func TestRecentActivityByMachineCoversTheNewestBucket(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	const (
		bucketSeconds = 300
		buckets       = 12
	)
	newestBucket := baseTime
	for minute := 1; minute < 5; minute++ {
		applyScrape(t, store, ScrapeDelta{
			MachineID:      machine.ID,
			At:             newestBucket.Add(time.Duration(minute) * time.Minute),
			TrappedSeconds: 10,
		})
	}

	activity, err := store.RecentActivityByMachine(ctx, newestBucket.Add(4*time.Minute+59*time.Second), bucketSeconds, buckets)
	if err != nil {
		t.Fatalf("RecentActivityByMachine: %v", err)
	}
	series := activity[machine.ID]
	if len(series) != buckets {
		t.Fatalf("got %d buckets, want %d", len(series), buckets)
	}
	assertFloat(t, "newest bucket", series[buckets-1], 40)
}

// TestRecentActivityByMachineLengthIsAlwaysTheBucketCount checks the dense
// promise across bucket counts, not just the twelve the API asks for.
func TestRecentActivityByMachineLengthIsAlwaysTheBucketCount(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, TrappedSeconds: 5})

	for _, buckets := range []int{1, 3, 12, 60} {
		activity, err := store.RecentActivityByMachine(ctx, baseTime, 300, buckets)
		if err != nil {
			t.Fatalf("RecentActivityByMachine with %d buckets: %v", buckets, err)
		}
		if got := len(activity[machine.ID]); got != buckets {
			t.Errorf("asked for %d buckets, got %d values", buckets, got)
		}
	}
}

// attackerFixture seeds one machine with four clients whose countries, IPs,
// activity and trapped time make every ListAttackers filter observable.
func attackerFixture(t *testing.T, store *Store) (Machine, time.Time) {
	t.Helper()
	machine := createMachine(t, store, "alpha")
	activeSince := baseTime.Add(-time.Minute)

	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "10.0.0.1", Connections: 3, TrappedSeconds: 100, Country: "US", Active: true},
		{IPAddress: "10.0.0.2", Connections: 5, TrappedSeconds: 50, Country: "DE", Active: false},
		{IPAddress: "192.168.0.9", Connections: 1, TrappedSeconds: 200, Country: "US", Active: true},
		{IPAddress: "172.16.0.4", Connections: 2, TrappedSeconds: 10, Active: false},
	}})
	return machine, activeSince
}

func attackerIPs(page AttackerPage) []string {
	ips := make([]string, len(page.Rows))
	for index, row := range page.Rows {
		ips[index] = row.IPAddress
	}
	return ips
}

func TestListAttackers(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine, activeSince := attackerFixture(t, store)

	tests := []struct {
		name      string
		filter    AttackerFilter
		wantIPs   []string
		wantTotal int
	}{
		{
			name:      "default sort is trapped_seconds ascending",
			filter:    AttackerFilter{},
			wantIPs:   []string{"172.16.0.4", "10.0.0.2", "10.0.0.1", "192.168.0.9"},
			wantTotal: 4,
		},
		{
			name:      "sort by trapped_seconds descending",
			filter:    AttackerFilter{SortColumn: "trapped_seconds", SortDescending: true},
			wantIPs:   []string{"192.168.0.9", "10.0.0.1", "10.0.0.2", "172.16.0.4"},
			wantTotal: 4,
		},
		{
			name:      "sort by connections",
			filter:    AttackerFilter{SortColumn: "connections"},
			wantIPs:   []string{"192.168.0.9", "172.16.0.4", "10.0.0.1", "10.0.0.2"},
			wantTotal: 4,
		},
		{
			name:      "unknown sort column falls back to the default",
			filter:    AttackerFilter{SortColumn: "trapped_seconds DESC; DROP TABLE attackers --"},
			wantIPs:   []string{"172.16.0.4", "10.0.0.2", "10.0.0.1", "192.168.0.9"},
			wantTotal: 4,
		},
		{
			name:      "filter by country",
			filter:    AttackerFilter{Country: "US"},
			wantIPs:   []string{"10.0.0.1", "192.168.0.9"},
			wantTotal: 2,
		},
		{
			name:      "filter by country with no matches",
			filter:    AttackerFilter{Country: "FR"},
			wantIPs:   nil,
			wantTotal: 0,
		},
		{
			name:      "status trapped",
			filter:    AttackerFilter{Status: StatusTrapped},
			wantIPs:   []string{"10.0.0.1", "192.168.0.9"},
			wantTotal: 2,
		},
		{
			name:      "status gave up",
			filter:    AttackerFilter{Status: StatusGaveUp},
			wantIPs:   []string{"172.16.0.4", "10.0.0.2"},
			wantTotal: 2,
		},
		{
			name:      "search by IP prefix",
			filter:    AttackerFilter{Search: "10.0."},
			wantIPs:   []string{"10.0.0.2", "10.0.0.1"},
			wantTotal: 2,
		},
		{
			name:      "a percent in the search matches nothing special",
			filter:    AttackerFilter{Search: "%"},
			wantIPs:   []string{"172.16.0.4", "10.0.0.2", "10.0.0.1", "192.168.0.9"},
			wantTotal: 4,
		},
		{
			// Unescaped, "10_0.0.1" would wildcard the underscore and match
			// 10.0.0.1; escaped, it is a literal that matches no IP at all.
			name:      "an underscore in the search is not a wildcard",
			filter:    AttackerFilter{Search: "10_0.0.1"},
			wantIPs:   nil,
			wantTotal: 0,
		},
		{
			name:      "a backslash in the search matches nothing special",
			filter:    AttackerFilter{Search: `10\.0`},
			wantIPs:   []string{"10.0.0.2", "10.0.0.1"},
			wantTotal: 2,
		},
		{
			// Search anchors at the start: "0.0.1" is inside 10.0.0.1 but is
			// not a prefix of it.
			name:      "search is a prefix match, not a substring match",
			filter:    AttackerFilter{Search: "0.0.1"},
			wantIPs:   nil,
			wantTotal: 0,
		},
		{
			name:      "since excludes older clients",
			filter:    AttackerFilter{Since: baseTime.Add(time.Hour)},
			wantIPs:   nil,
			wantTotal: 0,
		},
		{
			name:      "since includes the boundary",
			filter:    AttackerFilter{Since: baseTime},
			wantIPs:   []string{"172.16.0.4", "10.0.0.2", "10.0.0.1", "192.168.0.9"},
			wantTotal: 4,
		},
		{
			name:      "country and status combine",
			filter:    AttackerFilter{Country: "US", Status: StatusGaveUp},
			wantIPs:   nil,
			wantTotal: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := test.filter
			filter.MachineIDs = []int64{machine.ID}
			filter.ActiveSince = activeSince
			filter.Page = 1
			filter.PerPage = 10

			page, err := store.ListAttackers(ctx, filter)
			if err != nil {
				t.Fatalf("ListAttackers: %v", err)
			}
			if page.Total != test.wantTotal {
				t.Errorf("Total = %d, want %d", page.Total, test.wantTotal)
			}
			got := attackerIPs(page)
			if strings.Join(got, ",") != strings.Join(test.wantIPs, ",") {
				t.Errorf("rows = %v, want %v", got, test.wantIPs)
			}
		})
	}

	// The injection attempt above must not have executed as SQL.
	assertInt(t, "attackers still present", scanInt(t, store, "SELECT COUNT(*) FROM attackers"), 4)
}

func TestListAttackersRowFields(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine, activeSince := attackerFixture(t, store)

	page, err := store.ListAttackers(ctx, AttackerFilter{
		MachineIDs:  []int64{machine.ID},
		ActiveSince: activeSince,
		Search:      "192.168.0.9",
		Page:        1,
		PerPage:     10,
	})
	if err != nil {
		t.Fatalf("ListAttackers: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(page.Rows))
	}
	row := page.Rows[0]
	if row.MachineName != "alpha" || row.MachineID != machine.ID {
		t.Errorf("machine = %d/%q, want %d/alpha", row.MachineID, row.MachineName, machine.ID)
	}
	if row.Country != "US" || row.Connections != 1 {
		t.Errorf("row = %+v, want country US and 1 connection", row)
	}
	assertFloat(t, "row TrappedSeconds", row.TrappedSeconds, 200)
	if row.Status != StatusTrapped {
		t.Errorf("Status = %q, want %q", row.Status, StatusTrapped)
	}
	if !row.FirstSeen.Equal(baseTime) || !row.LastSeen.Equal(baseTime) {
		t.Errorf("timestamps = %v/%v, want %v", row.FirstSeen, row.LastSeen, baseTime)
	}

	gaveUp, err := store.ListAttackers(ctx, AttackerFilter{
		MachineIDs:  []int64{machine.ID},
		ActiveSince: activeSince,
		Search:      "10.0.0.2",
		Page:        1,
		PerPage:     10,
	})
	if err != nil {
		t.Fatalf("ListAttackers: %v", err)
	}
	if len(gaveUp.Rows) != 1 || gaveUp.Rows[0].Status != StatusGaveUp {
		t.Errorf("rows = %+v, want a single gave_up row", gaveUp.Rows)
	}

	if page, err := store.ListAttackers(ctx, AttackerFilter{ActiveSince: activeSince, Page: 1, PerPage: 10}); err != nil || page.Total != 0 || page.Rows != nil {
		t.Errorf("ListAttackers with no machines = %+v, %v, want an empty page", page, err)
	}
}

func TestListAttackersPagination(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine, activeSince := attackerFixture(t, store)

	base := AttackerFilter{
		MachineIDs:     []int64{machine.ID},
		ActiveSince:    activeSince,
		SortColumn:     "trapped_seconds",
		SortDescending: true,
		PerPage:        2,
	}

	first := base
	first.Page = 1
	firstPage, err := store.ListAttackers(ctx, first)
	if err != nil {
		t.Fatalf("ListAttackers page 1: %v", err)
	}
	if firstPage.Total != 4 {
		t.Errorf("Total = %d, want the unpaginated count of 4", firstPage.Total)
	}
	if firstPage.PerPage != 2 || firstPage.Page != 1 {
		t.Errorf("page metadata = %d/%d, want 1/2", firstPage.Page, firstPage.PerPage)
	}
	if got := strings.Join(attackerIPs(firstPage), ","); got != "192.168.0.9,10.0.0.1" {
		t.Errorf("page 1 = %s, want 192.168.0.9,10.0.0.1", got)
	}

	second := base
	second.Page = 2
	secondPage, err := store.ListAttackers(ctx, second)
	if err != nil {
		t.Fatalf("ListAttackers page 2: %v", err)
	}
	if secondPage.Total != 4 {
		t.Errorf("page 2 Total = %d, want 4", secondPage.Total)
	}
	if got := strings.Join(attackerIPs(secondPage), ","); got != "10.0.0.2,172.16.0.4" {
		t.Errorf("page 2 = %s, want 10.0.0.2,172.16.0.4", got)
	}

	third := base
	third.Page = 3
	thirdPage, err := store.ListAttackers(ctx, third)
	if err != nil {
		t.Fatalf("ListAttackers page 3: %v", err)
	}
	if len(thirdPage.Rows) != 0 || thirdPage.Total != 4 {
		t.Errorf("page 3 = %+v, want no rows but Total 4", thirdPage)
	}
}

func TestUsers(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	count, err := store.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 0 {
		t.Fatalf("CountUsers on a fresh database = %d, want 0", count)
	}

	created, err := store.CreateUser(ctx, User{
		Username:           "admin",
		PasswordHash:       "hash-one",
		MustChangePassword: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("CreateUser returned a zero id")
	}

	count, err = store.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 1 {
		t.Errorf("CountUsers = %d, want 1", count)
	}

	byName, err := store.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if byName.ID != created.ID || byName.PasswordHash != "hash-one" || !byName.MustChangePassword {
		t.Errorf("GetUserByUsername = %+v, want the created user", byName)
	}

	byID, err := store.GetUserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Username != "admin" {
		t.Errorf("GetUserByID = %+v, want admin", byID)
	}

	if _, err := store.GetUserByUsername(ctx, "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetUserByUsername unknown = %v, want ErrUserNotFound", err)
	}
	if _, err := store.GetUserByID(ctx, created.ID+9999); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetUserByID unknown = %v, want ErrUserNotFound", err)
	}

	if err := store.UpdateUserPassword(ctx, created.ID, "hash-two", false); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	updated, err := store.GetUserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUserByID after update: %v", err)
	}
	if updated.PasswordHash != "hash-two" || updated.MustChangePassword {
		t.Errorf("after UpdateUserPassword = %+v, want hash-two and MustChangePassword false", updated)
	}

	if err := store.UpdateUserPassword(ctx, created.ID+9999, "x", false); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("UpdateUserPassword unknown = %v, want ErrUserNotFound", err)
	}
}

func TestSessions(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, User{Username: "admin", PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	other, err := store.CreateUser(ctx, User{Username: "second", PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := baseTime
	live := Session{
		TokenHash: "live-token",
		UserID:    user.ID,
		CSRFToken: "csrf-live",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	expired := Session{
		TokenHash: "expired-token",
		UserID:    user.ID,
		CSRFToken: "csrf-expired",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}
	otherUsers := Session{
		TokenHash: "other-token",
		UserID:    other.ID,
		CSRFToken: "csrf-other",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	for _, session := range []Session{live, expired, otherUsers} {
		if err := store.CreateSession(ctx, session); err != nil {
			t.Fatalf("CreateSession(%s): %v", session.TokenHash, err)
		}
	}

	session, owner, err := store.GetSession(ctx, "live-token", now)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if session.CSRFToken != "csrf-live" || session.UserID != user.ID {
		t.Errorf("session = %+v, want the live session", session)
	}
	if !session.ExpiresAt.Equal(now.Add(time.Hour)) || !session.CreatedAt.Equal(now) {
		t.Errorf("session timestamps = %v/%v", session.CreatedAt, session.ExpiresAt)
	}
	if owner.ID != user.ID || owner.Username != "admin" {
		t.Errorf("owner = %+v, want admin", owner)
	}

	if _, _, err := store.GetSession(ctx, "expired-token", now); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetSession expired = %v, want ErrSessionNotFound", err)
	}
	if _, _, err := store.GetSession(ctx, "unknown-token", now); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetSession unknown = %v, want ErrSessionNotFound", err)
	}
	if _, _, err := store.GetSession(ctx, "live-token", now.Add(2*time.Hour)); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetSession past expiry = %v, want ErrSessionNotFound", err)
	}

	removed, err := store.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	assertInt(t, "DeleteExpiredSessions count", removed, 1)
	assertInt(t, "sessions left after expiry sweep",
		scanInt(t, store, "SELECT COUNT(*) FROM sessions"), 2)

	if err := store.DeleteSession(ctx, "live-token"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, _, err := store.GetSession(ctx, "live-token", now); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetSession after delete = %v, want ErrSessionNotFound", err)
	}
	if err := store.DeleteSession(ctx, "live-token"); err != nil {
		t.Errorf("deleting a missing session = %v, want nil", err)
	}

	for _, token := range []string{"a", "b"} {
		if err := store.CreateSession(ctx, Session{
			TokenHash: token, UserID: user.ID, CSRFToken: token,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("CreateSession(%s): %v", token, err)
		}
	}
	if err := store.DeleteSessionsForUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteSessionsForUser: %v", err)
	}
	assertInt(t, "sessions left for the user",
		scanInt(t, store, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", user.ID), 0)
	assertInt(t, "other user's session survives",
		scanInt(t, store, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", other.ID), 1)
}
