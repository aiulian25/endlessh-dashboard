package scrape

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func clientPorts(opens, times map[string]float64) string {
	var b strings.Builder
	for port, value := range opens {
		fmt.Fprintf(&b, "endlessh_client_open_count{ip=\"192.0.2.1\",local_port=\"%s\"} %g\n", port, value)
	}
	for port, value := range times {
		fmt.Fprintf(&b, "endlessh_client_trapped_time_seconds{ip=\"192.0.2.1\",local_port=\"%s\"} %g\n", port, value)
	}
	return b.String()
}

func TestClientPortResetAndMissingFamilies(t *testing.T) {
	db := newTestStore(t)
	p := newTestPoller(t, db)
	ctx := context.Background()
	machine, err := db.CreateMachine(ctx, store.Machine{Name: "ports", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(opens, times map[string]float64) {
		t.Helper()
		snapshot, e := Parse(strings.NewReader(clientPorts(opens, times)))
		if e != nil {
			t.Fatal(e)
		}
		if e = p.applySnapshot(ctx, machine, time.Now().UTC(), snapshot); e != nil {
			t.Fatal(e)
		}
	}
	apply(map[string]float64{"22": 10, "2222": 90}, map[string]float64{"22": 10.5, "2222": 90.5})
	apply(map[string]float64{"22": 0, "2222": 110}, map[string]float64{"22": 0, "2222": 110.5})
	row := readAttacker(t, db, machine.ID, "192.0.2.1")
	if row.Connections != 120 || row.TrappedSeconds != 121 {
		t.Fatalf("independent port reset: %+v", row)
	}
	// Missing opens must not replace the last raw opens readings with zero.
	apply(nil, map[string]float64{"22": 0, "2222": 110.5})
	before, e := db.LoadCounterStates(ctx, machine.ID)
	if e != nil {
		t.Fatal(e)
	}
	if before[RawClientSeriesKey(MetricClientOpenCount, "192.0.2.1", "2222")] != 110 {
		t.Fatal("missing family overwrote baseline")
	}
	// Recreate the poller to prove absence/reappearance continuity is persisted.
	p = newTestPoller(t, db)
	apply(map[string]float64{"22": 0, "2222": 110}, nil)
	apply(map[string]float64{"2222": 110}, map[string]float64{"2222": 110.5})
	apply(map[string]float64{"22": 0, "2222": 110}, map[string]float64{"22": 0, "2222": 110.5})
	after := readAttacker(t, db, machine.ID, "192.0.2.1")
	if after.Connections != row.Connections || after.TrappedSeconds != row.TrappedSeconds {
		t.Fatalf("reappearance reimported history: %+v", after)
	}
	// A returning port below its retained reading is an observed reset.
	apply(map[string]float64{"2222": 2}, nil)
	if got := readAttacker(t, db, machine.ID, "192.0.2.1").Connections; got != 122 {
		t.Fatalf("reset after absence = %d", got)
	}
	// A reset that catches up above 2 is indistinguishable from ordinary growth.
	apply(map[string]float64{"2222": 5}, nil)
	if got := readAttacker(t, db, machine.ID, "192.0.2.1").Connections; got != 125 {
		t.Fatalf("above-baseline observation = %d", got)
	}
}

func TestClientPresenceAndConflictingDuplicates(t *testing.T) {
	aliases, err := Parse(strings.NewReader("endlessh_client_open_count{ip=\"2001:0db8::1\",local_port=\"22\"} 7\nendlessh_client_trapped_time_seconds{ip=\"2001:db8::1\",local_port=\"22\"} 12.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases.Clients) != 1 || len(aliases.ClientSeries) != 2 {
		t.Fatal("canonical raw IP was split across fields")
	}

	for _, metric := range []string{MetricClientOpenCount, MetricClientTrappedTimeSeconds} {
		payload := fmt.Sprintf("%s{ip=\"192.0.2.1\",local_port=\"22\",source=\"a\"} 7\n%s{ip=\"192.0.2.1\",local_port=\"22\",source=\"b\"} 7\n", metric, metric)
		s, err := Parse(strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(s.ClientSeries) != 1 {
			t.Fatal("identical raw series duplicated")
		}
		if _, err = Parse(strings.NewReader(strings.Replace(payload, "source=\"b\"} 7", "source=\"b\"} 8", 1))); err == nil {
			t.Fatal("conflicting series accepted")
		}
	}
	snapshot, err := Parse(strings.NewReader(clientPorts(map[string]float64{"22": 7}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ClientSeries) != 1 {
		t.Fatal("missing time became a raw zero sample")
	}
	if RawClientSeriesKey(MetricClientOpenCount, "2001:0db8::1", "22") != RawClientSeriesKey(MetricClientOpenCount, "2001:db8::1", "22") {
		t.Fatal("raw key is not canonical")
	}
}

func TestLegacyClientBaselinesUpgradeWithoutLifetimeReimport(t *testing.T) {
	db := newTestStore(t)
	ctx := context.Background()
	machine, err := db.CreateMachine(ctx, store.Machine{Name: "legacy", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seed := store.ScrapeDelta{MachineID: machine.ID, At: time.Now().UTC(), Opens: 9, BytesSent: 33, TrappedSeconds: 50,
		Attackers:     []store.AttackerDelta{{IPAddress: "192.0.2.1", Connections: 100, TrappedSeconds: 100}},
		CounterStates: map[string]float64{ClientSeriesKey(MetricClientOpenCount, "192.0.2.1"): 100, ClientSeriesKey(MetricClientTrappedTimeSeconds, "192.0.2.1"): 100, TotalSeriesKey(MetricSentBytesTotal, "22"): 100},
	}
	if err = db.ApplyScrape(ctx, seed); err != nil {
		t.Fatal(err)
	}
	totals := readTotals(t, db, machine.ID)
	// Reconstruct a genuine version-6 database before opening the upgrade path.
	if _, err = db.DB().Exec("DROP TABLE port_rollups; DROP TABLE port_collection; DELETE FROM schema_migrations WHERE version=13; DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11; DROP TABLE attacker_ip_archive; DROP TABLE counter_ip_archive; DELETE FROM schema_migrations WHERE version=10; DROP INDEX idx_attackers_measured_activity; ALTER TABLE attackers DROP COLUMN last_observed_at; ALTER TABLE attackers DROP COLUMN last_measured_activity_at; ALTER TABLE attackers DROP COLUMN has_undated_history; ALTER TABLE attackers DROP COLUMN first_observation_known; ALTER TABLE machines DROP COLUMN target_generation; ALTER TABLE machines DROP COLUMN target_changed_at_ns; ALTER TABLE machines DROP COLUMN scrape_revision; ALTER TABLE machines DROP COLUMN last_metric_sample_ns; ALTER TABLE machines DROP COLUMN last_status_sample_ns; ALTER TABLE machines DROP COLUMN client_counter_policy; DELETE FROM schema_migrations WHERE version>=7"); err != nil {
		t.Fatal(err)
	}
	var path string
	if err = db.DB().QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if policy, e := db.ClientCounterPolicy(ctx, machine.ID); e != nil || policy != "baseline_only" {
		t.Fatalf("upgrade policy = %s: %v", policy, e)
	}
	p := newTestPoller(t, db)
	apply := func(opens map[string]float64) {
		t.Helper()
		snapshot, e := Parse(strings.NewReader(clientPorts(opens, nil)))
		if e != nil {
			t.Fatal(e)
		}
		snapshot.Totals[TotalSeriesKey(MetricSentBytesTotal, "22")] = 100
		if e = p.applySnapshot(ctx, machine, time.Now().UTC(), snapshot); e != nil {
			t.Fatal(e)
		}
	}
	apply(map[string]float64{"22": 90, "2222": 10})
	if got := readAttacker(t, db, machine.ID, "192.0.2.1").Connections; got != 100 {
		t.Fatalf("upgrade imported old lifetime values: %d", got)
	}
	if got := readTotals(t, db, machine.ID); got != totals {
		t.Fatalf("upgrade changed machine history: %+v", got)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	p = newTestPoller(t, db)
	apply(map[string]float64{"22": 0, "2222": 30})
	apply(map[string]float64{"22": 0, "2222": 30, "2200": 500})
	if got := readAttacker(t, db, machine.ID, "192.0.2.1").Connections; got != 120 {
		t.Fatalf("restart/late port reimported legacy history: %d", got)
	}
	// A duration family absent at upgrade must also baseline on its late return.
	for index, times := range []map[string]float64{{"22": 90, "2222": 10}, {"22": 0, "2222": 30}} {
		snapshot, e := Parse(strings.NewReader(clientPorts(nil, times)))
		if e != nil {
			t.Fatal(e)
		}
		if e = p.applySnapshot(ctx, machine, time.Now().UTC(), snapshot); e != nil {
			t.Fatal(e)
		}
		expected := float64(100 + 20*index)
		if got := readAttacker(t, db, machine.ID, "192.0.2.1").TrappedSeconds; got != expected {
			t.Fatalf("late family imported legacy duration: %g, want %g", got, expected)
		}
	}
	newer, err := db.CreateMachine(ctx, store.Machine{Name: "new", Host: "192.0.2.2", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if policy, e := db.ClientCounterPolicy(ctx, newer.ID); e != nil || policy != "import_lifetime" {
		t.Fatalf("new machine policy = %s: %v", policy, e)
	}
}
