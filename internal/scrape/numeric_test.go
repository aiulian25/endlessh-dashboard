package scrape

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestParserRejectsInvalidNumbers(t *testing.T) {
	for _, name := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal, MetricClientOpenCount, MetricClientTrappedTimeSeconds} {
		values := []string{"NaN", "+Inf", "-Inf", "-1"}
		if integerMetric(name) {
			values = append(values, "1.5", "9007199254740992", "9223372036854775808")
		}
		for _, value := range values {
			t.Run(name+"/"+value, func(t *testing.T) {
				payload := fmt.Sprintf("# TYPE %s counter\n%s{ip=\"192.0.2.1\",local_port=\"22\"} %s\n", name, name, value)
				if _, err := Parse(strings.NewReader(payload)); err == nil {
					t.Fatal("invalid sample accepted")
				}
			})
		}
	}
	for _, kind := range []string{"gauge", "histogram", "summary"} {
		t.Run(kind, func(t *testing.T) {
			payload := fmt.Sprintf("# TYPE %s %s\n%s 1\n", MetricSentBytesTotal, kind, MetricSentBytesTotal)
			if _, err := Parse(strings.NewReader(payload)); err == nil {
				t.Fatal("non-counter family accepted")
			}
		})
	}
	// Time remains fractional; an exact count at the documented boundary is valid.
	for _, payload := range []string{
		"endlessh_sent_bytes_total 9007199254740991\n",
		"endlessh_trapped_time_seconds_total 0.125\n",
	} {
		if _, err := Parse(strings.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	// Two ports overflow a collapsed client's supported raw count range.
	if _, err := Parse(strings.NewReader("endlessh_client_open_count{ip=\"192.0.2.1\",local_port=\"22\"} 9007199254740991\nendlessh_client_open_count{ip=\"192.0.2.1\",local_port=\"2222\"} 1\n")); err == nil {
		t.Fatal("merged count overflow accepted")
	}
	if _, err := Parse(strings.NewReader("endlessh_client_trapped_time_seconds{ip=\"192.0.2.1\",local_port=\"22\"} 1e308\nendlessh_client_trapped_time_seconds{ip=\"192.0.2.1\",local_port=\"2222\"} 1e308\n")); err == nil {
		t.Fatal("merged time overflow accepted")
	}
}

func TestInvalidSnapshotDoesNotAdvanceHistory(t *testing.T) {
	db := newTestStore(t)
	p := newTestPoller(t, db)
	ctx := context.Background()
	machine, err := db.CreateMachine(ctx, store.Machine{Name: "numeric", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	initial := Snapshot{Totals: map[string]float64{TotalSeriesKey(MetricOpenCountTotal, "22"): 0}, Clients: map[string]ClientSample{}}
	if err = p.applySnapshot(ctx, machine, at, initial); err != nil {
		t.Fatal(err)
	}
	// Simulate pre-port-limit baselines rather than asking the new collector to
	// accept an oversized scrape. The cross-port integer guard must still reject
	// overflow against legacy state, without advancing any history or baseline.
	tx, err := db.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 1025; i++ {
		key := TotalSeriesKey(MetricOpenCountTotal, fmt.Sprint(i))
		initial.Totals[key] = 0
		if _, err = tx.ExecContext(ctx, `INSERT INTO counter_states(machine_id,series,value,updated_at) VALUES(?,?,0,?) ON CONFLICT DO NOTHING`, machine.ID, key, at.Unix()); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before, err := db.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []float64{math.NaN(), math.Inf(1), -1, 9007199254740992} {
		snapshot := Snapshot{Totals: map[string]float64{TotalSeriesKey(MetricSentBytesTotal, "22"): invalid}}
		if err = p.applySnapshot(ctx, machine, at, snapshot); err == nil {
			t.Fatal("invalid snapshot committed")
		}
	}
	for key := range initial.Totals {
		initial.Totals[key] = 9007199254740991
	}
	if err = p.applySnapshot(ctx, machine, at, initial); err == nil {
		t.Fatal("cross-port int64 overflow committed")
	}
	after, err := db.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("baselines changed after rejection")
	}
	for _, table := range []string{"machine_rollups", "attackers"} {
		var count int
		if err = db.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s history changed", table)
		}
	}
}
