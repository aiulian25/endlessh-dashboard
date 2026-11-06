package scrape

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func portFixture(a, b int) string {
	var out strings.Builder
	for _, entry := range []struct {
		port  string
		value int
	}{{"22", a}, {"2222", b}} {
		if entry.value < 0 {
			continue
		}
		for _, metric := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal} {
			fmt.Fprintf(&out, "# TYPE %s counter\n%s{local_port=%q} %d\n", metric, metric, entry.port, entry.value)
		}
	}
	// TYPE declarations must occur once per family in Prometheus text.
	lines := strings.Split(out.String(), "\n")
	seen := map[string]bool{}
	var clean strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, "# TYPE") {
			if seen[line] {
				continue
			}
			seen[line] = true
		}
		clean.WriteString(line + "\n")
	}
	return clean.String()
}

func TestPerPortIndependentResetMissingNewGenerationAndSums(t *testing.T) {
	db := newTestStore(t)
	m, err := db.CreateMachine(context.Background(), store.Machine{Name: "ports", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, db)
	ctx := context.Background()
	start := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	apply := func(index, a, b int) {
		snapshot, err := Parse(strings.NewReader(portFixture(a, b)))
		if err != nil {
			t.Fatal(err)
		}
		if err = p.applySnapshot(ctx, m, start.Add(time.Duration(index)*time.Minute), snapshot); err != nil {
			t.Fatal(err)
		}
	}
	apply(0, 100, 200)
	apply(1, 110, 220)
	apply(2, 3, 240) // only port 22 resets
	summary, err := db.PortSummary(ctx, []int64{m.ID}, start, start.Add(3*time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Rows) != 2 || summary.Rows[0].Opens != 13 || summary.Rows[1].Opens != 40 {
		t.Fatalf("independent deltas wrong %+v", summary)
	}
	totals := readTotals(t, db, m.ID)
	if totals.Opens != 53 || totals.BytesSent != 53 || totals.TrappedSeconds != 53 {
		t.Fatalf("machine sum wrong %+v", totals)
	}
	healthy, err := db.TimeSeriesForPort(ctx, []store.Machine{m}, start.Add(time.Minute), start.Add(2*time.Minute), 60, "2222")
	if err != nil || healthy[0].Points[0].Coverage != "complete" {
		t.Fatal("another port reset erased healthy coverage", err)
	}
	apply(3, -1, 260)
	apply(4, 8, 280) // absence and recovery, no zero invention
	recovered, err := db.TimeSeriesForPort(ctx, []store.Machine{m}, start.Add(3*time.Minute), start.Add(5*time.Minute), 60, "22")
	if err != nil {
		t.Fatal(err)
	}
	if recovered[0].Points[0].Attempts != 0 || recovered[0].Points[0].ObservedSeconds != 0 || recovered[0].Points[1].Coverage != "incomplete" {
		t.Fatalf("gap coverage fabricated %+v", recovered)
	}
	// Endpoint changes create a fresh baseline, retaining old generation rows.
	m.Host = "192.0.2.2"
	if err = db.UpdateMachine(ctx, m); err != nil {
		t.Fatal(err)
	}
	m, err = db.GetMachine(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	apply(5, 500, 600)
	apply(6, 502, 603)
	summary, err = db.PortSummary(ctx, []int64{m.ID}, start, start.Add(7*time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Rows[0].Opens != 20 || summary.Rows[1].Opens != 83 || summary.Rows[0].Generations != 2 {
		t.Fatalf("generation history wrong %+v", summary)
	}
	totals = readTotals(t, db, m.ID)
	if totals.Opens != 103 {
		t.Fatalf("generation imported lifetimes %+v", totals)
	}
	// New valid ports remain queryable without changing another port's selection.
	snapshot, err := Parse(strings.NewReader(portFixture(504, 606) + "endlessh_sent_bytes_total{local_port=\"65535\"} 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.applySnapshot(ctx, m, start.Add(7*time.Minute), snapshot); err != nil {
		t.Fatal(err)
	}
	summary, err = db.PortSummary(ctx, []int64{m.ID}, start, start.Add(8*time.Minute), "65535")
	if err != nil || len(summary.Rows) != 1 || summary.Rows[0].BytesSent != 0 {
		t.Fatal("new port must baseline, not import lifetime", err)
	}
}

func TestAggregatePortLabelBounds(t *testing.T) {
	for _, port := range []string{"0", "65536", "-1", "022", "22|extra", "x", strings.Repeat("1", 400)} {
		if _, err := Parse(strings.NewReader(fmt.Sprintf("%s{local_port=%q} 1\n", MetricOpenCountTotal, port))); err == nil {
			t.Fatalf("accepted port %q", port)
		}
	}
	var body strings.Builder
	for i := 1; i <= store.MaxScrapePorts+1; i++ {
		fmt.Fprintf(&body, "%s{local_port=%q} 1\n", MetricOpenCountTotal, fmt.Sprint(i))
	}
	if _, err := Parse(strings.NewReader(body.String())); err == nil {
		t.Fatal("unbounded port count")
	}
	if _, err := Parse(strings.NewReader(MetricOpenCountTotal + " 1\n")); err != nil {
		t.Fatal("missing label must retain explicit unknown port", err)
	}
}
