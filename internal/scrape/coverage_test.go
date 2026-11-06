package scrape

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func coverageSnapshot(t *testing.T, value int) Snapshot {
	t.Helper()
	var input strings.Builder
	for _, metric := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal} {
		fmt.Fprintf(&input, "%s{local_port=\"22\"} %d\n", metric, value)
	}
	s, err := Parse(strings.NewReader(input.String()))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCoverageZeroOutageRecoveryRestartAndSeriesLoss(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	p := newTestPoller(t, db)
	p.interval = 15 * time.Second
	m, err := db.CreateMachine(ctx, store.Machine{Name: "coverage", Host: "203.0.113.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	apply := func(poller *Poller, second, value int, snapshot *Snapshot) {
		t.Helper()
		sample := coverageSnapshot(t, value)
		if snapshot != nil {
			sample = *snapshot
		}
		if err := poller.applySnapshot(ctx, m, at.Add(time.Duration(second)*time.Second), sample); err != nil {
			t.Fatal(err)
		}
	}
	apply(p, 0, 100, nil)
	for _, second := range []int{15, 30, 45, 60} {
		apply(p, second, 100, nil)
	}
	// A new poller instance loads continuity from SQLite, not in-memory scheduling.
	restarted := newTestPoller(t, db)
	restarted.interval = 15 * time.Second
	apply(restarted, 75, 110, nil)
	if err := db.RecordScrapeFailure(ctx, m.ID, at.Add(90*time.Second), "timeout", m.TargetGeneration); err != nil {
		t.Fatal(err)
	}
	apply(restarted, 300, 160, nil)
	// Zero after recovery can regain observation coverage without erasing uncertainty.
	if err := db.RecordScrapeSuccess(ctx, m.ID, at.Add(300*time.Second), m.TargetGeneration); err != nil {
		t.Fatal(err)
	}
	for _, second := range []int{315, 330, 345, 360} {
		apply(restarted, second, 160, nil)
	}
	// Missing series and resets must not turn partial data into observed zero.
	missing := coverageSnapshot(t, 160)
	delete(missing.Totals, "total:"+MetricSentBytesTotal+"|22")
	apply(restarted, 375, 160, &missing)
	apply(restarted, 390, 170, nil)
	apply(restarted, 405, 1, nil)
	points, err := db.TimeSeries(ctx, []store.Machine{m}, at, at.Add(8*time.Minute), 60)
	if err != nil {
		t.Fatal(err)
	}
	got := points[0].Points
	if got[0].Coverage != "complete" || got[0].TrappedSeconds != 0 || got[0].ObservedSeconds != 60 {
		t.Fatalf("successful zero: %+v", got[0])
	}
	if got[2].Coverage != "unknown" || got[2].Attempts != 0 {
		t.Fatalf("missing minute became zero: %+v", got[2])
	}
	if got[1].Attempts != 3 || got[1].Successes != 2 || got[1].Coverage != "incomplete" {
		t.Fatalf("timeout/backoff: %+v", got[1])
	}
	recovery := got[5]
	if recovery.TrappedSeconds != 50 || recovery.UncertainFrom == nil || !recovery.UncertainFrom.Equal(at.Add(75*time.Second)) || recovery.UncertainTo == nil || !recovery.UncertainTo.Equal(at.Add(300*time.Second)) {
		t.Fatalf("recovery timing: %+v", recovery)
	}
	if recovery.Coverage != "complete" {
		t.Fatalf("subsequent successful zero intervals lost: %+v", recovery)
	}
	if got[6].Coverage == "complete" || got[6].UncertainFrom == nil {
		t.Fatalf("partial family/reset became complete: %+v", got[6])
	}
	var total int64
	if err = db.DB().QueryRow("SELECT opens FROM machine_totals WHERE machine_id=?", m.ID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 71 {
		t.Fatalf("coverage changed counter total: %d", total)
	}
	var rows int
	if err = db.DB().QueryRow("SELECT COUNT(*) FROM scrape_coverage WHERE machine_id=?", m.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows > 8 {
		t.Fatalf("coverage not minute-coalesced: %d", rows)
	}
}

func TestCoverageIntervalChangesAndGenerationFence(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	snapshot := coverageSnapshot(t, 2)
	generation := int64(3)
	state := store.ScrapeState{Cadence: 15 * time.Second, Counters: snapshot.Totals, CounterTimes: map[string]time.Time{}, PreviousSample: &at, CoverageGeneration: &generation}
	for key := range snapshot.Totals {
		state.CounterTimes[key] = at
	}
	m := store.Machine{TargetGeneration: generation}
	if observationCoverage(state, m, at.Add(45*time.Second), snapshot, 30*time.Second).Complete {
		t.Fatal("short interval ignored outage")
	}
	if observationCoverage(state, m, at.Add(45*time.Second), snapshot, 60*time.Second).Complete {
		t.Fatal("interval change backfilled coverage")
	}
	state.Cadence = 30 * time.Second
	if !observationCoverage(state, m, at.Add(45*time.Second), snapshot, 60*time.Second).Complete {
		t.Fatal("stable longer cadence ignored")
	}
	m.TargetGeneration++
	if observationCoverage(state, m, at.Add(time.Second), snapshot, time.Minute).Complete {
		t.Fatal("coverage crossed enable/endpoint generation")
	}
	m.TargetGeneration = generation
	if observationCoverage(state, m, at.Add(2*time.Hour), snapshot, 3*time.Hour).Complete {
		t.Fatal("unbounded coverage interval")
	}
}

func TestWorkerReadinessExpiresWithoutFailures(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	now := time.Now().UTC()
	if p.WorkerReady(now) {
		t.Fatal("unstarted worker ready")
	}
	p.workerBeat(true)
	now = p.workerHeartbeat
	if !p.WorkerReady(now) {
		t.Fatal("running worker not ready")
	}
	if p.WorkerReady(now.Add(2*p.interval + p.timeout + time.Nanosecond)) {
		t.Fatal("stopped progress ready forever")
	}
	p.workerBeat(false)
	if p.WorkerReady(time.Now().UTC()) {
		t.Fatal("cancelled worker ready")
	}
}

func TestWorkerReadinessLifecycle(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("poller did not stop")
		}
	}()
	go func() { defer close(done); p.Run(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !p.WorkerReady(time.Now().UTC()) {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("running poller never ready")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("poller did not stop")
	}
	if p.WorkerReady(time.Now().UTC()) {
		t.Fatal("stopped poller still ready")
	}
}

func TestCancelledPollerStartsNoStages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &Poller{}
	p.Run(ctx)
	p.pollAll(ctx)
	p.pollOne(ctx, store.Machine{})
	if err := p.applySnapshot(ctx, store.Machine{}, time.Now(), Snapshot{}); err != context.Canceled {
		t.Fatal("started applying a cancelled sample", err)
	}
}
