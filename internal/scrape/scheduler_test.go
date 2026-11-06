package scrape

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func schedulerMachines(t *testing.T, p *Poller, count int) []store.Machine {
	t.Helper()
	result := make([]store.Machine, count)
	for i := range result {
		m, err := p.store.CreateMachine(t.Context(), store.Machine{Name: fmt.Sprintf("mock-%03d", i), Host: "127.0.0.1", Port: 2112, MetricsPath: fmt.Sprintf("/metrics/%d", i), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		result[i] = m
	}
	return result
}
func waitScheduler(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("scheduler fixture did not progress")
		}
		time.Sleep(time.Millisecond)
	}
}
func startScheduler(t *testing.T, p *Poller) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("scheduler did not drain")
		}
	})
	return cancel, done
}
func schedulerResponse() *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("endlessh_sent_bytes_total{local_port=\"22\"} 1\n")), Header: http.Header{}}
}

// Uses only the pre-existing constructor/helper surface so this same assertion
// can run against the exact task-start poller in an isolated source copy.
func TestFleetDefaultInflightIsBounded(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.interval = 10 * time.Millisecond
	for i := 0; i < 20; i++ {
		if _, err := p.store.CreateMachine(t.Context(), store.Machine{Name: fmt.Sprintf("bound-%d", i), Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	var active, peak atomic.Int64
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("poller did not stop")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for active.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(40 * time.Millisecond)
	if got := peak.Load(); got != 4 {
		t.Errorf("in-flight default work = %d, want bounded 4", got)
	}
	cancel()
	<-done
	if active.Load() != 0 {
		t.Fatal("active requests survived cancellation")
	}
}

func TestSchedulerLimitsAndProbeShareWorkBudget(t *testing.T) {
	for _, limit := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			db := newTestStore(t)
			base := newTestPoller(t, db)
			p := NewPoller(db, base.validator, base.geoResolver, base.logger, base.interval, base.timeout, limit)
			p.interval = 10 * time.Millisecond
			schedulerMachines(t, p, 12)
			var active, peak atomic.Int64
			p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})
			cancel, done := startScheduler(t, p)
			waitScheduler(t, func() bool { return active.Load() == int64(limit) })
			probeCtx, stopProbe := context.WithCancel(context.Background())
			probeDone := make(chan struct{})
			go func() { defer close(probeDone); p.Probe(probeCtx, "127.0.0.1", 2112, "/probe") }()
			time.Sleep(20 * time.Millisecond)
			stopProbe()
			<-probeDone
			cancel()
			<-done
			if peak.Load() > int64(limit) || active.Load() != 0 {
				t.Fatalf("work escaped cap: peak=%d active=%d", peak.Load(), active.Load())
			}
		})
	}
}

func TestSlowMachineDoesNotGateHealthyCadenceOrOverlap(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.concurrency = 2
	p.workSlots = make(chan struct{}, 2)
	p.interval = 15 * time.Millisecond
	p.timeout = time.Second
	p.httpClient.Timeout = time.Second
	machines := schedulerMachines(t, p, 4)
	var mutex sync.Mutex
	calls := map[string]int{}
	active := map[string]int{}
	overlap := false
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		path := r.URL.Path
		mutex.Lock()
		calls[path]++
		active[path]++
		if active[path] > 1 {
			overlap = true
		}
		mutex.Unlock()
		defer func() { mutex.Lock(); active[path]--; mutex.Unlock() }()
		if path == "/metrics/0" {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return schedulerResponse(), nil
	})
	cancel, done := startScheduler(t, p)
	waitScheduler(t, func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return calls["/metrics/1"] >= 3 && calls["/metrics/2"] >= 3 && calls["/metrics/3"] >= 3
	})
	mutex.Lock()
	if calls["/metrics/0"] != 1 || overlap {
		t.Error("per-machine overlap or slow-job retry while active", calls)
	}
	mutex.Unlock()
	// A second Run must not create a second scheduler owner.
	second := make(chan struct{})
	go func() { p.Run(context.Background()); close(second) }()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("duplicate Run started")
	}
	cancel()
	<-done
	for _, m := range machines[1:] {
		fresh, err := p.store.GetMachine(t.Context(), m.ID)
		if err != nil || fresh.LastOKAt == nil {
			t.Fatal("healthy peer starved", fresh, err)
		}
	}
}

func TestSchedulerEvictsDeletedRetryStateAndFencesLateResults(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.interval = 10 * time.Millisecond
	machines := schedulerMachines(t, p, 2)
	p.timeout = 5 * time.Second
	p.httpClient.Timeout = 5 * time.Second
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/metrics/0" {
			return &http.Response{StatusCode: 500, Status: "fixture failure", Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		}

		select {
		case <-entered:
		default:
			close(entered)
		}
		select {
		case <-release:
			return schedulerResponse(), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	cancel, done := startScheduler(t, p)
	waitScheduler(t, func() bool { p.mutex.Lock(); defer p.mutex.Unlock(); return p.failureStreaks[machines[0].ID] > 0 })
	<-entered
	for _, m := range machines {
		if err := p.store.DeleteMachine(t.Context(), m.ID); err != nil {
			t.Fatal(err)
		}
	}
	waitScheduler(t, func() bool {
		p.mutex.Lock()
		defer p.mutex.Unlock()
		return len(p.attemptGenerations) == 0 && len(p.failureStreaks) == 0 && len(p.nextAttempt) == 0
	})
	once.Do(func() { close(release) })
	for _, m := range machines {
		if p.due(m.ID, m.TargetGeneration) {
			t.Error("deleted target became eligible again")
		}
	}
	time.Sleep(25 * time.Millisecond)
	p.mutex.Lock()
	if len(p.attemptGenerations) != 0 || len(p.nextAttempt) != 0 || len(p.failureStreaks) != 0 {
		t.Error("deleted result resurrected retry state")
	}
	p.mutex.Unlock()
	cancel()
	<-done
}

func TestQueuedTargetIsRecheckedAfterSlotWait(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.concurrency = 1
	p.workSlots = make(chan struct{}, 1)
	p.interval = 10 * time.Millisecond
	m := schedulerMachines(t, p, 1)[0]
	p.workSlots <- struct{}{} // simulate a probe holding the only slot
	var calls atomic.Int64
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) { calls.Add(1); return schedulerResponse(), nil })
	cancel, done := startScheduler(t, p)
	waitScheduler(t, func() bool { p.mutex.Lock(); defer p.mutex.Unlock(); return len(p.scheduledGenerations) == 1 })
	m.Enabled = false
	if err := p.store.UpdateMachine(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	<-p.workSlots
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
	if calls.Load() != 0 {
		t.Fatal("disabled queued target was fetched")
	}
	got, err := p.store.GetMachine(t.Context(), m.ID)
	if err != nil || got.LastOKAt != nil {
		t.Fatal("cancelled/disabled queue wrote stale health", got, err)
	}
}

func TestSchedulerGenerationChangeWaitsForOldJob(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.interval = 10 * time.Millisecond
	p.timeout = 5 * time.Second
	p.httpClient.Timeout = 5 * time.Second
	m := schedulerMachines(t, p, 1)[0]
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var replacement atomic.Int64
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/replacement" {
			replacement.Add(1)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("endlessh_sent_bytes_total{local_port=\"22\"} 2\n")), Header: http.Header{}}, nil
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("endlessh_sent_bytes_total{local_port=\"22\"} 999999\n")), Header: http.Header{}}, nil
	})
	cancel, done := startScheduler(t, p)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("old request not started")
	}
	m.MetricsPath = "/replacement"
	if err := p.store.UpdateMachine(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	current, err := p.store.GetMachine(t.Context(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitScheduler(t, func() bool {
		p.mutex.Lock()
		defer p.mutex.Unlock()
		return p.scheduledGenerations[m.ID] == current.TargetGeneration
	})
	if replacement.Load() != 0 {
		t.Fatal("new generation overlapped the old scrape")
	}
	once.Do(func() { close(release) })
	waitScheduler(t, func() bool {
		fresh, err := p.store.GetMachine(t.Context(), m.ID)
		return err == nil && fresh.LastOKAt != nil
	})
	cancel()
	<-done
	states, err := p.store.LoadCounterStates(t.Context(), m.ID)
	if err != nil || states[TotalSeriesKey(MetricSentBytesTotal, "22")] != 2 || readTotals(t, p.store, m.ID).BytesSent != 0 {
		t.Fatal("old generation contaminated replacement", states, err)
	}
}

func TestSchedulerWriteContentionKeepsWholeJobsBounded(t *testing.T) {
	p := newTestPoller(t, newTestStore(t))
	p.interval = 10 * time.Millisecond
	machines := schedulerMachines(t, p, 20)
	tx, err := p.store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE machines SET name=name WHERE id=?", machines[0].ID); err != nil {
		t.Fatal(err)
	}
	var calls, probes atomic.Int64
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Path == "/probe" {
			probes.Add(1)
		}
		return schedulerResponse(), nil
	})
	cancel, done := startScheduler(t, p)
	waitScheduler(t, func() bool { return len(p.workSlots) == p.concurrency && calls.Load() > 0 })
	probeCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, err = p.Probe(probeCtx, "127.0.0.1", 2112, "/probe"); err != context.DeadlineExceeded {
		t.Fatal("contended probe did not obey queue deadline", err)
	}
	if calls.Load() > int64(p.concurrency) || probes.Load() != 0 {
		t.Fatal("fetch queue grew while writes were blocked", calls.Load(), probes.Load())
	}
	cancel()
	tx.Rollback()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled work did not drain")
	}
	var counters int
	if err = p.store.DB().QueryRow("SELECT COUNT(*) FROM counter_states").Scan(&counters); err != nil || counters != 0 {
		t.Fatal("cancelled queued work published baselines", counters, err)
	}
}

func TestSchedulerReleasesWorkAfterPanic(t *testing.T) {
	base := newTestPoller(t, newTestStore(t))
	p := NewPoller(base.store, base.validator, base.geoResolver, base.logger, time.Hour, time.Second, 1)
	schedulerMachines(t, p, 2)
	var calls atomic.Int64
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			panic("fixture parser/transport panic")
		}
		return schedulerResponse(), nil
	})
	cancel, done := startScheduler(t, p)
	waitScheduler(t, func() bool { return calls.Load() >= 2 })
	cancel()
	<-done
	if len(p.workSlots) != 0 {
		t.Fatal("panic leaked a work slot")
	}
}
