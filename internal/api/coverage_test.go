package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestMachineHealthExpiresAtExplicitAge(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	age := 30 * time.Second
	fresh := now.Add(-age)
	old := fresh.Add(-time.Nanosecond)
	future := now.Add(time.Second)
	for _, c := range []struct {
		name string
		m    store.Machine
		want string
	}{
		{"edge", store.Machine{Enabled: true, LastOKAt: &fresh}, statusOK},
		{"stopped poller", store.Machine{Enabled: true, LastOKAt: &old}, statusStale},
		{"future clock", store.Machine{Enabled: true, LastOKAt: &future}, statusStale},
		{"never", store.Machine{Enabled: true}, statusNever},
		{"never successful", store.Machine{Enabled: true, LastScrapeAt: &now, ConsecutiveFailures: 1}, statusNever},
		{"disabled", store.Machine{Enabled: false, LastOKAt: &fresh, ConsecutiveFailures: 5}, statusDisabled},
		{"offline", store.Machine{Enabled: true, LastOKAt: &old, ConsecutiveFailures: 3}, statusDown},
		{"recent failure", store.Machine{Enabled: true, LastOKAt: &fresh, ConsecutiveFailures: 1}, statusDegraded},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := machineStatusAt(c.m, now, age); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
	if machineStatusAt(store.Machine{Enabled: true, LastOKAt: &old}, now, time.Minute) != statusOK {
		t.Fatal("interval change ignored")
	}
}

type readinessProber struct {
	fakeProber
	ready bool
}

func (p *readinessProber) WorkerReady(time.Time) bool { return p.ready }
func TestReadinessIsCheapWorkerProgressAndLivenessStaysCompatible(t *testing.T) {
	p := &readinessProber{}
	s := &Server{prober: p}
	for _, ready := range []bool{false, true, false} {
		p.ready = ready
		r := httptest.NewRecorder()
		s.handleReady(r, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		want := http.StatusServiceUnavailable
		if ready {
			want = http.StatusOK
		}
		if r.Code != want {
			t.Fatalf("readiness=%d want %d", r.Code, want)
		}
	}
	if p.calls != 0 {
		t.Fatal("readiness polled a target")
	}
	r := httptest.NewRecorder()
	s.handleHealth(r, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if r.Code != 200 || r.Body.String() != "ok" {
		t.Fatal("liveness changed")
	}
	s.prober = &fakeProber{}
	r = httptest.NewRecorder()
	s.handleReady(r, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if r.Code != 503 {
		t.Fatal("unknown worker reported ready")
	}
}

func TestCoverageAPIKeepsMissingDistinctFromObservedZero(t *testing.T) {
	h := newSignedInHarness(t)
	m := h.seedMachine("coverage")
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	from := start
	end := start.Add(5 * time.Minute)
	if err := h.store.ApplyScrape(t.Context(), store.ScrapeDelta{MachineID: m.ID, TargetGeneration: m.TargetGeneration, At: end, Coverage: &store.ScrapeCoverage{From: &from, Complete: true}}); err != nil {
		t.Fatal(err)
	}
	answer := h.request(http.MethodGet, "/api/timeseries?machines="+strconv.FormatInt(m.ID, 10)+"&from=2026-11-05T12:00:00Z&to=2026-11-05T12:15:00Z", nil)
	assertStatus(t, "coverage series", answer, 200)
	var payload timeSeriesResponse
	answer.decode(t, &payload)
	if len(payload.Series) != 1 || len(payload.Series[0].Points) != 3 {
		t.Fatalf("series: %+v", payload)
	}
	first, second := payload.Series[0].Points[0], payload.Series[0].Points[1]
	if first.Coverage != "complete" || first.ObservedSeconds != 300 || first.TrappedSeconds != 0 || second.Coverage != "incomplete" || payload.Series[0].Points[2].Coverage != "unknown" {
		t.Fatalf("missing zero distinction: %+v %+v", first, second)
	}
}
