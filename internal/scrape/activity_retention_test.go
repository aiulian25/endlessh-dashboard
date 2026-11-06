package scrape

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestObservationDoesNotRefreshActivityOrReimportExpiredHistory(t *testing.T) {
	db := newTestStore(t)
	p := newTestPoller(t, db)
	ctx := context.Background()
	m, err := db.CreateMachine(ctx, store.Machine{Name: "retention", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	apply := func(at time.Time, value float64) {
		t.Helper()
		s, e := Parse(strings.NewReader(clientPorts(map[string]float64{"22": value}, nil)))
		if e != nil {
			t.Fatal(e)
		}
		if e = p.applySnapshot(ctx, m, at, s); e != nil {
			t.Fatal(e)
		}
	}
	apply(old, 100)
	observed, e := db.ListAttackers(ctx, store.AttackerFilter{MachineIDs: []int64{m.ID}, Since: old.Add(-time.Hour), ObservationOnly: true, PerPage: 50, Page: 1})
	if e != nil {
		t.Fatal(e)
	}
	if observed.Total != 1 || observed.Rows[0].LastMeasuredActivityAt != nil || !observed.Rows[0].HasUndatedHistory {
		t.Fatalf("first import timing was invented: %+v", observed)
	}
	apply(now, 100)
	activity, e := db.ListAttackers(ctx, store.AttackerFilter{MachineIDs: []int64{m.ID}, Since: now.Add(-time.Hour), PerPage: 50, Page: 1})
	if e != nil {
		t.Fatal(e)
	}
	if activity.Total != 0 {
		t.Fatal("unchanged presence counted as activity")
	}
	latest, found, e := db.LatestAttacker(ctx, []int64{m.ID})
	if e != nil || found {
		t.Fatalf("undated import became latest activity: %+v %v", latest, e)
	}
	state, e := db.LoadScrapeState(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Prune(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	// A pre-prune computation must not reinsert a just-expired aggregate.
	if e = db.ApplyScrape(ctx, store.ScrapeDelta{MachineID: m.ID, TargetGeneration: m.TargetGeneration, Revision: &state.Revision, At: now.Add(time.Second)}); !errors.Is(e, store.ErrObsoleteScrape) {
		t.Fatalf("stale pre-prune result = %v", e)
	}
	apply(now.Add(2*time.Second), 100)
	if countAttackers(t, db, m.ID) != 0 {
		t.Fatal("unchanged sample recreated expired aggregate")
	}
	apply(now.Add(3*time.Second), 105)
	row := readAttacker(t, db, m.ID, "192.0.2.1")
	if row.Connections != 5 {
		t.Fatalf("reactivation reimported lifetime: %d", row.Connections)
	}
	// Let both the aggregate and raw baseline expire, then return unchanged.
	future := now.Add(200 * 24 * time.Hour)
	if _, e = db.Prune(ctx, future.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	p = newTestPoller(t, db)
	apply(future, 105)
	if countAttackers(t, db, m.ID) != 0 {
		t.Fatal("baseline expiry reimported lifetime")
	}
	apply(future.Add(time.Second), 107)
	if got := readAttacker(t, db, m.ID, "192.0.2.1").Connections; got != 2 {
		t.Fatalf("post-expiry new growth = %d", got)
	}
}
