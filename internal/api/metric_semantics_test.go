package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/store"
)

func TestSampledActivityMetadataAndMachineIPPopulation(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.ScrapeInterval = 17 * time.Second })
	h.logIn(seedPassword)
	h.changePassword(seedPassword, replacementPassword)
	h.logIn(replacementPassword)
	ctx := context.Background()
	a, b, c := h.seedMachine("fresh"), h.seedMachine("outage"), h.seedMachine("unknown")
	now := time.Now().UTC().Truncate(time.Second)
	h.seedScrape(a.ID, now, "2001:db8::1", "Testland", 120, 100)
	h.seedScrape(b.ID, now, "2001:db8::1", "Testland", 240, 200)
	state, err := h.store.LoadScrapeState(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.ApplyScrape(ctx, store.ScrapeDelta{MachineID: c.ID, TargetGeneration: c.TargetGeneration, Revision: &state.Revision, At: now, Attackers: []store.AttackerDelta{{IPAddress: "192.0.2.33", Connections: 55, ImportedLifetime: true, FirstObservation: true}}}); err != nil {
		t.Fatal(err)
	}
	fresh, old := now.Add(-5*time.Second), now.Add(-10*time.Minute)
	for _, item := range []struct {
		id       int64
		at       time.Time
		failures int
	}{{a.ID, fresh, 0}, {b.ID, old, 3}} {
		if _, err = h.store.DB().Exec("UPDATE machines SET last_ok_at=?,last_scrape_at=?,consecutive_failures=? WHERE id=?", item.at.Unix(), now.Unix(), item.failures, item.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = h.store.DB().Exec("UPDATE machines SET enabled=0 WHERE id=?", c.ID); err != nil {
		t.Fatal(err)
	}
	selection := fmt.Sprintf("machines=%d,%d,%d", a.ID, b.ID, c.ID)
	answer := h.request(http.MethodGet, "/api/overview?"+selection, nil)
	assertStatus(t, "overview", answer, http.StatusOK)
	var overview overviewResponse
	answer.decode(t, &overview)
	meta := overview.Activity
	if meta.ThresholdSeconds != 34 || meta.EvaluatedAt.IsZero() || meta.UnobservedMachines != 1 || meta.FailedLatestScrapes != 1 || meta.DisabledMachines != 1 || meta.OldestSuccessAt == nil || !meta.OldestSuccessAt.Equal(old) || meta.NewestSuccessAt == nil || !meta.NewestSuccessAt.Equal(fresh) {
		t.Fatalf("activity context: %+v", meta)
	}
	if overview.TrappedNow != 1 || overview.UniqueAttackers != 1 {
		t.Fatal("shared IP or first lifetime import became a session/person count")
	}
	answer = h.request(http.MethodGet, "/api/attackers?"+selection+"&basis=observed&per_page=1", nil)
	assertStatus(t, "observed rows", answer, http.StatusOK)
	var page attackerPageResponse
	answer.decode(t, &page)
	if page.Total != 3 || page.DistinctIPs != 2 || len(page.Rows) != 1 || page.Activity.ThresholdSeconds != 34 {
		t.Fatalf("matching population: total=%d distinct=%d", page.Total, page.DistinctIPs)
	}
	answer = h.request(http.MethodGet, "/api/attackers?"+selection+"&basis=observed&status=unknown", nil)
	answer.decode(t, &page)
	if page.Total != 1 || page.Rows[0].LastMeasuredActivityAt != nil || !page.Rows[0].HasUndatedHistory {
		t.Fatal("first-import timing became known")
	}
	answer = h.request(http.MethodGet, "/api/machines", nil)
	var machines []machineResponse
	answer.decode(t, &machines)
	if len(machines) != 3 {
		t.Fatal("machine list lost data")
	}
	for _, machine := range machines {
		if machine.ActivityThresholdSeconds != 34 {
			t.Fatal("machine threshold was hardcoded")
		}
	}

}
