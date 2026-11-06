package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestObservationOnlyAPIExposesUnknownImportTiming(t *testing.T) {
	h := newSignedInHarness(t)
	m := h.seedMachine("undated")
	ctx := context.Background()
	state, err := h.store.LoadScrapeState(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	err = h.store.ApplyScrape(ctx, store.ScrapeDelta{MachineID: m.ID, TargetGeneration: m.TargetGeneration, Revision: &state.Revision, At: now, Attackers: []store.AttackerDelta{{IPAddress: "192.0.2.1", Country: "Testland", Connections: 100, ImportedLifetime: true, FirstObservation: true}}})
	if err != nil {
		t.Fatal(err)
	}
	var activity attackerPageResponse
	answer := h.request(http.MethodGet, "/api/attackers", nil)
	assertStatus(t, "activity list", answer, http.StatusOK)
	answer.decode(t, &activity)
	if activity.Total != 0 {
		t.Fatal("import treated as recent activity")
	}
	var observed attackerPageResponse
	answer = h.request(http.MethodGet, "/api/attackers?basis=observed&status=unknown", nil)
	assertStatus(t, "observation list", answer, http.StatusOK)
	answer.decode(t, &observed)
	if observed.Total != 1 {
		t.Fatalf("missing observed import: %+v", observed)
	}
	row := observed.Rows[0]
	if row.LastMeasuredActivityAt != nil || !row.HasUndatedHistory || row.Status != "unknown" || !row.LastObservedAt.Equal(now) || !row.LastSeen.Equal(now) || !row.FirstObservationKnown {
		t.Fatalf("incorrect provenance: %+v", row)
	}
	var countries []countryCountResponse
	answer = h.request(http.MethodGet, "/api/attackers/countries?basis=observed", nil)
	assertStatus(t, "observation countries", answer, http.StatusOK)
	answer.decode(t, &countries)
	if len(countries) != 1 {
		t.Fatalf("observed countries: %+v", countries)
	}
}
