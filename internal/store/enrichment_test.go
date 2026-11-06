package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestEnrichmentEligibilityPersistenceMergeAndNewCopies(t *testing.T) {
	s, path := newStore(t)
	ctx := context.Background()
	a := createMachine(t, s, "a")
	b := createMachine(t, s, "b")
	now := baseTime
	applyScrape(t, s, ScrapeDelta{MachineID: a.ID, At: now, Attackers: []AttackerDelta{{IPAddress: "8.8.8.8", Country: "Exporter country", Location: "Exporter city", Connections: 5}}})
	due, err := s.EnrichmentDue(ctx, "old", now, 100)
	if err != nil || len(due) != 1 {
		t.Fatal(due, err)
	}
	next := now.Add(time.Minute)
	if err = s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "::ffff:8.8.8.8", Generation: "old", At: now, NextAttempt: &next, Failures: 1, Outcome: "transient"}); err != nil {
		t.Fatal(err)
	}
	if due, err = s.EnrichmentDue(ctx, "old", now, 100); err != nil || len(due) != 0 {
		t.Fatal("failure retried early", due, err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if due, err = s.EnrichmentDue(ctx, "old", next, 100); err != nil || len(due) != 1 || due[0].Failures != 1 {
		t.Fatal("restart lost retry", due, err)
	}
	if due, err = s.EnrichmentDue(ctx, "new", now, 100); err != nil || len(due) != 1 || due[0].Failures != 0 {
		t.Fatal("source change did not reset eligibility", due, err)
	}
	if err = s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "8.8.8.8", Generation: "new", At: now, NextAttempt: &next, Outcome: "resolved", Location: &AttackerLocation{CountryCode: "US"}}); err != nil {
		t.Fatal(err)
	}
	if due, err = s.EnrichmentDue(ctx, "new", next, 100); err != nil || len(due) != 0 {
		t.Fatal("complete copy still eligible", due, err)
	}
	var country, location string
	var measured, observed int64
	if err = s.DB().QueryRow("SELECT country,location,last_measured_activity_at,last_observed_at FROM attackers WHERE machine_id=?", a.ID).Scan(&country, &location, &measured, &observed); err != nil || country != "Exporter country" || location != "Exporter city" || measured != now.Unix() || observed != now.Unix() {
		t.Fatal("geo merge changed history/labels", country, location, err)
	}
	applyScrape(t, s, ScrapeDelta{MachineID: b.ID, At: now, Attackers: []AttackerDelta{{IPAddress: "8.8.8.8", Connections: 1}}})
	if due, err = s.EnrichmentDue(ctx, "new", now, 100); err != nil || len(due) != 1 {
		t.Fatal("new machine copy suppressed by prior success", due, err)
	}
	if err = s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "8.8.8.8", Generation: "new", At: next, NextAttempt: &next, Outcome: "resolved", Location: &AttackerLocation{CountryCode: "US", Location: "Resolved city"}}); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 1 {
		t.Fatal("attempts accumulated per copy/source")
	}
	if err = s.DeleteMachine(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 1 {
		t.Fatal("deleting one copy lost shared progress")
	}
	if err = s.DeleteMachine(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 0 {
		t.Fatal("last-copy deletion retained orphan")
	}
	if err = s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "8.8.8.8", Generation: "new", At: next, Outcome: "unlookupable"}); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 0 {
		t.Fatal("late completion recreated orphan")
	}
}

func TestEnrichmentProgressAtomicityPruningAndQueryPlan(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "partial")
	ctx := context.Background()
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Location: "Keep this city", Connections: 1}}})
	// A failing progress write must roll back the location merge too.
	if _, err := s.DB().Exec(`CREATE TRIGGER fail_progress BEFORE INSERT ON enrichment_progress BEGIN SELECT RAISE(ABORT,'fixture progress failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "192.0.2.1", Generation: "source", At: baseTime, Outcome: "resolved", Location: &AttackerLocation{ISP: "must roll back"}}); err == nil {
		t.Fatal("failed progress write accepted")
	}
	if scanText(t, s, "SELECT isp FROM attackers WHERE machine_id=?", m.ID) != "" || scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 0 {
		t.Fatal("location update committed without progress")
	}
	if _, err := s.DB().Exec("DROP TRIGGER fail_progress"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishEnrichment(ctx, EnrichmentResult{IPAddress: "192.0.2.1", Generation: "source", At: baseTime, Outcome: "unlookupable"}); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.EnrichmentDue(ctx, "source", baseTime.Add(365*24*time.Hour), 100); err != nil || len(rows) != 0 {
		t.Fatal("permanent skip consumed queue", rows, err)
	}
	if rows, err := s.EnrichmentDue(ctx, "changed", baseTime, 100); err != nil || len(rows) != 1 {
		t.Fatal("permanent skip did not re-enable", rows, err)
	}
	rows, err := s.DB().Query("EXPLAIN QUERY PLAN "+enrichmentDueQuery, "source", "source", baseTime.Unix(), "source", 100)
	if err != nil {
		t.Fatal(err)
	}
	var plans strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plans.WriteString(detail + "\n")
	}
	rows.Close()
	if !strings.Contains(plans.String(), "idx_attackers_missing_location") {
		t.Fatal("eligible query scans placed rows", plans.String())
	}
	if _, err = s.Prune(ctx, baseTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM enrichment_progress") != 0 {
		t.Fatal("retention left orphan progress")
	}
}
