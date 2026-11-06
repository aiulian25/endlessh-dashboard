package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoverageMigrationRestartRetentionAndFencing(t *testing.T) {
	s, path := newStore(t)
	m := createMachine(t, s, "coverage")
	ctx := context.Background()
	start := baseTime.Truncate(time.Minute)
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: start, Opens: 12, TrappedSeconds: 90})
	if _, err := s.DB().Exec(`DROP TABLE port_rollups; DROP TABLE port_collection; DELETE FROM schema_migrations WHERE version=13; DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	points, err := s.TimeSeries(ctx, []Machine{m}, start, start.Add(time.Minute), 60)
	if err != nil {
		t.Fatal(err)
	}
	if points[0].Points[0].Coverage != "unknown" || points[0].Points[0].Opens != 12 {
		t.Fatal("legacy history inferred or lost")
	}
	end := start.Add(time.Minute)
	if err = s.ApplyScrape(ctx, ScrapeDelta{MachineID: m.ID, At: end, Coverage: &ScrapeCoverage{From: &start, Complete: true}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err := s.LoadScrapeState(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if state.PreviousSample == nil || !state.PreviousSample.Equal(end) {
		t.Fatal("restart lost coverage continuity")
	}
	if err = s.RecordScrapeFailure(ctx, m.ID, start, "late", m.TargetGeneration); !errors.Is(err, ErrObsoleteScrape) {
		t.Fatal("late failure accepted", err)
	}
	if scanInt(t, s, "SELECT SUM(attempts) FROM scrape_coverage WHERE machine_id=?", m.ID) != 1 {
		t.Fatal("obsolete failure changed coverage")
	}
	if err = s.RecordScrapeFailure(ctx, m.ID, end.Add(time.Second), "timeout", m.TargetGeneration+1); !errors.Is(err, ErrObsoleteScrape) {
		t.Fatal("old generation accepted", err)
	}
	recent, err := s.RecentCoverageByMachine(ctx, end, 60, 2)
	if err != nil {
		t.Fatal(err)
	}
	if recent[m.ID][0] != "complete" || recent[m.ID][1] != "incomplete" {
		t.Fatalf("sidebar coverage: %+v", recent)
	}
	if _, err = s.DB().Exec("UPDATE scrape_coverage SET uncertain_from=?,uncertain_to=? WHERE machine_id=? AND bucket=?", start.Unix(), end.Unix(), m.ID, start.Unix()); err != nil {
		t.Fatal(err)
	}
	recent, err = s.RecentCoverageByMachine(ctx, end, 60, 2)
	if err != nil || recent[m.ID][0] != "incomplete" {
		t.Fatal("sidebar hid recovery uncertainty", recent, err)
	}
	if _, err = s.DB().Exec(`CREATE TRIGGER reject_coverage BEFORE INSERT ON scrape_coverage BEGIN SELECT RAISE(ABORT,'fixture coverage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordScrapeFailure(ctx, m.ID, end.Add(time.Second), "timeout", m.TargetGeneration); err == nil {
		t.Fatal("failed coverage write accepted")
	}
	if scanInt(t, s, "SELECT consecutive_failures FROM machines WHERE id=?", m.ID) != 0 {
		t.Fatal("failed coverage write committed health alone")
	}
	if _, err = s.DB().Exec("DROP TRIGGER reject_coverage"); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Prune(ctx, end.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Coverage != 2 || scanInt(t, s, "SELECT COUNT(*) FROM scrape_coverage") != 0 {
		t.Fatalf("coverage not retained/pruned with history: %+v", stats)
	}
	if scanInt(t, s, "SELECT opens FROM machine_totals WHERE machine_id=?", m.ID) != 12 {
		t.Fatal("prune changed lifetime data")
	}
}

func TestCoverageInterveningFailureCannotBecomeObservedZero(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "failure-race")
	ctx := context.Background()
	start := baseTime.Truncate(time.Minute)
	state, err := s.LoadScrapeState(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a failure committing while a previously computed sample is pending.
	if err = s.RecordScrapeFailure(ctx, m.ID, start.Add(time.Second), "timeout", m.TargetGeneration); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyScrape(ctx, ScrapeDelta{MachineID: m.ID, TargetGeneration: m.TargetGeneration, Revision: &state.Revision, At: start.Add(2 * time.Second), Opens: 5, Coverage: &ScrapeCoverage{From: &start, Complete: true}}); err != nil {
		t.Fatal(err)
	}
	points, err := s.TimeSeries(ctx, []Machine{m}, start, start.Add(time.Minute), 60)
	if err != nil {
		t.Fatal(err)
	}
	point := points[0].Points[0]
	if point.ObservedSeconds != 0 || point.Coverage != "incomplete" || point.UncertainFrom == nil || point.Opens != 5 {
		t.Fatalf("failure race hid missing observation or lost totals: %+v", point)
	}
}
