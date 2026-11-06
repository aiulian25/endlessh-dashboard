package store

import (
	"context"
	"testing"
	"time"
)

func TestFleetNewUsesEarliestSelectedObservation(t *testing.T) {
	s, _ := newStore(t)
	a := createMachine(t, s, "a")
	b := createMachine(t, s, "b")
	ctx := context.Background()
	applyScrape(t, s, ScrapeDelta{MachineID: a.ID, At: baseTime.Add(-48 * time.Hour), Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 1}}})
	applyScrape(t, s, ScrapeDelta{MachineID: b.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 1}}})
	result, err := s.Overview(ctx, []int64{a.ID, b.ID}, baseTime.Add(-24*time.Hour), baseTime.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.AttackersTrappedDelta != 0 {
		t.Fatal("same IP counted new again on another selected machine")
	}
	selected, err := s.Overview(ctx, []int64{b.ID}, baseTime.Add(-24*time.Hour), baseTime.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if selected.AttackersTrappedDelta != 1 {
		t.Fatal("first observation in selected fleet not counted")
	}
}

func TestLegacyObservationMigrationDoesNotInventActivity(t *testing.T) {
	s, path := newStore(t)
	m := createMachine(t, s, "legacy")
	ctx := context.Background()
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 10}}})
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "192.0.2.2", Connections: 2, Active: true}}})
	if _, err := s.DB().Exec(`DROP TABLE port_rollups; DROP TABLE port_collection; DELETE FROM schema_migrations WHERE version=13; DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11; DROP TABLE attacker_ip_archive; DROP TABLE counter_ip_archive; DELETE FROM schema_migrations WHERE version=10; DROP INDEX idx_attackers_measured_activity;
 ALTER TABLE attackers DROP COLUMN last_observed_at;
 ALTER TABLE attackers DROP COLUMN last_measured_activity_at;
 ALTER TABLE attackers DROP COLUMN has_undated_history;
 ALTER TABLE attackers DROP COLUMN first_observation_known;
 DELETE FROM schema_migrations WHERE version=9;`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := reopened.ListAttackers(ctx, AttackerFilter{MachineIDs: []int64{m.ID}, ObservationOnly: true, Search: "192.0.2.1", Since: baseTime.Add(-time.Hour), Page: 1, PerPage: 50})
	if err != nil {
		t.Fatal(err)
	}
	if rows.Total != 1 || rows.Rows[0].LastMeasuredActivityAt != nil || !rows.Rows[0].HasUndatedHistory || !rows.Rows[0].LastObservedAt.Equal(baseTime) {
		t.Fatalf("legacy timing inferred: %+v", rows)
	}
	known, err := reopened.ListAttackers(ctx, AttackerFilter{MachineIDs: []int64{m.ID}, Search: "192.0.2.2", Since: baseTime.Add(-time.Hour), Page: 1, PerPage: 50})
	if err != nil || known.Total != 1 || known.Rows[0].LastMeasuredActivityAt == nil || !known.Rows[0].LastMeasuredActivityAt.Equal(baseTime) || !known.Rows[0].HasUndatedHistory {
		t.Fatalf("lost known legacy delta: %+v %v", known, err)
	}

}

func TestInactiveObservationDoesNotRefreshReportingOrRetention(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "inactive")
	ctx := context.Background()
	old := baseTime.Add(-100 * 24 * time.Hour)
	lat, lon := coordinate(1, 2)
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: old, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 10, Active: true, Country: "Testland", Latitude: lat, Longitude: lon}}})
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1"}}})
	since := baseTime.Add(-time.Hour)
	overview, err := s.Overview(ctx, []int64{m.ID}, since, since)
	if err != nil {
		t.Fatal(err)
	}
	if overview.UniqueAttackers != 0 || overview.Countries != 0 {
		t.Fatalf("observation refreshed activity: %+v", overview)
	}
	latest, found, err := s.LatestAttacker(ctx, []int64{m.ID})
	if err != nil || !found || latest.LastMeasuredActivityAt == nil || !latest.LastMeasuredActivityAt.Equal(old) || !latest.LastObservedAt.Equal(baseTime) {
		t.Fatalf("timestamps: %+v %v", latest, err)
	}
	points, err := s.GeoPoints(ctx, []int64{m.ID}, since)
	if err != nil || len(points) != 0 {
		t.Fatalf("inactive geography: %+v %v", points, err)
	}
	countries, err := s.CountryTotals(ctx, []int64{m.ID}, since)
	if err != nil || len(countries) != 0 {
		t.Fatalf("inactive countries: %+v %v", countries, err)
	}
	observed, err := s.CountryTotals(ctx, []int64{m.ID}, since, true)
	if err != nil || len(observed) != 1 {
		t.Fatalf("observed countries lost: %+v %v", observed, err)
	}
	stats, err := s.Prune(ctx, baseTime.Add(-90*24*time.Hour))
	if err != nil || stats.Attackers != 1 {
		t.Fatalf("observation retained inactive row: %+v %v", stats, err)
	}
}
