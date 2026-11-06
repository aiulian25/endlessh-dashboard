package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"endlessh-dashboard/internal/ipidentity"
)

func legacyIPFixture(t *testing.T) (*Store, string, Machine, Machine) {
	t.Helper()
	s, path := newStore(t)
	a := createMachine(t, s, "a")
	b := createMachine(t, s, "b")
	if _, err := s.DB().Exec(`DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11; DROP TABLE attacker_ip_archive; DROP TABLE counter_ip_archive; DELETE FROM schema_migrations WHERE version=10; UPDATE machines SET enabled=1`); err != nil {
		t.Fatal(err)
	}
	insert := func(machine int64, ip string, connections int64, seconds float64, observed time.Time) {
		t.Helper()
		_, err := s.DB().Exec(`INSERT INTO attackers(machine_id,ip_address,first_seen,last_seen,last_activity_at,connections,trapped_seconds,last_observed_at,last_measured_activity_at,has_undated_history,first_observation_known,isp) VALUES(?,?,?,?,?,?,?,?,?,0,1,?)`, machine, ip, baseTime.Add(-48*time.Hour).Unix(), observed.Unix(), observed.Unix(), connections, seconds, observed.Unix(), observed.Unix(), ip)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(a.ID, "2001:0DB8:0:0:0:0:0:1", 10, 100, baseTime.Add(-time.Hour))
	insert(a.ID, "2001:db8::1", 10, 100, baseTime)
	insert(a.ID, "::ffff:192.0.2.1", 8, 80, baseTime.Add(-time.Hour))
	insert(a.ID, "192.0.2.1", 5, 90, baseTime)
	insert(a.ID, "not-an-ip", 20, 200, baseTime)
	insert(b.ID, "2001:0db8::1", 4, 40, baseTime)
	keys := []string{ipidentity.RawKey("endlessh_client_open_count", "2001:0DB8::1", "22"), ipidentity.RawKey("endlessh_client_open_count", "2001:db8::1", "22"), ipidentity.RawKey("endlessh_client_open_count", "::ffff:192.0.2.1", "22"), "ip:endlessh_client_open_count|192.0.2.5", "total:endlessh_sent_bytes_total|22", ipidentity.RawKey("endlessh_client_open_count", "bad-ip", "22")}
	for i, key := range keys {
		if _, err := s.DB().Exec("INSERT INTO counter_states(machine_id,series,value,updated_at) VALUES(?,?,?,?)", a.ID, key, 100+i, baseTime.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB().Exec("UPDATE machine_totals SET opens=1000,bytes_sent=500,trapped_seconds=2000 WHERE machine_id=?", a.ID); err != nil {
		t.Fatal(err)
	}
	return s, path, a, b
}
func TestIPMigrationPreservesAmbiguityWithoutAddingCounters(t *testing.T) {
	s, path, a, b := legacyIPFixture(t)
	ctx := context.Background()
	// Verification upgrades a disposable copy, not this legacy source.
	if err := VerifyDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM schema_migrations") != 9 || scanInt(t, s, "SELECT COUNT(*) FROM attackers") != 6 {
		t.Fatal("verification changed source")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM attackers") != 3 {
		t.Fatal("canonical rows not consolidated")
	}
	if scanInt(t, s, "SELECT connections FROM attackers WHERE machine_id=? AND ip_address='2001:db8::1'", a.ID) != 10 {
		t.Fatal("duplicate counters added")
	}
	if scanInt(t, s, "SELECT connections FROM attackers WHERE machine_id=? AND ip_address='192.0.2.1'", a.ID) != 8 {
		t.Fatal("ambiguous counters added")
	}
	if scanFloat(t, s, "SELECT trapped_seconds FROM attackers WHERE machine_id=? AND ip_address='192.0.2.1'", a.ID) != 90 {
		t.Fatal("duration not conservative maximum")
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM attacker_ip_archive") != 6 || scanInt(t, s, "SELECT COUNT(*) FROM counter_ip_archive") != 5 {
		t.Fatal("original rows not all preserved")
	}
	var original string
	if err := s.DB().QueryRow("SELECT row_json FROM attacker_ip_archive WHERE machine_id=? AND original_ip='::ffff:192.0.2.1'", a.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(original), &row); err != nil {
		t.Fatal(err)
	}
	if row["connections"] != float64(8) || row["trapped_seconds"] != float64(80) || row["isp"] != "::ffff:192.0.2.1" {
		t.Fatal("archive changed original data")
	}
	if scanInt(t, s, "SELECT opens FROM machine_totals WHERE machine_id=?", a.ID) != 1000 || scanInt(t, s, "SELECT bytes_sent FROM machine_totals WHERE machine_id=?", a.ID) != 500 {
		t.Fatal("migration changed machine totals")
	}
	states, err := s.LoadCounterStates(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[ipidentity.RawKey("endlessh_client_open_count", "192.0.2.1", "22")] != 102 || states["total:endlessh_sent_bytes_total|22"] != 104 {
		t.Fatal("raw continuity not preserved/quarantined correctly")
	}
	if policy, err := s.ClientCounterPolicy(ctx, a.ID); err != nil || policy != "baseline_only" {
		t.Fatal("ambiguous machine can import lifetime")
	}
	overview, err := s.Overview(ctx, []int64{a.ID, b.ID}, baseTime.Add(-24*time.Hour), baseTime.Add(-time.Minute))
	if err != nil || overview.AttackersTrapped != 2 {
		t.Fatalf("fleet alias counted twice: %+v %v", overview, err)
	}
	found, err := s.ListAttackers(ctx, AttackerFilter{MachineIDs: []int64{a.ID, b.ID}, Search: "2001:0DB8:0:0:0:0:0:1", Page: 1, PerPage: 50})
	if err != nil || found.Total != 2 {
		t.Fatal("full alias search did not normalize")
	}
	if err = s.SetAttackerLocation(ctx, "2001:0DB8::1", AttackerLocation{Country: "Testland"}); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM attackers WHERE country='Testland'") != 2 {
		t.Fatal("enrichment did not normalize identity")
	}
	count, err := s.IPIdentityReviewCount(ctx)
	if err != nil || count != 9 {
		t.Fatalf("review not reported: %d %v", count, err)
	}
	if err = VerifyDatabaseFile(path); err != nil {
		t.Fatal("migrated archive cannot be backed up/restored", err)
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
	if scanInt(t, reopened, "SELECT COUNT(*) FROM attacker_ip_archive") != 6 {
		t.Fatal("restart repeated archive migration")
	}
	if err = reopened.DeleteMachine(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, reopened, "SELECT COUNT(*) FROM counter_ip_archive") != 0 || scanInt(t, reopened, "SELECT COUNT(*) FROM attacker_ip_archive") != 1 {
		t.Fatal("machine deletion retained its archives")
	}
}

func TestIPMigrationFailureRollsBackOriginalsAndArchives(t *testing.T) {
	s, _, a, _ := legacyIPFixture(t)
	if _, err := s.DB().Exec(`CREATE TRIGGER reject_identity_delete BEFORE DELETE ON attackers WHEN OLD.ip_address='2001:db8::1' BEGIN SELECT RAISE(ABORT,'injected identity failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err == nil {
		t.Fatal("migration failure reported success")
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM schema_migrations") != 9 || scanInt(t, s, "SELECT COUNT(*) FROM attackers") != 6 || scanInt(t, s, "SELECT COUNT(*) FROM counter_states") != 6 {
		t.Fatal("failed migration changed original history")
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM sqlite_master WHERE name='attacker_ip_archive'") != 0 {
		t.Fatal("failed migration left partial archive schema")
	}
	if _, err := s.DB().Exec("DROP TRIGGER reject_identity_delete"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if scanInt(t, s, "SELECT connections FROM attackers WHERE machine_id=? AND ip_address='2001:db8::1'", a.ID) != 10 {
		t.Fatal("retry inflated totals")
	}
}

func TestDirectScrapeRejectsInvalidOrDuplicateIPWithoutHistory(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "direct")
	if _, err := s.DB().Exec("UPDATE machines SET enabled=1 WHERE id=?", m.ID); err != nil {
		t.Fatal(err)
	}
	for _, attackers := range [][]AttackerDelta{{{IPAddress: "invalid", Connections: 1}}, {{IPAddress: "fe80::1%zone", Connections: 1}}, {{IPAddress: "192.0.2.1", Connections: 1}, {IPAddress: "::ffff:192.0.2.1", Connections: 1}}} {
		err := s.ApplyScrape(context.Background(), ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 99, Attackers: attackers})
		if err == nil {
			t.Fatal("invalid direct identity accepted")
		}
	}
	badKey := ipidentity.RawKey("endlessh_client_open_count", "bad-ip", "22")
	if err := s.ApplyScrape(context.Background(), ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 99, CounterStates: map[string]float64{badKey: 1}}); err == nil {
		t.Fatal("invalid direct baseline entered history")
	}
	if scanInt(t, s, "SELECT COUNT(*) FROM attackers") != 0 || scanInt(t, s, "SELECT opens FROM machine_totals WHERE machine_id=?", m.ID) != 0 {
		t.Fatal("invalid scrape partially committed")
	}
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{{IPAddress: "::ffff:192.0.2.1", Connections: 1}}})
	if scanInt(t, s, "SELECT COUNT(*) FROM attackers WHERE ip_address='192.0.2.1'") != 1 {
		t.Fatal("direct mapped IP not normalized")
	}
}

func TestCurrentBackupRejectsEditedNoncanonicalIdentity(t *testing.T) {
	for _, kind := range []string{"attacker", "baseline", "blob"} {
		t.Run(kind, func(t *testing.T) {
			s, path := newStore(t)
			m := createMachine(t, s, "edited")
			if kind == "blob" {
				if _, err := s.DB().Exec(`INSERT INTO attackers(machine_id,ip_address,first_seen,last_seen,last_activity_at) VALUES(?,CAST('192.0.2.1' AS BLOB),1,1,0)`, m.ID); err != nil {
					t.Fatal(err)
				}
			} else if kind == "attacker" {
				if _, err := s.DB().Exec(`INSERT INTO attackers(machine_id,ip_address,first_seen,last_seen,last_activity_at) VALUES(?,'not-an-ip',1,1,0)`, m.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.DB().Exec(`INSERT INTO counter_states(machine_id,series,value,updated_at) VALUES(?,?,1,1)`, m.ID, ipidentity.RawKey("endlessh_client_open_count", "::ffff:192.0.2.1", "22")); err != nil {
					t.Fatal(err)
				}
			}
			if err := VerifyDatabaseFile(path); err == nil {
				t.Fatal("edited current backup bypassed canonical contract")
			}
		})
	}
}
