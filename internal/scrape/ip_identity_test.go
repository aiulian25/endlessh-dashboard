package scrape

import (
	"context"
	"endlessh-dashboard/internal/store"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParserRequiresCanonicalValidIPIdentity(t *testing.T) {
	for _, metric := range []string{MetricClientOpenCount, MetricClientTrappedTimeSeconds} {
		for _, ip := range []string{"not-an-ip", "", " 192.0.2.1", "192.0.2.1 ", "fe80::1%eth0", "192.0.2.1:22", "192.168.001.1"} {
			if _, err := Parse(strings.NewReader(fmt.Sprintf("%s{ip=%q,local_port=\"22\"} 1\n", metric, ip))); err == nil {
				t.Errorf("accepted invalid IP for %s", metric)
			}
		}
	}
	for _, ip := range []string{"2001:0DB8:0:0:0:0:0:1", "2001:db8::1"} {
		snapshot, err := Parse(strings.NewReader(fmt.Sprintf("%s{ip=%q,local_port=\"22\"} 1\n", MetricClientOpenCount, ip)))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := snapshot.Clients["2001:db8::1"]; !ok {
			t.Error("attacker identity was not canonical")
		}
	}
}

func TestIPAliasesShareRowsAndBaselinesAcrossRestart(t *testing.T) {
	db := newTestStore(t)
	ctx := context.Background()
	m, err := db.CreateMachine(ctx, store.Machine{Name: "aliases", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, db)
	apply := func(ip string, count int) {
		t.Helper()
		snapshot, e := Parse(strings.NewReader(fmt.Sprintf("endlessh_client_open_count{ip=%q,local_port=\"22\"} %d\n", ip, count)))
		if e != nil {
			t.Fatal(e)
		}
		if e = p.applySnapshot(ctx, m, time.Now().UTC(), snapshot); e != nil {
			t.Fatal(e)
		}
	}
	apply("2001:0DB8:0:0:0:0:0:1", 10)
	p = newTestPoller(t, db)
	apply("2001:db8::1", 10)
	apply("2001:DB8::1", 12)
	apply("::ffff:192.0.2.2", 5)
	p = newTestPoller(t, db)
	apply("192.0.2.2", 5)
	if countAttackers(t, db, m.ID) != 2 {
		t.Fatal("aliases split attacker rows")
	}
	if got := readAttacker(t, db, m.ID, "2001:db8::1").Connections; got != 12 {
		t.Fatalf("alias reimported history: %d", got)
	}
	if got := readAttacker(t, db, m.ID, "192.0.2.2").Connections; got != 5 {
		t.Fatal("mapped IP reimported lifetime")
	}
	// A bad address alongside a valid sample must reject the complete snapshot.
	bad := fmt.Sprintf("endlessh_client_open_count{ip=\"2001:db8::1\"} 999\nendlessh_client_open_count{ip=\"invalid\"} 1\n")
	if _, err = Parse(strings.NewReader(bad)); err == nil {
		t.Fatal("partial invalid exposition accepted")
	}
}

func TestMappedAliasesAndDuplicatePortsAreNotAddedTwice(t *testing.T) {
	input := `endlessh_client_open_count{ip="::ffff:192.0.2.1",local_port="22"} 7
endlessh_client_open_count{ip="192.0.2.1",local_port="22"} 7
endlessh_client_open_count{ip="192.0.2.1",local_port="2222"} 3
endlessh_client_trapped_time_seconds{ip="::ffff:c000:201",local_port="22"} 9
`
	s, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Clients) != 1 || s.Clients["192.0.2.1"].Connections != 10 || s.Clients["192.0.2.1"].TrappedSeconds != 9 {
		t.Fatal("mapped family/port identity split or doubled")
	}
	if _, err = Parse(strings.NewReader(strings.Replace(input, "local_port=\"22\"} 7\nendlessh_client_open_count{ip=\"192.0.2.1\"", "local_port=\"22\"} 8\nendlessh_client_open_count{ip=\"192.0.2.1\"", 1))); err == nil {
		t.Fatal("conflicting alias duplicate accepted")
	}
	if _, err = Parse(strings.NewReader("endlessh_client_open_count{local_port=\"22\"} 1\n")); err == nil {
		t.Fatal("missing IP accepted")
	}
}

func TestLegacyIPCollisionRebaselinesWithoutLifetimeImport(t *testing.T) {
	db := newTestStore(t)
	ctx := context.Background()
	m, err := db.CreateMachine(ctx, store.Machine{Name: "upgrade", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB().Exec(`DROP TABLE port_rollups; DROP TABLE port_collection; DELETE FROM schema_migrations WHERE version=13; DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11; DROP TABLE attacker_ip_archive;DROP TABLE counter_ip_archive;DELETE FROM schema_migrations WHERE version=10`); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"2001:0DB8::1", "2001:db8::1"} {
		if _, err = db.DB().Exec(`INSERT INTO attackers(machine_id,ip_address,first_seen,last_seen,last_activity_at,connections) VALUES(?,?,1,1,0,10)`, m.ID, ip); err != nil {
			t.Fatal(err)
		}
		key := "ip:v2:endlessh_client_open_count|" + fmt.Sprintf("[%q,\"22\"]", ip)
		if _, err = db.DB().Exec("INSERT INTO counter_states(machine_id,series,value,updated_at) VALUES(?,?,100,1)", m.ID, key); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, db)
	apply := func(ip string, n int) {
		t.Helper()
		snapshot, e := Parse(strings.NewReader(fmt.Sprintf("endlessh_client_open_count{ip=%q,local_port=\"22\"} %d\n", ip, n)))
		if e != nil {
			t.Fatal(e)
		}
		if e = p.applySnapshot(ctx, m, time.Now().UTC(), snapshot); e != nil {
			t.Fatal(e)
		}
	}
	apply("2001:0DB8::1", 100)
	if got := readAttacker(t, db, m.ID, "2001:db8::1").Connections; got != 10 {
		t.Fatalf("migration reimported lifetime: %d", got)
	}
	p = newTestPoller(t, db)
	apply("2001:db8::1", 105)
	apply("2001:0db8:0:0:0:0:0:1", 2)
	if got := readAttacker(t, db, m.ID, "2001:db8::1").Connections; got != 17 {
		t.Fatalf("restart growth/reset = %d", got)
	}
}
