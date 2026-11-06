package geo

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestBackfillPassesOneHundredPermanentMisses(t *testing.T) {
	provider := newFakeProvider(t)
	db, e := newEnricherFixture(t, newTestOnlineResolver(t, provider))
	ctx := context.Background()
	m, err := db.CreateMachine(ctx, store.Machine{Name: "progress", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = db.ApplyScrape(ctx, store.ScrapeDelta{MachineID: m.ID, At: now.Add(-time.Hour), Attackers: []store.AttackerDelta{{IPAddress: "8.8.8.8", Connections: 1}}}); err != nil {
		t.Fatal(err)
	}
	delta := store.ScrapeDelta{MachineID: m.ID, At: now}
	for i := 1; i <= 100; i++ {
		delta.Attackers = append(delta.Attackers, store.AttackerDelta{IPAddress: fmt.Sprintf("10.0.0.%d", i), Connections: 1})
	}
	if err = db.ApplyScrape(ctx, delta); err != nil {
		t.Fatal(err)
	}
	e.runOnce(ctx)
	e.runOnce(ctx)
	var code string
	if err = db.DB().QueryRow("SELECT country_code FROM attackers WHERE ip_address='8.8.8.8'").Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code != "US" || provider.requests.Load() != 1 {
		t.Fatalf("101st address starved: country=%q requests=%d", code, provider.requests.Load())
	}
}

type changingLocalSource struct {
	generation string
	found      bool
}

func (s *changingLocalSource) Enabled() bool      { return true }
func (s *changingLocalSource) Generation() string { return s.generation }
func (s *changingLocalSource) Lookup(string) (Location, bool) {
	return Location{Country: "Local country", CountryCode: "LC", Location: "Local city"}, s.found
}

func TestLocalSourceRefreshReenablesMissesWithOnlineDisabled(t *testing.T) {
	provider := newFakeProvider(t)
	db, e := newEnricherFixture(t, NewOnlineResolver(false, provider.endpoint(), testRatePerMinute))
	local := &changingLocalSource{generation: "old"}
	e.local = local
	m, err := db.CreateMachine(t.Context(), store.Machine{Name: "local", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seedAttacker(t, db, m.ID, "8.8.8.8")
	e.runOnce(t.Context())
	e.runOnce(t.Context())
	local.generation = "new"
	local.found = true
	e.runOnce(t.Context())
	var code string
	if err = db.DB().QueryRow("SELECT country_code FROM attackers WHERE ip_address='8.8.8.8'").Scan(&code); err != nil || code != "LC" {
		t.Fatal("new local source did not re-enable miss", code, err)
	}
	if provider.requests.Load() != 0 {
		t.Fatal("online-disabled lookup sent data")
	}
	first, err := databaseFingerprint(strings.NewReader("first database"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := databaseFingerprint(strings.NewReader("other database"))
	if err != nil || first == second {
		t.Fatal("changed database content kept its generation")
	}
}

func TestTransientEnrichmentRetriesPersistAcrossRestart(t *testing.T) {
	provider := newFakeProvider(t)
	provider.status.Store(500)
	bad := "fixture error"
	provider.body.Store(&bad)
	db, e := newEnricherFixture(t, newTestOnlineResolver(t, provider))
	m, err := db.CreateMachine(t.Context(), store.Machine{Name: "retry", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seedAttacker(t, db, m.ID, "8.8.8.8")
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	e.runOnce(t.Context())
	e.runOnce(t.Context())
	if provider.requests.Load() != 1 {
		t.Fatal("transient retry ignored delay")
	}
	var seq int
	var schema, path string
	if err = db.DB().QueryRow("PRAGMA database_list").Scan(&seq, &schema, &path); err != nil {
		t.Fatal(err)
	}
	db.Close()
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	local, _ := Open("")
	nextOnline := newTestOnlineResolver(t, provider)
	restarted := NewEnricher(reopened, local, nextOnline, e.logger)
	restarted.now = func() time.Time { return now }
	restarted.runOnce(t.Context())
	if provider.requests.Load() != 1 {
		t.Fatal("restart lost durable retry delay")
	}
	provider.status.Store(200)
	answer := successPayload
	provider.body.Store(&answer)
	now = now.Add(time.Minute)
	restarted.runOnce(t.Context())
	var code string
	if err = reopened.DB().QueryRow("SELECT country_code FROM attackers WHERE ip_address='8.8.8.8'").Scan(&code); err != nil || code != "US" || provider.requests.Load() != 2 {
		t.Fatal("retry did not recover", code, provider.requests.Load(), err)
	}
	for _, c := range []struct {
		failures int
		delay    time.Duration
	}{{1, time.Minute}, {2, 2 * time.Minute}, {16, 24 * time.Hour}, {100, 24 * time.Hour}} {
		if got := enrichmentRetryDelay(c.failures); got != c.delay {
			t.Fatal("unbounded retry", got, c)
		}
	}
}

func TestProviderRefreshAndPartialAnswerDoNotClearExistingLocation(t *testing.T) {
	provider := newFakeProvider(t)
	db, e := newEnricherFixture(t, newTestOnlineResolver(t, provider))
	m, err := db.CreateMachine(t.Context(), store.Machine{Name: "partial", Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.ApplyScrape(t.Context(), store.ScrapeDelta{MachineID: m.ID, At: time.Now().UTC(), Attackers: []store.AttackerDelta{{IPAddress: "100.64.0.1", Country: "Exporter country", Location: "Exporter city", Connections: 1}}}); err != nil {
		t.Fatal(err)
	}
	e.runOnce(t.Context())
	e.runOnce(t.Context())
	if provider.requests.Load() != 1 {
		t.Fatal("negative answer re-requested without delay")
	}
	var country, location string
	if err = db.DB().QueryRow("SELECT country,location FROM attackers WHERE ip_address='100.64.0.1'").Scan(&country, &location); err != nil || country != "Exporter country" || location != "Exporter city" {
		t.Fatal("miss wiped partial geography", country, location, err)
	}
	changed := newFakeProvider(t)
	partial := `{"status":"success","country":"New country","isp":"New ISP"}`
	changed.body.Store(&partial)
	e.online = newTestOnlineResolver(t, changed)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	e.runOnce(t.Context())
	var outcome string
	if err = db.DB().QueryRow("SELECT outcome FROM enrichment_progress WHERE ip_address='100.64.0.1'").Scan(&outcome); err != nil || outcome != "partial" {
		t.Fatal("partial answer not deferred", outcome, err)
	}
	e.runOnce(t.Context())
	if changed.requests.Load() != 1 {
		t.Fatal("partial success monopolized queue")
	}
	answer := successPayload
	changed.body.Store(&answer)
	now = now.Add(24 * time.Hour)
	e.runOnce(t.Context())
	var code string
	if err = db.DB().QueryRow("SELECT country,location,country_code FROM attackers WHERE ip_address='100.64.0.1'").Scan(&country, &location, &code); err != nil || country != "Exporter country" || location != "Exporter city" || code != "US" || changed.requests.Load() != 2 {
		t.Fatal("eligible retry used stale cache or wiped labels", country, location, code, changed.requests.Load(), err)
	}
}
