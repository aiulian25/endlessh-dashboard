package store

import (
	"context"
	"testing"
	"time"
)

func TestCountryIdentityAcrossSummariesAndFilters(t *testing.T) {
	s, _ := newStore(t)
	a := createMachine(t, s, "a")
	b := createMachine(t, s, "b")
	ctx := context.Background()
	lat, lon := 50.0, 10.0
	rows := []AttackerDelta{
		{IPAddress: "192.0.2.1", Country: "Germany", CountryCode: " \tde\r ", Connections: 2, Latitude: &lat, Longitude: &lon},
		{IPAddress: "192.0.2.2", Country: "Deutschland", CountryCode: "DE", Connections: 3, Latitude: &lat, Longitude: &lon},
		{IPAddress: "192.0.2.3", Country: " \tGermany\n ", Connections: 5},
		{IPAddress: "192.0.2.4", Country: "GERMANY", CountryCode: "invalid", Connections: 7},
		{IPAddress: "192.0.2.5", Country: "Germany", CountryCode: "FR", Connections: 11, Latitude: &lat, Longitude: &lon},
		{IPAddress: "192.0.2.6", Connections: 13},
		{IPAddress: "192.0.2.7", CountryCode: "us", Connections: 17},
	}
	applyScrape(t, s, ScrapeDelta{MachineID: a.ID, At: baseTime, Attackers: rows})
	applyScrape(t, s, ScrapeDelta{MachineID: b.ID, At: baseTime, Attackers: []AttackerDelta{rows[0]}})
	ids := []int64{a.ID, b.ID}
	span := TimeRange{From: baseTime, To: baseTime.Add(time.Minute)}
	totals, err := s.CountryTotalsInRange(ctx, ids, span, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(totals) != 4 {
		t.Fatalf("identities: %+v", totals)
	}
	wants := map[string]struct {
		ips, copies int
		connections int64
	}{"code:DE": {2, 3, 7}, "name:germany": {2, 2, 12}, "code:FR": {1, 1, 11}, "code:US": {1, 1, 17}}
	for _, total := range totals {
		w, ok := wants[total.CountryKey]
		if !ok || total.Attackers != w.ips || total.Connections != w.connections {
			t.Fatalf("summary %+v", total)
		}
		page, err := s.ListAttackers(ctx, AttackerFilter{MachineIDs: ids, Since: span.From, Until: span.To, CountryKey: total.CountryKey, PerPage: 100})
		if err != nil || page.Total != w.copies || page.DistinctIPs != w.ips {
			t.Fatalf("filter %s: %+v %v", total.CountryKey, page, err)
		}
		if total.CountryKey == "code:DE" {
			for _, r := range page.Rows {
				if r.Country != "Germany" && r.Country != "Deutschland" {
					t.Fatal("lost original label", r)
				}
			}
		}
	}
	overview, err := s.Overview(ctx, ids, span.From, baseTime, span.To)
	if err != nil || overview.Countries != len(totals) {
		t.Fatal(overview, err)
	}
	points, err := s.GeoPoints(ctx, ids, span.From, span.To)
	if err != nil || len(points) != 2 {
		t.Fatalf("conflicting countries at same coordinate: %+v %v", points, err)
	}
	for _, point := range points {
		if point.CountryKey == "code:DE" && point.Attackers != 2 {
			t.Fatal(point)
		}
	}
	observed, err := s.CountryTotalsInRange(ctx, ids, span, true)
	if err != nil || len(observed) != 4 {
		t.Fatal(observed, err)
	}
	stale, err := s.CountryTotalsInRange(ctx, ids, TimeRange{From: span.To, To: span.To.Add(time.Minute)}, false)
	if err != nil || len(stale) != 0 {
		t.Fatal(stale, err)
	}
}
