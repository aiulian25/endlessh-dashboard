package api

import (
	"context"
	"endlessh-dashboard/internal/store"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCountryIdentityAPI(t *testing.T) {
	h := newSignedInHarness(t)
	m := h.seedMachine("aliases")
	now := time.Now().UTC()
	err := h.store.ApplyScrape(context.Background(), store.ScrapeDelta{MachineID: m.ID, At: now, Attackers: []store.AttackerDelta{
		{IPAddress: "192.0.2.1", Country: "Germany", CountryCode: "de", Connections: 2},
		{IPAddress: "192.0.2.2", Country: "Deutschland", CountryCode: "DE", Connections: 3},
		{IPAddress: "192.0.2.3", Country: "Germany", Connections: 5},
		{IPAddress: "192.0.2.4", Country: "Coast\u00a0", Connections: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var chips []countryCountResponse
	r := h.request(http.MethodGet, "/api/attackers/countries", nil)
	assertStatus(t, "chips", r, 200)
	r.decode(t, &chips)
	var donut []geoCountryResponse
	r = h.request(http.MethodGet, "/api/geo/countries", nil)
	assertStatus(t, "donut", r, 200)
	r.decode(t, &donut)
	var overview overviewResponse
	r = h.request(http.MethodGet, "/api/overview", nil)
	assertStatus(t, "overview", r, 200)
	r.decode(t, &overview)
	if len(chips) != 3 || len(donut) != 3 || overview.Countries != 3 {
		t.Fatal(chips, donut, overview)
	}
	for i, c := range chips {
		if c.CountryKey != donut[i].CountryKey || c.Count != donut[i].Attackers {
			t.Fatal("mismatched summaries", chips, donut)
		}
		var page attackerPageResponse
		r = h.request(http.MethodGet, "/api/attackers?country_key="+url.QueryEscape(c.CountryKey)+"&country=unrelated", nil)
		assertStatus(t, "stable filter", r, 200)
		r.decode(t, &page)
		if page.Total != c.Count {
			t.Fatal("summary does not select its rows", c, page)
		}
		if c.CountryKey == "code:DE" && (page.Total != 2 || page.Rows[0].Country == page.Rows[1].Country) {
			t.Fatal("aliases/source labels lost", page)
		}
	}
	// Existing integrations may still use the original name/code parameter.
	var legacy attackerPageResponse
	r = h.request(http.MethodGet, "/api/attackers?country=Germany", nil)
	assertStatus(t, "legacy filter", r, 200)
	r.decode(t, &legacy)
	if legacy.Total != 2 {
		t.Fatal(legacy)
	}
}
