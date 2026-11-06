package api

import (
	"endlessh-dashboard/internal/store"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestExplicitRangeAgreesAcrossRelatedEndpoints(t *testing.T) {
	h := newSignedInHarness(t)
	m := h.seedMachine("range")
	origin := time.Date(2024, 3, 31, 12, 0, 0, 0, time.UTC)
	for i, seconds := range []float64{10, 20, 30, 40, 50} {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		h.seedScrape(m.ID, origin.Add(time.Duration(i)*time.Minute), ip, "Testland", seconds, int64(seconds))
		lat, lon := 1., 2.
		h.placeAttacker(ip, store.AttackerLocation{Latitude: &lat, Longitude: &lon})
	}
	query := url.Values{"from": {origin.Add(90 * time.Second).Format(time.RFC3339)}, "to": {origin.Add(3 * time.Minute).Format(time.RFC3339)}, "window": {"7d"}}.Encode()
	var overview overviewResponse
	var chart timeSeriesResponse
	for _, endpoint := range []string{"overview", "timeseries", "attackers", "attackers/countries", "geo/points", "geo/countries"} {
		answer := h.request(http.MethodGet, "/api/"+endpoint+"?"+query, nil)
		assertStatus(t, endpoint, answer, http.StatusOK)
		if answer.header.Get("X-Range-From") != origin.Add(2*time.Minute).Format(time.RFC3339) || answer.header.Get("X-Range-To") != origin.Add(3*time.Minute).Format(time.RFC3339) || answer.header.Get("X-Range-Resolution-Seconds") != "60" {
			t.Fatalf("%s did not share effective range", endpoint)
		}
		switch endpoint {
		case "overview":
			answer.decode(t, &overview)
		case "timeseries":
			answer.decode(t, &chart)
		case "geo/points":
			var points []geoPointResponse
			answer.decode(t, &points)
			if len(points) != 1 || points[0].Attackers != 1 || points[0].Connections != 3 {
				t.Fatal("geography range widened")
			}
		case "geo/countries":
			var countries []geoCountryResponse
			answer.decode(t, &countries)
			if len(countries) != 1 || countries[0].Attackers != 1 {
				t.Fatal("country range widened")
			}
		case "attackers/countries":
			var countries []countryCountResponse
			answer.decode(t, &countries)
			if len(countries) != 1 || countries[0].Count != 1 {
				t.Fatal("country chip range widened")
			}
		case "attackers":
			var page attackerPageResponse
			answer.decode(t, &page)
			if page.Total != 1 || page.Rows[0].IPAddress != "192.0.2.3" {
				t.Fatal("attacker upper/lower range ignored")
			}
		}
	}
	var seconds float64
	var bytes int64
	for _, entry := range chart.Series {
		for _, point := range entry.Points {
			seconds += point.TrappedSeconds
			bytes += point.BytesSent
			if !point.Partial || point.At.Before(chart.From) || point.To.After(chart.To) {
				t.Fatal("partial interval not reported")
			}
		}
	}
	if seconds != 30 || overview.TimeWastedDeltaSeconds != seconds || overview.BytesSentDelta != bytes || !overview.From.Equal(chart.From) || !overview.To.Equal(chart.To) {
		t.Fatal("summary/chart ranges or sums differ")
	}
}

func TestRangeValidationSharedAsOfAndEmptyRange(t *testing.T) {
	h := newSignedInHarness(t)
	h.seedMachine("empty")
	stamp := "2024-10-27T01:30:30+01:00"
	var expectedFrom, expectedTo string
	for _, endpoint := range []string{"overview", "timeseries", "attackers", "attackers/countries", "geo/points", "geo/countries"} {
		query := url.Values{"window": {"7d"}, "as_of": {stamp}}.Encode()
		answer := h.request(http.MethodGet, "/api/"+endpoint+"?"+query, nil)
		assertStatus(t, endpoint, answer, http.StatusOK)
		if expectedFrom == "" {
			expectedFrom = answer.header.Get("X-Range-From")
			expectedTo = answer.header.Get("X-Range-To")
		}
		if answer.header.Get("X-Range-From") != expectedFrom || answer.header.Get("X-Range-To") != expectedTo {
			t.Fatal("as_of changed across requests")
		}
	}
	if expectedTo != "2024-10-27T00:31:00Z" {
		t.Fatal("UTC/DST offset incorrectly aligned")
	}
	for _, query := range []string{"from=9999-12-31T23:59:59Z&to=9999-12-31T23:59:59Z", "from=bad&to=bad", "from=2024-01-01T00:00:00Z", "as_of=bad", "from=2024-01-02T00:00:00Z&to=2024-01-01T00:00:00Z", "from=2020-01-01T00:00:00Z&to=2024-01-01T00:00:00Z", "from=2024-01-01T00:00:00Z&to=2024-01-01T00:00:00Z&as_of=2024-01-01T00:00:00Z"} {
		answer := h.request(http.MethodGet, "/api/timeseries?"+query, nil)
		assertStatus(t, "invalid range", answer, http.StatusBadRequest)
	}
	answer := h.request(http.MethodGet, "/api/timeseries?from=2024-01-01T00:00:30Z&to=2024-01-01T00:00:30Z", nil)
	assertStatus(t, "empty range", answer, http.StatusOK)
	var chart timeSeriesResponse
	answer.decode(t, &chart)
	if !chart.From.Equal(chart.To) || len(chart.Series) != 1 || len(chart.Series[0].Points) != 0 {
		t.Fatal("empty range widened")
	}
}
