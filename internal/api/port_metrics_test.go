package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestPortSummaryAndTimeseriesUnavailableAndValidation(t *testing.T) {
	h := newSignedInHarness(t)
	m := h.seedMachine("port history")
	at := time.Now().UTC().Truncate(5 * time.Minute).Add(-5 * time.Minute)
	// Legacy merged history remains available only in the unfiltered chart.
	if err := h.store.ApplyScrape(t.Context(), store.ScrapeDelta{MachineID: m.ID, At: at, Opens: 99}); err != nil {
		t.Fatal(err)
	}
	next := at.Add(5 * time.Minute)
	if err := h.store.ApplyScrape(t.Context(), store.ScrapeDelta{MachineID: m.ID, At: next, Opens: 5, BytesSent: 50, Ports: []store.PortDelta{{Port: "22", Opens: 2, BytesSent: 20}, {Port: "2222", Opens: 3, BytesSent: 30}}}); err != nil {
		t.Fatal(err)
	}
	query := fmt.Sprintf("?machines=%d&from=%s&to=%s", m.ID, at.Format(time.RFC3339), next.Add(time.Minute).Format(time.RFC3339))
	answer := h.request(http.MethodGet, "/api/ports"+query, nil)
	assertStatus(t, "ports", answer, 200)
	var summary store.PortSummaryResponse
	answer.decode(t, &summary)
	if !summary.Available || len(summary.Rows) != 2 || summary.Rows[0].Opens != 2 || summary.CollectionStartedAt == nil {
		t.Fatalf("unexpected summary %+v", summary)
	}
	selected := h.request(http.MethodGet, "/api/ports"+query+"&port=22", nil)
	selected.decode(t, &summary)
	if len(summary.Rows) != 1 || summary.Rows[0].Port != "22" {
		t.Fatal("port summary filter ignored")
	}
	chart := h.request(http.MethodGet, "/api/timeseries"+query+"&port=22", nil)
	assertStatus(t, "filtered chart", chart, 200)
	var response struct {
		Series []struct {
			Points []struct {
				Available bool   `json:"available"`
				Opens     *int64 `json:"opens"`
				Bytes     *int64 `json:"bytes_sent"`
			}
		}
	}
	if err := json.Unmarshal(chart.body, &response); err != nil {
		t.Fatal(err)
	}
	points := response.Series[0].Points
	if len(points) != 2 || points[0].Available || points[0].Opens != nil || !points[1].Available || points[1].Opens == nil || *points[1].Opens != 2 || points[1].Bytes == nil || *points[1].Bytes != 20 {
		t.Fatalf("old history became zero or port filter failed: %s", chart.body)
	}
	unknown := h.request(http.MethodGet, "/api/timeseries"+query+"&port=65535", nil)
	assertStatus(t, "new port", unknown, 200)
	if err := json.Unmarshal(unknown.body, &response); err != nil {
		t.Fatal(err)
	}
	for _, point := range response.Series[0].Points {
		if point.Available || point.Opens != nil {
			t.Fatal("unknown port fabricated zero")
		}
	}
	for _, suffix := range []string{"&port=0", "&port=65536", "&port=022", "&port=x", "&port=22&port=2222", "&port="} {
		for _, endpoint := range []string{"/api/ports", "/api/timeseries"} {
			bad := h.request(http.MethodGet, endpoint+query+suffix, nil)
			assertStatus(t, "invalid port", bad, 400)
		}
	}
}
