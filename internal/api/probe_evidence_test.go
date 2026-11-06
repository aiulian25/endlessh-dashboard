package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/scrape"
)

func TestProbeEvidenceFromRealParser(t *testing.T) {
	normal, err := os.ReadFile("../scrape/testdata/normal.txt")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := os.ReadFile("../scrape/testdata/empty.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, body, state string
		status, families  int
	}{
		{"unreachable", "", "unavailable", 502, 0},
		{"HTTP failure", "not found", "unavailable", 502, 0},
		{"runtime", "# TYPE go_goroutines gauge\ngo_goroutines 9\n", "inconclusive", 200, 0},
		{"fresh", string(empty), "inconclusive", 200, 0},
		{"empty", "", "inconclusive", 200, 0},
		{"known", string(normal), "compatible", 200, 6},
		{"partial", "# TYPE endlessh_client_open_count_total counter\nendlessh_client_open_count_total{local_port=\"2222\"} 0\n", "partial", 200, 1},
		{"untyped", "endlessh_client_open_count_total 0\n", "partial", 200, 1},
		{"wrong type", "# TYPE endlessh_client_open_count_total gauge\nendlessh_client_open_count_total 1\n", "unavailable", 502, 0},
		{"malformed", "bad{\n", "unavailable", 502, 0},
		{"oversized", "# " + strings.Repeat("x", 8<<20) + "\n", "unavailable", 502, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.name == "HTTP failure" {
					w.WriteHeader(404)
				}
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, c.body)
			}))
			defer target.Close()
			host, portText, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
			port, _ := strconv.Atoi(portText)
			if c.name == "unreachable" {
				target.Close()
			}
			_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
			validator := registry.NewValidator([]*net.IPNet{loopback}, false)
			poller := scrape.NewPoller(nil, validator, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Minute, 5*time.Second)
			s := &Server{registry: registry.NewService(nil, validator), prober: poller}
			input, _ := json.Marshal(map[string]any{"host": host, "port": port, "metrics_path": "/metrics"})
			response := httptest.NewRecorder()
			s.handleTestMachine(response, httptest.NewRequest("POST", "/api/machines/test", bytes.NewReader(input)))
			var body struct {
				Reachable bool   `json:"reachable"`
				Valid     bool   `json:"exposition_valid"`
				State     string `json:"endlessh_evidence"`
				Families  []struct {
					Name, Type string
					Samples    int
				} `json:"metric_families"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != c.status || body.Reachable != (c.name != "unreachable") || body.Valid != (c.status == 200) || body.State != c.state || len(body.Families) != c.families {
				t.Fatalf("unexpected probe: status=%d %s", response.Code, response.Body.String())
			}
			for _, family := range body.Families {
				if !strings.HasPrefix(family.Name, "endlessh_") || family.Samples < 1 || (family.Type != "counter" && family.Type != "untyped") {
					t.Fatalf("invalid evidence %+v", family)
				}
			}
			if strings.Contains(response.Body.String(), "45.155.205.233") || strings.Contains(response.Body.String(), "go1.23.4") {
				t.Fatal("raw labels or runtime version exposed as evidence")
			}
			if c.state == "inconclusive" && (!strings.Contains(body.Message, "inconclusive") || strings.Contains(body.Message, "Reached endlessh-go")) {
				t.Fatalf("misleading identity: %s", body.Message)
			}
			if c.name == "wrong type" && !strings.Contains(response.Body.String(), "got gauge") {
				t.Fatal("wrong-type diagnostic missing")
			}
		})
	}
}
