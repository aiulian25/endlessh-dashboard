package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/scrape"
)

// fakeProber stands in for the poller so the handler can be tested without a
// real endlessh-go on the other end.
type fakeProber struct {
	summary  scrape.ProbeSummary
	err      error
	calls    int
	lastHost string
	lastPort int
	lastPath string
}

func (f *fakeProber) Probe(_ context.Context, host string, port int, metricsPath string) (scrape.ProbeSummary, error) {
	f.calls++
	f.lastHost, f.lastPort, f.lastPath = host, port, metricsPath
	return f.summary, f.err
}

func TestTestMachineReportsAReachableTarget(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.prober.err = nil
	testHarness.prober.summary = scrape.ProbeSummary{
		Address:    "192.168.1.10:2112",
		Clients:    3,
		LocalPorts: []string{"2222"},
	}

	answer := testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "192.168.1.10", "port": 2112, "metrics_path": "/metrics"})
	assertStatus(t, "probe a reachable target", answer, http.StatusOK)

	var payload probeResponse
	answer.decode(t, &payload)
	if payload.Clients != 3 || payload.Address != "192.168.1.10:2112" {
		t.Errorf("probe response = %+v, want the summary the prober returned", payload)
	}
	for _, fragment := range []string{"Reached endlessh-go", "192.168.1.10:2112", "2222", "3 attackers"} {
		if !strings.Contains(payload.Message, fragment) {
			t.Errorf("message %q does not mention %q", payload.Message, fragment)
		}
	}
}

// A fresh tarpit has no clients yet; saying so plainly stops that reading as a fault.
func TestTestMachineExplainsAnEmptyButHealthyTarget(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.prober.err = nil
	testHarness.prober.summary = scrape.ProbeSummary{Address: "10.0.0.9:2112"}

	answer := testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "10.0.0.9", "port": 2112, "metrics_path": "/metrics"})
	assertStatus(t, "probe an idle target", answer, http.StatusOK)

	var payload probeResponse
	answer.decode(t, &payload)
	if !strings.Contains(payload.Message, "No attackers recorded there yet") {
		t.Errorf("message %q should reassure that an empty tarpit is normal", payload.Message)
	}
}

func TestTestMachineTranslatesFailures(t *testing.T) {
	cases := []struct {
		name     string
		cause    error
		status   int
		fragment string
	}{
		{"refused", errors.New(`request failed: Get "http://10.0.0.9:2112/metrics": dial tcp 10.0.0.9:2112: connect: connection refused`), http.StatusBadGateway, "-prometheus_enabled"},
		{"timeout", errors.New("request failed: context deadline exceeded"), http.StatusBadGateway, "firewall"},
		{"unknown host", errors.New(`request failed: dial tcp: lookup nope.invalid: no such host`), http.StatusBadGateway, "does not resolve"},
		{"not metrics", errors.New("parse metrics: unexpected token"), http.StatusBadGateway, "not Prometheus metrics"},
		{"wrong status", errors.New("metrics endpoint returned 404 Not Found"), http.StatusBadGateway, "not with metrics"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			testHarness := newSignedInHarness(t)
			testHarness.prober.err = testCase.cause

			answer := testHarness.request(http.MethodPost, "/api/machines/test",
				map[string]any{"host": "10.0.0.9", "port": 2112, "metrics_path": "/metrics"})
			assertStatus(t, testCase.name, answer, testCase.status)

			payload := answer.errorPayload(t)
			if !strings.Contains(payload.Error, testCase.fragment) {
				t.Errorf("error %q does not explain the cause (%q)", payload.Error, testCase.fragment)
			}
			if payload.Field != "host" {
				t.Errorf("field = %q, want host so the form can highlight it", payload.Field)
			}
		})
	}
}

// The test must refuse a target the scraper itself would refuse, otherwise it
// would advertise a machine that can never be added.
func TestTestMachineRefusesBlockedTargets(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.prober.err = nil

	answer := testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "127.0.0.1", "port": 70000, "metrics_path": "/metrics"})
	assertStatus(t, "probe an invalid port", answer, http.StatusBadRequest)
	if payload := answer.errorPayload(t); payload.Field != "port" {
		t.Errorf("field = %q, want port", payload.Field)
	}
	if testHarness.prober.calls != 0 {
		t.Errorf("prober was called %d times for input that failed validation", testHarness.prober.calls)
	}
}

// The name is not required to test a target: people test before they name.
func TestTestMachineDoesNotRequireAName(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.prober.err = nil
	testHarness.prober.summary = scrape.ProbeSummary{Address: "10.0.0.9:2112"}

	answer := testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "10.0.0.9", "port": 2112, "metrics_path": "/metrics"})
	assertStatus(t, "probe without a name", answer, http.StatusOK)
}

// An omitted metrics path must be probed at the same default a saved machine uses.
func TestTestMachineAppliesTheDefaultMetricsPath(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.prober.err = nil

	testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "10.0.0.9", "port": 2112, "metrics_path": ""})
	if testHarness.prober.lastPath != registry.DefaultMetricsPat {
		t.Errorf("probed path = %q, want the default %q", testHarness.prober.lastPath, registry.DefaultMetricsPat)
	}
}

func TestTestMachineNeedsAuthenticationAndCSRF(t *testing.T) {
	testHarness := newHarness(t)
	answer := testHarness.request(http.MethodPost, "/api/machines/test",
		map[string]any{"host": "10.0.0.9", "port": 2112})
	assertStatus(t, "probe without a session", answer, http.StatusUnauthorized)

	signedIn := newSignedInHarness(t)
	withoutToken := signedIn.send(http.MethodPost, "/api/machines/test", "",
		map[string]any{"host": "10.0.0.9", "port": 2112}, nil)
	assertStatus(t, "probe without the CSRF token", withoutToken, http.StatusForbidden)
}
