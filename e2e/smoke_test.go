//go:build e2e

// Package e2e drives the stack in docker-compose.e2e.yml: a real endlessh-go tarpit plus the
// dashboard built from this repo. Run it with:
//
//	docker compose -f e2e/docker-compose.e2e.yml up --build -d
//	E2E=1 go test -tags e2e -count=1 -timeout 15m ./e2e/...
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultBaseURL    = "http://127.0.0.1:18222"
	defaultTarpitAddr = "127.0.0.1:2222"

	seedUsername    = "admin"
	seedPassword    = "e2e-seed-password"
	changedPassword = "e2e-changed-password-4Kq7wz"

	machineName        = "e2e-tarpit"
	machineHost        = "tarpit" // resolved on the compose network by the dashboard container
	machineMetricsPort = 2112
	machineMetricsPath = "/metrics"

	// geographyWindow matches the window the rest of the flow asks for, so the
	// overview and the map endpoints are compared over the same slice of time.
	geographyWindow = "?window=24h"

	tarpitConnections = 5
	pollEvery         = 3 * time.Second
	startupTimeout    = 2 * time.Minute
	dataTimeout       = 3 * time.Minute
	growthTimeout     = 2 * time.Minute
)

type session struct {
	Username           string `json:"username"`
	MustChangePassword bool   `json:"must_change_password"`
	CSRFToken          string `json:"csrf_token"`
}

type machine struct {
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	MetricsPath         string `json:"metrics_path"`
	GroupLabel          string `json:"group_label"`
	Enabled             bool   `json:"enabled"`
	Status              string `json:"status"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastError           string `json:"last_error"`
	TrappedNow          int    `json:"trapped_now"`
	LastScrapeAt        string `json:"last_scrape_at"`
}

type overview struct {
	TimeWastedSeconds float64 `json:"time_wasted_seconds"`
	AttackersTrapped  int64   `json:"attackers_trapped"`
	BytesSent         int64   `json:"bytes_sent"`
	TrappedNow        int64   `json:"trapped_now"`
	MachineCount      int64   `json:"machine_count"`

	UniqueAttackers int64           `json:"unique_attackers"`
	Countries       int             `json:"countries"`
	LatestAttacker  *latestAttacker `json:"latest_attacker"`
}

// latestAttacker is null on an install that has never caught anybody, so it is a
// pointer here too — decoding it into a value would read "never" as a row of
// zeroes and pass.
type latestAttacker struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Location    string `json:"location"`
	At          string `json:"at"`
}

type geoPoint struct {
	Latitude       float64 `json:"lat"`
	Longitude      float64 `json:"lon"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"country_code"`
	Attackers      int     `json:"attackers"`
	Connections    int64   `json:"connections"`
	TrappedSeconds float64 `json:"trapped_seconds"`
}

type geoCountry struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Attackers   int    `json:"attackers"`
	Connections int64  `json:"connections"`
}

type settings struct {
	GeoIPEnabled       bool   `json:"geoip_enabled"`
	GeoIPSource        string `json:"geoip_source"`
	GeoIPOnlineEnabled bool   `json:"geoip_online_enabled"`
}

type attacker struct {
	IP             string  `json:"ip"`
	MachineID      int64   `json:"machine_id"`
	MachineName    string  `json:"machine_name"`
	Country        string  `json:"country"`
	Location       string  `json:"location"`
	FirstSeen      string  `json:"first_seen"`
	LastSeen       string  `json:"last_seen"`
	Connections    int64   `json:"connections"`
	TrappedSeconds float64 `json:"trapped_seconds"`
	BytesSent      int64   `json:"bytes_sent"`
	Status         string  `json:"status"`
}

type attackerPage struct {
	Total int        `json:"total"`
	Rows  []attacker `json:"rows"`
}

type client struct {
	http *http.Client
	base string
	csrf string
}

func newClient(t *testing.T, base string) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &client{
		http: &http.Client{Jar: jar, Timeout: 15 * time.Second},
		base: base,
	}
}

// do returns the status code and raw body; err covers transport and decode failures only.
func (c *client) do(method, path string, body, out any) (int, string, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, "", fmt.Errorf("encode request for %s %s: %w", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.base+path, payload)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read response of %s %s: %w", method, path, err)
	}
	if out == nil || resp.StatusCode/100 != 2 || len(raw) == 0 {
		return resp.StatusCode, string(raw), nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.StatusCode, string(raw), fmt.Errorf("decode response of %s %s: %w (body %s)", method, path, err, raw)
	}
	return resp.StatusCode, string(raw), nil
}

func (c *client) must(t *testing.T, method, path string, body, out any) {
	t.Helper()
	status, raw, err := c.do(method, path, body, out)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, path, err)
	}
	if status/100 != 2 {
		t.Fatalf("%s %s returned %d, want 2xx; body: %s", method, path, status, raw)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func TestTarpitTrafficReachesDashboard(t *testing.T) {
	if os.Getenv("E2E") != "1" {
		t.Skip("e2e disabled: start the stack with `docker compose -f e2e/docker-compose.e2e.yml up --build -d` and re-run with E2E=1")
	}

	baseURL := envOr("E2E_BASE_URL", defaultBaseURL)
	tarpitAddr := envOr("E2E_TARPIT_ADDR", defaultTarpitAddr)

	api := newClient(t, baseURL)
	waitForHealthz(t, api)
	logIn(t, api)

	registered := ensureMachine(t, api)
	t.Logf("machine %d (%s:%d%s) registered", registered.ID, registered.Host, registered.Port, registered.MetricsPath)

	openTarpitConnections(t, tarpitAddr, tarpitConnections)

	waitFor(t, "overview to report trapped attackers", dataTimeout, func() (bool, string) {
		var stats overview
		api.must(t, http.MethodGet, "/api/overview?window=24h", nil, &stats)
		if stats.TimeWastedSeconds > 0 && stats.AttackersTrapped > 0 {
			t.Logf("overview: %.1fs wasted, %d attackers, %d bytes, %d trapped now",
				stats.TimeWastedSeconds, stats.AttackersTrapped, stats.BytesSent, stats.TrappedNow)
			return true, ""
		}
		return false, fmt.Sprintf("time_wasted_seconds=%.1f attackers_trapped=%d bytes_sent=%d trapped_now=%d",
			stats.TimeWastedSeconds, stats.AttackersTrapped, stats.BytesSent, stats.TrappedNow)
	})

	// The tarpit sees the Docker gateway address, not this process's address, so the connecting IP
	// is whatever the API reports rather than something the test can predict.
	first := topAttacker(t, api)
	if first.MachineName != registered.Name {
		t.Fatalf("attacker %s attributed to machine %q, want %q", first.IP, first.MachineName, registered.Name)
	}
	if first.Status != "trapped" {
		t.Fatalf("attacker %s has status %q while its connections are still open, want %q", first.IP, first.Status, "trapped")
	}
	t.Logf("connecting IP %s trapped for %.1fs over %d connections", first.IP, first.TrappedSeconds, first.Connections)

	waitFor(t, fmt.Sprintf("trapped_seconds of %s to grow beyond %.1f", first.IP, first.TrappedSeconds), growthTimeout, func() (bool, string) {
		var page attackerPage
		api.must(t, http.MethodGet, "/api/attackers?window=24h&q="+first.IP, nil, &page)
		for _, row := range page.Rows {
			if row.IP != first.IP {
				continue
			}
			if row.TrappedSeconds > first.TrappedSeconds {
				return true, ""
			}
			return false, fmt.Sprintf("trapped_seconds still %.1f", row.TrappedSeconds)
		}
		return false, fmt.Sprintf("IP %s missing from %d rows returned by the IP-prefix filter", first.IP, len(page.Rows))
	})

	var machines []machine
	api.must(t, http.MethodGet, "/api/machines", nil, &machines)
	current, found := findMachine(machines, machineName)
	if !found {
		t.Fatalf("machine %q vanished from /api/machines", machineName)
	}
	if current.Status != "ok" {
		t.Fatalf("machine %q status is %q after a successful data flow, want \"ok\" (failures=%d, last_error=%q)",
			current.Name, current.Status, current.ConsecutiveFailures, current.LastError)
	}
	if current.ConsecutiveFailures != 0 {
		t.Fatalf("machine %q reports %d consecutive failures, want 0 (last_error=%q)", current.Name, current.ConsecutiveFailures, current.LastError)
	}
	if current.LastScrapeAt == "" {
		t.Fatalf("machine %q has no last_scrape_at despite reporting status %q", current.Name, current.Status)
	}

	assertGeography(t, api, first)
}

// assertGeography covers the map surface against the same window as the rest of
// the flow. A tarpit reached over the compose network only ever meets the Docker
// gateway, an RFC1918 address no source will place, so an empty map is the
// correct answer here rather than a missing feature — what is under test is that
// the endpoints answer, agree with the overview, and stay offline.
func assertGeography(t *testing.T, c *client, trapped attacker) {
	t.Helper()

	// The one thing this stack must never do. GEOIP_ONLINE is simply absent from
	// docker-compose.e2e.yml; this asserts the effect rather than trusting the
	// omission, because a default flipped to on would quietly have every e2e run
	// posting attacker addresses to a third party from whatever host it runs on.
	var effective settings
	c.must(t, http.MethodGet, "/api/settings", nil, &effective)
	if effective.GeoIPOnlineEnabled {
		t.Fatal("the e2e stack has online geography lookups enabled; this test must never send an address to a third party")
	}

	var points []geoPoint
	mustArray(t, c, "/api/geo/points"+geographyWindow, &points)
	for _, point := range points {
		if point.Latitude < -90 || point.Latitude > 90 || point.Longitude < -180 || point.Longitude > 180 {
			t.Errorf("map bubble %+v sits off the earth", point)
		}
		if point.Attackers < 1 {
			t.Errorf("map bubble %+v plots no attackers", point)
		}
	}

	var countries []geoCountry
	mustArray(t, c, "/api/geo/countries"+geographyWindow, &countries)
	for _, country := range countries {
		if country.Country == "" {
			t.Errorf("the country breakdown carries a nameless row: %+v", country)
		}
	}

	var stats overview
	c.must(t, http.MethodGet, "/api/overview"+geographyWindow, nil, &stats)
	if stats.UniqueAttackers < 1 {
		t.Errorf("overview counts %d unique attackers while %s is trapped", stats.UniqueAttackers, trapped.IP)
	}
	// Both numbers count placed countries over the same window and machines, so
	// disagreement means the overview and the map are reading the data
	// differently — the wiring this whole assertion exists to protect.
	if stats.Countries != len(countries) {
		t.Errorf("overview counts %d countries while the breakdown lists %d", stats.Countries, len(countries))
	}
	if stats.LatestAttacker == nil {
		t.Fatalf("overview carries no latest_attacker while %s is trapped", trapped.IP)
	}
	if net.ParseIP(stats.LatestAttacker.IP) == nil {
		t.Errorf("latest_attacker carries %q, which is not an IP address", stats.LatestAttacker.IP)
	}
	if stats.LatestAttacker.At == "" {
		t.Error("latest_attacker carries no timestamp")
	}

	t.Logf("geography: %d map bubbles, %d countries, %d unique attackers, newest %s (geoip source %q, online %v)",
		len(points), len(countries), stats.UniqueAttackers, stats.LatestAttacker.IP,
		effective.GeoIPSource, effective.GeoIPOnlineEnabled)
}

// mustArray fetches a collection endpoint and insists the body really is a JSON
// array. An install with nothing to plot has to answer [] rather than null: the
// pages that draw these iterate the payload they are handed.
func mustArray(t *testing.T, c *client, path string, out any) {
	t.Helper()
	status, raw, err := c.do(http.MethodGet, path, nil, out)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200; body: %s", path, status, raw)
	}
	if trimmed := strings.TrimSpace(raw); !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("GET %s returned %s, want a JSON array", path, trimmed)
	}
}

func waitForHealthz(t *testing.T, c *client) {
	t.Helper()
	waitFor(t, "the dashboard to answer /healthz", startupTimeout, func() (bool, string) {
		status, raw, err := c.do(http.MethodGet, "/healthz", nil, nil)
		if err != nil {
			return false, err.Error()
		}
		if status == http.StatusOK && strings.TrimSpace(raw) == "ok" {
			return true, ""
		}
		return false, fmt.Sprintf("status %d, body %q", status, raw)
	})
}

// logIn handles the forced first-login password change, and tolerates a re-run against a stack
// where that change already happened.
func logIn(t *testing.T, c *client) {
	t.Helper()
	current, ok := attemptLogin(t, c, seedPassword)
	if !ok {
		current, ok = attemptLogin(t, c, changedPassword)
		if !ok {
			t.Fatalf("login rejected for both the seed and the changed password; is ADMIN_PASSWORD in docker-compose.e2e.yml still %q?", seedPassword)
		}
	}
	if !current.MustChangePassword {
		return
	}

	c.must(t, http.MethodPost, "/api/password", map[string]string{
		"current_password": seedPassword,
		"new_password":     changedPassword,
	}, nil)

	var refreshed session
	status, raw, err := c.do(http.MethodGet, "/api/session", nil, &refreshed)
	if err != nil {
		t.Fatalf("GET /api/session after password change: %v", err)
	}
	if status == http.StatusUnauthorized {
		if _, ok := attemptLogin(t, c, changedPassword); !ok {
			t.Fatal("the new password does not work right after the forced password change")
		}
		return
	}
	if status/100 != 2 {
		t.Fatalf("GET /api/session after password change returned %d; body: %s", status, raw)
	}
	if refreshed.MustChangePassword {
		t.Fatal("session still reports must_change_password after a successful password change")
	}
	c.csrf = refreshed.CSRFToken
}

func attemptLogin(t *testing.T, c *client, password string) (session, bool) {
	t.Helper()
	var current session
	status, raw, err := c.do(http.MethodPost, "/api/login", map[string]string{
		"username": seedUsername,
		"password": password,
	}, &current)
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	if status == http.StatusUnauthorized {
		return session{}, false
	}
	if status/100 != 2 {
		t.Fatalf("POST /api/login returned %d; body: %s", status, raw)
	}
	if current.CSRFToken == "" {
		t.Fatal("login succeeded but returned an empty csrf_token")
	}
	c.csrf = current.CSRFToken
	return current, true
}

func ensureMachine(t *testing.T, c *client) machine {
	t.Helper()
	var existing []machine
	c.must(t, http.MethodGet, "/api/machines", nil, &existing)
	if found, ok := findMachine(existing, machineName); ok {
		return found
	}

	var created machine
	c.must(t, http.MethodPost, "/api/machines", map[string]any{
		"name":         machineName,
		"host":         machineHost,
		"port":         machineMetricsPort,
		"metrics_path": machineMetricsPath,
		"group_label":  "e2e",
		"enabled":      true,
	}, &created)
	if created.ID == 0 {
		t.Fatal("POST /api/machines returned a machine without an id")
	}
	return created
}

func findMachine(machines []machine, name string) (machine, bool) {
	for _, candidate := range machines {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return machine{}, false
}

func topAttacker(t *testing.T, c *client) attacker {
	t.Helper()
	var page attackerPage
	c.must(t, http.MethodGet, "/api/attackers?window=24h&sort=trapped_seconds&order=desc&per_page=50", nil, &page)
	if len(page.Rows) == 0 {
		t.Fatal("overview reported trapped attackers but /api/attackers returned no rows")
	}
	top := page.Rows[0]
	if top.TrappedSeconds <= 0 {
		t.Fatalf("top attacker %s has trapped_seconds %.1f, want > 0", top.IP, top.TrappedSeconds)
	}
	if net.ParseIP(top.IP) == nil {
		t.Fatalf("attacker row carries %q, which is not an IP address", top.IP)
	}
	return top
}

// openTarpitConnections holds raw TCP connections to the tarpit for the rest of the test, draining
// the banner so the connections stay alive.
func openTarpitConnections(t *testing.T, addr string, count int) {
	t.Helper()
	opened := 0
	for i := 0; i < count; i++ {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Logf("connection %d to the tarpit at %s failed: %v", i+1, addr, err)
			continue
		}
		t.Cleanup(func() { conn.Close() })
		go io.Copy(io.Discard, conn)
		opened++
	}
	if opened == 0 {
		t.Fatalf("could not open any connection to the tarpit at %s; is the e2e stack up?", addr)
	}
	t.Logf("holding %d connections open against the tarpit at %s", opened, addr)
}

func waitFor(t *testing.T, what string, timeout time.Duration, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := "no observation recorded"
	for {
		ok, detail := check()
		if ok {
			return
		}
		last = detail
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last observation: %s", timeout, what, last)
		}
		time.Sleep(pollEvery)
	}
}
