package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/auth"
	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

const (
	seedUsername        = "admin"
	seedPassword        = "seed-password-change-me"
	replacementPassword = "replacement-password-7Qx"

	testVersion = "test-version"

	// scrapeHost is in TEST-NET-3: it passes the address rules without being
	// loopback or private, and nothing in these tests ever dials it.
	scrapeHost = "203.0.113.10"
	scrapePort = 2112

	testScrapeInterval = 15 * time.Second
	defaultWindowSpan  = 24 * time.Hour
	defaultBucketWidth = 300
)

type harness struct {
	t            *testing.T
	httpServer   *httptest.Server
	client       *http.Client
	store        *store.Store
	prober       *fakeProber
	csrfToken    string
	databasePath string
	restart      chan struct{}
}

type response struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func (r response) decode(t *testing.T, target any) {
	t.Helper()
	if err := json.Unmarshal(r.body, target); err != nil {
		t.Fatalf("decode response %q: %v", r.body, err)
	}
}

func (r response) errorPayload(t *testing.T) errorResponse {
	t.Helper()
	var payload errorResponse
	r.decode(t, &payload)
	return payload
}

func (r response) sessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	for _, cookie := range r.cookies {
		if cookie.Name == SessionCookieName {
			return cookie
		}
	}
	t.Fatalf("no %s cookie in Set-Cookie: %v", SessionCookieName, r.header.Values("Set-Cookie"))
	return nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	directory := t.TempDir()
	configuration := &config.Config{
		DataDirectory:   directory,
		ScrapeInterval:  testScrapeInterval,
		ScrapeTimeout:   5 * time.Second,
		RetentionDays:   90,
		AdminUsername:   seedUsername,
		AdminPassword:   seedPassword,
		SecureCookies:   config.SecureCookieAuto,
		BackupKeepLast:  7,
		SessionLifetime: 12 * time.Hour,
	}

	dataStore, err := store.Open(configuration.DatabasePath())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	authService := auth.NewService(dataStore, configuration.SessionLifetime)
	created, err := authService.EnsureInitialUser(context.Background(), seedUsername, seedPassword)
	if err != nil {
		t.Fatalf("seed the admin account: %v", err)
	}
	if !created {
		t.Fatal("the admin account was not seeded into a fresh database")
	}

	geoResolver, err := geo.Open("")
	if err != nil {
		t.Fatalf("open geo resolver: %v", err)
	}
	backupManager := store.NewBackupManager(
		dataStore, configuration.BackupDirectory(), configuration.DatabasePath(), configuration.BackupKeepLast)
	registryService := registry.NewService(dataStore, registry.NewValidator(nil, false))
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	prober := &fakeProber{err: errors.New("probe not configured in this test")}
	restart := make(chan struct{}, 1)
	server := NewServer(configuration, dataStore, authService, registryService,
		backupManager, geoResolver, prober, logger, testVersion, restart)

	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	return &harness{
		t:            t,
		httpServer:   httpServer,
		client:       &http.Client{Jar: jar, Timeout: 30 * time.Second},
		store:        dataStore,
		prober:       prober,
		databasePath: configuration.DatabasePath(),
		restart:      restart,
	}
}

// newSignedInHarness returns a harness past the forced first password change,
// so its session can reach the ordinary endpoints.
func newSignedInHarness(t *testing.T) *harness {
	t.Helper()
	testHarness := newHarness(t)
	testHarness.logIn(seedPassword)
	testHarness.changePassword(seedPassword, replacementPassword)
	testHarness.logIn(replacementPassword)
	return testHarness
}

// send performs one request. csrfToken is sent verbatim; an empty value omits
// the header entirely.
func (h *harness) send(method, path, csrfToken string, body any, headers map[string]string) response {
	h.t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("encode body for %s %s: %v", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, h.httpServer.URL+path, payload)
	if err != nil {
		h.t.Fatalf("build request %s %s: %v", method, path, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrfToken != "" {
		request.Header.Set(CSRFHeaderName, csrfToken)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	answer, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer answer.Body.Close()

	raw, err := io.ReadAll(answer.Body)
	if err != nil {
		h.t.Fatalf("read the response of %s %s: %v", method, path, err)
	}
	return response{status: answer.StatusCode, body: raw, header: answer.Header, cookies: answer.Cookies()}
}

func (h *harness) request(method, path string, body any) response {
	h.t.Helper()
	return h.send(method, path, h.csrfToken, body, nil)
}

// logIn signs in and remembers the CSRF token the session was issued with.
func (h *harness) logIn(password string) sessionResponse {
	h.t.Helper()
	h.csrfToken = ""
	answer := h.send(http.MethodPost, "/api/login", "", credentials(password), nil)
	if answer.status != http.StatusOK {
		h.t.Fatalf("POST /api/login returned %d, want 200; body: %s", answer.status, answer.body)
	}

	var current sessionResponse
	answer.decode(h.t, &current)
	if current.CSRFToken == "" {
		h.t.Fatal("login succeeded but returned an empty csrf_token")
	}
	h.csrfToken = current.CSRFToken
	return current
}

func (h *harness) changePassword(current, replacement string) {
	h.t.Helper()
	answer := h.request(http.MethodPost, "/api/password", map[string]string{
		"current_password": current,
		"new_password":     replacement,
	})
	if answer.status != http.StatusNoContent {
		h.t.Fatalf("POST /api/password returned %d, want 204; body: %s", answer.status, answer.body)
	}
	h.csrfToken = ""
}

func (h *harness) seedMachine(name string) store.Machine {
	h.t.Helper()
	machine, err := h.store.CreateMachine(context.Background(), store.Machine{
		Name:        name,
		Host:        scrapeHost,
		Port:        scrapePort,
		MetricsPath: "/metrics",
		GroupLabel:  "test",
		Enabled:     true,
	})
	if err != nil {
		h.t.Fatalf("seed machine %q: %v", name, err)
	}
	return machine
}

// seedScrape writes one scrape's worth of history so the reporting endpoints
// have something real to aggregate. The timestamp matters: rollups land in a
// bucket derived from it, and an attacker counts as trapped only while its last
// activity is recent.
func (h *harness) seedScrape(machineID int64, at time.Time, ipAddress, country string, trappedSeconds float64, bytesSent int64) {
	h.t.Helper()
	err := h.store.ApplyScrape(context.Background(), store.ScrapeDelta{
		MachineID:      machineID,
		At:             at,
		Opens:          3,
		Closes:         1,
		BytesSent:      bytesSent,
		TrappedSeconds: trappedSeconds,
		Attackers: []store.AttackerDelta{{
			IPAddress:      ipAddress,
			Connections:    3,
			TrappedSeconds: trappedSeconds,
			Country:        country,
			Location:       country + ", Somewhere",
			Active:         true,
		}},
	})
	if err != nil {
		h.t.Fatalf("seed scrape for machine %d: %v", machineID, err)
	}
}

// placeAttacker stands in for the enrichment worker: it writes the coordinate
// and ISP a tarpit label never carries, so the map endpoints have real rows.
func (h *harness) placeAttacker(ipAddress string, location store.AttackerLocation) {
	h.t.Helper()
	if err := h.store.SetAttackerLocation(context.Background(), ipAddress, location); err != nil {
		h.t.Fatalf("place attacker %s: %v", ipAddress, err)
	}
}

func at(latitude, longitude float64) (*float64, *float64) {
	return &latitude, &longitude
}

func credentials(password string) map[string]string {
	return map[string]string{"username": seedUsername, "password": password}
}

func machinePayload(name, host string) map[string]any {
	return map[string]any{
		"name":         name,
		"host":         host,
		"port":         scrapePort,
		"metrics_path": "/metrics",
		"group_label":  "test",
		"enabled":      true,
	}
}

// jsonKeys returns the top-level field names of a JSON object, so a renamed
// field is caught instead of silently decoding to a zero value.
func jsonKeys(t *testing.T, label string, raw []byte) []string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("%s is not a JSON object: %v (body %s)", label, err, raw)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func assertJSONKeys(t *testing.T, label string, raw []byte, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := jsonKeys(t, label, raw)
	if !slices.Equal(got, want) {
		t.Fatalf("%s has fields %v, want %v", label, got, want)
	}
}

func assertStatus(t *testing.T, label string, answer response, want int) {
	t.Helper()
	if answer.status != want {
		t.Fatalf("%s returned %d, want %d; body: %s", label, answer.status, want, answer.body)
	}
}

// setCookieAttributes splits one Set-Cookie header into its attribute tokens,
// so "Secure" cannot be matched inside the random cookie value.
func setCookieAttributes(header string) map[string]bool {
	attributes := map[string]bool{}
	for index, part := range strings.Split(header, ";") {
		if index == 0 {
			continue
		}
		attributes[strings.TrimSpace(part)] = true
	}
	return attributes
}

func TestHealthzNeedsNoAuthentication(t *testing.T) {
	testHarness := newHarness(t)

	answer := testHarness.request(http.MethodGet, "/healthz", nil)
	assertStatus(t, "GET /healthz", answer, http.StatusOK)
	if strings.TrimSpace(string(answer.body)) != "ok" {
		t.Fatalf("GET /healthz returned body %q, want \"ok\"", answer.body)
	}
	if len(answer.cookies) != 0 {
		t.Fatalf("GET /healthz set cookies: %v", answer.cookies)
	}
}

func TestAPIEndpointsRejectAnonymousCallers(t *testing.T) {
	testHarness := newHarness(t)

	const backupName = "endlessh-20240102-030405.db"
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/logout"},
		{http.MethodGet, "/api/session"},
		{http.MethodPost, "/api/password"},
		{http.MethodGet, "/api/machines"},
		{http.MethodPost, "/api/machines"},
		{http.MethodPut, "/api/machines/1"},
		{http.MethodDelete, "/api/machines/1"},
		{http.MethodGet, "/api/overview"},
		{http.MethodGet, "/api/timeseries"},
		{http.MethodGet, "/api/attackers"},
		{http.MethodGet, "/api/attackers/countries"},
		{http.MethodGet, "/api/geo/points"},
		{http.MethodGet, "/api/geo/countries"},
		{http.MethodGet, "/api/backups"},
		{http.MethodPost, "/api/backups"},
		{http.MethodGet, "/api/backups/" + backupName},
		{http.MethodPost, "/api/backups/" + backupName + "/restore"},
		{http.MethodDelete, "/api/backups/" + backupName},
		{http.MethodPost, "/api/backups/upload"},
		{http.MethodGet, "/api/settings"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			label := route.method + " " + route.path
			answer := testHarness.send(route.method, route.path, "", nil, nil)
			assertStatus(t, label, answer, http.StatusUnauthorized)

			payload := answer.errorPayload(t)
			if payload.Error == "" {
				t.Fatalf("%s returned 401 without an error message: %s", label, answer.body)
			}
		})
	}

	// The machine list stays empty: nothing anonymous got through.
	var machines []machineResponse
	testHarness.logIn(seedPassword)
	testHarness.changePassword(seedPassword, replacementPassword)
	testHarness.logIn(replacementPassword)
	answer := testHarness.request(http.MethodGet, "/api/machines", nil)
	assertStatus(t, "GET /api/machines", answer, http.StatusOK)
	answer.decode(t, &machines)
	if len(machines) != 0 {
		t.Fatalf("an anonymous request created %d machines", len(machines))
	}
}

func TestLoginCookieIsHttpOnlyAndSameSiteStrict(t *testing.T) {
	testHarness := newHarness(t)

	plain := testHarness.send(http.MethodPost, "/api/login", "", credentials(seedPassword), nil)
	assertStatus(t, "POST /api/login", plain, http.StatusOK)

	cookie := plain.sessionCookie(t)
	if !cookie.HttpOnly {
		t.Fatal("the session cookie is not HttpOnly, so a script could read it")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("the session cookie has SameSite %v, want Strict", cookie.SameSite)
	}
	if cookie.Value == "" {
		t.Fatal("the session cookie carries no value")
	}

	attributes := setCookieAttributes(plain.header.Get("Set-Cookie"))
	if !attributes["HttpOnly"] {
		t.Fatalf("Set-Cookie %q lacks HttpOnly", plain.header.Get("Set-Cookie"))
	}
	if !attributes["SameSite=Strict"] {
		t.Fatalf("Set-Cookie %q lacks SameSite=Strict", plain.header.Get("Set-Cookie"))
	}
	// Auto mode over plain HTTP: marking it Secure would make the cookie
	// unusable, so it must be absent here.
	if attributes["Secure"] || cookie.Secure {
		t.Fatalf("Set-Cookie %q is marked Secure over plain HTTP in auto mode", plain.header.Get("Set-Cookie"))
	}

	behindProxy := testHarness.send(http.MethodPost, "/api/login", "", credentials(seedPassword),
		map[string]string{"X-Forwarded-Proto": "https"})
	assertStatus(t, "POST /api/login behind an HTTPS proxy", behindProxy, http.StatusOK)

	proxiedCookie := behindProxy.sessionCookie(t)
	if !proxiedCookie.Secure {
		t.Fatalf("Set-Cookie %q is not Secure behind X-Forwarded-Proto: https",
			behindProxy.header.Get("Set-Cookie"))
	}
	proxiedAttributes := setCookieAttributes(behindProxy.header.Get("Set-Cookie"))
	if !proxiedAttributes["Secure"] || !proxiedAttributes["HttpOnly"] || !proxiedAttributes["SameSite=Strict"] {
		t.Fatalf("Set-Cookie %q behind an HTTPS proxy is missing an attribute",
			behindProxy.header.Get("Set-Cookie"))
	}
	if behindProxy.header.Get("Strict-Transport-Security") == "" {
		t.Fatal("no Strict-Transport-Security header on a request that arrived over HTTPS")
	}
}

func TestMutatingRequestsRequireTheCSRFToken(t *testing.T) {
	testHarness := newSignedInHarness(t)
	existing := testHarness.seedMachine("already-here")

	cases := []struct {
		name       string
		method     string
		path       string
		body       any
		wantStatus int
	}{
		{"create", http.MethodPost, "/api/machines", machinePayload("csrf-machine", scrapeHost), http.StatusCreated},
		{"update", http.MethodPut, fmt.Sprintf("/api/machines/%d", existing.ID), machinePayload("renamed", scrapeHost), http.StatusOK},
		{"delete", http.MethodDelete, fmt.Sprintf("/api/machines/%d", existing.ID), nil, http.StatusNoContent},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			label := testCase.method + " " + testCase.path

			withoutToken := testHarness.send(testCase.method, testCase.path, "", testCase.body, nil)
			assertStatus(t, label+" without a CSRF token", withoutToken, http.StatusForbidden)
			if withoutToken.errorPayload(t).Error == "" {
				t.Fatalf("%s without a CSRF token returned 403 without a message", label)
			}

			wrongToken := testHarness.send(testCase.method, testCase.path, "not-the-real-token", testCase.body, nil)
			assertStatus(t, label+" with a wrong CSRF token", wrongToken, http.StatusForbidden)

			accepted := testHarness.request(testCase.method, testCase.path, testCase.body)
			assertStatus(t, label+" with the CSRF token", accepted, testCase.wantStatus)
		})
	}

	// A GET needs no token at all.
	read := testHarness.send(http.MethodGet, "/api/machines", "", nil, nil)
	assertStatus(t, "GET /api/machines without a CSRF token", read, http.StatusOK)
}

func TestForcedPasswordChangeGate(t *testing.T) {
	testHarness := newHarness(t)

	current := testHarness.logIn(seedPassword)
	if !current.MustChangePassword {
		t.Fatal("a freshly seeded admin is not asked to change the password")
	}

	for _, path := range []string{"/api/machines", "/api/overview", "/api/settings", "/api/attackers"} {
		answer := testHarness.request(http.MethodGet, path, nil)
		assertStatus(t, "GET "+path+" before the password change", answer, http.StatusForbidden)
		if answer.errorPayload(t).Error == "" {
			t.Fatalf("GET %s returned 403 without explaining why: %s", path, answer.body)
		}
	}
	blockedWrite := testHarness.request(http.MethodPost, "/api/machines", machinePayload("blocked", scrapeHost))
	assertStatus(t, "POST /api/machines before the password change", blockedWrite, http.StatusForbidden)

	// The three endpoints needed to get unstuck stay reachable.
	sessionAnswer := testHarness.request(http.MethodGet, "/api/session", nil)
	assertStatus(t, "GET /api/session while gated", sessionAnswer, http.StatusOK)
	var gated sessionResponse
	sessionAnswer.decode(t, &gated)
	if !gated.MustChangePassword {
		t.Fatal("GET /api/session does not report must_change_password while the gate is closed")
	}

	logoutAnswer := testHarness.request(http.MethodPost, "/api/logout", nil)
	assertStatus(t, "POST /api/logout while gated", logoutAnswer, http.StatusNoContent)
	testHarness.logIn(seedPassword)

	// CSRF is still enforced on the escape hatch itself.
	unprotected := testHarness.send(http.MethodPost, "/api/password", "", map[string]string{
		"current_password": seedPassword,
		"new_password":     replacementPassword,
	}, nil)
	assertStatus(t, "POST /api/password without a CSRF token", unprotected, http.StatusForbidden)

	wrongCurrent := testHarness.request(http.MethodPost, "/api/password", map[string]string{
		"current_password": "not-the-seed-password",
		"new_password":     replacementPassword,
	})
	assertStatus(t, "POST /api/password with a wrong current password", wrongCurrent, http.StatusBadRequest)
	if field := wrongCurrent.errorPayload(t).Field; field != "current_password" {
		t.Fatalf("the rejection blamed field %q, want \"current_password\"", field)
	}

	weak := testHarness.request(http.MethodPost, "/api/password", map[string]string{
		"current_password": seedPassword,
		"new_password":     "short",
	})
	assertStatus(t, "POST /api/password with a weak password", weak, http.StatusBadRequest)
	if field := weak.errorPayload(t).Field; field != "new_password" {
		t.Fatalf("the rejection blamed field %q, want \"new_password\"", field)
	}

	testHarness.changePassword(seedPassword, replacementPassword)

	stale := testHarness.send(http.MethodPost, "/api/login", "", credentials(seedPassword), nil)
	assertStatus(t, "POST /api/login with the old password", stale, http.StatusUnauthorized)

	renewed := testHarness.logIn(replacementPassword)
	if renewed.MustChangePassword {
		t.Fatal("the account is still gated after changing the password")
	}

	answer := testHarness.request(http.MethodGet, "/api/machines", nil)
	assertStatus(t, "GET /api/machines after the password change", answer, http.StatusOK)
}

func TestSecurityHeadersArePresent(t *testing.T) {
	testHarness := newSignedInHarness(t)

	wanted := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}

	for _, path := range []string{"/healthz", "/api/session", "/api/machines", "/"} {
		t.Run(path, func(t *testing.T) {
			answer := testHarness.request(http.MethodGet, path, nil)
			assertStatus(t, "GET "+path, answer, http.StatusOK)
			for name, expected := range wanted {
				value := answer.header.Get(name)
				if value == "" {
					t.Fatalf("GET %s has no %s header", path, name)
				}
				if !strings.Contains(value, expected) {
					t.Fatalf("GET %s has %s: %q, want it to contain %q", path, name, value, expected)
				}
			}
			if strings.Contains(answer.header.Get("Content-Security-Policy"), "unsafe-eval") {
				t.Fatal("the content security policy allows unsafe-eval")
			}
		})
	}
}

func TestMachinesLifecycle(t *testing.T) {
	testHarness := newSignedInHarness(t)

	created := testHarness.request(http.MethodPost, "/api/machines", machinePayload("first-tarpit", scrapeHost))
	assertStatus(t, "POST /api/machines", created, http.StatusCreated)

	var machine machineResponse
	created.decode(t, &machine)
	if machine.ID == 0 {
		t.Fatalf("the created machine has no id: %s", created.body)
	}
	if machine.Name != "first-tarpit" || machine.Host != scrapeHost || machine.Port != scrapePort {
		t.Fatalf("the created machine came back as %+v", machine)
	}
	assertJSONKeys(t, "POST /api/machines", created.body,
		"id", "name", "host", "port", "metrics_path", "group_label", "enabled", "status",
		"last_scrape_at", "last_ok_at", "consecutive_failures", "last_error", "trapped_now", "activity")

	listed := testHarness.request(http.MethodGet, "/api/machines", nil)
	assertStatus(t, "GET /api/machines", listed, http.StatusOK)
	var machines []machineResponse
	listed.decode(t, &machines)
	if len(machines) != 1 || machines[0].ID != machine.ID {
		t.Fatalf("the list holds %+v, want just the machine that was created", machines)
	}

	updated := testHarness.request(http.MethodPut, fmt.Sprintf("/api/machines/%d", machine.ID),
		map[string]any{
			"name":         "renamed-tarpit",
			"host":         scrapeHost,
			"port":         9999,
			"metrics_path": "/other-metrics",
			"group_label":  "edge",
			"enabled":      false,
		})
	assertStatus(t, "PUT /api/machines", updated, http.StatusOK)
	var afterUpdate machineResponse
	updated.decode(t, &afterUpdate)
	if afterUpdate.Name != "renamed-tarpit" || afterUpdate.Port != 9999 || afterUpdate.Enabled {
		t.Fatalf("the update did not stick: %+v", afterUpdate)
	}
	if afterUpdate.Status != statusDisabled {
		t.Fatalf("a disabled machine reports status %q, want %q", afterUpdate.Status, statusDisabled)
	}

	deleted := testHarness.request(http.MethodDelete, fmt.Sprintf("/api/machines/%d", machine.ID), nil)
	assertStatus(t, "DELETE /api/machines", deleted, http.StatusNoContent)

	empty := testHarness.request(http.MethodGet, "/api/machines", nil)
	empty.decode(t, &machines)
	if len(machines) != 0 {
		t.Fatalf("the machine list still holds %d entries after the delete", len(machines))
	}
}

func TestMachineListCarriesTheActivitySeries(t *testing.T) {
	testHarness := newSignedInHarness(t)
	quiet := testHarness.seedMachine("quiet")
	busy := testHarness.seedMachine("busy")
	const busyTrappedSeconds = 42
	testHarness.seedScrape(busy.ID, time.Now().UTC(), "198.51.100.7", "Testland", busyTrappedSeconds, 900)

	answer := testHarness.request(http.MethodGet, "/api/machines", nil)
	assertStatus(t, "GET /api/machines", answer, http.StatusOK)

	var machines []machineResponse
	answer.decode(t, &machines)
	if len(machines) != 2 {
		t.Fatalf("the list holds %d machines, want 2", len(machines))
	}

	activityByID := map[int64][]float64{}
	for _, machine := range machines {
		if len(machine.Activity) != activityBuckets {
			t.Fatalf("machine %q carries %d activity values, want exactly %d: %s",
				machine.Name, len(machine.Activity), activityBuckets, answer.body)
		}
		activityByID[machine.ID] = machine.Activity
	}

	for index, value := range activityByID[quiet.ID] {
		if value != 0 {
			t.Errorf("a machine with no history reports %v in bucket %d, want zero", value, index)
		}
	}

	total := 0.0
	for _, value := range activityByID[busy.ID] {
		total += value
	}
	if total != busyTrappedSeconds {
		t.Errorf("the seeded machine's activity sums to %v, want %d", total, busyTrappedSeconds)
	}

	// A nil slice would marshal to null and break the sparkline, so the raw JSON
	// has to hold an array even for the machine that never saw traffic.
	var rawMachines []json.RawMessage
	answer.decode(t, &rawMachines)
	for _, raw := range rawMachines {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("a machine entry is not a JSON object: %v", err)
		}
		if !strings.HasPrefix(string(fields["activity"]), "[") {
			t.Fatalf("activity is %s, want a JSON array", fields["activity"])
		}
	}
}

func TestMachineValidationErrors(t *testing.T) {
	testHarness := newSignedInHarness(t)

	loopback := testHarness.request(http.MethodPost, "/api/machines", machinePayload("loopback-tarpit", "127.0.0.1"))
	assertStatus(t, "POST /api/machines pointing at 127.0.0.1", loopback, http.StatusBadRequest)
	payload := loopback.errorPayload(t)
	if payload.Field != "host" {
		t.Fatalf("the rejection blamed field %q, want \"host\"", payload.Field)
	}
	if !strings.Contains(strings.ToLower(payload.Error), "loopback") {
		t.Fatalf("the error %q does not explain that 127.0.0.1 is a loopback address", payload.Error)
	}

	first := testHarness.request(http.MethodPost, "/api/machines", machinePayload("duplicate-name", scrapeHost))
	assertStatus(t, "POST /api/machines", first, http.StatusCreated)
	var created machineResponse
	first.decode(t, &created)

	duplicate := testHarness.request(http.MethodPost, "/api/machines", machinePayload("duplicate-name", scrapeHost))
	assertStatus(t, "POST /api/machines with a name already in use", duplicate, http.StatusBadRequest)
	if field := duplicate.errorPayload(t).Field; field != "name" {
		t.Fatalf("the duplicate rejection blamed field %q, want \"name\"", field)
	}

	badField := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"no name", machinePayload("", scrapeHost), "name"},
		{"no host", machinePayload("hostless", ""), "host"},
		{"port out of range", withPort(machinePayload("bad-port", scrapeHost), 70000), "port"},
	}
	for _, testCase := range badField {
		t.Run(testCase.name, func(t *testing.T) {
			answer := testHarness.request(http.MethodPost, "/api/machines", testCase.body)
			assertStatus(t, "POST /api/machines", answer, http.StatusBadRequest)
			if field := answer.errorPayload(t).Field; field != testCase.field {
				t.Fatalf("the rejection blamed field %q, want %q", field, testCase.field)
			}
		})
	}

	missing := testHarness.request(http.MethodPut, "/api/machines/999999", machinePayload("ghost", scrapeHost))
	assertStatus(t, "PUT /api/machines/999999", missing, http.StatusNotFound)
	if missing.errorPayload(t).Error == "" {
		t.Fatal("the 404 for an unknown machine carries no message")
	}

	missingDelete := testHarness.request(http.MethodDelete, "/api/machines/999999", nil)
	assertStatus(t, "DELETE /api/machines/999999", missingDelete, http.StatusNotFound)

	malformed := testHarness.request(http.MethodDelete, "/api/machines/not-a-number", nil)
	assertStatus(t, "DELETE /api/machines/not-a-number", malformed, http.StatusBadRequest)

	// Nothing above changed the stored list.
	listed := testHarness.request(http.MethodGet, "/api/machines", nil)
	var machines []machineResponse
	listed.decode(t, &machines)
	if len(machines) != 1 || machines[0].ID != created.ID {
		t.Fatalf("the machine list holds %+v after the rejected requests", machines)
	}
}

func withPort(payload map[string]any, port int) map[string]any {
	payload["port"] = port
	return payload
}

func TestOverviewReportsSeededTraffic(t *testing.T) {
	testHarness := newSignedInHarness(t)
	first := testHarness.seedMachine("alpha")
	second := testHarness.seedMachine("beta")
	now := time.Now().UTC()
	testHarness.seedScrape(first.ID, now, "198.51.100.1", "Testland", 120, 1000)
	testHarness.seedScrape(second.ID, now, "198.51.100.2", "Otherland", 30, 2000)

	answer := testHarness.request(http.MethodGet, "/api/overview", nil)
	assertStatus(t, "GET /api/overview", answer, http.StatusOK)
	assertJSONKeys(t, "GET /api/overview", answer.body,
		"time_wasted_seconds", "time_wasted_delta_seconds", "attackers_trapped",
		"attackers_trapped_delta", "bytes_sent", "bytes_sent_delta", "trapped_now", "machine_count",
		"unique_attackers", "countries", "latest_attacker")

	var everything overviewResponse
	answer.decode(t, &everything)
	if everything.MachineCount != 2 {
		t.Fatalf("machine_count is %d, want 2", everything.MachineCount)
	}
	if everything.UniqueAttackers != 2 {
		t.Fatalf("unique_attackers is %d, want 2", everything.UniqueAttackers)
	}
	if everything.Countries != 2 {
		t.Fatalf("countries is %d, want 2", everything.Countries)
	}
	if everything.LatestAttacker == nil {
		t.Fatalf("latest_attacker is null after two clients were seen: %s", answer.body)
	}
	if everything.LatestAttacker.IPAddress == "" || everything.LatestAttacker.At.IsZero() {
		t.Fatalf("latest_attacker came back as %+v", *everything.LatestAttacker)
	}
	if everything.BytesSent != 3000 {
		t.Fatalf("bytes_sent is %d, want 3000", everything.BytesSent)
	}
	if everything.TimeWastedSeconds != 150 {
		t.Fatalf("time_wasted_seconds is %v, want 150", everything.TimeWastedSeconds)
	}
	if everything.AttackersTrapped != 2 || everything.TrappedNow != 2 {
		t.Fatalf("attackers_trapped=%d trapped_now=%d, want 2 and 2",
			everything.AttackersTrapped, everything.TrappedNow)
	}

	narrowed := testHarness.request(http.MethodGet, fmt.Sprintf("/api/overview?machines=%d", first.ID), nil)
	assertStatus(t, "GET /api/overview?machines=", narrowed, http.StatusOK)
	var onlyFirst overviewResponse
	narrowed.decode(t, &onlyFirst)
	if onlyFirst.MachineCount != 1 {
		t.Fatalf("the machine selector left machine_count at %d, want 1", onlyFirst.MachineCount)
	}
	if onlyFirst.BytesSent != 1000 || onlyFirst.TimeWastedSeconds != 120 {
		t.Fatalf("the machine selector reported bytes_sent=%d time_wasted_seconds=%v, want 1000 and 120",
			onlyFirst.BytesSent, onlyFirst.TimeWastedSeconds)
	}
}

func TestTimeSeriesShapeAndWindowFallback(t *testing.T) {
	testHarness := newSignedInHarness(t)
	first := testHarness.seedMachine("alpha")
	second := testHarness.seedMachine("beta")
	// An hour back keeps the rollup clear of the newest, still-forming bucket,
	// so the totals below do not depend on where the clock happens to sit.
	anHourAgo := time.Now().UTC().Add(-time.Hour)
	testHarness.seedScrape(first.ID, anHourAgo, "198.51.100.1", "Testland", 120, 1000)
	testHarness.seedScrape(second.ID, anHourAgo, "198.51.100.2", "Otherland", 30, 2000)

	answer := testHarness.request(http.MethodGet, "/api/timeseries", nil)
	assertStatus(t, "GET /api/timeseries", answer, http.StatusOK)
	assertJSONKeys(t, "GET /api/timeseries", answer.body, "bucket_seconds", "from", "to", "series")

	var payload timeSeriesResponse
	answer.decode(t, &payload)
	if len(payload.Series) != 2 {
		t.Fatalf("the default window returned %d series, want one per enabled machine", len(payload.Series))
	}
	if payload.BucketSeconds != defaultBucketWidth {
		t.Fatalf("bucket_seconds is %d, want %d", payload.BucketSeconds, defaultBucketWidth)
	}
	if span := payload.To.Sub(payload.From); span != defaultWindowSpan {
		t.Fatalf("the default window spans %s, want %s", span, defaultWindowSpan)
	}

	// Field names are checked on the raw JSON, one level at a time.
	var rawTop map[string]json.RawMessage
	answer.decode(t, &rawTop)
	var rawSeries []json.RawMessage
	if err := json.Unmarshal(rawTop["series"], &rawSeries); err != nil {
		t.Fatalf("series is not a JSON array: %v", err)
	}
	assertJSONKeys(t, "a series entry", rawSeries[0], "machine_id", "machine_name", "points")
	var rawSeriesFields map[string]json.RawMessage
	if err := json.Unmarshal(rawSeries[0], &rawSeriesFields); err != nil {
		t.Fatalf("a series entry is not a JSON object: %v", err)
	}
	var rawPoints []json.RawMessage
	if err := json.Unmarshal(rawSeriesFields["points"], &rawPoints); err != nil {
		t.Fatalf("points is not a JSON array: %v", err)
	}
	if len(rawPoints) == 0 {
		t.Fatal("a series came back with no points")
	}
	assertJSONKeys(t, "a series point", rawPoints[0], "t", "trapped_seconds", "opens", "bytes_sent")

	total := 0.0
	for _, series := range payload.Series {
		for _, point := range series.Points {
			total += point.TrappedSeconds
		}
	}
	if total != 150 {
		t.Fatalf("the series carry %v trapped seconds in total, want 150", total)
	}

	narrowed := testHarness.request(http.MethodGet, fmt.Sprintf("/api/timeseries?machines=%d", second.ID), nil)
	assertStatus(t, "GET /api/timeseries?machines=", narrowed, http.StatusOK)
	var onlySecond timeSeriesResponse
	narrowed.decode(t, &onlySecond)
	if len(onlySecond.Series) != 1 {
		t.Fatalf("the machine selector returned %d series, want 1", len(onlySecond.Series))
	}
	if onlySecond.Series[0].MachineID != second.ID || onlySecond.Series[0].MachineName != "beta" {
		t.Fatalf("the machine selector returned series %+v, want machine %d", onlySecond.Series[0], second.ID)
	}

	windows := []struct {
		query             string
		wantBucketSeconds int
		wantSpan          time.Duration
	}{
		{"?window=7d", 3600, 7 * 24 * time.Hour},
		{"?window=90d", 86400, 90 * 24 * time.Hour},
		{"?window=nonsense", defaultBucketWidth, defaultWindowSpan},
		{"?window=", defaultBucketWidth, defaultWindowSpan},
		{"?window=24H", defaultBucketWidth, defaultWindowSpan},
	}
	for _, testCase := range windows {
		t.Run("window "+testCase.query, func(t *testing.T) {
			windowed := testHarness.request(http.MethodGet, "/api/timeseries"+testCase.query, nil)
			assertStatus(t, "GET /api/timeseries"+testCase.query, windowed, http.StatusOK)
			var selected timeSeriesResponse
			windowed.decode(t, &selected)
			if selected.BucketSeconds != testCase.wantBucketSeconds {
				t.Fatalf("bucket_seconds is %d, want %d", selected.BucketSeconds, testCase.wantBucketSeconds)
			}
			if span := selected.To.Sub(selected.From); span != testCase.wantSpan {
				t.Fatalf("the window spans %s, want %s", span, testCase.wantSpan)
			}
		})
	}
}

func TestAttackersListing(t *testing.T) {
	testHarness := newSignedInHarness(t)
	first := testHarness.seedMachine("alpha")
	second := testHarness.seedMachine("beta")
	now := time.Now().UTC()
	testHarness.seedScrape(first.ID, now, "198.51.100.1", "Testland", 120, 1000)
	testHarness.seedScrape(second.ID, now, "198.51.100.2", "Otherland", 30, 2000)

	answer := testHarness.request(http.MethodGet, "/api/attackers", nil)
	assertStatus(t, "GET /api/attackers", answer, http.StatusOK)
	assertJSONKeys(t, "GET /api/attackers", answer.body, "total", "page", "per_page", "rows")

	var page attackerPageResponse
	answer.decode(t, &page)
	if page.Total != 2 || len(page.Rows) != 2 {
		t.Fatalf("total=%d rows=%d, want 2 and 2", page.Total, len(page.Rows))
	}
	if page.Page != 1 || page.PerPage != defaultPageSize {
		t.Fatalf("page=%d per_page=%d, want 1 and %d", page.Page, page.PerPage, defaultPageSize)
	}
	// The default sort puts the longest-trapped client first.
	if page.Rows[0].IPAddress != "198.51.100.1" {
		t.Fatalf("the first row is %q, want the client with the most trapped seconds", page.Rows[0].IPAddress)
	}
	if page.Rows[0].TrappedSeconds != 120 || page.Rows[0].Connections != 3 {
		t.Fatalf("the first row reports %v trapped seconds over %d connections, want 120 and 3",
			page.Rows[0].TrappedSeconds, page.Rows[0].Connections)
	}
	if page.Rows[0].MachineName != "alpha" || page.Rows[0].Country != "Testland" {
		t.Fatalf("the first row is attributed to %q/%q, want alpha/Testland",
			page.Rows[0].MachineName, page.Rows[0].Country)
	}
	if page.Rows[0].Status != store.StatusTrapped {
		t.Fatalf("a client seen just now has status %q, want %q", page.Rows[0].Status, store.StatusTrapped)
	}

	var rawPage map[string]json.RawMessage
	answer.decode(t, &rawPage)
	var rawRows []json.RawMessage
	if err := json.Unmarshal(rawPage["rows"], &rawRows); err != nil {
		t.Fatalf("rows is not a JSON array: %v", err)
	}
	assertJSONKeys(t, "an attacker row", rawRows[0],
		"ip", "machine_id", "machine_name", "country", "country_code", "geohash", "location",
		"isp", "first_seen", "last_seen", "connections", "trapped_seconds", "status")

	narrowed := testHarness.request(http.MethodGet, fmt.Sprintf("/api/attackers?machines=%d", second.ID), nil)
	assertStatus(t, "GET /api/attackers?machines=", narrowed, http.StatusOK)
	var onlySecond attackerPageResponse
	narrowed.decode(t, &onlySecond)
	if onlySecond.Total != 1 || len(onlySecond.Rows) != 1 {
		t.Fatalf("the machine selector returned total=%d rows=%d, want 1 and 1",
			onlySecond.Total, len(onlySecond.Rows))
	}
	if onlySecond.Rows[0].IPAddress != "198.51.100.2" {
		t.Fatalf("the machine selector returned %q, want the client of the selected machine",
			onlySecond.Rows[0].IPAddress)
	}

	fallback := testHarness.request(http.MethodGet, "/api/attackers?window=nonsense", nil)
	assertStatus(t, "GET /api/attackers?window=nonsense", fallback, http.StatusOK)
	var afterFallback attackerPageResponse
	fallback.decode(t, &afterFallback)
	if afterFallback.Total != page.Total {
		t.Fatalf("an unknown window changed the result (total=%d, want %d)", afterFallback.Total, page.Total)
	}

	countries := testHarness.request(http.MethodGet, "/api/attackers/countries", nil)
	assertStatus(t, "GET /api/attackers/countries", countries, http.StatusOK)
	var counts []countryCountResponse
	countries.decode(t, &counts)
	if len(counts) != 2 {
		t.Fatalf("the country summary holds %d entries, want 2: %s", len(counts), countries.body)
	}
	var rawCountries []json.RawMessage
	countries.decode(t, &rawCountries)
	assertJSONKeys(t, "a country count", rawCountries[0], "country", "count")
}

// The chips on the attackers page and the donut beside the map answer the same
// question, so they have to answer it with the same number. They only disagreed
// when one address reached more than one machine, because the chips counted
// stored rows — one per machine — where the donut counted addresses. Both read
// the same aggregation now, and this is the shape that used to separate them.
func TestCountryChipsAndTheDonutCountTheSameAttackers(t *testing.T) {
	testHarness := newSignedInHarness(t)
	first := testHarness.seedMachine("alpha")
	second := testHarness.seedMachine("beta")
	now := time.Now().UTC()

	// One address caught by both machines: two stored rows, one attacker.
	testHarness.seedScrape(first.ID, now, "198.51.100.1", "Germany", 60, 500)
	testHarness.seedScrape(second.ID, now, "198.51.100.1", "Germany", 60, 500)
	testHarness.seedScrape(first.ID, now, "198.51.100.2", "Germany", 30, 250)

	chips := testHarness.request(http.MethodGet, "/api/attackers/countries", nil)
	assertStatus(t, "GET /api/attackers/countries", chips, http.StatusOK)
	var counts []countryCountResponse
	chips.decode(t, &counts)

	donut := testHarness.request(http.MethodGet, "/api/geo/countries", nil)
	assertStatus(t, "GET /api/geo/countries", donut, http.StatusOK)
	var breakdown []geoCountryResponse
	donut.decode(t, &breakdown)

	if len(counts) != 1 || len(breakdown) != 1 {
		t.Fatalf("chips hold %d countries and the donut %d, want one each: %s / %s",
			len(counts), len(breakdown), chips.body, donut.body)
	}
	if counts[0].Count != breakdown[0].Attackers {
		t.Errorf("the chip says %d attackers and the donut says %d for %s",
			counts[0].Count, breakdown[0].Attackers, counts[0].Country)
	}
	if counts[0].Count != 2 {
		t.Errorf("%s counts %d attackers, want the two addresses rather than the three stored rows",
			counts[0].Country, counts[0].Count)
	}

	// The deliberate half of the trade-off, pinned so it stays deliberate: the
	// table lists a row per machine that met an address, so filtering to this
	// country shows three rows while the chip beside it says two attackers. The
	// table is answering "what did each machine see", the chip "who was it".
	listed := testHarness.request(http.MethodGet, "/api/attackers?country=Germany", nil)
	assertStatus(t, "GET /api/attackers?country=Germany", listed, http.StatusOK)
	var page attackerPageResponse
	listed.decode(t, &page)
	if page.Total != 3 {
		t.Errorf("the attackers table holds %d rows for Germany, want one per machine sighting", page.Total)
	}
}

func TestGeographyEndpointsAnswerEmptyArraysWithNothingToPlot(t *testing.T) {
	testHarness := newSignedInHarness(t)
	// A machine with traffic but no coordinate: the map has nothing, the country
	// breakdown has a row. A nil slice would marshal to null and break both.
	machine := testHarness.seedMachine("alpha")
	testHarness.seedScrape(machine.ID, time.Now().UTC(), "198.51.100.9", "", 10, 100)

	for _, path := range []string{"/api/geo/points", "/api/geo/countries"} {
		answer := testHarness.request(http.MethodGet, path, nil)
		assertStatus(t, "GET "+path, answer, http.StatusOK)
		if got := strings.TrimSpace(string(answer.body)); got != "[]" {
			t.Fatalf("GET %s with nothing to report returned %s, want an empty array", path, got)
		}
	}

	overview := testHarness.request(http.MethodGet, "/api/overview", nil)
	assertStatus(t, "GET /api/overview", overview, http.StatusOK)
	var rawOverview map[string]json.RawMessage
	overview.decode(t, &rawOverview)
	if string(rawOverview["countries"]) != "0" {
		t.Fatalf("countries is %s with no country known, want 0", rawOverview["countries"])
	}
}

func TestOverviewReportsNoLatestAttackerOnAFreshInstall(t *testing.T) {
	testHarness := newSignedInHarness(t)
	testHarness.seedMachine("alpha")

	answer := testHarness.request(http.MethodGet, "/api/overview", nil)
	assertStatus(t, "GET /api/overview", answer, http.StatusOK)

	var rawOverview map[string]json.RawMessage
	answer.decode(t, &rawOverview)
	if string(rawOverview["latest_attacker"]) != "null" {
		t.Fatalf("latest_attacker is %s before anybody was seen, want null", rawOverview["latest_attacker"])
	}

	var payload overviewResponse
	answer.decode(t, &payload)
	if payload.UniqueAttackers != 0 || payload.Countries != 0 {
		t.Fatalf("unique_attackers=%d countries=%d on an empty install, want 0 and 0",
			payload.UniqueAttackers, payload.Countries)
	}
}

func TestGeographyEndpointsReportPlacedAttackers(t *testing.T) {
	testHarness := newSignedInHarness(t)
	first := testHarness.seedMachine("alpha")
	second := testHarness.seedMachine("beta")
	now := time.Now().UTC()
	testHarness.seedScrape(first.ID, now, "198.51.100.1", "Germany", 120, 1000)
	testHarness.seedScrape(second.ID, now, "198.51.100.2", "Germany", 30, 2000)
	testHarness.seedScrape(first.ID, now, "198.51.100.3", "Japan", 5, 500)

	berlinLatitude, berlinLongitude := at(52.5200, 13.4050)
	tokyoLatitude, tokyoLongitude := at(35.6762, 139.6503)
	for _, address := range []string{"198.51.100.1", "198.51.100.2"} {
		testHarness.placeAttacker(address, store.AttackerLocation{
			Country: "Germany", CountryCode: "DE", Location: "Germany, Berlin", ISP: "Example Telecom",
			Latitude: berlinLatitude, Longitude: berlinLongitude,
		})
	}
	testHarness.placeAttacker("198.51.100.3", store.AttackerLocation{
		Country: "Japan", CountryCode: "JP", Location: "Japan, Tokyo", ISP: "Example Networks",
		Latitude: tokyoLatitude, Longitude: tokyoLongitude,
	})

	points := testHarness.request(http.MethodGet, "/api/geo/points", nil)
	assertStatus(t, "GET /api/geo/points", points, http.StatusOK)

	var rawPoints []json.RawMessage
	points.decode(t, &rawPoints)
	if len(rawPoints) != 2 {
		t.Fatalf("the map holds %d bubbles, want one per city: %s", len(rawPoints), points.body)
	}
	assertJSONKeys(t, "a map bubble", rawPoints[0],
		"lat", "lon", "country", "country_code", "attackers", "connections", "trapped_seconds")

	var plotted []geoPointResponse
	points.decode(t, &plotted)
	if plotted[0].CountryCode != "DE" || plotted[0].Attackers != 2 {
		t.Fatalf("the busiest bubble is %+v, want the two German addresses", plotted[0])
	}
	if plotted[0].Latitude != 52.5 || plotted[0].Longitude != 13.4 {
		t.Fatalf("the busiest bubble sits at %v,%v, want the rounded Berlin coordinate",
			plotted[0].Latitude, plotted[0].Longitude)
	}

	countries := testHarness.request(http.MethodGet, "/api/geo/countries", nil)
	assertStatus(t, "GET /api/geo/countries", countries, http.StatusOK)

	var rawCountries []json.RawMessage
	countries.decode(t, &rawCountries)
	if len(rawCountries) != 2 {
		t.Fatalf("the breakdown holds %d countries, want 2: %s", len(rawCountries), countries.body)
	}
	assertJSONKeys(t, "a country total", rawCountries[0],
		"country", "country_code", "attackers", "connections")

	var breakdown []geoCountryResponse
	countries.decode(t, &breakdown)
	if breakdown[0].Country != "Germany" || breakdown[0].Attackers != 2 || breakdown[0].Connections != 6 {
		t.Fatalf("the leading country is %+v, want Germany with two attackers", breakdown[0])
	}

	narrowed := testHarness.request(http.MethodGet, fmt.Sprintf("/api/geo/points?machines=%d", second.ID), nil)
	assertStatus(t, "GET /api/geo/points?machines=", narrowed, http.StatusOK)
	var onlySecond []geoPointResponse
	narrowed.decode(t, &onlySecond)
	if len(onlySecond) != 1 || onlySecond[0].CountryCode != "DE" {
		t.Fatalf("the machine selector returned %+v, want only beta's German bubble", onlySecond)
	}

	// The enriched country code and ISP reach the attacker table too.
	attackers := testHarness.request(http.MethodGet, "/api/attackers", nil)
	assertStatus(t, "GET /api/attackers", attackers, http.StatusOK)
	var page attackerPageResponse
	attackers.decode(t, &page)
	if page.Rows[0].CountryCode != "DE" || page.Rows[0].ISP != "Example Telecom" {
		t.Fatalf("the first attacker row is %+v, want the enriched country code and ISP", page.Rows[0])
	}

	overview := testHarness.request(http.MethodGet, "/api/overview", nil)
	assertStatus(t, "GET /api/overview", overview, http.StatusOK)
	var summary overviewResponse
	overview.decode(t, &summary)
	if summary.UniqueAttackers != 3 || summary.Countries != 2 {
		t.Fatalf("unique_attackers=%d countries=%d, want 3 and 2",
			summary.UniqueAttackers, summary.Countries)
	}
	if summary.LatestAttacker == nil || summary.LatestAttacker.CountryCode == "" {
		t.Fatalf("latest_attacker is %+v, want the enriched newest catch", summary.LatestAttacker)
	}
}

func TestSettingsNeverLeakSecrets(t *testing.T) {
	testHarness := newSignedInHarness(t)

	answer := testHarness.request(http.MethodGet, "/api/settings", nil)
	assertStatus(t, "GET /api/settings", answer, http.StatusOK)
	assertJSONKeys(t, "GET /api/settings", answer.body,
		"scrape_interval_seconds", "scrape_timeout_seconds", "retention_days",
		"session_lifetime_seconds",
		"geoip_enabled", "geoip_source", "geoip_online_enabled", "geoip_online_rate_per_minute",
		"backup_keep_last", "backup_daily_enabled", "block_private", "version")

	body := strings.ToLower(string(answer.body))
	secrets := map[string]string{
		"the seeded admin password":    seedPassword,
		"the current admin password":   replacementPassword,
		"anything called a password":   "password",
		"anything called a secret":     "secret",
		"anything called a key":        "key",
		"anything called a token":      "token",
		"a stored password hash":       "argon2id",
		"the signed-in account's name": seedUsername,
	}
	for description, needle := range secrets {
		if strings.Contains(body, strings.ToLower(needle)) {
			t.Fatalf("GET /api/settings leaks %s: %s", description, answer.body)
		}
	}

	var settings settingsResponse
	answer.decode(t, &settings)
	if settings.ScrapeIntervalSeconds != int(testScrapeInterval.Seconds()) {
		t.Fatalf("scrape_interval_seconds is %d, want %d",
			settings.ScrapeIntervalSeconds, int(testScrapeInterval.Seconds()))
	}
	if settings.Version != testVersion {
		t.Fatalf("version is %q, want %q", settings.Version, testVersion)
	}
	if settings.GeoIPEnabled || settings.GeoIPSource != geo.SourceDisabled {
		t.Fatalf("geoip is reported as enabled=%v source=%q with no database mounted",
			settings.GeoIPEnabled, settings.GeoIPSource)
	}
	// The online provider is the one thing that leaves the host, so a default
	// install has to report it off.
	if settings.GeoIPOnlineEnabled {
		t.Fatal("geoip_online_enabled is true without the operator turning it on")
	}
}

func TestUnknownPaths(t *testing.T) {
	testHarness := newSignedInHarness(t)

	for _, path := range []string{"/api/nope", "/api/machines/1/extra", "/api/"} {
		t.Run(path, func(t *testing.T) {
			answer := testHarness.request(http.MethodGet, path, nil)
			assertStatus(t, "GET "+path, answer, http.StatusNotFound)
			if contentType := answer.header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
				t.Fatalf("GET %s answered with Content-Type %q, want JSON", path, contentType)
			}
			if answer.errorPayload(t).Error == "" {
				t.Fatalf("GET %s returned a 404 with no error message: %s", path, answer.body)
			}
		})
	}

	// Deep links belong to the single-page app, so they get the shell.
	for _, path := range []string{"/machines", "/attackers/deep/link", "/settings"} {
		t.Run(path, func(t *testing.T) {
			answer := testHarness.request(http.MethodGet, path, nil)
			assertStatus(t, "GET "+path, answer, http.StatusOK)
			if contentType := answer.header.Get("Content-Type"); !strings.Contains(contentType, "text/html") {
				t.Fatalf("GET %s answered with Content-Type %q, want HTML", path, contentType)
			}
			if !strings.Contains(string(answer.body), "<title>Endlessh Dashboard</title>") {
				t.Fatalf("GET %s did not serve the app shell", path)
			}
		})
	}
}

func TestStaticHandlerServesTheEmbeddedShell(t *testing.T) {
	testHarness := newHarness(t)

	answer := testHarness.send(http.MethodGet, "/", "", nil, nil)
	assertStatus(t, "GET /", answer, http.StatusOK)
	if contentType := answer.header.Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("GET / answered with Content-Type %q, want HTML", contentType)
	}

	body := string(answer.body)
	for _, fragment := range []string{"<!doctype html", "<title>Endlessh Dashboard</title>", "app.js"} {
		if !strings.Contains(strings.ToLower(body), strings.ToLower(fragment)) {
			t.Fatalf("the shell served at / does not contain %q", fragment)
		}
	}
	if cacheControl := answer.header.Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("the shell is served with Cache-Control %q, want no-store", cacheControl)
	}

	asset := testHarness.send(http.MethodGet, "/app.js", "", nil, nil)
	assertStatus(t, "GET /app.js", asset, http.StatusOK)
	if len(asset.body) == 0 {
		t.Fatal("GET /app.js served an empty file")
	}
}

// The auto-logout contract, end to end: the lifetime the operator configured is
// what the session is given, what the browser is told, and what the settings
// page reports. A cookie outliving its session would leave the browser sending
// a dead token; a cookie dying first would log someone out early.
func TestSessionLifetimeReachesTheCookieAndTheSettingsPage(t *testing.T) {
	testHarness := newHarness(t)
	const configured = 12 * time.Hour

	before := time.Now().UTC()
	answer := testHarness.send(http.MethodPost, "/api/login", "", credentials(seedPassword), nil)
	assertStatus(t, "POST /api/login", answer, http.StatusOK)

	cookie := answer.sessionCookie(t)
	if cookie.Expires.IsZero() {
		t.Fatal("the session cookie is a session cookie with no expiry, so it would outlive the server-side session")
	}
	// A second either side of the configured window, to absorb the time the
	// request itself took rather than pinning an exact instant.
	lived := cookie.Expires.Sub(before)
	if lived < configured-2*time.Second || lived > configured+2*time.Second {
		t.Errorf("cookie expires %s after login, want the configured %s", lived, configured)
	}

	testHarness.logIn(seedPassword)
	testHarness.changePassword(seedPassword, replacementPassword)
	testHarness.logIn(replacementPassword)

	settings := testHarness.request(http.MethodGet, "/api/settings", nil)
	assertStatus(t, "GET /api/settings", settings, http.StatusOK)
	var effective struct {
		SessionLifetimeSeconds int `json:"session_lifetime_seconds"`
	}
	settings.decode(t, &effective)
	if effective.SessionLifetimeSeconds != int(configured.Seconds()) {
		t.Errorf("settings report a %ds session, want %d", effective.SessionLifetimeSeconds, int(configured.Seconds()))
	}
}
