package geo

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real ip-api.com answers, field for field, for the three outcomes a caller has
// to tell apart.
const (
	successPayload = `{"status":"success","country":"United States","countryCode":"US",` +
		`"regionName":"California","city":"Mountain View","lat":37.4056,"lon":-122.0775,` +
		`"isp":"Google LLC","org":"Google Public DNS"}`
	reservedRangePayload = `{"status":"fail","message":"reserved range","query":"100.64.0.1"}`
	countryOnlyPayload   = `{"status":"success","country":"Sweden","countryCode":"SE",` +
		`"regionName":"","city":"","lat":0,"lon":0,"isp":"","org":"Bahnhof AB"}`

	// testRatePerMinute paces the fake provider at 50ms a request, fast enough
	// for a test and slow enough to be measurable.
	testRatePerMinute  = 1200
	testTickerInterval = time.Minute / testRatePerMinute
)

// fakeProvider stands in for ip-api.com: it answers by address and counts what
// actually reached it, which is how the tests prove nothing was sent.
type fakeProvider struct {
	server   *httptest.Server
	requests atomic.Int64
	status   atomic.Int64
	body     atomic.Pointer[string]
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	provider := &fakeProvider{}
	provider.status.Store(http.StatusOK)

	provider.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		provider.requests.Add(1)
		if override := provider.body.Load(); override != nil {
			writer.WriteHeader(int(provider.status.Load()))
			io.WriteString(writer, *override)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(request.URL.Path, "/json/") {
		case "100.64.0.1":
			io.WriteString(writer, reservedRangePayload)
		case "194.68.0.1":
			io.WriteString(writer, countryOnlyPayload)
		default:
			io.WriteString(writer, successPayload)
		}
	}))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeProvider) endpoint() string {
	return p.server.URL + "/json/" + OnlineIPPlaceholder + "?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org"
}

func (p *fakeProvider) answerWith(status int, body string) {
	p.status.Store(int64(status))
	p.body.Store(&body)
}

func newTestOnlineResolver(t *testing.T, provider *fakeProvider) *OnlineResolver {
	t.Helper()
	resolver := NewOnlineResolver(true, provider.endpoint(), testRatePerMinute)
	t.Cleanup(func() { resolver.Close() })
	return resolver
}

func TestOnlineResolverSuccess(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)

	location, ok, err := resolver.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("Lookup reported the address as unknown, want the provider's answer")
	}
	if location.Country != "United States" || location.CountryCode != "US" {
		t.Errorf("country = %q/%q, want United States/US", location.Country, location.CountryCode)
	}
	if location.Location != "United States, California, Mountain View" {
		t.Errorf("Location = %q, want country, region and city joined", location.Location)
	}
	if location.ISP != "Google LLC" {
		t.Errorf("ISP = %q, want Google LLC", location.ISP)
	}
	if location.Latitude == nil || location.Longitude == nil {
		t.Fatalf("coordinate = %v,%v, want the provider's numbers", location.Latitude, location.Longitude)
	}
	if math.Abs(*location.Latitude-37.4056) > 1e-6 || math.Abs(*location.Longitude+122.0775) > 1e-6 {
		t.Errorf("coordinate = %v,%v, want 37.4056,-122.0775", *location.Latitude, *location.Longitude)
	}
}

func TestOnlineResolverComposesWhatItWasGiven(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)

	location, ok, err := resolver.Lookup(context.Background(), "194.68.0.1")
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v, want a country-only answer", ok, err)
	}
	if location.Location != "Sweden" {
		t.Errorf("Location = %q, want just the country when region and city are empty", location.Location)
	}
	if location.ISP != "Bahnhof AB" {
		t.Errorf("ISP = %q, want the org when isp is empty", location.ISP)
	}
	// 0,0 is a real place in the Gulf of Guinea, so an answer with no coordinate
	// must arrive as no coordinate.
	if location.Latitude != nil || location.Longitude != nil {
		t.Errorf("coordinate = %v,%v, want nil for an answer that carried none",
			location.Latitude, location.Longitude)
	}
}

func TestOnlineResolverCachesBothOutcomes(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)
	ctx := context.Background()

	for attempt := 0; attempt < 3; attempt++ {
		if _, ok, err := resolver.Lookup(ctx, "8.8.8.8"); err != nil || !ok {
			t.Fatalf("Lookup attempt %d = %v, %v", attempt, ok, err)
		}
	}
	// An address the provider refuses must be remembered as refused, or an
	// unresolvable address would burn a request on every sweep forever.
	for attempt := 0; attempt < 3; attempt++ {
		location, ok, err := resolver.Lookup(ctx, "100.64.0.1")
		if err != nil {
			t.Fatalf("Lookup of a refused address returned an error: %v", err)
		}
		if ok || location.Country != "" {
			t.Fatalf("Lookup of a refused address = %+v, %v, want an empty miss", location, ok)
		}
	}

	if requests := provider.requests.Load(); requests != 2 {
		t.Errorf("provider saw %d requests, want 1 per distinct address", requests)
	}
}

// The cache is a memory saving, not a store of record, so it is allowed to
// forget — but never allowed to grow without end. Reaching the ceiling costs
// the evicted addresses one more request each and nothing else.
func TestOnlineResolverCacheStopsAtItsCeiling(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)
	ctx := context.Background()

	if _, ok, err := resolver.Lookup(ctx, "8.8.8.8"); err != nil || !ok {
		t.Fatalf("first Lookup = %v, %v", ok, err)
	}

	held := func() int {
		resolver.mutex.Lock()
		defer resolver.mutex.Unlock()
		return len(resolver.cache)
	}

	// Fill it the cheap way: driving this many addresses through the provider
	// would be a rate-limited hour, and what is under test is the bookkeeping.
	for entry := 0; entry < maxCacheEntries+1; entry++ {
		resolver.remember(fmt.Sprintf("203.0.113.%d", entry), cachedLookup{found: true})
		if size := held(); size > maxCacheEntries {
			t.Fatalf("the cache holds %d entries after %d writes, above the %d ceiling",
				size, entry+1, maxCacheEntries)
		}
	}

	// The address cached before the ceiling was dropped with everything else, so
	// it costs one more request — and still answers correctly.
	location, ok, err := resolver.Lookup(ctx, "8.8.8.8")
	if err != nil || !ok {
		t.Fatalf("Lookup after the cache was cleared = %v, %v", ok, err)
	}
	if location.CountryCode != "US" {
		t.Errorf("Lookup after the cache was cleared returned %+v, want the provider's answer", location)
	}
	if requests := provider.requests.Load(); requests != 2 {
		t.Errorf("provider saw %d requests, want one before the ceiling and one after", requests)
	}
}

func TestOnlineResolverNeverSendsLocalAddresses(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)
	ctx := context.Background()

	for _, ipAddress := range []string{
		"192.168.1.10", "10.4.5.6", "172.16.9.9", "127.0.0.1",
		"169.254.1.1", "::1", "fd00::1", "not-an-address", "",
	} {
		location, ok, err := resolver.Lookup(ctx, ipAddress)
		if ok || err != nil {
			t.Errorf("Lookup(%q) = %+v, %v, %v; want a silent miss", ipAddress, location, ok, err)
		}
	}
	if requests := provider.requests.Load(); requests != 0 {
		t.Errorf("provider saw %d requests; a LAN address must never leave this process", requests)
	}
}

func TestOnlineResolverProviderFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, body: ""},
		{name: "server error", status: http.StatusInternalServerError, body: "upstream is down"},
		{name: "malformed json", status: http.StatusOK, body: `{"status":"succ`},
		{name: "not json at all", status: http.StatusOK, body: "<html>blocked</html>"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := newFakeProvider(t)
			provider.answerWith(testCase.status, testCase.body)
			resolver := newTestOnlineResolver(t, provider)
			ctx := context.Background()

			location, ok, err := resolver.Lookup(ctx, "8.8.8.8")
			if err == nil {
				t.Fatalf("Lookup = %+v, %v, nil; want an error naming the provider failure", location, ok)
			}
			if ok {
				t.Errorf("Lookup reported success on a failed request")
			}

			// A broken provider says nothing about the address, so the answer must
			// not be cached as a miss: the next sweep has to be free to retry.
			if _, _, err := resolver.Lookup(ctx, "8.8.8.8"); err == nil {
				t.Error("second Lookup succeeded, so the first failure was cached")
			}
			if requests := provider.requests.Load(); requests != 2 {
				t.Errorf("provider saw %d requests, want the failure retried", requests)
			}
		})
	}
}

func TestOnlineResolverDisabledContactsNothing(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := NewOnlineResolver(false, provider.endpoint(), testRatePerMinute)
	defer resolver.Close()

	if resolver.Enabled() {
		t.Error("Enabled() = true for a resolver that was never switched on")
	}
	if resolver.Source() != SourceDisabled {
		t.Errorf("Source() = %q, want %q", resolver.Source(), SourceDisabled)
	}
	if resolver.Endpoint() != "" {
		t.Errorf("Endpoint() = %q, want empty while disabled", resolver.Endpoint())
	}

	location, ok, err := resolver.Lookup(context.Background(), "8.8.8.8")
	if ok || err != nil || location.Country != "" {
		t.Errorf("Lookup while disabled = %+v, %v, %v; want an empty miss", location, ok, err)
	}
	if requests := provider.requests.Load(); requests != 0 {
		t.Errorf("a disabled resolver made %d requests", requests)
	}
}

func TestOnlineResolverPacesRequests(t *testing.T) {
	provider := newFakeProvider(t)
	resolver := newTestOnlineResolver(t, provider)
	ctx := context.Background()

	const lookups = 3
	started := time.Now()
	for index := 1; index <= lookups; index++ {
		// Distinct addresses, so the cache cannot hide the pacing.
		if _, _, err := resolver.Lookup(ctx, fmt.Sprintf("8.8.8.%d", index)); err != nil {
			t.Fatalf("Lookup %d: %v", index, err)
		}
	}
	elapsed := time.Since(started)

	if elapsed < lookups*testTickerInterval {
		t.Errorf("%d lookups took %v, want at least %v: the rate limiter is not pacing them",
			lookups, elapsed, lookups*testTickerInterval)
	}
	if requests := provider.requests.Load(); requests != lookups {
		t.Errorf("provider saw %d requests, want %d", requests, lookups)
	}
}

func TestOnlineResolverStopsOnContextCancel(t *testing.T) {
	provider := newFakeProvider(t)
	// One request a minute: the lookup below can only leave the rate limiter by
	// noticing the cancelled context.
	resolver := NewOnlineResolver(true, provider.endpoint(), 1)
	defer resolver.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if _, ok, err := resolver.Lookup(ctx, "8.8.8.8"); ok || err == nil {
		t.Fatalf("Lookup with a cancelled context = %v, %v; want the cancellation", ok, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("Lookup waited %v for a cancelled context", elapsed)
	}
	if requests := provider.requests.Load(); requests != 0 {
		t.Errorf("a cancelled lookup still sent %d requests", requests)
	}
}
