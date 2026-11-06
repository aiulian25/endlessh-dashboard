package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SourceOnline names the opt-in provider on the settings page, so an operator
// can see at a glance that this install is talking to somebody.
const SourceOnline = "ip-api-online"

// OnlineIPPlaceholder is where the address goes in an endpoint template.
const OnlineIPPlaceholder = "{ip}"

// DefaultOnlineEndpoint is ip-api.com's free endpoint, asking for exactly the
// fields this app stores and nothing else. The free tier is HTTP-only; the
// request carries one attacker's address and no identifier of this install.
const DefaultOnlineEndpoint = "http://ip-api.com/json/" + OnlineIPPlaceholder +
	"?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org"

const (
	// onlineRequestTimeout is deliberately short: a backfill that stalls on one
	// unreachable provider is worse than a backfill that skips an address.
	onlineRequestTimeout = 5 * time.Second
	// maxOnlineResponseBytes bounds what a third party can make this process
	// read. A real answer is a few hundred bytes.
	maxOnlineResponseBytes = 16 << 10

	// maxCacheEntries is the ceiling on remembered answers. It is far above what
	// any single sweep needs — a sweep asks about at most backfillBatchSize
	// addresses — so it is only ever reached by months of distinct attackers, at
	// which point the entries that matter to the sweep in flight are the newest
	// few. That is what makes dropping the whole cache cheap enough to prefer
	// over an LRU: re-learning an evicted address costs one rate-limited request.
	maxCacheEntries = 50000

	onlineStatusSuccess = "success"
	onlineUserAgent     = "endlessh-dashboard"
)

// OnlineResolver looks addresses up with an online provider, one at a time and
// no faster than the configured rate. It is the only part of this app that
// sends anything to a third party, so it exists in a disabled state unless the
// operator explicitly turned it on.
type OnlineResolver struct {
	endpoint string
	client   *http.Client
	pace     *time.Ticker

	mutex sync.Mutex
	// In-process only, capped at maxCacheEntries and never written to disk: an
	// attacker's address and its resolved place already live in the database,
	// while durable retry eligibility is stored separately by the backfill worker.
	cache map[string]cachedLookup
}

// cachedLookup remembers a decided answer, including "the provider does not
// know this address", until an eligible durable retry explicitly invalidates it.
type cachedLookup struct {
	location Location
	found    bool
}

// NewOnlineResolver returns a disabled resolver when enabled is false, so
// callers never need a feature flag of their own. A disabled resolver never
// builds a request, never resolves a name, and never contacts anything.
func NewOnlineResolver(enabled bool, endpoint string, requestsPerMinute int) *OnlineResolver {
	if !enabled || requestsPerMinute <= 0 {
		return &OnlineResolver{}
	}
	return &OnlineResolver{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: onlineRequestTimeout,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return errOnlineRedirect
			},
		},
		// One evenly spaced request per slot is the whole rate limiter: it cannot
		// burst through the provider's per-minute allowance even after an idle
		// stretch, which a refilling bucket could.
		pace:  time.NewTicker(time.Minute / time.Duration(requestsPerMinute)),
		cache: map[string]cachedLookup{},
	}
}

func (r *OnlineResolver) Enabled() bool {
	return r != nil && r.pace != nil
}

func (r *OnlineResolver) Source() string {
	if !r.Enabled() {
		return SourceDisabled
	}
	return SourceOnline
}

func (r *OnlineResolver) Endpoint() string {
	if !r.Enabled() {
		return ""
	}
	return OnlineProvider(r.endpoint).Origin()
}

// ProviderDescriptor contains only the destination authority and transport, never
// credentials, paths, query parameters or fragments from the configured template.
type ProviderDescriptor struct {
	Host   string
	Scheme string
}

func OnlineProvider(endpoint string) ProviderDescriptor {
	if endpoint == "" {
		endpoint = DefaultOnlineEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ProviderDescriptor{}
	}
	return ProviderDescriptor{Host: parsed.Host, Scheme: parsed.Scheme}
}
func (p ProviderDescriptor) Origin() string {
	if p.Host == "" {
		return ""
	}
	return p.Scheme + "://" + p.Host
}

var errOnlineRedirect = errors.New("redirects are not followed")

// Transport errors often embed the full request URL (including redirect URLs).
// Keep only safe destination metadata and an actionable class. Context identity
// remains available to cancellation callers without retaining the unsafe cause.
func (r *OnlineResolver) requestError(err error) error {
	label := "transport error"
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("geography lookup at %s: %w", r.Endpoint(), context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("geography lookup at %s: %w", r.Endpoint(), context.DeadlineExceeded)
	case errors.Is(err, errOnlineRedirect):
		label = "redirects are not followed"
	default:
		var network net.Error
		if errors.As(err, &network) && network.Timeout() {
			label = "request timed out"
		}
	}
	return fmt.Errorf("geography lookup at %s failed: %s", r.Endpoint(), label)
}

func (r *OnlineResolver) Close() error {
	if !r.Enabled() {
		return nil
	}
	r.pace.Stop()
	return nil
}

// Lookup returns what the provider knows about one address. It reports false
// with a nil error when the provider answered that it does not know the
// address — unlike the local resolver, a failure to reach the provider at all
// is a different fact, and is returned as an error so it can be logged rather
// than silently read as "unknown".
func (r *OnlineResolver) Lookup(ctx context.Context, ipAddress string) (Location, bool, error) {
	if !r.Enabled() {
		return Location{}, false, nil
	}
	address, err := netip.ParseAddr(ipAddress)
	if err != nil {
		return Location{}, false, nil
	}
	// A LAN address tells the provider something about this network and gets a
	// "fail" back anyway, so it is never sent.
	if !isPubliclyRoutable(address) {
		return Location{}, false, nil
	}
	if cached, ok := r.cached(ipAddress); ok {
		return cached.location, cached.found, nil
	}
	if err := r.waitForSlot(ctx); err != nil {
		return Location{}, false, err
	}

	answer, err := r.request(ctx, ipAddress)
	if err != nil {
		// A provider that is down, throttling or answering nonsense says nothing
		// about this address, so nothing is remembered about it.
		return Location{}, false, err
	}
	if answer.Status != onlineStatusSuccess {
		r.remember(ipAddress, cachedLookup{})
		return Location{}, false, nil
	}

	located := cachedLookup{location: answer.toLocation(), found: true}
	r.remember(ipAddress, located)
	return located.location, true, nil
}

// Scheduled retries must consult the provider again after their durable delay,
// rather than recycling an in-process negative/partial answer forever.
func (r *OnlineResolver) forget(ip string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.cache, ip)
}

func (r *OnlineResolver) cached(ipAddress string) (cachedLookup, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	entry, ok := r.cache[ipAddress]
	return entry, ok
}

func (r *OnlineResolver) remember(ipAddress string, entry cachedLookup) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// A fresh map rather than a delete of the oldest key: Go does not return a
	// large map's buckets to the heap on delete, so evicting one at a time would
	// hold the high-water mark for the life of the process — the growth this cap
	// exists to stop.
	if len(r.cache) >= maxCacheEntries {
		r.cache = map[string]cachedLookup{}
	}
	r.cache[ipAddress] = entry
}

func (r *OnlineResolver) waitForSlot(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.pace.C:
		return nil
	}
}

func (r *OnlineResolver) request(ctx context.Context, ipAddress string) (ipAPIAnswer, error) {
	target := strings.Replace(r.endpoint, OnlineIPPlaceholder, url.PathEscape(ipAddress), 1)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ipAPIAnswer{}, fmt.Errorf("build geography lookup request: invalid endpoint")
	}
	request.Header.Set("User-Agent", onlineUserAgent)

	response, err := r.client.Do(request)
	if err != nil {
		return ipAPIAnswer{}, r.requestError(err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusTooManyRequests {
		return ipAPIAnswer{}, fmt.Errorf("geography provider is rate limiting this host; lower the configured requests per minute")
	}
	if response.StatusCode != http.StatusOK {
		return ipAPIAnswer{}, fmt.Errorf("geography provider returned HTTP %d", response.StatusCode)
	}

	var answer ipAPIAnswer
	if err := json.NewDecoder(io.LimitReader(response.Body, maxOnlineResponseBytes)).Decode(&answer); err != nil {
		return ipAPIAnswer{}, fmt.Errorf("geography provider returned an unreadable JSON answer")
	}
	return answer, nil
}

// ipAPIAnswer is ip-api.com's JSON shape. A refused lookup carries
// status "fail" with a message and no fields.
type ipAPIAnswer struct {
	Status       string  `json:"status"`
	Message      string  `json:"message"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"countryCode"`
	RegionName   string  `json:"regionName"`
	City         string  `json:"city"`
	Latitude     float64 `json:"lat"`
	Longitude    float64 `json:"lon"`
	ISP          string  `json:"isp"`
	Organisation string  `json:"org"`
}

func (a ipAPIAnswer) toLocation() Location {
	parts := make([]string, 0, 3)
	for _, part := range []string{a.Country, a.RegionName, a.City} {
		if strings.TrimSpace(part) != "" {
			parts = append(parts, part)
		}
	}

	network := a.ISP
	if network == "" {
		network = a.Organisation
	}

	location := Location{
		Country:     a.Country,
		CountryCode: a.CountryCode,
		Location:    strings.Join(parts, ", "),
		ISP:         network,
	}
	// The provider omits the coordinate for an answer it could not place, and
	// its zero value is a real point at sea, so an all-zero pair is dropped.
	if a.Latitude != 0 || a.Longitude != 0 {
		location.Latitude = &a.Latitude
		location.Longitude = &a.Longitude
	}
	return location
}

func isPubliclyRoutable(address netip.Addr) bool {
	unmapped := address.Unmap()
	switch {
	case !unmapped.IsValid(), unmapped.IsUnspecified(), unmapped.IsLoopback():
		return false
	case unmapped.IsPrivate(), unmapped.IsLinkLocalUnicast(), unmapped.IsLinkLocalMulticast():
		return false
	case unmapped.IsMulticast(), unmapped.IsInterfaceLocalMulticast():
		return false
	}
	return true
}
