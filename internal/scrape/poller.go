package scrape

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

const (
	// maxResponseBytes caps what a registered target can make this process read.
	maxResponseBytes = 8 << 20
	// maxBackoffShift bounds how far a failing machine backs off: the interval
	// doubles per consecutive failure up to interval x8.
	maxBackoffShift = 3
	acceptHeader    = "text/plain;version=0.0.4,text/plain;q=0.9,*/*;q=0.1"
	userAgent       = "endlessh-dashboard"
)

type Poller struct {
	store          *store.Store
	validator      *registry.Validator
	geoResolver    *geo.Resolver
	logger         *slog.Logger
	interval       time.Duration
	timeout        time.Duration
	httpClient     *http.Client
	failureStreaks map[int64]int
	nextAttempt    map[int64]time.Time
	mutex          sync.Mutex
}

func NewPoller(
	dataStore *store.Store,
	validator *registry.Validator,
	geoResolver *geo.Resolver,
	logger *slog.Logger,
	interval, timeout time.Duration,
) *Poller {
	return &Poller{
		store:       dataStore,
		validator:   validator,
		geoResolver: geoResolver,
		logger:      logger,
		interval:    interval,
		timeout:     timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return fmt.Errorf("redirects are not followed: %s", request.URL.Redacted())
			},
		},
		failureStreaks: map[int64]int{},
		nextAttempt:    map[int64]time.Time{},
	}
}

// Run polls every enabled machine on the configured interval until ctx is done.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.pollAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

func (p *Poller) pollAll(ctx context.Context) {
	machines, err := p.store.ListEnabledMachines(ctx)
	if err != nil {
		p.logger.Error("list machines for scraping", "error", err)
		return
	}

	var waitGroup sync.WaitGroup
	for _, machine := range machines {
		if !p.due(machine.ID) {
			continue
		}
		waitGroup.Add(1)
		go func(target store.Machine) {
			defer waitGroup.Done()
			// A scrape parses input from a machine this process does not
			// control. A panic in that path must cost one scrape, never the
			// whole dashboard.
			defer func() {
				if recovered := recover(); recovered != nil {
					p.logger.Error("scrape panicked", "machine", target.Name, "panic", recovered)
					p.recordFailure(ctx, target, time.Now().UTC(),
						fmt.Errorf("internal error while reading metrics: %v", recovered))
				}
			}()
			p.pollOne(ctx, target)
		}(machine)
	}
	waitGroup.Wait()
}

func (p *Poller) due(machineID int64) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	next, known := p.nextAttempt[machineID]
	return !known || !time.Now().Before(next)
}

func (p *Poller) pollOne(ctx context.Context, machine store.Machine) {
	scrapedAt := time.Now().UTC()
	snapshot, err := p.fetch(ctx, machine)
	if err != nil {
		p.recordFailure(ctx, machine, scrapedAt, err)
		return
	}
	if err := p.applySnapshot(ctx, machine, scrapedAt, snapshot); err != nil {
		p.recordFailure(ctx, machine, scrapedAt, err)
		return
	}

	p.mutex.Lock()
	p.failureStreaks[machine.ID] = 0
	p.nextAttempt[machine.ID] = time.Time{}
	p.mutex.Unlock()

	if err := p.store.RecordScrapeSuccess(ctx, machine.ID, scrapedAt); err != nil {
		p.logger.Error("record scrape success", "machine", machine.Name, "error", err)
	}
}

func (p *Poller) recordFailure(ctx context.Context, machine store.Machine, at time.Time, cause error) {
	p.mutex.Lock()
	streak := p.failureStreaks[machine.ID] + 1
	p.failureStreaks[machine.ID] = streak
	multiplier := 1 << min(streak-1, maxBackoffShift)
	p.nextAttempt[machine.ID] = at.Add(p.interval * time.Duration(multiplier))
	p.mutex.Unlock()

	p.logger.Warn("scrape failed", "machine", machine.Name, "error", cause, "consecutive_failures", streak)
	if err := p.store.RecordScrapeFailure(ctx, machine.ID, at, cause.Error()); err != nil {
		p.logger.Error("record scrape failure", "machine", machine.Name, "error", err)
	}
}

// ProbeSummary describes what a one-off connection test found, so the person
// adding a machine can see it is really an endlessh-go endpoint and not just
// something that answered on the port.
type ProbeSummary struct {
	Address        string
	Clients        int
	LocalPorts     []string
	Connections    int64
	TrappedSeconds float64
	GeoIPEnabled   bool
}

// Probe performs exactly one scrape against a candidate target using the same
// validation, dialling and parsing a real scrape uses. That shared path is the
// point: a test that passed while the scraper would fail would be worse than no
// test at all.
func (p *Poller) Probe(ctx context.Context, host string, port int, metricsPath string) (ProbeSummary, error) {
	snapshot, err := p.fetch(ctx, store.Machine{Host: host, Port: port, MetricsPath: metricsPath})
	if err != nil {
		return ProbeSummary{}, err
	}

	summary := ProbeSummary{Clients: len(snapshot.Clients)}
	if address, resolveErr := p.validator.ResolveTarget(ctx, host); resolveErr == nil {
		summary.Address = net.JoinHostPort(address.String(), strconv.Itoa(port))
	}

	ports := map[string]bool{}
	for key, value := range snapshot.Totals {
		if isTotalSeries(key, MetricOpenCountTotal) {
			summary.Connections += int64(math.Round(value))
		}
		if localPort := localPortFromSeriesKey(key); localPort != "" {
			ports[localPort] = true
		}
	}
	for localPort := range ports {
		summary.LocalPorts = append(summary.LocalPorts, localPort)
	}
	sort.Strings(summary.LocalPorts)

	for _, client := range snapshot.Clients {
		summary.TrappedSeconds += client.TrappedSeconds
		if client.Country != "" {
			summary.GeoIPEnabled = true
		}
	}
	return summary, nil
}

// localPortFromSeriesKey pulls the local_port back out of an aggregate series
// key, which is formatted as "total:<metric>|<local_port>".
func localPortFromSeriesKey(seriesKey string) string {
	if !strings.HasPrefix(seriesKey, "total:") {
		return ""
	}
	separator := strings.LastIndex(seriesKey, "|")
	if separator < 0 {
		return ""
	}
	return seriesKey[separator+1:]
}

// fetch resolves and re-vets the target on every scrape, then dials the exact
// address that passed, so a DNS record that changes between validation and the
// request cannot point this process somewhere else.
func (p *Poller) fetch(ctx context.Context, machine store.Machine) (Snapshot, error) {
	requestCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	address, err := p.validator.ResolveTarget(requestCtx, machine.Host)
	if err != nil {
		return Snapshot{}, err
	}

	target := "http://" + net.JoinHostPort(address.String(), strconv.Itoa(machine.Port)) + machine.MetricsPath
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("build request: %w", err)
	}
	request.Host = machine.Host
	request.Header.Set("Accept", acceptHeader)
	request.Header.Set("User-Agent", userAgent)

	response, err := p.httpClient.Do(request)
	if err != nil {
		return Snapshot{}, fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("metrics endpoint returned %s", response.Status)
	}
	return Parse(io.LimitReader(response.Body, maxResponseBytes))
}

func (p *Poller) applySnapshot(ctx context.Context, machine store.Machine, at time.Time, snapshot Snapshot) error {
	previous, err := p.store.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		return err
	}

	current := make(map[string]float64, len(snapshot.Totals)+2*len(snapshot.Clients))
	delta := store.ScrapeDelta{MachineID: machine.ID, At: at}

	for key, value := range snapshot.Totals {
		current[key] = value
		change := counterDelta(previous, key, value)
		switch {
		case isTotalSeries(key, MetricOpenCountTotal):
			delta.Opens += int64(math.Round(change))
		case isTotalSeries(key, MetricClosedCountTotal):
			delta.Closes += int64(math.Round(change))
		case isTotalSeries(key, MetricSentBytesTotal):
			delta.BytesSent += int64(math.Round(change))
		case isTotalSeries(key, MetricTrappedTimeSecondsTotal):
			delta.TrappedSeconds += change
		}
	}

	for ipAddress, sample := range snapshot.Clients {
		connectionsKey := ClientSeriesKey(MetricClientOpenCount, ipAddress)
		trappedKey := ClientSeriesKey(MetricClientTrappedTimeSeconds, ipAddress)
		current[connectionsKey] = sample.Connections
		current[trappedKey] = sample.TrappedSeconds

		// An attacker's row holds that client's own lifetime figures, with no
		// time bucketing, so the first sighting adopts the counter as it stands
		// rather than starting from zero — the client really did make those
		// connections. Liveness is a different question: nothing is known about
		// whether it is still connected until a later scrape shows growth, so a
		// first sighting is never reported as actively trapped.
		connectionsDelta, connectionsFirstSeen := clientCounterDelta(previous, connectionsKey, sample.Connections)
		trappedDelta, trappedFirstSeen := clientCounterDelta(previous, trappedKey, sample.TrappedSeconds)
		firstSighting := connectionsFirstSeen || trappedFirstSeen

		attacker := store.AttackerDelta{
			IPAddress:      ipAddress,
			Connections:    int64(math.Round(connectionsDelta)),
			TrappedSeconds: trappedDelta,
			Country:        sample.Country,
			Geohash:        sample.Geohash,
			Location:       sample.Location,
			Active:         !firstSighting && (trappedDelta > 0 || connectionsDelta > 0),
		}
		p.applyGeography(&attacker, sample.Geohash)
		delta.Attackers = append(delta.Attackers, attacker)
	}

	// The baseline goes in with the deltas it was measured against, in one
	// transaction: applying one without the other would double-count this
	// scrape on the next run.
	delta.CounterStates = current
	return p.store.ApplyScrape(ctx, delta)
}

// applyGeography fills in the place from the two sources a scrape can reach.
// The tarpit's own labels win: they cost nothing, and the operator chose that
// supplier when they configured endlessh-go. The local database only fills what
// the labels left empty. The online provider is never called here — a lookup can
// be rate limited into the minutes, and a scrape has to finish in seconds — so
// whatever is still missing is left to the backfill worker.
func (p *Poller) applyGeography(attacker *store.AttackerDelta, geohash string) {
	if latitude, longitude, ok := geo.DecodeGeohash(geohash); ok {
		attacker.Latitude = &latitude
		attacker.Longitude = &longitude
	}
	if attacker.Country != "" || !p.geoResolver.Enabled() {
		return
	}
	resolved, ok := p.geoResolver.Lookup(attacker.IPAddress)
	if !ok {
		return
	}
	attacker.Country = resolved.Country
	attacker.CountryCode = resolved.CountryCode
	attacker.Location = resolved.Location
	if attacker.Latitude == nil {
		attacker.Latitude = resolved.Latitude
		attacker.Longitude = resolved.Longitude
	}
}

// counterDelta turns two raw counter readings into a delta. A first sighting
// contributes nothing — importing a lifetime total as one minute's traffic
// would be a lie — and a value that went backwards means the monitored
// instance restarted, so the new value is the delta.
func counterDelta(previous map[string]float64, key string, value float64) float64 {
	earlier, seen := previous[key]
	if !seen {
		return 0
	}
	if value < earlier {
		return value
	}
	return value - earlier
}

// clientCounterDelta is counterDelta's per-attacker counterpart: on a first
// sighting it returns the whole current value, and reports that it was a first
// sighting so the caller can withhold the "trapped right now" claim.
func clientCounterDelta(previous map[string]float64, key string, value float64) (float64, bool) {
	earlier, seen := previous[key]
	if !seen {
		return value, true
	}
	if value < earlier {
		return value, false
	}
	return value - earlier, false
}

func isTotalSeries(seriesKey, metricName string) bool {
	return strings.HasPrefix(seriesKey, "total:"+metricName+"|")
}
