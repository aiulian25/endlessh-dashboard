package scrape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/metricvalue"
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

const (
	DefaultConcurrency = 4
	MaxConcurrency     = 32
)

type Poller struct {
	concurrency          int
	workSlots            chan struct{}
	runMutex             sync.Mutex
	scheduling           bool
	scheduledGenerations map[int64]int64
	store                *store.Store
	validator            *registry.Validator
	geoResolver          *geo.Resolver
	logger               *slog.Logger
	interval             time.Duration
	timeout              time.Duration
	httpClient           *http.Client
	failureStreaks       map[int64]int
	nextAttempt          map[int64]time.Time
	attemptGenerations   map[int64]int64
	workerRunning        bool
	workerHeartbeat      time.Time
	mutex                sync.Mutex
}

func NewPoller(
	dataStore *store.Store,
	validator *registry.Validator,
	geoResolver *geo.Resolver,
	logger *slog.Logger,
	interval, timeout time.Duration,
	limits ...int,
) *Poller {
	concurrency := DefaultConcurrency
	if len(limits) > 0 && limits[0] >= 1 && limits[0] <= MaxConcurrency {
		concurrency = limits[0]
	}
	return &Poller{
		concurrency: concurrency, workSlots: make(chan struct{}, concurrency),
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
		failureStreaks:     map[int64]int{},
		nextAttempt:        map[int64]time.Time{},
		attemptGenerations: map[int64]int64{},
	}
}

func (p *Poller) due(machineID int64, generations ...int64) bool {
	generation := int64(0)
	if len(generations) > 0 {
		generation = generations[0]
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.acceptGeneration(machineID, generation) {
		return false
	}
	next, known := p.nextAttempt[machineID]
	return !known || !time.Now().Before(next)
}

func (p *Poller) pollOne(ctx context.Context, machine store.Machine) {
	if ctx.Err() != nil {
		return
	}
	if !p.acquireWork(ctx) {
		return
	}
	defer p.releaseWork()
	// Validate after waiting for a slot, so queued metadata cannot bypass an
	// endpoint/enable change. Commit-time generation fences remain authoritative.
	p.mutex.Lock()
	scheduled := p.scheduling
	p.mutex.Unlock()
	if scheduled {
		current, err := p.store.GetMachine(ctx, machine.ID)
		if err != nil || !current.Enabled || current.TargetGeneration != machine.TargetGeneration {
			return
		}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			p.logger.Error("scrape panicked", "machine", machine.Name, "panic", recovered)
			p.recordFailure(ctx, machine, time.Now().UTC(), fmt.Errorf("internal error while reading metrics: %v", recovered))
		}
	}()
	scrapedAt := time.Now().UTC()
	snapshot, err := p.fetch(ctx, machine)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		p.recordFailure(ctx, machine, scrapedAt, err)
		return
	}
	if err := p.applySnapshot(ctx, machine, scrapedAt, snapshot); err != nil {
		if errors.Is(err, store.ErrObsoleteScrape) {
			return
		}
		p.recordFailure(ctx, machine, scrapedAt, err)
		return
	}

	if ctx.Err() != nil {
		return
	}
	if err := p.store.RecordScrapeSuccess(ctx, machine.ID, scrapedAt, machine.TargetGeneration); err != nil {
		if !errors.Is(err, store.ErrObsoleteScrape) {
			p.logger.Error("record scrape success", "error", err)
		}
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.acceptGeneration(machine.ID, machine.TargetGeneration) {
		return
	}
	p.failureStreaks[machine.ID] = 0
	p.nextAttempt[machine.ID] = time.Time{}
}

// acceptGeneration is called with p.mutex held; old work cannot poison a newer
// target's retry schedule. Generations also distinguish rapid disable/re-enable.
func (p *Poller) acceptGeneration(id, generation int64) bool {
	if p.scheduling {
		if current, ok := p.scheduledGenerations[id]; !ok || current != generation {
			return false
		}
	}
	old, known := p.attemptGenerations[id]
	if known && old > generation {
		return false
	}
	if !known || old != generation {
		p.failureStreaks[id] = 0
		p.nextAttempt[id] = time.Time{}
		p.attemptGenerations[id] = generation
	}
	return true
}

func (p *Poller) recordFailure(ctx context.Context, machine store.Machine, at time.Time, cause error) {
	if ctx.Err() != nil {
		return
	}
	if errors.Is(cause, store.ErrObsoleteScrape) {
		return
	}
	if err := p.store.RecordScrapeFailure(ctx, machine.ID, at, cause.Error(), machine.TargetGeneration); err != nil {
		if !errors.Is(err, store.ErrObsoleteScrape) {
			p.logger.Error("record scrape failure", "error", err)
		}
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.acceptGeneration(machine.ID, machine.TargetGeneration) {
		return
	}
	streak := p.failureStreaks[machine.ID] + 1
	p.failureStreaks[machine.ID] = streak
	multiplier := 1 << min(streak-1, maxBackoffShift)
	p.nextAttempt[machine.ID] = at.Add(p.interval * time.Duration(multiplier))
	p.logger.Warn("scrape failed", "machine", machine.Name, "error", cause, "consecutive_failures", streak)
}

// ProbeSummary describes what a one-off connection test found, so the person
// adding a machine can distinguish reachability from supported metric evidence.
type ProbeSummary struct {
	Reachable       bool
	ExpositionValid bool
	MetricFamilies  []MetricFamilyEvidence
	Address         string
	Clients         int
	LocalPorts      []string
	Connections     int64
	TrappedSeconds  float64
	GeoIPEnabled    bool
}

// EvidenceState describes compatibility of the observed samples, not product
// identity or a version. A childless exporter may have no supported samples yet.
func (s ProbeSummary) EvidenceState() string {
	if !s.ExpositionValid {
		return "unavailable"
	}
	switch len(s.MetricFamilies) {
	case 0:
		return "inconclusive"
	case 6:
		return "compatible"
	default:
		return "partial"
	}
}

// Probe performs exactly one scrape against a candidate target using the same
// validation, dialling and parsing a real scrape uses. That shared path is the
// point: a test that passed while the scraper would fail would be worse than no
// test at all.
func (p *Poller) Probe(ctx context.Context, host string, port int, metricsPath string) (ProbeSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if !p.acquireWork(ctx) {
		return ProbeSummary{}, ctx.Err()
	}
	defer p.releaseWork()
	snapshot, reachable, err := p.fetchWithReachability(ctx, store.Machine{Host: host, Port: port, MetricsPath: metricsPath})
	if err != nil {
		return ProbeSummary{Reachable: reachable}, err
	}

	summary := ProbeSummary{Reachable: true, ExpositionValid: true, MetricFamilies: snapshot.MetricFamilies, Clients: len(snapshot.Clients)}
	if address, resolveErr := p.validator.ResolveTarget(ctx, host); resolveErr == nil {
		summary.Address = net.JoinHostPort(address.String(), strconv.Itoa(port))
	}

	ports := map[string]bool{}
	for key, value := range snapshot.Totals {
		if isTotalSeries(key, MetricOpenCountTotal) {
			summary.Connections, err = metricvalue.AddInt(summary.Connections, int64(value))
			if err != nil {
				return ProbeSummary{Reachable: true}, err
			}
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
		summary.TrappedSeconds, err = metricvalue.AddFloat(summary.TrappedSeconds, client.TrappedSeconds)
		if err != nil {
			return ProbeSummary{Reachable: true}, err
		}
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
	snapshot, _, err := p.fetchWithReachability(ctx, machine)
	return snapshot, err
}

func (p *Poller) fetchWithReachability(ctx context.Context, machine store.Machine) (Snapshot, bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	address, err := p.validator.ResolveTarget(requestCtx, machine.Host)
	if err != nil {
		return Snapshot{}, false, err
	}

	target := "http://" + net.JoinHostPort(address.String(), strconv.Itoa(machine.Port)) + machine.MetricsPath
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("build request: %w", err)
	}
	request.Host = machine.Host
	request.Header.Set("Accept", acceptHeader)
	request.Header.Set("User-Agent", userAgent)

	response, err := p.httpClient.Do(request)
	if err != nil {
		return Snapshot{}, response != nil, fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Snapshot{}, true, fmt.Errorf("metrics endpoint returned %s", response.Status)
	}
	// Read at most one byte beyond the cap to distinguish overflow from EOF.
	// Parse may stop early on malformed input; finish the bounded read so a
	// valid prefix or early parse failure cannot conceal an oversized body.
	limited := &io.LimitedReader{R: response.Body, N: maxResponseBytes + 1}
	snapshot, parseErr := Parse(limited)
	_, readErr := io.Copy(io.Discard, limited)
	if limited.N == 0 {
		return Snapshot{}, true, fmt.Errorf("metrics response exceeds %d-byte limit (8 MiB)", maxResponseBytes)
	}
	if parseErr != nil {
		return Snapshot{}, true, parseErr
	}
	if readErr != nil {
		return Snapshot{}, true, fmt.Errorf("read metrics response: %w", readErr)
	}
	return snapshot, true, nil
}

func (p *Poller) applySnapshot(ctx context.Context, machine store.Machine, at time.Time, snapshot Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	state, err := p.store.LoadScrapeState(ctx, machine)
	if err != nil {
		return err
	}

	previous := state.Counters
	// Refuse poisoned legacy baselines instead of inventing a repair delta.
	for key, value := range previous {
		if err := metricvalue.Validate(value, !(isTotalSeries(key, MetricTrappedTimeSecondsTotal) || (strings.HasPrefix(key, "ip:"+MetricClientTrappedTimeSeconds+"|") || strings.HasPrefix(key, "ip:v2:"+MetricClientTrappedTimeSeconds+"|")))); err != nil {
			return fmt.Errorf("invalid stored baseline; operator repair required: %w", err)
		}
	}
	current := make(map[string]float64, len(snapshot.Totals)+2*len(snapshot.Clients))
	delta := store.ScrapeDelta{MachineID: machine.ID, At: at, TargetGeneration: machine.TargetGeneration, Revision: &state.Revision}

	for key, value := range snapshot.Totals {
		current[key] = value
		change := counterDelta(previous, key, value)
		switch {
		case isTotalSeries(key, MetricOpenCountTotal):
			delta.Opens, err = metricvalue.AddInt(delta.Opens, int64(change))
			if err != nil {
				return err
			}
		case isTotalSeries(key, MetricClosedCountTotal):
			delta.Closes, err = metricvalue.AddInt(delta.Closes, int64(change))
			if err != nil {
				return err
			}
		case isTotalSeries(key, MetricSentBytesTotal):
			delta.BytesSent, err = metricvalue.AddInt(delta.BytesSent, int64(change))
			if err != nil {
				return err
			}
		case isTotalSeries(key, MetricTrappedTimeSecondsTotal):
			delta.TrappedSeconds, err = metricvalue.AddFloat(delta.TrappedSeconds, change)
			if err != nil {
				return err
			}
		}
	}

	policy := state.Policy
	if policy != "import_lifetime" && policy != "baseline_only" {
		return fmt.Errorf("unsupported client counter policy")
	}
	knownIPs := map[string]bool{}
	for key := range previous {
		if strings.HasPrefix(key, "ip:v2:") {
			if split := strings.Index(key, "|"); split >= 0 {
				var tuple []string
				if json.Unmarshal([]byte(key[split+1:]), &tuple) == nil && len(tuple) == 2 {
					knownIPs[tuple[0]] = true
				}
			}
		}
	}
	changes := map[string]store.AttackerDelta{}
	for key, series := range snapshot.ClientSeries {
		current[key] = series.Value
		change, first := clientCounterDelta(previous, key, series.Value)
		if first && policy == "baseline_only" {
			change = 0
		}
		attacker := changes[series.IPAddress]
		attacker.IPAddress = series.IPAddress
		attacker.FirstObservation = policy == "import_lifetime" && !knownIPs[series.IPAddress]
		attacker.ImportedLifetime = attacker.ImportedLifetime || (first && policy == "import_lifetime" && change > 0)
		if series.Metric == MetricClientOpenCount {
			attacker.Connections, err = metricvalue.AddInt(attacker.Connections, int64(change))
		} else {
			attacker.TrappedSeconds, err = metricvalue.AddFloat(attacker.TrappedSeconds, change)
		}
		if err != nil {
			return err
		}
		attacker.Active = attacker.Active || (!first && change > 0)
		changes[series.IPAddress] = attacker
	}
	for ipAddress, attacker := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		sample := snapshot.Clients[ipAddress]
		attacker.Country = sample.Country
		attacker.Geohash = sample.Geohash
		attacker.Location = sample.Location
		p.applyGeography(&attacker, sample.Geohash)
		delta.Attackers = append(delta.Attackers, attacker)
	}

	// The baseline goes in with the deltas it was measured against, in one
	// transaction: applying one without the other would double-count this
	// scrape on the next run.
	delta.Coverage = observationCoverage(state, machine, at, snapshot, 2*p.interval)
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
