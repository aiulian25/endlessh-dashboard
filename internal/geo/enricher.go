package geo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"endlessh-dashboard/internal/store"
)

const (
	// backfillInterval is how often the worker looks for unplaced addresses. The
	// online rate limiter, not this tick, is what paces the actual lookups: a
	// sweep that outlasts the interval simply skips the tick it missed.
	backfillInterval = time.Minute
	// backfillBatchSize bounds one sweep so a database full of unplaceable
	// addresses cannot hold the worker in a single pass forever.
	backfillBatchSize = 100
)

// localEnrichmentSource supplies offline answers and a stable content generation.
type localEnrichmentSource interface {
	Enabled() bool
	Lookup(string) (Location, bool)
	Generation() string
}

// Enricher fills in the geography the tarpits themselves did not publish. It
// is the only caller of the online provider, and it exists as a worker rather
// than a step in the scrape because a lookup can be rate limited into the
// minutes while a scrape has to finish in seconds.
type Enricher struct {
	now    func() time.Time
	store  *store.Store
	local  localEnrichmentSource
	online *OnlineResolver
	logger *slog.Logger
}

func NewEnricher(dataStore *store.Store, local localEnrichmentSource, online *OnlineResolver, logger *slog.Logger) *Enricher {
	return &Enricher{store: dataStore, local: local, online: online, logger: logger, now: time.Now}
}

// Run backfills locations until ctx is done. With no local database and no
// online provider there is nothing any sweep could discover, so it returns
// immediately rather than querying for work it could not do.
func (e *Enricher) Run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if !e.local.Enabled() && !e.online.Enabled() {
		return
	}
	e.logger.Info("geography backfill running",
		"local_database", e.local.Enabled(), "online_provider", e.online.Enabled())

	ticker := time.NewTicker(backfillInterval)
	defer ticker.Stop()

	e.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runOnce(ctx)
		}
	}
}

func (e *Enricher) sourceGeneration() string {
	// Credentials and path/query changes still invalidate durable enrichment
	// progress, but only the hash leaves this private boundary.
	endpoint := ""
	if e.online.Enabled() {
		endpoint = e.online.endpoint
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte("enrichment-v1\x00"+e.local.Generation()+fmt.Sprint(e.online.Enabled())+"\x00"+endpoint)))
}
func (e *Enricher) clock() time.Time {
	if e.now != nil {
		return e.now().UTC()
	}
	return time.Now().UTC()
}

func (e *Enricher) runOnce(ctx context.Context) {
	if ctx.Err() != nil || (!e.local.Enabled() && !e.online.Enabled()) {
		return
	}
	generation := e.sourceGeneration()
	missing, err := e.store.EnrichmentDue(ctx, generation, e.clock(), backfillBatchSize)
	if err != nil {
		if ctx.Err() == nil {
			e.logger.Error("list enrichment work", "error", err)
		}
		return
	}
	placed := 0
	for _, attacker := range missing {
		if ctx.Err() != nil {
			return
		}
		location, outcome, err := e.resolveAttempt(ctx, attacker.IPAddress)
		if ctx.Err() != nil {
			return
		}
		result := store.EnrichmentResult{IPAddress: attacker.IPAddress, Generation: generation, At: e.clock(), Outcome: outcome, Location: location}
		switch outcome {
		case "transient":
			result.Failures = min(16, attacker.Failures+1)
			next := result.At.Add(enrichmentRetryDelay(result.Failures))
			result.NextAttempt = &next
			e.logger.Warn("online geography lookup", "ip", attacker.IPAddress, "error", err)
		case "miss", "resolved":
			// A partial successful answer may leave columns missing. FinishEnrichment
			// decides completeness after merging with all retained machine/IP copies.
			next := result.At.Add(24 * time.Hour)
			result.NextAttempt = &next
		}
		if err = e.store.FinishEnrichment(ctx, result); err != nil {
			if ctx.Err() == nil {
				e.logger.Error("store enrichment result", "ip", attacker.IPAddress, "error", err)
			}
			continue
		}
		if location != nil {
			placed++
		}
	}
	if placed > 0 {
		e.logger.Info("geography backfill placed attackers", "resolved", placed, "considered", len(missing))
	}
}
func enrichmentRetryDelay(failures int) time.Duration {
	return min(24*time.Hour, time.Minute*time.Duration(1<<min(11, max(0, failures-1))))
}

func (e *Enricher) resolveAttempt(ctx context.Context, ip string) (*store.AttackerLocation, string, error) {
	if ctx.Err() != nil {
		return nil, "transient", ctx.Err()
	}
	if location, ok := e.local.Lookup(ip); ok {
		result := attackerLocation(location)
		return &result, "resolved", nil
	}
	if ctx.Err() != nil {
		return nil, "transient", ctx.Err()
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || !isPubliclyRoutable(address) {
		return nil, "unlookupable", nil
	}
	if !e.online.Enabled() {
		return nil, "miss", nil
	}
	e.online.forget(ip)
	location, ok, err := e.online.Lookup(ctx, ip)
	if err != nil {
		return nil, "transient", err
	}
	if !ok {
		return nil, "miss", nil
	}
	result := attackerLocation(location)
	return &result, "resolved", nil
}

// resolve asks the cheap offline source first and only then the one that costs
// a request to a third party.
func (e *Enricher) resolve(ctx context.Context, ipAddress string) (store.AttackerLocation, bool) {
	location, _, err := e.resolveAttempt(ctx, ipAddress)
	if err != nil || location == nil {
		return store.AttackerLocation{}, false
	}
	return *location, true
}

func attackerLocation(location Location) store.AttackerLocation {
	return store.AttackerLocation{
		Country:     location.Country,
		CountryCode: location.CountryCode,
		Location:    location.Location,
		ISP:         location.ISP,
		Latitude:    location.Latitude,
		Longitude:   location.Longitude,
	}
}
