package geo

import (
	"context"
	"log/slog"
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

// Enricher fills in the geography the tarpits themselves did not publish. It
// is the only caller of the online provider, and it exists as a worker rather
// than a step in the scrape because a lookup can be rate limited into the
// minutes while a scrape has to finish in seconds.
type Enricher struct {
	store  *store.Store
	local  *Resolver
	online *OnlineResolver
	logger *slog.Logger
}

func NewEnricher(dataStore *store.Store, local *Resolver, online *OnlineResolver, logger *slog.Logger) *Enricher {
	return &Enricher{store: dataStore, local: local, online: online, logger: logger}
}

// Run backfills locations until ctx is done. With no local database and no
// online provider there is nothing any sweep could discover, so it returns
// immediately rather than querying for work it could not do.
func (e *Enricher) Run(ctx context.Context) {
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

func (e *Enricher) runOnce(ctx context.Context) {
	missing, err := e.store.AttackersMissingLocation(ctx, backfillBatchSize)
	if err != nil {
		e.logger.Error("list attackers missing a location", "error", err)
		return
	}

	placed := 0
	for _, attacker := range missing {
		if ctx.Err() != nil {
			return
		}
		location, ok := e.resolve(ctx, attacker.IPAddress)
		if !ok {
			continue
		}
		if err := e.store.SetAttackerLocation(ctx, attacker.IPAddress, location); err != nil {
			e.logger.Error("store resolved location", "ip", attacker.IPAddress, "error", err)
			continue
		}
		placed++
	}

	if placed > 0 {
		e.logger.Info("geography backfill placed attackers", "resolved", placed, "considered", len(missing))
	}
}

// resolve asks the cheap offline source first and only then the one that costs
// a request to a third party.
func (e *Enricher) resolve(ctx context.Context, ipAddress string) (store.AttackerLocation, bool) {
	if found, ok := e.local.Lookup(ipAddress); ok {
		return attackerLocation(found), true
	}
	found, ok, err := e.online.Lookup(ctx, ipAddress)
	if err != nil {
		// Nothing was learned about this address; the next sweep will try again.
		e.logger.Warn("online geography lookup", "ip", ipAddress, "error", err)
		return store.AttackerLocation{}, false
	}
	if !ok {
		return store.AttackerLocation{}, false
	}
	return attackerLocation(found), true
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
