package scrape

import (
	"endlessh-dashboard/internal/store"
	"strings"
	"time"
)

func portOfTotal(key string) string {
	port := localPortFromSeriesKey(key)
	if port == "" {
		return store.UnknownPort
	}
	return port
}

// Evaluate each port's four families independently: a disappearing/new/reset
// port must not erase continuity evidence for another port.
func portObservationCoverage(state store.ScrapeState, machine store.Machine, at time.Time, snapshot Snapshot, port string, gap time.Duration) *store.ScrapeCoverage {
	subset := Snapshot{Totals: map[string]float64{}}
	local := state
	local.Counters = map[string]float64{}
	local.CounterTimes = map[string]time.Time{}
	for key, value := range snapshot.Totals {
		if portOfTotal(key) == port {
			subset.Totals[key] = value
		}
	}
	for key, value := range state.Counters {
		if strings.HasPrefix(key, "total:") && portOfTotal(key) == port {
			local.Counters[key] = value
			local.CounterTimes[key] = state.CounterTimes[key]
		}
	}
	c := observationCoverage(local, machine, at, subset, gap)
	if !state.PortCollectionStarted {
		c.Complete = false
		c.From = nil
	}
	return c
}
