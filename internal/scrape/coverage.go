package scrape

import (
	"time"

	"endlessh-dashboard/internal/store"
)

func observationCoverage(state store.ScrapeState, machine store.Machine, at time.Time, snapshot Snapshot, maxGap time.Duration) *store.ScrapeCoverage {
	interval := maxGap / 2
	maxGap = min(maxGap, time.Hour)
	c := &store.ScrapeCoverage{From: state.PreviousSample, Interval: interval}
	stable := state.PreviousSample != nil && state.CoverageGeneration != nil && *state.CoverageGeneration == machine.TargetGeneration && state.Failures == 0 && state.Cadence == interval
	if stable {
		gap := at.Sub(*state.PreviousSample)
		stable = gap > 0 && gap <= maxGap
	}
	families := map[string]bool{}
	for key, value := range snapshot.Totals {
		if old, ok := state.Counters[key]; ok {
			if value < old {
				stable = false
			}
			stamp := state.CounterTimes[key]
			// Missing aggregate series can span more than the last whole-machine sample.
			if state.PreviousSample == nil || stamp.Unix() != state.PreviousSample.Unix() {
				stable = false
			}
			if value != old && (c.UncertainFrom == nil || stamp.Before(*c.UncertainFrom)) {
				t := stamp
				c.UncertainFrom = &t
			}
		} else {
			stable = false
		}
		for _, metric := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal} {
			if isTotalSeries(key, metric) {
				families[metric] = true
			}
		}
	}
	for key := range state.CounterTimes {
		if state.PreviousSample != nil && state.CounterTimes[key].Unix() == state.PreviousSample.Unix() {
			if _, ok := snapshot.Totals[key]; !ok {
				stable = false
			}
		}
	}
	c.Complete = stable && len(families) == 4
	// Regular samples still locate changes only between observations, but only
	// discontinuous samples require the explicit recovery uncertainty marker.
	if c.Complete {
		c.UncertainFrom = nil
	}
	return c
}

func (p *Poller) workerBeat(running bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.workerRunning = running
	p.workerHeartbeat = time.Now().UTC()
}

// WorkerReady checks only in-process state. It never polls a target or scans
// history, and it expires if the scheduler stops making progress.
func (p *Poller) WorkerReady(now time.Time) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	age := now.Sub(p.workerHeartbeat)
	return p.workerRunning && age >= 0 && age <= 2*p.interval+p.timeout
}
