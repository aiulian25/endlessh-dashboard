package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrObsoleteScrape means a fetched result no longer owns this machine's state.
var ErrObsoleteScrape = errors.New("obsolete scrape discarded")

type ScrapeState struct {
	Cadence            time.Duration
	Counters           map[string]float64
	Revision           int64
	Policy             string
	CounterTimes       map[string]time.Time
	PreviousSample     *time.Time
	CoverageGeneration *int64
	Failures           int
}

// LoadScrapeState reads a consistent baseline and revision. A competing result
// or edit between this read and ApplyScrape invalidates the transaction's claim.
func (s *Store) LoadScrapeState(ctx context.Context, machine Machine) (ScrapeState, error) {
	tx, err := s.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ScrapeState{}, err
	}
	defer tx.Rollback()
	state := ScrapeState{Counters: map[string]float64{}, CounterTimes: map[string]time.Time{}}
	var previousNS, generation, cadence sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT scrape_revision,client_counter_policy,consecutive_failures,c.sample_ns,c.generation,c.cadence_ns FROM machines m LEFT JOIN scrape_coverage_state c ON c.machine_id=m.id WHERE m.id=? AND target_generation=? AND enabled=1`, machine.ID, machine.TargetGeneration).Scan(&state.Revision, &state.Policy, &state.Failures, &previousNS, &generation, &cadence)
	if errors.Is(err, sql.ErrNoRows) {
		return ScrapeState{}, ErrObsoleteScrape
	}
	if err != nil {
		return ScrapeState{}, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT series,value,updated_at FROM counter_states WHERE machine_id=?", machine.ID)
	if err != nil {
		return ScrapeState{}, err
	}
	for rows.Next() {
		var key string
		var value float64
		var at int64
		if err = rows.Scan(&key, &value, &at); err != nil {
			break
		}
		state.Counters[key] = value
		if strings.HasPrefix(key, SeriesPrefixTotal) {
			// Chart coverage needs only aggregate timestamps, not a second per-IP map.
			state.CounterTimes[key] = time.Unix(at, 0).UTC()
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return ScrapeState{}, err
	}
	state.Cadence = time.Duration(cadence.Int64)
	if previousNS.Valid {
		at := time.Unix(0, previousNS.Int64).UTC()
		state.PreviousSample = &at
	}
	if generation.Valid {
		state.CoverageGeneration = &generation.Int64
	}
	if err = tx.Commit(); err != nil {
		return ScrapeState{}, err
	}
	return state, nil
}
