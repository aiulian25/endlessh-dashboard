package store

import (
	"context"
	"database/sql"
	"endlessh-dashboard/internal/ipidentity"
	"endlessh-dashboard/internal/metricvalue"
	"errors"
	"fmt"
	"strings"
	"time"
)

const rollupBucketSeconds = 60

// AttackerDelta is one client's change since the previous scrape of a machine.
// The coordinate is a pair of pointers because 0,0 is a real place: only nil
// means the scrape produced no position for this client.
type AttackerDelta struct {
	IPAddress        string
	Connections      int64
	TrappedSeconds   float64
	Country          string
	CountryCode      string
	Geohash          string
	Location         string
	Latitude         *float64
	Longitude        *float64
	Active           bool
	ImportedLifetime bool
	FirstObservation bool
}

// ScrapeDelta is everything one successful scrape adds to the history. Values
// are deltas, never raw counter readings, so a restart of the monitored
// instance cannot rewrite the past.
type ScrapeDelta struct {
	MachineID        int64
	TargetGeneration int64
	// Revision is supplied when deriving deltas from LoadScrapeState. Explicit
	// synchronous additive deltas may omit it; generation/enable checks still apply.
	Revision       *int64
	At             time.Time
	Coverage       *ScrapeCoverage
	Opens          int64
	Closes         int64
	BytesSent      int64
	TrappedSeconds float64
	Attackers      []AttackerDelta
	// CounterStates is the raw counter reading this scrape saw, which becomes
	// the baseline the next one subtracts from. It travels with the deltas
	// because the two only mean anything together: a baseline stored without
	// its delta loses a scrape, and a delta stored without its baseline applies
	// the same scrape again on the next run and over-counts it for good.
	CounterStates map[string]float64
}

func (s *Store) LoadCounterStates(ctx context.Context, machineID int64) (map[string]float64, error) {
	rows, err := s.database.QueryContext(ctx,
		"SELECT series, value FROM counter_states WHERE machine_id = ?", machineID)
	if err != nil {
		return nil, fmt.Errorf("load counter states: %w", err)
	}
	defer rows.Close()

	states := map[string]float64{}
	for rows.Next() {
		var (
			series string
			value  float64
		)
		if err := rows.Scan(&series, &value); err != nil {
			return nil, err
		}
		states[series] = value
	}
	return states, rows.Err()
}

func saveCounterStates(ctx context.Context, transaction *sql.Tx, machineID int64, states map[string]float64, at time.Time) error {
	if len(states) == 0 {
		return nil
	}

	statement, err := transaction.PrepareContext(ctx,
		`INSERT INTO counter_states (machine_id, series, value, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(machine_id, series) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("save counter states: %w", err)
	}
	defer statement.Close()

	for series, value := range states {
		if _, err := statement.ExecContext(ctx, machineID, series, value, at.Unix()); err != nil {
			return fmt.Errorf("save counter states: %w", err)
		}
	}
	return nil
}

// ApplyScrape writes everything one scrape produced in a single transaction:
// the minute rollup, the lifetime totals, every attacker it touched, and the
// counter baseline the next scrape will measure against. All of it lands or
// none of it does, so an interrupted scrape is retried in full rather than
// applied twice.
func (s *Store) ApplyScrape(ctx context.Context, delta ScrapeDelta) error {
	var err error
	delta, err = canonicalizeDelta(delta)
	if err != nil {
		return err
	}
	if err := validateScrapeNumbers(delta); err != nil {
		return err
	}
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()

	// Claim the generation/revision inside the same transaction as all history.
	comparison := "<="
	if delta.Revision != nil {
		comparison = "<"
	}
	query := `UPDATE machines SET scrape_revision=scrape_revision+1,last_metric_sample_ns=?
 WHERE id=? AND target_generation=? AND enabled=1
 AND (last_metric_sample_ns IS NULL OR last_metric_sample_ns` + comparison + `?)
 AND (last_status_sample_ns IS NULL OR last_status_sample_ns<=?)`
	args := []any{delta.At.UnixNano(), delta.MachineID, delta.TargetGeneration, delta.At.UnixNano(), delta.At.UnixNano()}
	if delta.Revision != nil {
		query += " AND scrape_revision=?"
		args = append(args, *delta.Revision)
	}
	result, err := transaction.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if err = requireOneRow(result, ErrObsoleteScrape); err != nil {
		return err
	}
	bucket := delta.At.Unix() / rollupBucketSeconds * rollupBucketSeconds
	hasAggregateChange := delta.Opens != 0 || delta.Closes != 0 || delta.BytesSent != 0 || delta.TrappedSeconds != 0

	if hasAggregateChange {
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO machine_rollups (machine_id, bucket, opens, closes, bytes_sent, trapped_seconds)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(machine_id, bucket) DO UPDATE SET
				opens = opens + excluded.opens,
				closes = closes + excluded.closes,
				bytes_sent = bytes_sent + excluded.bytes_sent,
				trapped_seconds = trapped_seconds + excluded.trapped_seconds`,
			delta.MachineID, bucket, delta.Opens, delta.Closes, delta.BytesSent, delta.TrappedSeconds); err != nil {
			return fmt.Errorf("write rollup: %w", err)
		}

		// Insert-on-conflict rather than a bare UPDATE: an UPDATE that matches
		// no row is not an error in SQLite, it is a silent no-op, so a machine
		// whose totals row went missing — created before this was written in one
		// transaction, or restored from a database old enough to predate the row
		// — would report zero lifetime figures for ever and never say why. This
		// way the next scrape with traffic in it puts the row back.
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO machine_totals (machine_id, opens, closes, bytes_sent, trapped_seconds)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(machine_id) DO UPDATE SET
				opens = opens + excluded.opens,
				closes = closes + excluded.closes,
				bytes_sent = bytes_sent + excluded.bytes_sent,
				trapped_seconds = trapped_seconds + excluded.trapped_seconds`,
			delta.MachineID, delta.Opens, delta.Closes, delta.BytesSent, delta.TrappedSeconds); err != nil {
			return fmt.Errorf("write totals: %w", err)
		}
	}

	for _, attacker := range delta.Attackers {
		if err := upsertAttacker(ctx, transaction, delta.MachineID, delta.At, attacker, delta.Revision != nil); err != nil {
			return err
		}
	}

	// SQLite promotes overflowing INTEGER additions to REAL. Read back affected
	// rows before commit so a promotion, non-finite sum or poisoned old value
	// rolls back the complete scrape, including every attacker and baseline.
	if hasAggregateChange {
		if err := validateStoredNumbers(transaction.QueryRowContext(ctx, "SELECT opens, closes, bytes_sent, trapped_seconds FROM machine_totals WHERE machine_id = ?", delta.MachineID), 3); err != nil {
			return err
		}
		if err := validateStoredNumbers(transaction.QueryRowContext(ctx, "SELECT opens, closes, bytes_sent, trapped_seconds FROM machine_rollups WHERE machine_id = ? AND bucket = ?", delta.MachineID, bucket), 3); err != nil {
			return err
		}
	}
	for _, attacker := range delta.Attackers {
		if err := validateStoredNumbers(transaction.QueryRowContext(ctx, "SELECT connections, trapped_seconds FROM attackers WHERE machine_id = ? AND ip_address = ?", delta.MachineID, attacker.IPAddress), 1, true); err != nil {
			return err
		}
	}
	if err := saveCounterStates(ctx, transaction, delta.MachineID, delta.CounterStates, delta.At); err != nil {
		return err
	}
	if delta.Coverage != nil {
		if err := saveScrapeCoverage(ctx, transaction, delta); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// transactionExecer is satisfied by *sql.Tx; it keeps the attacker upsert
// testable without reaching for the concrete transaction type.
type transactionExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func upsertAttacker(ctx context.Context, transaction transactionExecer, machineID int64, at time.Time, attacker AttackerDelta, collected bool) error {
	measured := attacker.Active || (!collected && (attacker.Connections > 0 || attacker.TrappedSeconds > 0))
	undated := attacker.ImportedLifetime
	firstKnown := !collected || attacker.FirstObservation
	activityAt := at.Unix()
	if !attacker.Active {
		activityAt = 0
	}

	// Every geography column keeps what it already knows unless the scrape
	// carried something: a tarpit that has GeoIP switched off publishes empty
	// labels, and one such scrape must not erase a location an earlier scrape,
	// the local database or the online provider had already established.
	result, err := transaction.ExecContext(ctx,
		`UPDATE attackers SET
			last_seen = ?, last_observed_at=?,
 last_measured_activity_at=CASE WHEN ? THEN MAX(COALESCE(last_measured_activity_at,0),?) ELSE last_measured_activity_at END,
 has_undated_history=MAX(has_undated_history,?),
			last_activity_at = MAX(last_activity_at, ?),
			connections = connections + ?,
			trapped_seconds = trapped_seconds + ?,
			country = CASE WHEN ? <> '' THEN ? ELSE country END,
			country_code = CASE WHEN ? <> '' THEN ? ELSE country_code END,
			geohash = CASE WHEN ? <> '' THEN ? ELSE geohash END,
			location = CASE WHEN ? <> '' THEN ? ELSE location END,
			latitude = CASE WHEN ? IS NOT NULL THEN ? ELSE latitude END,
			longitude = CASE WHEN ? IS NOT NULL THEN ? ELSE longitude END
		 WHERE machine_id = ? AND ip_address = ?`,
		at.Unix(), at.Unix(), measured, at.Unix(), undated, activityAt,
		attacker.Connections, attacker.TrappedSeconds,
		attacker.Country, attacker.Country,
		attacker.CountryCode, attacker.CountryCode,
		attacker.Geohash, attacker.Geohash,
		attacker.Location, attacker.Location,
		attacker.Latitude, attacker.Latitude,
		attacker.Longitude, attacker.Longitude,
		machineID, attacker.IPAddress)
	if err != nil {
		return fmt.Errorf("update attacker: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	// Retained baselines may still observe an expired IP. An unchanged or
	// baseline-only reading must not recreate its aggregate row.
	if collected && !measured && !undated {
		return nil
	}
	var measuredAt any
	if measured {
		measuredAt = at.Unix()
	}
	if _, err := transaction.ExecContext(ctx,
		`INSERT INTO attackers
			(machine_id, ip_address, first_seen, last_seen, last_activity_at,
			 connections, trapped_seconds, country, country_code, geohash, location,
			 latitude, longitude,last_observed_at,last_measured_activity_at,has_undated_history,first_observation_known)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?)`,
		machineID, attacker.IPAddress, at.Unix(), at.Unix(), activityAt,
		attacker.Connections, attacker.TrappedSeconds,
		attacker.Country, attacker.CountryCode, attacker.Geohash, attacker.Location,
		attacker.Latitude, attacker.Longitude, at.Unix(), measuredAt, undated, firstKnown); err != nil {
		return fmt.Errorf("insert attacker: %w", err)
	}
	return nil
}

func validateScrapeNumbers(delta ScrapeDelta) error {
	for _, v := range []int64{delta.Opens, delta.Closes, delta.BytesSent} {
		if _, err := metricvalue.AddInt(0, v); err != nil {
			return err
		}
	}
	if err := metricvalue.Validate(delta.TrappedSeconds, false); err != nil {
		return err
	}
	for _, v := range delta.CounterStates {
		if err := metricvalue.Validate(v, false); err != nil {
			return err
		}
	}
	for _, attacker := range delta.Attackers {
		if _, err := metricvalue.AddInt(0, attacker.Connections); err != nil {
			return err
		}
		if err := metricvalue.Validate(attacker.TrappedSeconds, false); err != nil {
			return err
		}
	}
	return nil
}

func validateStoredNumbers(row *sql.Row, integers int, allowMissing ...bool) error {
	counts := make([]int64, integers)
	var seconds float64
	fields := make([]any, integers+1)
	for i := range counts {
		fields[i] = &counts[i]
	}
	fields[integers] = &seconds
	if err := row.Scan(fields...); err != nil {
		if len(allowMissing) > 0 && allowMissing[0] && errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("stored counter overflow or invalid history: %w", err)
	}
	for _, v := range counts {
		if _, err := metricvalue.AddInt(0, v); err != nil {
			return err
		}
	}
	return metricvalue.Validate(seconds, false)
}

// ClientCounterPolicy is durable provenance for previously unseen raw series.
func (s *Store) ClientCounterPolicy(ctx context.Context, machineID int64) (string, error) {
	var policy string
	err := s.database.QueryRowContext(ctx, "SELECT client_counter_policy FROM machines WHERE id = ?", machineID).Scan(&policy)
	return policy, err
}

// Copy before normalizing so rejected input cannot rewrite the caller's data.
func canonicalizeDelta(delta ScrapeDelta) (ScrapeDelta, error) {
	attackers := make([]AttackerDelta, len(delta.Attackers))
	seen := map[string]bool{}
	for i, attacker := range delta.Attackers {
		ip, err := ipidentity.Canonical(attacker.IPAddress)
		if err != nil {
			return ScrapeDelta{}, err
		}
		if seen[ip] {
			return ScrapeDelta{}, fmt.Errorf("duplicate canonical attacker delta")
		}
		seen[ip] = true
		attacker.IPAddress = ip
		attackers[i] = attacker
	}
	states := make(map[string]float64, len(delta.CounterStates))
	for key, value := range delta.CounterStates {
		if strings.HasPrefix(key, "ip:v2:") {
			normalized, _, err := ipidentity.NormalizeRawKey(key)
			if err != nil {
				return ScrapeDelta{}, err
			}
			key = normalized
		}
		if old, ok := states[key]; ok && old != value {
			return ScrapeDelta{}, fmt.Errorf("conflicting canonical raw baselines")
		}
		states[key] = value
	}
	delta.Attackers = attackers
	delta.CounterStates = states
	return delta, nil
}
