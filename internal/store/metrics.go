package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const rollupBucketSeconds = 60

// AttackerDelta is one client's change since the previous scrape of a machine.
// The coordinate is a pair of pointers because 0,0 is a real place: only nil
// means the scrape produced no position for this client.
type AttackerDelta struct {
	IPAddress      string
	Connections    int64
	TrappedSeconds float64
	Country        string
	CountryCode    string
	Geohash        string
	Location       string
	Latitude       *float64
	Longitude      *float64
	Active         bool
}

// ScrapeDelta is everything one successful scrape adds to the history. Values
// are deltas, never raw counter readings, so a restart of the monitored
// instance cannot rewrite the past.
type ScrapeDelta struct {
	MachineID      int64
	At             time.Time
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
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()

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
		if err := upsertAttacker(ctx, transaction, delta.MachineID, delta.At, attacker); err != nil {
			return err
		}
	}

	if err := saveCounterStates(ctx, transaction, delta.MachineID, delta.CounterStates, delta.At); err != nil {
		return err
	}
	return transaction.Commit()
}

// transactionExecer is satisfied by *sql.Tx; it keeps the attacker upsert
// testable without reaching for the concrete transaction type.
type transactionExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func upsertAttacker(ctx context.Context, transaction transactionExecer, machineID int64, at time.Time, attacker AttackerDelta) error {
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
			last_seen = ?,
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
		at.Unix(), activityAt,
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

	if _, err := transaction.ExecContext(ctx,
		`INSERT INTO attackers
			(machine_id, ip_address, first_seen, last_seen, last_activity_at,
			 connections, trapped_seconds, country, country_code, geohash, location,
			 latitude, longitude)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		machineID, attacker.IPAddress, at.Unix(), at.Unix(), activityAt,
		attacker.Connections, attacker.TrappedSeconds,
		attacker.Country, attacker.CountryCode, attacker.Geohash, attacker.Location,
		attacker.Latitude, attacker.Longitude); err != nil {
		return fmt.Errorf("insert attacker: %w", err)
	}
	return nil
}
