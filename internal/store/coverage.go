package store

import (
	"context"
	"database/sql"
	"time"
)

// ScrapeCoverage describes observation continuity, independently of counter values.
// Complete means stable aggregate series observed at the configured cadence,
// not exact event times or proof that an exporter had no hidden reset.
type ScrapeCoverage struct {
	Interval      time.Duration
	From          *time.Time
	Complete      bool
	UncertainFrom *time.Time
}

func saveScrapeCoverage(ctx context.Context, tx *sql.Tx, delta ScrapeDelta) error {
	at := delta.At
	c := *delta.Coverage
	// A failure may commit after the collector read its baseline. Recheck under
	// the transaction's writer claim before asserting continuous observation.
	if c.Complete {
		var failures int
		if err := tx.QueryRowContext(ctx, "SELECT consecutive_failures FROM machines WHERE id=?", delta.MachineID).Scan(&failures); err != nil {
			return err
		}
		if failures > 0 {
			c.Complete = false
			if delta.Opens != 0 || delta.Closes != 0 || delta.BytesSent != 0 || delta.TrappedSeconds != 0 {
				c.UncertainFrom = c.From
			}
		}
	}
	bucket := at.Unix() / 60 * 60
	var uncertainFrom, uncertainTo any
	if c.UncertainFrom != nil {
		uncertainFrom = c.UncertainFrom.Unix()
		uncertainTo = at.Unix()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scrape_coverage(machine_id,bucket,attempts,successes,uncertain_from,uncertain_to) VALUES(?,?,1,1,?,?)
 ON CONFLICT(machine_id,bucket) DO UPDATE SET attempts=attempts+1,successes=successes+1,
 uncertain_from=CASE WHEN excluded.uncertain_from IS NULL THEN uncertain_from WHEN uncertain_from IS NULL THEN excluded.uncertain_from ELSE MIN(uncertain_from,excluded.uncertain_from) END,
 uncertain_to=CASE WHEN excluded.uncertain_to IS NULL THEN uncertain_to WHEN uncertain_to IS NULL THEN excluded.uncertain_to ELSE MAX(uncertain_to,excluded.uncertain_to) END`, delta.MachineID, bucket, uncertainFrom, uncertainTo); err != nil {
		return err
	}
	// Only short, continuous, validated observation intervals may add coverage.
	// This loop is bounded by the configured cadence, never an outage's duration.
	if c.Complete && c.From != nil && c.From.Before(at) && at.Sub(*c.From) <= time.Hour {
		for start := *c.From; start.Before(at); {
			b := start.Unix() / 60 * 60
			end := time.Unix(b+60, 0).UTC()
			if end.After(at) {
				end = at
			}
			seconds := end.Sub(start).Seconds()
			if _, err := tx.ExecContext(ctx, `INSERT INTO scrape_coverage(machine_id,bucket,covered_seconds) VALUES(?,?,?) ON CONFLICT(machine_id,bucket) DO UPDATE SET covered_seconds=MIN(60,covered_seconds+excluded.covered_seconds)`, delta.MachineID, b, seconds); err != nil {
				return err
			}
			start = end
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO scrape_coverage_state(machine_id,generation,sample_ns,cadence_ns) VALUES(?,?,?,?) ON CONFLICT(machine_id) DO UPDATE SET generation=excluded.generation,sample_ns=excluded.sample_ns,cadence_ns=excluded.cadence_ns`, delta.MachineID, delta.TargetGeneration, at.UnixNano(), int64(c.Interval))
	return err
}

// RecentCoverageByMachine matches the sidebar's twelve five-minute bins. All
// machines are grouped once; this is independent of lifetime/attacker cardinality.
func (s *Store) RecentCoverageByMachine(ctx context.Context, now time.Time, width, count int) (map[int64][]string, error) {
	newest := now.Unix() / int64(width) * int64(width)
	oldest := newest - int64(width*(count-1))
	rows, err := s.database.QueryContext(ctx, `SELECT machine_id,bucket / ? * ?,SUM(covered_seconds),SUM(attempts),MIN(uncertain_from) FROM scrape_coverage WHERE bucket>=? AND bucket<? GROUP BY machine_id,bucket / ?`, width, width, oldest, newest+int64(width), width)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[int64][]string{}
	for rows.Next() {
		var id, b, attempts int64
		var seconds float64
		var uncertain sql.NullInt64
		if err = rows.Scan(&id, &b, &seconds, &attempts, &uncertain); err != nil {
			return nil, err
		}
		if result[id] == nil {
			result[id] = make([]string, count)
			for i := range result[id] {
				result[id][i] = "unknown"
			}
		}
		status := "unknown"
		if attempts > 0 || seconds > 0 {
			status = "incomplete"
		}
		if seconds+0.000001 >= float64(width) && !uncertain.Valid {
			status = "complete"
		}
		result[id][(b-oldest)/int64(width)] = status
	}
	return result, rows.Err()
}
