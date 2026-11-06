package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"time"

	"endlessh-dashboard/internal/metricvalue"
)

const MaxScrapePorts = 128
const UnknownPort = "unknown"

// Missing exporter labels are kept as an explicit unlabelled group, never
// assigned to an invented port. Numeric labels must be canonical TCP ports.
func PortFromLabel(label string) (string, error) {
	if label == "" {
		return UnknownPort, nil
	}
	n, err := strconv.Atoi(label)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != label {
		return "", fmt.Errorf("local_port must be a canonical port in 1..65535 or absent")
	}
	return label, nil
}
func ValidatePort(port string) error {
	if port == UnknownPort {
		return nil
	}
	if port == "" {
		return fmt.Errorf("port must not be empty")
	}
	_, err := PortFromLabel(port)
	return err
}

type PortDelta struct {
	Port                     string
	Opens, Closes, BytesSent int64
	TrappedSeconds           float64
	Coverage                 *ScrapeCoverage
}

func validatePorts(d ScrapeDelta) error {
	if d.Ports == nil {
		return nil
	} // Older synchronous callers do not invent port data.
	if len(d.Ports) > MaxScrapePorts {
		return fmt.Errorf("too many local ports (maximum %d)", MaxScrapePorts)
	}
	seen := map[string]bool{}
	var opens, closes, bytes int64
	var seconds float64
	for _, p := range d.Ports {
		if err := ValidatePort(p.Port); err != nil {
			return err
		}
		if seen[p.Port] {
			return fmt.Errorf("duplicate port delta")
		}
		seen[p.Port] = true
		for _, n := range []int64{p.Opens, p.Closes, p.BytesSent} {
			if err := metricvalue.Validate(float64(n), true); err != nil {
				return err
			}
		}
		if err := metricvalue.Validate(p.TrappedSeconds, false); err != nil {
			return err
		}
		var err error
		if opens, err = metricvalue.AddInt(opens, p.Opens); err != nil {
			return err
		}
		if closes, err = metricvalue.AddInt(closes, p.Closes); err != nil {
			return err
		}
		if bytes, err = metricvalue.AddInt(bytes, p.BytesSent); err != nil {
			return err
		}
		if seconds, err = metricvalue.AddFloat(seconds, p.TrappedSeconds); err != nil {
			return err
		}
	}
	if opens != d.Opens || closes != d.Closes || bytes != d.BytesSent || math.Abs(seconds-d.TrappedSeconds) > 1e-9*math.Max(1, math.Abs(seconds)) {
		return fmt.Errorf("port deltas do not sum to machine delta")
	}
	return nil
}

func savePortRollups(ctx context.Context, tx *sql.Tx, d ScrapeDelta) error {
	if d.Ports == nil {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO port_collection(machine_id,generation,started_at_ns) VALUES(?,?,?) ON CONFLICT DO NOTHING`, d.MachineID, d.TargetGeneration, d.At.UnixNano()); err != nil {
		return err
	}
	var failures int
	if err := tx.QueryRowContext(ctx, `SELECT consecutive_failures FROM machines WHERE id=?`, d.MachineID).Scan(&failures); err != nil {
		return err
	}
	bucket := d.At.Unix() / 60 * 60
	for _, p := range d.Ports {
		var lo, hi any
		if p.Coverage != nil && p.Coverage.UncertainFrom != nil {
			lo = p.Coverage.UncertainFrom.Unix()
			hi = d.At.Unix()
		}
		if failures > 0 && p.Coverage != nil && p.Coverage.From != nil {
			lo = p.Coverage.From.Unix()
			hi = d.At.Unix()
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO port_rollups(machine_id,generation,port,bucket,opens,closes,bytes_sent,trapped_seconds,attempts,successes,uncertain_from,uncertain_to)
 VALUES(?,?,?,?,?,?,?,?,1,1,?,?) ON CONFLICT(machine_id,generation,port,bucket) DO UPDATE SET
 opens=opens+excluded.opens,closes=closes+excluded.closes,bytes_sent=bytes_sent+excluded.bytes_sent,trapped_seconds=trapped_seconds+excluded.trapped_seconds,attempts=attempts+1,successes=successes+1,
 uncertain_from=CASE WHEN excluded.uncertain_from IS NULL THEN uncertain_from WHEN uncertain_from IS NULL THEN excluded.uncertain_from ELSE MIN(uncertain_from,excluded.uncertain_from) END,
 uncertain_to=CASE WHEN excluded.uncertain_to IS NULL THEN uncertain_to WHEN uncertain_to IS NULL THEN excluded.uncertain_to ELSE MAX(uncertain_to,excluded.uncertain_to) END`, d.MachineID, d.TargetGeneration, p.Port, bucket, p.Opens, p.Closes, p.BytesSent, p.TrappedSeconds, lo, hi)
		if err != nil {
			return err
		}
		if err = validateStoredNumbers(tx.QueryRowContext(ctx, `SELECT opens,closes,bytes_sent,trapped_seconds FROM port_rollups WHERE machine_id=? AND generation=? AND port=? AND bucket=?`, d.MachineID, d.TargetGeneration, p.Port, bucket), 3); err != nil {
			return err
		}
		c := p.Coverage
		if c == nil || !c.Complete || failures > 0 || c.From == nil || !c.From.Before(d.At) || d.At.Sub(*c.From) > time.Hour {
			continue
		}
		for start := *c.From; start.Before(d.At); {
			b := start.Unix() / 60 * 60
			end := time.Unix(b+60, 0).UTC()
			if end.After(d.At) {
				end = d.At
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO port_rollups(machine_id,generation,port,bucket,covered_seconds) VALUES(?,?,?,?,?) ON CONFLICT(machine_id,generation,port,bucket) DO UPDATE SET covered_seconds=MIN(60,covered_seconds+excluded.covered_seconds)`, d.MachineID, d.TargetGeneration, p.Port, b, end.Sub(start).Seconds())
			if err != nil {
				return err
			}
			start = end
		}
	}
	return nil
}

type PortSummary struct {
	Port            string  `json:"port"`
	Opens           int64   `json:"opens"`
	Closes          int64   `json:"closes"`
	BytesSent       int64   `json:"bytes_sent"`
	TrappedSeconds  float64 `json:"trapped_seconds"`
	ObservedSeconds float64 `json:"observed_seconds"`
	Samples         int64   `json:"samples"`
	Generations     int     `json:"generations"`
}
type PortSummaryResponse struct {
	From                time.Time     `json:"from"`
	To                  time.Time     `json:"to"`
	CollectionStartedAt *time.Time    `json:"collection_started_at"`
	Available           bool          `json:"available"`
	Rows                []PortSummary `json:"rows"`
}

func (s *Store) PortSummary(ctx context.Context, ids []int64, from, to time.Time, port string) (PortSummaryResponse, error) {
	span := NewTimeRange(from, to)
	result := PortSummaryResponse{From: span.From, To: span.To, Rows: []PortSummary{}}
	if len(ids) == 0 {
		return result, nil
	}
	if port != "" {
		if err := ValidatePort(port); err != nil {
			return result, err
		}
	}
	tx, err := s.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var started sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT MIN(started_at_ns) FROM port_collection WHERE machine_id IN (`+placeholders(len(ids))+`)`, int64Args(ids)...).Scan(&started); err != nil {
		return result, err
	}
	if started.Valid {
		at := time.Unix(0, started.Int64).UTC()
		result.CollectionStartedAt = &at
	}
	args := append(int64Args(ids), span.From.Unix(), span.To.Unix())
	where := ""
	if port != "" {
		where = " AND port=?"
		args = append(args, port)
	}
	rows, err := tx.QueryContext(ctx, `SELECT port,SUM(opens),SUM(closes),SUM(bytes_sent),SUM(trapped_seconds),SUM(covered_seconds),SUM(successes),COUNT(DISTINCT CAST(machine_id AS TEXT)||':'||generation) FROM port_rollups WHERE machine_id IN (`+placeholders(len(ids))+`) AND bucket>=? AND bucket<?`+where+` GROUP BY port ORDER BY CASE WHEN port='unknown' THEN 65536 ELSE CAST(port AS INTEGER) END`, args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var p PortSummary
		if err = rows.Scan(&p.Port, &p.Opens, &p.Closes, &p.BytesSent, &p.TrappedSeconds, &p.ObservedSeconds, &p.Samples, &p.Generations); err != nil {
			break
		}
		result.Rows = append(result.Rows, p)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return result, err
	}
	result.Available = len(result.Rows) > 0
	return result, tx.Commit()
}
