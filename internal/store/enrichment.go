package store

import (
	"context"
	"fmt"
	"time"

	"endlessh-dashboard/internal/ipidentity"
)

// EnrichmentCandidate is selected once per canonical IP, across all machines.
type EnrichmentCandidate struct {
	MissingLocation
	Failures int
}

const enrichmentDueQuery = `SELECT MIN(a.machine_id), a.ip_address,
 CASE WHEN e.source_generation=? THEN e.failures ELSE 0 END
 FROM attackers a LEFT JOIN enrichment_progress e ON e.ip_address=a.ip_address
 WHERE (a.location='' OR a.country_code='')
 AND (e.ip_address IS NULL OR e.outcome='resolved' OR e.source_generation<>? OR (e.next_attempt_at IS NOT NULL AND e.next_attempt_at<=?))
 GROUP BY a.ip_address
 ORDER BY CASE WHEN e.source_generation=? THEN e.last_attempt_at ELSE 0 END ASC,MAX(a.last_seen) DESC,a.ip_address
 LIMIT ?`

func (s *Store) EnrichmentDue(ctx context.Context, generation string, now time.Time, limit int) ([]EnrichmentCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.database.QueryContext(ctx, enrichmentDueQuery, generation, generation, now.Unix(), generation, limit)
	if err != nil {
		return nil, fmt.Errorf("select enrichment work: %w", err)
	}
	defer rows.Close()
	var result []EnrichmentCandidate
	for rows.Next() {
		var entry EnrichmentCandidate
		if err = rows.Scan(&entry.MachineID, &entry.IPAddress, &entry.Failures); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

type EnrichmentResult struct {
	IPAddress   string
	Generation  string
	At          time.Time
	NextAttempt *time.Time
	Failures    int
	Outcome     string
	Location    *AttackerLocation
}

// FinishEnrichment publishes nonempty location fields and retry progress in one
// transaction. Do not retain state for an IP whose final attacker copy expired.
func (s *Store) FinishEnrichment(ctx context.Context, result EnrichmentResult) error {
	ip, err := ipidentity.Canonical(result.IPAddress)
	if err != nil {
		return err
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Acquire the writer before checking membership; deletion cannot race a new orphan.
	if _, err = tx.ExecContext(ctx, "DELETE FROM enrichment_progress WHERE ip_address=? AND NOT EXISTS(SELECT 1 FROM attackers WHERE ip_address=?)", ip, ip); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM attackers WHERE ip_address=?)", ip).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return tx.Commit()
	}
	if result.Location != nil {
		if err = setAttackerLocation(ctx, tx, ip, *result.Location); err != nil {
			return err
		}
		var missing bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM attackers WHERE ip_address=? AND (location='' OR country_code=''))", ip).Scan(&missing); err != nil {
			return err
		}
		if missing {
			result.Outcome = "partial"
		} else {
			result.Outcome = "resolved"
			result.NextAttempt = nil
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO enrichment_progress(ip_address,source_generation,last_attempt_at,next_attempt_at,failures,outcome) VALUES(?,?,?,?,?,?)
 ON CONFLICT(ip_address) DO UPDATE SET source_generation=excluded.source_generation,last_attempt_at=excluded.last_attempt_at,next_attempt_at=excluded.next_attempt_at,failures=excluded.failures,outcome=excluded.outcome`, ip, result.Generation, result.At.Unix(), unixOrNil(result.NextAttempt), min(16, max(0, result.Failures)), result.Outcome)
	if err != nil {
		return err
	}
	return tx.Commit()
}
