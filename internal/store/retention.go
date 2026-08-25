package store

import (
	"context"
	"fmt"
	"time"
)

// Series keys are prefixed so retention can tell the handful of permanent
// aggregate counters apart from the per-client series that churn constantly.
const (
	SeriesPrefixTotal  = "total:"
	SeriesPrefixClient = "ip:"
)

type PruneStats struct {
	Rollups       int64
	Attackers     int64
	CounterStates int64
	Sessions      int64
	PagesFreed    int64
}

// Prune drops history older than the cutoff and hands the freed pages back to
// the filesystem. Lifetime totals in machine_totals are deliberately untouched.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (PruneStats, error) {
	stats := PruneStats{}
	cutoffUnix := cutoff.Unix()

	pagesBefore, err := s.pageCount(ctx)
	if err != nil {
		return stats, err
	}

	deletions := []struct {
		target string
		query  string
		args   []any
		count  *int64
	}{
		{"rollups", "DELETE FROM machine_rollups WHERE bucket < ?", []any{cutoffUnix}, &stats.Rollups},
		{"attackers", "DELETE FROM attackers WHERE last_seen < ?", []any{cutoffUnix}, &stats.Attackers},
		{
			"counter states",
			"DELETE FROM counter_states WHERE updated_at < ? AND series LIKE ?",
			[]any{cutoffUnix, SeriesPrefixClient + "%"},
			&stats.CounterStates,
		},
		{"sessions", "DELETE FROM sessions WHERE expires_at <= ?", []any{time.Now().Unix()}, &stats.Sessions},
	}

	for _, deletion := range deletions {
		result, err := s.database.ExecContext(ctx, deletion.query, deletion.args...)
		if err != nil {
			return stats, fmt.Errorf("prune %s: %w", deletion.target, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("prune %s: %w", deletion.target, err)
		}
		*deletion.count = affected
	}

	if _, err := s.database.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return stats, fmt.Errorf("incremental vacuum: %w", err)
	}

	pagesAfter, err := s.pageCount(ctx)
	if err != nil {
		return stats, err
	}
	stats.PagesFreed = pagesBefore - pagesAfter
	return stats, nil
}

func (s *Store) pageCount(ctx context.Context) (int64, error) {
	var pages int64
	if err := s.database.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return 0, fmt.Errorf("read page count: %w", err)
	}
	return pages, nil
}
