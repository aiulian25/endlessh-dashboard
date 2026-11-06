// Package maintenance runs the housekeeping the app owes itself: pruning
// history so the database cannot grow without bound, clearing expired
// sessions, and taking the optional daily backup.
package maintenance

import (
	"context"
	"log/slog"
	"time"

	"endlessh-dashboard/internal/auth"
	"endlessh-dashboard/internal/store"
)

const (
	tickInterval = time.Hour
	dailyPeriod  = 24 * time.Hour
	hoursPerDay  = 24
)

type Worker struct {
	store         *store.Store
	auth          *auth.Service
	backups       *store.BackupManager
	logger        *slog.Logger
	retentionDays int
	dailyBackup   bool
	lastPrune     time.Time
	lastBackup    time.Time
}

func NewWorker(
	dataStore *store.Store,
	authService *auth.Service,
	backupManager *store.BackupManager,
	logger *slog.Logger,
	retentionDays int,
	dailyBackup bool,
) *Worker {
	return &Worker{
		store:         dataStore,
		auth:          authService,
		backups:       backupManager,
		logger:        logger,
		retentionDays: retentionDays,
		dailyBackup:   dailyBackup,
	}
}

func (w *Worker) Run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	w.seedLastBackup()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	w.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// seedLastBackup carries the daily schedule across a restart. lastBackup lives
// in memory, so without this every start looks like one where no backup has ever
// been taken and writes one immediately — and because each new backup rotates an
// old one out under BACKUP_KEEP_LAST, a few restarts in an afternoon replace the
// daily history the setting exists to keep.
//
// The backups on disk are the record. Their names carry the time they were taken,
// which is what List reads CreatedAt from.
func (w *Worker) seedLastBackup() {
	if !w.dailyBackup {
		return
	}
	backups, err := w.backups.List()
	if err != nil {
		// Starting the schedule from nothing is what this replaces, not a new
		// failure, so it is worth a line in the log and nothing more.
		w.logger.Error("read the backup directory to resume the daily schedule", "error", err)
		return
	}

	// Taken as a maximum rather than as the first entry: List happens to return
	// newest first today, and this does not need to depend on that.
	newest := time.Time{}
	for _, backup := range backups {
		if backup.CreatedAt.After(newest) {
			newest = backup.CreatedAt
		}
	}
	if newest.IsZero() {
		return
	}
	w.lastBackup = newest
	w.logger.Debug("resumed the daily backup schedule", "last_backup_at", newest)
}

func (w *Worker) runOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if removed, err := w.auth.PurgeExpiredSessions(ctx); err != nil {
		w.logger.Error("purge expired sessions", "error", err)
	} else if removed > 0 {
		w.logger.Debug("purged expired sessions", "count", removed)
	}

	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	if now.Sub(w.lastPrune) >= dailyPeriod {
		w.prune(ctx, now)
	}
	if ctx.Err() != nil {
		return
	}
	if w.dailyBackup && now.Sub(w.lastBackup) >= dailyPeriod {
		w.backup(ctx, now)
	}
}

func (w *Worker) prune(ctx context.Context, now time.Time) {
	if ctx.Err() != nil {
		return
	}
	cutoff := now.Add(-time.Duration(w.retentionDays) * hoursPerDay * time.Hour)
	stats, err := w.store.Prune(ctx, cutoff)
	if err != nil {
		w.logger.Error("prune history", "error", err)
		return
	}
	w.lastPrune = now
	w.logger.Info("pruned history older than the retention window",
		"retention_days", w.retentionDays,
		"rollups", stats.Rollups,
		"coverage_minutes", stats.Coverage,
		"attackers", stats.Attackers,
		"counter_states", stats.CounterStates,
		"pages_freed", stats.PagesFreed,
	)
}

func (w *Worker) backup(ctx context.Context, now time.Time) {
	if ctx.Err() != nil {
		return
	}
	backup, err := w.backups.Create(ctx)
	if err != nil {
		w.logger.Error("daily backup", "error", err)
		return
	}
	w.lastBackup = now
	w.logger.Info("daily backup written", "name", backup.Name, "size_bytes", backup.Size)
}
