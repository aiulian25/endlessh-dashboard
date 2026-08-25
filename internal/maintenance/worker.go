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

func (w *Worker) runOnce(ctx context.Context) {
	if removed, err := w.auth.PurgeExpiredSessions(ctx); err != nil {
		w.logger.Error("purge expired sessions", "error", err)
	} else if removed > 0 {
		w.logger.Debug("purged expired sessions", "count", removed)
	}

	now := time.Now().UTC()
	if now.Sub(w.lastPrune) >= dailyPeriod {
		w.prune(ctx, now)
	}
	if w.dailyBackup && now.Sub(w.lastBackup) >= dailyPeriod {
		w.backup(ctx, now)
	}
}

func (w *Worker) prune(ctx context.Context, now time.Time) {
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
		"attackers", stats.Attackers,
		"counter_states", stats.CounterStates,
		"pages_freed", stats.PagesFreed,
	)
}

func (w *Worker) backup(ctx context.Context, now time.Time) {
	backup, err := w.backups.Create(ctx)
	if err != nil {
		w.logger.Error("daily backup", "error", err)
		return
	}
	w.lastBackup = now
	w.logger.Info("daily backup written", "name", backup.Name, "size_bytes", backup.Size)
}
