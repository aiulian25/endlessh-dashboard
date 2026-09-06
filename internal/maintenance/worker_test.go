package maintenance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"endlessh-dashboard/internal/auth"
	"endlessh-dashboard/internal/store"
)

// backupNameLayout mirrors the unexported layout in internal/store: a backup
// carries the time it was taken in its own name, and that is where the worker
// reads it back from. It is restated here rather than reached into.
const backupNameLayout = "20060102-150405"

const (
	testRetentionDays  = 90
	testBackupKeepLast = 7
	testSessionLife    = 12 * time.Hour
)

func newTestWorker(t *testing.T, dailyBackup bool) (*Worker, *store.BackupManager, string) {
	t.Helper()

	directory := t.TempDir()
	databasePath := filepath.Join(directory, "endlessh.db")
	dataStore, err := store.Open(databasePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	backupDirectory := filepath.Join(directory, "backups")
	manager := store.NewBackupManager(dataStore, backupDirectory, databasePath, testBackupKeepLast)
	authService := auth.NewService(dataStore, testSessionLife)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	worker := NewWorker(dataStore, authService, manager, logger, testRetentionDays, dailyBackup)
	return worker, manager, backupDirectory
}

// writeBackupTakenAt puts a real backup in the directory and renames it so its
// name says it was taken then. Ageing it matters: a backup named for this second
// would collide with any spurious one written now, and the collision would hide
// the very bug these tests are here to catch.
func writeBackupTakenAt(t *testing.T, manager *store.BackupManager, directory string, at time.Time) {
	t.Helper()

	info, err := manager.Create(context.Background())
	if err != nil {
		t.Fatalf("create the backup to age: %v", err)
	}
	aged := "endlessh-" + at.UTC().Format(backupNameLayout) + ".db"
	if err := os.Rename(filepath.Join(directory, info.Name), filepath.Join(directory, aged)); err != nil {
		t.Fatalf("age the backup: %v", err)
	}
}

func countBackups(t *testing.T, directory string) int {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	return len(entries)
}

func TestRestartDoesNotRetakeATodaysBackup(t *testing.T) {
	worker, manager, directory := newTestWorker(t, true)
	writeBackupTakenAt(t, manager, directory, time.Now().UTC().Add(-time.Hour))

	// A restart an hour later. The schedule is daily, so this pass owes nothing:
	// before the worker read the directory, every start believed no backup had
	// ever been taken and wrote one, rotating a real day out of the history.
	worker.seedLastBackup()
	worker.runOnce(context.Background())

	if got := countBackups(t, directory); got != 1 {
		t.Errorf("backups after a restart = %d, want the one already there", got)
	}
}

func TestBackupIsTakenWhenThereIsNone(t *testing.T) {
	worker, _, directory := newTestWorker(t, true)

	worker.seedLastBackup()
	worker.runOnce(context.Background())

	if got := countBackups(t, directory); got != 1 {
		t.Errorf("backups on a first start = %d, want 1", got)
	}
}

func TestBackupIsTakenWhenTheNewestIsOlderThanADay(t *testing.T) {
	worker, manager, directory := newTestWorker(t, true)
	writeBackupTakenAt(t, manager, directory, time.Now().UTC().Add(-25*time.Hour))

	// Resuming the schedule must not become a way of never taking one again.
	worker.seedLastBackup()
	worker.runOnce(context.Background())

	if got := countBackups(t, directory); got != 2 {
		t.Errorf("backups after a day has passed = %d, want the old one and a new one", got)
	}
}

func TestNewestBackupWinsWhateverOrderTheDirectoryIsRead(t *testing.T) {
	worker, manager, directory := newTestWorker(t, true)
	now := time.Now().UTC()
	writeBackupTakenAt(t, manager, directory, now.Add(-40*time.Hour))
	writeBackupTakenAt(t, manager, directory, now.Add(-2*time.Hour))
	writeBackupTakenAt(t, manager, directory, now.Add(-30*time.Hour))

	// Two of the three are old enough to be due. Taking the newest, rather than
	// whichever the listing happens to hand back first, is what decides that
	// nothing is owed here.
	worker.seedLastBackup()
	worker.runOnce(context.Background())

	if got := countBackups(t, directory); got != 3 {
		t.Errorf("backups = %d, want the three already there and no more", got)
	}
}

func TestBackupsStayOffWhenTheSettingIsOff(t *testing.T) {
	worker, _, directory := newTestWorker(t, false)

	worker.seedLastBackup()
	worker.runOnce(context.Background())

	if got := countBackups(t, directory); got != 0 {
		t.Errorf("backups with BACKUP_DAILY off = %d, want none", got)
	}
}

func TestRunResumesTheScheduleBeforeItsFirstPass(t *testing.T) {
	worker, manager, directory := newTestWorker(t, true)
	writeBackupTakenAt(t, manager, directory, time.Now().UTC().Add(-time.Hour))

	// Through Run, which is how the app starts it: the seeding has to happen
	// before the first pass, not merely exist.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(finished)
	}()

	// A worker that had not resumed would write its backup within milliseconds,
	// so watching the directory settle is enough to tell the two apart. The next
	// scheduled pass is an hour away, well outside this window.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := countBackups(t, directory); got != 1 {
			t.Fatalf("Run took a backup that was not due: %d files, want 1", got)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
