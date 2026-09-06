package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	backupNameLayout  = "20060102-150405"
	backupNamePrefix  = "endlessh-"
	backupNameSuffix  = ".db"
	restorePendingExt = ".restore"
	// restorePreviousExt names the copy of the database a restore replaced. One
	// generation, kept beside the live file so it is inside the same volume the
	// operator already has mounted.
	restorePreviousExt = ".previous"
	backupFileMode     = 0o600
	backupDirMode      = 0o700
)

var (
	ErrBackupNotFound    = errors.New("backup not found")
	ErrInvalidBackupName = errors.New("invalid backup name")
	// ErrDatabaseTooNew marks a file this build cannot safely adopt. It is a
	// sentinel so the API can say why rather than reporting a generic failure:
	// the operator who hits this has downgraded an image, and the version
	// numbers are the whole of the explanation.
	ErrDatabaseTooNew = errors.New("database schema is newer than this build supports")
)

var backupNamePattern = regexp.MustCompile(`^endlessh-\d{8}-\d{6}\.db$`)

type BackupInfo struct {
	Name      string
	Size      int64
	CreatedAt time.Time
}

// BackupManager owns the backup directory: creating consistent snapshots,
// rotating old ones, and staging a restore for the next start.
type BackupManager struct {
	store        *Store
	directory    string
	databasePath string
	keepLast     int
	// creating serialises Create. Backup names have one-second resolution, so
	// two calls in the same second name the same file; left to race, both get
	// past the check that it does not exist yet and the loser fails on a
	// half-written snapshot rather than being handed the one that won.
	creating sync.Mutex
}

func NewBackupManager(store *Store, directory, databasePath string, keepLast int) *BackupManager {
	return &BackupManager{
		store:        store,
		directory:    directory,
		databasePath: databasePath,
		keepLast:     keepLast,
	}
}

func (m *BackupManager) EnsureDirectory() error {
	if err := os.MkdirAll(m.directory, backupDirMode); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	return nil
}

// Create writes a consistent snapshot with VACUUM INTO. A plain file copy of a
// live database can tear mid-write; VACUUM INTO takes SQLite's own snapshot.
func (m *BackupManager) Create(ctx context.Context) (BackupInfo, error) {
	m.creating.Lock()
	defer m.creating.Unlock()

	if err := m.EnsureDirectory(); err != nil {
		return BackupInfo{}, err
	}
	createdAt := time.Now().UTC()
	name := backupNamePrefix + createdAt.Format(backupNameLayout) + backupNameSuffix
	destination := filepath.Join(m.directory, name)

	// A backup asked for in the same second as the last one is that backup. The
	// name has one-second resolution, so a second click on "Back up now", or a
	// manual one landing in the same second as the worker's, would otherwise be
	// reported as a failure for a snapshot that exists and is current. Nothing
	// is rotated here: no file was added.
	if existing, err := os.Stat(destination); err == nil {
		return BackupInfo{Name: name, Size: existing.Size(), CreatedAt: createdAt}, nil
	}
	if _, err := m.store.database.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return BackupInfo{}, fmt.Errorf("create backup: %w", err)
	}
	if err := os.Chmod(destination, backupFileMode); err != nil {
		return BackupInfo{}, fmt.Errorf("secure backup file: %w", err)
	}

	info, err := os.Stat(destination)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("stat backup: %w", err)
	}
	if err := m.Rotate(); err != nil {
		return BackupInfo{}, err
	}
	return BackupInfo{Name: name, Size: info.Size(), CreatedAt: createdAt}, nil
}

func (m *BackupManager) List() ([]BackupInfo, error) {
	entries, err := os.ReadDir(m.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !backupNamePattern.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat backup %s: %w", entry.Name(), err)
		}
		backups = append(backups, BackupInfo{
			Name:      entry.Name(),
			Size:      info.Size(),
			CreatedAt: backupTimestamp(entry.Name(), info.ModTime()),
		})
	}
	sort.Slice(backups, func(first, second int) bool {
		return backups[first].Name > backups[second].Name
	})
	return backups, nil
}

func (m *BackupManager) Rotate() error {
	backups, err := m.List()
	if err != nil {
		return err
	}
	if m.keepLast <= 0 || len(backups) <= m.keepLast {
		return nil
	}
	for _, stale := range backups[m.keepLast:] {
		if err := os.Remove(filepath.Join(m.directory, stale.Name)); err != nil {
			return fmt.Errorf("rotate backups: %w", err)
		}
	}
	return nil
}

func (m *BackupManager) Path(name string) (string, error) {
	if !backupNamePattern.MatchString(name) {
		return "", ErrInvalidBackupName
	}
	path := filepath.Join(m.directory, name)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", ErrBackupNotFound
	} else if err != nil {
		return "", fmt.Errorf("stat backup: %w", err)
	}
	return path, nil
}

func (m *BackupManager) Delete(name string) error {
	path, err := m.Path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete backup: %w", err)
	}
	return nil
}

// StageRestore verifies the chosen backup and parks it beside the live
// database. ApplyPendingRestore swaps it in at the next start, when nothing
// holds the file open.
func (m *BackupManager) StageRestore(name string) error {
	source, err := m.Path(name)
	if err != nil {
		return err
	}
	if err := VerifyDatabaseFile(source); err != nil {
		return err
	}
	return copyFile(source, m.databasePath+restorePendingExt)
}

// StageRestoreFromReader accepts an uploaded database file, verifying it before
// it is allowed anywhere near the live data.
func (m *BackupManager) StageRestoreFromReader(reader io.Reader) error {
	if err := m.EnsureDirectory(); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(m.directory, "upload-*.db")
	if err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		os.Remove(temporaryPath)
		// Verification opens the upload, and a WAL-mode database gets a -shm
		// written beside it — which an uploaded endlessh.db.previous always is.
		removeSidecars(temporaryPath)
	}()

	if _, err := io.Copy(temporary, reader); err != nil {
		temporary.Close()
		return fmt.Errorf("stage upload: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	if err := VerifyDatabaseFile(temporaryPath); err != nil {
		return err
	}
	return copyFile(temporaryPath, m.databasePath+restorePendingExt)
}

// ApplyPendingRestore swaps in a staged restore. It runs before the database is
// opened, so the live file is never replaced underneath an open connection.
func ApplyPendingRestore(databasePath string) (bool, error) {
	pending := databasePath + restorePendingExt
	if _, err := os.Stat(pending); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("check pending restore: %w", err)
	}

	// A staged file that no longer verifies is moved aside rather than left in
	// place: blocking every future start on it would turn one bad upload into an
	// outage that needs a shell the runtime image does not have.
	if err := VerifyDatabaseFile(pending); err != nil {
		rejected := pending + ".rejected"
		if renameErr := os.Rename(pending, rejected); renameErr != nil {
			return false, fmt.Errorf("staged restore is unusable (%w) and could not be moved aside: %v", err, renameErr)
		}
		// The rejected file's own log goes too. Left here it would sit exactly
		// where the next staged restore is written and be read as that file's
		// log — turning one refused upload into a corrupted second attempt.
		if sidecarErr := removeSidecars(pending); sidecarErr != nil {
			return false, fmt.Errorf("staged restore was rejected (%w) and its log could not be cleared: %v", err, sidecarErr)
		}
		return false, fmt.Errorf("staged restore was rejected and moved to %s: %w", rejected, err)
	}
	if err := keepReplacedDatabase(databasePath); err != nil {
		return false, err
	}
	if err := os.Rename(pending, databasePath); err != nil {
		return false, fmt.Errorf("apply restore: %w", err)
	}
	// Verifying the staged file opened it, and opening a database in WAL mode
	// writes a -shm beside it. The rename moves only the file itself, so without
	// this the pair is left in the data directory for ever — and is waiting there
	// to be read as the next staged restore's own log.
	if err := removeSidecars(pending); err != nil {
		return false, err
	}
	return true, nil
}

// removeSidecars deletes the -wal and -shm files SQLite writes beside a
// database. They carry no meaning once separated from the file they belong to,
// and beside a different file they are worse than meaningless.
func removeSidecars(databasePath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(databasePath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear %s: %w", databasePath+suffix, err)
		}
	}
	return nil
}

// keepReplacedDatabase moves the live database aside instead of deleting it, so
// a restore of the wrong snapshot can be undone. The runtime image has no shell:
// once this file is gone there is nothing inside the container that can bring it
// back, and the operator's only remaining copy is whatever they took off-host.
//
// The write-ahead log moves with it. A WAL-mode database keeps committed
// transactions in -wal until they are checkpointed, so a copy taken without its
// log is a copy missing whatever was written last — and leaving the log beside
// the restored database instead would pair it with a file it was never written
// for. Moving both solves the same two problems in one step.
func keepReplacedDatabase(databasePath string) error {
	previous := databasePath + restorePreviousExt

	// The prior generation's log goes first either way. A leftover -wal belongs
	// to the database it was written with; pairing it with a different one is
	// how a readable file is turned into an unreadable one.
	if err := removeSidecars(previous); err != nil {
		return err
	}

	if err := os.Rename(databasePath, previous); err != nil {
		// Nothing to keep: a restore staged before this instance ever opened a
		// database of its own. The restore itself is unaffected.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("keep the replaced database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Rename(databasePath+suffix, previous+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keep the replaced database: %w", err)
		}
	}
	return nil
}

// VerifyDatabaseFile refuses anything that is not a healthy database of ours.
func VerifyDatabaseFile(path string) error {
	database, err := sql.Open(driverName, fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		return fmt.Errorf("open backup for verification: %w", err)
	}
	defer database.Close()

	var result string
	if err := database.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("backup failed integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("backup failed integrity check: %s", result)
	}

	var tableCount int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&tableCount); err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if tableCount == 0 {
		return errors.New("file is not an endlessh-dashboard database")
	}

	// Migrate applies the versions it does not find and nothing else, so a
	// database from a later release passes through it untouched and then fails
	// on the first query that reaches a column this build has never heard of —
	// by which point the file is already live and the image has no shell to
	// undo it with. Refuse it here, while it is still just a file.
	latest, err := LatestMigrationVersion()
	if err != nil {
		return err
	}
	var found int
	if err := database.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&found); err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if found > latest {
		return fmt.Errorf("%w: found version %d, this build supports %d", ErrDatabaseTooNew, found, latest)
	}
	return nil
}

func backupTimestamp(name string, fallback time.Time) time.Time {
	stamp := name[len(backupNamePrefix) : len(name)-len(backupNameSuffix)]
	parsed, err := time.Parse(backupNameLayout, stamp)
	if err != nil {
		return fallback.UTC()
	}
	return parsed.UTC()
}

// copyFile writes through a temporary file and renames it into place, so a
// failure part-way (a full disk, most likely) can never leave a truncated file
// at the destination. That matters most for the staged restore: a half-written
// .restore file would fail verification at every subsequent start, leaving the
// dashboard unable to boot until someone deleted it by hand.
func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer input.Close()

	output, err := os.CreateTemp(filepath.Dir(destination), filepath.Base(destination)+".partial-*")
	if err != nil {
		return fmt.Errorf("create %s: %w", destination, err)
	}
	temporaryPath := output.Name()
	defer os.Remove(temporaryPath)

	if err := output.Chmod(backupFileMode); err != nil {
		output.Close()
		return fmt.Errorf("secure %s: %w", temporaryPath, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("copy to %s: %w", destination, err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return fmt.Errorf("sync %s: %w", destination, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close %s: %w", temporaryPath, err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("finalise %s: %w", destination, err)
	}
	return nil
}
