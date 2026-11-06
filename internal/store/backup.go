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
	// creating serialises publication, rotation and deletion within this manager.
	// In particular a same-second caller verifies the completed winner's file.
	creating sync.Mutex
	files    backupFileOperations
}

// File operations are owned by each manager; tests inject storage failures
// without filling the host disk or touching the live volume.
type backupFileOperations struct {
	snapshot      func(context.Context, string) error
	chmod         func(string, os.FileMode) error
	sync          func(string) error
	publish       func(string, string) error
	syncDirectory func(string) error
}

func syncBackupFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncBackupDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err = directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func NewBackupManager(store *Store, directory, databasePath string, keepLast int) *BackupManager {
	return &BackupManager{
		store:        store,
		directory:    directory,
		databasePath: databasePath,
		keepLast:     keepLast,
		files: backupFileOperations{
			snapshot: func(ctx context.Context, path string) error {
				_, err := store.database.ExecContext(ctx, "VACUUM INTO ?", path)
				return err
			},
			chmod: os.Chmod, sync: syncBackupFile, publish: os.Link, syncDirectory: syncBackupDirectory,
		},
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
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}
	// Publication also shares this lock with restore/delete operations. A daily
	// worker waiting here must be able to leave when shutdown cancels its context.
	if !m.creating.TryLock() {
		retry := time.NewTicker(10 * time.Millisecond)
		defer retry.Stop()
		for {
			select {
			case <-ctx.Done():
				return BackupInfo{}, ctx.Err()
			case <-retry.C:
			}
			if m.creating.TryLock() {
				break
			}
		}
	}
	defer m.creating.Unlock()
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}

	if err := m.EnsureDirectory(); err != nil {
		return BackupInfo{}, err
	}
	createdAt := time.Now().UTC()
	name := backupNamePrefix + createdAt.Format(backupNameLayout) + backupNameSuffix
	destination := filepath.Join(m.directory, name)

	// Reuse only a verified completed snapshot. A failed verification must
	// never overwrite or remove a pre-existing file, which may be the only copy.
	if existing, err := os.Lstat(destination); err == nil {
		if !existing.Mode().IsRegular() {
			return BackupInfo{}, fmt.Errorf("backup destination is not a regular file")
		}
		if err := verifyDatabaseFileContext(ctx, destination); err != nil {
			return BackupInfo{}, fmt.Errorf("existing backup could not be verified: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return BackupInfo{}, err
		}
		return BackupInfo{Name: name, Size: existing.Size(), CreatedAt: createdAt}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupInfo{}, fmt.Errorf("inspect backup destination: %w", err)
	}

	temporary, err := os.CreateTemp(m.directory, ".snapshot-*")
	if err != nil {
		return BackupInfo{}, err
	}
	pending := temporary.Name()
	defer os.Remove(pending)
	defer removeSidecars(pending)
	if err := temporary.Close(); err != nil {
		return BackupInfo{}, err
	}
	if err := m.files.snapshot(ctx, pending); err != nil {
		return BackupInfo{}, fmt.Errorf("create backup: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}
	if err := m.files.chmod(pending, backupFileMode); err != nil {
		return BackupInfo{}, fmt.Errorf("secure backup file: %w", err)
	}
	if err := verifyDatabaseFileContext(ctx, pending); err != nil {
		return BackupInfo{}, fmt.Errorf("verify backup: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}
	if err := m.files.sync(pending); err != nil {
		return BackupInfo{}, fmt.Errorf("sync backup: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}
	// A hard link publishes atomically without overwriting a competing snapshot.
	// Both names are on the same filesystem; the hidden link is removed on return.
	if err := m.files.publish(pending, destination); err != nil {
		return BackupInfo{}, fmt.Errorf("publish backup: %w", err)
	}
	if err := m.files.syncDirectory(m.directory); err != nil {
		os.Remove(destination)
		return BackupInfo{}, fmt.Errorf("sync backup directory: %w", err)
	}

	info, err := os.Stat(destination)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("stat backup: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return BackupInfo{}, err
	}
	if err := m.rotate(); err != nil {
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
	m.creating.Lock()
	defer m.creating.Unlock()
	return m.rotate()
}

func (m *BackupManager) rotate() error {
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
	m.creating.Lock()
	defer m.creating.Unlock()
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
	m.creating.Lock()
	defer m.creating.Unlock()
	if err := checkRestoreIdle(m.databasePath); err != nil {
		return err
	}
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
	m.creating.Lock()
	defer m.creating.Unlock()
	if err := checkRestoreIdle(m.databasePath); err != nil {
		return err
	}
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

// VerifyDatabaseFile refuses anything that is not a healthy database of ours.
func VerifyDatabaseFile(path string) error {
	return verifyDatabaseFileContext(context.Background(), path)
}

func verifyDatabaseFileContext(parent context.Context, path string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	database, err := sql.Open(driverName, readOnlyURI(path))
	if err != nil {
		return fmt.Errorf("open backup for verification: %w", err)
	}
	defer database.Close()

	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("backup failed integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("backup failed integrity check: %s", result)
	}

	var tableCount int
	if err := database.QueryRowContext(ctx,
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
	if err := database.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&found); err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if found > latest {
		return fmt.Errorf("%w: found version %d, this build supports %d", ErrDatabaseTooNew, found, latest)
	}
	return verifyApplicationDatabase(ctx, database, filepath.Dir(path))
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
	return syncBackupDirectory(filepath.Dir(destination))
}
