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
	"time"
)

const (
	backupNameLayout  = "20060102-150405"
	backupNamePrefix  = "endlessh-"
	backupNameSuffix  = ".db"
	restorePendingExt = ".restore"
	backupFileMode    = 0o600
	backupDirMode     = 0o700
)

var (
	ErrBackupNotFound    = errors.New("backup not found")
	ErrInvalidBackupName = errors.New("invalid backup name")
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
	if err := m.EnsureDirectory(); err != nil {
		return BackupInfo{}, err
	}
	createdAt := time.Now().UTC()
	name := backupNamePrefix + createdAt.Format(backupNameLayout) + backupNameSuffix
	destination := filepath.Join(m.directory, name)

	if _, err := os.Stat(destination); err == nil {
		return BackupInfo{}, fmt.Errorf("backup %s already exists", name)
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
	defer os.Remove(temporaryPath)

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
		return false, fmt.Errorf("staged restore was rejected and moved to %s: %w", rejected, err)
	}
	for _, sidecar := range []string{databasePath + "-wal", databasePath + "-shm"} {
		if err := os.Remove(sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("clear %s: %w", sidecar, err)
		}
	}
	if err := os.Rename(pending, databasePath); err != nil {
		return false, fmt.Errorf("apply restore: %w", err)
	}
	return true, nil
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
