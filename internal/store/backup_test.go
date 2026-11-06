package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newBackupManager(t *testing.T, keepLast int) (*Store, *BackupManager, string) {
	t.Helper()
	store, databasePath := newStore(t)
	directory := filepath.Join(filepath.Dir(databasePath), "backups")
	return store, NewBackupManager(store, directory, databasePath, keepLast), directory
}

func openReadOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open(driverName, fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func scanIntFrom(t *testing.T, database *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var value int64
	if err := database.QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

// Successful startup includes the explicit confirmation step before .previous
// rotates. Interruption tests exercise the two phases independently.
func applyConfirmedRestore(path string) (bool, error) {
	applied, err := ApplyPendingRestore(path)
	if err == nil && applied {
		err = ConfirmPendingRestore(path)
	}
	return applied, err
}

func TestBackupCreateAndList(t *testing.T) {
	store, manager, directory := newBackupManager(t, 5)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")
	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID, At: baseTime,
		Opens: 3, BytesSent: 300, TrappedSeconds: 30,
		Attackers: []AttackerDelta{
			{IPAddress: "10.0.0.1", Connections: 1, TrappedSeconds: 20, Country: "US", Active: true},
			{IPAddress: "10.0.0.2", Connections: 2, TrappedSeconds: 10, Country: "DE", Active: false},
		},
	})

	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !backupNamePattern.MatchString(info.Name) {
		t.Errorf("backup name %q does not match the expected pattern", info.Name)
	}
	if info.Size <= 0 {
		t.Errorf("backup size = %d, want a non-empty file", info.Size)
	}

	backupPath := filepath.Join(directory, info.Name)
	stat, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if stat.Size() != info.Size {
		t.Errorf("reported size %d, file is %d bytes", info.Size, stat.Size())
	}
	if mode := stat.Mode().Perm(); mode != backupFileMode {
		t.Errorf("backup permissions = %v, want %v", mode, os.FileMode(backupFileMode))
	}

	listed, err := manager.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != info.Name {
		t.Fatalf("List = %+v, want just %q", listed, info.Name)
	}
	if listed[0].Size != info.Size {
		t.Errorf("List size = %d, want %d", listed[0].Size, info.Size)
	}

	if err := VerifyDatabaseFile(backupPath); err != nil {
		t.Fatalf("VerifyDatabaseFile on a fresh backup: %v", err)
	}

	snapshot := openReadOnly(t, backupPath)
	assertInt(t, "machines in the backup", scanIntFrom(t, snapshot, "SELECT COUNT(*) FROM machines"), 1)
	assertInt(t, "attackers in the backup", scanIntFrom(t, snapshot, "SELECT COUNT(*) FROM attackers"), 2)
	assertInt(t, "rollup opens in the backup", scanIntFrom(t, snapshot, "SELECT opens FROM machine_rollups"), 3)
	assertInt(t, "distinct attackers in the backup",
		scanIntFrom(t, snapshot, "SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID), 2)

	var name string
	if err := snapshot.QueryRow("SELECT name FROM machines").Scan(&name); err != nil {
		t.Fatalf("read machine from backup: %v", err)
	}
	if name != "alpha" {
		t.Errorf("machine name in the backup = %q, want alpha", name)
	}
}

func TestBackupIsConsistentDuringWrites(t *testing.T) {
	store, manager, directory := newBackupManager(t, 5)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	signalStarted := func() { once.Do(func() { close(started) }) }

	go func() {
		var writeErr error
		defer func() {
			signalStarted()
			done <- writeErr
		}()
		// The cap only stops a runaway loop; the backup below closes stop.
		for index := 0; index < 20000; index++ {
			select {
			case <-stop:
				return
			default:
			}
			err := store.ApplyScrape(ctx, ScrapeDelta{
				MachineID:      machine.ID,
				At:             baseTime.Add(time.Duration(index) * time.Second),
				Opens:          1,
				Closes:         1,
				BytesSent:      64,
				TrappedSeconds: 1,
				Attackers: []AttackerDelta{{
					IPAddress:      fmt.Sprintf("10.%d.%d.%d", index/65536, (index/256)%256, index%256),
					Connections:    1,
					TrappedSeconds: 1,
					Country:        "US",
					Active:         true,
				}},
			})
			if err != nil {
				writeErr = err
				return
			}
			signalStarted()
		}
	}()

	<-started
	info, createErr := manager.Create(ctx)
	close(stop)
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("background writes failed: %v", writeErr)
	}
	if createErr != nil {
		t.Fatalf("Create during writes: %v", createErr)
	}

	backupPath := filepath.Join(directory, info.Name)
	if err := VerifyDatabaseFile(backupPath); err != nil {
		t.Fatalf("backup taken during writes failed verification: %v", err)
	}

	snapshot := openReadOnly(t, backupPath)
	// Every ApplyScrape writes the rollup, the totals and the attacker in one
	// transaction, so a torn snapshot would break these invariants.
	rollupOpens := scanIntFrom(t, snapshot, "SELECT COALESCE(SUM(opens), 0) FROM machine_rollups")
	totalOpens := scanIntFrom(t, snapshot, "SELECT opens FROM machine_totals WHERE machine_id = ?", machine.ID)
	if rollupOpens != totalOpens {
		t.Errorf("rollup opens %d != lifetime opens %d: the snapshot is torn", rollupOpens, totalOpens)
	}
	attackers := scanIntFrom(t, snapshot, "SELECT COUNT(*) FROM attackers")
	distinctIPs := scanIntFrom(t, snapshot, "SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID)
	if attackers != distinctIPs {
		t.Errorf("attacker rows %d != distinct IPs %d: the snapshot is torn", attackers, distinctIPs)
	}
	if attackers == 0 {
		t.Error("the backup captured no attackers at all")
	}
}

func TestBackupRotateKeepsNewest(t *testing.T) {
	_, manager, directory := newBackupManager(t, 2)
	if err := manager.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory: %v", err)
	}

	names := []string{
		"endlessh-20240101-000000.db",
		"endlessh-20240102-000000.db",
		"endlessh-20240103-000000.db",
		"endlessh-20240104-000000.db",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("snapshot"), backupFileMode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// Files that are not backups must be ignored by both List and Rotate.
	if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("keep me"), backupFileMode); err != nil {
		t.Fatalf("write notes.txt: %v", err)
	}

	if err := manager.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	listed, err := manager.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("List after rotate = %+v, want 2 backups", listed)
	}
	if listed[0].Name != "endlessh-20240104-000000.db" || listed[1].Name != "endlessh-20240103-000000.db" {
		t.Errorf("kept %q and %q, want the two newest", listed[0].Name, listed[1].Name)
	}
	if _, err := os.Stat(filepath.Join(directory, "notes.txt")); err != nil {
		t.Errorf("rotate removed an unrelated file: %v", err)
	}

	if !listed[0].CreatedAt.Equal(time.Date(2024, 1, 4, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("CreatedAt = %v, want it parsed from the file name", listed[0].CreatedAt)
	}

	unlimited := NewBackupManager(nil, directory, "", 0)
	if err := unlimited.Rotate(); err != nil {
		t.Fatalf("Rotate with keepLast 0: %v", err)
	}
	listed, err = unlimited.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("keepLast 0 removed backups: %+v", listed)
	}
}

func TestBackupPathRejectsBadNames(t *testing.T) {
	_, manager, directory := newBackupManager(t, 5)
	if err := manager.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory: %v", err)
	}
	valid := "endlessh-20240104-010203.db"
	if err := os.WriteFile(filepath.Join(directory, valid), []byte("snapshot"), backupFileMode); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	tests := []struct {
		name   string
		backup string
		want   error
		wantOK bool
	}{
		{name: "traversal", backup: "../../etc/passwd", want: ErrInvalidBackupName},
		{name: "absolute path", backup: "/etc/passwd", want: ErrInvalidBackupName},
		{name: "nested traversal", backup: "endlessh-20240104-010203.db/../../secret", want: ErrInvalidBackupName},
		{name: "junk stamp", backup: "endlessh-x.db", want: ErrInvalidBackupName},
		{name: "empty", backup: "", want: ErrInvalidBackupName},
		{name: "wrong extension", backup: "endlessh-20240104-010203.sql", want: ErrInvalidBackupName},
		{name: "well formed but missing", backup: "endlessh-19990101-000000.db", want: ErrBackupNotFound},
		{name: "existing", backup: valid, wantOK: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, err := manager.Path(test.backup)
			if test.wantOK {
				if err != nil {
					t.Fatalf("Path(%q) = %v, want a path", test.backup, err)
				}
				if path != filepath.Join(directory, test.backup) {
					t.Errorf("Path(%q) = %q, want it inside the backup directory", test.backup, path)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("Path(%q) = %q, %v, want %v", test.backup, path, err, test.want)
			}
			if path != "" {
				t.Errorf("Path(%q) returned %q alongside an error", test.backup, path)
			}
		})
	}

	if err := manager.StageRestore("../../etc/passwd"); !errors.Is(err, ErrInvalidBackupName) {
		t.Errorf("StageRestore with a traversal name = %v, want ErrInvalidBackupName", err)
	}
	if err := manager.Delete("endlessh-19990101-000000.db"); !errors.Is(err, ErrBackupNotFound) {
		t.Errorf("Delete of a missing backup = %v, want ErrBackupNotFound", err)
	}
}

func TestVerifyDatabaseFileRejectsJunk(t *testing.T) {
	directory := t.TempDir()

	garbage := filepath.Join(directory, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is definitely not a sqlite database"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	err := VerifyDatabaseFile(garbage)
	if err == nil {
		t.Fatal("VerifyDatabaseFile accepted a file that is not a database")
	}
	if !strings.Contains(err.Error(), "integrity check") {
		t.Errorf("error for a non-database = %q, want it to name the failed integrity check", err)
	}

	truncated := filepath.Join(directory, "truncated.db")
	source, _ := newStore(t)
	if _, err := source.DB().Exec("VACUUM INTO ?", truncated); err != nil {
		t.Fatalf("VACUUM INTO: %v", err)
	}
	if err := VerifyDatabaseFile(truncated); err != nil {
		t.Fatalf("VerifyDatabaseFile on a good snapshot: %v", err)
	}
	contents, err := os.ReadFile(truncated)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	// Keep the 100-byte file header so the file is still recognised as SQLite;
	// everything after it is scrambled, which integrity_check must catch.
	for index := 100; index < len(contents); index++ {
		contents[index] ^= 0xff
	}
	if err := os.WriteFile(truncated, contents, 0o600); err != nil {
		t.Fatalf("rewrite snapshot: %v", err)
	}
	err = VerifyDatabaseFile(truncated)
	if err == nil {
		t.Fatal("VerifyDatabaseFile accepted a corrupted database")
	}
	if !strings.Contains(err.Error(), "integrity check") {
		t.Errorf("error for a corrupted database = %q, want it to name the failed integrity check", err)
	}

	// An empty file is a valid, healthy SQLite database — it just isn't ours.
	blank := filepath.Join(directory, "blank.db")
	if err := os.WriteFile(blank, nil, 0o600); err != nil {
		t.Fatalf("write blank: %v", err)
	}
	if err := VerifyDatabaseFile(blank); err == nil {
		t.Error("VerifyDatabaseFile accepted an empty database")
	}

	foreign := filepath.Join(directory, "foreign.db")
	other, err := sql.Open(driverName, "file:"+foreign)
	if err != nil {
		t.Fatalf("open foreign database: %v", err)
	}
	if _, err := other.Exec("CREATE TABLE something (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create foreign table: %v", err)
	}
	other.Close()

	if err = VerifyDatabaseFile(foreign); err == nil {
		t.Fatal("VerifyDatabaseFile accepted a database that is not ours")
	}
	if got := err.Error(); got != "file is not an endlessh-dashboard database" {
		t.Errorf("error = %q, want it to say the file is not ours", got)
	}
}

func TestStageAndApplyPendingRestore(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath

	machine := createMachine(t, store, "before-backup")
	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID, At: baseTime, Opens: 1, BytesSent: 10, TrappedSeconds: 5,
		Attackers: []AttackerDelta{{IPAddress: "10.0.0.1", Connections: 1, TrappedSeconds: 5, Active: true}},
	})

	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	createMachine(t, store, "after-backup")

	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	pending := databasePath + restorePendingExt
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("staged restore file missing: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}

	applied, err := applyConfirmedRestore(databasePath)
	if err != nil {
		t.Fatalf("ApplyPendingRestore: %v", err)
	}
	if !applied {
		t.Fatal("ApplyPendingRestore reported no restore, want true")
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pending restore file still present: %v", err)
	}

	restored, err := Open(databasePath)
	if err != nil {
		t.Fatalf("reopen after restore: %v", err)
	}
	defer restored.Close()

	machines, err := restored.ListMachines(ctx)
	if err != nil {
		t.Fatalf("ListMachines after restore: %v", err)
	}
	if len(machines) != 1 || machines[0].Name != "before-backup" {
		t.Fatalf("machines after restore = %+v, want only before-backup", machines)
	}
	assertInt(t, "attackers after restore", scanInt(t, restored, "SELECT COUNT(*) FROM attackers"), 1)
	assertInt(t, "lifetime opens after restore", scanInt(t, restored,
		"SELECT opens FROM machine_totals WHERE machine_id = ?", machines[0].ID), 1)
}

func TestStageRestoreRejectsAFileThatIsNotADatabase(t *testing.T) {
	_, manager, directory := newBackupManager(t, 5)
	if err := manager.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory: %v", err)
	}
	name := "endlessh-20240104-010203.db"
	if err := os.WriteFile(filepath.Join(directory, name), []byte("not a database"), backupFileMode); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	err := manager.StageRestore(name)
	if err == nil {
		t.Fatal("StageRestore accepted a file that is not a database")
	}
	if !strings.Contains(err.Error(), "integrity check") {
		t.Errorf("error = %q, want the verification failure", err)
	}
	pending := manager.databasePath + restorePendingExt
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a rejected restore was staged anyway: %v", err)
	}
}

func TestApplyPendingRestoreWithNothingStaged(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "endlessh.db")

	applied, err := applyConfirmedRestore(databasePath)
	if err != nil {
		t.Fatalf("ApplyPendingRestore = %v, want no error", err)
	}
	if applied {
		t.Error("ApplyPendingRestore reported a restore when nothing was staged")
	}
	if _, err := os.Stat(databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ApplyPendingRestore touched the database path: %v", err)
	}
}

func TestListBackupsOnMissingDirectory(t *testing.T) {
	_, manager, directory := newBackupManager(t, 5)

	listed, err := manager.List()
	if err != nil {
		t.Fatalf("List on a missing directory = %v, want no error", err)
	}
	if listed != nil {
		t.Errorf("List on a missing directory = %+v, want nil", listed)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("List created the backup directory: %v", err)
	}
}

func TestApplyPendingRestoreKeepsTheDatabaseItReplaced(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath

	createMachine(t, store, "before-backup")
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Work done after the snapshot. This is what a restore throws away, and what
	// the operator who restored the wrong file needs back.
	createMachine(t, store, "after-backup")

	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}
	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore: %v", err)
	}

	previous := databasePath + restorePreviousExt
	if _, err := os.Stat(previous); err != nil {
		t.Fatalf("the replaced database was not kept: %v", err)
	}
	if err := VerifyDatabaseFile(previous); err != nil {
		t.Fatalf("the kept copy does not verify: %v", err)
	}

	// It has to be the database as it stood, not merely a file that opens: the
	// point of keeping it is the work the restore discarded.
	kept, err := Open(previous)
	if err != nil {
		t.Fatalf("open the kept copy: %v", err)
	}
	defer kept.Close()
	keptMachines, err := kept.ListMachines(ctx)
	if err != nil {
		t.Fatalf("ListMachines on the kept copy: %v", err)
	}
	if len(keptMachines) != 2 {
		t.Fatalf("the kept copy holds %d machines, want both", len(keptMachines))
	}
}

func TestPreviousCopyCanBeRestoredToUndoARestore(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath

	createMachine(t, store, "before-backup")
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	createMachine(t, store, "after-backup")

	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}
	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore: %v", err)
	}

	// The undo the README documents, walked end to end: the operator uploads
	// endlessh.db.previous through "Restore from file" and gets their data back.
	reopened, err := Open(databasePath)
	if err != nil {
		t.Fatalf("reopen after restore: %v", err)
	}
	undoManager := NewBackupManager(reopened, manager.directory, databasePath, 5)

	previousFile, err := os.Open(databasePath + restorePreviousExt)
	if err != nil {
		t.Fatalf("open the kept copy: %v", err)
	}
	if err := undoManager.StageRestoreFromReader(previousFile); err != nil {
		previousFile.Close()
		t.Fatalf("stage the kept copy as an upload: %v", err)
	}
	previousFile.Close()
	if err := reopened.Close(); err != nil {
		t.Fatalf("close before the undo: %v", err)
	}
	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore(undo): %v", err)
	}

	undone, err := Open(databasePath)
	if err != nil {
		t.Fatalf("reopen after the undo: %v", err)
	}
	defer undone.Close()
	machines, err := undone.ListMachines(ctx)
	if err != nil {
		t.Fatalf("ListMachines after the undo: %v", err)
	}
	if len(machines) != 2 {
		t.Fatalf("after undoing the restore there are %d machines, want both back", len(machines))
	}
}

func TestUndoingARestoreLeavesNoOrphanedLogsBehind(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath

	createMachine(t, store, "alpha")
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}
	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore: %v", err)
	}

	// The kept copy is a WAL-mode database, so uploading it — the undo the
	// README documents — is the case that leaves logs beside the staged file and
	// inside the backup directory. The data volume has no shell to sweep them
	// out with, and a log left next to the next staged restore is a hazard, not
	// just clutter.
	reopened, err := Open(databasePath)
	if err != nil {
		t.Fatalf("reopen after restore: %v", err)
	}
	undoManager := NewBackupManager(reopened, manager.directory, databasePath, 5)
	previousFile, err := os.Open(databasePath + restorePreviousExt)
	if err != nil {
		t.Fatalf("open the kept copy: %v", err)
	}
	if err := undoManager.StageRestoreFromReader(previousFile); err != nil {
		previousFile.Close()
		t.Fatalf("stage the kept copy as an upload: %v", err)
	}
	previousFile.Close()
	if err := reopened.Close(); err != nil {
		t.Fatalf("close before the undo: %v", err)
	}
	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore(undo): %v", err)
	}

	for _, orphan := range []string{
		databasePath + restorePendingExt + "-wal",
		databasePath + restorePendingExt + "-shm",
	} {
		if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was left behind: %v", filepath.Base(orphan), err)
		}
	}

	entries, err := os.ReadDir(manager.directory)
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "upload-") {
			t.Errorf("an upload left %s in the backup directory", entry.Name())
		}
	}
}

func TestApplyPendingRestoreClearsAStaleLogBesideTheKeptCopy(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath
	previous := databasePath + restorePreviousExt

	createMachine(t, store, "alpha")
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}

	// A write-ahead log left by an earlier restore, belonging to a database that
	// is about to be replaced. Left in place it would be read as this copy's own
	// log, which is how a readable file becomes an unreadable one.
	if err := os.WriteFile(previous+"-wal", []byte("a log from a different database"), backupFileMode); err != nil {
		t.Fatalf("plant a stale log: %v", err)
	}

	if _, err := applyConfirmedRestore(databasePath); err != nil {
		t.Fatalf("ApplyPendingRestore: %v", err)
	}
	if _, err := os.Stat(previous + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stale log survived beside the kept copy: %v", err)
	}
	if err := VerifyDatabaseFile(previous); err != nil {
		t.Fatalf("the kept copy does not verify: %v", err)
	}
}

func TestLatestMigrationVersionMatchesTheEmbeddedMigrations(t *testing.T) {
	latest, err := LatestMigrationVersion()
	if err != nil {
		t.Fatalf("LatestMigrationVersion: %v", err)
	}

	// Derived independently of the function under test: whatever the highest
	// numbered file in migrations/ is, that is the answer.
	names, err := migrationNames()
	if err != nil {
		t.Fatalf("migrationNames: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no migrations are embedded")
	}
	highest := 0
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			t.Fatalf("migrationVersion(%q): %v", name, err)
		}
		if version > highest {
			highest = version
		}
	}
	if latest != highest {
		t.Errorf("LatestMigrationVersion = %d, want %d (from %v)", latest, highest, names)
	}
}

func TestVerifyDatabaseFileRefusesANewerSchema(t *testing.T) {
	store, path := newStore(t)
	ctx := context.Background()
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A healthy database of ours, migrated by this build, is accepted.
	if err := VerifyDatabaseFile(path); err != nil {
		t.Fatalf("VerifyDatabaseFile on a current database: %v", err)
	}

	latest, err := LatestMigrationVersion()
	if err != nil {
		t.Fatalf("LatestMigrationVersion: %v", err)
	}

	// Now it claims a migration this build does not carry, which is what a
	// backup taken by a later image looks like from here.
	reopened, err := sql.Open(driverName, "file:"+path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := reopened.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)", latest+1); err != nil {
		reopened.Close()
		t.Fatalf("record a future migration: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	err = VerifyDatabaseFile(path)
	if err == nil {
		t.Fatal("VerifyDatabaseFile accepted a database from a newer release")
	}
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Errorf("error = %v, want it to be ErrDatabaseTooNew so the API can explain it", err)
	}
	// Both numbers belong in the message: without them the operator cannot tell
	// which image wrote the file or which one is running.
	for _, want := range []string{fmt.Sprint(latest + 1), fmt.Sprint(latest)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name version %s", err, want)
		}
	}
}

func TestRejectedRestoreLeavesNoLogWhereTheNextOneGoes(t *testing.T) {
	store, manager, _ := newBackupManager(t, 5)
	ctx := context.Background()
	databasePath := manager.databasePath
	pending := databasePath + restorePendingExt

	createMachine(t, store, "alpha")
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := manager.StageRestore(info.Name); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}

	// Make the staged file unacceptable the way a downgraded image would find
	// it: a real database of ours, healthy, claiming a schema this build has
	// never carried.
	latest, err := LatestMigrationVersion()
	if err != nil {
		t.Fatalf("LatestMigrationVersion: %v", err)
	}
	staged, err := sql.Open(driverName, "file:"+pending)
	if err != nil {
		t.Fatalf("open the staged file: %v", err)
	}
	if _, err := staged.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)", latest+1); err != nil {
		staged.Close()
		t.Fatalf("record a future migration: %v", err)
	}
	// In WAL mode, because that is what makes this test about logs at all:
	// verifying a WAL-mode database writes a -wal and -shm beside it even when
	// opened read-only, and an uploaded endlessh.db.previous is always one.
	var journalMode string
	if err := staged.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		staged.Close()
		t.Fatalf("switch the staged file to WAL: %v", err)
	}
	if journalMode != "wal" {
		staged.Close()
		t.Fatalf("staged file is in %q mode, want wal", journalMode)
	}
	if err := staged.Close(); err != nil {
		t.Fatalf("close the staged file: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close before restore: %v", err)
	}

	applied, err := applyConfirmedRestore(databasePath)
	if err == nil {
		t.Fatal("ApplyPendingRestore accepted a staged database from a newer release")
	}
	if applied {
		t.Error("a rejected restore reported itself as applied")
	}
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Errorf("error = %v, want it to be ErrDatabaseTooNew", err)
	}

	// Nothing may be left where the next staged restore is written.
	for _, orphan := range []string{pending, pending + "-wal", pending + "-shm"} {
		if _, statErr := os.Stat(orphan); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s survived a rejected restore: %v", filepath.Base(orphan), statErr)
		}
	}
	// And the live database is untouched, so the next start comes up on it.
	if err := VerifyDatabaseFile(databasePath); err != nil {
		t.Errorf("the live database did not survive a rejected restore: %v", err)
	}
}

// alignToSecondBoundary waits until a second has just ticked over, so what
// follows has nearly a whole second before the backup name would change. Backup
// names carry one second, and these tests are about what happens inside one.
func alignToSecondBoundary() {
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(time.Second)))
}

func TestCreateTwiceInOneSecondReturnsTheSameBackup(t *testing.T) {
	_, manager, directory := newBackupManager(t, 5)
	ctx := context.Background()

	alignToSecondBoundary()
	first, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := manager.Create(ctx)
	if err != nil {
		t.Fatalf("second Create in the same second: %v", err)
	}

	if first.Name != second.Name {
		t.Skipf("the two calls straddled a second boundary (%s, %s); nothing to assert",
			first.Name, second.Name)
	}

	// The same snapshot, described the same way both times — not an error for a
	// file that exists and is current. A second click on "Back up now" is not a
	// mistake the operator needs to be told about.
	if second.Size != first.Size {
		t.Errorf("size = %d, want the existing backup's %d", second.Size, first.Size)
	}
	if second.Size == 0 {
		t.Error("the second call reported an empty backup")
	}
	assertBackupFileCount(t, directory, 1)
}

func TestCreateFromSeveralPlacesAtOnceNeverFails(t *testing.T) {
	_, manager, directory := newBackupManager(t, 20)
	ctx := context.Background()

	// The maintenance worker and an operator clicking "Back up now" share this
	// manager, so two calls really can overlap. They aim at the same filename
	// within a second, and before they were serialised both got past the check
	// that the file did not exist yet — leaving the loser with a SQLite error
	// about a snapshot the winner was still writing.
	const callers = 8
	var wait sync.WaitGroup
	names := make([]string, callers)
	failures := make([]error, callers)
	for index := range names {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			info, err := manager.Create(ctx)
			names[index], failures[index] = info.Name, err
		}(index)
	}
	wait.Wait()

	for index, err := range failures {
		if err != nil {
			t.Errorf("caller %d: %v", index, err)
		}
	}
	// Every name handed back has to be a backup that is really there and really
	// readable, whether it was written by that caller or by whoever won.
	for index, name := range names {
		if name == "" {
			t.Errorf("caller %d succeeded with no name", index)
			continue
		}
		path := filepath.Join(directory, name)
		if err := VerifyDatabaseFile(path); err != nil {
			t.Errorf("caller %d was handed %s, which does not verify: %v", index, name, err)
		}
	}
}

func assertBackupFileCount(t *testing.T, directory string, want int) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	if len(entries) != want {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("backup files = %d %v, want %d", len(entries), names, want)
	}
}
