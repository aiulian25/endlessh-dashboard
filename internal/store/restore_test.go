package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The child exits without closing SQLite, leaving a committed transaction only
// in WAL. It also terminates restore at real post-filesystem boundaries, so no
// deferred cleanup runs and recovery uses only what survived on disk.
func TestRestoreProcess(t *testing.T) {
	mode := os.Getenv("ENDLESSH_RESTORE_TEST_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("ENDLESSH_RESTORE_TEST_PATH")
	if mode == "wal" {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s.database.SetMaxOpenConns(1)
		if _, err = s.database.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
			t.Fatal(err)
		}
		createMachine(t, s, "wal-only")
		os.Exit(0)
	}
	n, err := strconv.Atoi(os.Getenv("ENDLESSH_RESTORE_TEST_STOP"))
	if err != nil {
		t.Fatal(err)
	}
	r := newRestoreOperation(path)
	r.files.after = func(string) error {
		n--
		if n == 0 {
			os.Exit(73)
		}
		return nil
	}
	if mode == "rollback" {
		_, err = r.apply()
	} else {
		var applied bool
		applied, err = r.apply()
		if err == nil && applied {
			err = r.confirm()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("requested crash boundary was not reached")
}
func restoreChild(t *testing.T, mode, path string, stop int) []byte {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^TestRestoreProcess$")
	c.Env = append(os.Environ(), "ENDLESSH_RESTORE_TEST_MODE="+mode, "ENDLESSH_RESTORE_TEST_PATH="+path, fmt.Sprintf("ENDLESSH_RESTORE_TEST_STOP=%d", stop))
	out, err := c.CombinedOutput()
	if mode == "wal" {
		if err != nil {
			t.Fatalf("WAL child: %v %s", err, out)
		}
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 73 {
			t.Fatalf("crash child: %v %s", err, out)
		}
	}
	return out
}
func restoreFixture(t *testing.T) string {
	t.Helper()
	s, m, _ := newBackupManager(t, 5)
	createMachine(t, s, "snapshot")
	info, err := m.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestore(info.Name); err != nil {
		t.Fatal(err)
	}
	source, err := m.Path(info.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err = copyFile(source, m.databasePath+restorePreviousExt); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	restoreChild(t, "wal", m.databasePath, 0)
	stat, err := os.Stat(m.databasePath + "-wal")
	if err != nil || stat.Size() == 0 {
		t.Fatalf("fixture has no committed WAL: %v", err)
	}
	return m.databasePath
}
func cloneRestoreFixture(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endlessh.db")
	for _, ext := range []string{"", "-wal", "-shm", restorePendingExt, restorePreviousExt} {
		if err := copyFile(source+ext, path+ext); err != nil {
			t.Fatal(err)
		}
	}
	return path
}
func checkRecoveredRestore(t *testing.T, path string) {
	t.Helper()
	applied, err := ApplyPendingRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		if err = ConfirmPendingRestore(path); err != nil {
			t.Fatal(err)
		}
	}
	if err = VerifyDatabaseFile(path); err != nil {
		t.Fatal(err)
	}
	db := openReadOnly(t, path)
	count := scanIntFrom(t, db, "SELECT COUNT(*) FROM machines")
	if count != 1 && count != 2 {
		t.Fatalf("unexplained live generation: %d machines", count)
	}
	if count == 2 && scanIntFrom(t, db, "SELECT COUNT(*) FROM machines WHERE name='wal-only'") != 1 {
		t.Fatal("rollback lost committed WAL")
	}
	db.Close()
	if again, err := ApplyPendingRestore(path); err != nil || again {
		t.Fatalf("recovery not idempotent: %v %v", again, err)
	}
	if err = ConfirmPendingRestore(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".restore") && !strings.HasSuffix(entry.Name(), ".restore.rejected") {
			t.Fatalf("recovery artifact remains: %s", entry.Name())
		}
	}
}
func TestRestoreCrashEveryPublicationBoundary(t *testing.T) {
	template := restoreFixture(t)
	path := cloneRestoreFixture(t, template)
	var trace []string
	r := newRestoreOperation(path)
	r.files.after = func(step string) error { trace = append(trace, step); return nil }
	if _, err := r.apply(); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	t.Logf("crashing after each of %d apply/confirm filesystem boundaries", len(trace))
	for i, step := range trace {
		t.Run(fmt.Sprintf("%02d_%s", i, step), func(t *testing.T) {
			path := cloneRestoreFixture(t, template)
			before, err := fileHash(path + restorePreviousExt)
			if err != nil {
				t.Fatal(err)
			}
			restoreChild(t, "apply", path, i+1)
			j, err := newRestoreOperation(path).readJournal()
			if err != nil {
				t.Fatal(err)
			}
			if j != nil && (j.Phase == "prepared" || j.Phase == "applying") {
				after, err := fileHash(path + restorePreviousExt)
				if err != nil || after != before {
					t.Fatal("previous generation rotated before readiness")
				}
			}
			checkRecoveredRestore(t, path)
		})
	}
}
func TestRestoreCrashEveryRollbackBoundary(t *testing.T) {
	template := restoreFixture(t)
	prepare := func(t *testing.T) string {
		path := cloneRestoreFixture(t, template)
		if _, err := ApplyPendingRestore(path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := prepare(t)
	var trace []string
	r := newRestoreOperation(path)
	r.files.after = func(step string) error { trace = append(trace, step); return nil }
	if _, err := r.apply(); err != nil {
		t.Fatal(err)
	}
	for i, step := range trace {
		t.Run(fmt.Sprintf("%02d_%s", i, step), func(t *testing.T) {
			path := prepare(t)
			restoreChild(t, "rollback", path, i+1)
			checkRecoveredRestore(t, path)
			db := openReadOnly(t, path)
			if scanIntFrom(t, db, "SELECT COUNT(*) FROM machines WHERE name='wal-only'") != 1 {
				t.Fatal("interrupted rollback lost WAL history")
			}
		})
	}
}
func TestRestoreFilesystemFailuresAreRetrySafe(t *testing.T) {
	template := restoreFixture(t)
	injected := errors.New("injected filesystem failure")
	for _, kind := range []string{"rename", "file-sync", "directory-sync", "remove"} {
		for failAt := 1; ; failAt++ {
			path := cloneRestoreFixture(t, template)
			r := newRestoreOperation(path)
			calls := 0
			fail := func() error {
				calls++
				if calls == failAt {
					return injected
				}
				return nil
			}
			switch kind {
			case "rename":
				r.files.rename = func(a, b string) error {
					if e := fail(); e != nil {
						return e
					}
					return os.Rename(a, b)
				}
			case "file-sync":
				r.files.syncFile = func(p string) error {
					if e := fail(); e != nil {
						return e
					}
					return syncBackupFile(p)
				}
			case "directory-sync":
				r.files.syncDir = func(p string) error {
					if e := fail(); e != nil {
						return e
					}
					return syncBackupDirectory(p)
				}
			case "remove":
				r.files.remove = func(p string) error {
					if e := fail(); e != nil {
						return e
					}
					return os.Remove(p)
				}
			}
			applied, err := r.apply()
			if err == nil && applied {
				err = r.confirm()
			}
			if err == nil {
				t.Logf("%s: %d injected failures", kind, failAt-1)
				break
			}
			if !errors.Is(err, injected) {
				t.Fatalf("%s/%d: %v", kind, failAt, err)
			}
			checkRecoveredRestore(t, path)
		}
	}
}
func TestRestoreRollbackIsStandaloneAndPreservesPreviousUntilReady(t *testing.T) {
	path := cloneRestoreFixture(t, restoreFixture(t))
	before, err := fileHash(path + restorePreviousExt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyPendingRestore(path); err != nil {
		t.Fatal(err)
	}
	after, err := fileHash(path + restorePreviousExt)
	if err != nil || after != before {
		t.Fatal("rotated previous before readiness")
	}
	// Copy only the rollback base, with no WAL/SHM, to prove it is self-contained.
	standalone := filepath.Join(t.TempDir(), "rollback.db")
	if err = copyFile(path+restoreRollbackExt, standalone); err != nil {
		t.Fatal(err)
	}
	db := openReadOnly(t, standalone)
	if scanIntFrom(t, db, "SELECT COUNT(*) FROM machines WHERE name='wal-only'") != 1 {
		t.Fatal("rollback snapshot omitted WAL")
	}
	if err = ConfirmPendingRestore(path); err != nil {
		t.Fatal(err)
	}
	checkRecoveredRestore(t, path)
	previous := openReadOnly(t, path+restorePreviousExt)
	if scanIntFrom(t, previous, "SELECT COUNT(*) FROM machines WHERE name='wal-only'") != 1 {
		t.Fatal("previous omitted WAL")
	}
}
func TestRestoreRefusesAmbiguousOrDamagedRecoveryState(t *testing.T) {
	for _, mode := range []string{"missing-base", "journal", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			path := cloneRestoreFixture(t, restoreFixture(t))
			switch mode {
			case "missing-base":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path + restorePendingExt); err != nil {
					t.Fatal(err)
				}
			case "journal":
				if err := os.WriteFile(path+restoreJournalExt, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "snapshot":
				if _, err := ApplyPendingRestore(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+restoreRollbackExt, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ApplyPendingRestore(path); err == nil {
				t.Fatal("ambiguous recovery silently accepted")
			}
		})
	}
}

func TestRestoreMissingBaseWithRecoveryCopyFailsClosed(t *testing.T) {
	s, path := newStore(t)
	createMachine(t, s, "recoverable")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".previous"); err != nil {
		t.Fatal(err)
	}
	if applied, err := ApplyPendingRestore(path); err == nil || applied {
		t.Fatalf("missing base silently permitted empty startup: applied=%v error=%v", applied, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery created a database")
	}
}

func TestRestoreWithoutOldDatabaseRetriesVerifiedCandidate(t *testing.T) {
	template := restoreFixture(t)
	path := cloneRestoreFixture(t, template)
	for _, ext := range []string{"", "-wal", "-shm", restorePreviousExt} {
		if err := os.Remove(path + ext); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ApplyPendingRestore(path); err != nil {
		t.Fatal(err)
	}
	// No old generation exists, so another startup must retry new, not roll back
	// to an absent file. Staging is refused until startup confirms this operation.
	if err := checkRestoreIdle(path); err == nil {
		t.Fatal("allowed another restore during recovery")
	}
	if applied, err := ApplyPendingRestore(path); err != nil || !applied {
		t.Fatalf("new-only recovery: %v %v", applied, err)
	}
	if err := ConfirmPendingRestore(path); err != nil {
		t.Fatal(err)
	}
	checkRecoveredRestore(t, path)
}

func TestRejectedRestoreCrashClearsPendingSidecars(t *testing.T) {
	template := restoreFixture(t)
	pending := template + restorePendingExt
	db, err := sql.Open(driverName, pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE schema_migrations SET version=version+100"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// Empty sidecars model the files created during verification. They must never
	// be left under the next upload's name after quarantine/restart.
	prepare := func(t *testing.T) string {
		path := cloneRestoreFixture(t, template)
		for _, ext := range []string{"-wal", "-shm"} {
			if err := os.WriteFile(path+restorePendingExt+ext, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	var trace []string
	r := newRestoreOperation(prepare(t))
	r.files.after = func(step string) error { trace = append(trace, step); return nil }
	if _, err = r.apply(); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	for i, step := range trace {
		t.Run(fmt.Sprintf("%d_%s", i, step), func(t *testing.T) {
			path := prepare(t)
			restoreChild(t, "apply", path, i+1)
			checkRecoveredRestore(t, path)
		})
	}
}
