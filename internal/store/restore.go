package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const restoreJournalExt = ".restore-journal"
const restoreRollbackExt = ".restore-rollback"
const restoreCandidateExt = ".restore-candidate"

// No caller may open the live database until recovery finishes. Only one
// dashboard process may own this data directory. All names share a filesystem.
type restoreJournal struct {
	Version int    `json:"version"`
	Phase   string `json:"phase"`
	HadOld  bool   `json:"had_old"`
	OldHash string `json:"old_hash"`
	NewHash string `json:"new_hash"`
}

// Instance-owned fault injection; never changed globally or via environment.
type restoreFiles struct {
	rename   func(string, string) error
	remove   func(string) error
	syncFile func(string) error
	syncDir  func(string) error
	after    func(string) error
}
type restoreOperation struct {
	path  string
	files restoreFiles
}

func newRestoreOperation(path string) *restoreOperation {
	return &restoreOperation{path: path, files: restoreFiles{os.Rename, os.Remove, syncBackupFile, syncBackupDirectory, func(string) error { return nil }}}
}

func checkRestoreIdle(path string) error {
	if _, err := os.Lstat(path + restoreJournalExt); err == nil {
		return errors.New("restore recovery is in progress; restart before staging another restore")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ApplyPendingRestore runs before Open. An interrupted, unconfirmed replacement
// rolls back on the next startup. With no old database, the verified candidate
// is retried instead. Invalid/ambiguous recovery state fails closed.
func ApplyPendingRestore(path string) (bool, error) { return newRestoreOperation(path).apply() }

// ConfirmPendingRestore is called only after migration, application setup and
// listener binding succeed, before workers or requests can write new history.
// It retains the replaced standalone snapshot as .previous and finalizes recovery.
func ConfirmPendingRestore(path string) error { return newRestoreOperation(path).confirm() }

func (r *restoreOperation) readJournal() (*restoreJournal, error) {
	f, err := os.Open(r.path + restoreJournalExt)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var j restoreJournal
	d := json.NewDecoder(io.LimitReader(f, 4096))
	d.DisallowUnknownFields()
	if err = d.Decode(&j); err != nil {
		return nil, fmt.Errorf("invalid restore journal; preserve recovery files: %w", err)
	}
	var trailing any
	if err = d.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid trailing restore journal data")
	}
	validHash := func(v string) bool { b, e := hex.DecodeString(v); return e == nil && len(b) == sha256.Size }
	if j.Version != 1 || !validHash(j.NewHash) || (j.HadOld && !validHash(j.OldHash)) {
		return nil, errors.New("unsupported restore journal; preserve recovery files")
	}
	switch j.Phase {
	case "prepared", "applying", "rolling_back", "rolled_back", "confirmed", "complete":
	default:
		return nil, errors.New("unknown restore phase; preserve recovery files")
	}
	return &j, nil
}

func (r *restoreOperation) apply() (bool, error) {
	if err := r.clearPartials(); err != nil {
		return false, err
	}
	j, err := r.readJournal()
	if err != nil {
		return false, err
	}
	if j != nil {
		switch j.Phase {
		case "prepared":
			return r.install(j)
		case "applying", "rolling_back":
			if !j.HadOld {
				return r.install(j)
			}
			return false, r.rollback(j)
		case "rolled_back":
			return false, r.cleanup(j)
		case "confirmed", "complete":
			return true, r.finalize(j)
		}
	}
	pending := r.path + restorePendingExt
	if _, err = os.Stat(pending); errors.Is(err, os.ErrNotExist) {
		if _, liveErr := os.Stat(r.path); errors.Is(liveErr, os.ErrNotExist) {
			for _, ext := range []string{restorePreviousExt, restoreRollbackExt, restoreCandidateExt, "-wal", "-shm"} {
				if _, e := os.Lstat(r.path + ext); !errors.Is(e, os.ErrNotExist) {
					return false, errors.New("database missing but recovery files exist; preserve the volume and recover a verified snapshot before startup")
				}
			}
		}
		// A crash while quarantining a rejected upload can leave its sidecars
		// under the pending name. Clear them before a future staged base can
		// accidentally inherit that unrelated WAL.
		for _, ext := range []string{"-wal", "-shm"} {
			if _, e := os.Lstat(pending + ext); e == nil {
				if e = r.sidecars(pending); e != nil {
					return false, e
				}
				break
			} else if !errors.Is(e, os.ErrNotExist) {
				return false, e
			}
		}
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err = VerifyDatabaseFile(pending); err != nil {
		if e := r.rename(pending, pending+".rejected"); e != nil {
			return false, e
		}
		if e := r.sidecars(pending); e != nil {
			return false, e
		}
		return false, fmt.Errorf("staged restore was rejected and moved to %s.rejected: %w", pending, err)
	}
	// VACUUM INTO captures committed WAL data without moving the live base or
	// its sidecars. The source stays intact until both snapshots and journal sync.
	if err = r.snapshot(pending, r.path+restoreCandidateExt); err != nil {
		return false, err
	}
	j = &restoreJournal{Version: 1, Phase: "prepared"}
	j.NewHash, err = fileHash(r.path + restoreCandidateExt)
	if err != nil {
		return false, err
	}
	if _, err = os.Stat(r.path); err == nil {
		j.HadOld = true
		if err = r.snapshot(r.path, r.path+restoreRollbackExt); err != nil {
			return false, err
		}
		j.OldHash, err = fileHash(r.path + restoreRollbackExt)
		if err != nil {
			return false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	} else {
		// A missing base with an older recovery generation is ambiguous, not a
		// first installation. Never silently discard possible old WAL transactions.
		for _, ext := range []string{restorePreviousExt, "-wal", "-shm"} {
			if _, e := os.Lstat(r.path + ext); !errors.Is(e, os.ErrNotExist) {
				return false, errors.New("missing live database with recovery files; manual recovery required")
			}
		}
	}
	if err = r.writeJournal(j); err != nil {
		return false, err
	}
	return r.install(j)
}

func (r *restoreOperation) install(j *restoreJournal) (bool, error) {
	if err := verifyRestoreHash(r.path+restoreCandidateExt, j.NewHash); err != nil {
		return false, err
	}
	if j.HadOld {
		if err := verifyRestoreHash(r.path+restoreRollbackExt, j.OldHash); err != nil {
			return false, err
		}
	}
	j.Phase = "applying"
	if err := r.writeJournal(j); err != nil {
		return false, err
	}
	if err := r.sidecars(r.path); err != nil {
		return false, err
	}
	if err := r.copy(r.path+restoreCandidateExt, r.path); err != nil {
		return false, err
	}
	if err := VerifyDatabaseFile(r.path); err != nil {
		return false, err
	}
	if err := r.removePending(); err != nil {
		return false, err
	}
	return true, nil
}

func (r *restoreOperation) rollback(j *restoreJournal) error {
	if err := verifyRestoreHash(r.path+restoreRollbackExt, j.OldHash); err != nil {
		return err
	}
	j.Phase = "rolling_back"
	if err := r.writeJournal(j); err != nil {
		return err
	}
	if err := r.sidecars(r.path); err != nil {
		return err
	}
	if err := r.copy(r.path+restoreRollbackExt, r.path); err != nil {
		return err
	}
	if err := VerifyDatabaseFile(r.path); err != nil {
		return err
	}
	j.Phase = "rolled_back"
	if err := r.writeJournal(j); err != nil {
		return err
	}
	return r.cleanup(j)
}

func (r *restoreOperation) confirm() error {
	j, err := r.readJournal()
	if err != nil || j == nil {
		return err
	}
	switch j.Phase {
	case "applying":
		if err = VerifyDatabaseFile(r.path); err != nil {
			return err
		}
		j.Phase = "confirmed"
		if err = r.writeJournal(j); err != nil {
			return err
		}
	case "confirmed", "complete":
	default:
		return errors.New("restore cannot be confirmed before application startup")
	}
	return r.finalize(j)
}

func (r *restoreOperation) finalize(j *restoreJournal) error {
	if err := VerifyDatabaseFile(r.path); err != nil {
		return fmt.Errorf("restored database is unusable; preserve recovery files: %w", err)
	}
	if j.Phase == "confirmed" {
		if j.HadOld {
			if err := verifyRestoreHash(r.path+restoreRollbackExt, j.OldHash); err != nil {
				return err
			}
			if err := r.sidecars(r.path + restorePreviousExt); err != nil {
				return err
			}
			if err := r.copy(r.path+restoreRollbackExt, r.path+restorePreviousExt); err != nil {
				return err
			}
		}
		j.Phase = "complete"
		if err := r.writeJournal(j); err != nil {
			return err
		}
	}
	return r.cleanup(j)
}

func (r *restoreOperation) cleanup(j *restoreJournal) error {
	if err := VerifyDatabaseFile(r.path); err != nil {
		return err
	}
	if j.Phase == "complete" && j.HadOld {
		if err := verifyRestoreHash(r.path+restorePreviousExt, j.OldHash); err != nil {
			return err
		}
	}
	if err := r.removePending(); err != nil {
		return err
	}
	for _, ext := range []string{restoreCandidateExt, restoreRollbackExt} {
		if err := r.sidecars(r.path + ext); err != nil {
			return err
		}
		if err := r.remove(r.path + ext); err != nil {
			return err
		}
	}
	// Persist cleanup before removing its recovery record. Missing snapshots are
	// allowed only in terminal phases where the live generation already verifies.
	if err := r.syncDir(); err != nil {
		return err
	}
	if err := r.remove(r.path + restoreJournalExt); err != nil {
		return err
	}
	return r.syncDir()
}

func (r *restoreOperation) removePending() error {
	if err := r.sidecars(r.path + restorePendingExt); err != nil {
		return err
	}
	if err := r.remove(r.path + restorePendingExt); err != nil {
		return err
	}
	return r.syncDir()
}

func (r *restoreOperation) sidecars(path string) error {
	for _, ext := range []string{"-wal", "-shm"} {
		if err := r.remove(path + ext); err != nil {
			return err
		}
	}
	return r.syncDir()
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyRestoreHash(path, want string) error {
	got, err := fileHash(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("restore snapshot %s changed; preserve recovery files", path)
	}
	return VerifyDatabaseFile(path)
}

func (r *restoreOperation) snapshot(source, destination string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	temp, err := os.CreateTemp(filepath.Dir(r.path), filepath.Base(r.path)+".restore-partial-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if err = temp.Close(); err != nil {
		return err
	}
	defer os.Remove(name)
	defer removeSidecars(name)
	db, err := sql.Open(driverName, readOnlyURI(source))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "VACUUM INTO ?", name)
	closeErr := db.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Chmod(name, backupFileMode); err != nil {
		return err
	}
	if err = VerifyDatabaseFile(name); err != nil {
		return err
	}
	if err = r.files.syncFile(name); err != nil {
		return err
	}
	if err = r.files.after("snapshot-sync"); err != nil {
		return err
	}
	return r.rename(name, destination)
}

func (r *restoreOperation) copy(source, destination string) error {
	return r.atomicWrite(destination, func(f *os.File) error {
		src, err := os.Open(source)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(f, src)
		return err
	})
}

func (r *restoreOperation) writeJournal(j *restoreJournal) error {
	return r.atomicWrite(r.path+restoreJournalExt, func(f *os.File) error { return json.NewEncoder(f).Encode(j) })
}

func (r *restoreOperation) atomicWrite(destination string, write func(*os.File) error) error {
	f, err := os.CreateTemp(filepath.Dir(r.path), filepath.Base(r.path)+".restore-partial-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = write(f); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = r.files.syncFile(name); err != nil {
		return err
	}
	if err = r.files.after("file-sync:" + filepath.Base(destination)); err != nil {
		return err
	}
	return r.rename(name, destination)
}

func (r *restoreOperation) rename(from, to string) error {
	if err := r.files.rename(from, to); err != nil {
		return err
	}
	if err := r.files.after("rename:" + filepath.Base(to)); err != nil {
		return err
	}
	return r.syncDir()
}

func (r *restoreOperation) syncDir() error {
	if err := r.files.syncDir(filepath.Dir(r.path)); err != nil {
		return err
	}
	return r.files.after("directory-sync")
}

func (r *restoreOperation) remove(path string) error {
	if err := r.files.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return r.files.after("remove:" + filepath.Base(path))
}

// A killed process can leave only unpublished temporary files. These names
// belong to this database, never to another database in the same directory.
func (r *restoreOperation) clearPartials() error {
	entries, err := os.ReadDir(filepath.Dir(r.path))
	if err != nil {
		return err
	}
	prefix := filepath.Base(r.path) + ".restore-partial-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			if err := r.remove(filepath.Join(filepath.Dir(r.path), entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
