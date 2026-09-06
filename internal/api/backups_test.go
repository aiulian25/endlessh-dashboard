package api

import (
	"bytes"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// pendingRestoreExt mirrors restorePendingExt in internal/store: the name of the
// staged file the next start looks for. It is unexported there, so the contract
// is restated here rather than reached into.
const pendingRestoreExt = ".restore"

// futureSchemaVersion is far enough ahead that no plausible number of real
// migrations reaches it, so this stays a test about the version gate rather than
// a counter to bump every time a migration is added.
const futureSchemaVersion = 9000

// databaseClaimingVersion rewrites a backup so it reports a schema this build
// does not carry — what a backup taken by a later image looks like from here.
func (h *harness) databaseClaimingVersion(content []byte, version int) []byte {
	h.t.Helper()
	path := filepath.Join(h.t.TempDir(), "from-the-future.db")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		h.t.Fatalf("write the database to rewrite: %v", err)
	}
	database, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		h.t.Fatalf("open the database to rewrite: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)", version); err != nil {
		database.Close()
		h.t.Fatalf("record a future migration: %v", err)
	}
	if err := database.Close(); err != nil {
		h.t.Fatalf("close the rewritten database: %v", err)
	}
	rewritten, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatalf("read the rewritten database: %v", err)
	}
	return rewritten
}

// uploadBackup posts a file the way the browser does: one multipart part named
// after restoreUploadField, with the boundary the client library chooses.
func (h *harness) uploadBackup(fieldName, filename string, content []byte) response {
	h.t.Helper()

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile(fieldName, filename)
	if err != nil {
		h.t.Fatalf("build the upload form: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		h.t.Fatalf("write the upload body: %v", err)
	}
	if err := form.Close(); err != nil {
		h.t.Fatalf("close the upload form: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, h.httpServer.URL+"/api/backups/upload", &body)
	if err != nil {
		h.t.Fatalf("build the upload request: %v", err)
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set(CSRFHeaderName, h.csrfToken)

	answer, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("POST /api/backups/upload: %v", err)
	}
	defer answer.Body.Close()

	raw, err := io.ReadAll(answer.Body)
	if err != nil {
		h.t.Fatalf("read the response of POST /api/backups/upload: %v", err)
	}
	return response{status: answer.StatusCode, body: raw, header: answer.Header, cookies: answer.Cookies()}
}

func (h *harness) restartWasRequested() bool {
	h.t.Helper()
	select {
	case <-h.restart:
		return true
	default:
		return false
	}
}

func (h *harness) stagedRestoreExists() bool {
	h.t.Helper()
	_, err := os.Stat(h.databasePath + pendingRestoreExt)
	return err == nil
}

// The round trip the backups page now offers: download a backup, then hand the
// same file back to restore from it. This is the only recovery path left when
// the server holds no backups of its own — a replaced volume — so it is worth
// exercising end to end rather than trusting each half separately.
func TestUploadedBackupIsStagedAndRestartsTheDashboard(t *testing.T) {
	testHarness := newSignedInHarness(t)

	created := testHarness.request(http.MethodPost, "/api/backups", nil)
	assertStatus(t, "POST /api/backups", created, http.StatusCreated)
	var backup backupResponse
	created.decode(t, &backup)

	downloaded := testHarness.request(http.MethodGet, "/api/backups/"+backup.Name, nil)
	assertStatus(t, "GET /api/backups/{name}", downloaded, http.StatusOK)
	if len(downloaded.body) == 0 {
		t.Fatal("the downloaded backup is empty")
	}

	if testHarness.stagedRestoreExists() {
		t.Fatal("a restore was staged before anything was uploaded")
	}

	answer := testHarness.uploadBackup(restoreUploadField, backup.Name, downloaded.body)
	assertStatus(t, "POST /api/backups/upload", answer, http.StatusAccepted)

	if !testHarness.stagedRestoreExists() {
		t.Error("the upload was accepted but no restore was staged for the next start")
	}
	if !testHarness.restartWasRequested() {
		t.Error("the upload was accepted but no restart was requested, so it would never be applied")
	}
}

// The important half of the feature is what it refuses. Anything can be dragged
// into a file picker, and a staged file becomes the whole database on the next
// start, so a file that is not a database must be rejected while the dashboard
// is still running and able to say so.
func TestUploadedBackupThatIsNotADatabaseIsRejectedAndStagesNothing(t *testing.T) {
	testHarness := newSignedInHarness(t)

	answer := testHarness.uploadBackup(restoreUploadField, "holiday.jpg", []byte("this is not a database"))
	assertStatus(t, "POST /api/backups/upload with a file that is not a database", answer, http.StatusBadRequest)

	if payload := answer.errorPayload(t); payload.Error == "" {
		t.Error("the upload was refused without saying why")
	}
	if testHarness.stagedRestoreExists() {
		t.Error("a file that is not a database was staged to replace the live one")
	}
	if testHarness.restartWasRequested() {
		t.Error("a rejected upload asked the dashboard to restart")
	}

	// The dashboard is still usable: a refusal is not an outage.
	assertStatus(t, "GET /api/backups after a refused upload",
		testHarness.request(http.MethodGet, "/api/backups", nil), http.StatusOK)
}

// A part under any other name is not the backup, and reading it as one would
// mean restoring from whatever a stray form field happened to carry.
func TestUploadedBackupUnderTheWrongFieldNameIsRejected(t *testing.T) {
	testHarness := newSignedInHarness(t)

	answer := testHarness.uploadBackup("file", "endlessh.db", []byte("SQLite format 3\x00"))
	assertStatus(t, "POST /api/backups/upload under the wrong field name", answer, http.StatusBadRequest)

	if testHarness.stagedRestoreExists() {
		t.Error("a part sent under the wrong field name was staged as the database")
	}
}

// Downgrading the image and then restoring a backup the newer one left behind
// is an easy mistake to make with two instances, and the file looks perfectly
// healthy: it is a real database, it passes its integrity check, and it is ours.
// Only its schema version gives it away, and the dashboard has to say so while
// it can still be read — after the swap there is no shell to undo it with.
func TestUploadedBackupFromANewerReleaseIsRefusedWithItsVersions(t *testing.T) {
	testHarness := newSignedInHarness(t)

	created := testHarness.request(http.MethodPost, "/api/backups", nil)
	assertStatus(t, "POST /api/backups", created, http.StatusCreated)
	var backup backupResponse
	created.decode(t, &backup)

	downloaded := testHarness.request(http.MethodGet, "/api/backups/"+backup.Name, nil)
	assertStatus(t, "GET /api/backups/{name}", downloaded, http.StatusOK)

	fromTheFuture := testHarness.databaseClaimingVersion(downloaded.body, futureSchemaVersion)
	answer := testHarness.uploadBackup(restoreUploadField, backup.Name, fromTheFuture)
	assertStatus(t, "POST /api/backups/upload from a newer release", answer, http.StatusBadRequest)

	// The numbers are the explanation. Without them the operator is told only
	// that something was wrong with a file that looks fine.
	message := answer.errorPayload(t).Error
	if !strings.Contains(message, strconv.Itoa(futureSchemaVersion)) {
		t.Errorf("refusal = %q, want it to name the schema version it found", message)
	}

	if testHarness.stagedRestoreExists() {
		t.Error("a database from a newer release was staged to replace the live one")
	}
	if testHarness.restartWasRequested() {
		t.Error("a refused upload asked the dashboard to restart")
	}
	assertStatus(t, "GET /api/backups after a refused upload",
		testHarness.request(http.MethodGet, "/api/backups", nil), http.StatusOK)
}

// The same file, reached the other way: already sitting in /data/backups because
// a newer image put it there. That path reports through writeBackupError, which
// turns anything it does not recognise into "the backup operation failed" — a
// message that would send the operator to the container logs to find out why.
func TestRestoringALocalBackupFromANewerReleaseSaysWhy(t *testing.T) {
	testHarness := newSignedInHarness(t)

	created := testHarness.request(http.MethodPost, "/api/backups", nil)
	assertStatus(t, "POST /api/backups", created, http.StatusCreated)
	var backup backupResponse
	created.decode(t, &backup)

	downloaded := testHarness.request(http.MethodGet, "/api/backups/"+backup.Name, nil)
	assertStatus(t, "GET /api/backups/{name}", downloaded, http.StatusOK)

	// Rewrite the stored backup in place, as a newer image would have left it.
	backupPath := filepath.Join(filepath.Dir(testHarness.databasePath), "backups", backup.Name)
	fromTheFuture := testHarness.databaseClaimingVersion(downloaded.body, futureSchemaVersion)
	if err := os.WriteFile(backupPath, fromTheFuture, 0o600); err != nil {
		t.Fatalf("rewrite the stored backup: %v", err)
	}

	answer := testHarness.request(http.MethodPost, "/api/backups/"+backup.Name+"/restore", nil)
	assertStatus(t, "POST /api/backups/{name}/restore from a newer release", answer, http.StatusConflict)

	message := answer.errorPayload(t).Error
	if !strings.Contains(message, strconv.Itoa(futureSchemaVersion)) {
		t.Errorf("refusal = %q, want it to name the schema version it found", message)
	}
	if testHarness.stagedRestoreExists() {
		t.Error("a backup from a newer release was staged to replace the live one")
	}
}

// "Back up now" is a button, and buttons get clicked twice. Backup names carry
// one second, so the second click asks for the file the first one just wrote.
// It has to come back as the backup it is, not as a failure — an operator told
// "could not create the backup" while looking at a backup that exists has been
// told something untrue about their own data.
func TestBackingUpTwiceInOneSecondIsNotAnError(t *testing.T) {
	testHarness := newSignedInHarness(t)

	// Just after a tick, so both requests fall inside the same second.
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(time.Second)))

	first := testHarness.request(http.MethodPost, "/api/backups", nil)
	assertStatus(t, "POST /api/backups", first, http.StatusCreated)
	second := testHarness.request(http.MethodPost, "/api/backups", nil)
	assertStatus(t, "POST /api/backups a second time", second, http.StatusCreated)

	var firstBackup, secondBackup backupResponse
	first.decode(t, &firstBackup)
	second.decode(t, &secondBackup)
	if firstBackup.Name != secondBackup.Name {
		t.Skipf("the two requests straddled a second boundary (%s, %s); nothing to assert",
			firstBackup.Name, secondBackup.Name)
	}
	if secondBackup.Size != firstBackup.Size {
		t.Errorf("second response size = %d, want the existing backup's %d",
			secondBackup.Size, firstBackup.Size)
	}

	// And the list shows one backup, not two entries for one file.
	listed := testHarness.request(http.MethodGet, "/api/backups", nil)
	assertStatus(t, "GET /api/backups", listed, http.StatusOK)
	var backups []backupResponse
	listed.decode(t, &backups)
	if len(backups) != 1 {
		t.Errorf("backups listed = %d, want 1", len(backups))
	}
}
