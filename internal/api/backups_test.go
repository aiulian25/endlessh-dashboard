package api

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
)

// pendingRestoreExt mirrors restorePendingExt in internal/store: the name of the
// staged file the next start looks for. It is unexported there, so the contract
// is restated here rather than reached into.
const pendingRestoreExt = ".restore"

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
