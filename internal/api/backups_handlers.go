package api

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"endlessh-dashboard/internal/store"
)

const restoreUploadField = "backup"

type backupResponse struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func (s *Server) handleListBackups(writer http.ResponseWriter, request *http.Request) {
	backups, err := s.backups.List()
	if err != nil {
		s.logger.Error("list backups", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not read the backup folder")
		return
	}

	payload := make([]backupResponse, 0, len(backups))
	for _, backup := range backups {
		payload = append(payload, backupResponse(backup))
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleCreateBackup(writer http.ResponseWriter, request *http.Request) {
	backup, err := s.backups.Create(request.Context())
	if err != nil {
		s.logger.Error("create backup", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not create the backup")
		return
	}
	writeJSON(writer, http.StatusCreated, backupResponse(backup))
}

func (s *Server) handleDownloadBackup(writer http.ResponseWriter, request *http.Request) {
	path, err := s.backups.Path(request.PathValue("name"))
	if s.writeBackupError(writer, err) {
		return
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(path)+`"`)
	http.ServeFile(writer, request, path)
}

func (s *Server) handleDeleteBackup(writer http.ResponseWriter, request *http.Request) {
	if err := s.backups.Delete(request.PathValue("name")); s.writeBackupError(writer, err) {
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// handleRestoreBackup stages the chosen snapshot and asks the process to stop.
// The swap happens at the next start, when nothing holds the database open.
func (s *Server) handleRestoreBackup(writer http.ResponseWriter, request *http.Request) {
	if err := s.backups.StageRestore(request.PathValue("name")); s.writeBackupError(writer, err) {
		return
	}
	s.requestRestart()
	writeJSON(writer, http.StatusAccepted, messageResponse{
		Message: "Restore staged. The dashboard is restarting and will come back with the restored data.",
	})
}

// handleUploadBackup streams the upload with MultipartReader rather than
// FormFile: FormFile spills anything over 32 MiB into os.TempDir(), which does
// not exist as a writable path under the read-only container filesystem, and a
// database backup is easily larger than that.
func (s *Server) handleUploadBackup(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxUploadBytes)

	reader, err := request.MultipartReader()
	if err != nil {
		writeError(writer, http.StatusBadRequest, "send the backup as a multipart form upload")
		return
	}

	var (
		file     io.Reader
		filename string
	)
	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			writeError(writer, http.StatusBadRequest, "could not read the upload: "+partErr.Error())
			return
		}
		if part.FormName() == restoreUploadField {
			file = part
			filename = part.FileName()
			break
		}
		part.Close()
	}
	if file == nil {
		writeError(writer, http.StatusBadRequest, "attach a backup file to restore in the \""+restoreUploadField+"\" field")
		return
	}

	if err := s.backups.StageRestoreFromReader(file); err != nil {
		s.logger.Warn("rejected uploaded backup", "filename", filename, "error", err)
		writeError(writer, http.StatusBadRequest, "that file was rejected: "+err.Error())
		return
	}
	s.requestRestart()
	writeJSON(writer, http.StatusAccepted, messageResponse{
		Message: "Upload accepted. The dashboard is restarting and will come back with the restored data.",
	})
}

func (s *Server) requestRestart() {
	select {
	case s.restart <- struct{}{}:
	default:
	}
}

func (s *Server) writeBackupError(writer http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrInvalidBackupName) {
		writeError(writer, http.StatusBadRequest, "that backup name is not valid")
		return true
	}
	if errors.Is(err, store.ErrBackupNotFound) {
		writeError(writer, http.StatusNotFound, "that backup no longer exists")
		return true
	}
	// Downgrading the image and then restoring a backup the newer one left
	// behind is the way to arrive here, and the version numbers are the only
	// useful thing to say about it.
	if errors.Is(err, store.ErrDatabaseTooNew) {
		writeError(writer, http.StatusConflict, err.Error())
		return true
	}
	s.logger.Error("backup operation", "error", err)
	writeError(writer, http.StatusInternalServerError, "the backup operation failed")
	return true
}
