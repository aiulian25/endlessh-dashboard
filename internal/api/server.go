// Package api is the transport layer: it parses requests, calls the domain
// services, and renders JSON. No business rules and no SQL live here.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"endlessh-dashboard/internal/auth"
	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

const (
	SessionCookieName = "endlessh_session"
	CSRFHeaderName    = "X-CSRF-Token"

	maxRequestBodyBytes = 1 << 20
	maxUploadBytes      = 512 << 20
)

// Windows the UI offers, with the bucket width each one aggregates to. Wider
// windows use wider buckets so a chart never has to draw thousands of points.
var windows = map[string]struct {
	Duration      time.Duration
	BucketSeconds int
}{
	"24h": {24 * time.Hour, 300},
	"7d":  {7 * 24 * time.Hour, 3600},
	"30d": {30 * 24 * time.Hour, 21600},
	"90d": {90 * 24 * time.Hour, 86400},
}

const defaultWindow = "24h"

type Server struct {
	config      *config.Config
	store       *store.Store
	auth        *auth.Service
	registry    *registry.Service
	backups     *store.BackupManager
	geoResolver *geo.Resolver
	prober      Prober
	logger      *slog.Logger
	version     string
	restart     chan<- struct{}
}

func NewServer(
	configuration *config.Config,
	dataStore *store.Store,
	authService *auth.Service,
	registryService *registry.Service,
	backupManager *store.BackupManager,
	geoResolver *geo.Resolver,
	prober Prober,
	logger *slog.Logger,
	version string,
	restart chan<- struct{},
) *Server {
	return &Server{
		config:      configuration,
		store:       dataStore,
		auth:        authService,
		registry:    registryService,
		backups:     backupManager,
		geoResolver: geoResolver,
		prober:      prober,
		logger:      logger,
		version:     version,
		restart:     restart,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.Handle("POST /api/login", s.public(s.handleLogin))
	mux.Handle("POST /api/logout", s.protected(s.handleLogout))
	mux.Handle("GET /api/session", s.protected(s.handleSession))
	mux.Handle("POST /api/password", s.protected(s.handleChangePassword))

	mux.Handle("GET /api/machines", s.protected(s.handleListMachines))
	mux.Handle("POST /api/machines", s.protected(s.handleCreateMachine))
	mux.Handle("POST /api/machines/test", s.protected(s.handleTestMachine))
	mux.Handle("PUT /api/machines/{id}", s.protected(s.handleUpdateMachine))
	mux.Handle("PUT /api/machines/order", s.protected(s.handleReorderMachines))
	mux.Handle("DELETE /api/machines/{id}", s.protected(s.handleDeleteMachine))

	mux.Handle("GET /api/overview", s.protected(s.handleOverview))
	mux.Handle("GET /api/timeseries", s.protected(s.handleTimeSeries))
	mux.Handle("GET /api/attackers", s.protected(s.handleAttackers))
	mux.Handle("GET /api/attackers/countries", s.protected(s.handleAttackerCountries))
	mux.Handle("GET /api/geo/points", s.protected(s.handleGeoPoints))
	mux.Handle("GET /api/geo/countries", s.protected(s.handleGeoCountries))

	mux.Handle("GET /api/backups", s.protected(s.handleListBackups))
	mux.Handle("POST /api/backups", s.protected(s.handleCreateBackup))
	mux.Handle("GET /api/backups/{name}", s.protected(s.handleDownloadBackup))
	mux.Handle("POST /api/backups/{name}/restore", s.protected(s.handleRestoreBackup))
	mux.Handle("DELETE /api/backups/{name}", s.protected(s.handleDeleteBackup))
	mux.Handle("POST /api/backups/upload", s.protected(s.handleUploadBackup))

	mux.Handle("GET /api/settings", s.protected(s.handleSettings))

	mux.Handle("/", s.staticHandler())

	return s.recoverPanics(s.logRequests(s.securityHeaders(mux)))
}

func (s *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		return
	}
}

type errorResponse struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, errorResponse{Error: message})
}

func writeFieldError(writer http.ResponseWriter, status int, field, message string) {
	writeJSON(writer, status, errorResponse{Error: message, Field: field})
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "could not read the request: "+err.Error())
		return false
	}
	return true
}

// resolveMachines turns the ?machines= parameter into the machines to report
// on, defaulting to every enabled machine.
func (s *Server) resolveMachines(request *http.Request) ([]store.Machine, error) {
	all, err := s.registry.List(request.Context())
	if err != nil {
		return nil, err
	}

	raw := strings.TrimSpace(request.URL.Query().Get("machines"))
	if raw == "" {
		enabled := make([]store.Machine, 0, len(all))
		for _, machine := range all {
			if machine.Enabled {
				enabled = append(enabled, machine)
			}
		}
		return enabled, nil
	}

	// An id matching no machine selects no machine, and the dashboard depends on
	// that: it sends machines=0 to say the operator deselected everything, since
	// an empty parameter would mean "not specified" and report on all of them.
	// What makes 0 unmatchable is that the machines table autoincrements from 1
	// (0001_init.sql), asserted by TestMachineCRUD. Ids starting anywhere else
	// would turn "none" into "one" here, silently — see NO_MACHINES in web/app.js.
	wanted := map[int64]bool{}
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		id, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			continue
		}
		wanted[id] = true
	}

	selected := make([]store.Machine, 0, len(wanted))
	for _, machine := range all {
		if wanted[machine.ID] {
			selected = append(selected, machine)
		}
	}
	return selected, nil
}

func machineIDs(machines []store.Machine) []int64 {
	ids := make([]int64, len(machines))
	for index, machine := range machines {
		ids[index] = machine.ID
	}
	return ids
}

func resolveWindow(request *http.Request) (time.Duration, int) {
	name := strings.TrimSpace(request.URL.Query().Get("window"))
	window, ok := windows[name]
	if !ok {
		window = windows[defaultWindow]
	}
	return window.Duration, window.BucketSeconds
}

func pathID(request *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
