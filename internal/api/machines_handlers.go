package api

import (
	"errors"
	"net/http"
	"time"

	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

const (
	statusOK       = "ok"
	statusDegraded = "degraded"
	statusDown     = "down"
	statusDisabled = "disabled"

	// degradedAfterFailures is the point where a machine stops being a blip and
	// starts being a problem worth showing in red.
	degradedAfterFailures = 1
	downAfterFailures     = 3

	// The sidebar sparkline draws the last hour as twelve five-minute buckets.
	activityBuckets       = 12
	activityBucketSeconds = 300
)

type machineResponse struct {
	ID                  int64      `json:"id"`
	Name                string     `json:"name"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	MetricsPath         string     `json:"metrics_path"`
	GroupLabel          string     `json:"group_label"`
	Enabled             bool       `json:"enabled"`
	Status              string     `json:"status"`
	LastScrapeAt        *time.Time `json:"last_scrape_at"`
	LastOKAt            *time.Time `json:"last_ok_at"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           string     `json:"last_error"`
	TrappedNow          int        `json:"trapped_now"`
	Activity            []float64  `json:"activity"`
	Colour              string     `json:"colour"`
}

type machineRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	MetricsPath string `json:"metrics_path"`
	GroupLabel  string `json:"group_label"`
	Enabled     *bool  `json:"enabled"`
	Colour      string `json:"colour"`
}

func (r machineRequest) toInput() registry.MachineInput {
	enabled := true
	if r.Enabled != nil {
		enabled = *r.Enabled
	}
	return registry.MachineInput{
		Name:        r.Name,
		Host:        r.Host,
		Port:        r.Port,
		MetricsPath: r.MetricsPath,
		GroupLabel:  r.GroupLabel,
		Enabled:     enabled,
		Colour:      r.Colour,
	}
}

// maxMachineOrderIDs bounds the reorder payload. The sidebar can only hold as
// many machines as are registered, so a list far longer than any plausible
// install is not an order — it is someone seeing how much work one request can
// make the database do.
const maxMachineOrderIDs = 1000

type machineOrderRequest struct {
	MachineIDs []int64 `json:"machine_ids"`
}

// handleReorderMachines stores the sidebar order. It changes no scrape target
// and no credential — the worst a malformed body can do is arrange the list
// badly, which the operator can drag back.
func (s *Server) handleReorderMachines(writer http.ResponseWriter, request *http.Request) {
	var payload machineOrderRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}
	if len(payload.MachineIDs) > maxMachineOrderIDs {
		writeError(writer, http.StatusBadRequest, "that is more machines than this dashboard can hold")
		return
	}
	if err := s.registry.Reorder(request.Context(), payload.MachineIDs); err != nil {
		s.logger.Error("reorder machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not save the machine order")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListMachines(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.registry.List(request.Context())
	if err != nil {
		s.logger.Error("list machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	now := time.Now().UTC()
	trappedNow, err := s.store.TrappedNowByMachine(request.Context(), now.Add(-s.config.StaleClientThreshold()))
	if err != nil {
		s.logger.Error("count trapped clients", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load machine activity")
		return
	}

	activity, err := s.store.RecentActivityByMachine(request.Context(), now, activityBucketSeconds, activityBuckets)
	if err != nil {
		s.logger.Error("recent machine activity", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load machine activity")
		return
	}

	responses := make([]machineResponse, 0, len(machines))
	for _, machine := range machines {
		responses = append(responses, toMachineResponse(machine, trappedNow[machine.ID], activity[machine.ID]))
	}
	writeJSON(writer, http.StatusOK, responses)
}

func (s *Server) handleCreateMachine(writer http.ResponseWriter, request *http.Request) {
	var payload machineRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}

	machine, err := s.registry.Create(request.Context(), payload.toInput())
	if s.writeRegistryError(writer, err, "could not add the machine") {
		return
	}
	writeJSON(writer, http.StatusCreated, toMachineResponse(machine, 0, nil))
}

func (s *Server) handleUpdateMachine(writer http.ResponseWriter, request *http.Request) {
	id, ok := pathID(request)
	if !ok {
		writeError(writer, http.StatusBadRequest, "that machine id is not valid")
		return
	}

	var payload machineRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}

	machine, err := s.registry.Update(request.Context(), id, payload.toInput())
	if s.writeRegistryError(writer, err, "could not update the machine") {
		return
	}
	writeJSON(writer, http.StatusOK, toMachineResponse(machine, 0, nil))
}

func (s *Server) handleDeleteMachine(writer http.ResponseWriter, request *http.Request) {
	id, ok := pathID(request)
	if !ok {
		writeError(writer, http.StatusBadRequest, "that machine id is not valid")
		return
	}

	err := s.registry.Delete(request.Context(), id)
	if s.writeRegistryError(writer, err, "could not delete the machine") {
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// writeRegistryError maps domain errors onto responses and reports whether it
// handled one, so each handler stays a straight line.
func (s *Server) writeRegistryError(writer http.ResponseWriter, err error, fallback string) bool {
	if err == nil {
		return false
	}

	var validationError *registry.ValidationError
	if errors.As(err, &validationError) {
		writeFieldError(writer, http.StatusBadRequest, validationError.Field, validationError.Message)
		return true
	}
	if errors.Is(err, store.ErrMachineNotFound) {
		writeError(writer, http.StatusNotFound, "that machine no longer exists")
		return true
	}

	s.logger.Error("machine registry", "error", err)
	writeError(writer, http.StatusInternalServerError, fallback)
	return true
}

func toMachineResponse(machine store.Machine, trappedNow int, activity []float64) machineResponse {
	return machineResponse{
		ID:                  machine.ID,
		Name:                machine.Name,
		Host:                machine.Host,
		Port:                machine.Port,
		MetricsPath:         machine.MetricsPath,
		GroupLabel:          machine.GroupLabel,
		Enabled:             machine.Enabled,
		Status:              machineStatus(machine),
		LastScrapeAt:        machine.LastScrapeAt,
		LastOKAt:            machine.LastOKAt,
		ConsecutiveFailures: machine.ConsecutiveFailures,
		LastError:           machine.LastError,
		TrappedNow:          trappedNow,
		Activity:            denseActivity(activity),
		Colour:              machine.Colour,
	}
}

// denseActivity keeps the response contract the sparkline relies on: exactly
// activityBuckets numbers, never a nil slice — that would marshal to JSON null.
func denseActivity(activity []float64) []float64 {
	if len(activity) == activityBuckets {
		return activity
	}
	return make([]float64, activityBuckets)
}

func machineStatus(machine store.Machine) string {
	if !machine.Enabled {
		return statusDisabled
	}
	if machine.ConsecutiveFailures >= downAfterFailures {
		return statusDown
	}
	if machine.ConsecutiveFailures >= degradedAfterFailures {
		return statusDegraded
	}
	if machine.LastOKAt == nil {
		return statusDegraded
	}
	return statusOK
}
