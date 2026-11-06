package api

import (
	"endlessh-dashboard/internal/store"
	"net/http"
)

func readPort(w http.ResponseWriter, r *http.Request) (string, bool) {
	values, exists := r.URL.Query()["port"]
	if !exists {
		return "", true
	}
	if len(values) != 1 || store.ValidatePort(values[0]) != nil {
		writeFieldError(w, http.StatusBadRequest, "port", "port must be 1..65535 in canonical form, or unknown for an absent label")
		return "", false
	}
	return values[0], true
}

// Port summaries are deliberately separate from IP/activity summaries: the
// exporter aggregate port counters cannot attribute distinct IPs or sessions.
func (s *Server) handlePortSummary(w http.ResponseWriter, r *http.Request) {
	port, ok := readPort(w, r)
	if !ok {
		return
	}
	machines, err := s.resolveMachines(r)
	if err != nil {
		writeError(w, 500, "could not load the machine list")
		return
	}
	span, _, ok := readTimeRange(w, r)
	if !ok {
		return
	}
	summary, err := s.store.PortSummary(r.Context(), machineIDs(machines), span.From, span.To, port)
	if err != nil {
		s.logger.Error("port summary", "error", err)
		writeError(w, 500, "could not load port data")
		return
	}
	writeJSON(w, 200, summary)
}
