package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/scrape"
)

// Prober performs a single trial scrape of a candidate target. The poller
// implements it, so the connection test exercises the same code path a real
// scrape takes rather than a lookalike.
type Prober interface {
	Probe(ctx context.Context, host string, port int, metricsPath string) (scrape.ProbeSummary, error)
}

type probeResponse struct {
	Reachable        bool                          `json:"reachable"`
	ExpositionValid  bool                          `json:"exposition_valid"`
	EndlesshEvidence string                        `json:"endlessh_evidence"`
	MetricFamilies   []scrape.MetricFamilyEvidence `json:"metric_families"`
	Address          string                        `json:"address"`
	Clients          int                           `json:"clients"`
	LocalPorts       []string                      `json:"local_ports"`
	Connections      int64                         `json:"connections"`
	TrappedSeconds   float64                       `json:"trapped_seconds"`
	GeoIPEnabled     bool                          `json:"geoip_enabled"`
	Message          string                        `json:"message"`
}

// handleTestMachine reports reachability and sample compatibility before saving;
// an inconclusive endpoint is not treated as verified product identity.
func (s *Server) handleTestMachine(writer http.ResponseWriter, request *http.Request) {
	var payload machineRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}

	input := payload.toInput()
	input.Normalize()

	validator := s.registry.Validator()
	if err := validator.ValidateTarget(input); err != nil {
		var validationError *registry.ValidationError
		if errors.As(err, &validationError) {
			writeFieldError(writer, http.StatusBadRequest, validationError.Field, validationError.Message)
			return
		}
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}

	summary, err := s.prober.Probe(request.Context(), input.Host, input.Port, input.MetricsPath)
	if err != nil {
		var validationError *registry.ValidationError
		if errors.As(err, &validationError) {
			writeFieldError(writer, http.StatusBadRequest, validationError.Field, validationError.Message)
			return
		}
		writeJSON(writer, http.StatusBadGateway, struct {
			errorResponse
			Reachable        bool   `json:"reachable"`
			ExpositionValid  bool   `json:"exposition_valid"`
			EndlesshEvidence string `json:"endlessh_evidence"`
		}{errorResponse: errorResponse{Error: probeFailureMessage(input, err), Field: "host"}, Reachable: summary.Reachable, EndlesshEvidence: "unavailable"})
		return
	}

	// A nil probe error means the bounded body passed the shared parser.
	summary.Reachable, summary.ExpositionValid = true, true
	if summary.MetricFamilies == nil {
		summary.MetricFamilies = []scrape.MetricFamilyEvidence{}
	}
	writeJSON(writer, http.StatusOK, probeResponse{
		Reachable:        summary.Reachable,
		ExpositionValid:  summary.ExpositionValid,
		EndlesshEvidence: summary.EvidenceState(),
		MetricFamilies:   summary.MetricFamilies,
		Address:          summary.Address,
		Clients:          summary.Clients,
		LocalPorts:       summary.LocalPorts,
		Connections:      summary.Connections,
		TrappedSeconds:   summary.TrappedSeconds,
		GeoIPEnabled:     summary.GeoIPEnabled,
		Message:          probeSuccessMessage(summary),
	})
}

func probeSuccessMessage(summary scrape.ProbeSummary) string {
	var message strings.Builder
	message.WriteString("Reachable metrics endpoint")
	if summary.Address != "" {
		message.WriteString(" at " + summary.Address)
	}
	message.WriteString(". ")
	if len(summary.MetricFamilies) == 0 {
		message.WriteString("No Endlessh samples yet; result is inconclusive. A fresh exporter and an unrelated metrics service can look the same. Check the target; saving is still allowed.")
		return message.String()
	}
	message.WriteString(fmt.Sprintf("Supported Endlessh metric samples found (%d of 6 families; %s evidence). ", len(summary.MetricFamilies), summary.EvidenceState()))
	if len(summary.LocalPorts) > 0 {
		message.WriteString("Reported local ports: " + strings.Join(summary.LocalPorts, ", ") + ". ")
	}
	message.WriteString(fmt.Sprintf("%d distinct IPs in the current metrics; cumulative samples do not establish active sessions. ", summary.Clients))
	if summary.GeoIPEnabled {
		message.WriteString("Country labels observed.")
	} else {
		message.WriteString("No usable country labels observed.")
	}
	return message.String()
}

// probeFailureMessage turns a transport error into something worth reading,
// naming the most likely cause for the shapes we can recognise.
func probeFailureMessage(input registry.MachineInput, err error) string {
	target := fmt.Sprintf("%s:%d%s", input.Host, input.Port, input.MetricsPath)
	reason := err.Error()

	switch {
	case strings.Contains(reason, "connection refused"):
		return fmt.Sprintf("Nothing is listening on %s. Check that endlessh-go runs with -prometheus_enabled and that port %d is published.", target, input.Port)
	case strings.Contains(reason, "context deadline exceeded"), strings.Contains(reason, "timeout"):
		return fmt.Sprintf("No answer from %s before the timeout. A firewall dropping the connection looks most likely.", target)
	case strings.Contains(reason, "no such host"):
		return fmt.Sprintf("The name %q does not resolve.", input.Host)
	case strings.Contains(reason, "returned "):
		return fmt.Sprintf("%s answered, but not with metrics: %s. Check the metrics path.", target, reason)
	case strings.Contains(reason, "metric "), strings.Contains(reason, "metrics response"), strings.Contains(reason, "read metrics"):
		return fmt.Sprintf("%s answered, but its metrics were not accepted: %s.", target, reason)
	case strings.Contains(reason, "parse metrics"):
		return fmt.Sprintf("%s answered, but the response is not Prometheus metrics. Is this really an endlessh-go metrics endpoint?", target)
	}
	return fmt.Sprintf("Connection test for %s failed: %s", target, reason)
}
