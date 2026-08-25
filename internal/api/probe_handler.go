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
	Address        string   `json:"address"`
	Clients        int      `json:"clients"`
	LocalPorts     []string `json:"local_ports"`
	Connections    int64    `json:"connections"`
	TrappedSeconds float64  `json:"trapped_seconds"`
	GeoIPEnabled   bool     `json:"geoip_enabled"`
	Message        string   `json:"message"`
}

// handleTestMachine answers "would this target actually work?" before a machine
// is saved, so a dead or mistyped host is caught at the point of typing rather
// than becoming a red row on the Machines page.
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
		writeFieldError(writer, http.StatusBadGateway, "host", probeFailureMessage(input, err))
		return
	}

	writeJSON(writer, http.StatusOK, probeResponse{
		Address:        summary.Address,
		Clients:        summary.Clients,
		LocalPorts:     summary.LocalPorts,
		Connections:    summary.Connections,
		TrappedSeconds: summary.TrappedSeconds,
		GeoIPEnabled:   summary.GeoIPEnabled,
		Message:        probeSuccessMessage(summary),
	})
}

func probeSuccessMessage(summary scrape.ProbeSummary) string {
	var message strings.Builder
	message.WriteString("Reached endlessh-go")
	if summary.Address != "" {
		message.WriteString(" at " + summary.Address)
	}
	if len(summary.LocalPorts) > 0 {
		message.WriteString(", trapping on port " + strings.Join(summary.LocalPorts, ", "))
	}
	message.WriteString(". ")

	switch {
	case summary.Clients == 1:
		message.WriteString("1 attacker is currently in its metrics")
	case summary.Clients > 1:
		message.WriteString(fmt.Sprintf("%d attackers are currently in its metrics", summary.Clients))
	default:
		message.WriteString("No attackers recorded there yet, which is normal for a fresh tarpit")
	}
	if summary.Clients > 0 && !summary.GeoIPEnabled {
		message.WriteString(", with GeoIP off so country and location will be blank")
	}
	message.WriteString(".")
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
	case strings.Contains(reason, "parse metrics"):
		return fmt.Sprintf("%s answered, but the response is not Prometheus metrics. Is this really an endlessh-go metrics endpoint?", target)
	}
	return fmt.Sprintf("Could not reach %s: %s", target, reason)
}
