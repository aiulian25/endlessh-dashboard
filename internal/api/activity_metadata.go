package api

import (
	"time"

	"endlessh-dashboard/internal/store"
)

// Activity metadata describes the existing sampled-IP heuristic, independently
// of the selected historical window. No session/disconnect count is inferred.
type activityMetadata struct {
	ThresholdSeconds    float64    `json:"threshold_seconds"`
	EvaluatedAt         time.Time  `json:"evaluated_at"`
	OldestSuccessAt     *time.Time `json:"oldest_success_at"`
	NewestSuccessAt     *time.Time `json:"newest_success_at"`
	UnobservedMachines  int        `json:"unobserved_machines"`
	FailedLatestScrapes int        `json:"failed_latest_scrapes"`
	DisabledMachines    int        `json:"disabled_machines"`
}

func (s *Server) activityMetadata(machines []store.Machine, now time.Time) activityMetadata {
	result := activityMetadata{ThresholdSeconds: s.config.StaleClientThreshold().Seconds(), EvaluatedAt: now}
	for _, machine := range machines {
		if !machine.Enabled {
			result.DisabledMachines++
		}
		if machine.ConsecutiveFailures > 0 {
			result.FailedLatestScrapes++
		}
		if machine.LastOKAt == nil {
			result.UnobservedMachines++
			continue
		}
		if result.OldestSuccessAt == nil || machine.LastOKAt.Before(*result.OldestSuccessAt) {
			result.OldestSuccessAt = machine.LastOKAt
		}
		if result.NewestSuccessAt == nil || machine.LastOKAt.After(*result.NewestSuccessAt) {
			result.NewestSuccessAt = machine.LastOKAt
		}
	}
	return result
}
