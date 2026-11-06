package api

import (
	"encoding/json"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func TestMachinePayloadIncludesEndpointBoundary(t *testing.T) {
	changed := time.Date(2026, 11, 5, 12, 0, 0, 123, time.UTC)
	encoded, err := json.Marshal(toMachineResponse(store.Machine{TargetChangedAt: &changed}, 0, nil, 30))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		TargetChangedAt *time.Time `json:"target_changed_at"`
	}
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TargetChangedAt == nil || !decoded.TargetChangedAt.Equal(changed) {
		t.Fatalf("missing endpoint boundary: %s", encoded)
	}
}
