package api

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONEncodingFailureReturnsControlledError(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1)} {
		response := httptest.NewRecorder()
		writeJSON(response, http.StatusOK, map[string]float64{"time": bad})
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", response.Code)
		}
		var payload errorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Error != "could not encode response" {
			t.Fatalf("uncontrolled error: %s", response.Body)
		}
	}
}
