package api

import (
	"fmt"
	"net/http"
	"testing"
)

func TestMachineSelectionContract(t *testing.T) {
	h := newSignedInHarness(t)
	a := h.seedMachine("enabled")
	b := h.seedMachine("disabled history")
	if _, err := h.store.DB().Exec("UPDATE machines SET enabled=0 WHERE id=?", b.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 1}, {fmt.Sprintf("?machines=%d,%d", a.ID, b.ID), 2}, {"?machines=0", 0}, {fmt.Sprintf("?machines=%d", b.ID), 1},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := h.request(http.MethodGet, "/api/overview"+tc.query, nil)
			assertStatus(t, "machine scope", r, 200)
			var body overviewResponse
			r.decode(t, &body)
			if body.MachineCount != tc.want {
				t.Fatalf("scope %q: got %d machines, want %d", tc.query, body.MachineCount, tc.want)
			}
		})
	}
}
