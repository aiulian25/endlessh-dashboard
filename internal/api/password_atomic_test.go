package api

import (
	"context"
	"net/http"
	"testing"
)

func TestPasswordRevocationFailureKeepsExistingLogin(t *testing.T) {
	h := newSignedInHarness(t)
	before, err := h.store.GetUserByUsername(context.Background(), seedUsername)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.DB().Exec(`CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	answer := h.request(http.MethodPost, "/api/password", map[string]string{"current_password": replacementPassword, "new_password": "another-test-password-8Qx"})
	assertStatus(t, "failed password rotation", answer, http.StatusInternalServerError)
	if len(answer.cookies) != 0 {
		t.Fatal("failed rotation changed the browser cookie")
	}
	after, err := h.store.GetUserByUsername(context.Background(), seedUsername)
	if err != nil {
		t.Fatal(err)
	}
	if before.PasswordHash != after.PasswordHash || before.MustChangePassword != after.MustChangePassword {
		t.Fatal("failed request changed persisted credentials")
	}
	answer = h.request(http.MethodGet, "/api/session", nil)
	assertStatus(t, "original session after failed rotation", answer, http.StatusOK)
	answer = h.send(http.MethodPost, "/api/login", "", credentials(replacementPassword), nil)
	assertStatus(t, "original password after failed rotation", answer, http.StatusOK)
}
