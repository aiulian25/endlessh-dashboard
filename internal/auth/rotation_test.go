package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordRotationRevocationFailureRollsBackCredentials(t *testing.T) {
	ctx := context.Background()
	service, db := newSeededService(t, time.Hour)
	before := mustGetUser(t, db)
	token, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB().Exec(`CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = service.ChangePassword(ctx, before.ID, testPassword, replacementPass); err == nil {
		t.Fatal("revocation failure reported success")
	}
	after := mustGetUser(t, db)
	if after.PasswordHash != before.PasswordHash || after.MustChangePassword != before.MustChangePassword {
		t.Fatal("failed revocation changed persisted credentials")
	}
	if _, _, err = service.Session(ctx, token); err != nil {
		t.Fatal("failed rotation invalidated original session")
	}
	if _, _, _, err = service.Login(ctx, testUsername, testPassword, "after-failed-rotation"); err != nil {
		t.Fatal("old password stopped working after failed rotation")
	}
	if _, _, _, err = service.Login(ctx, testUsername, replacementPass, "replacement-after-failure"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("replacement password accepted after failed rotation")
	}
}

// pauseVerification blocks after real Argon2 verification, outside any store
// write. Each service owns its verifier, so these barriers cannot affect peers.
func pauseVerification(service *Service) (<-chan struct{}, func()) {
	verified := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	var once sync.Once
	service.verifyPassword = func(hash, password string) (bool, error) {
		valid, err := VerifyPassword(hash, password)
		if first.CompareAndSwap(false, true) {
			close(verified)
			<-release
		}
		return valid, err
	}
	return verified, func() { once.Do(func() { close(release) }) }
}
func waitForVerification(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		t.Fatal("authentication did not reach verification barrier")
	}
}
func waitForRotation(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("password change did not complete")
		return nil
	}
}
func TestLoginVerifiedBeforeRotationCannotIssueValidSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	service, db := newSeededService(t, time.Hour)
	user := mustGetUser(t, db)
	ready, release := pauseVerification(service)
	defer release()
	type loginResult struct {
		token string
		err   error
	}
	result := make(chan loginResult, 1)
	go func() {
		token, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
		result <- loginResult{token, err}
	}()
	waitForVerification(t, ready)
	// A separate service shares the DB, not the barrier or hashing-slot limiter.
	rotation := NewService(db, time.Hour)
	if err := rotation.ChangePassword(ctx, user.ID, testPassword, replacementPass); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrInvalidCredentials) || got.token != "" {
			t.Fatal("stale login issued a session after rotation")
		}
	case <-ctx.Done():
		t.Fatal("stale login did not finish")
	}
	var count int
	if err := db.DB().QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("stale login left session state")
	}
	if _, _, _, err := rotation.Login(ctx, testUsername, replacementPass, "fresh-login"); err != nil {
		t.Fatal("fresh credentials failed after rotation")
	}
}
func TestConcurrentPasswordChangesRejectStaleVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, db := newSeededService(t, time.Hour)
	second := NewService(db, time.Hour)
	user := mustGetUser(t, db)
	firstReady, releaseFirst := pauseVerification(first)
	defer releaseFirst()
	secondReady, releaseSecond := pauseVerification(second)
	defer releaseSecond()
	firstResult, secondResult := make(chan error, 1), make(chan error, 1)
	otherPassword := "a-second-different-password"
	go func() { firstResult <- first.ChangePassword(ctx, user.ID, testPassword, replacementPass) }()
	go func() { secondResult <- second.ChangePassword(ctx, user.ID, testPassword, otherPassword) }()
	waitForVerification(t, firstReady)
	waitForVerification(t, secondReady)
	releaseFirst()
	if err := waitForRotation(t, firstResult); err != nil {
		t.Fatal(err)
	}
	// A new session under the winning password must survive the stale change.
	winner := NewService(db, time.Hour)
	token, _, _, err := winner.Login(ctx, testUsername, replacementPass, "winning-password")
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond()
	if err := waitForRotation(t, secondResult); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("stale password change overwrote winning credentials")
	}
	if _, _, err = winner.Session(ctx, token); err != nil {
		t.Fatal("stale change revoked the winning session")
	}
	if _, _, _, err = winner.Login(ctx, testUsername, otherPassword, "losing-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("losing rotation password accepted")
	}
}
