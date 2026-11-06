package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCredentialGuardAndRotationPreserveOtherUsers(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	a, err := s.CreateUser(ctx, User{Username: "a", PasswordHash: "a-old", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateUser(ctx, User{Username: "b", PasswordHash: "b-old"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := func(user User, token string) Session {
		return Session{UserID: user.ID, TokenHash: token, CSRFToken: token, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	if err = s.CreateSession(ctx, session(a, "a-before"), a.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateSession(ctx, session(b, "b-before"), b.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUserPassword(ctx, a.ID, a.PasswordHash, "a-new", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.GetSession(ctx, "a-before", now); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("rotation retained old session")
	}
	if _, _, err = s.GetSession(ctx, "b-before", now); err != nil {
		t.Fatal("rotation revoked another user's session")
	}
	if err = s.CreateSession(ctx, session(a, "a-stale"), a.PasswordHash); !errors.Is(err, ErrCredentialsChanged) {
		t.Fatal("stale credentials inserted session")
	}
	if err = s.CreateSession(ctx, session(a, "a-fresh"), "a-new"); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUserPassword(ctx, a.ID, a.PasswordHash, "a-stale-change", false); !errors.Is(err, ErrCredentialsChanged) {
		t.Fatal("stale update replaced password")
	}
	if _, _, err = s.GetSession(ctx, "a-fresh", now); err != nil {
		t.Fatal("stale change revoked fresh session")
	}
	if err = s.CreateSession(ctx, session(User{ID: a.ID + 999}, "missing-user"), a.PasswordHash); !errors.Is(err, ErrCredentialsChanged) {
		t.Fatal("deleted/absent user issued session")
	}
}

func TestPasswordUpdateFailureRetainsSessions(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	user, err := s.CreateUser(ctx, User{Username: "a", PasswordHash: "old", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.CreateSession(ctx, Session{UserID: user.ID, TokenHash: "token", CSRFToken: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, user.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().Exec(`CREATE TRIGGER reject_password_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'injected update failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUserPassword(ctx, user.ID, user.PasswordHash, "new", false); err == nil {
		t.Fatal("failed UPDATE returned success")
	}
	current, err := s.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.PasswordHash != user.PasswordHash || !current.MustChangePassword {
		t.Fatal("failed update changed credentials")
	}
	if _, _, err = s.GetSession(ctx, "token", now); err != nil {
		t.Fatal("failed update revoked session")
	}
}
