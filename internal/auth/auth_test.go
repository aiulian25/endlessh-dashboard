package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

const (
	testUsername    = "admin"
	testPassword    = "correct-horse-battery"
	wrongPassword   = "incorrect-horse-battery"
	replacementPass = "a-different-good-password"
	testClientKey   = "admin@198.51.100.7"
	otherClientKey  = "admin@198.51.100.8"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore, err := store.Open(filepath.Join(t.TempDir(), "endlessh.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate store: %v", err)
	}
	return dataStore
}

// newSeededService returns a service whose database already holds the single
// admin account with testPassword.
func newSeededService(t *testing.T, lifetime time.Duration) (*Service, *store.Store) {
	t.Helper()
	dataStore := newTestStore(t)
	service := NewService(dataStore, lifetime)
	created, err := service.EnsureInitialUser(context.Background(), testUsername, testPassword)
	if err != nil {
		t.Fatalf("seed initial user: %v", err)
	}
	if !created {
		t.Fatal("EnsureInitialUser reported no creation on an empty database")
	}
	return service, dataStore
}

func countSessionsWithTokenHash(t *testing.T, dataStore *store.Store, tokenHash string) int {
	t.Helper()
	var count int
	err := dataStore.DB().QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE token_hash = ?", tokenHash).Scan(&count)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return count
}

func TestHashPasswordIsSaltedPerCall(t *testing.T) {
	first, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	second, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash password again: %v", err)
	}

	if first == second {
		t.Fatal("two hashes of the same password are identical, so the salt is not random")
	}
	if strings.Contains(first, testPassword) {
		t.Fatalf("encoded hash %q contains the plaintext password", first)
	}

	for _, hash := range []string{first, second} {
		valid, err := VerifyPassword(hash, testPassword)
		if err != nil {
			t.Fatalf("verify correct password: %v", err)
		}
		if !valid {
			t.Fatal("the correct password was rejected")
		}

		valid, err = VerifyPassword(hash, wrongPassword)
		if err != nil {
			t.Fatalf("verify wrong password: %v", err)
		}
		if valid {
			t.Fatal("a wrong password was accepted")
		}
	}
}

func TestVerifyPasswordRejectsUnreadableHash(t *testing.T) {
	valid := mustHash(t, testPassword)
	fields := strings.Split(valid, "$")
	if len(fields) != 6 {
		t.Fatalf("encoded hash %q has %d fields, expected 6", valid, len(fields))
	}

	rebuild := func(index int, value string) string {
		copied := append([]string(nil), fields...)
		copied[index] = value
		return strings.Join(copied, "$")
	}

	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not a hash at all", "not-a-hash"},
		{"plaintext smuggled in as a hash", testPassword},
		{"too few fields", strings.Join(fields[:5], "$")},
		{"too many fields", valid + "$extra"},
		{"another algorithm", rebuild(1, "argon2i")},
		{"unknown version", rebuild(2, "v=99")},
		{"unreadable version", rebuild(2, "version-nineteen")},
		{"unreadable parameters", rebuild(3, "m=lots,t=some,p=few")},
		{"salt is not base64", rebuild(4, "!!!not-base64!!!")},
		{"key is not base64", rebuild(5, "!!!not-base64!!!")},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			accepted, err := VerifyPassword(testCase.hash, testPassword)
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("error is %v, want ErrInvalidHash", err)
			}
			if accepted {
				t.Fatal("an unreadable stored hash accepted the password")
			}
		})
	}

	// A well-formed hash of some other password must simply not match, without
	// being reported as unreadable.
	otherHash := mustHash(t, replacementPass)
	accepted, err := VerifyPassword(otherHash, testPassword)
	if err != nil {
		t.Fatalf("verify against another account's hash: %v", err)
	}
	if accepted {
		t.Fatal("a hash of a different password accepted this password")
	}
}

func TestCheckPasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"empty", "", ErrWeakPassword},
		{"one rune short of the minimum", strings.Repeat("a", MinPasswordLength-1), ErrWeakPassword},
		{"exactly the minimum", strings.Repeat("a", MinPasswordLength), nil},
		{"comfortably long", testPassword, nil},
		// 11 runes but 22 bytes: a byte-counting policy would let this through.
		{"short multi-byte password", strings.Repeat("é", MinPasswordLength-1), ErrWeakPassword},
		{"multi-byte password at the minimum rune count", strings.Repeat("é", MinPasswordLength), nil},
		{"exactly the maximum", strings.Repeat("a", MaxPasswordLength), nil},
		{"one over the maximum", strings.Repeat("a", MaxPasswordLength+1), ErrPasswordTooLong},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := CheckPasswordPolicy(testCase.password)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("policy for a %d-rune password returned %v, want %v",
					len([]rune(testCase.password)), err, testCase.wantErr)
			}
		})
	}
}

func TestCheckPasswordPolicyGuardsHashPassword(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", MinPasswordLength-1)); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("hashing a too-short password returned %v, want ErrWeakPassword", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordLength+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("hashing an over-long password returned %v, want ErrPasswordTooLong", err)
	}
}

func TestEnsureInitialUserSeedsOneAdmin(t *testing.T) {
	ctx := context.Background()
	_, dataStore := newSeededService(t, time.Hour)

	count, err := dataStore.CountUsers(ctx)
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("database holds %d users after seeding, want 1", count)
	}

	seeded, err := dataStore.GetUserByUsername(ctx, testUsername)
	if err != nil {
		t.Fatalf("read the seeded user: %v", err)
	}
	if !seeded.MustChangePassword {
		t.Fatal("the seeded admin is not marked must-change-password")
	}
	if seeded.PasswordHash == testPassword {
		t.Fatal("the seed password was stored verbatim")
	}
	valid, err := VerifyPassword(seeded.PasswordHash, testPassword)
	if err != nil || !valid {
		t.Fatalf("the stored hash does not verify the seed password (valid=%v, err=%v)", valid, err)
	}
}

func TestEnsureInitialUserIsNoOpWhenAUserExists(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)

	created, err := service.EnsureInitialUser(ctx, "someone-else", replacementPass)
	if err != nil {
		t.Fatalf("second EnsureInitialUser: %v", err)
	}
	if created {
		t.Fatal("EnsureInitialUser created a second account")
	}

	count, err := dataStore.CountUsers(ctx)
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("database holds %d users after a second seed attempt, want 1", count)
	}
	if _, err := dataStore.GetUserByUsername(ctx, "someone-else"); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("looking up the would-be second account returned %v, want ErrUserNotFound", err)
	}

	// The original credentials are untouched.
	if _, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey); err != nil {
		t.Fatalf("the seeded password stopped working after a second seed attempt: %v", err)
	}
}

func TestEnsureInitialUserNeedsAPassword(t *testing.T) {
	ctx := context.Background()
	dataStore := newTestStore(t)
	service := NewService(dataStore, time.Hour)

	created, err := service.EnsureInitialUser(ctx, testUsername, "")
	if err == nil {
		t.Fatal("seeding with no password succeeded, want an error")
	}
	if created {
		t.Fatal("EnsureInitialUser reported a creation while returning an error")
	}

	count, err := dataStore.CountUsers(ctx)
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("database holds %d users after a failed seed, want 0", count)
	}
}

func TestLoginStoresOnlyTheHashedToken(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)

	token, session, user, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if token == "" {
		t.Fatal("login returned an empty token")
	}
	if user.Username != testUsername {
		t.Fatalf("login returned user %q, want %q", user.Username, testUsername)
	}
	if session.CSRFToken == "" || session.CSRFToken == token {
		t.Fatalf("csrf token %q is empty or equal to the session token", session.CSRFToken)
	}

	if session.TokenHash == token {
		t.Fatal("the stored token hash is the raw token")
	}
	if session.TokenHash != HashToken(token) {
		t.Fatal("the stored token hash is not the hash of the returned token")
	}
	if count := countSessionsWithTokenHash(t, dataStore, token); count != 0 {
		t.Fatalf("%d session rows are keyed by the raw token; the cookie value must never reach the database", count)
	}
	if count := countSessionsWithTokenHash(t, dataStore, HashToken(token)); count != 1 {
		t.Fatalf("%d session rows are keyed by the token hash, want 1", count)
	}

	found, foundUser, err := service.Session(ctx, token)
	if err != nil {
		t.Fatalf("look up the session by its raw token: %v", err)
	}
	if found.TokenHash != session.TokenHash || foundUser.ID != user.ID {
		t.Fatal("Session returned a different session or user than Login did")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	ctx := context.Background()
	service, _ := newSeededService(t, time.Hour)

	cases := []struct {
		name     string
		username string
		password string
	}{
		{"wrong password", testUsername, wrongPassword},
		{"empty password", testUsername, ""},
		{"unknown user", "nobody", testPassword},
		{"unknown user with an empty password", "nobody", ""},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// A fresh client key per case keeps the throttle out of the way.
			token, session, user, err := service.Login(ctx, testCase.username, testCase.password, testCase.name)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("login returned %v, want ErrInvalidCredentials", err)
			}
			if token != "" || session.TokenHash != "" || user.ID != 0 {
				t.Fatal("a rejected login still handed out a session")
			}
		})
	}
}

func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	service, _ := newSeededService(t, time.Hour)

	for attempt := 1; attempt <= maxLoginAttempts; attempt++ {
		_, _, _, err := service.Login(ctx, testUsername, wrongPassword, testClientKey)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failed attempt %d returned %v, want ErrInvalidCredentials", attempt, err)
		}
	}

	// Even the right password is refused once the client key is locked.
	_, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("login after %d failures returned %v, want ErrTooManyAttempts", maxLoginAttempts, err)
	}

	// The lockout is scoped to the client key, not to the account itself.
	if _, _, _, err := service.Login(ctx, testUsername, testPassword, otherClientKey); err != nil {
		t.Fatalf("login from a different client key was refused: %v", err)
	}
}

func TestSuccessfulLoginClearsTheFailureCounter(t *testing.T) {
	ctx := context.Background()
	service, _ := newSeededService(t, time.Hour)

	failJustBelowTheThreshold := func() {
		t.Helper()
		for attempt := 0; attempt < maxLoginAttempts-1; attempt++ {
			if _, _, _, err := service.Login(ctx, testUsername, wrongPassword, testClientKey); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("failed attempt returned %v, want ErrInvalidCredentials", err)
			}
		}
	}

	failJustBelowTheThreshold()
	if _, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey); err != nil {
		t.Fatalf("login just below the lockout threshold was refused: %v", err)
	}

	// Without the counter reset these failures would carry over and lock the key.
	failJustBelowTheThreshold()
	if _, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey); err != nil {
		t.Fatalf("failures from before a successful login were not forgotten: %v", err)
	}
}

func TestChangePasswordRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)
	user := mustGetUser(t, dataStore)

	cases := []struct {
		name        string
		current     string
		replacement string
		wantErr     error
	}{
		{"wrong current password", wrongPassword, replacementPass, ErrInvalidCredentials},
		{"empty current password", "", replacementPass, ErrInvalidCredentials},
		{"reusing the same password", testPassword, testPassword, ErrSamePassword},
		{"new password too short", testPassword, strings.Repeat("a", MinPasswordLength-1), ErrWeakPassword},
		{"new password too long", testPassword, strings.Repeat("a", MaxPasswordLength+1), ErrPasswordTooLong},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := service.ChangePassword(ctx, user.ID, testCase.current, testCase.replacement)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("ChangePassword returned %v, want %v", err, testCase.wantErr)
			}
		})
	}

	// None of the rejections may have touched the stored password.
	if _, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey); err != nil {
		t.Fatalf("the original password stopped working after rejected changes: %v", err)
	}
}

func TestChangePasswordInvalidatesEverySession(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)
	user := mustGetUser(t, dataStore)

	firstToken, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	secondToken, _, _, err := service.Login(ctx, testUsername, testPassword, otherClientKey)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	if err := service.ChangePassword(ctx, user.ID, testPassword, replacementPass); err != nil {
		t.Fatalf("change password: %v", err)
	}

	for name, token := range map[string]string{"first": firstToken, "second": secondToken} {
		if _, _, err := service.Session(ctx, token); !errors.Is(err, store.ErrSessionNotFound) {
			t.Fatalf("the %s session survived the password change (err=%v)", name, err)
		}
	}

	updated := mustGetUser(t, dataStore)
	if updated.MustChangePassword {
		t.Fatal("the user is still marked must-change-password after changing it")
	}

	if _, _, _, err := service.Login(ctx, testUsername, testPassword, "after-change"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the old password still works after the change (err=%v)", err)
	}
	if _, _, _, err := service.Login(ctx, testUsername, replacementPass, "after-change"); err != nil {
		t.Fatalf("the new password does not work after the change: %v", err)
	}
}

func TestSessionRejectsUnknownAndExpiredTokens(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)

	for _, token := range []string{"", "not-a-real-token"} {
		if _, _, err := service.Session(ctx, token); !errors.Is(err, store.ErrSessionNotFound) {
			t.Fatalf("Session(%q) returned %v, want ErrSessionNotFound", token, err)
		}
	}

	// A service whose sessions are born expired isolates the expiry check from
	// everything else, with no waiting involved.
	expiring := NewService(dataStore, -time.Minute)
	token, session, _, err := expiring.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatalf("login on the short-lived service: %v", err)
	}
	if !session.ExpiresAt.Before(time.Now().UTC()) {
		t.Fatalf("session expiry %s is not in the past", session.ExpiresAt)
	}
	if count := countSessionsWithTokenHash(t, dataStore, HashToken(token)); count != 1 {
		t.Fatalf("the expired session row is missing (%d rows), so this would pass for the wrong reason", count)
	}
	if _, _, err := expiring.Session(ctx, token); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("an expired session was accepted (err=%v)", err)
	}
}

func TestPurgeExpiredSessionsRemovesOnlyExpiredRows(t *testing.T) {
	ctx := context.Background()
	service, dataStore := newSeededService(t, time.Hour)

	liveToken, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	expiring := NewService(dataStore, -time.Minute)
	if _, _, _, err := expiring.Login(ctx, testUsername, testPassword, otherClientKey); err != nil {
		t.Fatalf("login on the short-lived service: %v", err)
	}

	removed, err := service.PurgeExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("purge expired sessions: %v", err)
	}
	if removed != 1 {
		t.Fatalf("purge removed %d sessions, want 1", removed)
	}
	if _, _, err := service.Session(ctx, liveToken); err != nil {
		t.Fatalf("the live session was purged too: %v", err)
	}
}

func TestLogoutDropsOnlyTheCallersSession(t *testing.T) {
	ctx := context.Background()
	service, _ := newSeededService(t, time.Hour)

	firstToken, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	secondToken, _, _, err := service.Login(ctx, testUsername, testPassword, otherClientKey)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	if err := service.Logout(ctx, firstToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := service.Session(ctx, firstToken); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("the session survived logout (err=%v)", err)
	}
	if _, _, err := service.Session(ctx, secondToken); err != nil {
		t.Fatalf("logout also dropped the other session: %v", err)
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return hash
}

func mustGetUser(t *testing.T, dataStore *store.Store) store.User {
	t.Helper()
	user, err := dataStore.GetUserByUsername(context.Background(), testUsername)
	if err != nil {
		t.Fatalf("read the seeded user: %v", err)
	}
	return user
}

// The defect this guards: MaxUsernameLength was enforced when signing in but
// not when the account was seeded, so an over-long ADMIN_USERNAME created an
// account that could never be used. Refusing at creation turns a silent,
// unrecoverable state into a startup error the operator can act on.
func TestEnsureInitialUserRefusesAUsernameLoginCouldNeverAccept(t *testing.T) {
	// A bare service: EnsureInitialUser is a no-op once any user exists, so the
	// database has to be empty for the seeding path to run at all.
	ctx := context.Background()
	dataStore := newTestStore(t)
	service := NewService(dataStore, time.Hour)

	tooLong := strings.Repeat("a", MaxUsernameLength+1)
	created, err := service.EnsureInitialUser(ctx, tooLong, "seed-password-1")
	if err == nil {
		t.Fatal("an over-long username was accepted, so the account would exist but never sign in")
	}
	if created {
		t.Error("EnsureInitialUser reported creating an account it rejected")
	}
	if count, countErr := dataStore.CountUsers(ctx); countErr != nil || count != 0 {
		t.Errorf("users after a refused seed = %d (err %v), want none written", count, countErr)
	}

	// Exactly at the limit is usable, so the guard rejects only what Login would.
	atLimit := strings.Repeat("a", MaxUsernameLength)
	if _, err := service.EnsureInitialUser(ctx, atLimit, "seed-password-1"); err != nil {
		t.Fatalf("a username of exactly %d bytes was refused: %v", MaxUsernameLength, err)
	}
	if _, _, _, err := service.Login(ctx, atLimit, "seed-password-1", "test"); err != nil {
		t.Errorf("the account just created cannot sign in: %v", err)
	}
}

// Login measures bytes, so this must too. A rune-count check would pass a name
// of 40 multi-byte characters at creation and then reject it at sign-in — the
// same unusable account, reached by a subtler route.
func TestUsernamePolicyMeasuresTheSameLengthLoginDoes(t *testing.T) {
	// 40 runes, 120 bytes: comfortably under a 64-rune limit, over a 64-byte one.
	multiByte := strings.Repeat("é", 40)
	if len([]rune(multiByte)) > MaxUsernameLength {
		t.Fatalf("fixture is %d runes, which is not under the limit", len([]rune(multiByte)))
	}
	if len(multiByte) <= MaxUsernameLength {
		t.Fatalf("fixture is %d bytes, which is not over the limit", len(multiByte))
	}
	if err := CheckUsernamePolicy(multiByte); err == nil {
		t.Error("a username Login would refuse on byte length was accepted at creation")
	}
}

func TestUsernamePolicyRejectsEmptyAndBlank(t *testing.T) {
	for _, blank := range []string{"", "   ", "\t\n"} {
		if err := CheckUsernamePolicy(blank); err == nil {
			t.Errorf("CheckUsernamePolicy(%q) = nil, want it refused", blank)
		}
	}
	if err := CheckUsernamePolicy("admin"); err != nil {
		t.Errorf("CheckUsernamePolicy(\"admin\") = %v, want nil", err)
	}
}
