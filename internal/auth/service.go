package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"endlessh-dashboard/internal/store"
)

const (
	tokenBytes = 32

	// Login throttling: a handful of tries, then a cooling-off period. Aimed at
	// online guessing, not at a distributed attack, which auth alone cannot stop.
	maxLoginAttempts = 5
	loginWindow      = 15 * time.Minute
	lockoutDuration  = 15 * time.Minute

	// MaxUsernameLength bounds what an anonymous caller can make this process
	// remember. The throttle map is keyed by username, so without a length cap a
	// stream of long, always-different usernames grows it without bound.
	MaxUsernameLength = 64

	// maxTrackedClients caps the throttle map even against many short usernames.
	// Reaching it drops the stalest entries, never the locked-out ones.
	maxTrackedClients = 4096

	// maxConcurrentHashes bounds how many Argon2id verifications run at once.
	// Each one allocates argon2Memory (64 MiB), so an unbounded number of
	// anonymous login attempts would otherwise be a memory exhaustion lever.
	maxConcurrentHashes = 2

	// hashingQueueTimeout is how long a request waits for a hashing slot before
	// being turned away.
	hashingQueueTimeout = 5 * time.Second
)

var (
	ErrUsernameEmpty   = errors.New("username must not be empty")
	ErrUsernameTooLong = fmt.Errorf("username must be at most %d bytes", MaxUsernameLength)
)

var (
	ErrInvalidCredentials = errors.New("username or password is incorrect")
	ErrTooManyAttempts    = errors.New("too many failed sign-in attempts, try again later")
	ErrSamePassword       = errors.New("new password must be different from the current one")
	ErrBusy               = errors.New("the server is busy verifying other sign-ins, try again in a moment")
)

type Service struct {
	store        *store.Store
	lifetime     time.Duration
	hashingSlots chan struct{}

	mutex    sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	count       int
	firstFailed time.Time
	lockedUntil time.Time
}

func (r *attemptRecord) staleAt(now time.Time) bool {
	return now.After(r.lockedUntil) && now.Sub(r.firstFailed) > loginWindow
}

func NewService(dataStore *store.Store, lifetime time.Duration) *Service {
	return &Service{
		store:        dataStore,
		lifetime:     lifetime,
		hashingSlots: make(chan struct{}, maxConcurrentHashes),
		attempts:     map[string]*attemptRecord{},
	}
}

// withHashingSlot runs work under the Argon2id concurrency limit so a burst of
// anonymous sign-in attempts cannot multiply 64 MiB allocations without bound.
func (s *Service) withHashingSlot(ctx context.Context, work func() error) error {
	waitCtx, cancel := context.WithTimeout(ctx, hashingQueueTimeout)
	defer cancel()

	select {
	case s.hashingSlots <- struct{}{}:
	case <-waitCtx.Done():
		return ErrBusy
	}
	defer func() { <-s.hashingSlots }()

	return work()
}

// CheckUsernamePolicy rejects a username that could never be used. It must test
// exactly what Login tests — byte length, not a rune count — because the whole
// point is that the two agree: a name that passes here and fails there creates
// an account nobody can ever sign in to, recoverable only by clearing the user
// rows.
func CheckUsernamePolicy(username string) error {
	if strings.TrimSpace(username) == "" {
		return ErrUsernameEmpty
	}
	if len(username) > MaxUsernameLength {
		return ErrUsernameTooLong
	}
	return nil
}

// EnsureInitialUser seeds the single admin account on first start. The seeded
// password is marked for immediate change, so the value that sat in the
// environment stops working as soon as someone signs in.
func (s *Service) EnsureInitialUser(ctx context.Context, username, password string) (bool, error) {
	count, err := s.store.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return false, nil
	}
	if password == "" {
		return false, errors.New("no users exist yet and ADMIN_PASSWORD is not set")
	}
	// Checked before the account is written rather than discovered at the first
	// sign-in attempt, when the only way out would be deleting the user rows.
	if err := CheckUsernamePolicy(username); err != nil {
		return false, fmt.Errorf("the configured admin username is unusable: %w", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return false, err
	}
	if _, err := s.store.CreateUser(ctx, store.User{
		Username:           username,
		PasswordHash:       hash,
		MustChangePassword: true,
	}); err != nil {
		return false, err
	}
	return true, nil
}

// Login returns the raw session token for the cookie; only its hash is stored.
func (s *Service) Login(ctx context.Context, username, password, clientKey string) (string, store.Session, store.User, error) {
	// Rejected before any hashing work: a username this long cannot exist, and
	// answering cheaply keeps an anonymous caller from spending the server's
	// memory on it.
	if len(username) > MaxUsernameLength {
		return "", store.Session{}, store.User{}, ErrInvalidCredentials
	}
	if locked, retryAfter := s.locked(clientKey); locked {
		return "", store.Session{}, store.User{}, fmt.Errorf("%w (about %s)", ErrTooManyAttempts, retryAfter.Round(time.Minute))
	}

	user, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrUserNotFound) {
		// Spend the same work as a real verification so timing does not reveal
		// whether the username exists.
		if slotErr := s.withHashingSlot(ctx, func() error {
			_, hashErr := HashPassword("placeholder-for-constant-work")
			return hashErr
		}); errors.Is(slotErr, ErrBusy) {
			return "", store.Session{}, store.User{}, ErrBusy
		}
		s.recordFailure(clientKey)
		return "", store.Session{}, store.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", store.Session{}, store.User{}, err
	}

	var valid bool
	if err := s.withHashingSlot(ctx, func() error {
		var verifyErr error
		valid, verifyErr = VerifyPassword(user.PasswordHash, password)
		return verifyErr
	}); err != nil {
		return "", store.Session{}, store.User{}, err
	}
	if !valid {
		s.recordFailure(clientKey)
		return "", store.Session{}, store.User{}, ErrInvalidCredentials
	}
	s.clearFailures(clientKey)

	token, session, err := s.newSession(ctx, user.ID)
	if err != nil {
		return "", store.Session{}, store.User{}, err
	}
	return token, session, user, nil
}

func (s *Service) newSession(ctx context.Context, userID int64) (string, store.Session, error) {
	token, err := randomToken()
	if err != nil {
		return "", store.Session{}, err
	}
	csrfToken, err := randomToken()
	if err != nil {
		return "", store.Session{}, err
	}
	now := time.Now().UTC()
	session := store.Session{
		TokenHash: HashToken(token),
		UserID:    userID,
		CSRFToken: csrfToken,
		CreatedAt: now,
		ExpiresAt: now.Add(s.lifetime),
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return "", store.Session{}, err
	}
	return token, session, nil
}

func (s *Service) Session(ctx context.Context, token string) (store.Session, store.User, error) {
	if token == "" {
		return store.Session{}, store.User{}, store.ErrSessionNotFound
	}
	return s.store.GetSession(ctx, HashToken(token), time.Now().UTC())
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, HashToken(token))
}

// ChangePassword replaces the password and drops every existing session,
// including the caller's, so a fresh login is required everywhere.
func (s *Service) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	var valid bool
	if err := s.withHashingSlot(ctx, func() error {
		var verifyErr error
		valid, verifyErr = VerifyPassword(user.PasswordHash, currentPassword)
		return verifyErr
	}); err != nil {
		return err
	}
	if !valid {
		return ErrInvalidCredentials
	}
	if currentPassword == newPassword {
		return ErrSamePassword
	}

	var hash string
	if err := s.withHashingSlot(ctx, func() error {
		var hashErr error
		hash, hashErr = HashPassword(newPassword)
		return hashErr
	}); err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(ctx, userID, hash, false); err != nil {
		return err
	}
	return s.store.DeleteSessionsForUser(ctx, userID)
}

// PurgeExpiredSessions is called periodically by the maintenance loop.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredSessions(ctx, time.Now().UTC())
}

func (s *Service) locked(clientKey string) (bool, time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	record, known := s.attempts[clientKey]
	if !known {
		return false, 0
	}
	remaining := time.Until(record.lockedUntil)
	if remaining <= 0 {
		return false, 0
	}
	return true, remaining
}

func (s *Service) recordFailure(clientKey string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := time.Now()
	s.evictStaleAttempts(now)

	record, known := s.attempts[clientKey]
	if !known || now.Sub(record.firstFailed) > loginWindow {
		s.attempts[clientKey] = &attemptRecord{count: 1, firstFailed: now}
		return
	}
	record.count++
	if record.count >= maxLoginAttempts {
		record.lockedUntil = now.Add(lockoutDuration)
		record.count = 0
		record.firstFailed = now
	}
}

func (s *Service) clearFailures(clientKey string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.attempts, clientKey)
}

// evictStaleAttempts keeps the throttle map bounded. Records past both their
// window and their lockout carry no information, and if the map is still at its
// cap afterwards the oldest remaining entries go too — a locked-out attacker
// cannot flush their own lockout, because locked records are evicted last.
// Callers must hold the mutex.
func (s *Service) evictStaleAttempts(now time.Time) {
	for key, record := range s.attempts {
		if record.staleAt(now) {
			delete(s.attempts, key)
		}
	}
	if len(s.attempts) < maxTrackedClients {
		return
	}
	for key, record := range s.attempts {
		if len(s.attempts) < maxTrackedClients {
			return
		}
		if now.After(record.lockedUntil) {
			delete(s.attempts, key)
		}
	}
}

func randomToken() (string, error) {
	buffer := make([]byte, tokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// HashToken is what turns a cookie value into the database key.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
