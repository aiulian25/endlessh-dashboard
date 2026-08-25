package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrSessionNotFound = errors.New("session not found")
)

type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	MustChangePassword bool
	CreatedAt          time.Time
}

// Session stores only the hash of the token handed to the browser, so a stolen
// database file does not hand out live sessions.
type Session struct {
	TokenHash string
	UserID    int64
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var count int
	if err := s.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	row := s.database.QueryRowContext(ctx,
		`SELECT id, username, password_hash, must_change_password, created_at
		 FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (User, error) {
	row := s.database.QueryRowContext(ctx,
		`SELECT id, username, password_hash, must_change_password, created_at
		 FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) CreateUser(ctx context.Context, user User) (User, error) {
	user.CreatedAt = time.Now().UTC()
	result, err := s.database.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, must_change_password, created_at)
		 VALUES (?, ?, ?, ?)`,
		user.Username, user.PasswordHash, user.MustChangePassword, user.CreatedAt.Unix())
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	user.ID = id
	return user, nil
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error {
	result, err := s.database.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
		passwordHash, mustChange, userID)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return requireOneRow(result, ErrUserNotFound)
}

func (s *Store) CreateSession(ctx context.Context, session Session) error {
	_, err := s.database.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		session.TokenHash, session.UserID, session.CSRFToken,
		session.CreatedAt.Unix(), session.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession returns the live session and its owner, or ErrSessionNotFound when
// the token is unknown or expired.
func (s *Store) GetSession(ctx context.Context, tokenHash string, now time.Time) (Session, User, error) {
	row := s.database.QueryRowContext(ctx,
		`SELECT sessions.token_hash, sessions.user_id, sessions.csrf_token,
				sessions.created_at, sessions.expires_at,
				users.id, users.username, users.password_hash,
				users.must_change_password, users.created_at
		 FROM sessions
		 JOIN users ON users.id = sessions.user_id
		 WHERE sessions.token_hash = ? AND sessions.expires_at > ?`,
		tokenHash, now.Unix())

	var (
		session         Session
		user            User
		sessionCreated  int64
		sessionExpires  int64
		userCreatedUnix int64
	)
	err := row.Scan(
		&session.TokenHash, &session.UserID, &session.CSRFToken,
		&sessionCreated, &sessionExpires,
		&user.ID, &user.Username, &user.PasswordHash,
		&user.MustChangePassword, &userCreatedUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, User{}, fmt.Errorf("get session: %w", err)
	}
	session.CreatedAt = time.Unix(sessionCreated, 0).UTC()
	session.ExpiresAt = time.Unix(sessionExpires, 0).UTC()
	user.CreatedAt = time.Unix(userCreatedUnix, 0).UTC()
	return session, user, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.database.ExecContext(ctx,
		"DELETE FROM sessions WHERE token_hash = ?", tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForUser logs every other browser out, used after a password change.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID int64) error {
	if _, err := s.database.ExecContext(ctx,
		"DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("delete sessions for user: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.database.ExecContext(ctx,
		"DELETE FROM sessions WHERE expires_at <= ?", now.Unix())
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return result.RowsAffected()
}

func scanUser(scanner rowScanner) (User, error) {
	var (
		user        User
		createdUnix int64
	)
	err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash,
		&user.MustChangePassword, &createdUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	user.CreatedAt = time.Unix(createdUnix, 0).UTC()
	return user, nil
}
