// Package auth owns credentials and sessions. Passwords are only ever stored
// as Argon2id hashes, and session tokens are only ever stored hashed.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Memory dominates the cost and 64 MiB stays comfortable
// on the modest hardware this app is meant to share with a tarpit.
const (
	argon2Time      = 3
	argon2Memory    = 64 * 1024
	argon2Threads   = 4
	argon2KeyLength = 32
	saltLength      = 16

	// MinPasswordLength is deliberately a length floor rather than a character
	// -class rule: length is what actually resists guessing.
	MinPasswordLength = 12
	MaxPasswordLength = 1024
)

var (
	ErrWeakPassword    = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong = fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	ErrInvalidHash     = errors.New("stored password hash is not readable")
)

// HashPassword returns a self-describing encoded hash, so the parameters can be
// raised later without invalidating existing logins.
func HashPassword(password string) (string, error) {
	if err := CheckPasswordPolicy(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword compares in constant time and reports whether the stored hash
// was produced with the current parameters.
func VerifyPassword(encodedHash, password string) (bool, error) {
	fields := strings.Split(encodedHash, "$")
	if len(fields) != 6 || fields[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(fields[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(fields[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	storedKey, err := base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	// argon2.IDKey panics rather than returning an error on parameters it cannot
	// work with, and all of these are reachable from the stored string: a
	// zero-length key, no rounds, no threads. HashPassword never writes any of
	// them, so a hash carrying one is not ours whatever else it looks like, and
	// refusing it here is the difference between a rejected sign-in and a
	// panicking one. An empty salt does not panic but is refused with them: an
	// unsalted hash is not something this app has ever produced.
	if len(salt) == 0 || len(storedKey) == 0 || iterations == 0 || parallelism == 0 {
		return false, ErrInvalidHash
	}

	candidate := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(storedKey)))
	return subtle.ConstantTimeCompare(candidate, storedKey) == 1, nil
}

func CheckPasswordPolicy(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}
