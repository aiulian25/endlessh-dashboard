// Package credentials validates persisted credential metadata without hashing.
package credentials

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ValidateHash bounds work before any imported Argon2 parameters are used.
// These ceilings cover every hash emitted by the dashboard's current format.
func ValidateHash(encoded string) error {
	invalid := errors.New("unsupported stored password hash")
	if len(encoded) > 512 {
		return invalid
	}
	f := strings.Split(encoded, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" || f[2] != "v=19" {
		return invalid
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(f[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return invalid
	}
	if f[3] != fmt.Sprintf("m=%d,t=%d,p=%d", m, t, p) || p < 1 || p > 4 || m < 8*p || m > 65536 || t < 1 || t > 3 {
		return invalid
	}
	salt, e := base64.RawStdEncoding.DecodeString(f[4])
	if e != nil || len(salt) < 16 || len(salt) > 64 {
		return invalid
	}
	key, e := base64.RawStdEncoding.DecodeString(f[5])
	if e != nil || len(key) < 16 || len(key) > 64 {
		return invalid
	}
	return nil
}
