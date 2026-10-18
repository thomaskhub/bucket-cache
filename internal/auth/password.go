package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost parameters for new password hashes.
// Verification reads the parameters from the stored hash, so they can be
// raised later without invalidating existing passwords.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// PasswordParams is used for new hashes: the second recommended option of
// RFC 9106 (64 MiB, 3 passes, 4 lanes). Tests lower it to stay fast.
var PasswordParams = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 4}

// hashSlots bounds concurrent Argon2 runs, so a burst of logins can't use
// unbounded memory (each run allocates Memory KiB).
var hashSlots = make(chan struct{}, 4)

// ErrPasswordMismatch is returned by VerifyPassword for a wrong password.
var ErrPasswordMismatch = errors.New("password does not match")

// HashPassword returns an Argon2id hash in the PHC string format
// ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	p := PasswordParams
	key := argon2id([]byte(password), salt, p, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func argon2id(password, salt []byte, p Argon2Params, keyLen uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, keyLen)
}

// VerifyPassword checks password against a hash from HashPassword. It
// returns ErrPasswordMismatch for a wrong password and another error for a
// malformed hash.
func VerifyPassword(hash, password string) error {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return errors.New("malformed argon2 parameters")
	}
	if p.Memory == 0 || p.Memory > 1<<21 || p.Time == 0 || p.Time > 16 || p.Threads == 0 {
		return errors.New("argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("malformed argon2 salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return errors.New("malformed argon2 hash")
	}
	got := argon2id([]byte(password), salt, p, uint32(len(want))) //nolint:gosec // G115: len(want) is at most 64
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// dummyHash is verified against when a username doesn't exist, so a login
// for an unknown user takes as long as one for a known user.
var dummyHash = sync.OnceValue(func() string { return HashPassword("not a real password") })

// BurnPasswordCheck spends the same time as a real password verification.
func BurnPasswordCheck(password string) { _ = VerifyPassword(dummyHash(), password) }

// NewPassword returns a random one-time password (20 characters).
func NewPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, 20)
	buf := make([]byte, 32)
	for len(out) < 20 {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, c := range buf {
			// Rejection sampling keeps every character equally likely.
			if int(c) < 256-256%len(alphabet) && len(out) < 20 {
				out = append(out, alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return string(out)
}
