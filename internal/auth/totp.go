package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP uses HMAC-SHA1, which authenticator apps expect
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults that every authenticator app supports).
const (
	TOTPDigits = 6
	TOTPPeriod = 30 * time.Second
	// TOTPSkew is how many steps before and after the current one are
	// accepted, to allow for clock drift and typing time.
	TOTPSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit TOTP secret (RFC 4226 recommends
// at least 128 bits; 160 matches the HMAC-SHA1 block output).
func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// TOTPSecretString encodes a secret as unpadded base32 for manual entry.
func TOTPSecretString(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPStep returns the time step number for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod/time.Second) }

// HOTP computes the RFC 4226 code for counter with the given number of digits.
func HOTP(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// TOTPCode returns the 6-digit code for step.
func TOTPCode(secret []byte, step int64) string {
	return HOTP(secret, uint64(step), TOTPDigits) //nolint:gosec // G115: steps are positive
}

// MatchTOTP checks code against the steps around now and returns the
// matching step. Callers must reject steps at or before the last accepted
// one, so every code works only once.
func MatchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	matched, found := int64(0), false
	// Check every candidate step so the time taken doesn't depend on which matched.
	for s := cur - TOTPSkew; s <= cur+TOTPSkew; s++ {
		if hmac.Equal([]byte(TOTPCode(secret, s)), []byte(code)) && !found {
			matched, found = s, true
		}
	}
	return matched, found
}

// TOTPURI returns the otpauth:// URI that authenticator apps read from the
// QR code (Key Uri Format).
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", TOTPSecretString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(int(TOTPPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
