package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Sealer encrypts small secrets stored in the database (TOTP secrets) with
// AES-256-GCM (SEC-13). The key is derived with HKDF-SHA256 from the
// auth.db_encryption_key secret, so the secret file can hold any string.
type Sealer struct {
	aead    cipher.AEAD
	csrfKey []byte
}

const sealedPrefix = "v1:"

// ErrUnseal means a value couldn't be decrypted: it was changed, belongs to
// another record, or db_encryption_key is not the key it was sealed with.
var ErrUnseal = errors.New("cannot decrypt stored secret (was auth.db_encryption_key changed?)")

// NewSealer derives the encryption keys from master.
func NewSealer(master string) (*Sealer, error) {
	if len(master) < 16 {
		return nil, errors.New("auth.db_encryption_key must be at least 16 characters")
	}
	key, err := hkdf.Key(sha256.New, []byte(master), nil, "yproxy db encryption v1", 32)
	if err != nil {
		return nil, err
	}
	csrf, err := hkdf.Key(sha256.New, []byte(master), nil, "yproxy csrf v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, csrfKey: csrf}, nil
}

// Seal encrypts plaintext. aad binds the ciphertext to its record (the user
// ID), so a sealed value copied to another row doesn't decrypt.
func (s *Sealer) Seal(plaintext []byte, aad string) string {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := s.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(out)
}

// Open decrypts a value from Seal.
func (s *Sealer) Open(sealed, aad string) ([]byte, error) {
	raw, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return nil, ErrUnseal
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(b) < s.aead.NonceSize() {
		return nil, ErrUnseal
	}
	n := s.aead.NonceSize()
	pt, err := s.aead.Open(nil, b[:n], b[n:], []byte(aad))
	if err != nil {
		return nil, ErrUnseal
	}
	return pt, nil
}

// CSRFToken derives the CSRF token for a session from the session secret.
// It is stable for the session's lifetime and needs no storage.
func (s *Sealer) CSRFToken(sessionSecret string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte(sessionSecret))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// CheckCSRF reports whether token is the CSRF token for sessionSecret.
func (s *Sealer) CheckCSRF(sessionSecret, token string) bool {
	return token != "" && hmac.Equal([]byte(s.CSRFToken(sessionSecret)), []byte(token))
}
