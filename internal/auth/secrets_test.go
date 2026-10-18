package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 rows (8 digits, 30 s steps).
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		step := TOTPStep(time.Unix(c.unix, 0))
		if got := HOTP(secret, uint64(step), 8); got != c.code {
			t.Errorf("t=%d: got %s, want %s", c.unix, got, c.code)
		}
		// The 6-digit code is the low 6 digits of the same value.
		if got := TOTPCode(secret, step); got != c.code[2:] {
			t.Errorf("t=%d: 6-digit code %s, want %s", c.unix, got, c.code[2:])
		}
	}
}

func TestMatchTOTPWindow(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_015, 0)
	cur := TOTPStep(now)
	for _, d := range []int64{-1, 0, 1} {
		step, ok := MatchTOTP(secret, TOTPCode(secret, cur+d), now)
		if !ok || step != cur+d {
			t.Errorf("offset %d: ok=%v step=%d", d, ok, step)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := MatchTOTP(secret, TOTPCode(secret, cur+d), now); ok {
			t.Errorf("offset %d accepted", d)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := MatchTOTP(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("yproxy", "alice@example", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/yproxy:alice@example?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=yproxy", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI %s lacks %s", u, want)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	old := PasswordParams
	PasswordParams = Argon2Params{Memory: 64, Time: 1, Threads: 1}
	defer func() { PasswordParams = old }()

	h := HashPassword("correct horse battery")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash format: %s", h)
	}
	if err := VerifyPassword(h, "correct horse battery"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyPassword(h, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if a, b := HashPassword("x"), HashPassword("x"); a == b {
		t.Fatal("hashes are not salted")
	}
	for _, bad := range []string{"", "$2a$10$abc", "$argon2id$v=19$m=64,t=1,p=1$!!$abc", "$argon2i$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA"} {
		if err := VerifyPassword(bad, "x"); err == nil || errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("malformed hash %q: %v", bad, err)
		}
	}
	// Hashes made with other parameters still verify.
	PasswordParams = Argon2Params{Memory: 128, Time: 2, Threads: 2}
	h2 := HashPassword("pw")
	PasswordParams = Argon2Params{Memory: 64, Time: 1, Threads: 1}
	if err := VerifyPassword(h2, "pw"); err != nil {
		t.Fatalf("verify with stored params: %v", err)
	}
}

func TestNewPassword(t *testing.T) {
	p := NewPassword()
	if len(p) != 20 || p == NewPassword() {
		t.Fatalf("NewPassword = %q", p)
	}
}

func TestSealer(t *testing.T) {
	s, err := NewSealer("a-master-key-that-is-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.Seal([]byte("totp secret"), "usr_1")
	if strings.Contains(sealed, "totp secret") || !strings.HasPrefix(sealed, "v1:") {
		t.Fatalf("sealed = %s", sealed)
	}
	if s.Seal([]byte("totp secret"), "usr_1") == sealed {
		t.Fatal("nonce reused")
	}
	pt, err := s.Open(sealed, "usr_1")
	if err != nil || string(pt) != "totp secret" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := s.Open(sealed, "usr_2"); !errors.Is(err, ErrUnseal) {
		t.Fatalf("other record: %v", err)
	}
	other, _ := NewSealer("a-different-master-key-000000")
	if _, err := other.Open(sealed, "usr_1"); !errors.Is(err, ErrUnseal) {
		t.Fatalf("wrong key: %v", err)
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, err := s.Open(tampered, "usr_1"); !errors.Is(err, ErrUnseal) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := NewSealer("short"); err == nil {
		t.Fatal("short key accepted")
	}

	tok := s.CSRFToken("yps_session")
	if !s.CheckCSRF("yps_session", tok) || s.CheckCSRF("yps_other", tok) || s.CheckCSRF("yps_session", "") {
		t.Fatal("CSRF check")
	}
	if other.CheckCSRF("yps_session", tok) {
		t.Fatal("CSRF token valid under another key")
	}
}
