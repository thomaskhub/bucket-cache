package users

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

func init() { auth.PasswordParams = auth.Argon2Params{Memory: 64, Time: 1, Threads: 1} }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time            { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration)       { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func (c *clock) step(secret []byte) string { return auth.TOTPCode(secret, auth.TOTPStep(c.Now())) }

type fixture struct {
	svc    *Service
	st     *store.Store
	clk    *clock
	sealer *auth.Sealer
	logs   *bytes.Buffer
}

func b32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// wrongCode returns a code that differs from c in every digit.
func wrongCode(c string) string {
	b := []byte(c)
	for i := range b {
		b[i] = '0' + (b[i]-'0'+5)%10
	}
	return string(b)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealer, err := auth.NewSealer("test-master-key-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	svc := New(st, sealer, slog.New(slog.NewTextHandler(logs, nil)), Options{})
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	svc.Now = clk.Now
	return &fixture{svc: svc, st: st, clk: clk, sealer: sealer, logs: logs}
}

// enrol logs in with the password only, enrols TOTP and returns the secret.
func (f *fixture) enrol(t *testing.T, name, pw string) (*Session, []byte) {
	t.Helper()
	ctx := context.Background()
	ss, err := f.svc.Login(ctx, name, pw, "", "10.0.0.1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	if ss.Stage() != StageEnrolTOTP || ss.MFA {
		t.Fatalf("stage = %s, mfa = %v", ss.Stage(), ss.MFA)
	}
	e, err := f.svc.StartEnrolment(ctx, ss)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.URI, "otpauth://totp/yproxy:"+name+"?") || len(e.QRPNG) < 100 || !bytes.HasPrefix(e.QRPNG, []byte("\x89PNG")) {
		t.Fatalf("enrolment = %s, %d bytes", e.URI, len(e.QRPNG))
	}
	secret, err := b32Decode(e.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ConfirmEnrolment(ctx, ss, wrongCode(f.clk.step(secret))); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong confirmation code: %v", err)
	}
	if err := f.svc.ConfirmEnrolment(ctx, ss, f.clk.step(secret)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !ss.MFA || !ss.User.TOTPEnrolled() {
		t.Fatalf("after confirm: mfa=%v enrolled=%v", ss.MFA, ss.User.TOTPEnrolled())
	}
	return ss, secret
}

func TestBootstrapAndFirstLogin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	created, err := f.svc.Bootstrap(ctx, "admin\n", "initial-pass-1234")
	if err != nil || !created {
		t.Fatalf("Bootstrap = %v, %v", created, err)
	}
	// Only when the table is empty.
	if created, _ := f.svc.Bootstrap(ctx, "other", "initial-pass-1234"); created {
		t.Fatal("bootstrapped twice")
	}
	u, _ := f.st.UserByName(ctx, "admin")
	if u.Role != RoleAdmin || !u.MustChangePassword || u.TOTPEnrolled() {
		t.Fatalf("bootstrap admin = %+v", u)
	}

	ss, secret := f.enrol(t, "admin", "initial-pass-1234")
	if ss.Stage() != StageChangePassword {
		t.Fatalf("stage after enrolment = %s", ss.Stage())
	}
	if _, err := f.svc.StartEnrolment(ctx, ss); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second enrolment = %v", err)
	}
	if err := f.svc.ChangePassword(ctx, ss, "initial-pass-1234", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := f.svc.ChangePassword(ctx, ss, "wrong-current-pass", "a-much-better-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current password = %v", err)
	}
	if err := f.svc.ChangePassword(ctx, ss, "initial-pass-1234", "a-much-better-password"); err != nil {
		t.Fatal(err)
	}
	if ss.Stage() != StageOK {
		t.Fatalf("stage = %s", ss.Stage())
	}

	// Now login needs password and TOTP.
	f.clk.Add(30 * time.Second)
	if _, err := f.svc.Login(ctx, "admin", "a-much-better-password", "", "10.0.0.1"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("login without code = %v", err)
	}
	if _, err := f.svc.Login(ctx, "admin", "initial-pass-1234", f.clk.step(secret), "10.0.0.1"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("old password = %v", err)
	}
	code := f.clk.step(secret)
	ss2, err := f.svc.Login(ctx, "Admin", "a-much-better-password", code, "10.0.0.1")
	if err != nil || ss2.Stage() != StageOK || !ss2.MFA {
		t.Fatalf("login = %v, %v", ss2, err)
	}
	// Replay: the same code is rejected, even within its window.
	if _, err := f.svc.Login(ctx, "admin", "a-much-better-password", code, "10.0.0.1"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("replayed code = %v", err)
	}
	// Session lookups work with the cookie value, not the stored hash.
	if _, err := f.svc.Authenticate(ctx, ss2.Secret()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, ss2.IDHash); !errors.Is(err, ErrNoSession) {
		t.Fatalf("hash accepted as cookie: %v", err)
	}
	if f.svc.CheckCSRF(ss2, "") || !f.svc.CheckCSRF(ss2, f.svc.CSRFToken(ss2)) || f.svc.CheckCSRF(ss2, f.svc.CSRFToken(ss)) {
		t.Fatal("CSRF token checks")
	}

	// Nothing secret reaches the log.
	for _, s := range []string{"initial-pass-1234", "a-much-better-password", code, ss2.Secret(), auth.TOTPSecretString(secret)} {
		if strings.Contains(f.logs.String(), s) {
			t.Fatalf("log contains a secret: %q", s)
		}
	}
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.CreateUser(ctx, "bob", RoleUser, "bobs-password-123")
	for i := 0; i < 5; i++ {
		if _, err := f.svc.Login(ctx, "bob", "wrong", "", "10.0.0.2"); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("attempt %d = %v", i, err)
		}
	}
	// Locked: even the right password is refused for 15 minutes.
	if _, err := f.svc.Login(ctx, "bob", "bobs-password-123", "", "10.0.0.3"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked login = %v", err)
	}
	f.clk.Add(14 * time.Minute)
	if _, err := f.svc.Login(ctx, "bob", "bobs-password-123", "", "10.0.0.3"); !errors.Is(err, ErrLocked) {
		t.Fatalf("still locked = %v", err)
	}
	f.clk.Add(2 * time.Minute)
	if _, err := f.svc.Login(ctx, "bob", "bobs-password-123", "", "10.0.0.3"); err != nil {
		t.Fatalf("after lock expired = %v", err)
	}
	u, _ := f.st.UserByName(ctx, "bob")
	if u.FailedLogins != 0 {
		t.Fatalf("failures not reset: %d", u.FailedLogins)
	}
	// An admin unlock clears a lock at once.
	for i := 0; i < 5; i++ {
		f.svc.Login(ctx, "bob", "wrong", "", "10.0.0.4")
	}
	f.svc.Unlock(ctx, u.ID)
	if _, err := f.svc.Login(ctx, "bob", "bobs-password-123", "", "10.0.0.4"); err != nil {
		t.Fatalf("after unlock = %v", err)
	}
}

func TestIPRateLimit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	for i := 0; i < 20; i++ {
		f.svc.Login(ctx, "nobody", "x", "", "10.9.9.9")
	}
	if _, err := f.svc.Login(ctx, "nobody", "x", "", "10.9.9.9"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("after 20 failures = %v", err)
	}
	if _, err := f.svc.Login(ctx, "nobody", "x", "", "10.9.9.8"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("other IP = %v", err)
	}
}

func TestSessionLifetime(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.CreateUser(ctx, "carol", RoleUser, "carols-password-1")
	ss, err := f.svc.Login(ctx, "carol", "carols-password-1", "", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	// Activity keeps the session alive past the idle timeout...
	for i := 0; i < 3; i++ {
		f.clk.Add(7 * time.Hour)
		if _, err := f.svc.Authenticate(ctx, ss.Secret()); err != nil {
			t.Fatalf("active session expired after %d checks: %v", i, err)
		}
	}
	// ...but not past the absolute lifetime (24h).
	f.clk.Add(4 * time.Hour)
	if _, err := f.svc.Authenticate(ctx, ss.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session past max age = %v", err)
	}
	ss, _ = f.svc.Login(ctx, "carol", "carols-password-1", "", "10.0.0.5")
	f.clk.Add(8*time.Hour + time.Minute)
	if _, err := f.svc.Authenticate(ctx, ss.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session = %v", err)
	}
	ss, _ = f.svc.Login(ctx, "carol", "carols-password-1", "", "10.0.0.5")
	f.svc.Logout(ctx, ss)
	if _, err := f.svc.Authenticate(ctx, ss.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("after logout = %v", err)
	}
}

func TestAdminOperations(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	admin, _, _ := f.svc.CreateUser(ctx, "root", RoleAdmin, "root-password-123")
	dev, pw, err := f.svc.CreateUser(ctx, "dev", RoleUser, "")
	if err != nil || len(pw) != 20 {
		t.Fatalf("CreateUser = %v, %q", err, pw)
	}
	if _, _, err := f.svc.CreateUser(ctx, "DEV", RoleUser, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	for _, bad := range []string{"", "-x", "a b", strings.Repeat("a", 65)} {
		if _, _, err := f.svc.CreateUser(ctx, bad, RoleUser, ""); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("username %q: %v", bad, err)
		}
	}
	if _, _, err := f.svc.CreateUser(ctx, "x", "root", ""); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("bad role = %v", err)
	}

	// The last admin can't be disabled, demoted or deleted, nor act on itself.
	if err := f.svc.SetDisabled(ctx, admin.ID, true, ""); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin = %v", err)
	}
	if err := f.svc.SetRole(ctx, admin.ID, RoleUser, ""); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin = %v", err)
	}
	if err := f.svc.Delete(ctx, admin.ID, dev.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin = %v", err)
	}
	if err := f.svc.SetDisabled(ctx, admin.ID, true, admin.ID); !errors.Is(err, ErrSelf) {
		t.Fatalf("disable self = %v", err)
	}

	// Disabling ends sessions and blocks login.
	ss, err := f.svc.Login(ctx, "dev", pw, "", "10.0.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SetDisabled(ctx, dev.ID, true, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, ss.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("disabled user's session = %v", err)
	}
	if _, err := f.svc.Login(ctx, "dev", pw, "", "10.0.0.6"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("disabled login = %v", err)
	}
	f.svc.SetDisabled(ctx, dev.ID, false, admin.ID)

	// Reset TOTP: the user enrols again; reset password forces a change.
	_, secret := f.enrol(t, "dev", pw)
	f.clk.Add(30 * time.Second)
	if _, err := f.svc.Login(ctx, "dev", pw, f.clk.step(secret), "10.0.0.6"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ResetTOTP(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	ss, err = f.svc.Login(ctx, "dev", pw, "", "10.0.0.6")
	if err != nil || ss.Stage() != StageEnrolTOTP {
		t.Fatalf("after TOTP reset: %v, %v", ss, err)
	}
	newPW, err := f.svc.ResetPassword(ctx, dev.ID, "")
	if err != nil || newPW == "" {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, ss.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session after password reset = %v", err)
	}
	if err := f.svc.SetRole(ctx, dev.ID, RoleAdmin, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, admin.ID, dev.ID); err != nil {
		t.Fatalf("delete admin with another admin left = %v", err)
	}
}

// A session created before enrolment can't be used once TOTP is set up
// elsewhere: the user must log in with a code.
func TestPreEnrolmentSessionInvalidatedByEnrolment(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.CreateUser(ctx, "eve", RoleUser, "eves-password-123")
	early, _ := f.svc.Login(ctx, "eve", "eves-password-123", "", "10.0.0.7")
	f.enrol(t, "eve", "eves-password-123")
	if _, err := f.svc.Authenticate(ctx, early.Secret()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("pre-enrolment session = %v", err)
	}
}

func TestWrongEncryptionKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.CreateUser(ctx, "frank", RoleUser, "franks-password-1")
	_, secret := f.enrol(t, "frank", "franks-password-1")
	other, _ := auth.NewSealer("another-master-key-9876543210")
	svc2 := New(f.st, other, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), Options{})
	svc2.Now = f.clk.Now
	f.clk.Add(30 * time.Second)
	if _, err := svc2.Login(ctx, "frank", "franks-password-1", f.clk.step(secret), "10.0.0.8"); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("login with another key = %v", err)
	}
}

func TestLoginDisabledWithoutKey(t *testing.T) {
	f := newFixture(t)
	svc := New(f.st, nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), Options{})
	if _, err := svc.Login(context.Background(), "x", "y", "", "1.2.3.4"); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("login without key = %v", err)
	}
}
