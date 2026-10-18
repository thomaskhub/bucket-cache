// Package users implements web UI users: login with password and TOTP,
// enrolment, password changes, lockout and server-side sessions (FR-61,
// FR-64, SEC-13).
package users

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

const (
	// CookieName is the session cookie.
	CookieName = "yproxy_session"
	// SessionPrefix marks session cookie values.
	SessionPrefix = "yps_"

	RoleAdmin = "admin"
	RoleUser  = "user"

	// MinPasswordLength applies to passwords users choose.
	MinPasswordLength = 12
)

// Login and session errors. The login errors deliberately don't say which
// factor was wrong.
var (
	ErrInvalidLogin     = errors.New("invalid username, password or code")
	ErrLocked           = errors.New("account temporarily locked after repeated failed logins; try again later or ask an admin")
	ErrRateLimited      = errors.New("too many failed logins from this address; try again later")
	ErrNoSession        = errors.New("not logged in or session expired")
	ErrInvalidCode      = errors.New("invalid code")
	ErrAlreadyEnrolled  = errors.New("TOTP is already set up; an admin can reset it")
	ErrEnrolFirst       = errors.New("set up TOTP first")
	ErrWrongPassword    = errors.New("current password is wrong")
	ErrLastAdmin        = errors.New("this would leave no enabled admin")
	ErrSelf             = errors.New("you can't do this to your own account")
	ErrInvalidUsername  = errors.New("username must be 1-64 letters, digits, '.', '_', '@' or '-', starting with a letter or digit")
	ErrInvalidRole      = errors.New("role must be admin or user")
	ErrUnsealFailed     = errors.New("stored TOTP secret can't be decrypted")
	ErrLoginUnavailable = errors.New("web UI login is disabled: auth.db_encryption_key is not configured")
)

// Stages of a session. Only StageOK sessions may use the API.
const (
	StageEnrolTOTP      = "totp_enrolment"
	StageChangePassword = "password_change"
	StageOK             = "ok"
)

// Options tunes the service. Zero values get the defaults from FR-61.
type Options struct {
	IdleTimeout time.Duration // default 8h
	MaxAge      time.Duration // absolute session lifetime, default 24h
	MaxFailures int           // consecutive failures before lockout, default 5
	LockFor     time.Duration // default 15m
	Issuer      string        // shown in authenticator apps, default "yproxy"
}

// Service manages users and sessions.
type Service struct {
	st     *store.Store
	sealer *auth.Sealer // nil: login disabled (no db_encryption_key)
	log    *slog.Logger
	opt    Options
	ipLim  *auth.IPLimiter
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// New returns a Service. sealer may be nil, in which case user management
// works but nobody can log in (TOTP secrets can't be stored safely).
func New(st *store.Store, sealer *auth.Sealer, log *slog.Logger, opt Options) *Service {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 8 * time.Hour
	}
	if opt.MaxAge <= 0 {
		opt.MaxAge = 24 * time.Hour
	}
	if opt.MaxFailures <= 0 {
		opt.MaxFailures = 5
	}
	if opt.LockFor <= 0 {
		opt.LockFor = 15 * time.Minute
	}
	if opt.Issuer == "" {
		opt.Issuer = "yproxy"
	}
	return &Service{st: st, sealer: sealer, log: log, opt: opt,
		// 20 failures at once, then one more every 30 s per client IP.
		ipLim: auth.NewIPLimiter(1.0/30, 20), Now: time.Now}
}

// LoginEnabled reports whether logins are possible.
func (s *Service) LoginEnabled() bool { return s.sealer != nil }

// IdleTimeout returns the session idle timeout.
func (s *Service) IdleTimeout() time.Duration { return s.opt.IdleTimeout }

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// InputError is a problem with what the user entered; its message is safe
// to show.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// ValidatePassword checks a password a user chose.
func ValidatePassword(pw, username string) error {
	switch {
	case utf8.RuneCountInString(pw) < MinPasswordLength:
		return &InputError{fmt.Sprintf("password must be at least %d characters", MinPasswordLength)}
	case len(pw) > 256:
		return &InputError{"password must be at most 256 bytes"}
	case strings.EqualFold(pw, username):
		return &InputError{"password must not be the username"}
	}
	return nil
}

// Bootstrap creates the initial admin from the secret files if there are
// no users yet (FR-64). It reports whether a user was created.
func (s *Service) Bootstrap(ctx context.Context, username, password string) (bool, error) {
	if username == "" || password == "" {
		return false, nil
	}
	n, err := s.st.CountUsers(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	if _, _, err := s.CreateUser(ctx, strings.TrimSpace(username), RoleAdmin, password); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateUser adds a user who must enrol TOTP and change the password at
// first login. If password is empty a one-time password is generated and
// returned.
func (s *Service) CreateUser(ctx context.Context, username, role, password string) (*store.User, string, error) {
	if !usernameRe.MatchString(username) {
		return nil, "", ErrInvalidUsername
	}
	if role != RoleAdmin && role != RoleUser {
		return nil, "", ErrInvalidRole
	}
	generated := ""
	if password == "" {
		password = auth.NewPassword()
		generated = password
	} else if len(password) > 256 {
		return nil, "", &InputError{"password must be at most 256 bytes"}
	}
	u := &store.User{ID: auth.NewID("usr_"), Username: username, Role: role, PasswordHash: auth.HashPassword(password),
		MustChangePassword: true, CreatedAt: s.Now().UTC().Truncate(time.Second)}
	if err := s.st.CreateUser(ctx, u); err != nil {
		return nil, "", err
	}
	s.log.Info("user created", "user_id", u.ID, "role", role)
	return u, generated, nil
}

// Session is an authenticated session with its user.
type Session struct {
	*store.Session
	User   *store.User
	secret string // cookie value; needed to derive the CSRF token
}

// Secret returns the cookie value. It must never be logged.
func (ss *Session) Secret() string { return ss.secret }

// Stage says what the user must do before using the rest of the UI.
func (ss *Session) Stage() string {
	switch {
	case !ss.User.TOTPEnrolled():
		return StageEnrolTOTP
	case ss.User.MustChangePassword:
		return StageChangePassword
	default:
		return StageOK
	}
}

// Login checks password and TOTP code and creates a session (FR-61). A user
// who hasn't enrolled TOTP yet gets a session that can only enrol.
func (s *Service) Login(ctx context.Context, username, password, code, ip string) (*Session, error) {
	if s.sealer == nil {
		return nil, ErrLoginUnavailable
	}
	if s.ipLim.Blocked(ip) {
		return nil, ErrRateLimited
	}
	now := s.Now()
	u, err := s.st.UserByName(ctx, strings.TrimSpace(username))
	if errors.Is(err, store.ErrNotFound) {
		auth.BurnPasswordCheck(password)
		s.ipLim.Allow(ip)
		s.log.Warn("login failed", "reason", "unknown user", "client_ip", ip)
		return nil, ErrInvalidLogin
	}
	if err != nil {
		return nil, err
	}
	if u.Locked(now) {
		s.ipLim.Allow(ip)
		s.log.Warn("login refused", "reason", "locked", "user_id", u.ID, "client_ip", ip)
		return nil, ErrLocked
	}
	if u.Disabled() {
		auth.BurnPasswordCheck(password)
		s.ipLim.Allow(ip)
		s.log.Warn("login failed", "reason", "disabled", "user_id", u.ID, "client_ip", ip)
		return nil, ErrInvalidLogin
	}
	if err := auth.VerifyPassword(u.PasswordHash, password); err != nil {
		if !errors.Is(err, auth.ErrPasswordMismatch) {
			return nil, err
		}
		return nil, s.fail(ctx, u, ip, "wrong password")
	}
	mfa := false
	if u.TOTPEnrolled() {
		secret, err := s.sealer.Open(u.TOTPSecret, u.ID)
		if err != nil {
			s.log.Error("cannot decrypt TOTP secret; reset it with 'yproxy user reset-totp' or restore the old db_encryption_key", "user_id", u.ID)
			return nil, ErrUnsealFailed
		}
		step, ok := auth.MatchTOTP(secret, code, now)
		if !ok {
			return nil, s.fail(ctx, u, ip, "wrong code")
		}
		fresh, err := s.st.UseTOTPStep(ctx, u.ID, step)
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, s.fail(ctx, u, ip, "replayed code")
		}
		mfa = true
	}
	if err := s.st.RecordLoginSuccess(ctx, u.ID, now); err != nil {
		return nil, err
	}
	ss, err := s.newSession(ctx, u, mfa)
	if err != nil {
		return nil, err
	}
	s.log.Info("login", "user_id", u.ID, "stage", ss.Stage(), "client_ip", ip)
	return ss, nil
}

func (s *Service) fail(ctx context.Context, u *store.User, ip, reason string) error {
	s.ipLim.Allow(ip)
	n, err := s.st.RecordLoginFailure(ctx, u.ID, s.opt.MaxFailures, s.Now().Add(s.opt.LockFor))
	if err != nil {
		return err
	}
	s.log.Warn("login failed", "reason", reason, "user_id", u.ID, "failures", n, "client_ip", ip)
	if n >= s.opt.MaxFailures {
		s.log.Warn("account locked after repeated failed logins", "user_id", u.ID, "lock_for", s.opt.LockFor.String())
	}
	return ErrInvalidLogin
}

func (s *Service) newSession(ctx context.Context, u *store.User, mfa bool) (*Session, error) {
	now := s.Now().UTC().Truncate(time.Second)
	secret := auth.NewSecret(SessionPrefix)
	ss := &store.Session{IDHash: auth.Hash(secret), UserID: u.ID, MFA: mfa, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.opt.MaxAge)}
	if err := s.st.CreateSession(ctx, ss); err != nil {
		return nil, err
	}
	return &Session{Session: ss, User: u, secret: secret}, nil
}

// Authenticate returns the session for a cookie value, enforcing the idle
// timeout and absolute lifetime.
func (s *Service) Authenticate(ctx context.Context, secret string) (*Session, error) {
	if s.sealer == nil || !strings.HasPrefix(secret, SessionPrefix) || len(secret) > 100 {
		return nil, ErrNoSession
	}
	h := auth.Hash(secret)
	ss, err := s.st.SessionByHash(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.Now()
	if !now.Before(ss.ExpiresAt) || now.Sub(ss.LastSeenAt) > s.opt.IdleTimeout {
		_ = s.st.DeleteSession(ctx, h)
		return nil, ErrNoSession
	}
	u, err := s.st.UserByID(ctx, ss.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	// A session without a TOTP check is only good for enrolling; once the
	// user has TOTP it must log in again with a code.
	if u.Disabled() || (u.TOTPEnrolled() && !ss.MFA) {
		_ = s.st.DeleteSession(ctx, h)
		return nil, ErrNoSession
	}
	if now.Sub(ss.LastSeenAt) > time.Minute { // limit writes; the idle timeout is hours
		if err := s.st.TouchSession(ctx, h, now); err == nil {
			ss.LastSeenAt = now.UTC().Truncate(time.Second)
		}
	}
	return &Session{Session: ss, User: u, secret: secret}, nil
}

// Logout ends a session.
func (s *Service) Logout(ctx context.Context, ss *Session) error {
	s.log.Info("logout", "user_id", ss.UserID)
	return s.st.DeleteSession(ctx, ss.IDHash)
}

// CSRFToken returns the CSRF token for a session (SEC-22).
func (s *Service) CSRFToken(ss *Session) string { return s.sealer.CSRFToken(ss.secret) }

// CheckCSRF reports whether token matches the session.
func (s *Service) CheckCSRF(ss *Session, token string) bool {
	return s.sealer.CheckCSRF(ss.secret, token)
}

// Enrolment is what the user scans into an authenticator app. It is shown
// once; starting again replaces the pending secret.
type Enrolment struct {
	URI    string `json:"otpauth_uri"`
	Secret string `json:"secret"`
	QRPNG  []byte `json:"-"`
}

// StartEnrolment creates a new pending TOTP secret for the session's user.
func (s *Service) StartEnrolment(ctx context.Context, ss *Session) (*Enrolment, error) {
	if ss.User.TOTPEnrolled() {
		return nil, ErrAlreadyEnrolled
	}
	secret := auth.NewTOTPSecret()
	if err := s.st.SetPendingTOTP(ctx, ss.UserID, s.sealer.Seal(secret, ss.UserID)); err != nil {
		return nil, err
	}
	uri := auth.TOTPURI(s.opt.Issuer, ss.User.Username, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return &Enrolment{URI: uri, Secret: auth.TOTPSecretString(secret), QRPNG: png}, nil
}

// ConfirmEnrolment activates the pending secret if code matches it, and
// marks the session as having passed TOTP.
func (s *Service) ConfirmEnrolment(ctx context.Context, ss *Session, code string) error {
	u, err := s.st.UserByID(ctx, ss.UserID)
	if err != nil {
		return err
	}
	if u.TOTPEnrolled() {
		return ErrAlreadyEnrolled
	}
	if u.TOTPPending == "" {
		return &InputError{"start the TOTP setup first"}
	}
	secret, err := s.sealer.Open(u.TOTPPending, u.ID)
	if err != nil {
		return ErrUnsealFailed
	}
	step, ok := auth.MatchTOTP(secret, code, s.Now())
	if !ok {
		return ErrInvalidCode
	}
	if err := s.st.ActivateTOTP(ctx, u.ID, step); err != nil {
		return err
	}
	if err := s.st.SetSessionMFA(ctx, ss.IDHash); err != nil {
		return err
	}
	ss.MFA = true
	ss.User, err = s.st.UserByID(ctx, u.ID)
	if err != nil {
		return err
	}
	s.log.Info("totp enrolled", "user_id", u.ID)
	return nil
}

// ChangePassword sets a new password for the session's user and ends their
// other sessions.
func (s *Service) ChangePassword(ctx context.Context, ss *Session, current, next string) error {
	if !ss.User.TOTPEnrolled() {
		return ErrEnrolFirst
	}
	if err := auth.VerifyPassword(ss.User.PasswordHash, current); err != nil {
		if !errors.Is(err, auth.ErrPasswordMismatch) {
			return err
		}
		n, err := s.st.RecordLoginFailure(ctx, ss.UserID, s.opt.MaxFailures, s.Now().Add(s.opt.LockFor))
		if err != nil {
			return err
		}
		if n >= s.opt.MaxFailures { // locked: end every session, including this one
			_ = s.st.DeleteUserSessions(ctx, ss.UserID, "")
		}
		return ErrWrongPassword
	}
	if err := ValidatePassword(next, ss.User.Username); err != nil {
		return err
	}
	if next == current {
		return &InputError{"the new password must differ from the current one"}
	}
	if err := s.st.SetPassword(ctx, ss.UserID, auth.HashPassword(next), false); err != nil {
		return err
	}
	if err := s.st.DeleteUserSessions(ctx, ss.UserID, ss.IDHash); err != nil {
		return err
	}
	u, err := s.st.UserByID(ctx, ss.UserID)
	if err != nil {
		return err
	}
	ss.User = u
	s.log.Info("password changed", "user_id", u.ID)
	return nil
}

// Lookup finds a user by ID or, failing that, by username.
func (s *Service) Lookup(ctx context.Context, idOrName string) (*store.User, error) {
	u, err := s.st.UserByID(ctx, idOrName)
	if errors.Is(err, store.ErrNotFound) {
		return s.st.UserByName(ctx, idOrName)
	}
	return u, err
}

// ResetPassword sets a new password the user must change at next login and
// ends their sessions. An empty password generates a one-time password,
// which is returned.
func (s *Service) ResetPassword(ctx context.Context, id, password string) (string, error) {
	generated := ""
	if password == "" {
		password = auth.NewPassword()
		generated = password
	}
	if err := s.st.SetPassword(ctx, id, auth.HashPassword(password), true); err != nil {
		return "", err
	}
	if err := s.st.DeleteUserSessions(ctx, id, ""); err != nil {
		return "", err
	}
	s.log.Info("password reset", "user_id", id)
	return generated, nil
}

// ResetTOTP removes a user's TOTP secret (lost phone) and ends their
// sessions; they enrol again at next login.
func (s *Service) ResetTOTP(ctx context.Context, id string) error {
	if err := s.st.ResetTOTP(ctx, id); err != nil {
		return err
	}
	if err := s.st.DeleteUserSessions(ctx, id, ""); err != nil {
		return err
	}
	s.log.Info("totp reset", "user_id", id)
	return nil
}

// guardAdmins refuses changes that would leave no enabled admin.
func (s *Service) guardAdmins(ctx context.Context, target *store.User) error {
	if target.Role != RoleAdmin || target.Disabled() {
		return nil
	}
	n, err := s.st.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// SetDisabled disables or enables a user. actorID is the admin doing it;
// admins can't disable themselves.
func (s *Service) SetDisabled(ctx context.Context, id string, disabled bool, actorID string) error {
	u, err := s.st.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if disabled {
		if id == actorID {
			return ErrSelf
		}
		if err := s.guardAdmins(ctx, u); err != nil {
			return err
		}
	}
	if err := s.st.SetUserDisabled(ctx, id, disabled, s.Now()); err != nil {
		return err
	}
	if disabled {
		if err := s.st.DeleteUserSessions(ctx, id, ""); err != nil {
			return err
		}
	}
	s.log.Info("user updated", "user_id", id, "disabled", disabled, "by", actorID)
	return nil
}

// SetRole changes a user's role.
func (s *Service) SetRole(ctx context.Context, id, role, actorID string) error {
	if role != RoleAdmin && role != RoleUser {
		return ErrInvalidRole
	}
	u, err := s.st.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == role {
		return nil
	}
	if id == actorID {
		return ErrSelf
	}
	if err := s.guardAdmins(ctx, u); err != nil {
		return err
	}
	if err := s.st.SetUserRole(ctx, id, role); err != nil {
		return err
	}
	s.log.Info("user updated", "user_id", id, "role", role, "by", actorID)
	return nil
}

// Delete removes a user and their sessions.
func (s *Service) Delete(ctx context.Context, id, actorID string) error {
	u, err := s.st.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if id == actorID {
		return ErrSelf
	}
	if err := s.guardAdmins(ctx, u); err != nil {
		return err
	}
	if err := s.st.DeleteUser(ctx, id); err != nil {
		return err
	}
	s.log.Info("user deleted", "user_id", id, "by", actorID)
	return nil
}

// Unlock clears a lockout.
func (s *Service) Unlock(ctx context.Context, id string) error { return s.st.UnlockUser(ctx, id) }

// RunMaintenance deletes expired sessions every interval until ctx ends.
func (s *Service) RunMaintenance(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		now := s.Now()
		if _, err := s.st.PurgeSessions(ctx, now, now.Add(-s.opt.IdleTimeout)); err != nil && ctx.Err() == nil {
			s.log.Warn("purging sessions failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
