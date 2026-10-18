package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrConflict is returned when a unique value (a username) is already taken.
var ErrConflict = errors.New("already exists")

// User is a web UI user. Secrets are stored hashed (password) or sealed
// (TOTP) and are never serialised.
type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Role               string     `json:"role"`
	PasswordHash       string     `json:"-"`
	MustChangePassword bool       `json:"must_change_password"`
	TOTPSecret         string     `json:"-"` // sealed; "" until enrolled
	TOTPPending        string     `json:"-"` // sealed; set during enrolment
	TOTPLastStep       int64      `json:"-"`
	FailedLogins       int        `json:"failed_logins"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	DisabledAt         *time.Time `json:"disabled_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

// TOTPEnrolled reports whether the user has a confirmed TOTP secret.
func (u *User) TOTPEnrolled() bool { return u.TOTPSecret != "" }

// Disabled reports whether an admin disabled the account.
func (u *User) Disabled() bool { return u.DisabledAt != nil }

// Locked reports whether the account is locked after failed logins at now.
func (u *User) Locked(now time.Time) bool { return u.LockedUntil != nil && now.Before(*u.LockedUntil) }

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateUser inserts a user. It returns ErrConflict if the username exists
// (usernames compare case-insensitively).
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users
		(id, username, role, password_hash, must_change_password, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Role, u.PasswordHash, u.MustChangePassword, u.CreatedAt.Unix())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

const userCols = `id, username, role, password_hash, must_change_password, totp_secret, totp_pending,
	totp_last_step, failed_logins, locked_until, disabled_at, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var secret, pending sql.NullString
	var created int64
	var locked, disabled, lastLogin sql.NullInt64
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &u.MustChangePassword, &secret, &pending,
		&u.TOTPLastStep, &u.FailedLogins, &locked, &disabled, &created, &lastLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.TOTPSecret, u.TOTPPending = secret.String, pending.String
	u.LockedUntil = fromUnix(locked)
	u.DisabledAt = fromUnix(disabled)
	u.CreatedAt = time.Unix(created, 0).UTC()
	u.LastLoginAt = fromUnix(lastLogin)
	return &u, nil
}

// UserByID looks a user up by ID.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByName looks a user up by username, ignoring case.
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountActiveAdmins returns the number of enabled admins.
func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&n)
	return n, err
}

func (s *Store) updateUser(ctx context.Context, id, set string, args ...any) error {
	//nolint:gosec // G202: set is a constant from this file; values are bound parameters
	res, err := s.db.ExecContext(ctx, `UPDATE users SET `+set+` WHERE id = ?`, append(args, id)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword stores a new password hash, sets the forced-change flag and
// clears any lockout.
func (s *Store) SetPassword(ctx context.Context, id, hash string, mustChange bool) error {
	return s.updateUser(ctx, id, `password_hash = ?, must_change_password = ?, failed_logins = 0, locked_until = NULL`, hash, mustChange)
}

// SetPendingTOTP stores a sealed secret that is waiting for confirmation.
func (s *Store) SetPendingTOTP(ctx context.Context, id, sealed string) error {
	return s.updateUser(ctx, id, `totp_pending = ?`, nullStr(sealed))
}

// ActivateTOTP makes the pending secret the active one and records step as
// used, so the confirmation code can't be replayed at login.
func (s *Store) ActivateTOTP(ctx context.Context, id string, step int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ?
		WHERE id = ? AND totp_pending IS NOT NULL`, step, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetTOTP removes the user's TOTP secret, so they must enrol again, and
// clears any lockout.
func (s *Store) ResetTOTP(ctx context.Context, id string) error {
	return s.updateUser(ctx, id, `totp_secret = NULL, totp_pending = NULL, totp_last_step = 0, failed_logins = 0, locked_until = NULL`)
}

// UseTOTPStep records step as used if it is later than the last used step.
// It reports false if the step (or a later one) was already used, which
// makes every code single-use even under concurrent logins.
func (s *Store) UseTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecordLoginFailure counts a failed login and locks the account until
// lockUntil once the count reaches maxFailures. It returns the new count.
func (s *Store) RecordLoginFailure(ctx context.Context, id string, maxFailures int, lockUntil time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `UPDATE users SET failed_logins = failed_logins + 1,
		locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END
		WHERE id = ? RETURNING failed_logins`, maxFailures, lockUntil.Unix(), id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

// RecordLoginSuccess resets the failure counter and sets last_login_at.
func (s *Store) RecordLoginSuccess(ctx context.Context, id string, now time.Time) error {
	return s.updateUser(ctx, id, `failed_logins = 0, locked_until = NULL, last_login_at = ?`, now.Unix())
}

// UnlockUser clears a lockout after failed logins.
func (s *Store) UnlockUser(ctx context.Context, id string) error {
	return s.updateUser(ctx, id, `failed_logins = 0, locked_until = NULL`)
}

// SetUserRole changes a user's role.
func (s *Store) SetUserRole(ctx context.Context, id, role string) error {
	return s.updateUser(ctx, id, `role = ?`, role)
}

// SetUserDisabled disables (at now) or re-enables a user.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool, now time.Time) error {
	var at any
	if disabled {
		at = now.Unix()
	}
	return s.updateUser(ctx, id, `disabled_at = ?`, at)
}

// DeleteUser removes a user and, through the foreign key, their sessions.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeTokensBy revokes every usable token created by createdBy and
// returns the IDs revoked, so callers can clear them from caches.
func (s *Store) RevokeTokensBy(ctx context.Context, createdBy string, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE created_by = ? AND revoked_at IS NULL RETURNING id`,
		now.Unix(), createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Session is a logged-in web UI session. Only the hash of the cookie value
// is stored.
type Session struct {
	IDHash     string
	UserID     string
	MFA        bool // a TOTP code was verified for this session
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateSession inserts a session.
func (s *Store) CreateSession(ctx context.Context, ss *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, mfa, created_at, last_seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ss.IDHash, ss.UserID, ss.MFA, ss.CreatedAt.Unix(), ss.LastSeenAt.Unix(), ss.ExpiresAt.Unix())
	return err
}

// SessionByHash looks up a session by the hash of its cookie value.
func (s *Store) SessionByHash(ctx context.Context, hash string) (*Session, error) {
	var ss Session
	var created, seen, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash, user_id, mfa, created_at, last_seen_at, expires_at FROM sessions WHERE id_hash = ?`, hash).
		Scan(&ss.IDHash, &ss.UserID, &ss.MFA, &created, &seen, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ss.CreatedAt, ss.LastSeenAt, ss.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(seen, 0).UTC(), time.Unix(expires, 0).UTC()
	return &ss, nil
}

// TouchSession records activity on a session (for the idle timeout).
func (s *Store) TouchSession(ctx context.Context, hash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, now.Unix(), hash)
	return err
}

// SetSessionMFA marks a session as having passed a TOTP check.
func (s *Store) SetSessionMFA(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET mfa = 1 WHERE id_hash = ?`, hash)
	return err
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, hash)
	return err
}

// DeleteUserSessions removes a user's sessions except keepHash (may be "").
func (s *Store) DeleteUserSessions(ctx context.Context, userID, keepHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`, userID, keepHash)
	return err
}

// PurgeSessions deletes sessions that expired or were idle since before idleCutoff.
func (s *Store) PurgeSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at < ?`, now.Unix(), idleCutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
