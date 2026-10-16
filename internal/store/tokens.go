package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Scope says what a token may read.
type Scope struct {
	Buckets  []string   `json:"buckets"`
	Prefixes []string   `json:"prefixes,omitempty"`
	Git      []GitScope `json:"git,omitempty"`
}

// GitScope allows reading repos matching Repos on one git remote.
type GitScope struct {
	Remote string   `json:"remote"`
	Repos  []string `json:"repos"`
}

// Token is a stored token. The plaintext value is never stored, only Hash.
type Token struct {
	ID          string            `json:"id"`
	Hash        string            `json:"-"`
	Kind        string            `json:"kind"`
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
	Scope       Scope             `json:"scope"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	RevokedAt   *time.Time        `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	Requests    int64             `json:"requests"`
	Bytes       int64             `json:"bytes"`
}

// Usable reports whether the token is neither expired nor revoked at now.
func (t *Token) Usable(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

// CreateToken inserts a token.
func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	labels, _ := json.Marshal(t.Labels)
	scope, _ := json.Marshal(t.Scope)
	_, err := s.db.ExecContext(ctx, `INSERT INTO tokens
		(id, hash, kind, description, labels, scope, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, t.Kind, t.Description, string(labels), string(scope), t.CreatedBy,
		t.CreatedAt.Unix(), t.ExpiresAt.Unix())
	return err
}

//nolint:gosec // G101 false positive: a column list, not a credential
const tokenCols = `id, hash, kind, description, labels, scope, created_by, created_at, expires_at, revoked_at, last_used_at, requests, bytes`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var labels, scope string
	var created, expires int64
	var revoked, lastUsed sql.NullInt64
	if err := row.Scan(&t.ID, &t.Hash, &t.Kind, &t.Description, &labels, &scope, &t.CreatedBy,
		&created, &expires, &revoked, &lastUsed, &t.Requests, &t.Bytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(labels), &t.Labels)
	if err := json.Unmarshal([]byte(scope), &t.Scope); err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.ExpiresAt = time.Unix(expires, 0).UTC()
	t.RevokedAt = fromUnix(revoked)
	t.LastUsedAt = fromUnix(lastUsed)
	return &t, nil
}

// TokenByHash looks a token up by the SHA-256 hash of its value.
func (s *Store) TokenByHash(ctx context.Context, hash string) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE hash = ?`, hash))
}

// TokenByID looks a token up by its public ID.
func (s *Store) TokenByID(ctx context.Context, id string) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id = ?`, id))
}

// ListTokens returns tokens that are still usable at now, newest first. If
// createdBy is not empty only that creator's tokens are returned.
func (s *Store) ListTokens(ctx context.Context, now time.Time, createdBy string) ([]*Token, error) {
	q := `SELECT ` + tokenCols + ` FROM tokens WHERE revoked_at IS NULL AND expires_at > ?`
	args := []any{now.Unix()}
	if createdBy != "" {
		q += ` AND created_by = ?`
		args = append(args, createdBy)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken marks a token revoked. It returns ErrNotFound if the token
// doesn't exist or is already revoked.
func (s *Store) RevokeToken(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Usage is accumulated request and byte counts for one token.
type Usage struct {
	Requests int64
	Bytes    int64
	LastUsed time.Time
}

// AddUsage adds batched usage counters (FR-22).
func (s *Store) AddUsage(ctx context.Context, usage map[string]Usage) error {
	if len(usage) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for id, u := range usage {
		if _, err := tx.ExecContext(ctx, `UPDATE tokens SET requests = requests + ?, bytes = bytes + ?,
			last_used_at = MAX(COALESCE(last_used_at, 0), ?) WHERE id = ?`, u.Requests, u.Bytes, u.LastUsed.Unix(), id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// PurgeTokens deletes tokens that expired or were revoked before cutoff.
// Recently dead tokens are kept so they're still recognised (FR-24).
func (s *Store) PurgeTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	// A token is dead from the earlier of its revocation and its expiry.
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE MIN(COALESCE(revoked_at, expires_at), expires_at) < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountActiveTokens returns usable tokens per kind, for metrics.
func (s *Store) CountActiveTokens(ctx context.Context, now time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, COUNT(*) FROM tokens WHERE revoked_at IS NULL AND expires_at > ? GROUP BY kind`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}
