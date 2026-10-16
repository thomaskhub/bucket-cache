package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Ceiling limits the tokens an API key may issue. A nil ceiling (admin role)
// means no limit.
type Ceiling struct {
	Scope  Scope         `json:"scope"`
	MaxTTL time.Duration `json:"max_ttl"`
}

// APIKey is a long-lived key for CI and admins. Only Hash is stored.
type APIKey struct {
	ID         string     `json:"id"`
	Hash       string     `json:"-"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	Ceiling    *Ceiling   `json:"ceiling,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// CreateAPIKey inserts an API key.
func (s *Store) CreateAPIKey(ctx context.Context, k *APIKey) error {
	ceiling, _ := json.Marshal(k.Ceiling)
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (id, hash, name, role, ceiling, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, k.Hash, k.Name, k.Role, string(ceiling), k.CreatedAt.Unix())
	return err
}

//nolint:gosec // G101 false positive: a column list, not a credential
const apiKeyCols = `id, hash, name, role, ceiling, created_at, last_used_at, revoked_at`

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	var ceiling string
	var created int64
	var lastUsed, revoked sql.NullInt64
	if err := row.Scan(&k.ID, &k.Hash, &k.Name, &k.Role, &ceiling, &created, &lastUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if ceiling != "" && ceiling != "null" {
		k.Ceiling = &Ceiling{}
		if err := json.Unmarshal([]byte(ceiling), k.Ceiling); err != nil {
			return nil, err
		}
	}
	k.CreatedAt = time.Unix(created, 0).UTC()
	k.LastUsedAt = fromUnix(lastUsed)
	k.RevokedAt = fromUnix(revoked)
	return &k, nil
}

// APIKeyByHash looks up an API key by the hash of its value.
func (s *Store) APIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRowContext(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE hash = ?`, hash))
}

// ListAPIKeys returns all API keys that aren't revoked.
func (s *Store) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks an API key revoked.
func (s *Store) RevokeAPIKey(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchAPIKey records that an API key was used.
func (s *Store) TouchAPIKey(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.Unix(), id)
	return err
}
