package store

import (
	"context"
	"time"
)

// GitAllow is a git allowlist pattern added at runtime.
type GitAllow struct {
	Remote    string    `json:"remote"`
	Pattern   string    `json:"pattern"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ListGitAllow returns all runtime allowlist entries, oldest first.
func (s *Store) ListGitAllow(ctx context.Context) ([]GitAllow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT remote, pattern, created_by, created_at FROM git_allow ORDER BY created_at, pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitAllow
	for rows.Next() {
		var a GitAllow
		var created int64
		if err := rows.Scan(&a.Remote, &a.Pattern, &a.CreatedBy, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddGitAllow inserts an entry. It returns ErrConflict if the remote already
// has the pattern (compared case-insensitively).
func (s *Store) AddGitAllow(ctx context.Context, a GitAllow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO git_allow (remote, pattern, created_by, created_at) VALUES (?, ?, ?, ?)`,
		a.Remote, a.Pattern, a.CreatedBy, a.CreatedAt.Unix())
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteGitAllow removes an entry. It returns ErrNotFound if there is none.
func (s *Store) DeleteGitAllow(ctx context.Context, remote, pattern string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM git_allow WHERE remote = ? AND pattern = ?`, remote, pattern)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
