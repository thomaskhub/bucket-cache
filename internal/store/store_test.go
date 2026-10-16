package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	tok := &Token{ID: "tok_1", Hash: "h1", Kind: "ci", Labels: map[string]string{"job": "42"},
		Scope: Scope{Buckets: []string{"sstate"}}, CreatedBy: "bootstrap", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.TokenByHash(ctx, "h1")
	if err != nil || got.ID != "tok_1" || got.Labels["job"] != "42" || got.Scope.Buckets[0] != "sstate" || !got.Usable(now) {
		t.Fatalf("TokenByHash = %+v, %v", got, err)
	}
	if err := s.AddUsage(ctx, map[string]Usage{"tok_1": {Requests: 3, Bytes: 100, LastUsed: now}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.TokenByID(ctx, "tok_1")
	if got.Requests != 3 || got.Bytes != 100 || got.LastUsedAt == nil {
		t.Fatalf("usage not recorded: %+v", got)
	}
	list, _ := s.ListTokens(ctx, now, "")
	if len(list) != 1 {
		t.Fatalf("ListTokens = %d", len(list))
	}
	if err := s.RevokeToken(ctx, "tok_1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, "tok_1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke = %v", err)
	}
	got, _ = s.TokenByHash(ctx, "h1")
	if got.Usable(now) {
		t.Fatal("revoked token still usable")
	}
	// Kept while recently revoked, purged after the cutoff passes.
	if n, _ := s.PurgeTokens(ctx, now.Add(-time.Second)); n != 0 {
		t.Fatalf("purged %d too early", n)
	}
	if n, _ := s.PurgeTokens(ctx, now.Add(time.Second)); n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	if _, err := s.TokenByHash(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after purge = %v", err)
	}
}

func TestAPIKeys(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	k := &APIKey{ID: "key_1", Hash: "kh", Name: "ci", Role: "token-issuer",
		Ceiling: &Ceiling{Scope: Scope{Buckets: []string{"sstate"}}, MaxTTL: 6 * time.Hour}, CreatedAt: now}
	if err := s.CreateAPIKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	got, err := s.APIKeyByHash(ctx, "kh")
	if err != nil || got.Ceiling == nil || got.Ceiling.MaxTTL != 6*time.Hour {
		t.Fatalf("APIKeyByHash = %+v, %v", got, err)
	}
	admin := &APIKey{ID: "key_2", Hash: "ah", Name: "admin", Role: "admin", CreatedAt: now}
	s.CreateAPIKey(ctx, admin)
	got, _ = s.APIKeyByHash(ctx, "ah")
	if got.Ceiling != nil {
		t.Fatalf("admin key got a ceiling: %+v", got.Ceiling)
	}
	if err := s.RevokeAPIKey(ctx, "key_1", now); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListAPIKeys(ctx)
	if len(list) != 1 || list[0].ID != "key_2" {
		t.Fatalf("ListAPIKeys = %+v", list)
	}
}

func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAPIKey(ctx, &APIKey{ID: "k", Hash: "h", Name: "n", Role: "admin", CreatedAt: time.Now()})
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.APIKeyByHash(ctx, "h"); err != nil {
		t.Fatalf("data lost on reopen: %v", err)
	}
}
