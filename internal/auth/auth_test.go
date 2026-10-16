package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/store"
)

func setup(t *testing.T) (*Authenticator, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), "bootstrap-secret", 5*time.Second), st
}

func addToken(t *testing.T, st *store.Store, ttl time.Duration) (string, *store.Token) {
	t.Helper()
	v := NewSecret(TokenPrefix)
	now := time.Now()
	tok := &store.Token{ID: NewID("tok_"), Hash: Hash(v), Kind: "ci", Scope: store.Scope{Buckets: []string{"sstate"}},
		CreatedBy: "bootstrap", CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := st.CreateToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	return v, tok
}

func TestSecretFormat(t *testing.T) {
	v := NewSecret(TokenPrefix)
	if !LooksLikeToken(v) {
		t.Fatalf("%q doesn't look like a token", v)
	}
	if NewSecret(TokenPrefix) == v {
		t.Fatal("secrets repeat")
	}
	if LooksLikeToken("ybp_short") || LooksLikeToken(NewSecret(APIKeyPrefix)) {
		t.Fatal("bad values accepted as tokens")
	}
}

func TestTokenValidationAndRevocation(t *testing.T) {
	ctx := context.Background()
	a, st := setup(t)
	v, tok := addToken(t, st, time.Hour)

	got, err := a.Token(ctx, v)
	if err != nil || got.ID != tok.ID {
		t.Fatalf("valid token: %v", err)
	}
	if _, err := a.Token(ctx, NewSecret(TokenPrefix)); !errors.Is(err, ErrUnknown) {
		t.Fatalf("random token: %v", err)
	}

	// Revocation plus Forget takes effect immediately, despite the cache.
	st.RevokeToken(ctx, tok.ID, time.Now())
	a.ForgetID(tok.ID)
	got, err = a.Token(ctx, v)
	if !errors.Is(err, ErrDead) || got == nil || got.ID != tok.ID {
		t.Fatalf("revoked token: %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	a, st := setup(t)
	v, _ := addToken(t, st, time.Hour)
	a.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := a.Token(context.Background(), v); !errors.Is(err, ErrDead) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestAPIKeys(t *testing.T) {
	ctx := context.Background()
	a, st := setup(t)
	p, err := a.APIKey(ctx, "bootstrap-secret")
	if err != nil || !p.IsAdmin() {
		t.Fatalf("bootstrap key: %v", err)
	}
	if _, err := a.APIKey(ctx, "bootstrap-secreT"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("wrong key: %v", err)
	}
	v := NewSecret(APIKeyPrefix)
	st.CreateAPIKey(ctx, &store.APIKey{ID: "key_1", Hash: Hash(v), Name: "ci", Role: "token-issuer",
		Ceiling: &store.Ceiling{MaxTTL: time.Hour}, CreatedAt: time.Now()})
	p, err = a.APIKey(ctx, v)
	if err != nil || p.IsAdmin() || p.Ceiling == nil {
		t.Fatalf("issuer key: %+v %v", p, err)
	}
	st.RevokeAPIKey(ctx, "key_1", time.Now())
	if _, err := a.APIKey(ctx, v); !errors.Is(err, ErrDead) {
		t.Fatalf("revoked key: %v", err)
	}
}

func TestUsageFlush(t *testing.T) {
	ctx := context.Background()
	a, st := setup(t)
	_, tok := addToken(t, st, time.Hour)
	a.RecordUsage(tok.ID, 10)
	a.RecordUsage(tok.ID, 5)
	if err := a.FlushUsage(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := st.TokenByID(ctx, tok.ID)
	if got.Requests != 2 || got.Bytes != 15 {
		t.Fatalf("usage = %d req, %d bytes", got.Requests, got.Bytes)
	}
}

func TestScopes(t *testing.T) {
	s := store.Scope{Buckets: []string{"sstate"}, Prefixes: []string{"kirkstone/"},
		Git: []store.GitScope{{Remote: "github", Repos: []string{"acme/*", "yoctoproject/poky"}}}}
	cases := []struct {
		ok   bool
		got  bool
		name string
	}{
		{true, AllowsBucket(s, "sstate", "kirkstone/aa/bb.tar.zst"), "bucket+prefix"},
		{false, AllowsBucket(s, "sstate", "scarthgap/aa"), "wrong prefix"},
		{false, AllowsBucket(s, "downloads", "kirkstone/x"), "wrong bucket"},
		{true, AllowsBucket(store.Scope{Buckets: []string{"*"}}, "any", "k"), "star bucket"},
		{true, AllowsRepo(s, "github", "Acme/Meta-Acme"), "case-insensitive wildcard"},
		{true, AllowsRepo(s, "github", "yoctoproject/poky"), "exact repo"},
		{false, AllowsRepo(s, "github", "yoctoproject/other"), "other repo"},
		{false, AllowsRepo(s, "gitlab", "acme/x"), "other remote"},
		{false, AllowsRepo(store.Scope{}, "github", "acme/x"), "no git scope"},
	}
	for _, c := range cases {
		if c.ok != c.got {
			t.Errorf("%s: got %v", c.name, c.got)
		}
	}
}

func TestCeiling(t *testing.T) {
	c := &store.Ceiling{MaxTTL: 6 * time.Hour, Scope: store.Scope{Buckets: []string{"sstate"},
		Git: []store.GitScope{{Remote: "github", Repos: []string{"acme/*"}}}}}
	ok := store.Scope{Buckets: []string{"sstate"}, Git: []store.GitScope{{Remote: "github", Repos: []string{"acme/meta"}}}}
	if err := WithinCeiling(c, ok, time.Hour); err != nil {
		t.Fatalf("within ceiling: %v", err)
	}
	for name, tc := range map[string]struct {
		s   store.Scope
		ttl time.Duration
	}{
		"ttl":         {ok, 7 * time.Hour},
		"bucket":      {store.Scope{Buckets: []string{"downloads"}}, time.Hour},
		"star bucket": {store.Scope{Buckets: []string{"*"}}, time.Hour},
		"repo":        {store.Scope{Git: []store.GitScope{{Remote: "github", Repos: []string{"other/x"}}}}, time.Hour},
		"wider repo":  {store.Scope{Git: []store.GitScope{{Remote: "github", Repos: []string{"*/*"}}}}, time.Hour},
	} {
		if err := WithinCeiling(c, tc.s, tc.ttl); err == nil {
			t.Errorf("%s: expected ceiling error", name)
		}
	}
	if err := WithinCeiling(nil, store.Scope{Buckets: []string{"*"}}, 1000*time.Hour); err != nil {
		t.Fatalf("nil ceiling: %v", err)
	}
}

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter(1, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("failure %d blocked too early", i)
		}
	}
	if l.Allow("10.0.0.1") || !l.Blocked("10.0.0.1") {
		t.Fatal("4th failure should be blocked")
	}
	if l.Blocked("10.0.0.2") {
		t.Fatal("other IP blocked")
	}
}
