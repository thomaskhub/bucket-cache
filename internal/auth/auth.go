// Package auth validates tokens and API keys.
//
// Token checks are on the hot path: one build fires thousands of parallel
// HEAD requests. Results are cached in memory for at most
// auth.validation_cache_ttl (FR-25), and revocation clears the cache entry
// so it takes effect at once (FR-23).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/store"
)

const (
	TokenPrefix  = "ybp_"
	APIKeyPrefix = "ybk_"

	// DeadTokenRetention is how long expired and revoked tokens are kept so
	// they are recognised (and not counted as guesses, SEC-3).
	DeadTokenRetention = 7 * 24 * time.Hour
)

var (
	// ErrUnknown means the credential has never existed (or was purged).
	ErrUnknown = errors.New("unknown credential")
	// ErrDead means the token exists but is expired or revoked.
	ErrDead = errors.New("token expired or revoked")
)

// NewSecret returns a random credential with the given prefix: 32 random
// bytes, base64url-encoded (SEC-1).
func NewSecret(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a short random public identifier such as "tok_3f9a1c2b7d4e".
func NewID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}

// Hash returns the stored form of a credential.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// LooksLikeToken reports whether s has the token format, so obviously wrong
// values can be rejected without a database lookup.
func LooksLikeToken(s string) bool {
	return strings.HasPrefix(s, TokenPrefix) && len(s) == len(TokenPrefix)+43
}

// Principal is who is calling the management API.
type Principal struct {
	KeyID   string         // API key ID, "bootstrap", or the user ID for a UI session
	Role    string         // admin | token-issuer | user
	Ceiling *store.Ceiling // nil = unlimited (admin)

	// UserID and Username are set when the caller is a logged-in UI user.
	UserID   string
	Username string
}

// IsAdmin reports whether the principal has the admin role.
func (p *Principal) IsAdmin() bool { return p.Role == "admin" }

type cacheEntry struct {
	tok   *store.Token // nil if unknown
	until time.Time
}

// Authenticator validates credentials against the store.
type Authenticator struct {
	store        *store.Store
	log          *slog.Logger
	bootstrapKey string
	cacheTTL     time.Duration
	now          func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry // keyed by token hash

	usageMu sync.Mutex
	usage   map[string]store.Usage
}

// New returns an Authenticator. bootstrapKey may be empty.
func New(st *store.Store, log *slog.Logger, bootstrapKey string, cacheTTL time.Duration) *Authenticator {
	return &Authenticator{
		store: st, log: log, bootstrapKey: bootstrapKey, cacheTTL: cacheTTL,
		now: time.Now, cache: map[string]cacheEntry{}, usage: map[string]store.Usage{},
	}
}

// Token validates a token value. It returns ErrUnknown, ErrDead (with the
// token, so callers can log its ID), or the usable token.
func (a *Authenticator) Token(ctx context.Context, value string) (*store.Token, error) {
	if !LooksLikeToken(value) {
		return nil, ErrUnknown
	}
	h := Hash(value)
	now := a.now()

	a.mu.Lock()
	e, ok := a.cache[h]
	a.mu.Unlock()
	if !ok || now.After(e.until) {
		tok, err := a.store.TokenByHash(ctx, h)
		switch {
		case errors.Is(err, store.ErrNotFound):
			tok = nil
		case err != nil:
			return nil, err
		}
		e = cacheEntry{tok: tok, until: now.Add(a.cacheTTL)}
		a.mu.Lock()
		if len(a.cache) > 100_000 { // bound memory under a flood of random tokens
			a.cache = map[string]cacheEntry{}
		}
		a.cache[h] = e
		a.mu.Unlock()
	}
	if e.tok == nil {
		return nil, ErrUnknown
	}
	if !e.tok.Usable(now) {
		return e.tok, ErrDead
	}
	return e.tok, nil
}

// Forget drops a token from the validation cache (after revocation).
func (a *Authenticator) Forget(hash string) {
	a.mu.Lock()
	delete(a.cache, hash)
	a.mu.Unlock()
}

// ForgetID drops a token from the cache by its ID.
func (a *Authenticator) ForgetID(id string) {
	a.mu.Lock()
	for h, e := range a.cache {
		if e.tok != nil && e.tok.ID == id {
			delete(a.cache, h)
		}
	}
	a.mu.Unlock()
}

// APIKey validates a management API key. The bootstrap key from secrets
// is checked in constant time and never stored.
func (a *Authenticator) APIKey(ctx context.Context, value string) (*Principal, error) {
	if a.bootstrapKey != "" && subtle.ConstantTimeCompare([]byte(value), []byte(a.bootstrapKey)) == 1 {
		return &Principal{KeyID: "bootstrap", Role: "admin"}, nil
	}
	if !strings.HasPrefix(value, APIKeyPrefix) {
		return nil, ErrUnknown
	}
	k, err := a.store.APIKeyByHash(ctx, Hash(value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknown
	}
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, ErrDead
	}
	_ = a.store.TouchAPIKey(ctx, k.ID, a.now())
	return &Principal{KeyID: k.ID, Role: k.Role, Ceiling: k.Ceiling}, nil
}

// RecordUsage adds to a token's in-memory counters; FlushUsage writes them.
func (a *Authenticator) RecordUsage(tokenID string, bytes int64) {
	a.usageMu.Lock()
	u := a.usage[tokenID]
	u.Requests++
	u.Bytes += bytes
	u.LastUsed = a.now()
	a.usage[tokenID] = u
	a.usageMu.Unlock()
}

// FlushUsage writes batched usage counters to the store (FR-22).
func (a *Authenticator) FlushUsage(ctx context.Context) error {
	a.usageMu.Lock()
	batch := a.usage
	a.usage = map[string]store.Usage{}
	a.usageMu.Unlock()
	return a.store.AddUsage(ctx, batch)
}

// RunMaintenance flushes usage every interval and purges long-dead tokens,
// until ctx is cancelled. It flushes once more on exit.
func (a *Authenticator) RunMaintenance(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	purge := func() {
		n, err := a.store.PurgeTokens(ctx, a.now().Add(-DeadTokenRetention))
		if err != nil {
			a.log.Warn("purging dead tokens failed", "error", err.Error())
		} else if n > 0 {
			a.log.Info("purged dead tokens", "count", n)
		}
	}
	purge()
	lastPurge := a.now()
	for {
		select {
		case <-ctx.Done():
			if err := a.FlushUsage(context.Background()); err != nil {
				a.log.Warn("flushing token usage failed", "error", err.Error())
			}
			return
		case <-t.C:
			if err := a.FlushUsage(ctx); err != nil {
				a.log.Warn("flushing token usage failed", "error", err.Error())
			}
			if a.now().Sub(lastPurge) > time.Hour {
				purge()
				lastPurge = a.now()
			}
		}
	}
}

// AllowsBucket reports whether scope allows reading key in bucket.
func AllowsBucket(s store.Scope, bucket, key string) bool {
	ok := false
	for _, b := range s.Buckets {
		if b == "*" || b == bucket {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if len(s.Prefixes) == 0 {
		return true
	}
	for _, p := range s.Prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// AllowsRepo reports whether scope allows reading owner/repo on remote.
// Patterns are "owner/repo" or "owner/*", compared case-insensitively.
func AllowsRepo(s store.Scope, remote, ownerRepo string) bool {
	ownerRepo = strings.ToLower(ownerRepo)
	for _, g := range s.Git {
		if g.Remote != remote && g.Remote != "*" {
			continue
		}
		for _, p := range g.Repos {
			if ok, _ := path.Match(strings.ToLower(p), ownerRepo); ok {
				return true
			}
		}
	}
	return false
}

// WithinCeiling reports whether a requested scope and TTL fit the ceiling.
// A nil ceiling allows everything.
func WithinCeiling(c *store.Ceiling, s store.Scope, ttl time.Duration) error {
	if c == nil {
		return nil
	}
	if c.MaxTTL > 0 && ttl > c.MaxTTL {
		return errors.New("ttl exceeds this key's maximum of " + c.MaxTTL.String())
	}
	for _, b := range s.Buckets {
		if !containsOrStar(c.Scope.Buckets, b) {
			return errors.New("bucket " + b + " is outside this key's allowed buckets")
		}
	}
	if len(c.Scope.Prefixes) > 0 {
		if len(s.Prefixes) == 0 {
			return errors.New("this key may only issue tokens restricted to prefixes")
		}
		for _, p := range s.Prefixes {
			if !hasAnyPrefix(p, c.Scope.Prefixes) {
				return errors.New("prefix " + p + " is outside this key's allowed prefixes")
			}
		}
	}
	for _, g := range s.Git {
		for _, r := range g.Repos {
			if !ceilingAllowsRepoPattern(c.Scope, g.Remote, r) {
				return errors.New("git scope " + g.Remote + ":" + r + " is outside this key's allowed repos")
			}
		}
	}
	return nil
}

func containsOrStar(list []string, v string) bool {
	for _, x := range list {
		if x == "*" || x == v {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ceilingAllowsRepoPattern checks a requested repo pattern against the
// ceiling. A requested wildcard is only allowed if the ceiling has the same
// or a broader wildcard.
func ceilingAllowsRepoPattern(c store.Scope, remote, pattern string) bool {
	pattern = strings.ToLower(pattern)
	for _, g := range c.Git {
		if g.Remote != remote && g.Remote != "*" {
			continue
		}
		for _, p := range g.Repos {
			p = strings.ToLower(p)
			if p == pattern || p == "*/*" {
				return true
			}
			if strings.HasSuffix(p, "/*") && strings.HasPrefix(pattern, strings.TrimSuffix(p, "*")) {
				return true
			}
		}
	}
	return false
}
