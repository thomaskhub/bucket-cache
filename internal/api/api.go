// Package api implements the JSON management API under /api/v1.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/cache"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/users"
)

// API serves the management endpoints.
type API struct {
	cfg      *config.Config
	store    *store.Store
	auth     *auth.Authenticator
	backends map[string]s3proxy.Backend
	caches   map[string]*cache.Store
	log      *slog.Logger
	now      func() time.Time
	users    *users.Service // nil: no UI sessions (see WithUsers)
}

// New returns the API.
func New(cfg *config.Config, st *store.Store, a *auth.Authenticator, backends map[string]s3proxy.Backend, log *slog.Logger) *API {
	return &API{cfg: cfg, store: st, auth: a, backends: backends, log: log, now: time.Now}
}

// WithCaches gives the API the disk caches for stats and purging (FR-57).
func (a *API) WithCaches(c map[string]*cache.Store) *API {
	a.caches = c
	return a
}

// Register mounts the endpoints on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tokens", a.withKey(a.createToken))
	mux.HandleFunc("GET /api/v1/tokens", a.withKey(a.listTokens))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", a.withKey(a.revokeToken))
	mux.HandleFunc("DELETE /api/v1/tokens/self", a.revokeSelf)
	mux.HandleFunc("GET /api/v1/apikeys", a.withAdmin(a.listAPIKeys))
	mux.HandleFunc("POST /api/v1/apikeys", a.withAdmin(a.createAPIKey))
	mux.HandleFunc("DELETE /api/v1/apikeys/{id}", a.withAdmin(a.revokeAPIKey))
	mux.HandleFunc("GET /api/v1/buckets", a.withViewer(a.listBuckets))
	mux.HandleFunc("POST /api/v1/buckets/{alias}/test", a.withAdmin(a.testBucket))
	mux.HandleFunc("GET /api/v1/buckets/{alias}/cache", a.withViewer(a.cacheStats)) // FR-60: users see cache stats
	mux.HandleFunc("DELETE /api/v1/buckets/{alias}/cache", a.withAdmin(a.purgeCache))
	a.registerSession(mux)
	a.registerUsers(mux)
}

// Authenticated wraps a handler from another package (such as the git
// mirror API) so it needs a valid API key of any role.
func (a *API) Authenticated(h http.HandlerFunc) http.HandlerFunc {
	return a.withKey(func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) { h(w, r) })
}

// AdminOnly wraps a handler from another package so it needs the admin role.
func (a *API) AdminOnly(h http.HandlerFunc) http.HandlerFunc {
	return a.withAdmin(func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) { h(w, r) })
}

// AdminActor wraps a handler from another package so it needs the admin
// role and receives the caller's ID, for audit logs and created_by fields.
func (a *API) AdminActor(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return a.withAdmin(func(w http.ResponseWriter, r *http.Request, p *auth.Principal) { h(w, r, p.KeyID) })
}

type handlerWithPrincipal func(http.ResponseWriter, *http.Request, *auth.Principal)

func bearer(r *http.Request) string {
	v, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(v)
}

func (a *API) withKey(next handlerWithPrincipal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) == "" && a.hasSessionCookie(r) {
			a.withSession(w, r, next) // a logged-in UI user (FR-62)
			return
		}
		p, err := a.auth.APIKey(r.Context(), bearer(r))
		if err != nil {
			if !errors.Is(err, auth.ErrUnknown) && !errors.Is(err, auth.ErrDead) {
				a.log.Error("api key lookup failed", "error", err.Error())
				writeErr(w, http.StatusServiceUnavailable, "service unavailable")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="yproxy-api"`)
			writeErr(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next(w, r, p)
	}
}

func (a *API) withAdmin(next handlerWithPrincipal) http.HandlerFunc {
	return a.withKey(func(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
		if !p.IsAdmin() {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r, p)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

type createTokenReq struct {
	Buckets     []string          `json:"buckets"`
	Prefixes    []string          `json:"prefixes"`
	Git         []store.GitScope  `json:"git"`
	TTL         string            `json:"ttl"`
	Kind        string            `json:"kind"` // ci (default) | personal (UI users only, FR-91)
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
}

type createTokenResp struct {
	*store.Token
	Value    string            `json:"token"`
	Examples map[string]string `json:"examples,omitempty"`
}

// validateScope checks that every bucket and git remote in the scope exists.
func (a *API) validateScope(s store.Scope) error {
	if len(s.Buckets) == 0 && len(s.Git) == 0 {
		return errors.New("a token needs at least one bucket or git scope")
	}
	for _, b := range s.Buckets {
		if b == "*" {
			continue
		}
		if _, ok := a.backends[b]; !ok {
			return errors.New("unknown bucket " + b)
		}
	}
	remotes := map[string]bool{}
	if a.cfg.Git != nil {
		for _, r := range a.cfg.Git.Remotes {
			remotes[r.Name] = true
		}
	}
	for _, g := range s.Git {
		if !remotes[g.Remote] {
			return errors.New("unknown git remote " + g.Remote)
		}
		if len(g.Repos) == 0 {
			return errors.New("git scope for " + g.Remote + " needs at least one repo pattern")
		}
		for _, p := range g.Repos {
			if strings.Count(p, "/") != 1 {
				return errors.New("repo pattern " + p + " must be owner/repo or owner/*")
			}
		}
	}
	for _, p := range s.Prefixes {
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return errors.New("invalid prefix " + p)
		}
	}
	return nil
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var req createTokenReq
	if !decode(w, r, &req) {
		return
	}
	kind, ttl, maxTTL := "ci", a.cfg.Auth.TokenDefaultTTL.D(), a.cfg.Auth.TokenMaxTTL.D()
	switch req.Kind {
	case "", "ci":
	case "personal":
		if p.UserID == "" {
			writeErr(w, http.StatusForbidden, "personal tokens can only be created by UI users")
			return
		}
		kind, maxTTL = "personal", a.cfg.Auth.PersonalTokenMaxTTL.D()
		ttl = min(30*24*time.Hour, maxTTL)
	default:
		writeErr(w, http.StatusBadRequest, "kind must be ci or personal")
		return
	}
	if req.TTL != "" {
		d, err := config.ParseDuration(req.TTL)
		if err != nil || d <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		ttl = d
	}
	if ttl > maxTTL {
		writeErr(w, http.StatusBadRequest, "ttl exceeds the maximum of "+maxTTL.String())
		return
	}
	scope := store.Scope{Buckets: req.Buckets, Prefixes: req.Prefixes, Git: req.Git}
	if err := a.validateScope(scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auth.WithinCeiling(p.Ceiling, scope, ttl); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	value := auth.NewSecret(auth.TokenPrefix)
	now := a.now().UTC().Truncate(time.Second)
	tok := &store.Token{
		ID: auth.NewID("tok_"), Hash: auth.Hash(value), Kind: kind, Description: req.Description,
		Labels: req.Labels, Scope: scope, CreatedBy: p.KeyID, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if tok.Labels == nil {
		tok.Labels = map[string]string{}
	}
	if err := a.store.CreateToken(r.Context(), tok); err != nil {
		a.log.Error("creating token failed", "error", err.Error())
		writeErr(w, http.StatusInternalServerError, "could not create token")
		return
	}
	a.log.Info("token created", "token_id", tok.ID, "by", p.KeyID, "expires_at", tok.ExpiresAt)
	writeJSON(w, http.StatusCreated, createTokenResp{Token: tok, Value: value, Examples: a.examples(value, scope)})
}

// examples returns ready-to-use mirror lines for the token (FR-21).
func (a *API) examples(value string, s store.Scope) map[string]string {
	base := strings.TrimRight(a.cfg.Server.PublicBaseURL, "/")
	if base == "" {
		return nil
	}
	out := map[string]string{"env": "export SSTATE_PROXY_TOKEN=" + value}
	if len(s.Buckets) > 0 && s.Buckets[0] != "*" {
		out["sstate_mirrors"] = `SSTATE_MIRRORS ?= "file://.* ` + base + `/t/${SSTATE_PROXY_TOKEN}/` + s.Buckets[0] + `/PATH;downloadfilename=PATH"`
	}
	if len(s.Git) > 0 && a.cfg.Git != nil {
		for _, r := range a.cfg.Git.Remotes {
			if r.Name == s.Git[0].Remote {
				// Basic auth with the token as password (FR-81), as in requirements 10.3.
				scheme, host, _ := strings.Cut(base, "://")
				out["git_insteadof"] = `git config --global url."` + scheme + `://ci:${SSTATE_PROXY_TOKEN}@` + host + `/git/` + r.Name +
					`/".insteadOf "` + strings.TrimRight(r.URL, "/") + `/"`
			}
		}
	}
	return out
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	by := ""
	if !p.IsAdmin() {
		by = p.KeyID
	}
	toks, err := a.store.ListTokens(r.Context(), a.now(), by)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": toks})
}

func (a *API) revokeToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	tok, err := a.store.TokenByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !p.IsAdmin() && tok.CreatedBy != p.KeyID) {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not revoke token")
		return
	}
	a.revoke(w, r.Context(), tok, p.KeyID)
}

// revokeSelf lets a build revoke its own token when it finishes (FR-26).
func (a *API) revokeSelf(w http.ResponseWriter, r *http.Request) {
	tok, err := a.auth.Token(r.Context(), bearer(r))
	if err != nil {
		if errors.Is(err, auth.ErrDead) {
			w.WriteHeader(http.StatusNoContent) // already unusable; nothing to do
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="yproxy-api"`)
		writeErr(w, http.StatusUnauthorized, "missing or invalid token")
		return
	}
	a.revoke(w, r.Context(), tok, "self")
}

func (a *API) revoke(w http.ResponseWriter, ctx context.Context, tok *store.Token, by string) {
	err := a.store.RevokeToken(ctx, tok.ID, a.now())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "could not revoke token")
		return
	}
	a.auth.Forget(tok.Hash)
	a.log.Info("token revoked", "token_id", tok.ID, "by", by)
	w.WriteHeader(http.StatusNoContent)
}

type ceilingJSON struct {
	Scope  store.Scope `json:"scope"`
	MaxTTL string      `json:"max_ttl"`
}

func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var raw struct {
		Name    string       `json:"name"`
		Role    string       `json:"role"`
		Ceiling *ceilingJSON `json:"ceiling"`
	}
	if !decode(w, r, &raw) {
		return
	}
	if strings.TrimSpace(raw.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	k := &store.APIKey{ID: auth.NewID("key_"), Name: raw.Name, Role: raw.Role, CreatedAt: a.now().UTC()}
	switch raw.Role {
	case "admin":
		if raw.Ceiling != nil {
			writeErr(w, http.StatusBadRequest, "admin keys have no ceiling")
			return
		}
	case "token-issuer":
		if raw.Ceiling == nil {
			writeErr(w, http.StatusBadRequest, "token-issuer keys need a ceiling (scope and max_ttl)")
			return
		}
		c := &store.Ceiling{Scope: raw.Ceiling.Scope}
		if raw.Ceiling.MaxTTL != "" {
			d, err := config.ParseDuration(raw.Ceiling.MaxTTL)
			if err != nil || d <= 0 {
				writeErr(w, http.StatusBadRequest, "invalid ceiling.max_ttl")
				return
			}
			c.MaxTTL = d
		}
		if err := a.validateScope(c.Scope); err != nil {
			writeErr(w, http.StatusBadRequest, "ceiling: "+err.Error())
			return
		}
		k.Ceiling = c
	default:
		writeErr(w, http.StatusBadRequest, "role must be admin or token-issuer")
		return
	}
	value := auth.NewSecret(auth.APIKeyPrefix)
	k.Hash = auth.Hash(value)
	if err := a.store.CreateAPIKey(r.Context(), k); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create API key")
		return
	}
	a.log.Info("api key created", "key_id", k.ID, "role", k.Role, "by", p.KeyID)
	writeJSON(w, http.StatusCreated, struct {
		*store.APIKey
		Value string `json:"key"`
	}{k, value})
}

func (a *API) listAPIKeys(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	keys, err := a.store.ListAPIKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list API keys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apikeys": keys})
}

func (a *API) revokeAPIKey(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	err := a.store.RevokeAPIKey(r.Context(), r.PathValue("id"), a.now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "API key not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not revoke API key")
		return
	}
	a.log.Info("api key revoked", "key_id", r.PathValue("id"), "by", p.KeyID)
	w.WriteHeader(http.StatusNoContent)
}

type bucketInfo struct {
	Alias     string `json:"alias"`
	Provider  string `json:"provider"`
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix,omitempty"`
	PathStyle bool   `json:"path_style"`
	Mode      string `json:"mode"`
}

func (a *API) listBuckets(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) {
	out := make([]bucketInfo, 0, len(a.cfg.Buckets))
	for _, b := range a.cfg.Buckets {
		out = append(out, bucketInfo{b.Alias, b.Provider, b.Endpoint, b.Region, b.Bucket, b.Prefix, *b.PathStyle, b.Mode})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	writeJSON(w, http.StatusOK, map[string]any{"buckets": out})
}

// testBucket checks reachability and credentials (FR-42). Backend error
// details are logged, not returned, since they can contain bucket names.
func (a *API) testBucket(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	alias := r.PathValue("alias")
	b, ok := a.backends[alias]
	if !ok {
		writeErr(w, http.StatusNotFound, "bucket not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	start := time.Now()
	err := b.Test(ctx)
	res := map[string]any{"alias": alias, "ok": err == nil, "latency_ms": time.Since(start).Milliseconds()}
	if err != nil {
		a.log.Warn("bucket test failed", "bucket", alias, "error", err.Error())
		var be *s3proxy.BackendError
		switch {
		case errors.Is(err, s3proxy.ErrTimeout):
			res["error"] = "timeout"
		case errors.As(err, &be) && (be.Status == 401 || be.Status == 403):
			res["error"] = "access denied: check credentials and bucket policy"
		case errors.Is(err, s3proxy.ErrNotFound):
			res["error"] = "bucket not found"
		default:
			res["error"] = "unreachable or unexpected response (see proxy log)"
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// bucketCache finds the cache of the bucket in the path, or writes an error.
func (a *API) bucketCache(w http.ResponseWriter, r *http.Request) *cache.Store {
	alias := r.PathValue("alias")
	if _, ok := a.backends[alias]; !ok {
		writeErr(w, http.StatusNotFound, "bucket not found")
		return nil
	}
	c := a.caches[alias]
	if c == nil {
		writeErr(w, http.StatusConflict, "bucket is not in cache mode")
		return nil
	}
	return c
}

func (a *API) cacheStats(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	if c := a.bucketCache(w, r); c != nil {
		writeJSON(w, http.StatusOK, c.Stats())
	}
}

// purgeCache removes the whole cache of a bucket, one key (?key=) or every
// key under a prefix (?prefix=) (FR-57).
func (a *API) purgeCache(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	c := a.bucketCache(w, r)
	if c == nil {
		return
	}
	key, prefix := r.URL.Query().Get("key"), r.URL.Query().Get("prefix")
	if key != "" && prefix != "" {
		writeErr(w, http.StatusBadRequest, "use either key or prefix, not both")
		return
	}
	n, bytes := c.Purge(key, prefix)
	a.log.Info("cache purge", "bucket", c.Alias(), "key", key, "prefix", prefix, "objects", n, "by", p.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{"alias": c.Alias(), "removed": n, "bytes_freed": bytes})
}
