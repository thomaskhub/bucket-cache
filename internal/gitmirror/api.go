package gitmirror

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// Wrap adds authentication to an admin handler (see api.API).
type Wrap func(http.HandlerFunc) http.HandlerFunc

// RegisterAPI mounts the git admin endpoints (FR-86, FR-92) on the admin
// mux. anyKey guards read-only listing, admin guards changes.
//
//	GET    /api/v1/repos                                  list mirrors and remotes
//	POST   /api/v1/repos/{remote}/{owner}/{repo}/refresh  fetch now (creates the mirror if missing)
//	DELETE /api/v1/repos/{remote}/{owner}/{repo}          remove the mirror
func (m *Manager) RegisterAPI(mux *http.ServeMux, anyKey, admin Wrap) {
	mux.HandleFunc("GET /api/v1/repos", anyKey(m.apiList))
	mux.HandleFunc("POST /api/v1/repos/{remote}/{owner}/{repo}/refresh", admin(m.apiRefresh))
	mux.HandleFunc("DELETE /api/v1/repos/{remote}/{owner}/{repo}", admin(m.apiDelete))
	// Alias used in the M5 brief.
	mux.HandleFunc("POST /api/v1/git/{remote}/{owner}/{repo}/refresh", admin(m.apiRefresh))
}

// ActorWrap adds admin authentication to a handler that also needs the
// caller's ID (see api.API.AdminActor).
type ActorWrap func(func(w http.ResponseWriter, r *http.Request, actor string)) http.HandlerFunc

// RegisterAllowAPI mounts the endpoints that edit the allowlist at runtime.
// The config file's patterns are read-only; these add to them.
//
//	POST   /api/v1/git/remotes/{remote}/allow            {"pattern": "owner/*"}
//	DELETE /api/v1/git/remotes/{remote}/allow?pattern=owner/*
func (m *Manager) RegisterAllowAPI(mux *http.ServeMux, admin ActorWrap) {
	mux.HandleFunc("POST /api/v1/git/remotes/{remote}/allow", admin(m.apiAllowAdd))
	mux.HandleFunc("DELETE /api/v1/git/remotes/{remote}/allow", admin(m.apiAllowDelete))
}

type remoteInfo struct {
	Name            string           `json:"name"`
	URL             string           `json:"url"`
	Allow           []string         `json:"allow"`        // everything that applies: config and runtime
	AllowConfig     []string         `json:"allow_config"` // from the config file, read-only
	AllowExtra      []store.GitAllow `json:"allow_extra"`
	AllowEditable   bool             `json:"allow_editable"`
	ProxyURL        string           `json:"proxy_url,omitempty"` // prefix for git config insteadOf rules
	IncludePullRefs bool             `json:"include_pull_refs"`
	Credentials     string           `json:"credentials"` // none | token | github-app (never the value)
}

func (m *Manager) apiList(w http.ResponseWriter, _ *http.Request) {
	remotes := make([]remoteInfo, 0, len(m.order))
	for _, name := range m.order {
		rm := m.remotes[name]
		cfgAllow := rm.cfg.Allow
		if cfgAllow == nil {
			cfgAllow = []string{}
		}
		extra := m.allowEntries(name)
		all := append([]string{}, cfgAllow...)
		for _, a := range extra {
			all = append(all, a.Pattern)
		}
		ri := remoteInfo{Name: name, URL: rm.base, Allow: all, AllowConfig: cfgAllow, AllowExtra: extra,
			AllowEditable: m.allowStore != nil, IncludePullRefs: rm.cfg.IncludePullRefs, Credentials: "none"}
		switch {
		case rm.cfg.Credentials.Token.Configured():
			ri.Credentials = "token"
		case rm.cfg.Credentials.AppID != "":
			ri.Credentials = "github-app"
		}
		if m.baseURL != "" {
			ri.ProxyURL = m.baseURL + "/git/" + name + "/"
		}
		remotes = append(remotes, ri)
	}
	repos := m.statuses()
	if repos == nil {
		repos = []Status{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"repos": repos, "remotes": remotes})
}

func (m *Manager) apiRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), m.cfg.FetchTimeout.D()+time.Minute)
	defer cancel()
	st, err := m.Refresh(ctx, r.PathValue("remote"), r.PathValue("owner"), r.PathValue("repo"))
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "repository not found or not allowed"})
	case err != nil:
		// Admin-only response; git's message (redacted) helps diagnose upstream problems.
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "refresh failed: " + err.Error(), "repo": st})
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (m *Manager) apiDelete(w http.ResponseWriter, r *http.Request) {
	err := m.Remove(r.Context(), r.PathValue("remote"), r.PathValue("owner"), r.PathValue("repo"))
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mirror not found"})
	case errors.Is(err, ErrBusy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "mirror is in use; try again later"})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove mirror"})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// allowEntries returns a copy of the remote's runtime allowlist entries.
func (m *Manager) allowEntries(remote string) []store.GitAllow {
	m.allowMu.RLock()
	defer m.allowMu.RUnlock()
	return append([]store.GitAllow{}, m.allowExtra[remote]...)
}

func (m *Manager) apiAllowAdd(w http.ResponseWriter, r *http.Request, actor string) {
	name := r.PathValue("remote")
	rm, ok := m.remotes[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown remote"})
		return
	}
	if m.allowStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "the allowlist can only be changed in the config file"})
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	p := strings.TrimSuffix(strings.TrimSpace(req.Pattern), ".git")
	if !config.ValidAllowPattern(p) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the pattern must be owner/repo or owner/* (owner can't be a wildcard)"})
		return
	}
	for _, c := range rm.cfg.Allow {
		if strings.EqualFold(c, p) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "the config file already allows " + c})
			return
		}
	}
	a := store.GitAllow{Remote: name, Pattern: p, CreatedBy: actor, CreatedAt: m.now().UTC().Truncate(time.Second)}
	m.allowMu.Lock()
	defer m.allowMu.Unlock()
	if err := m.allowStore.AddGitAllow(r.Context(), a); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": p + " is already allowed"})
			return
		}
		m.log.Error("adding git allowlist entry failed", "remote", name, "pattern", p, "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the pattern"})
		return
	}
	m.allowExtra[name] = append(m.allowExtra[name], a)
	m.log.Info("git allowlist entry added", "remote", name, "pattern", p, "by", actor)
	writeJSON(w, http.StatusCreated, a)
}

func (m *Manager) apiAllowDelete(w http.ResponseWriter, r *http.Request, actor string) {
	name := r.PathValue("remote")
	if _, ok := m.remotes[name]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown remote"})
		return
	}
	if m.allowStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "the allowlist can only be changed in the config file"})
		return
	}
	p := r.URL.Query().Get("pattern")
	m.allowMu.Lock()
	defer m.allowMu.Unlock()
	if err := m.allowStore.DeleteGitAllow(r.Context(), name, p); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such pattern (patterns from the config file can't be removed here)"})
			return
		}
		m.log.Error("removing git allowlist entry failed", "remote", name, "pattern", p, "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove the pattern"})
		return
	}
	kept := m.allowExtra[name][:0]
	for _, a := range m.allowExtra[name] {
		if !strings.EqualFold(a.Pattern, p) {
			kept = append(kept, a)
		}
	}
	m.allowExtra[name] = kept
	m.log.Info("git allowlist entry removed", "remote", name, "pattern", p, "by", actor)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
