package gitmirror

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
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

type remoteInfo struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	Allow           []string `json:"allow"`
	ProxyURL        string   `json:"proxy_url,omitempty"` // prefix for git config insteadOf rules
	IncludePullRefs bool     `json:"include_pull_refs"`
	Credentials     string   `json:"credentials"` // none | token | github-app (never the value)
}

func (m *Manager) apiList(w http.ResponseWriter, _ *http.Request) {
	remotes := make([]remoteInfo, 0, len(m.order))
	for _, name := range m.order {
		rm := m.remotes[name]
		ri := remoteInfo{Name: name, URL: rm.base, Allow: rm.cfg.Allow, IncludePullRefs: rm.cfg.IncludePullRefs, Credentials: "none"}
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
