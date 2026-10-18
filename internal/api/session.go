package api

import (
	"encoding/base64"
	"errors"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/users"
)

// CSRFHeader carries the session's CSRF token on state-changing requests
// made with a session cookie (SEC-22).
const CSRFHeader = "X-CSRF-Token"

// WithUsers enables UI sessions: login endpoints, user management, and
// session cookies as an alternative to API keys on every /api/v1 endpoint.
func (a *API) WithUsers(u *users.Service) *API {
	a.users = u
	return a
}

func (a *API) hasSessionCookie(r *http.Request) bool {
	_, err := r.Cookie(users.CookieName)
	return err == nil && a.users != nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isHTTPS reports whether the browser reached us over HTTPS, directly or
// through a TLS-terminating reverse proxy (D7). A forged header only makes
// the cookie Secure, which can't weaken anything.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// session authenticates the session cookie and, for state-changing
// requests, the CSRF token. It writes the error response itself.
func (a *API) session(w http.ResponseWriter, r *http.Request) (*users.Session, bool) {
	if a.users == nil {
		writeErr(w, http.StatusNotFound, "web UI users are not enabled")
		return nil, false
	}
	c, err := r.Cookie(users.CookieName)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, users.ErrNoSession.Error())
		return nil, false
	}
	ss, err := a.users.Authenticate(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, users.ErrNoSession) {
			a.clearCookie(w, r)
			writeErr(w, http.StatusUnauthorized, users.ErrNoSession.Error())
			return nil, false
		}
		a.log.Error("session lookup failed", "error", err.Error())
		writeErr(w, http.StatusServiceUnavailable, "service unavailable")
		return nil, false
	}
	if !safeMethod(r.Method) && !a.users.CheckCSRF(ss, r.Header.Get(CSRFHeader)) {
		writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
		return nil, false
	}
	return ss, true
}

// withSession runs next as the session's user. Sessions that still have to
// enrol TOTP or change the password can't use the API yet.
func (a *API) withSession(w http.ResponseWriter, r *http.Request, next handlerWithPrincipal) {
	ss, ok := a.session(w, r)
	if !ok {
		return
	}
	if st := ss.Stage(); st != users.StageOK {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "finish the login first", "stage": st})
		return
	}
	next(w, r, a.principalFor(ss.User))
}

// principalFor maps a UI user to an API principal. Admins have no
// ceiling; users are limited to auth.user_token_scope (FR-20, FR-91).
func (a *API) principalFor(u *store.User) *auth.Principal {
	p := &auth.Principal{KeyID: u.ID, Role: u.Role, UserID: u.ID, Username: u.Username}
	if u.Role != users.RoleAdmin {
		p.Ceiling = &store.Ceiling{Scope: a.userScope()}
	}
	return p
}

func (a *API) userScope() store.Scope {
	sc := a.cfg.Auth.UserTokenScope
	if sc == nil {
		return store.Scope{Buckets: []string{"*"}, Git: []store.GitScope{{Remote: "*", Repos: []string{"*/*"}}}}
	}
	out := store.Scope{Buckets: sc.Buckets}
	for _, g := range sc.Git {
		out.Git = append(out.Git, store.GitScope{Remote: g.Remote, Repos: g.Repos})
	}
	return out
}

// withViewer allows admins and UI users (read-only pages such as buckets).
func (a *API) withViewer(next handlerWithPrincipal) http.HandlerFunc {
	return a.withKey(func(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
		if !p.IsAdmin() && p.Role != users.RoleUser {
			writeErr(w, http.StatusForbidden, "admin or user role required")
			return
		}
		next(w, r, p)
	})
}

// Secure is set only over HTTPS: on plain HTTP (D7) a Secure cookie would
// never be sent back, so login couldn't work.
func (a *API) setCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure depends on the scheme, see above
		Name: users.CookieName, Value: value, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.cfg.Server.TLS.Enabled() || isHTTPS(r),
	})
}

func (a *API) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: as in setCookie
		Name: users.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.cfg.Server.TLS.Enabled() || isHTTPS(r),
	})
}

func (a *API) registerSession(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/session", a.login)
	mux.HandleFunc("GET /api/v1/session", a.withAnySession(a.getSession))
	mux.HandleFunc("DELETE /api/v1/session", a.withAnySession(a.logout))
	mux.HandleFunc("POST /api/v1/session/totp", a.withAnySession(a.startEnrolment))
	mux.HandleFunc("POST /api/v1/session/totp/confirm", a.withAnySession(a.confirmEnrolment))
	mux.HandleFunc("POST /api/v1/session/password", a.withAnySession(a.changePassword))
}

type sessionHandler func(http.ResponseWriter, *http.Request, *users.Session)

// withAnySession accepts a session at any stage (for the login steps).
func (a *API) withAnySession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ss, ok := a.session(w, r); ok {
			next(w, r, ss)
		}
	}
}

type sessionUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type sessionLimits struct {
	TokenDefaultTTL     int64 `json:"token_default_ttl_seconds"`
	TokenMaxTTL         int64 `json:"token_max_ttl_seconds"`
	PersonalTokenMaxTTL int64 `json:"personal_token_max_ttl_seconds"`
}

type sessionResp struct {
	User        sessionUser   `json:"user"`
	Stage       string        `json:"stage"`
	CSRFToken   string        `json:"csrf_token"`
	IdleTimeout int64         `json:"idle_timeout_seconds"`
	Limits      sessionLimits `json:"limits"`
	GitRemotes  []string      `json:"git_remotes"`
	PublicURL   string        `json:"public_base_url,omitempty"`
}

func (a *API) sessionInfo(ss *users.Session) sessionResp {
	sec := func(d time.Duration) int64 { return int64(d / time.Second) }
	remotes := []string{}
	if a.cfg.Git != nil {
		for _, r := range a.cfg.Git.Remotes {
			remotes = append(remotes, r.Name)
		}
	}
	return sessionResp{
		User:  sessionUser{ss.User.ID, ss.User.Username, ss.User.Role},
		Stage: ss.Stage(), CSRFToken: a.users.CSRFToken(ss), IdleTimeout: sec(a.users.IdleTimeout()),
		Limits: sessionLimits{sec(a.cfg.Auth.TokenDefaultTTL.D()), sec(a.cfg.Auth.TokenMaxTTL.D()),
			sec(a.cfg.Auth.PersonalTokenMaxTTL.D())},
		GitRemotes: remotes, PublicURL: a.cfg.Server.PublicBaseURL,
	}
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// login is POST /api/v1/session. It needs a JSON body, which a cross-site
// form can't send without a CORS preflight (login CSRF).
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		writeErr(w, http.StatusNotFound, "web UI users are not enabled")
		return
	}
	if !isJSON(r) {
		writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	ss, err := a.users.Login(r.Context(), req.Username, req.Password, req.Code, clientIP(r))
	switch {
	case err == nil:
	case errors.Is(err, users.ErrInvalidLogin):
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, users.ErrLocked), errors.Is(err, users.ErrRateLimited):
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return
	case errors.Is(err, users.ErrLoginUnavailable), errors.Is(err, users.ErrUnsealFailed):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	default:
		a.log.Error("login failed", "error", err.Error())
		writeErr(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	a.setCookie(w, r, ss.Secret())
	writeJSON(w, http.StatusOK, a.sessionInfo(ss))
}

func (a *API) getSession(w http.ResponseWriter, _ *http.Request, ss *users.Session) {
	writeJSON(w, http.StatusOK, a.sessionInfo(ss))
}

func (a *API) logout(w http.ResponseWriter, r *http.Request, ss *users.Session) {
	if err := a.users.Logout(r.Context(), ss); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not log out")
		return
	}
	a.clearCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) startEnrolment(w http.ResponseWriter, r *http.Request, ss *users.Session) {
	e, err := a.users.StartEnrolment(r.Context(), ss)
	if errors.Is(err, users.ErrAlreadyEnrolled) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		a.log.Error("starting TOTP enrolment failed", "user_id", ss.UserID, "error", err.Error())
		writeErr(w, http.StatusInternalServerError, "could not start TOTP setup")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"otpauth_uri": e.URI, "secret": e.Secret,
		"qr_png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(e.QRPNG),
	})
}

func (a *API) confirmEnrolment(w http.ResponseWriter, r *http.Request, ss *users.Session) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := a.users.ConfirmEnrolment(r.Context(), ss, req.Code)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, a.sessionInfo(ss))
	case errors.Is(err, users.ErrInvalidCode):
		writeErr(w, http.StatusBadRequest, "the code doesn't match; check the time on your phone and try again")
	case errors.Is(err, users.ErrAlreadyEnrolled):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		a.log.Error("confirming TOTP enrolment failed", "user_id", ss.UserID, "error", err.Error())
		writeErr(w, http.StatusBadRequest, "could not confirm TOTP setup; start again")
	}
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request, ss *users.Session) {
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := a.users.ChangePassword(r.Context(), ss, req.Current, req.New)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, a.sessionInfo(ss))
	case errors.Is(err, users.ErrWrongPassword):
		writeErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, users.ErrEnrolFirst):
		writeErr(w, http.StatusForbidden, err.Error())
	default:
		a.userErr(w, err)
	}
}

// userErr answers an error from the users service: input problems and
// rule violations are shown, anything else is logged.
func (a *API) userErr(w http.ResponseWriter, err error) {
	var ie *users.InputError
	switch {
	case errors.As(err, &ie):
		writeErr(w, http.StatusBadRequest, ie.Msg)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "user not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "a user with this name already exists")
	case errors.Is(err, users.ErrInvalidUsername), errors.Is(err, users.ErrInvalidRole):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, users.ErrLastAdmin), errors.Is(err, users.ErrSelf):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		a.log.Error("user operation failed", "error", err.Error())
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}
