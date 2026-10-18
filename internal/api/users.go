package api

import (
	"net/http"
	"strings"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// registerUsers mounts user management (FR-60 Users page, admin only).
func (a *API) registerUsers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", a.withAdmin(a.withUsersEnabled(a.listUsers)))
	mux.HandleFunc("POST /api/v1/users", a.withAdmin(a.withUsersEnabled(a.createUser)))
	mux.HandleFunc("PATCH /api/v1/users/{id}", a.withAdmin(a.withUsersEnabled(a.updateUser)))
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.withAdmin(a.withUsersEnabled(a.deleteUser)))
	mux.HandleFunc("POST /api/v1/users/{id}/reset-password", a.withAdmin(a.withUsersEnabled(a.resetPassword)))
	mux.HandleFunc("POST /api/v1/users/{id}/reset-totp", a.withAdmin(a.withUsersEnabled(a.resetTOTP)))
}

func (a *API) withUsersEnabled(next handlerWithPrincipal) handlerWithPrincipal {
	return func(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
		if a.users == nil {
			writeErr(w, http.StatusNotFound, "web UI users are not enabled")
			return
		}
		next(w, r, p)
	}
}

// userView is a user as the API shows it.
type userView struct {
	*store.User
	TOTPEnrolled bool `json:"totp_enrolled"`
	Locked       bool `json:"locked"`
}

func (a *API) view(u *store.User) userView {
	return userView{User: u, TOTPEnrolled: u.TOTPEnrolled(), Locked: u.Locked(a.now())}
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	list, err := a.store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list users")
		return
	}
	out := make([]userView, 0, len(list))
	for _, u := range list {
		out = append(out, a.view(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// createUser adds a user with a generated one-time password, returned once.
func (a *API) createUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, pw, err := a.users.CreateUser(r.Context(), strings.TrimSpace(req.Username), req.Role, "")
	if err != nil {
		a.userErr(w, err)
		return
	}
	a.log.Info("user created via API", "user_id", u.ID, "by", p.KeyID)
	writeJSON(w, http.StatusCreated, map[string]any{"user": a.view(u), "password": pw})
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Unlock   bool    `json:"unlock"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if _, err := a.store.UserByID(ctx, id); err != nil {
		a.userErr(w, err)
		return
	}
	if req.Role != nil {
		if err := a.users.SetRole(ctx, id, *req.Role, p.UserID); err != nil {
			a.userErr(w, err)
			return
		}
	}
	if req.Disabled != nil {
		if err := a.users.SetDisabled(ctx, id, *req.Disabled, p.UserID); err != nil {
			a.userErr(w, err)
			return
		}
		if *req.Disabled {
			a.revokeUserTokens(r, id, p)
		}
	}
	if req.Unlock {
		if err := a.users.Unlock(ctx, id); err != nil {
			a.userErr(w, err)
			return
		}
	}
	u, err := a.store.UserByID(ctx, id)
	if err != nil {
		a.userErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.view(u))
}

// revokeUserTokens revokes the tokens a disabled or deleted user created,
// so a leaver's personal tokens stop working at once.
func (a *API) revokeUserTokens(r *http.Request, userID string, p *auth.Principal) {
	ids, err := a.store.RevokeTokensBy(r.Context(), userID, a.now())
	if err != nil {
		a.log.Error("revoking a user's tokens failed", "user_id", userID, "error", err.Error())
		return
	}
	for _, id := range ids {
		a.auth.ForgetID(id)
	}
	if len(ids) > 0 {
		a.log.Info("revoked a user's tokens", "user_id", userID, "count", len(ids), "by", p.KeyID)
	}
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if err := a.users.Delete(r.Context(), id, p.UserID); err != nil {
		a.userErr(w, err)
		return
	}
	a.revokeUserTokens(r, id, p)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) resetPassword(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if _, err := a.store.UserByID(r.Context(), id); err != nil {
		a.userErr(w, err)
		return
	}
	pw, err := a.users.ResetPassword(r.Context(), id, "")
	if err != nil {
		a.userErr(w, err)
		return
	}
	a.log.Info("password reset via API", "user_id", id, "by", p.KeyID)
	writeJSON(w, http.StatusOK, map[string]string{"password": pw})
}

func (a *API) resetTOTP(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if err := a.users.ResetTOTP(r.Context(), id); err != nil {
		a.userErr(w, err)
		return
	}
	a.log.Info("totp reset via API", "user_id", id, "by", p.KeyID)
	w.WriteHeader(http.StatusNoContent)
}
