package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/users"
)

func init() { auth.PasswordParams = auth.Argon2Params{Memory: 64, Time: 1, Threads: 1} }

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type uenv struct {
	t     *testing.T
	srv   *httptest.Server
	st    *store.Store
	svc   *users.Service
	clk   *testClock
	authn *auth.Authenticator
}

// browser is one logged-in client: its session cookie and CSRF token.
type browser struct {
	e      *uenv
	cookie string
	csrf   string
	secret []byte // TOTP secret once enrolled
}

const initialPW = "initial-admin-pw-1"

func newUserEnv(t *testing.T, tlsServer bool) *uenv {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "s")
	os.WriteFile(sec, []byte("SUPERSECRETVALUE"), 0o600)
	yml := `
server:
  public_base_url: http://cache.lan:8080
auth:
  token_max_ttl: 24h
  personal_token_max_ttl: 90d
  user_token_scope:
    buckets: [sstate]
    git: [{ remote: github, repos: ["acme/*"] }]
buckets:
  - alias: sstate
    provider: generic
    endpoint: http://s3.lan
    bucket: real-bucket
    credentials: { access_key_id: { file: ` + sec + ` }, secret_access_key: { file: ` + sec + ` } }
  - alias: downloads
    provider: generic
    endpoint: http://s3.lan
    bucket: real-dl
    credentials: { access_key_id: { file: ` + sec + ` }, secret_access_key: { file: ` + sec + ` } }
git:
  remotes:
    - name: github
      url: https://github.com
      allow: ["acme/*"]
`
	cfg, err := config.Parse([]byte(yml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authn := auth.New(st, log, adminKey, 5*time.Second)
	sealer, _ := auth.NewSealer("api-test-master-key-123456")
	svc := users.New(st, sealer, log, users.Options{})
	clk := &testClock{t: time.Now()}
	svc.Now = clk.Now
	if _, err := svc.Bootstrap(context.Background(), "admin", initialPW); err != nil {
		t.Fatal(err)
	}
	backends := map[string]s3proxy.Backend{"sstate": fakeBackend{}, "downloads": fakeBackend{}}
	mux := http.NewServeMux()
	New(cfg, st, authn, backends, log).WithUsers(svc).Register(mux)
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(mux)
	} else {
		srv = httptest.NewServer(mux)
	}
	t.Cleanup(srv.Close)
	return &uenv{t: t, srv: srv, st: st, svc: svc, clk: clk, authn: authn}
}

type resp struct {
	code   int
	body   map[string]any
	header http.Header
	raw    string
}

func (e *uenv) client() *http.Client {
	if e.srv.TLS != nil {
		return e.srv.Client()
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
}

func (e *uenv) do(method, path, cookie, csrf string, body any, hdr ...string) resp {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: users.CookieName, Value: cookie})
	}
	if csrf != "" {
		req.Header.Set(CSRFHeader, csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := e.client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp{res.StatusCode, out, res.Header, string(raw)}
}

func sessionCookie(t *testing.T, h http.Header) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == users.CookieName {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", h)
	return nil
}

func (e *uenv) login(name, pw string, secret []byte) (*browser, resp) {
	e.t.Helper()
	code := ""
	if secret != nil {
		e.clk.Add(30 * time.Second) // a fresh TOTP step; earlier codes were used
		code = auth.TOTPCode(secret, auth.TOTPStep(e.clk.Now()))
	}
	r := e.do("POST", "/api/v1/session", "", "", map[string]string{"username": name, "password": pw, "code": code})
	if r.code != 200 {
		return nil, r
	}
	return &browser{e: e, cookie: sessionCookie(e.t, r.header).Value, csrf: r.body["csrf_token"].(string), secret: secret}, r
}

func (b *browser) do(method, path string, body any) resp {
	b.e.t.Helper()
	return b.e.do(method, path, b.cookie, b.csrf, body)
}

// onboard runs the forced first-login flow: enrol TOTP, change password.
func (e *uenv) onboard(name, pw, newPW string) *browser {
	e.t.Helper()
	b, r := e.login(name, pw, nil)
	if b == nil || r.body["stage"] != users.StageEnrolTOTP {
		e.t.Fatalf("first login: %d %v", r.code, r.body)
	}
	r = b.do("POST", "/api/v1/session/totp", nil)
	if r.code != 200 || !strings.HasPrefix(r.body["qr_png"].(string), "data:image/png;base64,") {
		e.t.Fatalf("start enrolment: %d %v", r.code, r.raw)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.body["secret"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	r = b.do("POST", "/api/v1/session/totp/confirm", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(e.clk.Now()))})
	if r.code != 200 || r.body["stage"] != users.StageChangePassword {
		e.t.Fatalf("confirm: %d %v", r.code, r.body)
	}
	r = b.do("POST", "/api/v1/session/password", map[string]string{"current_password": pw, "new_password": newPW})
	if r.code != 200 || r.body["stage"] != users.StageOK {
		e.t.Fatalf("password change: %d %v", r.code, r.body)
	}
	b.secret = secret
	return b
}

// Acceptance criterion 9, at API level: the admin from the secret files
// needs password and TOTP, is forced to enrol and change the password, and
// can create a user who sees only their own tokens.
func TestSessionOnboardingAndRoles(t *testing.T) {
	e := newUserEnv(t, false)

	// Before onboarding is complete the API refuses the session.
	b, r := e.login("admin", initialPW, nil)
	if b == nil {
		t.Fatalf("login: %d %v", r.code, r.body)
	}
	if r := b.do("GET", "/api/v1/tokens", nil); r.code != 403 || r.body["stage"] != users.StageEnrolTOTP {
		t.Fatalf("tokens before enrolment: %d %v", r.code, r.body)
	}
	e.do("DELETE", "/api/v1/session", b.cookie, b.csrf, nil)

	admin := e.onboard("admin", initialPW, "admin-new-password")
	if r := admin.do("GET", "/api/v1/tokens", nil); r.code != 200 {
		t.Fatalf("tokens after onboarding: %d %v", r.code, r.body)
	}
	// Logging in again needs password and TOTP.
	if _, r := e.login("admin", "admin-new-password", nil); r.code != 401 {
		t.Fatalf("login without code: %d", r.code)
	}
	if _, r := e.login("admin", initialPW, admin.secret); r.code != 401 {
		t.Fatalf("login with the initial password: %d", r.code)
	}
	admin, r = e.login("admin", "admin-new-password", admin.secret)
	if admin == nil || r.body["stage"] != users.StageOK {
		t.Fatalf("full login: %d %v", r.code, r.body)
	}

	// The admin creates a user.
	r = admin.do("POST", "/api/v1/users", map[string]string{"username": "dev", "role": "user"})
	if r.code != 201 || r.body["password"] == "" {
		t.Fatalf("create user: %d %v", r.code, r.body)
	}
	devPW := r.body["password"].(string)
	dev := e.onboard("dev", devPW, "dev-chosen-password")
	devID := dev.userID(t)

	adminTok := admin.do("POST", "/api/v1/tokens", map[string]any{"buckets": []string{"downloads"}, "description": "admin's"})
	if adminTok.code != 201 {
		t.Fatalf("admin token: %d %v", adminTok.code, adminTok.body)
	}
	devTok := dev.do("POST", "/api/v1/tokens", map[string]any{"buckets": []string{"sstate"}, "description": "dev ci"})
	if devTok.code != 201 || devTok.body["created_by"] != devID {
		t.Fatalf("dev token: %d %v", devTok.code, devTok.body)
	}
	// Personal tokens may live up to personal_token_max_ttl (FR-91).
	pers := dev.do("POST", "/api/v1/tokens", map[string]any{"kind": "personal", "buckets": []string{"sstate"},
		"git": []map[string]any{{"remote": "github", "repos": []string{"acme/app"}}}, "ttl": "60d"})
	if pers.code != 201 || pers.body["kind"] != "personal" {
		t.Fatalf("personal token: %d %v", pers.code, pers.body)
	}
	if r := dev.do("POST", "/api/v1/tokens", map[string]any{"kind": "personal", "buckets": []string{"sstate"}, "ttl": "100d"}); r.code != 400 {
		t.Fatalf("personal token over max: %d", r.code)
	}
	if r := dev.do("POST", "/api/v1/tokens", map[string]any{"buckets": []string{"sstate"}, "ttl": "60d"}); r.code != 400 {
		t.Fatalf("ci token over max: %d", r.code)
	}
	if code, _ := (&env{t: t, srv: e.srv}).call("POST", "/api/v1/tokens", adminKey, map[string]any{"kind": "personal", "buckets": []string{"sstate"}}); code != 403 {
		t.Fatalf("personal token via API key: %d", code)
	}
	// The user's ceiling (auth.user_token_scope) applies.
	if r := dev.do("POST", "/api/v1/tokens", map[string]any{"buckets": []string{"downloads"}}); r.code != 403 {
		t.Fatalf("bucket outside user ceiling: %d", r.code)
	}
	if r := dev.do("POST", "/api/v1/tokens", map[string]any{"git": []map[string]any{{"remote": "github", "repos": []string{"other/x"}}}}); r.code != 403 {
		t.Fatalf("repo outside user ceiling: %d", r.code)
	}

	// The user sees only their own tokens; the admin sees all.
	if n := len(dev.do("GET", "/api/v1/tokens", nil).body["tokens"].([]any)); n != 2 {
		t.Fatalf("dev sees %d tokens, want 2", n)
	}
	if n := len(admin.do("GET", "/api/v1/tokens", nil).body["tokens"].([]any)); n != 3 {
		t.Fatalf("admin sees %d tokens, want 3", n)
	}
	if r := dev.do("DELETE", "/api/v1/tokens/"+adminTok.body["id"].(string), nil); r.code != 404 {
		t.Fatalf("dev revoking admin's token: %d", r.code)
	}
	if r := dev.do("DELETE", "/api/v1/tokens/"+devTok.body["id"].(string), nil); r.code != 204 {
		t.Fatalf("dev revoking own token: %d", r.code)
	}

	// Role checks.
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/v1/buckets", 200},
		{"POST", "/api/v1/buckets/sstate/test", 403},
		{"GET", "/api/v1/apikeys", 403},
		{"POST", "/api/v1/apikeys", 403},
		{"GET", "/api/v1/users", 403},
		{"POST", "/api/v1/users", 403},
	} {
		var body any
		if c.method == "POST" {
			body = map[string]any{}
		}
		if r := dev.do(c.method, c.path, body); r.code != c.want {
			t.Errorf("dev %s %s = %d, want %d", c.method, c.path, r.code, c.want)
		}
	}
	if r := admin.do("POST", "/api/v1/apikeys", map[string]any{"name": "ci", "role": "admin"}); r.code != 201 {
		t.Fatalf("admin creating API key via session: %d %v", r.code, r.body)
	}
	if r := admin.do("POST", "/api/v1/buckets/sstate/test", nil); r.code != 200 {
		t.Fatalf("admin bucket test: %d", r.code)
	}

	// Disabling the user ends their session and revokes their tokens.
	persValue := pers.body["token"].(string)
	if _, err := e.authn.Token(context.Background(), persValue); err != nil {
		t.Fatalf("personal token before disable: %v", err)
	}
	if r := admin.do("PATCH", "/api/v1/users/"+devID, map[string]any{"disabled": true}); r.code != 200 {
		t.Fatalf("disable: %d %v", r.code, r.body)
	}
	if r := dev.do("GET", "/api/v1/tokens", nil); r.code != 401 {
		t.Fatalf("disabled user's session: %d", r.code)
	}
	if _, err := e.authn.Token(context.Background(), persValue); err == nil {
		t.Fatal("disabled user's personal token still works")
	}
	// Admins can't lock themselves out.
	if r := admin.do("PATCH", "/api/v1/users/"+admin.userID(t), map[string]any{"disabled": true}); r.code != 409 {
		t.Fatalf("self-disable: %d", r.code)
	}
	if r := admin.do("DELETE", "/api/v1/users/"+admin.userID(t), nil); r.code != 409 {
		t.Fatalf("self-delete: %d", r.code)
	}
	// Reset TOTP / password responses.
	if r := admin.do("POST", "/api/v1/users/"+devID+"/reset-totp", nil); r.code != 204 {
		t.Fatalf("reset totp: %d", r.code)
	}
	if r := admin.do("POST", "/api/v1/users/"+devID+"/reset-password", nil); r.code != 200 || len(r.body["password"].(string)) != 20 {
		t.Fatalf("reset password: %d %v", r.code, r.body)
	}
	list := admin.do("GET", "/api/v1/users", nil)
	if list.code != 200 || len(list.body["users"].([]any)) != 2 || strings.Contains(list.raw, "argon2") || strings.Contains(list.raw, "v1:") {
		t.Fatalf("list users: %d %s", list.code, list.raw)
	}
}

func (b *browser) userID(t *testing.T) string {
	t.Helper()
	r := b.do("GET", "/api/v1/session", nil)
	if r.code != 200 {
		t.Fatalf("GET session: %d", r.code)
	}
	return r.body["user"].(map[string]any)["id"].(string)
}

func TestSessionCSRF(t *testing.T) {
	e := newUserEnv(t, false)
	admin := e.onboard("admin", initialPW, "admin-new-password")
	tok := admin.do("POST", "/api/v1/tokens", map[string]any{"buckets": []string{"sstate"}})
	if tok.code != 201 {
		t.Fatalf("create with CSRF token: %d", tok.code)
	}
	id := tok.body["id"].(string)
	for _, csrf := range []string{"", "wrong-token"} {
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{"POST", "/api/v1/tokens", map[string]any{"buckets": []string{"sstate"}}},
			{"DELETE", "/api/v1/tokens/" + id, nil},
			{"POST", "/api/v1/users", map[string]any{"username": "x", "role": "user"}},
			{"POST", "/api/v1/session/password", map[string]any{"current_password": "admin-new-password", "new_password": "something-else-12"}},
			{"DELETE", "/api/v1/session", nil},
		} {
			if r := e.do(c.method, c.path, admin.cookie, csrf, c.body); r.code != 403 {
				t.Errorf("%s %s with CSRF %q = %d, want 403", c.method, c.path, csrf, r.code)
			}
		}
	}
	// Safe methods don't need the token.
	if r := e.do("GET", "/api/v1/tokens", admin.cookie, "", nil); r.code != 200 {
		t.Fatalf("GET without CSRF token: %d", r.code)
	}
	// Another session's token doesn't work either.
	other, _ := e.login("admin", "admin-new-password", admin.secret)
	if r := e.do("DELETE", "/api/v1/tokens/"+id, admin.cookie, other.csrf, nil); r.code != 403 {
		t.Fatalf("other session's CSRF token: %d", r.code)
	}
	if r := admin.do("DELETE", "/api/v1/tokens/"+id, nil); r.code != 204 {
		t.Fatalf("revoke with CSRF token: %d", r.code)
	}
	// The token is still valid; logout ends the session.
	if r := admin.do("DELETE", "/api/v1/session", nil); r.code != 204 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := admin.do("GET", "/api/v1/tokens", nil); r.code != 401 {
		t.Fatalf("after logout: %d", r.code)
	}

	// Login requires a JSON body (a cross-site form can't send one).
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/session", strings.NewReader("username=admin&password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 415 {
		t.Fatalf("form login: %d", res.StatusCode)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	check := func(t *testing.T, e *uenv, wantSecure bool, hdr ...string) {
		t.Helper()
		r := e.do("POST", "/api/v1/session", "", "", map[string]string{"username": "admin", "password": initialPW}, hdr...)
		if r.code != 200 {
			t.Fatalf("login: %d %v", r.code, r.body)
		}
		c := sessionCookie(t, r.header)
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure != wantSecure {
			t.Fatalf("cookie %+v: want HttpOnly, SameSite=Strict, Secure=%v", c, wantSecure)
		}
		if !strings.HasPrefix(c.Value, users.SessionPrefix) {
			t.Fatalf("cookie value %q", c.Value)
		}
		// Only the hash is stored.
		if _, err := e.st.SessionByHash(context.Background(), c.Value); err == nil {
			t.Fatal("session stored by its plain value")
		}
		if _, err := e.st.SessionByHash(context.Background(), auth.Hash(c.Value)); err != nil {
			t.Fatalf("session not stored by hash: %v", err)
		}
	}
	t.Run("plain HTTP", func(t *testing.T) { check(t, newUserEnv(t, false), false) })
	t.Run("HTTPS", func(t *testing.T) { check(t, newUserEnv(t, true), true) })
	t.Run("behind a TLS reverse proxy", func(t *testing.T) {
		check(t, newUserEnv(t, false), true, "X-Forwarded-Proto", "https")
	})
}

func TestLoginLockoutAPI(t *testing.T) {
	e := newUserEnv(t, false)
	for i := 0; i < 5; i++ {
		if _, r := e.login("admin", "wrong-password", nil); r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	if _, r := e.login("admin", initialPW, nil); r.code != 429 {
		t.Fatalf("locked account: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/v1/session", "", "", nil); r.code != 401 {
		t.Fatalf("GET session without cookie: %d", r.code)
	}
	if r := e.do("GET", "/api/v1/tokens", "yps_forged", "", nil); r.code != 401 {
		t.Fatalf("forged cookie: %d", r.code)
	}
}
