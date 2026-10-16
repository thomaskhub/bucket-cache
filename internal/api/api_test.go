package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

type fakeBackend struct{ err error }

func (f fakeBackend) Get(context.Context, string, s3proxy.Conditions) (*s3proxy.Object, error) {
	return nil, s3proxy.ErrNotFound
}
func (f fakeBackend) Head(context.Context, string, s3proxy.Conditions) (*s3proxy.Object, error) {
	return nil, s3proxy.ErrNotFound
}
func (f fakeBackend) Test(context.Context) error { return f.err }

type env struct {
	t     *testing.T
	srv   *httptest.Server
	authn *auth.Authenticator
}

const adminKey = "bootstrap-admin-key"

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "s")
	os.WriteFile(sec, []byte("SUPERSECRETVALUE"), 0o600)
	yml := `
server:
  public_base_url: http://cache.lan:8080
auth:
  token_max_ttl: 24h
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
	backends := map[string]s3proxy.Backend{
		"sstate":    fakeBackend{},
		"downloads": fakeBackend{err: &s3proxy.BackendError{Status: 403, Err: errors.New("AccessDenied real-dl")}},
	}
	mux := http.NewServeMux()
	New(cfg, st, authn, backends, log).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, authn: authn}
}

func (e *env) call(method, path, key string, body any) (int, map[string]any) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{}
	}
	out["_raw"] = string(raw)
	return resp.StatusCode, out
}

func TestCreateAndUseToken(t *testing.T) {
	e := newEnv(t)
	code, out := e.call("POST", "/api/v1/tokens", adminKey, map[string]any{
		"buckets": []string{"sstate"}, "ttl": "6h", "description": "pipeline 4711", "labels": map[string]string{"job": "4711"}})
	if code != 201 {
		t.Fatalf("create = %d %v", code, out["_raw"])
	}
	value, _ := out["token"].(string)
	if !auth.LooksLikeToken(value) {
		t.Fatalf("bad token value %q", value)
	}
	ex, _ := out["examples"].(map[string]any)
	if !strings.Contains(ex["sstate_mirrors"].(string), "http://cache.lan:8080/t/${SSTATE_PROXY_TOKEN}/sstate/PATH") {
		t.Errorf("mirror example = %v", ex["sstate_mirrors"])
	}
	exp, _ := time.Parse(time.RFC3339, out["expires_at"].(string))
	if d := time.Until(exp); d < 5*time.Hour || d > 6*time.Hour+time.Minute {
		t.Errorf("expires in %s, want ~6h", d)
	}
	if _, err := e.authn.Token(context.Background(), value); err != nil {
		t.Fatalf("created token doesn't validate: %v", err)
	}

	code, out = e.call("GET", "/api/v1/tokens", adminKey, nil)
	if code != 200 || strings.Contains(out["_raw"].(string), value) || strings.Contains(out["_raw"].(string), "hash") {
		t.Fatalf("list = %d, leaks token or hash: %v", code, out["_raw"])
	}

	// Self-revoke at the end of a build; the token stops working at once.
	if code, _ := e.call("DELETE", "/api/v1/tokens/self", value, nil); code != 204 {
		t.Fatalf("self revoke = %d", code)
	}
	if _, err := e.authn.Token(context.Background(), value); !errors.Is(err, auth.ErrDead) {
		t.Fatalf("token still usable after self-revoke: %v", err)
	}
	if code, _ := e.call("DELETE", "/api/v1/tokens/self", value, nil); code != 204 {
		t.Fatalf("second self revoke = %d, want 204", code)
	}
}

func TestCreateTokenValidation(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"ttl over max":    {map[string]any{"buckets": []string{"sstate"}, "ttl": "48h"}, 400},
		"bad ttl":         {map[string]any{"buckets": []string{"sstate"}, "ttl": "soon"}, 400},
		"unknown bucket":  {map[string]any{"buckets": []string{"nope"}}, 400},
		"empty scope":     {map[string]any{}, 400},
		"unknown remote":  {map[string]any{"git": []map[string]any{{"remote": "gitlab", "repos": []string{"a/b"}}}}, 400},
		"bad repo":        {map[string]any{"git": []map[string]any{{"remote": "github", "repos": []string{"*"}}}}, 400},
		"unknown field":   {map[string]any{"buckets": []string{"sstate"}, "bukets": 1}, 400},
		"git scope works": {map[string]any{"git": []map[string]any{{"remote": "github", "repos": []string{"acme/*"}}}}, 201},
	} {
		if code, out := e.call("POST", "/api/v1/tokens", adminKey, tc.body); code != tc.want {
			t.Errorf("%s: %d, want %d (%v)", name, code, tc.want, out["_raw"])
		}
	}
	if code, _ := e.call("POST", "/api/v1/tokens", "", map[string]any{"buckets": []string{"sstate"}}); code != 401 {
		t.Errorf("no key: %d, want 401", code)
	}
	if code, _ := e.call("POST", "/api/v1/tokens", "wrong", map[string]any{"buckets": []string{"sstate"}}); code != 401 {
		t.Errorf("wrong key: %d, want 401", code)
	}
}

func TestIssuerKeyCeiling(t *testing.T) {
	e := newEnv(t)
	code, out := e.call("POST", "/api/v1/apikeys", adminKey, map[string]any{
		"name": "ci", "role": "token-issuer",
		"ceiling": map[string]any{"scope": map[string]any{"buckets": []string{"sstate"}}, "max_ttl": "8h"}})
	if code != 201 {
		t.Fatalf("create issuer = %d %v", code, out["_raw"])
	}
	issuer := out["key"].(string)
	issuerID := out["id"].(string)

	if code, out := e.call("POST", "/api/v1/tokens", issuer, map[string]any{"buckets": []string{"sstate"}, "ttl": "6h"}); code != 201 {
		t.Fatalf("within ceiling = %d %v", code, out["_raw"])
	}
	if code, _ := e.call("POST", "/api/v1/tokens", issuer, map[string]any{"buckets": []string{"downloads"}}); code != 403 {
		t.Errorf("bucket outside ceiling = %d, want 403", code)
	}
	if code, _ := e.call("POST", "/api/v1/tokens", issuer, map[string]any{"buckets": []string{"sstate"}, "ttl": "10h"}); code != 403 {
		t.Errorf("ttl over ceiling = %d, want 403", code)
	}
	if code, _ := e.call("POST", "/api/v1/tokens", issuer, map[string]any{"git": []map[string]any{{"remote": "github", "repos": []string{"acme/x"}}}}); code != 403 {
		t.Errorf("git outside ceiling = %d, want 403", code)
	}

	// Issuers see and revoke only their own tokens.
	e.call("POST", "/api/v1/tokens", adminKey, map[string]any{"buckets": []string{"downloads"}})
	_, out = e.call("GET", "/api/v1/tokens", issuer, nil)
	toks := out["tokens"].([]any)
	if len(toks) != 1 || toks[0].(map[string]any)["created_by"] != issuerID {
		t.Fatalf("issuer sees %d tokens: %v", len(toks), out["_raw"])
	}
	_, out = e.call("GET", "/api/v1/tokens", adminKey, nil)
	var adminTok string
	for _, x := range out["tokens"].([]any) {
		if m := x.(map[string]any); m["created_by"] == "bootstrap" {
			adminTok = m["id"].(string)
		}
	}
	if code, _ := e.call("DELETE", "/api/v1/tokens/"+adminTok, issuer, nil); code != 404 {
		t.Errorf("issuer revoking admin's token = %d, want 404", code)
	}
	if code, _ := e.call("DELETE", "/api/v1/tokens/"+adminTok, adminKey, nil); code != 204 {
		t.Errorf("admin revoke = %d", code)
	}

	// Issuers can't manage keys or see buckets.
	if code, _ := e.call("GET", "/api/v1/apikeys", issuer, nil); code != 403 {
		t.Errorf("issuer listing keys = %d, want 403", code)
	}
	// Revoked keys stop working.
	if code, _ := e.call("DELETE", "/api/v1/apikeys/"+issuerID, adminKey, nil); code != 204 {
		t.Fatalf("revoke key = %d", code)
	}
	if code, _ := e.call("POST", "/api/v1/tokens", issuer, map[string]any{"buckets": []string{"sstate"}}); code != 401 {
		t.Errorf("revoked key = %d, want 401", code)
	}
}

func TestAPIKeyValidation(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]map[string]any{
		"no name":            {"role": "admin"},
		"bad role":           {"name": "x", "role": "root"},
		"issuer no ceiling":  {"name": "x", "role": "token-issuer"},
		"admin with ceiling": {"name": "x", "role": "admin", "ceiling": map[string]any{"max_ttl": "1h"}},
	} {
		if code, _ := e.call("POST", "/api/v1/apikeys", adminKey, body); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}

func TestBuckets(t *testing.T) {
	e := newEnv(t)
	code, out := e.call("GET", "/api/v1/buckets", adminKey, nil)
	if code != 200 || strings.Contains(out["_raw"].(string), "SUPERSECRETVALUE") {
		t.Fatalf("buckets = %d, leaks secret: %v", code, out["_raw"])
	}
	if len(out["buckets"].([]any)) != 2 {
		t.Fatalf("buckets = %v", out["_raw"])
	}
	_, out = e.call("POST", "/api/v1/buckets/sstate/test", adminKey, nil)
	if out["ok"] != true {
		t.Errorf("sstate test = %v", out["_raw"])
	}
	_, out = e.call("POST", "/api/v1/buckets/downloads/test", adminKey, nil)
	if out["ok"] != false || !strings.Contains(out["error"].(string), "access denied") || strings.Contains(out["_raw"].(string), "real-dl") {
		t.Errorf("downloads test = %v", out["_raw"])
	}
	if code, _ := e.call("POST", "/api/v1/buckets/nope/test", adminKey, nil); code != 404 {
		t.Errorf("unknown bucket test = %d", code)
	}
}
