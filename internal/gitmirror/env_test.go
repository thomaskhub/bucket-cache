package gitmirror

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/api"
	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

func TestMain(m *testing.M) {
	// Tests only talk to 127.0.0.1; never route them through a proxy.
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		os.Unsetenv(k)
	}
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Println("git not installed; skipping gitmirror tests")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// upstream is a fake GitHub: bare repos under root served by
// `git http-backend` through net/http/cgi.
type upstream struct {
	t    *testing.T
	root string
	srv  *httptest.Server
	cgi  *cgi.Handler

	requireAuth string       // Authorization value required for git requests ("" = public)
	secrets     []string     // values that must never appear in a process command line
	down        atomic.Int32 // 1 = hang until the request is cancelled, 2 = 503
	gitRequests atomic.Int64 // all git requests
	sawAuth     atomic.Bool  // a git request carried the required Authorization
	argvLeak    atomic.Value // string: a command line that contained a secret
	bytes       atomic.Int64 // response bytes sent
	api         http.Handler // optional GitHub API under /api/v3/
	authFn      atomic.Value // optional func(*http.Request) bool for git requests
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	gitBin, _ := exec.LookPath("git")
	u := &upstream{t: t, root: t.TempDir()}
	home := t.TempDir()
	u.cgi = &cgi.Handler{
		Path:   gitBin,
		Args:   []string{"http-backend"},
		Stderr: io.Discard,
		Env: []string{
			"GIT_PROJECT_ROOT=" + u.root, "GIT_HTTP_EXPORT_ALL=1", "HOME=" + home,
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
			// Like GitHub: commits can be fetched by SHA.
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=uploadpack.allowAnySHA1InWant", "GIT_CONFIG_VALUE_0=true",
			"GIT_CONFIG_KEY_1=uploadpack.allowFilter", "GIT_CONFIG_VALUE_1=true",
		},
	}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

type countingWriter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (c countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (u *upstream) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/v3/") && u.api != nil {
		u.api.ServeHTTP(w, r)
		return
	}
	switch u.down.Load() {
	case 1:
		<-r.Context().Done()
		return
	case 2:
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	u.gitRequests.Add(1)
	u.checkArgv()
	if f, ok := u.authFn.Load().(func(*http.Request) bool); ok && !f(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if u.requireAuth != "" {
		if r.Header.Get("Authorization") != u.requireAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		u.sawAuth.Store(true)
	}
	u.cgi.ServeHTTP(countingWriter{w, &u.bytes}, r)
}

// checkArgv scans every process's command line for the secrets while the
// proxy's git (and its git-remote-http helper) is talking to us.
func (u *upstream) checkArgv() {
	if len(u.secrets) == 0 {
		return
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		for _, s := range u.secrets {
			if bytes.Contains(b, []byte(s)) {
				u.argvLeak.Store(strings.ReplaceAll(string(b), "\x00", " "))
			}
		}
	}
}

// gitEnv is a clean environment for test-side git commands.
func gitEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=t@example.com", "LANG=C",
		"GIT_TRACE_PACKET=" + os.Getenv("TEST_GIT_TRACE_PACKET"), // debugging aid
	}
}

func runGit(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(t.TempDir())
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.String(), nil
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGit(t, dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// repo is a bare upstream repo plus a work tree used to push to it.
type repo struct {
	t    *testing.T
	bare string
	work string
}

// newRepo creates owner/name with a main branch, a feature branch, a
// lightweight and an annotated tag, a big random blob (so filters and
// shallow clones visibly reduce transfer size) and a GitHub-style PR ref.
func (u *upstream) newRepo(owner, name string) *repo {
	t := u.t
	t.Helper()
	bare := filepath.Join(u.root, owner, name+".git")
	mustGit(t, "", "init", "--quiet", "--bare", "--initial-branch=main", bare)
	work := t.TempDir()
	mustGit(t, work, "init", "--quiet", "--initial-branch=main")
	r := &repo{t: t, bare: bare, work: work}
	big := make([]byte, 200<<10)
	_, _ = rand.Read(big)
	r.write("big.bin", base64.StdEncoding.EncodeToString(big))
	r.commit("first")
	r.write("README", "hello\n")
	r.commit("second")
	mustGit(t, work, "tag", "v1.0")
	mustGit(t, work, "tag", "-a", "-m", "release", "v1.1")
	mustGit(t, work, "checkout", "--quiet", "-b", "kirkstone")
	r.write("kirkstone.txt", "lts\n")
	r.commit("kirkstone")
	mustGit(t, work, "checkout", "--quiet", "main")
	mustGit(t, work, "push", "--quiet", bare, "main", "kirkstone", "--tags")
	// A PR head that is on no branch.
	mustGit(t, work, "checkout", "--quiet", "-b", "pr")
	r.write("pr.txt", "pr\n")
	r.commit("pr commit")
	mustGit(t, work, "push", "--quiet", bare, "pr:refs/pull/1/head")
	mustGit(t, work, "checkout", "--quiet", "main")
	mustGit(t, work, "branch", "--quiet", "-D", "pr")
	return r
}

func (r *repo) write(name, content string) {
	if err := os.WriteFile(filepath.Join(r.work, name), []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) string {
	mustGit(r.t, r.work, "add", "-A")
	mustGit(r.t, r.work, "commit", "--quiet", "-m", msg)
	return mustGit(r.t, r.work, "rev-parse", "HEAD")
}

func (r *repo) push(args ...string) {
	mustGit(r.t, r.work, append([]string{"push", "--quiet", "--force", r.bare}, args...)...)
}

// env is a proxy in front of an upstream.
type env struct {
	t        *testing.T
	up       *upstream
	cfg      *config.Config
	st       *store.Store
	authn    *auth.Authenticator
	mgr      *Manager
	reg      *prometheus.Registry
	proxy    *httptest.Server
	admin    *httptest.Server
	adminKey string

	execMu sync.Mutex
	execs  [][]string
}

type envOpts struct {
	extraRemote string // YAML appended to the remote
	extraGit    string // YAML appended to the git block
}

func newEnv(t *testing.T, up *upstream, o envOpts) *env {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "admin_key")
	adminKey := "test-admin-key-0123456789"
	if err := os.WriteFile(keyFile, []byte(adminKey), 0o600); err != nil {
		t.Fatal(err)
	}
	yml := fmt.Sprintf(`
server:
  public_base_url: http://proxy.example
auth:
  bootstrap_admin_key: { file: %s }
storage:
  db_path: %s
git:
  storage: %s
%s
  remotes:
    - name: test
      url: %s
      allow: ["acme/*", "solo/one"]
      ls_remote_cache: 200ms
      upstream_timeout: 1s
      refresh_interval: 1h
%s
`, keyFile, filepath.Join(dir, "p.db"), filepath.Join(dir, "git"), o.extraGit, up.srv.URL, o.extraRemote)
	cfg, err := config.Parse([]byte(yml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), cfg.Storage.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	authn := auth.New(st, log, adminKey, time.Second)
	reg := prometheus.NewRegistry()
	mgr, err := New(context.Background(), cfg.Git, Options{Logger: log, Registerer: reg, PublicBaseURL: cfg.Server.PublicBaseURL, AllowStore: st})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, up: up, cfg: cfg, st: st, authn: authn, mgr: mgr, reg: reg, adminKey: adminKey}
	mgr.SetExecHook(func(args []string) {
		e.execMu.Lock()
		e.execs = append(e.execs, args)
		e.execMu.Unlock()
	})
	h := mgr.NewHandler(authn, false)
	e.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.Match(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(e.proxy.Close)
	mux := http.NewServeMux()
	a := api.New(cfg, st, authn, nil, log)
	a.Register(mux)
	mgr.RegisterAPI(mux, a.Authenticated, a.AdminOnly)
	mgr.RegisterAllowAPI(mux, a.AdminActor)
	e.admin = httptest.NewServer(mux)
	t.Cleanup(e.admin.Close)
	return e
}

// token creates a token for the given git scope.
func (e *env) token(repos ...string) string {
	return e.tokenTTL(time.Hour, repos...)
}

func (e *env) tokenTTL(ttl time.Duration, repos ...string) string {
	v := auth.NewSecret(auth.TokenPrefix)
	now := time.Now()
	tok := &store.Token{ID: auth.NewID("tok_"), Hash: auth.Hash(v), Kind: "ci",
		Scope:     store.Scope{Git: []store.GitScope{{Remote: "test", Repos: repos}}},
		CreatedBy: "test", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(ttl)}
	if err := e.st.CreateToken(context.Background(), tok); err != nil {
		e.t.Fatal(err)
	}
	return v
}

// url returns the proxy URL of a repo with the token in the path.
func (e *env) url(token, ownerRepo string) string {
	return e.proxy.URL + "/t/" + token + "/git/test/" + ownerRepo + ".git"
}

// basicURL returns the proxy URL with the token as Basic password.
func (e *env) basicURL(token, ownerRepo string) string {
	return strings.Replace(e.proxy.URL, "http://", "http://ci:"+token+"@", 1) + "/git/test/" + ownerRepo
}

func (e *env) direct(ownerRepo string) string { return e.up.srv.URL + "/" + ownerRepo + ".git" }

// metric sums a counter or gauge from the registry over series whose
// labels include all of want.
func (e *env) metric(name string, want map[string]string) float64 {
	mfs, err := e.reg.Gather()
	if err != nil {
		e.t.Fatal(err)
	}
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			for k, v := range want {
				if labels[k] != v {
					continue next
				}
			}
			switch {
			case m.Counter != nil:
				sum += m.Counter.GetValue()
			case m.Gauge != nil:
				sum += m.Gauge.GetValue()
			case m.Histogram != nil:
				sum += float64(m.Histogram.GetSampleCount())
			}
		}
	}
	return sum
}

func (e *env) execLog() [][]string {
	e.execMu.Lock()
	defer e.execMu.Unlock()
	return append([][]string{}, e.execs...)
}

func (e *env) do(method, path string, hdr map[string]string, body io.Reader) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.proxy.URL+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// Don't let the client clean the path: BitBake sends "//" as-is.
	req.URL.Opaque, _, _ = strings.Cut(path, "?")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) adminDo(method, path, key string) (*http.Response, string) {
	e.t.Helper()
	return e.adminDoBody(method, path, key, "")
}

func (e *env) adminDoBody(method, path, key, body string) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// refs returns `git for-each-ref` of a clone, without remote HEAD lines.
func refs(t *testing.T, dir string, patterns ...string) string {
	t.Helper()
	out := mustGit(t, dir, append([]string{"for-each-ref", "--format=%(objectname) %(refname)"}, patterns...)...)
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasSuffix(l, "/HEAD") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
